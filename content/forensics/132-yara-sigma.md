---
id: forensics-yara-sigma
title: "YARA и Sigma: правила для файлов, памяти и логов"
category: forensics
parent: forensics-tooling
difficulty: medium
order: 2
tags: [yara, sigma, rules, detection, siem, malware]
prerequisites: [forensics-tooling]
useful_for:
  - "CTF Forensics категория"
  - "Threat Hunting"
  - "Malware Analysis"
estimated_minutes: 52
summary: "Написание и применение правил: YARA для файлов/памяти и Sigma для логов; синтаксис, условия, производительность, конвертация Sigma в SIEM-запросы и типичные ошибки."
---

YARA и Sigma — два стандарта описания «плохого». **YARA** ищет байтовые паттерны в файлах и памяти; **Sigma** описывает события логов независимо от SIEM. Вместе они закрывают две плоскости: содержимое артефактов и поведение в логах. Для форензика это способ автоматизировать поиск известных угроз и аномалий.

## YARA: синтаксис

Правило состоит из `meta`, `strings` и `condition`:

```yara
rule Suspicious_PowerShell
{
    meta:
        author = "analyst"
        description = "PowerShell with encoded command"
        severity = "high"
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "-nop" nocase
        $d = { 4D 5A 90 00 }              // hex-паттерн (MZ)
    condition:
        uint16(0) == 0x5A4D and ($a and $b) or ($b and $c)
}
```

Элементы:

| Элемент | Значение |
|---------|----------|
| `$a = "text"` | текстовая строка |
| `nocase` | без учёта регистра |
| `wide` | UTF-16LE |
| `$h = { 4D 5A ?? ?? }` | hex с wildcards |
| `$r = /regex/` | регулярное выражение |
| `filesize` | размер файла |
| `uint16(0)` | первые 2 байта |
| `#a > 3` | счётчик вхождений |
| `$a at 0` | по смещению |

## Применение YARA

```bash
# Файл
yara rule.yar suspect.bin
# Каталог рекурсивно
yara -r rules/ /evidence/
# С печатью совпавших строк
yara -s rule.yar suspect.bin
# Таймаут на правило (для больших наборов)
yara -a 60 -r rules/ /evidence/
# Компиляция набора для повторного использования
yarac rules.yar rules.compiled
yara rules.compiled suspect.bin
```

В памяти YARA применяют через Volatility (`yarascan`), в дисках — через Autopsy (YARA-модуль) или `yara -r`.

## Sigma: синтаксис

Sigma — YAML-правило для логов:

```yaml
title: Suspicious PowerShell Encoded Command
id: 1234abcd-...
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
  condition: selection
falsepositives:
  - Admin scripts
level: high
```

Поля `logsource` описывают источник; `detection` — условия; `condition` комбинирует селекторы (`and`, `or`, `not`, `1 of`, `all of`).

## Конвертация и применение Sigma

```bash
# Установить sigmac
pip install sigma-cli
# Конвертировать в Elastic/Splunk/Sentinel
sigma convert -t es-qs rule.yml
sigma convert -t splunk rule.yml
sigma convert -t microsoft365defender rule.yml
# Прогнать по логам через sigmac
sigmac -t splunk -c config.yml rules/ > splunk_query.txt
```

Sigma-правила живут в репозитории SigmaHQ; берите проверенные и адаптируйте под свои логи.

## Разобранный пример

```bash
$ cat hunt.yar
rule CTF_Flag {
  strings: $f = /flag\{[a-z0-9_]+\}/
  condition: $f
}
$ yara -r hunt.yar /evidence
CTF_Flag /evidence/secret.txt
$ cat ps.yml
title: Encoded PowerShell
logsource: {product: windows}
detection:
  sel: {CommandLine|contains: '-enc'}
  condition: sel
level: high
$ sigma convert -t es-qs ps.yml
(CommandLine:*\\-enc*)
```

YARA нашла флаг в файле; Sigma дала запрос для SIEM, которым можно найти запуск encoded PowerShell.

## Производительность

- **YARA regex дороги.** Anchored-строки и `nocase` дешевле; избегайте `.` в начале regex.
- **Порядок условий.** Ставьте дешёвые проверки первыми (`uint16(0)==0x5A4D and ...`).
- **Компиляция.** Для повторных прогонов используйте `yarac`.
- **Таймауты.** `-a` ограничивает время на правило.
- **Sigma.** Конвертируйте один раз, храните готовые запросы.

## Краевые случаи и подводные камни

- **Ложные срабатывания.** Общие строки («powershell») дают шум; добавляйте контекст.
- **Обфускация.** Малварь может избегать строк; используйте hex/regex.
- **Кодировки.** Windows-строки часто UTF-16 (`wide`).
- **Версии Sigma.** Формат развивается; старые правила могут не конвертироваться.
- **logsource.** Неверный источник → правило не сработает.
- **Память.** YARA в памяти может находить декодированные данные, которых нет на диске.
- **Права.** Сканирование `/evidence` требует доступа.

## YARA: продвинутые условия

```yara
rule Advanced
{
    meta:
        author = "analyst"
    strings:
        $mz = { 4D 5A }
        $str1 = "CreateRemoteThread" ascii wide
        $re = /https?:\/\/[a-z0-9.\-]+\/[a-z0-9]+/ nocase
        $x = { 48 8B ?? ?? 48 89 ?? }
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        #str1 > 2 and $re and any of ($x*)
}
```

Полезные операторы:

| Оператор | Значение |
|----------|----------|
| `any of them` | любая строка |
| `all of them` | все строки |
| `2 of ($a*)` | 2 из группы `$a*` |
| `#a > N` | больше N вхождений |
| `$a at 0` | по смещению 0 |
| `$a in (0..1024)` | в диапазоне |
| `for any i in (1..#a)` | цикл |
| `for all of them` | все (аналог) |

## Модули YARA

YARA имеет модули для разбора форматов:

```yara
import "pe"
import "elf"
import "math"
import "hash"

rule SuspiciousPE
{
    condition:
        pe.is_pe and pe.number_of_sections > 0 and
        pe.imports("kernel32.dll", "VirtualAlloc") and
        pe.entry_point == 0
}
```

- `pe` — секции, импорты, ресурсы, timestamp.
- `elf` — ELF-структуры.
- `math` — вычисления (энтропия).
- `hash` — md5/sha1/sha256 содержимого.

Модули делают правила точнее: можно искать PE с нулевым entry point и импортом `VirtualAlloc` — типичный признак упаковщика.

## Sigma: condition и модификаторы

```yaml
detection:
  selection_img:
    Image|endswith: '\powershell.exe'
  selection_flag:
    CommandLine|contains:
      - '-enc'
      - '-nop'
  filter_legit:
    User|endswith: '$'
  condition: selection_img and selection_flag and not filter_legit
```

Модификаторы полей: `contains`, `startswith`, `endswith`, `re`, `all`, `base64`, `cidr`. Комбинируя их, описывают сложное поведение.

Правила конвертируются в запросы разных бэкендов:

```bash
sigma convert -t splunk rules/ps.yml
sigma convert -t es-qs rules/ps.yml
sigma convert -t microsoft365defender rules/ps.yml
sigma convert -t chronicle rules/ps.yml
```

## Корреляция правил

- **YARA** — «что это за файл/код».
- **Sigma** — «что произошло в логах».
- Вместе: YARA находит образец, Sigma — как он был запущен и что делал.

Пример цепочки: YARA ловит beacon в памяти → Sigma-правило находит запуск `rundll32` с этим файлом в логах → коррелируете время и хост.

## Хранение и версионирование правил

- Храните правила в git; фиксируйте версии.
- Тестируйте на безопасных образцах перед продакшеном.
- Избегайте дублирующихся sid/rule-id.
- Документируйте `meta` (author, description, severity, reference).
- Обновляйте из SigmaHQ/awesome-yara, но проверяйте на ложные срабатывания.

## Типичные ошибки

- **Слишком широкие строки.** `"http"` даст тысячи совпадений.
- **Отсутствие `nocase`/`wide`.** Пропуск реальных срабатываний.
- **Regex в начале правила.** Медленно; ставьте дешёвые условия первыми.
- **Нет тестов.** Правило может не срабатывать вообще.
- **Неверный logsource в Sigma.** Правило «молчит».
- **Дубли sid.** Конфликты в SIEM.
- **Игнорирование модулей.** `pe`/`hash` дают точность.

## Готовые наборы правил

Не пишите всё с нуля — используйте проверенные источники:

- **SigmaHQ** — официальный репозиторий Sigma-правил (Windows/Linux/cloud).
- **awesome-yara** — коллекция YARA-правил.
- **Neo23x0/signature-base** — правила от Florian Roth.
- **Elastic protections-artifacts** — правила для EDR.
- **YARA-Rules/rules** — большой набор.

```bash
git clone https://github.com/SigmaHQ/sigma
git clone https://github.com/Neo23x0/signature-base
# Прогнать YARA-набор
yara -r signature-base/yara /evidence
# Конвертировать Sigma
sigma convert -t es-qs -p ecs_windows sigma/rules/windows/ > es_queries.txt
```

## Пайплайн детекта

1. Собрать правила из репозиториев.
2. Отфильтровать под свою среду (убрать нерелевантные logsource).
3. Протестировать на исторических логах (false positive rate).
4. Развернуть в SIEM/EDR.
5. Регулярно обновлять.

## Отладка правил

```bash
# YARA: проверить синтаксис
yara -d rule.yar    # debug-вывод
# Sigma: конвертация покажет ошибки
sigma convert -t es-qs rule.yml
# Проверить на «хорошем» файле — не должно срабатывать
yara rule.yar /usr/bin/ls
```

## Итоговый чек-лист

1. Определить цель: файлы/память (YARA) или логи (Sigma).
2. Взять правила из проверенного репозитория.
3. Адаптировать под среду и logsource.
4. Протестировать (false positives, false negatives).
5. Применить (`yara -r`, `sigma convert` + SIEM).
6. Задокументировать срабатывания.

## Правила в CI/CD и мониторинге

Правила полезно встроить в конвейер:

- **CI** — YARA по артефактам сборки (детект заражённых бинарей).
- **SIEM** — Sigma-правила как детекты.
- **EDR** — YARA в памяти/на диске.
- **Ретроспектива** — прогон новых правил по историческим логам.

```bash
# Прогон YARA в CI
yara -r rules/ build/ || exit 1
# Обновление правил Sigma в SIEM
sigma convert -t splunk rules/ > /etc/siem/rules.txt
```

## Итог

YARA и Sigma — универсальные языки детекта: первый для содержимого, второй для событий. Используйте готовые репозитории, адаптируйте под среду, тестируйте на ложные срабатывания и встраивайте в конвейер.

## Ключевые выводы

- YARA — содержимое (файлы/память), Sigma — события логов.
- Готовые репозитории (SigmaHQ, signature-base) экономят недели.
- Тестируйте правила на ложные срабатывания до продакшена.
- Конвертируйте Sigma один раз под свой SIEM.
- Документируйте и версионируйте правила в git.

## Мини-таблица конвертации Sigma

| Бэкенд | Команда |
|--------|---------|
| Splunk | `sigma convert -t splunk` |
| Elastic | `sigma convert -t es-qs` |
| Sentinel | `sigma convert -t microsoft365defender` |
| Chronicle | `sigma convert -t chronicle` |

Одно правило — множество SIEM. Это и есть смысл Sigma: независимость от вендора.

## Что дальше / решение

1. Написать/взять YARA-правила под задачу.
2. Прогнать по файлам (`yara -r`) и памяти (`yarascan`).
3. Взять Sigma-правила из SigmaHQ, адаптировать `logsource`.
4. Конвертировать в SIEM-запросы (`sigma convert`).
5. Задокументировать срабатывания и подтвердить контекстом.

Дальше — `forensics-python-tooling` (автоматизация) и `forensics-malware-yara`.

## Квиз

```quiz
- question: "Чем YARA отличается от Sigma?"
  options:
    - "YARA — для файлов/памяти, Sigma — для логов"
    - "YARA — для логов, Sigma — для файлов"
    - "Это одно и то же"
    - "Sigma работает только в облаке"
  answer: 0
  explanation: "YARA ищет байтовые паттерны; Sigma описывает события логов."
- question: "Что означает модификатор `wide` в YARA?"
  options:
    - "поиск в UTF-16LE"
    - "поиск без учёта регистра"
    - "regex"
    - "hex-паттерн"
  answer: 0
  explanation: "wide — строки в UTF-16LE, типичные для Windows."
- question: "Как применить Sigma-правило к SIEM?"
  options:
    - "yara -r"
    - "sigma convert -t <backend>"
    - "vol yarascan"
    - "binwalk"
  answer: 1
  explanation: "sigma convert транслирует правило в запрос конкретного SIEM."
- question: "Почему YARA-regex может быть медленным?"
  options:
    - "YARA не поддерживает regex"
    - "Незаанкоренные regex требуют много сравнений"
    - "Он работает только на диске"
    - "Из-за шифрования"
  answer: 1
  explanation: "Regex без привязки дорог; используйте anchored-строки и порядок условий."
```

## Где пригодится

- **CTF:** поиск флагов и сигнатур в файлах/памяти.
- **Threat Hunting:** массовый поиск известных угроз.
- **Malware Analysis:** классификация образцов.
- **SOC:** детекты в логах через Sigma.
