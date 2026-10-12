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

## Вопрос, с которого всё начинается

На диске тысячи файлов, а в логах миллионы строк. Искать «глазами» бессмысленно. Нужен способ один раз описать, что мы считаем **плохим**, и применить это описание к тысячам объектов. Для содержимого и для событий логов такие языки разные.

## Наш пример: ищем флаг в каталоге улик

У нас есть каталог `/evidence` с извлечёнными файлами. Напишем правило, которое найдёт шаблон флага.

## Шаг 1: YARA — правила для содержимого

**YARA** ищет байтовые паттерны в файлах и памяти. Правило состоит из трёх частей: `meta` (описание), `strings` (что искать) и `condition` (когда правило срабатывает):

```yara
rule CTF_Flag {
    strings:
        $f = /flag\{[a-z0-9_]+\}/
    condition:
        $f
}
```

Применяем к каталогу рекурсивно (`-r`):

```bash
$ yara -r hunt.yar /evidence
CTF_Flag /evidence/secret.txt
```

Правило нашло флаг в файле. Ключевые элементы строк:

| Элемент | Значение |
|---------|----------|
| `$a = "text"` | текстовая строка |
| `nocase` | без учёта регистра |
| `wide` | UTF-16LE (типично для Windows) |
| `$h = { 4D 5A ?? ?? }` | hex с wildcards |
| `$r = /regex/` | регулярное выражение |
| `#a > 3` | счётчик вхождений |

## Шаг 2: более реалистичное правило

Для детекта малвари правила комбинируют несколько условий. Например, ищем подозрительный PE-файл:

```yara
rule SuspiciousPE {
    strings:
        $mz = { 4D 5A }
        $api = "VirtualAlloc"
        $url = /https?:\/\/[a-z0-9.\-]+\/[a-z0-9]+/ nocase
    condition:
        uint16(0) == 0x5A4D and $api and $url
}
```

`uint16(0) == 0x5A4D` проверяет первые два байта (сигнатуру `MZ`). Порядок условий важен: дешёвые проверки ставят первыми. Для больших наборов правил применяют таймаут (`-a`) и компиляцию (`yarac`):

```bash
$ yara -a 60 -r rules/ /evidence/
$ yarac rules.yar rules.compiled
```

## Шаг 3: Sigma — правила для логов

**Sigma** — YAML-описание событий логов, независимое от конкретного SIEM. Опишем подозрительный запуск PowerShell с закодированной командой:

```yaml
title: Suspicious PowerShell Encoded Command
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
level: high
```

`logsource` описывает источник, `detection` — условия, `condition` комбинирует селекторы (`and`, `or`, `not`, `1 of`, `all of`).

## Шаг 4: конвертация Sigma под свой SIEM

Sigma ценна тем, что одно правило превращается в запросы разных систем через `sigma convert`:

```bash
$ sigma convert -t es-qs ps.yml
(CommandLine:*\\-enc*)
$ sigma convert -t splunk ps.yml
```

Готовые правила берут из репозитория **SigmaHQ**, а не пишут с нуля. Для YARA — из `Neo23x0/signature-base`, `elastic/protections-artifacts`, `awesome-yara`.

## Шаг 5: производительность и корреляция

YARA-регулярки дороги. Советы: якорьте строки, ставьте дешёвые проверки первыми, используйте `yarac` для повторных прогонов. Sigma конвертируют один раз и хранят готовые запросы.

Две системы дополняют друг друга:

- **YARA** — «что это за файл/код».
- **Sigma** — «что произошло в логах».

Пример цепочки: YARA ловит beacon в памяти → Sigma-правило находит запуск `rundll32` с этим файлом в логах → коррелируете время и хост. Правила полезно встроить в CI (YARA по артефактам сборки), SIEM (Sigma как детекты) и EDR.

## Что мы теперь знаем

- **YARA** — содержимое (файлы/память); **Sigma** — события логов.
- Правило YARA: `meta` + `strings` + `condition`; условия ставят от дешёвых к дорогим.
- `wide` — строки UTF-16LE, типичные для Windows.
- Sigma конвертируется в запросы SIEM командой `sigma convert -t <backend>`.
- Готовые репозитории (SigmaHQ, signature-base) экономят недели.
- Тестируйте правила на ложные срабатывания до продакшена.

## На что смотреть дальше: модули и отладка

YARA умеет разбирать форматы через модули, что делает правила точнее:

```yara
import "pe"

rule SuspiciousPE {
    condition:
        pe.is_pe and pe.imports("kernel32.dll", "VirtualAlloc")
}
```

- `pe` — секции, импорты, ресурсы, timestamp.
- `elf` — структуры ELF; `math` — вычисления (энтропия); `hash` — md5/sha1/sha256 содержимого.

Отладка правил: проверьте синтаксис (`yara -d rule.yar`), прогоните на «хорошем» файле (`yara rule.yar /usr/bin/ls` — срабатывать не должно). В Sigma модификаторы полей (`contains`, `startswith`, `endswith`, `re`, `base64`, `cidr`) позволяют описывать сложное поведение. Типичные ошибки: слишком широкие строки (`"http"` даст тысячи совпадений), отсутствие `nocase`/`wide`, незаанкоренный regex в начале правила, неверный `logsource`. Правила храните в git, тестируйте на ложные срабатывания и обновляйте из SigmaHQ/signature-base.

## Квиз

Проверь себя.

```quiz
- question: "Чем YARA отличается от Sigma?"
  options:
    - "YARA — для файлов/памяти, Sigma — для логов"
    - "YARA — для логов, Sigma — для файлов"
    - "Это одно и то же"
    - "Sigma работает только в облаке"
  answer: 0
  explanation: "YARA ищет байтовые паттерны; Sigma описывает события логов."
- question: "Что означает модификатор wide в YARA?"
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
- question: "Из каких трёх частей состоит правило YARA?"
  options:
    - "meta, strings, condition"
    - "header, body, footer"
    - "logsource, detection, level"
    - "import, rule, match"
  answer: 0
  explanation: "Правило YARA = meta (описание) + strings (паттерны) + condition (условие)."
```

## Куда дальше

Мы освоили языки детекта. В следующем уроке (`forensics-python-tooling`) соберём собственные пайплайны на Python — когда готовых инструментов не хватает. А пока главное запомни: **YARA описывает содержимое, Sigma — события; одно Sigma-правило конвертируется в запросы любого SIEM**.

## Где пригодится

- **CTF:** поиск флагов и сигнатур в файлах/памяти.
- **Threat Hunting:** массовый поиск известных угроз.
- **Malware Analysis:** классификация образцов.
- **SOC:** детекты в логах через Sigma.
