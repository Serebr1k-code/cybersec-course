---
id: reversing-yara-sigma
title: "YARA и Sigma: правила обнаружения"
category: reversing
parent: reversing-malware-static
difficulty: medium
order: 1
tags: [reversing, yara, sigma, detection, rules, soc, dfir]
prerequisites: [reversing-malware-static]
useful_for:
  - "CTF Forensics"
  - "SOC / detection engineering"
  - "Threat intelligence"
estimated_minutes: 55
summary: "Написание YARA-правил для файлов и Sigma-правил для логов: синтаксис, тестирование, false positives."
---
**YARA** ищет паттерны в **файлах** (сигнатуры malware, дампы памяти), **Sigma** описывает детекты для **логов** (SIEM, EDR). Владение обоими — ключевой навык detection engineering и DFIR: аналитик превращает IOC и поведение в правила, которые ловят угрозу на других системах. YARA-правило — это набор строк (текст, hex, регулярки) и условие; Sigma — это YAML-описание события с полями лога. В этом уроке — синтаксис, тестирование, конвертация и борьба с ложными срабатываниями, с полными примерами.

## YARA и Sigma: назначение и место в пайплайне

YARA работает на уровне файлов и памяти: сканирует байты и строки, поддерживает модули (`pe`, `elf`, `math`, `hash`), условия по размеру, энтропии, импортам. Sigma работает на уровне событий: описывает, какие поля логов (Sysmon, Windows Event Log, Linux audit) и с какими значениями указывают на атаку, а затем конвертируется в запросы SIEM (Splunk, Elastic, QRadar). Вместе они покрывают и хосты, и логи. Обычно YARA-правила рождаются из статики/памяти, а Sigma — из динамики/телеметрии.

## Синтаксис YARA

Правило состоит из `meta`, `strings`, `condition`:

```yara
rule Example_Malware
{
    meta:
        author = "analyst"
        description = "detects sample X"
        reference = "https://example.com/report"
        date = "2026-01-01"
    strings:
        $s1 = "cmd.exe /c" ascii wide nocase
        $s2 = { 4D 5A 90 00 ?? ?? 00 00 }        // hex-паттерн с wildcard
        $re1 = /https?:\/\/[a-z0-9.]+\.onion/    // регулярка
        $xor = { 6A ?? 68 ?? ?? ?? ?? E8 }        // push/ call
    condition:
        uint16(0) == 0x5A4D and ($s1 or $s2) and filesize < 5MB
}
```

Модификаторы строк: `ascii`, `wide` (UTF-16), `nocase`, `fullword`, `xor`, `base64`. Wildcards в hex: `??` (любой байт), `?A` (полубайт), `[4-6]` (диапазон), `(11|22)` (альтернатива). Условия: `all of them`, `any of ($s*)`, `2 of ($s*)`, `for any i in (1..#s1): (@s1[i] < 100)`.

## Условия, модули и продвинутые конструкции

Модули расширяют возможности. `pe` — импорты, секции, энтропия, checksum; `math` — вычисления; `hash` — хеши; `elf` — для Linux. Пример с модулем pe:

```yara
import "pe"
import "math"

rule Suspicious_Packer
{
    condition:
        pe.is_pe and
        math.entropy(0, filesize) > 7.2 and
        pe.number_of_sections < 4
}
```

Правила можно объединять (`include "common.yar"`) и задавать приватные (`private rule`) — вспомогательные, не выводящие срабатывание. `global rule` действует на все правила файла. Для дампов памяти добавляют `uint16(0) == 0x5A4D` (PE) или сигнатуры шеллкода.

## Компиляция и тестирование YARA

Компиляция выявляет ошибки, `yarac` создаёт скомпилированный набор:

```bash
yara rules.yar sample.bin
yara -r rules.yar samples/          # рекурсивно
yara -s rules.yar sample.bin        # показать сработавшие строки
yarac rules.yar rules.yarc          # скомпилировать
yara -C rules.yarc sample.bin
```

Проверка на ложные срабатывания — обязательна: сканируют правило на **чистом** наборе (системные файлы, популярные приложения) и смотрят, не срабатывает ли. Инструмент `yara-validator`/`yaraQA` проверяет качество. Для производительности избегают слишком общих строк (`MZ`, `This program`) и условий вида `filesize > 0`.

## Sigma: правила для логов

Sigma-правило — YAML с заголовком (title, id, status, level), `logsource` (product/category/service) и `detection` (selections + condition):

```yaml
title: Suspicious PowerShell Encoded Command
id: 1234abcd-5678-efgh
status: experimental
level: high
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - 'FromBase64String'
            - 'Invoke-Expression'
    condition: selection
falsepositives:
    - Admin scripts
tags:
    - attack.execution
    - attack.t1059.001
```

Модификаторы полей: `|contains`, `|startswith`, `|endswith`, `|re`, `|all`, `|base64`. Несколько selections объединяются (`and`/`or`/`not`), `condition: selection and not filter`.

## Конвертация Sigma и пайплайн

Sigma-правила конвертируются в запросы SIEM инструментом `sigma` (ранее `sigmac`):

```bash
sigma convert -t splunk rules/susp.yml
sigma convert -t elasticsearch -p ecs_windows rules/susp.yml
sigma convert -t qradar rules/susp.yml
```

Так одно правило работает в разных SIEM. Правила хранят в git, версионируют, тестируют (`sigma check rules/`). Для YARA — интеграция в `yara-сканеры` (ClamAV, VirusTotal, Elastic Endpoint), для Sigma — в SIEM. Оба используют MITRE ATT&CK-теги для сопоставления с техниками.

## Ложные срабатывания и качество правил

Главная проблема — false positives (FP). Приёмы снижения:

- комбинировать несколько условий (`and`), а не одну общую строку;
- исключать легитимные пути/процессы (`filter` в Sigma, `not` в YARA);
- проверять на чистых наборах;
- использовать контекст (родительский процесс, подпись, хеш);
- избегать строк, встречающихся в стандартных библиотеках;
- для YARA — ограничивать размер и энтропию, добавлять `pe`-условия.

Оценка: precision/recall на размеченном наборе. Хорошее правило ловит вариант и не срабатывает на нормальном ПО.

## Полный разбор: правило для образца

**Шаг 1 — собрать IOC:** из динамики получили домен, User-Agent, mutex, расшифрованные строки. **Шаг 2 — написать YARA:**

```yara
rule SampleX_Config
{
    strings:
        $ua = "Mozilla/5.0 (Windows NT 10.0; Bot)" ascii
        $mutex = "Global\\SampX_123" ascii wide
        $url = "https://bad.example/gate" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
```

**Шаг 3 — проверить:** `yara -s rules.yar sample.exe` (срабатывает) и на чистом наборе (не срабатывает). **Шаг 4 — Sigma для сетевого детекта:** правило на DNS-запрос `bad.example` или на User-Agent. **Шаг 5 — конвертировать** в SIEM-запрос и развернуть.

## Шпаргалка

| Задача | Команда/конструкция |
|---|---|
| Сканировать файл | `yara rules.yar sample` |
| Рекурсивно | `yara -r rules.yar dir/` |
| Показать строки | `yara -s rules.yar sample` |
| Компилировать | `yarac rules.yar rules.yarc` |
| Hex-wildcard | `{ 4D 5A ?? ?? }` |
| Модификаторы | `ascii wide nocase` |
| Конвертация Sigma | `sigma convert -t splunk rule.yml` |
| Проверка Sigma | `sigma check rules/` |

## Что дальше / решение

Маршрут: соберите IOC, напишите YARA-правило с несколькими строками и условием `2 of them`, протестируйте на образце и на чистом наборе, затем напишите Sigma-правило для сетевого/логового детекта и сконвертируйте в SIEM. Избегайте общих строк и всегда проверяйте FP. Дальше изучайте модули YARA (`pe`, `elf`, `dotnet`), retrohunting (поиск угроз по историческим данным) и интеграцию правил в EDR/SIEM пайплайн.

## YARA для памяти и шеллкода

YARA особенно полезна для сканирования **дампов памяти**, где malware живёт расшифрованным. Условия для памяти отличаются от файлов: нет PE-заголовка, зато есть страницы с исполняемым кодом. Правило для шеллкода:

```yara
rule Shellcode_Egg_Hunter
{
    strings:
        $egg = { 90 90 90 90 90 90 90 90 }
        $api = { 6A ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D0 }
    condition:
        #egg > 4 and $api
}
```

Для сканирования дампов: `yara -r mem_rules.yar dumps/`. Часто комбинируют с `malfind`-дампом Volatility (только RWX-страницы) — это снижает FP. Для PE-в-памяти проверяют `uint16(0) == 0x5A4D` и наличие `pe.is_pe` (модуль pe умеет парсить и in-memory-заголовки). Строки ищут и в wide-кодировке (`wide`), так как Windows API используют UTF-16.

## Sigma: продвинутые поля и корреляция

Sigma поддерживает `|all` (все значения должны встретиться), `|base64offset`, `|cased`, временные корреляции (`near` в новых версиях) и `filter` для исключений:

```yaml
detection:
    selection:
        EventID: 1
        Image|endswith: '\powershell.exe'
    suspicious:
        CommandLine|contains|all:
            - 'DownloadString'
            - 'IEX'
    filter:
        ParentImage|endswith: '\svchost.exe'
    condition: selection and suspicious and not filter
```

Поля ECS (Elastic Common Schema) обеспечивают переносимость между SIEM. `level` (informational/low/medium/high/critical) задаёт приоритет алерта. `tags` связывают с MITRE ATT&CK (`attack.t1059.001`). Корреляционные правила (Sigma Correlation) описывают цепочки событий (например, «несколько неудачных логинов, затем успех»).

## Тестирование правил и анализ ложных срабатываний

Качество правил проверяют на наборах: для YARA — `yarac` (компиляция) + прогон на чистых файлах; для Sigma — `sigma check` (валидация схемы) + прогон на реальных логах. Метрики: **precision** (доля верных срабатываний) и **recall** (доля пойманных образцов). Приёмы борьбы с FP: требовать несколько условий, исключать легитимные пути, проверять на системных файлах, ограничивать контекст (процесс-родитель, подпись). Хорошая практика — вести каталог FP и регулярно прогонять правила по нему. Для YARA полезна `-w` (отключить warnings) и разбиение правил по уровням (`private` для вспомогательных).

## Пайплайн и автоматизация

Полный пайплайн: статика/динамика → IOC → правила (YARA для файлов/памяти, Sigma для логов) → конвертация (Sigma → SIEM) → развёртывание → мониторинг FP → обновление. Автоматизация: git-репозиторий правил, CI с `sigma check` и `yarac`, регулярное сканирование (retrohunting) исторических данных. Интеграции: YARA в EDR (Elastic, CrowdStrike), Sigma в Splunk/Elastic/QRadar. Для threat hunting правила комбинируют с IOC-фидами и MITRE-техниками. Так detection engineering замыкает цикл: обнаружение → анализ → новое правило.

## Retrohunting и масштабирование детекта

Retrohunting — применение новых правил к **историческим** данным (архивам логов, дампам, старым образцам), чтобы найти угрозу, которая уже была, но не детектировалась. Практика: пишете правило → прогоняете по архиву логов (Sigma → SIEM-запрос за прошлый период) и по коллекции образцов (`yara -r rules.yar malware_corpus/`). Это позволяет обнаружить компрометацию задним числом и оценить охват правила. Для масштаба используют `yara -r` с многопоточностью (`-p N`), компиляцию в `.yarc` и распределённый запуск. Retrohunting замыкает цикл detection engineering: правило не только ловит будущее, но и переоценивает прошлое.

## Типичные ошибки при написании правил

Частые грабли: слишком общая строка (`MZ`, `http://`) → масса FP; условие `any of them` при слабых строках; отсутствие `fullword` (строка `cat` ловит `concatenate`); hex-паттерн без wildcard на изменяемых байтах; игнорирование wide-строк в Windows; правило без `meta`/`reference` (невозможно сопровождать); проверка только на одном образце без чистого набора. Для Sigma — неверный `logsource` (правило не срабатывает), неправильные имена полей, отсутствие `filter`. Хорошая практика: минимальный, но достаточный набор условий; документирование FP; версионирование; регулярная переоценка на новых данных.

## Квиз

```quiz
- question: "Для чего YARA?"
  options:
    - "Поиск паттернов в файлах (сигнатуры malware)"
    - "Анализ логов"
    - "Отладка"
    - "Шифрование"
  answer: 0
  explanation: "YARA сопоставляет строки/hex/regex в файлах."
- question: "Для чего Sigma?"
  options:
    - "Описание детектов для логов/SIEM"
    - "Поиск в файлах"
    - "Реверс бинарей"
    - "Сканирование портов"
  answer: 0
  explanation: "Sigma — формат правил для логов, конвертируется в SIEM-запросы."
- question: "Как задать hex-паттерн в YARA?"
  options:
    - "{ 4D 5A 90 00 }"
    - '"4D5A"'
    - "/4D5A/"
    - "0x4D5A"
  answer: 0
  explanation: "Hex-строки задаются в фигурных скобках."
- question: "Как уменьшить ложные срабатывания YARA?"
  options:
    - "Использовать уникальные строки и несколько условий"
    - "Убрать condition"
    - "Использовать только MZ"
    - "Не тестировать"
  answer: 0
  explanation: "Уникальные признаки и комбинации условий снижают FP."
- question: "Во что конвертируют Sigma-правило?"
  options:
    - "В запрос SIEM (Splunk/Elastic)"
    - "В YARA"
    - "В ELF"
    - "В SQL"
  answer: 0
  explanation: "sigma convert превращает правило в запрос конкретного SIEM."
```

## Где пригодится

- **CTF:** Forensics — поиск артефактов.
- **SOC/detection engineering:** правила.
- **Threat intelligence:** сигнатуры.
- **Работа:** DFIR, malware detection.
