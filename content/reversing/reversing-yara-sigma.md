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
## Вопрос, с которого всё начинается

Ты разобрал образец malware и вытащил из него уникальные признаки: mutex, User-Agent, домен C2.
Хочется не разбирать каждый следующий образец руками, а написать **правило**, которое поймает
все похожие. Как превратить найденные признаки в детект, который работает на тысячах файлов и
в логах SIEM?

Для этого есть два инструмента. **YARA** ищет паттерны в **файлах** (сигнатуры malware, дампы
памяти). **Sigma** описывает детекты для **логов** (SIEM, EDR). Вместе они покрывают и хосты,
и телеметрию — это базовый навык detection engineering и DFIR.

Опираемся на прошлые уроки: ты умеешь смотреть на бинарник (`strings`, `xxd`) и находить в нём
строки-признаки. Теперь мы оформим эти признаки в правило.

## Наш пример

Пусть после статического анализа у нас есть файл-образец `sample.bin`. Посмотрим на его начало:

```
$ xxd sample.bin | head -3
00000000: 4d5a 9000 0000 0000 0000 0000 476c 6f62  MZ..........Glob
00000010: 616c 5c53 616d 7058 5f31 3233 004d 6f7a  al\SampX_123.Moz
00000020: 696c 6c61 2f35 2e30 2028 5769 6e64 6f77  illa/5.0 (Window
```

Первые байты `4d5a` — это `MZ`, сигнатура **PE-файла** (формат исполняемых файлов Windows). А
строки, которые нас интересуют, видны целиком:

```
$ strings -a sample.bin
Global\SampX_123
Mozilla/5.0 (Windows NT 10.0; Bot)
https://bad.example/gate
```

Вот три уникальных признака: **mutex** (`Global\SampX_123`), **User-Agent**
(`Mozilla/5.0 (Windows NT 10.0; Bot)`) и **домен C2** (`https://bad.example/gate`). В файле есть
и wide-версия mutex (UTF-16), что важно для Windows:

```
$ strings -a -e l sample.bin | head
Global\SampX_123
```

## Шаг 1: пишем YARA-правило

YARA-правило состоит из трёх блоков: `meta` (описание), `strings` (что искать) и `condition`
(когда считать файл совпавшим):

```yara
rule SampleX_Config
{
    meta:
        author = "analyst"
        description = "detects SampleX family config"
        reference = "https://example.com/report"
        date = "2026-01-01"
    strings:
        $ua    = "Mozilla/5.0 (Windows NT 10.0; Bot)" ascii
        $mutex = "Global\\SampX_123" ascii wide
        $url   = "https://bad.example/gate" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
```

Разберём: `uint16(0) == 0x5A4D` читает первые два байта как little-endian-число и требует, чтобы
это был `MZ` — то есть правило сработает только на PE-файлах. `2 of them` означает «совпали
минимум две из трёх строк». Модификатор `wide` заставляет искать строку и в UTF-16, `ascii` — в
обычном виде; `nocase` добавил бы нечувствительность к регистру.

## Шаг 2: проверяем правило

В этом окружении `yara` не установлен, поэтому проверим **логику условия** тем же скриптом, а
на боевой машине то же самое делает `yara rules.yar sample.bin`:

```
$ python3 - <<'PY'
data = open('sample.bin','rb').read()
mz = int.from_bytes(data[:2],'little') == 0x5A4D
markers = [b'Global\\SampX_123', b'Mozilla/5.0 (Windows NT 10.0; Bot)',
           b'https://bad.example/gate']
hits = [m.decode() for m in markers if m in data]
print("uint16(0)==0x5A4D :", mz)
print("strings matched    :", len(hits), "of 3 ->", hits)
print("RULE SampleX_Config:", "MATCH" if (mz and len(hits) >= 2) else "no match")
PY
uint16(0)==0x5A4D : True
strings matched    : 3 of 3 -> ['Global\\SampX_123', 'Mozilla/5.0 (Windows NT 10.0; Bot)', 'https://bad.example/gate']
RULE SampleX_Config: MATCH
```

Условие выполнилось: и PE-заголовок на месте, и совпали все три строки. На боевой машине
полезно прогнать правило с флагом `-s`, чтобы увидеть, **какие именно** строки сработали:

```
yara -s rules.yar sample.bin      # показать совпавшие строки
yara -r rules.yar samples/        # рекурсивно по каталогу
yarac rules.yar rules.yarc        # скомпилировать правила
yara -C rules.yarc sample.bin     # запустить скомпилированные
```

**Компиляция обязательна** перед боем: `yarac` выявит синтаксические ошибки, а прогон на
**чистом** наборе (системные файлы) покажет ложные срабатывания.

## Шаг 3: модификаторы, модули и память

YARA-строки бывают трёх видов: текст (`"..."`), hex (`{ 4D 5A ?? ?? }`) и регулярки
(`/https?:\/\/[a-z0-9.]+\.onion/`). В hex `??` — любой байт, `[4-6]` — диапазон, `(11|22)` —
альтернатива. Модули расширяют условия:

```yara
import "pe"
import "math"
rule Suspicious_Packer {
    condition:
        pe.is_pe and
        math.entropy(0, filesize) > 7.2 and
        pe.number_of_sections < 4
}
```

Такое правило ловит упакованные образцы по высокой **энтропии** (мера «случайности» байтов —
сжатый/зашифрованный код выглядит почти случайным). Для **дампов памяти**, где malware
расшифрован и PE-заголовка может не быть, условие строят иначе — по сигнатурам шеллкода:

```yara
rule Shellcode_Egg_Hunter {
    strings:
        $egg = { 90 90 90 90 90 90 90 90 }   // NOP-«яйцо»
        $api = { 6A ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D0 }
    condition:
        #egg > 4 and $api
}
```

Здесь `#egg` — число вхождений строки. Сканируют дампы так: `yara -r mem_rules.yar dumps/`.

## Шаг 4: Sigma — детект по логам

Sigma описывает не файлы, а **события** в логах. Правило — это YAML с `logsource` (какой лог) и
`detection` (какие поля и значения):

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

Модификаторы полей: `|contains`, `|startswith`, `|endswith`, `|re`, `|all`, `|base64`. Блок
`filter` задаёт исключения: `condition: selection and not filter` — классический способ убрать
легитимные события. Тег `attack.t1059.001` связывает правило с техникой MITRE ATT&CK.

Одно правило конвертируется в запрос любого SIEM:

```
sigma convert -t splunk rules/susp.yml
sigma convert -t elasticsearch -p ecs_windows rules/susp.yml
sigma check rules/        # валидация схемы
```

## Что мы теперь знаем

- **YARA** ищет паттерны в файлах и памяти: блоки `meta`/`strings`/`condition`.
- Строки бывают текст, hex (`{ 4D 5A ?? }`) и регулярки; модификаторы — `ascii`, `wide`,
  `nocase`, `fullword`.
- Условия: `uint16(0) == 0x5A4D` (PE), `2 of them`, `#s1 > 4`, модули `pe`/`math`.
- **Sigma** описывает детекты для логов на YAML и конвертируется в запросы SIEM.
- Качество детекта — это борьба с **ложными срабатываниями**: несколько условий, `filter`,
  прогон на чистом наборе.

## На что смотреть дальше

- Слишком общая строка (`MZ`, `http://`) даёт массу ложных срабатываний — комбинируй признаки.
- Не забывай `wide` для Windows-строк (API используют UTF-16).
- Без `fullword` строка `cat` поймает `concatenate` — учитывай границы слов.
- Hex-паттерн без `??` на изменяемых байтах ломается на новой версии образца.
- Правило без `meta`/`reference` невозможно сопровождать — документируй.
- Всегда проверяй правило на **чистом** наборе, а не только на одном образце.

## Квиз

Проверь себя.

```quiz
- question: "Для чего YARA?"
  options:
    - "Поиск паттернов в файлах (сигнатуры malware)"
    - "Анализ логов"
    - "Отладка"
    - "Шифрование"
  answer: 0
  explanation: "YARA сопоставляет строки/hex/regex в файлах и памяти."
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

## Куда дальше

В следующем уроке мы перейдём от статики к **динамике** и посмотрим, как запускать образец в
безопасной песочнице и наблюдать его поведение. А пока главное запомни: **правило — это
формализованный признак**, и YARA/Sigma превращают разовый анализ в масштабируемый детект.

## Где пригодится

- **CTF Forensics:** поиск артефактов по сигнатурам.
- **SOC / detection engineering:** написание и сопровождение правил.
- **Threat intelligence:** сигнатуры для обмена и retrohunting.
- **Работа:** DFIR, malware detection, threat hunting.
