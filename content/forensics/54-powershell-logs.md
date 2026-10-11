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
---

## Почему PowerShell — золотая жила для DFIR

PowerShell — мощный инструмент, который атакующие используют для fileless-атак: загрузка и выполнение кода в памяти, обход защиты, латеральное движение. Если включено логирование, PowerShell оставляет **богатые** артефакты: полные тексты команд (даже обфусцированных — после декодирования), скрипт-блоки, историю модулей. Это один из самых ценных источников при расследовании Windows-инцидентов.

## Уровни логирования PowerShell

| Канал/лог | Event ID | Что содержит |
|---|---|---|
| Windows PowerShell (Operational) | 4104 | **Script Block Logging** — полный текст выполняемых блоков |
| Windows PowerShell | 400/403 | запуск/остановка движка |
| Microsoft-Windows-PowerShell/Operational | 4103 | Module Logging (команды, вызовы) |
| PowerShell/Operational | 4104 | то же, что Script Block |
| Transcription | файл | полная текстовая запись сессии |
| Module Logging | 4103 | команды модулей |

**4104** — самый важный: содержит `ScriptBlockText` (текст команды) и `ScriptBlockId`. Даже если атакующий обфусцировал команду (`-EncodedCommand`), в логе 4104 часто видно **декодированный** текст.

## Включение логирования

```powershell
# Script Block Logging (Group Policy / реестр)
# HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
#   EnableScriptBlockLogging = 1
# Module Logging
# HKLM\...\PowerShell\ModuleLogging -> EnableModuleLogging=1
# Transcription
# HKLM\...\PowerShell\Transcription -> EnableTranscripting=1
```

Артефакты даже при выключенном логировании: **ConsoleHost_history.txt** (`%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`) — история команд в интерактивной сессии.

## Чтение EVTX

```bash
# evtx_dump (python-evtx) или evtx_dump (rust)
evtx_dump.py "Microsoft-Windows-PowerShell%4Operational.evtx" > ps.json
# фильтр по 4104
jq -r 'select(.["Event.System.EventID"]==4104) | .["Event.EventData.ScriptBlockText"]' ps.json
# или через Chainsaw
chainsaw hunt powershell.evtx --sigma sigma/ --mapping mappings/
```

## Деобфускация

Атакующие используют:

- **`-EncodedCommand`** (Base64 UTF-16LE). Декодирование:

```python
import base64
enc = "SQBFAFgA..."       # из лога
print(base64.b64decode(enc).decode("utf-16-le"))
```

- **Конкатенация строк** (`"IE"+"X"`).
- **`-replace`**, `-join`, `[char]` — сборка команд.
- **Сжатие** (Gzip/Deflate) с base64.
- **Invoke-Expression (IEX)**, `DownloadString`.

Инструменты: **PSDecode**, **PowerDecode**, **CyberChef** (рецепты), **revshells.com** (для распознавания payload'ов).

```python
# Gzip+Base64
import base64, gzip, io
data = base64.b64decode(blob)
print(gzip.decompress(data).decode())
```

## LOLBins и подозрительные паттерны

- `powershell -enc <base64>` — обфускация.
- `IEX (New-Object Net.WebClient).DownloadString(...)` — загрузка.
- `Invoke-Mimikatz`, `Invoke-Expression`, `FromBase64String`.
- `Add-MpPreference -ExclusionPath` — обход Defender.
- `Set-MpPreference -DisableRealtimeMonitoring` — отключение защиты.
- `DownloadFile`, `DownloadData`, `Start-BitsTransfer`.
- `net user ... /add`, `net localgroup administrators ... /add`.
- `schtasks`, `Register-ScheduledTask` — persistence.

## Практический пример: анализ 4104

```bash
# Извлекаем все ScriptBlockText, ищем подозрительное
evtx_dump.py PowerShell-Operational.evtx | \
  jq -r 'select(.["Event.System.EventID"]==4104) | .["Event.EventData.ScriptBlockText"]' | \
  grep -iE 'download|iex|frombase64|mimikatz|invoke-'
```

Затем декодируем найденное (base64/gzip) и восстанавливаем намерение.

## Транскрипция и история

```bash
# Транскрипция
dir C:\Users\*\Documents\PowerShell_transcript*.txt
# PSReadline history
type C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

История PSReadline содержит **введённые** команды (даже если логирование было выключено) — ценный артефакт.

## Sysmon и корреляция с PowerShell

**Sysmon** (System Monitor) обогащает картину событиями, которых нет в стандартных логах:

| Sysmon ID | Событие |
|---|---|
| 1 | Process Create (с command line!) |
| 3 | Network Connect |
| 7 | Image Loaded (DLL) |
| 8 | CreateRemoteThread (инъекция) |
| 11 | File Create |
| 12/13/14 | Registry |
| 22 | DNS Query |
| 25 | Process Tampering |

```bash
# Sysmon process create с командной строкой
evtx_dump.py Sysmon.evtx | jq -r 'select(.["Event.System.EventID"]==1) |
  [.["Event.EventData.Image"], .["Event.EventData.CommandLine"]] | @tsv'
```

Корреляция: **Sysmon 1** (запуск `powershell.exe` с подозрительной командной строкой) + **4104** (декодированный скрипт) + **Sysmon 3** (сетевое соединение после) = полная цепочка «запуск → выполнение → C2».

## Деобфускация: примеры

**Base64 UTF-16LE:**

```python
import base64
print(base64.b64decode("SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=").decode("utf-16-le"))
# IEX (New-Object)...
```

**Gzip+Base64:**

```python
import base64, gzip
blob = "H4sIAAAAAAAA..."
print(gzip.decompress(base64.b64decode(blob)).decode())
```

**Конкатенация/подстановка:**

```powershell
# "I" + "EX" -> IEX
# -replace 'x','' , [char]105+[char]101+[char]120
```

Инструменты: **PSDecode** (PowerShell-парсер), **CyberChef** (рецепты `From Base64` → `Decode text UTF-16LE` → `Gunzip`), **PowerDecode**.

## Индикаторы компрометации (IOC)

- `-enc`, `-EncodedCommand`, `-nop`, `-w hidden`, `-ep bypass`.
- `IEX`, `Invoke-Expression`, `DownloadString`, `DownloadFile`.
- `FromBase64String`, `[Convert]`.
- `Mimikatz`, `Invoke-Mimikatz`, `sekurlsa`.
- `Add-MpPreference -ExclusionPath`, `Set-MpPreference -DisableRealtimeMonitoring`.
- `net user /add`, `net localgroup administrators /add`.
- `schtasks /create`, `Register-ScheduledTask`.
- `New-Object Net.WebClient`, `Start-BitsTransfer`.

## Практический сценарий: полная цепочка

```bash
# 1. Sysmon: запуск powershell с -enc
evtx_dump.py Sysmon.evtx | jq -r 'select(.["Event.System.EventID"]==1) |
  select(.["Event.EventData.Image"]|test("powershell")) |
  [.["Event.EventData.CommandLine"], .["Event.EventData.ProcessId"]] | @tsv'
# 2. PowerShell 4104: декодированный скрипт
evtx_dump.py PS-Operational.evtx | jq -r 'select(.["Event.System.EventID"]==4104) |
  .["Event.EventData.ScriptBlockText"]'
# 3. Декодируем base64 UTF-16LE
python3 -c "import base64;print(base64.b64decode('...').decode('utf-16-le'))"
# 4. Sysmon 3: сетевые соединения того же процесса
evtx_dump.py Sysmon.evtx | jq -r 'select(.["Event.System.EventID"]==3) |
  [.["Event.EventData.Image"], .["Event.EventData.DestinationIp"], .["Event.EventData.DestinationPort"]] | @tsv'
```

Так восстанавливается «что запускалось → что выполнялось → куда ушло».

## PowerShell в контексте атак

Атакующие используют PowerShell для:

- **Загрузки и выполнения** кода в памяти (`IEX`, `DownloadString`).
- **Обхода защиты** (`-ep bypass`, `-nop`, `-w hidden`).
- **Persistence** (реестр, задачи, WMI).
- **Латерального движения** (`Invoke-Command`, WinRM).
- **Кражи кредов** (`Invoke-Mimikatz`, `sekurlsa`).
- **Ransomware** (шифрование через .NET).

Даже при выключенном логировании остаются: **PSReadline history**, **транскрипция** (если включена), **Sysmon 1** (командная строка), **Prefetch** (`POWERSHELL.EXE-...`), **Amcache**.

## Включение логирования: GPO и реестр

```powershell
# Реестр (локально)
$base = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
New-Item -Path "$base\ScriptBlockLogging" -Force
Set-ItemProperty -Path "$base\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
New-Item -Path "$base\ModuleLogging" -Force
Set-ItemProperty -Path "$base\ModuleLogging" -Name EnableModuleLogging -Value 1
New-Item -Path "$base\Transcription" -Force
Set-ItemProperty -Path "$base\Transcription" -Name EnableTranscripting -Value 1
```

Через GPO: `Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell`. Также включайте **Sysmon** и **Command Line auditing** (4688 с командной строкой) — они дополняют PowerShell-логи.

## Итог

PowerShell-логи — один из самых ценных источников при расследовании Windows-инцидентов. Даже при обфускации **4104** (Script Block Logging) часто содержит декодированный текст. Всегда проверяйте PSReadline-историю и транскрипцию как fallback, коррелируйте с Sysmon (1/3) и ищите LOLBin-паттерны. Если логирование было выключено — восстановите факт запуска через Prefetch/Amcache.

## Резюме

4104 → декодировать → коррелировать с Sysmon → восстановить цепочку. PSReadline и транскрипция — fallback. Включайте логирование заранее: без него большая часть командного текста теряется.

## Частые ошибки

- **Не включён Script Block Logging.** Тогда 4104 нет; ищите транскрипцию/историю.
- **Смотреть только 4104.** Есть 4103 (module), 400/403 (engine).
- **Забыть декодировать.** `-EncodedCommand` — это base64 UTF-16LE.
- **Не проверить PSReadline.** Часто содержит команды.
- **Игнорировать время.** Коррелируйте с другими артефактами.
- **Не искать LOLBins.** Это ключевые индикаторы.

## Как не застрять

- **4104 — первым делом.**
- **Декодируйте** всё обфусцированное.
- **PSReadline history** как fallback.
- **Транскрипция** — если включена.
- **Ищите LOLBin-паттерны.**
- **Коррелируйте** с EVTX/Sysmon.

## Квиз

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

## Где пригодится

- **CTF Forensics** — задачи с EVTX PowerShell.
- **DFIR/IR** — расследование fileless-атак.
- **SOC/Threat Hunting** — детекты на LOLBins.
- **Malware analysis** — деобфускация payload'ов.
- **Аудит** — проверка включённого логирования.
