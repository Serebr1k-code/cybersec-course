---
id: forensics-defender-logs
title: "Логи Windows Defender: детекты, карантин и MPLog"
category: forensics
parent: forensics-evtx-deep
difficulty: hard
order: 1
tags: [windows, defender, antivirus, mplog, evtx, quarantine, detection-history, dfir]
prerequisites: [forensics-evtx-deep, forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting / SOC"
estimated_minutes: 65
summary: "Как читать следы антивируса Windows Defender: канал Operational (Event ID 1116/1117/5001/5007), текстовые MPLog-журналы, история детектов в реестре и карантин — чтобы восстановить, что защита видела и что с этим сделала."
---

## Вопрос, с которого всё начинается

Ты разбираешь инцидент на Windows-хосте. Защита (Defender) что-то нашла и, возможно,
удалила — а сам файл уже недоступен. Как восстановить, **что именно** сработало, **когда**
и **что с файлом сделали**?

Антивирус — это свидетель, который записывает свои наблюдения. Если научиться читать его
логи, можно восстановить атаку даже когда улики удалены. Опираемся на урок про EVTX: мы уже
умеем читать журналы событий, теперь посмотрим на конкретный и очень ценный канал.

## Наш пример

У нас есть выгрузка с хоста `FIN-WS-07`. Разбираем каталог Defender:

```
$ ls -la /home/student/task
-rw-r--r-- 1 student student  4096 MPLog-20240115.log
-rw-r--r-- 1 student student  1180 DefenderOperational.json
-rw-r--r-- 1 student student   412 task.md
```

Два файла — это два разных источника. `DefenderOperational.json` — выгрузка событий из
канала журнала (как их отдаёт `Get-WinEvent`), а `MPLog-20240115.log` — текстовый журнал
самого движка. Разберём оба.

## Шаг 1: канал Operational — события в EVTX

Defender пишет в журнал `Microsoft-Windows-Windows Defender/Operational`. Его события —
это готовые структурированные записи. Посмотрим на выгрузку:

```
$ cat DefenderOperational.json
{"TimeCreated":"2024-01-15T02:11:03Z","Id":1116,"Level":"Warning","Message":"Windows Defender Antivirus has detected malware or other potentially unwanted software. Name: Trojan:Win32/Emotet Path: file:_C:\\Users\\svc\\AppData\\Local\\Temp\\inv.dll"}
{"TimeCreated":"2024-01-15T02:11:07Z","Id":1117,"Level":"Info","Message":"Action: Quarantine. Name: Trojan:Win32/Emotet Path: file:_C:\\Users\\svc\\AppData\\Local\\Temp\\inv.dll"}
{"TimeCreated":"2024-01-15T02:12:40Z","Id":5001,"Level":"Warning","Message":"Real-time protection is disabled."}
```

Читаем построчно. **Event ID 1116** — «обнаружено»: имя угрозы и путь. **1117** — «предпринято
действие» (здесь Quarantine — карантин). **5001** — «защита в реальном времени отключена» —
тревожный сигнал: атакующие часто отключают антивирус перед запуском полезной нагрузки.

Запомни главные ID:

| Event ID | Что означает |
|---|---|
| 1006 | Обнаружение (устаревший формат) |
| 1116 | Обнаружена угроза (срабатывание сигнатуры) |
| 1117 | Действие по угрозе (clean/quarantine/allow) |
| 1118 / 1119 | Проблема при устранении угрозы |
| 5001 | Отключена защита в реальном времени |
| 5007 | Изменена конфигурация Defender |
| 5010 / 5012 | Ошибка сканирования |
| 1150 / 1151 | Изменение состояния защиты |
| 1121 / 1122 | Срабатывание ASR-правила (attack surface reduction) |

## Шаг 2: MPLog — текстовый журнал движка

EVTX-канал даёт события, но не всю внутреннюю кухню. Рядом лежит **MPLog** —
`MPLog-YYYYMMDD.log` в `C:\ProgramData\Microsoft\Windows Defender\Support\`. Это
plain-text журнал движка: сканирования, загрузка сигнатур, решения. Смотрим:

```
$ head -6 MPLog-20240115.log
[02:10:55.101] MpScanStart  ScanType=1 ScanID={7c91...}
[02:11:03.220] MpThreatFound Name=Trojan:Win32/Emotet Path=C:\Users\svc\AppData\Local\Temp\inv.dll Resource=b64:QzpcVXNlcnNcdnNcQXBwRGF0YVxMb2NhbFxUZW1wXGludi5kbGw=
[02:11:07.400] MpThreatAction Name=Trojan:Win32/Emotet Action=Quarantine Status=Success
```

Здесь видно хронологию: старт сканирования, детект и действие. Поле `Resource=b64:` — это
закодированное имя ресурса. Обрати внимание на строку с `b64:` — в реальных логах движок так
иногда кодирует чувствительные строки (пути, имена). Раз код — значит, декодируем:

```
$ grep -o 'b64:[A-Za-z0-9+/=]*' MPLog-20240115.log | cut -d: -f2 | base64 -d
C:\Users\svc\AppData\Local\Temp\inv.dll
```

Теперь понятно: закодированное поле — это полный путь к изолированному файлу. В **задаче**
этим же способом будет закодирован ответ — декодируй все `b64:`-поля и посмотри, что в них.

## Шаг 3: история детектов в реестре

Даже если EVTX и MPLog подчищены, остаётся **история детектов** в реестре:

```
HKLM\SOFTWARE\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory
HKLM\SOFTWARE\Microsoft\Windows Defender\Scans\History\Service\ResourceData
```

Ключи вида `DetectionHistory\<NN>\{GUID}` хранят записи о каждом детекте (имя, путь,
время). А в `Quarantine\Entries` — метаданные карантина: какой файл изолирован, под каким
внутренним именем и в каком `ResourceData` он лежит. Инструмент `MpCmdRun.exe -Restore`
умеет вернуть файл из карантина — это законный способ получить образец.

## Шаг 4: карантин и восстановление файла

Карантин — не «корзина», а отдельное хранилище с шифрованием:

```
$ ls "C:/ProgramData/Microsoft/Windows Defender/Quarantine/Entries"
7C91A2F0  A0B4C1D2
```

Каждая запись — каталог с файлами `ResourceData` (шифрованные байты) и `Entry` (метаданные).
Сопоставив GUID из реестра с каталогом, можно понять, какой именно файл изолирован. Для
экспертизы карантинный образец расшифровывается специальными утилитами (например,
`DefenderTools`), но чаще достаточно метаданных: имя, хеш, путь, время.

## Шаг 5: связываем в цепочку

Соберём картину:

1. `02:10:55` — начато сканирование (MPLog).
2. `02:11:03` — детект `Emotet` в `%TEMP%\inv.dll` (1116 + MPLog).
3. `02:11:07` — файл помещён в карантин (1117).
4. `02:12:40` — защита в реальном времени отключена (5001).

Вывод: на хосте работал `svc`, который вытащил DLL во временный каталог и, видимо, сразу
после этого попытался отключить защиту — классический сценарий dropper'а. Дальше ищем в
Sysmon (Event ID 1, 11) процесс, создавший `inv.dll`.

## Что мы теперь знаем

- Defender ведёт два независимых источника: **EVTX-канал** `Windows Defender/Operational` и
  текстовый **MPLog** в `ProgramData\...\Support`.
- Ключевые ID: **1116** (детект), **1117** (действие), **5001** (отключение защиты),
  **5007** (смена конфига), **1121/1122** (ASR).
- **MPLog** содержит детали движка и может кодировать строки (`b64:`) — декодируй их.
- История детектов дублируется в **реестре** (`Scans\History`), а файлы — в **карантине**.
- Цепочка «скан → детект → действие → отключение защиты» восстанавливает атаку.

## На что смотреть дальше

- Время в EVTX — UTC; на хосте оно может быть в локальной зоне — сверяйся с часовым поясом.
- Event 5001 сам по себе не доказывает злой умысел: защиту мог отключить и админ.
- MPLog перезаписывается по дням — на живом хосте снимай его **до** сбора образа.
- Если сигнатуры старые, детекта может не быть вовсе — ищи поведенческие события (ASR).
- Сопоставляй GUID детекта в EVTX с каталогами карантина, а не по имени файла.

## Шаг 6: ASR-правила и поведенческие события

Современный Defender детектирует не только сигнатуры, но и **поведение** через ASR (Attack Surface Reduction). Правила — это набор GUID, каждое блокирует класс действий: запуск макросов Office, создание дочернего процесса из Office, загрузку исполняемых файлов из почты, обфусцированные скрипты. События срабатывания — **1121** (блок в режиме аудита/блокировки) и **1122** (только аудит). Посмотреть активные правила:

```powershell
Get-MpPreference |
  Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference |
  Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
```

Если сигнатурного детекта нет, а поведение подозрительно, сработает именно ASR — поэтому в IR эти ID ищут наравне с 1116.

## Шаг 7: PowerShell-команды для сбора состояния

На живом хосте состояние защиты снимается одним конвейером:

```powershell
Get-MpComputerStatus |
  Select-Object AMRunningMode, RealTimeProtectionEnabled,
    IsTamperProtected, AntivirusSignatureLastUpdated
Get-MpThreatDetection | Select-Object ThreatID, Resources, InitialDetectionTime
Get-MpThreat | Select-Object ThreatName, SeverityID, IsActive
Get-MpPreference | Select-Object DisableRealtimeMonitoring, ExclusionPath
```

`IsTamperProtected` — критично: если Tamper Protection выключен, атакующий мог менять настройки защиты. `ExclusionPath` показывает добавленные исключения — часто злоумышленник исключает свой каталог из сканирования. `Get-MpThreatDetection` отдаёт те же записи, что и канал Operational, но структурированно, что удобно для автоматического сбора.

## Шаг 8: офлайн-разбор EVTX и MPLog

На образе EVTX-канал читают парсерами. Основные:

```bash
$ evtx_dump.py "Microsoft-Windows-Windows Defender%4Operational.evtx" > defender.xml
$ EvtxECmd.exe -f defender.evtx --csv outdir --csvf defender.csv
$ hayabusa csv-timeline -d . -o timeline.csv
$ chainsaw hunt . -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

`evtx_dump.py` (python-evtx) разворачивает записи в XML, `EvtxECmd` — в CSV, `hayabusa` и `chainsaw` применяют Sigma-правила и строят таймлайн. Для MPLog отдельного парсера нет — это plain text, поэтому его обрабатывают `grep`/`awk` по ключевым словам (`MpThreatFound`, `MpThreatAction`, `MpScanStart`) и декодируют `b64:`-поля.

## Шаг 9: анти-форензика и Tamper Protection

Атакующий, получив права администратора, часто пытается ослепить защиту:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Add-MpPreference -ExclusionPath 'C:\Users\Public'
```

Каждое действие оставляет след: **5001** (отключена защита в реальном времени), **5007** (изменена конфигурация), **5013** (отключён контроль поведения). Политикой реестра `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` защиту можно выключить централизованно. Tamper Protection мешает таким изменениям, но обходится через уязвимости драйвера или доверенный установщик. В MPLog видно и обратное: строки вида `MpServiceStop`/`MpConfigChange` фиксируют, что защиту гасили.

## Шаг 10: связка с другими артефактами

Логи Defender редко дают полную картину сами — их сопоставляют с:

| Артефакт | Что добавляет |
|----------|---------------|
| Sysmon EID 1 | процесс, создавший изолированный файл |
| Sysmon EID 11 | запись файла на диск (путь и время) |
| Amcache | хеш и путь запущенного файла |
| Prefetch | факт и число запусков |
| SRUM | сетевой трафик процесса |
| EVTX 4688 | командная строка создателя файла |

Цепочка «процесс → записал файл → Defender изолировал → защита отключена» восстанавливается за минуты, если держать эти источники рядом.

## Шаг 11: что считается «детектом» в отчёте

Одно срабатывание — это не одно событие, а цепочка: `1116` (нашёл), `1117` (сделал действие), при неудаче `1118`/`1119`, а поведенческий аналог — `1121`/`1122`. В отчёт выносят имя угрозы, путь, хеш (из `Get-MpThreatDetection`), время в UTC и действие. Путь часто указывает на стадию атаки: `Temp`/`Downloads` — доставка, `Startup`/`Tasks` — закрепление.

## Квиз

Проверь себя.

```quiz
- question: "Что означает Event ID 1116 в канале Defender Operational?"
  options:
    - "Обнаружена угроза (детект)"
    - "Действие по угрозе выполнено"
    - "Отключена защита в реальном времени"
    - "Ошибка сканирования"
  answer: 0
  explanation: "1116 — обнаружена угроза; 1117 — действие по ней."
- question: "Где лежит текстовый журнал движка Defender (MPLog)?"
  options:
    - "C:\\ProgramData\\Microsoft\\Windows Defender\\Support"
    - "C:\\Windows\\System32\\drivers"
    - "C:\\Users\\Public\\Logs"
    - "C:\\Windows\\Temp"
  answer: 0
  explanation: "MPLog-YYYYMMDD.log — в каталоге Support."
- question: "Что означает Event ID 5001?"
  options:
    - "Защита в реальном времени отключена"
    - "Обнаружен вирус"
    - "Файл помещён в карантин"
    - "Обновлены сигнатуры"
  answer: 0
  explanation: "5001 фиксирует отключение real-time protection — частый шаг атакующих."
- question: "Где Defender хранит историю детектов, если журналы подчищены?"
  options:
    - "В реестре, HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Scans\\History"
    - "В WMI-репозитории"
    - "В pagefile.sys"
    - "В MFT"
  answer: 0
  explanation: "История детектов дублируется в ветке Scans\\History."
- question: "Что означает префикс b64: в строке MPLog?"
  options:
    - "Строка закодирована в base64 и требует декодирования"
    - "Файл повреждён"
    - "Это хеш"
    - "Это номер события"
  answer: 0
  explanation: "Движок кодирует часть строк; base64 -d вернёт читаемый текст."
```

## Куда дальше

Мы научились читать следы антивируса. Дальше возьмём подозрительный файл и запустим его в
**изолированной песочнице**, чтобы увидеть поведение своими глазами — сеть, файлы, реестр.
А пока главное запомни: **логи Defender — это свидетельство защиты; 1116 + MPLog + реестр
восстанавливают детект даже после удаления файла**.

## Где пригодится

- **CTF Forensics:** задачи с выгрузками Defender/EVTX.
- **DFIR:** восстановление истории срабатываний при разборе инцидента.
- **Threat Hunting:** поиск отключения защиты и ASR-событий.
- **Работа:** SOC-аналитик, антивирусная экспертиза.
