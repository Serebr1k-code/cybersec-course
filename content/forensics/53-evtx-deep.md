---
id: forensics-evtx-deep
title: "EVTX глубоко: ключевые Event ID и Sysmon"
category: forensics
parent: forensics-win-logs
difficulty: hard
order: 3
tags: [evtx, sysmon, eventid, windows, dfir, sigma, logs]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting / SOC"
estimated_minutes: 50
summary: "Формат EVTX, восстановление повреждённых журналов, ключевые Event ID (logon/process/service/task) и богатый набор событий Sysmon для детекта атак."
---
EVTX — формат журналов событий Windows. Это, пожалуй, richest источник форензических данных: входы, запуск процессов, установка служб, изменения системы, сетевые события. Умение разбирать EVTX, восстанавливать повреждённые журналы и знать ключевые Event ID — базовый навык DFIR. Этот урок — про формат, инструменты и события, а также про Sysmon и правила Sigma.

## Формат EVTX

EVTX — бинарный формат на базе `ElfFile`/`ElfChnk` (chunks по 64 КБ). Каждый журнал состоит из заголовка файла и чанков; событие — это XML с `System` (EventID, TimeCreated, Computer, Provider) и `EventData`/`UserData`. Формат позволяет **восстанавливать повреждённые журналы**: даже если заголовок битый, чанки часто читаемы.

```bash
$ file Security.evtx
Security.evtx: MS Windows Vista Event Log
$ xxd -l 16 Security.evtx
00000000: 456c 6646 696c 6500 ...   ElfFile.
```

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `evtx_dump` (python-evtx) | конвертация в XML/JSON |
| `EvtxECmd` (Zimmerman) | CSV/JSON, карты Event ID |
| `Chainsaw` | быстрый поиск и hunting |
| `Hayabusa` | детект по правилам Sigma |
| `wevtutil` (Windows) | экспорт/запрос |
| `EvtxeCmd`/`FullEventLogView` | просмотр |

```bash
# конвертация в JSON и фильтрация через jq
$ evtx_dump -o json Security.evtx | jq -c 'select(.Event.System.EventID==4625) | .Event.EventData' | head
# CSV с картами
$ EvtxECmd.exe -f Security.evtx --csv out --csvf security.csv
$ EvtxECmd.exe -d C:\Windows\System32\winevt\Logs --csv out --csvf all.csv
# Chainsaw: hunting по правилам
$ chainsaw hunt evtx/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

## Восстановление повреждённых журналов

Если EVTX повреждён (обрезан, битый заголовок), инструменты умеют извлекать уцелевшие чанки.

```bash
$ evtx_dump broken.evtx            # python-evtx попытается прочитать
$ EvtxECmd.exe -f broken.evtx --csv out
# Chainsaw тоже устойчив к повреждениям
$ chainsaw dump broken.evtx
```

Даже частично восстановленный журнал ценен: главное — времена и Event ID.

## Ключевые Event ID

| ID | Лог | Смысл |
|----|-----|-------|
| 4624 | Security | успешный вход (LogonType 2/3/10) |
| 4625 | Security | неудачный вход |
| 4634/4647 | Security | выход |
| 4648 | Security | явные учётные данные (runas) |
| 4672 | Security | особые привилегии (админ) |
| 4688 | Security | создание процесса (+cmdline) |
| 4720/4722/4726 | Security | создание/включение/удаление пользователя |
| 4732 | Security | добавление в привилегированную группу |
| 1102 | Security | очистка журнала |
| 7045 | System | установка службы |
| 104 | System | очистка журнала |
| 6005/6006 | System | старт/стоп Event Log |
| 1/3/11/22 | Sysmon | процесс/сеть/файл/DNS |

```bash
# все 4688 с командной строкой
$ evtx_dump -o json Security.evtx | jq -r 'select(.Event.System.EventID==4688) | [.Event.EventData.NewProcessName, .Event.EventData.CommandLine] | @tsv' | head
# установка служб
$ evtx_dump -o json System.evtx | jq 'select(.Event.System.EventID==7045) | .Event.EventData'
```

## Sysmon

Sysmon добавляет детальный мониторинг: создание процессов (с хешами и родителем), сетевые соединения, загрузку драйверов, доступ к файлам, DNS-запросы. Без Sysmon многие атаки не оставляют событий.

| Sysmon ID | Событие |
|-----------|---------|
| 1 | создание процесса |
| 2 | изменение времени файла (timestomp!) |
| 3 | сетевое соединение |
| 7 | загрузка образа (DLL) |
| 8 | CreateRemoteThread (инъекция) |
| 10 | доступ к процессу (LSASS!) |
| 11 | создание файла |
| 12/13/14 | реестр |
| 22 | DNS-запрос |

```bash
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==1) | [.Event.EventData.Image, .Event.EventData.ParentImage, .Event.EventData.CommandLine] | @tsv' | head
$ evtx_dump -o json Sysmon.evtx | jq 'select(.Event.System.EventID==10 and (.Event.EventData.TargetImage|test("lsass")))'
```

Событие 10 с `TargetImage=lsass.exe` — прямой признак дампа LSASS (mimikatz/`comsvcs.dll`).

## Sigma и детект

**Sigma** — универсальный формат правил детекта, конвертируемый в SIEM-запросы. `Chainsaw`/`Hayabusa` применяют Sigma к EVTX.

```bash
$ chainsaw hunt evtx/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -o results/
$ hayabusa csv-timeline -d evtx/ -o timeline.csv -p standard
```

## Разобранный пример

Дан `Security.evtx` и `Sysmon.evtx`. Нужно найти подозрительную активность.

```bash
# 1. Всплеск неудачных входов (брутфорс)
$ evtx_dump -o json Security.evtx | jq -r 'select(.Event.System.EventID==4625) | .Event.EventData.IpAddress' | sort | uniq -c | sort -rn | head
   120 203.0.113.9
# 2. Затем успешный вход
$ evtx_dump -o json Security.evtx | jq 'select(.Event.System.EventID==4624 and .Event.EventData.LogonType==10)'
# 3. Процесс от подозрительного родителя
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==1 and (.Event.EventData.ParentImage|test("winword"))) | .Event.EventData.CommandLine'
# 4. Доступ к LSASS
$ evtx_dump -o json Sysmon.evtx | jq 'select(.Event.System.EventID==10 and (.Event.EventData.TargetImage|test("lsass")))'
```

Итог: брутфорс с `203.0.113.9` → вход → Word породил `cmd.exe` (макрос) → доступ к LSASS (кража кредов).

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| Дамп в XML/JSON | `evtx_dump` |
| CSV с картами | `EvtxECmd` |
| Hunting/Sigma | `Chainsaw`, `Hayabusa` |
| Экспорт (Windows) | `wevtutil epl` |
| Повреждённый лог | `evtx_dump`, `EvtxECmd`, `Chainsaw` |

## Частые ошибки

- **Смотреть один Event ID** — коррелируйте (4625→4624→4688→Sysmon).
- **Забывать про LogonType** — 3 (сеть), 10 (RDP) различают доступ.
- **Игнорировать Sysmon 10** — прямой след кражи LSASS.
- **Верить, что лог пуст** — мог быть очищен (1102/104); проверьте пробелы.
- **Не нормализовать время** — EVTX в UTC.
- **Не сохранять вывод** — для отчёта и повторного анализа.

## Что дальше / решение

Конвейер: `EvtxECmd`/`evtx_dump` (дамп) → `jq` (фильтры) → ключевые Event ID → `Chainsaw`/Sigma (детект) → сведение с MFT/Sysmon. Связка: `forensics-windows-artifacts` (обзор), `forensics-powershell-logs` (4103/4104), `forensics-plaso` (таймлайн), `forensics-attack-mapping` (ATT&CK).

## PowerShell и другие журналы

PowerShell пишет в `Microsoft-Windows-PowerShell/Operational`: **4104** — содержимое скрипт-блока (если включён Script Block Logging), **4103** — запуск команды (Module Logging). Это ключ к fileless-атакам.

```bash
$ evtx_dump -o json 'PowerShell%4Operational.evtx' | jq -r 'select(.Event.System.EventID==4104) | .Event.EventData.ScriptBlockText' | head
$ grep -iE 'Invoke-Expression|FromBase64String|DownloadString' ps_blocks.txt | head
```

Другие важные логи: `Microsoft-Windows-TaskScheduler` (закрепление через задачи), `Microsoft-Windows-WMI-Activity` (5857/5860/5861), `TerminalServices-RemoteConnectionManager` (RDP), `Microsoft-Windows-Bits-Client` (загрузки), `Defender` (обнаружения).

## Экспорт, целостность и объёмы

EVTX можно экспортировать и верифицировать:

```bash
# экспорт журнала (Windows)
$ wevtutil epl Security C:\evidence\Security.evtx
# размер и число событий
$ evtx_dump -o json Security.evtx | wc -l
# только времена и ID (быстрая сводка)
$ evtx_dump -o json Security.evtx | jq -r '[.Event.System.TimeCreated."#attributes".SystemTime, .Event.System.EventID] | @tsv' | head
```

На больших журналах (гигабайты) `jq`-поток предпочтительнее загрузки в память. Сохраняйте хеш оригинального `.evtx` до анализа — целостность улики.

## Уровни журналов и включение аудита

Многие события (4688 с командной строкой, 4104) пишутся **только если включён аудит**. Если событий нет — возможно, аудит выключен, а не атаки не было. Проверяйте `auditpol /get /category:*` и настройки `Microsoft-Windows-PowerShell` — отсутствие событий 4104 часто объясняется выключенным логированием, а не «чистотой».

## Квиз

```quiz
- question: "Что означает Event ID 1102 в Security.evtx?"
  options:
    - "успешный вход"
    - "журнал был очищен"
    - "создание процесса"
    - "установка службы"
  answer: 1
- question: "Какой LogonType соответствует RDP-входу?"
  options:
    - "2"
    - "3"
    - "10"
    - "5"
  answer: 2
- question: "Какое событие Sysmon указывает на доступ к lsass.exe (дамп учёток)?"
  options:
    - "EventID 1"
    - "EventID 3"
    - "EventID 10 (ProcessAccess)"
    - "EventID 22"
  answer: 2
- question: "Какое событие Sysmon фиксирует изменение времени файла?"
  options:
    - "EventID 2"
    - "EventID 11"
    - "EventID 15"
    - "EventID 23"
  answer: 0
- question: "Почему нельзя ограничиться Security.evtx при разборе вторжения?"
  options:
    - "он всегда пуст"
    - "Sysmon/System/Application/Defender содержат критичные данные о процессах, сети и защите"
    - "в нём нет времени"
    - "он зашифрован"
  answer: 1
```

## Где пригодится

- **CTF:** задачи на восстановление цепочки атаки по журналам.
- **DFIR:** реконструкция входа, запуска процессов, персистентности.
- **SOC / Threat Hunting:** разработка и проверка детектов (Sigma).
- **Судебная экспертиза:** доказательство факта и времени действий.
- **Анализ anti-forensics:** выявление очистки журналов (1102/104).
