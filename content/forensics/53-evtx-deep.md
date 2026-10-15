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
lab:
  kind: shell
  title: 'Практика: разбор EVTX (заголовок, чанк, записи)'
  toolset: [core, hex, python3]
  workdir: /home/student/task
  files: [task.md, Security.evtx, parse_evtx.py]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - "Повторение (`forensics-windows-artifacts`): сначала `xxd -l 16 Security.evtx` — сигнатура EVTX `ElfFile\\0`."
    - 'Файл EVTX начинается с `ElfFile\x00`; чанки — с `ElfChnk\x00`.'
    - 'Записи начинаются с магии `0x00002a2a` и имеют поле размера.'
    - 'BinXML хранит строки как UTF-16LE — раскодируй тело записи.'
    - '`python3 parse_evtx.py | grep nto > found.txt`.'
---

## Вопрос, с которого всё начинается

Тебе дали `Security.evtx` и `Sysmon.evtx` — журналы событий Windows. Нужно
восстановить цепочку атаки: как вошли, что запустили, как закрепились.

**EVTX** — это бинарный формат журналов событий Windows, и это, пожалуй, самый
богатый источник форензических данных: входы, запуски процессов, установка служб,
сетевые соединения. В этом уроке мы разберём журналы и восстановим атаку по событиям.

## Шаг 1: формат EVTX

Журнал состоит из заголовка и **чанков** (chunks) по 64 КиБ. Каждое событие — это
XML со двумя частями: `System` (кто, когда, какой Event ID) и `EventData` (детали).
Формат устойчив к повреждениям: даже если заголовок битый, чанки часто читаются.

```bash
$ file Security.evtx
Security.evtx: MS Windows Vista Event Log
$ xxd -l 16 Security.evtx
00000000: 456c 6646 696c 6500 ...   ElfFile.
```

`ElfFile` — сигнатура формата («Event Log File»), не путать с ELF-бинарниками Linux.

## Шаг 2: инструменты разбора

| Инструмент | Назначение |
|-----------|-----------|
| `evtx_dump` (python-evtx) | конвертация в XML/JSON |
| `EvtxECmd` | CSV/JSON с картами Event ID |
| `Chainsaw` | быстрый поиск и hunting |
| `Hayabusa` | детект по правилам Sigma |
| `wevtutil` | экспорт журнала в Windows |

Самый удобный способ — превратить EVTX в JSON и фильтровать `jq`:

```bash
$ evtx_dump -o json Security.evtx | jq -c 'select(.Event.System.EventID==4625) | .Event.EventData' | head
```

## Шаг 3: ключевые Event ID

Event ID — числовой «код события». Основные, которые надо знать:

| ID | Лог | Смысл |
|----|-----|-------|
| 4624 | Security | успешный вход |
| 4625 | Security | **неудачный** вход |
| 4648 | Security | вход с явными учётными данными (runas) |
| 4672 | Security | выданы привилегии администратора |
| 4688 | Security | создание процесса (с командной строкой) |
| 4720 | Security | создание пользователя |
| 4732 | Security | добавление в привилегированную группу |
| 1102 | Security | **журнал очищен** |
| 7045 | System | установка службы |
| 104 | System | очистка журнала |

Особое внимание — 1102 и 104: это следы **очистки журналов**, типичная анти-форензика.

## Шаг 4: читаем брутфорс и вход

Разбираем поток неудачных входов (4625) и группируем по IP-адресу источника:

```bash
$ evtx_dump -o json Security.evtx | jq -r 'select(.Event.System.EventID==4625) | .Event.EventData.IpAddress' | sort | uniq -c | sort -rn | head
   120 203.0.113.9
```

120 неудачных попыток с одного адреса — это **брутфорс** (перебор пароля). Смотрим,
не увенчался ли он успехом (4624):

```bash
$ evtx_dump -o json Security.evtx | jq 'select(.Event.System.EventID==4624 and .Event.EventData.LogonType==10)'
```

`LogonType` различает способы входа: `2` — локально, `3` — по сети, `10` — **RDP**
(удалённый рабочий стол). Если после брутфорса есть 4624 с типом 10 — атакующий вошёл.

## Шаг 5: процессы и родитель

Событие 4688 (или Sysmon Event ID 1) показывает создание процесса. Особенно ценно
поле `ParentImage` — **какой процесс его породил**:

```bash
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==1 and (.Event.EventData.ParentImage|test("winword"))) | .Event.EventData.CommandLine'
```

Если Microsoft Word породил `cmd.exe` — это классика: сработал макрос в документе.
Обычно Word не запускает командную строку, поэтому такая связка — красный флаг.

## Шаг 6: Sysmon — детальный мониторинг

**Sysmon** — системный монитор Microsoft, который пишет события, которых нет в
стандартных журналах. Без него многие атаки не оставляют следов:

| Sysmon ID | Событие |
|-----------|---------|
| 1 | создание процесса |
| 2 | изменение времени файла (timestomp!) |
| 3 | сетевое соединение |
| 7 | загрузка образа (DLL) |
| 8 | CreateRemoteThread (инъекция) |
| 10 | доступ к процессу |
| 11 | создание файла |
| 22 | DNS-запрос |

Особенно важен Event ID 10 (доступ к процессу). Если цель — `lsass.exe`, это прямой
признак кражи учётных данных:

```bash
$ evtx_dump -o json Sysmon.evtx | jq 'select(.Event.System.EventID==10 and (.Event.EventData.TargetImage|test("lsass")))'
```

А Event ID 2 фиксирует изменение времени файла — след timestomp.

## Шаг 7: Sigma и автоматический детект

**Sigma** — универсальный формат правил детекта, который можно применять к EVTX.
Инструменты `Chainsaw` и `Hayabusa` делают это автоматически:

```bash
$ chainsaw hunt evtx/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -o results/
$ hayabusa csv-timeline -d evtx/ -o timeline.csv -p standard
```

Так вы получаете таймлайн и список сработавших правил — быстрее, чем читать тысячи
событий вручную.

## Шаг 8: собираем атаку целиком

Соединим всё в одну цепочку:

1. 120 событий 4625 с `203.0.113.9` — брутфорс;
2. 4624 с `LogonType 10` — успешный вход по RDP;
3. Sysmon 1: `winword.exe` → `cmd.exe` — макрос;
4. Sysmon 10 с `TargetImage=lsass.exe` — кража учётных данных;
5. 1102 — очистка журнала, чтобы замести следы.

Так из разрозненных событий складывается полная картина вторжения.

## Шаг 9: другие журналы и объёмы

EVTX — не только `Security.evtx`. Важные источники рядом:

- `Microsoft-Windows-PowerShell/Operational`: **4104** — содержимое скрипт-блока,
  **4103** — запуск команды;
- `Microsoft-Windows-TaskScheduler` — закрепление через задачи;
- `Microsoft-Windows-WMI-Activity` (5857/5860/5861) — WMI-персистентность;
- `TerminalServices-RemoteConnectionManager` — RDP;
- `Microsoft-Windows-Defender/Operational` — обнаружения.

На больших журналах (гигабайты) фильтруйте потоком (`jq`), не загружая в память.
Сохраните хеш оригинального `.evtx` до анализа — это часть целостности улики. И
помните: многих событий (4688 с командной строкой, 4104) **нет, если аудит выключен** —
отсутствие записей не всегда означает отсутствие атаки.

## Что мы теперь знаем

- EVTX — бинарный формат; каждое событие — XML с `System` и `EventData`.
- Ключевые ID: 4624/4625 (вход), 4688 (процесс), 7045 (служба), 1102 (очистка).
- `LogonType` различает локальный/сетевой/RDP-вход.
- Sysmon добавляет детальный мониторинг (процессы, сеть, LSASS, timestomp).
- Chainsaw/Hayabusa применяют правила Sigma автоматически.

## На что смотреть дальше

- **Смотреть один Event ID** — коррелируйте цепочку (4625→4624→4688→Sysmon).
- **Забывать про `LogonType`** — он отличает RDP от сетевого входа.
- **Игнорировать Sysmon 10** — прямой след кражи LSASS.
- **Верить, что журнал пуст** — он мог быть очищен (1102/104); ищите пробелы.
- **Забывать про уровни аудита** — событий 4688/4104 нет, если аудит выключен.
- **Не нормализовать время** — EVTX пишет в UTC.

## Повреждённые журналы и «дыры»

EVTX устойчив к повреждениям, но иногда заголовок или часть чанков битые. Тогда работают
по чанкам напрямую:

```bash
$ evtx_dump -o json Security.evtx 2>/dev/null | jq -r '.Event.System.EventRecordID' | head
$ python3 -c "import Evtx; print(len(list(Evtx.PyEvtxParser('Security.evtx').records())))"
```

Главный признак anti-forensics — **разрыв в `EventRecordID`**: если записи идут
…,1042,1043,1050,…, значит блок удалён. Дыра плюс событие 1102 — уверенный вывод об
очистке журнала.

## Нормализация времени

Все времена в EVTX — UTC (`System.TimeCreated`). Для сопоставления с другими
источниками приводите всё к одному поясу:

```bash
$ evtx_dump -o json Security.evtx | jq -r '.Event.System.TimeCreated."#attributes".SystemTime'
```

События Sysmon и Security часто разнесены по разным файлам — объединяйте их в один
таймлайн (Hayabusa/Chainsaw делают это автоматически).

## Chainsaw и Hayabusa: быстрый hunting

```bash
$ chainsaw hunt evtx/ --sigma sigma/ -o out/ --full
$ hayabusa json-timeline -d evtx/ -o tl.jsonl -p verbose
```

`chainsaw hunt` применяет Sigma-правила и выделяет подозрительные события; `hayabusa`
строит полный таймлайн с оценкой уровня угрозы. Оба хороши как «первый проход» перед
ручным разбором.

## Если не сработало

- `evtx_dump` падает на повреждённом файле → извлеките чанки вручную (по сигнатуре `ElfChnk`).
- Нет событий 4688 → включён неполный аудит; смотрите Sysmon Event ID 1.
- PowerShell-логи пусты → включите Script Block Logging (4104).
- Время «съезжает» → приведите все источники к UTC перед сведением.

## Персистентность: что искать

Кроме брутфорса, важны следы закрепления:

- **7045** (System) — установка службы; смотрите `ImagePath`.
- TaskScheduler **106/200/201** — создание задачи.
- WMI-Activity **5861** — постоянная подписка WMI.
- **4720/4732** — новый пользователь в привилегированной группе.

```bash
$ evtx_dump -o json System.evtx | jq -r 'select(.Event.System.EventID==7045) | .Event.EventData.ImagePath'
```

Подозрительный `ImagePath` в `%TEMP%` или с `powershell -enc` — почти наверняка backdoor.

## Быстрый jq-фильтр подозрительных процессов

Отфильтруйте процессы по командной строке — так за секунды видно загрузчики и лолбины:

```bash
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==1) | .Event.EventData.CommandLine' | grep -iE 'enc |IEX|downloadstring|frombase64'
```

Совпадение с `-enc`/`IEX`/`FromBase64String` — сильный признак PowerShell-нагрузки.

## Итог

EVTX — это не один журнал, а распределённая по нескольким файлам хроника. Соберите её в
единый таймлайн и читайте цепочкой событий, а не по одному ID: только так из разрозненных
записей складывается картина вторжения.

## Квиз

Проверь себя.

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
    - "Sysmon/System/Application содержат критичные данные о процессах, сети и защите"
    - "в нём нет времени"
    - "он зашифрован"
  answer: 1
```

## Куда дальше

Мы разобрали журналы событий. Дальше посмотрим на **логи PowerShell** — отдельный
источник для бесфайловых атак, где видно содержимое выполнявшихся скриптов. А пока
запомни: **EVTX — это хроника системы; читай её цепочкой, а не по одному событию**.

## Где пригодится

- **CTF:** задачи на восстановление цепочки атаки по журналам.
- **DFIR:** реконструкция входа, запуска процессов, персистентности.
- **SOC / Threat Hunting:** разработка и проверка детектов (Sigma).
- **Судебная экспертиза:** доказательство факта и времени действий.
- **Анализ anti-forensics:** выявление очистки журналов (1102/104).
