---
id: forensics-jumplists-srum
title: "JumpLists, SRUM и BAM/DAM: активность пользователя"
category: forensics
parent: forensics-win-deep
difficulty: hard
order: 3
tags: [windows, jumplists, srum, bam, dam, jlecmd, srumdump, dfir]
prerequisites: [forensics-win-deep]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response (Windows)"
  - "Threat Hunting"
estimated_minutes: 52
summary: "Артефакты пользовательской активности Windows: JumpLists (недавние файлы и задачи), SRUM (сетевая/процессная активность по приложениям), BAM/DAM (доступ к исполняемым файлам) — инструменты JLECmd, SrumECmd, разбор баз ESE."
---

Если Prefetch/ShimCache/AmCache отвечают на вопрос «что запускалось», то JumpLists, SRUM и BAM/DAM показывают **что делал пользователь**: какие документы открывал, сколько тратил сети, к каким EXE обращался. Эти артефакты особенно ценны, когда prefetch очищен, а действия нужно доказать.

## JumpLists

JumpLists — списки недавних и закреплённых элементов, которые Windows показывает при правом клике на иконку в панели задач. Хранятся в:
`C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms`
и `CustomDestinations\*.customDestinations-ms`.

Automatic-файлы — это **OLE-контейнеры с embedded LNK-потоками**: каждый поток — LNK-запись о файле/задаче. Имя файла кодирует AppID (какое приложение). Custom — конкатенация LNK без OLE-обёртки.

```bash
# JLECmd (Eric Zimmerman)
JLECmd.exe -d "C:\Users\bob\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv out --csvf jl.csv
JLECmd.exe -f 1b4dd67f29cb1962.automaticDestinations-ms

# Linux: jlecmd / python
pip install jlecmd 2>/dev/null || true
python3 -m jlecmd /path/to/AutomaticDestinations 2>/dev/null || true
```

Столбцы: `AppId`, `AppIdDescription`, `TargetPath`, `TargetCreated`, `TargetModified`, `TargetAccessed`, `VolumeSerialNumber`, `DriveType`. AppID указывает приложение (напр. `1b4dd67f29cb1962` — Windows Explorer).

## SRUM (System Resource Usage Monitor)

SRUM — база `C:\Windows\System32\sru\SRUDB.dat` (формат **ESE**, extensible storage engine). Она хранит по приложениям: **сетевую активность** (байты sent/received по интерфейсам), время CPU, работу с энергией. Ключевая ценность: SRUM может показать, **какое приложение сколько данных передало** — идеально для поиска эксфильтрации.

SRUM требует **мягких таблиц** (SruDbIdMapTable) для сопоставления ID приложения с именем. Данные хранятся по 60-минутным интервалам.

```bash
# SrumECmd (Eric Zimmerman)
SrumECmd.exe -f SRUDB.dat --csv out --csvf srum.csv
SrumECmd.exe -d "C:\Windows\System32\sru" --csv out

# Извлечь таблицы как ESE (esentutl / libesedb)
esedbexport -t sru_export SRUDB.dat
# таблица {D10CA2FE-...} = Network Usage
```

Типичный вывод: `ExeName`, `Timestamp`, `BytesSent`, `BytesReceived`, `InterfaceLuid`. Аномалия — процесс, который внезапно передал сотни мегабайт.

## BAM/DAM

BAM (Background Activity Moderator) и DAM (Desktop Activity Moderator) — ветки реестра:
`HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` (и `dam`).

Они хранят время последнего запуска исполняемых файлов **по пользователю**, с полным путём. Это ещё один независимый источник «что запускалось», устойчивый к очистке prefetch.

```bash
# Разбор через реестр
regipy-dump SYSTEM --path 'ControlSet001\Services\bam\State\UserSettings' -o bam.json
# или RECmd (Kroll)
RECmd.exe -f SYSTEM --bn BatchExamples\Kroll_Batch.reb --csv out
```

Формат значения: путь в UTF-16 + 8-байтный FILETIME последнего запуска.

## Сводная таблица

| Артефакт | Источник | Что даёт | Инструмент |
|----------|----------|----------|------------|
| JumpLists | Automatic/CustomDestinations | недавние/закреплённые файлы и задачи | JLECmd |
| SRUM | SRUDB.dat (ESE) | сеть и CPU по приложениям | SrumECmd |
| BAM | SYSTEM hive (bam) | последний запуск EXE по пользователю | RECmd/regipy |
| DAM | SYSTEM hive (dam) | активность desktop-приложений | RECmd/regipy |

## Разобранный пример

```bash
$ JLECmd.exe -d ./AutomaticDestinations --csv ./out --csvf jl.csv
Processed 12 files, 240 entries.
$ grep -i secret ./out/jl.csv | head
...\AutomaticDestinations\1b4dd67f29cb1962...,Explorer,...\Downloads\secret.docx,...
$ SrumECmd.exe -f SRUDB.dat --csv ./out --csvf srum.csv
$ sort -t, -k5 -nr ./out/srum.csv | head -3
ExeName,Timestamp,BytesSent,BytesReceived,...
chrome.exe,2024-03-01 22:30:00,524288000,12000000,...
```

Вывод: пользователь открывал `secret.docx`, а chrome передал ~500 МБ — гипотеза об эксфильтрации; проверяем сетевые артефакты и PCAP.

## Краевые случаи и подводные камни

- **SRUM требует ESE.** `SRUDB.dat` нельзя читать как текст; нужен `esedbexport`/`SrumECmd`.
- **SRUM не хранит содержимое.** Только счётчики; но их достаточно, чтобы заподозрить эксфильтрацию.
- **JumpLists бывают повреждены.** При некорректном завершении OLE-потоки могут не читаться; попробуйте `--recover` в JLECmd.
- **AppID неизвестен.** Сопоставляйте с таблицей AppID; неизвестные ID — тоже сигнал.
- **BAM/DAM привязаны к SID.** Нужно сопоставить SID с именем пользователя (`ProfileList`).
- **SRUM сбрасывается.** Данные старше ~30–60 дней могут отсутствовать.
- **Часовые пояса.** JumpLists/SRUM — UTC; BAM — FILETIME (UTC).
- **SRUM можно подделать.** Считайте артефакт вспомогательным, а не единственным доказательством.

## JumpLists: структура файлов

Automatic Destinations — это **OLE Compound File** (как старые `.doc`). Внутри — несколько потоков, каждый обычно содержит одну LNK-запись плюс «destList»-поток с порядком и метаданными.

- Имя файла: `<AppID>.automaticDestinations-ms`.
- AppID — 16 hex-символов; сопоставляется с приложением через таблицу AppID (напр. `1b4dd67f29cb1962` — Explorer, `5f7b5f1e01b83767` — Notepad).
- Внутри — потоки с именами вроде `1`, `2`, … и `DestList`.
- Каждый поток — embedded LNK с полем `TargetPath`, временами, volume serial.

Custom Destinations — конкатенация LNK без OLE-обёртки; читаются как последовательность записей с сигнатурой `4C 00 00 00`.

```bash
# JLECmd рекурсивно
JLECmd.exe -d "C:\...\AutomaticDestinations" --csv out --csvf auto.csv
JLECmd.exe -d "C:\...\CustomDestinations" --csv out --csvf custom.csv
# Извлечь embedded LNK для отдельного анализа
JLECmd.exe -f 1b4dd67f29cb1962.automaticDestinations-ms --dumpTo dumped
```

Поле `DestList` хранит счётчик обращений и время последнего доступа — по нему видно, какие документы открывали чаще всего.

## SRUM: таблицы и интервалы

SRUDB.dat содержит несколько таблиц; для форензика важнейшие:

- `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` — Network Usage (по приложениям и интерфейсам).
- `{973F5D5C-1D90-4944-BE8E-24B94231A174}` — Network Connections.
- `{DD6636C4-8929-4683-974E-22C046A43763}` — Energy Usage.
- `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` — Application Resource Usage.

Данные хранятся по 60-минутным «ведрам»; ключ включает ID приложения, ID пользователя и время. `SruDbIdMapTable` связывает числовые ID с именем процесса/пользователя.

```bash
# Экспорт таблиц
esedbexport -t sru_out SRUDB.dat
ls sru_out/
# Разбор через SrumECmd
SrumECmd.exe -f SRUDB.dat --csv out --csvf srum.csv
```

## BAM/DAM: детали

BAM хранится в `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` (на старых системах — `...\bam\UserSettings`). Каждое значение — имя в UTF-16 (путь к EXE) + 8-байтный FILETIME последнего запуска. DAM аналогичен, но для desktop-приложений.

```bash
# RECmd с batch-файлом Kroll
RECmd.exe -f SYSTEM --bn BatchExamples\Kroll_Batch.reb --csv out --csvf reg.csv
# Вручную через python-registry
python3 - <<'PY'
from Registry import Registry
r = Registry.Registry("SYSTEM")
k = r.open("ControlSet001\\Services\\bam\\State\\UserSettings")
for sk in k.subkeys():
    print("SID:", sk.name())
    for v in sk.values():
        print(" ", v.name(), v.value()[:60])
PY
```

SID сопоставляется с пользователем через `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`.

## Сценарии использования

- **Доказать открытие документа.** JumpLists показывают `TargetPath` и время; этого достаточно, чтобы связать пользователя с файлом.
- **Оценить объём утечки.** SRUM `BytesSent` по приложению — количественная оценка.
- **Установить последний запуск EXE.** BAM/DAM дают время без зависимости от Prefetch.
- **Сопоставить с внешними событиями.** JumpLists + SRUM + EVTX образуют связный таймлайн.

## Типичные ошибки

- **Читать SRUDB.dat как текст.** Только ESE-парсер.
- **Игнорировать DestList.** Без него теряется порядок и счётчик обращений.
- **Путать AppID и имя приложения.** Нужна таблица сопоставления.
- **Не сопоставлять SID с пользователем.** Иначе BAM/DAM «безымянные».
- **Забывать про сброс SRUM.** Данные старше периода могут отсутствовать.
- **Считать один артефакт доказательством.** Всегда подтверждайте вторым источником.

## Разбор LNK внутри JumpLists

Каждый поток automaticDestinations — это полноценный LNK-файл, который можно выгрузить и проанализировать отдельно. Полезные поля LNK:

- `TargetPath` — путь к цели.
- `LocalBasePath`/`CommonPathSuffix` — для локальных файлов.
- `VolumeSerialNumber` и `DriveType` — на каком носителе был файл.
- Creation/Modified/Access times цели.
- `NetName`/`DeviceName` — для сетевых/съёмных путей.

```bash
# Выгрузить embedded LNK
JLECmd.exe -f 1b4dd67f29cb1962.automaticDestinations-ms --dumpTo dumped
ls dumped/
# Разобрать конкретный LNK
LECmd.exe -f dumped\1.lnk --csv out --csvf lnk.csv
```

Так вы связываете «пользователь открывал файл X» с «файл X лежал на съёмном носителе с таким-то serial» — сильная связка при расследовании утечки.

## Сводная таблица артефактов активности

| Артефакт | Путь | Ключевые поля |
|----------|------|---------------|
| JumpLists (auto) | `...\Recent\AutomaticDestinations` | AppID, TargetPath, DestList |
| JumpLists (custom) | `...\Recent\CustomDestinations` | TargetPath |
| SRUM | `System32\sru\SRUDB.dat` | ExeName, BytesSent/Received, Timestamp |
| BAM | `SYSTEM\...\bam\State\UserSettings\<SID>` | путь EXE, FILETIME |
| DAM | `SYSTEM\...\dam\State\UserSettings\<SID>` | путь EXE, FILETIME |

Используйте все источники вместе: JumpLists показывают документы, SRUM — трафик, BAM/DAM — запуски. Только совпадение нескольких артефактов даёт уверенный вывод.

## Почему эти артефакты важны в паре

Ни один из трёх артефактов не даёт полной картины сам по себе. JumpLists знают, **что открывали**, но не знают сетевого контекста. SRUM знает трафик, но не имена файлов. BAM/DAM знают запуски, но не содержание работы. Комбинируя их, аналитик восстанавливает цепочку: пользователь открыл документ (JumpLists), приложение передало данные (SRUM), а вредоносный EXE был запущен (BAM/DAM). Именно корреляция по времени превращает разрозненные записи в доказательство.

## Периоды хранения

Полезно помнить, как долго живут данные:

- **JumpLists** — пока пользователь их не очистит или не превысит лимит элементов (обычно 10 на приложение); переживают удаление файлов.
- **SRUM** — около 30–60 дней (циклический буфер).
- **BAM/DAM** — до 30 дней (историчность ограничена), но фиксирует последний запуск.

Поэтому на «старом» образе JumpLists могут быть самым богатым источником, а SRUM — уже пустым.

## Что дальше / решение

1. Собрать `AutomaticDestinations`, `SRUDB.dat`, `SYSTEM` hive.
2. Прогнать `JLECmd`, `SrumECmd`, `RECmd` (все с `--csv`).
3. Сопоставить по времени: открытые файлы ↔ сетевой трафик ↔ запуски.
4. Аномалии проверить другими артефактами (Prefetch, EVTX, PCAP).

Дальше — `forensics-ads` и `forensics-evtx-deep`.

## Квиз

```quiz
- question: "В каком формате хранится база SRUM (SRUDB.dat)?"
  options:
    - "SQLite"
    - "ESE (Extensible Storage Engine)"
    - "JSON"
    - "CSV"
  answer: 1
  explanation: "SRUDB.dat — база ESE; читается esedbexport/SrumECmd."
- question: "Что показывают JumpLists?"
  options:
    - "сетевой трафик"
    - "недавние и закреплённые файлы/задачи приложения"
    - "хеши программ"
    - "пароли"
  answer: 1
  explanation: "JumpLists — списки недавних/закреплённых элементов панели задач."
- question: "Чем BAM/DAM полезны аналитику?"
  options:
    - "Хранят время последнего запуска EXE по пользователю"
    - "Расшифровывают диск"
    - "Содержат PCAP"
    - "Заменяют Prefetch"
  answer: 0
  explanation: "BAM/DAM в реестре фиксируют последний запуск исполняемых файлов с путями."
- question: "Какая метрика SRUM прямо указывает на возможную эксфильтрацию?"
  options:
    - "BytesSent по приложению"
    - "имя пользователя"
    - "размер диска"
    - "номер SID"
  answer: 0
  explanation: "Аномально большой объём отправленных байт у процесса — сигнал утечки."
```

## Где пригодится

- **CTF:** задачи об активности пользователя и эксфильтрации.
- **IR:** доказательство передачи данных и открытия документов.
- **Threat Hunting:** поиск аномального сетевого поведения приложений.
- **Судебная экспертиза:** независимое подтверждение запусков.
