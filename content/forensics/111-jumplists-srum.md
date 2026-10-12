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

## Вопрос, с которого всё начинается

В прошлом уроке мы доказали по Prefetch, ShimCache и AmCache, **что запускалось** на Windows-машине. Но есть другой, не менее важный вопрос: **что делал сам человек** — какие документы открывал, сколько данных передал в сеть, к каким программам обращался. Особенно если Prefetch очистили антифорензикой, а действия пользователя всё равно надо доказать.

## Наш пример: образ с «вытертым» Prefetch

Нам достали образ рабочей станции. Папка `C:\Windows\Prefetch` почти пуста — следов запуска нет. Зато целы каталоги пользователя и системная база `SRUDB.dat`. Разберём их по очереди и восстановим картину.

Начнём с **JumpLists** (списки переходов). Это те списки, что Windows показывает при правом клике на иконку в панели задач — «недавние» и «закреплённые» документы. Хранятся они в двух папках:

- `...\Recent\AutomaticDestinations\*.automaticDestinations-ms`
- `...\Recent\CustomDestinations\*.customDestinations-ms`

Разбирает их инструмент `JLECmd` (Eric Zimmerman):

```bash
$ JLECmd.exe -d ./AutomaticDestinations --csv ./out --csvf jl.csv
Processed 12 files, 240 entries.
$ grep -i secret ./out/jl.csv | head
...\AutomaticDestinations\1b4dd67f29cb1962...,Explorer,...,\Downloads\secret.docx,...
```

Первое, что видим: пользователь открывал файл `secret.docx` из папки `Downloads`. Это уже конкретный факт, а не догадка.

## Шаг 1: какое приложение оставило запись

Имя файла JumpList — это **AppID**: 16 шестнадцатеричных символов, кодирующих приложение. `1b4dd67f29cb1962` — Windows Explorer. Полные таблицы AppID ведут в справочниках; неизвестный AppID — сам по себе сигнал (редкое или стороннее приложение).

Внутри файла `*.automaticDestinations-ms` лежит **OLE Compound File** — контейнер, как в старых `.doc`, внутри которого несколько потоков. Каждый поток — отдельная запись **LNK** (ссылка на файл или задачу) со своим `TargetPath`, временами создания/изменения/доступа цели и серийным номером тома.

```bash
$ JLECmd.exe -f 1b4dd67f29cb1962.automaticDestinations-ms --dumpTo dumped
$ ls dumped/
1.lnk  2.lnk  ...
```

Выгруженные LNK можно разобрать отдельно (`LECmd.exe`). Так связывают «пользователь открывал файл X» с «файл X лежал на съёмном носителе с таким-то серийником» — сильная связка при расследовании утечки.

## Шаг 2: сколько данных ушло в сеть — SRUM

Открытие документа само по себе безобидно. Следующий артефакт отвечает на вопрос «сколько трафика». **SRUM** (System Resource Usage Monitor) — системная база `C:\Windows\System32\sru\SRUDB.dat`. Формат — **ESE** (Extensible Storage Engine), тот же движок, что у баз Exchange/AD, а не текст и не SQLite.

SRUM ведёт учёт **по приложениям**: отправленные и полученные байты, время CPU, энергопотребление — с шагом примерно в час.

```bash
$ SrumECmd.exe -f SRUDB.dat --csv ./out --csvf srum.csv
$ sort -t, -k5 -nr ./out/srum.csv | head -3
ExeName,Timestamp,BytesSent,BytesReceived,...
chrome.exe,2024-03-01 22:30:00,524288000,12000000,...
```

Читаем: `chrome.exe` в 22:30 отправил **~500 МБ** (524288000 байт). Для браузера, обычно передающего килобайты, это аномалия — гипотеза об эксфильтрации. SRUM не хранит содержимое, но счётчиков достаточно, чтобы понять масштаб.

Тонкость: имена приложений подставляются из **soft-таблицы** `SruDbIdMapTable` — без неё вы увидите числовые ID, а не `chrome.exe`. Ключевые таблицы: `{D10CA2FE-...}` (Network Usage), `{973F5D5C-...}` (Network Connections).

## Шаг 3: последний запуск EXE — BAM/DAM

Третий независимый источник — **BAM** (Background Activity Moderator) и **DAM** (Desktop Activity Moderator). Это ветки реестра:

`HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>`

(и аналогично `dam`). Они хранят время последнего запуска исполняемых файлов **по каждому пользователю**, с полным путём.

```bash
$ python3 - <<'PY'
from Registry import Registry
r = Registry.Registry("SYSTEM")
k = r.open("ControlSet001\\Services\\bam\\State\\UserSettings")
for sk in k.subkeys():
    print("SID:", sk.name())
    for v in sk.values():
        print("  ", v.name(), v.value()[:60])
PY
```

Значение — путь к EXE в UTF-16 плюс 8-байтный **FILETIME** (число 100-наносекундных интервалов с 1601 года UTC). BAM/DAM полезны именно тогда, когда Prefetch пуст: они от него не зависят. SID сопоставляется с именем пользователя через `SOFTWARE\...\ProfileList`.

## Шаг 4: сводим три источника в таймлайн

| Артефакт | Отвечает на вопрос | Формат |
|----------|--------------------|--------|
| JumpLists | что открывал пользователь | OLE + LNK |
| SRUM | сколько трафика у приложения | ESE-база |
| BAM/DAM | когда запускался EXE | реестр + FILETIME |

Для нашего образа картина складывается: в 22:15 открыт `secret.docx` (JumpLists), в 22:30 `chrome.exe` отправил 500 МБ (SRUM), запуск подозрительного EXE подтверждает BAM. По отдельности каждый факт — крупица; вместе они дают связную историю. И помните о сроках: JumpLists живут, пока их не очистят; SRUM — 30–60 дней (циклический буфер); BAM/DAM — до ~30 дней.

## Что мы теперь знаем

- **JumpLists** хранят недавние и закреплённые документы/задачи; AppID кодирует приложение.
- Файлы `*.automaticDestinations-ms` — это OLE-контейнеры с embedded LNK-потоками.
- **SRUM** (`SRUDB.dat`, формат ESE) даёт сетевую активность и CPU по приложениям — идеален для поиска утечки.
- **BAM/DAM** в реестре фиксируют последний запуск EXE по пользователю.
- SRUM читается только ESE-парсером, имена процессов — из soft-таблицы.
- Один артефакт не доказательство: подтверждайте вторым источником.

## Квиз

Проверь себя.

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
- question: "Что такое AppID в имени файла JumpList?"
  options:
    - "серийный номер диска"
    - "16 hex-символов, кодирующих приложение"
    - "пароль пользователя"
    - "номер раздела"
  answer: 1
  explanation: "AppID сопоставляется с приложением по справочной таблице."
```

## Куда дальше

Мы научились восстанавливать активность пользователя по JumpLists, SRUM и BAM/DAM. В следующем уроке (`forensics-ads`) разберём, как злоумышленники прячут данные в **Alternate Data Streams** NTFS — и как их найти. А пока главное запомни: **JumpLists показывают документы, SRUM — трафик, BAM/DAM — запуски; вместе они дают таймлайн активности**.

## Где пригодится

- **CTF:** задачи об активности пользователя и эксфильтрации.
- **IR:** доказательство передачи данных и открытия документов.
- **Threat Hunting:** поиск аномального сетевого поведения приложений.
- **Судебная экспертиза:** независимое подтверждение запусков.
