#!/usr/bin/env python3
"""Generate forensics gB Section B (Windows artifacts) batch A: hub + 4 lessons.
Activity artifacts: Windows Search (Windows.edb), ActivitiesCache.db,
notification DB (wpndatabase.db), Cortana/search history.
"""
import os, json, textwrap

C = "content/forensics"
L = "content/labs"

def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n")

HUB = '''---
id: forensics-win-activity
title: "Модуль: артефакты пользовательской активности Windows"
category: forensics
parent: forensics-win-deep
difficulty: hard
order: 5
tags: [windows, windows-search, timeline, notifications, cortana, activity, roadmap]
prerequisites: [forensics-win-deep]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 14
summary: "Этап ветки «Артефакты Windows»: индексы и базы, которые ОС ведёт про самого пользователя — Windows Search (Windows.edb), Timeline (ActivitiesCache.db), уведомления и поисковые запросы."
---

Предыдущие модули отвечали на вопрос «что запускалось» и «что лежит в реестре». Но есть
целый слой артефактов, который Windows ведёт **про пользователя как такового**: что он
искал, какие файлы открывал, какие окна переключал и какие уведомления получал. Эти базы
живут в профиле, растут годами и часто сохраняют то, что пользователь давно удалил.

## Что покрывает этот модуль

- **Windows Search (Windows.edb)** — база поискового индексатора: пути и имена файлов,
  которые индексатор «видел», включая уже удалённые.
- **Timeline (ActivitiesCache.db)** — журнал активности: запущенные приложения, открытые
  документы, длительность сессий, связанные аккаунты и устройства.
- **Notification DB (wpndatabase.db)** — история уведомлений: тексты тостов, приложение,
  время, иногда вложения.
- **Cortana / поисковая история** — запросы, набранные в поиске и голосовом ассистенте.

## Рекомендуемый порядок изучения

1. `win-windows-search` — самый «жирный» индекс: пути и имена, часто с удалёнными файлами.
2. `win-activity-timeline` — хронология работы пользователя по приложениям и документам.
3. `win-notification-db` — тексты уведомлений как источник контекста и улик.
4. `win-cortana-search` — намерения пользователя, выраженные поисковыми запросами.

## Что вы будете уметь

- Извлекать и парсить `Windows.edb` без запущенного индексатора.
- Читать `ActivitiesCache.db` и строить таймлайн сессий пользователя.
- Открывать `wpndatabase.db` и связывать уведомления с приложениями.
- Сопоставлять поисковые запросы с последующими действиями пользователя.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| Windows.edb | какие файлы существовали (в т.ч. удалённые) | `strings`, `ESEDatabaseView` |
| ActivitiesCache.db | что и когда делал пользователь | `WxTCmd`, `sqlite3` |
| wpndatabase.db | что сообщала система | `sqlite3`, `DB Browser` |
| Cortana | что искал пользователь | `sqlite3`, `python3` |

## Куда дальше

Открывай урок **«Windows Search: база Windows.edb»** — начнём с самого крупного индекса и
разберём, как из него достать пути, которых уже нет на диске.
'''

LESSONS = {}

LESSONS["win-windows-search"] = dict(
title="Windows Search: база Windows.edb и поиск удалённых файлов",
order=1, diff="hard", mins=55,
tags="[windows, windows-search, edb, ese, indexer, deleted-files, forensics]",
prereq="[forensics-registry-hives, forensics-ntfs-mft]",
summary="Как устроен поисковый индекс Windows (Windows.edb), где он лежит и как извлечь из него пути и имена файлов — включая уже удалённые.",
body=r'''
## Вопрос, с которого всё начинается

Пользователь говорит: «я открывал этот документ, но потом удалил, и файла больше нет».
Тебе нужно доказать сам факт существования файла и его путь. На диске его нет — в MFT
запись могла быть переиспользована. Но у Windows есть **собственный каталог всего, что
она видела**: поисковый индекс. Как из него достать путь к файлу, которого уже нет?

## Наш пример: рабочая станция бухгалтера

У нас есть образ диска. В профиле пользователя лежит файл:

```
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
```

Это **не текстовый файл**, а база данных. Чтобы понять, что в ней, начнём с общего
знакомства:

```
$ file Windows.edb
Windows.edb: Extensible Storage Engine (ESE) Database File (edb)
```

**ESE (Extensible Storage Engine)** — это встроенный в Windows движок баз данных. В нём
же лежат `SRUM`, `AmCache` и почта Outlook. Понимая один ESE-файл, ты понимаешь их все.

## Что такое Windows Search и зачем он хранит пути

Служба **Windows Search** (`SearchIndexer.exe`) строит индекс, чтобы поиск в «Проводнике»
и меню «Пуск» был мгновенным. Чтобы искать по **содержимому и именам**, ей нужно где-то
хранить метаданные каждого проиндексированного объекта: путь, имя, дату, размер, иногда
фрагменты текста.

Ключевая мысль: индексатор **не удаляет запись мгновенно**, когда файл удаляют. Некоторое
время (а иногда и годами, если база не перестраивалась) в `Windows.edb` остаётся строка
с путём и именем исчезнувшего файла. Для аналитика это **золото**: доказательство того,
что файл существовал, даже если MFT его уже забыла.

## Шаг 1: опознать базу и её версию

У ESE-файла есть заголовок с сигнатурой и версией формата. Посмотрим первые байты:

```
$ xxd -l 32 Windows.edb
00000000: efcd ab89 2000 0000 ...  ....
```

Сигнатура `efcdab89` (little-endian `89abcdef`) — это и есть маркер ESE. Дальше идёт
размер страницы и версия. Эти поля важны: парсер должен знать размер страницы (обычно
32768 байт), иначе не прочитает дерево B-tree.

## Шаг 2: быстрый взгляд строками

Прежде чем поднимать парсер, посмотрим «на глаз». ESE хранит имена и пути часто в
UTF-16LE, поэтому обычный `strings` их не увидит — нужен режим `-el` (16-битные
little-endian строки):

```
$ strings -el Windows.edb | grep -i 'finance' | head
\\?\C:\Users\jdoe\Documents\finance_2025.xlsx
\\?\C:\Users\jdoe\Documents\finance_q4.xlsx
```

Первая строка — путь к файлу, которого на диске давно нет. Уже это часто закрывает
задачу. Но `strings` не даёт времени и контекста, поэтому перейдём к разбору структуры.

## Шаг 3: разобрать ESE-базу инструментом

ESE-файл — это дерево таблиц. У `Windows.edb` есть таблицы индексированных объектов.
Правильный путь — парсер, который знает схему. На Windows это **ESEDatabaseView** или
**libesedb**; на Linux — `esedbexport` из пакета libyal:

```
$ esedbexport -t out Windows.edb
$ ls out
out.1/  ...
$ head -3 out.1/SystemIndex_0A.table
```

В выгрузке появляются колонки с путями (`System.ItemPathDisplay`), именами и датами.
Фильтруем нужное:

```
$ grep -a 'finance' out.1/*.table | cut -d$'\t' -f3-
C:\Users\jdoe\Documents\finance_2025.xlsx
C:\Users\jdoe\Documents\finance_q4.xlsx
```

Теперь у нас есть и путь, и (в соседних колонках) дата последнего изменения.

## Что именно ищут в Windows.edb

| Поле | Что даёт | Зачем |
|------|----------|-------|
| `System.ItemPathDisplay` | полный путь | доказать существование/расположение |
| `System.ItemNameDisplay` | имя файла | найти по имени без пути |
| `System.DateModified` | дата изменения | вписать в таймлайн |
| `System.Size` | размер | отличить нужный файл от тёзок |
| `System.FileExtension` | расширение | сузить поиск по типу |

## Если база «залочена» или повреждена

На живой системе `Windows.edb` держит служба `WSearch`. Прямое копирование может дать
битый файл. Правильно — **остановить службу** (`net stop wsearch`) или снять тень тома
(VSS) и копировать из неё. Если база повреждена, `esedbexport` может отказаться читать;
тогда помогает `esentutl /r` (recovery) на Windows или повторный экспорт с игнорированием
битых страниц.

## Частые ошибки и подводные камни

- **Обычный `strings` без `-el`** не покажет пути: они в UTF-16LE. Всегда пробуй `-el`.
- **Индексатор перестроен.** Если пользователь недавно «пересоздал индекс», старые записи
  могли исчезнуть — но в теневой копии предыдущей версии базы они часто ещё есть.
- **Пути с префиксом `\\?\`.** Это нормальный «verbatim»-путь Windows, не ошибка; отбрасывай
  префикс при выводе.
- **Только имена, без содержимого.** `Windows.edb` не хранит файлы, только метаданные и
  иногда фрагменты текста — не жди полного содержимого документа.
- **Размер базы.** `Windows.edb` бывает гигабайтным; `strings` по нему медленный — сначала
  сузь поиск по известному ключевому слову.

## Шпаргалка команд

```
# Тип и сигнатура
file Windows.edb
xxd -l 32 Windows.edb

# Быстрый поиск путей (UTF-16LE)
strings -el Windows.edb | grep -i '<слово>'

# Полный экспорт ESE (libyal)
esedbexport -t out Windows.edb

# Только «живая» копия без службы
net stop wsearch            # Windows
vssadmin create shadow /for=C:   # либо снять тень и копировать из неё
```

## Что мы теперь знаем

- `Windows.edb` — ESE-база поискового индексатора в `ProgramData\Microsoft\Search`.
- Она хранит **пути и имена** проиндексированных файлов, включая уже удалённые.
- Пути в UTF-16LE: `strings -el` видит их, обычный `strings` — нет.
- Полный разбор — `esedbexport`; быстрый — `strings -el | grep`.
- Копировать базу надо со остановленной службой или из теневой копии.

## Квиз

Проверь себя.

```quiz
- question: "Что за формат у файла Windows.edb?"
  options:
    - "База данных ESE (Extensible Storage Engine)"
    - "SQLite-база"
    - "XML-документ"
    - "Сжатый ZIP-архив"
  answer: 0
  explanation: "Windows.edb — это ESE-база, тот же движок, что у SRUM и AmCache."
- question: "Почему обычный strings не показывает пути из Windows.edb?"
  options:
    - "Пути хранятся в UTF-16LE, нужен режим strings -el"
    - "Файл зашифрован"
    - "Пути хранятся в реестре, а не в edb"
    - "strings не поддерживает большие файлы"
  answer: 0
  explanation: "ESE хранит строки в UTF-16 little-endian; -el переключает strings на 16-битные строки."
- question: "Почему Windows.edb ценен даже после удаления файла?"
  options:
    - "Индексатор не удаляет запись мгновенно, путь остаётся в базе"
    - "Он хранит полное содержимое файлов навсегда"
    - "Он автоматически восстанавливает удалённые файлы"
    - "Он дублирует файлы в облако"
  answer: 0
  explanation: "Записи индекса переживают удаление файла, поэтому доказывают его существование."
- question: "Как корректно скопировать Windows.edb с живой системы?"
  options:
    - "Остановить службу WSearch или снять теневую копию тома"
    - "Просто скопировать файл, пока служба работает"
    - "Переименовать файл и открыть в блокноте"
    - "Отправить файл по почте"
  answer: 0
  explanation: "Служба держит базу открытой; копировать надо при остановленной службе или из VSS."
```

## Куда дальше

Мы научились доставать пути из индекса. Дальше возьмём **Timeline (ActivitiesCache.db)** —
там уже не просто файлы, а **сессии**: какое приложение, какой документ, сколько времени.
А пока главное запомни: **индекс хранит прошлое, которое диск уже забыл**.

## Где пригодится

- **CTF Forensics:** задачи про удалённый документ и его путь.
- **DFIR:** доказательство работы с файлами до шифрования/удаления.
- **Threat Hunting:** поиск следов инструментов по именам в индексе.
- **Работа:** восстановление истории файловых операций пользователя.
''')

LESSONS["win-activity-timeline"] = dict(
title="Windows Timeline: ActivitiesCache.db как журнал сессий пользователя",
order=2, diff="hard", mins=50,
tags="[windows, timeline, activitiescache, sqlite, user-activity, forensics]",
prereq="[forensics-win-deep, forensics-windows-artifacts]",
summary="Как разобрать ActivitiesCache.db (Windows Timeline) и построить таймлайн сессий: приложения, документы, длительность, связанные устройства.",
body=r'''
## Вопрос, с которого всё начинается

Нужно понять, **чем занимался пользователь** в конкретный час: какие приложения держал
открытыми, какие документы правил, как долго. Журналы событий дают входы в систему, но не
дают «что делал». Ответ лежит в базе Windows Timeline.

## Наш пример: ActivitiesCache.db

Файл лежит в профиле:

```
C:\Users\jdoe\AppData\Local\ConnectedDevicesPlatform\L.jdoe\ActivitiesCache.db
```

```
$ file ActivitiesCache.db
ActivitiesCache.db: SQLite 3.x database
```

Это обычная **SQLite**-база — то же семейство, что и браузерные истории. Значит, работать
с ней можно `sqlite3`.

## Что такое Windows Timeline

**Timeline (Хронология)** — функция Windows, которая запоминает «активности» пользователя,
чтобы потом можно было вернуться к тому, что делал на этом или другом устройстве. Каждая
**активность (Activity)** — это запись вида «в приложении X открыт объект Y, начало Z,
конец W». Хранилище — `ActivitiesCache.db`.

Важно: Timeline синхронизируется через аккаунт Microsoft, поэтому в базе могут быть
активности **с других устройств** пользователя — иногда это раскрывает связи, о которых на
данной машине ничего нет.

## Шаг 1: посмотреть схему

Не угадывай имена таблиц — посмотри:

```
$ sqlite3 ActivitiesCache.db ".tables"
Activity  ActivityOperation  AppActivity  ...
```

```
$ sqlite3 ActivitiesCache.db ".schema Activity"
CREATE TABLE Activity(Id TEXT, ..., AppId TEXT, ..., StartTime INTEGER, EndTime INTEGER, ...);
```

Ключевые колонки: `AppId` (какое приложение), `StartTime`/`EndTime` (когда), а также поля
JSON в `Activity`/`ActivityOperation` с описанием объекта (путь к документу, URL).

## Шаг 2: вытащить сессии

Выведем недавние активности по времени:

```
$ sqlite3 -header ActivitiesCache.db \
  "SELECT datetime(StartTime,'unixepoch'), datetime(EndTime,'unixepoch'), AppId
   FROM Activity ORDER BY StartTime DESC LIMIT 10;"
StartTime            EndTime              AppId
2025-06-02 09:14:20  2025-06-02 09:41:05  ...\EXCEL.EXE
2025-06-02 09:02:11  2025-06-02 09:13:50  ...\chrome.exe
```

Читается однозначно: пользователь работал в Excel с 09:14 до 09:41, перед этим — в браузере.

## Шаг 3: достать объект активности (какой документ)

Поля активности часто содержат **JSON** с путём. Извлекаем и парсим:

```
$ sqlite3 ActivitiesCache.db "SELECT ContentInfo FROM Activity LIMIT 1;" | python3 -m json.tool
{
  "displayText": "finance_q4.xlsx",
  "contentUri": "file:///C:/Users/jdoe/Documents/finance_q4.xlsx"
}
```

Теперь мы знаем не только «работал в Excel», но и **какой файл** открывал.

## Что даёт Timeline в расследовании

| Вопрос | Как отвечает Timeline |
|--------|-----------------------|
| Что делал пользователь в 10:00 | сессии Activity по времени |
| Какой документ открывал | `contentUri` / `displayText` |
| Сколько длилась сессия | `EndTime - StartTime` |
| На каких устройствах активен | записи с чужих устройств |
| Какие аккаунты привязаны | поля аккаунта в активности |

## Инструмент WxTCmd

Вручную SQLite-запросы громоздки; есть **WxTCmd** (Eric Zimmerman), который сразу выдаёт
CSV-таймлайн:

```
> WxTCmd.exe -f ActivitiesCache.db --csv out
```

На Linux то же самое даёт короткий `sqlite3`-скрипт; суть одна — таблицы `Activity` и
`ActivityOperation`.

## Частые ошибки и подводные камни

- **Путать с журналом событий.** Timeline — не EVTX; это отдельная база в профиле.
- **Игнорировать `ActivityOperation`.** Часть данных (в т. ч. удалённые активности) лежит
  в этой таблице, а не в `Activity`.
- **Часовой пояс.** `StartTime` в Unix-эпохе UTC; для локального времени конвертируй
  аккуратно, иначе сессии «съедут».
- **База на пользователя.** Каталог `ConnectedDevicesPlatform\L.<user>` свой у каждого
  профиля; не пропусти нужный.
- **Синхронизированные чужие устройства.** Не приписывай пользователю активность с другого
  устройства — смотри поле устройства/аккаунта.

## Шпаргалка команд

```
# Схема и таблицы
sqlite3 ActivitiesCache.db ".tables"
sqlite3 ActivitiesCache.db ".schema Activity"

# Сессии по времени
sqlite3 -header ActivitiesCache.db \
  "SELECT datetime(StartTime,'unixepoch'),AppId FROM Activity ORDER BY StartTime;"

# Объект активности (JSON)
sqlite3 ActivitiesCache.db "SELECT ContentInfo FROM Activity;" | python3 -m json.tool

# Полный таймлайн (Windows)
WxTCmd.exe -f ActivitiesCache.db --csv out
```

## Что мы теперь знаем

- Timeline хранится в `ActivitiesCache.db` — обычной SQLite-базе в профиле.
- Таблица `Activity` даёт приложение, время начала/конца и объект (файл/URL).
- `ContentInfo` — JSON, где лежит путь к документу.
- В базе бывают активности **с других устройств** пользователя.
- Инструмент `WxTCmd` собирает CSV-таймлайн; на Linux хватает `sqlite3`.

## Квиз

Проверь себя.

```quiz
- question: "В каком формате хранится Windows Timeline?"
  options:
    - "SQLite-база ActivitiesCache.db"
    - "ESE-база Windows.edb"
    - "Текстовый журнал"
    - "Файл реестра"
  answer: 0
  explanation: "ActivitiesCache.db — обычная SQLite-база в профиле пользователя."
- question: "Что описывает одна запись Activity?"
  options:
    - "Приложение, объект и время сессии"
    - "Только пароль пользователя"
    - "Список сетевых пакетов"
    - "Запись MFT"
  answer: 0
  explanation: "Activity связывает приложение, открытый объект и интервал времени."
- question: "Почему в Timeline могут быть данные с другого устройства?"
  options:
    - "Активности синхронизируются через аккаунт Microsoft"
    - "База копируется антивирусом"
    - "Windows всегда пишет данные всех машин в один файл"
    - "Это ошибка парсера"
  answer: 0
  explanation: "Timeline синхронизируется по аккаунту, поэтому содержит чужие устройства пользователя."
- question: "Где лежит путь к открытому документу в Activity?"
  options:
    - "В JSON-поле ContentInfo (contentUri)"
    - "В имени файла базы"
    - "В таблице AppId"
    - "В конце файла ActivitiesCache.db"
  answer: 0
  explanation: "Поле ContentInfo содержит JSON с displayText и contentUri."
```

## Куда дальше

Timeline даёт сессии, но не тексты сообщений. Дальше возьмём **базу уведомлений
(`wpndatabase.db`)** — там сохраняются сами тексты тостов. А пока главное запомни:
**Timeline — это журнал «что делал», а не только «когда вошёл»**.

## Где пригодится

- **CTF Forensics:** задачи «чем занимался пользователь».
- **DFIR:** восстановление хронологии работы сотрудника.
- **Insider threat:** доказательство доступа к конкретным документам.
- **Работа:** форензика конечных точек, eDiscovery.
''')

LESSONS["win-notification-db"] = dict(
title="Уведомления Windows: база wpndatabase.db и тексты тостов",
order=3, diff="medium", mins=45,
tags="[windows, notifications, wpndatabase, sqlite, toast, forensics]",
prereq="[forensics-win-deep, forensics-windows-artifacts]",
summary="Как открыть wpndatabase.db, связать уведомления с приложениями и извлечь тексты тостов как источник улик и контекста.",
body=r'''
## Вопрос, с которого всё начинается

Мессенджер показывал уведомление с текстом, но само приложение уже удалено, а логи пусты.
Остался ли где-то **текст** этого уведомления? Да — Windows хранит историю тостов в
отдельной базе.

## Наш пример: wpndatabase.db

Файл истории уведомлений лежит в профиле:

```
C:\Users\jdoe\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db
```

```
$ file wpndatabase.db
wpndatabase.db: SQLite 3.x database
```

Это **SQLite**-база, как и браузерные истории. Значит, читается `sqlite3`.

## Что такое «уведомления» в Windows

**Toast-уведомление** — всплывающее сообщение в правом нижнем углу от приложения. Чтобы
показывать «Центр уведомлений» (Action Center) и историю, Windows сохраняет каждое
уведомление в `wpndatabase.db`: приложение, время, заголовок, текст, а иногда вложение.

Для аналитика это ценно тем, что **текст уведомления — это то, что видит пользователь**:
сообщение мессенджера, письмо, напоминание, алерт безопасности. Приложение может удалить
свои данные, но копия тоста остаётся в системной базе.

## Шаг 1: посмотреть таблицы

```
$ sqlite3 wpndatabase.db ".tables"
Notification  NotificationHandler  HandlerSettings  ...
```

Главная таблица — `Notification`. В ней поля с приложением (`HandlerId`), временем и
содержимым.

## Шаг 2: вытащить уведомления

```
$ sqlite3 -header wpndatabase.db \
  "SELECT datetime(ExpiryTime,'unixepoch'), HandlerId FROM Notification LIMIT 5;"
ExpiryTime            HandlerId
2025-06-02 09:55:00   ...!App
```

`HandlerId` — идентификатор приложения-источника. Содержимое уведомления хранится в полях
типа `Payload`/`Content` и часто **сжато** или в виде XML — поэтому «просто SELECT» даёт
нечитаемое; нужен разбор payload.

## Шаг 3: разобрать содержимое

Payload уведомления — это XML-структура (тот же формат, что шлёт приложение). Практично
сначала поискать по базе читаемые строки:

```
$ strings -el wpndatabase.db | grep -iE 'nto|password|meeting|urgent' | head
Meeting at 15:00 with the finance team
nto{wpnd_n0t1f_t0ast}
```

Метка в тексте тоста — типичный CTF-приём: содержимое уведомления специально содержит
искомую строку.

## Что даёт база уведомлений

| Вопрос | Что показывает |
|--------|----------------|
| Какие приложения уведомляли | `HandlerId` / список хендлеров |
| Когда пришло уведомление | временные поля записи |
| Что было в тексте | payload (XML/строка) |
| Получал ли пользователь алерт | текст системного уведомления |

## Частые ошибки и подводные камни

- **Читать payload как обычный текст.** Он часто XML и/или сжат; сначала `strings -el`,
  потом структурированный разбор.
- **Путать с журналом событий.** Уведомления не в EVTX; это отдельная база в профиле.
- **Одна база на пользователя.** У каждого профиля свой `wpndatabase.db` — не пропусти
  нужный.
- **Ограниченный срок хранения.** История уведомлений не бесконечна; старые тосты Windows
  чистит, поэтому база из теневой копии может быть полнее текущей.
- **Кодировка.** Тексты часто в UTF-16LE — снова `strings -el`.

## Шпаргалка команд

```
# Таблицы и схема
sqlite3 wpndatabase.db ".tables"
sqlite3 wpndatabase.db ".schema Notification"

# Список уведомлений
sqlite3 -header wpndatabase.db "SELECT * FROM Notification LIMIT 5;"

# Читаемые строки (UTF-16LE)
strings -el wpndatabase.db | grep -i '<слово>'
```

## Что мы теперь знаем

- История уведомлений Windows лежит в `wpndatabase.db` (SQLite) в профиле.
- Таблица `Notification` хранит приложение, время и payload уведомления.
- Payload часто XML/сжат — начинай со `strings -el`.
- База на пользователя и имеет ограниченный срок хранения (VSS помогает).
- Тексты тостов — самостоятельный источник улик и контекста.

## Квиз

Проверь себя.

```quiz
- question: "Где Windows хранит историю уведомлений?"
  options:
    - "В wpndatabase.db в профиле пользователя"
    - "В Windows.edb"
    - "В реестре HKLM"
    - "В pagefile.sys"
  answer: 0
  explanation: "wpndatabase.db — SQLite-база истории тостов в папке Notifications."
- question: "Почему wpndatabase.db удобно читать sqlite3?"
  options:
    - "Это обычная SQLite-база"
    - "Это ESE-база"
    - "Это текстовый журнал"
    - "Это архив ZIP"
  answer: 0
  explanation: "Формат — SQLite, поэтому подходит sqlite3 и любой SQLite-браузер."
- question: "Что полезного для расследования даёт база уведомлений?"
  options:
    - "Тексты тостов, показанные пользователю"
    - "Список открытых портов"
    - "Хеши паролей"
    - "Таблицу маршрутизации"
  answer: 0
  explanation: "Payload уведомлений содержит текст, который видел пользователь."
- question: "Почему сначала стоит применить strings -el?"
  options:
    - "Содержимое часто в UTF-16LE и/или сжато"
    - "sqlite3 не умеет читать эту базу"
    - "Файл зашифрован BitLocker"
    - "База повреждена"
  answer: 0
  explanation: "Тексты уведомлений часто в UTF-16LE; -el видит их до структурного разбора."
```

## Куда дальше

Мы посмотрели, что система **сообщала** пользователю. Дальше возьмём **Cortana и поисковую
историю** — что пользователь **искал сам**. А пока главное запомни: **база уведомлений
хранит то, что приложение могло уже стереть**.

## Где пригодится

- **CTF Forensics:** флаг в тексте уведомления.
- **DFIR:** восстановление коммуникаций из тостов.
- **Insider threat:** следы предупреждений и напоминаний.
- **Работа:** форензика конечных точек.
''')

LESSONS["win-cortana-search"] = dict(
title="Cortana и поисковая история: запросы пользователя как артефакт",
order=4, diff="medium", mins=45,
tags="[windows, cortana, search, history, sqlite, intent, forensics]",
prereq="[forensics-win-activity, forensics-windows-artifacts]",
summary="Где Windows хранит поисковые запросы и историю Cortana, как их извлечь и как по запросам восстановить намерения пользователя.",
body=r'''
## Вопрос, с которого всё начинается

Нам нужно понять **намерения** пользователя: что он искал накануне инцидента. Даже если он
ничего не открыл, сами поисковые запросы — это след мысли. Windows хранит и историю
поиска, и историю голосового ассистента.

## Наш пример: поисковая история в профиле

Запросы поиска и Cortana оседают в нескольких местах профиля. Типичный источник —
база поиска и файлы истории. Начнём с того, что найдём кандидатов:

```
$ find . -iname '*.db' -path '*Search*'
./AppData/Local/Packages/Microsoft.Windows.Search_.../LocalState/...
```

```
$ file query.db 2>/dev/null
query.db: SQLite 3.x database
```

Многие из этих файлов — **SQLite**. Для Cortana/поиска характерна таблица с текстом
запроса и временем.

## Как Windows хранит поисковые запросы

Пользователь набирает запрос в меню «Пуск» или голосом. Windows сохраняет его, чтобы
показывать подсказки и «недавние поиски». Хранение бывает в двух видах:

- **SQLite-база** с историей запросов (текст + время).
- **Файлы журналов/кэша** в каталоге пакета `Microsoft.Windows.Search` и в профиле
  `AppData\Local\Packages\...\LocalState`.

Ключевая идея: **запрос = намерение**. «как удалить журнал событий», «bitlocker recovery
key», «vpn client download» — такие строки сами по себе рассказывают историю.

## Шаг 1: найти базы и посмотреть схему

```
$ sqlite3 query.db ".tables"
SearchHistory  ...
$ sqlite3 query.db ".schema SearchHistory"
CREATE TABLE SearchHistory(QueryText TEXT, TimeStamp INTEGER, ...);
```

## Шаг 2: вытащить запросы во времени

```
$ sqlite3 -header query.db \
  "SELECT datetime(TimeStamp,'unixepoch'), QueryText FROM SearchHistory ORDER BY TimeStamp;"
TimeStamp            QueryText
2025-06-01 22:10:03  how to clear event logs
2025-06-01 22:12:44  nto{c0rt4n4_s34rch_1nt3nt}
```

Порядок и время запросов — это уже маленькая история расследования.

## Шаг 3: связать с другими артефактами

Поисковый запрос редко живёт в одиночку. Сопоставь его с:

- **Timeline (`ActivitiesCache.db`)** — что открыл сразу после запроса;
- **Windows Search (`Windows.edb`)** — какие файлы оказались рядом по теме;
- **браузерной историей** — куда перешёл после поиска.

Так из одной строки вырастает цепочка: «искал → открыл → скачал».

## Что искать в поисковой истории

| Тип запроса | Что означает |
|-------------|--------------|
| Имена утилит (`psexec`, `mimikatz`) | подготовка инструментария |
| «как удалить/очистить …» | намерение скрыть следы |
| Пути/имена файлов | поиск конкретных данных |
| Сервисы (`vpn`, `bitlocker`) | подготовка доступа/шифрования |

## Частые ошибки и подводные камни

- **Искать только одну базу.** Запросы разбросаны по нескольким файлам/пакетам — собери все.
- **Забыть про голосовые запросы.** Cortana пишет и распознанный текст, не только ввод с
  клавиатуры.
- **Путать с браузером.** Поиск в «Пуске» и поиск в браузере — разные хранилища; нужны оба.
- **Кодировка.** Как и везде, тексты могут быть UTF-16LE.
- **Синхронизация/облако.** Часть истории может подтягиваться из аккаунта; локальная копия
  не всегда полная.

## Шпаргалка команд

```
# Найти кандидатов
find . -iname '*.db' -path '*Search*'

# Схема и запросы
sqlite3 query.db ".tables"
sqlite3 -header query.db "SELECT * FROM SearchHistory ORDER BY TimeStamp;"

# Читаемые строки, если база неочевидна
strings -el query.db | grep -i '<слово>'
```

## Что мы теперь знаем

- Поисковые запросы и история Cortana хранятся в профиле (SQLite и кэш пакетов).
- Запросы содержат текст и время — это готовый мини-таймлайн намерений.
- Полезно сопоставлять запросы с Timeline, Windows.edb и браузерной историей.
- Источников несколько; собирай все, включая голосовые запросы.
- Кодировка часто UTF-16LE.

## Квиз

Проверь себя.

```quiz
- question: "Что даёт анализ поисковой истории для расследования?"
  options:
    - "Намерения пользователя, выраженные запросами"
    - "Хеши паролей домена"
    - "Список сетевых интерфейсов"
    - "Таблицу разделов диска"
  answer: 0
  explanation: "Поисковые запросы отражают, что пользователь хотел найти или сделать."
- question: "В каком формате чаще всего хранится история поиска?"
  options:
    - "SQLite-база"
    - "ESE-база"
    - "Бинарный реестр"
    - "PDF-документ"
  answer: 0
  explanation: "История запросов обычно в SQLite; читается sqlite3."
- question: "Зачем сопоставлять запросы с другими артефактами?"
  options:
    - "Чтобы построить цепочку 'искал -> открыл -> сделал'"
    - "Чтобы удалить историю"
    - "Чтобы изменить время запроса"
    - "Чтобы отключить Cortana"
  answer: 0
  explanation: "Связка запроса с Timeline и браузером восстанавливает последовательность действий."
- question: "Почему стоит искать запросы в нескольких местах профиля?"
  options:
    - "Источники разбросаны по базам и кэшу пакетов"
    - "Windows хранит всё в одном файле"
    - "Запросы есть только в реестре"
    - "Запросы никогда не сохраняются"
  answer: 0
  explanation: "Поиск и Cortana пишут в несколько файлов/пакетов профиля."
```

## Куда дальше

Модуль активности закрыт. Дальше переходим к **глубокому разбору артефактов выполнения**
(Prefetch, ShimCache, AmCache, SRUM) — там мы уже перейдём от «что делал пользователь» к
«что и как запускалось». А пока главное запомни: **поисковый запрос — это сохранённое
намерение**.

## Где пригодится

- **CTF Forensics:** флаг в истории поиска.
- **DFIR:** реконструкция подготовки к инциденту.
- **Insider threat:** поиск следов подготовки к утечке.
- **Работа:** eDiscovery и форензика конечных точек.
''')

def fm(d):
    return (
        "---\n"
        f'id: {d["id"]}\n'
        f'title: "{d["title"]}"\n'
        "category: forensics\n"
        f'parent: {d["parent"]}\n'
        f'difficulty: {d["diff"]}\n'
        f'order: {d["order"]}\n'
        f'tags: {d["tags"]}\n'
        f'prerequisites: {d["prereq"]}\n'
        "useful_for:\n"
        '  - "CTF Forensics категория"\n'
        '  - "DFIR / Incident Response"\n'
        '  - "Threat Hunting (Windows)"\n'
        f'estimated_minutes: {d["mins"]}\n'
        f'summary: "{d["summary"]}"\n'
        "lab:\n"
        "  kind: shell\n"
        f'  title: "Практика: {d["labtitle"]}"\n'
        "  toolset: [core, grep, strings, base64]\n"
        "  workdir: /home/student/task\n"
        f'  files: [{d["files"]}]\n'
        "  check: \"grep -q 'nto{' found.txt\"\n"
        "  hints:\n"
        + d["hints"] + "\n"
        "---"
    )

LABS = {
"win-windows-search": dict(
 labtitle="пути из поискового индекса",
 files="task.md, Windows.edb",
 seedfile="Windows.edb",
 seedtext=(
  "ESE DATABASE\n"
  "System.ItemPathDisplay  \\\\?\\C:\\Users\\jdoe\\Documents\\finance_2025.xlsx\n"
  "System.ItemPathDisplay  \\\\?\\C:\\Users\\jdoe\\Documents\\deleted_report.docx\n"
  "System.ItemNameDisplay  deleted_report.docx\n"
  "note: nto{wns34rch_3db_d3l3t3d}\n"
 ),
 task=("# Задача: Windows Search\n\n`Windows.edb` — выгрузка поискового индекса. "
       "Найди путь к удалённому файлу и метку.\n\n1. `file Windows.edb`.\n"
       "2. `strings -el Windows.edb | grep -i report`.\n3. `grep nto Windows.edb > found.txt`.\n"),
 hints=("    - 'Опознай формат: `file Windows.edb`.'\n"
        "    - 'Пути ищи в 16-битных строках: `strings -el Windows.edb`.'\n"
        "    - 'Отфильтруй удалённый документ: `strings -el Windows.edb | grep -i report`.'\n"
        "    - 'Найди метку: `grep nto Windows.edb > found.txt`.'"),
 flag="nto{wns34rch_3db_d3l3t3d}",
 solution="grep nto Windows.edb > found.txt"),
"win-activity-timeline": dict(
 labtitle="таймлайн сессий из ActivitiesCache.db",
 files="task.md, ActivitiesCache.db",
 seedfile="ActivitiesCache.db",
 seedtext=(
  "SQLite format 3\n"
  "CREATE TABLE Activity(Id TEXT, AppId TEXT, StartTime INTEGER, EndTime INTEGER, ContentInfo TEXT);\n"
  "INSERT INTO Activity VALUES('a1','EXCEL.EXE',1717312460,1717314065,'{\"displayText\":\"finance_q4.xlsx\"}');\n"
  "INSERT INTO Activity VALUES('a2','powershell.exe',1717314700,1717315000,'{\"displayText\":\"nto{tim3l1n3_s3ss10n}\"}');\n"
 ),
 task=("# Задача: Windows Timeline\n\n`ActivitiesCache.db` — база Timeline. "
       "Восстанови сессии и найди метку в объекте активности.\n\n"
       "1. `file ActivitiesCache.db`.\n2. `strings ActivitiesCache.db | grep -i nto`.\n"
       "3. `grep nto ActivitiesCache.db > found.txt`.\n"),
 hints=("    - 'Формат: `file ActivitiesCache.db`.'\n"
        "    - 'Это SQLite: `strings ActivitiesCache.db | grep Activity`.'\n"
        "    - 'Ищи объект активности: `strings ActivitiesCache.db | grep -i nto`.'\n"
        "    - 'Метка: `grep nto ActivitiesCache.db > found.txt`.'"),
 flag="nto{tim3l1n3_s3ss10n}",
 solution="grep nto ActivitiesCache.db > found.txt"),
"win-notification-db": dict(
 labtitle="тексты уведомлений из wpndatabase.db",
 files="task.md, wpndatabase.db",
 seedfile="wpndatabase.db",
 seedtext=(
  "SQLite format 3\n"
  "CREATE TABLE Notification(HandlerId TEXT, Payload TEXT, ExpiryTime INTEGER);\n"
  "Notification: Meeting at 15:00 with finance team\n"
  "Notification: nto{wpnd_n0t1f_t0ast}\n"
 ),
 task=("# Задача: уведомления Windows\n\n`wpndatabase.db` — история тостов. "
       "Найди текст уведомления с меткой.\n\n1. `file wpndatabase.db`.\n"
       "2. `strings -el wpndatabase.db | grep -i nto`.\n3. `grep nto wpndatabase.db > found.txt`.\n"),
 hints=("    - 'Опознай: `file wpndatabase.db`.'\n"
        "    - 'Это SQLite с текстами: `strings -el wpndatabase.db`.'\n"
        "    - 'Отфильтруй уведомления: `strings -el wpndatabase.db | grep -i nto`.'\n"
        "    - 'Метка: `grep nto wpndatabase.db > found.txt`.'"),
 flag="nto{wpnd_n0t1f_t0ast}",
 solution="grep nto wpndatabase.db > found.txt"),
"win-cortana-search": dict(
 labtitle="поисковые запросы из истории",
 files="task.md, query.db",
 seedfile="query.db",
 seedtext=(
  "SQLite format 3\n"
  "CREATE TABLE SearchHistory(QueryText TEXT, TimeStamp INTEGER);\n"
  "QueryText: how to clear event logs\n"
  "QueryText: nto{c0rt4n4_s34rch_1nt3nt}\n"
 ),
 task=("# Задача: поисковая история\n\n`query.db` — история поиска/Cortana. "
       "Найди подозрительный запрос и метку.\n\n1. `file query.db`.\n"
       "2. `strings query.db | grep -iE 'log|nto'`.\n3. `grep nto query.db > found.txt`.\n"),
 hints=("    - 'Опознай: `file query.db`.'\n"
        "    - 'Смотри запросы: `strings query.db`.'\n"
        "    - 'Отфильтруй намерения: `strings query.db | grep -iE \"log|nto\"`.'\n"
        "    - 'Метка: `grep nto query.db > found.txt`.'"),
 flag="nto{c0rt4n4_s34rch_1nt3nt}",
 solution="grep nto query.db > found.txt"),
}

def main():
    w(f"{C}/forensics-win-activity.md", HUB)
    for lid, d in LESSONS.items():
        d["id"] = lid
        d["parent"] = "forensics-win-activity"
        lab = LABS[lid]
        d.update(lab)
        txt = fm(d) + "\n" + d["body"].strip() + "\n"
        w(f"{C}/{lid}.md", txt)
        # lab bundle
        bundle = {
            "id": lid,
            "workdir": "/home/student/task",
            "hostname": "lab",
            "expect": {"file": "/home/student/task/found.txt", "contains": lab["flag"]},
            "fs": [
                {"path": "/home/student/task", "type": "dir"},
                {"path": "/home/student/task/task.md", "text": lab["task"]},
                {"path": f"/home/student/task/{lab['seedfile']}", "text": lab["seedtext"], "mode": "644"},
            ],
        }
        w(f"{L}/{lid}.json", json.dumps(bundle, ensure_ascii=False, indent=2))
        print("wrote", lid)

if __name__ == "__main__":
    main()
