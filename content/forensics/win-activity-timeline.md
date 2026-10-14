---
id: win-activity-timeline
title: "Windows Timeline: ActivitiesCache.db как журнал сессий пользователя"
category: forensics
parent: forensics-win-activity
difficulty: hard
order: 2
tags: [windows, timeline, activitiescache, sqlite, user-activity, forensics]
prerequisites: [forensics-win-deep, forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting (Windows)"
estimated_minutes: 50
summary: "Как разобрать ActivitiesCache.db (Windows Timeline) и построить таймлайн сессий: приложения, документы, длительность, связанные устройства."
lab:
  kind: shell
  title: "Практика: таймлайн сессий из ActivitiesCache.db"
  toolset: [core, grep, strings, base64]
  workdir: /home/student/task
  files: [task.md, ActivitiesCache.db]
  check: "grep -q 'nto{' found.txt"
  hints:
    - 'Формат: `file ActivitiesCache.db`.'
    - 'Это SQLite: `strings ActivitiesCache.db | grep Activity`.'
    - 'Ищи объект активности: `strings ActivitiesCache.db | grep -i nto`.'
    - 'Метка: `grep nto ActivitiesCache.db > found.txt`.'
---
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

## Сквозной пример: восстановление сессии редактирования документа

Разберём один рабочий день целиком. Цель — доказать, что пользователь редактировал
финансовый документ 2 июня утром.

Сначала вытащим все активности за нужный интервал и отсортируем по времени:

```
$ sqlite3 -header ActivitiesCache.db \
  "SELECT datetime(StartTime,'unixepoch') AS s, datetime(EndTime,'unixepoch') AS e, AppId
   FROM Activity WHERE StartTime BETWEEN 1717310000 AND 1717320000 ORDER BY StartTime;"
s                     e                     AppId
2025-06-02 09:02:11   2025-06-02 09:13:50   ...\chrome.exe
2025-06-02 09:14:20   2025-06-02 09:41:05   ...\EXCEL.EXE
2025-06-02 09:45:00   2025-06-02 09:52:30   ...\OUTLOOK.EXE
```

Видно: браузер → Excel → Outlook. Теперь достаём объект для сессии Excel:

```
$ sqlite3 ActivitiesCache.db \
  "SELECT ContentInfo FROM Activity WHERE AppId LIKE '%EXCEL%' LIMIT 1;" | python3 -m json.tool
{
  "displayText": "payroll_q1.xlsx",
  "contentUri": "file:///C:/Users/jdoe/Documents/payroll_q1.xlsx"
}
```

Итог: пользователь работал в Excel с файлом `payroll_q1.xlsx` 27 минут. Сверяем с
`Windows.edb` (файл там есть) и с `JumpLists` (последний документ) — картина сходится в
трёх независимых источниках. Именно **сходимость** источников и делает вывод надёжным.

## Поля Activity в деталях

Чтобы не гадать, что значит колонка, держи разбор ключевых полей:

| Поле | Смысл | Тонкость |
|------|-------|----------|
| `Id` | уникальный идентификатор активности | по нему связываются записи |
| `AppId` | приложение/исполнитель | может быть путь или AUMID |
| `StartTime` / `EndTime` | интервал сессии, Unix-эпоха UTC | конвертируй в нужный пояс |
| `ContentInfo` | JSON с объектом (файл/URL) | ключ `contentUri` |
| `ActivityType` | тип (открытие/использование) | различает клик и длительную работу |
| `Platform` | устройство/платформа | помогает отделить чужие устройства |

Поле `Platform` особенно важно: если сессия пришла с другого устройства пользователя, не
приписывай её данной машине.

## Сверка времени: UTC против локального

Одна из самых частых ошибок — построить таймлайн «со сдвигом». `StartTime` хранится в
Unix-эпохе (UTC). Если в отчёте ты пишешь локальное время, конвертируй явно и фиксируй
пояс. Летом/зимой смещение меняется (DST), поэтому для событий на границе перехода
проверяй обе интерпретации. Лучше хранить и UTC, и локальное время в отчёте — тогда не
возникнет спора «а в каком поясе это было».

## Ограничения и приватность

Timeline ведёт себя по-разному в зависимости от настроек приватности и редакции Windows.
Пользователь может отключить сбор активности, а очистка истории в «Параметрах» удаляет
записи. Поэтому важны два вывода: (1) отсутствие активности — не доказательство, что
действия не совершались; (2) исторический снимок из VSS может содержать то, что текущая
база уже не хранит.

## Что фиксировать в отчёте

Опиши источник (путь к `ActivitiesCache.db`), инструмент, интервал и приложения, объекты
(`contentUri`) и явно укажи часовой пояс. Если активность пришла с другого устройства —
вынеси это отдельной строкой, чтобы не приписать её локальному пользователю.

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
