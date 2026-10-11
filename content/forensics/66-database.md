---
id: forensics-database
title: "Форензика баз данных: MySQL, PostgreSQL, MSSQL"
category: forensics
parent: forensics-web-forensics
difficulty: hard
order: 2
tags: [mysql, postgresql, mssql, innodb, wal, forensics, recovery]
prerequisites: [forensics-web-forensics, forensics-sqlite]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Веб-форензика"
estimated_minutes: 45
summary: "Форензика серверных СУБД: файлы данных и журналы MySQL/InnoDB, PostgreSQL/WAL, MSSQL/MDF+LDF, восстановление удалённых записей и разбор логов запросов."
---

## Зачем форензика СУБД

Серверные базы данных — сердце веб-приложений. После компрометации нужно понять: какие данные читались/изменялись/удалялись, были ли SQL-инъекции, экспорт данных. У СУБД богатая внутренняя структура (журналы, страницы, undo/redo), которая позволяет **восстановить удалённое** и **доказать действия**.

## MySQL / MariaDB

**Файлы данных:** для InnoDB — `ibdata1` (общий tablespace) или `.ibd` (file-per-table), `ib_logfile*` (redo log), `undo` (undo log), `mysql.ibd` (системные таблицы). MyISAM — `.MYD` (данные), `.MYI` (индексы).

**Журналы:**

- **Binary log** (`binlog`): все изменения данных (INSERT/UPDATE/DELETE) — ключевой источник для восстановления.
- **General query log**: все запросы (если включён).
- **Slow query log**: медленные запросы.
- **Error log**: ошибки.

```bash
# Разбор binary log
mysqlbinlog --base64-output=DECODE-ROWS -v binlog.000001 > binlog.txt
# Восстановление до момента
mysqlbinlog --stop-datetime="2024-01-01 12:00:00" binlog.* | mysql -u root
# Показать события
mysqlbinlog --start-position=4 binlog.000001
```

**Восстановление удалённых строк:** InnoDB хранит удалённые записи в undo/страницах; инструменты `undrop-for-innodb`, `innodb_ruby`, `stream_parser`.

```bash
# stream_parser — разбор страниц InnoDB
./stream_parser -f ibdata1
./c_parser -6f pages-ibdata1/FIL_PAGE_INDEX/... -t table.sql > rows.txt
```

## PostgreSQL

**Файлы данных:** `$PGDATA/base/<oid>/` — по файлу на таблицу; `pg_wal/` — WAL (Write-Ahead Log); `pg_xact/` — статус транзакций.

**WAL** — журнал всех изменений до применения; позволяет восстановить и удалённое.

```bash
# Просмотр WAL
pg_waldump pg_wal/000000010000000000000001 | less
# Point-in-time recovery
# 1. restore basebackup
# 2. recovery.conf / postgresql.conf: restore_command, recovery_target_time
# 3. запустить -> восстановление до момента
```

**Логи:** `log/` (если `logging_collector=on`), `postgresql.conf` (`log_statement=all` для полного логирования).

## MSSQL

**Файлы:** `.mdf` (данные), `.ldf` (log), `.ndf` (вторичные). Внутри — страницы 8 КБ, organized в extents.

**Transaction log** (`.ldf`) — все транзакции; можно прочитать логически с помощью `fn_dblog` (на живой БД) или сторонних парсеров офлайн.

```sql
-- На живой БД
SELECT * FROM fn_dblog(NULL, NULL);
-- Восстановление удалённых строк (если в log есть)
SELECT * FROM fn_dblog(NULL, NULL) WHERE Operation = 'LOP_DELETE_ROWS';
```

**Логи:** SQL Server Error Log, Extended Events, audit.

## Восстановление удалённых записей

- **MySQL:** `undrop-for-innodb`, `ibd2sdi`, разбор `.ibd`.
- **PostgreSQL:** WAL + PITR; `pg_dirtyread` (чтение «мёртвых» строк).
- **MSSQL:** `.ldf`-парсеры, `ApexSQL Log`, `fn_dblog`.

Удалённые данные часто остаются на страницах до перезаписи (как в файловых системах).

## Практический пример: SQL-инъекция по логам

1. **General query log / audit** → найти аномальные запросы (`UNION SELECT`, `OR 1=1`, `INTO OUTFILE`).
2. **binlog/WAL** → какие данные читались/менялись.
3. **Ошибки** → синтаксис, указывающий на инъекцию.
4. **Экспорт** → `INTO OUTFILE`, `COPY ... TO PROGRAM`.
5. **Таймлайн** и сопоставление с веб-логами.

```bash
grep -iE "union|or 1=1|into outfile|copy .*program" /var/log/mysql/general.log
```

## Инструменты и команды

```bash
# MySQL
mysqlbinlog, undrop-for-innodb, innodb_ruby
# PostgreSQL
pg_waldump, pg_dirtyread
# MSSQL
fn_dblog, ApexSQL Log, SQL Log Rescue
# Общие
strings, grep, hexdump для «сырого» анализа
```

## InnoDB: структура страниц

InnoDB хранит данные в **страницах** (16 КБ): `FIL_PAGE_INDEX` (B-tree узлы), `FIL_PAGE_UNDO_LOG`, `FIL_PAGE_TYPE_FSP_HDR` (заголовок tablespace). Каждая страница — заголовок + записи. Удалённые строки помечаются `delete-marked`, но **остаются** на странице до очистки (purge).

```bash
# Разбор страниц через innodb_ruby
innodb_space -f ibdata1 space-page-type-regions
innodb_space -f ibdata1 -T db/table space-index-pages-summary
# undrop-for-innodb: stream_parser + c_parser
./stream_parser -f ibdata1
./c_parser -6f pages-ibdata1/FIL_PAGE_INDEX/*.page -t table.sql > rows.txt
```

## PostgreSQL: WAL и PITR детально

WAL состоит из 16-МБ сегментов в `pg_wal/`. Каждая запись — `XLogRecord` с типом (heap insert/update/delete, commit). `pg_waldump` показывает содержимое.

```bash
pg_waldump pg_wal/000000010000000000000001 | head -30
# PITR:
# 1. Восстановить basebackup
# 2. postgresql.conf: restore_command='cp /archive/%f %p'
#    recovery_target_time='2024-01-01 12:00:00'
#    recovery_target_action='promote'
# 3. touch recovery.signal && start
```

`pg_dirtyread` расширение позволяет читать «мёртвые» (удалённые, но не очищенные) строки.

## MSSQL: .ldf и восстановление

Transaction log (`.ldf`) содержит все операции. Офлайн-парсеры (ApexSQL Log, SQL Log Rescue) извлекают `LOP_DELETE_ROWS`, `LOP_INSERT_ROWS` и т. д. На живой БД — `fn_dblog`.

```sql
SELECT Operation, [Transaction Name], [Begin Time]
FROM fn_dblog(NULL, NULL)
WHERE Operation IN ('LOP_DELETE_ROWS','LOP_INSERT_ROWS');
```

Также `.mdf` содержит **unallocated**-страницы с удалёнными данными — можно карвить.

## Практический чек-лист по СУБД-форензике

1. **Определите СУБД и версию** (файлы, banner).
2. **Снимите образ** со всеми журналами (`ibdata1`+`.ibd`+`binlog`; `PGDATA`+`pg_wal`; `.mdf`+`.ldf`).
3. **Разберите журналы:** binlog (`mysqlbinlog`), WAL (`pg_waldump`), `.ldf` (`fn_dblog`).
4. **Восстановите удалённое** (undrop/WAL/PITR).
5. **Найдите инъекции** в query/audit-логах.
6. **Проверьте экспорт** (`INTO OUTFILE`, `COPY ... TO PROGRAM`).
7. **Сопоставьте** с веб-логами и таймлайном.

## Инструменты и команды

```bash
# MySQL
mysqlbinlog --base64-output=DECODE-ROWS -v binlog.000001 > binlog.txt
mysqlbinlog --stop-datetime="2024-01-01 12:00:00" binlog.* | mysql -u root
innodb_ruby, undrop-for-innodb, ibd2sdi

# PostgreSQL
pg_waldump pg_wal/000000010000000000000001
# PITR через recovery_target_time

# MSSQL
SELECT * FROM fn_dblog(NULL,NULL) WHERE Operation='LOP_DELETE_ROWS';
# ApexSQL Log, SQL Log Rescue

# Общее
strings, grep, hexdump, sqlite3 (для мелких)
```

## Учётные данные в конфигурациях

СУБД хранят пароли в конфигурациях, и их можно найти:

- **MySQL:** `/etc/mysql/my.cnf`, `~/.my.cnf` (пароль в открытом виде!), `.mylogin.cnf` (зашифрован, но дешифруем).
- **PostgreSQL:** `pg_hba.conf` (методы аутентификации), `postgresql.conf` (пароли в `ALTER ROLE`?), `.pgpass`.
- **MSSQL:** конфиги служб, linked servers.
- **Веб-приложения:** `config.php`, `.env`, `settings.py` — учётки БД.

```bash
grep -riE 'password|passwd|pwd' /var/www/html/*.php /etc/mysql/ 2>/dev/null
# MySQL .mylogin.cnf
mysql_config_editor print --all
```

Это часто ключ к пониманию, как атакующий получил доступ к БД.

## Снятие «горячего» образа СУБД

Останавливать СУБД нельзя (теряется кэш, незаписанные данные). Правильно:

- **MySQL:** `FLUSH TABLES WITH READ LOCK` (или `mysqlpump`/`xtrabackup`), затем копирование файлов.
- **PostgreSQL:** `pg_basebackup` (создаёт согласованный basebackup + WAL).
- **MSSQL:** backup (`.bak`) или снапшот тома (VSS).
- **Любая:** снапшот тома/ВМ (VSS/APFS/LVM) — атомарный и консистентный.

```bash
# MySQL
mysql -e "FLUSH TABLES WITH READ LOCK;"
cp -a /var/lib/mysql /evidence/
mysql -e "UNLOCK TABLES;"
# PostgreSQL
pg_basebackup -D /evidence/basebackup -Ft -z -P
# MSSQL (VSS)
# diskshadow / vssadmin
```

## Итог

СУБД-форензика: снять консистентный образ (журналы + данные), разобрать журналы (binlog/WAL/.ldf), восстановить удалённое (undrop/PITR), найти инъекции в query-логах и экспорт. Ключ — журналы: они содержат всю историю изменений. Не забывайте про пароли в конфигах и «горячее» снятие образа.

## Частые ошибки

- **Остановить СУБД и потерять незаписанное.** Снимайте образ «на горячую» с учётом журналов.
- **Игнорировать binlog/WAL.** Там вся история изменений.
- **Забыть про general log.** Может быть выключен.
- **Путать логические и физические файлы.** Разные уровни.
- **Не сохранить `ibdata1` + `.ibd` вместе.**
- **Считать удалённое потерянным.** Часто восстановимо.

## Как не застрять

- **Определите СУБД** по файлам/версии.
- **Журналы (binlog/WAL/ldf)** — главный источник.
- **Восстановите удалённое** через undrop/WAL.
- **Ищите SQL-инъекции** в query log.
- **Снимайте образ** со всеми журналами.
- **Сопоставляйте** с веб-логами.

## Квиз

```quiz
- question: "Какой журнал MySQL содержит все изменения данных?"
  options:
    - "error log"
    - "binary log (binlog)"
    - "slow log"
    - "access log"
  answer: 1
- question: "Что такое WAL в PostgreSQL?"
  options:
    - "индекс"
    - "журнал предзаписи (Write-Ahead Log) всех изменений"
    - "пароль"
    - "тип данных"
  answer: 1
- question: "Файлы данных MSSQL:"
  options:
    - ".mdf и .ldf"
    - ".ibd"
    - ".db"
    - ".sqlite"
  answer: 0
- question: "Как восстановить удалённые строки MySQL InnoDB?"
  options:
    - "перезапустить"
    - "undrop-for-innodb / разбор страниц"
    - "удалить базу"
    - "невозможно"
  answer: 1
- question: "Где искать SQL-инъекции?"
  options:
    - "в error log"
    - "в general query log / audit"
    - "в binlog"
    - "в .ldf"
  answer: 1
```

## Где пригодится

- **CTF Forensics** — задачи с дампами БД.
- **DFIR** — расследование утечек данных.
- **Веб-форензика** — SQL-инъекции.
- **Recovery** — восстановление удалённых записей.
- **SOC** — детекты аномальных запросов.
