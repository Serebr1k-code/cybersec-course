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

## Вопрос, с которого всё начинается

Веб-приложение было скомпрометировано, и злоумышленник что-то делал с базой данных: возможно, выкачал таблицу пользователей или удалил следы. Серверный диск у нас есть. Задача: понять, какие данные читались и менялись, и восстановить то, что удалили.

Серверная **СУБД** (система управления базами данных) хранит данные не в одном файле, а в наборе: страницы данных плюс **журналы**, куда пишутся все изменения. Именно журналы и позволяют восстановить картину. Разберём MySQL как основной пример.

## Наш пример: сервер MySQL

Первым делом — определить, что за СУБД и версия. Достаточно посмотреть на файлы данных в каталоге базы:

```bash
$ ls /var/lib/mysql/
ibdata1  ib_logfile0  ib_logfile1  mysql.ibd  app/  binlog.000001
```

Видим характерные имена. `ibdata1` — общий **tablespace** InnoDB (файл, где лежат страницы данных). `ib_logfile*` — **redo log** (журнал восстановления InnoDB). `mysql.ibd` — системные таблицы. `app/` — каталог нашей базы. `binlog.000001` — **binary log**, о котором ниже.

## Шаг 1: снимаем образ со всеми журналами

Форензика СУБД начинается с **правильного снятия образа**. Нельзя копировать только файл данных — потеряются журналы, а без них восстановление невозможно. Для MySQL нужны:

- файлы данных: `ibdata1` + `.ibd` (в file-per-table режиме);
- `ib_logfile*` (redo log);
- `binlog.*` (binary log);
- `undo` (undo log).

Практический приём: остановить СУБД или снять образ раздела целиком, чтобы все файлы были консистентны. Живое копирование «на ходу» даёт рассогласованные данные.

## Шаг 2: читаем binary log

**Binary log** — ключевой источник. В него MySQL пишет **все** изменения данных: `INSERT`, `UPDATE`, `DELETE`. Читается утилитой `mysqlbinlog`:

```bash
$ mysqlbinlog --base64-output=DECODE-ROWS -v binlog.000001 | head -20
# at 195
#250301 03:14:07 server id 1  end_log_pos 260 CRC32 0x1a2b3c4d  Query  thread_id=8
#   Query: DELETE FROM app.users WHERE username='admin'
```

`--base64-output=DECODE-ROWS -v` заставляет инструмент показать сами строки (по умолчанию они в base64). В примере видно `DELETE FROM app.users WHERE username='admin'` — атакующий удалил учётную запись администратора. Теперь мы знаем, **что** и **когда** произошло.

## Шаг 3: ищем SQL-инъекцию по логам запросов

Часто база страдает через **SQL-инъекцию** — атаку, при которой злоумышленник «встраивает» свой SQL в запрос приложения. Следы ищем в general query log (если включён) — там все запросы:

```bash
$ grep -iE 'union|or 1=1|into outfile|copy .*program' /var/log/mysql/general.log | head
2025-03-01T03:14:02  8 Query  SELECT * FROM users WHERE id=1 UNION SELECT user,password FROM mysql.user
```

Запрос с `UNION SELECT` из таблицы `mysql.user` — явная попытка вытащить пароли. А конструкция `INTO OUTFILE` или `COPY ... TO PROGRAM` означает не только чтение, но и **запись файла** или **выполнение команды** на сервере.

## Шаг 4: восстанавливаем удалённые строки

Данные, которые удалили, не исчезают сразу. InnoDB хранит их в **страницах** (блоках по 16 КБ). Удалённая строка помечается как `delete-marked`, но физически остаётся на странице, пока её не перезапишут. Инструмент `undrop-for-innodb` парсит страницы напрямую:

```bash
$ ./stream_parser -f ibdata1
$ ./c_parser -6f pages-ibdata1/FIL_PAGE_INDEX/*.page -t table.sql > rows.txt
$ grep admin rows.txt
admin  $2y$10$...  2025-03-01
```

`stream_parser` разбивает файл на страницы, `c_parser` извлекает из них строки по схеме таблицы. Так мы вернули удалённую запись администратора.

## Шаг 5: PostgreSQL и MSSQL — коротко

У других СУБД механика та же, меняются имена и инструменты.

**PostgreSQL** хранит журнал изменений в **WAL** (Write-Ahead Log) — каталог `pg_wal/`. Читается `pg_waldump`:

```bash
$ pg_waldump pg_wal/000000010000000000000001 | head
```

Восстановление на момент времени (Point-In-Time Recovery) позволяет «откатить» базу до атаки. А расширение `pg_dirtyread` читает «мёртвые» (удалённые, но не очищенные) строки.

**MSSQL** держит данные в `.mdf`, а журнал транзакций — в `.ldf`. На живой базе его читают функцией `fn_dblog`, офлайн — сторонними парсерами:

```sql
SELECT Operation, [Transaction Name], [Begin Time]
FROM fn_dblog(NULL, NULL)
WHERE Operation IN ('LOP_DELETE_ROWS','LOP_INSERT_ROWS');
```

`LOP_DELETE_ROWS` — операции удаления; по ним восстанавливают, что и когда стёрли.

## Где ещё искать: пароли в конфигурациях

Помимо журналов, СУБД хранят учётные данные в конфигурационных файлах — и это отдельная находка для расследования. У MySQL это `my.cnf` (`user`, `password`), у PostgreSQL — `pg_hba.conf` (какие адреса и методы аутентификации разрешены) и `.pgpass`, у MSSQL — строки подключения приложений. Часто там лежат пароли в открытом виде:

```bash
$ grep -riE 'password|passwd' /etc/mysql/ /var/lib/mysql/ 2>/dev/null | head
```

Ещё один приём — сопоставить базу с **веб-логами**: SQL-инъекция сначала проявляется в `access.log` веб-сервера, а уже потом в query log базы. Совпадение по времени и IP подтверждает связь.

## Что мы теперь знаем

- СУБД хранит данные в страницах плюс журналы; образ снимают со **всеми** журналами, иначе восстановление невозможно.
- MySQL: `ibdata1`/`.ibd` (данные), `ib_logfile*` (redo), `binlog.*` (все изменения).
- Binary log читается `mysqlbinlog --base64-output=DECODE-ROWS -v` и показывает `INSERT/UPDATE/DELETE`.
- SQL-инъекцию ищут в general query log (`UNION SELECT`, `OR 1=1`, `INTO OUTFILE`).
- Удалённые строки восстанавливают из страниц (`undrop-for-innodb`); в PostgreSQL — WAL, в MSSQL — `.ldf`.
- `COPY ... TO PROGRAM` / `INTO OUTFILE` — это уже запись файлов или выполнение команд.

## Квиз

Проверь себя.

```quiz
- question: "Что такое binary log в MySQL?"
  options:
    - "резервная копия"
    - "журнал всех изменений данных (INSERT/UPDATE/DELETE)"
    - "файл паролей"
    - "журнал ошибок"
  answer: 1
  explanation: "binlog фиксирует все изменения данных; читается mysqlbinlog."
- question: "Какая утилита читает binary log?"
  options:
    - "mysqlbinlog"
    - "mysqldump"
    - "ibdata1"
    - "binwalk"
  answer: 0
  explanation: "mysqlbinlog --base64-output=DECODE-ROWS -v показывает сами строки."
- question: "Где в PostgreSQL хранится журнал изменений?"
  options:
    - "pg_wal/"
    - "binlog"
    - ".ldf"
    - "ib_logfile"
  answer: 0
  explanation: "WAL (Write-Ahead Log) в pg_wal; читается pg_waldump."
- question: "Чем восстанавливают удалённые строки InnoDB?"
  options:
    - "undrop-for-innodb / разбор страниц"
    - "удалить базу"
    - "перезапустить MySQL"
    - "exiftool"
  answer: 0
  explanation: "undrop-for-innodb парсит страницы, где удалённые строки остаются до purge."
- question: "Где искать признаки SQL-инъекции?"
  options:
    - "в error log"
    - "в general query log / audit"
    - "в .ldf"
    - "в redo log"
  answer: 1
  explanation: "general query log содержит запросы с UNION SELECT, OR 1=1 и т.п."
```

## Куда дальше

Мы разобрали форензику серверной базы данных. В следующем уроке (`forensics-timestomp`) мы переключимся на анти-форензику: посмотрим, как атакующий подделывает метки времени файлов и как это раскрыть. А пока главное запомни: **СУБД хранит данные в страницах и журналах, binary log/WAL показывают все изменения, а удалённое восстанавливают разбором страниц**.

## Где пригодится

- **CTF Forensics:** задачи с дампами баз данных.
- **DFIR:** расследование утечек данных.
- **Веб-форензика:** разбор SQL-инъекций.
- **Recovery:** восстановление удалённых записей.
- **SOC:** детекты аномальных запросов.
