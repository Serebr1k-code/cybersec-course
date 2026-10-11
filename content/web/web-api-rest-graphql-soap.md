---
id: web-api-rest-graphql-soap
title: "API: REST, GraphQL и SOAP"
category: web
parent: web-architecture-protocols
difficulty: easy
order: 1
tags: [api, rest, graphql, soap, swagger, openapi, introspection]
prerequisites: [web-architecture]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Три парадигмы API, как их различать, находить документацию и где в каждой из них живут уязвимости."
---

Современные приложения — это SPA или мобильное приложение поверх **API**. Если вы понимаете, как выглядит API, вы найдёте половину багов быстрее. Существует три больших парадигмы: REST, GraphQL и SOAP. У каждой свои соглашения, своя документация и свои типовые ошибки. В этом уроке — как определить, с чем вы имеете дело, и где искать документацию.

## Теория: REST

**REST** — это стиль, а не стандарт. Ресурсы адресуются путями, действия — HTTP-методами:

```
GET    /api/v1/users          -> список
GET    /api/v1/users/42       -> один
POST   /api/v1/users          -> создать
PUT    /api/v1/users/42       -> заменить
PATCH  /api/v1/users/42       -> частично изменить
DELETE /api/v1/users/42       -> удалить
```

Форматы: обычно JSON (`Content-Type: application/json`), иногда XML или form-urlencoded. Ключевые для тестировщика свойства:

- **Идентификаторы в пути** (`/users/42`) → прямой кандидат на IDOR/BOLA (см. `web-api-security`).
- **Версионирование** (`/v1/`, `/v2/`) → старые версии часто оставляют без патчей.
- **Пагинация/фильтры** (`?page=`, `?limit=`, `?sort=`, `?fields=`) → инъекции и mass assignment.
- **HATEOAS** (`_links`) — редко, но указывает на связанные ресурсы.

## Теория: GraphQL

**GraphQL** — единая точка входа (`POST /graphql`), где клиент сам описывает, какие поля ему нужны. Вместо множества эндпоинтов — один, а «запрос» — это тело с `query`/`mutation`.

```graphql
query {
  user(id: 42) { id email role }
}
```

Уязвимости GraphQL специфичны:

1. **Introspection** (`__schema`) — если включена, вы получаете всю схему: типы, поля, аргументы, мутации. Это карта API.
2. **Отсутствие авторизации на поле** — top-level запрос может быть защищён, а вложенное поле отдаёт чужие данные.
3. **Batching** — множество операций в одном запросе; помогает обходить rate-limit и брутить.
4. **Alias overloading** — много алиасов одного запроса для перебора/DoS.
5. **Injection в аргументах** — если резолверы конкатенируют строки (SQLi/NoSQLi внутри резолвера).
6. **Depth/complexity abuse** — рекурсивные связи (`user -> posts -> author -> posts...`) валят сервер.

## Теория: SOAP

**SOAP** — старый XML-протокол: один эндпоинт, `POST`, тело — XML с `Envelope`/`Body`, описание в **WSDL** (`?wsdl`). Уязвимости: **XXE** (см. `web-xxe`), **XML bomb**, injection в XML-полях, слабая аутентификация WS-Security. Если видите `Content-Type: text/xml` и `SOAPAction` — это SOAP.

## Инструменты: как найти API и документацию

Определить тип по ответу:

```bash
curl -s -i https://target.local/api/v1/health
curl -s -i -X POST https://target.local/graphql -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'
curl -s -i 'https://target.local/service?wsdl'
```

Поиск документации — это самое ценное на этапе разведки. Пробуйте типовые пути:

```bash
for p in swagger.json swagger/v1/swagger.json openapi.json api-docs v2/api-docs \
         .well-known/openapi.json graphql graphiql playground api/graphql; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://target.local/$p")
  echo "$code $p"
done
```

Лучше — через ffuf с wordlist API-путей (см. `web-tooling` и `web-recon-fuzzing`).

Извлечь схему GraphQL (если introspection включена):

```bash
curl -s -X POST https://target.local/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name kind fields{name}}}}"}' | jq .
```

Инструменты: **graphql-voyager** (визуализация схемы), **InQL** (Burp-расширение), **clairvoyance** (схема без introspection).

## Разобранный пример: от SPA-бандла к API

Шаг 1. Открываем приложение, DevTools → Network. Видим XHR к `https://api.target.local/v2/`.

Шаг 2. Ищем в JS-бандле все пути API:

```bash
curl -s https://target.local/static/js/app.js -o app.js
grep -oE '"/api/[a-zA-Z0-9_/{}-]+"' app.js | sort -u
```

Шаг 3. Находим `openapi.json`:

```bash
curl -s https://api.target.local/openapi.json | jq '.paths | keys'
```

Теперь у вас список всех эндпоинтов с параметрами. Дальше — тестирование авторизации и инъекций.

Шаг 4. Для GraphQL — включаем introspection и получаем мутации:

```bash
curl -s -X POST https://api.target.local/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{mutationType{fields{name args{name type{name}}}}}}"}' | jq .
```

Видим мутацию `updateUserRole` — прямой кандидат на BFLA/mass-assignment.

## Частые ошибки

- **Искать только UI-пути.** API живёт отдельно; ключ — JS-бандлы, `swagger`, мобильные клиенты.
- **Считать GraphQL «защищённым».** Отключённая introspection не мешает отправлять запросы по известным именам полей (clairvoyance их восстанавливает).
- **Забывать про старые версии.** `/v1/` рядом с `/v2/` часто не пропатчен.
- **Путать GraphQL-ошибки.** Ответ всегда `200 OK` с полем `errors` — не ориентируйтесь только на HTTP-код.
- **Игнорировать WSDL.** `?wsdl` открывает полное описание SOAP-сервиса со всеми операциями.
- **Слать массово.** Для перебора путей используйте ffuf с `-maxtime`; ручные циклы `for p in ...; do curl` — плохая практика (нагрузка и беспорядок).

## Полный разбор: GraphQL introspection → брут полей (с выводом)

Шаг 1. Проверяем, включена ли introspection:

```bash
curl -s -X POST https://api.target.local/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__typename}"}'
# {"data":{"__typename":"Query"}}
```

Шаг 2. Выгружаем типы и поля:

```bash
curl -s -X POST https://api.target.local/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name kind fields{name type{name kind ofType{name}}}}}}}"}' \
  | jq -r '.data.__schema.types[] | select(.kind=="OBJECT") | "\(.name): \(.fields|map(.name)|join(", "))"'
# User: id, username, email, role, passwordHash
# Query: user, users, adminPanel
# Mutation: updateUserRole, deleteUser, login
```

Шаг 3. Пробуем «дорогие» поля напрямую (часто авторизация на уровне типа, а не поля):

```bash
curl -s -X POST https://api.target.local/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{user(id:1){id username email role passwordHash}}"}'
# {"data":{"user":{"id":1,"username":"admin","role":"admin","passwordHash":"..."}}}
# -> утечка секретного поля
```

Шаг 4. Если introspection выключена, восстанавливаем схему по ошибкам и словарю (clairvoyance):

```bash
python3 clairvoyance.py -o schema.json -u https://api.target.local/graphql -w fieldnames.txt
```

Шаг 5. Пробуем мутации для эскалации (BFLA):

```bash
curl -s -X POST https://api.target.local/graphql -H 'Content-Type: application/json' \
  -d '{"query":"mutation{updateUserRole(userId:1,role:\"admin\"){ok}}"}'
```

## Reference-таблица: REST/GraphQL/SOAP — где какие баги

| Парадигма | Точки входа | Типовые уязвимости |
|-----------|-------------|--------------------|
| REST | `/api/vN/<res>/<id>` | BOLA/IDOR, mass assignment, инъекции, старая версия |
| REST | `?fields=`,`?expand=` | over-fetching приватных полей |
| GraphQL | `/graphql` (одна точка) | introspection, авторизация на уровне поля, batching/aliasing, depth DoS |
| GraphQL | мутации | BFLA, mass assignment |
| SOAP | `?wsdl`, `POST text/xml` | XXE, XML bomb, WS-Security слабости, injection в полях |
| Любая | документация | `/swagger.json`, `/openapi.json`, `/graphiql`, `?wsdl` |

## GraphQL: batching, aliasing, depth DoS, авторизация на уровне полей

- **Aliasing:** один запрос вызывает одно поле много раз под разными алиасами — обход rate-limit и брут:
  ```graphql
  { a0: login(user:"admin",pass:"1") a1: login(user:"admin",pass:"2") ... }
  ```
- **Batching (массив запросов):** сервер, принимающий `[{query:...},{query:...}]`, выполняет их пачкой — тот же обход лимитов.
- **Depth/complexity DoS:** рекурсивные вложенные поля (`user{friends{friends{...}}}`) кладут сервер; проверяйте лимиты глубины.
- **Авторизация на уровне поля:** тип защищён, а `passwordHash`/`role` — нет; перебирайте все поля типа.
- **Introspection off ≠ безопасно:** clairvoyance восстановит схему по suggestions/ошибкам.
- **GET-мутации:** `?query=mutation{...}` — CSRF-вектор.

## SOAP/WSDL: XXE и операционные уязвимости

```bash
curl -s 'https://target.local/service?wsdl' | head -40   # полное описание операций
```

- **XXE:** XML-парсер без запрета внешних сущностей → чтение файлов/SSRF (см. `web-xxe`).
- **XML bomb (billion laughs):** экспоненциальное раскрытие сущностей → DoS.
- **WS-Security:** слабая подпись/шифрование, replay, отсутствие timestamp-проверки.
- **Injection в полях:** значения SOAP-полей уходят в БД/систему — SQLi/командная инъекция.
- **WSDL как карта:** он перечисляет все операции и типы — не игнорируйте `?wsdl`.

## Что делать дальше / решение

1. **Определить парадигму** (REST/GraphQL/SOAP) по ответу/заголовкам.
2. **Найти документацию** (`swagger.json`, `openapi.json`, `graphiql`, `?wsdl`).
3. **GraphQL:** включить introspection или восстановить схему (clairvoyance), затем тестировать авторизацию **на уровне поля**.
4. **REST:** пройтись по всем ресурсам/версиям, проверить BOLA/mass assignment.
5. **SOAP:** проверить XXE, XML bomb, WS-Security.
6. **Зафиксировать** найденные эндпоинты и уязвимые операции как артефакт.

## OpenAPI/Swagger: как читать спеку и находить баги

Спецификация OpenAPI — лучшая карта API. Получив `openapi.json`/`swagger.json`:

```bash
curl -s https://api.target.local/openapi.json -o api.json
jq -r '.paths | to_entries[] | "\(.key)  [\(.value|keys|join(","))]"' api.json
# /users/{id}  [get,put,delete]
# /admin/users [get]
# /orders      [get,post]
```

Что искать в спеке:

- **Скрытые/админские пути** (`/admin`, `/internal`, `/debug`) — сразу проверить доступ.
- **Методы** — `PUT/PATCH/DELETE` на объектах (mass assignment, BFLA).
- **Параметры** — `sort`, `filter`, `fields`, `expand` (инъекции, over-fetching).
- **`security`/`securitySchemes`** — какие эндпоинты без auth (сравнить с фактическим поведением).
- **Схемы (`components/schemas`)** — все поля объектов; ищите `role`, `isAdmin`, `balance`, `password` → mass assignment.
- **`$ref`** — раскрывают связанные модели.

```bash
jq -r '.components.schemas.User.properties | keys[]' api.json
# id username email role isAdmin passwordHash
```

Если `isAdmin`/`role` есть в схеме, но не в UI — попробуйте передать их при регистрации/обновлении (mass assignment). Если эндпоинт без `security` — проверьте доступ без токена. Swagger UI (`/swagger-ui`, `/docs`) позволяет слать запросы прямо из браузера — удобно для быстрой проверки.

## Быстрый чек-лист по API

1. **Найти спеку:** `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphiql`, `?wsdl`.
2. **Инвентаризировать эндпоинты** (из спеки и JS-бандла), включая старые версии.
3. **Проверить авторизацию** на каждом: без токена, с чужим ID (BOLA), с низкой ролью (BFLA).
4. **Mass assignment:** передать `role`/`isAdmin`/`balance` в create/update.
5. **GraphQL:** introspection или clairvoyance; авторизация на уровне поля; batching/aliasing.
6. **SOAP:** `?wsdl`, XXE, XML bomb, WS-Security.
7. **Зафиксировать** найденные ручки и уязвимые операции как артефакт.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Чем REST отличается от GraphQL?"
  options:
    - "REST использует один эндпоинт, GraphQL — много"
    - "GraphQL использует один эндпоинт и клиент выбирает поля"
    - "REST работает только с XML"
    - "GraphQL не использует HTTP"
  answer: 1
  explanation: "GraphQL — единая точка входа, запрос описывает нужные поля."
- question: "Что даёт включённая introspection в GraphQL?"
  options:
    - "Ускоряет запросы"
    - "Раскрывает всю схему (типы, поля, мутации)"
    - "Включает кэширование"
    - "Защищает от инъекций"
  answer: 1
  explanation: "`__schema` отдаёт полную карту API."
- question: "По какому признаку узнать SOAP?"
  options:
    - "`Content-Type: application/json`"
    - "`Content-Type: text/xml` и `SOAPAction`"
    - "`Accept: text/event-stream`"
    - "`Content-Type: multipart/form-data`"
  answer: 1
  explanation: "SOAP — XML-конверт с заголовком `SOAPAction`; описание в WSDL."
- question: "Где чаще всего искать документацию REST API?"
  options:
    - "`/robots.txt`"
    - "`/swagger.json`, `/openapi.json`, `/api-docs`"
    - "`/favicon.ico`"
    - "`/sitemap.xml`"
  answer: 1
  explanation: "Спецификации OpenAPI/Swagger обычно отдаются по этим путям."
- question: "Почему GraphQL-ответ с ошибкой может прийти с кодом 200?"
  options:
    - "Это баг сервера"
    - "GraphQL кладёт ошибки в тело ответа в поле `errors`"
    - "Так работает кэш"
    - "Это означает успех"
  answer: 1
  explanation: "GraphQL возвращает `200` и JSON с полем `errors`; смотрите тело, а не только код."
```

## Где пригодится

- **CTF (Web):** задачи часто дают SPA/GraphQL; introspection и скрытые мутации — ключ к решению.
- **Bug bounty:** API-эндпоинты без UI, старые версии, BOLA — основной источник выплат.
- **Пентест:** инвентаризация API — обязательный этап; без неё покрытие тестирования неполное.
- **Работа (AppSec):** ревью OpenAPI-спеки и GraphQL-схемы на предмет избыточных полей — часть secure design review.
