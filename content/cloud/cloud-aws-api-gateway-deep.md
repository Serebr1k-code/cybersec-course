---
id: cloud-aws-api-gateway-deep
title: 'API Gateway deep: authorizers, usage-планы и Lambda-интеграции'
category: cloud
parent: cloud-aws-edge
difficulty: hard
order: 3
tags: [cloud, aws, api-gateway, authorizer, lambda, usage-plan]
prerequisites: [cloud-aws-deep]
useful_for:
  - 'Пентест AWS API'
  - 'Аудит serverless-бэкендов'
  - 'CTF cloud'
estimated_minutes: 45
summary: 'API Gateway как точка входа в бэкенды: как устроены методы и интеграции, чем опасны неполные authorizer-ы, как Lambda-интеграции дают доступ к роли, и как обходятся usage-планы и API-ключи.'
lab:
  kind: shell
  title: 'Практика: метод без авторизации'
  toolset: [core]
  workdir: /home/student/apigw
  files: [task.md, api-config.json, notes.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - "Повторение (`cloud-aws-deep`): сначала `head -n 5 api-config.json` — вернись к материалу предшествующего урока."
    - 'Изучи конфигурацию API: `cat api-config.json` — какие методы без авторизации?'
    - 'Флаг — в notes.md. Найди строку с nto: `grep nto notes.md` и запиши флаг в found.txt.'
---

## Вопрос, с которого всё начинается

У API есть авторизатор, который проверяет JWT на большинстве маршрутов. Но маршрут `GET /health` его не требует — а Lambda за ним имеет роль с доступом к базе. Ты дёргаешь `/health?q=<payload>`, и Lambda исполняет твой ввод от имени своей роли. Вопрос: как один незащищённый маршрут отдаёт всю роль, и что ещё скрыто в конфигурации API Gateway?

## Что такое API Gateway

API Gateway — управляемый шлюз перед бэкендами (Lambda, HTTP, AWS-сервисы). Он описывает ресурсы (пути), методы (GET/POST/...), интеграции (куда переслать) и авторизацию (authorizer). Каждый метод можно защитить или оставить открытым. Именно эта гранулярность — источник мисконфигов: один метод забыли закрыть, и он открывает доступ.

## Сквозной пример: метод без авторизации

Смотрим конфигурацию API:
```
$ aws apigateway get-method --rest-api-id abc123 --resource-id xyz --http-method GET
{
  "authorizationType": "NONE",
  "methodIntegration": {"type": "AWS_PROXY",
     "uri": "arn:aws:apigateway:...:lambda:path/.../functions:acme-api/invocations"}
}
```
`authorizationType: NONE` означает, что метод открыт. `AWS_PROXY` — интеграция с Lambda, где весь запрос уходит в функцию. Значит, любой может вызвать `acme-api`, а функция исполняется от имени своей роли. Если в коде функции есть инъекция (в SQL, команду, SSRF) — это доступ к тому, что видит роль.

## Authorizer-ы: что они проверяют

API Gateway поддерживает: IAM (SigV4), Cognito user pools, Lambda authorizer (кастомный) и JWT authorizer (HTTP API). Каждый настраивается на определённые маршруты. Типичные ошибки: авторизатор настроен на одни методы, но не на все; Lambda authorizer кэширует результат и путает пользователей; resource policy не ограничивает источник. Проверяй, какие методы реально требуют авторизацию, а какие — `NONE`.

## Lambda-интеграции и роль

При `AWS_PROXY` шлюз передаёт в Lambda весь запрос. Функция исполняется от имени execution role — именно она определяет, что можно. Поэтому атака на API Gateway чаще всего = атака на Lambda: SSRF, инъекция, доступ к переменным окружения. Если функция использует `event` (вход) без валидации, атакующий влияет на её поведение. Ищи открытые методы, которые доходят до функций с широкими ролями.

## Usage-планы и API-ключи

API-ключи и usage-планы ограничивают скорость и квоты, но НЕ являются аутентификацией. Ключ часто лежит в клиенте (JS, мобильное приложение) и виден любому. Не полагайся на него как на защиту: он лишь «лимитирует», а не «запрещает». Проверь, не отключён ли троттлинг и не равен ли лимит бесконечности.

## Resource policies и private API

Resource policy может ограничить доступ по source IP, VPC endpoint или principal. Если политика отсутствует или разрешает `*`, API открыт из интернета. Private API (через VPC endpoint) доступен только из VPC — но если endpoint открыт для чужого VPC, граница ломается. Проверяй и политику, и тип endpoint.

## WAF и защита API

На API Gateway можно навесить WAF (правила, rate-based). Он фильтрует по паттернам, но обходится кодированием и вариациями. WAF снижает шум, но не заменяет авторизацию на каждом методе. Если WAF стоит, а метод всё равно `NONE`, это лишь вопрос формулировки payload-а.

## Типовые мисконфиги API Gateway

| Мисконфиг | Последствие | Как искать |
|---|---|---|
| Метод с `authorizationType: NONE` | открытый доступ к Lambda | get-method по всем ресурсам |
| Lambda authorizer с кэшем | подмена пользователя | конфиг authorizer |
| API-ключ вместо аутентификации | обход (ключ в клиенте) | поиск ключа в JS |
| Resource policy `*` | доступ из интернета | get-rest-api policy |
| Lambda с широкой ролью | эскалация | execution role |
| Нет троттлинга | abuse/DoS | usage-планы |

<!-- lab -->

## Полный прогон: от маршрута к роли

Шаги. Первый: найти API (домен `execute-api`, фронтенд-бандл). Второй: перечислить ресурсы и методы (по поведению или через CLI). Третий: найти методы без авторизации. Четвёртый: изучить, какая Lambda за ними и что она делает. Пятый: найти инъекцию/SSRF в открытом методе. Шестой: получить данные/действия от имени роли. Седьмой: зафиксировать доступ.

## Инструменты и команды

Полезны: `aws apigateway get-rest-apis/get-resources/get-method`, `curl` для перебора методов, `ffuf` для поиска путей, анализ фронтенд-бандлов на ключи и базовый URL. Для HTTP API — `aws apigatewayv2 get-routes`. Для теста инъекций в Lambda — обычные web-техники (SQLi, SSRF, command injection).

## OPSEC и детект

Вызовы API Gateway логируются (CloudWatch access logs, execution logs). Обращения к `NONE`-методам с необычными payload-ами заметны. WAF фиксирует блокировки. Тихий сценарий: один вызов открытого метода, найденного по конфигу, без массового перебора. Помни: если включён X-Ray, видна вся цепочка до Lambda.

## Разведка без доступа

Без прав видно: базовый URL API (`execute-api`), пути из фронтенда, ошибки с именами функций. OPTIONS-запросы иногда раскрывают методы. Публичные репозитории содержат SAM/OpenAPI-спеки с описанием маршрутов. По этому строится карта API.

## Частые вопросы

API-ключ — это аутентификация? Нет, только квота. Все методы требуют авторизацию? Нет, часть бывает `NONE`. Опасна ли Lambda за открытым методом? Да, она исполняется от имени роли. Помогает ли WAF? Частично. Что если API private? Доступен только из VPC, но граница может быть открыта.

## Что не сработает

Если все методы защищены строгим authorizer-ом, обход не пройдёт. Если Lambda валидирует вход и не имеет широких прав, открытый метод не даёт многого. API-ключ с малым лимитом не остановит, но ограничит перебор. Resource policy с конкретным principal закроет анонимный доступ.

## Сценарий: незащищённый /health

Цепочка. Перебор путей находит `/health` с 200 без токена. За ним — Lambda, читающая параметр `q` и подставляющая его в запрос к DynamoDB (или в команду). Инъекция в `q` позволяет читать чужие данные. Роль функции имеет `dynamodb:*` на таблицу с пользователями. Так один `NONE`-метод превращается в чтение всей таблицы. Фиксируем: авторизация неполна.

## Практический чек-лист пентеста API Gateway

Порядок. Один: найти API и его базовый URL. Два: перечислить маршруты. Три: найти методы без авторизации. Четыре: изучить интеграцию (Lambda/HTTP). Пять: найти инъекцию в открытом методе. Шесть: оценить роль функции. Семь: проверить resource policy и endpoint. Восемь: оценить логи и WAF.

## Что мы теперь знаем

1. API Gateway защищает маршруты по-отдельности — один `NONE` открывает доступ.
2. Lambda-интеграции исполняются от имени execution role.
3. API-ключ — это квота, а не аутентификация.
4. Resource policy и тип endpoint определяют сетевую границу.
5. WAF снижает шум, но не заменяет авторизацию.

## Полный проход: перечисление методов и поиск `NONE`

Разберём аудит API Gateway по шагам с реальными ответами CLI. Начинаем с перечисления API в аккаунте:

```bash
$ aws apigateway get-rest-apis --query 'items[].{id:id,name:name}' --output table
------------
|  id  | name  |
------------
| a1b2 | acme  |
```

Шаг 2 — обходим ресурсы и для каждого метода смотрим `authorizationType`:

```bash
$ for r in $(aws apigateway get-resources --rest-api-id a1b2 --query 'items[].id' --output text); do
    for m in GET POST PUT DELETE; do
      t=$(aws apigateway get-method --rest-api-id a1b2 --resource-id $r --http-method $m \
            --query 'authorizationType' --output text 2>/dev/null)
      [ -n "$t" ] && echo "$r $m -> $t"
    done
  done
abc123 GET -> NONE
abc123 POST -> AWS_IAM
def456 GET -> CUSTOM
```

Метод `abc123 GET` открыт (`NONE`) — это цель. Шаг 3 — смотрим интеграцию:

```bash
$ aws apigateway get-integration --rest-api-id a1b2 --resource-id abc123 --http-method GET \
    --query 'uri' --output text
arn:aws:apigateway:eu-west-1:lambda:path/2015-03-31/functions/arn:aws:lambda:eu-west-1:123456789012:function:acme-api/invocations
```

Шаг 4 — определяем роль функции и её права:

```bash
$ aws lambda get-function-configuration --function-name acme-api \
    --query 'Role' --output text
arn:aws:iam::123456789012:role/acme-api-role
$ aws iam list-attached-role-policies --role-name acme-api-role \
    --query 'AttachedPolicies[].PolicyName' --output text
DynamoDBAccess
```

Теперь понятно: открытый `/health` доходит до Lambda с `DynamoDBAccess`. Дальше — стандартный тест инъекции в параметрах (`q`, `id`), которые функция передаёт в DynamoDB/команду.

## Таблица: типы авторизаторов и их подводные камни

| Тип | Как работает | Типичная ошибка |
|-----|--------------|-----------------|
| `NONE` | без проверки | метод случайно оставлен открытым |
| `AWS_IAM` | SigV4-подпись | у вызывающего есть `execute-api:Invoke` |
| `CUSTOM` (Lambda authorizer) | ваш код возвращает allow/deny | кэш TTL путает пользователей |
| `COGNITO_USER_POOLS` | проверка JWT Cognito | audience/issuer не проверены |
| `JWT` (HTTP API) | проверка JWT | issuer не зафиксирован |
| API-ключ + usage-plan | только квота | ключ утёк в клиентский бандл |

Ключевое: API-ключ — **не** авторизация; авторизация — это `AWS_IAM`/`CUSTOM`/`COGNITO_USER_POOLS`/`JWT`. Если метод открыт (`NONE`), никакая resource policy его не «закроет» от интернета, кроме явного `deny`.

## Ограничения и подводные камни

- **Lambda authorizer с кэшем.** `authorizerResultTtlInSeconds > 0` кэширует результат по ключу (по умолчанию — identity source); при общем источнике разные пользователи могут получить чужой allow. Ставьте `ttl=0` или включайте `identitySource` в ключ.
- **Proxy vs non-proxy.** В `AWS_PROXY` шлюз передаёт весь запрос и ждёт ответ от Lambda; в non-proxy маппинг задаётся шаблонами — там другая поверхность (VTL-инъекции, `$context`).
- **Resource policy не спасает от NONE.** Она ограничивает principal/IP, но при отсутствии политики метод доступен всем; при `Principal: "*"` — тоже.
- **Приватный API ≠ закрытый.** Private API доступен только через VPC endpoint, но если endpoint открыт для чужого VPC или `execute-api` interface endpoint разрешает чужой аккаунт, граница ломается.
- **WAF — не авторизация.** Правила фильтруют паттерны, но обходятся кодированием; метод `NONE` остаётся достижим, меняется лишь формулировка payload-а.
- **Логи.** Access/execution logs и X-Ray показывают всю цепочку; тихий сценарий — один вызов по найденному в конфиге методу, без массового перебора путей.

## Квиз

Проверь себя.

```quiz
- question: "Что означает `authorizationType: NONE`?"
  options:
    - "Метод открыт и не требует авторизации"
    - "Метод удалён"
    - "Метод кэшируется"
    - "Метод только для чтения"
  answer: 0
  explanation: "Такой метод вызывает бэкенд без проверки вызывающего."
- question: "От чьего имени исполняется Lambda за API Gateway?"
  options:
    - "От имени своей execution role"
    - "От имени анонимного пользователя"
    - "От имени root"
    - "Без прав"
  answer: 0
  explanation: "Функция действует с правами execution role, поэтому доступ к ней = доступ к её правам."
- question: "Является ли API-ключ аутентификацией?"
  options:
    - "Нет, это только квота/троттлинг"
    - "Да, это пароль"
    - "Да, это сертификат"
    - "Он шифрует трафик"
  answer: 0
  explanation: "Ключ часто утекает в клиент и не подтверждает личность."
- question: "Где искать методы без авторизации?"
  options:
    - "По поведению API и в конфигурации get-method"
    - "В DNS"
    - "В сертификате"
    - "В логах S3"
  answer: 0
  explanation: "Перебор и CLI показывают, какие методы отвечают без токена."
```

## Куда дальше

Следующий урок — EventBridge: события связывают сервисы, и ошибки политик шины позволяют чужим аккаунтам «вбрасывать» события. А пока главное: в API Gateway авторизация гранулярна, и одного открытого метода достаточно.

## Где пригодится

- Пентест AWS API и serverless.
- Аудит маршрутов и authorizer-ов.
- CTF-задачи категории cloud/AWS.
