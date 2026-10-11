---
id: cloud-api-gateway
title: "API Gateway и WAF: обход, инъекции, авторизация"
category: cloud
parent: cloud-network-deep
difficulty: medium
order: 2
tags: [cloud, api-gateway, waf, authorizer, apim, apigee, bypass]
prerequisites: [cloud-network-deep, cloud-serverless]
useful_for:
  - "Пентест публичных API в облаке"
  - "Обход авторизаторов и WAF"
  - "Поиск ошибок маршрутизации API"
estimated_minutes: 45
summary: "Как устроены API Gateway (AWS), API Management (Azure) и Apigee/API Gateway (GCP), как искать методы без авторизации, обходить авторизаторы и WAF и находить расхождения между шлюзом и бэкендом."
---

## Зачем этот урок

Облачный API Gateway — это публичная дверь к бэкенду: Lambda, контейнерам, микросервисам. AWS API Gateway, Azure API Management (APIM) и GCP Apigee/API Gateway публикуют внутренние сервисы в интернет. Атакующий ищет здесь три вещи: **методы без авторизации**, **слабую проверку токенов** и **расхождения между шлюзом и бэкендом** (path confusion, request smuggling), которые позволяют обойти защиту. Плюс WAF перед API часто настроен на сигнатуры и легко обходится вариациями кодирования. Этот урок — про разведку API Gateway, поиск ошибок авторизации и обход WAF.

## Как устроены API Gateway и WAF

- **AWS API Gateway (REST/HTTP/WebSocket).** Ресурсы и методы (`GET /users`), интеграции (Lambda, HTTP, AWS-сервисы), **authorizers** (IAM, Cognito, Lambda custom), usage plans и API keys, resource policies (IP/VPCE), stage variables.
- **Azure API Management (APIM).** Products, subscriptions (subscription keys), policies (XML-пайплайн), backends, JWT validation, rate limit. Может «скрывать» реальные пути.
- **GCP Apigee / API Gateway / Cloud Endpoints.** Proxy, quotas, API keys, JWT validation, ESPv2.
- **WAF.** AWS WAF (rules, managed rule groups), Azure WAF (Front Door/App Gateway), Cloud Armor (GCP). Работает по сигнатурам и эвристикам.

Ключевые слабости:

- Метод/ресурс опубликован без authorizer (`authorizationType: NONE`).
- Authorizer проверяет наличие токена, но не его подпись/аудиторию.
- API key в клиентском коде (мобильное/веб) — не секрет.
- Расхождение нормализации пути: шлюз проверяет `/admin`, а бэкенд резолвит `/admin/` или `//admin`, `/admin%2f`.
- WAF-сигнатуры обходятся двойным кодированием, Unicode, комментариями, регистром.
- Отсутствие проверки метода: `OPTIONS`/`HEAD`/`TRACE` могут пройти мимо правил.

## Инструменты и команды

Разведка AWS:

```bash
aws apigateway get-rest-apis --query 'items[].{Id:id,Name:name}'
aws apigateway get-resources --rest-api-id <id> --query 'items[].{Path:path,Methods:resourceMethods}'
# Методы без авторизации
aws apigateway get-method --rest-api-id <id> --resource-id <rid> --http-method GET \
  --query 'authorizationType'
# NONE означает отсутствие авторизатора
```

Разведка Azure APIM:

```bash
az apim list --query '[].{Name:name,RG:resourceGroup,URL:gatewayUrl}'
az apim api list --service-name myapim -g myrg --query '[].{Name:name,Path:path,ServiceUrl:serviceUrl}'
# Subscription keys / products
az apim product list --service-name myapim -g myrg
```

Разведка GCP:

```bash
gcloud api-gateway gateways list
gcloud api-gateway api-configs list --api=myapi
```

Фаззинг путей и методов (с учётом auth):

```bash
# Методы без токена
ffuf -u https://api.example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
  -mc 200,201,401,403 -H "Authorization: Bearer $TOKEN"

# Path confusion: разные нормализации
for p in "/admin" "/admin/" "//admin" "/./admin" "/%2e/admin" "/admin%2f" "/Admin"; do
  echo -n "$p -> "; curl -s -o /dev/null -w "%{http_code}\n" "https://api.example.com$p" -H "Authorization: Bearer $TOKEN"
done
```

WAF-обход (примеры):

```bash
# Двойное кодирование
curl "https://api.example.com/item?id=1%2527%2520OR%25201=1"
# Unicode/полноширинный
curl "https://api.example.com/item?id=1%EF%BC%87%20OR%201=1"
# Разный регистр ключевых слов
curl "https://api.example.com/item?id=1 uNiOn SeLeCt 1,2,3"
```

## Разобранный пример: обход авторизатора и доступ к бэкенду

Сценарий: REST API в AWS API Gateway, методы защищены Cognito authorizer, но есть бэкенд-сервис, доступный напрямую.

Шаг 1 — перечисляем методы и их authorizationType:

```bash
aws apigateway get-resources --rest-api-id abc123 \
  --query 'items[].{Path:path,Methods:resourceMethods}' --output json
# {"Path":"/orders","Methods":{"GET":{"authorizationType":"COGNITO_USER_POOLS"},
#                              "POST":{"authorizationType":"NONE"}}}
```

Метод `POST /orders` — **без авторизации**. Это прямая находка.

Шаг 2 — находим интеграцию и, возможно, backend URL:

```bash
aws apigateway get-integration --rest-api-id abc123 --resource-id rid --http-method POST \
  --query '{Type:type,Uri:uri}'
# {"Type":"HTTP_PROXY","Uri":"https://internal-api.example.com/orders"}
```

Шаг 3 — пробуем бэкенд напрямую. Если он доступен из интернета (misconfig), шлюз и его WAF обойдены:

```bash
curl -s https://internal-api.example.com/orders -X POST -d '{"id":1}'
```

Шаг 4 — path confusion. Если бэкенд нормализует путь иначе, чем шлюз, можно добраться до «скрытых» ресурсов:

```bash
curl -s "https://api.example.com/admin" -H "Authorization: Bearer $TOKEN"          # 403 (WAF/authorizer)
curl -s "https://api.example.com/admin/" -H "Authorization: Bearer $TOKEN"         # 200 (обход)
curl -s "https://api.example.com/orders/../admin" -H "Authorization: Bearer $TOKEN" # 200
```

Шаг 5 — если authorizer — Lambda, проверьте, что он валидирует: подпись JWT, `aud`, `iss`, `exp`. Часто проверяется только наличие токена, и поддельный/чужой токен проходит.

Шаг 6 — эксплуатация найденного доступа: чтение/изменение данных, вызов внутренних функций. Записывайте метод, путь и результат.

## Варианты атак и обходы

- **`authorizationType: NONE`.** Метод без авторизатора — самый частый баг.
- **Weak JWT validation.** Authorizer проверяет формат, но не подпись; или принимает любой `aud`.
- **API key в клиенте.** Ключ из мобильного/веб-кода — не секрет; ищите его и используйте.
- **Stage variables и environments.** `dev`/`staging` stage может быть менее защищён, чем `prod`.
- **Resource policy bypass.** Политика разрешает только по IP/VPCE; если вы внутри сети — обходите.
- **WAF bypass.** Двойное кодирование, Unicode, `/**/`, смена регистра, HTTP/2 smuggling.
- **Request smuggling.** Расхождение `Content-Length`/`Transfer-Encoding` между шлюзом и бэкендом.
- **Path traversal к backend.** `/orders/../admin`, `%2e%2e`, двойные слэши.
- **CORS misconfig.** `Access-Control-Allow-Origin: *` с credentials — утечка через браузер.
- **GraphQL на шлюзе.** Introspection, batch-запросы, обход depth-limit.

## Частые ошибки и подводные камни

- **Проверять только `GET`.** POST/PUT/DELETE/OPTIONS могут быть без авторизации.
- **Считать API key защитой.** Ключ идентифицирует проект, а не пользователя; он утекает.
- **Игнорировать stages.** У API несколько stage с разными настройками.
- **Путать 401 и 403.** 401 — нет аутентификации, 403 — нет прав; путь обхода разный.
- **Не проверять прямой доступ к backend.** Часто бэкенд не изолирован.
- **Перебирать WAF «в лоб».** Без понимания правила это шум; анализируйте ответы и стройте гипотезы.

## Защита и детект

- **Явные authorizer на каждый метод.** Никаких `NONE` для непубличных ресурсов.
- **Строгая валидация JWT.** Подпись, `iss`, `aud`, `exp`, `nbf`.
- **Единая нормализация пути** между шлюзом и бэкендом; бэкенд не доступен напрямую.
- **WAF с актуальными правилами** и логированием; не полагайтесь только на сигнатуры.
- **Детект.** CloudWatch Logs/access logs API Gateway, AWS WAF logs, Azure APIM analytics, Cloud Armor logs. Алерты на 403/401 всплеск, на необычные пути, на вызовы без токена, на аномальные User-Agent.
- **Rate limiting и quotas** для ограничения перебора.

## WAF: как он работает и как его обходят

WAF — это набор правил, которые инспектируют запрос (URL, заголовки, тело, cookies) и блокируют подозрительное. AWS WAF использует правила с условиями и managed rule groups (AWSManagedRulesCommonRuleSet, SQLiRuleSet и др.); Azure WAF — OWASP CRS; Cloud Armor — выражения и предопределённые правила. Ключевое ограничение: WAF работает по **сигнатурам и эвристикам**, а не по смыслу, поэтому обходится вариациями представления того же запроса.

Классы обходов:

- **Кодирование.** Двойное URL-кодирование (`%2527` → `%27` → `'`), смешение hex/Unicode (`%u0027`), UTF-8 overlong. WAF декодирует один раз, бэкенд — снова.
- **Разбиение.** `/**/` между ключевыми словами SQL, `un/**/ion`, комментарии `--`, `#`.
- **Регистр.** `uNiOn SeLeCt` — некоторые сигнатуры регистрозависимы.
- **Полноширинные символы.** `＇` (U+FF07) вместо `'` — бэкенд нормализует, WAF нет.
- **Разные транспорты.** Тело как `multipart/form-data` вместо `application/x-www-form-urlencoded`, JSON вместо query.
- **HTTP/2 и smuggling.** Расхождения парсинга между WAF и бэкендом.
- **Параметры-дубликаты.** `?id=1&id=1' OR 1=1` — WAF проверяет первое значение, бэкенд — последнее.
- **Заголовки.** Инъекция через `X-Forwarded-For`, `Referer`, cookies, которые WAF не проверяет.
- **Обход по пути.** WAF-правило на `/api/`, но бэкенд принимает `/api//`, `/api/.`, `/api/..;/`.

Практический подход: определите, что именно блокируется (сравнивайте ответы `403` vs `400` vs нормальный), и варьируйте **одну** характеристику за раз. Инструменты: `wafw00f` для фингерпринта, `ffuf` с кастомными пейлоадами, `nuclei` с тегами `waf`.

## Практический чек-лист проверки API Gateway

1. Перечислите все API/сервисы и их stage/environment.
2. Для каждого метода выпишите `authorizationType`/политику — ищите `NONE`.
3. Проверьте, валидируется ли JWT полностью (подпись, `aud`, `iss`, `exp`).
4. Найдите API keys/subscription keys в клиентском коде и проверьте их права.
5. Проверьте прямой доступ к backend-URL (обход шлюза).
6. Протестируйте path confusion: `/x`, `/x/`, `//x`, `/./x`, `/x%2f`, регистр.
7. Проверьте методы OPTIONS/HEAD/TRACE и их поведение.
8. Оцените WAF: фингерпринт, затем точечные обходы.
9. Проверьте CORS: `Access-Control-Allow-Origin` с credentials.
10. Проверьте rate limiting и лимиты (можно ли перебирать).

Этот порядок ведёт от «что опубликовано» к «как это обойти», покрывая типовые ошибки конфигурации.

## Логирование и заметность

API Gateway логирует запросы по-разному: AWS — access logging (в CloudWatch/S3) и execution logging (CloudWatch Logs), Azure APIM — analytics и Application Insights, GCP — Cloud Logging. Эти логи содержат путь, метод, статус, User-Agent, иногда заголовки и IP. Для OPSEC это означает, что все ваши пробы path confusion и WAF-обходы останутся в логах. AWS WAF тоже логирует заблокированные запросы (`waf-logs`), поэтому агрессивный фаззинг виден. Практические соображения: используйте один-два точечных запроса вместо широкого ffuf там, где нужна тишина; помните, что 403-всплеск — сигнал для SOC. С другой стороны, если логи утекают в бакет с доступом у вас, они сами становятся источником разведки (пути, параметры, токены в query). При пентесте фиксируйте, включены ли логи и куда они пишутся — это часть оценки защищённости.

## Что дальше / решение

API Gateway — это фасад, и ошибки фасада открывают бэкенд. Начните с полного перечисления ресурсов и методов, ищите `NONE`, слабые authorizer и доступ к бэкенду напрямую. Затем — path confusion и WAF-обход. Найденный доступ эксплуатируйте и документируйте. Если API защищён корректно, переходите к бизнес-логике и инъекциям внутри разрешённых методов. Записывайте каждый обойдённый контроль как отдельную находку с точным запросом и ответом.

## Квиз

```quiz
- question: "Что означает authorizationType: NONE у метода API Gateway?"
  options:
    - "Метод не требует авторизации"
    - "Метод отключён"
    - "Метод доступен только из VPC"
    - "Метод использует API key"
  answer: 0
  explanation: "NONE означает отсутствие авторизатора — метод публичный."
- question: "Что такое path confusion в контексте шлюза?"
  options:
    - "Расхождение нормализации пути между шлюзом и бэкендом"
    - "Ошибка в DNS"
    - "Смена TLS"
    - "Отключение WAF"
  answer: 0
  explanation: "Разные нормализации позволяют обойти правила, проверяющие другой путь."
- question: "Почему API key в мобильном приложении не является секретом?"
  options:
    - "Он извлекается из клиента и идентифицирует проект, а не пользователя"
    - "Он шифруется"
    - "Он одноразовый"
    - "Он хранится в HSM"
  answer: 0
  explanation: "Ключ доступен клиенту, поэтому его легко извлечь и злоупотребить."
- question: "Какой типовой обход WAF используется?"
  options:
    - "Двойное кодирование и Unicode-вариации"
    - "Отключение TLS"
    - "Смена IP"
    - "Использование GET вместо POST"
  answer: 0
  explanation: "Разные кодировки обходят сигнатурные правила WAF."
```

## Где пригодится

- **Пентест:** публичные API и их авторизация.
- **Bug bounty:** обход авторизаторов и WAF.
- **Red team:** доступ к внутренним сервисам через шлюз.
- **Blue team:** аудит конфигураций API Gateway и WAF-логов.
