---
id: cloud-cross-account
title: "Многоуровневые cross-account цепочки и межпровайдерное доверие"
category: cloud
parent: cloud-cross-deep
difficulty: expert
order: 2
tags: [cloud, aws, sts, assume-role, confused-deputy, cross-account, trust-policy]
prerequisites: [cloud-cross-deep, cloud-assume-role]
useful_for:
  - "Эскалация между облачными аккаунтами"
  - "Эксплуатация слабых trust-политик"
  - "Понимание confused deputy"
estimated_minutes: 50
summary: "Cross-account доверие и confused deputy: AssumeRole, trust policies, условия (ExternalId, PrincipalOrgID) и цепочки ролей между аккаунтами. Как из одного аккаунта добраться до другого."
---
Этот урок — про **цепочки** cross-account доверия и **межпровайдерные** переходы. Механику
`sts:AssumeRole`, поиск слабых trust-политик и базовый confused deputy мы разбираем в отдельном
уроке `cloud-assume-role`; здесь считаем, что вы уже умеете «встать» на роль и проверить себя
через `get-caller-identity`. Задача этого урока — научиться строить многоуровневые маршруты
A → B → C между аккаунтами, обходить условия trust и переносить приёмы на GCP и Azure.

## Зачем нужны цепочки между аккаунтами

Современная облачная инфраструктура разбита на множество аккаунтов: prod, dev, shared-services,
security, sandbox. Между ними настроено доверие — роли одного аккаунта доверяют ролям другого,
сервисам и внешним IdP. Один слабый trust-линк редко даёт сразу прод; чаще атакующий собирает
**цепочку**: встаёт на роль в dev, оттуда на shared-services, оттуда на prod. Каждый отдельный
шаг выглядит «легитимно» для защитников, потому что использует штатный `AssumeRole`.

## Граф доверия: узлы и рёбра

Моделируйте облако как направленный граф. Узлы — принципалы (пользователи, роли, сервисы,
сервисные аккаунты, managed identities). Рёбра — право «принять» другой принципал.

| Ребро | AWS | GCP | Azure |
|---|---|---|---|
| Принятие роли | `sts:AssumeRole` | `iam.serviceAccountTokenCreator` | federated credential |
| Имперсонация | AssumeRole | `iam.serviceAccounts.getAccessToken` | managed identity |
| Внешний IdP | OIDC/SAML provider | Workload Identity Federation | federated credential |
| Resource-based | S3/KMS/SQS policy | bucket/SA IAM policy | RBAC scope |

Ключевые рёбра, которые ищем: роль доверяет `root` другого аккаунта; роль доверяет сервису с
SSRF-поверхностью; OIDC-условие содержит wildcard; resource-based policy открыта внешнему
принципалу.

## Построение цепочек ролей

`pmapper` строит граф и отвечает на вопросы «кто может принять кого». Это самый быстрый способ
увидеть маршрут до административной роли.

```bash
pmapper --profile default graph create --include-all
# кто может встать на Admin в любом аккаунте
pmapper --profile default query 'who can do sts:AssumeRole with arn:aws:iam::*:role/Admin'
# пресеты эскалации
pmapper --profile default query 'preset privesc *'
```

Ручная проверка одной роли:

```bash
aws iam get-role --role-name cross-account-role \
  --query 'Role.AssumeRolePolicyDocument' --output json
# {"Statement":[{"Effect":"Allow",
#   "Principal":{"AWS":"arn:aws:iam::111122223333:root"},
#   "Action":"sts:AssumeRole"}]}
```

`Principal: arn:aws:iam::111122223333:root` — это **весь** аккаунт, а не только root-пользователь:
любой принципал там с правом `sts:AssumeRole` может встать на эту роль. Это самое частое ребро
цепочки.

## Обход условий в trust-политике

Условия (`Condition`) — единственное, что отделяет слабый trust от защищённого. Разбираем типовые.

- **ExternalId** — секрет, который должен предъявить внешний аккаунт. Если он отсутствует или
  предсказуем (равен номеру аккаунта клиента, встречается в документации/логах) — доверие
  обходится.
- **aws:PrincipalOrgID** — доверие ограничено организациями. Если ваш аккаунт в той же AWS
  Organization (например, купленный/слитый бизнес-юнит) — условие проходит.
- **aws:SourceArn / aws:SourceAccount** — ограничивают, откуда пришёл вызов. Если `SourceAccount`
  указывает на контролируемый вами аккаунт — условие проходит.
- **MFA** — trust может требовать MFA. Обход: у вас уже есть MFA-сессия, или проверка стоит только
  на части ролей.
- **`sts:RoleSessionName` / теги сессии** — иногда условия привязаны к имени сессии; подберите
  подходящее.

```bash
# Найти роли с Condition, но без ExternalId
aws iam list-roles --query 'Roles[].{N:RoleName,T:AssumeRolePolicyDocument}' --output json \
 | jq '.[] | select(.T.Statement[].Condition == null) | .N'
```

## Resource-based policies и cross-account

Cross-account доступ бывает не только через AssumeRole, но и через resource-based policy. Это
«короткое ребро»: не нужно принимать роль — достаточно, чтобы политика ресурса доверяла вашему
принципалу напрямую.

```bash
# S3-бакет доверяет внешнему аккаунту
aws s3api get-bucket-policy --bucket cross-account-bucket | jq .
# KMS-ключ
aws kms get-key-policy --key-id <id> --policy-name default | jq .
# SQS / SNS / Secrets Manager
aws sqs get-queue-attributes --queue-url <url> --attribute-names Policy
```

Ищите `Principal` с внешним аккаунтом без `Condition`, особенно на бакетах с чувствительными
данными и на KMS-ключах (расшифровка чужих секретов).

## Cross-account через сервис-принципалы и SSRF

Роль может доверять сервису (`ec2.amazonaws.com`, `lambda.amazonaws.com`, `ecs-tasks`). Тогда
принять её можно, захватив инстанс/функцию с этой ролью. Связка с SSRF/RCE:

```bash
# с инстанса с ролью — получить временные креды
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/RoleName
# затем от имени роли
aws sts get-caller-identity
```

Если роль умеет `sts:AssumeRole` в другой аккаунт — SSRF превращается в cross-account прыжок.
Сервис-принципал — это ребро «сервис → роль», и его часто недооценивают.

## Межпровайдерное доверие: GCP

В GCP границы проектов пересекают через имперсонацию сервисных аккаунтов и Workload Identity
Federation.

```bash
# может ли наш SA имперсонировать чужой SA?
gcloud iam service-accounts get-iam-policy sa@other-project.iam.gserviceaccount.com
# если у нас roles/iam.serviceAccountTokenCreator:
gcloud auth print-access-token \
  --impersonate-service-account=sa@other-project.iam.gserviceaccount.com
# Workload Identity Federation: проверить провайдера и условия
gcloud iam workload-identity-pools providers describe PROVIDER \
  --workload-identity-pool=POOL --location=global
```

Ключевые права: `roles/iam.serviceAccountTokenCreator` (имперсонация) и
`roles/iam.workloadIdentityUser` (федерация). Слабое условие `attribute.sub` (например,
`assertion.repository_owner == '*'`) — confused deputy: любой внешний workflow получает токен.

## Межпровайдерное доверие: Azure

В Azure переход между тенантами/подписками идёт через managed identities и federated credentials
приложений.

```bash
az identity list --query '[].{Name:name,PrincipalId:principalId}'
az ad app federated-credential list --id <appId>
# выдать роль managed identity на чужой scope
az role assignment create --assignee <principalId> --role Contributor --scope <scope>
```

Federated credential приложения позволяет внешним workload'ам (GitHub Actions, Kubernetes)
принимать identity. Слабое условие (`subject` = любой repo/ref) — прямой путь к confused deputy.

## Разобранный пример: цепочка через три аккаунта

Сценарий: наш аккаунт 111122223333 имеет право принять `DevRole` в 222233334444; `DevRole`
доверяет `BuildRole` в 333344445555; `BuildRole` доверяет `AdminRole` в 444455556666.

```bash
# шаг 1: DevRole
aws sts assume-role --role-arn arn:aws:iam::222233334444:role/DevRole \
  --role-session-name s1 --query 'Credentials' --output json > c1.json
export AWS_ACCESS_KEY_ID=$(jq -r .AccessKeyId c1.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .SecretAccessKey c1.json)
export AWS_SESSION_TOKEN=$(jq -r .SessionToken c1.json)
aws sts get-caller-identity
# {"Account":"222233334444","Arn":"arn:aws:sts::222233334444:assumed-role/DevRole/s1"}

# шаг 2: BuildRole (из assumed role — role chaining)
aws sts assume-role --role-arn arn:aws:iam::333344445555:role/BuildRole \
  --role-session-name s2 --query 'Credentials' --output json > c2.json
# подставляем, проверяем
aws sts get-caller-identity
# {"Account":"333344445555","Arn":"arn:aws:sts::333344445555:assumed-role/BuildRole/s2"}

# шаг 3: AdminRole
aws sts assume-role --role-arn arn:aws:iam::444455556666:role/AdminRole \
  --role-session-name s3 --query 'Credentials' --output json > c3.json
# подставляем
aws sts get-caller-identity
# {"Account":"444455556666","Arn":"arn:aws:sts::444455556666:assumed-role/AdminRole/s3"}
```

Каждый шаг — обычный `AssumeRole`; защитник видит три «нормальных» вызова в разных аккаунтах.
Учтите ограничение **role chaining**: сессия, полученная через AssumeRole, живёт не дольше
исходной; планируйте длительность и порядок шагов.

## Детект и защита

- Использовать `ExternalId` для всех третьих сторон; не доверять `root` без условий.
- Ограничивать trust через `aws:PrincipalOrgID` и явные `SourceArn`/`SourceAccount`.
- Требовать MFA для чувствительных `AssumeRole`.
- Ревьюить resource-based policies на внешних принципалов.
- Мониторить `sts:AssumeRole` в CloudTrail: алертить на кросс-аккаунтные вызовы и цепочки
  (`assumed-role` в `userIdentity`).
- Для GCP/Azure — ограничивать `attribute.sub`/`subject` в федерации и права имперсонации.

## Частые ошибки

- Считать `Principal: root` «только root» — это весь аккаунт.
- Игнорировать resource-based policies, проверяя лишь trust-роли.
- Не проверять условия trust (ExternalId, OrgID, SourceAccount).
- Забывать про role chaining и лимит длительности сессии.
- Не переносить модель на GCP/Azure, хотя доверие там устроено иначе.

## Что дальше / решение

1. Постройте граф доверия (`pmapper graph create`), найдите маршрут до админ-роли.
2. Проверьте условия trust: ExternalId, OrgID, SourceArn, MFA.
3. Пройдите цепочку пошагово, фиксируя аккаунт и принципал на каждом шаге.
4. Ищите «короткие» рёбра: resource-based policies и сервис-принципалы (SSRF).
5. Перенесите модель на GCP (SA impersonation, WIF) и Azure (managed identity, federated
   credentials).

Дальше — `cloud-cross-deep` (SSRF-цепочки к облачным API) и `cloud-privesc-iam` (эскалация
внутри полученного аккаунта).

## Квиз

```quiz
- question: "Что означает Principal: arn:aws:iam::111122223333:root в trust policy?"
  options:
    - "Любой принципал этого аккаунта с правом sts:AssumeRole"
    - "Только root-пользователь"
    - "Никто"
    - "Все аккаунты AWS"
  answer: 0
  explanation: "root в Principal означает аккаунт целиком, а не только root-пользователя."
- question: "Зачем нужен ExternalId?"
  options:
    - "Защита от confused deputy (подтверждение, что запрос от нужного клиента)"
    - "Шифрование"
    - "Ускорение"
    - "MFA"
  answer: 0
  explanation: "ExternalId доказывает, что AssumeRole инициирован правильной стороной."
- question: "Какое условие ограничивает доверие организацией?"
  options:
    - "aws:PrincipalOrgID"
    - "aws:SourceVpc"
    - "aws:RequestedRegion"
    - "aws:CurrentTime"
  answer: 0
  explanation: "PrincipalOrgID ограничивает принципалов рамками организации."
- question: "Где ещё есть cross-account доверие кроме ролей?"
  options:
    - "Resource-based policies (S3, KMS, SQS) и federation"
    - "Только в IAM-пользователях"
    - "Только в CloudTrail"
    - "Только в VPC"
  answer: 0
  explanation: "Ресурсные политики и федерация тоже задают доверие."
```

## Где пригодится

- **Red team:** латеральное движение между аккаунтами.
- **Пентест AWS:** анализ trust-политик.
- **Blue team:** hardening доверия.
- **Сертификация:** AWS Security — Specialty.
