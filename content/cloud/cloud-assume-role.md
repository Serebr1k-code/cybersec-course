---
id: cloud-assume-role
title: "Cross-account роли и confused deputy: цепочки доверия"
category: cloud
parent: cloud-privesc-iam
difficulty: expert
order: 3
tags: [cloud, aws, sts, assume-role, confused-deputy, cross-account, trust-policy]
prerequisites: [cloud-privesc-iam, cloud-aws-organizations]
useful_for:
  - "Эскалация между AWS-аккаунтами"
  - "Эксплуатация misconfigured trust policies"
  - "Понимание confused deputy и OIDC-доверия"
estimated_minutes: 40
summary: "Как работают cross-account роли, цепочки AssumeRole, ExternalId и confused deputy. Практические приёмы поиска и эксплуатации слабых trust policies."
---
## Зачем этот урок

AssumeRole — центральный механизм доверия в AWS. Роль не имеет постоянных ключей: чтобы ей воспользоваться, нужно «встать» на неё через `sts:AssumeRole`. Если trust policy роли слишком широка или допускает confused deputy — вы получаете её права. Понимание цепочек AssumeRole критично для lateral movement и cross-account атак.

## Механика AssumeRole

```bash
aws sts assume-role --role-arn arn:aws:iam::111122223333:role/Admin \
  --role-session-name pentest --duration-seconds 3600
```

Ответ содержит `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration`. Их подставляют в переменные окружения:

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

`get-caller-identity` — первый шаг: он показывает, кто вы теперь. Полезно сохранить креды в профиль:

```bash
aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID --profile assumed
aws configure set aws_session_token $AWS_SESSION_TOKEN --profile assumed
```

## Что искать

- Роли с `"Principal":"*"` или `"Principal":{"AWS":"*"}`.
- Отсутствие `sts:ExternalId`.
- Доверие к целым аккаунтам (`arn:aws:iam::123456789012:root`) — любой в том аккаунте может встать.
- Trust к сервисам с SSRF-поверхностью (lambda, ec2, ecs-tasks).
- Доверие к GitHub Actions OIDC без ограничения repo/branch.

```bash
aws iam list-roles --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}' \
  --output json | jq '.[] | select(.Trust.Statement[].Principal=="*")'
```

## Confused deputy

Классика: SaaS-сервис получает роль для доступа к вашему аккаунту. Если trust не требует ExternalId, другой клиент сервиса может заставить его обратиться к вашей роли. Решение — ExternalId. Атакующий ищет роли с `Condition` без ExternalId или с предсказуемым ExternalId (например, ID аккаунта клиента).

## Разобранный пример: GitHub Actions → AWS-роль

Trust policy с `token.actions.githubusercontent.com:sub` = `repo:org/*:*`. Тогда любой репозиторий организации (включая форк/PR) может встать на роль. Атакующий создаёт PR, модифицирует workflow и получает креды через `aws-actions/configure-aws-credentials`. Проверка:

```bash
aws iam get-role --role-name GitHubDeployRole \
  --query 'Role.AssumeRolePolicyDocument' --output json
```

Если `sub` содержит wildcard — уязвимо. Корректно: `repo:org/repo:ref:refs/heads/main`.

## Цепочки AssumeRole

A → B → C: роль A доверяет вам, B доверяет A, C доверяет B. Пройдя цепочку, вы получаете C. Инструмент pmapper строит граф:

```bash
pmapper --profile default graph create --include-all
pmapper --profile default query 'who can do sts:AssumeRole with arn:aws:iam::*:role/Admin'
pmapper --profile default query 'preset privesc *'
```

Также `cloudmapper`, `pacu` (модуль `iam__privesc_scan`), `weirdAAL`.

## Внешние принципалы

- Другой AWS-аккаунт (номер).
- SAML/OIDC-провайдер.
- Service principal (`ec2.amazonaws.com`, `lambda.amazonaws.com`).
- Anonymous (`"Principal":"*"` без Condition) — прямой публичный доступ.
- Federated principal с condition `:aud`/`:sub`.

## Частые ошибки

- Считать, что роль «недоступна», потому что нет ключей — ключи выдаются через AssumeRole.
- Забывать про `DurationSeconds` (максимум зависит от роли, до 12ч).
- Не проверять MFA-условия в trust.
- Игнорировать cross-account доверие к `root` — оно означает весь аккаунт.
- Путать identity-based и resource-based trust.
- Не перепроверять, что новая сессия реально имеет права (`get-caller-identity` + тестовый вызов).

## Что дальше / решение

Найдя роль с широким trust, встаньте на неё, вызовите `get-caller-identity`, перечислите права (`enumerate-iam`), ищите новые роли и цепочки. Для защиты — ExternalId, ограничение `sub` в OIDC, MFA, аудит trust-политик и запрет `Principal: *`.

## Виды STS-вызовов

| API | Назначение | Атакующий сценарий |
|-----|------------|--------------------|
| AssumeRole | встать на роль | lateral movement, privesc |
| AssumeRoleWithSAML | федерация SSO | обход MFA при слабом IdP |
| AssumeRoleWithWebIdentity | OIDC (GitHub, Google) | подмена sub/aud |
| GetFederationToken | временные креды | расширение сессии |
| GetSessionToken | MFA-сессия | обход MFA-условий |
| AssumeRoleWithWebIdentity | EKS IRSA | кража SA-токена |

## Разобранный пример: цепочка из трёх ролей

```bash
# 1. исходная роль
aws sts get-caller-identity
# {"Arn":"arn:aws:sts::111122223333:assumed-role/DevRole/user"}
# 2. DevRole доверяет BuildRole
aws sts assume-role --role-arn arn:aws:iam::111122223333:role/BuildRole \
  --role-session-name s1 --query 'Credentials' --output json > c1.json
export AWS_ACCESS_KEY_ID=$(jq -r .AccessKeyId c1.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .SecretAccessKey c1.json)
export AWS_SESSION_TOKEN=$(jq -r .SessionToken c1.json)
# 3. BuildRole доверяет AdminRole
aws sts assume-role --role-arn arn:aws:iam::111122223333:role/AdminRole \
  --role-session-name s2 --query 'Credentials' --output json > c2.json
# ...подставляем и проверяем
aws sts get-caller-identity
# {"Arn":"arn:aws:sts::111122223333:assumed-role/AdminRole/s2"}
```

## Аудит через CloudTrail

События `AssumeRole` содержат `requestParameters.roleArn`, `roleSessionName`, `sourceIPAddress`, `userIdentity`. Защитник ищет аномалии: сессии с подозрительных IP, роли, на которые «встают» из нетипичных мест.

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --max-results 20 --query 'Events[].CloudTrailEvent' --output text | jq -r '.requestParameters.roleArn'
```

## Инструменты

```bash
# pmapper — граф доверия и запросы
pmapper --profile default graph create --include-all
pmapper --profile default query 'who can do sts:AssumeRole with *'
# pacu — интерактивный фреймворк
pacu
> import_keys default
> run iam__enum_roles
> run iam__privesc_scan
# aws sts один-лайнер: перебрать роли и встать
aws iam list-roles --query 'Roles[].Arn' --output text | tr '\t' '\n' | while read r; do
  aws sts assume-role --role-arn "$r" --role-session-name t 2>/dev/null && echo "OK $r"; done
```

## OPSEC

- `role-session-name` виден в CloudTrail — не используйте «pentest»/«hack».
- `DurationSeconds` > 3600 требует `MaxSessionDuration` роли.
- Множественные AssumeRole подряд с одного IP — аномалия для GuardDuty.
- Ограничивайте регион и сервис для уменьшения шума.

## Практика: проверка OIDC-доверия

1. Найти OIDC-провайдер: `aws iam list-open-id-connect-providers`.
2. Посмотреть роли с `AssumeRoleWithWebIdentity` в trust.
3. Проверить условие `sub`/`aud` на wildcard.
4. Если wildcard — сформировать JWT от имени разрешённого провайдера (в рамках пентеста) и встать на роль.

## Частые ошибки (продолжение)

- Не проверять `MaxSessionDuration` — попытка 12ч сессии упадёт на роли с 1ч.
- Игнорировать `SourceIdentity` в CloudTrail.
- Забывать, что trust к `root` аккаунта = любой principal аккаунта с `sts:AssumeRole`.
- Не сбрасывать переменные окружения между сессиями (путаница в identity).

## Смежные техники

- **GetFederationToken**: если у вас есть `sts:GetFederationToken`, можно выпустить временные креды с subset прав — полезно для ограничения и для OPSEC.
- **AssumeRoleWithWebIdentity**: подмена `sub` при слабой проверке OIDC.
- **Instance profile hijack**: изменение роли инстанса через `iam:ReplaceIamInstanceProfileAssociation`.
- **UpdateAssumeRolePolicy**: если есть право менять trust роли — добавьте себя и встаньте.

```bash
aws iam update-assume-role-policy --role-name TargetRole \
  --policy-document file://new-trust.json
```

## Сопоставление с GCP/Azure

| AWS | GCP | Azure |
|-----|-----|-------|
| AssumeRole | impersonate service account | managed identity / OAuth |
| Trust policy | IAM binding + conditions | RBAC + federated credential |
| ExternalId | condition | federated credential subject |
| OIDC federation | Workload Identity | federated identity credential |

В GCP имперсонация требует `roles/iam.serviceAccountTokenCreator` или `serviceAccountUser`; в Azure — право на managed identity или federated credential.

## Чек-лист охоты за AssumeRole

1. Перечислить все роли: `aws iam list-roles`.
2. Для каждой выгрузить trust: `get-role --query Role.AssumeRolePolicyDocument`.
3. Найти `Principal: *`, отсутствие ExternalId, wildcard в OIDC `sub`.
4. Найти роли с cross-account доверием к `root`.
5. Проверить `sts:AssumeRole` в собственных правах.
6. Построить граф (pmapper) и найти путь к админ-роли.
7. Встать на роль, зафиксировать `get-caller-identity`.

## Квиз

```quiz
- question: "Что означает Principal arn:aws:iam::111122223333:root в trust policy?"
  options:
    - "Только root-пользователь аккаунта 111122223333"
    - "Любой принципал аккаунта 111122223333, чья IAM-политика разрешает sts:AssumeRole"
    - "Все аккаунты AWS"
    - "Сервис EC2"
  answer: 1
  explanation: ":root в Principal означает аккаунт целиком, а не конкретного root-пользователя."
- question: "Чем опасна trust policy с Principal равным звездочке?"
  options:
    - "Ничем"
    - "Любой принципал может ассумировать роль"
    - "Она даёт только чтение"
    - "Она требует MFA"
  answer: 1
  explanation: "Principal * означает, что роль может ассумировать кто угодно (с учётом условий)."
- question: "Что такое confused deputy в контексте OIDC-доверия GitHub Actions?"
  options:
    - "Ошибка в TLS"
    - "Роль проверяет только aud, но не sub, поэтому любой репозиторий получает доступ"
    - "Слишком короткий пароль"
    - "Отсутствие шифрования"
  answer: 1
  explanation: "Без проверки sub любое совпадающее по aud/OIDC приложение получает роль."
- question: "Какой инструмент строит граф путей AssumeRole в AWS?"
  options:
    - "TruffleHog"
    - "PMapper (principalmapper)"
    - "sqlmap"
    - "Wireshark"
  answer: 1
  explanation: "PMapper анализирует IAM-политики и находит пути эскалации/ассумирования."
- question: "Почему право iam:PassRole может вести к выполнению кода под другой ролью?"
  options:
    - "Оно даёт root"
    - "Оно позволяет передать роль сервису (Lambda/EC2/Glue), который исполнит код от её имени"
    - "Оно шифрует данные"
    - "Оно не связано с ролями"
  answer: 1
  explanation: "PassRole передаёт существующую роль сервису, который затем действует с её правами."
```

## Где пригодится

- **Пентест AWS** — межаккаунтная эскалация.
- **Red team** — построение цепочек доверия.
- **Bug bounty** — облачные приложения с OIDC-интеграциями.
- **IR/Blue team** — детект аномальных AssumeRole/AssumeRoleWithWebIdentity.
- **DevSecOps** — ужесточение trust policies и ExternalId.
