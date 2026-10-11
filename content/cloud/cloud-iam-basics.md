---
id: cloud-iam-basics
title: "IAM: пользователи, роли и политики — как читать права в облаке"
category: cloud
parent: cloud-foundations-security
difficulty: easy
order: 1
tags: [cloud, iam, aws, policy, json, access-control]
prerequisites: [cloud-fundamentals]
useful_for:
  - "Анализ любой облачной политики доступа"
  - "Понимание, что можно сделать с найденным ключом"
  - "Основа для эскалации привилегий (cloud-privesc-iam)"
estimated_minutes: 30
summary: "IAM — сердце облачной безопасности. Разбираем сущности (пользователи, группы, роли), структуру JSON-политики, как быстро находить over-permissive права и как работает AssumeRole — фундамент для всей эксплуатации."
---
## Что такое IAM

IAM (Identity and Access Management) — слой авторизации облака: кто (principal) может делать что (action) с каким ресурсом и при каких условиях. В AWS это users, groups, roles, policies; в GCP — IAM members + roles + bindings; в Azure — Entra ID (объекты) + RBAC (роли) + scopes. Понимание IAM — фундамент: почти любая эскалация в облаке есть комбинация прав, приводящая к новым правам.

## Сущности IAM

- **User** — постоянная сущность с ключами/паролем.
- **Group** — набор пользователей, политики наследуются.
- **Role** — сущность без долговременных креденшелов, на которую «встают» через AssumeRole; используется сервисами, кросс-аккаунтом, федерацией.
- **Policy** — документ прав (identity-based или resource-based).
- **Trust policy** — кто может «встать» на роль.
- **Permission boundary** — верхняя граница прав сущности.
- **SCP** — политика Organization, ограничивающая целые аккаунты.

## Структура JSON-политики

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid":"AllowS3","Effect":"Allow",
     "Action":["s3:GetObject","s3:ListBucket"],
     "Resource":["arn:aws:s3:::mybucket","arn:aws:s3:::mybucket/*"],
     "Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}
  ]
}
```

Ключевые поля: Effect (Allow/Deny), Action (с wildcard `*`), Resource (ARN), Principal (в resource-based), Condition (ограничения). **Deny всегда побеждает Allow**, а SCP и boundary сужают то, что разрешено identity-политикой.

## Как читать политику и находить over-permissive

Красные флаги:

- `"Action":"*"` или `"Resource":"*"`.
- `iam:*`, `sts:*`, `s3:*`.
- Principal `*` в resource-based политике без Condition.
- `NotAction`/`NotResource` — легко ошибиться.
- Отсутствие условий MFA/IP.

```bash
aws iam get-policy-version --policy-arn <arn> --version-id v3
aws iam list-attached-user-policies --user-name alice
aws iam list-role-policies --role-name MyRole
aws iam list-user-policies --user-name alice
enumerate-iam --access-key AKIA... --secret-key ...
cloudsplaining scan-policy-file --input-file policy.json
```

## AssumeRole и цепочки ролей

Роль нельзя «использовать» напрямую — на неё встают через `sts:AssumeRole`, получая временные креденшелы. Trust policy определяет, кто может это сделать:

```json
{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},
 "Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"secret123"}}}
```

Если trust-политика слишком широка (Principal `*`, нет ExternalId) — это **confused deputy**: сторонний сервис может «попросить» роль от вашего имени.

## Роли для сервисов (service roles)

EC2-инстансы, Lambda, ECS-таски получают роль через metadata/endpoint. Если вы получили RCE на инстансе — вы наследуете права его роли. Это мост из «сети» в «облако». Проверка:

```bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/MyEC2Role
# IMDSv2 требует токен:
TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## Практика: анализ политики

Дана политика с `"Action":["iam:CreatePolicyVersion","iam:PassRole","ec2:RunInstances"]`. Вывод: можно создать новую версию политики с `*` (CreatePolicyVersion), привязать роль с широкими правами к инстансу (PassRole + RunInstances) и получить её креденшелы через metadata. Это типовой путь privesc — разберём его в `cloud-privesc-iam`.

## Условия (Condition) и их обход

- `aws:SourceIp` — обходится при SSRF/прокси из разрешённого диапазона.
- `aws:PrincipalArn` — если совпадает с ролью, которую можно «примерить».
- `aws:MultiFactorAuthPresent` — обходится при краже MFA-токена.
- `aws:RequestedRegion` — ограничивает регион, но не сервис.
- `aws:ResourceTag` / `aws:PrincipalTag` — обходится изменением тегов при наличии прав.

Понимание условий отличает «есть право» от «есть право, которым можно воспользоваться».

## Защита

Least privilege, permission boundaries, SCP на уровне Organization, регулярный аудит (IAM Access Analyzer, Prowler), MFA для чувствительных действий, ротация ключей, запрет `*`.

## Частые ошибки

- Читать только attached-политики, забыв inline и boundaries.
- Не учитывать наследование через группы.
- Игнорировать resource-based политики (S3, KMS, SQS) — они дают доступ в обход identity-based.
- Считать `Deny` из SCP «просто текстом» — SCP реально ограничивает.
- Путать `iam:PassRole` (передать роль сервису) и `sts:AssumeRole` (встать самому).

## Что дальше / решение

Освоив чтение политик, переходите к `cloud-privesc-iam`: там каталог «прав-мостов» (CreatePolicyVersion, PassRole, UpdateAssumeRolePolicy, AttachUserPolicy и др.) и полный путь эскалации. Для защиты — периодически прогоняйте pmapper/cloudsplaining и закрывайте избыточные права.

## Политики vs Permission Boundary vs SCP

| Механизм | Область | Кто задаёт | Эффект |
|----------|---------|------------|--------|
| Identity policy | сущность (user/role) | админ аккаунта | разрешает |
| Resource policy | ресурс (S3, KMS, SQS) | владелец ресурса | разрешает/доверяет |
| Permission boundary | максимум для сущности | админ | ограничивает |
| SCP | аккаунт/OU | организация | ограничивает |
| ACL | ресурс | владелец | legacy |

Итоговые права = (identity ∪ resource) ∩ boundary ∩ SCP − explicit Deny. Если вы видите `Action:*`, но права не работают — ищите boundary или SCP.

## Разбор реальной политики

Дана policy:
```json
{"Statement":[
 {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::logs/*"},
 {"Effect":"Allow","Action":["iam:PassRole"],"Resource":"*"},
 {"Effect":"Allow","Action":["ec2:RunInstances"],"Resource":"*"}]}
```
Анализ: `s3:PutObject` на `logs/*` → запись логов (подделка/подмена). `iam:PassRole:*` + `ec2:RunInstances:*` → классическая эскалация: запустить EC2 с ролью, имеющей больше прав, и забрать её креденшелы через metadata. Вывод — это не «ограниченный» доступ, а путь к админу.

## GCP и Azure: аналоги

| AWS | GCP | Azure |
|-----|-----|-------|
| User | member (user:...) | Entra ID user |
| Role | role binding | RBAC role assignment |
| Policy | IAM policy (allow) | role definition + scope |
| AssumeRole | serviceAccountTokenCreator / impersonate | managed identity |
| SCP | Organization Policy | Azure Policy |
| Permission boundary | deny policy | not directly |

В GCP нет `Deny`-политик в классической модели (есть IAM Deny policies в preview), а имперсонация сервис-аккаунтов — через `roles/iam.serviceAccountTokenCreator`.

## Инструменты аудита

```bash
prowler aws --profile default -M json-ocsf -o prowler-out
scoutsuite aws --profile default --report-dir scout
pmapper --profile default graph create --include-all
pmapper --profile default query 'who can do iam:CreatePolicyVersion'
cloudsplaining scan-policy-file --input-file policy.json
enumerate-iam --access-key AKIA... --secret-key ... --session-token ...
```

`prowler -M` — формат вывода, `-o` — директория, `-c` — чек. `scoutsuite` собирает инвентарь и находит мисконфиги.

## Разобранный пример: от read-only к админу

1. `aws sts get-caller-identity` — кто вы.
2. `enumerate-iam` — какие вызовы разрешены.
3. Находим `iam:CreatePolicyVersion` → создаём версию своей политики с `*`.
4. `aws iam set-default-policy-version` — активируем.
5. Повторяем `enumerate-iam` → теперь `iam:*`. Админ получен.
Подробный каталог таких «мостов» — в `cloud-privesc-iam`.

## OPSEC и минимизация шума

`enumerate-iam` делает десятки API-вызовов, которые видны в CloudTrail. Используйте `--brute-force` только при необходимости, ограничивайте `--region`, и учитывайте, что GuardDuty может помечать аномалии (`Recon:IAMUser`). При возможности работайте из уже «шумного» сервиса (SSRF через приложение).

## Частые ошибки (продолжение)

- Забывать, что resource-based политика может разрешить доступ без identity-прав.
- Не проверять `iam:UpdateAssumeRolePolicy` — изменение trust даёт доступ к роли.
- Игнорировать inline-политики в отчётах.
- Не сопоставлять `NotAction`-политики с реальными действиями.

## Как строится итоговое решение о доступе

Разберём пошагово запрос `s3:GetObject` к `arn:aws:s3:::mybucket/secret`:

1. **SCP**: если есть Deny на `s3:*` — отказ.
2. **Permission boundary**: если объект вне разрешённого набора — отказ.
3. **Identity policy**: есть ли Allow на этот ресурс?
4. **Resource policy**: есть ли Allow/Deny на бакете?
5. **ACL**: legacy-проверка.

Если хотя бы один explicit Deny сработал — доступ запрещён, независимо от Allow. Это объясняет «нелогичные» отказы: право есть, но boundary/SCP режет.

## Мини-лаборатория: читаем политику

```bash
aws iam get-user --user-name alice
aws iam list-groups-for-user --user-name alice
aws iam list-attached-user-policies --user-name alice
aws iam list-user-policies --user-name alice
# собрать эффективные права
pmapper --profile alice query 'show all'
```

Сопоставляя действия из всех источников, вы строите карту «что могу» и находите лишние права.

## Триаж находок

- `Action:*` — критично.
- `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `iam:PutUserPolicy` — privesc.
- `iam:PassRole` + вычислительные сервисы — privesc.
- `sts:AssumeRole` на широкий trust — lateral.
- `s3:*` на `*` — эксфильтрация.
- Отсутствие MFA-условий — усиление риска.

## Что дальше (расширение)

После чтения политик переходите к практике: `cloud-privesc-iam` (каталог путей), `cloud-assume-role` (цепочки доверия), `cloud-aws-organizations` (SCP и кросс-аккаунт). Для защиты — регулярный аудит и устранение избыточных прав.

## Квиз

```quiz
- question: "В чём ключевое отличие IAM User от IAM Role?"
  options:
    - "Роль нельзя привязать к политике"
    - "User имеет долговременные креды, Role выдаёт временные токены через AssumeRole"
    - "Роль работает только в Azure"
    - "User всегда мощнее роли"
  answer: 1
  explanation: "User — постоянные access key; Role — временная идентичность, которую принимают."
- question: "Что делает `Effect: Deny` при конфликте с `Allow`?"
  options:
    - "Ничего, Allow приоритетнее"
    - "Deny всегда побеждает"
    - "Зависит от порядка statement"
    - "Вызывает ошибку API"
  answer: 1
  explanation: "Явный Deny всегда перекрывает Allow."
- question: "Какая комбинация в политике — классический красный флаг эскалации?"
  options:
    - "`s3:GetObject` на конкретный бакет"
    - "`iam:CreateAccessKey` на `Resource: *`"
    - "`ec2:DescribeInstances` с Condition на IP"
    - "`logs:CreateLogGroup` на конкретный лог"
  answer: 1
  explanation: "Создание access key для любого пользователя = возможность зайти под админом."
- question: "Кто может принять роль `target-role`?"
  options:
    - "Любой, у кого есть пароль"
    - "Только тот, кого разрешает trust policy роли"
    - "Все пользователи аккаунта без исключения"
    - "Только root-аккаунт"
  answer: 1
  explanation: "Trust policy (AssumeRolePolicyDocument) определяет principals."
```

## Где пригодится

- **Любой облачный пентест** — первым делом вы читаете IAM, чтобы понять свои возможности.
- **Bug bounty** — over-permissive IAM и confused-deputy в cross-account ролях.
- **CTF** — задачи почти всегда дают «слабый» ключ и требуют найти путь к админу.
- **Аудит и compliance** — поиск нарушений least-privilege, избыточных `*`.
- **Дальше по дереву** — `cloud-privesc-iam` (что делать с найденными правами) и `cloud-metadata-ssrf` (как получить роль из инстанса).
