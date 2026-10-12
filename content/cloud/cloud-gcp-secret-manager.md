---
id: cloud-gcp-secret-manager
title: "Secret Manager GCP: версии, доступ и кража секретов"
category: cloud
parent: cloud-gcp-secrets-deep
difficulty: medium
order: 1
tags: [cloud, gcp, secret-manager, secrets, iam, kms, audit]
prerequisites: [cloud-gcp-secrets-deep, cloud-secrets-manager]
useful_for:
  - "Кража секретов из GCP"
  - "Анализ IAM на уровне секрета"
  - "Аудит доступа к секретам"
estimated_minutes: 45
summary: "Secret Manager: версии, права secretmanager.versions.access, IAM на уровне секрета, CMEK и audit-логи. Как найти и прочитать секреты при слабых правах."
---
## Задача

Мы разбирали секреты в CI и state. Теперь — централизованное хранилище секретов GCP: **Secret Manager**. Идея сервиса благая: секреты лежат не в коде, а в защищённом хранилище, и приложение берёт их по имени. Задача: показать, как при слабых правах секреты из него вытаскиваются. Разберём на конкретном GCP-проекте.

## Данные: проект и наши права

У нас есть service-account или пользовательский доступ к проекту `acme-prod`. Смотрим, какие секреты вообще есть:

```
$ gcloud secrets list --project acme-prod --format='table(name,createTime)'
NAME                CREATE_TIME
db-password         2025-01-10T10:00:00Z
api-signing-key     2025-02-02T12:30:00Z
stripe-secret       2025-03-01T09:15:00Z
```

`gcloud secrets list` — перечисление секретов. Имён достаточно, чтобы понять, за чем охотиться. Но чтобы **прочитать значение**, нужно право `secretmanager.versions.access`.

## Пробуем в лоб: пробуем прочитать

Пробуем получить последнюю версию секрета:

```
$ gcloud secrets versions access latest --secret=db-password --project acme-prod
Pr0d-DB-P@ss
```

Сработало. Значит, у нашего принципала есть `secretmanager.versions.access` — либо на уровне проекта, либо на конкретном секрете. Это ключевой момент: **доступ к секретам выдаётся по IAM, и его легко перевыдать**.

## Приём: перечисляем все версии и читаем

Секрет — это контейнер, у которого есть **версии** (versions). Старые версии часто остаются и содержат предыдущие (тоже валидные или «резервные») пароли. Перечисляем версии:

```
$ gcloud secrets versions list db-password --project acme-prod --format='table(name,state)'
NAME  STATE
3     ENABLED
2     ENABLED
1     DISABLED
```

Версия 2 всё ещё `ENABLED` — читаем и её:

```
$ gcloud secrets versions access 2 --secret=db-password --project acme-prod
Pr0d-DB-P@ss-OLD
```

Зачем: старый пароль может работать дольше, чем кажется, — его забыли ротировать на стороне БД. Плюс он даёт подсказку о шаблоне паролей.

Читаем остальные:

```
$ for s in api-signing-key stripe-secret; do echo "== $s"; gcloud secrets versions access latest --secret=$s; done
== api-signing-key
-----BEGIN PRIVATE KEY-----
...
== stripe-secret
sk_live_51H...
```

## Полный прогон: от списка до компрометации

1. **Разведка.** `secrets list` → имена секретов.
2. **Права.** Проверяем, что можем читать: `versions access latest`.
3. **Версии.** `versions list` → читаем старые ENABLED-версии.
4. **Использование.** Пароль БД → подключение к базе; `stripe_secret` → платежи; signing key → подделка токенов.
5. **Эскалация.** Часто в секретах лежат креды с более широкими правами. Проверяем:

```
$ gcloud secrets versions access latest --secret=db-password > /tmp/db
$ psql "host=prod-db.abc.internal user=admin password=$(cat /tmp/db)" -c '\du'
```

## IAM на уровне секрета

Доступ к Secret Manager выдаётся двумя способами: на уровне **проекта** (всем секретам) и на уровне **конкретного секрета**. Смотрим, кому что разрешено:

```
$ gcloud secrets get-iam-policy db-password --project acme-prod
bindings:
- members:
  - serviceAccount:app-sa@acme-prod.iam.gserviceaccount.com
  role: roles/secretmanager.secretAccessor
```

`secretAccessor` на конкретном секрете — правильная практика. Плохая — когда роль выдана на весь проект или на `allAuthenticatedUsers`:

```
$ gcloud projects get-iam-policy acme-prod --flatten='bindings[].members' \
    --filter='bindings.role:secretmanager' --format='table(bindings.role,bindings.members)'
ROLE                             MEMBERS
roles/secretmanager.secretAccessor  allAuthenticatedUsers
```

`allAuthenticatedUsers` — любой, кто прошёл аутентификацию в Google, читает все секреты проекта. Это катастрофа.

## CMEK, аудит и ротация

- **CMEK** (Customer-Managed Encryption Key) — секрет шифруется ключом KMS, который вы контролируете. Не мешает чтению через IAM, но даёт возможность «отозвать» данные, удалив ключ.
- **Audit logs** — каждое `versions.access` пишется в Cloud Audit Logs. Атакующий оставляет след; защита это видит (см. `cloud-logging-detection`).
- **Ротация** — секреты надо регулярно менять; старые версии — `DISABLED`/удалять.
- **Replication** — секрет реплицируется в регионы; проверяйте, нет ли копии в «слабом» регионе.

## Секреты в других местах GCP

Secret Manager — не единственное хранилище. Прежде чем сдаваться, проверьте:

- **Instance metadata.** На VM сервисный аккаунт отдаёт токен через `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (см. `cloud-gcp-metadata`). С этим токеном — тот же `gcloud secrets access`.
- **Cloud Storage.** Секреты в бакетах: `gsutil ls`, `gsutil cat`.
- **Firestore/Firebase.** Открытые правила отдают данные (см. `cloud-gcp-firebase`).
- **Cloud Functions / Cloud Run.** Переменные окружения функций содержат креды.
- **App Engine / Config.** `gcloud app describe` и конфиги.

```
$ curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token
ya29....
```

Тот же токен открывает Secret Manager — часто это и есть кратчайший путь к секретам.

## Защита и что ломает атаку

- **Роль на конкретный секрет**, а не на проект.
- **Убрать `allAuthenticatedUsers`/`allUsers`** из IAM.
- **CMEK** + права на KMS-ключ отдельно.
- **Аудит** `secretmanager.versions.access` и алерты на аномалии.
- **Ротация** и отключение старых версий.

## Если не сработало

- **Нет `secretmanager.versions.access`** — читать нечего; ищем другой принципал (сервисный аккаунт пода, CI).
- **`allUsers` убран, роли узкие** — переходим к поиску секретов в других местах (env, state, CI).
- **CMEK-ключ недоступен** — данные не расшифровать.
- **Аудит включён** — активность заметна; учитываем OPSEC.

## Мини-сценарий: чтение секрета целиком

1. **Список.** `gcloud secrets list --project acme-prod` → `db-password`, `api-signing-key`, `stripe-secret`.
2. **Чтение latest.** `gcloud secrets versions access latest --secret=db-password` → `Pr0d-DB-P@ss`. Право есть.
3. **Старые версии.** `gcloud secrets versions list db-password` → версия 2 `ENABLED`; читаем и её → `Pr0d-DB-P@ss-OLD`.
4. **IAM.** `gcloud secrets get-iam-policy db-password` → `app-sa@...` имеет `secretAccessor`. Проверяем проект: `get-iam-policy acme-prod` → `allAuthenticatedUsers` с той же ролью.
5. **Использование.** `psql` с паролем БД → доступ к базе; `stripe-secret` → платежи.
6. **Аудит.** В Cloud Audit Logs — событие `secretmanager.versions.access` на наш принципал.

Доступ к секретам держится на IAM: одна широкая привязка открывает всё.

## Что мы теперь знаем

1. Secret Manager хранит секреты с версиями.
2. Чтение требует `secretmanager.versions.access`.
3. IAM можно выдать на проект или на конкретный секрет.
4. `allAuthenticatedUsers` = утечка всех секретов.
5. Аудит и CMEK — контроли; старые версии надо отключать.
6. Тот же доступ к секретам часто открывается через metadata-токен VM.

Главная мысль: Secret Manager — это надёжное хранилище, но его IAM легко сделать слишком широким.

## Частые ошибки

- **`allAuthenticatedUsers` в роли `secretAccessor`** — секреты доступны всем.
- **Роль выдана на весь проект**, а не на конкретный секрет.
- **Старые версии не отключены** — забытые пароли продолжают работать.
- **Нет CMEK/аудита** — нет контроля и видимости доступа.
- **Metadata-токен SA открывает Secret Manager** без доп. проверок.

## На что смотреть дальше

- `gcloud secrets list` — какие секреты есть.
- `versions access latest`/`N` — доступ и старые версии.
- `get-iam-policy` секрета и проекта — кому разрешено чтение.
- Наличие `allAuthenticatedUsers`/`allUsers`.
- CMEK и настройки аудита.

## Быстрая проверка

Три команды показывают, насколько открыт Secret Manager:

```bash
gcloud secrets list --project acme-prod
gcloud secrets versions access latest --secret=db-password --project acme-prod
gcloud projects get-iam-policy acme-prod --filter='bindings.role:secretmanager'
```

Если вторая команда вернула значение, а третья — `allAuthenticatedUsers`, проект открыт всем.

## Квиз

Проверь себя.

```quiz
- question: "Какое право нужно для чтения значения секрета в GCP?"
  options:
    - "secretmanager.versions.access"
    - "secretmanager.versions.list"
    - "storage.objects.get"
    - "iam.roles.list"
  answer: 0
  explanation: "Значение версии читается через versions.access."
- question: "Что такое версии секрета?"
  options:
    - "Исторические значения секрета, часть остаётся включённой"
    - "Копии секрета в других проектах"
    - "Права на секрет"
    - "Регионы хранения"
  answer: 0
  explanation: "Каждое обновление создаёт версию."
- question: "Почему allAuthenticatedUsers в роли secretAccessor опасен?"
  options:
    - "Любой аутентифицированный пользователь Google читает все секреты"
    - "Он ускоряет доступ"
    - "Он шифрует секреты"
    - "Он блокирует чтение"
  answer: 0
  explanation: "Это делает секреты доступными всем."
- question: "Как правильно выдавать доступ к секрету?"
  options:
    - "Роль secretAccessor на конкретный секрет"
    - "Роль на весь проект"
    - "allUsers на секрет"
    - "Никак"
  answer: 0
  explanation: "Минимум прав — роль на конкретный ресурс."
- question: "Что пишется в Cloud Audit Logs при чтении секрета?"
  options:
    - "Событие secretmanager.versions.access"
    - "Ничего"
    - "Только вход в консоль"
    - "Только ошибки"
  answer: 0
  explanation: "Доступ к секрету аудируется."
```

## Куда дальше

В следующем уроке (`cloud-gitlab-ci`) мы вернёмся к CI и разберём раннеры и переменные GitLab подробнее. А пока главное: централизованное хранилище секретов защищено ровно настолько, насколько узко выданы права IAM.

## Где пригодится

- **Bug bounty:** проекты с широкими правами на Secret Manager.
- **Red team:** от чтения секретов к БД и платежам.
- **Пентест:** аудит IAM GCP и секретов.
- **Работа/DevSecOps:** роли на конкретный секрет, CMEK, аудит, ротация.
- **Дальше по дереву:** `cloud-secrets-manager`, `cloud-secrets-sprawl`.
