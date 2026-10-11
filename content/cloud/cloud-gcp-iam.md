---
id: cloud-gcp-iam
title: "GCP IAM и имперсонация сервисных аккаунтов: пути эскалации"
category: cloud
parent: cloud-iam-identity
difficulty: hard
order: 3
tags: [cloud, gcp, iam, service-account, impersonation, privesc]
prerequisites: [cloud-gcp-basics, cloud-iam-basics]
useful_for:
  - "Эскалация привилегий в GCP"
  - "Анализ IAM-политик и поиск путей имперсонации"
  - "Автоматизация аудита GCP-проектов"
estimated_minutes: 40
summary: "Как читать IAM-политики GCP, находить пути имперсонации сервисных аккаунтов и эскалировать до owner. Практические команды gcloud, gcpwn и разбор типовых цепочек."
---
## Зачем этот урок

GCP IAM строится вокруг members и roles, привязанных к ресурсам в иерархии (организация → папка → проект → ресурс). Главная особенность — имперсонация сервис-аккаунтов (impersonate), которая позволяет действовать от имени SA, не имея его ключей. Это одновременно удобный механизм и частый путь эскалации.

## Примитивы имперсонации

| Роль | Что даёт |
|------|----------|
| roles/iam.serviceAccountUser | запуск compute/функций под SA |
| roles/iam.serviceAccountTokenCreator | выпуск токенов/ключей SA |
| roles/iam.serviceAccountKeyAdmin | создание ключей SA |
| roles/iam.workloadIdentityUser | привязка K8s SA к GCP SA |
| roles/iam.serviceAccountAdmin | управление SA |

Комбинация `serviceAccountTokenCreator` + доступ к SA с широкими правами = полный контроль.

## Как читать политику

```bash
gcloud projects get-iam-policy my-project --format=json
gcloud projects get-iam-policy my-project \
  --flatten="bindings[].members" \
  --format="table(bindings.role,bindings.members)"
gcloud iam service-accounts list
gcloud iam service-accounts get-iam-policy sa@my-project.iam.gserviceaccount.com
```

Ищите `roles/owner`, `roles/editor`, а также `serviceAccountTokenCreator` на широкие SA.

## Разведка: кто есть кто

```bash
gcloud auth list
gcloud config list
gcloud projects list
gcloud iam service-accounts list --format='value(email)'
# проверка прав
gcloud projects get-iam-policy my-project --format=json | jq '.bindings[] | select(.members[]|test("user:me"))'
```

## Разобранный пример: от TokenCreator до owner

1. Вы имеете `roles/iam.serviceAccountTokenCreator` на SA `ci@proj.iam.gserviceaccount.com`.
2. Выпускаем токен доступа:
```bash
gcloud auth print-access-token --impersonate-service-account=ci@proj.iam.gserviceaccount.com
curl -H "Authorization: Bearer $(gcloud auth print-access-token --impersonate-service-account=ci@proj.iam.gserviceaccount.com)" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/proj:getIamPolicy"
```
3. SA `ci` имеет `roles/owner` — вы теперь owner проекта.
4. Создаём собственный ключ SA для персистентности:
```bash
gcloud iam service-accounts keys create key.json --iam-account=ci@proj.iam.gserviceaccount.com
```

## Цепочки имперсонации

SA A имеет TokenCreator на SA B, B — на C. Имперсонируя по цепочке, получаем C. Инструмент `gcp_iam_analyzer` или ручной обход:

```bash
for sa in $(gcloud iam service-accounts list --format='value(email)'); do
  echo "== $sa"; gcloud iam service-accounts get-iam-policy "$sa" --format=json 2>/dev/null | jq -c '.bindings[]?'
done
```

## GKE и Workload Identity

K8s SA привязывается к GCP SA через аннотацию. Из пода можно получить токен и обратиться к GCP API. Проверьте `iam.gke.io/gcp-service-account` в манифесте и права `workloadIdentityUser`.

## Частые ошибки

- Считать, что без ключей SA нет доступа — имперсонация обходит это.
- Игнорировать `serviceAccountUser` на compute (запуск под SA).
- Не проверять организацию/папку — права наследуются вниз.
- Забывать про `roles/editor` — это почти owner для многих сервисов.
- Не смотреть default compute SA (часто имеет editor).

## Что дальше / решение

Найдя имперсонацию, двигайтесь вверх по цепочке до owner, затем к данным (GCS, BigQuery, Secret Manager). Для защиты — минимизируйте `TokenCreator`, используйте Workload Identity вместо ключей, аудируйте bindings.

## Разбор bindings и conditions

```bash
gcloud projects get-iam-policy my-project --format=json > policy.json
jq '.bindings[] | {role, members}' policy.json
# условия
jq '.bindings[] | select(.condition) | {role, members, condition}' policy.json
```

Conditions (IAM Conditions) ограничивают binding по времени/ресурсу/атрибутам. Слабые условия (`resource.name.startsWith`) обходятся подбором имени. Проверяйте также `auditConfigs` и `etag` (защита от гонок).

## Инструменты

```bash
gcloud iam service-accounts list --format='table(email,disabled)'
gcloud iam service-accounts keys list --iam-account sa@proj.iam.gserviceaccount.com
gcloud projects get-iam-policy proj --format=json | gcp_scanner
scoutsuite gcp --report-dir scout-gcp
gcloud asset search-all-iam-policies --scope=projects/proj
```

`gcloud asset search-all-iam-policies` — мощный способ увидеть все привязки сразу. `scoutsuite` строит отчёт по мисконфигам.

## Разобранный пример 2: Workload Identity в GKE

1. В поде есть K8s SA с аннотацией `iam.gke.io/gcp-service-account=ci@proj.iam.gserviceaccount.com`.
2. Читаем токен: `cat /var/run/secrets/kubernetes.io/serviceaccount/token`.
3. Обмениваем на access-token GCP:
```bash
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/ci@proj.iam.gserviceaccount.com/token"
```
4. Получаем права SA — часто `storage.objectViewer` или больше.

## Таблица примитивов и последствий

| Право | Немедленный эффект |
|-------|-------------------|
| iam.serviceAccounts.actAs | запуск compute/функций под SA |
| iam.serviceAccountTokenCreator | выпуск токена SA |
| iam.serviceAccountKeys.create | постоянный ключ SA |
| iam.workloadIdentityUser | привязка K8s SA |
| resourcemanager.projects.setIamPolicy | выдача любых ролей |

## OPSEC

Каждая имперсонация пишется в Cloud Audit Logs (`GenerateAccessToken`, `GetAccessToken`). Всплеск таких событий — аномалия. Работайте минимальным числом вызовов, используйте уже выданные токены, не создавайте ключи без необходимости.

## Разбор частого мисконфига: default compute SA

Каждый GCP-проект создаёт Compute Engine default service account (`<project-number>-compute@developer.gserviceaccount.com`), который по умолчанию имеет `roles/editor`. Любая VM, запущенная без явного SA, получает эти права. Если вы скомпрометировали такую VM, вы фактически имеете editor на проект. Проверка:

```bash
gcloud iam service-accounts describe <project-number>-compute@developer.gserviceaccount.com
gcloud projects get-iam-policy proj --format=json | \
  jq '.bindings[] | select(.members[]|test("compute@developer"))'
```

Это один из самых недооценённых путей: не нужны ни ключи, ни имперсонация — права уже на инстансе.

## Имперсонация: практические команды

```bash
# выпустить access-token от имени SA
gcloud auth print-access-token --impersonate-service-account=sa@proj.iam.gserviceaccount.com
# использовать в REST
curl -H "Authorization: Bearer $(gcloud auth print-access-token \
  --impersonate-service-account=sa@proj.iam.gserviceaccount.com)" \
  "https://storage.googleapis.com/storage/v1/b?project=proj"
# короткоживущий ключ SA
gcloud iam service-accounts keys create k.json \
  --iam-account=sa@proj.iam.gserviceaccount.com --key-file-type=json
# активировать и проверить
gcloud auth activate-service-account --key-file=k.json
gcloud auth list
```

Команда `print-access-token --impersonate-service-account` требует `serviceAccountTokenCreator`. `keys create` требует `serviceAccountKeyAdmin`. Различие важно: первая выдаёт временный токен (часы), вторая — постоянный ключ (персистентность, но заметнее в логах).

## Наследование прав в иерархии

Права, выданные на организацию или папку, наследуются всеми проектами внутри. Поэтому `roles/owner` на уровне организации — это контроль над всем. Проверяйте всю иерархию:

```bash
gcloud organizations list
gcloud resource-manager folders list --organization=ORG_ID
gcloud projects get-ancestors proj
gcloud organizations get-iam-policy ORG_ID --format=json | jq '.bindings[]'
```

Частая ошибка аудита — смотреть только на уровень проекта и не замечать права, унаследованные сверху.

## Частые находки при аудите GCP

- **Default compute SA с editor** — почти в каждом проекте, если не поменяли.
- **Публичные GCS-бакеты** — `storage.objects.get` для `allUsers`.
- **Сервисные ключи в репозиториях** — JSON-файлы с `private_key`.
- **SA с Owner** — избыточно, но встречается.
- **Workload Identity без ограничения namespace** — любой под может встать.
- **Отсутствие Organization Policy** — нет запрета на внешние домены.
- **Audit Logs выключены** — инцидент не расследовать.

Каждую находку проверяйте на практическую эксплуатируемость: право `editor` бесполезно, если нет ресурсов, а ключ в репо — бесполезен, если отозван.

## Аудит наследования и Organization Policy

Проверяйте права на всех уровнях иерархии, а не только на проекте. Organization Policy задаёт ограничения (например, запрет внешних IP, запрет создания ключей SA). Если политика ослаблена, атакующий может создать ключ SA или публичный ресурс. Смотрите:

```bash
gcloud resource-manager org-policies list --organization=ORG
gcloud projects get-ancestors proj
```

## Сводка по примитивам имперсонации

| Роль | Эффект |
|------|--------|
| serviceAccountUser | запуск под SA |
| serviceAccountTokenCreator | токен SA |
| serviceAccountKeyAdmin | ключ SA |
| workloadIdentityUser | привязка K8s SA |

Наличие любой из них на привилегированный SA — путь к эскалации. Проверяйте get-iam-policy на каждом SA.

## Квиз

```quiz
- question: "Какое право позволяет напрямую выпустить access token от имени сервисного аккаунта?"
  options:
    - "roles/viewer"
    - "iam.serviceAccounts.getAccessToken"
    - "roles/storage.admin"
    - "roles/editor"
  answer: 1
  explanation: "getAccessToken — прямой примитив имперсонации сервисного аккаунта."
- question: "Почему get-iam-policy проекта может не показать все ваши права?"
  options:
    - "Потому что GCP скрывает права"
    - "Потому что роли могут быть унаследованы с уровня Organization или Folder"
    - "Потому что нужен VPN"
    - "Потому что политика хранится в S3"
  answer: 1
  explanation: "Наследование сверху вниз: роль на Organization/Folder действует на проект, но не видна в его политике."
- question: "Что даёт создание нового user-managed ключа для сервисного аккаунта?"
  options:
    - "Ничего"
    - "Долгоживущий доступ — персистентность после отзыва сессии"
    - "Только чтение бакетов"
    - "Временный токен на минуту"
  answer: 1
  explanation: "SA-ключ не истекает автоматически — идеальная персистентность."
- question: "Как Workload Identity в GKE может вести к эскалации?"
  options:
    - "Она шифрует поды"
    - "Под можно привязать (annotate) к привилегированному GCP-сервисному аккаунту и получить его токен"
    - "Она открывает порт 22"
    - "Она не связана с GCP IAM"
  answer: 1
  explanation: "Аннотация iam.gke.io/gcp-service-account связывает K8s SA с GCP SA — из пода можно действовать от его имени."
- question: "Почему SA с roles/owner на инстансе может дать урезанный токен?"
  options:
    - "Owner не действует на инстансах"
    - "Scopes инстанса (--scopes) ограничивают, какие API доступны токену"
    - "Токен всегда полный"
    - "Из-за MFA"
  answer: 1
  explanation: "Даже owner-роль ограничена access scopes, заданными при создании инстанса."
```

## Где пригодится

- **Пентест GCP** — поиск и эксплуатация путей имперсонации.
- **Red team** — от низкопривилегированного аккаунта до owner.
- **IR/Blue team** — детект создания ключей и аномальной имперсонации.
- **DevSecOps** — аудит IAM-политик, минимизация actAs/TokenCreator.
- **Сертификации** — Google Cloud Security Engineer.
