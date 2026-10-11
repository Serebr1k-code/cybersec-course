---
id: cloud-gcp-orgpolicy
title: "GCP resource hierarchy и org policies: границы и обход"
category: cloud
parent: cloud-gcp-deep
difficulty: hard
order: 4
tags: [cloud, gcp, resource-manager, folders, org-policy, constraints, iam]
prerequisites: [cloud-gcp-deep, cloud-gcp-iam]
useful_for:
  - "Пентест крупных GCP-организаций"
  - "Понимание наследования прав и границ"
  - "Поиск проектов вне действия политик"
estimated_minutes: 50
summary: "Как устроена иерархия Organization → Folder → Project, как наследуется IAM и как org policies задают границы. Где искать проекты-исключения и как из folder-админа получить контроль над организацией."
---

## Зачем этот урок

В GCP права и ограничения живут не только в проекте. Над проектом стоит **иерархия ресурсов**: Organization → Folders → Projects → ресурсы. IAM-роли наследуются вниз, а **org policies** (constraints) задают границы, которые нельзя обойти IAM-политикой. Для пентестера это два ключевых вопроса: (1) какие права я унаследовал от папки/организации и (2) какие проекты выпали из-под политик и потому менее защищены. Понимание иерархии объясняет, почему «безобидная» роль на папке открывает десятки проектов и почему один проект может иметь ключи SA, запрещённые в остальной организации.

## Как устроена иерархия GCP

Уровни:

- **Organization** — корень (привязан к домену Cloud Identity/Workspace). Здесь живут org-level роли и политики.
- **Folder** — группировка проектов (по среде, команде, бизнес-юниту). Вложенность допускается.
- **Project** — единица биллинга, IAM и API.
- **Resource** — конкретные объекты (VM, бакет, функция).

Наследование IAM: роль, выданная на Organization, действует во всех проектах; роль на Folder — во всех проектах внутри; роль на Project — только там. При этом **deny policies** (IAM Deny) имеют приоритет над allow. Важно: **SCP-аналога как в AWS нет**; вместо «жёсткой границы» в GCP используются org policies, но они покрывают не всё и могут быть исключены на уровне проекта.

Org policies (constraints) — типовые:

| Constraint | Что запрещает |
|------------|---------------|
| `constraints/iam.disableServiceAccountKeyCreation` | создание ключей SA |
| `constraints/iam.allowedPolicyMemberDomains` | выдачу прав внешним доменам |
| `constraints/compute.vmExternalIpAccess` | внешние IP у VM |
| `constraints/compute.requireShieldedVm` | незащищённые VM |
| `constraints/storage.uniformBucketLevelAccess` | ACL на бакетах |
| `constraints/gcp.resourceLocations` | ресурсы вне разрешённых регионов |
| `constraints/compute.skipDefaultNetworkCreation` | default-сеть |

Ключевой момент: политика может быть `enforced` (запрет) или «dry-run»/предупреждение; исключения задаются на уровне проекта или папки. Проекты, созданные до включения политики, и проекты с исключениями — часто самые слабые места.

## Инструменты и команды

Разведка иерархии:

```bash
# Организация и папки
gcloud organizations list
gcloud resource-manager folders list --organization=123456789012
gcloud resource-manager folders list --folder=987654321098

# Проекты
gcloud projects list
gcloud projects describe my-project --format='value(parent,projectNumber)'

# IAM на уровнях
gcloud organizations get-iam-policy 123456789012 --format=json
gcloud resource-manager folders get-iam-policy 987654321098 --format=json
gcloud projects get-iam-policy my-project --format=json
```

Org policies:

```bash
# Что задано на уровне организации/папки/проекта
gcloud resource-manager org-policies list --organization=123456789012
gcloud resource-manager org-policies describe constraints/iam.disableServiceAccountKeyCreation \
  --project=my-project --effective
gcloud resource-manager org-policies list --project=my-project

# Эффективные политики (с наследованием)
gcloud resource-manager org-policies describe constraints/compute.vmExternalIpAccess \
  --folder=987654321098 --effective
```

Asset inventory (если есть Cloud Asset API права):

```bash
gcloud asset search-all-resources --scope=organizations/123456789012 \
  --asset-types=cloudresourcemanager.googleapis.com/Project
gcloud asset search-all-iam-policies --scope=organizations/123456789012 \
  --query="policy:allUsers"
```

## Разобранный пример: от folder-роли к контролю над организацией

Сценарий: у вашей идентичности есть `roles/resourcemanager.folderAdmin` на папке `dev` и `roles/iam.serviceAccountAdmin` на проекте.

Шаг 1 — смотрим, что наследуется. Folder `dev` содержит 12 проектов; роль folderAdmin даёт создание/удаление проектов и управление IAM внутри папки.

```bash
gcloud resource-manager folders list --folder=987654321098
# NAME  ID
# dev-1 111111111111
# dev-2 222222222222
```

Шаг 2 — проверяем, можно ли выдать себе роли в проектах. `resourcemanager.folderAdmin` включает `resourcemanager.projects.setIamPolicy` на проектах папки. Выдаём себе `roles/owner` на проект с интересными ресурсами:

```bash
gcloud projects add-iam-policy-binding target-project \
  --member="user:me@example.com" --role="roles/owner"
```

Шаг 3 — ищем проекты с исключениями org policy. Например, проект, где не действует `iam.disableServiceAccountKeyCreation`. Проверяем effective policy:

```bash
for p in $(gcloud projects list --format='value(projectId)'); do
  echo "== $p"
  gcloud resource-manager org-policies describe constraints/iam.disableServiceAccountKeyCreation \
    --project=$p --effective --format='value(listPolicy)' 2>/dev/null
done
```

Проект, где constraint не enforced, позволяет выпустить долгоживущий ключ SA — персистентность и обход ограничений.

Шаг 4 — ищем проекты с `allUsers` в IAM (публичные ресурсы) через asset inventory или `get-iam-policy`:

```bash
gcloud projects get-iam-policy my-project --format=json | jq '.bindings[] | select(.members[]?=="allUsers")'
```

Шаг 5 — эскалация вверх. Если папка наследует роли от организации, а вы можете изменить политику папки (`folderAdmin` включает `setIamPolicy`), вы можете добавить себя на более высокий уровень — если у вас есть право на организацию. Часто этого нет, но folderAdmin уже даёт контроль над всеми проектами папки, включая их сервисные аккаунты.

Цепочка: `folderAdmin → setIamPolicy на проектах → owner проекта → serviceAccountAdmin → ключи SA → персистентность`.

## Варианты атак и обходы

- **Folder admin.** `roles/resourcemanager.folderAdmin` даёт `setIamPolicy` на проектах папки — это де-факто owner всех проектов.
- **`resourcemanager.projectIamAdmin`.** Позволяет выдавать роли в проекте, включая `owner` (если нет deny).
- **`iam.serviceAccountTokenCreator`.** Имперсонация SA проекта (`cloud-gcp-metadata`).
- **Проекты вне org.** Проект может быть создан вне организации (personal account) и не подчиняться org policies; часто там ключи и открытые бакеты.
- **Исключения политик.** `excludedFolders`/`excludedProjects` в org policy создают дыры.
- **Dry-run политики.** Если constraint в режиме dry-run, он ничего не блокирует — проверяйте `--effective` и фактическое состояние.
- **Default service account.** `PROJECT@appspot.gserviceaccount.com` или compute default SA могут иметь широкие роли.
- **Legacy projects.** Проекты, созданные до внедрения политик, могут иметь ключи и старые настройки.
- **VPC-SC и perimeter.** Если проект вне service perimeter, он доступен без дополнительных ограничений — ищите такие проекты.

## Частые ошибки и подводные камни

- **Путать уровень роли.** Роль на папке действует во всех проектах; не оценивайте её по одному проекту.
- **Считать org policy всеобъемлющей.** Она не покрывает все сервисы и может иметь исключения.
- **Игнорировать deny policies.** IAM Deny может блокировать вашу выдачу ролей — проверяйте.
- **Забывать про биллинг.** Проект без биллинга не запустит новые ресурсы, но старые могут работать.
- **Не проверять `--effective`.** Локальная политика проекта не показывает унаследованное; используйте effective-описание.
- **Пробовать только `get-iam-policy`.** Без `cloudasset` вы не увидите все политики и ресурсы организации.

## Защита и детект

- **Минимум прав на папках.** `folderAdmin` — очень мощная роль; выдавайте её только платформенной команде.
- **Org policy enforced, без исключений.** Особенно `disableServiceAccountKeyCreation`, `allowedPolicyMemberDomains`, `vmExternalIpAccess`.
- **Deny policies** на критичные действия (`iam.googleapis.com/*` для не-админов).
- **VPC Service Controls** вокруг чувствительных проектов.
- **Детект.** Cloud Audit Logs: `SetIamPolicy`, `CreateServiceAccountKey`, `CreateProject`, изменения org policy. Алерты на `setIamPolicy` с добавлением внешних участников, на создание ключей, на проекты вне организации.
- **Cloud Asset Inventory** для регулярного аудита «кто где имеет права».

## Deny policies и VPC Service Controls

Помимо org policies, в GCP есть два механизма, которые важно учитывать:

- **IAM Deny policies.** Позволяют явно запретить действия для принципалов, даже если allow-роль есть. Deny имеет приоритет. Если ваша попытка выдать себе роль не срабатывает, несмотря на `setIamPolicy`, — ищите deny policy на проекте/папке/организации. Проверка через `gcloud resource-manager` или Cloud Asset API.
- **VPC Service Controls (VPC-SC).** Задают **perimeter** вокруг проектов: даже с валидными кредами API-вызовы извне периметра блокируются. Если вы получили токен SA, но вызовы к Storage/Secret Manager падают с ошибкой периметра, значит проект внутри perimeter, а вы — снаружи. Обход VPC-SC — отдельная тема (SSRF изнутри периметра, мисконфиг ingress/egress правил, `accessLevels`). Для пентеста важно понимать: успешный токен ещё не гарантирует доступ — проверьте, не режет ли perimeter.

Практический приём: получив токен, сделайте «пробный» вызов к Storage. Если ошибка `VPC Service Controls: Request is prohibited by organization's policy` — вы за perimeter. Тогда ищите ресурс **внутри** периметра, из которого можно обратиться к цели (SSRF/RCE в сервисе периметра).

## Практический чек-лист аудита иерархии

Чтобы не утонуть в уровнях, ведите разведку по шагам:

1. Организации и папки (`organizations list`, `folders list`) — постройте дерево.
2. Для каждой папки и проекта — `get-iam-policy`; отметьте роли, дающие `setIamPolicy`, `actAs`, `getAccessToken`, `serviceAccountKeys.create`.
3. Effective org policies по критичным constraints (`--effective`) — найдите проекты без enforced-ограничений.
4. Проекты вне организации и вне perimeter — отдельный список «слабых звеньев».
5. Default и legacy service accounts с широкими ролями.
6. Публичные привязки (`allUsers`, `allAuthenticatedUsers`) через asset inventory или перебор IAM-политик.
7. Биллинг-аккаунты — проекты без биллинга могут содержать «замороженные», но живые ресурсы.

Этот чек-лист даёт структурированную картину и помогает приоритизировать: сначала проекты с наследованными широкими правами и без ограничений, затем всё остальное.

## Что дальше / решение

Иерархия GCP объясняет, откуда берутся «слишком широкие» права: они унаследованы с папки или организации. Первый шаг — построить карту: организация, папки, проекты, роли на каждом уровне, effective org policies. Затем искать проекты-исключения (без enforced-политик, вне org, вне perimeter) — там самые слабые места. Если у вас folderAdmin или projectIamAdmin, вы можете выдать себе owner и дальше действовать свободно; если есть serviceAccountTokenCreator — имперсонируйте привилегированный SA. Записывайте карту и найденные исключения как отдельные находки: они объясняют, почему ограничения организации не сработали.

## Квиз

```quiz
- question: "Как наследуются IAM-роли в GCP?"
  options:
    - "Сверху вниз: организация → папки → проекты"
    - "Снизу вверх"
    - "Не наследуются"
    - "Только внутри проекта"
  answer: 0
  explanation: "Роль на верхнем уровне действует во всех вложенных ресурсах."
- question: "Чем org policy отличается от IAM-роли?"
  options:
    - "Org policy задаёт границу (запрет), а IAM выдаёт права"
    - "Это одно и то же"
    - "Org policy выдаёт роли"
    - "IAM отменяет org policy всегда"
  answer: 0
  explanation: "Org policy — guardrail, ограничивающий возможное; IAM — разрешения."
- question: "Почему проекты-исключения из org policy опасны?"
  options:
    - "В них не действуют ограничения (например, можно создать ключи SA)"
    - "Они дешевле"
    - "Они быстрее"
    - "В них нет IAM"
  answer: 0
  explanation: "Исключения создают дыры: constraint не enforced, значит запрет не применяется."
- question: "Какая роль даёт контроль над IAM всех проектов папки?"
  options:
    - "roles/resourcemanager.folderAdmin"
    - "roles/viewer"
    - "roles/logging.viewer"
    - "roles/storage.objectViewer"
  answer: 0
  explanation: "folderAdmin включает setIamPolicy на проектах папки."
```

## Где пригодится

- **Пентест GCP:** карта иерархии и поиск исключений.
- **Red team:** эскалация от folder-роли к контролю над проектами.
- **Blue team:** аудит org policies и прав на папках.
- **Сертификация:** Google Professional Cloud Security Engineer.
