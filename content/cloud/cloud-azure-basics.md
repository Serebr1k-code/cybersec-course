---
id: cloud-azure-basics
title: "Azure: фундамент, терминология и поверхность атаки"
category: cloud
parent: cloud-foundations-providers
difficulty: medium
order: 1
tags: [cloud, azure, entra-id, arm, rbac, managed-identity, recon]
prerequisites: [cloud-fundamentals]
useful_for:
  - "Пентест Azure-подписок и Entra ID (Azure AD)"
  - "Понимание терминологии Azure для bug bounty"
  - "Разбор инцидентов в гибридных Microsoft-средах"
estimated_minutes: 35
summary: "Как устроен Azure: подписки, ресурсные группы, ARM, Entra ID, RBAC и Managed Identity. Карта поверхности атаки и первые команды разведки через Azure CLI."
lab:
  kind: shell
  title: "Практика: базовая разведка Azure-тенанта"
  toolset: [core, az]
  workdir: /home/student/azbasics
  files: [task.md, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Начни с аккаунтов: `az account list`."
    - "Перечисли storage accounts: `az storage account list`."
    - "В теге storage account найден флаг: сохрани вывод и `grep nto sa.json > found.txt`."

---

## Вопрос, с которого всё начинается

Ты получил доступ к Azure-аккаунту — например, нашёл в репозитории логин сервисного принципала или вошёл под учётной записью сотрудника. С чего начать разведку? У Azure своя терминология, и без неё не понять ни вывод команд, ни права.

В этом уроке мы разберём Azure на одном примере: зайдём через CLI и посмотрим, кто мы, что нам видно и где лежат секреты. Попутно разберём ключевые термины — они понадобятся во всей ветке Cloud.

## Наш пример: сессия в Azure CLI

У нас есть доступ, и мы работаем через `az` — командную строку Azure. Сначала надо войти:

```
$ az login --service-principal -u $APP_ID -p $SECRET --tenant $TENANT_ID
[
  {
    "cloudName": "AzureCloud",
    "id": "b1a2c3d4-...-subscription-id",
    "name": "Production",
    "state": "Enabled",
    "user": { "name": "deploy-sp", "type": "servicePrincipal" }
  }
]
```

Читаем: мы вошли как **service principal** (сервисный принципал) по имени `deploy-sp` в подписку `Production`. Уже два термина: принципал — это «робот-учётка», подписка — контейнер для ресурсов и оплаты.

Следующий вопрос: **что нам видно?**

## Шаг 1: кто мы и где мы

Команда `az account show` подтверждает контекст:

```
$ az account show --query '{user:user.name, tenant:tenantId, sub:name}' -o table
User       Tenant                                Sub
---------  ------------------------------------  ----------
deploy-sp  72f988bf-86f1-41af-91ab-2d7cd011db47  Production
```

Здесь важно поле **tenant** — это арендатор (Entra ID, бывший Azure AD): каталог пользователей и приложений. Один тенант может содержать много подписок. А `user` говорит, под кем мы действуем.

Следующий вопрос: **какие ресурсы нам доступны?**

## Шаг 2: перечисляем ресурсы

Все ресурсы Azure живут в **ресурсных группах** (Resource Group, RG) — логических контейнерах. Перечислим их и всё, что внутри:

```
$ az group list --query '[].name' -o tsv
rg-prod-web
rg-prod-data
rg-shared

$ az resource list --query '[].{name:name, type:type}' -o table
Name              Type
----------------  ----------------------------------------
prod-web-app      Microsoft.Web/sites
prod-sql          Microsoft.Sql/servers
prod-kv           Microsoft.KeyVault/vaults
```

Вот карта инфраструктуры: веб-приложение, SQL-сервер и **Key Vault** — хранилище секретов. Последнее особенно интересно.

Следующий вопрос: **что нам разрешено?**

## Шаг 3: роли и права

Права в Azure описываются через **RBAC** (Role-Based Access Control): роли назначаются субъектам на область (scope). Смотрим, какие роли есть у нас:

```
$ az role assignment list --assignee deploy-sp --all \
    --query '[].{role:roleDefinitionName, scope:scope}' -o table
Role                 Scope
-------------------  --------------------------------------------
Contributor          /subscriptions/b1a2c3d4-...
Key Vault Secrets User  /subscriptions/.../resourceGroups/rg-prod-data
```

Читаем: у нас роль **Contributor** на всю подписку — это очень широко (можно менять почти всё, кроме выдачи прав). Плюс отдельная роль на чтение секретов Key Vault. Такая комбинация — почти полный контроль.

Термин: **scope** (область) — на что распространяется роль: подписка, ресурсная группа или отдельный ресурс. Чем шире scope, тем больше возможностей.

Следующий вопрос: **можно ли достать секреты?**

## Шаг 4: где лежат секреты

**Key Vault** — это сейф для паролей, ключей и сертификатов. Если у нас есть роль на чтение секретов:

```
$ az keyvault secret list --vault-name prod-kv --query '[].name' -o tsv
db-connection-string
storage-account-key
api-token
```

```
$ az keyvault secret show --vault-name prod-kv --name db-connection-string \
    --query value -o tsv
Server=tcp:prod-sql.database.windows.net;User ID=sqladmin;Password=Sup3rS3cret!
```

Секрет в руках: строка подключения к базе с паролем. Именно так из одной роли вырастает доступ к данным.

## Шаг 5: терминология Azure

Соберём ключевые понятия в одну таблицу:

| Термин | Что это |
|--------|---------|
| Tenant (Entra ID) | каталог пользователей и приложений |
| Subscription | контейнер ресурсов и оплаты |
| Resource Group | логическая папка для ресурсов |
| ARM | Azure Resource Manager — слой управления ресурсами |
| RBAC | роли и назначения прав |
| Service Principal | «робот-учётка» для приложений |
| Managed Identity | автоматическая учётка для ресурса Azure |
| Key Vault | хранилище секретов |

Отдельно стоит **Managed Identity**: это сервисная учётка, которую Azure создаёт для ресурса (например, для виртуальной машины) автоматически, без паролей. Если такой ресурс уязвим (например, через SSRF), злоумышленник может получить его токен — об этом в следующих уроках.

## Поверхность атаки Azure

Где искать проблемы:

- **Слишком широкие роли:** `Contributor` или `Owner` на подписку.
- **Key Vault с доступными секретами.**
- **Managed Identity:** захват токена через уязвимость ресурса.
- **Публичные хранилища:** blob-контейнеры с открытым доступом.
- **Service principals с долгоживущими секретами** в репозиториях и пайплайнах.

## Чем Azure отличается от AWS по терминам

Чтобы не путаться, держите соответствие:

| Понятие | AWS | Azure |
|---------|-----|-------|
| Каталог пользователей | IAM | Entra ID |
| Контейнер ресурсов | Account | Subscription |
| Папка ресурсов | (нет прямого) | Resource Group |
| Робот-учётка | IAM Role | Service Principal |
| Секреты | Secrets Manager | Key Vault |
| Управление ресурсами | CloudFormation | ARM |

Смысл один: идентичность + ресурсы + права. Меняются названия, а логика атаки та же.

## Как получить доступ в Azure

Типичные пути попадания в аккаунт:

- **Секрет сервисного принципала** в репозитории или пайплайне.
- **Учётные данные сотрудника** из фишинга или утечки.
- **Managed Identity** через уязвимость в приложении (SSRF, RCE).
- **Открытые приложения** с включённой аутентификацией по слабым правилам.

Как только доступ есть, разведка идёт ровно по шагам этого урока: кто мы → что видно → какие роли → где секреты.

## Команды-шпаргалка

| Команда | Что делает |
|---------|-----------|
| `az account show` | текущий контекст |
| `az group list` | ресурсные группы |
| `az resource list` | все ресурсы |
| `az role assignment list` | роли |
| `az keyvault list` | хранилища секретов |
| `az keyvault secret list` | имена секретов |
| `az ad user list` | пользователи Entra ID |

Этого набора хватает для первой разведки.

## Что мы теперь знаем

По-простому:

1. Azure строится на тенантах, подписках и ресурсных группах.
2. Управление идёт через ARM и `az`.
3. Права описывает RBAC: роли на область (scope).
4. Key Vault хранит секреты, а Managed Identity — автоматические учётки.
5. Широкие роли и доступный Key Vault — главные находки.

## На что смотреть дальше

- **Начинайте с `az account show`.** Поймите, под кем вы и в каком тенанте.
- **Ищите `Contributor`/`Owner`.** Это почти полный контроль.
- **Проверяйте Key Vault.** Секреты часто открыты вместе с ролью.
- **Помните про логи.** Azure пишет активность; шумно работать рискованно.

## Квиз

Проверь себя.

```quiz
- question: "Что такое tenant в Azure?"
  options:
    - "Виртуальная машина"
    - "Каталог пользователей и приложений (Entra ID)"
    - "Хранилище секретов"
    - "Балансировщик"
  answer: 1
- question: "Что описывает RBAC?"
  options:
    - "Роли и назначения прав на область (scope)"
    - "Сетевые маршруты"
    - "Размер диска"
    - "Версию ОС"
  answer: 0
- question: "Что такое Managed Identity?"
  options:
    - "Пароль администратора"
    - "Автоматическая сервисная учётка ресурса Azure без пароля"
    - "Тип базы данных"
    - "Регион Azure"
  answer: 1
- question: "Какая роль даёт почти полный контроль над подпиской?"
  options:
    - "Reader"
    - "Contributor"
    - "Key Vault Secrets User"
    - "Guest"
  answer: 1
- question: "Что хранит Key Vault?"
  options:
    - "Виртуальные машины"
    - "Пароли, ключи и сертификаты"
    - "Логи трафика"
    - "Пользователей Entra ID"
  answer: 1
```

## Куда дальше

В следующем уроке мы разберём **GCP**: проекты, IAM и сервисные аккаунты — и увидим, чем модель Google отличается от Azure. А пока запомни главное: в Azure разведка начинается с `az account show`, а находки почти всегда лежат в широких ролях и доступном Key Vault.

## Где пригодится

- **CTF (Cloud):** задачи с доступом к облачному аккаунту.
- **Bug bounty:** оценка облачной конфигурации компаний.
- **Пентест:** аудит Azure, поиск переразданных прав.
- **Blue team / SOC:** понимание, что видит атакующий с одной ролью.
