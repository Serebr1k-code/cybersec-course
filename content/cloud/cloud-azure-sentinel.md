---
id: cloud-azure-sentinel
title: "Microsoft Sentinel: SIEM/SOAR, правила и слепые зоны"
category: cloud
parent: cloud-azure-platform-deep
difficulty: hard
order: 2
tags: [cloud, azure, sentinel, siem, soar, analytics-rules, detection]
prerequisites: [cloud-azure-platform-deep, cloud-logging-detection]
useful_for:
  - "Оценка слепых зон детекта в Azure"
  - "Понимание SIEM/SOAR для OPSEC"
  - "Аудит аналитических правил"
estimated_minutes: 45
summary: "Microsoft Sentinel: data connectors, analytics rules, workbooks и automation. Что реально детектируется, где слепые зоны и как атакующий минимизирует след."
---

## Зачем этот урок

Microsoft Sentinel — облачный SIEM/SOAR на базе Log Analytics. Он собирает логи из Entra ID, Azure, Office 365, сторонних источников, применяет аналитические правила и запускает автоматизации (playbooks). Для атакующего Sentinel важен по двум причинам: во-первых, он определяет, что защита реально видит (какие логи подключены, какие правила включены); во-вторых, сам Sentinel — ресурс Azure, и ошибки в его настройках могут создавать слепые зоны или, наоборот, давать атакующему данные о детекте.

## Модель Sentinel

- **Workspace** — Log Analytics workspace, где хранятся логи.
- **Data connector** — источник (Entra ID, Azure Activity, Defender, AWS, syslog). Если коннектор не настроен — событий нет.
- **Analytics rule** — правило (Scheduled, NRT, Fusion, ML), которое ищет паттерны и создаёт инциденты.
- **Incident** — сработавшее правило; может иметь severity и автоматизации.
- **Workbook** — дашборд.
- **Automation rule / Playbook** — SOAR-логика (Logic Apps), реагирующая на инцидент.
- **Watchlist** — списки (IP, домены) для обогащения.

Ключевой принцип: **если лог не подключён, Sentinel его не видит**. Типичные пробелы — Azure Activity (management) подключён, а диагностические логи сервисов (Key Vault, Storage, NSG flow) — нет.

## Инструменты и команды

```bash
# Список workspace и коннекторов
az monitor log-analytics workspace list --query '[].{Name:name,RG:resourceGroup}'
az sentinel data-connector list --workspace-name sentinel-ws --resource-group rg

# Аналитические правила и их состояние
az sentinel alert-rule list --workspace-name sentinel-ws --resource-group rg \
  --query '[].{Name:name,Enabled:enabled,Severity:severity}'

# Инциденты
az sentinel incident list --workspace-name sentinel-ws --resource-group rg \
  --query '[].{Title:title,Severity:severity,Status:status}'

# Запросы к Log Analytics (KQL)
az monitor log-analytics query --workspace <workspace-id> \
  --analytics-query "AzureActivity | where OperationNameValue contains 'roleAssignments' | take 10"

# Что вообще приходит в workspace
az monitor log-analytics query --workspace <workspace-id> \
  --analytics-query "search * | summarize count() by Type | top 20 by count_"
```

## Разобранный пример: оценка слепых зон

Сценарий: мы в подписке с Sentinel и хотим понять, что нас выдаст.

```bash
az sentinel data-connector list --workspace-name sentinel-ws --resource-group rg \
  --query '[].{Name:name,Kind:kind}'
# [{"Name":"AzureActiveDirectory","Kind":"AzureActiveDirectory"},
#  {"Name":"AzureActivity","Kind":"AzureActiveDirectory"}]

az sentinel alert-rule list --workspace-name sentinel-ws --resource-group rg \
  --query '[?enabled==`true`].name'
# ["Suspicious sign-in","New role assignment","Mass file download"]
```

Вывод: подключены Entra ID и Azure Activity; аналитические правила ловят подозрительный вход, назначение ролей и массовое скачивание файлов. Но **диагностические логи Key Vault/Storage не подключены** — значит, чтение секретов и данных не попадёт в Sentinel (хотя может попасть в Azure Activity, если включить diagnostic settings). Проверяйте `az monitor diagnostic-settings list` для критичных ресурсов.

## Что реально видит Sentinel

| Действие | Источник логов | Ловится, если подключено |
|---|---|---|
| Назначение роли | Azure Activity | Да (правило) |
| Подозрительный вход | Entra ID sign-in | Да |
| Чтение секрета Key Vault | Key Vault diagnostic | Только если включено |
| Скачивание Blob | Storage diagnostic | Только если включено |
| NSG flow | Network Watcher | Только если включено |
| Аномальный ARM-вызов | Azure Activity | Да |
| Создание подозрительного ресурса | Azure Activity | Часто да |

Атакующий, который знает эту таблицу, выбирает действия в наименее покрытых категориях и избегает «громких» операций (role assignment, создание ресурсов).

## Обход защит и edge cases

- **Diagnostic settings.** Чтение Key Vault/Storage логируется только при включённых диагностических логах. Если их нет — невидимо.
- **Data retention.** Логи хранятся ограниченное время (30-90 дней); старые действия исчезают.
- **Analytics rule tuning.** Правила могут быть отключены/настроены слишком узко. Проверяйте список enabled.
- **Playbook (Logic App).** Автоматизация может блокировать действие; но её тоже можно изучить/отключить, если есть права.
- **Workspace access.** Если у вас есть доступ к workspace, вы можете читать логи детекта и подстраиваться.
- **Fusion.** Корреляционные правила могут связать разрозненные события; учитывайте.

## Частые ошибки и подводные камни

- Считать, что «Sentinel включён» = полный детект: без коннекторов он слеп.
- Не проверить диагностические логи ресурсов.
- Игнорировать retention: старые следы исчезают.
- Путать Azure Activity (management) и resource logs (data).
- Не проверить enabled-состояние правил.

## Защита и детект

- Подключить все критичные коннекторы, включая диагностические логи Key Vault/Storage/NSG.
- Включить аналитические правила для назначения ролей, доступа к секретам, аномальных входов.
- Настроить automation rules/playbooks для блокировки.
- Ограничить доступ к workspace; включить RBAC.
- Регулярно проверять покрытие коннекторов и включённость правил.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — Azure Activity подключён, а диагностические логи сервисов — нет. Второй — отключённые правила. Третий — короткий retention. Четвёртый — широкий доступ к workspace. Пятый — отсутствие playbooks. Все они создают слепые зоны для OPSEC.

## Практическое задание

1. Создайте Log Analytics workspace и подключите Azure Activity.
2. Включите правило «New role assignment» и назначьте роль — убедитесь, что инцидент создан.
3. Не подключайте Key Vault diagnostic и прочитайте секрет — убедитесь, что инцидента нет.
4. Подключите diagnostic и повторите.

## Что дальше / решение

Понимание Sentinel — часть OPSEC в Azure. Определите, какие действия логируются, и выбирайте минимально покрытые. Зафиксируйте слепые зоны в графе. Если Sentinel настроен полно — действуйте быстро, через легитимные операции и в рамках существующих ресурсов.

## Разобранный пример 2: проверка покрытия через KQL

Лучший способ понять слепые зоны — посмотреть, какие типы таблиц вообще есть в workspace, и сверить их с тем, что вы планируете делать.

```bash
WS=$(az monitor log-analytics workspace list --query '[0].customerId' -o tsv)

# Какие таблицы наполняются
az monitor log-analytics query --workspace "$WS" \
  --analytics-query "search * | summarize Count=count() by \$table | order by Count desc | take 25"

# Есть ли Key Vault-логи
az monitor log-analytics query --workspace "$WS" \
  --analytics-query "AzureDiagnostics | where ResourceProvider == 'MICROSOFT.KEYVAULT' | count"

# Есть ли Storage-логи
az monitor log-analytics query --workspace "$WS" \
  --analytics-query "StorageBlobLogs | count"

# Проверяем, включены ли диагностические логи у ресурса
az monitor diagnostic-settings list --resource <resource-id> \
  --query '[].{Name:name,Logs:logs[].category}'
```

Если `AzureDiagnostics` по Key Vault пуст, чтение секретов в Sentinel не видно. Если `StorageBlobLogs` отсутствует, скачивание файлов невидимо. Заполните таблицу покрытия и действуйте в наименее логируемых категориях. Помните: `AzureActivity` (management) обычно подключён и ловит изменения ресурсов, поэтому избегайте «громких» операций.

## Практическое задание

1. Включите Sentinel и подключите Azure Activity.
2. Проверьте KQL-запросом, какие таблицы наполняются.
3. Не подключайте Storage diagnostic и скачайте blob; проверьте, что события нет.
4. Подключите Storage diagnostic и повторите.

## Квиз

```quiz
- question: "Что определяет, видит ли Sentinel событие?"
  options:
    - "Подключён ли соответствующий data connector/диагностический лог"
    - "Размер workspace"
    - "Регион"
    - "Тип подписки"
  answer: 0
  explanation: "Без коннектора события в workspace не попадают."
- question: "Почему чтение Key Vault может быть невидимым?"
  options:
    - "Диагностические логи Key Vault не подключены к workspace"
    - "Key Vault не логирует вообще"
    - "Sentinel не поддерживает Key Vault"
    - "Логи шифруются"
  answer: 0
  explanation: "Data-plane логи идут в диагностику, которую надо явно включить."
- question: "Что создаёт analytics rule?"
  options:
    - "Инцидент при совпадении условия"
    - "Ресурс Azure"
    - "Managed identity"
    - "VNet"
  answer: 0
  explanation: "Правило анализирует логи и создаёт инциденты."
- question: "Что делает automation rule/playbook?"
  options:
    - "Автоматически реагирует на инцидент (SOAR)"
    - "Шифрует логи"
    - "Меняет регион"
    - "Удаляет подписку"
  answer: 0
  explanation: "Playbooks — это Logic Apps, реагирующие на инциденты."
```

## Где пригодится

- **Red team:** оценка детекта и OPSEC.
- **Blue team:** настройка Sentinel.
- **Пентест Azure:** понимание видимости действий.
- **Сертификация:** SC-200.
