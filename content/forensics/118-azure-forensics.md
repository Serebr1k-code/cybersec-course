---
id: forensics-azure-forensics
title: "Форензика Azure и Entra ID: логи и признаки компрометации"
category: forensics
parent: forensics-cloud-multi
difficulty: hard
order: 1
tags: [azure, entra, activity-log, signin, cloud-forensics, kql]
prerequisites: [forensics-cloud]
useful_for:
  - "CTF Forensics категория"
  - "Cloud Incident Response"
  - "Threat Hunting"
estimated_minutes: 52
summary: "Источники логов Azure (Activity Log, Entra ID sign-in/audit, Diagnostic settings) и признаки компрометации: подозрительные входы, изменения RBAC, создание приложений и managed identity, сбор доказательств через KQL."
---

Azure — это два связанных, но разных control plane: **ARM** (управление ресурсами: VM, storage, сеть) и **Entra ID** (бывшая Azure AD — идентичность: пользователи, приложения, роли). Инцидент почти всегда затрагивает оба: сначала компрометация идентичности (Entra), затем действия с ресурсами (ARM). Поэтому форензика Azure начинается с правильного набора логов.

## Источники логов

| Источник | Что логирует | Где |
|----------|--------------|-----|
| Azure Activity Log | операции ARM с ресурсами | Portal / Log Analytics |
| Entra ID Sign-in logs | входы пользователей | Entra portal / Log Analytics |
| Entra ID Audit logs | изменения объектов, ролей, приложений | Entra portal |
| Diagnostic settings | перенаправление логов в Log Analytics/Storage/Event Hub | на каждом ресурсе |
| NSG flow logs | сетевые потоки (5-tuple) | Storage / Log Analytics |

Важно: по умолчанию срок хранения Activity Log — **90 дней**, Entra — 30 дней (для некоторых логов); для длительного расследования нужен экспорт в Storage/Log Analytics.

```bash
# Azure CLI: список подписок и Activity Log
az login
az account list -o table
az monitor activity-log list --start-time 2024-03-01T00:00:00Z --max-events 50 -o table
# Фильтр по типу операции
az monitor activity-log list --offset 7d --query "[?contains(operationName.value,'roleAssignments')]" -o table
```

## Entra ID: подключение модуля и выгрузка

```bash
# Microsoft Graph PowerShell
Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All"
# Sign-in logs
Get-MgAuditLogSignIn -Top 50 | Select-Object CreatedDateTime,UserPrincipalName,IPAddress,ClientAppUsed,Status
# Audit logs
Get-MgAuditLogDirectoryAudit -Top 50 | Select-Object ActivityDateTime,ActivityDisplayName,InitiatedBy,TargetResources
```

## Признаки компрометации

- **Входы из нетипичных мест** — аномальный IP/страна, impossible travel.
- **Успешный вход после серии неудач** — password spray.
- **Legacy-аутентификация** — старые протоколы (IMAP/POP) в обход MFA.
- **Создание/изменение приложения** — новые app registration, добавление credentials/секретов.
- **Изменения RBAC** — назначение Owner/Contributor, повышение прав service principal.
- **Managed identity abuse** — выдача прав managed identity, доступ к Key Vault.
- **Создание новых пользователей/гостей** — персистентность.
- **Изменение политик условного доступа** — отключение MFA.

```bash
# KQL в Log Analytics: входы с ошибкой (spray)
SigninLogs
| where ResultType != 0
| summarize attempts=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where attempts > 20
# Успешный вход после неудач
SigninLogs
| where UserPrincipalName == "user@contoso.com"
| project TimeGenerated, IPAddress, ResultType, AppDisplayName
| order by TimeGenerated desc
# Изменения ролей
AuditLogs
| where OperationName has "role"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

## Разобранный пример

```bash
$ az monitor activity-log list --offset 3d --query "[?operationName.value=='Microsoft.Authorization/roleAssignments/write']" -o table
Time                ResourceGroup  OperationName                                  Status  Caller
2024-03-01 22:14Z   rg-prod        Microsoft.Authorization/roleAssignments/write  Succeeded  app-sp-abc
$ # Кто такой app-sp-abc?
$ az ad sp list --display-name "app-sp-abc" -o table
DisplayName   AppId                                 CreatedDateTime
app-sp-abc    11111111-2222-3333-4444-555555555555  2024-03-01T22:10:00Z
```

Вывод: незадолго до назначения роли был создан service principal — типичная цепочка «создал приложение → выдал себе Owner». Дальше — смотреть sign-in logs этого приложения и действия от его имени.

## Сбор доказательств

- **Экспорт Activity Log** в Storage account (JSON) для сохранения.
- **Экспорт Entra logs** через `Get-MgAuditLog*` в CSV/JSON.
- **Снапшот диска ВМ** (`az snapshot create`) — для последующего disk-forensics.
- **NSG flow logs** — сетевой контекст.
- **Key Vault audit logs** — доступ к секретам.

```bash
# Создать снапшот диска для оффлайн-анализа
az snapshot create -g rg-forensics -n snap-disk1 --source /subscriptions/.../disks/disk1
# Выгрузить Activity Log
az monitor activity-log list --offset 30d -o json > activity.json
```

## Краевые случаи и подводные камни

- **Сроки хранения.** 90/30 дней по умолчанию; без Diagnostic settings старые логи не вернуть.
- **Два control plane.** Логи Entra и ARM раздельны; коррелируйте по времени и identity.
- **Права на чтение логов.** `AuditLog.Read.All` нужен; без него выгрузка неполна.
- **IP-адреса за прокси.** `IPAddress` в sign-in может быть прокси/CDN; смотрите `OriginalTransferMethod`.
- **Managed identity не логинится как пользователь.** Её действия видны в Activity/Audit по principal id.
- **Логи можно отключить.** Атакующий может изменить Diagnostic settings — проверяйте и это.
- **Часовой пояс.** Azure логирует UTC.
- **App credentials.** Секреты приложений можно добавить без «входа» — проверяйте `Update application` события.

## KQL: язык запросов Log Analytics

Если логи Azure/Entra перенаправлены в Log Analytics, расследование ведётся на KQL (Kusto Query Language). Основные таблицы:

| Таблица | Содержимое |
|---------|-----------|
| `SigninLogs` | входы пользователей (Entra) |
| `AADNonInteractiveUserSignInLogs` | неинтерактивные входы |
| `AuditLogs` | изменения в Entra |
| `AzureActivity` | операции ARM |
| `AzureNetworkAnalytics_CL` | сетевые потоки NSG |
| `SecurityEvent` | события безопасности ВМ (Sentinel) |

```kusto
// Входы с риском
SigninLogs
| where RiskLevelDuringSignIn in ("high","medium")
| project TimeGenerated, UserPrincipalName, IPAddress, RiskDetail, AppDisplayName
| order by TimeGenerated desc

// Impossible travel (упрощённо): два IP из разных стран за короткое время
SigninLogs
| summarize Countries=dcount(Location), IPs=make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h)
| where Countries > 1

// Новые приложения
AuditLogs
| where OperationName == "Add application"
| project TimeGenerated, InitiatedBy, TargetResources

// Изменения в условном доступе
AuditLogs
| where OperationName has "conditional access"
| project TimeGenerated, OperationName, InitiatedBy
```

## Интеграция с Microsoft Sentinel

Sentinel добавляет аналитические правила, watchlists и инциденты. Для форензика полезно:

- **Bookmarks** — зафиксировать ключевые события.
- **Hunting queries** — сохранять KQL-запросы.
- **Incident timeline** — связать события из разных источников.
- **Entity mapping** — автоматически связывать IP/пользователя/хост.

```kusto
// Подозрительное создание service principal + назначение роли
let sp = AuditLogs | where OperationName == "Add service principal" | project spTime=TimeGenerated, spName=TargetResources;
let ra = AzureActivity | where OperationName contains "roleAssignments/write" | project raTime=TimeGenerated, Caller;
sp | join kind=inner (ra) on $left.spTime < $right.raTime
```

## Сбор артефактов из ресурсов

Помимо логов, Azure хранит артефакты на уровне ресурсов:

- **Диски ВМ** — снапшоты для disk-forensics.
- **Blob-хранилища** — версии и soft-delete; журнал доступа.
- **Key Vault** — audit-логи доступа к секретам/ключам.
- **Function App** — код и переменные окружения (могут содержать секреты).
- **Container Registry** — образы, теги, подписи.

```bash
# Снапшот диска
az snapshot create -g rg-forensics -n snap-vm1 --source /subscriptions/SUB/resourceGroups/rg-prod/providers/Microsoft.Compute/disks/vm1_OsDisk
# Список версий blob
az storage blob list --container-name data --account-name acct --include v -o table
# Audit Key Vault
az monitor diagnostic-settings list --resource /subscriptions/SUB/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1
```

## Признаки компрометации: расширенный список

- **Consent grant** — злоумышленник выдаёт приложению доступ к данным (OAuth consent phishing).
- **Добавление federated credential** — долгоживущий доступ к app.
- **Изменение trusted IP** в условном доступе.
- **Создание временных учёток** и их быстрое удаление.
- **Экспорт данных** — массовое скачивание из SharePoint/OneDrive.
- **Runbook/automation account** — исполнение кода через Automation.
- **Managed identity к Key Vault** — кража секретов.

## Ограничения и подводные камни

- **Задержка логирования.** Некоторые логи появляются с задержкой до 5–15 минут.
- **Разные схемы.** `SigninLogs` и `AADNonInteractiveUserSignInLogs` различаются; учитывайте оба.
- **Стоимость.** Log Analytics тарифицируется по объёму; большие запросы дороги.
- **Права.** Для полного доступа нужны роли Log Analytics Reader + Directory Reader.
- **Прокси.** IP в логах может быть прокси; используйте geo/ASN, а не только IP.
- **Отключение логирования.** Атакующий может изменить Diagnostic settings — это само по себе индикатор.

## Чек-лист Azure-расследования

1. Собрать Activity Log + Entra sign-in/audit.
2. Перенаправить в Log Analytics (если ещё нет).
3. Искать: spray, impossible travel, новые apps, RBAC-изменения, consent.
4. Сопоставить identity (Entra) ↔ действия (ARM) ↔ сеть (NSG flows).
5. Сделать снапшоты дисков и выгрузить blob-версии.
6. Задокументировать таймлайн в UTC.

## Экспорт логов и цепочка сохранности в облаке

Для облачных доказательств важна та же дисциплина, что и для дисков:

- **Фиксируйте время выгрузки** и период покрытия логов.
- **Считайте хеши** выгруженных JSON/CSV-файлов.
- **Не редактируйте** исходные логи — анализируйте копии.
- **Документируйте запросы** (KQL/CLI), которыми получены данные.

```bash
az monitor activity-log list --offset 30d -o json > activity_$(date -u +%Y%m%d).json
sha256sum activity_*.json > activity.sha256
```

Такой подход делает облачное расследование воспроизводимым и пригодным для отчёта.

## Что дальше / решение

1. `az login` и собрать Activity Log за период.
2. Выгрузить Entra sign-in/audit logs (Graph).
3. Найти аномалии (spray, impossible travel, новые apps, RBAC).
4. Сопоставить Entra ↔ ARM ↔ NSG flow logs.
5. Сделать снапшоты дисков для disk-forensics.

Дальше — `forensics-gcp-forensics` (второе облако) и `forensics-cloud-trail` (AWS).

## Квиз

```quiz
- question: "Какой лог Azure фиксирует операции с ресурсами (control plane ARM)?"
  options:
    - "Sign-in log"
    - "Activity Log"
    - "NSG flow log"
    - "Key Vault audit"
  answer: 1
  explanation: "Azure Activity Log — журнал операций ARM с ресурсами."
- question: "Какой признак в Entra sign-in logs указывает на password spray?"
  options:
    - "один успешный вход"
    - "много неудачных попыток по многим пользователям с одного IP"
    - "использование MFA"
    - "вход из офиса"
  answer: 1
  explanation: "Spray — массовые неудачные попытки; успех после серии неудач особенно подозрителен."
- question: "Почему создание нового app registration — тревожный сигнал?"
  options:
    - "Это всегда ошибка"
    - "Через приложение можно получить доступ и добавить credentials для персистентности"
    - "Приложения не логируются"
    - "Это замедляет Azure"
  answer: 1
  explanation: "App registration + credentials — распространённая персистентность в Entra."
- question: "Что делать, чтобы сохранить логи дольше 90 дней?"
  options:
    - "Ничего, они хранятся вечно"
    - "Настроить Diagnostic settings и экспорт в Storage/Log Analytics"
    - "Удалить подписку"
    - "Отключить MFA"
  answer: 1
  explanation: "По умолчанию срок ограничен; для длительного хранения нужен экспорт."
```

## Где пригодится

- **CTF:** задачи с логами Azure/Entra.
- **Cloud IR:** расследование компрометации идентичности и ресурсов.
- **Threat Hunting:** поиск аномальных входов и изменений RBAC.
- **Аудит:** проверка настроек логирования.
