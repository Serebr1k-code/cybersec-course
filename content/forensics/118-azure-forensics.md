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

## Вопрос, с которого всё начинается

В облаке нет диска, который можно «снять» и принести в лабораторию. Единственный след действий — **логи**. Но у Azure их много, и лежат они в разных местах. Как понять, что аккаунт скомпрометировали, если смотреть не на что, кроме журналов?

## Наш пример: подозрительное назначение роли

В службу безопасности пришёл алерт: в подписке появился новый владелец. У нас есть доступ к Azure CLI и к логам. Разберёмся, что произошло.

Сначала важная модель. У Azure **два control plane** (плоскости управления):

- **ARM** (Azure Resource Manager) — управление ресурсами: виртуальные машины, хранилища, сеть.
- **Entra ID** (бывшая Azure AD) — идентичность: пользователи, приложения, роли.

Инцидент обычно затрагивает обе: сначала компромисс идентичности (Entra), затем действия с ресурсами (ARM).

## Шаг 1: смотрим Activity Log

**Activity Log** — журнал операций ARM с ресурсами. Ищем изменения ролей (`roleAssignments`):

```bash
$ az login
$ az monitor activity-log list --offset 3d \
    --query "[?operationName.value=='Microsoft.Authorization/roleAssignments/write']" -o table
Time                ResourceGroup  OperationName                                  Status     Caller
2024-03-01 22:14Z   rg-prod        Microsoft.Authorization/roleAssignments/write  Succeeded  app-sp-abc
```

Кто-то `app-sp-abc` выдал себе роль в `rg-prod`. Имя похоже на **service principal** — это «сервисная учётка», от имени которой работает приложение или автоматизация.

## Шаг 2: кто такой app-sp-abc

```bash
$ az ad sp list --display-name "app-sp-abc" -o table
DisplayName   AppId                                 CreatedDateTime
app-sp-abc    11111111-2222-3333-4444-555555555555  2024-03-01T22:10:00Z
```

Вот и связь: service principal создан в **22:10**, а роль назначена в **22:14** — четыре минуты спустя. Типичная цепочка атаки: «создал приложение → выдал ему права → работает от его имени». Дальше — смотреть sign-in logs этого приложения.

## Шаг 3: sign-in и audit логи Entra

**Sign-in logs** фиксируют входы пользователей, **Audit logs** — изменения объектов (ролей, приложений, пользователей). Выгружаются через Microsoft Graph PowerShell:

```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All"
Get-MgAuditLogSignIn -Top 50 | Select-Object CreatedDateTime,UserPrincipalName,IPAddress,ClientAppUsed,Status
Get-MgAuditLogDirectoryAudit -Top 50 | Select-Object ActivityDateTime,ActivityDisplayName,InitiatedBy,TargetResources
```

Что искать в этих логах:

- **Входы из нетипичных мест** — аномальный IP/страна, «impossible travel» (два входа из разных стран за минуты).
- **Успешный вход после серии неудач** — признак password spray (перебор паролей по многим аккаунтам).
- **Legacy-аутентификация** — старые протоколы (IMAP/POP) в обход MFA.
- **Создание/изменение приложения** — новые app registration, добавление секретов.
- **Изменения RBAC** — назначение Owner/Contributor.
- **Consent grant** — приложению выдали доступ к данным (OAuth phishing).

## Шаг 4: KQL — язык запросов Log Analytics

Если логи перенаправлены в **Log Analytics**, расследование ведётся на **KQL** (Kusto Query Language). Основные таблицы: `SigninLogs`, `AuditLogs`, `AzureActivity`.

```kusto
// Входы с риском
SigninLogs
| where RiskLevelDuringSignIn in ("high","medium")
| project TimeGenerated, UserPrincipalName, IPAddress, RiskDetail
| order by TimeGenerated desc

// Spray: много неудач по многим пользователям с одного IP
SigninLogs
| where ResultType != 0
| summarize attempts=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where attempts > 20

// Новые приложения
AuditLogs
| where OperationName == "Add application"
| project TimeGenerated, InitiatedBy, TargetResources
```

## Шаг 5: сроки хранения и сбор доказательств

Важная практическая деталь: по умолчанию Activity Log хранится **90 дней**, Entra — меньше (30 дней для некоторых логов). Без настройки **Diagnostic settings** (перенаправление логов в Storage/Log Analytics) старые события не вернуть. Сам факт отключения логирования — тоже индикатор атаки.

Сбор доказательств:

```bash
# Выгрузить Activity Log за 30 дней и зафиксировать хеш
$ az monitor activity-log list --offset 30d -o json > activity_$(date -u +%Y%m%d).json
$ sha256sum activity_*.json > activity.sha256
# Снапшот диска ВМ для последующего disk-forensics
$ az snapshot create -g rg-forensics -n snap-disk1 --source /subscriptions/.../disks/disk1
```

Для облачных доказательств действует та же дисциплина, что и для дисков: фиксируйте время выгрузки, считайте хеши, анализируйте копии, документируйте запросы. Все метки — в **UTC**.

## Что мы теперь знаем

- У Azure два control plane: **ARM** (ресурсы) и **Entra ID** (идентичность); инцидент затрагивает оба.
- **Activity Log** фиксирует операции ARM; **sign-in/audit logs Entra** — входы и изменения объектов.
- Связка «новый service principal → назначение роли» — классическая цепочка эскалации.
- **KQL** в Log Analytics — основной язык расследования (`SigninLogs`, `AuditLogs`, `AzureActivity`).
- По умолчанию логи хранятся ограниченно; без Diagnostic settings старые события теряются.
- Сам факт отключения логирования — индикатор компрометации.

## Квиз

Проверь себя.

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
- question: "На каком языке строят запросы к Log Analytics?"
  options:
    - "SQL"
    - "KQL (Kusto Query Language)"
    - "YAML"
    - "SPARQL"
  answer: 1
  explanation: "KQL — язык запросов Kusto, используемый в Log Analytics/Sentinel."
```

## Куда дальше

Мы разобрали расследование Azure/Entra. В следующем уроке (`forensics-gcp-forensics`) перейдём во второе облако — GCP — и увидим, как аудит устроен через единые Cloud Audit Logs. А пока главное запомни: **в Azure инцидент связывает Entra (кто) и ARM (что); ключ к расследованию — корреляция sign-in, audit и Activity Log по времени**.

## Где пригодится

- **CTF:** задачи с логами Azure/Entra.
- **Cloud IR:** расследование компрометации идентичности и ресурсов.
- **Threat Hunting:** поиск аномальных входов и изменений RBAC.
- **Аудит:** проверка настроек логирования.
