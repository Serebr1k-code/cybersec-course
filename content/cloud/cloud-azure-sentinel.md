---
id: cloud-azure-sentinel
title: "Microsoft Sentinel: SIEM/SOAR, правила и слепые зоны"
category: cloud
parent: cloud-logging-detection
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
lab:
  kind: shell
  title: "Практика: Microsoft Sentinel — правила и слепые зоны"
  toolset: [core]
  workdir: /home/student/sentinel
  files: [task.md, notes.md, analytics-rules.json, signin-logs.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`analytics-rules.json` — правила детекта; `signin-logs.txt` — события входа."
    - "Ищи активность, не покрытую правилами."
    - "Найди флаг: `grep nto signin-logs.txt > found.txt`."

---
## Задача

Мы разбирали AWS-детект. Теперь — Azure. В Azure журналы собирает **Microsoft Sentinel** — облачный **SIEM** (Security Information and Event Management: система сбора и анализа событий безопасности) с элементами **SOAR** (автоматическое реагирование). Задача: понять, как Sentinel видит атакующего и где у него слепые зоны. Разберём на конкретном тенанте.

## Данные: что и откуда собирает Sentinel

Sentinel собирает данные через **data connectors** (коннекторы). Каждый коннектор подключает источник: Azure AD, Activity Log, Defender, firewall, сторонние системы. Смотрим подключённые:

```
$ az sentinel data-connector list --workspace-name acme-sentinel -g sec-rg \
    --query '[].{name:name,kind:kind}' -o table
Name                        Kind
AzureActiveDirectory        AzureActiveDirectory
AzureActivity               AzureActivity
MicrosoftDefenderAdvancedThreatProtection  MicrosoftDefenderAdvancedThreatProtection
```

Три коннектора. Замечаем: **нет** коннектора на, скажем, Azure Key Vault или Storage. Значит, действия с секретами и блобами в Sentinel **не видны** — первая слепая зона.

## Пробуем в лоб: ищем правила, которые нас поймают

**Analytics rules** (аналитические правила) — это запросы на языке KQL, которые срабатывают на события. Смотрим, какие есть:

```
$ az sentinel alert-rule list --workspace-name acme-sentinel -g sec-rg \
    --query '[].{name:name,severity:severity}' -o table
Name                              Severity
Suspicious sign-in                 Medium
Mass secret read                   High
New admin role assignment          High
```

Правило `Mass secret read` — High. Если оно использует Key Vault, а коннектора Key Vault нет, правило не сработает: **правило есть, данных нет**. Смотрим его запрос:

```
$ az sentinel alert-rule show --workspace-name acme-sentinel -g sec-rg \
    --rule-id <id> --query 'query'
AzureDiagnostics | where ResourceProvider == "MICROSOFT.KEYVAULT" | where OperationName == "SecretGet"
```

Правило опирается на `AzureDiagnostics` от Key Vault. Если диагностические логи Key Vault не включены на самом хранилище — правило пустое.

## Приём: действуем в непокрытой зоне

Ключевой вывод: Sentinel видит только то, что подключено **и** на источнике включено. Ищем ресурсы, чьи логи не текут в workspace.

**1. Диагностические настройки не включены.** У Key Vault нет diagnostic settings:

```
$ az monitor diagnostic-settings list --resource $(az keyvault show -n acme-kv --query id -o tsv) \
    --query 'value[].name'
[]
```

Пусто — операции с секретами никуда не пишутся. Читаем секреты:

```
$ az keyvault secret show --vault-name acme-kv --name db-password --query value -o tsv
Pr0d-DB-P@ss
```

В Sentinel — тишина.

**2. Плоскость управления vs данные.** Azure Activity Log (management plane) пишет `Microsoft.KeyVault/vaults/write`, но **не** чтение секрета (data plane). Часто ловят создание хранилища, но не кражу из него.

**3. Регионы и подписки вне коннектора.** Если коннектор настроен на одну подписку, действия в другой не попадут.

## Полный прогон: от слепой зоны до тихой кражи

1. **Смотрим коннекторы.** `data-connector list` → чего не хватает.
2. **Смотрим правила.** `alert-rule list` → на каких данных они основаны.
3. **Находим непокрытый ресурс.** Key Vault/Storage без diagnostic settings.
4. **Проверяем.** `diagnostic-settings list` → пусто.
5. **Действуем.** `keyvault secret show` / `az storage blob download`.
6. **Не оставляем шума.** Management-plane вызовы (`az login`, `list`) неизбежны, но чтение данных — нет.

## Что реально ловится

Sentinel хорошо видит:

- **Входы и рискованные sign-ins** (Entra ID connector).
- **Изменения ролей** (`New admin role assignment`).
- **Создание ресурсов** (Activity Log).
- **Defender-алерты** (подозрительные процессы, malware).

Плохо видит:

- **Чтение данных** в сервисах без diagnostic settings.
- **Действия внутри VM/контейнера** (нужен агент/Defender).
- **Ресурсы в подписках без коннектора.**
- **Тонкие аномалии** в паттерне «легитимного» сервисного принципала.

## Защита и что ломает атаку (глазами защитника)

- **Включить diagnostic settings на критичные ресурсы** (Key Vault, Storage, SQL) и направить в Sentinel.
- **Коннекторы на все подписки и типы ресурсов.**
- **Правила на data-plane операции** (`SecretGet`, `BlobGet`).
- **Автоматизация (playbooks)** — изоляция учётки/ресурса по алерту.
- **UEBA** — анализ поведения пользователей, а не только одиночных событий.

## Если не сработало

- **Все diagnostic settings включены** — data-plane виден.
- **Правила покрывают Key Vault/Storage** — кража детектится.
- **Playbooks авто-реагируют** — доступ отзывают мгновенно.
- **Defender на VM** — действия внутри хоста видны.

## Мини-сценарий: кража без алерта

1. **Разведка коннекторов.** `az sentinel data-connector list` → подключены Entra ID, Activity Log, Defender. **Нет** Key Vault.
2. **Проверка правил.** `alert-rule list` → есть `Mass secret read`, но её запрос опирается на `AzureDiagnostics` от Key Vault.
3. **Проверка источника.** `az monitor diagnostic-settings list --resource <kv-id>` → пусто. Логи Key Vault никуда не идут.
4. **Действие.** `az keyvault secret show --vault-name acme-kv --name db-password -o tsv` → `Pr0d-DB-P@ss`.
5. **Результат.** В Sentinel — тишина: правило есть, данных нет. Activity Log фиксирует управление, но не чтение секрета.
6. **Закрепление.** Тот же приём с Storage: `az storage blob download` без diagnostic settings.

Вывод: наличие правила детекта ничего не значит без подключённого источника и включённых diagnostic settings. Это и есть слепая зона SIEM.

## Разбор: детект начинается с данных

Sentinel — это аналитика поверх данных, и без данных он бессилен. Правило `Mass secret read` звучит грозно, но если диагностические логи Key Vault не включены, запрос всегда возвращает пусто. Это фундаментальный урок про SIEM в облаке: **сначала поток данных, потом правило**. Многие команды пишут десятки правил и забывают включить `diagnostic settings` на критичных ресурсах — и получают ложное чувство защищённости. Аудит Sentinel начинается не со списка правил, а со списка **источников**: какие коннекторы подключены, на какие подписки, и включены ли diagnostic settings на ресурсах, которые нас интересуют (Key Vault, Storage, SQL).

## Что мы теперь знаем

1. Sentinel собирает данные через коннекторы; чего нет в коннекторе — не видно.
2. Analytics rules — KQL-запросы; без данных они молчат.
3. Diagnostic settings на ресурсе — условие видимости data-plane.
4. Activity Log видит управление, но не чтение данных.
5. Слепые зоны — непокрытые ресурсы, подписки и data-plane операции.

## Частые ошибки

- **Коннектор не покрывает все подписки** — часть ресурсов вне видимости.
- **Правила без данных**: diagnostic settings выключены.
- **Нет playbooks** — алерты не приводят к реакции.
- **Только management-plane** — чтение данных не видно.
- **Нет UEBA** — аномалии поведения принципалов не ловятся.

## На что смотреть дальше

- Список data connectors и чего в нём нет.
- Analytics rules и их источник данных.
- Diagnostic settings на Key Vault/Storage/SQL.
- Покрытие подписок коннекторами.
- Наличие playbooks (авто-реакции).

## Быстрая проверка

```bash
az sentinel data-connector list --workspace-name acme-sentinel -g sec-rg -o table
az sentinel alert-rule list --workspace-name acme-sentinel -g sec-rg -o table
az monitor diagnostic-settings list --resource <resource-id>
az keyvault secret show --vault-name acme-kv --name db-password --query value -o tsv
```

## Квиз

Проверь себя.

```quiz
- question: "Что такое Microsoft Sentinel?"
  options:
    - "Облачный SIEM/SOAR для сбора и анализа событий безопасности"
    - "Реестр контейнеров"
    - "Виртуальная машина"
    - "Хранилище секретов"
  answer: 0
  explanation: "Sentinel — SIEM с автоматизацией (SOAR)."
- question: "Как Sentinel получает данные?"
  options:
    - "Через data connectors"
    - "Через пароли"
    - "Через DNS"
    - "Через SSH"
  answer: 0
  explanation: "Коннекторы подключают источники данных."
- question: "Почему analytics rule может не срабатывать при наличии правила?"
  options:
    - "Нет данных: источник не подключён или diagnostic settings выключены"
    - "Правило слишком быстрое"
    - "KQL устарел"
    - "Нет интернета"
  answer: 0
  explanation: "Без данных запрос возвращает пусто."
- question: "Что видит Azure Activity Log, а что нет?"
  options:
    - "Видит управление ресурсами, но не чтение данных (data plane)"
    - "Видит всё"
    - "Не видит ничего"
    - "Видит только DNS"
  answer: 0
  explanation: "Activity Log — management plane."
- question: "Как закрыть слепую зону по чтению секретов?"
  options:
    - "Включить diagnostic settings Key Vault и направить в Sentinel"
    - "Отключить Key Vault"
    - "Сменить регион"
    - "Убрать MFA"
  answer: 0
  explanation: "Без diagnostic settings data-plane не виден."
```

## Куда дальше

В следующем уроке (`cloud-container-forensics`) мы перейдём на сторону защитника и разберём, как собирают следы после инцидента в облаке и контейнерах. А пока главное: SIEM видит только подключённые источники — и это одновременно и защита, и слепая зона.

## Где пригодится

- **Red team:** OPSEC в Azure, обход слепых зон.
- **Blue team:** покрытие коннекторов и правил.
- **Пентест:** оценка видимости действий.
- **Работа/DevSecOps:** diagnostic settings, правила, playbooks.
- **Дальше по дереву:** `cloud-logging-detection`, `cloud-azure-keyvault`.
