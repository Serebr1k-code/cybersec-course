---
id: forensics-gcp-forensics
title: "Форензика GCP: Cloud Audit Logs и анализ IAM-событий"
category: forensics
parent: forensics-cloud-multi
difficulty: hard
order: 2
tags: [gcp, cloud-audit-logs, iam, service-account, logging, forensics]
prerequisites: [forensics-cloud]
useful_for:
  - "CTF Forensics категория"
  - "Cloud Incident Response"
  - "Threat Hunting"
estimated_minutes: 50
summary: "Источники логов GCP (Cloud Audit Logs: Admin Activity, Data Access, System Event, Policy Denied), признаки компрометации service account, анализ IAM-изменений и сбор доказательств."
---

GCP строит аудит вокруг **Cloud Audit Logs** — единой системы, которая логирует действия в проекте. В отличие от AWS/Azure, здесь меньше отдельных сервисов логирования: почти всё видно через один API (`logging.googleapis.com`) и один язык запросов. Это упрощает форензика, но требует понимания четырёх типов audit-логов и того, какие из них включены по умолчанию.

## Четыре типа Cloud Audit Logs

| Тип | Что логирует | Включён по умолчанию |
|-----|--------------|----------------------|
| Admin Activity | изменения ресурсов и IAM | да (нельзя отключить) |
| Data Access | чтение/запись данных | нет (нужно включать) |
| System Event | действия Google-систем | да |
| Policy Denied | отказы по org policy/VPC-SC | да |

Ключевой вывод: **Admin Activity всегда доступен** — это основа расследования. Но **Data Access по умолчанию выключен**, поэтому массовое чтение данных может не оставить следа, если его не включили заранее.

## Выгрузка логов

```bash
# Авторизация
gcloud auth login
gcloud config set project PROJECT_ID
# Admin Activity за период
gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity"' \
  --freshness=7d --format=json --limit=100 > admin_activity.json
# Data Access (если включён)
gcloud logging read 'logName:"cloudaudit.googleapis.com%2Fdata_access"' \
  --freshness=7d --format=json --limit=100 > data_access.json
# Фильтр по principal
gcloud logging read 'protoPayload.authenticationInfo.principalEmail="sa@proj.iam.gserviceaccount.com"' \
  --freshness=30d --format=json
```

## Признаки компрометации

- **Создание service account key** — `google.iam.admin.v1.CreateServiceAccountKey`; классическая персистентность.
- **Назначение ролей** — `SetIamPolicy` с повышением прав.
- **Включение Data Access logs** — иногда атакующий включает их, чтобы запутать, но чаще — отключает.
- **Создание ВМ/функций** — развёртывание криптомайнера.
- **Доступ к Secret Manager** — `AccessSecretVersion` (если Data Access включён).
- **Изменение firewall/бакетов** — `compute.firewalls.patch`, `storage.setIamPermissions`.
- **Workload Identity Federation** — добавление внешнего провайдера.
- **Импорт ключей в KMS/создание HSM-ключей**.

```bash
# Создание ключей service account
gcloud logging read 'protoPayload.methodName:"CreateServiceAccountKey"' --freshness=30d --format=json
# Изменения IAM
gcloud logging read 'protoPayload.methodName:"SetIamPolicy"' --freshness=30d --format=json
# Доступ к секретам
gcloud logging read 'protoPayload.methodName:"AccessSecretVersion"' --freshness=30d --format=json
```

## Разобранный пример

```bash
$ gcloud logging read 'protoPayload.methodName:"CreateServiceAccountKey"' --freshness=7d --format='value(protoPayload.authenticationInfo.principalEmail, protoPayload.request.name, timestamp)'
attacker@example.com  projects/p/serviceAccounts/ci-sa@p.iam.gserviceaccount.com/keys/abc  2024-03-01T22:10:00Z
$ gcloud logging read 'protoPayload.methodName:"SetIamPolicy"' --freshness=7d --format='value(protoPayload.authenticationInfo.principalEmail, timestamp)'
attacker@example.com  2024-03-01T22:12:00Z
```

Вывод: `attacker@example.com` создал ключ для `ci-sa`, затем изменил IAM — цепочка эскалации. Дальше — искать использование этого ключа (по `principalEmail` = service account) и действия от его имени.

## Инструменты

```bash
# Анализ IAM: кто что может
gcloud projects get-iam-policy PROJECT_ID --format=json > iam.json
# Поиск широких ролей
gcloud asset search-all-iam-policies --scope=projects/PROJECT_ID --query='policy:roles/owner'
# Рекомендации по безопасности
gcloud recommender recommendations list --project=PROJECT_ID --location=global \
  --recommender=google.iam.policy.Recommender
# Forseti / SCC (Security Command Center)
gcloud scc findings list organizations/ORG_ID
```

## Сбор артефактов

- **Снапшоты дисков** (`gcloud compute disks snapshot`) — для disk-forensics.
- **Экспорт логов в BigQuery/Storage** — для долгого хранения.
- **Метаданные ВМ** (`gcloud compute instances describe`) — startup-script, SSH-ключи.
- **Cloud Storage версии** — `gcloud storage ls --all-versions`.
- **Cloud Functions код** — `gcloud functions describe --gen2`.

```bash
# Снапшот диска
gcloud compute disks snapshot vm1-disk --snapshot-names=snap-vm1 --zone=us-central1-a
# Экспорт логов в Storage (sink)
gcloud logging sinks create forensic-sink storage.googleapis.com/forensic-bucket \
  --log-filter='logName:"cloudaudit.googleapis.com"'
```

## Краевые случаи и подводные камни

- **Data Access выключен.** Массовое чтение данных может не логироваться — проверяйте настройки заранее.
- **Срок хранения.** Admin Activity хранится 400 дней в `_Default`; далее — только через sink.
- **Service account key не «входит».** Его действия видны по principal, но не как sign-in.
- **Workload Identity.** Внешний провайдер может выдавать токены без явного «входа».
- **Разные проекты.** Логи разбросаны по проектам; используйте organization-level sink.
- **Время в UTC.** Все метки — UTC.
- **IAM-политики кэшируются.** Изменения могут «проявиться» с задержкой.

## Query language и фильтры logging

`gcloud logging read` принимает фильтр в синтаксисе Cloud Logging. Полезные примеры:

```bash
# Все действия конкретного пользователя
gcloud logging read 'protoPayload.authenticationInfo.principalEmail="bob@example.com"' \
  --freshness=30d --format=json
# Все изменения в проекте
gcloud logging read 'protoPayload.methodName=~"\.(create|delete|update|setIamPolicy)$"' --freshness=7d
# Действия по конкретному ресурсу
gcloud logging read 'resource.type="gce_instance" AND protoPayload.methodName:"compute.instances"' --freshness=7d
# Ошибки
gcloud logging read 'severity>=ERROR' --freshness=2d --format=json
```

Фильтр поддерживает `=`, `!=`, `:`, `=~` (regex) и логические `AND`/`OR`/`NOT`. Формат `json` удобен для последующего `jq`-разбора.

```bash
# Топ вызывающих методы
gcloud logging read 'logName:"activity"' --freshness=7d --format='value(protoPayload.methodName)' \
  | sort | uniq -c | sort -nr | head
# IP-адреса вызывающих
gcloud logging read 'logName:"activity"' --freshness=7d \
  --format='value(protoPayload.requestMetadata.callerIp)' | sort | uniq -c | sort -nr | head
```

## Поля, на которые смотреть

Каждая audit-запись имеет структуру:

| Поле | Значение |
|------|----------|
| `protoPayload.authenticationInfo.principalEmail` | кто выполнил |
| `protoPayload.requestMetadata.callerIp` | откуда |
| `protoPayload.requestMetadata.callerSuppliedUserAgent` | чем (CLI/консоль/SDK) |
| `protoPayload.methodName` | что сделано |
| `protoPayload.resourceName` | над чем |
| `protoPayload.serviceData` | детали (policyDelta и т. п.) |
| `protoPayload.status` | успех/ошибка |
| `resource.labels` | проект/зон/ресурс |

`callerSuppliedUserAgent` помогает отличить автоматизацию (`google-cloud-sdk`, `google-api-python-client`) от консольного доступа и сторонних инструментов — важный контекст.

## Реконструкция цепочки атаки

Типовая GCP-атака и её следы:

1. **Первичный доступ** — украденный токен/ключ, часто через публичный репозиторий или SSRF к metadata.
2. **Разведка** — `GetIamPolicy`, `ListServiceAccounts`, `TestIamPermissions`.
3. **Эскалация** — `SetIamPolicy`, `CreateServiceAccountKey`, добавление роли.
4. **Персистентность** — ключ SA, добавление в IAM, Workload Identity.
5. **Воздействие** — создание ВМ для майнинга, доступ к секретам, эксфильтрация из GCS/BigQuery.

```bash
# Шаг 3-4: создание ключа и изменение политики
gcloud logging read 'protoPayload.methodName:"CreateServiceAccountKey" OR protoPayload.methodName:"SetIamPolicy"' \
  --freshness=30d --format='value(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.methodName)'
```

Собрав шаги по времени, вы получаете таймлайн с одним и тем же principal.

## Включение Data Access и org-level sink

```bash
# Включить Data Access для всех сервисов (может быть дорого)
gcloud projects get-iam-policy PROJECT --format=json
# Sink на уровне организации — собирает логи всех проектов
gcloud logging sinks create org-forensic-sink \
  storage.googleapis.com/org-forensic-bucket --organization=ORG_ID \
  --log-filter='logName:"cloudaudit.googleapis.com"'
# Проверить, какие audit-логи включены
gcloud logging settings describe --project=PROJECT
```

Org-level sink критичен: без него логи разных проектов разбросаны, и атакующий, двигающийся между проектами, оставляет «острова» следов.

## Security Command Center

SCC даёт находки (findings) по конфигурациям и угрозам:

```bash
gcloud scc findings list organizations/ORG_ID --format=json > scc.json
# Фильтр по категории
gcloud scc findings list organizations/ORG_ID --filter='category="PERSISTENCE:IAM:Anomalous"'
```

Findings SCC — не доказательство, а указатель; подтверждайте первичными логами.

## Чек-лист GCP-расследования

1. Выгрузить Admin Activity за период (всегда доступен).
2. Проверить/включить Data Access и искать чтения.
3. Найти: CreateServiceAccountKey, SetIamPolicy, AccessSecretVersion, создание ВМ.
4. Собрать `callerIp`/`callerSuppliedUserAgent` для каждого principal.
5. Сопоставить с SCC findings.
6. Сделать снапшоты и выгрузить артефакты.

## Быстрая шпаргалка gcloud logging

| Цель | Команда |
|------|---------|
| Admin Activity | `gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity"' --freshness=7d` |
| По principal | `... 'protoPayload.authenticationInfo.principalEmail="user"'` |
| По методу | `... 'protoPayload.methodName:"SetIamPolicy"'` |
| По ресурсу | `... 'resource.type="gce_instance"'` |
| Только ошибки | `... 'severity>=ERROR'` |
| JSON-вывод | добавить `--format=json` |

Собрав таймлайн по principal и callerIp, вы получаете связную картину действий атакующего в проекте.

## Итог: маршрут расследования GCP

1. **Инвентарь**: `gcloud config`, список проектов/сервис-аккаунтов.
2. **Логи**: Admin Activity (всегда), Data Access (если включён).
3. **Аномалии**: CreateServiceAccountKey, SetIamPolicy, AccessSecretVersion, создание ВМ.
4. **Контекст**: callerIp, callerSuppliedUserAgent по каждому principal.
5. **Артефакты**: снапшоты дисков, версии GCS, код функций.
6. **Корреляция**: SCC findings + первичные логи + сетевые потоки.

GCP хорош тем, что аудит централизован в Cloud Audit Logs; задача аналитика — знать, какие типы включены, и не пропустить выключенный Data Access.

## Ключевые выводы

- Admin Activity всегда доступен — это база расследования.
- Data Access по умолчанию выключен — чтения данных могут быть невидимы.
- Создание ключа service account и SetIamPolicy — главные индикаторы эскалации.
- Org-level sink собирает логи всех проектов в одном месте.
- Всегда коррелируйте principal, callerIp и метод, чтобы восстановить таймлайн.

## Мини-шпаргалка методов GCP

| Цель | Фильтр |
|------|--------|
| Ключи SA | `protoPayload.methodName:"CreateServiceAccountKey"` |
| IAM | `protoPayload.methodName:"SetIamPolicy"` |
| Секреты | `protoPayload.methodName:"AccessSecretVersion"` |
| ВМ | `protoPayload.methodName:"compute.instances.insert"` |
| Ошибки | `severity>=ERROR` |

Достаточно этих пяти фильтров, чтобы поймать большинство GCP-инцидентов.

## Что дальше / решение

1. `gcloud logging read` по Admin Activity за период.
2. Проверить, включён ли Data Access; при возможности включить и искать чтения.
3. Искать: CreateServiceAccountKey, SetIamPolicy, AccessSecretVersion, создание ВМ.
4. Сопоставить principal ↔ действия ↔ IP (`requestMetadata.callerIp`).
5. Сделать снапшоты и выгрузить артефакты.

Дальше — `forensics-azure-forensics` и `forensics-cloud-trail` (AWS) для мультиоблачной картины.

## Квиз

```quiz
- question: "Какой тип Cloud Audit Logs включён всегда и логирует изменения ресурсов?"
  options:
    - "Data Access"
    - "Admin Activity"
    - "Policy Denied"
    - "System Event"
  answer: 1
  explanation: "Admin Activity всегда включён и не может быть отключён."
- question: "Какой метод в GCP создаёт ключ service account (персистентность)?"
  options:
    - "SetIamPolicy"
    - "CreateServiceAccountKey"
    - "AccessSecretVersion"
    - "GetBucket"
  answer: 1
  explanation: "google.iam.admin.v1.CreateServiceAccountKey — создание долгоживущего ключа."
- question: "Почему Data Access logs важны, но могут отсутствовать?"
  options:
    - "Они всегда включены"
    - "Они выключены по умолчанию и логируют доступ к данным"
    - "Они не содержат данных"
    - "Они только для IPv6"
  answer: 1
  explanation: "Data Access по умолчанию выключен; без него чтения данных не видны."
- question: "Что нужно для долгого хранения логов GCP?"
  options:
    - "Ничего, они вечны"
    - "Настроить logging sink в Storage/BigQuery"
    - "Отключить Admin Activity"
    - "Удалить проект"
  answer: 1
  explanation: "Для хранения дольше стандартного срока настраивают sink."
```

## Где пригодится

- **CTF:** задачи с логами GCP.
- **Cloud IR:** расследование компрометации service account и IAM.
- **Threat Hunting:** поиск аномальных IAM-операций.
- **Аудит:** проверка включённости логирования.
