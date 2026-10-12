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

## Вопрос, с которого всё начинается

В прошлом уроке мы разбирали Azure, где логи разложены по нескольким сервисам. В GCP всё иначе: аудит собран в **одну систему** — Cloud Audit Logs. Это упрощает расследование, но только если понимать, какие типы логов включены, а какие — нет. Именно на этом различии чаще всего теряются следы.

## Наш пример: подозрительный ключ service account

Есть проект GCP и подозрение, что кто-то выкачал данные. У нас есть `gcloud` и права на чтение логов. Начнём с самого подозрительного события — создания ключа сервисной учётки.

```bash
$ gcloud auth login
$ gcloud config set project PROJECT_ID
$ gcloud logging read 'protoPayload.methodName:"CreateServiceAccountKey"' \
    --freshness=7d --format='value(protoPayload.authenticationInfo.principalEmail, protoPayload.request.name, timestamp)'
attacker@example.com  projects/p/serviceAccounts/ci-sa@p.iam.gserviceaccount.com/keys/abc  2024-03-01T22:10:00Z
```

Читаем: пользователь `attacker@example.com` создал **ключ** для сервисной учётки `ci-sa`. Это классическая персистентность: ключ даёт долгоживущий доступ, не требующий «входа».

## Шаг 1: четыре типа Cloud Audit Logs

Прежде чем искать дальше, важно понять, что вообще логируется:

| Тип | Что логирует | Включён по умолчанию |
|-----|--------------|----------------------|
| Admin Activity | изменения ресурсов и IAM | да (нельзя отключить) |
| Data Access | чтение/запись данных | нет (нужно включать) |
| System Event | действия Google-систем | да |
| Policy Denied | отказы по org policy/VPC-SC | да |

Ключевой вывод: **Admin Activity всегда доступен** — это основа расследования. Но **Data Access по умолчанию выключен**, поэтому массовое чтение данных может не оставить следа, если его не включили заранее.

## Шаг 2: ищем эскалацию

Продолжаем разбирать наш инцидент. После создания ключа атакующий должен как-то повысить права — ищем изменение IAM:

```bash
$ gcloud logging read 'protoPayload.methodName:"SetIamPolicy"' --freshness=7d \
    --format='value(protoPayload.authenticationInfo.principalEmail, timestamp)'
attacker@example.com  2024-03-01T22:12:00Z
```

Цепочка складывается: в 22:10 создан ключ, в 22:12 изменена политика IAM. Дальше — искать действия **от имени** этой сервисной учётки (по `principalEmail` = SA). Основные индикаторы компрометации GCP:

- `CreateServiceAccountKey` — долгоживущий ключ.
- `SetIamPolicy` — повышение прав.
- `AccessSecretVersion` — доступ к секретам (если Data Access включён).
- `compute.instances.insert` — создание ВМ (часто для криптомайнинга).
- `storage.setIamPermissions`, `compute.firewalls.patch` — изменение доступа.
- Workload Identity Federation — добавление внешнего провайдера.

## Шаг 3: поля, на которые смотреть

Каждая audit-запись имеет структуру. Полезные поля:

| Поле | Значение |
|------|----------|
| `protoPayload.authenticationInfo.principalEmail` | кто выполнил |
| `protoPayload.requestMetadata.callerIp` | откуда |
| `protoPayload.requestMetadata.callerSuppliedUserAgent` | чем (CLI/консоль/SDK) |
| `protoPayload.methodName` | что сделано |
| `protoPayload.resourceName` | над чем |

`callerSuppliedUserAgent` помогает отличить автоматизацию (`google-cloud-sdk`) от консольного доступа и сторонних инструментов — важный контекст. Строим таймлайн по principal:

```bash
$ gcloud logging read 'protoPayload.authenticationInfo.principalEmail="attacker@example.com"' \
    --freshness=30d --format='value(timestamp, protoPayload.methodName, protoPayload.requestMetadata.callerIp)'
```

## Шаг 4: как фильтровать логи

`gcloud logging read` принимает фильтр в синтаксисе Cloud Logging. Поддерживаются `=`, `!=`, `:` (подстрока), `=~` (regex) и логические `AND`/`OR`/`NOT`.

```bash
# Все изменения в проекте
gcloud logging read 'protoPayload.methodName=~"\.(create|delete|update|setIamPolicy)$"' --freshness=7d
# Только ошибки
gcloud logging read 'severity>=ERROR' --freshness=2d --format=json
# Топ вызывающих методов
gcloud logging read 'logName:"activity"' --freshness=7d --format='value(protoPayload.methodName)' \
  | sort | uniq -c | sort -nr | head
```

## Шаг 5: хранение и сбор артефактов

Admin Activity хранится 400 дней в `_Default`, дальше — только через **sink** (перенаправление в Storage/BigQuery). Для расследования на уровне организации нужен **org-level sink**: без него логи разных проектов разбросаны, и атакующий, двигающийся между проектами, оставляет «острова» следов.

```bash
# Org-level sink собирает логи всех проектов
gcloud logging sinks create org-forensic-sink \
  storage.googleapis.com/org-forensic-bucket --organization=ORG_ID \
  --log-filter='logName:"cloudaudit.googleapis.com"'
# Снапшот диска ВМ для disk-forensics
gcloud compute disks snapshot vm1-disk --snapshot-names=snap-vm1 --zone=us-central1-a
```

Дополнительно: `gcloud scc findings list` (Security Command Center) даёт указатели на аномалии, но findings — не доказательство, их подтверждают первичными логами. Все метки времени — UTC.

## Что мы теперь знаем

- **Admin Activity** всегда включён — это база расследования; **Data Access** по умолчанию выключен, и чтения данных могут быть невидимы.
- Создание ключа service account и `SetIamPolicy` — главные индикаторы эскалации.
- Ключевые поля: `principalEmail`, `callerIp`, `callerSuppliedUserAgent`, `methodName`.
- Фильтры Cloud Logging поддерживают `:`, `=~` (regex) и логические операторы.
- **Org-level sink** собирает логи всех проектов в одном месте.
- Findings SCC — указатели, а не доказательства.

## Квиз

Проверь себя.

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
- question: "Какое поле audit-записи помогает понять, чем действовал атакующий (CLI/консоль/SDK)?"
  options:
    - "callerSuppliedUserAgent"
    - "severity"
    - "resource.labels"
    - "insertId"
  answer: 0
  explanation: "callerSuppliedUserAgent различает автоматизацию (google-cloud-sdk) и консольный доступ."
```

## Куда дальше

Мы разобрали расследование GCP. Дальше по курсу — **live-forensics** (`forensics-live-forensics`): как собирать данные с работающей системы, не выключая её. А пока главное запомни: **в GCP аудит централизован в Cloud Audit Logs; Admin Activity всегда доступен, а Data Access надо включать заранее**.

## Где пригодится

- **CTF:** задачи с логами GCP.
- **Cloud IR:** расследование компрометации service account и IAM.
- **Threat Hunting:** поиск аномальных IAM-операций.
- **Аудит:** проверка включённости логирования.
