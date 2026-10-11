---
id: cloud-logging-detection
title: "Логи и детект в облаке: CloudTrail, аудит и OPSEC атакующего"
category: cloud
parent: cloud-foundations-security
difficulty: medium
order: 3
tags: [cloud, logging, cloudtrail, detection, opsec, guardduty, incident-response]
prerequisites: [cloud-fundamentals, cloud-iam-basics]
useful_for:
  - "Снижение шума при облачных атаках (OPSEC)"
  - "Разбор CloudTrail/аудит-логов при IR"
  - "Понимание, что видит защита"
estimated_minutes: 45
summary: "Каждое облачное действие логируется. Разбираем CloudTrail, Cloud Logging, Azure Activity Log, что искать при детекте, как защищается организация (GuardDuty, Security Hub) и как атакующему минимизировать шум."
---

В облаке нет «тихих» действий: почти каждый вызов API попадает в аудит-лог. Для атакующего это риск, для защищающегося — сокровищница. Этот урок про то, **что именно логируется**, **как читать логи** при расследовании и **как атакующему снижать шум**. Без понимания аудита любая облачная атака — это заявка о себе в службу безопасности.

## Модель аудита: control plane vs data plane

Ключевое разделение, которое надо усвоить с самого начала:

| Плоскость | Что это | Логируется по умолчанию? | Примеры |
|-----------|---------|---------------------------|---------|
| **Control plane** (management) | Изменение ресурсов, IAM, сеть | Да (почти всегда) | `CreateUser`, `RunInstances`, `PutBucketPolicy` |
| **Data plane** | Операции с данными внутри ресурса | Часто НЕТ, включается отдельно | `GetObject`, `Invoke` на Lambda, чтение из RDS |

Практический вывод: `CreateAccessKey` (control plane) почти всегда в логе, а массовое скачивание объектов из S3 (data plane) — только если включён **S3 data events**. Поэтому атакующий любит «чтение данных» (тише), а защита в первую очередь строит детект на control plane.

## AWS CloudTrail: структура и где лежит

CloudTrail — основной аудит-сервис AWS. Каждое событие — JSON с полями:

- `eventTime`, `eventName` (напр. `AssumeRole`), `eventSource` (`sts.amazonaws.com`);
- `userIdentity` — тип (`IAMUser`, `AssumedRole`, `Root`), ARN, `accessKeyId`, `sessionContext`;
- `sourceIPAddress`, `userAgent`, `requestParameters`, `responseElements`;
- `errorCode` / `errorMessage` — если вызов провалился (важно для детекта брута!).

Типы трейлов:
- **Management events** — включены по умолчанию, 90 дней в Event history.
- **Data events** — S3 object-level, Lambda Invoke; платно, выключены по умолчанию.
- **Insight events** — аномалии (всплеск IAM-изменений и т.п.).
- **Organization trail** — общий трейл на все аккаунты организации (обойти сложнее).

```bash
# Последние события (Event history, 90 дней)
aws cloudtrail lookup-events --max-results 20 \
  --query 'Events[].{t:EventTime,name:EventName,user:Username}'

# Фильтр по имени события
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --max-results 50

# Список трейлов и их статус
aws cloudtrail describe-trails --include-shadow-trails
aws cloudtrail get-trail-status --name <trail-name>

# Куда пишутся логи (S3 bucket + CloudWatch Logs group)
aws cloudtrail get-event-selectors --trail-name <trail-name>
```

## Чтение CloudTrail: Athena, jq, CloudWatch

Логи лежат в S3 (gzip JSON) и/или в CloudWatch Logs. Быстрые способы разбора:

```bash
# Прямо из S3, без Athena (для одного-двух файлов)
aws s3 cp s3://<trail-bucket>/AWSLogs/<acct>/CloudTrail/<region>/2026/10/11/ ./logs/ --recursive
zcat logs/*.json.gz | jq -c 'select(.eventName=="CreateAccessKey")
  | {t:.eventTime, u:.userIdentity.arn, ip:.sourceIPAddress}'

# Полноценные запросы — Athena поверх таблицы CloudTrail
# (в консоли: Athena -> CloudTrail table -> SQL)
```

```sql
-- Пример Athena: кто создавал ключи за сутки
SELECT eventtime, useridentity.arn, sourceipaddress, requestparameters
FROM cloudtrail_logs
WHERE eventname = 'CreateAccessKey'
  AND eventtime >= '2026-10-10T00:00:00Z'
ORDER BY eventtime DESC;
```

В CloudWatch Logs удобно ловить всплески:

```bash
aws logs filter-log-events --log-group-name <trail-group> \
  --filter-pattern '{ $.eventName = "StopLogging" }'
```

## Azure: Activity Log, Entra audit, Diagnostic settings

В Azure аудит разложен по нескольким источникам:

| Источник | Что пишет | Где смотреть |
|----------|-----------|--------------|
| **Activity Log** | Control plane подписки (создание VM, роли) | `az monitor activity-log list` |
| **Entra ID audit logs** | Входы, изменения пользователей/ролей | `az rest` / Graph API |
| **Sign-in logs** | Успешные/неудачные входы, MFA, риск | Entra -> Sign-in logs |
| **Diagnostic settings** | Экспорт логов в Log Analytics/Storage | настраивается вручную |

```bash
# Последние операции подписки
az monitor activity-log list --max-events 20 \
  --query '[].{t:eventTimestamp,op:operationName.localizedValue,who:caller}'

# Неудачные входы в Entra (требует прав на Graph)
az rest --method get \
  --url 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=20'
```

Важно: **Entra audit logs хранятся 30 дней** по умолчанию (Premium — дольше), а Activity Log — 90 дней. Без Diagnostic settings логи не уходят наружу, и после истечения окна их не восстановить.

## GCP: Cloud Audit Logs

GCP делит аудит на четыре потока:

- **Admin Activity** — включён всегда, хранится 400 дней. Изменения конфигурации/IAM.
- **Data Access** — чтение данных; по умолчанию выключен (кроме BigQuery).
- **System Event** — действия Google.
- **Policy Denied** — отказы по org policy/VPC-SC.

```bash
# Читать Admin Activity через gcloud logging
gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity"
  AND protoPayload.methodName:"SetIamPolicy"' \
  --limit 20 --format json | jq -r \
  '.[] | [.timestamp, .protoPayload.authenticationInfo.principalEmail,
          .protoPayload.methodName] | @tsv'

# Проверить, включён ли Data Access audit
gcloud projects get-iam-policy <project> --format json | \
  jq '.auditConfigs'
```

## Что детектит защита: GuardDuty, Security Hub, Sentinel, Defender

Аудит-логи бесполезны без детекта. Типовые сервисы:

- **AWS GuardDuty** — ML + threat intel: аномальные API-вызовы, `CredentialsUnusualBehavior`, майнинг, обращения к известным C2.
- **AWS Security Hub** — агрегирует findings по стандартам (CIS, AWS FSBP).
- **Azure Defender for Cloud** + **Microsoft Sentinel** — SIEM/SOAR, корреляции.
- **GCP Security Command Center** — findings по Event Threat Detection.

Что чаще всего триггерит алерт:

| Действие атакующего | Детект |
|---------------------|--------|
| `DisableSecurityHub`, `DeleteTrail` | GuardDuty: `Stealth:IAMUser/CloudTrailLoggingDisabled` |
| Брут `AssumeRole` с одного IP | `CredentialAccess:IAMUser/AnomalousBehavior` |
| Обращение к metadata извне | VPC Flow + GuardDuty |
| Много `GetObject` в короткий срок | S3 data events + Macie |

## OPSEC атакующего: как снижать шум

Это раздел «как защита видит атакующего» — знать его нужно и red, и blue.

1. **Отключать логирование — громко и почти всегда детектится.** `StopLogging`/`DeleteTrail` сами пишут событие и триггерят GuardDuty. Не делать, если цель — тихо.
2. **Использовать уже существующие роли** (`AssumeRole` в легіт-роль) вместо создания новых сущностей.
3. **Работать из ожидаемого региона/IP.** Аномальный `sourceIPAddress` — топ-сигнал.
4. **Читать, а не менять.** Data plane чтения часто не логируется (если не включены data events).
5. **Быть аккуратным с `userAgent`.** Кастомные инструменты (Pacu, скрипты) дают нетипичный UA. `aws` CLI и SDK выглядят обычно.
6. **Не создавать access keys** — `CreateAccessKey` один из самых отслеживаемых вызовов.
7. **Учитывать Organization trail** — его нельзя отключить из дочернего аккаунта.

```bash
# Показать свои последние действия (самопроверка OPSEC)
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=AccessKeyId,AttributeValue=<AKIA...> --max-results 50
```

## Разобранный пример: расследование и заметание следов

**Сценарий (IR).** Пришёл алерт GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`. Задача — восстановить цепочку.

Шаг 1. Смотрим события вокруг времени алерта:

```bash
aws cloudtrail lookup-events --start-time 2026-10-11T02:00:00Z \
  --end-time 2026-10-11T02:30:00Z --max-results 200 | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    [.eventTime,.eventName,.userIdentity.arn,.sourceIPAddress] | @tsv' | sort
```

Шаг 2. Ищем эксфильтрацию роли: `AssumeRole`, `GetCallerIdentity`, `GetSecretValue`, `ListBuckets`.

Шаг 3. Проверяем, не отключали ли логи: `StopLogging`, `DeleteTrail`, `UpdateTrail`.

Шаг 4. Строим timeline: IP → какие ключи/роли → какие ресурсы.

Шаг 5. **Атакующий side.** На этом же примере видно, что `GetSecretValue` из чужого IP сразу дал алерт. Урок: красть роль — мало, надо ещё действовать из «правильной» сети (например, через тот же EC2/NAT).

## Частые ошибки

- **Считать, что data plane логируется.** S3 object-level и Lambda Invoke по умолчанию НЕ пишутся.
- **Игнорировать 90-дневное окно.** Event history хранит 90 дней; дальше только если есть трейл в S3.
- **Путать Activity Log и Entra audit.** Это разные источники, разные сроки хранения.
- **Думать, что отключение трейла скроет следы.** Само отключение логируется и алертит.
- **Не смотреть `errorCode`.** Массовые `AccessDenied` = брут/enumeration, часто первый сигнал.
- **Забывать про мульти-аккаунт.** Organization trail виден в management-аккаунте — из дочернего не спрятать.

## Что дальше / решение

Дальше по дереву логично идти в:
- `cloud-credential-hunting` — где вообще искать креды, за которыми охотится детект;
- `cloud-cloudtrail-evasion` — конкретные техники обхода/снижения шума;
- `cloud-iam-basics` — чтобы понимать, чьи действия вы видите в `userIdentity`.

Если вы blue teamer — стройте детект в первую очередь на control plane: `CreateAccessKey`, `AssumeRole`, `PutBucketPolicy`, `StopLogging`. Если red — минимизируйте именно эти вызовы.

## Квиз

```quiz
- question: "Какое утверждение о CloudTrail верно по умолчанию?"
  options:
    - "Management events логируются, data events (S3 object-level) — нет"
    - "Всё логируется, включая чтение объектов S3"
    - "Логируется только вход root-пользователя"
    - "CloudTrail нужно включать в каждом регионе вручную с нуля"
  answer: 0
  explanation: "Data events выключены по умолчанию и стоят денег."
- question: "Сколько дней CloudTrail Event history хранит события без трейла в S3?"
  options:
    - "7 дней"
    - "90 дней"
    - "1 год"
    - "бессрочно"
  answer: 1
  explanation: "Стандартное окно Event history — 90 дней."
- question: "Почему отключение трейла (StopLogging) плохая идея для скрытной атаки?"
  options:
    - "Само действие логируется и триггерит GuardDuty"
    - "Оно требует root"
    - "Оно удаляет S3-бакет"
    - "Оно блокирует IAM"
  answer: 0
  explanation: "StopLogging/DeleteTrail — сами по себе детектируемые события."
- question: "Где в Azure хранятся неудачные попытки входа?"
  options:
    - "В Activity Log"
    - "В Sign-in logs Entra ID"
    - "В S3"
    - "В CloudTrail"
  answer: 1
  explanation: "Входы и MFA-события — в Entra sign-in logs."
- question: "Какой признак в логах чаще всего указывает на брут/enumeration?"
  options:
    - "Массовые errorCode AccessDenied"
    - "Один успешный GetObject"
    - "Изменение цвета консоли"
    - "Ротация сертификата"
  answer: 0
  explanation: "Серии отказов — классический сигнал перебора прав."
```

## Где пригодится

- **IR/Blue team:** восстановление цепочки атаки по CloudTrail/Activity Log/Sign-in logs.
- **Red team / пентест:** OPSEC — что попадёт в лог и как не засветиться.
- **CTF:** облачные задачи, где надо найти «кто и что сделал» в аудит-логе.
- **Работа:** настройка Diagnostic settings, retention, детект-правил.
- **Дальше по дереву:** `cloud-cloudtrail-evasion`, `cloud-credential-hunting`.
