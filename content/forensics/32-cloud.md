---
id: forensics-cloud
title: "Форензика облака: логи, артефакты и восстановление событий"
category: forensics
parent: forensics-logs
difficulty: hard
order: 4
tags: [cloud, aws, azure, gcp, cloudtrail, s3, iam, logs]
prerequisites: [forensics-logs]
useful_for:
  - "CTF Forensics категория"
  - "Cloud Incident Response"
  - "Аудит облачной безопасности"
estimated_minutes: 45
summary: "Форензика облачных сред: CloudTrail/Activity/audit-логи, метаданные объектов, снапшоты дисков, IAM-события и восстановление действий атакующего без доступа к железу."
---

## Специфика облачной форензики

В облаке нет «диска» и «железа» — есть API-вызовы, логи, снапшоты. Главный принцип: **всё, что делает пользователь, проходит через API**, и эти вызовы логируются. Задача — восстановить действия атакующего по аудит-логам и артефактам: созданные ресурсы, доступ к данным, персистентность (новые ключи, роли), эксфильтрация.

## AWS: CloudTrail

**CloudTrail** — главный аудит-лог AWS: все API-вызовы (кто, когда, откуда, что). Хранится в S3 (JSON.gz) и/или CloudWatch.

```bash
# Скачать и разобрать
aws s3 cp s3://bucket/AWSLogs/.../CloudTrail/ . --recursive
gunzip -c *.json.gz | jq -c 'select(.eventName=="CreateAccessKey")'
# Ключевые события
jq -r '.eventName' *.json | sort | uniq -c | sort -rn | head
```

Что искать:

- **`CreateAccessKey`, `CreateUser`, `AttachUserPolicy`** — персистентность/эскалация.
- **`AssumeRole`, `GetCallerIdentity`** — разведка.
- **`GetSecretValue`** (Secrets Manager) — кража секретов.
- **`PutBucketPolicy`, `PutBucketAcl`** — открытие S3.
- **`RunInstances`** — запуск майнеров/атакующих инстансов.
- **`DeleteTrail`, `StopLogging`** — anti-forensics.
- **`ConsoleLogin`** с новыми IP.

```bash
jq -c 'select(.eventName|test("Create|Delete|Put|Attach|Assume")) | {t:.eventTime,u:.userIdentity.arn,e:.eventName,s:.sourceIPAddress}' cloudtrail.json
```

## AWS: другие источники

- **S3 access logs** и **CloudTrail data events** — доступ к объектам.
- **VPC Flow Logs** — сетевой трафик.
- **GuardDuty** — детекты.
- **Config** — история конфигураций.
- **IAM Access Analyzer**, **Security Hub**.

```bash
# S3 data events (если включены)
jq -c 'select(.eventName|test("GetObject|PutObject"))' cloudtrail-data.json
```

## Azure

- **Activity Log** — операции на ресурсах (портал/API).
- **Azure AD Sign-in logs** — входы.
- **Azure AD Audit logs** — изменения в AD (создание пользователей, роли).
- **NSG Flow Logs** — сеть.
- **Defender for Cloud** — детекты.

```bash
az monitor activity-log list --start-time 2024-01-01 --output json > activity.json
az ad sign-in list > signin.json
```

## GCP

- **Cloud Audit Logs:** Admin Activity (изменения), Data Access (доступ к данным), System Events.
- **VPC Flow Logs**, **Cloud IDS**.
- **Security Command Center**.

```bash
gcloud logging read 'logName:"cloudaudit.googleapis.com"' --format json > audit.json
gcloud logging read 'protoPayload.methodName:"SetIamPolicy"' --format json
```

## Артефакты и снапшоты

- **Снапшоты дисков** — снять снапшот EC2/EBS (не трогая инстанс), затем смонтировать.
- **Снимок памяти** — сложнее (нужен агент/SSM).
- **Образы ВМ**, **AMI**.
- **Метаданные объектов S3** (версии, лог).
- **Секреты** — Secrets Manager, Parameter Store.

```bash
# Снапшот EBS
aws ec2 create-snapshot --volume-id vol-xxxx
# Потом: создать volume из снапшота, примонтировать к аналитической машине
```

## Практический пример: расследование AWS

1. **CloudTrail** — все API за окно.
2. **Найдите `CreateAccessKey`/`AssumeRole`** от подозрительного субъекта.
3. **Проследите `GetSecretValue`** и куда ушли данные.
4. **Проверьте S3** (PutBucketPolicy, GetObject).
5. **Снапшот затронутых инстансов.**
6. **Отзовите ключи, ротация.**
7. **Таймлайн и отчёт.**

## Инструменты и команды

```bash
# AWS
aws cloudtrail lookup-events
aws s3, aws ec2 create-snapshot
# Анализ
jq, grep, Athena (SQL по CloudTrail)
# Azure/GCP
az monitor, gcloud logging
# Специализированные: CloudTrail-Parser, Stratus Red Team (для тестов)
```

## Анализ через Athena/SQL

CloudTrail-логи в S3 удобно анализировать SQL-ом (AWS Athena) или локально через `jq`/DuckDB.

```sql
-- Athena: все создания ключей доступа
SELECT eventtime, useridentity.arn, sourceipaddress
FROM cloudtrail_logs
WHERE eventname = 'CreateAccessKey';
-- Подозрительные IP
SELECT sourceipaddress, COUNT(*) c
FROM cloudtrail_logs
GROUP BY sourceipaddress ORDER BY c DESC LIMIT 20;
```

```bash
# Локально через DuckDB
duckdb -c "SELECT eventName, COUNT(*) FROM read_json_auto('cloudtrail/*.json') GROUP BY 1 ORDER BY 2 DESC"
```

## Детекты и hunting

Ключевые индикаторы в облаке:

- **Новые access keys** для существующих пользователей.
- **Изменения IAM-политик** (расширение прав).
- **AssumeRole с необычного IP/UA.**
- **Массовое чтение S3/секретов.**
- **Запуск инстансов** в необычных регионах (криптомайнинг).
- **Отключение логирования** (StopLogging, DeleteTrail, UpdateTrail).
- **Публичные бакеты** (PutBucketAcl public).
- **Создание пользователей** вне обычных процессов.

## Хронология инцидента

1. **Начальное проникновение** (скомпрометированный ключ, SSRF к metadata, фишинг).
2. **Разведка** (ListBuckets, DescribeInstances, GetCallerIdentity).
3. **Эскалация** (AttachUserPolicy, AssumeRole, CreateLoginProfile).
4. **Эксфильтрация** (GetObject, GetSecretValue).
5. **Персистентность** (CreateAccessKey, CreateUser, backdoor role).
6. **Anti-forensics** (StopLogging, удаление ресурсов).

## Инструменты и команды

```bash
# AWS
aws cloudtrail lookup-events --start-time 2024-01-01 --max-items 100
aws s3 cp s3://trail-bucket/ . --recursive
aws ec2 create-snapshot --volume-id vol-xxx
aws iam list-access-keys --user-name suspect

# Анализ
gunzip -c *.json.gz | jq -c 'select(.eventName|test("Create|Attach|Assume|GetSecret"))'
duckdb -c "SELECT eventName, COUNT(*) FROM read_json_auto('*.json') GROUP BY 1 ORDER BY 2 DESC"

# Azure
az monitor activity-log list --start-time 2024-01-01 -o json
az ad sign-in list -o json
az ad audit list -o json

# GCP
gcloud logging read 'logName:"cloudaudit.googleapis.com"' --format json
gcloud logging read 'protoPayload.methodName:"SetIamPolicy"'
```

## Облачная форензика: сложности

- **Эфемерность:** контейнеры/инстансы исчезают; нужны снапшоты и логи.
- **Распределённость:** ресурсы в разных регионах/аккаунтах.
- **Общая ответственность:** часть логов у провайдера (недоступна).
- **API-центричность:** всё через API; логи — единственный «след».
- **Масштаб:** миллионы событий; нужны Athena/SQL/hunting.
- **Шифрование:** снапшоты/тома могут быть зашифрованы KMS (нужен доступ к ключу).

Порядок: **собрать логи** (CloudTrail/Activity/Audit), **снапшоты** (EBS/диски), **отозвать креды**, **ротировать ключи**, **восстановить таймлайн**.

## Ответ на инцидент в облаке

1. **Изоляция:** отозвать скомпрометированные ключи/сессии, ограничить роль.
2. **Сохранение улик:** снапшоты дисков, копии логов в защищённый аккаунт/бакет.
3. **Анализ:** CloudTrail/Activity/Audit → восстановить цепочку.
4. **Устранение:** удалить backdoor-пользователей/ключи/роли, закрыть публичные бакеты.
5. **Восстановление:** из снапшотов/бэкапов.
6. **Усиление:** MFA, least privilege, включение логов, GuardDuty/Defender.

Ключевое отличие от on-prem: нет физического доступа, всё через API, и **улики могут исчезнуть** при удалении ресурсов — сохраняйте логи в отдельный аккаунт с immutable retention (S3 Object Lock).

## Итог

Облачная форензика — это логи + снапшоты. CloudTrail/Activity/Audit восстанавливают действия API (персистентность, эксфильтрация, эскалация), снапшоты дают артефакты ФС. Сохраняйте логи в отдельный аккаунт (immutable retention), отзывайте креды, проверяйте все регионы. Ключевые индикаторы: Create*/Attach*/Assume*/GetSecret/StopLogging.

## Резюме

Логи (CloudTrail/Activity/Audit) + снапшоты. Индикаторы: Create/Attach/Assume/GetSecret/StopLogging. Сохраняйте логи в отдельный аккаунт с immutable retention, отзывайте креды, проверяйте все регионы и сопоставляйте API-события в единый таймлайн. Без логов расследование облачного инцидента практически невозможно, поэтому включайте аудит заранее.

## Частые ошибки

- **CloudTrail не включён** на всех регионах/сервисах.
- **Data events выключены** — нет доступа к объектам.
- **Игнорировать `AssumeRole`.** Часто путь эскалации.
- **Не снять снапшот** до удаления.
- **Забыть про CloudTrail в S3** (могут удалить trail, но лог в S3 остаётся).
- **Смотреть один регион.** Атаки идут в нескольких.

## Как не застрять

- **CloudTrail/Activity/Audit — основа.**
- **Ищите Create/Attach/Assume/GetSecret.**
- **Снапшоты дисков** для артефактов.
- **Отзовите и ротируйте** ключи.
- **Проверьте все регионы.**
- **Таймлайн и отчёт.**

## Квиз

```quiz
- question: "Главный аудит-лог AWS:"
  options:
    - "syslog"
    - "CloudTrail"
    - "SAM"
    - "EVTX"
  answer: 1
- question: "Признак персистентности в CloudTrail:"
  options:
    - "GetObject"
    - "CreateAccessKey / CreateUser / AttachUserPolicy"
    - "DescribeInstances"
    - "ListBuckets"
  answer: 1
- question: "Как снять образ EC2 без остановки?"
  options:
    - "удалить инстанс"
    - "создать снапшот EBS"
    - "перезагрузить"
    - "ничего"
  answer: 1
- question: "Что такое Azure Activity Log?"
  options:
    - "сетевой трафик"
    - "журнал операций на ресурсах Azure"
    - "пароли"
    - "диск"
  answer: 1
- question: "Anti-forensics в облаке:"
  options:
    - "StopLogging / DeleteTrail"
    - "GetObject"
    - "ListBuckets"
    - "DescribeRegions"
  answer: 0
```

## Где пригодится

- **CTF Forensics** — задачи с облачными логами.
- **Cloud IR** — реальные расследования.
- **Аудит** — оценка конфигурации и событий.
- **SOC** — детекты на облачные API.
- **Пентест** — понимание следов.
