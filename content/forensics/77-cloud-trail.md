---
id: forensics-cloud-trail
title: "Аудит-логи облаков: CloudTrail, Azure, GCP"
category: forensics
parent: forensics-cloud
difficulty: hard
order: 1
tags: [cloudtrail, aws, azure, gcp, audit, forensics, iam]
prerequisites: [forensics-cloud]
useful_for:
  - "CTF Forensics категория"
  - "Cloud DFIR"
  - "Threat Hunting"
estimated_minutes: 55
summary: "Расследование инцидентов в облаке по аудит-логам: AWS CloudTrail, Azure Activity/Sign-in, GCP Audit Logs — атрибуция, персистентность, эксфильтрация."
---
Облачные аудит-логи — основной источник для расследования инцидентов в AWS/Azure/GCP: кто, что, когда и откуда делал. В отличие от локальных систем, в облаке нет «диска», но есть подробный журнал API-вызовов. Этот урок — про CloudTrail, Azure Activity/Sign-in и GCP Audit Logs, атрибуцию и обнаружение персистентности/эксфильтрации.

## AWS CloudTrail

CloudTrail пишет каждый API-вызов: `eventName`, `userIdentity`, `sourceIPAddress`, `eventTime`, `requestParameters`, `responseElements`, `errorCode`. Хранится в S3 (JSON.gz), часто с журналом событий управления и данными.

```bash
# скачать и разобрать
$ aws s3 cp s3://bucket/AWSLogs/.../CloudTrail/... . --recursive
$ gunzip -c trail.json.gz | jq -r '.Records[] | [.eventTime,.eventName,.userIdentity.arn,.sourceIPAddress,.awsRegion] | @tsv' | head
# фильтр по подозрительному событию
$ gunzip -c trail.json.gz | jq '.Records[] | select(.eventName=="CreateUser" or .eventName=="CreateAccessKey")'
# кто создавал ключи/пользователей
$ jq -r '.Records[] | select(.eventName|test("CreateUser|CreateAccessKey|AttachUserPolicy")) | [.eventTime,.userIdentity.arn,.requestParameters] | @tsv' *.json
```

Ключевые события для расследования:

| Событие | Значение |
|---------|----------|
| `ConsoleLogin` | вход в консоль |
| `CreateUser`/`CreateAccessKey` | создание доступа |
| `AttachUserPolicy`/`PutUserPolicy` | повышение прав |
| `AssumeRole` | смена роли |
| `CreateBucket`/`PutBucketPolicy` | данные |
| `GetSecretValue` | чтение секретов |
| `StopLogging`/`DeleteTrail` | анти-форензика |
| `RunInstances` | новые ресурсы |

## Azure: Activity и Sign-in

- **Azure Activity Log** — операции с ресурсами (control plane).
- **Azure AD Sign-in Logs** — входы пользователей (успешные/неудачные, MFA, риск).
- **Azure AD Audit Logs** — изменения каталога (роли, приложения).

```bash
# Azure CLI
$ az monitor activity-log list --start-time 2024-03-01 --output json | jq -r '.[] | [.eventTimestamp,.operationName,.caller,.resourceId] | @tsv' | head
$ az rest --url 'https://graph.microsoft.com/v1.0/auditLogs/signIns' | jq -r '.value[] | [.createdDateTime,.userPrincipalName,.ipAddress,.status.errorCode] | @tsv'
# экспорт в SIEM: Azure Monitor, Microsoft Sentinel
```

Признаки: вход из необычной страны/IP, успех после множества неудач, регистрация нового приложения, добавление секрета к приложению (persistence), изменение ролей.

## GCP Audit Logs

- **Admin Activity** — изменения конфигурации (всегда включён).
- **Data Access** — доступ к данным (нужно включить).
- **System Event**, **Policy Denied**.

```bash
$ gcloud logging read 'logName:"cloudaudit.googleapis.com"' --format=json --limit=100 | jq -r '.[] | [.timestamp,.protoPayload.methodName,.protoPayload.authenticationInfo.principalEmail,.protoPayload.requestMetadata.callerIp] | @tsv'
```

## Атрибуция и персистентность

```bash
# откуда действовал атакующий
$ jq -r '.Records[].sourceIPAddress' trail.json | sort | uniq -c | sort -rn | head
# какой ключ использовался
$ jq -r '.Records[].userIdentity.accessKeyId' trail.json | sort | uniq -c | sort -rn | head
# временная шкала создания доступа
$ jq -r '.Records[] | select(.eventName|test("Create|Attach|Put")) | [.eventTime,.eventName,.userIdentity.arn] | @tsv' trail.json | sort
```

Механизмы персистентности в облаке: новые IAM-пользователи/ключи, роли с доверием, лямбды/функции, EC2 user-data, обновление SSO, приложения с секретами, снапшоты и AMI.

## Эксфильтрация

Признаки: `GetObject`/`ListBucket` на чувствительные бакеты, массовые `CopyObject`, `CreateSnapshot`, публичные политики бакетов, выгрузка в сторонние аккаунты.

```bash
$ jq -r '.Records[] | select(.eventName|test("GetObject|ListBucket|PutBucketPolicy|CreateSnapshot")) | [.eventTime,.eventName,.requestParameters.bucketName,.sourceIPAddress] | @tsv' trail.json | head
```

## Разобранный пример

Дан CloudTrail. Нужно найти компрометацию.

```bash
# 1. Подозрительный вход
$ jq -r '.Records[] | select(.eventName=="ConsoleLogin") | [.eventTime,.userIdentity.arn,.sourceIPAddress] | @tsv' trail.json | tail
# 2. Создание ключа после входа
$ jq -r '.Records[] | select(.eventName=="CreateAccessKey") | [.eventTime,.userIdentity.arn,.responseElements.accessKey.accessKeyId] | @tsv' trail.json
# 3. Повышение прав
$ jq -r '.Records[] | select(.eventName=="AttachUserPolicy") | .requestParameters' trail.json
# 4. Анти-форензика
$ jq -r '.Records[] | select(.eventName|test("StopLogging|DeleteTrail")) | [.eventTime,.userIdentity.arn] | @tsv' trail.json
# 5. Эксфильтрация
$ jq -r '.Records[] | select(.eventName|test("GetObject|PutBucketPolicy")) | [.eventTime,.requestParameters.bucketName,.sourceIPAddress] | @tsv' trail.json | head
```

Итог: вход из необычного IP → создание ключа → повышение прав → попытка отключить логирование → выгрузка данных.

## Справочная таблица

| Облако | Лог | Инструмент |
|--------|-----|-----------|
| AWS | CloudTrail | `aws s3`, `jq` |
| Azure | Activity/Sign-in | `az`, Sentinel |
| GCP | Audit Logs | `gcloud logging` |
| Общий | SIEM | Splunk/Sentinel |

## Частые ошибки

- **Смотреть только события данных** — control plane важнее.
- **Игнорировать `sourceIPAddress`** — атрибуция атакующего.
- **Не проверять `AssumeRole`** — смена роли скрывает источник.
- **Забывать про анти-форензику** (`StopLogging`) — сама она улика.
- **Пропустить data-access логи** — их надо включать заранее.
- **Не сохранять экспорт** — логи имеют retention.

## Что дальше / решение

Конвейер: экспорт (S3/az/gcloud) → `jq` (фильтры) → атрибуция (IP/ключ/ARN) → персистентность (IAM) → эксфильтрация (S3/snapshot). Связка: `forensics-cloud` (облако), `forensics-exfil` (утечка), `forensics-timeline` (хронология), `forensics-attack-mapping` (ATT&CK).

## Сравнение облаков и общие IOC

| Облако | Control plane | Sign-in | Data access |
|--------|---------------|---------|-------------|
| AWS | CloudTrail (management) | CloudTrail ConsoleLogin | CloudTrail (data events) |
| Azure | Activity Log | AD Sign-in Logs | Storage diagnostics |
| GCP | Admin Activity | — | Data Access Logs |

Общие IOC облачных атак: вход из необычной страны, создание нового доступа (ключ/пользователь/приложение), изменение IAM-политик, доступ к секретам (`GetSecretValue`/`Key Vault`), отключение логирования, массовая выгрузка из хранилищ, создание снапшотов, новые ресурсы (инстансы/функции).

```bash
# общий поиск по всем облачным логам (после экспорта в JSON)
$ jq -r '.Records[]? | select(.eventName|test("CreateUser|CreateAccessKey|AttachUserPolicy|GetSecretValue|StopLogging")) | [.eventTime,.eventName,.userIdentity.arn] | @tsv' *.json
```

## Сводный чек-лист

1. Экспортировать логи (CloudTrail/Activity/Audit).
2. Найти вход (`ConsoleLogin`/Sign-in) с необычного IP.
3. Проверить создание доступа (ключи/пользователи/приложения).
4. Проверить повышение прав (политики/роли).
5. Проверить доступ к секретам.
6. Проверить анти-форензику (`StopLogging`/`DeleteTrail`).
7. Проверить эксфильтрацию (бакеты/снапшоты).
8. Зафиксировать IOC и цепочку.

## Ограничения

- **Data access логи** нужно включать заранее; по умолчанию их нет.
- **Retention** ограничен — экспортируйте вовремя.
- **AssumeRole** скрывает исходного пользователя (смотрите цепочку).
- **Сторонние сервисы** (SaaS) могут не логировать в облако.
- **Логи можно отключить** — тогда их отсутствие само улика.

## Атрибуция по ключам и ролям

Каждый API-вызов несёт `userIdentity`: `type` (IAMUser, AssumedRole, Root), `arn`, `accessKeyId`, `sessionContext`. По `accessKeyId` находят, какой ключ использовался; по `arn` — кто. При `AssumeRole` в `sessionContext` виден исходный пользователь.

```bash
# типы identity
$ jq -r '.Records[].userIdentity.type' trail.json | sort | uniq -c
# ARN действующих лиц
$ jq -r '.Records[].userIdentity.arn' trail.json | sort | uniq -c | sort -rn | head
# цепочка AssumeRole
$ jq -r '.Records[] | select(.eventName=="AssumeRole") | [.userIdentity.arn, .requestParameters.roleArn] | @tsv' trail.json
```

## Инструменты: сводка

| Инструмент | Задача |
|-----------|--------|
| `aws s3 cp` | скачать CloudTrail |
| `jq` | фильтрация JSON |
| `az monitor` | Azure Activity |
| `gcloud logging` | GCP Audit |
| `pacu` | AWS-эксплуатация (для контекста) |
| SIEM (Sentinel/Splunk) | корреляция |

## Практические приёмы

- **Экспортируйте логи сразу** — retention ограничен.
- **`jq`-поток** для больших файлов.
- **Стройте таймлайн** (плазо не парсит CloudTrail — используйте jq+sort).
- **Сравнивайте baseline** — что «обычно» делает пользователь.
- **Проверяйте region** — атаки часто из неожиданных регионов.
- **Фиксируйте хеши** экспортированных логов.

## Отчёт по облачному инциденту

Укажите: время входа, действующее лицо (ARN/ключ), источник (IP/UA), созданные сущности (пользователи/ключи/роли), доступ к данным, анти-форензику, эксфильтрацию, IOC. Облачные инциденты быстро развиваются — раннее обнаружение критично.

## Квиз

```quiz
- question: "Какой лог AWS фиксирует все API-вызовы control plane?"
  options:
    - "VPC Flow Logs"
    - "CloudTrail"
    - "S3 access log"
    - "CloudWatch metrics"
  answer: 1
- question: "Какое событие CloudTrail указывает на персистентность?"
  options:
    - "ConsoleLogin"
    - "CreateAccessKey/CreateUser"
    - "GetObject"
    - "DescribeInstances"
  answer: 1
- question: "Что означает событие StopLogging/DeleteTrail?"
  options:
    - "нормальная работа"
    - "отключение аудита — anti-forensics"
    - "эксфильтрация"
    - "вход в консоль"
  answer: 1
- question: "Какой лог Azure фиксирует входы и MFA?"
  options:
    - "Activity Log"
    - "Sign-in Logs (Entra ID)"
    - "VNet Flow"
    - "Storage log"
  answer: 1
- question: "Что в GCP указывает на эскалацию прав?"
  options:
    - "SetIamPolicy с roles/owner"
    - "storage.objects.list"
    - "compute.instances.get"
    - "logging.read"
  answer: 0
```

## Где пригодится

- **CTF:** задачи с облачными аудит-логами.
- **Cloud DFIR:** расследование компрометации аккаунта/клауда.
- **Threat Hunting:** охота на создание ключей, эскалацию, эксфильтрацию.
- **SOC:** правила на CloudTrail/Entra ID события.
- **Судебная экспертиза:** атрибуция действий в облаке.
