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

## Вопрос, с которого всё начинается

Аккаунт AWS скомпрометирован: кто-то получил доступ к ключам. Диска и железа у нас нет —
есть только **CloudTrail**, аудит-лог всех API-вызовов. Можно ли по нему восстановить,
что делал атакующий?

Да. В облаке всё, что делает пользователь, проходит через **API**, и эти вызовы
логируются. В этом уроке мы восстановим действия злоумышленника по одному логу.

## Наш пример: cloudtrail.json

Сначала — общая картина. Каких событий больше всего:

```bash
$ jq -r '.eventName' cloudtrail.json | sort | uniq -c | sort -rn | head
    312 DescribeInstances
    118 ListBuckets
     24 CreateAccessKey
      6 AssumeRole
```

`jq -r '.eventName'` вытаскивает имя события из каждого JSON-объекта, `uniq -c` считает
частоту. Много `DescribeInstances` и `ListBuckets` — это **разведка**. А `CreateAccessKey`
и `AssumeRole` — уже действия.

## Шаг 1: персистентность через CreateAccessKey

```bash
$ jq -c 'select(.eventName=="CreateAccessKey") | {t:.eventTime,u:.userIdentity.arn,s:.sourceIPAddress}' cloudtrail.json | head
{"t":"2024-03-01T10:05:00Z","u":"arn:aws:iam::123:user/bob","s":"203.0.113.9"}
```

**Access key** — постоянный ключ доступа. Злоумышленник создаёт себе новый ключ, чтобы
сохранить доступ, даже если исходный отзовут. Смотрим, с какого IP и от чьего имени —
это наша зацепка.

## Шаг 2: эскалация через AssumeRole

```bash
$ jq -c 'select(.eventName=="AssumeRole") | {t:.eventTime,role:.requestParameters.roleArn,s:.sourceIPAddress}' cloudtrail.json
```

**AssumeRole** — это получение временных прав другой роли. Часто именно так эскалируют
привилегии: из слабой роли «примерить» сильную. Необычный IP или время — красный флаг.

## Шаг 3: кража секретов

```bash
$ jq -c 'select(.eventName=="GetSecretValue") | {t:.eventTime,id:.requestParameters.secretId}' cloudtrail.json
```

`GetSecretValue` — чтение секрета из Secrets Manager. Если секретов читают много и подряд,
данные уводят. Сопоставьте это с последующим доступом к S3.

## Шаг 4: открытие данных наружу

```bash
$ jq -c 'select(.eventName|test("PutBucketPolicy|PutBucketAcl")) | {b:.requestParameters.bucketName,s:.sourceIPAddress}' cloudtrail.json
```

`PutBucketPolicy`/`PutBucketAcl` делают бакет публичным — способ вынести данные или
открыть их всему миру. Это уже прямая эксфильтрация.

## Шаг 5: anti-forensics

```bash
$ jq -c 'select(.eventName|test("StopLogging|DeleteTrail|UpdateTrail"))' cloudtrail.json
```

Злоумышленник может попытаться **отключить логирование** (`StopLogging`) или удалить
trail. Но даже если он это сделал, копия логов уже могла уйти в S3 — их стоит искать там.

## Шаг 6: снапшоты вместо живого диска

Артефакты файловой системы снимают через снапшот тома, не трогая инстанс:

```bash
$ aws ec2 create-snapshot --volume-id vol-xxxx
```

Из снапшота создают новый том и монтируют его к аналитической машине — так получают
образ диска без остановки сервера.

## Шаг 7: Azure и GCP

Те же идеи в других облаках:

```bash
$ az monitor activity-log list --start-time 2024-01-01 -o json > activity.json
$ gcloud logging read 'logName:"cloudaudit.googleapis.com"' --format json > audit.json
```

В Azure это **Activity Log** (операции на ресурсах) и **Azure AD Sign-in/Audit logs**, в
GCP — **Cloud Audit Logs** (Admin Activity, Data Access).

## Анализ через SQL и hunting

CloudTrail-логи в S3 удобно анализировать SQL-ом (AWS Athena) или локально через DuckDB:

```sql
SELECT eventtime, useridentity.arn, sourceipaddress
FROM cloudtrail_logs
WHERE eventname = 'CreateAccessKey';
```

```bash
$ duckdb -c "SELECT eventName, COUNT(*) FROM read_json_auto('cloudtrail/*.json') GROUP BY 1 ORDER BY 2 DESC"
```

Ключевые индикаторы для охоты:

- **Новые access keys** для существующих пользователей.
- **Изменения IAM-политик** (расширение прав).
- **AssumeRole с необычного IP/UA.**
- **Массовое чтение S3 или секретов.**
- **Запуск инстансов** в необычных регионах (криптомайнинг).
- **Отключение логирования** (`StopLogging`, `DeleteTrail`).

## Хронология инцидента

1. **Проникновение** — скомпрометированный ключ, SSRF к metadata, фишинг.
2. **Разведка** — `ListBuckets`, `DescribeInstances`, `GetCallerIdentity`.
3. **Эскалация** — `AttachUserPolicy`, `AssumeRole`, `CreateLoginProfile`.
4. **Эксфильтрация** — `GetObject`, `GetSecretValue`.
5. **Персистентность** — `CreateAccessKey`, `CreateUser`.
6. **Anti-forensics** — `StopLogging`, удаление ресурсов.

## Порядок ответа на инцидент

1. **Изоляция** — отозвать ключи и сессии.
2. **Сохранение улик** — снапшоты дисков, копии логов в защищённый аккаунт.
3. **Анализ** — CloudTrail/Activity/Audit → восстановить цепочку.
4. **Устранение** — удалить backdoor-пользователей, ключи, роли; закрыть бакеты.
5. **Усиление** — MFA, least privilege, GuardDuty/Defender.

Порядок важен: сначала сохранить улики, и только потом чистить ресурсы.

## Azure и GCP подробнее

В Azure ключевые источники — Activity Log, Sign-in и Audit logs:

```bash
$ az monitor activity-log list --start-time 2024-01-01 -o json
$ az ad sign-in list -o json
$ az ad audit list -o json
```

В GCP — Cloud Audit Logs с разделением на Admin Activity (изменения конфигурации) и Data
Access (доступ к данным):

```bash
$ gcloud logging read 'protoPayload.methodName:"SetIamPolicy"' --format json
$ gcloud logging read 'logName:"cloudaudit.googleapis.com"' --format json
```

## Ключевые события, которые надо знать

| Событие | Что значит |
|---------|-----------|
| `CreateAccessKey` | новый постоянный ключ (персистентность) |
| `AttachUserPolicy` | расширение прав |
| `AssumeRole` | получение прав другой роли |
| `GetSecretValue` | чтение секрета |
| `PutBucketPolicy` | открытие бакета |
| `StopLogging` | отключение аудита |

Запомнив этот короткий список, вы быстро отфильтруете из тысяч событий именно те, что
относятся к атаке.

## Сложности облачной форензики

- **Эфемерность** — контейнеры и инстансы исчезают; нужны снапшоты и логи.
- **Распределённость** — ресурсы в разных регионах и аккаунтах.
- **Общая ответственность** — часть логов у провайдера и недоступна.
- **API-центричность** — логи единственный «след».
- **Масштаб** — миллионы событий; нужны Athena/SQL/hunting.
- **Шифрование** — снапшоты могут быть зашифрованы KMS (нужен доступ к ключу).

Главное отличие от on-prem: нет физического доступа, и **улики могут исчезнуть** при
удалении ресурсов. Поэтому логи заранее выгружают в отдельный аккаунт с immutable
retention.

## Проникновение через metadata endpoint

Частый путь в облако — **SSRF к metadata endpoint** (`169.254.169.254`). Через него
приложение может отдать временные креды роли инстанса, и дальше атакующий действует от
её имени. В CloudTrail это видно как первый вызов `GetCallerIdentity` с того же IP, что
и у уязвимого сервиса.

## Что мы теперь знаем

- В облаке всё проходит через API, и вызовы логируются (CloudTrail/Activity/Audit).
- Персистентность выдаёт `CreateAccessKey`/`CreateUser`/`AttachUserPolicy`.
- Эскалацию — `AssumeRole`; кражу секретов — `GetSecretValue`.
- Открытие данных — `PutBucketPolicy`/`PutBucketAcl`; anti-forensics — `StopLogging`.
- Артефакты ФС получают через снапшоты EBS, не трогая инстанс.

## На что смотреть дальше

- **CloudTrail может быть не включён** во всех регионах и сервисах.
- **Data events выключены** — тогда нет доступа к объектам.
- **Не игнорировать `AssumeRole`** — часто путь эскалации.
- **Проверять все регионы** — атаки идут в нескольких.
- **Сохранять логи в отдельный аккаунт** с immutable retention (S3 Object Lock).
- **Включать аудит заранее** — без логов облачное расследование почти невозможно.

## Квиз

Проверь себя.

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

## Куда дальше

Мы разобрали облако. Но всё чаще сервисы запускают в **контейнерах** — и там свои
артефакты: слои образов, логи контейнера, монтирования. Об этом — в следующем уроке. А
пока запомни: **в облаке нет диска — есть API-логи и снапшоты**.

## Где пригодится

- **CTF Forensics** — задачи с облачными логами.
- **Cloud IR** — реальные расследования.
- **Аудит** — оценка конфигурации и событий.
- **SOC** — детекты на облачные API.
- **Пентест** — понимание следов.
