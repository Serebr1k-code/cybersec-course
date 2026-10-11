---
id: cloud-gcp-cloudsql
title: "Cloud SQL: публичный доступ, IAM database auth и снапшоты"
category: cloud
parent: cloud-gcp-data-deep
difficulty: hard
order: 4
tags: [cloud, gcp, cloudsql, database, iam-auth, snapshot, privesc]
prerequisites: [cloud-gcp-data-deep, cloud-rds-aurora]
useful_for:
  - "Пентест управляемых баз GCP"
  - "Использование IAM database authentication"
  - "Извлечение данных из бэкапов"
estimated_minutes: 45
summary: "Cloud SQL: публичные инстансы, SSL-настройки, IAM database authentication, чтение пароля из Secret Manager и восстановление из бэкапов."
---

## Зачем этот урок

Cloud SQL — управляемые MySQL/PostgreSQL/SQL Server в GCP. Как и RDS, это «база без ОС», но с несколькими способами добраться до данных: публичный IP без firewall, слабые пароли, IAM database authentication, пароль в Secret Manager и бэкапы/реплики. Атакующего интересуют данные, а также секреты, которые приложения хранят в БД. Отдельная особенность GCP — тесная интеграция с IAM: иногда вход возможен токеном, без пароля.

## Модель Cloud SQL

- **Instance** — сам сервер; имеет public IP (опционально) и private IP (через VPC).
- **Authorized networks** — список CIDR, которым разрешён доступ по public IP.
- **SSL/TLS** — может быть обязательным или опциональным; клиентские сертификаты.
- **IAM database authentication** — вход токеном через Cloud SQL Auth Proxy; пользователь должен существовать как IAM-аккаунт или как DB-пользователь с флагом `cloudsql.iam_authentication`.
- **Backups / on-demand backups** — снимки, которые можно восстановить в новый инстанс.
- **Replicas** — read replicas, часто с более слабыми настройками.
- **Connector / Auth Proxy** — рекомендованный способ подключения с IAM.

## Инструменты и команды

```bash
# Инвентаризация
gcloud sql instances list
gcloud sql instances describe prod-db --format=json | jq '{ip:ipAddresses,settings:{ipConfiguration:.settings.ipConfiguration,dbFlags:.settings.databaseFlags}}'

# Публичный IP и authorized networks
gcloud sql instances describe prod-db \
  --format='value(ipAddresses[].ipAddress,settings.ipConfiguration.authorizedNetworks)'

# Пользователи и флаги
gcloud sql users list --instance=prod-db
gcloud sql instances describe prod-db --format='value(settings.databaseFlags)'

# Подключение через Auth Proxy с IAM
gcloud sql connect prod-db --user=appuser

# Пароль в Secret Manager
gcloud secrets versions access latest --secret=cloudsql-db-password

# Бэкапы
gcloud sql backups list --instance=prod-db
gcloud sql backups describe BACKUP_ID --instance=prod-db
```

Через Auth Proxy:

```bash
# Запускаем прокси (нужен IAM-токен)
cloud-sql-proxy --auto-iam-authn PROJECT_ID:us-central1:prod-db &
psql -h 127.0.0.1 -U appuser -d app
```

## Разобранный пример: IAM database auth без пароля

Сценарий: у нас есть право `cloudsql.instances.connect` и `roles/cloudsql.client`, а на инстансе включена IAM database authentication.

```bash
# 1. Проверяем флаг
gcloud sql instances describe prod-db --format='value(settings.databaseFlags)'
# [{'name': 'cloudsql.iam_authentication', 'value': 'on'}]

# 2. Список пользователей — есть ли IAM-пользователи
gcloud sql users list --instance=prod-db
# NAME          HOST  TYPE
# appuser             CLOUD_IAM_USER
# postgres            BUILT_IN

# 3. Подключаемся через Auth Proxy с auto-iam-authn (пароль не нужен)
cloud-sql-proxy --auto-iam-authn PROJECT_ID:us-central1:prod-db &
PGPASSWORD=$(gcloud auth print-access-token) \
  psql -h 127.0.0.1 -U appuser -d app
# app=>
```

IAM database authentication выдаёт токен как пароль (короткоживущий, ~1 час). Это значит: утечка роли с `cloudsql.instances.connect` = вход в БД без пароля. Проверьте, какие IAM-пользователи существуют и какие роли у вашего аккаунта.

## Публичный доступ и authorized networks

Классическая ошибка — `0.0.0.0/0` в authorized networks.

```bash
gcloud sql instances describe prod-db \
  --format='value(settings.ipConfiguration.authorizedNetworks[].value)'
# 0.0.0.0/0
```

Тогда инстанс доступен из интернета, и остаётся только подобрать креды (или использовать IAM auth). Проверяйте также `requireSsl`:

```bash
gcloud sql instances describe prod-db --format='value(settings.ipConfiguration.requireSsl)'
# False   -> трафик может идти без шифрования
```

## Бэкапы, реплики и восстановление

- **On-demand backup** — `gcloud sql backups create`; восстановление создаёт новый инстанс.
- **PITR (point-in-time recovery)** — бинарные логи; восстановление на момент времени.
- **Read replica** — отдельный инстанс с копией; часто имеет свой IP и более слабые настройки (в т.ч. публичный).
- **Clone** — `gcloud sql instances clone` создаёт копию без влияния на прод (быстро и удобно для атакующего).

```bash
# Клонируем инстанс (если есть права)
gcloud sql instances clone prod-db prod-clone
# Затем меняем пароль и читаем данные
gcloud sql users set-password postgres --instance=prod-clone --password='Pwn3d!'
```

## Обход защит и edge cases

- **Private IP only.** Если публичного IP нет, нужен доступ в VPC (пивот). Auth Proxy изнутри VPC работает.
- **SSL required.** При `requireSsl=true` клиент должен предъявить сертификат; с IAM auth это делается через proxy.
- **CMEK.** Данные шифруются ключом KMS; чтение требует прав на ключ (обычно через сервисный аккаунт инстанса).
- **VPC-SC.** Периметр блокирует доступ извне; нужен пивот.
- **Connector.** Serverless (Cloud Run/Functions) подключаются через Serverless VPC Connector — проверяйте его сеть.

## Частые ошибки и подводные камни

- Считать, что «нет публичного IP» = нет доступа: реплики и клоны часто публичны.
- Игнорировать IAM database auth: пароль не нужен, нужен токен.
- Не проверить authorized networks `0.0.0.0/0`.
- Забыть про Secret Manager как источник пароля.
- Путать `cloudsql.client` (подключение) и `cloudsql.admin` (управление).

## Защита и детект

- Не использовать `0.0.0.0/0`; ограничить authorized networks конкретными CIDR.
- Требовать SSL и использовать IAM database auth с минимальными ролями.
- Хранить пароли в Secret Manager с ограниченным доступом.
- Ограничить `cloudsql.instances.connect`/`clone`; алертить на клонирование и изменение пользователей.
- Включить audit logs и мониторинг аномальных подключений.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — `0.0.0.0/0` в authorized networks. Второй — `requireSsl=false`. Третий — IAM database auth с широкими ролями. Четвёртый — пароль в открытом Secret. Пятый — публичная read replica. Все они дают доступ к данным.

## Практическое задание

1. Создайте Cloud SQL с публичным IP и ограничьте доступ своим CIDR.
2. Включите IAM database authentication и подключитесь через `cloud-sql-proxy --auto-iam-authn`.
3. Сделайте бэкап и восстановите из него новый инстанс.
4. Создайте read replica и проверьте её сетевые настройки.

## Что дальше / решение

Из Cloud SQL достаём данные и секреты. Дальше — использовать их. Зафиксируйте путь «IAM auth/публичный инстанс → данные» в графе. При private-only без пивота — `blocked`. Для бэкапов ищите возможность клонирования.

## Разобранный пример 2: пароль из Secret Manager

Если IAM auth не включён, пароль часто лежит в Secret Manager или в переменных среды приложения.

```bash
# Ищем секрет с паролем БД
gcloud secrets list --format='value(name)' | grep -iE 'sql|db|database'
# cloudsql-prod-password

gcloud secrets versions access latest --secret=cloudsql-prod-password
# S3cr3t-Pr0d-!

# Подключаемся по публичному IP (если authorized networks разрешает)
psql "host=34.1.2.3 port=5432 dbname=app user=postgres password=S3cr3t-Pr0d-! sslmode=require"
# app=#

# Или без SSL, если requireSsl=false
mysql -h 34.1.2.3 -u root -p'S3cr3t-Pr0d-!' app
```

Часто пароль к БД лежит не в Secret Manager, а в переменной среды Cloud Run/Functions или в файле `.env` внутри контейнера. Тогда путь такой: получить RCE/SSRF в сервисе → прочитать переменные → подключиться к БД. Проверяйте оба варианта.

## Практическое задание

1. Создайте Cloud SQL с паролем в Secret Manager и публичным IP.
2. Выдайте роль `secretmanager.secretAccessor` на секрет и прочитайте пароль.
3. Подключитесь к БД и убедитесь, что доступ есть.
4. Отключите публичный IP и проверьте, что подключение извне падает.

## Квиз

```quiz
- question: "Что нужно для входа через IAM database authentication?"
  options:
    - "Токен вместо пароля и включённый флаг cloudsql.iam_authentication"
    - "Только root-пароль"
    - "SSH-ключ"
    - "KMS-ключ"
  answer: 0
  explanation: "IAM auth использует короткоживущий токен как пароль."
- question: "Что означает 0.0.0.0/0 в authorized networks?"
  options:
    - "Доступ к инстансу разрешён из интернета"
    - "Инстанс приватный"
    - "SSL обязателен"
    - "Бэкапы включены"
  answer: 0
  explanation: "Это разрешает подключения с любого IP."
- question: "Зачем атакующему cloudsql.instances.clone?"
  options:
    - "Создать копию инстанса и читать данные, не трогая прод"
    - "Удалить инстанс"
    - "Сменить регион"
    - "Отключить SSL"
  answer: 0
  explanation: "Клон — быстрая копия, к которой можно менять пароль."
- question: "Где часто лежит пароль к Cloud SQL?"
  options:
    - "В Secret Manager"
    - "В CloudTrail"
    - "В VPC"
    - "В KMS"
  answer: 0
  explanation: "Приложения хранят пароль в Secret Manager или переменных среды."
```

## Где пригодится

- **Пентест GCP:** доступ к управляемым БД.
- **Red team:** клонирование и тихий доступ.
- **Cloud IR:** восстановление из бэкапов.
- **Data security:** настройка сетевой изоляции.
