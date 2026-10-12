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

## Задача

**Cloud SQL** — управляемые MySQL/PostgreSQL/SQL Server в GCP. Как и RDS, это «база без ОС», но с несколькими входами: публичный IP без firewall, слабые пароли, IAM database authentication, пароль в Secret Manager, бэкапы и реплики. Отдельная особенность GCP — тесная интеграция с IAM: иногда вход возможен **токеном, без пароля**.

Цель урока: войти в продовую базу Cloud SQL, не зная пароля.

## Данные, с которыми работаем

Разберём модель:
- **Instance** — сервер с public IP (опционально) и private IP (через VPC);
- **Authorized networks** — список CIDR, которым разрешён доступ по public IP;
- **IAM database authentication** — вход токеном через Cloud SQL Auth Proxy;
- **Backups / replicas** — снимки и копии, часто с более слабыми настройками.

Начинаем с инвентаризации:

```bash
$ gcloud sql instances list
NAME     DATABASE_VERSION  LOCATION       TIER
prod-db  POSTGRES_15       us-central1    db-custom-2-7680
```

Смотрим сеть и флаги:

```bash
$ gcloud sql instances describe prod-db --format='value(settings.ipConfiguration.authorizedNetworks[].value)'
0.0.0.0/0
$ gcloud sql instances describe prod-db --format='value(settings.databaseFlags)'
[{'name': 'cloudsql.iam_authentication', 'value': 'on'}]
```

Две важные находки: в authorized networks стоит **`0.0.0.0/0`** (доступ из интернета), и включён флаг **`cloudsql.iam_authentication`**. Значит, можно попробовать вход по токену.

## Шаг 1: проверяем пользователей

```bash
$ gcloud sql users list --instance=prod-db
NAME      HOST  TYPE
appuser         CLOUD_IAM_USER
postgres        BUILT_IN
```

Пользователь `appuser` имеет тип **`CLOUD_IAM_USER`** — он аутентифицируется через IAM, а не по паролю.

## Шаг 2: подключаемся без пароля

Запускаем **Cloud SQL Auth Proxy** в режиме `--auto-iam-authn` — он сам подставит наш IAM-токен:

```bash
$ cloud-sql-proxy --auto-iam-authn acme-prod:us-central1:prod-db &
$ PGPASSWORD=$(gcloud auth print-access-token) psql -h 127.0.0.1 -U appuser -d app
app=>
```

Паролем здесь служит **короткоживущий access token** (около часа). Никакого пароля мы не знали. Если у роли есть `cloudsql.instances.connect`, вход в базу доступен по одной лишь идентичности IAM.

Читаем данные:

```bash
app=> SELECT email, role FROM users LIMIT 3;
        email         | role
----------------------+-------
 admin@acme.com       | admin
 billing@acme.com     | finance
```

## Полный прогон от начала до конца

1. `instances list` → нашли `prod-db`.
2. Описали сеть → `0.0.0.0/0`; флаги → IAM auth включён.
3. `users list` → есть `CLOUD_IAM_USER`.
4. Запустили Auth Proxy с `--auto-iam-authn` → вошли без пароля.

## Если IAM auth нет: пароль из Secret Manager

Когда IAM-аутентификация выключена, пароль часто лежит в **Secret Manager** (хранилище секретов GCP) или в переменных среды приложения:

```bash
$ gcloud secrets list --format='value(name)' | grep -iE 'sql|db|database'
cloudsql-prod-password
$ gcloud secrets versions access latest --secret=cloudsql-prod-password
S3cr3t-Pr0d-!
$ psql "host=34.1.2.3 port=5432 dbname=app user=postgres password=S3cr3t-Pr0d-! sslmode=require"
app=#
```

`versions access latest` отдаёт текущее значение секрета. Если `requireSsl=false`, можно и без TLS. Часто пароль лежит не в Secret Manager, а в переменной среды Cloud Run/Functions или в `.env` внутри контейнера — тогда путь такой: получить RCE/SSRF в сервисе → прочитать переменные → подключиться к БД.

## Если не сработало: клоны, реплики, бэкапы

Даже без пароля и IAM можно добраться до данных через копии:

```bash
$ gcloud sql instances clone prod-db prod-clone
$ gcloud sql users set-password postgres --instance=prod-clone --password='Pwn3d!'
```

Клон — быстрая копия, **не влияющая на прод**. Меняем на нём пароль и читаем данные. Аналогично:
- **Read replica** — отдельный инстанс с копией, часто с собственным (публичным) IP и слабыми настройками.
- **On-demand backup** — `gcloud sql backups create`; восстановление создаёт новый инстанс.
- **PITR** (point-in-time recovery) — восстановление на момент времени по бинарным логам.

## Обходы и edge cases

- **Private IP only.** Если публичного IP нет — нужен доступ в VPC (пивот); Auth Proxy изнутри VPC работает.
- **SSL required.** При `requireSsl=true` клиент предъявляет сертификат; с IAM auth это делает proxy.
- **CMEK.** Данные шифруются ключом KMS — чтение требует прав на ключ (обычно через сервисный аккаунт инстанса).
- **VPC-SC.** Периметр блокирует доступ извне — нужен пивот.
- **Serverless connector.** Cloud Run/Functions подключаются через Serverless VPC Connector — проверяй его сеть.

## Частые ошибки и подводные камни

- **Считать, что «нет публичного IP» = «нет доступа».** Реплики и клоны часто публичны.
- **Игнорировать IAM database auth.** Пароль не нужен — нужен короткоживущий токен.
- **Не проверить authorized networks.** `0.0.0.0/0` открывает инстанс всему интернету.
- **Забывать про Secret Manager.** Пароль к БД часто лежит там (`versions access latest`).
- **Путать `cloudsql.client` и `cloudsql.admin`.** Первое — подключение, второе — управление инстансом.

- **Не проверять `requireSsl`.** При `false` трафик может идти без шифрования.
- **Забывать про read replicas.** У них часто свой публичный IP и более слабые настройки.
- **Игнорировать Serverless VPC Connector.** Cloud Run/Functions подключаются к базе через него — проверяйте его сеть.

- **Не проверять бэкапы.** `gcloud sql backups list` показывает снимки, из которых можно восстановить новый инстанс.
- **Забывать про PITR.** Point-in-time recovery позволяет вернуть состояние на нужный момент по бинарным логам.
- **Считать CMEK препятствием навсегда.** Иногда доступ к ключу есть у сервисного аккаунта инстанса — проверяйте.

## Что мы теперь знаем

- `0.0.0.0/0` в authorized networks = база доступна из интернета.
- IAM database auth позволяет войти **токеном вместо пароля** (`CLOUD_IAM_USER`).
- `cloud-sql-proxy --auto-iam-authn` подставляет IAM-токен как пароль.
- Пароль часто лежит в Secret Manager (`versions access latest`) или в env сервиса.
- `instances clone` даёт копию без влияния на прод; реплики и бэкапы — тоже пути.
- `cloudsql.instances.connect` — вход, `cloudsql.admin` — управление.

## На что смотреть дальше

- **cloud-network-security**: сетевые барьеры GCP и как их обходить.
- **api-gateway**: публичные API-шлюзы и их мисконфиги.
- **cloud-enum-methodology**: инструменты разведки облака.

## Квиз

Проверь себя.

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
    - "В объекте VPC"
    - "В KMS"
  answer: 0
  explanation: "Приложения хранят пароль в Secret Manager или переменных среды."
- question: "Почему тип пользователя CLOUD_IAM_USER важен?"
  options:
    - "Он аутентифицируется через IAM, а не по паролю"
    - "Он всегда администратор"
    - "Он не может подключаться"
    - "Он хранит пароль в открытом виде"
  answer: 0
  explanation: "Такой пользователь входит токеном, сгенерированным из IAM-идентичности."
```

## Куда дальше

В следующем уроке мы займёмся **сетевой безопасностью облака** — security groups, NACL и firewall, — и разберём, как обходить сетевые барьеры. А пока главное запомни: **в Cloud SQL пароль часто не нужен вовсе** — IAM-токен и правильная роль дают вход, а клоны и реплики открывают данные в обход прода.

## Где пригодится

- **Пентест GCP:** доступ к управляемым БД.
- **Red team:** клонирование и тихий доступ.
- **Cloud IR:** восстановление из бэкапов.
- **Data security:** настройка сетевой изоляции.
