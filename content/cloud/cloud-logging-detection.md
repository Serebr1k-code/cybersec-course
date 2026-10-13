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
lab:
  kind: shell
  title: "Практика: читаем след в CloudTrail"
  toolset: [core]
  workdir: /home/student/trail
  files: [task.md, notes.md, cloudtrail.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Посмотри все userAgent в логе: `grep userAgent cloudtrail.json`."
    - "Обычные вызовы идут от `aws-cli/...`; один — не похож на стандартный."
    - "Аномальный userAgent — это и есть маркер атакующего (кастомный скрипт)."
    - "Запиши флаг: `grep nto cloudtrail.json > found.txt`."
---

## Вопрос, с которого всё начинается

В прошлом уроке мы нашли ключ `ci-deploy` и сделали пару вызовов: `sts get-caller-identity` и `aws s3 ls`. На первый взгляд — безобидно. Но в облаке нет «тихих» действий: почти каждый вызов API попадает в журнал аудита. Значит, кто-то из службы безопасности уже видит эти строки.

Вопрос урока: **что именно записывается**, как это прочитать и — если ты атакующий — как сделать так, чтобы твой след был как можно тише?

## Наш пример: след, который оставил наш ключ

Пойдём тем же путём, что и защита. В AWS журнал аудита называется **CloudTrail**. Посмотрим на последние события в аккаунте:

```
$ aws cloudtrail lookup-events --max-results 5 \
  --query 'Events[].{t:EventTime,name:EventName,user:Username}'
[
  {"t":"2026-10-11T09:14:02Z","name":"GetCallerIdentity","user":"ci-deploy"},
  {"t":"2026-10-11T09:14:07Z","name":"ListBuckets","user":"ci-deploy"},
  {"t":"2026-10-11T09:13:40Z","name":"ConsoleLogin","user":"admin"}
]
```

Вот и мы: два наших вызова лежат в открытом виде — с временем, именем события и тем, кто его сделал. Каждое событие в CloudTrail — это JSON с полями `eventTime`, `eventName`, `eventSource`, `userIdentity` (кто), `sourceIPAddress` (откуда) и `userAgent` (каким инструментом). Для защиты это готовая картина атаки.

## Шаг 1: control plane и data plane — почему видно не всё

Ключевое разделение, которое надо усвоить сразу:

- **Control plane** («плоскость управления») — действия, меняющие ресурсы: создать пользователя, изменить политику, поднять сервер. Логируется почти всегда.
- **Data plane** («плоскость данных») — операции с содержимым: прочитать файл из S3, вызвать Lambda. Часто **не** логируется, пока не включат отдельно.

Практический вывод: `CreateAccessKey` (создание ключа) виден всегда, а массовое скачивание файлов из S3 — только если включены *data events* (объектные события S3, платная опция). Поэтому атакующий предпочитает читать данные — это тише, а защита в первую очередь следит за control plane.

## Шаг 2: читаем свой след целиком

Посмотрим на все наши действия за последний час — так же, как это сделает аналитик:

```
$ aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE \
  --max-results 50 | jq -r '.Events[].CloudTrailEvent | fromjson |
    [.eventTime,.eventName,.sourceIPAddress,.userAgent] | @tsv'
2026-10-11T09:14:02Z  GetCallerIdentity  203.0.113.7  aws-cli/2.15.0
2026-10-11T09:14:07Z  ListBuckets        203.0.113.7  aws-cli/2.15.0
```

Видно всё: время, IP `203.0.113.7`, стандартный `userAgent` от `aws` CLI. Это важный сигнал для нас: пока мы выглядим как обычный пользователь CLI. Но если запустить кастомный скрипт, `userAgent` станет нетипичным — и это первый «красный флаг» для GuardDuty.

## Шаг 3: что именно ловит защита

Логи бесполезны без детекта. В AWS за это отвечает **GuardDuty** — сервис, который смотрит на CloudTrail, сетевой трафик и DNS и ищет аномалии. Рядом стоит **Security Hub**, агрегирующий находки.

Что чаще всего поднимает тревогу:

| Действие атакующего | Что срабатывает |
|---------------------|-----------------|
| `StopLogging`, `DeleteTrail` | GuardDuty: `Stealth:IAMUser/CloudTrailLoggingDisabled` |
| Серия отказов `AccessDenied` | признак перебора прав |
| `GetSecretValue` из чужого IP | `UnauthorizedAccess:IAMUser/...` |
| Много `GetObject` за минуту | S3 data events + Macie |

Отдельно про отказы: поле `errorCode` в событии показывает неуспешные вызовы. Массовые `AccessDenied` — классический признак того, что кто-то «нащупывает» права ключа.

## Шаг 4: OPSEC атакующего — как снижать шум

Это раздел про то, как защита видит нас. Знать его нужно и red, и blue.

1. **Не отключай логирование.** `StopLogging`/`DeleteTrail` сами пишут событие и почти всегда триггерят алерт. Тихо не выйдет.
2. **Используй существующие роли** (`AssumeRole` в легитимную роль) вместо создания новых сущностей.
3. **Работай из ожидаемого региона и сети.** Аномальный `sourceIPAddress` — топ-сигнал; лучше действовать через тот же EC2/NAT, что и легитимный трафик.
4. **Читай, а не меняй.** Чтение данных часто не логируется (если не включены data events).
5. **Следи за `userAgent`.** `aws` CLI и SDK выглядят обычно; кастомные скрипты и инструменты вроде Pacu — нет.
6. **Не создавай access keys.** `CreateAccessKey` — один из самых отслеживаемых вызовов.
7. **Помни про Organization trail** — общий журнал на все аккаунты организации, который из дочернего аккаунта не отключить.

Самопроверка OPSEC выглядит так — ты смотришь на себя глазами защиты:

```
$ aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE --max-results 50
```

## Шаг 5: то же самое у Azure и GCP

Модель одна, названия разные.

- **Azure:** control plane пишется в **Activity Log** (`az monitor activity-log list`), входы и MFA — в **Sign-in logs** Entra ID, изменения пользователей — в Entra audit logs. По умолчанию Entra audit хранится 30 дней, Activity Log — 90.
- **GCP:** **Admin Activity** включён всегда и хранится 400 дней; **Data Access** по умолчанию выключен. Читается через `gcloud logging read`.

```
$ az monitor activity-log list --max-events 5 \
  --query '[].{t:eventTimestamp,op:operationName.localizedValue,who:caller}'
```

Обрати внимание на окна хранения: в AWS CloudTrail Event history держит 90 дней, и если нет трейла в S3, старые события пропадут.

## Что мы теперь знаем

1. Почти каждое облачное действие попадает в аудит — control plane почти всегда, data plane часто нет.
2. CloudTrail показывает кто/что/когда/откуда; `errorCode` выдаёт перебор.
3. Отключение логов — само по себе событие и детектится.
4. Для атакующего главные сигналы — чужой IP, нетипичный `userAgent`, создание ключей.
5. Читать данные тише, чем менять конфигурацию.

## На что смотреть дальше

- **Не считай data plane логируемым.** S3 object-level и Lambda Invoke по умолчанию не пишутся.
- **Следи за окном хранения.** Без трейла в S3 события живут 90 дней.
- **Различай источники в Azure.** Activity Log и Entra audit — разные логи и сроки.
- **Строй детект на control plane:** `CreateAccessKey`, `AssumeRole`, `PutBucketPolicy`, `StopLogging`.

## Глазами защитника

Первое правило — включить то, что по умолчанию выключено: CloudTrail во все регионы, data events для критичных бакетов S3, GuardDuty и CloudTrail Insights. Отдельно логируют доступ к секретам (Secrets Manager, SSM) и вызовы `AssumeRole`, потому что именно они отмечают движение между ролями. В GCP включают Data Access-логи для важных сервисов, в Azure — diagnostic settings на ключевые ресурсы.

Второе — смотреть не только на «что», но и на «откуда»: новые source IP, необычные user-agent, резкие всплески объёма API-вызовов. Корреляция CloudTrail с VPC Flow Logs помогает связать вызов с конкретным сетевым путём. Для атакующего вывод простой: control-plane операции почти всегда видны, поэтому шум планируют заранее и не создают лишних сущностей.

## Частые вопросы

**Что CloudTrail пишет, а что нет?**

CloudTrail по умолчанию записывает management events — операции с ресурсами и конфигурацией: `CreateUser`, `AssumeRole`, `RunInstances`, `PutBucketPolicy`. Data events (чтение объектов S3, элементы DynamoDB) по умолчанию выключены и стоят отдельно. Поэтому кража данных через `GetObject` часто не видна, а вот создание роли или эскалация — видны всегда.

**Чем management events отличаются от data events?**

Management — это «кто что настроил»: создал, удалил, изменил, вошёл. Data — это «кто что прочитал или записал в содержимое»: объект S3, элемент таблицы, секрет. Для атакующего разница критична: первый тип логируется почти всегда, второй — только если его специально включили.

**Почему AssumeRole — самый заметный шаг?**

`AssumeRole` всегда пишется в CloudTrail с `sourceIPAddress`, `userAgent` и, при настройке, source identity. Резкий всплеск `AssumeRole` с новых IP или необычного user-agent — классический сигнал, который ловят CloudTrail Insights и GuardDuty. Поэтому цепочки ролей планируют заранее, а не «на бегу».

**Как снизить шум при работе в облаке?**

Использовать существующие роли и регионы, не плодить новых IAM-пользователей, держать API-вызовы в рамках привычного профиля аккаунта, знать про GuardDuty (аномалии) и CloudTrail Insights (всплески). Помни: любые `CreateUser`/`CreateAccessKey` остаются в логах и легко привязываются к твоему IP.

**Что аналогично в GCP и Azure?**

В GCP — Cloud Audit Logs, разделённые на Admin Activity (всегда пишутся) и Data Access (обычно выключены). В Azure — Activity Log и diagnostic settings, где data-plane логи тоже нужно включать отдельно. Везде принцип один: control plane виден, data plane — только по желанию защитника.

**Можно ли отключить логирование, чтобы не оставлять следов?**

`StopLogging` и `DeleteTrail` возможны при широких правах, но это крайне заметное действие: оно само пишется в CloudTrail и вызывает алерт. Практичнее работать в рамках привычного профиля аккаунта, чем гасить аудит — защитники почти всегда ловят именно отключение логов.

**Что такое CloudTrail Insights?**

Это функция, которая анализирует baseline API-вызовов и помечает аномалии: всплески `RunInstances`, `CreateKey`, серии `AccessDenied`. Для атакующего это значит, что «необычный объём» и «новый тип вызова» — сигнал сами по себе, даже если каждый отдельный вызов разрешён.

## Квиз

Проверь себя.

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
- question: "Какой признак в логах чаще всего указывает на брут/enumeration?"
  options:
    - "Массовые errorCode AccessDenied"
    - "Один успешный GetObject"
    - "Изменение цвета консоли"
    - "Ротация сертификата"
  answer: 0
  explanation: "Серии отказов — классический сигнал перебора прав."
- question: "Что из перечисленного для атакующего «тише»?"
  options:
    - "Чтение объектов из S3"
    - "CreateAccessKey"
    - "DeleteTrail"
    - "PutBucketPolicy"
  answer: 0
  explanation: "Чтение данных часто не логируется, если data events выключены."
```

## Куда дальше

В следующем уроке (`cloud-storage-s3`) мы возьмём конкретный бакет и разберём, как его мисконфигурации открывают данные наружу. А пока главное: любое изменение конфигурации в облаке видно защите, и самый тихий путь — читать, а не менять.

## Где пригодится

- **IR/Blue team:** восстановление цепочки атаки по CloudTrail/Activity Log/Sign-in logs.
- **Red team / пентест:** OPSEC — что попадёт в лог и как не засветиться.
- **CTF:** облачные задачи, где надо найти «кто и что сделал» в аудит-логе.
- **Работа:** настройка Diagnostic settings, retention, детект-правил.
- **Дальше по дереву:** `cloud-cloudtrail-evasion`, `cloud-credential-hunting`.
