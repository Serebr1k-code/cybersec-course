---
id: cloud-log-pipeline
title: "Вмешательство в лог-пайплайн: CloudTrail, Monitor и audit"
category: cloud
parent: cloud-defense-deep
difficulty: expert
order: 2
tags: [cloud, cloudtrail, logging, tampering, opsec, forensics, audit]
prerequisites: [cloud-defense-deep, cloud-cloudtrail-evasion]
useful_for:
  - "Понимание целостности логов в облаке"
  - "OPSEC: ослепление защиты"
  - "IR: доказательства и их сохранность"
estimated_minutes: 55
summary: "Как устроены лог-пайплайны облака (CloudTrail, CloudWatch, Azure Monitor, Cloud Logging), какие действия нарушают целостность логов, как это детектится и что это значит для атаки и расследования."
---

## Зачем этот урок

Логи — это то, на чём стоит детект, расследование и доказательства. В облаке лог-пайплайн состоит из нескольких звеньев: сервис-источник (CloudTrail, Azure Activity Log, Cloud Audit Logs), хранилище (S3/Storage/Log Analytics), обработчик (CloudWatch/Event Hub/Log Router) и потребитель (SIEM). Атакующий, который может **вмешаться** в любое звено, ослепляет защиту и лишает IR доказательств. Но такие действия сами логируются и детектятся — поэтому важно понимать механику. Этот урок — про устройство лог-пайплайнов, техники вмешательства, их заметность и последствия для обеих сторон.

## Как устроены лог-пайплайны

**AWS CloudTrail:**

- **Trail** — конфигурация: `IsMultiRegion`, `IsOrganizationTrail`, S3 bucket, CloudWatch Logs group, `EnableLogFileValidation` (digest-файлы).
- **Event selectors** — какие события пишутся (management по умолчанию, data events отдельно).
- **Insights** — аномалии API-активности.
- **CloudTrail Lake** — SQL-запросы по событиям.
- Логи пишутся в S3 (JSON gzip) и опционально в CloudWatch Logs.

**Azure Monitor / Activity Log:**

- **Diagnostic settings** — куда экспортировать логи (Log Analytics, Storage, Event Hub).
- **Activity Log** — control-plane операции.
- **Microsoft Sentinel** — SIEM поверх.

**GCP Cloud Logging:**

- **Log sinks** — маршрутизация логов в BigQuery/Storage/PubSub.
- **Audit Logs** — Admin Activity (всегда), Data Access (настраивается), System Event, Policy Denied.

Общее: логи собираются на уровне сервиса и маршрутизируются в хранилище. Целостность зависит от того, включена ли защита (log file validation, immutable storage, отдельный аккаунт для логов).

## Инструменты и команды

Проверка конфигурации CloudTrail:

```bash
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name my-trail
aws cloudtrail get-event-selectors --trail-name my-trail
aws cloudtrail get-insight-selectors --trail-name my-trail
```

Проверка Azure/GCP:

```bash
az monitor diagnostic-settings list --resource <resource-id>
az monitor activity-log list --max-events 5
gcloud logging sinks list
gcloud logging read "logName:activity" --limit 5
```

Действия, нарушающие пайплайн (все логируются):

```bash
# AWS
aws cloudtrail stop-logging --name my-trail
aws cloudtrail delete-trail --name my-trail
aws cloudtrail update-trail --name my-trail --s3-bucket-name attacker-bucket
aws cloudtrail put-event-selectors --trail-name my-trail --event-selectors '[]'

# Azure
az monitor diagnostic-settings delete --name mydiag --resource <id>

# GCP
gcloud logging sinks delete my-sink
```

## Разобранный пример: оценка вмешательства в CloudTrail

Сценарий: атакующий рассматривает варианты ослепить CloudTrail. Разбираем заметность каждого.

Шаг 1 — читаем конфигурацию:

```bash
aws cloudtrail describe-trails --query 'trailList[].{Name:Name,MultiRegion:IsMultiRegionTrail,Org:IsOrganizationTrail,Validation:LogFileValidationEnabled,Bucket:S3BucketName}'
# [{"Name":"org-trail","MultiRegion":true,"Org":true,"Validation":true,"Bucket":"audit-logs-org"}]
```

Вывод: multi-region, organization trail, validation включён, бакет в отдельном аккаунте. Это зрелая конфигурация.

Шаг 2 — вариант `StopLogging`:

```bash
aws cloudtrail stop-logging --name org-trail
```

Проблема: сам вызов `StopLogging` **пишется** в CloudTrail (до остановки) и почти всегда вызывает finding/алерт. Хуже того, в организации trail управляется management account, и остановка member-аккаунтом может не сработать или быть замечена. Это самый громкий вариант.

Шаг 3 — вариант `PutEventSelectors` (сужение):

```bash
aws cloudtrail put-event-selectors --trail-name org-trail \
  --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":false,"DataResources":[]}]'
```

Это отключает management events — тоже громко и легко детектится (изменение селекторов). Плюс organization trail защищён от member-модификации.

Шаг 4 — вариант «удалить логи в S3». Если у вас есть доступ к бакету с логами, можно удалять объекты. Но: log file validation (digest) делает удаление/подмену обнаружимым; версионирование и Object Lock могут сохранять копии; доступ к бакету обычно ограничен. Это тоже заметно.

Шаг 5 — вывод: в зрелой конфигурации вмешательство в пайплайн **не** является хорошей стратегией. Вместо этого — действовать в рамках уже собираемых событий, выбирая тихие API, или использовать регионы/сервисы, которые не покрыты (если такие есть). Заметность вмешательства выше, чем заметность самой атаки.

## Варианты атак и обходы

- **StopLogging/DeleteTrail.** Максимально громко; детектится GuardDuty (`Stealth:IAMUser/CloudTrailLoggingDisabled`) и Config.
- **PutEventSelectors.** Сужение событий — громко, но иногда менее очевидно; всё равно логируется.
- **UpdateTrail (смена бакета).** Перенаправление логов в ваш бакет — громко и подозрительно.
- **Удаление/подмена логов в S3.** Ломает digest (если validation включён); версионирование/Object Lock могут сохранить копии.
- **Отключение CloudWatch log subscription.** Меньше алертов, но изменение подписки логируется.
- **Disable GuardDuty / Config recorder.** См. `cloud-guardduty-evasion`; тоже громко.
- **Azure/GCP аналоги.** Удаление diagnostic settings, log sink, изменение retention.
- **Слепые зоны.** Data-plane события, не включённые регионы, аккаунты вне org trail — легитимные «дыры» без вмешательства.
- **Шум как маскировка.** Массовые легитимные события могут затруднить поиск, но это рискованно.

## Частые ошибки и подводные камни

- **Думать, что логи можно «тихо» удалить.** Валидация, версионирование и отдельный аккаунт делают это обнаружимым.
- **Забывать, что вмешательство само логируется.** `StopLogging` пишется до остановки.
- **Считать member-аккаунт всемогущим.** Organization trail управляется management account.
- **Игнорировать immutable storage.** Object Lock/WORM сохраняет логи даже при удалении.
- **Путать management и data events.** Data events нужно включать; без них чтение данных не в логах.
- **Не проверять retention.** Логи могут храниться 90 дней и более; старые события доступны.

## Защита и детект

- **Organization trail + отдельный аккаунт для логов.** Member-аккаунты не могут изменить trail.
- **Log file validation.** Digest-файлы для обнаружения подмены.
- **Object Lock / immutable storage.** Защита от удаления.
- **CloudWatch/EventBridge alerts** на `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `DeleteDetector`.
- **AWS Config rules** и GuardDuty findings на изменения логирования.
- **SIEM с независимым хранением** (копия в другом аккаунте/облаке).
- **Регулярный аудит** конфигурации логов (multi-region, все сервисы, retention).

## Что делать, если логи всё же нарушены

Если атакующий ослепил пайплайн, IR переключается на независимые источники:

- **Flow logs** (если собираются отдельно) показывают сетевую активность даже без CloudTrail.
- **GuardDuty findings** хранятся в сервисе и не удаляются вместе с CloudTrail.
- **SIEM-копия** (если логи экспортировались в отдельную систему/аккаунт) переживает компромисс.
- **Ресурсные следы:** теги, время создания ресурсов, история развёртываний, изменения IAM — восстанавливают часть таймлайна.
- **S3 server access logs** и **VPC Flow Logs** в отдельном аккаунте.

Практический вывод: устойчивость расследования зависит от того, были ли **независимые копии**. Если всё логирование жило в одном аккаунте с атакующим — доказательства потеряны. Поэтому защита должна дублировать логи в изолированный аккаунт/облако, а пентест — отмечать, есть ли такая изоляция. Это ключевой критерий зрелости.

## Практический чек-лист оценки лог-пайплайна

1. Включён ли CloudTrail/Activity Log/Audit Logs для всех регионов и сервисов?
2. Organization trail? Multi-region? Data events?
3. Где хранятся логи — отдельный аккаунт или рабочий?
4. Log file validation включён? Object Lock/immutable?
5. Куда экспортируются логи в SIEM — есть ли независимая копия?
6. Кто имеет права на `StopLogging`/`DeleteTrail`/`PutEventSelectors`/удаление логов?
7. Есть ли алерты на изменения логирования?
8. Каков retention и версионирование бакета логов?
9. Собираются ли flow logs и DNS-логи независимо?
10. Проверено ли восстановление таймлайна из независимых источников?

Этот чек-лист даёт оценку устойчивости пайплайна и подсказывает, какие действия атакующего останутся незамеченными, а какие — нет.

## Логи как актив: почему их читают обе стороны

Логи — это не только защита, но и **разведывательный актив**. Если логи утекают в бакет/хранилище, к которому у вас есть доступ, вы можете читать чужую активность: пути, параметры, IP, имена пользователей, иногда токены в query. Типовые находки:

- **S3-бакет с CloudTrail-логами** доступен на чтение → вы видите историю API-вызовов всей организации.
- **Логи приложений** в общем бакете → токены, cookies, персональные данные.
- **Flow logs** в доступном хранилище → сетевая топология и активность.
- **CI-логи** → секреты, замаскированные неполностью, пути к артефактам.

С другой стороны, зрелая защита изолирует логи: отдельный аккаунт, Object Lock, ограниченный доступ, SIEM-копия. Поэтому при оценке проверяйте, где лежат логи и кто их видит. Это и находка (если логи доступны), и оценка зрелости (если изолированы). Для пентеста чтение логов может ускорить понимание среды; для red team — дать контекст для OPSEC.

## Итоговая мысль

Логи — это одновременно цель и оружие: их можно ослепить (что громко и детектится), а можно прочитать (что тихо и полезно). Поэтому зрелая стратегия обеих сторон строится вокруг **изоляции и целостности**. Атакующий, который понимает, что вмешательство заметнее самой атаки, выбирает «растворение» в легитимных событиях. Защита, которая понимает это, делает пайплайн устойчивым (отдельный аккаунт, validation, Object Lock) и алертит на любые изменения. Именно поэтому оценка лог-пайплайна — обязательная часть пентеста облака: она показывает, насколько организация способна увидеть и доказать атаку.

## Что дальше / решение

Лог-пайплайн — это основа детекта и доказательств, и его вмешательство почти всегда громче самой атаки. Для red team правильная стратегия — не ослеплять, а **растворяться**: выбирать тихие API, использовать существующие сущности, избегать всплесков, работать в рамках покрытых событий (которые выглядят легитимно). Для blue team — сделать пайплайн устойчивым: org trail, отдельный аккаунт, validation, Object Lock, алерты на изменения. Для IR — понимать, что если логи были нарушены, доказательства нужно искать в независимых источниках (flow logs, SIEM-копия, GuardDuty). Записывайте в отчёт состояние лог-пайплайна: это ключевая часть оценки зрелости.

## Квиз

```quiz
- question: "Почему StopLogging в CloudTrail — плохая идея для атакующего?"
  options:
    - "Вызов логируется и почти всегда детектится"
    - "Он ускоряет атаку"
    - "Он удаляет бакеты"
    - "Он бесплатный"
  answer: 0
  explanation: "StopLogging фиксируется в CloudTrail до остановки и вызывает findings/алерты."
- question: "Что защищает логи CloudTrail от подмены?"
  options:
    - "Log file validation (digest-файлы)"
    - "SAS-токен"
    - "Security group"
    - "Route table"
  answer: 0
  explanation: "Digest-файлы позволяют обнаружить изменение/удаление логов."
- question: "Зачем хранить логи в отдельном аккаунте?"
  options:
    - "Чтобы member-аккаунты не могли их изменить или удалить"
    - "Чтобы ускорить запросы"
    - "Чтобы сэкономить"
    - "Чтобы шифровать"
  answer: 0
  explanation: "Изоляция логов в отдельном аккаунте защищает их от компромисса рабочего аккаунта."
- question: "Что такое слепая зона без вмешательства в пайплайн?"
  options:
    - "Data-plane события, которые не включены в сбор"
    - "Удалённые логи"
    - "Зашифрованные логи"
    - "Логи другого облака"
  answer: 0
  explanation: "Невключённые data events не попадают в детект без всякого вмешательства."
```

## Где пригодится

- **Red team:** OPSEC и понимание заметности.
- **Blue team:** укрепление лог-пайплайна и алерты.
- **IR:** целостность доказательств.
- **Пентест:** оценка зрелости логирования.
