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
## Задача

Детект-сервисы питаются логами. Значит, логи — это цель. В этом уроке — про **лог-пайплайн** (цепочку доставки логов) и его **целостность**: как логи собираются, как их можно нарушить и как защита это замечает. Разберём на AWS CloudTrail.

## Данные: как устроен пайплайн CloudTrail

CloudTrail не хранит события «внутри себя» — он **доставляет** их в S3 (и опционально в CloudWatch Logs). Цепочка такая:

1. API-вызов → событие.
2. CloudTrail пишет событие в S3-бакет (`trail`).
3. (Опц.) доставка в CloudWatch Logs для метрик/алертов.

Смотрим, куда доставляет trail:

```
$ aws cloudtrail describe-trails --query 'trailList[].{Name:Name,Bucket:S3BucketName,MultiRegion:IsMultiRegionTrail}'
[ { "Name": "acme-trail", "Bucket": "acme-cloudtrail-logs", "MultiRegion": true } ]
```

События лежат в `s3://acme-cloudtrail-logs/...`. Значит, **кто контролирует бакет — контролирует логи**.

## Пробуем в лоб: удалить trail

Прямой путь — `delete-trail`/`stop-logging`. Мы уже знаем (`cloud-cloudtrail-evasion`), что это пишется и часто блокируется. Но есть тоньше — работать с **бакетом логов** напрямую.

## Приём: нарушение целостности через бакет

**1. Удаление объектов логов.** Если у нас есть `s3:DeleteObject` на бакет логов, мы можем удалить записи о своих действиях:

```
$ aws s3 rm s3://acme-cloudtrail-logs/AWSLogs/123456789012/CloudTrail/us-east-1/2026/10/12/ \
    --recursive
```

**2. Правка политики бакета.** Закрываем доставку логов, сняв разрешение CloudTrail:

```
$ aws s3api get-bucket-policy --bucket acme-cloudtrail-logs
{ "Statement": [ { "Principal": {"Service":"cloudtrail.amazonaws.com"}, "Action":"s3:PutObject" } ] }
```

Убираем это разрешение — новые логи перестают писаться.

**3. Отключение валидации.** CloudTrail умеет писать **digest-файлы** — хэши для проверки целостности. Проверяем:

```
$ aws cloudtrail describe-trails --query 'trailList[0].LogFileValidationEnabled'
true
```

Если `true` — удалённые/изменённые логи можно обнаружить по digest-файлам. Если `false` — подмена незаметна. Проверка целостности:

```
$ aws cloudtrail validate-logs --trail-arn <arn> --start-time 2026-10-12T00:00:00Z
Results requested for 2026-10-12T00:00:00Z to ...
1 validation error(s) found between ...
```

Ошибка валидации — сигнал, что логи трогали.

## Полный прогон: от правки бакета к «чистому» следу

1. **Разведка.** `describe-trails` → бакет логов и включена ли валидация.
2. **Права.** Есть ли `s3:DeleteObject`/`PutBucketPolicy` на бакет.
3. **Нарушение.** Удаляем/правим объекты, либо ломаем доставку.
4. **Проверка.** `validate-logs` покажет ошибки, если валидация включена.
5. **Сокрытие.** Если валидация выключена — следов нарушения не видно.

**Важно:** в реальности это очень шумно. Изменение политики бакета логов, `DeleteTrail`, `StopLogging` — всё это события, которые защита мониторит отдельно. Поэтому на практике чаще не «ломают логи», а **не попадают в них** (data events, непокрытые регионы).

## Azure Monitor и GCP Cloud Logging

Те же идеи в других облаках:

- **Azure Monitor.** Диагностические настройки направляют логи в Log Analytics/Storage. Отключение diagnostic settings = слепая зона (см. `cloud-azure-sentinel`). Хранилище логов — отдельный ресурс с IAM.
- **GCP Cloud Logging.** Логи хранятся в **log buckets**; можно менять retention, а **log sinks** экспортируют их в BigQuery/Storage. Удаление sink'а или снижение retention = потеря следов.

Проверка GCP:

```
$ gcloud logging sinks list
NAME          DESTINATION
audit-sink    storage.googleapis.com/acme-audit-logs
$ gcloud logging buckets list --location=global
BUCKET_ID   RETENTION_DAYS
_Default    30
```

Если retention мал, а sink'ов нет — следы быстро исчезают сами.

## Защита и что ломает вмешательство

- **Log file validation** включена — подмена детектится digest'ами.
- **Object Lock / immutability** на бакете логов — объекты нельзя удалить.
- **Отдельный аккаунт для логов** — trail пишет в другой аккаунт, недоступный атакующему.
- **SCP запрещает** `DeleteTrail`/`StopLogging`/правку бакета.
- **Алерты на изменения** лог-инфраструктуры.

## Если не сработало

- **Валидация включена** — подмена видна.
- **Object Lock** — удалить нельзя.
- **Логи в отдельном аккаунте** — нет прав.
- **SCP блокирует** изменения — остаётся только «не попадать в логи».

## Мини-сценарий: подмена и её обнаружение

Покажем, как вмешательство в пайплайн выглядит с двух сторон.

1. **Атакующий.** У него есть `s3:DeleteObject` на бакет логов. Он удаляет объекты за нужный день: `aws s3 rm s3://acme-cloudtrail-logs/AWSLogs/.../2026/10/12/ --recursive`.
2. **След.** В CloudTrail остаётся событие `DeleteObject` (если оно само не удалено). Плюс — `PutBucketPolicy`/`StopLogging`, если он их трогал.
3. **Защитник запускает валидацию.** `aws cloudtrail validate-logs --trail-arn <arn> --start-time ...` → `validation error(s) found`. Digest-файл не сходится с оставшимися логами.
4. **Если Object Lock включён.** Удаление отвергается: `AccessDenied` — объекты неизменяемы.
5. **Если логи в отдельном аккаунте.** У атакующего в основном аккаунте вообще нет прав на бакет логов — вектор не работает.

Вывод: подмена логов возможна ровно там, где нет валидации, Object Lock и изоляции аккаунта. Поэтому защита строится из этих трёх слоёв.

## Разбор: целостность логов — это слои

Логи защищены ровно настолько, насколько многослойна их защита. Один слой — **валидация** (digest-файлы): она не мешает удалить лог, но делает удаление обнаружимым. Второй — **immutability** (Object Lock): мешает удалить вообще. Третий — **изоляция аккаунта**: у атакующего просто нет прав на бакет логов. Если есть только один слой, он обходится: без валидации удаление незаметно, без Object Lock объекты исчезают, без изоляции у атакующего есть права. Поэтому зрелые организации комбинируют все три и добавляют алерты на изменения лог-инфраструктуры. Тогда «стереть следы» становится либо невозможно, либо мгновенно заметно.

И держите отдельный мониторинг на изменения самой лог-инфраструктуры — это очень громкий и полезный сигнал.

Если логи нужны для комплаенса, храните их дольше и в неизменяемом виде — иначе к моменту проверки следов просто не останется.

## Что мы теперь знаем

1. CloudTrail **доставляет** события в S3 — логи живут в бакете.
2. Правка бакета/удаление объектов нарушает целостность.
3. Digest-файлы (log file validation) позволяют это обнаружить.
4. Azure Monitor и GCP Cloud Logging устроены аналогично.
5. Практичнее «не попадать в логи», чем ломать пайплайн.

## Частые ошибки

- **Считать, что CloudTrail «сам себя» защищает** — логи лежат в бакете с IAM.
- **Валидация выключена** (`LogFileValidationEnabled: false`) — подмена незаметна.
- **Нет Object Lock** на бакете логов — объекты можно удалить.
- **Trail в том же аккаунте**, что и прод — атакующий может иметь права на логи.
- **SCP не запрещает** `StopLogging`/`DeleteTrail`/правку бакета.

## На что смотреть дальше

- Бакет логов и его политика/права.
- `LogFileValidationEnabled`.
- Object Lock / immutability на бакете.
- Отдельный аккаунт для логов.
- Azure diagnostic settings и GCP sinks/retention.

## Быстрая проверка

```bash
aws cloudtrail describe-trails --query 'trailList[0].{B:S3BucketName,V:LogFileValidationEnabled}'
aws s3api get-bucket-policy --bucket acme-cloudtrail-logs
aws cloudtrail validate-logs --trail-arn <arn> --start-time 2026-10-12T00:00:00Z
gcloud logging sinks list
```

## Квиз

Проверь себя.

```quiz
- question: "Куда CloudTrail доставляет события?"
  options:
    - "В S3-бакет (и опционально в CloudWatch Logs)"
    - "В Lambda"
    - "В DynamoDB"
    - "В DNS"
  answer: 0
  explanation: "Trail пишет события в S3."
- question: "Что позволяют обнаружить digest-файлы CloudTrail?"
  options:
    - "Нарушение целостности логов (удаление/подмену)"
    - "Пароли пользователей"
    - "Тип инстанса"
    - "Регион бакета"
  answer: 0
  explanation: "Log file validation проверяет хэши."
- question: "Как защитить бакет логов от удаления объектов?"
  options:
    - "Включить Object Lock (immutability)"
    - "Отключить логирование"
    - "Сменить регион"
    - "Убрать MFA"
  answer: 0
  explanation: "Object Lock запрещает удаление."
- question: "Почему trail в отдельном аккаунте эффективен?"
  options:
    - "Атакующий в основном аккаунте не имеет прав на логи"
    - "Логи быстрее пишутся"
    - "Логи шифруются сильнее"
    - "Это ускоряет API"
  answer: 0
  explanation: "Изоляция аккаунта логов убирает доступ."
- question: "Что практичнее для атакующего, чем ломать пайплайн?"
  options:
    - "Не попадать в логи (слепые зоны), а не подменять их"
    - "Удалить аккаунт"
    - "Отключить интернет"
    - "Сменить пароль"
  answer: 0
  explanation: "Вмешательство шумно; лучше остаться вне покрытия."
```

## Куда дальше

В следующем уроке (`cloud-ir-playbook`) мы соберём всё это в пошаговый план реагирования на облачный инцидент. А пока главное: логи — это данные в бакете, и их целостность надо защищать отдельно от самого логирования.

## Где пригодится

- **Red team:** понимание, что и как логируется.
- **Blue team:** целостность и изоляция логов.
- **Пентест:** оценка лог-пайплайна.
- **Работа/DevSecOps:** validation, Object Lock, отдельный аккаунт, SCP.
- **Дальше по дереву:** `cloud-cloudtrail-evasion`, `cloud-ir-playbook`.
