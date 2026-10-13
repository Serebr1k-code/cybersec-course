---
id: cloud-cloudtrail-evasion
title: "CloudTrail и GuardDuty: evasion, слепые зоны и OPSEC атакующего"
category: cloud
parent: cloud-logging-detection
difficulty: hard
order: 1
tags: [cloud, cloudtrail, guardduty, detection, opsec, evasion, logging]
prerequisites: [cloud-logging-detection, cloud-post-exploit]
useful_for:
  - "Снижение обнаруживаемости при облачных атаках"
  - "Понимание слепых зон логирования"
  - "IR/Blue team: усиление детекта"
estimated_minutes: 40
summary: "Как устроены CloudTrail, GuardDuty и аудит, какие слепые зоны существуют, и как атакующий минимизирует следы. Практические приёмы OPSEC и что всё равно выдаёт активность."
lab:
  kind: shell
  title: "Практика: анализ CloudTrail после инцидента"
  toolset: [core]
  workdir: /home/student/logs
  files: [task.md, cloudtrail.json, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Открой лог: `cat cloudtrail.json` — это записи CloudTrail."
    - "Ищи «тихие» события: `StopLogging`, `DeleteTrail`. С какого IP они пришли?"
    - "В поле `requestParameters` одного события лежит флаг. Поищи: `grep nto cloudtrail.json`."
    - "Итог: `grep nto cloudtrail.json | cut -d'\"' -f4 > found.txt`."
---
## Задача

Мы научились добывать креды и двигаться по облаку. Теперь — про то, что нас выдаёт. В AWS каждое действие через API пишется в **CloudTrail** (журнал аудита), а подозрительное поведение ловит **GuardDuty** (сервис детекта угроз). Задача: понять, как читать эти журналы глазами атакующего и где у них слепые зоны. Разберём на конкретном аккаунте.

## Данные: что пишет CloudTrail

**CloudTrail** записывает **management events** (управляющие события) — вызовы API управления: создание пользователя, чтение секрета, изменение политики. Ищем, например, наш собственный вызов чтения секрета:

```
$ aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
    --max-results 1
{
  "EventName": "GetSecretValue",
  "Username": "intern",
  "SourceIPAddress": "203.0.113.9",
  "EventTime": "2026-10-12T09:14:02Z"
}
```

Вот он — наш вызов, с нашим IP и именем. Каждое действие оставляет запись. Отсюда первый вывод: **тихих API-вызовов в AWS нет**.

## Пробуем в лоб: а можно ли отключить логирование?

Логичная мысль — выключить CloudTrail. Команда есть:

```
$ aws cloudtrail stop-logging --name acme-trail
$ aws cloudtrail lookup-events --max-results 1
{ "EventName": "StopLogging", "Username": "intern", "ErrorCode": "AccessDenied" }
```

Но два «но»: во-первых, само `StopLogging` **пишется в CloudTrail** (и часто вызывает алерт), во-вторых, организация может запретить отключение через SCP, а trail — быть **organization trail** (один на все аккаунты). Прямое отключение — шумный и плохой путь.

## Приём: слепые зоны и снижение заметности

Вместо отключения ищем зоны, где логируется меньше, и действуем через «шумные» сервисы.

**1. Data events не включены.** CloudTrail по умолчанию пишет только management events. Чтение объектов S3 (`GetObject`) — это **data event**, и он не логируется, если не включён явно. Значит, эксфильтрация из S3 может быть невидимой:

```
$ aws s3 cp s3://acme-secrets/db.txt . # GetObject — без data events не в логе
```

**2. Регион вне trail.** Если trail — single-region, действия в «неохваченном» регионе не пишутся. Атакующие любят редкие регионы:

```
$ aws ec2 run-instances --region af-south-1 ...
```

**3. Сервисы без подробного логирования.** Некоторые вызовы попадают в CloudTrail, но не в GuardDuty; другие (например, работа через уже полученный доступ внутри EC2) вообще не идут через API AWS.

**4. Использование уже выданных ролей.** Действия из-под украденной роли пишутся, но выглядят как «легитимный» сервис — нужно, чтобы аналитик заметил аномалию в паттерне.

## Полный прогон: от следа до маскировки

1. **Осознаём след.** `lookup-events` показывает наши вызовы.
2. **Не трогаем логи напрямую.** `StopLogging`/`DeleteTrail` — громко и часто блокируется.
3. **Идём в слепые зоны.** Читаем S3 без data events, работаем в редком регионе.
4. **Сливаемся с шумом.** Используем сервисы, которые и так делают много вызовов (Lambda, ECS), чтобы наши вызовы не выделялись.
5. **Проверяем, что видно.** Смотрим, что реально записалось:

```
$ aws cloudtrail lookup-events --max-results 5 --query 'Events[].EventName'
["GetCallerIdentity","ListBuckets","GetSecretValue","AssumeRole","RunInstances"]
```

`GetCallerIdentity` — наш разведочный вызов, `RunInstances` — в редком регионе (если trail его не покрыл — его тут нет).

## GuardDuty: что он ловит

**GuardDuty** — управляемый детект: он анализирует CloudTrail, VPC Flow Logs и DNS-логи и выдаёт **findings** (находки) по моделям угроз. Примеры:

- `UnauthorizedAccess:IAMUser/TorIPCaller` — вызовы с Tor-выхода.
- `Recon:IAMUser/UserPermissions` — перебор прав (`ListRoles`, `DescribeInstances` подряд).
- `CredentialAccess:IAMUser/AnomalousBehavior` — нетипичное для пользователя чтение секретов.
- `Exfiltration:S3/ObjectRead.Unusual` — аномальное чтение S3.

Смотрим findings (если есть доступ):

```
$ aws guardduty list-findings --detector-id <id> --query 'FindingIds' --output text | head
9f2c... 1a2b...
$ aws guardduty get-findings --detector-id <id> --finding-ids 9f2c... \
    --query 'Findings[0].{Type:Type,Severity:Severity}'
{ "Type": "Recon:IAMUser/UserPermissions", "Severity": 5.0 }
```

GuardDuty реагирует на **поведение**: перебор, аномальные регионы, Tor, всплеск чтения. Значит, OPSEC — не «отключить GuardDuty», а **не выглядеть аномально**.

## Защита и что ломает атаку (глазами защитника)

- **Organization trail + все регионы** — закрывает региональную слепую зону.
- **Data events на критичные бакеты** — видит чтение секретов.
- **SCP запрещает `StopLogging`/`DeleteTrail`.**
- **GuardDuty во всех аккаунтах и регионах**, с авто-реакцией.
- **Алерты на аномалии** (новый IP, новый регион, всплеск API).

## Если не сработало

- **Data events включены** — чтение S3 видно.
- **Trail все-региональный** — редкий регион не спасает.
- **GuardDuty с авто-изоляцией** — учётку отключают автоматически.
- **Всё логируется и алертится** — активность заметна, нужна легитимная «легенда».

## Мини-сценарий: заметный доступ против тихого

Сравним два подхода на одном и том же аккаунте.

**Громкий путь.**
1. `aws cloudtrail stop-logging --name acme-trail` → событие `StopLogging` с нашим ARN. Алерт.
2. `aws iam list-users`, `list-roles`, `list-policies`, `describe-instances` подряд → GuardDuty: `Recon:IAMUser/UserPermissions`.
3. `aws secretsmanager get-secret-value` для десяти секретов → `CredentialAccess` finding.
Итог: три сигнала за минуту, учётку изолируют.

**Тихий путь.**
1. Trail все-региональный и data events выключены — читаем S3 через `GetObject` (в логе не появится).
2. Действуем из-под уже используемой роли сервиса в обычном регионе — совпадаем с baseline.
3. Точечные вызовы вместо перебора — нет паттерна разведки.
Итог: ни одного finding.

Разница не в инструментах, а в **паттерне**. OPSEC — это дисциплина поведения, а не отключение детекта.

## Разбор: OPSEC — это поведение, а не инструмент

Главная ошибка новичка — думать, что «тихая» атака означает «другой инструмент». На самом деле инструменты тут ни при чём: те же `aws`-вызовы пишутся в CloudTrail и анализируются GuardDuty. Разница — в **паттерне**. Перебор прав, всплеск чтения секретов, работа из Tor, действия в 3 часа ночи — всё это отклонения от baseline, и именно на них ловят. Поэтому OPSEC в облаке — это дисциплина: меньше вызовов, из ожидаемого контекста, в ожидаемом регионе, без аномальных объёмов. Отключение детекта — противоположность: оно само создаёт громкий сигнал.

## Что мы теперь знаем

1. CloudTrail пишет все management events; data events — только если включены.
2. Прямое отключение логирования — громко и часто блокируется SCP.
3. Слепые зоны: data events, регионы вне trail, отсутствие GuardDuty.
4. GuardDuty ловит поведение, а не только отдельные вызовы.
5. OPSEC — не отключать детект, а не выделяться.

## Частые ошибки

- **Single-region trail** — действия в других регионах не пишутся.
- **Data events выключены** — чтение S3/секретов невидимо.
- **Нет SCP на `StopLogging`/`DeleteTrail`.**
- **GuardDuty не во всех аккаунтах/регионах.**
- **Алерты только на критичное** — разведка не замечается.

## На что смотреть дальше

- Включены ли data events и в каких бакетах.
- Single-region или organization trail.
- Покрытие GuardDuty по аккаунтам/регионам.
- SCP на `cloudtrail:StopLogging`.
- Наличие авто-реакции на findings.

## Быстрая проверка

```bash
aws cloudtrail describe-trails --query 'trailList[].{Name:Name,MultiRegion:IsMultiRegionTrail}'
aws cloudtrail get-event-selectors --trail-name acme-trail
aws guardduty list-detectors
aws cloudtrail lookup-events --max-results 5 --query 'Events[].EventName'
```

## Квиз

Проверь себя.

```quiz
- question: "Какие события CloudTrail пишет по умолчанию?"
  options:
    - "Только management events"
    - "Только data events"
    - "Все события, включая data"
    - "Только ошибки"
  answer: 0
  explanation: "Data events включаются отдельно."
- question: "Почему StopLogging — плохой выбор для атакующего?"
  options:
    - "Само действие пишется в CloudTrail и часто вызывает алерт"
    - "Оно шифрует логи"
    - "Оно ускоряет API"
    - "Оно удаляет аккаунт"
  answer: 0
  explanation: "StopLogging логируется и может блокироваться SCP."
- question: "Что относится к слепой зоне CloudTrail?"
  options:
    - "Data events S3, не включённые явно"
    - "Вход в консоль"
    - "Создание пользователя"
    - "AssumeRole"
  answer: 0
  explanation: "GetObject не пишется без data events."
- question: "На чём основаны findings GuardDuty?"
  options:
    - "На поведении: перебор, аномальные регионы, Tor, всплески"
    - "Только на тегах ресурсов"
    - "На паролях"
    - "На DNS-зонах"
  answer: 0
  explanation: "GuardDuty анализирует поведение и модели угроз."
- question: "Как правильно снижать заметность в AWS?"
  options:
    - "Не выделяться на фоне легитимного трафика, а не отключать детект"
    - "Удалить CloudTrail"
    - "Отключить GuardDuty"
    - "Сменить пароль root"
  answer: 0
  explanation: "Отключение детекта шумно; OPSEC — сливаться с нормой."
```

## Куда дальше

В следующем уроке (`cloud-azure-sentinel`) мы посмотрим, как устроен SIEM в Azure и где его слепые зоны. А пока главное: в облаке логируется почти всё, и выживают не те, кто отключает логи, а те, кто не выделяется.

## Где пригодится

- **Red team:** OPSEC при облачных атаках.
- **Blue team:** усиление детекта и покрытие слепых зон.
- **Пентест:** оценка видимости действий.
- **Работа/DevSecOps:** organization trail, data events, SCP, GuardDuty.
- **Дальше по дереву:** `cloud-logging-detection`, `cloud-guardduty-evasion`.
