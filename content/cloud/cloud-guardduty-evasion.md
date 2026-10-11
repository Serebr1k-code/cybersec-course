---
id: cloud-guardduty-evasion
title: "GuardDuty, Defender for Cloud и SCC: evasion и слепые зоны"
category: cloud
parent: cloud-defense-deep
difficulty: expert
order: 2
tags: [cloud, guardduty, defender, scc, detection, evasion, opsec]
prerequisites: [cloud-defense-deep, cloud-cloudtrail-evasion]
useful_for:
  - "Снижение обнаруживаемости облачных атак"
  - "Понимание источников детекта"
  - "Red team OPSEC в облаке"
estimated_minutes: 55
summary: "Как работают облачные детект-сервисы (GuardDuty, Defender for Cloud, Security Command Center), какие источники они используют, где слепые зоны и как снизить заметность, не отключая детект напрямую."
---

## Зачем этот урок

Облачные провайдеры дают встроенные детект-сервисы: AWS GuardDuty, Microsoft Defender for Cloud, GCP Security Command Center (SCC). Они анализируют логи и метрики и выдают **findings** о подозрительной активности. Для red team и пентеста критично понимать, **что именно** они видят, а что — нет: не все регионы включены, не все типы событий собираются, часть API-вызовов не покрыта, а «легитимные» действия проходят мимо. Этот урок — про источники детекта, их слепые зоны и практические приёмы снижения заметности (без прямого отключения, которое само по себе громкое).

## Как работают детект-сервисы

**AWS GuardDuty** использует:

- **CloudTrail management events** — все control-plane вызовы API.
- **VPC Flow Logs** — сетевые метаданные (без необходимости включать свои flow logs; GuardDuty собирает независимо).
- **DNS logs** — через Route 53 Resolver.
- **EKS audit logs** — для кластеров EKS.
- **S3 data events**, **RDS login activity**, **Lambda network activity**, **Malware Protection** (EBS) — при включении защитных планов.

Findings бывают по категориям: `Recon`, `Discovery`, `UnauthorizedAccess`, `CredentialAccess`, `Exfiltration`, `Impact`, `PrivilegeEscalation`, `Persistence`.

**Defender for Cloud** (Azure) собирает Activity Log, Defender-планы по сервисам (Storage, Key Vault, App Service, Containers), alerts и рекомендации.

**SCC** (GCP) собирает Cloud Audit Logs, Event Threat Detection, Container Threat Detection, Security Health Analytics.

Ключевая идея: детект работает по **сигнатурам и аномалиям** на основе собираемых источников. Всё, что вне источников, — слепая зона.

## Инструменты и команды

Проверка, что включено (если есть права):

```bash
# GuardDuty: детекторы и регионы
aws guardduty list-detectors
aws guardduty get-detector --detector-id <id>
aws guardduty list-organization-admin-accounts

# Trusted IP sets и threat intel (белый список!)
aws guardduty list-ip-sets --detector-id <id>
aws guardduty get-ip-set --detector-id <id> --ip-set-id <setid>
aws guardduty list-threat-intel-sets --detector-id <id>

# Включённые защитные планы
aws guardduty list-members --detector-id <id>
```

Azure:

```bash
az security pricing list --query '[].{Name:name,Tier:pricingTier}'
az security alert list --query '[].{Name:name,Severity:severity}'
az security assessment list --query '[].displayName'
```

GCP:

```bash
gcloud scc findings list <organization-id> --format='table(finding.category,state)'
gcloud scc settings describe --organization=<id>
```

Эти команды показывают, какие источники включены, есть ли белые списки и на каком уровне. Если прав нет — оценивайте по косвенным признакам (наличие flow logs, GuardDuty через обнаружение изменений).

## Разобранный пример: оценка заметности операции

Сценарий: вы планируете серию API-вызовов для эскалации. Нужно оценить, что из этого заметно.

Шаг 1 — определяем, включён ли GuardDuty и какие планы:

```bash
aws guardduty list-detectors
# [{"DetectorId":"abc","CreatedAt":"..."}]
aws guardduty get-detector --detector-id abc --query '{Status:Status,Features:Features}'
# Status: ENABLED, Features: [EKS Audit Logs ENABLED, S3 Data Events ENABLED, ...]
```

Шаг 2 — проверяем trusted IP sets. Если вы работаете с IP, который в белом списке, часть findings подавляется:

```bash
aws guardduty list-ip-sets --detector-id abc
aws guardduty get-ip-set --detector-id abc --ip-set-id set-1 --query '{Format:Format,Location:Location}'
# Читаем S3-объект с CIDR — возможно, там офисные IP
aws s3 cp s3://guardduty-bucket/whitelist.txt -
```

Шаг 3 — оцениваем каждый запланированный вызов. Громкие действия: `StopLogging`, `DeleteTrail`, `CreateUser`, `CreateAccessKey`, `AttachUserPolicy` (с админской), `GetSecretValue` (всплеск), `CreateSnapshot`+`ModifySnapshotAttribute` (share). Тихие: `GetObject` из S3 (если data events не включены), чтение параметров, обычные `Describe*` в малом объёме.

Шаг 4 — выбираем путь с меньшей заметностью: не создавать новых сущностей, использовать существующие роли, читать данные там, где data events не включены, работать в регионе, который не покрыт (если такой есть, но это может быть признаком незрелой защиты — проверьте).

Шаг 5 — распределяем действия во времени (low-and-slow) и избегаем всплесков (`GetSecretValue` ×100 за минуту — явный сигнал). Оцениваем, не попадаем ли под `Discovery:IAMUser/AnomalousBehavior` (аномальный объём `List*`/`Get*`).

## Варианты атак и обходы

- **Не покрытые регионы.** GuardDuty может быть включён не во всех регионах; работа в неохваченном регионе менее заметна (но это красный флаг для зрелой защиты).
- **Отключение детекта.** `DeleteDetector`/`UpdateDetector` — громкое действие, которое само выдаёт атаку. Иногда проще **приглушить** (удалить trusted IP? нет — добавить свой IP в trusted set, если есть права).
- **Модификация trusted IP set.** Добавление своего IP в белый список подавляет часть findings.
- **Сужение источников.** Если есть права на `PutEventSelectors` (CloudTrail) — исключить события (см. `cloud-log-pipeline`).
- **Использование сервисов без data-plane логирования.** S3 без data events, DynamoDB без Streams-детекта.
- **Легитимные API.** Действия, входящие в обычный паттерн (деплой, чтение своих секретов), не триггерят.
- **Role chaining.** Цепочка AssumeRole между аккаунтами размывает атрибуцию; GuardDuty может выдать `CredentialAccess` при аномалии, но не всегда.
- **DNS-канал.** GuardDuty анализирует DNS-логи; эксфильтрация через DNS может детектиться (`Exfiltration:DNS`), но объём и шаблон важны.
- **Тихое чтение.** `GetObject` без data events не видно в GuardDuty (видно только в S3 server access logs, если включены).

## Частые ошибки и подводные камни

- **Считать GuardDuty всевидящим.** Он видит только источники, которые собирает, и только в включённых регионах/аккаунтах.
- **Отключать детект.** Это самое заметное действие; почти всегда хуже, чем действовать тихо.
- **Игнорировать trusted IP sets.** Иногда атакующий уже в белом списке — тогда часть действий не детектится.
- **Путать findings и alerts.** Finding может быть, но не отправлен в SIEM; alerts — только часть.
- **Забывать про data events.** S3/RDS data-plane нужно включать отдельно; часто выключено.
- **Работать «в лоб».** Всплески и новые сущности — главные триггеры.

## Защита и детект (для blue team)

- **Включайте все планы и все регионы.** GuardDuty org-wide, S3 data events, EKS audit, Malware Protection.
- **Экспорт findings в SIEM** и алерты на критические категории (`Exfiltration`, `CredentialAccess`, `Persistence`).
- **Мониторинг изменений в детекте.** Алерт на `DeleteDetector`, `UpdateDetector`, изменения trusted IP sets, `StopLogging`, `PutEventSelectors`.
- **Проверяйте trusted IP sets** — не должны содержать широкие CIDR или внешние адреса.
- **Automated response.** Lambda/Logic App на finding → изоляция, ротация ключей.
- **Периодический аудит покрытия** (какие регионы/аккаунты/планы включены).

## Defender for Cloud и SCC: особенности эвайжена

Хотя принципы те же, у Azure и GCP есть нюансы:

- **Defender for Cloud** привязывает «планы защиты» к подпискам и типам ресурсов. Если план для Storage/Key Vault/Containers выключен — соответствующие alerts не появляются. Проверяйте `az security pricing list`: `pricingTier` = `Standard` означает включённый план, `Free` — выключенный. Атакующему выгодны подписки с `Free`-планами, но это же и признак незрелой защиты.
- **Defender-алерты** по data-plane (например, аномальный доступ к Key Vault) требуют включённого плана; без него вы действуете в слепой зоне.
- **Azure Activity Log** собирает control-plane, но diagnostic settings могут не экспортировать логи в SIEM — тогда алертов нет.
- **SCC (GCP)** зависит от включённых детекторов (Event Threat Detection, Container Threat Detection) и от того, собираются ли Data Access audit logs (по умолчанию их **нет** — только Admin Activity). Это значит, что чтение данных в GCP часто не детектится вовсе без явной настройки.
- **Premium-уровень SCC** даёт больше детекторов; Standard — меньше.

Практический вывод: перед атакой выясните, какие планы/детекторы включены. Часто «слепая зона» — это не отсутствие логов, а невключённый план, который не анализирует уже собираемые данные.

## Пример оценки: что заметно в конкретной среде

Допустим, вы выяснили: GuardDuty включён в `us-east-1`, но не в `eu-west-1`; S3 data events выключены; EKS audit — включён. Тогда: чтение объектов S3 (даже массовое) не даст findings GuardDuty; создание IAM-пользователя — даст (`Persistence:IAMUser/...`); работа в `eu-west-1` менее покрыта. Вы строите план: основные действия — в непокрытом регионе, чтение данных — из S3 (не детектится), избегаете создания IAM-сущностей, используете существующие роли. Это и есть эвайжен по существу — на основе **знания покрытия**, а не отключения детекта. Записывайте вывод в отчёт: он показывает, где защите нужно расширить покрытие.

## Итоговая модель эвайжена

Соберём всё вместе. Эвайжен — это управление **отношением ваших действий к источникам детекта**. Формула проста: чем больше ваше действие похоже на «нормальную» активность, чем меньше источников его видят и чем ниже его объём, тем меньше шанс найтись. Практически это означает:

- **Знай покрытие.** Какие регионы/аккаунты/планы/типы событий включены. Это ваш «радар».
- **Выбирай тихие API.** Чтение данных там, где data events выключены; использование существующих сущностей; действия, входящие в легитимный паттерн.
- **Избегай громких триггеров.** Создание пользователей/ключей, отключение логов, шаринг снапшотов с внешним аккаунтом, публичные бакеты, всплески.
- **Распределяй во времени.** Low-and-slow вместо всплесков; аномальный объём — главный сигнал.
- **Не трогай сам детект.** Отключение GuardDuty/Defender/SCC — самое громкое действие.

Для пентеста конечная цель — не «остаться незамеченным любой ценой», а **продемонстрировать риск и оценить зрелость защиты**. Поэтому в отчёт идёт не только результат, но и оценка: какие действия детектируются, какие нет, где пробелы в покрытии. Это и есть настоящая ценность — заказчик получает карту своих слепых зон.

## Что дальше / решение

Эвайжен — это не отключение детекта, а **понимание источников и слепых зон**. Сначала выясните, что включено (GuardDuty/Defender/SCC, регионы, планы, trusted IP sets). Затем оцените каждый запланированный вызов по заметности и выберите минимально шумный путь: существующие сущности, тихие API, разрешённые каналы, распределение во времени. Помните, что отключение детекта — громкое действие; чаще выгоднее «раствориться» в легитимной активности. Записывайте оценку заметности в отчёт: она показывает зрелость защиты и объясняет, почему вас не заметили.

## Квиз

```quiz
- question: "Какие источники использует AWS GuardDuty?"
  options:
    - "CloudTrail, VPC Flow Logs, DNS logs, EKS audit logs и др."
    - "Только CloudTrail"
    - "Только сетевые пакеты"
    - "Только логи приложений"
  answer: 0
  explanation: "GuardDuty комбинирует несколько источников, включая flow и DNS logs."
- question: "Что такое trusted IP set в GuardDuty?"
  options:
    - "Белый список IP, для которых часть findings подавляется"
    - "Список заблокированных IP"
    - "Список ключей"
    - "Список регионов"
  answer: 0
  explanation: "Trusted IP sets подавляют определённые findings для указанных адресов."
- question: "Почему отключение GuardDuty — плохая идея для атакующего?"
  options:
    - "Это громкое действие, которое само детектится"
    - "Оно ускоряет атаку"
    - "Оно удаляет данные"
    - "Оно бесплатно"
  answer: 0
  explanation: "DeleteDetector/UpdateDetector логируются и алертятся."
- question: "Почему S3 data events важны для детекта?"
  options:
    - "Без них чтение объектов не попадает в детект"
    - "Они ускоряют загрузку"
    - "Они шифруют данные"
    - "Они создают бакеты"
  answer: 0
  explanation: "Data-plane события нужно включать отдельно; иначе GetObject не виден GuardDuty."
```

## Где пригодится

- **Red team:** OPSEC и снижение заметности.
- **Blue team:** тюнинг и проверка покрытия детекта.
- **Пентест:** оценка зрелости защиты.
- **IR:** понимание, что доступно для расследования.
