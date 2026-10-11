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
---

## Зачем этот урок

Облачный детект строится на **логах управления** (CloudTrail, Activity Log, Audit Log) и **аналитике** (GuardDuty, Defender for Cloud). Атакующий должен понимать, что именно логируется, где слепые зоны, и как не попасться. Защитник — наоборот, использовать эту карту для усиления детекта.

## Что логирует CloudTrail

- **Management events** — control-plane: создание/удаление/изменение ресурсов, IAM, STS.
- **Data events** — операции с данными (S3 GetObject/PutObject, Lambda Invoke) — **по умолчанию выключены**.
- **Insight events** — аномальные паттерны.

Важно:

- **CloudTrail включён по умолчанию** для management events в большинстве аккаунтов, но **один trail может покрывать один регион**. Нужен **multi-region trail** для полноты.
- **Data events** часто не включены → чтение/запись объектов S3 может быть невидимо.

## Слепые зоны

| Активность | Логируется? |
|-----------|-------------|
| `s3:GetObject` (data event) | Только если включены data events |
| `s3:ListBucket` (management) | Да |
| Чтение секретов (GetSecretValue) | Да (management) |
| Вызов Lambda (Invoke) | Только data events |
| Доступ к metadata-сервису | **Нет** в CloudTrail (это не API) |
| Использование уже полученных кред | Да (STS/сервисные вызовы) |
| IMDS-запросы | Нет |

Ключевой вывод: **кража токена из metadata невидима**, но **последующее использование** токена логируется.

## GuardDuty

GuardDuty анализирует CloudTrail, VPC Flow Logs и DNS-логи. Типовые findings:

- **Recon** — `enumerate-iam`-подобная активность, массовые `Describe*`.
- **UnauthorizedAccess** — аномальные API-вызовы.
- **CryptoCurrency** — майнинг.
- **InstanceCredentialExfiltration** — использование кред инстанса извне.
- **Persistence** — создание backdoor-ролей/пользователей.

GuardDuty **не смотрит** в data plane напрямую, но комбинирует источники. Аномальный регион/IP — частый триггер.

## Evasion: принципы

1. **Использовать существующее, не создавать новое.** Чтение чужих кред тише, чем создание пользователей.
2. **Data plane вместо control plane.** Чтение объекта S3 (если data events не логируются) тише, чем IAM-операции.
3. **Двигаться из «легитимных» IP.** GuardDuty помечает аномальные IP/регионы.
4. **Не включать/не отключать логирование** — это громкое событие (и часто запрещено SCP).
5. **Ротировать сессии.** Долгие аномальные сессии заметнее.
6. **Учитывать API rate.** Массовые вызовы (enumerate-iam) создают burst-паттерн.

## Что НЕ стоит делать

- `cloudtrail:StopLogging`, `DeleteTrail` — громко, детектится, часто запрещено.
- Массовый `iam:CreateUser`/`CreateAccessKey` — классический persistence-детект.
- Использование root-аккаунта — сразу алерт.
- Отключение GuardDuty/Config — отдельный finding.
- Сканирование из неожиданных регионов.

## Разобранный пример: тихая работа

1. Получили токен роли через metadata (невидимо в CloudTrail).
2. Проверяем права — но **не** через `enumerate-iam` (громко), а точечно:
   ```bash
   aws sts get-caller-identity
   aws iam get-role --role-name <ROLE>   # если разрешено
   ```
3. Читаем данные через **data plane**, не создавая ресурсов:
   ```bash
   aws s3 ls s3://target-bucket/          # ListBucket — management, но типично
   aws s3 cp s3://target-bucket/db.sql ./  # GetObject — data event (часто не логируется)
   ```
4. Секреты — точечно, по именам, а не `list-secrets` целиком.
5. Не создаём пользователей; для персистентности — **добавляем ключ к существующему** или правим trust policy (тише).
6. Работаем из региона/сети, близких к легитимным.

## Защита (для защитников)

- Multi-region trail + data events на критичные бакеты.
- GuardDuty во всех регионах, SCP-запрет отключения.
- Алерты на `CreateAccessKey`, `PutRolePolicy`, `CreateUser`, `StopLogging`.
- CloudTrail в отдельный, изолированный аккаунт (log archive).
- Обнаружение использования IMDS-токенов извне (GuardDuty InstanceCredentialExfiltration).

## Частые ошибки

- **Считать, что CloudTrail покрывает всё.** Data events и metadata — вне его.
- **Массовая разведка.** `enumerate-iam` создаёт burst, который ловит GuardDuty.
- **Создание новых сущностей.** Громче, чем изменение существующих.
- **Не учитывать регион.** Single-region trail оставляет дыры.
- **Трогать логирование.** Почти всегда алерт и запрет SCP.

## Слепые зоны в деталях

- **Регионы без trail**: если trail не multi-region, события в других регионах не логируются.
- **Data events**: по умолчанию только management events; S3 `GetObject`/`PutObject` и Lambda `Invoke` — data events, их часто не включают.
- **CloudTrail отключён**: `StopLogging`/`DeleteTrail` (если есть права) — но это громко.
- **GuardDuty выключен** в регионе/аккаунте.
- **VPC endpoints/приватные пути** не всегда логируются как ожидается.
- **S3-бакет логов** — если атакующий может его очистить.

## Evasion-техники

| Техника | Эффект | Риск |
|---------|--------|------|
| Работа в регионе без trail | нет событий | средний |
| Использование уже выданных кред | нет новых API | низкий |
| Избегать data events | нет записи чтения | низкий |
| Имперсонация существующей роли | сливается с фоном | низкий |
| Отключение логирования | полная слепота | очень высокий |
| Очистка S3-логов | уничтожение доказательств | очень высокий |

## Практическое задание

В тестовом аккаунте включите multi-region trail и посмотрите, какие ваши действия НЕ попадают в лог (например, S3 `GetObject` без data events). Затем включите data events и повторите. Сравните. Это даёт понимание, какие действия атакующего остаются невидимыми при типовой конфигурации, и почему защитнику нужно включать data events и GuardDuty.

## Что видно и что нет: таблица

| Действие | Management event? | Видно по умолчанию |
|----------|-------------------|--------------------|
| CreateUser, AssumeRole | да | да |
| RunInstances | да | да |
| GetObject (S3) | нет (data event) | нет |
| PutObject (S3) | нет (data event) | нет |
| Invoke (Lambda) | нет (data event) | нет |
| GetSecretValue | да | да |
| Decrypt (KMS) | да | да |
| Сетевой трафик | нет | только Flow Logs |

Из таблицы видно: чтение данных часто невидимо. Значит, тихая эксфильтрация через `GetObject` без data events не оставляет следа в CloudTrail.

## Разбор: как детектит защитник

CloudTrail Insights находит аномальные всплески API; GuardDuty — поведенческие детекты. Примеры правил: `CreateAccessKey` вне CI, `AssumeRole` из нового IP, `GetSecretValue` из необычного principal. Атакующему важно понимать, что «тихо» — это не «незаметно вообще», а «в пределах нормального профиля аккаунта».

## Практическое задание 2

Возьмите набор CloudTrail-событий из тестового аккаунта и составьте профиль «нормального» поведения (кто, какие API, откуда). Затем добавьте в лог одно подозрительное событие (`CreateAccessKey` из нового IP) и найдите его глазами аналитика. Так вы учитесь и атаковать (сливаться с фоном), и защищаться (видеть аномалию).

## Data events: включение и цена

Data events (S3 object-level, Lambda invoke) нужно включать отдельно и они платные. Поэтому в большинстве аккаунтов их нет — чтение данных невидимо. Проверьте `get-event-selectors` у trail: если `DataResources` пуст, data events не пишутся. Это ключевая слепая зона.

## Квиз

```quiz
- question: "Что CloudTrail НЕ логирует по умолчанию?"
  options:
    - "Создание IAM-пользователя"
    - "Data events (например, S3 GetObject) и запросы к metadata-сервису"
    - "AssumeRole"
    - "DescribeInstances"
  answer: 1
  explanation: "Data events выключены по умолчанию, а IMDS-запросы вообще вне CloudTrail."
- question: "Какая активность наиболее заметна для GuardDuty?"
  options:
    - "Чтение объекта S3"
    - "Массовые вызовы Describe* (burst-разведка) и создание пользователей"
    - "GetCallerIdentity"
    - "Чтение одного секрета"
  answer: 1
  explanation: "Burst-разведка и создание IAM-сущностей — типовые findings GuardDuty."
- question: "Почему multi-region trail важен для детекта?"
  options:
    - "Он быстрее"
    - "Одиночный trail покрывает один регион, оставляя дыры в других"
    - "Он дешевле"
    - "Он шифрует логи"
  answer: 1
  explanation: "Без multi-region trail активность в других регионах не логируется."
- question: "Какой приём OPSEC тише всего для персистентности?"
  options:
    - "Создать нового IAM-пользователя с админ-правами"
    - "Добавить ключ существующему пользователю или изменить trust policy"
    - "Отключить CloudTrail"
    - "Создать root-ключ"
  answer: 1
  explanation: "Изменение существующих сущностей менее заметно, чем создание новых."
- question: "Какое действие почти гарантированно вызовет алерт?"
  options:
    - "GetCallerIdentity"
    - "cloudtrail:StopLogging или DeleteTrail"
    - "s3:ListBucket"
    - "sts:AssumeRole"
  answer: 1
  explanation: "Отключение/удаление логирования — громкое и часто запрещённое SCP действие."
```

## Где пригодится

- **Red team** — тихая работа в облаке.
- **IR/Blue team** — усиление детекта и приоритизация алертов.
- **Threat hunting** — поиск persistence-паттернов.
- **DevSecOps** — включение data events и multi-region trail.
- **Сертификации** — AWS Security Specialty.
