---
id: cloud-aws-config
title: "AWS Config и наблюдаемость: правила, агрегаторы и слепые зоны"
category: cloud
parent: cloud-aws-access-deep
difficulty: medium
order: 1
tags: [cloud, aws, config, cloudtrail, audit, compliance, detection]
prerequisites: [cloud-aws-access-deep, cloud-logging-detection]
useful_for:
  - "Оценка слепых зон аудита AWS"
  - "Понимание детекта и его обхода"
  - "Аудит соответствия и конфигураций"
estimated_minutes: 40
summary: "AWS Config: configuration items, rules, conformance packs и агрегаторы. Что реально пишется, какие правила ловят атакующего и где остаются слепые зоны для OPSEC."
lab:
  kind: shell
  title: "Практика: AWS Config и слепые зоны наблюдаемости"
  toolset: [core]
  workdir: /home/student/awsconfig
  files: [task.md, notes.md, config-rules.json, aggregator.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`config-rules.json` — активные правила; `aggregator.json` — агрегатор."
    - "Ищи регион/аккаунт, не покрытый агрегатором (слепая зона)."
    - "Найди флаг: `grep nto aggregator.json > found.txt`."

---
## Задача

Мы разбирали CloudTrail (кто что **сделал**) и GuardDuty (что **подозрительно**). Теперь — **AWS Config**: сервис, который записывает **состояние ресурсов** и их изменения. Задача: понять, что Config видит, какие **rules** (правила) ловят атакующего и где у него слепые зоны. Разберём на конкретном аккаунте.

## Данные: что записывает Config

**AWS Config** ведёт **configuration items** (CI) — снимки конфигурации ресурса: когда создан, какие свойства, кто менял. В отличие от CloudTrail (события API), Config отвечает на вопрос «как ресурс выглядел в момент времени T».

Проверяем, включён ли recorder (записыватель):

```
$ aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[].{Name:name,All:recordingGroup.allSupported}'
[ { "Name": "default", "All": true } ]
```

`allSupported: true` — записываются все поддерживаемые типы. Смотрим, какие ресурсы в истории:

```
$ aws configservice list-discovered-resources --resource-type AWS::EC2::Instance \
    --query 'resourceIdentifiers[].resourceId'
[ "i-0abc123def456" ]
$ aws configservice get-resource-config-history --resource-type AWS::EC2::Instance \
    --resource-id i-0abc123def456 --query 'configurationItems[].configuration'
```

История покажет, **кто** менял конфигурацию и когда. Для атакующего это означает: изменения, которые «не оставляют событий», всё равно видны как смена CI.

## Пробуем в лоб: правила (rules)

Config rules проверяют соответствие ресурсов политике. Типичные:

- `s3-bucket-public-read-prohibited` — публичный бакет.
- `iam-user-mfa-enabled` — MFA у пользователя.
- `restricted-ssh` — SSH открыт миру.
- `encrypted-volumes` — незашифрованный диск.

Смотрим, какие правила включены и что они нашли:

```
$ aws configservice describe-config-rules --query 'ConfigRules[].ConfigRuleName'
[ "s3-bucket-public-read-prohibited", "iam-user-mfa-enabled", "encrypted-volumes" ]
$ aws configservice describe-compliance-by-config-rule --query 'ComplianceByConfigRules[].{n:ConfigRuleName,s:Compliance.ComplianceType}'
[ { "n": "encrypted-volumes", "s": "NON_COMPLIANT" } ]
```

`NON_COMPLIANT` — есть незашифрованный диск. Правила работают и видят отклонения.

## Приём: слепые зоны Config

Config — мощный детект, но у него есть границы.

**1. Config не пишет data-plane.** Он фиксирует **конфигурацию**, а не операции чтения данных. `GetObject`, `GetSecretValue` — это не изменения конфигурации, и Config их не увидит.

**2. Задержка (latency).** CI пишется не мгновенно: между действием и появлением в Config — задержка. Атакующий успевает сделать многое до реакции.

**3. Rules ловят известные паттерны.** Если правило не написано под конкретную аномалию (например, новый IAM-пользователь), оно её не заметит.

**4. Aggregators.** В мульти-аккаунт среде Config использует **aggregators** (агрегаторы) для сбора из многих аккаунтов. Если агрегатор покрывает не все аккаунты/регионы — там слепая зона:

```
$ aws configservice describe-configuration-aggregators --query 'ConfigurationAggregators[].{n:ConfigurationAggregatorName,all:AccountAggregationSources}'
[ { "n": "org-agg", "all": [ { "AllAwsRegions": false } ] } ]
```

`AllAwsRegions: false` — часть регионов не покрыта.

## Полный прогон: что атакующий делает с учётом Config

1. **Разведка.** `describe-config-rules` → какие правила включены.
2. **Обход известных правил.** Держим ресурсы «compliant» (зашифрованные диски, MFA), чтобы не попадать под rules.
3. **Активность в data-plane.** Читаем S3/секреты — Config это не видит.
4. **Быстрые действия.** Используем задержку Config: меняем и откатываем конфигурацию.
5. **Проверяем покрытие.** Если аккаунт/регион не в агрегаторе — там Config молчит.

## Config vs CloudTrail: в чём разница

- **CloudTrail** — «кто вызвал какой API» (событие).
- **Config** — «как ресурс выглядел и менялся» (состояние).
- **GuardDuty** — «что выглядит подозрительно» (аналитика).

Для полной картины защите нужны все три. Атакующему важно, что **Config не видит чтение данных** — это его главная слепая зона.

## Защита и что ломает атаку (глазами защитника)

- **Config во всех аккаунтах и регионах**, агрегатор с `AllAwsRegions: true`.
- **Conformance packs** — наборы правил под стандарты.
- **Авто-ремедиация** (SSM Automation) по NON_COMPLIANT.
- **Правила на неожиданные изменения** (новый пользователь/ключ/публичный бакет).
- **Сочетание с CloudTrail и GuardDuty** — события + состояние + аналитика.

## Если не сработало

- **Config везде с авто-ремедиацией** — отклонения откатываются.
- **Правила на data-plane аномалии** (через CloudTrail/GuardDuty) — чтение тоже видно.
- **Нет задержки** — реакции быстрые.

## Мини-сценарий: изменение, которое заметит Config

1. **Атакующий расшаривает AMI.** `aws ec2 modify-image-attribute --image-id ami-0abc --launch-permission "Add=[{UserId:999999999999}]"`.
2. **Что видит Config.** Для типа `AWS::EC2::Image` меняется configuration item: `Public`/`LaunchPermissions`. Если есть правило на публичные AMI — статус `NON_COMPLIANT`.
3. **Что видит CloudTrail.** Событие `ModifyImageAttribute` с нашим ARN — «кто».
4. **Реакция защиты.** Config-правило + SSM Automation автоматически откатывает разрешение (если авто-ремедиация настроена).
5. **Слепая зона.** Если атакующий просто **читает** данные через `GetObject`, Config молчит: это не изменение конфигурации.

Так становится видно разделение ролей: Config фиксирует **изменение состояния**, CloudTrail — **событие API**, GuardDuty — **подозрительный паттерн**. Вместе они закрывают картину, по отдельности — нет.

## Разбор: почему одного Config недостаточно

Config отвечает только на один вопрос — «как изменилась конфигурация». Он не видит, **читали ли** данные, и не отличает легитимное изменение от вредоносного: если атакующий создал бэкдор-пользователя, Config честно запишет новый CI, но не скажет «это атака». Отсюда вывод о разделении труда: CloudTrail даёт событие (кто вызвал API), Config — состояние (как ресурс выглядел), GuardDuty — аналитику (что подозрительно). Защита, построенная только на Config, пропустит кражу данных и опоздает из-за задержки записи. Полнота достигается **комбинацией** трёх сервисов плюс авто-ремедиация на нежелательные изменения.

Наконец, Config бессилен против того, что не является изменением ресурса: чтение данных, эксфильтрация, использование уже выданных прав. Это зона CloudTrail и GuardDuty.

И не забывайте: Config — про соответствие, а не про инциденты; для реакции нужны алерты на конкретные события и изменения.

<!-- lab -->

## Что мы теперь знаем

1. Config записывает состояние ресурсов и их изменения (configuration items).
2. Config rules проверяют соответствие политике.
3. Config **не видит data-plane** (чтение данных).
4. Задержка записи и агрегаторы создают слепые зоны.
5. Для полной картины нужны Config + CloudTrail + GuardDuty.

## Частые ошибки

- **Агрегатор не покрывает все регионы** (`AllAwsRegions: false`).
- **Только «известные» rules** — нет правила на новые аномалии.
- **Нет авто-ремедиации** — NON_COMPLIANT остаётся.
- **Полагаться на Config для data-plane** — чтение данных он не видит.
- **Recorder выключен** в части аккаунтов.

## На что смотреть дальше

- Включён ли recorder и `allSupported`.
- Список Config rules и их compliance.
- Покрытие агрегатора (`AllAwsRegions`, все аккаунты).
- Наличие авто-ремедиации.
- Что Config не покрывает по определению (data-plane).

## Быстрая проверка

```bash
aws configservice describe-configuration-recorders
aws configservice describe-config-rules --query 'ConfigRules[].ConfigRuleName'
aws configservice describe-compliance-by-config-rule
aws configservice describe-configuration-aggregators
```

## Глазами защитника

AWS Config записывает изменения конфигурации ресурсов и проверяет правила (rules). Он видит изменения, но не всё: data events и ряд сервисов не покрыты, а правила срабатывают с задержкой. Защита: включить recording всех типов ресурсов, использовать conformance packs, агрегаторы, коррелировать с CloudTrail. Для атакующего важно, что Config показывает, что изменилось, но не всегда кто и как.

## Частые вопросы

**Что записывает Config?**

Изменения конфигурации ресурсов (создание, обновление, удаление) и соответствие правилам. Это история состояния, а не поток API-вызовов.

**Чем Config отличается от CloudTrail?**

CloudTrail показывает, кто сделал API-вызов; Config — что изменилось в ресурсе. Они дополняют друг друга.

**Что такое Config rules?**

Проверки соответствия (например, «S3 не публичен»). Они дают compliance-статус, но не блокируют изменения.

**Где слепые зоны Config?**

Data plane (чтение объектов), некоторые сервисы, задержка обнаружения, ресурсы вне recording.

**Как атакующий учитывает Config?**

Понимает, что изменения конфигурации будут записаны, и минимизирует изменения, используя существующие ресурсы.

**Что даёт агрегатор?**

Свод данных из нескольких аккаунтов и регионов; полезен защитнику, но и подсказывает атакующему структуру.

**Как защититься?**

Полное recording, conformance packs, агрегаторы, алерты на изменения, корреляция с CloudTrail.

**Можно ли отключить Config?**

Да, при широких правах, но это заметное действие, как и отключение CloudTrail.

## Разбор: изменение, которое заметит Config

Атакующий меняет bucket policy на публичную. Config фиксирует изменение и помечает ресурс как несоответствующий правилу. Защитник видит алерт и коррелирует с CloudTrail, находя роль и IP. Если бы атакующий использовал уже публичный бакет вместо изменения политики, Config не дал бы нового события. Защита — полное recording и алерты на изменения конфигурации.

## Что чаще всего упускают

Задержку и покрытие: Config не мгновенный и не полный. Второе — data plane: чтение объектов он не видит. Третье — корреляцию: Config без CloudTrail не отвечает на вопрос «кто». Вывод: используй Config вместе с CloudTrail и включай recording всех типов ресурсов.

**Есть ли аналоги Config в GCP и Azure?**

Да: Cloud Asset Inventory и Azure Resource Graph. Логика та же — снимок конфигурации и проверка правил.

**Что такое conformance pack?**

Набор правил и ремедиаций для стандарта (CIS, PCI). Даёт структурированный контроль соответствия.

## Квиз

Проверь себя.

```quiz
- question: "Что записывает AWS Config?"
  options:
    - "Состояние ресурсов и их изменения (configuration items)"
    - "Только пароли"
    - "Только сетевой трафик"
    - "Только DNS"
  answer: 0
  explanation: "Config ведёт историю конфигурации ресурсов."
- question: "Видит ли Config чтение объектов S3?"
  options:
    - "Нет, это data-plane, Config его не фиксирует"
    - "Да, все GetObject"
    - "Только DELETE"
    - "Только PUT"
  answer: 0
  explanation: "Config фиксирует конфигурацию, не операции чтения."
- question: "Что такое Config rule?"
  options:
    - "Проверка соответствия ресурса политике"
    - "Снимок диска"
    - "Тип инстанса"
    - "Пользователь IAM"
  answer: 0
  explanation: "Rules оценивают ресурсы на соответствие."
- question: "Зачем нужен configuration aggregator?"
  options:
    - "Для сбора Config из многих аккаунтов и регионов"
    - "Для шифрования"
    - "Для балансировки"
    - "Для DNS"
  answer: 0
  explanation: "Агрегатор объединяет данные мульти-аккаунт среды."
- question: "Какая слепая зона есть у Config?"
  options:
    - "Задержка записи и непокрытые аккаунты/регионы"
    - "Отсутствие интернета"
    - "Наличие MFA"
    - "Шифрование диска"
  answer: 0
  explanation: "Latency и неполное покрытие агрегатора."
```

## Куда дальше

В следующем уроке (`cloud-aws-ebs`) мы вернёмся к данным и разберём, как вытаскивать секреты из EBS-снапшотов. А пока главное: Config видит изменения конфигурации, но не чтение данных, — и это граница, которую надо учитывать обеим сторонам.

## Где пригодится

- **Red team:** OPSEC с учётом Config.
- **Blue team:** покрытие и авто-ремедиация.
- **Пентест:** оценка зрелости аудита AWS.
- **Работа/DevSecOps:** conformance packs, агрегаторы, правила.
- **Дальше по дереву:** `cloud-logging-detection`, `cloud-aws-ebs`.
