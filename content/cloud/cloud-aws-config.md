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
---

## Зачем этот урок

AWS Config — сервис инвентаризации и оценки конфигураций. Он записывает изменения ресурсов (configuration items), проверяет их правилами (managed и custom) и собирает conformance packs для соответствия. Для атакующего Config важен по двум причинам: во-первых, он показывает, что защита реально видит (и что нет); во-вторых, Config Recorder — источник телеметрии, которую иногда можно отключить или обойти. Понимание Config — обязательная часть OPSEC в AWS.

## Модель AWS Config

- **Configuration recorder** — собирает изменения ресурсов в конкретном регионе. Может быть включён или выключен; может записывать «all supported resources» или только выбранные.
- **Configuration item (CI)** — снимок конфигурации ресурса + связей.
- **Rule** — проверка (managed rule, например `s3-bucket-public-read-prohibited`, или custom Lambda).
- **Conformance pack** — набор правил и ремедиаций (например, CIS, PCI).
- **Aggregator** — собирает данные из нескольких аккаунтов/регионов в один.
- **Remediation** — автоматическое исправление через SSM Automation.

Ключевой момент: Config пишет **конфигурационные изменения**, а не все API-вызовы. Чтение данных (`s3:GetObject`, `dynamodb:Scan`) Config не фиксирует — это делает CloudTrail (и то не всегда, если data events выключены).

## Инструменты и команды

```bash
# Что вообще настроено
aws configservice describe-configuration-recorders
aws configservice describe-configuration-recorder-status
aws configservice describe-delivery-channels

# Правила и их статус
aws configservice describe-config-rules --query 'ConfigRules[].{Name:ConfigRuleName,State:ConfigRuleState,Source:Source.Owner}'
aws configservice describe-compliance-by-config-rule --query 'ComplianceByConfigRules[].{Rule:ConfigRuleName,Status:Compliance.ComplianceType}'

# Conformance packs и агрегаторы
aws configservice describe-conformance-packs
aws configservice describe-configuration-aggregators

# История конфигураций конкретного ресурса
aws configservice get-resource-config-history --resource-type AWS::S3::Bucket \
  --resource-name my-bucket --query 'configurationItems[].{Time:captureTime,Status:configurationItemStatus}'

# Текущее состояние
aws configservice get-compliance-details-by-config-rule --config-rule-name s3-bucket-public-read-prohibited

# Агрегатор из другого аккаунта
aws configservice describe-configuration-aggregator-sources --configuration-aggregator-name org-aggregator
```

## Разобранный пример: оценка слепых зон

Сценарий: мы вошли в аккаунт и хотим понять, что нас выдаст.

```bash
aws configservice describe-configuration-recorders \
  --query 'ConfigurationRecorders[].{Name:name,Role:roleARN,AllResources:recordingGroup.allSupported}'
# [{"Name":"default","Role":"arn:aws:iam::111122223333:role/config-role","AllResources":false}]

aws configservice describe-configuration-recorder-status
# [{"name":"default","recording":true,"lastStatus":"SUCCESS"}]

aws configservice describe-config-rules --query 'ConfigRules[].ConfigRuleName'
# ["s3-bucket-public-read-prohibited","iam-user-mfa-enabled","encrypted-volumes"]
```

Вывод: записываются не все ресурсы (`AllResources:false`), правила покрывают только S3, IAM и EBS. Значит, создание Lambda, изменение DynamoDB или работа с Secrets Manager не вызовут Config-алерт. Это позволяет планировать действия вне зоны видимости Config — но CloudTrail всё равно пишет management events, поэтому «слепота» Config ≠ полная невидимость.

## Что реально ловит Config (и что нет)

| Событие | Config | CloudTrail (mgmt) | CloudTrail (data) |
|---|---|---|---|
| Публичный S3-бакет | Да (если правило есть) | Да | — |
| Изменение security group | Да (если recorder включён) | Да | — |
| Чтение S3-объекта | Нет | Нет | Да (если включено) |
| Scan DynamoDB | Нет | Нет | Нет (data event только для streams) |
| Вызов Lambda | Нет | Нет | Нет |
| GetSecretValue | Нет | Да (management) | — |

Из таблицы видно: Config — про конфигурации, CloudTrail — про вызовы API, а data events надо включать отдельно. Атакующий, который понимает это, строит действия так, чтобы попадать в минимально логируемые категории.

## Обход защит и edge cases

- **Отключение recorder.** `stop-configuration-recorder` требует `config:StopConfigurationRecorder`. Если у вас есть это право — можно ослепить Config (но это шумно и часто алертится).
- **Региональность.** Recorder работает по регионам; ресурсы в неохваченном регионе не записываются. Проверяйте все регионы.
- **Custom rules через Lambda.** Если у роли Lambda есть широкие права, компрометация правила = доступ. Иногда правила пишут данные в S3-бакет, который можно подменить.
- **Remediation.** Автоисправление может «откатить» ваш бэкдор (например, вернуть публичный бакет в приватный). Учитывайте это в персистентности.
- **Aggregator.** В мульти-аккаунт среде агрегатор собирает данные; если он не покрывает аккаунт, действия в нём видны хуже.
- **Delivery channel.** Данные Config пишутся в S3 + SNS. Доступ к этому бакету даёт историю изменений (полезно для форензики и для понимания, что видно).

## Частые ошибки и подводные камни

- Считать, что «Config включён» = полный аудит. Часто включён частично.
- Путать Config и CloudTrail: Config не пишет чтения данных.
- Игнорировать ремедиации: бэкдор может «сам исчезнуть».
- Не проверить регион: Config в `us-east-1` не видит ресурсы `eu-west-1`.
- Забыть, что custom-правила — это код с ролью, потенциальная цель.

## Защита и детект

- Включать recorder для всех поддерживаемых ресурсов во всех регионах.
- Использовать conformance packs (CIS/AWS Foundational) и агрегатор в management-аккаунте.
- Ограничить `config:StopConfigurationRecorder`/`DeleteConfigurationRecorder` и алертить на них.
- Включить CloudTrail data events для критичных бакетов и S3 Object Lock для логов.
- Настроить remediation с осторожностью и мониторить её выполнение.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — recorder только для части ресурсов или только в одном регионе. Второй — отсутствие custom-правил для «ваших» сервисов. Третий — Config-роль с широкими правами. Четвёртый — отсутствие алертов на изменения Config. Пятый — бакет Config без Object Lock, который можно очистить. Все они создают слепые зоны, которые атакующий использует для OPSEC.

## Практическое задание

1. Включите recorder для всех ресурсов и добавьте правило `s3-bucket-public-read-prohibited`.
2. Сделайте бакет публичным и посмотрите, как правило помечает ресурс non-compliant.
3. Выключите recorder и проверьте, что изменения больше не записываются.
4. Настройте агрегатор из второго аккаунта и убедитесь, что данные видны.

## Что дальше / решение

Понимание Config/CloudTrail — фундамент OPSEC. Определите, какие ваши действия логируются, и выбирайте минимально шумные пути. Зафиксируйте в графе атаки «слепые зоны аудита». Если Config пишет всё и включены алерты — действуйте быстро и в рамках легитимных API, либо работайте через сервисы, не покрытые правилами.

## Разобранный пример 2: агрегатор и история ресурса

Агрегатор собирает данные Config из нескольких аккаунтов и регионов. Если он настроен не полностью, часть аккаунтов остаётся вне видимости — это слепая зона.

```bash
aws configservice describe-configuration-aggregators --query 'ConfigurationAggregators[].{Name:ConfigurationAggregatorName,Sources:AccountAggregationSources}'
# [{"Name":"org-aggregator","Sources":[{"AccountIds":["111122223333"],"AllRegions":false}]}]

# В какие регионы собирает (AllRegions:false -> только один)
aws configservice describe-configuration-aggregator-sources \
  --configuration-aggregator-name org-aggregator

# История конкретного ресурса: видно, кто и когда менял
aws configservice get-resource-config-history --resource-type AWS::EC2::SecurityGroup \
  --resource-name sg-0abc123 --query 'configurationItems[].[captureTime,configurationItemStatus]' --output text
# 2024-03-01T10:00:00Z  ResourceDiscovered
# 2024-03-02T11:30:00Z  ResourceUpdated
```

История ресурса — отличный инструмент и для защитника (форензика изменений), и для атакующего (понять, как админы меняли конфигурацию и что за этим следит). Если `AllRegions:false`, изменения в других регионах не попадут в агрегатор — там можно действовать тише.

## Config и OPSEC: как выбрать путь

Практический алгоритм: перед каждым действием спрашивайте, в какую категорию телеметрии оно попадает.

1. **Изменение конфигурации ресурса** (создание бакета, изменение SG) → почти наверняка попадёт в Config (если recorder включён) и CloudTrail. Шумно.
2. **Вызов management API** (GetSecretValue, AssumeRole, StartBuild) → CloudTrail mgmt events. Видно, но не в Config.
3. **Чтение данных** (GetObject, Scan) → только CloudTrail data events, если они включены. Часто невидимо.
4. **Внутренние вызовы сервиса** (Lambda вызывает DynamoDB) → data events по умолчанию выключены; видно хуже всего.

Отсюда стратегия: предпочитать действия, которые не меняют конфигурацию (чтение вместо создания), работать через уже существующие ресурсы и избегать вызовов `config:Put*`/`iam:*`, которые триггерят правила. Помните: Config часто настроен только на «известные» сервисы (S3, IAM, EBS), поэтому менее популярные сервисы остаются вне правил.

## Квиз

```quiz
- question: "Что записывает AWS Config?"
  options:
    - "Изменения конфигураций ресурсов (configuration items)"
    - "Все чтения S3-объектов"
    - "Пароли IAM"
    - "Трафик VPC"
  answer: 0
  explanation: "Config — про конфигурации, а не про чтение данных."
- question: "Какой API может ослепить Config?"
  options:
    - "stop-configuration-recorder"
    - "s3:GetObject"
    - "sts:GetCallerIdentity"
    - "ec2:DescribeInstances"
  answer: 0
  explanation: "Остановка recorder прекращает запись изменений."
- question: "Что покрывает conformance pack?"
  options:
    - "Набор правил и ремедиаций для соответствия (CIS/PCI)"
    - "Только S3"
    - "Только IAM"
    - "Только логи"
  answer: 0
  explanation: "Conformance pack группирует правила и автоматические исправления."
- question: "Почему Config не заменяет CloudTrail?"
  options:
    - "Config не пишет вызовы API чтения, а CloudTrail — management/data events"
    - "Config дороже"
    - "Config только для Azure"
    - "CloudTrail не логирует"
  answer: 0
  explanation: "Разные назначения: конфигурации против API-вызовов."
```

## Где пригодится

- **Red team:** оценка слепых зон и OPSEC.
- **Blue team:** настройка детекта и соответствия.
- **Пентест AWS:** понимание, что видит защита.
- **Сертификация:** AWS Security — Specialty.
