---
id: cloud-aws-access-deep
title: "Модуль: AWS — доступ, наблюдаемость и снапшоты"
category: cloud
parent: cloud-foundations-security
difficulty: hard
order: 4
tags: [cloud, aws, sso, identity-center, config, cloudtrail, ebs, snapshot, module]
prerequisites: [cloud-aws-deep, cloud-iam-basics]
useful_for:
  - "Пентест корпоративных AWS-организаций"
  - "Анализ следов и слепых зон аудита"
  - "Извлечение секретов из EBS-снапшотов"
estimated_minutes: 18
summary: "Подмодуль AWS про идентичность и наблюдаемость: AWS IAM Identity Center (SSO), AWS Config, CloudTrail-пробелы и EBS-снапшоты как источник данных и секретов."
---

Этот подмодуль — часть ветки «Основы облака → идентичность, секреты и логи». Он собирает три урока о том, как атакующий входит в корпоративный AWS (SSO/Identity Center), что о нём могут записать сервисы наблюдаемости (Config, CloudTrail) и как из «просто снапшота диска» вытащить секреты целого инстанса.

## Что покрывает подмодуль

1. **AWS SSO / IAM Identity Center** (`cloud-aws-sso`) — роль-ассайнменты, permission sets, temporary credentials и злоупотребление доверием к внешнему IdP.
2. **AWS Config и наблюдаемость** (`cloud-aws-config`) — правила, conformance packs, агрегаторы и слепые зоны аудита.
3. **EBS-снапшоты** (`cloud-aws-ebs`) — расшаривание снапшотов, монтирование тома и поиск ключей/секретов на диске.

## Почему такой порядок

SSO — это то, как современная компания выдаёт доступ: почти все инженеры входят не ключами, а через Identity Center. Понимание permission sets объясняет, какие роли доступны после компрометации пользователя. Config и CloudTrail идут вторыми: они показывают, что атакующий оставляет и где детект слеп. EBS-снапшоты замыкают модуль — это классический «тихий» способ добраться до данных и ключей, если есть права на снапшот, но нет доступа к хосту.

## Как проходить

- Разбирайте примеры с `aws sso-admin`, `aws configservice`, `aws ec2` на тестовом аккаунте.
- Отмечайте, какой API-вызов пишется в CloudTrail, а какой — нет: это основа OPSEC.
- В уроке про EBS обязательно пройдите шаг монтирования тома и поиска `authorized_keys`, `.env`, `.aws/credentials`.

## Чему вы научитесь

- Читать permission sets и находить роли, доступные через SSO.
- Оценивать слепые зоны Config/CloudTrail и обходить шумные вызовы.
- Расшаривать и монтировать EBS-снапшот, извлекая секреты и ключи SSH.

## Квиз

```quiz
- question: "Чем AWS IAM Identity Center отличается от обычных IAM-пользователей?"
  options:
    - "Выдаёт временные креды через permission sets и внешний IdP"
    - "Хранит постоянные access keys"
    - "Заменяет KMS"
    - "Работает только в GovCloud"
  answer: 0
  explanation: "Identity Center выдаёт краткосрочные креды для ролей (permission sets), а не долгоживущие ключи."
- question: "Что даёт расшаренный EBS-снапшот?"
  options:
    - "Побайтовую копию диска, которую можно смонтировать и обыскать"
    - "Права администратора"
    - "Доступ к CloudTrail"
    - "Мгновенный RCE"
  answer: 0
  explanation: "Снапшот — это снимок тома; его монтируют в свой инстанс и ищут секреты/ключи."
- question: "Почему CloudTrail не всегда ловит атакующего?"
  options:
    - "Data events для S3/Lambda могут быть отключены, а трейл — региональным"
    - "CloudTrail не пишет API-вызовы"
    - "CloudTrail шифруется"
    - "CloudTrail удаляет IAM"
  answer: 0
  explanation: "По умолчанию пишутся management events; data events и мульти-регион требуют явной настройки."
```

## Где пригодится

- **Пентест AWS:** вход в организацию через SSO и тихий сбор данных из снапшотов.
- **Red team:** понимание слепых зон аудита для OPSEC.
- **Форензика:** извлечение артефактов из EBS-снапшотов после инцидента.
- **Сертификация:** AWS Security — Specialty.
