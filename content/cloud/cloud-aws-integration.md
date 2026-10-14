---
id: cloud-aws-integration
title: "Модуль: Интеграция и IoT"
category: cloud
parent: cloud-aws-services-deep
difficulty: medium
order: 2
tags: [cloud, module, roadmap]
prerequisites: [cloud-aws-services-deep]
useful_for:
- Аудит AWS.
- Пентест IoT.
- Red team.
estimated_minutes: 10
summary: "Step functions, eventbridge и iot core"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Интеграция и IoT»: Step Functions, EventBridge и IoT Core.

- **cloud-aws-step-functions** — Step Functions: определения, PassRole и захват через workflow.
- **cloud-aws-eventbridge** — EventBridge: правила, cross-account шины и инъекция событий.
- **cloud-aws-iot-core** — AWS IoT Core: policies, thing-сертификаты и захват через правила.

## Почему такой порядок

Интеграционные сервисы связывают системы и часто несут избыточные права.

## Что вы сможете после этапа

- Искать злоупотребление PassRole.
- Разбирать IoT-политики и правила.

## Квиз

Проверь себя.

```quiz
- question: Чем опасен PassRole в Step Functions?
  options:
    - "Позволяет выдать роль сервису и повысить права"
    - "Шифрует данные"
    - "Ускоряет workflow"
    - "Чистит логи"
  answer: 0
  explanation: PassRole позволяет действовать от имени более привилегированной роли.
- question: Что такое EventBridge rule?
  options:
    - "Правило маршрутизации событий к цели"
    - "Тип инстанса"
    - "Формат файла"
    - "Схема БД"
  answer: 0
  explanation: Правило сопоставляет события и вызывает цель.
- question: Что задаёт IoT policy?
  options:
    - "Какие топики/операции доступны сертификату"
    - "Размер диска"
    - "Регион"
    - "Логи"
  answer: 0
  explanation: IoT-политика ограничивает действия thing-сертификата.
```

## Где пригодится

- Аудит AWS.
- Пентест IoT.
- Red team.
