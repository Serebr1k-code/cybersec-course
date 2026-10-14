---
id: cloud-aws-edge
title: "Модуль: Edge и балансировка"
category: cloud
parent: cloud-aws-services-deep
difficulty: medium
order: 1
tags: [cloud, module, roadmap]
prerequisites: [cloud-aws-services-deep]
useful_for:
- Аудит AWS.
- Пентест облачных edge.
- Red team.
estimated_minutes: 10
summary: "Elb/alb/nlb, cloudfront и api gateway deep"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Edge и балансировка»: ELB/ALB/NLB, CloudFront и API Gateway deep.

- **cloud-aws-alb-elb** — AWS ELB/ALB/NLB: listener rules, request smuggling и health-checks.
- **cloud-aws-cloudfront** — AWS CloudFront: OAI/OAC, origin-экспозиция и подписанные URL.
- **cloud-aws-api-gateway-deep** — API Gateway deep: authorizers, usage-планы и Lambda-интеграции.

## Почему такой порядок

Edge-сервисы стоят на входе, поэтому их конфигурация определяет всю поверхность атаки.

## Что вы сможете после этапа

- Искать smuggling и обход origin.
- Разбирать authorizers API Gateway.

## Квиз

Проверь себя.

```quiz
- question: Чем опасен request smuggling на ALB?
  options:
    - "Расхождением парсинга и обходом контролей"
    - "Ускорением доставки"
    - "Шифрованием"
    - "Логированием"
  answer: 0
  explanation: Расхождение парсеров позволяет обойти защиту.
- question: Что защищает CloudFront OAC?
  options:
    - "Доступ к S3-origin"
    - "Пароли"
    - "Ключи TLS"
    - "Логи"
  answer: 0
  explanation: OAC ограничивает доступ к origin.
- question: Что такое authorizer в API Gateway?
  options:
    - "Компонент проверки авторизации запроса"
    - "Формат файла"
    - "Тип балансировщика"
    - "Схема БД"
  answer: 0
  explanation: Authorizer проверяет токен/подпись до Lambda.
```

## Где пригодится

- Аудит AWS.
- Пентест облачных edge.
- Red team.
