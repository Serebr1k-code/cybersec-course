---
id: cloud-aws-deep
title: "Модуль: AWS глубоко"
category: cloud
parent: cloud-provider-deep
difficulty: hard
order: 1
tags: [cloud, aws, cognito, ssm, ecs, vpc, module]
prerequisites: [cloud-provider-deep, cloud-iam-basics]
useful_for:
  - "Пентест AWS-аккаунтов за пределами S3 и EC2"
  - "Поиск путей эскалации через сервисы"
  - "Подготовка к AWS Security Specialty"
estimated_minutes: 18
summary: "Подмодуль AWS: Cognito, SSM, ECS/Fargate и VPC. Сервисы, которые дают креды, RCE и сетевой доступ, но редко проверяются."
---

Этот подмодуль — часть этапа «Модуль: провайдеры глубоко». Он собирает четыре урока по AWS-сервисам, которые в пентесте встречаются часто, но остаются в тени «классических» S3 и metadata. Проходите уроки по порядку.

## Что покрывает подмодуль

1. **Cognito** (`cloud-aws-cognito`) — user pool, identity pool и кража временных кредов через публичные identity pools.
2. **SSM** (`cloud-aws-ssm`) — Run Command как RCE на инстансах, Parameter Store и Session Manager.
3. **ECS и Fargate** (`cloud-aws-ecs`) — task role, определения задач и `execute-command`.
4. **AWS VPC** (`cloud-aws-vpc`) — security groups, VPC endpoints и сетевая изоляция.

## Почему такой порядок

Cognito даёт входной билет: временные креды из публичного identity pool — самый частый способ получить первый `AWS_ACCESS_KEY_ID`. С этими кредами открываются SSM (RCE на парке EC2), затем ECS/Fargate (RCE внутри контейнерных задач). VPC идёт последним: он объясняет, почему часть сервисов недоступна и как это обходить.

## Как проходить

- Каждый урок заканчивается разобранным примером с реальными командами `aws`. Выполняйте их на своём тестовом аккаунте.
- Держите включённым CloudTrail, чтобы видеть, какие API-вызовы вы оставляете, — это заодно тренировка OPSEC.
- Не пропускайте раздел «Защита и детект»: он объясняет, что именно выдаёт атаку.

## Чему вы научитесь

- Получать первые AWS-креды из Cognito без аутентификации.
- Превращать `ssm:SendCommand` в выполнение кода на EC2.
- Захватывать task role в ECS/Fargate.
- Читать VPC-конфигурацию и находить доступные из интернета сервисы.

## Квиз

```quiz
- question: "Какой сервис AWS чаще всего даёт первые временные креды без входа?"
  options:
    - "Cognito identity pool с неаутентифицированным доступом"
    - "Route 53"
    - "CloudFront"
    - "Trusted Advisor"
  answer: 0
  explanation: "Identity pool, разрешающий guest-доступ, выдаёт временные креды по публичному identity ID."
- question: "Что превращает ssm:SendCommand в RCE?"
  options:
    - "Возможность выполнить команду на инстансе с привязанным SSM-агентом"
    - "Только чтение параметров"
    - "Создание бакета"
    - "Просмотр метрик"
  answer: 0
  explanation: "SSM-агент на инстансе исполнит присланную команду от имени root/системы."
- question: "Зачем в подмодуле разбирается VPC?"
  options:
    - "Чтобы понять, какие сервисы доступны извне, а какие изолированы"
    - "Чтобы настроить биллинг"
    - "Чтобы сменить регион"
    - "Чтобы удалить аккаунт"
  answer: 0
  explanation: "Сетевая конфигурация определяет достижимость сервисов и пути lateral movement."
```

## Где пригодится

- **Пентест AWS:** поиск входных точек и эскалации через сервисы.
- **Bug bounty:** облачные программы с Cognito и SSM в scope.
- **Red team:** получение RCE на парке EC2/ECS.
- **Сертификация:** AWS Certified Security — Specialty.
