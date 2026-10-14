---
id: cloud-aws-ai-edge
title: 'Модуль: AWS AI и edge-защита — WAF/Shield, Bedrock, SageMaker, Cognito'
category: cloud
parent: cloud-aws-deep
difficulty: hard
order: 6
tags: [cloud, aws, waf, shield, bedrock, sagemaker, cognito, module]
prerequisites: [cloud-aws-services-deep]
useful_for:
  - 'Пентест AWS'
  - 'Обход WAF и захват AI-платформ'
  - 'CTF cloud'
estimated_minutes: 18
summary: 'Подмодуль о сервисах AWS на границе и в AI-слое: WAF/Shield (обход правил и слепые зоны), Bedrock (доступ к моделям и prompt injection), SageMaker (ноутбуки, endpoints и захват роли) и Cognito deep (identity/identity pool, маппинг ролей и кража токенов). Общий мотив: граница и AI-слой часто дают более короткий путь к данным, чем «основная» инфраструктура.'
---

Ты уже разобрал VPC, SSM, ECS, CloudFront, ALB, EventBridge, Step Functions и IoT Core. Этот подмодуль закрывает ещё два направления. Первое — edge-защита: WAF и Shield стоят перед приложением, и их обход — отдельная техника. Второе — AI-слой: Bedrock и SageMaker дают доступ к моделям и данным под ролями, которые часто шире, чем кажется. И третье — Cognito, где путаница между user pool и identity pool превращается в выдачу IAM-ролей.

## Что покрывает подмодуль

1. **WAF & Shield** (`cloud-aws-waf-shield`) — web ACL, правила и managed rule groups, rate-based, логирование и обход.
2. **Bedrock** (`cloud-aws-bedrock`) — model access, guardrails, agents и knowledge bases, prompt injection.
3. **SageMaker** (`cloud-aws-sagemaker`) — ноутбуки, endpoints, execution role, lifecycle-конфиги и эскалация.
4. **Cognito deep** (`cloud-aws-cognito-deep`) — user/identity pools, IAM-маппинг, квота и кража токенов.

## Почему такой порядок

Идём от границы (WAF) к моделям (Bedrock) и вычислениям (SageMaker), затем к identity (Cognito). WAF защищает вход; Bedrock открывает модели и данные, которые они видят; SageMaker исполняет код под ролью; Cognito выдаёт IAM-роли конечным пользователям. Последний пункт особенно важен: ошибка в Cognito отдаёт роль AWS любому, кто может зарегистрироваться.

## Как проходить подмодуль

Держи один вопрос: «какой ролью или ключом открывается эта поверхность?». У WAF — обход правила; у Bedrock — ключ/роль с доступом к моделям; у SageMaker — execution role ноутбука или endpoint; у Cognito — маппинг identity pool на роль. В каждом случае путь атаки — не «сломать сервис», а найти, чьими правами он ходит и что эти права позволяют.

## Квиз

Проверь себя.

```quiz
- question: "Что объединяет сервисы этого подмодуля?"
  options:
    - "Каждый открывает данные через ключ или роль"
    - "Они бесплатны"
    - "У них нет IAM"
    - "Они не логируются"
  answer: 0
  explanation: "Везде доступ определяется ролью или ключом, и его широта — суть атаки."
- question: "Чем Cognito может быть опасен?"
  options:
    - "Ошибка маппинга отдаёт IAM-роль пользователю"
    - "Он хранит DNS"
    - "Он только читает"
    - "Он заменяет VPC"
  answer: 0
  explanation: "Identity pool сопоставляет пользователя с IAM-ролью; ошибка даёт роль кому угодно."
- question: "Почему Bedrock/SageMaker интересны атакующему?"
  options:
    - "Они дают доступ к моделям и данным под ролями"
    - "Они не имеют сети"
    - "Они не хранят данные"
    - "Они только для чтения"
  answer: 0
  explanation: "AI-платформы работают под ролями с доступом к данным и дорогим ресурсам."
- question: "Зачем обходить WAF?"
  options:
    - "Он стоит между тобой и приложением"
    - "Он хранит ключи"
    - "Он заменяет IAM"
    - "Он ускоряет запросы"
  answer: 0
  explanation: "WAF — граница на пути трафика, и её обход открывает доступ к приложению."
```

## Куда дальше

Дальше — WAF & Shield: граница, которую нужно понять, прежде чем обходить. А пока главное: у каждого сервиса AWS есть роль или ключ, и его широта определяет доступ.

## Где пригодится

- Пентест AWS-организаций.
- Обход WAF и захват AI-платформ.
- CTF-задачи категории cloud.
