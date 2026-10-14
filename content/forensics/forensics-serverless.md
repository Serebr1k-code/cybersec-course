---
id: forensics-serverless
title: 'Serverless-форензика: следы функций без диска'
category: forensics
parent: forensics-cloud-runtime
difficulty: hard
order: 1
tags: [cloud, serverless, lambda, cloudwatch, cloudtrail, forensics]
prerequisites: [forensics-cloud-identity]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Cloud Security'
estimated_minutes: 50
summary: 'Как расследовать serverless-функции (Lambda/Functions/Cloud Functions), у которых нет диска: логи, конфигурация, роль исполнения, версии и события провайдера.'
lab:
  kind: shell
  title: 'Практика: Serverless-форензика'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

В облаке атакующий использовал **serverless-функцию**, чтобы не поднимать сервер. Функция
отработала за секунды и исчезла. Диска нет, процесса нет, памяти нет. Что вообще можно
расследовать?

## Наш пример: подозрительная функция

Находим функцию `process-upload` в AWS Lambda. Смотрим её конфигурацию:

```
$ aws lambda get-function-configuration --function-name process-upload
{
  "FunctionArn": "arn:aws:lambda:eu-west-1:123456789012:function:process-upload",
  "Runtime": "python3.11",
  "Role": "arn:aws:iam::123456789012:role/process-upload-role",
  "Timeout": 900,
  "Environment": { "Variables": { "BUCKET": "data-bucket" } },
  "LastModified": "2026-03-10T03:14:00.000+0000"
}
```

Уже здесь много улик: роль, таймаут 900 секунд (необычно много), переменные окружения,
время последнего изменения.

## Что такое serverless

**Serverless (функция как сервис)** — модель, где ты пишешь код, а провайдер сам его
запускает по событию. Функция живёт только на время выполнения (обычно до 15 минут),
потом среда уничтожается. Диска, который можно «снять», нет. Зато провайдер ведёт
**логи** и **события управления**.

## Шаг 1: логи выполнения

Каждый запуск пишет в лог-сервис (CloudWatch Logs):

```
$ aws logs filter-log-events --log-group-name /aws/lambda/process-upload \
    --filter-pattern "ERROR"
2026-03-10T03:14:05Z  task timed out after 900.00 seconds
2026-03-10T03:14:07Z  uploading to s3://exfil-bucket/...
```

Логи показывают **что функция делала**: обращалась к подозрительному бакету
`exfil-bucket`. Это ключевая улика.

## Шаг 2: роль исполнения

Функция работает под **IAM-ролью**. Её права показывают, **что функция могла**:

```
$ aws iam get-role-policy --role-name process-upload-role --policy-name inline
{ "Action": ["s3:PutObject", "s3:GetObject", "secretsmanager:GetSecretValue"], ... }
```

Право `GetSecretValue` + `PutObject` = потенциальная утечка секретов наружу.

## Шаг 3: события управления (CloudTrail)

CloudTrail фиксирует **кто и когда** менял функцию:

```
$ aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=process-upload
UpdateFunctionCode  user/alice  2026-03-10T03:10:00Z
```

Видно, что код функции обновили за 4 минуты до запуска — вероятно, это и был атакующий.

## Шаг 4: версии и слои

Lambda хранит **версии** кода. Можно сравнить старую и новую:

```
$ aws lambda get-function --function-name process-upload --qualifier 3
$ aws lambda get-function --function-name process-upload --qualifier 4
```

Также проверяются **слои** (layers) — общие библиотеки, куда могли внедрить код. Всё это
даёт версии артефактов для анализа.

## Что переживает «исчезновение» функции

Хотя среда уничтожается, остаются:

- **логи** выполнения (в лог-сервисе);
- **события управления** (CloudTrail);
- **конфигурация и версии** кода;
- **роль и её политики**;
- **следы в других сервисах** (S3, KMS, базы), к которым функция обращалась.

Именно эта «периферия» и есть объект расследования.

## Что мы теперь знаем

- У serverless нет диска — расследуют логи, конфигурацию и события.
- Логи выполнения показывают действия функции.
- Роль исполнения показывает её права.
- CloudTrail фиксирует, кто менял код.
- Версии и слои дают артефакты для анализа.

## Квиз

Проверь себя.

```quiz
- question: Что расследуют у serverless-функции, если диска нет?
  options:
    - 'ничего'
    - 'логи, конфигурацию и события управления'
    - 'только память'
    - 'SMART диска'
  answer: 1
  explanation: 'Диска нет, поэтому опираются на логи, конфигурацию и события провайдера.'
- question: Какой сервис фиксирует, кто менял код функции?
  options:
    - 'S3'
    - 'CloudTrail'
    - 'VPC Flow Logs'
    - 'CloudWatch'
  answer: 1
  explanation: 'CloudTrail хранит события управления (UpdateFunctionCode и т.п.).'
- question: Что показывает роль исполнения (execution role)?
  options:
    - 'пароль функции'
    - 'права, которые функция может использовать'
    - 'версию ОС'
    - 'IP-адрес'
  answer: 1
  explanation: 'Роль определяет доступ функции к сервисам облака.'
- question: Что переживает «исчезновение» функции?
  options:
    - 'ничего'
    - 'логи выполнения, события, конфигурация, версии'
    - 'только память'
    - 'только диск'
  answer: 1
  explanation: 'Улики живут на «периферии»: логи, события, конфигурация, версии.'
```

## Куда дальше

Мы разобрали самый эфемерный случай. Дальше — **контейнеры**: у них есть образ и слои, но
тоже нет долгой жизни. А пока запомни: у serverless улики живут на «периферии» — в логах
и событиях.

## Где пригодится

- **Cloud Security** — расследование инцидентов в serverless.
- **DFIR / Incident Response** — восстановление действий функции.
- **CTF Forensics** — задачи с логами облачных функций.
