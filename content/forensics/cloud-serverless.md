---
id: cloud-serverless
title: 'Serverless-форензика: функции, логи и роли'
category: forensics
parent: forensics-cloud-compute
difficulty: hard
order: 1
tags: [forensics, cloud, serverless, lambda, faas, logs]
prerequisites: [forensics-cloud-multi]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как расследовать serverless-инциденты: логи функций, роли/политики, слои и что остаётся после выполнения.'
lab:
  kind: shell
  title: 'Практика: Serverless-форензика'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Взломали Lambda-функцию. Но функции **эфемерны**: контейнер живёт секунды и исчезает.
Где искать следы? Разберём.

## Наш пример: Lambda-функция

## Шаг 1: что остаётся

Serverless-функция не хранит состояние. Остаются:

- **логи** (CloudWatch/Cloud Logging);
- **метрики**;
- **конфигурация** (роль, переменные окружения);
- **API-логи** (CloudTrail/Activity Log).

## Шаг 2: логи функций

```
$ aws logs filter-log-events --log-group-name /aws/lambda/fn --start-time 1705000000000
2026-01-14T03:20:00Z  START RequestId: ...
2026-01-14T03:20:01Z  downloading http://203.0.113.5/x
```

Логи содержат stdout/stderr функции — там могут быть URL, ошибки, отладка.

## Шаг 3: роль и права

Функция работает под **IAM-ролью**. Компромисс функции = компромисс её прав:

```
$ aws lambda get-function-configuration --function-name fn --query Role
arn:aws:iam::123:role/lambda-admin
```

Если роль широкая (админ) — атакующий получает её права.

## Шаг 4: переменные окружения и слои

- **env vars** могут содержать секреты (утечка);
- **layers** — общие библиотеки (могут быть отравлены);
- **event-триггеры** — откуда приходят данные (API Gateway, S3).

## Шаг 5: что искать

- необычные внешние соединения (C2/эксфильтрация);
- изменение конфигурации (кто вызвал UpdateFunctionCode);
- кражу временных креденшелов (`AWS_...` в env);
- использование функции как прокси.

## Что мы теперь знаем

- Serverless эфемерен; следы — логи, метрики, конфиг.
- Логи содержат stdout функции.
- Роль определяет права (компромисс = её права).
- Env vars и слои — источники утечки/отравления.
- Смотрим CloudTrail на изменения кода.

## Если не сработало

- Логов нет? Включи логирование (но уже после).
- Нужен код? Смотри версии функции.
- Нужны права? Читай IAM-политику роли.

## Квиз

Проверь себя.

```quiz
- question: Что остаётся после выполнения Lambda-функции?
  options:
    - 'диск'
    - 'логи, метрики, конфигурация'
    - 'память'
    - 'ничего'
  answer: 1
  explanation: 'Функция эфемерна; следы — в логах и конфиге.'
- question: Что определяет права функции?
  options:
    - 'её код'
    - 'IAM-роль'
    - 'сеть'
    - 'обои'
  answer: 1
  explanation: 'Функция действует под IAM-ролью.'
- question: Чем опасны переменные окружения функции?
  options:
    - 'ничем'
    - 'могут содержать секреты'
    - 'ускоряют'
    - 'шифруют'
  answer: 1
  explanation: 'Env vars часто хранят токены/ключи.'
- question: Что искать в CloudTrail по функции?
  options:
    - 'обои'
    - 'изменения кода/конфигурации (UpdateFunctionCode)'
    - 'музыку'
    - 'шрифты'
  answer: 1
  explanation: 'API-логи показывают, кто менял функцию.'
```
