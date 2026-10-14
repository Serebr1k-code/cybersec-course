---
id: cloud-aws-sagemaker
title: 'AWS SageMaker: ноутбуки, endpoints и захват роли'
category: cloud
parent: cloud-aws-ai-edge
difficulty: hard
order: 3
tags: [cloud, aws, sagemaker, notebooks, execution-role, endpoints, lifecycle]
prerequisites: [cloud-aws-bedrock]
useful_for:
  - 'Пентест AI-платформ AWS'
  - 'Захват execution role'
  - 'CTF cloud'
estimated_minutes: 45
summary: 'SageMaker: notebook instances и Studio, execution role и её права, lifecycle-конфиги как исполнение кода, training jobs, endpoints и model registry, захват роли. Сквозной пример — ноутбук с execution role, читающей S3 и Secrets Manager.'
lab:
  kind: shell
  title: 'Практика: execution role SageMaker'
  toolset: [core, python]
  workdir: /home/student/sagemaker
  files: [task.md, role.txt, notes.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Изучи роль ноутбука: `cat role.txt` — какие политики привязаны?'
    - 'Определи, к каким данным имеет доступ execution role.'
    - 'Флаг — в notes.md: найди строку `nto` и запиши её в found.txt.'
---

## Вопрос, с которого всё начинается

Ты получаешь доступ к SageMaker-ноутбуку или возможность создать training job. Вопрос: чья execution role у ноутбука, что она позволяет, можно ли через lifecycle-конфиг исполнить код при старте инстанса, и как из «доступ к ноутбуку» получить креды и данные. Начнём с того, что SageMaker исполняет код под execution role, и её права — это реальный уровень доступа.

## Что такое SageMaker

SageMaker — платформа ML в AWS: notebook instances (JupyterLab), SageMaker Studio (IDE), training jobs, processing jobs, endpoints для инференса, Model Registry и pipelines. Всё исполняется под execution role — IAM-ролью, которую ты задаёшь при создании ресурса. Ноутбук имеет эту роль, training job тоже. Плюс есть lifecycle-конфиги — скрипты, которые выполняются при создании/старте инстанса. Это делает SageMaker одновременно вычислительным ресурсом и точкой доступа к данным через роль.

## Сквозной пример: execution role ноутбука

Смотрим роль ноутбука:
```
$ aws sagemaker describe-notebook-instance --notebook-instance-name acme-nb
{ "RoleArn": "arn:aws:iam::111111111111:role/sm-notebook-role" }
$ aws iam list-attached-role-policies --role-name sm-notebook-role
{ "AttachedPolicies": [ { "PolicyName": "AmazonSageMakerFullAccess" } ] }
```
Ноутбук ходит под `sm-notebook-role`, у которого `AmazonSageMakerFullAccess` — широкая managed-политика. Дальше смотрим, есть ли у роли доступ к S3, Secrets Manager, ECR. Часто есть, потому что «ноутбуку нужны данные и образы».

## Execution role и её широта

Execution role определяет, что может делать код. Часто ей выдают широкие managed-политики (SageMakerFullAccess) плюс доступ к S3 и Secrets Manager. Это значит, что любой код под этой ролью читает данные и секреты. Ключевой вопрос: кто может запускать код под ролью. Если ты можешь создать notebook instance, training job или pipeline с произвольной ролью, ты получаешь её доступ. Проверяй, какие роли разрешено передавать SageMaker (`iam:PassRole`).

## Lifecycle-конфиги

Lifecycle-конфиг — это shell-скрипт, который SageMaker выполняет при создании или старте notebook instance (on-start) или при создании Studio. Если атакующий может изменить lifecycle-конфиг, его код выполнится при следующем старте инстанса под execution role — это отложенное исполнение кода с правами роли. Плюс on-start выполняется от root внутри инстанса, что даёт доступ к metadata и, при определённых настройках, к сети. Проверяй lifecycle-конфиги на возможность изменения.

## Training jobs и pipelines

Training job запускает контейнер с твоим кодом под execution role. Если ты можешь определить образ и entrypoint, ты исполняешь свой код под ролью. Pipelines связывают шаги и роли. Это тот же принцип, что «code execution via configuration»: изменение конфигурации обучения превращается в исполнение кода с правами роли. Проверяй, кто может создавать jobs и менять определения pipelines, и какие роли можно использовать.

## Endpoints и Model Registry

Endpoint отдаёт инференс модели по HTTP. Если endpoint открыт без аутентификации (нет IAM-авторизации), его можно вызывать и использовать модель бесплатно. Model Registry хранит артефакты моделей (в S3), и доступ к реестру — это доступ к моделям и их данным. Плюс контейнер модели может иметь доступ к данным через роль endpoint. Проверяй авторизацию endpoint и права на артефакты.

## Захват роли

Основной вектор — получить доступ к роли через код. Способы: запустить notebook instance/training job с ролью (если есть PassRole), изменить lifecycle-конфиг, обновить endpoint с другим образом. Каждый из них исполняет код под ролью, а из инстанса роль можно украсть через metadata (IMDS) — если инстанс в сети и версия IMDS не требует токена. Проверяй IMDS (IMDSv2) и права на PassRole.

## Типовые мисконфиги

| Мисконфиг | Последствие | Как искать |
|---|---|---|
| Широкая execution role | доступ к данным/секретам | IAM роли |
| PassRole на широкие роли | запуск кода под ролью | iam:PassRole |
| Изменяемый lifecycle-конфиг | исполнение при старте | конфиги |
| Endpoint без авторизации | abuse инференса | auth endpoint |
| IMDSv1 на инстансе | кража токена роли | metadata options |
| Нет логирования | слепые зоны | logging |

## Полный прогон: от ноутбука к данным

Шаги. Первый: определить execution role. Второй: перечислить её политики. Третий: проверить доступ к данным и секретам. Четвёртый: оценить, можно ли запустить код под ролью (PassRole, jobs, lifecycle). Пятый: исполнить код и вытащить данные/секреты. Шестой: украсть токен роли через metadata. Седьмой: закрепиться и учесть CloudTrail.

## Инструменты и команды

Полезны: `aws sagemaker list-notebook-instances`, `describe-notebook-instance`, `list-training-jobs`, `describe-endpoint`, `aws iam get-role`, metadata-сервер для токена роли, `aws sts get-caller-identity`. Для поиска ролей — `list-roles`, `list-attached-role-policies`. Для lifecycle — `describe-notebook-instance-lifecycle-config`.

## OPSEC и детект

SageMaker пишет CloudTrail: создание инстансов, jobs, изменения lifecycle. Новый notebook instance или job заметен. Кража токена через metadata не логируется как отдельное событие, но использование роли из неожиданного места видно. Тихий сценарий — использовать существующий ноутбук и не создавать новых ресурсов.

## Частые вопросы

Нужен ли PassRole? Для запуска job с ролью — да. Даёт ли ноутбук доступ к сети? Часто да, если в VPC с NAT. Помогает ли IMDSv2? Да, он требует токен и усложняет кражу. Даёт ли endpoint данные? Через роль контейнера. Оставляет ли след? Да, CloudTrail.

## Что не сработает

Узкая роль не даст читать данные. IMDSv2 с hop limit 1 не даст украсть токен из контейнера. Endpoint с IAM-авторизацией не даст abuse. И без PassRole не запустишь job под чужой ролью.

## Разбор кейса: ноутбук с широкой ролью

История из практики. У SageMaker-ноутбука была execution role с SageMakerFullAccess и S3-доступом на все бакеты. Атакующий получил доступ к ноутбуку, взял токен роли и прочитал бакет с бэкапами, включая базу данных. Урок: execution role ноутбука — это роль с доступом к данным; «доступ к ноутбуку» равен доступу к роли.

## Что мы теперь знаем

1. SageMaker исполняет код под execution role; её права — твой доступ.
2. Lifecycle-конфиги и training jobs — способы исполнить код под ролью.
3. PassRole определяет, какие роли можно назначить ресурсам.
4. Endpoints и Model Registry — отдельная поверхность (abuse, данные).
5. Токен роли крадётся через metadata; IMDSv2 усложняет это.

## Notebook instance и Studio

SageMaker имеет два интерфейса: классические notebook instances и Studio (домены с пользовательскими профилями и приложениями). У обоих есть execution role, но в Studio роль может быть на уровне домена, а пользовательские профили — свои. Компромисс профиля даёт доступ к роли домена. Плюс Studio-приложения (JupyterLab, Code Editor) работают в сети и имеют доступ к metadata. Проверяй, какие домены и профили есть, какие роли им назначены и открыт ли доступ к интерфейсу без IAM-аутентификации.

## Контейнеры и образы

Training и inference используют контейнеры из ECR. Если ты можешь подменить образ (или указать свой), код выполнится под execution role. Это supply chain-вектор внутри SageMaker: образ из ECR, к которому у тебя есть push, или публичный образ с изменённым entrypoint. Проверяй, какие образы используются, кто может их менять и есть ли проверка подписи. Плюс inference-контейнер наследует права роли endpoint и часто имеет доступ к S3 с моделями.

## Итог по SageMaker

SageMaker — это вычислительный сервис, который исполняет код под execution role. Твой путь: определить роль, понять её права и найти способ исполнить код под ней (ноутбук, job, lifecycle, образ). Затем украсть токен роли через metadata и закрепиться. Ключевые ограничители — IMDSv2 и строгий PassRole; если они настроены правильно, путь усложняется, но роль всё равно остаётся целью.

## Практический чек-лист по SageMaker

Сначала найди ресурсы: notebook instances, Studio-домены, training jobs, endpoints. Для каждого определи execution role и её политики. Затем проверь PassRole: какие роли разрешено передавать SageMaker. Посмотри lifecycle-конфиги: можно ли их изменить. Оцени образы: кто может их менять и есть ли проверка подписи. Дальше найди способ исполнить код под ролью и украсть токен через metadata. И проверь endpoints на авторизацию: открытый endpoint даёт бесплатный инференс. Такой проход покрывает все способы захвата роли через SageMaker.

## Чего ожидать на практике

Роль ноутбука почти никогда не ограничена только SageMaker: рядом обычно лежат S3 и Secrets Manager, потому что «модели нужны данные и ключи». Именно эти смежные права и есть цель. Второй момент — сеть: если ноутбук в VPC с NAT, он видит внутренние сервисы и metadata. И третий — IMDS: если включён IMDSv2 с hop limit 1, кражу токена усложняют, но роль всё равно остаётся целью через PassRole и lifecycle.

## Квиз

Проверь себя.

```quiz
- question: "Чьими правами исполняется код в SageMaker-ноутбуке?"
  options:
    - "Execution role ноутбука"
    - "Роль браузера"
    - "Роль S3"
    - "Без роли"
  answer: 0
  explanation: "Ноутбук ходит под execution role, и её права определяют доступ."
- question: "Что такое lifecycle-конфиг?"
  options:
    - "Скрипт, выполняемый при старте инстанса"
    - "Пароль"
    - "Роль IAM"
    - "Сертификат"
  answer: 0
  explanation: "Lifecycle-конфиг исполняется под ролью при создании/старте инстанса."
- question: "Что нужно, чтобы запустить job под ролью?"
  options:
    - "iam:PassRole на эту роль"
    - "Только пароль"
    - "Только VPC"
    - "Ничего"
  answer: 0
  explanation: "PassRole разрешает передать роль сервису, который исполнит код."
- question: "Как украсть токен роли из инстанса?"
  options:
    - "Через metadata (IMDS), если версия позволяет"
    - "Через DNS"
    - "Через сертификат"
    - "Через логи"
  answer: 0
  explanation: "IMDS выдаёт токен роли; IMDSv2 усложняет кражу."
```

## Куда дальше

Дальше — Cognito deep: identity и user pools, где ошибка маппинга отдаёт IAM-роль. А пока главное: в SageMaker execution role — это твой реальный доступ, а ноутбук — способ его получить.

## Где пригодится

- Пентест AI-платформ AWS.
- Захват ролей через вычислительные сервисы.
- CTF-задачи категории cloud.
