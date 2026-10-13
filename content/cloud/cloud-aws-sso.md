---
id: cloud-aws-sso
title: "AWS IAM Identity Center: permission sets, роли и вход через SSO"
category: cloud
parent: cloud-aws-access-deep
difficulty: hard
order: 3
tags: [cloud, aws, sso, identity-center, permission-set, saml, scim, federation]
prerequisites: [cloud-aws-access-deep, cloud-iam-basics]
useful_for:
  - "Пентест корпоративных AWS-организаций"
  - "Анализ permission sets и role assignments"
  - "Атаки на федерацию с внешним IdP"
estimated_minutes: 45
summary: "IAM Identity Center (SSO): permission sets, assignments, SCIM-провижининг и федерация с внешним IdP. Как получить роли аккаунтов и где искать ошибки доверия."
lab:
  kind: shell
  title: "Практика: AWS IAM Identity Center (SSO)"
  toolset: [core, aws]
  workdir: /home/student/sso
  files: [task.md, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Посмотри permission sets: `aws sso-admin list-permission-sets --instance-arn ...`."
    - "Один permission set содержит административную политику."
    - "Найди флаг: `aws sso-admin describe-permission-set ... > ps.json`, затем `grep nto ps.json > found.txt`."

---
## Задача

Крупные организации входят в AWS не через IAM-пользователей с ключами, а через **SSO**. В AWS это **IAM Identity Center** (раньше — AWS SSO). Задача: понять, как устроен вход, что такое **permission sets** и где ошибки доверия дают широкие роли. Разберём на конкретной организации.

## Данные: как устроен вход через SSO

**IAM Identity Center** — центральная точка входа: пользователь логинится один раз, получает список аккаунтов и ролей, выбирает нужную. Смотрим, что нам доступно:

```
$ aws sso list-accounts --access-token $TOKEN \
    --query 'accountList[].{id:accountId,name:accountName}'
[ { "id": "123456789012", "name": "prod" },
  { "id": "210987654321", "name": "dev" } ]
```

Два аккаунта. Для каждого — набор ролей, которые нам разрешены:

```
$ aws sso list-account-roles --account-id 123456789012 --access-token $TOKEN \
    --query 'roleList[].roleName'
[ "ReadOnlyAccess", "PowerUserAccess", "AdministratorAccess" ]
```

Три роли, включая `AdministratorAccess`. Если она назначена нашему пользователю — мы админы аккаунта `prod`.

## Пробуем в лоб: получаем креды роли

SSO выдаёт **временные** креды под выбранную роль:

```
$ aws sso get-role-credentials --account-id 123456789012 --role-name AdministratorAccess \
    --access-token $TOKEN --query 'roleCredentials.{k:accessKeyId,s:secretAccessKey}'
{ "k": "ASIA...", "s": "..." }
```

Экспортируем их и проверяем:

```
$ export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
$ aws sts get-caller-identity
{ "Arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_.../ivan" }
```

Мы — `AdministratorAccess` в проде. Но это **легитимно**: роль назначена нашему пользователю. Интереснее — ошибки конфигурации.

## Приём: permission sets и ошибки назначений

**Permission set** — это шаблон ролей и политик, который Identity Center выдаёт в аккаунты. Смотрим, какие есть и что в них:

```
$ aws sso-admin list-permission-sets --instance-arn $INSTANCE_ARN \
    --query 'PermissionSets' --output text
ps-0abc... ps-0def...
$ aws sso-admin list-managed-policies-in-permission-set --instance-arn $INSTANCE_ARN \
    --permission-set-arn arn:...:permissionSet/ps-0abc... --query 'AttachedManagedPolicies[].Name'
[ "PowerUserAccess" ]
```

Типичные слабости:

- **Слишком широкий permission set**, назначенный на всю группу. Например, `PowerUserAccess` на группу `all-developers` — любой разработчик почти админ.
- **`AdministratorAccess` на широкую группу** — любой участник группы админ.
- **Assignments** (привязки) — кому и в каком аккаунте какой permission set выдан:

```
$ aws sso-admin list-account-assignments --instance-arn $INSTANCE_ARN \
    --account-id 123456789012 --permission-set-arn arn:...:ps-0abc... \
    --query 'AccountAssignments[].{type:PrincipalType,id:PrincipalId}'
[ { "type": "GROUP", "id": "0a1b2c..." } ]
```

Если permission set с широкими правами назначен на большую группу — это и есть дыра.

## Полный прогон: от группы к админским кредам

1. **Разведка.** `list-accounts` → аккаунты; `list-account-roles` → роли.
2. **Поиск широких permission sets.** `list-permission-sets` + `list-managed-policies-in-permission-set`.
3. **Assignments.** Кому назначен широкий set (группам? всем?).
4. **Вход в группу.** Если мы можем попасть в группу (через IdP, SCIM, инвайт) — получаем её права.
5. **Креды.** `get-role-credentials` → админские креды.
6. **Эскалация.** Дальше — как обычно (см. `cloud-privesc-iam`).

## SCIM и внешний IdP

Identity Center почти всегда связан с **внешним IdP** (Okta, Entra ID, Google) через **SAML** (вход) и **SCIM** (провижининг пользователей/групп). Слабые места:

- **SCIM-токен утёк** — атакующий создаёт пользователей/группы в Identity Center.
- **Слишком широкая группа в IdP** — синхронизируется в Identity Center с широкими правами.
- **SAML без проверки условий** — вход возможен от чужого IdP (см. `cloud-oidc-federation`).

Проверка SCIM-токена (если есть доступ к IdP):

```
$ curl -s -H "Authorization: Bearer $SCIM_TOKEN" \
    https://scim.us-east-1.amazonaws.com/$IDP_ID/Users | jq '.totalResults'
```

## Защита и что ломает атаку

- **Минимум прав в permission sets** — не `AdministratorAccess` на группы.
- **Узкие assignments** — только нужным группам и аккаунтам.
- **MFA и conditional access** в IdP.
- **Защита SCIM-токена**, ротация.
- **Аудит** назначений и входов.

## Если не сработало

- **Узкие permission sets** — эскалации через SSO нет.
- **MFA включён, группы маленькие** — сложно попасть в группу.
- **SCIM-токен защищён** — новых сущностей не создать.
- **Нет широких assignments** — идём через другие векторы (ключи, CI).

## Мини-сценарий: вход и роль целиком

1. **Вход.** Пользователь логинится в Identity Center (`aws sso login`), получает токен доступа.
2. **Список.** `aws sso list-accounts` → `prod`, `dev`; `list-account-roles` → `ReadOnlyAccess`, `PowerUserAccess`, `AdministratorAccess`.
3. **Выбор роли.** `get-role-credentials --role-name AdministratorAccess` → временные креды.
4. **Проверка.** `sts get-caller-identity` → `AWSReservedSSO_AdministratorAccess_.../ivan`. Это легитимно — роль назначена пользователю.
5. **Поиск слабости.** `list-permission-sets` + `list-managed-policies-in-permission-set` → у permission set `ps-0def` политика `PowerUserAccess`.
6. **Assignments.** `list-account-assignments` → `ps-0def` выдан группе `all-developers`.
7. **Эскалация.** Любой разработчик, попавший в группу (через IdP/SCIM), получает `PowerUserAccess` в проде — почти админ.

Ошибка не в самом SSO, а в **широте** permission set и назначения. Одна привязка «широкие права → большая группа» обесценивает всю модель.

## Разбор: проблема не в SSO, а в широте

IAM Identity Center сам по себе безопаснее статических ключей: креды временные, вход централизованный, MFA возможен. Проблема появляется на уровне **конфигурации**. Permission set — это шаблон, и если в него положили `AdministratorAccess` или `PowerUserAccess`, то любой, кому он назначен, получает эти права. А назначение на **широкую группу** (`all-developers`) размножает админский доступ на десятки людей. SSO не защищает от «мы случайно выдали слишком много». Поэтому аудит начинается с вопросов: какие permission sets есть, какие в них политики, на какие группы они назначены. Минимум прав и узкие группы — вот что делает SSO реально безопасным.

И проверяйте аудит: без логирования входов и назначений вы не узнаете, что кто-то получил широкую роль.

## Что мы теперь знаем

1. IAM Identity Center — централизованный вход в аккаунты AWS.
2. Permission sets — шаблоны прав; assignments привязывают их к группам.
3. `get-role-credentials` выдаёт временные креды под роль.
4. Широкий permission set на большую группу — путь к админу.
5. SCIM и внешний IdP — точки, где конфигурация ломает безопасность.

## Частые ошибки

- **`AdministratorAccess` на широкую группу.**
- **SCIM-токен без ротации** — создание пользователей атакующим.
- **MFA не обязателен** в IdP.
- **Нет аудита assignments** — никто не видит, кому что выдано.
- **SAML без проверки условий** — вход от чужого IdP.

## На что смотреть дальше

- Список permission sets и их политики.
- Assignments: каким группам что выдано.
- Наличие `AdministratorAccess`/`PowerUserAccess` на широкие группы.
- SCIM-провижининг и его токен.
- Условия SAML-федерации с IdP.

## Быстрая проверка

```bash
aws sso list-accounts --access-token $TOKEN
aws sso list-account-roles --account-id 123456789012 --access-token $TOKEN
aws sso-admin list-permission-sets --instance-arn $INSTANCE_ARN
aws sso-admin list-account-assignments --instance-arn $INSTANCE_ARN --account-id 123456789012 \
  --permission-set-arn arn:...:permissionSet/ps-0abc...
```

## Квиз

Проверь себя.

```quiz
- question: "Что такое IAM Identity Center?"
  options:
    - "Централизованный SSO-вход в аккаунты AWS"
    - "Сервис снапшотов"
    - "Балансировщик"
    - "Хранилище секретов"
  answer: 0
  explanation: "Identity Center даёт единый вход и роли."
- question: "Что такое permission set?"
  options:
    - "Шаблон ролей и политик, выдаваемый в аккаунты"
    - "Снимок диска"
    - "Тип инстанса"
    - "Ключ KMS"
  answer: 0
  explanation: "Permission set определяет права роли в аккаунте."
- question: "Какая конфигурация опасна?"
  options:
    - "AdministratorAccess, назначенный на широкую группу"
    - "ReadOnly на группу аудита"
    - "MFA в IdP"
    - "Узкий permission set"
  answer: 0
  explanation: "Широкие права на большую группу = много админов."
- question: "Что делает SCIM в Identity Center?"
  options:
    - "Провижинит пользователей и группы из внешнего IdP"
    - "Шифрует креды"
    - "Создаёт снапшоты"
    - "Балансирует трафик"
  answer: 0
  explanation: "SCIM синхронизирует пользователей/группы."
- question: "Что выдаёт get-role-credentials?"
  options:
    - "Временные креды под выбранную роль"
    - "Постоянные IAM-ключи"
    - "Пароль root"
    - "Сертификат TLS"
  answer: 0
  explanation: "SSO выдаёт временные креды роли."
```

## Куда дальше

В следующем уроке (`cloud-s3-deep`) мы углубимся в S3: ACL, bucket policies и presigned URL. А пока главное: SSO безопасен ровно настолько, насколько узки permission sets и assignments.

## Где пригодится

- **Red team:** эскалация через SSO и permission sets.
- **Пентест:** аудит Identity Center и assignments.
- **Blue team:** минимум прав, MFA, защита SCIM.
- **Работа/DevSecOps:** узкие permission sets и группы.
- **Дальше по дереву:** `cloud-iam-basics`, `cloud-privesc-iam`.
