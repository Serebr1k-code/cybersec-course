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
lab:
  kind: shell
  title: "Практика: Cognito — от identity pool к данным пользователя"
  toolset: [core, aws]
  workdir: /home/student/cognito
  files: [task.md, notes.md, identity-pool.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Прочитай `identity-pool.json`: он разрешает unauth-доступ и отдаёт роль, а user pool доверяет ей."
    - "Получи пользователя по токену: `aws cognito-idp get-user --access-token <token>`."
    - "В UserAttributes лежит `custom:flag`: `grep nto user.json > found.txt`."

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

## Шаг 4: что именно искать в бандле

Идентификатор identity pool почти всегда лежит в клиентском JS — он не секрет по замыслу AWS, но
именно он открывает guest-доступ. Типичные места и паттерны:

```bash
# общий поиск формата us-east-1:uuid
$ curl -s https://app.example.com/static/js/main.js \
  | grep -Eo '[a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36}' | sort -u
us-east-1:12345678-1234-1234-1234-1234567890ab

# конфиг Amplify (частый шаблон)
$ curl -s https://app.example.com/static/js/main.js \
  | grep -A6 -i 'aws_cognito_identity_pool_id\|identityPoolId\|identity_pool_id'
```

Помимо identity pool, в бандле часто лежат:

- **`aws_cognito_user_pool_id`** (`us-east-1_ABC123`) и **`aws_user_pools_web_client_id`** — для user pool;
- **`aws_appsync_graphqlEndpoint`** и **`aws_appsync_apiKey`** — AppSync-ключ, тоже дающий доступ к API;
- **регион** — обязателен для корректных вызовов.

Собрав эти значения, ты получаешь полную картину клиентской конфигурации AWS. Это типичный старт
пентеста SPA/мобильного приложения: **клиентская конфигурация = поверхность атаки**.

## Шаг 5: цепочка от guest до более широких прав

Получив unauth-роль, не останавливайся на `s3 ls`. Типовая эскалация:

1. **`enumerate-iam`** — карта разрешённых API (быстро и тихо).
2. **Чтение S3/SSM/Secrets Manager** — часто там лежат статические ключи, `.env`, конфиги.
3. **Статические ключи** → уже не ограничены unauth-ролью: `sts get-caller-identity` покажет нового
   пользователя, а его права могут включать `iam:CreatePolicyVersion` (полная эскалация).
4. **`sts:AssumeRole`** — если роль может переключаться на другие, иди по цепочке к админской.

Так одна включённая галочка `AllowUnauthenticatedIdentities` превращается в полный доступ к аккаунту —
через промежуточное хранилище секретов.

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

## Как это видят защитники

Cognito-мисконфиг виден и в логах, и в конфигурации:

- **`get-id`/`get-credentials-for-identity` без аутентификации** — в CloudTrail как
  `GetId`/`GetCredentialsForIdentity` с `identityPoolId`; всплеск таких вызовов — признак abuse;
- **`AssumeRoleWithWebIdentity` от Cognito** — в CloudTrail видно, кто и когда получил креды;
- **`enumerate-iam`-подобный перебор** — серия `AccessDenied` по многим API от одной роли;
- **чтение S3/SSM** с unauth-роли — аномалия, если приложение этим не занимается.

Защита: выключить `AllowUnauthenticatedIdentities`, если гости не нужны; в trust policy роли добавить
условие на **`amr`**; выдать unauth-роли минимум прав; не хранить статические ключи в доступных
бакетах; включить CloudTrail-мониторинг на `GetCredentialsForIdentity`.

## Частые ошибки и подводные камни

- **Путать user pool и identity pool.** JWT из user pool сам по себе AWS-прав не даёт; нужен обмен через identity pool.
- **Забывать про регион.** `get-id` и `get-credentials-for-identity` должны идти в регион пула.
- **Считать guest-доступ безобидным.** «Unauth-роль только для чтения» часто читает весь S3-бакет компании.
- **Игнорировать срок жизни кредов.** Временные креды истекают примерно за час — их надо обновлять.
- **Перебирать API вслепую.** `enumerate-iam` быстрее и тише, чем десятки пробных вызовов.
- **Не проверять `get-caller-identity`.** Без него легко перепутать роль и записать неверную находку.

- **Не проверять `AllowUnauthenticatedIdentities` явно.** Наличие `IdentityPoolId` ещё не значит, что guest включён — без проверки вы получите `NotAuthorizedException`.

- **Не проверять self-registration.** Включённая регистрация в user pool даёт путь к authenticated-роли без чужих паролей.

<!-- lab -->

## Что мы теперь знаем

- User pool выдаёт JWT; identity pool обменивает идентичность на **временные AWS-креды**.
- `AllowUnauthenticatedIdentities: true` = guest-доступ: креды без логина.
- `get-id` + `get-credentials-for-identity` дают тройку ключей за две команды.
- `get-caller-identity` показывает assumed-роль (`Cognito_...Unauth_Role`).
- Креды временные (~1 час) — их надо периодически обновлять.
- Self-registration в user pool даёт путь к authenticated-роли без чужих паролей.
- Идентификатор identity pool лежит в клиентском JS — это не секрет, но он открывает guest-доступ.
- В бандле ищите также user pool id, web client id и AppSync api key — вся клиентская конфигурация AWS.

## На что смотреть дальше

- **aws-ssm**: Session Manager как путь внутрь без открытых портов.
- **cloud-privesc-iam**: что делать с ролью, полученной из Cognito.
- **cloud-assume-role**: цепочки `sts:AssumeRole` к более широким ролям.

## Чеклист пентеста Cognito

Соберём всё в короткий список — так проверка приложения занимает минуты:

1. **Найди конфиг.** Ищи в JS/мобильном бандле `identityPoolId`, `user_pool_id`, `client_id`,
   `apiKey`, регион.
2. **Проверь guest.** `aws cognito-identity get-id` — если вернулся `IdentityId`, guest включён.
3. **Забери креды.** `get-credentials-for-identity` → временные ключи.
4. **Определи роль.** `aws sts get-caller-identity` → `Cognito_...Unauth_Role`.
5. **Разведай права.** `enumerate-iam` (не слепой перебор).
6. **Проверь trust policy.** Нет условия на `amr` → попробуй guest→authenticated.
7. **Проверь user pool.** Self-registration включена? Клиент без секрета (`GenerateSecret: false`)?
8. **Ищи секреты.** S3/SSM/Secrets Manager от полученной роли.
9. **Обновляй креды.** Они живут ~час — держи refresh-цепочку.

Пункты 1–5 дают первые креды за минуты; пункты 6–9 превращают их в более широкий доступ.

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
