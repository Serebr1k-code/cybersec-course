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

Секрет-менеджеры — централизованные хранилища паролей, ключей и токенов. Они лучше, чем секреты в env, но при слабых правах становятся «одной кнопкой» для получения всех кредов сразу. Урок про извлечение секретов и злоупотребление KMS.

## AWS Secrets Manager

Каждый секрет — отдельная сущность с ARN, политикой ресурса и версиями.

```bash
# Список секретов
aws secretsmanager list-secrets --query 'SecretList[].Name'

# Чтение значения
aws secretsmanager get-secret-value --secret-id <name> \
  --query 'SecretString' --output text

# Метаданные и политика ресурса
aws secretsmanager describe-secret --secret-id <name>
```

Типовые мисконфиги: политика ресурса с `Principal: "*"` без condition, доступ для всей организации, секреты в публичных аккаунтах.

```bash
# Проверить, кто может читать секрет
aws secretsmanager get-resource-policy --secret-id <name>
```

## Azure Key Vault

Key Vault хранит секреты, ключи и сертификаты. Доступ — через RBAC или Access Policies.

```bash
# Список хранилищ
az keyvault list --query '[].name'

# Список секретов и чтение
az keyvault secret list --vault-name <kv> --query '[].id'
az keyvault secret show --vault-name <kv> --name <name> --query value -o tsv

# Ключи и сертификаты
az keyvault key list --vault-name <kv>
az keyvault certificate list --vault-name <kv>
```

Частая ошибка — `Access Policies` с `get`/`list` для широкой группы или managed identity, доступной из пода.

## GCP Secret Manager

```bash
# Список секретов
gcloud secrets list --format='value(name)'
# Чтение последней версии
gcloud secrets versions access latest --secret=<name>
# Проверка IAM
gcloud secrets get-iam-policy <name>
```

Секреты могут быть доступны через `roles/secretmanager.secretAccessor` сервисному аккаунту пода — тогда SSRF/код в поде = чтение секретов.

## KMS: как злоупотреблять

KMS управляет ключами шифрования. Атакующему важны два права: `kms:Decrypt` и `kms:CreateGrant`.

```bash
# Список ключей и их политики
aws kms list-keys
aws kms describe-key --key-id <id>
aws kms get-key-policy --key-id <id> --policy-name default

# Расшифровать перехваченный ciphertext
aws kms decrypt --ciphertext-blob fileb://enc.bin \
  --query Plaintext --output text | base64 -d

# Опасное: выдать себе грант на чужой ключ
aws kms create-grant --key-id <id> \
  --grantee-principal <my-arn> --operations Decrypt
```

Опасные конфигурации: ключ с политикой `Principal: "*"`, `kms:Decrypt` на `*`, или возможность `CreateGrant` — она превращается в Decrypt.

## Разобранный пример: от пода в GCP к секретам

**Дано:** под с service account, у которого `secretmanager.secretAccessor`.

1. Из пода читаем креды SA (metadata или env) и проверяем:

```bash
gcloud auth list
gcloud secrets list
```

2. Читаем секреты:

```bash
for s in $(gcloud secrets list --format='value(name)'); do
  echo "=== $s ==="
  gcloud secrets versions access latest --secret="$s"
done
```

3. Среди секретов — ключи к БД, API-токены, ключи других сервисов. Расширяем доступ.

## Секреты в IaC и логике

Частые ошибки, которые ведут к утечке секрет-менеджера:

- Секрет в открытом виде в Terraform state/plan (см. `cloud-terraform`).
- Env-переменная с ARN секрета, но широкие права.
- Политика ресурса, доверяющая `*`.
- Managed identity пода с доступом ко всему Key Vault.

```bash
# Поиск ссылок на секреты в коде/пайплайнах
grep -rE 'secretsmanager|keyvault|secretmanager|SecretString' . --hidden
```

## Частые ошибки

- **Считать секрет-менеджер безопасным по определению.** Права решают всё.
- **Забывать про resource policy.** Она может открывать секрет наружу.
- **Игнорировать `kms:CreateGrant`.** Грант = Decrypt для получателя.
- **Не проверять версии секрета.** Старая версия может содержать ещё валидный ключ.
- **Путать права на секрет и права на ключ.** Чтение ciphertext без Decrypt бесполезно.
- **Не смотреть логи.** `GetSecretValue` фиксируется в CloudTrail.

## Что дальше / решение

- Есть `GetSecretValue`/`get` → перебирайте все секреты, ищите «зонтичные» креды.
- Есть `kms:Decrypt` → расшифровывайте перехваченные данные.
- Есть `kms:CreateGrant` → выдайте себе Decrypt.
- Смежные уроки: `cloud-credential-hunting`, `cloud-privesc-iam`, `cloud-terraform`.

## KMS: как злоупотреблять

KMS-ключ защищает секреты, но если у вас есть `kms:Decrypt` и доступ к зашифрованному blob — вы его расшифруете. Ключевые права: `kms:Decrypt`, `kms:GenerateDataKey`, `kms:CreateGrant`, `kms:PutKeyPolicy`. Последние два позволяют выдать себе доступ:

```bash
aws kms create-grant --key-id <id> --grantee-principal arn:aws:iam::111122223333:user/me \
  --operations Decrypt
aws kms get-key-policy --key-id <id> --policy-name default
```

Key policy с `Principal: *` и `Condition` на аккаунт — частый мисконфиг.

## Инструменты по провайдерам

```bash
# AWS
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id db/prod
aws ssm get-parameters-by-path --path /app --with-decryption
# Azure
az keyvault secret list --vault-name kv-prod
az keyvault secret show --vault-name kv-prod --name db-password
# GCP
gcloud secrets list
gcloud secrets versions access latest --secret=db-password
```

Флаги важны: `--with-decryption` (SSM), `--name`/`--vault-name` (Azure), `versions access latest` (GCP).

## Разобранный пример 2: от роли пода к секретам

1. Роль пода имеет `secretsmanager:GetSecretValue` на `*`.
2. `list-secrets` → находим `prod/db`, `prod/api-keys`.
3. `get-secret-value` → получаем креды БД и API-ключи.
4. Креды БД → подключение к RDS; API-ключи → внешние сервисы.
5. Оцениваем blast radius и ротируем.

## Таблица примитивов

| Право | Эффект |
|-------|--------|
| GetSecretValue | чтение секрета |
| ListSecrets | карта секретов |
| kms:Decrypt | расшифровка blob |
| kms:CreateGrant | выдать себе доступ |
| ssm:GetParameter | параметры с секретами |
| secretmanager.versions.access | секрет GCP |

## Секреты в IaC и коде

Секреты часто попадают в Terraform/CloudFormation (пароли RDS), в переменные окружения функций, в Helm-чарты, в CI-переменные. Ищите их через trufflehog/gitleaks по репозиториям и по state. В CI переменные могут быть «protected», но `printenv` в раннере их покажет. В Kubernetes — Secret-объекты и CSI-драйверы.

## Практическое задание

Создайте в LocalStack (или тестовом аккаунте) секрет с помощью `aws secretsmanager create-secret`, ограничьте доступ политикой, затем попробуйте прочитать его другой ролью — должен быть AccessDenied. Далее выдайте `kms:CreateGrant` и покажите, как можно расширить себе доступ к ключу. Это демонстрирует разницу между «секрет защищён» и «секрет реально недоступен».

## Отличие «секрет-менеджер» от «секрет в переменной»

Секрет-менеджер даёт аудит доступа, ротацию и централизованные права. Переменная окружения — нет: она утекает в логи, дампы памяти, `docker inspect`. При компрометации пода сначала читайте env (быстро), затем обращайтесь к менеджеру (аудит, но там свежие секреты). Разница для атакующего: менеджер требует отдельного права и оставляет след; env бесплатен, но может быть устаревшим.

## Аудит доступа к секретам

Включите CloudTrail data events для Secrets Manager/KMS и отслеживайте `GetSecretValue`/`Decrypt` из нетипичных principal. В Azure — diagnostic settings на Key Vault; в GCP — Data Access audit logs. Без этих логов вы не увидите кражу секретов. Атакующему важно знать, что `GetSecretValue` всегда логируется (в отличие от S3 GetObject без data events).

## Быстрая проверка

```bash
aws secretsmanager list-secrets
aws ssm get-parameters-by-path --path / --with-decryption
az keyvault secret list --vault-name kv
gcloud secrets list
```

Начните с перечисления секретов (если есть права), затем читайте по одному. Проверьте key policy KMS — широкий доступ к ключу равносилен доступу ко всем секретам.

## Квиз

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
- question: "Почему resource policy секрета с Principal * опасна?"
  options:
    - "Открывает чтение секрета широкому кругу субъектов"
    - "Ускоряет шифрование"
    - "Уменьшает стоимость"
    - "Блокирует IAM"
  answer: 0
  explanation: "Wildcard principal = потенциальный публичный доступ."
```

## Где пригодится

- **Red team / пентест:** быстрый сбор кредов из хранилищ.
- **Bug bounty:** мисконфиги resource policy и IAM.
- **CTF:** облачные задачи с секрет-менеджером и KMS.
- **Работа/DevSecOps:** least-privilege на секреты, аудит грантов KMS.
- **Дальше по дереву:** `cloud-credential-hunting`, `cloud-privesc-iam`.
