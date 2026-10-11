---
id: cloud-ec2-ssrf
title: "EC2 и IMDSv2: обход, hop limit и защита metadata"
category: cloud
parent: cloud-metadata-ssrf
difficulty: hard
order: 1
tags: [cloud, aws, ec2, imdsv2, ssrf, hop-limit, metadata]
prerequisites: [cloud-metadata-ssrf, cloud-ssrf-to-cloud]
useful_for:
  - "Обход защиты IMDSv2 на AWS"
  - "Понимание hop limit и сетевой изоляции metadata"
  - "Пентест EC2 и контейнеров на EC2"
estimated_minutes: 40
summary: "Глубокий разбор AWS IMDS: IMDSv1 vs IMDSv2, hop limit, как контейнеры ограничивают metadata, и какие техники обхода реально работают."
---
## Зачем этот урок

AWS перевёл EC2 на **IMDSv2** и добавил **hop limit**, чтобы усложнить кражу ролей через SSRF. Но защита не абсолютна: конфигурации бывают разными, а приложения — слабыми. Здесь разбираем, как именно устроена защита metadata в AWS, чем IMDSv2 реально отличается, где она ломается (ECS task endpoint, host networking, SSRF с методами) и как всё это проверяется на практике.

## Как AWS защищает metadata

Три механизма:
1. **IMDSv2** — session-oriented доступ с токеном (защита от простого GET-SSRF).
2. **Hop limit** (`HttpPutResponseHopLimit`) — ограничивает число сетевых хопов до metadata.
3. **HttpEndpoint: disabled** — полное отключение metadata, если она не нужна.

Все три настраиваются per-instance и проверяются через `MetadataOptions`.

## IMDSv1: анатомия запроса

Простые GET без аутентификации:

```bash
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role
curl http://169.254.169.254/latest/user-data
curl http://169.254.169.254/latest/meta-data/placement/region
```

Любой GET-SSRF, умеющий читать ответ, вытаскивает креды.

## IMDSv2: session-токен и его свойства

IMDSv2 — двухшаговый:

```bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role
```

Свойства токена: обязательный **PUT**, TTL (1..21600 секунд), привязка к инстансу. IMDSv2 защищает от: простого GET-only SSRF, CRLF-инъекций в GET и открытых редиректов, которые нельзя превратить в PUT.

## Hop limit: механика

`HttpPutResponseHopLimit` (1 или 2) задаёт, сколько хопов может пройти запрос до metadata. Значение **1** означает, что запрос должен идти с самого инстанса, а не из контейнера или через дополнительный сетевой слой. Это защищает от кражи токена из контейнера на EC2.

```bash
aws ec2 describe-instances --instance-ids <ID> \
  --query "Reservations[].Instances[].MetadataOptions"
```

`HttpTokens: optional` — IMDSv1 разрешён (защита ослаблена). `required` — только v2.

## Контейнеры на EC2

Docker-контейнеры по умолчанию **не имеют** доступа к IMDS при hop limit = 1. Но при `--network host` контейнер видит metadata как хост:

```bash
curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
ip addr show; cat /proc/net/route
```

Проверьте сетевой режим и наличие маршрута к 169.254.169.254.

## ECS task metadata: 169.254.170.2

Для ECS-задач есть **отдельный** endpoint, отдающий креды task role **без токена IMDSv2**:

```bash
curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

Переменная `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (или `..._FULL_URI`) задаёт путь, например `/v2/credentials/<uuid>`. Если приложение читает эту env, SSRF на endpoint отдаёт креды даже при IMDSv2. Это ключевой обход.

## EKS и IRSA

В EKS поды получают креды через **IRSA**: в env есть `AWS_WEB_IDENTITY_TOKEN_FILE` (путь к OIDC-токену) и `AWS_ROLE_ARN`. Прочитав файл, токен можно обменять на креды роли через `sts:AssumeRoleWithWebIdentity`:

```bash
TOKEN=$(cat $AWS_WEB_IDENTITY_TOKEN_FILE)
aws sts assume-role-with-web-identity --role-arn "$AWS_ROLE_ARN" \
  --role-session-name pod --web-identity-token "$TOKEN"
```

Файл доступен только процессу пода, но если SSRF/RCE может его прочитать — роль пода ваша.

## Техники обхода

1. **SSRF с произвольным методом/заголовками** — прямой обход IMDSv2.
2. **CRLF-инъекция** в URL: `url=http://169.254.169.254/latest/api/token%0d%0aX-aws-ec2-metadata-token-ttl-seconds: 21600`.
3. **gopher://** — отправка произвольного TCP-потока, включая PUT.
4. **Открытый редирект** на metadata-хост.
5. **Контейнер с host networking** — прямой доступ.
6. **ECS task endpoint** (`169.254.170.2`) — без токена.

## Разобранный пример: ECS task role через SSRF

1. Приложение в ECS; в окружении `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/<uuid>`.
2. SSRF на `http://169.254.170.2/v2/credentials/<uuid>` → JSON с `AccessKeyId`/`SecretAccessKey`/`Token`.
3. Это креды **task role** — часто с широкими правами на сервисы приложения.
4. `export` + `aws sts get-caller-identity`, затем `enumerate-iam`.

Этот путь обходит IMDSv2, потому что ECS-эндпоинт токена не требует.

## Защита (для защитников)

- `HttpTokens: required` — только IMDSv2.
- `HttpPutResponseHopLimit: 1` — блокирует контейнеры.
- `HttpEndpoint: disabled` — если metadata не нужна.
- Сетевые политики: блокировать `169.254.169.254` из приложений (iptables/security group egress).
- Для ECS/EKS — минимальные права task role и IRSA-роли.
- Аудит: `describe-instances` по `MetadataOptions`, алерт на инстансы с `optional`.

## Частые ошибки

- **Сдаваться после 401 на IMDS.** Проверьте `MetadataOptions` — возможно, v1 разрешён на других инстансах.
- **Забыть про ECS/EKS endpoints.** `169.254.170.2` — отдельная дверь.
- **Не проверять hop limit.** Контейнер может не видеть metadata именно из-за него.
- **Путать `optional` и `required`.** `optional` = IMDSv1 работает.
- **Игнорировать регион/аккаунт.** Проверьте, к какому аккаунту принадлежит роль.

## Что делать дальше / решение

Практика: на учебном EC2 проверьте `MetadataOptions`, попробуйте IMDSv1 и IMDSv2, затем ECS-endpoint в задаче. Дальше — `cloud-ssrf-to-cloud` (сквозная цепочка), `cloud-privesc-iam` (эскалация от роли).

## IMDSv2 глубже: свойства токена и атаки

Session-токен IMDSv2 привязан к инстансу и имеет TTL до 21600 секунд (6 часов). Он передаётся заголовком `X-aws-ec2-metadata-token` в **каждом** последующем запросе. Ключевые атаки: (1) SSRF, умеющий PUT; (2) CRLF-инъекция для добавления заголовков; (3) `gopher://` для полного контроля над запросом. Если ни одно не работает — ищем ECS/EKS endpoint или host networking.

## ECS task metadata: детали

`169.254.170.2` — отдельный endpoint, отдающий креды task role. Путь берётся из `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (например, `/v2/credentials/<uuid>`) или из `AWS_CONTAINER_CREDENTIALS_FULL_URI`. Формат ответа совпадает с IMDS: `AccessKeyId`, `SecretAccessKey`, `Token`, `Expiration`. Endpoint не требует токена IMDSv2, поэтому SSRF на него работает даже при `HttpTokens: required`.

## EKS и pod identity

В EKS два механизма: **IRSA** (OIDC-токен в файле `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`) и **EKS Pod Identity** (endpoint `169.254.170.23` или через agent). Если SSRF может прочитать файл токена — обмен через `assume-role-with-web-identity`. Для pod identity endpoint отдаёт креды по пути `/v1/credentials`. Проверяйте env пода: `env | grep -iE 'AWS_|WEB_IDENTITY'`.

## Сетевая изоляция и namespace

Docker с `--network host` видит metadata как хост. В k8s поды обычно изолированы, но `hostNetwork: true` возвращает доступ. Проверьте: `ip route`, наличие маршрута к `169.254.169.254`, `iptables -L -n`. Некоторые CNI блокируют link-local — тогда metadata недоступен из пода, но доступен с хоста (через node-level RCE).

## Практическая проверка на инстансе

```bash
# Что разрешено
TOKEN=$(curl -s -m 2 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
if [ -z "$TOKEN" ]; then echo "IMDSv1 (no token)"; else echo "IMDSv2"; fi
curl -s -m 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s -m 2 "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
```

Этот однострочник быстро определяет, какой путь доступен.

## Почему IMDSv2 не спасает от SSRF с методами

Главное заблуждение: «включили IMDSv2 — вектор закрыт». На деле IMDSv2 защищает только от **GET-only** SSRF. Любой SSRF, способный (а) задать HTTP-метод PUT и (б) добавить заголовок, проходит защиту за два запроса. Многие API-клиенты (webhook-тестеры, импортёры, генераторы превью, прокси) позволяют и то и другое. Поэтому IMDSv2 — необходимое, но не достаточное условие; обязательны hop limit 1 и сетевая блокировка 169.254.169.254.

## Чеклист тестировщика EC2

- Определить, IMDSv1 или IMDSv2 (`HttpTokens`).
- Проверить `HttpPutResponseHopLimit`.
- Проверить `HttpEndpoint` (не `disabled` ли).
- Найти в приложении SSRF/RCE.
- Проверить env на `AWS_CONTAINER_CREDENTIALS_*` и `AWS_WEB_IDENTITY_TOKEN_FILE`.
- Попробовать ECS/EKS endpoints, если применимо.
- Забрать креды и прогнать триаж.

## Квиз

```quiz
- question: "Какое значение HttpTokens означает, что IMDSv1 всё ещё разрешён?"
  options:
    - "required"
    - "optional"
    - "disabled"
    - "strict"
  answer: 1
  explanation: "optional разрешает и v1, и v2; required — только v2."
- question: "Какой hop limit блокирует доступ к IMDS из контейнера на EC2?"
  options:
    - "3"
    - "1"
    - "64"
    - "255"
  answer: 1
  explanation: "Hop limit 1 требует, чтобы запрос шёл с самого инстанса, а не из контейнера."
- question: "Какой endpoint отдаёт креды task role в ECS?"
  options:
    - "169.254.169.254/latest/meta-data"
    - "169.254.170.2 с путём из AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
    - "127.0.0.1:8080"
    - "metadata.google.internal"
  answer: 1
  explanation: "ECS task metadata endpoint 169.254.170.2 не требует токена IMDSv2."
- question: "Какая техника SSRF позволяет отправить PUT-запрос к IMDSv2?"
  options:
    - "gopher:// или SSRF с произвольным методом/заголовками"
    - "Только GET"
    - "Только HTTPS"
    - "Никакая"
  answer: 0
  explanation: "gopher:// и контроль метода/заголовков позволяют выполнить PUT для получения токена."
- question: "Где проверить настройки metadata у инстанса EC2?"
  options:
    - "В /etc/hosts"
    - "aws ec2 describe-instances --query MetadataOptions"
    - "В security group"
    - "В Route 53"
  answer: 1
  explanation: "MetadataOptions содержит HttpTokens, HttpEndpoint и hop limit."
```

## Где пригодится

- **Пентест AWS** — обход IMDSv2 и ECS/EKS endpoints.
- **Bug bounty** — SSRF в AWS-приложениях.
- **CTF** — категория Cloud.
- **IR/Blue team** — оценка защищённости metadata.
- **Cloud security** — настройка IMDSv2 по умолчанию.
