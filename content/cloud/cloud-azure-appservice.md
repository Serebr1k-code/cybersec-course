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

## Зачем этот урок

Azure App Service (веб-приложения) и Azure Functions (серверлесс) — две самые частые PaaS-платформы в Azure. У обеих есть особенности, критичные для пентеста: **Kudu/SCM-эндпоинт** (`*.scm.azurewebsites.net`) с командным API, **deployment credentials**, переменные окружения с секретами и **managed identity** (MI), доступная через локальный endpoint. Если в приложении есть SSRF или RCE, вы получаете MI-токен, а он открывает Key Vault, ARM, Graph, Storage — в пределах прав идентичности. Этот урок — про Kudu, SSRF к MI, кражу токена и цепочку к секретам.

## Как устроены App Service и Functions

- **App Service Plan** — вычислительный тариф. Приложение живёт на Windows или Linux.
- **Web App** — сайт; имеет `*.azurewebsites.net`, Kudu/SCM на `*.scm.azurewebsites.net`.
- **Function App** — Functions; тот же хостинг и Kudu.
- **Kudu/SCM** — сайт управления: файловый менеджер, редактор, консоль (`/api/command`), логи, deployment. Доступ по deployment credentials или publish profile, а также по MI/RBAC.
- **Deployment credentials** — логин/пароль уровня приложения (site-level), часто слабые или утёкшие.
- **Publish profile** — XML с кредами и URL; утечка даёт полный деплой.
- **Managed identity** — system- или user-assigned; токен выдаётся через `IDENTITY_ENDPOINT` + `IDENTITY_HEADER` (App Service) или через IMDS (`169.254.169.254`) для VM/ACI.
- **Environment variables** — `APPSETTING_*`, `WEBSITE_*`, `IDENTITY_ENDPOINT`, `IDENTITY_HEADER`, строки подключения.

Опасности: SSRF в приложении → MI-токен; открытый Kudu → RCE; утёкшие deployment credentials → деплой своего кода; publish profile в Git; секреты в env.

## Инструменты и команды

Разведка:

```bash
az webapp list --query '[].{Name:name,RG:resourceGroup,Host:defaultHostName,MI:identity}'
az functionapp list --query '[].{Name:name,RG:resourceGroup,MI:identity}'

# Настройки приложения (секреты часто тут)
az webapp config appsettings list -n myapp -g myrg
az functionapp config appsettings list -n myfunc -g myrg

# Публикационные профили (утечка!)
az webapp deployment list-publishing-profiles -n myapp -g myrg
```

Kudu/SCM:

```bash
# Проверка доступности SCM
curl -s -o /dev/null -w "%{http_code}\n" https://myapp.scm.azurewebsites.net/

# Выполнение команды (нужны creds)
curl -s -u '$myapp:<deploy_pass>' -X POST \
  https://myapp.scm.azurewebsites.net/api/command \
  -H 'Content-Type: application/json' \
  -d '{"command":"id","dir":"/"}'
```

Захват MI-токена изнутри App Service (если есть RCE/SSRF):

```bash
# Переменные окружения содержат endpoint и header
curl -s "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"
# => {"access_token":"eyJ...","expires_on":"...","resource":"https://vault.azure.net/"}
```

Использование токена:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://myvault.vault.azure.net/secrets/db-password?api-version=7.4"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

## Разобранный пример: от SSRF к Key Vault

Сценарий: в App Service есть SSRF (параметр `url` уходит в `requests.get`), у приложения включена system-assigned MI с доступом к Key Vault.

Шаг 1 — через SSRF читаем переменные окружения. Часто SSRF ограничен, но если есть возможность читать локальные файлы или env — забираем `IDENTITY_ENDPOINT` и `IDENTITY_HEADER`:

```
GET /proxy?url=http://127.0.0.1:...  → не сработает для env
```

Если SSRF только HTTP, но приложение само ходит к MI-endpoint (например, эндпоинт «получить секрет»), используем его: `GET /api/get-secret?name=db-password` может вернуть секрет напрямую — это логическая ошибка, а не SSRF. Проверяйте такие «удобные» API.

Шаг 2 — если SSRF позволяет произвольный URL, но требует доступ к `IDENTITY_ENDPOINT` и заголовку, попробуйте обход: некоторые SSRF позволяют задавать заголовки; либо используйте редирект. В App Service MI-endpoint — `http://127.0.0.1:41293/MSI/token` с обязательным `X-IDENTITY-HEADER`; без него токена не будет.

Шаг 3 — получив токен, определяем identity и ресурсы:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

Шаг 4 — читаем Key Vault:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://prod-vault.vault.azure.net/secrets?api-version=7.4"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://prod-vault.vault.azure.net/secrets/sql-conn?api-version=7.4"
```

Шаг 5 — с паролем БД идём к базе; если MI имеет доступ к Storage — читаем бэкапы; если к Graph — перечисляем пользователей/группы.

Альтернативный путь — **Kudu RCE**: если доступны deployment credentials (утёкшие или слабые), выполняем команду через `/api/command`, читаем `D:\home\site\wwwroot` (или `/home/site/wwwroot`), находим `appsettings.json` и env, затем — MI-токен изнутри.

## Варианты атак и обходы

- **Kudu/SCM без аутентификации.** Если SCM открыт или creds слабые — прямой RCE.
- **Deployment credentials.** Утечка через `list-publishing-profiles`, Git, конфиги CI; даёт деплой своего кода.
- **Publish profile.** XML с `userPWD`; утечка = полный контроль приложения.
- **Zip deploy / run-from-package.** Деплой вредоносного пакета; если приложение перезапустится, код исполнится.
- **SSRF → MI.** Основная цепочка для облачной эскалации; требует доступа к `IDENTITY_ENDPOINT` и header.
- **IMDS через VM.** Если приложение на VM/ACI — `169.254.169.254/metadata/identity/oauth2/token?resource=...&api-version=2018-02-01` с заголовком `Metadata: true`.
- **Env var leakage.** `WEBSITE_*`, строки подключения, `IDENTITY_HEADER` видны в `appsettings`.
- **User-assigned MI.** Если у приложения несколько MI, проверьте все — одна может быть привилегированной.
- **Hybrid Connections / VNet integration.** Даёт доступ к внутренним ресурсам, расширяя pivot.

## Частые ошибки и подводные камни

- **Забывать `X-IDENTITY-HEADER`.** Без него MI-endpoint App Service вернёт ошибку.
- **Путать IMDS и App Service MI-endpoint.** У них разные адреса и заголовки.
- **Считать SCM отдельным хостом.** `*.scm.azurewebsites.net` — часть того же приложения, но с другим доступом.
- **Игнорировать Linux vs Windows.** Пути и поведение Kudu различаются.
- **Не проверять все MI.** System-assigned и user-assigned — разные идентичности с разными правами.
- **Пробовать destructive-деплой без согласования.** Zip deploy перезапускает приложение — это заметно и может нарушить сервис.

## Защита и детект

- **Ограничьте SCM.** App Service Access Restrictions на SCM-сайт, отключение basic auth (`az resource update --set properties.siteConfig.scmIpSecurityRestrictions`), использование Entra ID для деплоя.
- **Ротируйте deployment credentials и publish profiles.** Не храните их в репозиториях.
- **Минимальные права MI.** MI приложения должна иметь доступ только к нужным секретам, не `Owner`/`Contributor` на подписку.
- **Key Vault через RBAC с узкими ролями**, не access policies на всё.
- **Детект.** Activity Log: `listpublishingprofiles`, `listkeys`, изменения appsettings, вызовы Kudu `/api/command`. Defender for App Service флагует подозрительные команды и аномальные запросы. Алерты на доступ к MI-токенам с новых процессов, на чтение многих секретов.
- **VNet integration + private endpoints** для изоляции.

## Functions: источники событий и инъекции

Azure Functions можно атаковать не только через HTTP, но и через **источники событий**. Если у вас есть права на соответствующий ресурс, вы можете подсунуть событие, которое функция обработает в своём контексте (с её MI):

- **Blob trigger.** `Microsoft.Storage` — запись блоба в контейнер запускает функцию. Если у вас есть SAS с правом `w` на этот контейнер (`cloud-azure-storage-sas`), вы запускаете функцию с произвольным содержимым. Если функция небезопасно обрабатывает блоб (десериализация, инъекция пути), это RCE/чтение.
- **Queue trigger.** Запись в очередь (`Microsoft.Storage` или Service Bus) запускает обработчик. Формат сообщения может содержать команды или SQL.
- **Event Grid / Event Hub.** Подделка события через право отправки.
- **Cosmos DB trigger.** Изменение документа запускает функцию.
- **Timer trigger.** Расписание; нельзя подсунуть событие, но можно предсказать тайминг.

Общий приём: найдите Function App с MI, имеющей широкие права, и источник события, в который вы можете писать. Подсунутое событие исполнится от имени MI функции — это «инъекция через данные» (`cloud-serverless-injection`). Часто достаточно записать специально сформированный JSON, чтобы функция выполнила нежелательное действие.

## Сравнение PaaS Azure, AWS и GCP

| Аспект | Azure App Service/Functions | AWS Elastic Beanstalk/Lambda | GCP App Engine/Functions |
|--------|------------------------------|-------------------------------|--------------------------|
| Управляющий сайт | Kudu/SCM (`*.scm...`) | нет аналога | нет аналога |
| Идентичность | Managed Identity (`IDENTITY_ENDPOINT`) | Lambda execution role (env) | runtime service account (metadata) |
| Деплой | zip deploy, publish profile | deploy пакет/образ | gcloud deploy, Cloud Build |
| Секреты | app settings, Key Vault refs | env, Secrets Manager | env, Secret Manager |
| Публичный доступ | auth settings / Easy Auth | Function URL | allUsers invoker |

Kudu/SCM — уникальная особенность Azure: это отдельный управляющий сайт, который часто доступен и хранит креды деплоя. В AWS/GCP аналога нет, поэтому в Azure всегда проверяйте SCM в первую очередь — он нередко даёт RCE быстрее, чем SSRF.

## Что дальше / решение

App Service/Functions — это либо Kudu-RCE, либо SSRF→MI. Начните с проверки SCM-эндпоинта и утёкших publish profiles/deployment credentials: это самый прямой путь к коду. Если приложение имеет MI, а у вас есть SSRF или RCE — забирайте токен (`IDENTITY_ENDPOINT` + header) и проверяйте его права: Key Vault, ARM, Graph, Storage. Найденные секреты (строки подключения, пароли БД, токены) открывают следующий хост. Если у MI есть `Contributor` на подписку, вы можете развернуть ресурс или выполнить команду на VM (`cloud-azure-arm`). Записывайте цепочку и все токены/секреты.

## Квиз

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
```

## Где пригодится

- **Пентест Azure:** App Service, Functions, MI.
- **Red team:** SSRF/RCE → MI → Key Vault.
- **Bug bounty:** Azure-приложения и утёкшие профили.
- **Blue team:** аудит SCM, MI-прав и секретов в env.
