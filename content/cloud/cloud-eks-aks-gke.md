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

## Зачем этот урок

Managed-кластеры (EKS, AKS, GKE) скрывают control plane, но добавляют **связь между k8s-идентичностями и облачными ролями**. Именно эта связь — главный приз: из пода можно получить облачные права и выйти за пределы кластера в аккаунт.

## EKS (AWS)

- **Control plane** управляется AWS, но **worker nodes** — ваши EC2.
- **IRSA (IAM Roles for Service Accounts)** — привязка k8s SA к IAM-роли через OIDC.
- **aws-auth ConfigMap** — маппинг IAM-принципалов на k8s RBAC.

Связь SA ↔ IAM-роль:

```bash
# В поде с IRSA: переменные и токен
env | grep -i AWS_ROLE_ARN
cat $AWS_WEB_IDENTITY_TOKEN_FILE
# Креды приходят от STS AssumeRoleWithWebIdentity
aws sts get-caller-identity
```

Атаки:

- **Захват SA с IRSA** → получение IAM-роли.
- **Чтение/изменение `aws-auth`** (нужны права на ConfigMap) → выдать себе `system:masters`.
- **Node IAM role**: если узлы имеют широкую роль, побег на узел даёт её креды (IMDS).

```bash
# На узле EKS — креды node role через IMDS
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## AKS (Azure)

- **Control plane** — бесплатный/managed; nodes — Azure VMSS.
- **Workload Identity** — привязка k8s SA к Azure managed identity/user-assigned identity через OIDC federation.
- **Kubelet identity** — используется для pull образов и управления ресурсами.

Связь SA ↔ Azure identity:

```bash
# В поде: токен projected SA и федерация
ls /var/run/secrets/azure/tokens/
cat /var/run/secrets/azure/tokens/azure-identity-token
# Обмен на токен Azure AD через OIDC
```

Атаки:

- **Захват SA с workload identity** → токен Azure.
- **Kubelet identity** на узле → права на ACR, VMSS.
- **`az aks get-credentials`** при наличии прав → доступ к API кластера.

## GKE (GCP)

- **Workload Identity** — привязка k8s SA к GCP service account.
- **Node service account** — используется узлами.
- **GKE metadata server** — поды без Workload Identity получают node SA по умолчанию (риск!).

Связь:

```bash
# В поде с Workload Identity
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Возвращает токен GCP SA, привязанного к k8s SA
```

Атаки:

- **Поды без Workload Identity используют node SA** — часто широкие права.
- **Аннотация `iam.gke.io/gcp-service-account`** при праве создавать SA/поды → привязка к привилегированному GCP SA.
- **Захват `roles/container.admin`** → полный контроль кластера.

## Разобранный пример: GKE pod → GCP project

1. Мы в поде GKE. Проверяем metadata:
   ```bash
   curl -s -H "Metadata-Flavor: Google" \
     "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
   ```
2. Получаем токен:
   ```bash
   TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
     "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)
   ```
3. Определяем права SA:
   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     "https://cloudresourcemanager.googleapis.com/v1/projects"
   ```
4. Если SA имеет доступ к GCS/секретам — читаем данные:
   ```bash
   gcloud storage ls --access-token-file=<(echo "$TOKEN") 2>/dev/null || \
   curl -s -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/storage/v1/b?project=<PROJ>"
   ```
5. Если SA — `roles/container.admin`, создаём привилегированный под или меняем RBAC кластера.

## Общее: escape из кластера в облако

Ключевая идея — найти **мост** между k8s и облаком:

| Платформа | Мост |
|-----------|------|
| EKS | IRSA (SA→IAM role), node IAM role, aws-auth |
| AKS | workload identity, kubelet identity |
| GKE | workload identity, node SA |

Ищите в подах: env с `AWS_ROLE_ARN`, `/var/run/secrets/azure/tokens`, GCP metadata. Затем — стандартная облачная эскалация.

## Частые ошибки

- **Считать managed = безопасный.** Control plane скрыт, но data plane — ваш.
- **Не проверять node role/SA.** Поды без workload identity часто используют широкую node-идентичность.
- **Игнорировать `aws-auth`/RBAC.** Изменение маппинга = `system:masters`.
- **Забыть про pull-секреты.** `imagePullSecrets` могут содержать креды registry.
- **Не смотреть ACR/ECR/GCR.** Права kubelet identity часто включают registry.

## Сравнение managed-кластеров

| Аспект | EKS | AKS | GKE |
|--------|-----|-----|-----|
| Идентичность пода | IRSA (OIDC) | Workload Identity | Workload Identity |
| Metadata | IMDS (169.254.169.254) | IMDS Azure | metadata.google.internal |
| Control plane | управляемый AWS | управляемый Azure | управляемый Google |
| Доступ к API | aws-auth ConfigMap | Azure RBAC | GCP IAM |
| Аудит | CloudTrail + audit | Azure Monitor | Cloud Audit Logs |
| Секреты | EKS secrets (KMS) | Key Vault CSI | Secret Manager CSI |

Общее: managed-кластер не отменяет конфигурацию узлов и RBAC; большинство побегов идут через pod → node → облачные креды.

## Детали IRSA и Workload Identity

EKS: SA в namespace связан с IAM-ролью через OIDC-провайдер. Токен проецируется в под и обменивается на AWS-креды:

```bash
TOKEN=$(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token)
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::111122223333:role/EksPodRole \
  --role-session-name pod --web-identity-token "$TOKEN"
```

GKE: аннотация `iam.gke.io/gcp-service-account`; токен берётся с metadata-сервера GKE. AKS: federated credential связывает K8s SA с Azure managed identity.

## Инструменты

```bash
aws eks list-clusters
aws eks describe-cluster --name prod --query 'cluster.{version:version,ep:endpoint,oidc:identity.oidc.issuer}'
az aks list -o table
gcloud container clusters list
kubectl config get-contexts
kube-bench run --targets=node
```

## Разобранный пример 2: EKS pod → AWS

1. В поде читаем projected-токен IRSA.
2. `assume-role-with-web-identity` → временные AWS-креды.
3. `aws sts get-caller-identity` → роль пода.
4. `enumerate-iam` → ищем эскалацию (часто роль имеет доступ к S3/Secrets).
5. Через найденные права двигаемся в аккаунт.

## Частые мисконфиги идентичности

- **IRSA trust с wildcard в `sub`** — любой SA кластера может встать на роль.
- **Node role с широкими правами** — компрометация узла = доступ ко всему.
- **`aws-auth` ConfigMap с лишними маппингами** — сторонние пользователи получают `system:masters`.
- **AKS без Azure RBAC для Kubernetes** — локальные аккаунты и сертификаты.
- **GKE без Workload Identity** — поды используют node SA (часто editor).

Проверка `aws-auth`:
```bash
kubectl -n kube-system get configmap aws-auth -o yaml
```

## Практическое задание

Разверните kind-кластер и настройте IRSA-подобную привязку (можно эмулировать через проекцию токена). Покажите, что под читает токен и обменивает его на креды. Затем ограничьте `sub` в trust-политике до конкретного namespace/SA и убедитесь, что другой SA больше не может встать. Это ключевой навык защиты managed-кластеров.

## Аудит aws-auth и локальных аккаунтов AKS

```bash
kubectl -n kube-system get configmap aws-auth -o yaml
az aks show -g rg -n cluster --query 'disableLocalAccounts'
```

Если в `aws-auth` есть лишние маппинги к `system:masters`, сторонний IAM-пользователь получит админ-доступ к кластеру. В AKS `disableLocalAccounts=false` оставляет локальные сертификаты/ключи — их утечка даёт доступ в обход Azure RBAC. Оба — частые мисконфиги managed-кластеров.

## Быстрая проверка

```bash
kubectl -n kube-system get configmap aws-auth -o yaml
az aks show -g rg -n cluster --query disableLocalAccounts
gcloud container clusters describe prod --format=json | jq '.workloadIdentityConfig'
```

Лишние маппинги в aws-auth, локальные аккаунты AKS и отсутствие Workload Identity в GKE — три частые дыры managed-кластеров.

## Квиз

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
    - "Они медленнее"
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
  explanation: "Маппинг IAM→system:masters даёт административный доступ к кластеру."
```

## Где пригодится

- **Пентест managed-k8s** — связь k8s и облака.
- **Red team** — из пода в облачный аккаунт.
- **IR/Blue team** — детект аномалий в IRSA/workload identity.
- **DevSecOps** — настройка Workload Identity и минимизация node-ролей.
- **Сертификации** — CKS, облачные security-сертификаты.
