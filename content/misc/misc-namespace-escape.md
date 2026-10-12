---
id: misc-namespace-escape
title: "Namespaces и cgroups: изоляция и побег"
category: misc
parent: misc-sandbox-containers
difficulty: expert
order: 3
tags: [namespace, cgroup, linux, isolation, escape, container]
prerequisites: [misc-sandbox-containers]
useful_for:
  - "CTF pwn/Misc категория"
  - "Аудит контейнерной изоляции"
  - "Побег из контейнеров"
estimated_minutes: 32
summary: "Восемь Linux-namespaces, cgroups v1/v2, как они образуют контейнер, проверка изоляции и типовые векторы побега через mount, /proc и capabilities."
---

## Вопрос, с которого всё начинается

В прошлом уроке мы сбежали через `docker.sock`. Но что делать, если сокета нет, привилегий вроде тоже, а флаг всё равно «на хосте»? Тогда пора понять, **из чего вообще сделан контейнер**. Контейнер — это не отдельное ядро и не виртуальная машина. Это обычный процесс Linux, которому ядро «показывает» урезанную картину мира через **namespaces** и ограничивает ресурсы через **cgroups**. Понять эту картину — значит найти, где она дырявая.

## Наш пример: контейнер — это не виртуальная машина

Представь, что тебе дали шелл. Ты видишь свой PID 1, свой hostname, свой сетевой интерфейс — как будто ты один на машине. Но это иллюзия, которую создают namespaces. Проверим:

```bash
$ ls -l /proc/self/ns/
lrwxrwxrwx ... cgroup -> cgroup:[4026531835]
lrwxrwxrwx ... mnt    -> mnt:[4026531832]
lrwxrwxrwx ... net    -> net:[4026531833]
lrwxrwxrwx ... pid    -> pid:[4026531836]
lrwxrwxrwx ... user   -> user:[4026531837]
```

Числа в скобках — **inode namespace'ов**. Если сравнить их с числами у процесса хоста, видно, какие «миры» общие, а какие свои. Общий namespace — это и есть потенциальный мост.

## Шаг 1: восемь namespaces

Linux изолирует восемь аспектов системы:

| Namespace | Флаг `clone` | Что изолирует |
|-----------|--------------|----------------|
| Mount | `CLONE_NEWNS` | точки монтирования |
| PID | `CLONE_NEWPID` | номера процессов |
| Network | `CLONE_NEWNET` | интерфейсы и порты |
| IPC | `CLONE_NEWIPC` | SysV IPC, очереди |
| UTS | `CLONE_NEWUTS` | hostname и домен |
| User | `CLONE_NEWUSER` | uid/gid и capabilities |
| Cgroup | `CLONE_NEWCGROUP` | иерархия cgroups |
| Time | `CLONE_NEWTIME` | монотонные часы |

Контейнерный рантайм просто создаёт для процесса новые экземпляры этих namespace'ов. Если какой-то из них **не** создан — контейнер делит его с хостом.

## Шаг 2: где мы находимся

```bash
$ cat /proc/self/cgroup
0::/docker/a1b2c3d4
$ mount | grep -E 'overlay|cgroup'
overlay on / type overlay (rw,...)
cgroup2 on /sys/fs/cgroup type cgroup2 (rw,...)
$ ls -la /var/run/docker.sock
ls: cannot access '/var/run/docker.sock': No such file or directory
```

`overlay` в `mount` — верный признак контейнера. `cgroup2` говорит, что это cgroup v2 (в v1 был `release_agent`, в v2 его убрали). Сокета нет — значит, вектор `docker.sock` закрыт, ищем дальше.

## Шаг 3: user namespace — почему это важно

`CLONE_NEWUSER` позволяет непривилегированному пользователю «стать root» **внутри** namespace: uid 0 в контейнере маппится на обычный uid на хосте. Именно поэтому Docker с user-namespaces безопаснее — «root» в контейнере не равен root на хосте.

```bash
$ unshare --user --map-root-user --mount-proc bash
$ id
uid=0(root) gid=0(root) groups=0(root)
```

Если `unshare` в песочнице разрешён, можно создавать вложенные namespaces и обходить часть ограничений. Если контейнер запущен **без** user-namespace, то uid 0 — настоящий root с реальными возможностями.

## Шаг 4: cgroups и release_agent

**cgroups** ограничивают CPU, память и доступ к устройствам. В cgroup **v1** был опасный механизм `release_agent`: при «опустошении» группы ядро запускает указанный скрипт **на хосте**. Если контейнер имеет `CAP_SYS_ADMIN` и cgroup v1 смонтирован, побег строится так: указываем в `release_agent` путь к нашему скрипту и заставляем группу опустеть. В cgroup **v2** `release_agent` убран, но остаются другие векторы (например, `core_pattern`).

```bash
$ mount | grep cgroup
cgroup on /sys/fs/cgroup type cgroup (rw,...,release_agent=/sbin/cgrp)
```

## Шаг 5: побег через nsenter

Если у контейнера есть `CAP_SYS_ADMIN`, работает самый чистый побег — `nsenter` в namespaces процесса хоста. Находим PID 1 хоста (он виден, если PID-namespace общий) и входим во все его «миры»:

```bash
$ ps aux | head -3
root 1 0.0 0.1 ... /sbin/init
$ nsenter --target 1 --mount --uts --ipc --net --pid --root -- /bin/bash
$ cat /root/flag
FLAG{nsenter_is_king}
```

`--target 1` указывает на процесс хоста, а флаги `--mount --uts --ipc --net --pid` переключают нас в его namespaces. Если `nsenter` в контейнере нет — тот же результат даёт комбинация `setns`/`/proc/1/ns/`.

## Шаг 6: побег через /proc/1/root

Самый простой путь, не требующий capabilities: если `/proc` хоста виден (общий PID-namespace), то `/proc/1/root` — символическая ссылка на корень процесса 1, то есть на корневую файловую систему хоста:

```bash
$ ls -l /proc/1/root
lrwxrwxrwx ... /proc/1/root -> /
$ cat /proc/1/root/etc/hostname
host-machine
$ cat /proc/1/root/root/flag
FLAG{proc_root_escape}
```

Чтение через `/proc/1/root` обходит mount-namespace контейнера, потому что мы обращаемся к корню **чужого** процесса. Если PID-namespace изолирован, PID 1 — это init контейнера, и его root — корень контейнера; тогда нужен другой вектор. Всегда начинай с `ls -l /proc/1/root` — это бесплатная проверка.

## Шаг 7: capabilities — нарезанный root

**Capabilities** — это раздробленные привилегии root. Даже если uid ≠ 0, `CAP_SYS_ADMIN` делает тебя почти всемогущим: он разрешает `mount`, `unshare`, `pivot_root`, `setns`, `bpf`. `CAP_NET_ADMIN` меняет сеть, `CAP_SYS_PTRACE` отлаживает чужие процессы, `CAP_DAC_READ_SEARCH` обходит права на файлы.

```bash
$ grep Cap /proc/self/status
CapEff: 0000003fffffffff
$ capsh --decode=0000003fffffffff | tr ',' '\n' | grep -E 'sys_admin|sys_ptrace'
cap_sys_admin
cap_sys_ptrace
```

Помимо namespaces, изоляцию формируют **seccomp** (ограничение syscalls), **AppArmor/SELinux** и **no-new-privileges**. Они могут заблокировать побег даже при наличии capabilities: проверь `cat /proc/self/status | grep -E 'Seccomp|NoNewPrivs'` и `cat /proc/self/attr/current`. Побег — это всегда поиск комбинации «слабое место в одном слое + отсутствие компенсации в другом».

## Что мы теперь знаем

- Контейнер — это **namespaces + cgroups** над общим ядром, а не виртуальная машина.
- Восемь namespaces изолируют mount, PID, сеть, IPC, UTS, user, cgroup и время.
- **User namespace** делает uid 0 внутри контейнера не равным root хоста.
- **cgroup v1 `release_agent`** выполняет скрипт на хосте; в v2 его нет.
- **`nsenter`** при `CAP_SYS_ADMIN` и **`/proc/1/root`** при общем PID-namespace — прямые побеги.
- **Capabilities** — нарезанный root; `CAP_SYS_ADMIN` почти всегда означает побег.

## На что смотреть дальше

Разверни локально контейнеры с разными флагами (`--privileged`, `--cap-add SYS_ADMIN`, без user-namespace) и найди побег в каждом. При отладке читай ошибки: `Operation not permitted` от `nsenter` — нет `CAP_SYS_ADMIN` или seccomp блокирует `setns`; запрет `mount` — смотри AppArmor (`dmesg | tail`). Дальше — `misc-container-runtime` (побег из runc/containerd) и `misc-seccomp-escape` (фильтры syscalls).

## Квиз

Проверь себя.

```quiz
- question: "Что изолирует PID namespace?"
  options:
    - "номера процессов (видно только своё поддерево)"
    - "сетевые интерфейсы"
    - "точки монтирования"
    - "hostname"
  answer: 0
  explanation: "Внутри контейнера PID 1 — это его собственный init."
- question: "Что даёт CLONE_NEWUSER?"
  options:
    - "позволяет стать root внутри namespace без прав на хосте"
    - "шифрует диск"
    - "ускоряет сеть"
    - "отключает seccomp"
  answer: 0
  explanation: "User-namespace маппит uid/gid и capabilities."
- question: "Какой классический побег использует docker.sock?"
  options:
    - "запуск нового контейнера с монтированием корня хоста"
    - "изменение hostname"
    - "смена пароля root"
    - "перезагрузка хоста"
  answer: 0
  explanation: "Сокет даёт полный контроль над Docker-демоном."
- question: "Зачем проверять /proc/1/root?"
  options:
    - "это ссылка на корень процесса 1 — часто путь к файловой системе хоста"
    - "там хранятся пароли"
    - "это точка входа SSH"
    - "это лог ядра"
  answer: 0
  explanation: "Чтение через неё обходит mount-namespace контейнера."
- question: "Какая capability делает побег из контейнера почти тривиальным?"
  options:
    - "CAP_SYS_ADMIN"
    - "CAP_NET_BIND_SERVICE"
    - "CAP_CHOWN"
    - "CAP_KILL"
  answer: 0
  explanation: "SYS_ADMIN разрешает mount, unshare, nsenter и многое другое."
```

## Куда дальше

В следующем уроке `misc-container-runtime` мы спустимся на уровень ниже — к самому рантайму (runc/containerd) и его CVE. А пока главное запомни: **изоляция — это набор слоёв, и побег живёт на стыке** — там, где один namespace или capability настроен слишком щедро.

## Где пригодится

- **CTF misc/pwn** — побег из контейнера.
- **Аудит** — проверка конфигурации Docker/Kubernetes.
- **Работа** — безопасность CI/CD и изоляция нагрузок.
- **Research** — контейнерные CVE и их эксплуатация.
