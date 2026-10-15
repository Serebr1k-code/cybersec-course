---
id: linux-container-escape
title: 'Побег из контейнера: границы изоляции и их следы'
category: forensics
parent: forensics-linux-runtime
difficulty: hard
order: 1
tags: [linux, docker, container, namespaces, escape, forensics]
prerequisites: [forensics-linux-artifacts-advanced]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как устроена изоляция контейнеров (namespaces, cgroups, capabilities), как из неё выходят и какие следы это оставляет на хосте.'
lab:
  kind: shell
  title: 'Практика: Побег из контейнера'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Внутри контейнера ты видишь только его процессы и файлы. Но контейнер — это не
виртуальная машина: он использует **общее ядро** с хостом. Если контейнер запущен
неаккуратно, из него можно «выпрыгнуть» на хост. Для форензики важно понять: был ли
побег и как его найти.

## Наш пример: подозрительный контейнер

## Шаг 1: что такое изоляция

Контейнер изолирован четырьмя механизмами:

- **namespaces** — отдельные «взгляды» на процессы, сеть, монтирования;
- **cgroups** — ограничения ресурсов;
- **capabilities** — нарезанные права root;
- **seccomp** — фильтр системных вызовов.

Если хоть один настроен слабо, изоляция пробивается.

## Шаг 2: определяем, что процесс в контейнере

```
$ cat /proc/1/cgroup
0::/docker/3f2a1b... 
```

Строка `/docker/<id>` выдаёт контейнер. Ещё надёжнее — сравнить PID 1:

```
$ ps -p 1 -o comm=
myapp
```

Если PID 1 — не `systemd`/`init`, а приложение, это контейнер.

## Шаг 3: слабое место — смонтированный docker.sock

Классический побег:

```
$ ls -la /var/run/docker.sock
srw-rw---- 1 root docker 0 Jan 14 03:30 /var/run/docker.sock
```

Если сокет Docker смонтирован внутрь контейнера, любой процесс может запустить новый
привилегированный контейнер и смонтировать корень хоста:

```
$ docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host
```

Это уже полный контроль над хостом.

## Шаг 4: следы на хосте

Смотрим `docker events` и логи демона:

```
$ docker events --since "2026-01-14T03:00" --until "2026-01-14T04:00"
2026-01-14T03:31:05 container create ... image=alpine
2026-01-14T03:31:06 container start ...
```

Создание «левого» контейнера `alpine` с монтированием `/` — вот побег.

## Шаг 5: другие векторы

- **privileged**-контейнер: `--privileged` даёт все capabilities;
- **hostPID/hostNetwork**: видны процессы/сеть хоста;
- **CVE** в runc/containerd (например, CVE-2019-5736) — перезапись `runc` на хосте.

Проверить, был ли контейнер привилегированным, можно по его конфигу:

```
$ docker inspect 3f2a1b --format '{{.HostConfig.Privileged}}'
true
```

## Что мы теперь знаем

- Контейнер делит ядро с хостом; изоляция — это namespaces/cgroups/caps/seccomp.
- `/proc/1/cgroup` и PID 1 выдают контейнер.
- Смонтированный `docker.sock` = побег.
- `docker events` и `docker inspect` фиксируют создание и привилегии контейнеров.
- Privileged/hostPID и CVE runc — другие векторы.

## Если не сработало

- Нет доступа к docker CLI? Читай `/var/log/docker.log` или journald `-u docker`.
- Контейнер уже удалён? Ищи образ и слои в `/var/lib/docker/overlay2`.
- Kubernetes? Смотри audit-лог API-сервера.

## Namespaces по видам

Изоляция контейнера — это набор независимых пространств имён, и каждое скрывает свою
часть системы:

| Namespace | Что изолирует | Где смотреть |
|---|---|---|
| `pid` | список процессов | `/proc/<pid>/ns/pid` |
| `net` | интерфейсы, маршруты, сокеты | `/proc/<pid>/ns/net` |
| `mnt` | точки монтирования | `/proc/<pid>/ns/mnt` |
| `uts` | hostname/domainname | `/proc/<pid>/ns/uts` |
| `ipc` | SysV IPC, POSIX MQ | `/proc/<pid>/ns/ipc` |
| `user` | uid/gid-маппинг | `/proc/<pid>/ns/user` |
| `cgroup` | иерархия cgroups | `/proc/<pid>/ns/cgroup` |

Проверка «в каком namespace находится процесс»:

```
$ ls -l /proc/1/ns/
pid -> 'pid:[4026531836]'
net -> 'net:[4026531840]'
```

Сравни номер с хостом (`ls -l /proc/1/ns/net` на хосте). Совпадение `net` означает,
что контейнер использует **сеть хоста** (`--network host`) — это уже ослабление
изоляции.

## cgroups и определение runtime

Второй слой — cgroups, ограничивающие CPU/память и показывающие, к какому runtime
принадлежит процесс:

```
$ cat /proc/self/cgroup
0::/system.slice/docker-3f2a1b...scope
```

Маркеры runtime:

- `/docker/<id>` или `docker-<id>.scope` — Docker;
- `/kubepods/...` — Kubernetes;
- `/libpod-<id>.scope` — Podman;
- `/lxc/<name>` — LXC.

Дополнительно монтирования выдают контейнер: `/proc/self/mountinfo` покажет
`overlay`/`fuse-overlayfs` для корня и bind-монты из хоста. Присутствие
`/var/lib/docker` внутри — грубая ошибка конфигурации.

## Векторы побега и их следы

Каждый вектор оставляет характерный артефакт на хосте:

| Вектор | Условие | След на хосте |
|---|---|---|
| docker.sock внутрь | смонтирован `/var/run/docker.sock` | новый контейнер в `docker events` |
| `--privileged` | контейнер привилегирован | `docker inspect ... Privileged=true` |
| hostPID/hostNetwork | общие namespace | виден PID 1 хоста, host-интерфейсы |
| hostPath `/` | корень хоста смонтирован | запись в `/etc`, `/root` из контейнера |
| CVE-2019-5736 (runc) | старый runc | перезапись `/usr/bin/runc` на хосте |
| CVE-2022-0492 (cgroups) | cgroup v1 release_agent | аномальная запись в `release_agent` |
| kernel exploit | ядро без патча | паника/root на хосте, `dmesg` |

Проверка привилегий конкретного контейнера:

```
$ docker inspect 3f2a1b --format '{{.HostConfig.Privileged}} {{.HostConfig.PidMode}}'
true host
```

## Пост-эксплуатация и её следы

После побега злоумышленник обычно:

- запускает привилегированный контейнер и монтирует корень хоста
  (`docker run -v /:/host alpine chroot /host`);
- заходит в namespace хоста через `nsenter --target 1 --mount --pid --net`;
- пишет persistence: cron, systemd-unit, ключ в `~/.ssh/authorized_keys` хоста;
- создаёт пользователя в `/etc/passwd` хоста;
- ставит имплант и чистит следы в `docker events`/journald.

Ищи: новые unit-файлы, свежие записи в `/etc/passwd`, изменения `authorized_keys`,
нетипичные образы в `/var/lib/docker`, обрывы в journald.

## Kubernetes-специфика

В кластере векторов больше:

- **service account token** внутри пода (`/var/run/secrets/...`) — доступ к API;
- **privileged pod** — тот же побег, но через манифест;
- **hostPath** в спецификации пода;
- **RBAC-ошибки** — право создавать поды/читать секреты.

Следы — в **audit-логе API-сервера** (`/var/log/kubernetes/audit.log`), где видно, кто
создавал поды и менял RBAC. Это отдельный, очень богатый источник.

## Ограничения

- Без доступа к демону Docker читай `/var/log/docker.log` и `journalctl -u docker`.
- Удалённый контейнер оставляет слои в `overlay2` — их можно разобрать вручную.
- Следы побега на хосте могут быть подчищены — сопоставляй несколько источников.
- Не запускай подозрительные образы «чтобы посмотреть» — только копия/оффлайн-анализ.

## Namespaces детально

Контейнер изолируется набором пространств имён. Каждое можно проверить изнутри:

| Namespace | Флаг | Что изолирует | Признак слабости |
|---|---|---|---|
| PID | CLONE_NEWPID | номера процессов | hostPID → видно PID хоста |
| NET | CLONE_NEWNET | интерфейсы, порты | hostNetwork → сеть хоста |
| MNT | CLONE_NEWNS | точки монтирования | доступ к `/host` |
| UTS | CLONE_NEWUTS | hostname | видно имя хоста |
| IPC | CLONE_NEWIPC | SysV IPC, очереди | общие очереди |
| USER | CLONE_NEWUSER | uid/gid-маппинг | root внутри = root снаружи |
| CGROUP | CLONE_NEWCGROUP | иерархия cgroup | видна иерархия хоста |

Проверка изнутри:

```
$ readlink /proc/self/ns/pid /proc/self/ns/net /proc/self/ns/mnt
$ cat /proc/self/uid_map      # пустой -> не user-namespace
```

Если `/proc/self/ns/net` совпадает с хостовым (нет отдельного net-namespace) — контейнер
с `--network host`.

## Capabilities: что даёт каждое

Docker по умолчанию даёт набор capabilities, но `--privileged` выдаёт **все**. Опасные
для побега:

| Capability | Зачем опасна |
|---|---|
| CAP_SYS_ADMIN | монтирование, `mount`, часть обходов |
| CAP_SYS_PTRACE | чтение памяти процессов хоста |
| CAP_DAC_READ_SEARCH | чтение любых файлов в обход прав |
| CAP_NET_ADMIN | манипуляции сетью, ARP-спуф |
| CAP_SYS_MODULE | загрузка модулей ядра |
| CAP_SYS_RAWIO | прямой доступ к устройствам |

```
$ capsh --print | grep Current
$ grep CapEff /proc/self/status
```

Полный `CapEff: 000001ffffffffff` — это `--privileged`.

## Векторы побега: сводка

| Вектор | Условие | След на хосте |
|---|---|---|
| docker.sock внутрь | сокет смонтирован | create/start в `docker events` |
| privileged + `mount` | `--privileged` | mount в auditd, `/dev` |
| hostPID + ptrace | общий PID-ns | ptrace в auditd |
| hostNetwork + ARP | общая сеть | ARP-аномалии, spoofing |
| CVE-2019-5736 (runc) | старый runc | перезапись `/usr/bin/runc` |
| cgroup release_agent | cgroup v1 + priv | запись в `release_agent` |
| `/proc/sysrq-trigger` | privileged | reboot/dmesg |

Каждый вектор оставляет свой набор артефактов — их и ищут.

## Практический разбор: побег через docker.sock

```
$ ls -la /var/run/docker.sock          # смонтирован внутрь?
$ docker -H unix:///var/run/docker.sock ps -a
$ docker -H unix:///var/run/docker.sock events --since 2026-01-14T03:00
2026-01-14T03:31:05 container create ... image=alpine
2026-01-14T03:31:06 container start ...
```

Признаки побега: создание контейнера `alpine`/`busybox` с `-v /:/host`, короткое время
жизни, запуск из необычного родителя. Проверяем привилегии:

```
$ docker inspect <id> --format '{{.HostConfig.Privileged}} {{.HostConfig.PidMode}} {{.HostConfig.Binds}}'
true host [/:/host]
```

## Следы на хосте

- **`/var/lib/docker/overlay2/`** — слои; удалённый контейнер можно частично
  восстановить по diff-слоям.
- **journald**: `journalctl -u docker --since ...` — create/start/die с образами.
- **auditd**: правила на `mount`, `ptrace`, `init_module` покажут сам побег.
- **`/etc/crontab`, systemd-юниты** — персистентность после побега.
- **Файлы, изменённые вне контейнера** — по overlay-diff видно, что «вылезло» наружу.

## Чек-лист

1. Убедиться, что процесс в контейнере (`/proc/1/cgroup`, PID 1).
2. Проверить namespaces и capabilities.
3. Проверить, смонтирован ли `docker.sock` и привилегии контейнера.
4. Собрать `docker events` / journald за окно инцидента.
5. Найти аномальные контейнеры и их монтирования.
6. Проверить персистентность на хосте (cron, units, ключи).
7. Для Kubernetes — audit-лог API-сервера (`exec`, `create pods`).

## Как отличить контейнер от хоста

Прежде чем говорить о побеге, нужно доказать, что процесс **был** в контейнере.
Признаки, которые проверяют по отдельности и вместе:

| Признак | Контейнер | Хост |
|---|---|---|
| PID 1 | приложение | `systemd`/`init` |
| `/proc/1/cgroup` | `docker`/`kubepods` | `system.slice` |
| `/` монтирование | `overlay`/`fuse` | `ext4`/`xfs` |
| число процессов | единицы | десятки |
| `/.dockerenv` | существует | нет |
| `/proc/self/mountinfo` | много bind-монтов | обычные ФС |

Простая проверка:

```
$ [ -f /.dockerenv ] && echo container
$ awk '$5=="overlay" || $5=="fuse-overlayfs"' /proc/self/mountinfo
```

Но помни: эти маркеры можно **подделать** (создать `/.dockerenv`, примонтировать
overlay), поэтому вывод делается по совокупности, а не по одному файлу.

## CVE-2019-5736: побег через runc

Этот вектор стоит разобрать детально, потому что он оставил много следов в реальных
инцидентах. Уязвимость позволяла перезаписать бинарник `runc` на **хосте** из
контейнера:

1. Контейнер открывает `/proc/self/exe` (это и есть `runc`).
2. Заменяет его на полезную нагрузку.
3. При следующем запуске контейнера хост исполняет подменённый `runc` от root.

Следы на хосте:

```
$ ls -la /usr/bin/runc
-rwxr-xr-x 1 root root 9876543 Jan 14 03:35 /usr/bin/runc   # свежая дата
$ sha256sum /usr/bin/runc   # не совпадает с пакетом
$ dpkg -V runc || rpm -V runc   # проверка целостности пакета
```

Проверка целостности пакетного менеджера (`dpkg -V`/`rpm -V`) — быстрый способ найти
подменённый бинарник. Также смотри `dmesg` и журналы containerd на предмет аномалий.

## Где лежат метаданные runtime

Чтобы восстановить события, нужно знать, где runtime хранит данные:

- **Docker**: `/var/lib/docker/` (образы, слои, контейнеры), `docker events`;
- **containerd**: `/var/lib/containerd/`, `ctr` и namespace;
- **Podman**: `/var/lib/containers/storage/`, rootless-конфиги в `~/.config/containers/`;
- **Kubernetes**: `/var/log/pods/`, `/var/lib/kubelet/`, audit-лог API.

Метаданные контейнера (даже удалённого) читаются из `config.v2.json`:

```
$ cat /var/lib/docker/containers/<id>/config.v2.json | jq '.Config.Image, .HostConfig.Privileged'
```

Даже если контейнер удалён, слои `overlay2` могут остаться — по ним восстанавливают,
что выполнялось.

## Таймлайн и корреляция

Побег — это последовательность событий, и её надо выстроить по времени:

1. **Создание контейнера** — `docker events` / audit-лог.
2. **Признаки ослабления** — `privileged`, `hostPID`, монтирование сокета.
3. **Действие побега** — запуск привилегированного контейнера, `nsenter`, CVE-триггер.
4. **Персистентность** — cron/systemd/ключи на хосте.
5. **Сокрытие** — чистка логов демона.

Сопоставляй три независимых источника: журнал демона, journald хоста и файловую
систему (слои, изменённые файлы). Расхождение между ними — признак подчистки.

## Инструменты

- `docker events`, `docker inspect`, `docker logs` — штатные;
- `ctr`, `crictl`, `kubectl` — для containerd/Kubernetes;
- `sysdig`/`falco` — поведенческие детекты (создание контейнера, mount хоста);
- `nsenter` — вход в namespace (в т.ч. для верификации побега);
- `journalctl -u docker -u containerd` — системные логи;
- `dive` — разбор слоёв образа.

Типовая проверка конфигурации контейнера на ослабления:

```
$ docker inspect <id> --format '{{json .HostConfig}}' | jq '{Privileged,PidMode,NetworkMode,Binds}'
```

## Дополнительные ограничения анализа

- Следы побега на хосте можно подчистить — проверяй целостность логов.
- `docker events` хранит историю ограниченно; для длинной ретроспективы нужен auditd.
- В rootless-контейнерах пути и владельцы другие — не путай с хостом.
- Не запускай подозрительный образ для «проверки» — используй `dive` и оффлайн-слои.

## Квиз

Проверь себя.

```quiz
- question: Почему контейнер — не виртуальная машина?
  options:
    - 'он медленный'
    - 'он использует общее ядро с хостом'
    - 'он не умеет сеть'
    - 'он только для Windows'
  answer: 1
  explanation: 'Контейнеры изолируют пространства имён, но ядро общее — отсюда векторы побега.'
- question: Что означает /proc/1/cgroup со строкой /docker/<id>?
  options:
    - 'процесс на хосте'
    - 'процесс находится в контейнере Docker'
    - 'процесс в ядре'
    - 'это swap'
  answer: 1
  explanation: 'cgroup-путь с /docker/ указывает на контейнер.'
- question: Чем опасен смонтированный внутрь docker.sock?
  options:
    - 'занимает место'
    - 'позволяет запустить привилегированный контейнер и смонтировать хост'
    - 'ускоряет сеть'
    - 'ничем'
  answer: 1
  explanation: 'Доступ к сокету Docker = контроль над демоном и хостом.'
- question: Где искать следы создания «левого» контейнера?
  options:
    - 'в /etc/hosts'
    - 'в docker events / логах демона'
    - 'в /proc/meminfo'
    - 'в /etc/passwd'
  answer: 1
  explanation: 'Docker логирует create/start с образом и временем.'
```
