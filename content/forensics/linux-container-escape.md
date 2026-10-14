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
