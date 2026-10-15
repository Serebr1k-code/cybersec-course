---
id: misc-crun-podman
title: 'crun и podman: rootless-контейнеры и побег'
category: misc
parent: misc-sandbox-containers-hub
difficulty: expert
order: 4
tags: [crun, podman, oci, rootless, user-namespace, escape, container]
prerequisites: [misc-sandbox-containers-hub]
useful_for:
  - 'CTF misc: sandbox-escape'
  - 'Аудит контейнерных рантаймов'
  - 'Понимание rootless-контейнеров'
estimated_minutes: 31
summary: 'OCI-рантаймы crun и runc, rootless-контейнеры podman на user namespaces, почему это безопаснее и где остаются векторы побега (privileged, монтирования, capabilities, docker.sock).'
lab:
  kind: shell
  title: 'Практика: инспекция контейнера podman'
  toolset: [core]
  workdir: /home/student/task
  files: [task.md, podman_inspect.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Шаг из пути: сначала прочитай вывод инспекции, как разбирали изоляцию в `misc-sandbox-containers-hub`: `cat podman_inspect.txt`.'
    - 'Строки имеют вид `поле=значение`; значение строки `flag` — это base64.'
    - 'Вырежи и раскодируй: `grep flag podman_inspect.txt | cut -d= -f2 | base64 -d > found.txt`.'
---

## Вопрос, с которого всё начинается

Ты запускаешь контейнер от обычного пользователя — без `sudo` — и он работает. Как это возможно, ведь контейнер требует изоляции, а изоляция исторически требовала root? Ответ — **rootless-контейнеры** на user namespaces, и рантаймы вроде **crun** с менеджером **podman**. Разберём, как это устроено и где всё ещё можно «выйти».

## Наш пример: вывод podman inspect

```
$ cat podman_inspect.txt
runtime=crun
rootless=true
userns=host->container:0:65536
privileged=false
cap_add=[]
mounts=/host-data:/data:rw
```

Здесь видно: рантайм `crun`, режим rootless, маппинг пользователей и — подозрительное — общий том с хоста. Разберём по порядку.

## Шаг 1: OCI-рантайм

**OCI** (Open Container Initiative) — стандарт формата контейнера и его запуска. **Рантайм** — программа, которая по этому стандарту создаёт контейнер: namespaces, cgroups, монтирования, запуск процесса. Классический рантайм — `runc`; более новый и лёгкий — `crun` (написан на C). Оба совместимы с OCI, поэтому взаимозаменяемы.

## Шаг 2: crun против runc

- `runc` — референсный рантайм на Go, используется Docker по умолчанию;
- `crun` — быстрый рантайм на C, часто в podman; меньше памяти, быстрее старт.

С точки зрения безопасности разница невелика: оба используют одни механизмы ядра. Важнее **конфигурация**, чем имя рантайма.

## Шаг 3: rootless и user namespaces

**Rootless** означает, что контейнер запускается без прав root на хосте. Работает это через **user namespace**: внутри контейнера процесс может быть UID 0 (root), но этот «root» маппится на обычного пользователя хоста (`userns=host->container:0:65536`). Даже если внутри ты root — снаружи ты никто. Это сильно уменьшает ущерб от побега.

## Шаг 4: podman

**podman** — менеджер контейнеров, работающий без демона и по умолчанию rootless. В отличие от Docker (демон с правами root), podman запускает контейнеры от имени пользователя. Это убирает классический риск «демон — единая точка отказа».

## Шаг 5: векторы побега

Даже rootless-контейнер может «протечь»:

- **privileged** — если контейнер запущен с `--privileged`, изоляция почти снята;
- **общие монтирования** — том `/host-data:/data:rw` даёт доступ к хостовым файлам;
- **capabilities** — лишние возможности (`cap_add`) расширяют права;
- **docker.sock / podman.sock** — если сокет смонтирован в контейнер, ты можешь управлять контейнерами хоста;
- **user namespace без ограничений** — старые ядра позволяли эскалацию через userns.

## Шаг 6: практический порядок

1. Определить рантайм и режим (rootless/rootful).
2. Посмотреть маппинг user namespace.
3. Проверить `privileged` и `cap_add`.
4. Проверить монтирования (особенно хостовые пути).
5. Искать смонтированные сокеты (`.sock`) — это прямой путь на хост.

## Что мы теперь знаем

- OCI-рантайм создаёт контейнер по стандарту; `runc` и `crun` взаимозаменяемы.
- Rootless работает через user namespaces: root внутри ≠ root снаружи.
- podman запускает контейнеры без демона и по умолчанию rootless.
- Векторы: privileged, общие тома, capabilities, смонтированный сокет.
- Безопасность определяется конфигурацией, а не только рантаймом.

## Квиз

Проверь себя.

```quiz
- question: Как rootless-контейнер запускается без root?
  options:
    - Через user namespace: root внутри маппится на обычного пользователя
    - Через отключение изоляции
    - Через сеть
    - Через шифрование
  answer: 0
  explanation: userns даёт «фальшивый» root.
- question: Чем podman отличается от Docker?
  options:
    - Работает без демона и по умолчанию rootless
    - Не поддерживает контейнеры
    - Требует root всегда
    - Это язык программирования
  answer: 0
  explanation: Нет привилегированного демона.
- question: Что такое crun?
  options:
    - OCI-рантайм на C, часто в podman
    - Менеджер пакетов
    - Гипервизор
    - Сетевой протокол
  answer: 0
  explanation: Совместим с runc.
- question: Какой смонтированный файл даёт прямой путь на хост?
  options:
    - docker.sock или podman.sock
    - /etc/hostname
    - /dev/null
    - /proc/uptime
  answer: 0
  explanation: Через сокет управляют контейнерами хоста.
```

## Куда дальше

На этом модуль контейнеров заканчивается. Дальше — `misc-barcode-formats`: разберём форматы штрихкодов. А пока запомни: **rootless безопаснее, но privileged, общие тома и сокеты всё равно ведут на хост**.

## Где пригодится

- **CTF misc**: escape из контейнера.
- **Аудит**: проверка конфигурации рантайма.
- **DevOps**: безопасные rootless-сборки.
- **Cloud**: изоляция нагрузок.
