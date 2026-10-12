---
id: misc-kernel-misc-deep
title: "Ядро и системные вызовы в misc"
category: misc
parent: misc-runtime-more
difficulty: hard
order: 3
tags: [kernel, syscall, seccomp, namespaces, capabilities, linux]
prerequisites: [misc-sandbox, misc-runtime-more]
useful_for:
  - "CTF misc/pwn: sandbox и syscall-задачи"
  - "Побег из контейнера"
  - "Понимание изоляции процессов"
estimated_minutes: 50
summary: "Ядро и системные вызовы: seccomp, namespaces, cgroups, /proc и /sys, capabilities, побег из изоляции, инструменты и разборы."
---

## Вопрос, с которого всё начинается

Тебе дают бинарник `challenge`. Он ставит **seccomp** — фильтр системных вызовов — и разрешает только `read`, `write` и `exit`. Ты пытаешься открыть `/flag` — «operation not permitted». Запустить шелл нельзя, `open` запрещён. Кажется, задача нерешаема. Но флаг уже лежит **внутри** процесса: его открыли до того, как включили фильтр. Задача — понять, как программа разговаривает с ядром и как обойти изоляцию.

Разберём низкоуровневую misc-задачу целиком.

## Наш пример: sandbox с фильтром syscall

Программа не трогает диск и сеть напрямую — она просит ядро через **системные вызовы** (syscalls): `openat`, `read`, `write`, `execve`, `socket`. Ядро — единственный посредник между программой и железом. **Изоляция** строится из трёх механизмов: **seccomp** (какие syscall разрешены), **namespaces** (какие ресурсы видны) и **capabilities** (какие привилегии есть). Наша задача использует первый.

## Шаг 1: смотрим состояние процесса

Первое — понять, что вообще включено. Ядро отдаёт это через `/proc/self/status`:

```bash
$ cat /proc/self/status | grep -E 'Seccomp|NoNewPrivs'
Seccomp: 2
Seccomp_filters: 1
NoNewPrivs: 0
```

`Seccomp: 2` означает «активен фильтр». `NoNewPrivs: 0` — привилегии поднять нельзя, но и не заблокировано. Теперь надо увидеть **сам фильтр**.

## Шаг 2: дампим фильтр

Утилита `seccomp-tools` переводит BPF-программу фильтра в читаемый вид:

```bash
$ seccomp-tools dump ./challenge
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x01 0x00 0x00000000  if (A == read) goto 0006
 0004: 0x15 0x01 0x00 0x00000001  if (A == write) goto 0006
 0005: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0006
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x00050000  return ERRNO(0)
```

Читаем: разрешены только `read` (0), `write` (1) и `exit` (60); всё остальное — ошибка. Значит, `open`/`openat` недоступны, шелл не запустить. Но фильтр не может запретить читать то, что **уже открыто**.

## Шаг 3: флаг уже открыт — /proc/self/fd

Дескрипторы (fd) открытых файлов процесса видны в `/proc/self/fd`. Вот как это выглядит для обычного процесса:

```bash
$ ls -l /proc/self/fd/
lrwx------ 1 user user 64 ... 0 -> /dev/null
lrwx------ 1 user user 64 ... 1 -> pipe:[12345]
lrwx------ 1 user user 64 ... 2 -> socket:[67890]
lr-x------ 1 user user 64 ... 3 -> /flag
```

Дескриптор `3` ведёт на `/flag`. Программа открыла его до применения фильтра, и теперь нам достаточно прочитать `read(3, buf, n)` и вывести `write(1, buf, n)` — оба вызова разрешены. В pwntools это делается shellcode'ом или ROP: `read` из fd 3 и `write` в stdout. Это классика seccomp-задач: **«сложный» sandbox обходится уже открытым дескриптором**.

## Шаг 4: namespaces — изоляция ресурсов

Второй механизм — **namespaces**. Они «отрезают» процессу часть мира: `pid` (номера процессов), `net` (сеть), `mnt` (монтирования), `user` (uid/gid), `uts`, `ipc`, `cgroup`. Смотрим, в каких namespace мы находимся:

```bash
$ ls -l /proc/self/ns/
lrwxrwxrwx ... mnt  -> mnt:[4026531832]
lrwxrwxrwx ... net  -> net:[4026531833]
lrwxrwxrwx ... pid  -> pid:[4026531836]
lrwxrwxrwx ... user -> user:[4026531837]
```

Числа в скобках — inode namespace'ов. Если `net` совпадает с хостом — мы в хост-сети; если `pid` общий — видим процессы хоста. Контейнер — это просто процесс в наборе своих namespace'ов.

## Шаг 5: capabilities — дробление root

Третий механизм — **capabilities**: права root разбиты на отдельные «кнопки». `CAP_SYS_ADMIN` разрешает монтирование и работу с cgroup, `CAP_DAC_READ_SEARCH` — чтение любых файлов в обход прав, `CAP_NET_RAW` — сырые сокеты. Смотрим:

```bash
$ grep Cap /proc/self/status
CapEff: 0000000000000000
$ getcap -r / 2>/dev/null
/usr/bin/ping cap_net_raw=ep
```

Если у бинарника есть, например, `cap_setuid+ep`, он может стать root — классический локальный privesc. Даже без полного root отдельные capabilities дают утечки.

## Шаг 6: побег из контейнера

Слабые конфигурации контейнера позволяют выйти на хост:

- **privileged** — доступ к устройствам: монтируем диск хоста;
- **общий pid namespace** — `nsenter -t 1 -m -u -i -n -p`;
- **docker.sock смонтирован** — создаём привилегированный контейнер;
- **`CAP_SYS_ADMIN`** — монтируем cgroup, применяем известные техники.

```bash
$ docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine
$ cat /host/root/flag
FLAG{kernel_escape}
```

В CTF контейнерные задачи проверяют именно понимание namespaces и capabilities. Подробнее — в `misc-docker-misc` и `misc-namespace-escape`.

## Шаг 7: трассируем системные вызовы

Понять, что программа реально просит у ядра, помогает `strace` — она печатает каждый системный вызов:

```bash
$ strace -f ./challenge 2>&1 | tail -8
openat(AT_FDCWD, "/flag", O_RDONLY) = 3
read(0, "", 64)                       = 0
write(1, "password: ", 10)            = 10
read(3, "FLAG{...", 64)               = 9
```

Здесь сразу видно: программа **сама открыла** `/flag` (получила fd 3) до того, как включила фильтр. Если вызов упирается в `EPERM` или `Operation not permitted` — именно этот syscall и запрещён seccomp. Трассировка — самый быстрый способ найти «уже открытый дескриптор» и понять, какой вызов блокируется.

## Что мы теперь знаем

- Программы общаются с железом только через **системные вызовы** ядра.
- **seccomp** ограничивает набор syscall; смотри `Seccomp: 2` в `/proc/self/status` и дамп через `seccomp-tools`.
- Если разрешены только `read`/`write`, ищи **уже открытый дескриптор** в `/proc/self/fd`.
- **namespaces** изолируют pid, сеть, монтирования и др.; сравнивай inode'ы.
- **capabilities** — дробление root; `CAP_SYS_ADMIN` почти всегда путь к побегу.
- Слабые конфигурации контейнера (privileged, общий pid, docker.sock) дают доступ к хосту.

## На что смотреть дальше

Порядок для низкоуровневой задачи: `/proc/self/status` (seccomp, caps) → `/proc/self/fd` (открытые файлы) → дамп фильтра → построение обхода. Если получаешь «operation not permitted» — скорее всего, seccomp запретил syscall; `strace -f ./bin` покажет, на каком именно (`EPERM`). Держи под рукой `strace`, `seccomp-tools`, `capsh`, `getcap`. Дальше — `misc-reversing-misc` и подветка контейнеров. И помни: три механизма изоляции — seccomp, namespaces и capabilities — работают вместе, поэтому смотри все три, а не только тот, о котором сказано в условии.

## Квиз

Проверь себя.

```quiz
- question: "Что ограничивает seccomp?"
  options:
    - "набор разрешённых системных вызовов"
    - "объём оперативной памяти"
    - "размер диска"
    - "пропускную способность сети"
  answer: 0
  explanation: "BPF-фильтр решает судьбу каждого syscall."
- question: "Где посмотреть открытые дескрипторы процесса?"
  options:
    - "/proc/self/fd/"
    - "/etc/passwd"
    - "/var/log"
    - "/tmp"
  answer: 0
  explanation: "Это симлинки на открытые файлы процесса."
- question: "Что такое capabilities?"
  options:
    - "дробление привилегий root на отдельные права"
    - "тип файловой системы"
    - "сетевой протокол"
    - "формат архива"
  answer: 0
  explanation: "Например, CAP_SYS_ADMIN и CAP_DAC_READ_SEARCH."
- question: "Какой инструмент дампит seccomp-фильтр?"
  options:
    - "seccomp-tools"
    - "nmap"
    - "hashcat"
    - "binwalk"
  answer: 0
  explanation: "Команда seccomp-tools dump показывает BPF-программу."
- question: "Что делать, если разрешены только read и write, а open запрещён?"
  options:
    - "искать уже открытый дескриптор флага в /proc/self/fd"
    - "сдаться, задача нерешаема"
    - "перезагрузить машину"
    - "запустить nmap"
  answer: 0
  explanation: "Флаг часто открыт до применения фильтра."
```

## Куда дальше

В следующем уроке `misc-reversing-misc` мы разберём, как понять логику незнакомого бинарника: дизассемблирование, трассировка и поиск проверок. А пока главное запомни: **изоляция — это фильтр syscall, набор namespace'ов и capabilities**, и дыра почти всегда там, где один из них настроен слабо.

## Где пригодится

- **CTF pwn/misc** — sandbox и syscall-задачи.
- **Контейнеры** — побег из изоляции.
- **Работа** — аудит привилегий и изоляции процессов.
- **Эксплуатация** — локальный privesc через capabilities.
