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

## Что такое ядро и системные вызовы

Ядро — посредник между программами и железом. Программа не может напрямую трогать диск или сеть; она просит ядро через **системные вызовы** (`read`, `write`, `openat`, `execve`, `socket`, …). В CTF это встречается в задачах на sandbox (seccomp), побег из контейнера (namespaces) и низкоуровневые утилиты.

## Seccomp

**Seccomp** ограничивает набор системных вызовов, доступных процессу. Часто в CTF-песочницах разрешены только `read`/`write`/`exit`, а `execve`/`openat` запрещены. Проверить фильтр можно через `/proc/self/status` (`Seccomp: 2`) и инструмент `seccomp-tools`:

```bash
seccomp-tools dump ./challenge
# 0000: 0x20 0x00 0x00 0x00000004  A = arch
# ...
```

Если `execve` запрещён, шелл не запустить — приходится читать флаг через уже открытые дескрипторы (`openat` флага до применения фильтра) или через `open`+`read`+`write`, если они разрешены.

## Namespaces и cgroups

**Namespaces** изолируют процессы друг от друга: `pid`, `net`, `mnt`, `user`, `uts`, `ipc`, `cgroup`. Контейнер — это процесс в наборе namespaces. Проверить:

```bash
ls -l /proc/self/ns/
unshare --help
```

**cgroups** ограничивают ресурсы (CPU, память). Слабости в конфигурации (например, привилегированный контейнер, общий `pid` namespace) позволяют «увидеть» и атаковать хост.

## /proc и /sys

Это псевдо-файловые системы, через которые ядро отдаёт информацию:

```bash
cat /proc/self/maps     # карта памяти
cat /proc/self/status   # состояние, seccomp, capabilities
ls /proc/self/fd/       # открытые дескрипторы
cat /sys/kernel/...     # параметры ядра
```

Частый приём в misc: флаг лежит в открытом дескрипторе (`/proc/self/fd/3`) или в `/proc/<pid>/environ`.

## Capabilities

Linux разбивает права root на **capabilities**: `CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_DAC_READ_SEARCH` и др. Даже не-root процесс с `CAP_DAC_READ_SEARCH` может читать любые файлы.

```bash
getcap -r / 2>/dev/null
capsh --print
```

Если у бинарника есть `cap_setuid+ep`, он может стать root — классика локального privesc.

## Инструменты

- **seccomp-tools** — дамп и анализ BPF-фильтров.
- **strace** — трассировка системных вызовов.
- **ltrace** — трассировка библиотечных вызовов.
- **unshare / nsenter** — работа с namespaces.
- **capsh / getcap** — capabilities.
- **/proc, /sys** — ручной осмотр.

## Разобранный пример

Дано: программа ставит seccomp и просит ввод. Нужно прочитать `/flag`.

```bash
seccomp-tools dump ./challenge | grep -E 'open|execve|read|write'
```

Если `open` разрешён, а `execve` — нет, открываем флаг сами и выводим через `write`. Если всё запрещено кроме `read/write`, ищем уже открытый дескриптор:

```bash
ls -l /proc/self/fd/
cat /proc/self/fd/3
```

## Частые ошибки и подводные камни

- **Считать seccomp непреодолимым.** Часто разрешены `open`/`read`/`write` — этого достаточно.
- **Забыть про уже открытые fd.** Флаг может быть в дескрипторе.
- **Путать namespace с chroot.** Это разные механизмы изоляции.
- **Игнорировать capabilities.** `CAP_SYS_ADMIN` даёт огромные возможности.
- **Не проверить `/proc/self/status`.** Там видно seccomp и caps.

## Справочная таблица

| Механизм | Назначение |
|----------|-----------|
| seccomp | фильтр syscall |
| namespaces | изоляция ресурсов |
| cgroups | лимиты ресурсов |
| capabilities | дробление root |
| `/proc/self/fd` | открытые дескрипторы |
| `seccomp-tools` | дамп фильтра |

## Что дальше / решение

1. Проверьте `Seccomp` в `/proc/self/status` и capabilities.
2. Дампните фильтр `seccomp-tools dump`.
3. Определите, какие syscall разрешены; постройте обход (open+read+write).
4. Проверьте открытые дескрипторы на флаг.
5. Для контейнера — оцените namespaces и caps на побег.

## Syscall-фильтры и их обход

Seccomp-фильтр задаётся BPF-программой, которая для каждого syscall решает: разрешить, запретить (`EPERM`), убить процесс (`SECCOMP_RET_KILL`). Частые схемы в CTF:

- разрешены только `read`/`write`/`exit` — тогда нельзя открыть файл, но можно читать из уже открытого fd;
- разрешён `openat`, но запрещён `execve` — читаем флаг сами;
- проверка номера syscall, но не аргументов — обходим через другие вызовы.

```bash
seccomp-tools dump ./challenge
# смотрим, какие syscall разрешены и с какими аргументами
```

Если `open`/`openat` разрешены, а `execve` — нет, просто открываем `/flag` и выводим через `write` (в pwntools — через shellcode или `open`+`read`+`write` ROP).

## Побег из контейнера: практика

Слабые конфигурации контейнера позволяют выйти на хост:

- **privileged** — доступ к устройствам хоста; монтируем `/dev` и читаем диск;
- **общий pid namespace** — `nsenter -t 1 -m -u -i -n -p`;
- **docker.sock смонтирован** — через него создаём привилегированный контейнер;
- **`CAP_SYS_ADMIN`** — монтируем cgroup, используем известные техники escape.

```bash
# пример: проброс хостового корня через privileged
mkdir /tmp/host && mount /dev/sda1 /tmp/host
cat /tmp/host/root/flag
```

В CTF контейнерные задачи проверяют именно понимание namespaces и capabilities.

## Инструменты для низкого уровня

- **seccomp-tools** — дамп фильтра.
- **strace -f -e trace=...** — какие syscall делает программа.
- **/proc/self/{maps,status,fd,environ}** — состояние процесса.
- **capsh --print / getcap -r /** — capabilities.
- **unshare/nsenter** — работа с namespaces.

## Частые вопросы по ядру

- **Флаг не читается, «operation not permitted»?** Скорее всего, seccomp запретил syscall — ищите обход.
- **Как понять, что запрещено?** `strace` покажет `EPERM` на конкретном вызове.
- **Контейнер или хост?** `ls /proc/self/ns`, `cat /proc/1/cgroup`.
- **Есть CAP_SYS_ADMIN?** Это почти всегда путь к побегу.

## Мини-шпаргалка ядра

```bash
cat /proc/self/status          # Seccomp, Capabilities
ls -l /proc/self/ns/           # namespaces
ls -l /proc/self/fd/           # открытые дескрипторы
seccomp-tools dump ./bin       # фильтр syscall
strace -f ./bin                # трассировка
capsh --print; getcap -r /     # capabilities
```

## Итог по ядру

Низкоуровневые misc-задачи проверяют понимание изоляции: seccomp ограничивает syscall, namespaces — ресурсы, capabilities — привилегии. Первым делом смотрите `/proc/self/status` и `fd`; затем дампните seccomp-фильтр. Часто флаг уже открыт в дескрипторе, а «сложный» sandbox обходится разрешёнными `open`/`read`/`write`. Для контейнеров ищите слабые места (privileged, общий pid ns, docker.sock) — это прямой путь на хост.

## Кейс: sandbox только с read/write

Дано: программа под seccomp, разрешены только `read`, `write`, `exit`. Открыть файл нельзя, но флаг уже открыт — в дескрипторе.

```bash
ls -l /proc/self/fd/
# lrwx------ ... 0 -> /dev/pts/0
# lr-x------ ... 3 -> /flag
cat /proc/self/fd/3
```

Если программа сама открыла флаг до фильтра, остаётся прочитать его через `read(3)`/`write(1)`. Это классика seccomp-задач.

## Кейс: побег через docker.sock

Дано: контейнер с примонтированным `/var/run/docker.sock`. Создаём привилегированный контейнер и читаем хост:

```bash
docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine
cat /host/root/flag
```

Так «побег» из контейнера превращается в доступ к файловой системе хоста.

## Итог по ядру

Низкоуровневые misc-задачи проверяют изоляцию: seccomp (какие syscall разрешены), namespaces (какие ресурсы изолированы) и capabilities (какие привилегии есть). Первым делом смотрите `/proc/self/status` и `/proc/self/fd`; затем дампните seccomp-фильтр. Часто флаг уже открыт, а «сложный» sandbox обходится разрешёнными `open`/`read`/`write`. Для контейнеров ищите privileged, общий pid namespace и docker.sock — это прямые пути на хост.

## Квиз

```quiz
- question: "Что ограничивает seccomp?"
  options:
    - "Набор разрешённых системных вызовов"
    - "Память"
    - "Диск"
    - "Сеть"
  answer: 0
  explanation: "BPF-фильтр syscall."
- question: "Где посмотреть открытые дескрипторы процесса?"
  options:
    - "/proc/self/fd/"
    - "/etc/passwd"
    - "/var/log"
    - "/tmp"
  answer: 0
  explanation: "Симлинки на открытые файлы."
- question: "Что такое capabilities?"
  options:
    - "Дробление привилегий root на отдельные права"
    - "Тип файловой системы"
    - "Протокол"
    - "Формат архива"
  answer: 0
  explanation: "CAP_SYS_ADMIN и др."
- question: "Какой инструмент дампит seccomp-фильтр?"
  options:
    - "seccomp-tools"
    - "nmap"
    - "hashcat"
    - "binwalk"
  answer: 0
  explanation: "seccomp-tools dump."
```

## Где пригодится

- **CTF pwn/misc:** sandbox и syscall-задачи.
- **Контейнеры:** побег из изоляции.
- **Работа:** аудит привилегий и изоляции.
- **Эксплуатация:** локальный privesc через caps.
