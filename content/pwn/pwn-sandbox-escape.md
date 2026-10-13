---
id: pwn-sandbox-escape
title: "Побег из песочницы: seccomp, nsjail, контейнеры"
category: pwn
parent: pwn-kernel-modern
difficulty: expert
order: 5
tags: [sandbox, seccomp, nsjail, container, escape, capabilities]
prerequisites: [pwn-kernel-smep-smap]
useful_for:
  - "CTF Pwn — песочницы и escape"
  - "Пентест — выход из контейнера"
estimated_minutes: 60
summary: "Виды песочниц, обход seccomp через ORW и user-notify, escape из nsjail/firejail и контейнеров (docker.sock, privileged, capabilities)."
lab:
  kind: shell
  title: "Практика: разбор seccomp-фильтра"
  toolset: [core, hex]
  workdir: /home/student/task
  files: [task.md, filter.bpf, seccomp.py]
  check: "grep -q 'allowed=0,1,2,60' answer.txt"
  hints:
    - "`xxd filter.bpf` — записи по 8 байт (`struct sock_filter`)."
    - "`python3 seccomp.py filter.bpf` декодирует фильтр."
    - "Интерпретатор прогоняет номера syscall и печатает разрешённые."
---

## Вопрос, с которого всё начинается

Даже получив выполнение кода (RCE) внутри песочницы, вы не всегда можете прочитать флаг: окружение ограничено. Песочница может запрещать системные вызовы, изолировать файловую систему или запускать вас в контейнере. Значит, после RCE нужен второй шаг — **побег из песочницы**. Сегодня разберём, какие бывают песочницы и как из них выходить.

## Наш пример: проверяем окружение

Прежде чем что-то делать, надо понять, в каком окружении мы находимся. Посмотрим статус процесса:

```
$ grep -E "Seccomp|CapEff" /proc/self/status
CapEff:	0000000000000000
Seccomp:	0
Seccomp_filters:	0
$ ls -l /proc/self/ns/ | awk '{print $NF}' | tr '\n' ' '
cgroup:[...] ipc:[...] mnt:[...] net:[...] pid:[...] time:[...] user:[...] uts:[...]
$ ls -la /.dockerenv
ls: cannot access '/.dockerenv': No such file or directory
$ head -1 /proc/1/cgroup
0::/init.scope
```

Читаем:

- `Seccomp: 0` — фильтра системных вызовов **нет**. Значит, мы не ограничены `seccomp` (в отличие от типичной CTF-песочницы).
- `CapEff: 0` — эффективных capabilities нет.
- Список namespaces показывает стандартные init-namespace'ы (`pid:[4026531836]`, `mnt:[4026531832]` и т.д.) — это не изолированное окружение.
- Отсутствие `/.dockerenv` и cgroup `/init.scope` подтверждают: мы на хосте, не в контейнере.

Это базовый «разведочный» шаг: понять, какая песочница перед нами.

## Шаг 1. Виды песочниц

| Песочница | Механизм | Типичный escape |
|---|---|---|
| `seccomp` | BPF-фильтр syscall'ов | ORW / баги user-notify |
| `nsjail` | namespaces + seccomp | неправильно разрешённые syscall'ы |
| `chroot` | изоляция ФС | `chdir`+`chroot`, открытые fd |
| Docker | namespaces + cgroups | `docker.sock`, privileged, ядерные баги |

Разные песочницы требуют разных подходов. `seccomp` ограничивает **что можно вызвать**, namespaces — **что видно**, контейнеры — комбинация.

## Шаг 2. seccomp и ORW

`seccomp` устанавливает BPF-программу, фильтрующую syscall'ы. Типичная CTF-задача: разрешены только `read`, `write`, `open`, `exit` — так называемый **ORW** (open-read-write). `execve` запрещён, поэтому запустить `/bin/sh` нельзя.

Это не «обход», а **адаптация** под фильтр: вместо шелла мы открываем флаг, читаем и пишем в stdout. В ROP-цепочке это выглядит так:

```python
from pwn import *
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi','ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx','ret'])[0]
buf = elf.bss(0x100)
chain  = flat(pop_rdi, flag_addr, pop_rsi, 0, elf.plt['open'])
chain += flat(pop_rdi, 3, pop_rsi, buf, pop_rdx, 0x100, elf.plt['read'])
chain += flat(pop_rdi, 1, pop_rsi, buf, pop_rdx, 0x100, elf.plt['write'])
```

Обрати внимание: `open` возвращает дескриптор в `rax` (обычно 3), и его подставляют в `read`.

## Шаг 3. Как узнать фильтр

Первым делом — посмотреть фильтр:

```
$ seccomp-tools dump ./chall
```

Утилита `seccomp-tools` (ставится отдельно) показывает, какие syscall'ы разрешены и запрещены. Без этого можно потратить время на обход того, что и так разрешено. Полезно помнить: иногда `open` запрещён, а `openat` — нет; иногда разрешены `sendfile`/`splice`. Всегда проверяйте конкретный список.

Разберём, как выглядит вывод `seccomp-tools` и что из него следует. Типичный фильтр печатает строки вида:

```text
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x02 0xffffffff  if (A != 0xffffffff) goto 0007
 ...
```

Читать это по-человечески просто: программа загружает номер syscall'а в аккумулятор `A` и сравнивает его с константами. Если номер совпадает с разрешённым — возвращается `ALLOW`, иначе `KILL`/`ERRNO`. Практический вывод для нас: выписать список разрешённых номеров (например, `0` = `read`, `1` = `write`, `2` = `open`) и убедиться, что нужный вызов в него входит. Если `execve` (`59`) запрещён — шелл не запустить, значит, строим ORW.

Отдельно стоит сказать про `nsjail` и `firejail`. `nsjail` запускает процесс в изолированных namespace'ах с фильтром syscall'ов. Escape возможен через уязвимости в самом `nsjail`, через неправильно разрешённые syscall'ы (например, `mount`, `unshare`) или через ядерные баги. `firejail` — аналогично, но с известной историей SUID-багов: неправильная работа с правами в SUID-бинаре давала повышение привилегий. Изучайте **конфигурацию** песочницы: какие namespaces и capabilities доступны, какие пути смонтированы.

## Шаг 4. seccomp user-notify

В режиме `user-notify` ядро при syscall'е, помеченном `SECCOMP_RET_USER_NOTIF`, **уведомляет супервизор** — внешний процесс, который решает, что делать. Ошибки в супервизоре (доверие структуре `struct seccomp_notif` без проверки, гонки) позволяют обойти песочницу. Это «горячая» область: CVE в `user-notify` и в коде, который его использует (например, в `runc`), приводят к контейнерным escape.

## Шаг 5. Контейнерные escape

Из контейнера можно выйти через:

1. **privileged container** — доступ к устройствам и `mount`.
2. **`docker.sock`** — если смонтирован, можно управлять Docker и создать привилегированный контейнер.
3. **host paths** — смонтированные директории хоста.
4. **capabilities** (`CAP_SYS_ADMIN`) — `mount`, `unshare`.
5. **ядерные баги** (`runc`, overlayfs, cgroups).

Инструменты разведки: `deepce`, `cdk`, ручной анализ (`/proc/1/cgroup`, `/proc/self/status`, смонтированные тома).

Практический порядок действий при контейнерном escape такой. Сначала определите, что именно ограничивает вас: посмотрите capabilities (`CapEff`), смонтированные пути (`mount`, `/proc/mounts`), наличие `docker.sock` (`ls -la /var/run/docker.sock`), тип cgroup. Затем выберите путь: если есть `docker.sock` — создайте привилегированный контейнер и примонтируйте корень хоста; если есть `CAP_SYS_ADMIN` — попробуйте `mount` или `unshare`; если контейнер privileged — обратитесь к устройствам хоста. И только если ничего из этого нет, переходите к ядерным уязвимостям.

## Если не сработало

- **Не проверили фильтр.** Сначала `seccomp-tools dump`.
- **Игнорируете `openat`.** Иногда `open` запрещён, а `openat` — нет.
- **Неверный fd.** `open` возвращает дескриптор в `rax`; используйте его в `read`.
- **Забыли про escape.** RCE внутри песочницы ≠ флаг; нужен второй шаг.
- **nsjail/firejail-баги.** Изучайте конфигурацию, а не только бинарь.

## Что мы теперь знаем

- Песочницы бывают на `seccomp`, namespaces, chroot и контейнерах.
- `seccomp` фильтрует syscall'ы; при запрете `execve` применяют ORW.
- `seccomp-tools dump` показывает фильтр.
- `user-notify` — режим с супервизором; его баги дают escape.
- Контейнерный escape: `docker.sock`, privileged, host paths, capabilities, ядерные баги.
- Первый шаг всегда — разведка окружения.

## На что смотреть дальше

- **Статус.** `Seccomp` в `/proc/self/status`.
- **Фильтр.** `seccomp-tools dump`.
- **Namespaces.** `/proc/self/ns/`.
- **Контейнер.** `/.dockerenv`, `/proc/1/cgroup`.
- **Capabilities.** `CapEff`, `capsh --print`.

## Квиз

Проверь себя.

```quiz
- question: "Что ограничивает seccomp?"
  options:
    - "Список разрешённых системных вызовов через BPF-фильтр"
    - "Видимость файлов"
    - "Сетевые подключения"
    - "Память процесса"
  answer: 0
  explanation: "seccomp фильтрует syscall'ы."
- question: "Что такое ORW-цепочка?"
  options:
    - "open + read + write вместо execve под seccomp"
    - "ROP по стеку"
    - "Heap-атака"
    - "Отключение ASLR"
  answer: 0
  explanation: "При запрете execve открывают, читают и печатают флаг."
- question: "Какая утилита показывает фильтр seccomp?"
  options:
    - "seccomp-tools dump"
    - "checksec"
    - "readelf"
    - "objdump"
  answer: 0
  explanation: "Она выводит разрешённые и запрещённые syscall'ы."
- question: "Что даёт смонтированный docker.sock?"
  options:
    - "Возможность управлять Docker и создать привилегированный контейнер"
    - "Утечку libc"
    - "Снятие canary"
    - "Отключение seccomp"
  answer: 0
  explanation: "Это частый путь выхода из контейнера."
- question: "Почему RCE внутри песочницы — ещё не победа?"
  options:
    - "Ограничения песочницы могут мешать прочитать флаг"
    - "Нужен root"
    - "Нужен интернет"
    - "Нужен canary"
  answer: 0
  explanation: "После RCE нужен побег из песочницы."
```

## Куда дальше

В `pwn-sigreturn-exploit` мы вернёмся в userland и разберём SROP — технику, где сигнал `sigreturn` используется для установки всех регистров сразу. А пока главное: **после RCE разведай окружение и обойди песочницу — ORW, user-notify или контейнерный escape.**

## Где пригодится

- **CTF:** Pwn — задачи с seccomp и контейнерами.
- **Bug bounty:** побег из песочницы.
- **Пентест:** выход из контейнера.
- **Работа:** анализ песочниц и их конфигураций.
