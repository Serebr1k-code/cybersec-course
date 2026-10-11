---
id: pwn-sandbox-escape
title: "Sandbox escapes (seccomp user-notify, nsjail)"
category: pwn
parent: pwn-seccomp-srop
difficulty: expert
order: 2
tags: [pwn, sandbox, seccomp, nsjail, container]
prerequisites: [pwn-seccomp-srop, pwn-kernel-intro]
useful_for:
  - "CTF Pwn — sandbox escape"
  - "Эксплуатация контейнеров"
estimated_minutes: 60
summary: "Как выходить из песочниц: seccomp-фильтры, user-notify, nsjail/namespaces, и типовые приёмы эскалации от ограниченного процесса."
---
Sandbox escape — это выход из ограниченного окружения, в котором выполняется уязвимый код. В pwn-задачах песочница обычно реализована через `seccomp` (фильтр системных вызовов), `nsjail`/`firejail` (namespaces), chroot или контейнер. Даже получив RCE внутри песочницы, вы не всегда можете прочитать флаг: нужно обойти ограничения. В этом уроке — виды песочниц, seccomp и его обход, seccomp user-notify, nsjail, контейнерные escape-приёмы и практические сценарии.

## Виды песочниц

- **seccomp-bpf** — фильтр syscall'ов, разрешающий/запрещающий вызовы. Часто запрещает `execve`, `open`, оставляя `read`/`write`.
- **seccomp user-notify** — режим, где супервизор (внешний процесс) обрабатывает вызовы; ошибки в нём — вектор escape.
- **namespaces** — изоляция PID/NET/MNT/USER; escape через уязвимости ядра или неправильную настройку.
- **chroot** — изоляция файловой системы; escape через `chdir`+`chroot` (если есть root), `open` дескрипторов.
- **контейнеры (Docker)** — комбинация namespaces + cgroups + capabilities; escape через `docker.sock`, privileged, ядерные баги.

## seccomp и его обход

`seccomp` устанавливает BPF-программу, фильтрующую syscall'ы. Типичная задача: разрешены только `read`, `write`, `open`, `exit` (ORW). Обходы:

1. **ORW-цепочка.** Вместо `execve` открыть флаг (`open`), прочитать (`read`), записать (`write`). Это не «обход», а адаптация под фильтр.
2. **Использование разрешённых syscall'ов.** Иногда `openat`, `sendfile`, `splice` не запрещены.
3. **seccomp user-notify баги.** Если супервизор неправильно обрабатывает вызовы (например, доверяет user-данным), можно получить привилегии.
4. **Отключение seccomp.** Через уязвимость ядра (например, `prctl`/`seccomp` баги) или перезапись структур.

Проверка фильтра: `seccomp-tools dump ./chall` покажет разрешённые/запрещённые syscall'ы.

```bash
seccomp-tools dump ./chall
```

## seccomp user-notify

В режиме user-notify ядро при syscall'е, помеченном `SECCOMP_RET_USER_NOTIF`, уведомляет супервизор, который решает, что делать. Ошибки в супервизоре (например, доверие `struct seccomp_notif` без проверки, гонки) позволяют обойти песочницу. Это относительно новая и «горячая» область: CVE в user-notify и в коде, его использующем (например, в runc), приводят к контейнерным escape.

## nsjail и firejail

`nsjail` — популярная песочница на основе namespaces и seccomp. Она запускает процесс в изолированных namespace'ах с фильтром syscall'ов. Escape возможен через: (1) уязвимости в самом nsjail; (2) неправильно разрешённые syscall'ы (например, `mount`, `unshare`); (3) ядерные баги. `firejail` — аналогично, но с известной историей SUID-багов. Изучайте конфигурацию песочницы: какие namespaces и capabilities доступны.

## Контейнерные escape-приёмы

Из контейнера можно выйти через: (1) **privileged container** — доступ к устройствам и `mount`; (2) **docker.sock** — если смонтирован, можно управлять Docker и создать привилегированный контейнер; (3) **host paths** — смонтированные директории хоста; (4) **capabilities** (`CAP_SYS_ADMIN`) — `mount`, `unshare`; (5) **ядерные баги** (runc, overlayfs, cgroups). Инструменты: `deepce`, `cdk`, ручной анализ.

## Разобранный пример: ORW под seccomp

```python
from pwn import *
context.binary = elf = ELF('./chall')
# фильтр запрещает execve, разрешает open/read/write
# ROP: open("flag", 0); read(fd, buf, 0x100); write(1, buf, 0x100)
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi','ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx','ret'])[0]
buf = elf.bss(0x100)
chain  = flat(pop_rdi, flag_addr, pop_rsi, 0, elf.plt['open'])
chain += flat(pop_rdi, 3, pop_rsi, buf, pop_rdx, 0x100, elf.plt['read'])
chain += flat(pop_rdi, 1, pop_rsi, buf, pop_rdx, 0x100, elf.plt['write'])
```

## Частые ошибки

- **Не проверили фильтр.** Всегда делайте `seccomp-tools dump` первым делом.
- **Игнорирование `openat`.** Иногда `open` запрещён, а `openat` — нет.
- **Неверный fd.** `open` возвращает fd в `rax`; используйте его.
- **Забыть про sandbox escape.** RCE внутри песочницы ≠ флаг.
- **nsjail/firejail баги.** Изучайте конфигурацию, а не только бинарь.

## Справочные таблицы

| Песочница | Механизм | Escape |
|---|---|---|
| seccomp | BPF-фильтр | ORW / баги user-notify |
| nsjail | namespaces | неправильные syscall'ы |
| chroot | FS-изоляция | chdir+chroot, fd |
| Docker | namespaces+cgroups | docker.sock, privileged |

| Инструмент | Назначение |
|---|---|
| `seccomp-tools dump` | показать фильтр |
| `deepce` | контейнерная разведка |
| `cdk` | container escape |

## Что дальше / решение

Дальше: `pwn-seccomp-srop`, `pwn-kernel-intro`, `pwn-browser` (sandbox escape), `pwn-heap-uaf`. Практический алгоритм: (1) определите тип песочницы; (2) для seccomp — сделайте dump и адаптируйте цепочку (ORW); (3) для namespaces/контейнеров — ищите неправильные capabilities/paths; (4) для user-notify — ищите баги супервизора; (5) получите флаг. Sandbox escape — обязательный навык, потому что современные задачи часто дают RCE в изоляции, и без escape вы не получите цель.
## Полный разбор ORW под seccomp

Разберём сквозной пример. Дано: 64-битный бинарь с переполнением стека, seccomp-фильтр запрещает `execve` и `execveat`, но разрешает `open`, `read`, `write`, `exit`. Цель — прочитать флаг. Первым делом выполняем `seccomp-tools dump ./chall` и видим фильтр: он проверяет `rax` (номер syscall) и возвращает `KILL` для `execve` (59), `ALLOW` для остальных. Стратегия — ORW. Шаги: (1) найти гаджеты `pop rdi`, `pop rsi`, `pop rdx`, `pop rax`, `syscall`; (2) найти адрес строки `"flag"` или записать её в `.bss`; (3) найти записываемую область (`.bss`) для буфера; (4) построить цепочку: `openat(AT_FDCWD, "flag", 0)` (syscall 257) или `open("flag", 0)` (2), затем `read(fd, buf, 0x100)` (0), затем `write(1, buf, 0x100)` (1); (5) отправить. `open` возвращает fd в `rax` (обычно 3), но для простоты используйте фиксированный fd 3. Проверяйте каждый syscall в gdb.

## Тонкости ORW и seccomp

Важные детали: (1) **`open` vs `openat`** — на современных системах `open` может отсутствовать, а `openat` (257) работать; (2) **fd** — `open` возвращает дескриптор, обычно 3, но если stdin/stdout/stderr заняты, проверьте; (3) **буфер** — используйте `.bss` или стек (если writable); (4) **размер чтения** — читайте достаточно (например, 0x100), чтобы получить весь флаг; (5) **seccomp может фильтровать аргументы** — иногда проверяется не только номер syscall, но и аргументы (например, `open` только для определённых путей). Изучите дамп фильтра внимательно: `seccomp-tools dump` показывает каждую проверку. Если `open` запрещён, но `openat` разрешён — используйте `openat`. Если запрещены и они, ищите `sendfile`/`splice`/`mmap` или баг в фильтре.

## Выход из namespaces и контейнеров

Если задача — не seccomp, а namespaces/контейнер, стратегия иная. Проверьте: `cat /proc/self/status | grep -i cap` (capabilities), `cat /proc/self/cgroup` (cgroup), `ls -la /` (файлы хоста), `mount` (точки монтирования). Ищите: (1) смонтированный `docker.sock` (`/var/run/docker.sock`) — можно создать привилегированный контейнер и выйти; (2) `CAP_SYS_ADMIN` — `mount`/`unshare` для выхода; (3) host-пути (`/host`, `/proc/1/root`) — доступ к файловой системе хоста; (4) `CAP_DAC_READ_SEARCH` — чтение любых файлов через `open_by_handle_at`. Инструменты `deepce` и `cdk` автоматизируют разведку. Помните, что RCE внутри контейнера ≠ доступ к хосту; escape — отдельный этап.

## Практические рекомендации

Всегда начинайте с определения песочницы: `seccomp-tools dump`, проверка namespaces, capabilities, монтирований. Для seccomp — адаптируйте цепочку (ORW) или ищите баги user-notify. Для контейнеров — ищите docker.sock, host-пути, capabilities. Для nsjail/firejail — изучайте конфигурацию. Помните, что современные песочницы (Chrome, gVisor) требуют отдельных багов для escape. Практикуйтесь на задачах с seccomp (самые частые в CTF), затем переходите к контейнерным escape. Sandbox escape — финальный этап цепочки, без него RCE не даёт цели.
## Разбор seccomp-tools и типичных фильтров

`seccomp-tools dump ./chall` выводит BPF-программу с аннотациями: видно каждое сравнение `rax` (номер syscall) и действие (`ALLOW`/`KILL`/`ERRNO`). Типичные фильтры: (1) запрет `execve`/`execveat` (59/322) — тогда ORW; (2) запрет `open`/`openat` (2/257) — тогда читайте через уже открытый fd или используйте `sendfile`; (3) разрешение только `read`/`write`/`exit` — тогда нужен уже открытый флаг или утечка; (4) проверка аргументов (например, `open` только для определённого пути). Внимательно читайте фильтр: иногда разрешён `openat` при запрещённом `open`, или разрешён `pread64`. Иногда фильтр имеет баг (например, проверяет 32-битный `rax`, а syscall 64-битный) — это вектор обхода. Изучите архитектуру BPF и `struct seccomp_data`.

## Контейнерный escape: практика

Для выхода из Docker-контейнера проверьте: (1) `cat /proc/1/cgroup` — тип контейнера; (2) `ls -la /var/run/docker.sock` — если есть, `docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host`; (3) `capsh --print` — capabilities; при `CAP_SYS_ADMIN` можно `mount`/`unshare`; (4) `mount | grep host` — смонтированные host-пути; (5) `/proc/1/root` — корень хоста, если доступен. Инструменты `deepce`/`cdk` автоматизируют. В Kubernetes проверьте service account token (`/var/run/secrets/kubernetes.io/serviceaccount/token`) и RBAC — иногда он позволяет создать привилегированный pod. Escape — отдельная дисциплина; практикуйтесь на уязвимых контейнерах.

## Практические рекомендации

Всегда определяйте песочницу первой. Для seccomp — dump и адаптация (ORW). Для контейнеров — capabilities, сокеты, host-пути. Для nsjail/firejail — конфигурация. Помните, что RCE внутри изоляции — лишь первый этап; цель — escape. Изучайте публичные writeup'ы (Docker escape, Kubernetes privesc) и практикуйтесь. Sandbox escape часто решает исход задачи, поэтому уделяйте ему столько же внимания, сколько эксплуатации самого бага.

## Квиз

```quiz
- question: "Что делает seccomp-фильтр?"
  options:
    - "Ограничивает набор доступных системных вызовов"
    - "Шифрует память"
    - "Включает ASLR"
    - "Изолирует сеть"
  answer: 0
  explanation: "seccomp через BPF-фильтр разрешает/запрещает syscalls."
- question: "Что такое техника ORW?"
  options:
    - "open/read/write — чтение файла без execve под seccomp"
    - "Обход KPTI"
    - "Заполнение tcache"
    - "Расширение fastbin"
  answer: 0
  explanation: "Когда execve запрещён, флаг читают через open/read/write."
- question: "Что означает SECCOMP_RET_USER_NOTIF?"
  options:
    - "Запросы обрабатывает супервизор в userspace (потенциальный баг -> escape)"
    - "Фильтр отключён"
    - "Разрешены все syscalls"
    - "Ядро обрабатывает всё само"
  answer: 0
  explanation: "User-notify передаёт решения в userspace-супервизор, что расширяет поверхность атаки."
- question: "Что часто даёт CAP_SYS_ADMIN внутри user namespace?"
  options:
    - "Практически root-возможности внутри namespace (mount и т.д.)"
    - "Ничего"
    - "Полный доступ к хосту сразу"
    - "Отключение seccomp"
  answer: 0
  explanation: "CAP_SYS_ADMIN в userns позволяет mount/overlay и часто ведёт к escape."
- question: "Какой инструмент статически показывает seccomp-фильтр бинаря?"
  options:
    - "seccomp-tools dump"
    - "lsmod"
    - "uname -r"
    - "nm"
  answer: 0
  explanation: "seccomp-tools dump дизассемблирует BPF-фильтр и печатает разрешённые syscalls."
```

## Где пригодится

- **CTF:** Pwn — задачи с песочницей (seccomp/nsjail), отдельная сложность.
- **Bug bounty:** контейнерные/песочничные escape.
- **Пентест:** выход из ограниченного контекста.
- **Работа:** security research, hardening review.
