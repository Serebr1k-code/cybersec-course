---
id: pwn-kernel-subsystems
title: "Ядро: подсистемы (pipe buffer, eBPF, io_uring, nftables)"
category: pwn
parent: pwn-kernel-intro
difficulty: hard
order: 2
tags: [pwn, kernel, pipe, ebpf, io_uring, nftables]
prerequisites: [pwn-kernel-intro]
useful_for:
  - "CTF Pwn: kernel-задачи на подсистемах"
  - "Анализ CVE в ядре Linux"
estimated_minutes: 10
summary: "Второй kernel-этап: эксплуатация конкретных подсистем ядра — pipe buffer, eBPF, io_uring и nftables."
lab:
  kind: shell
  title: "Практика: syscall eBPF"
  toolset: [core, bin]
  workdir: /home/student/task
  files: [task.md, unistd_64.h]
  check: "grep -q 'nto{bpf=321}' answer.txt"
  hints:
    - "Каждая подсистема (eBPF, io_uring, nftables) входит через свой syscall."
    - "`grep bpf unistd_64.h` — найди строку `__NR_bpf`."
    - "Число в конце строки — номер системного вызова."
    - "Запиши `nto{bpf=<номер>}`."
---
Второй модуль по эксплуатации ядра: переход от общих техник к конкретным подсистемам, в которых регулярно находят уязвимости. Каждая из четырёх тем — это отдельный класс CVE, и вместе они покрывают большинство современных kernel-задач.

## Что покрывает этап

**pwn-kernel-pipe-buffer** — эксплойт через pipe_buffer: page-ориентированный примитив порчи.
**pwn-kernel-ebpf** — eBPF: верификатор, баги в JIT и получение примитивов.
**pwn-kernel-io_uring** — io_uring как источник багов и примитивов в современном ядре.
**pwn-kernel-nftables** — nftables/netfilter: UAF и порча в подсистеме фильтрации.

## Почему такой порядок

Pipe buffer идёт первым: это классический и наглядный page-примитив, встречавшийся в реальных эксплойтах. eBPF вторым — там важна работа с верификатором. io_uring и nftables замыкают модуль как наиболее современные и «горячие» подсистемы, породившие множество недавних CVE.

## Что вы сможете после этапа

- Использовать pipe_buffer для page-примитива.
- Находить слабости верификатора eBPF и JIT.
- Разбирать UAF в io_uring и nftables и строить эксплойт.

## Квиз

```quiz
- question: "Почему pipe buffer идёт первым в модуле?"
  options:
    - "Это классический и наглядный page-примитив"
    - "Он самый сложный"
    - "Он не связан с ядром"
    - "Он работает только в userspace"
  answer: 0
  explanation: "pipe_buffer даёт понятный page-ориентированный примитив."
- question: "Что важно понимать при эксплуатации eBPF?"
  options:
    - "Работу верификатора и JIT"
    - "Только HTML"
    - "Синтаксис CSS"
    - "Протокол SMTP"
  answer: 0
  explanation: "Верификатор eBPF — основной барьер для атакующего."
- question: "Почему io_uring и nftables замыкают модуль?"
  options:
    - "Это современные подсистемы, породившие множество недавних CVE"
    - "Они проще pipe buffer"
    - "Они не относятся к ядру"
    - "Они отключены по умолчанию"
  answer: 0
  explanation: "Это «горячие» подсистемы с регулярными уязвимостями."
```

## Где пригодится

- **CTF:** задачи категории pwn и смежные.
- **Bug bounty:** поиск и воспроизведение уязвимостей в реальном ПО.
- **Пентест:** работа с бинарями и встроенными системами на этапе эксплуатации.
- **Работа:** анализ инцидентов, реверс и vulnerability research.
