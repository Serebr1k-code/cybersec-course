---
id: pwn-signal-handlers
title: "Модуль: signal handlers, SROP и sigreturn-фреймы"
category: pwn
parent: pwn-seccomp-srop
difficulty: hard
order: 1
tags: [signal, srop, sigreturn, sigframe, roadmap]
prerequisites: [pwn-seccomp-srop]
useful_for:
  - "CTF Pwn категория"
  - "Vulnerability research"
  - "Kernel/glibc internals"
estimated_minutes: 12
summary: "Отдельный этап: эксплуатация обработчиков сигналов и sigreturn-фреймов — SROP, подделка ucontext и гонки в async-signal-коде."
lab:
  kind: shell
  title: "Практика: смещение rip в SigreturnFrame"
  toolset: [core]
  workdir: /home/student/task
  files: [task.md, frame.bin, frame.hex.txt]
  check: "grep -q 'rip_off=0xa8' answer.txt"
  hints:
    - "SigreturnFrame — это 248 байт; каждое поле лежит по своему смещению."
    - "`frame.hex.txt` — реальный hex дампа фрейма (pwntools, amd64)."
    - "Мы положили в `rip` маркер `0xdeadbeefcafebabe` — найди его в дампе."
    - "Маркер `bebafecaefbeadde` (little-endian) стоит по смещению 168 = `0xa8`."
---

Сигналы — механизм асинхронных уведомлений ядра, и в pwn они превращаются в отдельный класс примитивов. Как только программа устанавливает обработчик через `signal()`/`sigaction()`, ядро при доставке сигнала сохраняет полный контекст на стек и вызывает обработчик; возврат идёт через `rt_sigreturn`, который восстанавливает регистры **из стека**. Если атакующий контролирует стек, он контролирует и восстановление — это и есть SROP (Sigreturn-Oriented Programming).

## Что покрывает этот модуль

- **Механику sigreturn** — layout `ucontext`/`rt_sigframe`, что именно восстанавливается, какие поля валидирует ядро.
- **Полный SROP-эксплойт** — подделка фрейма, установка всех регистров, `execve` без единого гаджета (кроме `syscall; ret`).
- **Подделку сигнальных фреймов** — `SigreturnFrame` в pwntools, `setcontext`-гаджеты, связка с FSOP.
- **Async-signal-safety** — гонки в обработчиках, небезопасные вызовы, `setjmp`/`longjmp` и `SIGALRM`.

## Рекомендуемый порядок изучения

1. `pwn-sigreturn-exploit` — SROP с нуля: `rt_sigreturn`, layout фрейма, регистры, полный эксплойт.
2. `pwn-signal-frame-forgery` — подделка `ucontext`, `SigreturnFrame`, `setcontext+0x35`, обход проверок.
3. `pwn-async-signal-race` — гонки в обработчиках сигналов, `SIGALRM`, небезопасные функции.

Материал опирается на `pwn-seccomp-srop` (базовый SROP) и `pwn-rop` (цепочки и гаджеты), а также напрямую связан с `pwn-fsop` — `setcontext` часто совмещают с перезаписью `_IO_FILE`.

## Что вы будете уметь

- Строить `rt_sigframe` вручную и объяснять каждое поле.
- Писать SROP-цепочку, которая ставит **все** регистры одним кадром.
- Подделывать `ucontext` и обходить проверки ядра на корректность фрейма.
- Находить и эксплуатировать гонки в async-signal-коде.

## Квиз

```quiz
- question: "Что делает системный вызов rt_sigreturn?"
  options:
    - "Отправляет сигнал процессу"
    - "Восстанавливает контекст процесса из rt_sigframe на стеке"
    - "Блокирует все сигналы"
    - "Создаёт новый поток"
  answer: 1
  explanation: "rt_sigreturn читает фрейм со стека и загружает регистры из него."
- question: "Почему SROP особенно удобен при жёстком seccomp-фильтре?"
  options:
    - "Он не использует системные вызовы"
    - "Один кадр позволяет задать произвольный syscall и все его аргументы"
    - "Он отключает seccomp"
    - "Он работает без стека"
  answer: 1
  explanation: "Кадр задаёт rax (номер syscall) и rdi/rsi/rdx/r10/r8/r9 (аргументы)."
- question: "Что нужно атакующему, чтобы выполнить SROP?"
  options:
    - "Только адрес libc"
    - "Контроль над стеком и гаджет syscall; ret"
    - "Права root"
    - "Скомпилированный shellcode"
  answer: 1
  explanation: "Ядро само сделает syscall; нужен лишь syscall-гаджет и управляемый фрейм."
```

## Где пригодится

- **CTF:** задачи с seccomp и минимальным набором гаджетов (SROP — классика).
- **Bug bounty:** эксплуатация обработчиков сигналов в демонах.
- **Пентест:** обход seccomp-песочниц и sandbox-escape.
- **Работа:** анализ async-signal-safety и гонок в системном коде.
