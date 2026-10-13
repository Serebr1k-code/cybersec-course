---
id: pwn-kernel-rop
title: "Kernel ROP: commit_creds и возврат в userland"
category: pwn
parent: pwn-kernel-core
difficulty: expert
order: 2
tags: [kernel, rop, commit_creds, smep, smap, kpti]
prerequisites: [pwn-kernel-heap, pwn-rop]
useful_for:
  - "CTF Pwn — kernel-задачи"
  - "Разработка эксплойтов ядра"
estimated_minutes: 70
summary: "Построение ROP-цепочки в ядре: гаджеты, commit_creds(prepare_kernel_cred(0)), обход SMEP/SMAP/KPTI через trampoline и возврат в userland."
lab:
  kind: shell
  title: 'Практика: поиск гаджетов в vmlinux'
  toolset: [core, elf]
  workdir: /home/student/task
  files: [task.md, vmlinux, vmlinux.ropgadget.txt]
  check: 'grep -q ''pop_rdi=0x401036'' answer.txt'
  hints:
    - 'ROPgadget ищет гаджеты в ELF: `ROPgadget --binary ./vmlinux --only "pop|ret"`.'
    - 'Первый аргумент в x86-64 передаётся через `rdi`, поэтому нужен гаджет `pop rdi ; ret`.'
    - 'Готовый вывод захвачен в `vmlinux.ropgadget.txt` (файл `vmlinux` — тот же образ).'
    - 'Найди строку `pop rdi ; ret` и запиши её адрес: `pop_rdi=0x401036`. Затем `check`.'
---

## Вопрос, с которого всё начинается

В прошлом уроке мы получили контроль RIP в ядре — например, перезаписали `seq_operations->start`. Но просто «прыгнуть на свою функцию» в userland не получится: этому мешают SMEP и SMAP. Как тогда повысить привилегии? Единственный путь — склеить **гаджеты из самого кода ядра**, чтобы вызвать `commit_creds(prepare_kernel_cred(0))`, а затем корректно вернуться в userland. Это **kernel ROP**.

## Наш пример: сохраняем состояние userland

Прежде чем строить цепочку, нужно сохранить состояние текущего потока — то, куда мы вернёмся после работы в ядре. Возьмём программу, которая это делает:

```c
#include "common.h"
static unsigned long user_cs, user_ss, user_rflags, user_sp;
static void save_state(void){
    __asm__(
        "movq %%cs, %0\n"      /* сегмент кода */
        "movq %%ss, %1\n"      /* сегмент стека */
        "movq %%rsp, %3\n"     /* указатель стека */
        "pushfq\n"
        "popq %2\n"            /* флаги */
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_sp)
        :: "memory");
}
int main(void){
    save_state();
    printf("user_cs=0x%lx ss=0x%lx rflags=0x%lx rsp=0x%lx\n",
           user_cs, user_ss, user_rflags, user_sp);
    return 0;
}
```

Компилируем и запускаем:

```
$ gcc -fno-pie -no-pie -O0 -o krop krop.c
$ ./krop
user_cs     = 0x33
user_ss     = 0x2b
user_rflags = 0x246
user_rsp    = 0x7ffc295cb030
```

Это реальные значения нашего процесса: `cs = 0x33`, `ss = 0x2b` — стандартные селекторы userland на x86-64; `rflags = 0x246`; `rsp` — адрес стека. Эти четыре значения мы подставим в конец ROP-цепочки, чтобы ядро смогло вернуться именно в наш код.

## Шаг 1. Почему нельзя просто прыгнуть в userland

Три защиты закрывают «наивный» путь:

- **SMEP** (Supervisor Mode Execution Prevention) — ядро не может исполнять код из user-страниц. Значит, вернуться на свою функцию нельзя.
- **SMAP** — ядро не может читать/писать user-данные напрямую.
- **KPTI** (изоляция таблиц страниц) — адресное пространство ядра и userland разделены, поэтому простой `iretq` не сработает.

Поэтому ROP использует **существующий код ядра**: гаджеты «выполняют за нас» нужные действия.

## Шаг 2. Поиск гаджетов в ядре

Гаджеты ищут в распакованном ядре `vmlinux` утилитами ROPgadget/ropper:

```
$ ROPgadget --binary ./vmlinux --only "pop|ret" | grep "pop rdi"
$ ROPgadget --binary ./vmlinux --only "pop|ret" | grep "pop rsi"
$ ROPgadget --binary ./vmlinux | grep "swapgs"
```

Нужны, как правило, четыре вещи:

- `pop rdi; ret` — положить аргумент (например, `0` для `prepare_kernel_cred`).
- `mov rdi, rax; ...; ret` — перенести результат `prepare_kernel_cred` (в `rax`) в аргумент `commit_creds`.
- `swapgs; ret` и `iretq` — вернуться в userland (или trampoline, см. ниже).

В ядре гаджетов меньше, чем в glibc, и они зависят от сборки.

## Шаг 3. Целевая цепочка

Классическая цель — повысить привилегии текущего процесса:

```text
pop rdi; ret
0                       ; аргумент prepare_kernel_cred(NULL)
prepare_kernel_cred
mov rdi, rax; ret       ; rax (новые creds) -> rdi
commit_creds
<trampoline>            ; возврат в userland
```

`prepare_kernel_cred(0)` создаёт новые привилегированные «удостоверения» (creds) от имени root, `commit_creds` применяет их к текущему процессу. После этого наш процесс становится root.

Однако чтобы цепочка вообще сработала, нужны две дополнительные вещи: **утечка базы ядра** и **контроль над стеком**. Разберём обе.

**KASLR.** Ядро загружается по случайному адресу, поэтому символы `commit_creds`, `prepare_kernel_cred` и адреса гаджетов заранее неизвестны. Нужна утечка базы ядра — например, через `msg_msg` (OOB-read возвращает адреса ядра), через информацию из `/proc` или из самого уязвимого модуля. Получив базу, вычисляем адреса: `addr = kbase + offset`, где `offset` берётся из `vmlinux` (символы видны в `nm vmlinux`). Без утечки ROP невозможен.

**Контроль стека.** ROP-цепочка лежит на стеке, а `ret` читает адрес оттуда. Значит, нам нужно, чтобы указатель стека (`rsp`) указывал на нашу цепочку. Если уязвимость даёт только контроль RIP без контроля стека, применяют **stack pivot** — гаджет вида `mov rsp, rax; ret` или `xchg rsp, rax; ret`, который переставляет `rsp` на контролируемую область (часто в userland-буфер, но при SMAP его нельзя читать из ядра — тогда цепочку кладут в ядро, например в `msg_msg`). В простых CTF-задачах уязвимость сразу даёт возможность записать цепочку в ядро, и pivot не нужен.

Проверять цепочку удобно по шагам в отладчике: поставьте точку останова на первом гаджете и смотрите, как `rsp` движется по цепочке, а `rax`/`rdi` меняются. Это сразу покажет, где цепочка «порвалась».

## Шаг 4. Обход KPTI: trampoline

Из-за KPTI просто `swapgs; iretq` не вернёт нас в userland. В ядре есть готовый код-«трамплин», который корректно переключает таблицы страниц: `swapgs_restore_regs_and_return_to_usermode`. В цепочке переходим на него по смещению (обычно `+22` или `+54`), а дальше на стеке раскладываем:

```text
+0x00: swapgs_restore_regs_and_return_to_usermode + offset
+0x08: 0x0            (rax)
+0x10: 0x0            (rdi)
+0x18: user_rip       (наш код возврата)
+0x20: user_cs        (0x33)
+0x28: user_rflags    (0x246)
+0x30: user_rsp
+0x38: user_ss        (0x2b)
```

Именно здесь пригождаются значения из `save_state()`: `user_cs = 0x33`, `user_ss = 0x2b`, `user_rflags`, `user_rsp`. Без них возврат упадёт.

После возврата в userland наш `user_rip` — это функция, которая читает флаг (`system("/bin/sh")` или `open/read/write`).

## Шаг 5. Альтернатива: modprobe_path

ROP нужен, когда у нас есть только контроль RIP и стек. Если же доступна **произвольная запись**, есть путь проще: перезаписать `modprobe_path` (путь к скрипту, который ядро запускает при загрузке неизвестного модуля) на свой скрипт и триггернуть `request_module`. Ядро выполнит наш скрипт от root — гаджеты и KPTI-обход не нужны.

Выбор такой: есть RIP-контроль и стек → ROP; есть произвольная запись → `modprobe_path`.

## Если не сработало

- **SMEP/SMAP мешают.** Убедитесь, что не возвращаетесь в user-код напрямую; используйте только гаджеты ядра.
- **KPTI роняет возврат.** Нужен trampoline, а не голый `iretq`.
- **Неверные смещения.** KASLR + конкретная сборка: гаджеты берите из своего `vmlinux`.
- **Потеря контекста.** Не сохранили `cs/ss/rflags/rsp` — возврат падает.
- **Паника.** Любая ошибка в ядре убивает систему. Отлаживайте в QEMU.

## Что мы теперь знаем

- SMEP/SMAP/KPTI закрывают прямой возврат в userland из ядра.
- Kernel ROP собирает гаджеты из кода ядра.
- Цель — `commit_creds(prepare_kernel_cred(0))`.
- Нужны `pop rdi`, `mov rdi, rax`, trampoline `swapgs_restore_regs_and_return_to_usermode`.
- Состояние userland (`cs/ss/rflags/rsp`) сохраняют заранее.
- `modprobe_path` — альтернатива, если есть произвольная запись.

## На что смотреть дальше

- **Гаджеты.** ROPgadget/ropper по вашему `vmlinux`.
- **Trampoline.** Точное смещение для вашей версии ядра.
- **KASLR.** Нужна утечка базы ядра.
- **Отладка.** `target remote :1234` к QEMU.
- **Защиты.** SMEP/SMAP/KPTI и их обход.

## Квиз

Проверь себя.

```quiz
- question: "Почему нельзя просто вернуться на свою user-функцию из ядра?"
  options:
    - "SMEP запрещает исполнение user-страниц в режиме ядра"
    - "Включён canary"
    - "Нет ASLR"
    - "Ядро read-only"
  answer: 0
  explanation: "SMEP блокирует исполнение кода из user-страниц в ring 0."
- question: "Что делает связка commit_creds(prepare_kernel_cred(0))?"
  options:
    - "Создаёт root-creds и применяет их к текущему процессу"
    - "Отключает SMEP"
    - "Снимает KPTI"
    - "Утекает libc"
  answer: 0
  explanation: "prepare_kernel_cred(0) даёт привилегированные creds, commit_creds их применяет."
- question: "Зачем нужен trampoline swapgs_restore_regs_and_return_to_usermode?"
  options:
    - "Чтобы корректно вернуться в userland при включённом KPTI"
    - "Чтобы найти гаджеты"
    - "Чтобы утечь ядро"
    - "Чтобы снять canary"
  answer: 0
  explanation: "KPTI изолирует таблицы страниц, и trampoline переключает их при возврате."
- question: "Какие значения сохраняет save_state()?"
  options:
    - "cs, ss, rflags, rsp"
    - "rax, rbx, rcx, rdx"
    - "GOT и PLT"
    - "canary и NX"
  answer: 0
  explanation: "Они нужны для iretq/trampoline при возврате в userland."
- question: "Когда modprobe_path проще, чем ROP?"
  options:
    - "Когда есть произвольная запись"
    - "Когда есть только RIP-контроль"
    - "Когда включён SMEP"
    - "Когда нет KASLR"
  answer: 0
  explanation: "modprobe_path требует записи в память, но не гаджетов и не KPTI-обхода."
```

## Куда дальше

В `pwn-kernel-smep-smap` мы разберём, что делать, если SMEP/SMAP включены и обычный ROP усложняется — и какие приёмы обходят эти защиты. А пока главное: **в ядре прыгают не на свой код, а склеивают гаджеты, чтобы вызвать `commit_creds`, и возвращаются через trampoline.**

## Где пригодится

- **CTF:** Pwn — kernel-задачи с RIP-контролем.
- **Bug bounty:** ядерные драйверы.
- **Пентест:** локальное повышение привилегий.
- **Работа:** kernel exploit development.
