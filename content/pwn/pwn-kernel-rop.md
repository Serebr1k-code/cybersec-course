---
id: pwn-kernel-rop
title: "Kernel ROP и обход KPTI (trampoline)"
category: pwn
parent: pwn-kernel-core
difficulty: expert
order: 3
tags: [pwn, kernel, rop, kpti, smep, smap]
prerequisites: [pwn-kernel-intro, pwn-rop, pwn-mitigations]
useful_for:
  - "CTF Pwn — kernel"
  - "Разработка эксплойтов"
estimated_minutes: 70
summary: "Как строить kernel ROP: утечка KASLR, контроль RIP в ядре, обход SMEP/SMAP/KPTI через trampoline и получение root."
---
Kernel ROP — это построение цепочек возвратно-ориентированного программирования в контексте ядра Linux. Когда SMEP/SMAP включены и нельзя исполнить user-код, а KPTI изолирует адресные пространства, единственный путь — «склеить» гаджеты из кода ядра, чтобы выполнить `commit_creds(prepare_kernel_cred(0))` и вернуться в userland. Kernel ROP сложнее userland из-за KASLR, ограниченного набора гаджетов, требований к сохранению/восстановлению контекста и обхода KPTI (trampoline). В этом уроке — поиск гаджетов, сборка цепочки, обход SMEP/SMAP/KPTI и практические примеры.

## Зачем kernel ROP

SMEP запрещает исполнение user-страниц в режиме ядра, SMAP — доступ к user-данным из ядра. Поэтому `ret2usr` не работает. ROP использует существующий код ядра (и модулей) для выполнения нужных действий. Цель обычно — повысить привилегии текущего процесса (`commit_creds(prepare_kernel_cred(0))`) и вернуться в userland, где можно прочитать флаг. Альтернатива — `modprobe_path` (произвольная запись), но ROP нужен, когда есть только контроль RIP и стек.

## Поиск гаджетов в ядре

Гаджеты ищут в `vmlinux` (распакованное ядро) с помощью ROPgadget/ropper:

```bash
ROPgadget --binary ./vmlinux --only "pop|ret" | grep -E "pop rdi"
ROPgadget --binary ./vmlinux --only "pop|ret" | grep -E "pop rsi"
ropper --file ./vmlinux --search "pop rdx"
ROPgadget --binary ./vmlinux | grep "swapgs"
```

В ядре гаджетов меньше, чем в glibc, и они зависят от сборки. Часто нужны: `pop rdi; ret`, `pop rsi; ret`, `pop rdx; ret`, `mov rdi, rax; ...`, `swapgs; ret`, `iretq`. Для вызова `prepare_kernel_cred` аргумент идёт в `rdi`; для `commit_creds` — результат в `rax` нужно переложить в `rdi`.

## Обход KPTI: trampoline

KPTI изолирует user- и kernel-таблицы страниц, поэтому простой `iretq`/`swapgs` не вернёт вас в userland. В ядре есть «trampoline» — код, корректно переключающий таблицы: символ `swapgs_restore_regs_and_return_to_usermode` (в старых ядрах `swapgs_restore_regs_and_return_to_usermode+22` или `+54`). Цепочка завершается переходом на этот trampoline с подготовленным стеком:

```text
... commit_creds ...
+0x00: swapgs_restore_regs_and_return_to_usermode + offset
+0x08: 0x0            (rax)
+0x10: 0x0            (rdi)
+0x18: user_rip       (точка возврата в userland)
+0x20: user_cs
+0x28: user_rflags
+0x30: user_rsp
+0x38: user_ss
```

Адреса `user_rip/cs/rflags/rsp/ss` сохраняются в userland до эксплуатации (например, через `save_state()`).

## Сохранение состояния userland

```c
unsigned long user_cs, user_ss, user_rflags, user_sp;
void save_state() {
    __asm__(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_sp)
        :: "memory");
}
```

Эти значения нужны для `iretq`/trampoline. Без них возврат в userland упадёт.

## Разобранный пример цепочки

```python
from pwn import *
context.binary = kernel = ELF('./vmlinux')
# смещения гаджетов (из ROPgadget)
pop_rdi   = kernel.symbols['...'] + 0x...
pop_rsi   = ...
pop_rdx   = ...
swapgs    = kernel.symbols['swapgs_restore_regs_and_return_to_usermode'] + 22
prepare_kernel_cred = kernel.symbols['prepare_kernel_cred']
commit_creds = kernel.symbols['commit_creds']

chain  = p64(pop_rdi) + p64(0)
chain += p64(prepare_kernel_cred)
chain += p64(pop_rdi) + p64(0)          # для переноса rax->rdi нужен mov rdi,rax
# (в реальности используем гаджет mov rdi, rax; ret)
chain += p64(commit_creds)
chain += p64(swapgs)
chain += p64(0)*2 + p64(user_rip) + p64(user_cs) + p64(user_rflags) + p64(user_sp) + p64(user_ss)
```

Порядок и смещения зависят от ядра; проверяйте в gdb.

## Альтернатива: modprobe_path без ROP

Если у вас есть произвольная запись, `modprobe_path` проще ROP: перезаписываете путь и триггерите `request_module`. Это не требует гаджетов и KPTI-обхода. ROP применяют, когда есть только RIP-контроль и стек. Выбор зависит от примитива.

## Проверка в gdb

```bash
gdb ./vmlinux
(gdb) target remote :1234
(gdb) b commit_creds
(gdb) p &modprobe_path
(gdb) x/20i swapgs_restore_regs_and_return_to_usermode
```

Убедитесь, что гаджеты валидны и что trampoline действительно переключает контекст.

## Частые ошибки

- **Неверные смещения.** KASLR + разные сборки — всегда берите гаджеты из своего `vmlinux`.
- **Забытый trampoline.** Без KPTI-обхода возврат падает.
- **Не сохранён userland-контекст.** `iretq` с мусором — краш.
- **Переполнение стека ядра.** Цепочка должна уместиться в доступное место.
- **SMAP при доступе к user-данным.** Если цепочка обращается к user-памяти, нужен `stac`/`clac` или обход.

## Справочные таблицы

| Гаджет | Назначение |
|---|---|
| `pop rdi; ret` | аргумент 1 |
| `pop rsi; ret` | аргумент 2 |
| `pop rdx; ret` | аргумент 3 |
| `mov rdi, rax; ...; ret` | перенос результата |
| `swapgs_restore_regs...` | возврат в userland |

| Защита | Обход |
|---|---|
| SMEP | ROP (не ret2usr) |
| SMAP | `stac`/`clac` или ROP |
| KPTI | trampoline |
| KASLR | утечка/`nokaslr` |

## Что дальше / решение

Дальше: `pwn-kernel-intro`, `pwn-kernel-smep-smap`, `pwn-kernel-heap`, `pwn-kernel-userfaultfd`, `pwn-kernel-pipe-buffer`. Практический алгоритм: (1) определите защиты; (2) найдите гаджеты в `vmlinux`; (3) сохраните userland-контекст; (4) соберите цепочку `prepare_kernel_cred`→`commit_creds`→trampoline; (5) триггерните RIP-контроль; (6) проверьте `id`/флаг. Kernel ROP — ключевой навык для современных kernel-задач; отработайте его на QEMU с `nokaslr`, затем переходите к KASLR.
## Полный разбор kernel ROP-цепочки

Разберём сквозной пример на QEMU с `nokaslr`, чтобы сосредоточиться на механике. Есть модуль с переполнением ядерного стека (например, в `ioctl` копируется слишком много данных в локальный буфер). Цель — выполнить `commit_creds(prepare_kernel_cred(0))` и вернуться в userland. Шаги: (1) сохранить userland-контекст (`cs`, `ss`, `rflags`, `rsp`) функцией `save_state`; (2) найти гаджеты в `vmlinux`: `pop rdi; ret`, `mov rdi, rax; ret`, `swapgs_restore_regs_and_return_to_usermode`; (3) собрать цепочку: `pop rdi; 0; prepare_kernel_cred; mov rdi, rax; commit_creds; trampoline`; (4) после trampoline вернуться в userland-функцию, которая печатает результат. Проверяем в gdb: ставим точки на `prepare_kernel_cred`, `commit_creds`, `swapgs_restore_regs_and_return_to_usermode` и следим за регистрами. Если `commit_creds` не вызывается — проверьте перенос `rax`→`rdi`.

## Гаджеты и их поиск в ядре

В ядре гаджетов существенно меньше, чем в glibc, и они зависят от конфигурации сборки. Используйте ROPgadget с фильтром по нужным инструкциям:

```bash
ROPgadget --binary vmlinux --only "pop|ret" | grep "pop rdi"
ROPgadget --binary vmlinux --only "mov|ret" | grep "mov rdi, rax"
ROPgadget --binary vmlinux | grep "swapgs"
ROPgadget --binary vmlinux | grep "iretq"
```

Если гаджета `mov rdi, rax` нет, ищите `push rax; pop rdi; ret` или вызывайте `commit_creds` через другой путь. Иногда удобно использовать `xchg` или промежуточную запись в известное место. Всегда берите гаджеты из **своего** `vmlinux` — чужие смещения не подойдут из-за KASLR и различий сборок. Сохраняйте найденные смещения в отдельный файл, чтобы не искать повторно.

## Возврат в userland и проверка привилегий

После `commit_creds` нужно вернуться в userland корректно, иначе процесс упадёт. Trampoline `swapgs_restore_regs_and_return_to_usermode` ожидает на стеке последовательность `rax, rdi, user_rip, user_cs, user_rflags, user_rsp, user_ss` (порядок зависит от ядра — проверяйте дизассемблер). `user_rip` — адрес функции, которая выполнится уже с root-правами; в ней можно вызвать `system("/bin/sh")` или прочитать флаг. Проверка: в userland после возврата вызовите `getuid()` — должен вернуть 0. Если возвращает прежний uid, значит `commit_creds` не выполнился или аргумент неверен. Логируйте `uid` и `gid`.

## Альтернативы и упрощения

Если ROP слишком трудоёмок, рассмотрите альтернативы. `modprobe_path`: перезапись пути и `request_module` — не требует гаджетов. `core_pattern`: перезапись обработчика core dump для выполнения скрипта от root. `ret2dir`: возврат к «прямо映射» страницам (актуально на старых ядрах). `userfaultfd`/FUSE: для гонок, расширяющих окно. Выбор зависит от примитива: ROP — когда есть контроль стека; `modprobe_path` — когда есть произвольная запись. Не усложняйте без необходимости.

## Чек-лист

1. Определите защиты (SMEP/SMAP/KPTI/KASLR).
2. Сохраните userland-контекст (`save_state`).
3. Найдите гаджеты в своём `vmlinux`.
4. Соберите цепочку `prepare_kernel_cred`→`commit_creds`.
5. Добавьте trampoline для возврата.
6. Проверьте `uid` после возврата.
7. При наличии произвольной записи рассмотрите `modprobe_path`.

## Итог

Kernel ROP — навык, который открывает большинство современных kernel-задач. Он требует аккуратности: неверное смещение, забытый trampoline или несогласованный стек приводят к панике. Тренируйтесь на QEMU с `nokaslr`, затем включайте KASLR и обходите его утечками. Постепенно вы научитесь собирать цепочки быстро и надёжно.

## Итоговая мысль

Kernel ROP — навык, который требует терпения и точности. Ключевые элементы: корректные гаджеты из своего ядра, перенос результата `prepare_kernel_cred` в `commit_creds`, сохранение userland-контекста и trampoline для возврата. Если есть произвольная запись, предпочтите `modprobe_path` — это проще и надёжнее. Тренируйтесь на QEMU, и со временем сборка цепочек станет рутинной.

## Взаимодействие с KPTI и таблицами страниц

KPTI изолирует таблицы страниц user- и kernel-пространства, поэтому при возврате в userland нужно переключить CR3. Trampoline `swapgs_restore_regs_and_return_to_usermode` делает это корректно: он переключает стек, выполняет `swapgs` и `iretq` с восстановлением таблиц. Если вы попытаетесь вернуться через обычный `iretq`, процесс упадёт из-за несоответствия таблиц. Поэтому в ROP-цепочке обязательно используйте trampoline, а не самодельный `swapgs; iretq`. Точное смещение внутри trampoline (часто `+22` или `+54`) зависит от ядра — определите его в gdb, посмотрев дизассемблер, и убедитесь, что на стеке лежит ожидаемая последовательность значений.

## Работа с несколькими ядрами и переполнением стека

Переполнение ядерного стека (в отличие от heap) даёт прямой контроль RIP, но объём данных ограничен размером стека. Учитывайте, что стек ядра — это отдельный регион на поток; при переполнении вы затираете сохранённые регистры и адрес возврата. Цепочка должна уместиться в доступное пространство, поэтому иногда приходится использовать stack pivot (например, `xchg rsp, rax; ret` или `pop rsp; ret`) и переносить цепочку в контролируемую память. Проверьте в gdb, сколько байт доступно до конца стека, и спланируйте цепочку accordingly. Это частая причина «цепочка не влезает».

## Квиз

```quiz
- question: "Зачем нужен KPTI trampoline?"
  options:
    - "Корректно вернуться в userspace при включённом KPTI (переключение CR3)"
    - "Отключить ASLR"
    - "Расширить tcache"
    - "Сжать указатели"
  answer: 0
  explanation: "Trampoline (swapgs_restore_regs_and_return_to_usermode) правильно возвращает в userspace."
- question: "Что делает цепочка commit_creds(prepare_kernel_cred(0))?"
  options:
    - "Повышает привилегии текущего процесса до root"
    - "Отключает SMEP"
    - "Включает KPTI"
    - "Сжимает кучу"
  answer: 0
  explanation: "prepare_kernel_cred(0) создаёт root-cred, commit_creds применяет его."
- question: "Как обычно обходят SMEP в kernel ROP?"
  options:
    - "Сбросом бита SMEP в CR4 (mov cr4, rdi)"
    - "Отключением ASLR"
    - "Заполнением tcache"
    - "Утечкой canary"
  answer: 0
  explanation: "Запись в CR4 очищает биты SMEP/SMAP, позволяя исполнить userspace-код."
- question: "Откуда берут ядерные гаджеты?"
  options:
    - "Из vmlinux (ROPgadget по образу ядра)"
    - "Из libc"
    - "Из tcache"
    - "Из vDSO"
  answer: 0
  explanation: "Ядерные гаджеты ищут в образе ядра (vmlinux), с учётом KASLR."
- question: "Что нужно, чтобы адреса гаджетов стали известны?"
  options:
    - "Утечка KASLR (kernel base)"
    - "Отключение SMAP"
    - "Расширение fastbin"
    - "Включение JIT"
  answer: 0
  explanation: "KASLR рандомизирует базу ядра; leak даёт конкретные адреса."
```

## Где пригодится

- **CTF:** Pwn — kernel-задачи с контролем RIP.
- **Bug bounty:** реальные ядерные LPE.
- **Пентест:** локальное повышение привилегий.
- **Работа:** security research ядра.
