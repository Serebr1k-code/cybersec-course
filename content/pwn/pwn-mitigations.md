---
id: pwn-mitigations
title: "Защиты: NX, ASLR, PIE, canary и их обход"
category: pwn
parent: pwn-ret2libc
difficulty: medium
order: 2
tags: [nx, aslr, pie, canary, relro, bypass]
prerequisites: [pwn-ret2libc]
useful_for:
  - "CTF Pwn категория"
  - "Оценка эксплуатируемости"
  - "Secure coding"
estimated_minutes: 40
summary: "Систематизируем современные бинарные защиты и практические техники их обхода: leak, brute-force, canary leak, PIE base recovery."
---
Митигации — набор защитных механизмов компилятора, линкера и ядра, усложняющих эксплуатацию. Задача pwn-специалиста — сначала определить, какие митигации включены (`checksec`), затем выбрать технику обхода. Этот урок — карта митигаций и соответствующих обходов: NX, ASLR, PIE, canary, RELRO, CET, FORTIFY, seccomp.

## checksec: первая команда

```bash
checksec --file=./chall
```

Вывод:

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

В pwntools то же самое: `ELF('./chall').checksec()`. Из этого вывода сразу выводится план: canary → нужна утечка/обход; NX → ROP; PIE → утечка базы; Full RELRO → цель не GOT, а hooks/FSOP.

## NX / DEP: неисполняемая память

NX помечает стек и кучу как `rw-`. Shellcode-инъекция перестаёт работать. Обход: ROP/ret2libc — исполнение существующего кода. Проверка: `readelf -l ./chall | grep GNU_STACK` (`RW` без `E`).

## ASLR: рандомизация адресного пространства

Ядро случайно размещает libc, стек, кучу, а при PIE — и образ. Обход: утечка адреса (GOT, `%p`, environ) и вычисление базы. Проверка: `cat /proc/sys/kernel/randomize_va_space` (2 = полный ASLR).

```python
libc.address = leak - libc.symbols['puts']
elf.address  = leak - known_offset
```

## PIE: рандомизация самого бинаря

При PIE адреса кода неизвестны. Обход: утечка базы кода или partial overwrite. Подробно — в `pwn-pie-bypass`.

## Canary: защита от переполнения стека

Случайное значение перед сохранённым адресом возврата. Обход: утечка, брутфорс на fork-сервере, не трогать canary. Подробно — в `pwn-canary-bypass`.

## RELRO: защита GOT

| RELRO | GOT | Что доступно |
|---|---|---|
| No | writable, ленивый резолв | перезапись GOT |
| Partial | writable (частично) | перезапись GOT |
| Full | read-only | hooks, FSOP, `__exit_funcs` |

Full RELRO переводит `.got` в read-only через `mprotect` после резолва всех символов (`BIND_NOW`). Обход: `__free_hook`/`__malloc_hook` (до glibc 2.34), `_IO_2_1_stdout_`, `_IO_str_overflow`, `__exit_funcs`, `atexit`.

## FORTIFY_SOURCE

Заменяет опасные функции (`strcpy`, `sprintf`) на проверяющие версии (`__strcpy_chk`). Обход: найти функцию без проверки, использовать переполнение через `read`, изменить размер так, чтобы проверка не сработала. Иногда FORTIFY даёт неожиданные утечки через `__fortify_fail`.

## CET / shadow stack / IBT

Intel CET вводит shadow stack (проверка `ret`) и IBT (проверка косвенных переходов). Классический ROP ломается. Обход: JOP/COOP, подмена shadow stack, использование легитимных `call`. Подробно — в `pwn-cet-cfi`. На большинстве CTF выключен.

## seccomp: фильтр syscall

Контейнеры и задачи применяют seccomp-bpf, запрещая `execve`, `open`, `fork`. Тогда shellcode/`system` бесполезны. Обход: ORW (`open`/`read`/`write`), если разрешены; SROP; вызов разрешённых syscall для чтения флага.

```bash
seccomp-tools dump ./chall
```

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 ...
```

`seccomp-tools dump` показывает разрешённые/запрещённые syscall — обязательный шаг перед выбором shellcode.

## Комбинированные защиты и стратегии

| Комбинация | Техника |
|---|---|
| NX only | ROP/ret2libc |
| NX + ASLR | утечка + ROP |
| NX + PIE + ASLR | two-stage leak |
| + canary | утечка canary |
| + Full RELRO | FSOP/hooks |
| + seccomp | ORW/SROP |
| + CET | JOP/COOP |

## Проверка митигаций вручную

```bash
readelf -h ./chall | grep Type          # PIE?
readelf -l ./chall | grep GNU_STACK     # NX?
readelf -l ./chall | grep GNU_RELRO     # RELRO?
readelf -d ./chall | grep BIND_NOW      # Full RELRO?
readelf -s ./chall | grep stack_chk     # canary?
```

## Краевые случаи

- **`checksec` может врать** при статической линковке или кастомных загрузчиках — перепроверяйте `readelf`.
- **ASLR можно выключить** (`echo 0 > /proc/sys/kernel/randomize_va_space`) для отладки — но не на удалённой цели.
- **Partial RELRO ≠ writable всё.** `.got.plt` writable, `.got` может быть read-only.
- **FORTIFY зависит от оптимизации.** При `-O0` проверки часто отсутствуют.
- **seccomp может разрешать `openat`**, но не `open` — читайте дамп внимательно.

## Справочные таблицы

| Митигация | Флаг | Обход |
|---|---|---|
| NX | `-z noexecstack` | ROP |
| ASLR | ядро | утечка |
| PIE | `-pie` | утечка/partial |
| Canary | `-fstack-protector` | утечка/брутфорс |
| RELRO Full | `-z relro -z now` | hooks/FSOP |
| CET | `-fcf-protection` | JOP/COOP |
| seccomp | фильтр | ORW/SROP |

## Что дальше / решение

Дальше: `pwn-canary-bypass`, `pwn-pie-bypass`, `pwn-got-plt`, `pwn-seccomp-srop`, `pwn-fsop`. Практический алгоритм: (1) `checksec` — фиксируем все митигации; (2) для каждой выбираем обход из таблицы; (3) `seccomp-tools dump`, если есть подозрение на фильтр; (4) строим эксплойт снизу вверх: утечка → обход canary/PIE → ROP → финал. Митигации не абсолютны: каждая имеет известный обход, а их комбинация лишь удлиняет цепочку.

## Как митигации включаются и отключаются

При сборке митигации задаются флагами компилятора и линкера. Понимание флагов помогает и при реверсе (определить, что включено), и при подготовке окружения для отладки.

| Митигация | Включить | Отключить |
|---|---|---|
| Canary | `-fstack-protector-all` | `-fno-stack-protector` |
| NX | `-z noexecstack` | `-z execstack` |
| PIE | `-pie -fPIC` | `-no-pie` |
| Full RELRO | `-z relro -z now` | `-z norelro` |
| FORTIFY | `-D_FORTIFY_SOURCE=2` | без define |
| CET | `-fcf-protection=full` | `-fcf-protection=none` |

Для отладки часто удобно пересобрать бинарь с `-no-pie -fno-stack-protector -z execstack -z norelro`, чтобы отработать логику, а затем вернуть митигации и заняться их обходом.

## Продвинутые митигации: CFI, MTE, LAM

Помимо классических, современные системы добавляют: CFI (Control Flow Integrity) — проверка легитимности косвенных вызовов и переходов; MTE (Memory Tagging Extension) на ARM64 — тегирование памяти, ловящее UAF; LAM (Linear Address Masking) на x86 — маскирование адресов. CFI ограничивает набор целей для `call`/`jmp`, поэтому JOP/COOP становится сложнее. MTE делает heap-эксплуатацию значительно труднее, так как обращение по «устаревшему» указателю вызывает fault. На CTF эти митигации встречаются редко, но в реальных браузерах и мобильных ОС — постоянно.

## Влияние seccomp на выбор техники

Если `seccomp-tools dump ./chall` показывает, что разрешены только `read`, `write`, `open`/`openat`, `exit`, — `execve` и `system` недоступны. Тогда:
- стройте ORW-цепочку через ROP (`pop rax/rdi/rsi/rdx` + `syscall`);
- если гаджетов мало — SROP (`rt_sigreturn` восстанавливает регистры, затем ORW);
- если и `open` запрещён — читайте уже открытый файл (флаг часто уже открыт в fd 3) через `read`/`sendfile`.

`seccomp` в контейнерах (Docker) по умолчанию запрещает десятки syscall; это влияет на то, какой shellcode вообще возможен.

## Таблица: задача → техника

| Ситуация | Техника |
|---|---|
| NX off, ASLR off | shellcode на стеке |
| NX off, ASLR on | утечка стека + shellcode |
| NX on, no PIE | ROP/ret2libc |
| NX on, PIE, leak | two-stage ROP |
| canary + overflow | утечка canary |
| Full RELRO | FSOP/hooks |
| seccomp ORW | open/read/write ROP |
| нет гаджетов | SROP |
| CET | JOP/COOP |

## Практический чек-лист определения митигаций

1. `checksec --file=./chall` — общая картина.
2. `readelf -h` — PIE (`DYN`/`EXEC`).
3. `readelf -l | grep GNU_STACK` — NX.
4. `readelf -l | grep GNU_RELRO` и `readelf -d | grep BIND_NOW` — RELRO.
5. `readelf -s | grep stack_chk` — canary.
6. `seccomp-tools dump ./chall` — фильтр syscall (если есть подозрение).
7. `cat /proc/sys/kernel/randomize_va_space` — ASLR (для локальной отладки).

Результат каждого шага определяет следующий: наличие canary требует утечки, PIE — базы, seccomp — ORW. Пропуск любого пункта ведёт к эксплойту, который падает на неизвестной защите.

## Сводка

Митигации — это набор условий, а не стена. `checksec` и `readelf` дают точную картину; таблица «задача → техника» подсказывает путь обхода. Комбинация защит лишь удлиняет цепочку: утечка снимает ASLR/PIE/canary, ROP обходит NX, FSOP обходит Full RELRO, ORW обходит seccomp. Единственная защита, для которой нет универсального обхода в userland, — корректно настроенный CET, но и он встречается редко.

## Мини-шпаргалка

| Вопрос | Команда |
|---|---|
| всё сразу | `checksec --file=./chall` |
| PIE | `readelf -h ./chall` |
| NX | `readelf -l ./chall \| grep GNU_STACK` |
| RELRO | `readelf -d ./chall \| grep BIND_NOW` |
| canary | `readelf -s ./chall \| grep stack_chk` |
| seccomp | `seccomp-tools dump ./chall` |

## Заключительное замечание

Умение быстро и точно определять митигации отличает методичного pwn-специалиста от того, кто действует наугад. `checksec` плюс несколько `readelf` и `seccomp-tools` дают полную картину за минуту. Дальше каждая защита превращается в конкретную задачу: утечка, обход, выбор гаджетов. Митигации — это ограничения задачи, а не приговор; знание их обходов и есть суть бинарной эксплуатации.

## Квиз

```quiz
- question: "Почему младший байт stack canary всегда `\x00`?"
  options:
    - "Для выравнивания"
    - "Чтобы строковые функции обрывались и не раскрывали canary"
    - "Это случайно"
    - "Так требует NX"
  answer: 1
- question: "Когда brute-force canary реалистичен?"
  options:
    - "Всегда"
    - "Когда сервер форкается на каждый коннект и canary общий"
    - "Только при No PIE"
    - "Только при Full RELRO"
  answer: 1
- question: "Что даёт partial overwrite при PIE?"
  options:
    - "Полный контроль над адресом"
    - "Смена младших 1–2 байт адреса возврата в пределах той же страницы"
    - "Обход NX"
    - "Отключение ASLR"
  answer: 1
- question: "Чем обходят NX?"
  options:
    - "Shellcode на стеке"
    - "ROP / ret2libc"
    - "Отключением ASLR"
    - "Canary"
  answer: 1
- question: "Что нужно при Full RELRO вместо перезаписи GOT?"
  options:
    - "Писать в GOT всё равно"
    - "Использовать FSOP / exit handlers / heap-структуры"
    - "Отключить RELRO"
    - "Shellcode"
  answer: 1
```

## Где пригодится

- **CTF Pwn:** checksec-«алфавит» и выбор техники обхода — обязательный навык.
- **Bug bounty:** оценка реальной эксплуатируемости memory corruption (есть ли leak, можно ли обойти canary).
- **Работа:** рекомендации по компиляции (`-fstack-protector-strong`, PIE, Full RELRO, CET) как меры защиты.
- **Исследования:** анализ современных эксплойтов, где комбинируются несколько обходов.
