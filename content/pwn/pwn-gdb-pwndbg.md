---
id: pwn-gdb-pwndbg
title: "GDB + pwndbg/gef: отладка эксплойтов"
category: pwn
parent: pwn-pwntools
difficulty: easy
order: 1
tags: [gdb, pwndbg, gef, debugging, tools, registers]
prerequisites: [pwn-pwntools, pwn-buffer-overflow]
useful_for:
  - "CTF Pwn категория"
  - "Отладка эксплойтов"
  - "Реверс-инжиниринг"
estimated_minutes: 50
summary: "Осваиваем GDB с расширениями pwndbg/gef: смотрим стек, регистры, кучу и находим точное смещение до RIP прямо во время работы эксплойта."
---
GDB — основной отладчик при разработке эксплойтов, а pwndbg (или gef) превращает его из неудобного ассемблерного интерфейса в полноценную среду для pwn: цветной контекст, автоматический разбор кучи, поиск гаджетов, работа с бинами tcache/fastbin, декомпиляция через Ghidra-интеграцию. Без уверенного владения GDB + pwndbg отладка эксплойта занимает в разы больше времени. В этом уроке — установка, базовый и продвинутый workflow, ключевые команды с полным синтаксисом и разобранные сценарии: поиск смещения, чтение утечки, анализ кучи, отладка ROP.

## Установка и настройка

```bash
# pwndbg (рекомендуется)
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# gef (альтернатива)
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# базовый gdb (Debian/Ubuntu)
sudo apt install gdb gdb-multiarch

# .gdbinit
echo "source ~/pwndbg/gdbinit.py" >> ~/.gdbinit
```

Для кросс-архитектур (ARM/MIPS/RISC-V) используйте `gdb-multiarch` и `set architecture arm64`. Для ядра — `gdb ./vmlinux` и `target remote :1234` (QEMU с `-s`).

## Базовый workflow отладки эксплойта

Стандартная последовательность: запустить под отладчиком, поставить точки останова, дойти до уязвимого вызова, посмотреть состояние.

```bash
gdb ./chall
(gdb) b *main
(gdb) b *vuln+40
(gdb) r
(gdb) info registers
(gdb) x/20gx $rsp
(gdb) ni          # step over
(gdb) si          # step into
(gdb) c           # continue
```

В pwndbg после каждого шага автоматически печатается контекст: регистры, дизассемблер, стек, backtrace. Это позволяет сразу видеть, куда указывает `rsp` и что лежит на стеке.

## Ключевые команды pwndbg

pwndbg добавляет десятки команд. Основные:

```bash
(gdb) checksec              # митигации текущего процесса
(gdb) vmmap                 # карта памяти (адреса libc, heap, stack)
(gdb) got                   # содержимое GOT
(gdb) plt                   # содержимое PLT
(gdb) heap                  # состояние кучи (chunks, bins)
(gdb) bins                  # tcache/fastbin/smallbin/unsortedbin
(gdb) vis_heap_chunks       # визуализация чанков
(gdb) telescope $rsp 20     # разыменовать стек (цепочка указателей)
(gdb) rop --grep "pop rdi"  # поиск гаджетов (если включён ropper)
(gdb) search -s "/bin/sh"   # поиск строки в памяти
(gdb) p/x &main_arena
```

Команда `heap`/`bins` особенно ценна при heap-эксплуатации: видно размеры чанков, указатели `fd`/`bk`, состояние tcache.

## Поиск смещения переполнения

Классический способ — cyclic-паттерн. В pwntools:

```python
from pwn import *
p = process('./chall')
p.sendline(cyclic(300))
p.wait()
```

После падения смотрим `rsp` (или значение в `rip`) и находим смещение:

```bash
(gdb) run < <(python3 -c "from pwn import *; print(cyclic(300))")
# ... падение ...
(gdb) x/s $rsp
# 0x...: 'kaaalaaa...'
```

Затем в Python: `offset = cyclic_find(0x6161616c)` (или значение из `$rsp`). Для x86-64 смещение = индекс найденного 4-байтового паттерна. Точность обеспечивается тем, что cyclic-паттерн не повторяется в пределах длины.

## Чтение утечек и адресов

Чтобы понять, что утекло, смотрите регистры и память прямо в момент печати:

```bash
(gdb) b *puts@plt
(gdb) r
(gdb) x/gx $rdi        # что передаётся в puts
(gdb) vmmap            # сопоставить адрес с регионом
```

`vmmap` покажет, что адрес принадлежит `libc.so.6` или `[heap]`, — это подскажет, какая утечка вам доступна. Если нужно узнать базу libc: `p/x (void*)libc_base` (pwndbg вычисляет автоматически при наличии отладочных символов) или вычесть оффсет вручную.

## Анализ кучи

Пример: программа выделяет чанк, освобождает и снова читает (UAF). Под отладчиком:

```bash
(gdb) b *main+120
(gdb) r
(gdb) heap
(gdb) vis_heap_chunks 10
(gdb) bins
(gdb) x/4gx 0x555555559000   # адрес heap
```

`vis_heap_chunks` рисует чанки с `prev_size`, `size`, `fd`, `bk`, `data`. Для tcache видно поле `next` и `key`. Это позволяет проверить, что double-free действительно попал в tcache (по `key`), и рассчитать poisoning.

## Разобранный пример: отладка ret2libc

Сценарий: переполнение стека, NX, Partial RELRO, PIE. Нужна утечка libc.

```bash
gdb ./chall
(gdb) b *vuln+60
(gdb) r
# дошли до ret
(gdb) x/6gx $rsp
# 0x...: 0x4141414141414141 ...
(gdb) info frame
(gdb) p $rbp
```

Вычисляем offset, строим цепочку `pop rdi; ret` → `puts@plt` → `puts@got` → возврат в `vuln`, получаем утечку, затем второй этап — `system("/bin/sh")`. На каждом шаге `vmmap` подтверждает базу libc.

## Работа с pwntools gdb.debug

Автоматизируйте отладку из эксплойта:

```python
from pwn import *
context.binary = elf = ELF('./chall')
p = gdb.debug('./chall', gdbscript='''
    b *vuln+60
    c
''')
p.interactive()
```

Это запускает бинарь под GDB с открытым терминалом. Для удалённого ядра — `gdb.attach(p)`.

## Частые ошибки и приёмы

- **Точка останова по неверному адресу.** У PIE адрес меняется; используйте `b *vuln+40` (по символу+смещению) или `b *$base+0x1234`.
- **`x/s` печатает не то.** `x/s` останавливается на нулевом байте; для указателей используйте `x/gx`.
- **Забыли `set follow-fork-mode child`.** Многие сервисы форкают — при отладке дочернего процесса это обязательно.
- **ASLR мешает.** `set disable-randomization on` (по умолчанию включено) для стабильных адресов локально; но помните, что удалённо ASLR включён.
- **Стек не выровнен.** Падение в `movaps` в `system` — добавьте `ret`.
- **Память «портится» между запусками.** Проверяйте `vmmap` каждый раз.
- **Нет отладочных символов.** Установите `libc6-dbg` или используйте `pwndbg`'s `libc` symbols.

## Справочные таблицы

| Команда | Назначение |
|---|---|
| `checksec` | митигации |
| `vmmap` | карта памяти |
| `heap` / `bins` | состояние кучи |
| `vis_heap_chunks` | визуализация чанков |
| `telescope $rsp` | разыменование стека |
| `got` / `plt` | таблицы |
| `search -s "str"` | поиск в памяти |
| `b *addr` | точка останова |

| Клавиша/команда | Действие |
|---|---|
| `r` | запуск |
| `c` | продолжить |
| `si`/`ni` | шаг внутрь/через |
| `fin` | до конца функции |
| `x/20gx $rsp` | дамп стека |
| `info registers` | регистры |

## Что дальше / решение

Дальше: `pwn-pwntools` (автоматизация), `pwn-heap-tcache` (что именно смотреть в `bins`), `pwn-heap-qemu-debug` (кросс-архитектурная отладка), `pwn-buffer-overflow` (первый практический эксплойт). Практический алгоритм: (1) поставьте `b *main` и запустите; (2) найдите уязвимую функцию и точку перед `ret`; (3) определите offset через cyclic; (4) проверьте митигации через `checksec`; (5) при heap-баге используйте `heap`/`bins`/`vis_heap_chunks`; (6) проверьте выравнивание стека перед вызовом libc-функций. Освоив `vmmap`, `telescope` и `bins`, вы будете отлаживать эксплойты в разы быстрее.
## Продвинутые команды pwndbg для heap и ROP

Помимо базовых, pwndbg предоставляет мощные команды: `p2p` (pointer to pointer — разыменовывает цепочку указателей), `malloc_chunk <addr>` (детальный разбор одного чанка с полями `prev_size`, `size`, `fd`, `bk`, `key`), `tcache` (полное состояние tcache включая counts и entries), `fastbins`, `smallbins`, `largebins`, `unsortedbin` (каждый бин отдельно), `heap_config` (параметры аллокатора glibc). Для ROP: `rop --grep "pop rdi"`, `ropper` (интеграция), `search -p <bytes>` (поиск байтового паттерна), `nearpc` (дизассемблер вокруг `pc`). Команда `context` настраивается: `set context-sections "regs disasm stack backtrace"`, `set context-output /tmp/ctx.txt`. Это позволяет сфокусироваться на нужном и не засорять экран.

## Отладка многопоточных и форкающих сервисов

Сервисы часто вызывают `fork` на каждое соединение. Для отладки дочернего процесса: `set follow-fork-mode child`, `set detach-on-fork off`. Для многопоточных: `info threads`, `thread <n>`, `set scheduler-locking on` (останавливать только текущий поток — критично для гонок). Если сервис слушает сокет, удобно использовать `socat TCP-LISTEN:1337,reuseaddr,fork EXEC:./chall` и подключаться к нему pwntools, а gdb цеплять через `gdb -p $(pgrep -n chall)`. Для гонок помогает `set non-stop on` и точки останова с условиями (`break ... if ...`).

## Интеграция с Ghidra и декомпиляция

Современный pwndbg умеет декомпилировать через Ghidra: команда `decompiler` (или `ghidra`) запускает фоновый анализ и показывает псевдокод текущей функции прямо в gdb. Это экономит переключение между инструментами. Если интеграции нет, используйте `objdump -d -M intel` или открывайте бинарь в Ghidra параллельно, сверяя адреса. Для больших бинарей загружайте их в IDA/Ghidra с базой, совпадающей с рантаймом (при PIE задайте базу). Декомпилятор даёт понимание логики, а gdb — точные значения в рантайме; вместе они закрывают почти любую задачу.

## Автоматизация повторяющихся проверок

Напишите `.gdbinit`-скрипты или gdbscript для типовых сценариев: вывод `checksec`, `vmmap`, дампа стека на каждом шаге, логирования регистров. Например:

```python
gdbscript = '''
set pagination off
b *vuln+60
commands
  silent
  printf "RSP=%p RIP=%p\\n", $rsp, $rip
  x/6gx $rsp
  continue
end
c
'''
```

Это особенно полезно при фаззинге эксплойта, когда нужно понять, в какой момент и почему происходит падение. Логируйте всё, что может понадобиться позже: адреса libc, heap, stack, значения канареек.
## Связка gdb с pwntools и воспроизводимость

Чтобы отладка была воспроизводимой, фиксируйте окружение: одну и ту же libc, одинаковые переменные окружения, отключённую рандомизацию локально. Команда `gdb.debug` из pwntools поднимает бинарь под отладчиком с нужным `gdbscript`, а `gdb.attach` цепляется к уже запущенному процессу — удобно для удалённых или уже работающих сервисов. Сохраняйте gdbscript рядом с эксплойтом, чтобы вернуться к задаче через день и сразу восстановить контекст. Логируйте `vmmap` и дамп стека в файл — это дешевле, чем перезапускать отладку.

## Квиз

```quiz
- question: "Какая команда pwndbg показывает карту памяти?"
  options:
    - "vmmap"
    - "heap"
    - "got"
    - "cyclic"
  answer: 0
  explanation: "vmmap отображает отображённые регионы (стек/куча/libc)."
- question: "Как pwndbg показывает состояние tcache?"
  options:
    - "tcachebins"
    - "vmmap"
    - "bt"
    - "ni"
  answer: 0
  explanation: "tcachebins выводит содержимое tcache-бакетов."
- question: "Как найти смещение до RIP с помощью cyclic?"
  options:
    - "cyclic -l <значение_из_rip>"
    - "info registers"
    - "vmmap"
    - "search -s"
  answer: 0
  explanation: "cyclic -l находит позицию паттерна по значению, попавшему в RIP."
- question: "Что нужно для отладки PIE-бинаря?"
  options:
    - "Ставить брейкпоинты относительно базы (например, b *vuln+off после старта)"
    - "Отключить PIE"
    - "Использовать nm"
    - "Ничего"
  answer: 0
  explanation: "Под PIE абсолютные адреса меняются; брейкпоинты ставят относительно символов/базы."
- question: "Какая команда смотрит стек с разыменованием указателей?"
  options:
    - "telescope $rsp 20"
    - "info registers"
    - "bt"
    - "checksec"
  answer: 0
  explanation: "telescope (pwndbg) рекурсивно разыменовывает значения стека."
```

## Где пригодится

- **CTF:** Pwn — ежедневная отладка.
- **Bug bounty:** анализ крашей.
- **Пентест:** разработка эксплойтов.
- **Работа:** vulnerability research.
