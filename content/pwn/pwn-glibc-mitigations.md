---
id: pwn-glibc-mitigations
title: "Митигации glibc 2.3x: safe-linking и удалённые хуки"
category: pwn
parent: pwn-tcache-mechanics
difficulty: expert
order: 2
tags: [glibc, safe-linking, tcache, malloc-hook, mitigations, modern]
prerequisites: [pwn-heap-tcache, pwn-fastbin-dup]
useful_for:
  - "CTF Pwn категория"
  - "Modern glibc exploitation"
  - "Vulnerability research"
estimated_minutes: 60
summary: "Разбираем эволюцию защит glibc 2.26-2.35: tcache key, safe-linking указателей, проверки размера и удаление __malloc_hook/__free_hook, а также современные цели для записи."
---
Современные glibc (2.32+) закрыли целый класс классических heap-эксплойтов: safe-linking защищает tcache/fastbin от простого poisoning, удалены `__malloc_hook`/`__free_hook`/`__realloc_hook`, усилены проверки в unlink и consolidation, появились tcache double-free key. Это означает, что эксплойты «из 2018» больше не работают, и нужно понимать, какие примитивы остались. В этом уроке — разбор митигаций glibc 2.3x по версиям, их влияние на атаки, и обходы, которые остаются актуальными: FSOP через `_IO_FILE`, tcache stashing unlink, House of Botcake, перезапись `_IO_2_1_stdout_`, `__exit_funcs`, а также утечка heap-базы для обхода safe-linking.

## Хронология митигаций

- **glibc 2.26:** появился tcache (без проверок key/next) — эпоха простого tcache poisoning.
- **glibc 2.29:** добавлен `key` в tcache entry и проверка double-free (`e->key == tcache`), усложнив double-free.
- **glibc 2.32:** включён **safe-linking** — указатели `fd`/`next` в tcache/fastbin хранятся как `ptr ^ (chunk_addr >> 12)`. Простое poisoning требует утечки heap-адреса.
- **glibc 2.34:** удалены `__malloc_hook`, `__free_hook`, `__realloc_hook`, `__memalign_hook`. Традиционный «write hook → shell» умер.
- **glibc 2.35+:** усилены проверки `_IO_FILE` vtable (`_IO_vtable_check`), усложнив FSOP через подделку vtable.

## Safe-linking: как работает и как обойти

Safe-linking маскирует указатель: `stored = ptr ^ (pos >> 12)`, где `pos` — адрес самой ячейки. При извлечении glibc восстанавливает `ptr = stored ^ (pos >> 12)`. Чтобы подделать `next`, указывающий на произвольный адрес `T`, нужно записать `T ^ (pos >> 12)`, где `pos` — адрес поля `next` в чанке, куда вы пишете. Без знания heap-базы это невозможно. Обходы:

1. **Утечка heap-адреса.** Через `show`-функцию, неинициализированную память или `environ`. Зная heap-базу, вычисляете `pos` и маскируете корректно.
2. **Частичное перекрытие.** Меняете только младшие 2 байта `next`, не трогая замаскированные старшие — работает, если целевой чанк в той же куче.
3. **Атаки без safe-linking.** House of Botcake, tcache stashing unlink, largebin attack, FSOP — они не полагаются на прямой poisoning.

```python
def safe_link(ptr, pos):
    return ptr ^ (pos >> 12)

# пример: подделать next на target
pos = heap + 0x10          # адрес поля next
stored = safe_link(target, pos)
```

## Удалённые хуки и что вместо них

На glibc < 2.34 запись `system` в `__free_hook` и последующий `free("/bin/sh")` — самый простой путь. С 2.34 хуков нет. Альтернативы:

- **FSOP через `_IO_2_1_stdout_` / `_IO_list_all`:** подделка `_IO_FILE` и vtable, вызов при `exit`/`fflush`. Требует учёта `_IO_vtable_check`.
- **`__exit_funcs`:** перезапись списка `atexit`-обработчиков, вызов при `exit` (см. `pwn-exit-handlers`).
- **`.fini_array`:** запись указателя, вызов при завершении (см. `pwn-fini-init-array`).
- **`tls_dtor_list`:** TLS-деструкторы, вызов при `exit` потока.
- **Объекты приложения:** виртуальные таблицы C++, function pointers, callback-структуры — если они есть.

## Tcache stashing unlink attack

Эта атака обходит отсутствие прямого poisoning, эксплуатируя `tcache_stashing_unlink` при `_int_malloc` из smallbin. Идея: при аллокации из smallbin glibc перекладывает часть чанков в tcache. Если подделать `bk` чанка в smallbin, при «перекладывании» glibc запишет в tcache указатель на произвольный адрес. Работает на glibc ≥ 2.29 и не требует safe-linking-обхода, если цель — smallbin. Подробности — в уроке `pwn-tcache-stashing`.

## House of Botcake

Атака на double-free под tcache, обходящая проверку `key`. Идея: переполнить tcache (7 чанков), затем освободить два смежных чанка A и B, создать double-free через перекрытие, и использовать consolidated unsortedbin-чанк для получения двух указателей на одну память. После этого — poisoning, но с обходом key. Разбор — в `pwn-house-botcake`.

## Практический сценарий: обход safe-linking с утечкой heap

```python
from pwn import *
context.binary = elf = ELF('./chall')
p = process('./chall')

def alloc(sz, data=b''):
    p.sendlineafter(b'> ', b'1'); p.sendline(str(sz).encode()); p.sendafter(b'data: ', data)
def free(i):
    p.sendlineafter(b'> ', b'2'); p.sendline(str(i).encode())
def show(i):
    p.sendlineafter(b'> ', b'3'); p.sendline(str(i).encode())
    return p.recvline()

# 1) утечка heap через show освобождённого чанка
alloc(0x60, b'A'*0x10)          # chunk0
free(0)
leak = u64(show(0).strip().ljust(8, b'\x00'))   # safe-linked next
heap = leak << 12                                # восстановить heap (младшие 12 бит 0)
log.success('heap @ %#x', heap)
```

После утечки heap-базы можно корректно маскировать `next` и выполнять tcache poisoning даже под safe-linking.

## Частые ошибки

- **Игнорирование версии glibc.** Эксплойт для 2.31 не сработает на 2.35; всегда проверяйте `libc.version`/`strings`.
- **Прямой poisoning под safe-linking.** Без утечки heap-базы указатель будет испорчен.
- **Поиск удалённых хуков.** `__free_hook` в 2.34+ не существует — не тратьте время.
- **Подделка vtable без учёта `_IO_vtable_check`.** Нужна корректная vtable в пределах libc либо обход через `_IO_str_jumps`.
- **Забытая инициализация `key`.** В tcache entry поле `key` должно быть валидным (или нулевым в определённых атаках).

## Справочные таблицы

| Версия | Митигация | Влияние |
|---|---|---|
| 2.26 | tcache | простой poisoning |
| 2.29 | tcache key | double-free сложнее |
| 2.32 | safe-linking | нужна heap-утечка |
| 2.34 | удалены хуки | нет `__free_hook` |
| 2.35 | vtable check | FSOP сложнее |

| Атака | Работает на | Требует |
|---|---|---|
| tcache poisoning | < 2.32 без утечки | heap-утечка (2.32+) |
| tcache stashing | ≥ 2.29 | smallbin, unsorted |
| House of Botcake | ≥ 2.29 | double-free |
| largebin attack | любая | largebin, 2 записи |
| FSOP stdout | ≥ 2.24 | `_IO_FILE`, vtable |
| `__exit_funcs` | любая | exit |

## Что дальше / решение

Дальше: `pwn-tcache-stashing`, `pwn-house-botcake`, `pwn-house-modern` (Kiwi/Emma/Apple/God), `pwn-fsop`, `pwn-exit-handlers`, `pwn-largebin-attack`. Практический алгоритм: (1) определите версию glibc (`strings libc.so.6 | grep -i "GNU C"`); (2) отметьте, какие митигации включены (safe-linking, хуки); (3) если safe-linking — добудьте heap-утечку; (4) выберите атаку из таблицы, соответствующую версии; (5) проверьте локально на той же libc. Понимание эволюции митигаций glibc — обязательное условие для решения современных heap-задач: то, что работало год назад, сегодня может быть закрыто.
## Largebin attack как обход современных защит

Largebin attack — одна из немногих атак, которая пережила все митигации и работает даже на самых новых glibc. Она не требует poisoning tcache и не зависит от safe-linking: при вставке чанка в largebin glibc записывает указатель в поле `bk_nextsize`/`fd_nextsize` целевого чанка, и если подделать эти поля, запись произойдёт по произвольному адресу. Обычно цель — `_IO_list_all` (для FSOP) или `__exit_funcs`. Атака требует двух записей и понимания сортировки largebin, но зато универсальна. Подробности — в уроке `pwn-largebin-attack`.

## FSOP как основной вектор после 2.34

С удалением хуков FSOP (File Stream Oriented Programming) стал главным способом получить исполнение. Идея: вы подделываете структуру `_IO_FILE` (обычно через перекрытие чанка) так, чтобы при `exit` → `_IO_flush_all_lockp` → `_IO_OVERFLOW` вызвалась нужная функция. На glibc 2.24+ добавлена проверка `_IO_vtable_check`, поэтому vtable должна лежать в пределах libc — используют `_IO_str_jumps` или `_IO_wfile_jumps`. На новых версиях `_IO_str_overflow` больше не вызывает произвольный указатель, поэтому применяют цепочки через `_IO_wfile_overflow`/`_IO_wdoallocbuf`. Это сложнее, но остаётся рабочим.

## Проверка митигаций на практике

Перед выбором атаки выполните:

```bash
strings ./libc.so.6 | grep -i "GNU C Library"     # версия
readelf -s ./libc.so.6 | grep -E "free_hook|malloc_hook"   # есть ли хуки
python3 -c "from pwn import *; print(ELF('./libc.so.6').version)"
```

Затем в gdb посмотрите, включён ли safe-linking: освободите чанк и проверьте `next` — если значение не совпадает с реальным адресом (замаскировано), safe-linking включён. Для tcache key: `x/gx <chunk+8>` после `free` покажет `tcache_perthread_struct`. Эти три проверки (версия, хуки, safe-linking) определяют всё дальнейшее дерево атак.

## Справочник по версиям и техникам

| glibc | Хуки | safe-linking | tcache key | Рекомендуемая атака |
|---|---|---|---|---|
| 2.27 | есть | нет | нет | tcache poisoning, `__free_hook` |
| 2.29 | есть | нет | да | House of Botcake, stashing |
| 2.31 | есть | нет | да | `__free_hook`, Botcake |
| 2.32 | есть | да | да | + heap-утечка, largebin |
| 2.34 | нет | да | да | FSOP, `__exit_funcs`, largebin |
| 2.35+ | нет | да | да | FSOP с `_IO_wfile`, largebin |

Эта таблица — быстрый ориентир: по версии вы сразу отбрасываете нерабочие техники и сосредотачиваетесь на актуальных.

## Итог: как думать о митигациях

Воспринимайте каждую митигацию glibc как ограничение пространства атак, а не как абсолютный барьер. Safe-linking убирает прямолинейный poisoning, но оставляет stashing и largebin; удаление хуков переносит финал на FSOP и `__exit_funcs`; проверка vtable сужает выбор целей, но `_IO_wfile` остаётся. Ваша задача — по версии glibc и доступному примитиву выбрать рабочую технику из таблицы. Регулярно сверяйтесь с исходниками glibc и публичными writeup'ами: защиты развиваются, и «мёртвые» техники иногда возвращаются в новом виде.

## Квиз

```quiz
- question: "Что кодирует safe-linking (glibc 2.32+)?"
  options:
    - "Указатели fd/next в tcache/fastbin"
    - "Canary"
    - "GOT"
    - "vtable"
  answer: 0
  explanation: "safe-linking маскирует fd/next: next = (target>>12) ^ addr."
- question: "Какая версия glibc удалила __malloc_hook/__free_hook?"
  options:
    - "2.34"
    - "2.23"
    - "2.26"
    - "2.40"
  answer: 0
  explanation: "Хуки удалены в 2.34, поэтому цели сместились на FSOP/TLS/exit."
- question: "Что проверяет tcache key при free?"
  options:
    - "Что чанк не освобождается повторно (double-free)"
    - "Размер кучи"
    - "ASLR"
    - "Canary"
  answer: 0
  explanation: "Поле key сравнивается с tcache, детектируя повторный free."
- question: "Что нужно для обхода safe-linking при tcache poisoning?"
  options:
    - "Знать адрес поля fd (heap-утечка) для размаскировки"
    - "Отключить ASLR"
    - "Снять canary"
    - "Расширить fastbin"
  answer: 0
  explanation: "Маскировка зависит от адреса поля, поэтому нужна heap-утечка."
- question: "Какая современная цель для записи вместо __free_hook?"
  options:
    - "_IO_list_all (FSOP), __exit_funcs или tls_dtor_list"
    - "GOT"
    - "canary"
    - "tcache key"
  answer: 0
  explanation: "После удаления хуков используются FSOP/exit/TLS-пути."
```

## Где пригодится

- **CTF:** Pwn — современные glibc-задачи.
- **Bug bounty:** эксплуатация на актуальных системах.
- **Пентест:** разработка эксплойтов.
- **Работа:** security research glibc.
