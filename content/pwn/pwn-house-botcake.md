---
id: pwn-house-botcake
title: "House of Botcake: double-free под tcache"
category: pwn
parent: pwn-tcache-mechanics
difficulty: expert
order: 2
tags: [pwn, heap, glibc, tcache, double-free]
prerequisites: [pwn-heap-tcache, pwn-heap-uaf]
useful_for:
  - "CTF Pwn — heap-задачи"
  - "Разработка эксплойтов"
estimated_minutes: 55
summary: "Обход проверки double-free в tcache (glibc 2.29+) через комбинацию с unsorted bin: слияние и повторное освобождение одного и того же чанка."
---
House of Botcake — это техника double-free под tcache, которая **обходит проверку `key`**, добавленную в glibc 2.29. Когда вы освобождаете чанк, glibc записывает в его поле `key` адрес `tcache_perthread_struct`, и при повторном `free` того же чанка проверяет `e->key == tcache` — если совпало, это double-free и программа падает. House of Botcake обходит это, используя перекрытие чанков и консолидацию в unsortedbin. Атака надёжна и широко применяется в задачах glibc 2.29–2.35. В этом уроке — пошаговый разбор с кодом и проверкой в gdb.

## Идея атаки

Схема: выделяем два смежных чанка `A` и `B` размера, попадающего в tcache (например, 0x100). Заполняем tcache (7 чанков) того же размера, чтобы при освобождении `A`/`B` они **не** попали в tcache, а ушли в unsortedbin (где нет проверки key). Затем освобождаем `A`, освобождаем `B` — они консолидируются в один большой unsortedbin-чанк. Теперь, если освободить `A` ещё раз (double-free), проверка `key` не сработает, потому что `A` был консолидирован в `B` и его `key` перезаписан. Получаем два указателя на пересекающуюся память — примитив для дальнейшего poisoning.

## Пошаговый план

```text
1) Выделить 7 чанков размера S (заполнить tcache S).
2) Выделить A и B (смежные), тоже размера S.
3) free(A); free(B)  -> консолидация в unsortedbin (чанк C = A+B).
4) Выделить чанк размера S из tcache (вернёт один из 7) — освобождает слот в tcache.
5) free(A) снова        -> A уходит в tcache (key-проверка проходит, т.к. key перезаписан).
6) Теперь A присутствует и в unsortedbin (как часть C), и в tcache -> перекрытие.
7) Выделить размер S -> вернётся A из tcache; при этом unsortedbin всё ещё содержит C,
   который пересекается с A -> UAF/overlap.
```

## Разобранный пример

```python
from pwn import *
context.binary = elf = ELF('./chall')
p = process('./chall')

def alloc(sz, data=b'A'):
    p.sendlineafter(b'> ', b'1'); p.sendline(str(sz).encode()); p.sendafter(b'data: ', data)
def free(i):
    p.sendlineafter(b'> ', b'2'); p.sendline(str(i).encode())
def show(i):
    p.sendlineafter(b'> ', b'3'); p.sendline(str(i).encode())
    return p.recvline()

S = 0x100
# 1) заполняем tcache
fillers = [alloc(S) for _ in range(7)]
# 2) A и B
A = alloc(S); B = alloc(S)
# 3) консолидация
free(A); free(B)
# 4) освобождаем слот в tcache
tmp = alloc(S)
# 5) повторный free(A)
free(A)
# 6) теперь A в tcache и в unsortedbin(C)
victim = alloc(S)      # вернёт A из tcache
# 7) overlap: victim пересекается с unsortedbin C
```

После этого можно утечь heap/libc через unsortedbin (`show` чанка C), затем выполнить poisoning, записав подделанный `next` в `victim`.

## Утечка через unsortedbin

Освобождённый в unsortedbin чанк C содержит `fd` и `bk`, указывающие на `main_arena` (в libc). Прочитав их через `show`, вы получаете **утечку libc**:

```python
leak = u64(show(B).strip().ljust(8, b'\x00'))   # bk -> main_arena
libc.address = leak - libc.symbols['main_arena'] - 0x60
log.success('libc @ %#x', libc.address)
```

Смещение `main_arena` зависит от версии; подбирайте в gdb (`p &main_arena`).

## Что делать после overlap

Получив перекрытие, вы можете: (1) подделать `next` в tcache-чанке, чтобы вернуть указатель на произвольный адрес (`__free_hook` на старых glibc, `_IO_2_1_stdout_` или стек на новых); (2) перезаписать размер соседнего чанка и выполнить House of Einherjar; (3) получить arbitrary write и далее — FSOP. House of Botcake — это «входной билет», а финальную цель выбирают по версии glibc.

## Проверка в gdb

```bash
gdb ./chall
(gdb) b *main+200
(gdb) r
(gdb) heap
(gdb) bins           # посмотреть tcache и unsortedbin
(gdb) vis_heap_chunks 20
(gdb) x/4gx <addr_of_A>
```

Убедитесь, что `A` одновременно фигурирует в tcache и внутри unsortedbin-чанка `C`. Команда `bins` покажет counts и entries.

## Обход проверки key: почему работает

Проверка в `free`:

```c
if (__glibc_unlikely (e->key == tcache)) { ... double free detected ... }
```

При консолидации `A` и `B` в `C` поле `key` чанка `A` перезаписывается (оно больше не является tcache-записью). Поэтому повторный `free(A)` видит `key != tcache` и не срабатывает. Это и есть суть обхода.

## Частые ошибки

- **Не заполнен tcache.** Если tcache не полон, `free(A)`/`free(B)` уйдут в tcache, и консолидации не будет.
- **Не смежные чанки.** Между `A` и `B` не должно быть других аллокаций, иначе консолидация не сработает.
- **Неверный размер.** Все чанки должны быть одного размера, попадающего в tcache.
- **Забытый шаг освобождения слота.** Без `tmp = alloc(S)` повторный `free(A)` не попадёт в tcache.
- **Версия glibc.** На 2.35+ проверки могли усилиться — сверяйтесь с целевой версией.
- **main_arena offset.** Утечка libc требует точного смещения `main_arena`.

## Справочные таблицы

| Шаг | Действие | Результат |
|---|---|---|
| 1 | 7×alloc(S) | tcache полон |
| 2 | alloc A, B | смежные чанки |
| 3 | free A; free B | unsortedbin C |
| 4 | alloc(S) | слот в tcache свободен |
| 5 | free A | A в tcache |
| 6 | alloc(S) | overlap A/C |
| 7 | show C | утечка libc |

| Версия | Работает | Примечание |
|---|---|---|
| 2.29–2.31 | да | классика |
| 2.32–2.35 | да | + safe-linking для poisoning |
| 2.35+ | обычно да | проверяйте |

## Что дальше / решение

Дальше: `pwn-heap-tcache` (устройство tcache), `pwn-fastbin-dup` (альтернатива), `pwn-tcache-stashing` (другая атака), `pwn-glibc-mitigations` (эволюция защит), `pwn-fsop` (финальная цель). Практический алгоритм: (1) проверьте версию glibc и наличие tcache key; (2) выделите 7 чанков-заполнителей; (3) создайте смежные A и B; (4) консолидируйте их в unsortedbin; (5) освободите слот и повторите `free(A)`; (6) получите overlap и утечку libc; (7) перейдите к poisoning или FSOP. House of Botcake — надёжный обход double-free-защиты, который стоит отработать на учебной задаче glibc 2.31.
## House of Botcake на glibc 2.32+ и safe-linking

На glibc 2.32 включён safe-linking, который маскирует указатели в tcache и fastbin. Это не ломает House of Botcake, но добавляет требование: для финального poisoning нужно знать heap-базу, чтобы корректно замаскировать `next`. Сама атака (консолидация + повторный free) работает, потому что она оперирует smallbin/unsortedbin, где указатели не маскируются. Порядок действий: (1) выполните Botcake и получите overlap; (2) через overlap утеките heap-адрес (например, прочитав `fd`/`bk` unsortedbin-чанка, которые указывают на `main_arena`, и/или `next` tcache-чанка); (3) вычислите `pos = &tcache_next`, замаскируйте целевой адрес как `target ^ (pos >> 12)`; (4) запишите маскированное значение и вызовите `alloc`. Без heap-утечки poisoning под safe-linking невозможен.

## Альтернативы и сравнение техник

House of Botcake — не единственный обход double-free. Сравнение:

| Техника | Требует | Версия | Сложность |
|---|---|---|---|
| Botcake | tcache полон, 2 смежных чанка | ≥2.29 | средняя |
| tcache stashing | smallbin, unsortedbin | ≥2.29 | высокая |
| fastbin dup | fastbin, 7 чанков | любая | низкая |
| House of Einherjar | off-by-null | любая | высокая |
| largebin attack | largebin, 2 записи | любая | высокая |

Выбор зависит от доступного примитива: если у вас double-free и есть 7 аллокаций — Botcake; если есть off-by-null — Einherjar; если нужна произвольная запись без double-free — largebin. Botcake выигрывает простотой и предсказуемостью на 2.29–2.31.

## Отладка overlap в gdb

Чтобы убедиться, что overlap действительно получен, выполните:

```bash
gdb ./chall
(gdb) b *main+0x200
(gdb) r
(gdb) bins
(gdb) vis_heap_chunks 30
```

В `bins` вы увидите tcache-бин с одним элементом (A) и unsortedbin с чанком C. Проверьте, что адрес A лежит **внутри** диапазона C: `p (char*)A >= (char*)C && (char*)A < (char*)C + size`. Если да — overlap подтверждён. Дополнительно посмотрите поля: `x/4gx A` покажет, что `A->next` указывает в tcache, а `C->fd` — в `main_arena`. Эти два указателя и есть основа дальнейшего эксплойта. Зафиксируйте все адреса и смещения, они понадобятся при сборке финального payload.

## Полный сценарий: от Botcake до shell

Заключительный маршрут: (1) Botcake даёт overlap; (2) утечка libc через unsortedbin (`bk` → `main_arena`); (3) утечка heap (через tcache-чанк или overlap); (4) poisoning: записываем `target` (например, `_IO_2_1_stdout_` или `__exit_funcs`) в tcache `next`; (5) `alloc` дважды, чтобы получить указатель на цель; (6) пишем поддельную структуру `_IO_FILE`; (7) триггерим `exit`. На старых glibc финалом может быть `__free_hook = system` и `free("/bin/sh")`. Каждый шаг проверяйте в gdb — heap-эксплойты чувствительны к точным адресам и размерам.

## Квиз

```quiz
- question: "Что обходит House of Botcake?"
  options:
    - "Проверку double-free в tcache (key)"
    - "ASLR"
    - "Canary"
    - "SMEP"
  answer: 0
  explanation: "Botcake обходит tcache key, комбинируя tcache и unsorted bin."
- question: "Почему при первом free жертва идёт в unsorted, а не в tcache?"
  options:
    - "tcache-бакет уже полон"
    - "Жертва слишком большая"
    - "Отключён tcache"
    - "Включён safe-linking"
  answer: 0
  explanation: "Если tcache заполнен, free направляет чанк в unsorted bin."
- question: "Зачем освобождают соседний чанк?"
  options:
    - "Для консолидации с жертвой (жертва становится частью unsorted-чанка)"
    - "Чтобы снять canary"
    - "Чтобы расширить GOT"
    - "Чтобы включить ASLR"
  answer: 0
  explanation: "Консолидация убирает/меняет состояние жертвы, позволяя повторный free."
- question: "Что нужно сделать перед повторным free жертвы?"
  options:
    - "Освободить место в tcache (выдать один объект)"
    - "Заполнить tcache"
    - "Снять canary"
    - "Отключить ASLR"
  answer: 0
  explanation: "Нужно место в tcache, чтобы повторный free попал именно туда."
- question: "Что даёт Botcake в итоге?"
  options:
    - "Один чанк доступен дважды -> tcache poisoning"
    - "Утечку libc"
    - "Отключение NX"
    - "Снятие canary"
  answer: 0
  explanation: "Двойное использование чанка позволяет отравить tcache."
```

## Где пригодится

- **CTF:** Pwn — modern glibc double-free.
- **Bug bounty:** эксплуатация heap-багов.
- **Пентест:** разработка эксплойтов.
- **Работа:** security research glibc.
