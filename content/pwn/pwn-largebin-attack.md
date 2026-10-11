---
id: pwn-largebin-attack
title: "Large bin attack: произвольная запись через большие чанки"
category: pwn
parent: pwn-heap-bin-attacks
difficulty: expert
order: 3
tags: [pwn, heap, glibc, largebin, malloc]
prerequisites: [pwn-heap-basics, pwn-heap-uaf]
useful_for:
  - "CTF Pwn — heap-задачи"
  - "Разработка эксплойтов"
estimated_minutes: 45
summary: "Устройство large bin в glibc, почему вставка чанка даёт запись указателя по контролируемому адресу и как применять примитив на современном glibc."
---
Large bin attack — это техника произвольной записи через манипуляцию largebin (бины для чанков размером ≥ 0x400). Она не требует double-free, не зависит от tcache и работает на всех современных glibc (даже с safe-linking). При вставке чанка в largebin glibc записывает указатели в поля `bk_nextsize`/`fd_nextsize` соседних чанков; подделав эти поля, можно записать произвольное значение по произвольному адресу. Largebin attack — фундамент многих современных цепочек (FSOP через `_IO_list_all`, House of God). В этом уроке — устройство largebin, механика атаки, пошаговый эксплойт и практические сценарии.

## Устройство largebin

Largebin содержит чанки размером ≥ 0x400 (для 64-бит). В отличие от smallbin, чанки в largebin **отсортированы** по размеру, и каждый чанк имеет дополнительные поля `fd_nextsize`/`bk_nextsize`, связывающие чанки разного размера. При вставке нового чанка glibc находит его место в отсортированном списке и обновляет указатели `nextsize`. Именно эти обновления — цель атаки.

## Механика атаки

При вставке чанка `victim` в largebin glibc выполняет примерно:

```c
// находим позицию по размеру
fwd = bck->fd;
// обновляем nextsize-связи
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;
fwd->bk_nextsize = victim;
victim->bk_nextsize->fd_nextsize = victim;   // <-- запись по victim->bk_nextsize + 0x20
```

Если подделать `victim->bk_nextsize` (через UAF/overflow), то запись `victim->bk_nextsize->fd_nextsize = victim` произойдёт по адресу `fake + 0x20`, где `fake` — подделанный указатель. Это даёт произвольную запись значения `victim` (адреса чанка) по выбранному адресу.

## Пошаговый эксплойт

```text
1) Выделить largebin-чанк A (размер >= 0x400) и smallbin-чанк B.
2) Освободить A -> он попадает в unsortedbin, затем при следующей аллокации
   переходит в largebin.
3) Освободить B -> unsortedbin.
4) Через UAF/overflow подделать A->bk_nextsize = target - 0x20.
5) Аллоцировать так, чтобы B вставился в largebin (trigger insert).
6) Запись: target = адрес B (значение victim).
7) Использовать запись (например, перезаписать _IO_list_all -> FSOP).
```

## Разобранный пример

```python
from pwn import *
context.binary = elf = ELF('./chall')
p = process('./chall')

# 1) largebin-чанки
a = alloc(0x500)
b = alloc(0x500)
# 2) подготовить largebin
free(a)
alloc(0x600)         # a уходит в largebin
# 3) smallbin-жертва
c = alloc(0x100)
free(c)
# 4) подделка bk_nextsize
target = libc.sym['_IO_list_all']
edit(a, p64(0)*2 + p64(0) + p64(target - 0x20))
# 5) триггер вставки
alloc(0x600)
# 6) target теперь содержит адрес c -> используем для FSOP
```

Точные смещения и последовательность зависят от glibc; проверяйте в gdb.

## Цели атаки

Обычные цели: `_IO_list_all` (для FSOP), `__exit_funcs`, `_IO_2_1_stdout_`, `global_max_fast` (для fastbin-атак), `mp_.tcache_bins`, указатели в приложении. Largebin attack даёт запись **адреса чанка** (не произвольного значения), поэтому цель должна быть указателем на структуру, которую вы контролируете.

## Проверка в gdb

```bash
gdb ./chall
(gdb) bins
(gdb) vis_heap_chunks 40
(gdb) p main_arena.bins[<idx>]
(gdb) x/8gx <addr_a>
```

Смотрите `fd_nextsize`/`bk_nextsize` и состояние largebin до/после вставки.

## Частые ошибки

- **Неверный размер.** Чанк должен попадать в largebin (≥ 0x400).
- **Не тот порядок.** Вставка в largebin требует правильной последовательности.
- **Safe-linking.** Не влияет на largebin (указатели не маскируются).
- **Версия glibc.** Механика стабильна, но смещения полей проверяйте.
- **Цель.** Нужна цель-указатель на контролируемую структуру.

## Справочные таблицы

| Бин | Размер | Особенность |
|---|---|---|
| fastbin | < 0x80 | LIFO |
| smallbin | < 0x400 | двусвязный |
| largebin | ≥ 0x400 | отсортирован, nextsize |
| unsortedbin | — | промежуточный |

| Поле | Смещение |
|---|---|
| `fd` | 0x10 |
| `bk` | 0x18 |
| `fd_nextsize` | 0x20 |
| `bk_nextsize` | 0x28 |

## Что дальше / решение

Дальше: `pwn-fsop`, `pwn-house-modern`, `pwn-glibc-mitigations`, `pwn-heap-basics`. Практический алгоритм: (1) подготовьте largebin (чанк ≥ 0x400); (2) освободите smallbin-жертву; (3) подделайте `bk_nextsize` на `target - 0x20`; (4) триггерните вставку в largebin; (5) получите запись адреса жертвы по target; (6) используйте для FSOP/`_IO_list_all`. Largebin attack — универсальная техника, работающая на всех glibc; освоив её, вы получите произвольную запись без double-free.
## Полный разбор largebin attack

Разберём сквозной пример. Дано: glibc 2.31, heap-меню с UAF/edit, цель — FSOP. Шаги: (1) выделите два больших чанка (`A` и `B`, ≥ 0x400); (2) освободите `A` — он попадёт в unsortedbin; (3) аллоцируйте чанк большего размера, чтобы `A` перешёл в largebin; (4) выделите smallbin-жертву `C` и освободите её — она в unsortedbin; (5) через UAF/edit подделайте `A->bk_nextsize = target - 0x20` (где `target` — например, `_IO_list_all`); (6) триггерните вставку `C` в largebin (аллокацией подходящего размера); (7) glibc выполнит `victim->bk_nextsize->fd_nextsize = victim`, записав адрес `C` по `target`; (8) теперь `_IO_list_all` указывает на `C` — подделайте `_IO_FILE` в `C` и триггерните `exit`. Проверяйте в gdb: `bins`, `x/8gx A`, `x/8gx target`. Точные смещения (`bk_nextsize` = 0x28) и порядок операций зависят от версии; сверяйте.

## Largebin attack в современных цепочках

Largebin attack — ключевой элемент House of God и других современных техник. Она даёт запись **адреса чанка** по произвольному адресу, что идеально для установки `_IO_list_all`/`__exit_funcs` на поддельную структуру. После записи вы конструируете `_IO_FILE` (FSOP) и триггерите `exit`. На glibc 2.34+ (нет хуков) это основной путь к исполнению. Также largebin attack используют для перезаписи `global_max_fast` (включая fastbin-атаки) и `mp_.tcache_bins`. Комбинируйте с House of Apple/Kiwi для финального вызова. Изучайте порядок обновления `nextsize` в исходниках glibc (`_int_malloc`, largebin path).

## Тонкости и версии

Механика largebin attack стабильна между версиями, но детали (смещения полей, проверки) могут отличаться. На glibc 2.31 поле `bk_nextsize` по смещению 0x28; на других версиях проверяйте. Safe-linking не влияет на largebin (указатели не маскируются), поэтому атака работает даже на 2.32+. Однако некоторые версии добавили проверки целостности largebin — сверяйтесь. Для успеха нужен чанк ≥ 0x400 и правильная последовательность (unsortedbin → largebin). Проверяйте в gdb состояние бинов и полей `nextsize` перед триггером. Помните, что largebin attack требует контроля над `bk_nextsize` (через UAF/overflow), поэтому нужен соответствующий примитив.

## Практические рекомендации

Подготовьте largebin (чанк ≥ 0x400), smallbin-жертву, подделайте `bk_nextsize`, триггерните вставку. Используйте для FSOP (`_IO_list_all`) или `global_max_fast`. Проверяйте в gdb. Largebin attack — универсальная техника, работающая на всех glibc; освоив её, вы сможете строить цепочки без double-free и tcache. Практикуйтесь на учебных задачах glibc 2.31 и 2.35, комбинируя с House of Apple/God.
## Largebin attack: детали реализации glibc

Разберём точную механику в `_int_malloc` (largebin path). Когда чанк вставляется в largebin, glibc выполняет:

```c
if (fwd->size > victim->size) {   // вставка в середину
    victim->fd_nextsize = fwd;
    victim->bk_nextsize = fwd->bk_nextsize;
    fwd->bk_nextsize = victim;
    victim->bk_nextsize->fd_nextsize = victim;   // запись #1
} else {
    victim->fd_nextsize = fwd;
    victim->bk_nextsize = fwd->bk_nextsize;
    fwd->bk_nextsize = victim;
    victim->bk_nextsize->fd_nextsize = victim;   // запись #2
}
```

В обоих случаях последняя строка выполняет запись `victim` по адресу `victim->bk_nextsize + 0x20` (смещение `fd_nextsize`). Подделав `victim->bk_nextsize = target - 0x20`, вы пишете адрес `victim` по `target`. Это и есть largebin attack. Точное смещение `fd_nextsize` (0x20) и `bk_nextsize` (0x28) зависит от структуры `malloc_chunk`; проверяйте в gdb. Условие входа (`fwd->size > victim->size`) влияет на то, какая ветка выполнится, — учитывайте размеры.

## Выбор цели и последующие шаги

Поскольку записывается **адрес чанка** (`victim`), цель должна быть указателем на структуру, которую вы контролируете. Идеальные цели: `_IO_list_all` (для FSOP), `__exit_funcs`, `_IO_2_1_stdout_`. После записи `_IO_list_all = victim`, вы подделываете `_IO_FILE` в `victim` и триггерите `exit` (см. House of God/Apple). Альтернативы: `global_max_fast` (для включения fastbin-атак — запись большого значения), `mp_.tcache_bins` (расширение tcache). Каждая цель требует своей последующей цепочки. Планируйте весь эксплойт, а не только largebin-шаг.

## Тонкости версий и проверки

Largebin attack работает на glibc от 2.23 до современных. На 2.32+ safe-linking не влияет (указатели largebin не маскируются). Однако некоторые версии добавили проверки целостности largebin (`malloc_printerr` при неверных `nextsize`), поэтому убедитесь, что подделка корректна. На glibc 2.31 (Ubuntu 20.04) атака классическая; на 2.35 проверки строже, но атака всё ещё применима (largebin attack пережила митигации). Сверяйте исходники `_int_malloc` для вашей версии. Проверяйте в gdb: после вставки `x/8gx target` должен показать адрес `victim`.

## Практические рекомендации

Подготовьте largebin (чанк ≥ 0x400), smallbin-жертву, подделайте `bk_nextsize`, триггерните вставку. Используйте для FSOP (`_IO_list_all`) или `global_max_fast`. Проверяйте в gdb. Largebin attack — универсальная техника, работающая на всех glibc; освоив её, вы сможете строить цепочки без double-free и tcache. Практикуйтесь на задачах glibc 2.31 и 2.35, комбинируя с House of Apple/God и FSOP.

## Квиз

```quiz
- question: "Какой минимальный размер (на 64-бит) нужен чанку, чтобы попасть в large bin?"
  options:
    - "0x80"
    - "0x400"
    - "0x20"
    - "0x10000"
  answer: 1
  explanation: "MIN_LARGE_SIZE = 0x400 на 64-битных системах; меньшие размеры уходят в small bins."
- question: "Какое значение записывается примитивом large bin attack в адрес bck->fd?"
  options:
    - "Адрес нового (вставляемого) чанка victim"
    - "Адрес main_arena"
    - "Ноль"
    - "Указатель на libc"
  answer: 0
  explanation: "Выполняется bck->fd = victim, где victim — свежевставленный large-чанк (heap-адрес)."
- question: "Что делает проверка в glibc 2.30+, мешающая слепому large bin attack?"
  options:
    - "Проверяет, что bck->fd == fwd, иначе malloc_printerr"
    - "Шифрует указатели safe-linking"
    - "Запрещает чанки больше 0x1000"
    - "Отключает large bins полностью"
  answer: 0
  explanation: "Добавлено условие bck->fd != fwd -> abort, поэтому цель уже должна содержать fwd."
- question: "Почему для срабатывания атаки нужен ещё один malloc после free?"
  options:
    - "Чтобы чанк отсортировался из unsorted bin в large bin"
    - "Чтобы сбросить кэш процессора"
    - "Чтобы увеличить ASLR-энтропию"
    - "Чтобы освободить tcache"
  answer: 0
  explanation: "Пока чанк в unsorted bin, он не в large bin; сортировка происходит при следующем malloc."
```

## Где пригодится

- **CTF:** категория Pwn — heap-задачи уровня expert, где нужен write-primitive без утечки libc.
- **Bug bounty:** понимание внутренностей malloc помогает в задачах на real-world heap-уязвимости в сервисах.
- **Пентест:** эксплуатация heap-багов в нативных сервисах (парсеры, демоны).
- **Работа:** разработка эксплойтов, анализ glibc-митигаций, security research.
