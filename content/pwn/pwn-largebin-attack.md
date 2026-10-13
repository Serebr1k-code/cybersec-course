---
id: pwn-largebin-attack
title: "Large bin attack: произвольная запись через большие чанки"
category: pwn
parent: pwn-heap-bin-attacks
difficulty: expert
order: 2
tags: [pwn, heap, glibc, largebin, malloc]
prerequisites: [pwn-heap-basics, pwn-heap-uaf]
useful_for:
  - "CTF Pwn — heap-задачи"
  - "Разработка эксплойтов"
estimated_minutes: 45
summary: "Устройство large bin в glibc, почему вставка чанка даёт запись указателя по контролируемому адресу и как применять примитив на современном glibc."
lab:
  kind: shell
  title: "Практика: граница large bin"
  toolset: [core, objdump]
  workdir: /home/student/task
  files: [task.md, largebin.c, largebin, run.txt]
  check: "grep -q 'threshold=0x400' answer.txt"
  hints:
    - "`cat largebin.c` — размер чанка 0x420."
    - "`cat run.txt` — чанк сортируется в large bin."
    - "Граница между small и large bins — 0x400."
    - "Запиши `threshold=0x400`."
---

## Вопрос, с которого всё начинается

Unsorted bin attack умела писать адрес libc, но на glibc 2.29 её закрыли проверкой. Как же тогда в современных задачах получают **произвольную запись**, да ещё и без double-free? Ответ — в другом списке: large bin. Чанки там отсортированы по размеру и связаны дополнительными указателями `fd_nextsize`/`bk_nextsize`. Подделав один из них, можно заставить `malloc` записать адрес чанка по выбранному адресу. Это **large bin attack**.

## Наш пример: два больших чанка

Возьмём программу, которая освобождает большой чанк и показывает его связи в large bin:

```c
#include "common.h"
int main(void){
    char *a = malloc(0x418);          /* чанк 0x420 -> largebin (>= 0x400) */
    char *b = malloc(0x418);
    char *guard = malloc(0x20);
    printf("a=%p b=%p\n", a, b);
    free(a);                          /* a -> unsorted bin */
    char *big = malloc(0x500);        /* триггерит сортировку: a уходит в largebin */
    unsigned long *c = (unsigned long*)a;
    printf("  fd=%p  bk=%p\n", (void*)c[0], (void*)c[1]);
    printf("  fd_nextsize=%p  bk_nextsize=%p\n", (void*)c[2], (void*)c[3]);
    ...
}
```

Почему `0x420`? Граница между small и large bins — `0x400`: чанки размером `≥ 0x400` идут в large bin. А `guard` не даёт чанку `a` слиться с top chunk, чтобы он остался отдельным.

## Шаг 1. Устройство large bin

В отличие от small bin, чанки в large bin **отсортированы по размеру**, и каждый чанк дополнительно связан с соседями *другого* размера через `fd_nextsize`/`bk_nextsize`. Смещения полей от начала чанка:

| Поле | Смещение | Смысл |
|---|---|---|
| `fd` | `0x10` | сосед в списке (тот же размер) |
| `bk` | `0x18` | сосед в списке (тот же размер) |
| `fd_nextsize` | `0x20` | следующий чанк другого размера |
| `bk_nextsize` | `0x28` | предыдущий чанк другого размера |

## Шаг 2. Смотрим реальные указатели

Компилируем и запускаем:

```
$ gcc -fno-pie -no-pie -O0 -o largebin largebin.c
$ ./largebin
a=0x127e9020 b=0x127e9440
a в largebin:
  fd=0x7f0eb79a6eb8  bk=0x7f0eb79a6eb8
  fd_nextsize=0x127e9010  bk_nextsize=0x127e9010
```

Читаем:

- `fd`/`bk` равны `0x7f…` — адрес в libc. Это голова large bin (внутри `main_arena`). Значит, чанк `a` — единственный, и оба указателя смотрят на список.
- `fd_nextsize`/`bk_nextsize` равны `0x127e9010` — это адрес **самого чанка** `a` минус `0x10` (шапка). Когда чанк в списке один, его `nextsize`-связи замкнуты на себя.

Почему «минус `0x10`»? Потому что `nextsize`-указатели тоже ссылаются на **начало шапки** чанка, а не на данные. Наш указатель `a` — это данные, то есть шапка на `0x10` раньше. Поэтому `fd_nextsize`/`bk_nextsize` и показывают `a - 0x10`. Это важно запомнить: все указатели в бинах адресуют шапку чанка.

Заметь, что `fd`/`bk` указывают в libc, а `nextsize` — в кучу. Когда чанков разного размера несколько, `nextsize` связывают их в отсортированную цепочку. Именно по этой цепочке и «проедет» запись при вставке нового чанка.

## Шаг 3. Механика атаки

Когда `malloc` вставляет новый чанк `victim` в large bin, выполняется такая последовательность:

```c
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;
fwd->bk_nextsize = victim;
victim->bk_nextsize->fd_nextsize = victim;   /* ЗАПИСЬ */
```

Последняя строка пишет адрес `victim` в поле `fd_nextsize` чанка, лежащего по адресу `victim->bk_nextsize`. Поле `fd_nextsize` — на смещении `0x20`, значит запись идёт по `victim->bk_nextsize + 0x20`. Если подделать `victim->bk_nextsize = target - 0x20`, то по адресу `target` ляжет адрес `victim`. Произвольная запись **адреса чанка**.

Важно: записывается именно адрес чанка, а не произвольное значение. Поэтому цель должна быть указателем на структуру, которую вы контролируете (например, `_IO_list_all`), чтобы дальше подсунуть туда поддельный `_IO_FILE`.

## Шаг 4. Пробуем на современной glibc

Подделываем `bk_nextsize` у чанка `a` и триггерим вставку маленького чанка в large bin:

```c
unsigned long target = 0x4040a0;
c[3] = target - 0x20;                 /* a->bk_nextsize = target - 0x20 */
char *sm = malloc(0x100);
free(sm);                             /* sm -> unsorted */
char *t = malloc(0x500);              /* вставка sm в largebin */
printf("*(target)=%p\n", *(void**)target);
```

Запускаем:

```
$ ./largebin
подделываем a->bk_nextsize = 0x404080 (target-0x20)
corrupted double-linked list (not small)
Aborted (core dumped)
```

Атака **не проходит**: glibc падает с `corrupted double-linked list (not small)`. Это проверка, добавленная в 2.30: перед записью `malloc` сверяет, что `bck->fd == victim` и связи `nextsize` согласованы. Наивная подделка одного `bk_nextsize` ломает целостность — и аллокатор обрывается.

## Шаг 5. Как обходят проверку

Проверка требует, чтобы цель `target` уже содержала ожидаемый указатель, и чтобы связи large bin оставались согласованными. На практике это делают так:

1. **Два чанка разного размера в large bin.** Вставляют `victim` так, чтобы ветка кода с записью выполнилась при уже согласованных `fwd->bk`. Тогда проверка проходит, а запись всё равно происходит по `victim->bk_nextsize + 0x20`.
2. **House of God / House of Apple.** Large bin attack — их первый шаг: записать адрес контролируемого чанка в `_IO_list_all`, затем подделать `_IO_FILE` и вызвать `exit`. На glibc 2.34+ (где удалены `__free_hook`/`__malloc_hook`) это основной путь к исполнению.
3. **Другие цели.** `global_max_fast` (расширить fastbin), `mp_.tcache_bins` (расширить tcache), `__exit_funcs`.

Ключевое преимущество large bin attack: указатели в large bin **не маскируются safe-linking**, поэтому атака работает и на glibc 2.32+.

## Если не сработало

- **`corrupted double-linked list (not small)`.** Наивная подделка `bk_nextsize` не проходит проверку. Нужны согласованные связи — вставляйте так, чтобы выполнялось предусловие.
- **Чанк не в large bin.** Размер < `0x400` уходит в small bin. Берите ≥ `0x400`.
- **Чанк не отсортирован.** Пока чанк в unsorted bin, он не в large bin; нужен дополнительный `malloc` для сортировки.
- **Неверная цель.** Записывается адрес чанка — цель обязана быть указателем на контролируемую структуру.
- **Версия glibc.** Проверки в largebin path менялись; сверяйтесь с исходником `_int_malloc` для своей версии.

## Что мы теперь знаем

- Large bin — список чанков ≥ `0x400`, отсортированный по размеру.
- У чанков есть дополнительные поля `fd_nextsize`/`bk_nextsize` (смещения `0x20`/`0x28`).
- При вставке `malloc` пишет адрес `victim` по `victim->bk_nextsize + 0x20`.
- Подделав `bk_nextsize`, получаем запись адреса чанка по выбранному адресу.
- С glibc 2.30 проверка целостности блокирует наивный вариант.
- Safe-linking на large bin не действует — техника живёт на всех версиях.

## На что смотреть дальше

- **Предусловие проверки.** Цель должна содержать ожидаемый указатель.
- **Выбор цели.** `_IO_list_all` (FSOP), `global_max_fast`, `mp_.tcache_bins`.
- **Порядок операций.** Сначала подготовьте large bin, затем вставляйте `victim`.
- **Отладка.** `bins` и `x/8gx <addr>` в pwndbg показывают связи `nextsize`.
- **Цепочка целиком.** Large bin — только шаг; планируйте FSOP наперёд.

## Квиз

Проверь себя.

```quiz
- question: "Какой минимальный размер (на 64-бит) нужен чанку, чтобы попасть в large bin?"
  options:
    - "0x80"
    - "0x400"
    - "0x20"
    - "0x10000"
  answer: 1
  explanation: "MIN_LARGE_SIZE = 0x400 на 64-бит; меньшие уходят в small bins."
- question: "Какое значение записывается примитивом large bin attack?"
  options:
    - "Адрес вставляемого чанка victim"
    - "Адрес main_arena"
    - "Ноль"
    - "Указатель на стек"
  answer: 0
  explanation: "Выполняется victim->bk_nextsize->fd_nextsize = victim, где victim — heap-адрес."
- question: "Какая проверка мешает наивной атаке с glibc 2.30+?"
  options:
    - "Сверка целостности связей nextsize (иначе corrupted double-linked list)"
    - "Шифрование safe-linking"
    - "Запрет чанков > 0x1000"
    - "Полное отключение large bins"
  answer: 0
  explanation: "Аллокатор проверяет согласованность bck->fd и nextsize-связей."
- question: "Почему нужен дополнительный malloc после free большого чанка?"
  options:
    - "Чтобы чанк отсортировался из unsorted bin в large bin"
    - "Чтобы сбросить кэш процессора"
    - "Чтобы увеличить энтропию ASLR"
    - "Чтобы очистить tcache"
  answer: 0
  explanation: "Пока чанк в unsorted bin, он не в large bin; сортировка — при следующем malloc."
- question: "Почему large bin attack работает и на glibc 2.32+?"
  options:
    - "Указатели large bin не маскируются safe-linking"
    - "safe-linking отключается автоматически"
    - "Она использует tcache"
    - "Она не пишет по адресу"
  answer: 0
  explanation: "safe-linking защищает только fastbin/tcache, а не nextsize-связи large bin."
```

## Куда дальше

В `pwn-mmap-exploitation` мы разберём чанки, которые glibc создаёт через `mmap`, и атаки вроде House of Muney. А пока главное: **large bin даёт запись адреса чанка через `bk_nextsize`, и это работает даже на новых glibc.**

## Где пригодится

- **CTF:** категория Pwn — heap-задачи уровня expert, где нужен write-primitive без утечки libc.
- **Bug bounty:** понимание внутренностей malloc помогает в задачах на real-world heap-уязвимости в сервисах.
- **Пентест:** эксплуатация heap-багов в нативных сервисах (парсеры, демоны).
- **Работа:** разработка эксплойтов, анализ glibc-митигаций, security research.
