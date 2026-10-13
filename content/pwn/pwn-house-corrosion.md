---
id: pwn-house-corrosion
title: "House of Corrosion: атака на large bin и bk_nextsize"
category: pwn
parent: pwn-modern-houses
difficulty: expert
order: 2
tags: [heap, house-of-corrosion, large-bin, bk_nextsize, glibc, 2.27]
prerequisites: [pwn-house-roman]
useful_for:
  - "CTF Pwn категория"
  - "Modern glibc exploitation"
  - "Vulnerability research"
estimated_minutes: 50
summary: "Разбираем House of Corrosion: эксплуатация large bin через bk_nextsize в glibc 2.27–2.30 и получение произвольной записи."
lab:
  kind: shell
  title: "Практика: смещение bk_nextsize"
  toolset: [core, hex]
  workdir: /home/student/task
  files: [task.md, largebin.bin]
  check: "grep -q 'bk_nextsize=0x28' answer.txt"
  hints:
    - "`xxd largebin.bin` — дамп заголовка чанка."
    - "Поля идут подряд: prev_size, size, fd, bk, fd_nextsize, bk_nextsize."
    - "Каждое поле — 8 байт."
    - "bk_nextsize — шестое поле, смещение 0x28."
---

## Вопрос, с которого всё начинается

Large bin attack, которую мы разбирали, использует поля `fd_nextsize`/`bk_nextsize`. Но её применимость зависит от версии glibc: в каких-то версиях эти поля обрабатывались слишком доверчиво. Отдельная техника, нацеленная именно на этот диапазон, называется **House of Corrosion**. Сегодня разберём, как устроен «размерный» список large bin и почему в glibc 2.27–2.30 он давал запись.

## Наш пример: два large-чанка разного размера

Возьмём программу, которая помещает в large bin два чанка разных размеров и показывает их связи:

```c
#include "common.h"
int main(void){
    char *a  = malloc(0x418);   /* чанк 0x420 */
    char *g1 = malloc(0x20);    /* страж: не даёт a и b слиться */
    char *b  = malloc(0x448);   /* чанк 0x450 */
    char *g2 = malloc(0x20);
    printf("a=%p b=%p\n", a, b);
    free(a); free(b);           /* оба -> unsorted bin */
    char *x = malloc(0x600);    /* триггерит сортировку: a,b -> large bin */
    unsigned long *ca = (unsigned long*)a, *cb = (unsigned long*)b;
    printf("a: fd=%p bk=%p fd_ns=%p bk_ns=%p\n",
           (void*)ca[0], (void*)ca[1], (void*)ca[2], (void*)ca[3]);
    printf("b: fd=%p bk=%p fd_ns=%p bk_ns=%p\n",
           (void*)cb[0], (void*)cb[1], (void*)cb[2], (void*)cb[3]);
    return 0;
}
```

Стражи `g1`/`g2` нужны, чтобы освобождённые `a` и `b` не слились в один чанк (иначе large bin получит один большой чанк вместо двух). А `malloc(0x600)` заставляет glibc отсортировать чанки из unsorted bin в large bin.

## Шаг 1. Структура large-чанка

У large-чанка есть два дополнительных поля, которых нет у small-чанка:

| Смещение | Поле | Назначение |
|---|---|---|
| `+0x10` | `fd` | следующий в обычном списке |
| `+0x18` | `bk` | предыдущий в обычном списке |
| `+0x20` | `fd_nextsize` | следующий чанк другого размера |
| `+0x28` | `bk_nextsize` | предыдущий чанк другого размера |

Large bin хранит чанки **отсортированными по размеру**, и `nextsize`-поля связывают чанки разных размеров в отдельный список. Именно эти поля — мишень House of Corrosion.

## Шаг 2. Смотрим реальные связи

```
$ gcc -fno-pie -no-pie -O0 -o corrosion corrosion.c
$ ./corrosion
a=0x306f3020 b=0x306f3470
a: fd=0x7f862d071eb8 bk=0x7f862d071eb8 fd_ns=0x306f3010 bk_ns=0x306f3010
b: fd=0x7f862d071ec8 bk=0x7f862d071ec8 fd_ns=0x306f3460 bk_ns=0x306f3460
```

Читаем:

- `fd`/`bk` обоих чанков указывают в libc (`0x7f86…`) — на головы списков large bin внутри `main_arena`. Это готовая утечка libc.
- `fd_ns`/`bk_ns` указывают на сами чанки минус `0x10` (например, `0x306f3010 = a − 0x10`). Это «размерные» связи; у каждого размера свой подсписок.

## Шаг 3. Механика House of Corrosion

Когда `malloc` вставляет новый чанк в large bin, он идёт по размерному списку и обновляет `nextsize`-связи. В glibc 2.27–2.30 одна из этих операций выполнялась без достаточной проверки:

```c
victim->bk_nextsize->fd_nextsize = victim;   /* ЗАПИСЬ */
```

Если подделать `victim->bk_nextsize` на `target − 0x20`, то по адресу `target` (точнее, в поле `fd_nextsize`, смещение `0x20`) запишется адрес `victim` — heap-указатель. Это и есть произвольная запись адреса чанка.

Схема атаки:

1. Наполнить large bin чанками разных размеров (чтобы список был «населён»).
2. Через UAF/переполнение подделать `bk_nextsize` нужного чанка на `target − 0x20`.
3. Триггерить вставку нового чанка так, чтобы выполнилась строка с записью.
4. Получить heap-указатель по адресу `target`.

Разберём подробнее, зачем large bin вообще нужен второй список. В small bin все чанки одного размера, и обычного `fd`/`bk` достаточно. В large bin размеры разные, и чтобы быстро находить подходящий по размеру чанк, glibc поддерживает второй, «размерный» список: каждый чанк дополнительно связан с ближайшим меньшим/большим по размеру. Когда чанк вставляется, glibc проходит этот размерный список, находит место по размеру и переписывает четыре указателя: два у вставляемого чанка и по одному у соседей. Именно последний из них — `bk_nextsize->fd_nextsize = victim` — и является записью.

Ключевая мысль: значение, которое записывается, — это **адрес чанка** (`victim`), а не произвольное число. Поэтому House of Corrosion (как и large bin attack) применяют там, где нужен именно heap-указатель: например, чтобы установить `_IO_list_all` на поддельный `_IO_FILE` или подменить указатель в структуре приложения. Адрес записи равен `victim->bk_nextsize + 0x20` — отсюда вычитание `0x20` при подделке.

Заметь ещё, что обычные `fd`/`bk` large-чанка, указывающие в `main_arena`, дают утечку libc независимо от версии. Так что даже на новых glibc large bin остаётся источником утечки, а запись через `nextsize` — уже вопрос версии и проверок.

## Шаг 4. Почему это диапазон версий

House of Corrosion привязана к конкретным версиям glibc:

| Версия glibc | Состояние |
|---|---|
| 2.27–2.30 | `bk_nextsize` обрабатывается слабо → атака работает |
| 2.31+ | добавлены проверки консистентности nextsize |
| 2.32+ | safe-linking (не влияет на large bin, но меняет окружение) |

Наш демонстрационный запуск идёт на glibc 2.43, где проверки строже: наивная подделка `bk_nextsize` не даёт запись, а в ряде случаев приводит к `corrupted double-linked list (not small)`. Поэтому House of Corrosion — техника **историческая**, но она объясняет устройство размерного списка, которое важно и для современной large bin attack.

## Шаг 5. Как понять, что версия подходит

Первым делом определите версию libc:

```
$ ldd --version | head -1
ldd (GNU libc) 2.43
```

Если версия в диапазоне 2.27–2.30, House of Corrosion применима напрямую. Если новее — используйте large bin attack (она пережила митигации) или FSOP. В отладчике проверяйте состояние large bin командой `bins` и поля чанка через `x/8gx <addr>`.

## Если не сработало

- **`corrupted double-linked list (not small)`.** Проверки large bin не пройдены — версия новее 2.30.
- **Чанк не в large bin.** Размер < `0x400` уходит в small bin.
- **Чанки слились.** Нужны стражи между ними.
- **tcache перехватил.** Размер должен быть выше `tcache_max`.
- **Неверная цель.** Записывается heap-адрес — цель должна быть указателем на структуру.

## Что мы теперь знаем

- Large bin хранит чанки, отсортированные по размеру, и использует `fd_nextsize`/`bk_nextsize`.
- Смещения: `fd_ns = 0x20`, `bk_ns = 0x28`.
- Вставка чанка выполняет `bk_nextsize->fd_nextsize = victim` — запись.
- Подделка `bk_nextsize` даёт запись heap-адреса по цели.
- House of Corrosion работает на glibc 2.27–2.30; новее — проверки.
- `fd`/`bk` large-чанка дают утечку libc.

## На что смотреть дальше

- **Версия libc.** Ключевой фактор применимости.
- **Стражи.** Чтобы чанки не сливались.
- **Цель.** `_IO_list_all`, GOT, `__exit_funcs`.
- **Отладка.** `bins`, `x/8gx` — сверяйте nextsize до/после.
- **Современная замена.** large bin attack + FSOP.

## Квиз

Проверь себя.

```quiz
- question: "Какие поля есть только у large-чанка?"
  options:
    - "fd_nextsize и bk_nextsize"
    - "fd и bk"
    - "prev_size и size"
    - "canary"
  answer: 0
  explanation: "Они связывают чанки разных размеров в отсортированном large bin."
- question: "На каком смещении от начала чанка лежит bk_nextsize?"
  options:
    - "0x28"
    - "0x10"
    - "0x18"
    - "0x20"
  answer: 0
  explanation: "fd_nextsize = 0x20, bk_nextsize = 0x28."
- question: "Какое значение записывает House of Corrosion?"
  options:
    - "Адрес вставляемого чанка (heap-указатель)"
    - "Адрес main_arena"
    - "Ноль"
    - "Адрес стека"
  answer: 0
  explanation: "Выполняется bk_nextsize->fd_nextsize = victim."
- question: "В каком диапазоне версий glibc работает House of Corrosion?"
  options:
    - "примерно 2.27–2.30"
    - "только 2.23"
    - "2.35+"
    - "все версии без исключения"
  answer: 0
  explanation: "Позже добавили проверки консистентности nextsize."
- question: "Почему нужны страж-чанки между большими?"
  options:
    - "Чтобы освобождённые чанки не слились в один"
    - "Чтобы включить ASLR"
    - "Чтобы снять canary"
    - "Чтобы расширить GOT"
  answer: 0
  explanation: "Иначе backward consolidation объединит соседние чанки."
```

## Куда дальше

В `pwn-house-water` мы разберём FSOP-цепочку через `_IO_list_all` — то, во что в конечном счёте превращается любая запись адреса на modern glibc. А пока главное: **large bin хранит размерные связи `nextsize`, и их подделка в старых версиях давала запись heap-адреса.**

## Где пригодится

- **CTF:** large-bin задачи на glibc 2.27–2.30.
- **Bug bounty:** эксплуатация heap-багов на больших объектах.
- **Пентест:** обход hardening в реальных сервисах.
- **Работа:** research актуальных heap-техник.
