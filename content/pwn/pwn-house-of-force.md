---
id: pwn-house-of-force
title: "House of Force / Spirit / Orange"
category: pwn
parent: pwn-heap-house
difficulty: hard
order: 3
tags: [heap, house-of-force, house-of-spirit, house-of-orange, top-chunk]
prerequisites: [pwn-heap-basics, pwn-fastbin-dup]
useful_for:
  - "CTF Pwn категория"
  - "Эксплуатация heap-уязвимостей"
  - "Vulnerability research"
estimated_minutes: 70
summary: "Разбираем три классические heap-техники: House of Force (перезапись top chunk), House of Spirit (поддельный fastbin) и House of Orange (unsorted bin -> FSOP) с полным разбором каждой."
lab:
  kind: shell
  title: "Практика: sentinel для top->size"
  toolset: [core]
  workdir: /home/student/task
  files: [task.md, force.c, run.txt, libc.strings]
  check: "grep -q 'size=0xffffffffffffffff' answer.txt"
  hints:
    - "`cat force.c` и `cat run.txt`."
    - "Оригинальный House of Force писал в top->size максимальное значение."
    - "Это SIZE_MAX — все 64 бита в единице."
    - "Запиши `size=0xffffffffffffffff`."
---

## Вопрос, с которого всё начинается

До сих пор мы атаковали чанки в списках свободных. Но есть ещё один особый чанк — **top chunk**, «вершина» кучи, из которой `malloc` отрезает память, когда списки пусты. Если переполнить поле `size` этого чанка, можно заставить `malloc` выдать память в любой точке адресного пространства. Сегодня разберём три классические «домашние» техники: House of Force, House of Spirit и House of Orange.

## Наш пример: чанк рядом с top

Возьмём программу, которая аллоцирует один чанк и перезаписывает размер следующего за ним top-чанка:

```c
#include "common.h"
int main(void){
    char *a = malloc(0x18);                        /* чанк 0x20 */
    unsigned long *top = (unsigned long*)(a + 0x10);/* сразу за a лежит top */
    printf("a=%p  top size=0x%lx\n", a, top[1]);
    puts("пишем в top size мусор 0xdeadbeef ...");
    top[1] = 0xdeadbeef;
    puts("malloc(0x100) -> sysmalloc проверяет top ...");
    char *b = malloc(0x100);
    printf("b=%p\n", b);
    return 0;
}
```

Адрес top вычисляется просто: чанк `a` занимает `0x20` байт, поэтому top начинается сразу после него, а его поле `size` — на `a + 0x10 + 8 = a + 0x18`.

## Шаг 1. Что такое top chunk

Top chunk — последний чанк в куче. Его `size` показывает, сколько свободной памяти осталось. Когда `malloc` не находит подходящий чанк в бинах, он «отрезает» нужный кусок от top. Проверка в `_int_malloc` примерно такая:

```c
if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE)) {
    remainder = chunk_at_offset(victim, nb);
    set_head(victim, nb | PREV_INUSE);
}
```

`nb` — запрошенный размер. Если `size` top больше `nb`, отрезаем. Подделав `size` на огромное значение, можно «разрешить» любую аллокацию.

## Шаг 2. Что происходит на современной glibc

Запускаем:

```
$ gcc -fno-pie -no-pie -O0 -o force force.c
$ ./force
== House of Force: перезапись top chunk ==
a=0x341d3020  top size=0x20fd1
пишем в top size мусор 0xdeadbeef ...
malloc(0x100) -> sysmalloc проверяет top ...
malloc(): corrupted top size
Aborted (core dumped)
```

Атака **не проходит**: glibc падает с `malloc(): corrupted top size`. Это проверка, добавленная в версии 2.29: `if (size > av->system_mem) malloc_printerr("malloc(): corrupted top size")`. Размер top сверяется с общим размером арены, и «мусор» вроде `0xdeadbeef` не проходит.

## Шаг 3. Как работал House of Force

На glibc до 2.29 такой проверки не было. Тогда атака выглядела так:

1. Переполнить чанк, смежный с top, записав в `top->size` значение `0xffffffffffffffff` (SIZE_MAX).
2. Вычислить цель: `target` (например, `__malloc_hook` или `.bss`).
3. Запросить `malloc(target − top − 0x10)` — «прыжок» к цели.
4. Следующий `malloc` вернёт память по адресу `target`.

Формула критична: `target = top + 0x10 + запрошенный_размер`. Отсюда `запрошенный_размер = target − top − 0x10`. `target` должен быть **выше** top, иначе размер получится отрицательным.

## Шаг 4. House of Spirit: поддельный чанк

Другая техника — когда у нас есть `free` указателя, который мы контролируем. Сделаем «чанк» прямо на стеке и освободим его:

```c
unsigned long fake[32];
char *p = (char*)&fake[2];              /* «данные» фейка */
unsigned long *h = (unsigned long*)(p - 0x10);
h[0] = 0;                               /* fake prev_size */
h[1] = 0x71;                            /* fake size (диапазон fastbin/tcache) */
*(unsigned long*)(p + 0x60) = 0x71;     /* size следующего чанка (проверка) */
free(p);                                /* glibc принимает фейк в список свободных */
char *q = malloc(0x68);
printf("malloc(0x68) вернул %p (p=%p, совпало=%d)\n", q, p, q == p);
```

Запускаем:

```
== House of Spirit: поддельный чанк на стеке ==
фейковый чанк: p=0x7ffe4405a630  size=0x71
malloc(0x68) вернул 0x7ffe4405a630  (p=0x7ffe4405a630, совпало=1)
```

Сработало: `malloc` вернул указатель на **стек**. Условия — корректный `size` в диапазоне fastbin/tcache, выровненный адрес и валидный размер следующего чанка.

## Шаг 5. House of Orange

House of Orange нужна, когда в программе **нет функции `free`**. Переполнением top-чанка эмулируют освобождение: подделывают `prev_inuse` и размер так, чтобы glibc «освободила» top в unsorted bin. Это даёт утечку libc, а затем через unsorted bin attack адрес `main_arena` записывается в `_IO_list_all` — и запускается FSOP-цепочка до `system`. Техника — классический мост от heap к выполнению кода.

Разберём идею подробнее. Обычно House of Orange требует двух примитивов: возможности переполнить top-чанк и возможности аллоцировать память с контролируемым размером. Сначала переполнением ставим у top маленький `size` (например, `0xc01` при `PREV_INUSE=1`) и правим `prev_size`. При следующем `malloc`, если запрошенный размер больше «оставшегося» top, glibc решает расширить кучу через `sysmalloc`. Но при определённых условиях (подделанный top) она вместо расширения **освобождает** старый top, помещая его в unsorted bin. Теперь у нас есть чанк в unsorted bin: читаем его `fd`/`bk` — это утечка libc. Далее unsorted bin attack записывает адрес `main_arena` в `_IO_list_all`, мы подделываем `_IO_FILE` и при `exit`/`fflush` получаем вызов `system("/bin/sh")`. Это уже полноценная FSOP-цепочка (см. `pwn-fsop`).

Сводка применимости по версиям:

| Техника | Работает | Закрыта проверкой |
|---|---|---|
| House of Force | glibc < 2.29 | `corrupted top size` (2.29) |
| House of Spirit | широко | усиленные проверки free |
| House of Orange | старые glibc | проверки unsorted bin (2.29+) |

## Если не сработало

- **`malloc(): corrupted top size`.** Проверка top на glibc 2.29+. House of Force закрыта — используйте large bin attack.
- **`free(): invalid pointer`.** У фейкового чанка неверный `size` или выравнивание.
- **`free(): invalid next size`.** Не задан корректный размер следующего чанка.
- **Фейк не в fastbin.** Размер вне диапазона fastbin/tcache.
- **Версия glibc.** Проверки менялись; сверяйтесь с версией.

## Что мы теперь знаем

- top chunk — вершина кучи; `malloc` отрезает от него память.
- Перезапись `size` top даёт аллокацию по произвольному адресу (House of Force).
- С glibc 2.29 проверка `size > system_mem` закрывает House of Force.
- House of Spirit: поддельный чанк в контролируемой памяти + `free` → аллокация там.
- House of Orange: переполнение top эмулирует `free` и ведёт к FSOP.

## На что смотреть дальше

- **Версия glibc.** От неё зависит, какая из трёх техник применима.
- **Адрес top.** Его берут из heap-утечки.
- **Формула House of Force.** `target − top − 0x10`.
- **Условия House of Spirit.** `size`, выравнивание, следующий чанк.
- **Отладка.** `heap` и `top_chunk` в pwndbg показывают top и его размер.

## Квиз

Проверь себя.

```quiz
- question: "Что даёт перезапись поля size у top chunk (House of Force)?"
  options:
    - "Аллокацию по произвольному адресу через «прыжок» от top"
    - "Утечку стека"
    - "Снятие canary"
    - "Отключение ASLR"
  answer: 0
  explanation: "Огромный size top позволяет malloc выдать память в выбранной точке."
- question: "Какая проверка закрыла House of Force в glibc 2.29?"
  options:
    - "size > av->system_mem -> malloc(): corrupted top size"
    - "safe-linking"
    - "canary"
    - "tcache key"
  answer: 0
  explanation: "Размер top сверяется с размером арены."
- question: "В чём суть House of Spirit?"
  options:
    - "Подделать чанк в контролируемой памяти и free его, чтобы malloc вернул тот адрес"
    - "Утечь libc"
    - "Переполнить стек"
    - "Расширить GOT"
  answer: 0
  explanation: "Фейковый чанк с валидным size попадает в список свободных, и malloc возвращает его."
- question: "Когда нужна House of Orange?"
  options:
    - "Когда в программе нет функции free"
    - "Когда нет ASLR"
    - "Когда есть canary"
    - "Когда Full RELRO"
  answer: 0
  explanation: "Освобождение top эмулируется переполнением, чтобы получить unsorted bin и FSOP."
- question: "Какой формулой вычисляется «прыжок» в House of Force?"
  options:
    - "запрошенный размер = target − top − 0x10"
    - "target = top + size"
    - "target = fd + 0x18"
    - "size = nb + MINSIZE"
  answer: 0
  explanation: "malloc вернёт target, если запросить target − top − 0x10 байт."
```

## Куда дальше

В `pwn-custom-allocator` мы выйдем за пределы glibc: разберём самописный аллокатор из CTF-задачи и покажем, как находить в нём свои баги. А пока главное: **top chunk — тоже цель; его `size` управляет тем, куда `malloc` выдаст память.**

## Где пригодится

- **CTF:** Pwn — heap-задачи с top/fastbin/unsorted.
- **Bug bounty:** понимание glibc-примитивов.
- **Пентест:** эксплуатация heap-багов.
- **Работа:** security research glibc.
