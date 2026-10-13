---
id: pwn-unsortedbin-attack
title: "Unsorted bin attack: классический примитив записи"
category: pwn
parent: pwn-heap-bin-attacks
difficulty: hard
order: 1
tags: [pwn, heap, glibc, unsortedbin, malloc]
prerequisites: [pwn-heap-basics, pwn-heap-uaf]
useful_for:
  - "CTF Pwn — heap-задачи"
  - "Разработка эксплойтов"
estimated_minutes: 55
summary: "Как удаление чанка из unsorted bin записывает адрес main_arena по контролируемому адресу и как использовать это для утечки и записи."
lab:
  kind: shell
  title: "Практика: unsorted bin и main_arena"
  toolset: [core, gdb]
  workdir: /home/student/task
  files: [task.md, unsorted, unsorted.gdb.txt]
  check: "grep -q '0x7ffff7f7cac8' answer.txt"
  hints:
    - "Чанк размером > 0x410 при free попадает в unsorted bin (минуя tcache)."
    - "У единственного чанка в unsorted bin `fd == bk`."
    - "Оба указывают в `main_arena` — это libc leak."
---

## Вопрос, с которого всё начинается

Мы умеем перекрывать чанки и писать по адресу через `unlink`. Но откуда взять **адрес libc**? Без него не вычислить ни `system`, ни адреса внутренних структур. Оказывается, сама glibc при освобождении чанка кладёт в него указатель на внутреннюю структуру `main_arena`, лежащую в libc. Прочитав этот указатель, мы утекаем libc. А подделав его — заставляем `malloc` записать адрес libc туда, куда нам надо. Это **unsorted bin attack**.

## Наш пример: один чанк и «карантин»

Возьмём программу, которая освобождает один большой чанк и показывает его содержимое:

```c
#include "common.h"
int main(void){
    char *a = malloc(0x418);          /* чанк 0x420 — больше tcache */
    char *guard = malloc(0x20);       /* «страж», чтобы a не слился с top */
    printf("a=%p\n", a);
    free(a);                          /* a уходит в unsorted bin */
    unsigned long *c = (unsigned long*)a;
    printf("a->fd=%p  a->bk=%p\n", (void*)c[0], (void*)c[1]);
    ...
}
```

Почему размер `0x420`? Чанки до `0x410` при `free` сначала попадают в tcache — маленький кэш, из которого `malloc` отдаёт их обратно, не заглядывая в unsorted bin. Нам же нужно, чтобы чанк действительно оказался в unsorted bin. Размер больше `0x410` это гарантирует.

Страж `guard` нужен, чтобы освобождённый `a` не слился с «верхним» чанком (top chunk) — иначе он бы не остался отдельным чанком в списке.

## Шаг 1. Куда попадает free

`unsorted bin` — это «карантин» между быстрыми (fastbins) и отсортированными (small/large) списками. Освобождённый чанк, не попавший в tcache/fastbin, кладётся туда. При следующем `malloc` аллокатор обходит этот карантин, сортирует чанки по их спискам и, если находит точное совпадение по размеру, возвращает его программе.

## Шаг 2. Читаем fd/bk — утечка libc

Запускаем:

```
$ gcc -fno-pie -no-pie -O0 -o unsorted unsorted.c
$ ./unsorted
== unsorted bin attack ==
a=0x3d814020
a->fd=0x7fc948d1cac8  a->bk=0x7fc948d1cac8
```

Оба указателя равны `0x7fc948d1cac8` — это адрес внутри libc (обрати внимание на диапазон `0x7f…`). В свободном чанке `fd` и `bk` указывают на «голову» списка unsorted bin, а она лежит в статической структуре `main_arena`. Её адрес фиксирован относительно базы libc. Значит:

```
libc.address = leak - offset
```

где `offset` — смещение `main_arena + 0x60` от начала libc. Точное значение зависит от версии; его берут из GDB (`p &main_arena`) или из символа `__malloc_hook`. Это самый простой способ утечь libc.

## Шаг 3. Что делает malloc при сортировке

Когда `malloc` вынимает чанк `victim` из unsorted bin и сортирует его, выполняется такая последовательность:

```c
bck = victim->bk;                    /* «сосед» из поля bk */
unsorted_chunks(av)->bk = bck;
bck->fd = unsorted_chunks(av);       /* ЗАПИСЬ по адресу bck + 0x10 */
```

Последняя строка — и есть запись. Значение `unsorted_chunks(av)` — это `main_arena + 0x60`, адрес libc. Адрес записи — `bck + 0x10`, где `bck = victim->bk`. Если подделать `victim->bk`, мы управляем адресом записи.

Почему запись идёт именно по `bck + 0x10`? Потому что `fd` чанка лежит со смещением `0x10` от начала шапки. Мы пишем в поле `fd` чанка, расположенного по адресу `bck`. Отсюда и правило: чтобы попасть в `target`, задавайте `bck = target - 0x10`, то есть `victim->bk = target - 0x10`. Это ровно то, что мы сделали в примере.

Заметь ещё одно: значение записи мы не выбираем — это всегда адрес libc. Поэтому unsorted bin attack называют «записью адреса», а не «записью произвольного значения». Именно этого хватает, например, чтобы положить большое число в `global_max_fast` и расширить fastbin.

## Шаг 4. Пытаемся подделать bk — и что ловит glibc

Продолжим программу: перезапишем `bk` на `target - 0x10` и вызовем `malloc` того же размера.

```c
unsigned long target = 0x4040a0;      /* условная цель, например global_max_fast */
printf("подменяем bk на %p (target-0x10)\n", (void*)target);
c[1] = target - 0x10;                 /* victim->bk = target - 0x10 */
puts("malloc(0x418) -> вынимаем a из unsorted bin ...");
char *b = malloc(0x418);
printf("после: *(target)=%p\n", *(void**)target);
```

Запускаем:

```
$ ./unsorted
a->fd=0x7fc948d1cac8  a->bk=0x7fc948d1cac8
подменяем bk на 0x4040a0 (target-0x10)
malloc(0x418) -> вынимаем a из unsorted bin ...
malloc(): unsorted double linked list corrupted
Aborted (core dumped)
```

Атака **не проходит**: glibc падает с `malloc(): unsorted double linked list corrupted`. Это защита, добавленная в версии 2.29. Перед записью `bck->fd = unsorted_chunks(av)` glibc проверяет `if (bck->fd != victim)`. То есть по адресу `bck + 0x10` (наш `target`) должен уже лежать указатель на `victim`. В наивном варианте там лежит мусор — и аллокатор обрывает работу.

## Шаг 5. Что делать вместо

На старых glibc (до 2.29) проверки не было, и запись libc-адреса по произвольному адресу работала «в лоб»: классические цели — `global_max_fast` (расширить диапазон fastbin на все размеры) и `_IO_list_all` (в связке с House of Orange — подделка `_IO_FILE`, приводящая к `system`).

На новых версиях есть два пути:

1. **Выполнить предусловие проверки.** Записать в `target` указатель на `victim` — тогда `bck->fd == victim` и проверка пройдёт. Часто это возможно, если тем же примитивом вы уже контролируете `target`.
2. **Перейти на largebin attack.** Она использует поля `fd_nextsize`/`bk_nextsize` больших чанков и даёт произвольную запись на glibc 2.29+. Ей посвящён следующий урок.

Даже если запись не проходит, **чтение `fd`/`bk` из unsorted bin остаётся рабочим** и даёт утечку libc — половину успеха в любой heap-задаче.

## Если не сработало

- **`unsorted double linked list corrupted`.** Сработала проверка `bck->fd == victim`. Либо выполните предусловие, либо используйте largebin attack.
- **Чанк не в unsorted bin.** Размер ≤ `0x410` уходит в tcache. Берите больше `0x410`.
- **Чанк слился с top.** Нужен страж (`guard`) после него.
- **Неверный offset.** `main_arena + 0x60` зависит от версии libc — уточняйте в GDB.
- **Чанк не единственный.** Если в unsorted bin несколько чанков, `fd`/`bk` указывают друг на друга, и наивная утечка даёт не то значение.

## Что мы теперь знаем

- Освобождённый чанк > `0x410` попадает в unsorted bin.
- Его `fd`/`bk` указывают в `main_arena` — это утечка адреса libc.
- При сортировке `malloc` выполняет `bck->fd = unsorted_chunks(av)` — запись.
- Подделка `victim->bk` управляет адресом записи.
- С glibc 2.29 проверка `bck->fd == victim` ломает наивную атаку.
- Замена — largebin attack через `fd_nextsize`/`bk_nextsize`.

## На что смотреть дальше

- **Offset main_arena.** Разный для версий; считайте из символа в libc.
- **Предусловие проверки.** Можно ли записать в цель указатель на `victim`?
- **Цель записи.** `global_max_fast`, `_IO_list_all`, `__exit_funcs`.
- **Страж.** Без `guard` чанк уйдёт в top.
- **Отладка.** `bins` и `vis_heap_chunks` в pwndbg показывают содержимое unsorted bin.

## Квиз

Проверь себя.

```quiz
- question: "Что записывает unsorted bin attack на старых glibc?"
  options:
    - "Адрес main_arena (libc) по контролируемому адресу"
    - "Ноль в canary"
    - "Указатель на стек"
    - "Содержимое GOT"
  answer: 0
  explanation: "При сортировке выполняется bck->fd = unsorted_chunks(av), где значение — libc-адрес."
- question: "Какое поле чанка нужно подделать?"
  options:
    - "bk (указатель назад)"
    - "prev_size"
    - "size"
    - "fd_nextsize"
  answer: 0
  explanation: "victim->bk определяет адрес записи: bck = victim->bk, запись по bck+0x10."
- question: "Какая проверка усложнила атаку с glibc 2.29?"
  options:
    - "bck->fd == victim при сортировке unsorted bin"
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
- question: "Почему нужен guard-чанк после освобождаемого?"
  options:
    - "Чтобы чанк не консолидировался с top"
    - "Чтобы включить ASLR"
    - "Чтобы снять canary"
    - "Чтобы расширить GOT"
  answer: 0
  explanation: "Иначе чанк сольётся с top и не останется в unsorted bin."
```

## Куда дальше

В `pwn-largebin-attack` мы возьмём большие чанки и поля `fd_nextsize`/`bk_nextsize` и получим произвольную запись **на современной glibc**, где unsorted bin attack уже заблокирована. А пока главное: **освобождённый чанк сам выдаёт адрес libc — читай `fd`/`bk`.**

## Где пригодится

- **CTF:** Pwn — heap-задачи с unsorted bin.
- **Bug bounty:** понимание glibc-примитивов.
- **Пентест:** эксплуатация heap-багов.
- **Работа:** security research glibc.
