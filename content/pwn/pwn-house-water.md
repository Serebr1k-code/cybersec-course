---
id: pwn-house-water
title: "House of Water: _IO_list_all и FSOP-цепочка"
category: pwn
parent: pwn-modern-houses
difficulty: expert
order: 3
tags: [heap, house-of-water, fsop, io-list-all, vtable, glibc]
prerequisites: [pwn-house-corrosion]
useful_for:
  - "CTF Pwn категория"
  - "Modern glibc exploitation"
  - "Vulnerability research"
estimated_minutes: 50
summary: "Разбираем House of Water: манипуляция _IO_list_all и построение FSOP-цепочки до захвата управления в modern glibc."
lab:
  kind: shell
  title: "Практика: смещение _IO_list_all"
  toolset: [core, nm]
  workdir: /home/student/task
  files: [task.md, libc.syms]
  check: "grep -q 'list_all=0x1e8480' answer.txt"
  hints:
    - "`nm -D libc.syms` — динамические символы libc."
    - "Ищи символ `_IO_list_all`."
    - "Первый столбец — смещение от базы libc."
    - "Запиши `list_all=0x1e8480`."
---

## Вопрос, с которого всё начинается

Мы научились получать произвольную запись (large bin, tcache, unsorted). Но куда писать, чтобы **выполнился код**? На glibc 2.34+ привычных хуков (`__free_hook`, `__malloc_hook`) больше нет. Остаётся один надёжный путь — заставить саму libc вызвать наш код через механизм работы с потоками ввода-вывода. Техника, которая этим занимается, называется **FSOP** (File-Stream-Oriented Programming), а её «домашняя» реализация — **House of Water**.

## Наш пример: список открытых потоков

Возьмём программу, которая читает и печатает внутренние структуры libc:

```c
#include "common.h"
extern void *_IO_list_all;
extern void *_IO_2_1_stdout_;
int main(void){
    printf("_IO_list_all     = %p\n", (void*)_IO_list_all);
    printf("&_IO_2_1_stdout_ = %p\n", (void*)&_IO_2_1_stdout_);
    char *fp = (char*)_IO_list_all;
    printf("первый поток fp  = %p\n", (void*)fp);
    printf("  _flags         = 0x%lx\n", *(unsigned long*)(fp+0x00));
    printf("  _IO_write_base = %p\n", *(void**)(fp+0x20));
    printf("  _IO_write_ptr  = %p\n", *(void**)(fp+0x28));
    printf("  _chain         = %p\n", *(void**)(fp+0x68));
    printf("  vtable         = %p\n", *(void**)(fp+0xd8));
    return 0;
}
```

`_IO_list_all` — глобальная переменная в libc: указатель на список всех открытых потоков (`stdin`, `stdout`, `stderr`). Каждый поток — структура `_IO_FILE_plus`.

## Шаг 1. Устройство _IO_FILE

Структура `_IO_FILE` — это большой набор полей. Важные для нас:

| Смещение | Поле | Смысл |
|---|---|---|
| `+0x00` | `_flags` | флаги потока |
| `+0x20` | `_IO_write_base` | начало буфера записи |
| `+0x28` | `_IO_write_ptr` | текущая позиция записи |
| `+0x68` | `_chain` | следующий поток в списке |
| `+0xd8` | `vtable` | таблица виртуальных функций потока |

Поле `vtable` — указатель на таблицу функций, которые libc вызывает для операций ввода-вывода (`_IO_OVERFLOW`, `_IO_UNDERFLOW` и т.д.).

## Шаг 2. Читаем список

Запускаем:

```
$ gcc -fno-pie -no-pie -O0 -o water water.c
$ ./water
== House of Water: список потоков _IO_list_all ==
_IO_list_all       = 0x7fbc2450f4a0
&_IO_2_1_stdout_   = 0x404020
первый поток fp    = 0x7fbc2450f4a0
  _flags           = 0xfbad2086
  _IO_write_base   = (nil)
  _IO_write_ptr    = (nil)
  _chain           = 0x404020
  vtable           = 0x7fbc2450d030
```

Читаем:

- `_IO_list_all` указывает на первый поток — структуру в libc (`0x7fbc…`).
- `_chain = 0x404020` — это `&_IO_2_1_stdout_`, следующий поток в списке. Список связывает потоки через `_chain`.
- `vtable = 0x7fbc2450d030` — таблица функций в libc.

## Шаг 3. Как срабатывает FSOP

Когда программа завершается (или вызывается `exit`), libc обходит список `_IO_list_all` и для каждого потока вызывает `_IO_flush_all_lockp`. Внутри — проверка условия и вызов через vtable:

```c
if ((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
    && _IO_OVERFLOW(fp, EOF) == EOF)
```

`_IO_OVERFLOW` — это `fp->vtable->__overflow(fp, EOF)`. То есть libc читает указатель на функцию из `vtable` и вызывает её. Если мы подделаем `vtable`, вызов уйдёт туда, куда мы хотим.

Ключевые два элемента:

1. Условие `_IO_write_ptr > _IO_write_base` должно быть истинным, чтобы поток «созрел» для flush.
2. `vtable->__overflow` должен указывать на наш гаджет.

## Шаг 4. House of Water: запись в _IO_list_all

Идея техники: имея произвольную запись (например, через large bin attack или tcache poisoning), перезаписать `_IO_list_all` указателем на **поддельную** структуру `_IO_FILE` в контролируемой памяти. В ней выставляем поля так, чтобы условие прошло, и подделываем `vtable`. Затем вызываем `exit` — и libc прыгает на наш гаджет.

Схема:

1. Получить произвольную запись и утечку libc.
2. Создать поддельный `_IO_FILE` в куче (или перекрыть существующий).
3. Выставить `_IO_write_ptr > _IO_write_base`, `_mode`, корректный `_flags`.
4. Записать `_IO_list_all = &fake_file`.
5. Спровоцировать `exit`/завершение программы.

Записываемое в `_IO_list_all` значение — адрес структуры (heap-указатель), поэтому large bin attack подходит идеально: она пишет именно адрес чанка.

Покажем, как выглядит поддельная структура в коде. Мы размещаем `_IO_FILE` в контролируемом чанке и заполняем поля:

```python
fake = heap_base + 0x2a0
payload  = p64(0)              # +0x00 _flags
payload += p64(0) * 3         # +0x08..+0x18 (read-поля)
payload += p64(0)              # +0x20 _IO_write_base
payload += p64(1)              # +0x28 _IO_write_ptr  > base -> условие истинно
payload += p64(0) * 8         # +0x30..+0x68 прочее, включая _chain
payload += p64(fake_vtable)    # +0xd8 vtable
edit(0, payload)
```

Здесь важны ровно два «работающих» поля: `_IO_write_ptr` (должен быть больше `_IO_write_base`, чтобы поток сбросился) и `vtable` (куда уйдёт вызов `__overflow`). Остальные поля можно обнулить. После этого произвольной записью кладём `fake` в `_IO_list_all` — и при `exit` libc пойдёт по нашему фейку.

Обрати внимание на смещение `0xd8` — это `vtable`. Оно зависит от разрядности и версии, но для 64-битных glibc стабильно; в отладчике его удобно подтвердить через `p &((struct _IO_FILE_plus*)0)->vtable` или просто распечатав структуру, как в нашем примере.

## Шаг 5. Проверка vtable и обход

Начиная с glibc 2.24, есть проверка `IO_validate_vtable`: `vtable` обязан лежать внутри секции `__libc_IO_vtables`. Произвольный указатель не пройдёт. Обходят это так:

- Используют **валидную** таблицу, но со смещением, чтобы `__overflow` попал на нужную функцию (например, `_IO_wfile_jumps + 0x10`).
- В modern glibc применяют цепочку House of Apple/Apple2: подделывают `_wide_data` и `_IO_wfile_jumps`, приводя к вызову `setcontext` или `system`.

Именно поэтому House of Water — не самостоятельная атака, а «финальный шаг»: она опирается на уже полученный примитив записи и на знание внутренностей libc.

## Если не сработало

- **Программа не зовёт exit.** Поток не сбросится; ищите другой триггер (`fflush`, `abort`).
- **Условие не прошло.** `_IO_write_ptr` должен быть больше `_IO_write_base`.
- **Проверка vtable.** Произвольный указатель не пройдёт `IO_validate_vtable` — используйте валидную таблицу со смещением.
- **Структура не в куче.** Адрес должен быть контролируемым и выровненным.
- **Версия glibc.** Смещения полей и доступные таблицы меняются; сверяйтесь.

## Инструмент: nm — таблица символов

`nm` перечисляет символы бинарника: имена функций и глобальных переменных с их адресами. Если символы не срезаны, это самый быстрый способ найти нужную функцию.

Ключи, которые пригодятся:
* `nm <файл>` — все символы с адресами;
* `nm -C <файл>` — демутируй C++-имена (читаемые сигнатуры);
* `T`/`t` — код (глобальный/локальный), `R`/`r` — только чтение (`.rodata`), `D`/`B` — данные;
* нижний регистр = локальный символ, верхний = глобальный/экспортируемый.

### Рабочий пример (как в лаборатории)

```
$ nm -D libc.syms
00000000001e84a0 D _IO_2_1_stderr_@@GLIBC_2.2.5
00000000001e8580 D _IO_2_1_stdout_@@GLIBC_2.2.5
00000000001e6030 D _IO_file_jumps@@GLIBC_2.2.5
00000000001e8480 D _IO_list_all@@GLIBC_2.2.5
0000000000092110 T _IO_str_overflow@@GLIBC_2.2.5
00000000001e6228 D _IO_wfile_jumps@@GLIBC_2.2.5
00000000001ee188 V __free_hook@GLIBC_2.2.5
00000000000a7d70 T __libc_calloc@@GLIBC_2.2.5
00000000000a7520 T __libc_free@@GLIBC_2.2.5
00000000000a9540 T __libc_freeres@@GLIBC_2.2.5
00000000000a6fd0 T __libc_malloc@@GLIBC_2.2.5
00000000001ee180 V __malloc_hook@GLIBC_2.2.5
```

Подсказка из лаборатории: `nm -D <файл> — динамические символы`.

## Что мы теперь знаем

- `_IO_list_all` — список открытых потоков; связаны через `_chain`.
- Поток — структура `_IO_FILE` с полями `_flags`, `_IO_write_base/ptr`, `vtable`.
- При выходе libc обходит список и вызывает `_IO_OVERFLOW` через `vtable`.
- Условие срабатывания: `_IO_write_ptr > _IO_write_base`.
- FSOP: подделать структуру и `vtable`, перезаписать `_IO_list_all`, вызвать `exit`.
- Проверка `IO_validate_vtable` требует валидной таблицы.

## На что смотреть дальше

- **Триггер.** Как программа завершается (`exit`, `abort`, `fflush`).
- **Смещения полей.** Они зависят от версии libc.
- **Валидные vtable.** `_IO_wfile_jumps`, `_IO_str_jumps` и смещения внутри.
- **Отладка.** `p _IO_list_all`, `p *(struct _IO_FILE_plus*)_IO_list_all`.
- **Modern-цепочки.** House of Apple/Apple2 для 2.34+.

## Отладка FSOP-цепочки в gdb

FSOP легко «не срабатывает» молча, поэтому отладка обязательна. Поставь точку останова на `_IO_flush_all_lockp` (символ есть в libc) — именно там libc обходит список потоков при выходе. В точке посмотри:

```
pwndbg> b _IO_flush_all_lockp
pwndbg> c
pwndbg> p _IO_list_all
pwndbg> p *(struct _IO_FILE_plus*)_IO_list_all
pwndbg> p *(struct _IO_FILE_plus*)_IO_list_all->vtable
```

Первая проверка — что `_IO_list_all` действительно указывает на твой поддельный `_IO_FILE` (адрес в куче, а не в libc). Вторая — что `_IO_write_ptr > _IO_write_base`, иначе поток будет пропущен. Третья — что `vtable` проходит `IO_validate_vtable` (указывает внутрь `__libc_IO_vtables`). Если `exit` не вызывается, поставь точку на `abort` или `fflush` — триггером может быть любой из них. Полезно также проверить условие `_mode <= 0`.

## Когда какой «дом» применять

House of Water — лишь один приём из семейства. Выбор зависит от версии glibc и доступного примитива:

| Техника | Идея | Ограничение |
|---|---|---|
| House of Force | топ-чанк в произвольный адрес | glibc ≤ 2.28 (проверка размера) |
| House of Orange | unsorted → `_IO_list_all` через `abort` | старые 2.23–2.27 |
| House of Spirit | фейковый чанк на стеке/в данных | нужен указатель на него |
| House of Water | перезапись `_IO_list_all` + FSOP | нужен примитив записи |
| House of Apple/Apple2 | `_wide_data` + `_IO_wfile_jumps` | modern glibc 2.34+ |

Ключевая мысль: с 2.34 убрали `__free_hook`/`__malloc_hook`, и FSOP через потоки ввода-вывода стала основным путём. Поэтому House of Water и Apple — не экзотика, а повседневный инструмент для modern glibc.

## Квиз

Проверь себя.

```quiz
- question: "Что хранит _IO_list_all?"
  options:
    - "Указатель на список открытых потоков _IO_FILE"
    - "Адрес main_arena"
    - "Канарейку"
    - "Таблицу GOT"
  answer: 0
  explanation: "Это голова списка потоков ввода-вывода libc."
- question: "Какое условие должно выполниться, чтобы поток сбросился при exit?"
  options:
    - "_IO_write_ptr > _IO_write_base"
    - "_IO_write_ptr == 0"
    - "_flags == 0"
    - "vtable == NULL"
  answer: 0
  explanation: "Иначе _IO_flush_all_lockp пропускает поток."
- question: "Какой вызов идёт через vtable потока?"
  options:
    - "_IO_OVERFLOW (vtable->__overflow)"
    - "malloc"
    - "free"
    - "main"
  answer: 0
  explanation: "libc вызывает fp->vtable->__overflow(fp, EOF)."
- question: "В чём суть House of Water?"
  options:
    - "Перезаписать _IO_list_all указателем на поддельную _IO_FILE и вызвать exit"
    - "Утечь libc"
    - "Снять canary"
    - "Расширить fastbin"
  answer: 0
  explanation: "FSOP-цепочка через список потоков."
- question: "Что проверяет IO_validate_vtable с glibc 2.24+?"
  options:
    - "Что vtable лежит внутри __libc_IO_vtables"
    - "Что vtable == NULL"
    - "Что vtable на стеке"
    - "Ничего"
  answer: 0
  explanation: "Поэтому используют валидную таблицу со смещением."
```

## Куда дальше

В `pwn-kernel-heap` мы сменим уровень: перейдём из userspace в ядро и разберём, как устроен slab-аллокатор и почему UAF в ядре даёт такой же примитив перекрытия. А пока главное: **на modern glibc код выполняют через FSOP — подделку `_IO_list_all` и `vtable`.**

## Где пригодится

- **CTF:** FSOP-задачи на modern glibc.
- **Bug bounty:** баги в обработке потоков ввода-вывода.
- **Пентест:** обход hardening glibc.
- **Работа:** понимание внутренностей libc I/O.
