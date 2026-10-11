---
id: pwn-fsop
title: "FSOP: перезапись _IO_FILE и vtable"
category: pwn
parent: pwn-heap-tcache
difficulty: expert
order: 1
tags: [fsop, io-file, vtable, house-of-orange, stdout, glibc]
prerequisites: [pwn-glibc-mitigations, pwn-heap-tcache]
useful_for:
  - "CTF Pwn категория"
  - "Modern glibc exploitation"
  - "Vulnerability research"
estimated_minutes: 70
summary: "Разбираем FSOP: структуру _IO_FILE, механизм vtable и её валидацию, а также построение поддельного файла, чей overflow вызовет system('/bin/sh')."
---
FSOP (File Stream Oriented Programming) — это техника получения контроля над потоком выполнения через подделку внутренних структур `_IO_FILE` в glibc. Когда программа завершается или сбрасывает буферы (`exit`, `fflush`, `_IO_cleanup`), glibc обходит связный список потоков `_IO_list_all` и вызывает для каждого виртуальные функции из его vtable. Если вы можете перезаписать структуру `_IO_FILE` и её vtable, вы получаете вызов произвольной функции. FSOP стала особенно важной после удаления `__free_hook`/`__malloc_hook` в glibc 2.34: это один из немногих оставшихся путей к исполнению кода из userland-heap. В этом уроке — устройство `_IO_FILE`, vtable-механизм, House of Orange, `_IO_2_1_stdout_`, проверка `_IO_vtable_check` и практические эксплойты.

## Устройство _IO_FILE

Структура `_IO_FILE` (и её расширенная версия `_IO_FILE_plus`) содержит поля, описывающие поток: указатели на буферы, флаги, позиции, а в конце — указатель на vtable `_IO_jump_t`. Ключевые поля:

| Поле | Смещение (x86-64) | Смысл |
|---|---|---|
| `_flags` | 0x00 | флаги потока |
| `_IO_read_ptr` | 0x08 | указатель чтения |
| `_IO_read_end` | 0x10 | конец буфера чтения |
| `_IO_read_base` | 0x18 | база буфера чтения |
| `_IO_write_base` | 0x20 | база буфера записи |
| `_IO_write_ptr` | 0x28 | указатель записи |
| `_IO_write_end` | 0x30 | конец буфера записи |
| `_IO_buf_base` | 0x38 | база буфера |
| `_IO_buf_end` | 0x40 | конец буфера |
| `_chain` | 0x68 | следующий поток |
| `_fileno` | 0x70 | дескриптор |
| `_lock` | 0x88 | мьютекс |
| `_wide_data` | 0xa0 | широкие данные |
| `vtable` | 0xd8 | таблица виртуальных функций |

Именно `vtable` (в `_IO_FILE_plus` по смещению 0xd8) определяет, какие функции вызовутся.

## Механизм vtable и _IO_jump_t

`_IO_jump_t` — таблица указателей на функции: `__xsputn`, `__overflow`, `__underflow`, `__uflow`, `__pbackfail`, `__seekoff`, `__seekpos`, `__setbuf`, `__sync`, `__doallocate`, `__read`, `__write`, `__close`, `__stat`, `__showmanyc`, `__imbue`. При операциях над потоком glibc берёт соответствующий указатель из vtable. Например, при `fflush` вызывается `_IO_OVERFLOW`, что раскрывается как `fp->vtable->__overflow(fp, EOF)`. Если подменить `vtable` на поддельную таблицу, где `__overflow` указывает на `system` или one-gadget, при `fflush`/`exit` произойдёт вызов.

## Проверка _IO_vtable_check

Начиная с glibc 2.24 введена проверка `_IO_vtable_check`: адрес vtable должен лежать в пределах секции `__libc_IO_vtables` внутри libc, иначе — abort. Поэтому подделать vtable «на куче» нельзя. Обходы: (1) использовать существующие vtable в libc (`_IO_str_jumps`, `_IO_wfile_jumps`, `_IO_file_jumps`) и подделать поля структуры так, чтобы нужная функция вызвала контролируемый указатель; (2) на glibc < 2.24 — поддельная vtable на куче напрямую. Классический приём — `_IO_str_jumps`, где `__overflow` = `_IO_str_overflow`, которая (на glibc < 2.28) вызывает `((_IO_strfile*)fp)->_s._allocate_buffer(size)`, а это поле можно контролировать.

## House of Orange

House of Orange — атака, превращающая переполнение top-чанка в FSOP. Идея: (1) переполнить top chunk, подделав его размер, чтобы при следующей аллокации он был «освобождён» и помещён в unsortedbin; (2) это даёт утечку libc через `fd`/`bk`; (3) далее подделывается `_IO_FILE` для stdout/`_IO_list_all` и триггерится `exit`. Атака работает, когда нет функции `free` (нельзя освободить чанк обычным путём). Требует аккуратной подделки `_IO_list_all` и vtable.

```python
# эскиз House of Orange
# 1) переполнить top chunk: prev_size/size
payload = b'A'*0x... + p64(0) + p64(0x21)   # подделка top
# 2) вызвать malloc -> старый top уходит в unsortedbin -> libc leak
# 3) подделать _IO_FILE и _IO_list_all, вызвать exit
```

## _IO_2_1_stdout_ и House of Husk

`_IO_2_1_stdout_` — статическая структура в libc для stdout. Её часто атакуют, потому что она в libc (vtable-проверка проходит) и вызывается при `puts`/`printf`. House of Husk — техника через `_IO_2_1_stdout_`: подделываются поля так, чтобы `_IO_OVERFLOW` указал на полезную функцию. Подробно — в уроке `pwn-io-stdout`. Ключевая идея: выставляем `_flags`, `_IO_write_base`, `_IO_write_ptr` так, чтобы при `fflush`/`puts` произошёл вызов нужной функции из `_IO_str_jumps`.

## Разобранный пример: FSOP через _IO_str_jumps

```python
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)

# 1) получить утечку libc и heap
# ...
# 2) подделать _IO_FILE в известном чанке
fake = FileStructure()
fake.flags = 0
fake._IO_write_base = 0
fake._IO_write_ptr = 1
fake.vtable = libc.sym['_IO_str_jumps'] - 0x18   # смещение до __overflow
fake._s._allocate_buffer = libc.sym['system']
# 3) связать с _IO_list_all и вызвать exit
```

Здесь `_IO_str_jumps - 0x18` — трюк, чтобы указатель на vtable «съехал» так, что `__overflow` указывает на начало vtable (часто на `_IO_str_overflow`). Точные смещения зависят от версии glibc и проверяются в gdb.

## Практические шаги и проверка

```bash
gdb ./chall
(gdb) p &_IO_2_1_stdout_
(gdb) p &_IO_list_all
(gdb) x/30gx &_IO_2_1_stdout_
(gdb) p _IO_str_jumps
(gdb) p _IO_wfile_jumps
```

Смотрите реальные адреса vtable и полей — они основа для подделки. Проверяйте `_IO_vtable_check`: `disassemble _IO_vtable_check`.

## Частые ошибки

- **Подделка vtable на куче (glibc ≥ 2.24).** Проверка `_IO_vtable_check` прервёт процесс.
- **Неверные смещения.** Поля `_IO_FILE` меняются между версиями — сверяйте в gdb.
- **Забытый триггер.** Нужно вызвать `exit`/`fflush`/`puts`, иначе подделка не сработает.
- **Порядок обхода `_IO_list_all`.** Проверьте, что ваш поддельный поток находится в цепочке.
- **`_IO_str_overflow` после 2.28.** Поведение изменилось — используйте другие jumps (`_IO_wfile`).

## Справочные таблицы

| Символ | Роль |
|---|---|
| `_IO_list_all` | голова списка потоков |
| `_IO_2_1_stdout_` | структура stdout |
| `_IO_file_jumps` | vtable обычного файла |
| `_IO_str_jumps` | vtable строкового потока |
| `_IO_wfile_jumps` | vtable wide-файла |
| `_IO_vtable_check` | проверка адреса vtable |

| Триггер | Когда вызывается |
|---|---|
| `exit` | `_IO_cleanup` → `_IO_flush_all_lockp` |
| `fflush` | сброс буфера |
| `puts`/`printf` | через `__overflow` |

## Что дальше / решение

Дальше: `pwn-io-stdout` (House of Husk), `pwn-io-str-overflow` (цепочки через `_IO_str_overflow`), `pwn-exit-handlers` (`__exit_funcs`), `pwn-house-of-force` (переполнение top), `pwn-glibc-mitigations` (эволюция). Практический алгоритм: (1) получите утечки libc/heap; (2) определите версию glibc и доступные vtable; (3) подделайте `_IO_FILE` в известном чанке; (4) выставите vtable на `_IO_str_jumps`/`_IO_wfile_jumps`; (5) подставьте полезную функцию; (6) поместите поток в `_IO_list_all`; (7) триггерните `exit`. FSOP — основной путь после удаления хуков, поэтому отработайте его на учебной задаче glibc 2.31 и 2.35.
## Полный разбор FSOP на примере glibc 2.31

Разберём сквозной сценарий на конкретной версии, чтобы увидеть все шаги. Пусть задача: heap-меню с `alloc`/`free`/`edit`/`show`, glibc 2.31, включены tcache и Full RELRO, хуки ещё существуют, но GOT защищён. План — FSOP через подделку `_IO_2_1_stdout_`. Сначала эксплуатируем tcache poisoning: заливаем tcache 0x90 семью чанками, освобождаем ещё один (уходит в fastbin или в unsortedbin), подделываем `next` так, чтобы аллокация вернула адрес `_IO_2_1_stdout_`. Затем через `edit` записываем поля структуры: `_flags = 0`, `_IO_write_base = 0`, `_IO_write_ptr = 1` — этого достаточно, чтобы при следующем `puts`/`fflush` произошёл вывод по нужному адресу (утечка) либо, при подстановке `_IO_str_jumps`, вызов. Далее утекаем libc, строим второй этап и триггерим `exit`. Каждый шаг проверяем в gdb командами `bins`, `vis_heap_chunks`, `p &_IO_2_1_stdout_`.

## Почему FSOP сложнее простого захвата хука

Простой захват `__free_hook` — это одна запись и один вызов `free`. FSOP требует: подделки целой структуры (десятки полей), корректной vtable в пределах libc, правильного триггера и учёта проверок. Ошибка в одном поле — и `_IO_flush_all_lockp` просто пропустит поток или упадёт. Поэтому FSOP применяют, когда хуки недоступны (glibc 2.34+) или когда у вас уже есть произвольная запись и вы хотите надёжный «финал». На практике порядок такой: сначала получите произвольную запись и утечки, затем выберите между `__exit_funcs`, `.fini_array`, `_IO_2_1_stdout_` и `_IO_list_all` в зависимости от того, что проще подделать в вашей версии. FSOP — не первый шаг, а завершающий.

## Тонкости проверки _IO_vtable_check и обход

Функция `_IO_vtable_check` сверяет, что адрес vtable лежит в диапазоне `__start___libc_IO_vtables` .. `__stop___libc_IO_vtables`. Обойти это можно тремя способами. Первый — использовать легитимную vtable из libc и подделать только данные структуры так, чтобы нужная функция вызвала контролируемый указатель (классика для `_IO_str_overflow` на старых версиях). Второй — сместить указатель vtable на несколько байт (`vtable - 0x18`), чтобы `__overflow` попало на нужную функцию внутри уже существующей таблицы. Третий — на glibc < 2.24 проверки нет, и поддельная vtable на куче работает напрямую. Для 2.35+ чаще используют `_IO_wfile_jumps` и `_wide_vtable`, потому что «wide»-путь вызывает указатель из `_wide_data`, который контролируется слабее. Разберитесь, какая проверка в вашей версии, и выберите соответствующий путь.

## Диагностика: почему FSOP не срабатывает

Если после подделки структуры ничего не происходит, проверьте по шагам: (1) находится ли ваш поддельный поток в списке `_IO_list_all` — иначе `_IO_flush_all_lockp` его не увидит; (2) корректен ли `_flags` — если поток помечен как «не активный», обход пропустит его; (3) проходит ли vtable проверку `_IO_vtable_check` — поставьте точку останова на неё и посмотрите, не вызывается ли `abort`; (4) происходит ли вообще триггер — `exit`/`fflush`/`puts`; (5) не портит ли ваш payload соседние поля, из-за чего структура «рассыпается». В gdb удобно поставить `b _IO_flush_all_lockp`, пройти по циклу и убедиться, что доходит до вашего потока. Логируйте адреса и значения полей, не полагайтесь на память.

## Квиз

```quiz
- question: "Через какое поле _IO_FILE вызываются виртуальные функции?"
  options:
    - "vtable"
    - "_flags"
    - "_chain"
    - "_fileno"
  answer: 0
  explanation: "Вызовы вида _IO_OVERFLOW идут через fp->vtable->__overflow."
- question: "Какая проверка мешает поставить vtable на произвольный адрес (glibc ≥ 2.24)?"
  options:
    - "_IO_vtable_check"
    - "safe-linking"
    - "PTR_MANGLE"
    - "tcache key"
  answer: 0
  explanation: "Проверка требует, чтобы vtable лежала в пределах __libc_IO_vtables."
- question: "Какое условие включает _IO_OVERFLOW при flush?"
  options:
    - "_IO_write_ptr > _IO_write_base"
    - "PREV_INUSE == 0"
    - "IS_MMAPPED == 1"
    - "_fileno == 1"
  answer: 0
  explanation: "Flush вызывает overflow, только если в буфере есть данные для вывода."
- question: "Какой глобальный указатель обходит _IO_cleanup на exit?"
  options:
    - "_IO_list_all"
    - "global_max_fast"
    - "main_arena.top"
    - "__free_hook"
  answer: 0
  explanation: "_IO_flush_all_lockp обходит список _IO_list_all и вызывает overflow для каждого файла."
- question: "Что такое House of Orange?"
  options:
    - "Техника получения чанка в unsorted bin без free, с последующей FSOP"
    - "Атака на tcache"
    - "Обход KPTI"
    - "Утечка canary"
  answer: 0
  explanation: "House of Orange создаёт unsorted-чанк через top chunk overflow и перекрывает _IO_list_all."
```

## Где пригодится

- **CTF:** Pwn — FSOP-задачи на современных glibc (основной путь к RCE).
- **Bug bounty:** эксплуатация heap-багов в нативных сервисах.
- **Пентест:** анализ stdio-внутренностей.
- **Работа:** security research glibc.
