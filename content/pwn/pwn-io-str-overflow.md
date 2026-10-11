---
id: pwn-io-str-overflow
title: "_IO_str_overflow и vtable-цепочки (glibc 2.24+)"
category: pwn
parent: pwn-fsop
difficulty: expert
order: 4
tags: [pwn, heap, glibc, fsop, iofile, vtable]
prerequisites: [pwn-fsop, pwn-io-stdout]
useful_for:
  - "CTF Pwn — FSOP"
  - "Разработка эксплойтов"
estimated_minutes: 60
summary: "Как через _IO_str_overflow/_IO_str_finish и поддельную vtable добиться вызова произвольной функции на glibc 2.24–2.27."
---
`_IO_str_overflow` — функция в glibc, обслуживающая «строковые» потоки (создаваемые `fmemopen`/`open_memstream`). Исторически она стала популярной целью FSOP, потому что вызывала контролируемый указатель `_s._allocate_buffer` как функцию. Это позволяло получить исполнение, подделав структуру `_IO_strfile` и vtable. Однако начиная с glibc 2.28 поведение изменилось: `_IO_str_overflow` больше не вызывает `_allocate_buffer` напрямую, что сломало старые цепочки. В этом уроке — как работала классическая атака, что изменилось в 2.28+, и какие vtable-цепочки используются сегодня (`_IO_wfile_jumps`, `_IO_wfile_overflow`).

## Устройство _IO_strfile

`_IO_strfile` расширяет `_IO_FILE` полями строкового потока:

```c
struct _IO_strfile_ {
    struct _IO_streambuf _sbf;   // база _IO_FILE
    struct _IO_str_fields _s;    // строковые поля
};
struct _IO_str_fields {
    char *_allocate_buffer;
    char *_free_buffer;
    size_t _allocate_buffer_size;
};
```

Поле `_allocate_buffer` — указатель на функцию выделения буфера. В классической атаке его подменяли на `system` (или one-gadget), а размер буфера — на указатель на `"/bin/sh"`, после чего `_IO_str_overflow` вызывала `_allocate_buffer(buf, size)`.

## Классическая атака (glibc < 2.28)

Схема: подделываем `_IO_FILE` так, чтобы vtable указывал на `_IO_str_jumps` (с нужным смещением, чтобы `__overflow` = `_IO_str_overflow`), а `_s._allocate_buffer` = `system`. Условия входа в ветку вызова:

```c
if ((size_t)(fp->_IO_write_ptr - fp->_IO_write_base) >=
    (size_t)(fp->_IO_buf_end - fp->_IO_buf_base))
{
    if (fp->_IO_buf_end > fp->_IO_buf_base) {
        // увеличение буфера
        char *new_buf = (_IO_str_fields*)(fp)->_allocate_buffer(fp, size);
        ...
    }
}
```

То есть нужно, чтобы буфер «переполнился» (write_ptr - write_base >= buf_end - buf_base) и buf_end > buf_base. Тогда вызывается `_allocate_buffer(fp, size)`.

```python
fake = FileStructure()
fake.flags = 0
fake._IO_write_base = 0
fake._IO_write_ptr = 1
fake._IO_buf_base = 0
fake._IO_buf_end = 2            # buf_end > buf_base -> вход в ветку
fake.vtable = libc.sym['_IO_str_jumps'] - 0x18
fake._s._allocate_buffer = libc.sym['system']
# связать с _IO_list_all и вызвать exit
```

## Что изменилось в glibc 2.28+

В 2.28 `_IO_str_overflow` переписали: вместо вызова `_allocate_buffer` она использует `malloc`/`realloc` напрямую, а `_allocate_buffer` удалили из логики. Поэтому старая цепочка больше не даёт вызова. Современные обходы:

1. **`_IO_wfile_jumps` + `_IO_wfile_overflow` + `_IO_wdoallocbuf`.** Подделываются `_wide_data`, `_wide_data->_wide_vtable` и поля так, чтобы вызвался контролируемый указатель из `_wide_vtable`. Это «wide»-вариант, который остался рабочим.
2. **`_IO_str_jumps` с другими полями.** Используются иные ветки `_IO_str_overflow`, ведущие к вызову через `_IO_str_init_static`/`_IO_str_finish` (если применимо).
3. **Largebin attack на `_IO_list_all`** с последующим FSOP через `_IO_file_jumps`.

## Современная цепочка через _IO_wfile

```python
# эскиз: подделка _wide_data и _wide_vtable
fake = FileStructure()
fake.flags = 0
fake.vtable = libc.sym['_IO_wfile_jumps']
fake._wide_data = fake_addr + 0xe0          # указатель на наши wide-данные
# в wide-данных: _wide_vtable -> поддельная таблица, где __doallocate = system
fake._wide_data._wide_vtable = wide_vtable_addr
wide_vtable.__doallocate = libc.sym['system']
```

Точные смещения зависят от версии; сверяйте в gdb (`ptype struct _IO_wide_data`).

## Проверка в gdb

```bash
gdb ./chall
(gdb) p _IO_str_jumps
(gdb) p _IO_wfile_jumps
(gdb) p &_IO_str_overflow
(gdb) disassemble _IO_str_overflow
(gdb) p &_IO_wfile_overflow
(gdb) p &_IO_wdoallocbuf
```

Дизассемблируйте `_IO_str_overflow` в вашей libc: увидите, вызывает ли она `_allocate_buffer` (старая версия) или `malloc` (новая). Это определяет, применима ли классическая цепочка.

## Частые ошибки

- **Использование старой цепочки на glibc ≥ 2.28.** `_allocate_buffer` больше не вызывается — атака не сработает.
- **Неверное смещение vtable.** `_IO_str_jumps - 0x18` подбирается под конкретную версию.
- **Не выполнены условия входа.** Без «переполнения» буфера ветка вызова не активируется.
- **Забыт `_wide_data`.** Для `_IO_wfile` нужны корректные wide-поля и `_wide_vtable`.
- **`_IO_vtable_check`.** Поддельная vtable должна лежать в libc; используйте существующие jumps.

## Справочные таблицы

| Версия glibc | `_IO_str_overflow` вызывает | Обход |
|---|---|---|
| < 2.28 | `_allocate_buffer` | классическая атака |
| ≥ 2.28 | `malloc`/`realloc` | `_IO_wfile` цепочки |
| ≥ 2.34 | то же + нет хуков | FSOP обязателен |

| Символ | Роль |
|---|---|
| `_IO_str_jumps` | vtable строкового потока |
| `_IO_wfile_jumps` | vtable wide-файла |
| `_IO_wdoallocbuf` | выделение wide-буфера |
| `_wide_data` | wide-поля потока |

## Что дальше / решение

Дальше: `pwn-fsop` (основы), `pwn-io-stdout` (House of Husk), `pwn-exit-handlers`, `pwn-largebin-attack`, `pwn-glibc-mitigations`. Практический алгоритм: (1) определите версию glibc; (2) если < 2.28 — используйте классическую цепочку с `_allocate_buffer`; (3) если ≥ 2.28 — переходите на `_IO_wfile`/`_wide_vtable`; (4) подделайте структуру и vtable; (5) триггерните `exit`/`fflush`. Понимание эволюции `_IO_str_overflow` — пример того, как митигации glibc меняют доступные примитивы; всегда сверяйтесь с исходниками целевой версии.
## Сквозной разбор на glibc 2.27

Рассмотрим конкретную задачу: glibc 2.27, есть heap-перекрытие и произвольная запись, `__free_hook` существует, но GOT защищён, и мы хотим надёжный «финал». План — классическая `_IO_str_overflow`-цепочка. Шаги: (1) через heap-примитив получаем указатель на известный чанк; (2) утекаем libc через unsortedbin (`bk` → `main_arena`); (3) вычисляем адреса `_IO_list_all`, `_IO_str_jumps`, `system`; (4) в нашем чанке конструируем поддельный `_IO_FILE` со `vtable = _IO_str_jumps - 0x18` и `_s._allocate_buffer = system`; (5) подделываем `_IO_list_all` так, чтобы он указывал на наш чанк; (6) триггерим `exit`. При `_IO_flush_all_lockp` glibc дойдёт до нашего потока, вызовет `__overflow` = `_IO_str_overflow`, которая (на 2.27) обратится к `_allocate_buffer`, то есть к `system`, с аргументом-указателем на наши данные. Если вместо `system` нужен `"/bin/sh"`, размещаем строку в начале чанка так, чтобы она стала аргументом.

## Разбор дизассемблера _IO_str_overflow

Откройте функцию в gdb или Ghidra и проследите ветку:

```bash
objdump -d -M intel ./libc.so.6 | grep -A60 "<_IO_str_overflow@@"
```

В старых версиях вы увидите `call rax` или `call QWORD PTR [rbp+...]`, где загружается `_allocate_buffer`; в новых — `call malloc`/`realloc`. Это ключевая точка: именно здесь старая атака получала исполнение. Также обратите внимание на предварительные проверки (`_IO_write_ptr - _IO_write_base >= _IO_buf_end - _IO_buf_base`), которые определяют, попадёте ли вы в нужную ветку. Подделывая поля структуры, вы управляете этими сравнениями. Сверяйте каждое поле с реальным смещением в вашей сборке — они отличались между 2.23, 2.27 и 2.31.

## Современные альтернативы: _IO_wfile и _wide_vtable

На glibc 2.28+ основной путь — «wide»-версия: `_IO_wfile_jumps` содержит указатели на `_IO_wfile_overflow`/`_IO_wfile_underflow`, а те в свою очередь вызывают `_IO_wdoallocbuf`, которая берёт указатель из `_wide_data->_wide_vtable->__doallocate`. Подделав `_wide_data` и `_wide_vtable`, вы получаете вызов контролируемой функции. Преимущество: проверка `_IO_vtable_check` применяется к основной vtable, а `_wide_vtable` контролируется слабее. Требуется корректно выставить `_mode`, `_wide_data` и флаги. Это более кропотливо, но работает на современных версиях. Разберитесь со структурой `_IO_wide_data` (`ptype` в gdb) и потренируйтесь на учебной задаче.

## Чек-лист применения цепочек через _IO

1. Определите версию glibc (`strings | grep "GNU C Library"`).
2. Дизассемблируйте `_IO_str_overflow`: есть ли вызов `_allocate_buffer`.
3. Если да (< 2.28) — классическая цепочка; если нет — `_IO_wfile`.
4. Получите произвольную запись и утечки libc/heap.
5. Подделайте структуру, vtable и связанные поля.
6. Свяжите поток с `_IO_list_all` или модифицируйте `_IO_2_1_stdout_`.
7. Триггерните `exit`/`fflush`.
8. Проверьте в gdb на каждом шаге (`b _IO_flush_all_lockp`, `b _IO_str_overflow`).

## Практические заметки по смещениям vtable

Смещение `_IO_str_jumps - 0x18` — это не магия, а следствие раскладки `_IO_jump_t`: чтобы указатель `__overflow` (третье поле таблицы) попал на начало `_IO_str_jumps` (где обычно лежит `_IO_str_overflow` в первых версиях), приходится «съезжать» назад. В разных сборках точное смещение отличается, поэтому вычисляйте его в gdb: `p &_IO_str_jumps`, `p &_IO_str_overflow`, разница даст искомое. Аналогично для `_IO_wfile_jumps`: определите, на каком смещении лежит нужная функция, и подставьте `vtable = _IO_wfile_jumps + delta`. Заведите табличку смещений для используемых версий glibc — это ускорит сборку эксплойтов. Не забывайте, что `_IO_vtable_check` проверяет диапазон `__libc_IO_vtables`, поэтому итоговый адрес vtable должен оставаться в этом диапазоне.

## Отладка цепочки пошагово

Поставьте точки останова на ключевые функции и пройдите цепочку вручную: `b _IO_flush_all_lockp`, `b _IO_str_overflow` (или `_IO_wfile_overflow`), `b _IO_wdoallocbuf`, `b system`. На каждом шаге смотрите регистры и стек: попадает ли управление в нужную функцию, с какими аргументами. Если `_IO_vtable_check` вызывает `abort`, значит адрес vtable вне libc — исправьте. Если ветка не активируется, проверьте условия входа (переполнение буфера). Такой пошаговый прогон выявляет ошибку за минуты, тогда как слепые правки payload'а могут занять часы.

## Итог

`_IO_str_overflow` — исторический пример техники, которая была закрыта митигацией, но породила семейство «wide»-обходов. Знание этой эволюции помогает понимать, почему современные эксплойты выглядят сложнее и какие пути остались. На glibc < 2.28 используйте классическую цепочку, на ≥ 2.28 — `_IO_wfile`/`_wide_vtable`. Всегда определяйте версию и сверяйте смещения, а финальный вызов проверяйте в gdb до триггера `exit`.

Помните, что после каждой митигации glibc находились обходные пути, и `_IO_str_overflow` — лишь один эпизод в этой гонке; следите за изменениями в исходниках и адаптируйте цепочки под конкретную сборку, а не копируйте payload из старых writeup без проверки.

## Квиз

```quiz
- question: "Какую функцию вызывает _IO_str_finish через указатель в структуре (2.24–2.27)?"
  options:
    - "_s._free_buffer"
    - "GOT[free]"
    - "main_arena.top"
    - "global_max_fast"
  answer: 0
  explanation: "До 2.28 поле _free_buffer было указателем на функцию, что позволяло подставить system."
- question: "На каких версиях glibc применима классическая _IO_str_* FSOP-цепочка?"
  options:
    - "2.24–2.27"
    - "2.34+"
    - "2.0–2.10"
    - "любых"
  answer: 0
  explanation: "С 2.28 поля заменили обычными функциями, и вызов через указатель исчез."
- question: "Что нужно, чтобы сработал _IO_OVERFLOW при обходе _IO_list_all?"
  options:
    - "_IO_write_ptr > _IO_write_base"
    - "PREV_INUSE == 0"
    - "IS_MMAPPED == 1"
    - "safe-linking выключен"
  answer: 0
  explanation: "Flush вызывает overflow только при наличии непрочитанных данных."
- question: "Что подменяют в fake _IO_FILE, чтобы вызов ушёл в _IO_str_overflow?"
  options:
    - "vtable (на _IO_str_jumps + смещение слота)"
    - "prev_size"
    - "fd_nextsize"
    - "_IO_read_ptr"
  answer: 0
  explanation: "Вызов __overflow идёт через fp->vtable, поэтому vtable указывает на _IO_str_jumps."
- question: "Какое поле даёт аргумент для system в цепочке _IO_str_overflow?"
  options:
    - "_IO_buf_base (передаётся в подделанную функцию)"
    - "_IO_read_ptr"
    - "_chain"
    - "_mode"
  answer: 0
  explanation: "_IO_buf_base становится аргументом вызываемой через _s._allocate_buffer функции."
```

## Где пригодится

- **CTF:** Pwn — FSOP-задачи на glibc 2.24–2.27 (частый формат).
- **Bug bounty:** понимание stdio-vtable для анализа исторических CVE.
- **Пентест:** эксплуатация heap-багов в legacy-сервисах.
- **Работа:** security research glibc.
