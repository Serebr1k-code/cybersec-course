---
id: reversing-ida-deep
title: "IDA Pro: FLIRT, декомпилятор, IDAPython"
category: reversing
parent: reversing-decompiler-tools
difficulty: hard
order: 3
tags: [reversing, ida, flirt, hexrays, idapython, decompiler, plugins]
prerequisites: [reversing-decompiler]
useful_for:
  - "CTF Reversing"
  - "Malware analysis"
  - "Vuln research"
estimated_minutes: 55
summary: "Продвинутая работа в IDA: сигнатуры FLIRT, типы, Hex-Rays, автоматизация на IDAPython."
---
IDA — индустриальный стандарт реверса, и её сила не только в дизассемблере, но и в экосистеме:
библиотека сигнатур **FLIRT** мгновенно распознаёт функции стандартных библиотек, декомпилятор
**Hex-Rays** даёт лучший псевдо-C в индустрии, а **IDAPython** позволяет автоматизировать почти всё.
Этот урок — про то, как выжать из IDA больше, чем «нажать F5»: сигнатуры, типы, микрокод, плагины
и отладку.

## Теория: что делает IDA особенной

- **FLIRT (Fast Library Identification and Recognition Technology).** Сигнатуры статических
  библиотек. Когда бинарник статически слинкован, FLIRT помечает сотни функций как `printf`,
  `memcpy` и т.д. — вы не тратите время на реверс стандартной библиотеки.
- **Type Libraries (TIL).** Заголовки (`mssdk`, `gnu`, пользовательские) восстанавливают прототипы
  функций и структуры. С ними декомпилятор показывает `FILE*`, `size_t`, поля структур.
- **Hex-Rays.** Декомпилятор, работающий на микро-коде (microcode) — внутреннем IR. Понимание
  microcode помогает писать плагины, оптимизирующие вывод.
- **Lumina.** Сервер, отдающий имена функций, уже разобранных другими пользователями IDA; полезен
  для опознания библиотек без сигнатур.
- **Идёт на десятках архитектур** и имеет встроенный отладчик (локально и удалённо).

## Инструменты и команды: настройка анализа

```bash
# загрузка
ida64 ./target        # или ida (32-bit)
ida -B ./target       # batch-режим, автоанализ без GUI
```

В GUI при первом открытии: подтвердить Processor, при необходимости `Manual load`/Loading offset,
включить опции анализа (`Rename thunks`, `Function prolog`, `Create FLIRT signatures`).

После загрузки:

- `Shift+F12` — список строк (Strings window). Двойной клик → переход к xref.
- `Ctrl+P` — список функций; `Ctrl+S` — секции; `Shift+F7` — сегменты.
- `X` на символе/адресе — перекрёстные ссылки (xrefs); `Ctrl+X` — xrefs к текущей.
- `N` — переименовать; `Y` — задать тип; `:` — комментарий; `/` — комментарий блока.
- `F5` — декомпилировать функцию (Hex-Rays); `Space` — переключить вид (листинг/граф).
- `G` — переход по адресу; `Alt+T` — текстовый поиск; `Alt+B` — бинарный поиск.

## Инструменты и команды: FLIRT и типы

**Применить сигнатуры:**

```text
File → Load file → FLIRT signature file...
# или в консоли IDA:  flirt apply <sig>
```

Если бинарник статически слинкован с libc, примените `libc.sig`/`libc64.sig`. Функции станут
именованными, и декомпилятор покажет `strcpy`, а не `sub_401230`. Для Windows — `vc6`, `vc7`,
`mssdk` сигнатуры из `sig/`.

**Загрузить типы:**

```text
Options → Type libraries (Shift+F11) → добавить mssdk/gnulnx/...
```

Для Windows-бинарников добавление `mssdk`/`vc` типов резко улучшает вид структур (`_CONTEXT`,
`PEB` и т.д.). Можно подключить символы из PDB через `File → Load file → PDB file`.

**Создать свои структуры** (для проприетарных форматов):

```text
Shift+F9 → Local Types → Insert → вставить C-структуру → Compile
```

```c
struct packet {
    uint32_t magic;
    uint16_t len;
    uint8_t  data[0x100];
};
```

Затем `Y` на переменной — выбрать `packet*` — декомпилятор покажет `p->len`. Массовое применение
типов: `Y` на массиве байт, `Alt+Q` — «apply to all matching» в новых версиях.

## Инструменты и команды: IDAPython

IDAPython выполняется в консоли IDA или в скрипте (`File → Script file`, `Alt+F7`). Модульная
структура IDA 7+: `ida_*` (`ida_bytes`, `ida_funcs`, `ida_name`, `ida_hexrays`, `ida_xref`),
плюс совместимые `idc`/`idautils`.

**Пример 1. Найти все xrefs на строку, содержащую «flag».**

```python
# IDAPython
import idautils, idc

for s in idautils.Strings():
    text = str(s)
    if "flag" in text.lower():
        print("0x%x  %s" % (s.ea, text))
        for xref in idautils.XrefsTo(s.ea):
            print("    from 0x%x" % xref.frm)
```

**Пример 2. Переименовать все функции, вызывающие `system`.**

```python
import idautils, idc

system_ea = idc.get_name_ea_simple("system")
for xref in idautils.XrefsTo(system_ea):
    f = idc.get_func_name(xref.frm)
    print("system called in %s @ 0x%x" % (f, xref.frm))
    idc.set_name(xref.frm, "calls_system", idc.SN_NOWARN)
```

**Пример 3. Декомпиляция функции и обход AST.**

```python
import ida_hexrays, ida_funcs

f = ida_funcs.get_func(0x401000)
cf = ida_hexrays.decompile(f.start_ea)
print(cf)                          # псевдо-C
for item in cf.treeitems:          # обход дерева AST
    if "strcmp" in item.print1(None):
        print("strcmp @ 0x%x" % item.ea)
```

`ida_hexrays` даёт доступ к AST — это основа для автоматических деобфускаторов и анализаторов.
Можно менять AST и применять изменения обратно (`cf.treeitems` → `citem`), чем пользуются плагины
деобфускации.

## Hex-Rays microcode: зачем лезть внутрь

Микрокод — промежуточное представление между листингом и псевдо-C. Он состоит из базовых блоков
(`mblock_t`) и инструкций (`minsn_t`) над виртуальными регистрами. Зачем это нужно:

- **Оптимизация декомпиляции** — плагины переписывают микрокод, убирая мусор обфускации
  (например, `simplify`-проходы).
- **Кастомный анализ** — taint-анализ, поиск паттернов на уровне IR.
- **Деобфускация control-flow** — восстановление реального потока управления из «сплющенного».

Просмотр микрокода: правый клик в Decompiler → `Show microcode` / плагин `hexrays_microcode`.
Пример вывода для `x = a + b; if (x > 5)`:
```text
mblock 0:
    mov  v1.4, arg_a
    add  v1.4, arg_b
    jg   v1.4, #5, @2
```

## Разобранный пример: восстановление формата и проверки

Дано: Windows-бинарник, парсит файл, проверяет «лицензию».

**Шаг 1. Загружаем, применяем типы.** `Shift+F11` → добавляем `mssdk`. FLIRT применяется
автоматически (`ida64` подхватывает `.sig` из `sig/`).

**Шаг 2. Строки.** `Shift+F12` → ищем `Invalid license`. `X` на строке → функция проверки.

**Шаг 3. Декомпилируем (`F5`).** Получаем псевдо-C. Если типы не восстановлены, видим
`sub_401230(a1, a2)`; задаём прототип через `Y`: `int check_license(char *buf, size_t len)`.

**Шаг 4. Восстанавливаем структуру.** Замечаем `*(_DWORD*)(a1 + 8)`. Создаём структуру `header`
(`Shift+F9`), назначаем тип указателя — декомпилятор покажет `hdr->len`.

**Шаг 5. Находим проверку.** В псевдо-C видно:

```c
if ( hdr->magic != 0x4B554253 )   // "KUSB"
    return 0;
if ( hdr->len > 0x100 )
    return 0;
memcpy(dst, hdr->data, hdr->len);
```

**Шаг 6. Вывод.** Магия `0x4B554253` = `'KUSB'`, ограничение длины 0x100. Из этого строим валидный
файл-триггер. Дальше — при необходимости, отладка IDA (`F9`, breakpoints).

## Инструменты и команды: отладка в IDA

```text
Debugger → Select debugger (Local Windows/Linux, Remote gdbserver)
F9    — запуск
F2    — breakpoint
F7/F8 — шаг с заходом/без
F4    — run to cursor
```

Удалённая отладка Linux-бинарника:

```bash
# на цели
gdbserver :1234 ./target
# в IDA: Debugger → Remote GDB → localhost:1234
```

Полезно: окна `Registers`, `Stack`, `Locals`; условные breakpoints (`F2` → Condition);
watchpoints на память (правый клик в Hex View → `Add write watchpoint`).

## Плагины, которые стоит поставить

- **FindCrypt** — крипто-константы (AES/DES/SHA).
- **Keypatch** — патчинг инструкций прямо в листинге (сборка по ассемблеру).
- **LazyIDA** — быстрые действия: дамп, копирование адресов, преобразования.
- **HexRaysPyTools** — реконструкция структур и классов.
- **Diaphora** — диффинг бинарников (поиск изменённых функций между версиями).
- **ret-sync** — синхронизация IDA с gdb/x64dbg/WinDbg.

## Частые ошибки и подводные камни

- **Не применять FLIRT на статических бинарниках.** Вы будете реверсить libc вручную — часы впустую.
- **Игнорировать типы.** Без `Y`/структур декомпилятор выдаёт `int` везде и псевдо-C нечитаем.
- **Верить декомпилятору на 100%.** Hex-Rays ошибается на косвенных вызовах, `longjmp`, inline asm.
  Всегда сверяйтесь с листингом.
- **Путать `X` (xrefs) и `Enter` (follow).** `X` показывает все ссылки, `Enter` уходит по одной.
- **Писать IDAPython без проверки версии API.** IDA 7+ перешла на `ida_*` модули; старый `idc` частично жив.
- **Забывать сохранять `.idb`/`.i64`.** Вся разметка (имена, типы) хранится в базе — не потеряйте её.
- **Отлаживать malware без изоляции.** IDA-отладчик запускает код; используйте VM.
- **Слишком длинный автоанализ.** Для гигантских бинарников отключайте ненужные проходы, иначе
  анализ идёт часами.

## Что дальше / решение

1. Загрузить бинарник, дать автоанализу завершиться, применить FLIRT и типы.
2. Пройти по строкам/импортам, найти точку входа и «интересные» функции.
3. Декомпилировать (`F5`), восстанавливать структуры и прототипы.
4. Автоматизировать рутину через IDAPython (поиск xref, переименование, декомпиляция).
5. Для сложных случаев — микрокод, плагины деобфускации, отладка.
6. Сравнить версии через Diaphora, если задача — найти патч.

Приём профессионала: **каждая переименованная переменная и каждый расставленный тип делают
следующую декомпиляцию точнее**. IDA — это инструмент, который «учится» на вашей разметке.

## Справочная таблица: горячие клавиши и API

| Действие | GUI | IDAPython |
|---|---|---|
| Декомпилировать | `F5` | `ida_hexrays.decompile(ea)` |
| Xrefs к адресу | `X` | `idautils.XrefsTo(ea)` |
| Переименовать | `N` | `idc.set_name(ea, "n")` |
| Задать тип | `Y` | `idc.SetType(ea, "int")` |
| Строки | `Shift+F12` | `idautils.Strings()` |
| Функции | `Ctrl+P` | `idautils.Functions()` |
| Сегменты | `Ctrl+S` | `idautils.Segments()` |
| Ссылка на функцию | `X` | `ida_funcs.get_func(ea)` |

## Батч-анализ и сравнение версий

Две задачи, где IDA экономит дни:

**Батч-анализ (headless).** IDA умеет работать без GUI через `idat`/`idat64`:
```bash
idat64 -A -S"dump.py" ./sample     # -A автономно, -S запустить скрипт
```
Скрипт `dump.py` в `IDAPython` сохраняет функции/строки/импорты в JSON. Так обрабатывают партии
образцов malware.

**Диффинг (Diaphora).** Diaphora сравнивает два `.idb` и выдаёт список изменённых функций по
матчингу (похожесть псевдо-C + граф вызовов). Сценарий:
```text
1. Открыть обе версии в IDA, запустить Diaphora на каждой (File → Script → diaphora.py)
2. Экспортировать в .sqlite
3. Открыть первый .idb, запустить Diaphora → Diff against → выбрать .sqlite второго
4. Получить списки: added / deleted / changed / matched
```
Это прямой путь к патчу: изменённые функции с высокой вероятностью содержат исправление уязвимости.

## IDA microcode API: пример плагина

Плагин на IDAPython может переписать микрокод функции. Скелет:

```python
import ida_hexrays, ida_funcs

class MaturityVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
    def visit_expr(self, e):
        # например, лог всех вызовов
        if e.op == ida_hexrays.cot_call:
            print("call @ 0x%x" % e.ea)
        return 0

def run(ea):
    f = ida_funcs.get_func(ea)
    cfunc = ida_hexrays.decompile(f.start_ea)
    v = MaturityVisitor()
    v.apply_to(cfunc.body, None)
    cfunc.refresh_func_ctext()
```

`ctree_visitor_t` позволяет обходить AST псевдо-C и модифицировать его — основа деобфускаторов.
Полноценная работа с микрокодом (`mblock_t`, `minsn_t`) доступна через `ida_hexrays` при более
глубоком погружении и требует понимания IR.

## Квиз

```quiz
- question: "Для чего нужны FLIRT-сигнатуры?"
  options:
    - "Для распаковки бинарника"
    - "Для распознавания функций стандартных библиотек в статически слинкованном коде"
    - "Для эмуляции"
    - "Для шифрования"
  answer: 1
- question: "Какая горячая клавиша декомпилирует функцию в IDA?"
  options:
    - "`F2`"
    - "`F9`"
    - "`F5`"
    - "`F7`"
  answer: 2
- question: "Что делает `Shift+F11` в IDA?"
  options:
    - "Открывает строки"
    - "Управление Type Libraries"
    - "Показывает секции"
    - "Открывает консоль"
  answer: 1
- question: "Какая функция IDAPython даёт доступ к декомпилированному AST?"
  options:
    - "`idautils.Strings()`"
    - "`ida_hexrays.decompile()`"
    - "`idc.get_name_ea_simple()`"
    - "`ida_bytes.get_bytes()`"
  answer: 1
- question: "Почему нельзя полностью доверять Hex-Rays?"
  options:
    - "Декомпилятор может ошибаться на косвенных вызовах, longjmp и inline asm"
    - "Он не поддерживает x86"
    - "Он не умеет показывать строки"
    - "Он работает только с PE"
  answer: 0
```

## Где пригодится

- **CTF Reversing:** быстрый разбор через декомпилятор и распознавание библиотек.
- **Malware analysis:** восстановление типов структур (PEB, контексты), анализ API-вызовов.
- **Vuln research:** поиск уязвимых паттернов, автоматизация через IDAPython/Hex-Rays AST.
- **Работа (RE-команда):** IDA — стандарт в enterprise и malware-лабораториях.
- **Собес:** FLIRT, Hex-Rays microcode, IDAPython — маркеры профессионального уровня.
