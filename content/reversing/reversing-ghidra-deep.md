---
id: reversing-ghidra-deep
title: "Ghidra: скриптинг, P-Code и headless"
category: reversing
parent: reversing-decompiler-tools
difficulty: hard
order: 2
tags: [reversing, ghidra, pcode, scripting, headless, python, decompiler]
prerequisites: [reversing-decompiler]
useful_for:
  - "CTF Reversing"
  - "Автоматизация анализа"
  - "Malware analysis"
estimated_minutes: 55
summary: "Глубокое использование Ghidra: скрипты, P-Code IR, headless-анализ и автоматизация."
---
Ghidra — бесплатный реверс-фреймворк от NSA, который за годы стал полноценной заменой IDA для
большинства задач. Его сила — в открытой архитектуре: любой этап (загрузка, анализ, декомпиляция)
расширяется скриптами на Java или Python (Jython), а декомпилятор на базе `decompiler` уступает
Hex-Rays лишь в мелочах. Этот урок — про профессиональную работу в Ghidra: скрипты, кастомные
загрузчики/плагины, тонкая настройка анализа и автоматизация.

## Почему Ghidra, а не IDA

- **Бесплатна и открыта** — нет проблем с лицензией, можно ставить на любую машину.
- **Мультиплатформенна** — x86/x64, ARM/ARM64, MIPS, PowerPC, RISC-V, 6502 и десятки других.
- **Декомпилятор в комплекте** для всех поддерживаемых процессоров.
- **Скриптинг на Python (Jython 2.7) и Java** — полноценный API.
- **Headless-режим** — анализ и батч-обработка без GUI.
- **Открытые форматы** — `.gzf` проект, экспорт/импорт.

Слабые места: скорость на очень больших бинарниках, отладчик (внешний, через gdb/lldb), некоторые
фишки Hex-Rays (например, микрокод) отсутствуют. Но для 90% задач — более чем достаточно.

## Установка и запуск

```bash
# скачать и распаковать релиз
unzip ghidra_*.zip -d /opt
/opt/ghidra/support/launch.sh        # GUI (Linux)
# или
/opt/ghidra/ghidraRun                # wrapper
# headless (без GUI)
/opt/ghidra/support/analyzeHeadless /tmp/ghproj MyProj \
    -import ./target -postScript myscript.py
```

Ключевой путь: `$GHIDRA/support/` (`analyzeHeadless`, `launch.sh`), `$GHIDRA/Ghidra/Features/`.

## Интерфейс: карта горячих клавиш

| Действие | Клавиша |
|---|---|
| Декомпилировать | `Ctrl+E` (окно Decompiler) |
| Rename | `L` |
| Set type | `Ctrl+L` / правый клик → Retype |
| Xrefs | `Ctrl+Shift+F` |
| Search strings | `Search → For Strings` |
| Go to address | `G` |
| Comment | `;` (EOL), `/` (pre) |
| List functions | окно Symbol Tree |
| Patch bytes | правый клик → Patch Instruction |
| Run script | `Window → Script Manager` |

Полезные окна: **Symbol Tree** (функции/классы), **Listing**, **Decompiler**, **Data Type Manager**,
**Script Manager**, **Function Graph**.

## Скриптинг: Python (Jython) и Java

Скрипты лежат в `$GHIDRA_SCRIPTS` или в `~/ghidra_scripts`. Минимальный пример — перечислить функции
и их xrefs:

```python
# list_funcs.py  (Jython 2.7)
from ghidra.program.model.listing import Function
fm = currentProgram.getFunctionManager()
for f in fm.getFunctions(True):
    print("%s @ %s" % (f.getName(), f.getEntryPoint()))
```

Полезные объекты: `currentProgram`, `currentAddress`, `monitor`, `state`.

**Поиск строки и xref:**
```python
listing = currentProgram.getListing()
for data in listing.getDefinedData(True):
    val = data.getValue()
    if val is not None and "flag" in str(val).lower():
        print("string @ %s = %r" % (data.getAddress(), str(val)))
        for ref in data.getReferenceIteratorTo() if False else \
                   getReferencesTo(data.getAddress()):
            print("   from %s" % ref.getFromAddress())
```

**Автопереименование по вызовам:**
```python
from ghidra.program.model.symbol import RefType
fm = currentProgram.getFunctionManager()
st = currentProgram.getSymbolTable()
sym = st.getGlobalSymbols("strcpy")
if sym:
    for ref in getReferencesTo(sym[0].getAddress()):
        f = fm.getFunctionContaining(ref.getFromAddress())
        if f:
            print("strcpy in %s" % f.getName())
```

**Декомпиляция из скрипта** — используем API декомпилятора:
```python
from ghidra.app.decompiler import DecompInterface
dec = DecompInterface()
dec.openProgram(currentProgram)
f = getFunctionAt(toAddr(0x401000))
res = dec.decompileFunction(f, 60, monitor)
print(res.getDecompiledFunction().getC())
```

## Кастомный загрузчик и процессор

Если формат бинарника проприетарный (прошивка, ROM), Ghidra не распознает его. Решение — **свой
loader** (Java-класс, наследующий `AbstractLoader`) или `GhidraScript` для ручного маппинга:

- **Raw binary import** — `File → Import File`, выбрать «Raw Binary», задать base address,
  language (процессор), memory block.
- **Свой loader** — реализовать `findSupportedLoadSpecs`, `load`, указать processor/language.
- **Свой processor** — для экзотических ISA: описать `.slaspec` (SLEIGH) и собрать.

Пример raw-импорта из скрипта:
```python
from ghidra.app.util.importer import MessageLog
from ghidra.app.util.opinion import BinaryLoader
# проще через GUI: Import → Raw Binary → base 0x08000000, ARM Cortex-M
```

Для прошивок часто удобно сначала определить архитектуру (`binwalk`, `file`, CPUID в загрузчике),
затем импортировать как raw по нужному адресу.

## Разобранный пример: автоматический поиск проверки

Дано: crackme, где нужно найти функцию валидации. Скрипт `find_check.py`:

```python
# ищем функции, вызывающие strcmp/memcmp, и печатаем их декомпиляцию
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
dec = DecompInterface(); dec.openProgram(currentProgram)
mon = ConsoleTaskMonitor()
st = currentProgram.getSymbolTable()
fm = currentProgram.getFunctionManager()
for name in ("strcmp", "memcmp", "strncmp"):
    syms = st.getGlobalSymbols(name)
    for s in syms:
        for ref in getReferencesTo(s.getAddress()):
            f = fm.getFunctionContaining(ref.getFromAddress())
            if not f: continue
            print("=== %s calls %s ===" % (f.getName(), name))
            res = dec.decompileFunction(f, 30, mon)
            print(res.getDecompiledFunction().getC())
```

Запуск: `Script Manager → find_check.py → Run`. В консоли получим псевдо-C функций-кандидатов.

## Разобранный пример: headless-анализ партии файлов

Для сотен образцов malware удобен headless:

```bash
/opt/ghidra/support/analyzeHeadless /tmp/proj Batch \
  -import /samples/*.bin \
  -scriptPath /home/user/ghidra_scripts \
  -postScript dump_strings.py \
  -deleteProject
```

`dump_strings.py` сохраняет строки и импорты каждого файла в JSON — удобно для дальнейшей
корреляции. Так можно за минуты обработать сотни образцов.

## Плагины и расширения

- **FindCrypt** — сигнатуры крипто-констант (см. урок crypto-binaries).
- **GhidraRetDec** — интеграция декомпилятора RetDec как альтернативы.
- **Kaiju** — анализ строк и анти-анализа.
- **Ghidra P-Code** — низкоуровневый IR для кастомного анализа (основа для символьного исполнения).
- **BSim** — поиск похожих функций (для группировки malware-семейств).

Установка расширений: `File → Install Extensions`, затем перезапуск.

## P-Code и промежуточное представление

Центральная абстракция Ghidra — **P-Code**: промежуточное представление, в которое транслируется
любая инструкция. Оно не зависит от архитектуры, что делает анализ переносимым. Пример: инструкция
`MOV EAX, [EBX+4]` транслируется в `LOAD` + `INT_ADD`. P-Code используется:

- декомпилятором (строит из него AST),
- символьным исполнением (эмуляторы вроде `pcode-emu`),
- кастомными анализами (taint, деобфускация).

Увидеть P-Code: правый клик в листинге → `Instruction → P-Code` или окно Decompiler с включённым
«Show P-Code».

## Крайние случаи и подводные камни

- **Автоанализ может ошибаться** на обфусцированных/упакованных бинарниках — сначала распакуйте (UPX и др.).
- **Jython — Python 2.7**, не 3. `print` без скобок, `str`/`unicode` — учитывайте.
- **Скрипты падают молча** — смотрите Console (`Window → Console`) и `print` для отладки.
- **Типы важнее, чем кажется.** Задавайте структуры через Data Type Manager — декомпилятор сразу
  станет читаемым (аналог `Y` в IDA).
- **Долгий анализ.** Для больших бинарников отключайте ненужные анализаторы (`Analysis → Auto Analyze`
  → выбрать подмножество).
- **Отладка только внешняя.** Ghidra-отладчик подключается к gdb/lldb/WinDbg; настройка требует
  ghidra-bridge.
- **Совместимость версий.** API меняется между релизами — скрипты для 10.x могут не работать на 11.x.

## Что дальше / решение

1. Загрузить бинарник, дать автоанализу завершиться, применить типы/структуры.
2. Найти точку входа (strings, xref на `main`, entry point).
3. Декомпилировать ключевые функции (`Ctrl+E`), переименовывать по мере понимания.
4. Для рутины — писать скрипты (перечисление, поиск, декомпиляция, патч).
5. Для партий образцов — headless + postScript.
6. Для экзотики — raw-импорт или свой loader/processor.

Методический приём: **чем чаще вы переименовываете и типизируете, тем чище становится декомпиляция**.
Ghidra не «угадывает» так агрессивно, как Hex-Rays, поэтому ручная разметка окупается сторицей.

## Справочная таблица: API Ghidra (Python)

| Задача | API |
|---|---|
| Текущая программа | `currentProgram` |
| Менеджер функций | `currentProgram.getFunctionManager()` |
| Функция по адресу | `getFunctionAt(toAddr(0x401000))` |
| Ссылки на адрес | `getReferencesTo(addr)` |
| Таблица символов | `currentProgram.getSymbolTable()` |
| Декомпилятор | `DecompInterface()` |
| Листинг | `currentProgram.getListing()` |
| Дизассемблировать | `disassemble(toAddr(0x401000))` |
| Читать память | `getBytes(addr, n)` |
| Монитор | `monitor` / `ConsoleTaskMonitor()` |

## Типы и структуры: делаем декомпиляцию читаемой

В Ghidra, как и в IDA, качество декомпиляции на 80% зависит от типов. Работа со структурами:

- **Data Type Manager** (`Window → Data Type Manager`) — иерархия типов. Здесь можно:
  - импортировать типы из заголовков C (`File → Parse C Source` → указать `.h` и пути include);
  - создать структуру вручную (`Create → Structure`), добавить поля;
  - импортировать типы из PDB (для Windows-бинарников) — `File → Load PDB` или symbol-server.
- **Применить тип**: правый клик на переменной в Decompiler → `Retype Variable` (`Ctrl+L`) →
  ввести `struct packet *`. Декомпилятор покажет `p->len`.
- **Auto-create structures** — анализатор может сам построить структуру по паттернам доступа.

Пример: для Windows-драйвера импортируем `ntifs.h` и `wdm.h` — декомпилятор начнёт показывать
`PEPROCESS`, `IRP`, `KIRQL` вместо `void *`/`int`.

## Отладка через ghidra-bridge / gdb

Ghidra не имеет собственного отладчика в классическом смысле — она подключается к внешнему:

- **gdb** (`ghidra-bridge` или встроенный `Debugger → Connect` для Linux) — запуск/подключение к
  `gdbserver`, синхронизация адресов, точки останова в GUI.
- **lldb** — для macOS/iOS.
- **WinDbg** — через `dbgeng` (плагин сообщества).

Типовой сценарий:
```bash
gdbserver :1234 ./target
# Ghidra: Debugger → Configure and launch → gdb → localhost:1234
```
Затем `F9` (continue), `F2` (breakpoint), шаг с заходом/без. Полезно: в Ghidra видно одновременно
декомпилированный C, листинг и регистры — лучше, чем голый gdb.

## Сравнение с IDA: что выбрать

| Возможность | Ghidra | IDA Pro |
|---|---|---|
| Цена | бесплатно | очень дорого |
| Декомпилятор | встроен | Hex-Rays (отдельно) |
| Микрокод | нет (есть P-Code) | да (microcode) |
| FLIRT | BSim (похожие функции) | FLIRT (сигнатуры) |
| Скриптинг | Jython 2.7 + Java | IDAPython (Py3) |
| Отладчик | внешний | встроенный |
| Скорость | медленнее на больших | быстрее |
| Коллаборация | Ghidra Server | IDA Teams |

Практика: Ghidra — основной инструмент для malware/CTF/академии; IDA — там, где нужен
промышленный отладчик или редкие процессоры с готовыми `.sig`.

## Полезные приёмы автоматизации

- **Batch decompile в текст** — пройти все функции и сохранить псевдо-C для grep:
```python
from ghidra.app.decompiler import DecompInterface
dec = DecompInterface(); dec.openProgram(currentProgram)
out = open("/tmp/all.c", "w")
for f in currentProgram.getFunctionManager().getFunctions(True):
    r = dec.decompileFunction(f, 20, monitor)
    out.write("// %s @ %s\n%s\n\n" % (f.getName(), f.getEntryPoint(),
              r.getDecompiledFunction().getC()))
out.close()
```
Затем `grep -n "memcpy" /tmp/all.c` находит все опасные копирования сразу.
- **Поиск констант** — `Search → For Scalars` или скрипт с `listing.getDefinedData`.
- **Экспорт в JSON** — для интеграции с внешними анализаторами.
- **Diff двух версий** — `Version Tracking` сопоставляет функции по BSim-схожести, что ускоряет
  поиск патча между релизами.

## Квиз

```quiz
- question: "Что такое P-Code в Ghidra?"
  options:
    - "Исходный код на C"
    - "Промежуточное представление (IR), не зависящее от архитектуры"
    - "Формат проекта"
    - "Плагин для IDA"
  answer: 1
- question: "Какая функция API ищет байтовую сигнатуру в памяти?"
  options:
    - "`getSymbols()`"
    - "`memory.findBytes()`"
    - "`getFunctionContaining()`"
    - "`decompileFunction()`"
  answer: 1
- question: "Как запустить Ghidra без GUI?"
  options:
    - "`analyzeHeadless`"
    - "`ghidra -nogui`"
    - "`ghidraRun --batch`"
    - "`ghidraServer`"
  answer: 0
- question: "На каком языке пишутся скрипты Ghidra?"
  options:
    - "Только Java"
    - "Java или Jython (Python 2)"
    - "C++"
    - "Lua"
  answer: 1
- question: "Зачем нужен `-processor` в headless?"
  options:
    - "Задать язык/архитектуру для импорта «сырого» бинарника"
    - "Указать число потоков"
    - "Задать таймаут"
    - "Включить отладку"
  answer: 0
```

## Где пригодится

- **CTF Reversing:** быстрый автоматический поиск проверок и крипто-таблиц.
- **Malware analysis:** пакетный headless-анализ сотен образцов, извлечение IOC.
- **Vuln research:** поиск уязвимых паттернов (копирование без проверки, format strings) по коду.
- **Работа (RE-команда):** построение автоматизированных пайплайнов триажа на базе Ghidra.
- **Собес:** вопросы про P-Code, скриптинг и headless отличают продвинутого Ghidra-пользователя.
