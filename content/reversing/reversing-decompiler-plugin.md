---
id: reversing-decompiler-plugin
title: "Разработка плагинов декомпилятора (Ghidra/IDA)"
category: reversing
parent: reversing-ghidra-deep
difficulty: hard
order: 1
tags: [reversing, ghidra, ida, plugin, scripting, automation, pcode]
prerequisites: [reversing-ghidra-deep, reversing-binary-lifting]
useful_for:
  - "CTF Reversing"
  - "Automation / tooling"
  - "Program analysis research"
estimated_minutes: 55
summary: "Разработка плагинов Ghidra/IDA: скрипты, P-Code, автоматизация анализа, свои пассы и интеграция."
---
**Плагины декомпилятора** превращают Ghidra и IDA из «просмотрщика ассемблера» в автоматизированную платформу: скрипты распознают структуры, деобфусцируют, аннотируют функции, извлекают строки и патчат байты пачками. Когда вручную разбирать сотни функций невозможно, плагин/скрипт — единственный путь. Урок даёт полный практический навык: от «Hello World» в Ghidra Script Manager и IDAPython до реального скрипта, который автоматически переименовывает и комментирует функции, плюс разбор архитектуры расширений и подводных камней API.

## Зачем писать плагины

- **Масштаб.** Программа на 500 функций — руками не разобрать; скрипт пройдёт по всем.
- **Повторяемость.** Один и тот же анализ для серии бинарников (malware-семейство, серия crackme).
- **Автоаннотация.** Распознать `memcpy`-паттерны, XOR-циклы, хеш-константы и подписать их.
- **Деобфускация.** Снять «мусорные» инструкции, восстановить контрольный поток.
- **Интеграция.** Вызвать внешние инструменты (Z3, angr) изнутри декомпилятора.

## Ghidra: три формы расширений

Ghidra расширяется через **Java** (основной API) и **Python (Jython)**. Три уровня:

1. **Scripts** — одиночный файл `.java`/`.py` в `~/ghidra_scripts/`, запускается из Script Manager. Быстро для разовых задач.
2. **Plugins** — `.jar` с GUI-панелями и хуками на события (анализ, навигация). Для постоянных инструментов.
3. **Loaders / Analyzers / Processors** — расширения для новых форматов, авт-анализа и архитектур.

```java
// HelloWorld.java — Ghidra script
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
public class HelloWorld extends GhidraScript {
    public void run() throws Exception {
        Function f = getFunctionAt(currentAddress);
        println("Function: " + (f != null ? f.getName() : "?"));
    }
}
```

Ключевые API Ghidra:

| API | Назначение |
|---|---|
| `currentProgram` | текущая программа |
| `getFunctionAt(addr)` / `getFunctionContaining(addr)` | функция |
| `currentProgram.getFunctionManager()` | перебор функций |
| `getListing()` / `getListing().getInstructions(...)` | инструкции |
| `createFunction(addr, name)` | создать/переименовать функцию |
| `setPlateComment`/`setComment` | комментарии |
| `getReferencesTo(addr)` | перекрёстные ссылки |
| `DecompInterface` | программный доступ к декомпилятору |

Пример авто-переименования функций, вызывающих `strcmp`:

```python
# ghidra_scripts/AutoNameStrCmp.py
from ghidra.program.model.symbol import SourceType
fm = currentProgram.getFunctionManager()
refmgr = currentProgram.getReferenceManager()
strcmp = getSymbol("strcmp", None)
if strcmp:
    for ref in refmgr.getReferencesTo(strcmp.getAddress()):
        f = getFunctionContaining(ref.getFromAddress())
        if f and not f.getName().startswith("sub_"):
            continue
        if f:
            f.setName("check_strcmp_%08x" % f.getEntryPoint().getOffset(),
                      SourceType.USER_DEFINED)
            print("renamed", f.getName())
```

Запуск: **Script Manager → New → Python → вставить → Run**. Или headless:

```bash
$GHIDRA_HOME/support/analyzeHeadless /tmp/proj proj1 \
  -import ./target -postScript AutoNameStrCmp.py -scriptPath ./ghidra_scripts
```

`analyzeHeadless` — мощнейшая опция для батч-обработки: она прогоняет анализ и все скрипты без GUI.

## IDA: IDAPython и IDC

В IDA основной язык автоматизации — **IDAPython** (`idaapi`, `idc`, `idautils`). Скрипт запускается через **File → Script file** или `-S` в командной строке.

```python
# ida_scripts/autoname_strcmp.py
import idautils, idaapi, idc, ida_name
ea = idc.get_name_ea_simple("strcmp")
if ea != idc.BADADDR:
    for xref in idautils.XrefsTo(ea, 0):
        f = idaapi.get_func(xref.frm)
        if f:
            name = "check_strcmp_%X" % f.start_ea
            idc.set_name(f.start_ea, name, idc.SN_NOWARN)
            print("renamed", name)
```

Ключевые API IDA:

| API | Назначение |
|---|---|
| `idc.get_name_ea_simple("sym")` | адрес символа |
| `idautils.XrefsTo(ea)` | кто ссылается |
| `idautils.Functions()` | перебор функций |
| `idaapi.get_func(ea)` | функция по адресу |
| `idc.set_name(ea, name)` | переименовать |
| `idc.set_cmt(ea, txt, 0)` | комментарий |
| `idc.get_bytes(ea, n)` / `idc.patch_byte` | чтение/патч байт |
| `idc.decompile(ea)` / `ida_hexrays` | декомпилятор (Hex-Rays) |

Запуск из командной строки:

```bash
ida64 -A -S"autoname_strcmp.py" ./target
# -A автономный режим, -S скрипт после загрузки
```

## Loader/Processor/Plugin: архитектура

Если нужен новый формат или архитектура — пишется **Loader** (распознать и загрузить), **Processor** (дизассемблировать) и **Analyzer** (автоанализ). Для этого в Ghidra используют `AbstractLoader`, `Language`/`Processor` (sleigh), `AbstractAnalyzer`. В IDA — `loader_t`, `processor_t`, `plugin_t` через IDAPython `ida_loader`/`ida_ida` или C++ SDK.

Скелет IDA-плагина на Python (`idaapi.plugin_t`):

```python
import idaapi, ida_kernwin
class MyPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "demo"
    help = ""
    wanted_name = "MyPlugin"
    def init(self): return idaapi.PLUGIN_KEEP
    def run(self, arg): ida_kernwin.info("Hello from plugin")
    def term(self): pass
def PLUGIN_ENTRY(): return MyPlugin()
```

## Разобранный пример: автоматический разбор XOR-цикла

Задача: в бинарнике есть цикл XOR-дешифровки строк. Нужно найти его и расшифровать все строки автоматически.

**Шаг 1. Найти цикл вручную и понять паттерн** (инструкции `xor [reg], imm` в цикле). 

**Шаг 2. Скрипт Ghidra**, который эмулирует цикл и заменяет строку:

```python
# ghidra_scripts/DecodeXorStrings.py
from ghidra.program.model.scalar import Scalar
listing = currentProgram.getListing()
it = listing.getInstructions(True)
for ins in it:
    if ins.getMnemonicString().lower() == "xor":
        # упрощённо: ищем xor с immediate и счётчиком
        pass
print("scan done")
```

**Шаг 3. Более практичный вариант** — пройти по ссылкам на data и применить XOR:

```python
from ghidra.program.model.address import AddressSet
def xor_decode(addr, length, key):
    mem = currentProgram.getMemory()
    buf = bytearray(length)
    mem.getBytes(addr, buf)
    return bytes(b ^ key for b in buf)

key = 0x5A
for block in currentProgram.getMemory().getBlocks():
    if not block.isInitialized(): continue
    data = bytearray(block.getSize())
    block.getBytes(block.getStart(), data)
    decoded = bytes(b ^ key for b in data)
    if b"flag{" in decoded:
        print("FOUND at", block.getStart(), decoded[:64])
```

## Интеграция с внешними движками

Из скрипта можно вызывать angr/Z3, передавая байты:

```python
# внутри Ghidra/IDA: получить код функции и отдать в angr
func_bytes = getBytes(func.getEntryPoint(), func.getBody().getNumAddresses())
# сохранить и запустить внешний angr-скрипт через subprocess
```

Это позволяет соединить статику (декомпилятор) с символьным исполнением — см. `reversing-symbolic-execution`.

## Сравнение Ghidra и IDA для плагинов

| Критерий | Ghidra | IDA |
|---|---|---|
| Языки | Java, Python (Jython) | IDAPython, C++ |
| Открытость API | полная, исходники | частично (SDK) |
| Headless | `analyzeHeadless` | `-A -S` |
| Декомпилятор API | `DecompInterface` | `ida_hexrays` |
| Стоимость | бесплатно | платно (Hex-Rays отдельно) |
| Скорость | медленнее | быстрее |

## Частые ошибки и подводные камни

- **Jython 2.7, а не Python 3.** В Ghidra-скриптах нет f-строк и части библиотек — используйте `.format()`.
- **Транзакции.** Любая модификация БД в Ghidra требует `startTransaction`/`endTransaction`, иначе изменения не сохранятся.
- **Устаревшие адреса.** После re-analysis адреса меняются — кэшируйте осторожно.
- **Типы данных.** `getBytes` требует правильного `Address`/`AddressSet`; выход за границы блока — исключение.
- **Hex-Rays только в IDA Pro.** `idc.decompile` вернёт ошибку в бесплатной версии.
- **Скрипт падает молча.** Оборачивайте в try/except и печатайте в консоль (`print` в Ghidra идёт в Script Output).

## Что дальше / решение

Начните с простого **скрипта-аннотатора** (переименовать все вызовы `strcmp`/`malloc`), затем переходите к **деобфускации** (снятие opaque-предикатов, восстановление строк) и **интеграции с angr/Z3**. Для серии бинарников обязателен headless-режим (`analyzeHeadless`/`ida -A -S`). Дальше — `reversing-ghidra-deep`, `reversing-ida-deep` и `reversing-symbolic-execution`: плагин — это способ соединить декомпилятор с символьным движком и автоматизировать то, что раньше делалось руками.

## Headless-автоматизация: полный разбор

Батч-обработка — главная причина писать плагины. У Ghidra и IDA разные CLI-контракты.

```bash
# Ghidra: импорт + автоанализ + скрипт
$GHIDRA_HOME/support/analyzeHeadless /tmp/proj demo \
  -import ./target \
  -postScript AutoNameStrCmp.py \
  -scriptPath ./ghidra_scripts \
  -deleteProject
```

| Флаг analyzeHeadless | Смысл |
|---|---|
| `-import <file>` | импортировать бинарник |
| `-postScript <s>` | скрипт после анализа |
| `-preScript <s>` | скрипт до анализа |
| `-scriptPath <dir>` | где искать скрипты |
| `-processor <lang>` | задать архитектуру |
| `-loader <class>` | задать загрузчик формата |
| `-deleteProject` | не оставлять проект |

```bash
# IDA: автономный режим
ida64 -A -S"autoname_strcmp.py" -Lida.log ./target
# -A автономно (без диалогов), -S скрипт, -L лог
```

Обратите внимание: в IDA `-S` выполняется **после** загрузки, но автоанализ может ещё идти; для ожидания используйте `ida_auto.auto_wait()` в начале скрипта.

## Разобранный пример: деобфускация XOR-строк целиком

Задача: бинарник хранит строки XOR-зашифрованными. Пишем скрипт, который находит расшифровку и подписывает данные.

**Шаг 1.** Находим в декомпиляторе цикл вида `for (i=0;i<n;i++) buf[i]^=key;`.

**Шаг 2.** Скрипт IDA, который эмулирует и патчит строку:

```python
import idc, ida_bytes, ida_bytes as ib
key = 0x5A
ea = idc.get_screen_ea()
raw = ida_bytes.get_bytes(ea, 64)
dec = bytes(b ^ key for b in raw)
if b"flag{" in dec or b"http" in dec:
    idc.set_cmt(ea, "XOR-decoded: " + dec.split(b"\x00")[0].decode("latin1"), 0)
    ida_bytes.patch_bytes(ea, dec)   # заменить на расшифрованное
print("done at %X" % ea)
```

**Шаг 3.** Массово по всем строкам:

```python
import idautils, ida_bytes
for s in idautils.Strings():
    raw = ida_bytes.get_bytes(s.ea, s.length)
    for k in range(1, 256):
        dec = bytes(b ^ k for b in raw)
        if b"flag{" in dec:
            print("key=%#x at %X: %s" % (k, s.ea, dec))
```

Вывод:

```
key=0x5a at 404050: flag{xor_is_not_crypto}
```

## Отладка скриптов и типовые исключения API

- **`NullPointerException` в Ghidra** — почти всегда неинициализированный объект (`currentProgram` вне контекста, `null` из `getFunctionAt`).
- **Модификация без транзакции** — в Ghidra изменения откатываются: всегда `startTransaction(...)`/`endTransaction(...)`.
- **IDAPython `NameError`** — модуль не загружен; в новых версиях API переехал в `ida_*` пакеты (`ida_bytes`, `ida_name`, `ida_funcs`).
- **Скрипт «завис»** — бесконечный цикл по `XrefsTo` при циклических ссылках; ограничивайте обход.
- **`ida_hexrays` недоступен** — Hex-Rays не установлен (только IDA Pro).

## Сравнение с внешними фреймворками автоматизации

| Инструмент | Язык | Плюс | Минус |
|---|---|---|---|
| Ghidra scripts | Java/Jython | бесплатно, полный API | медленно, Jython 2.7 |
| IDAPython | Python 3 | быстрый, зрелый | платно |
| Binary Ninja API | Python | удобный IL | платно |
| angr | Python | символьное исполнение | тяжёлый |
| radare2 r2pipe | Python/любой | лёгкий, скриптуемый | слабее декомпилятор |

## Что дальше / решение

Практический маршрут: **аннотатор → деобфускатор → интеграция с angr/Z3**. Для серий бинарников обязателен headless-режим. Дальше — `reversing-ghidra-deep` и `reversing-ida-deep` для тонкостей API, `reversing-symbolic-execution` для связки декомпилятора с символьным движком. Плагин — это мост: статика (структуры, типы, xref) плюс динамика/символика дают полную картину быстрее ручного разбора.

## Квиз

```quiz
- question: "Какой язык используют для скриптов Ghidra?"
  options:
    - "Java и Python (Jython)"
    - "Только C"
    - "Только Rust"
    - "Только Bash"
  answer: 0
  explanation: "Ghidra поддерживает Java и Jython-скрипты."
- question: "Что такое P-Code в Ghidra?"
  options:
    - "Промежуточное представление инструкций для анализа семантики"
    - "Формат файла"
    - "Тип структуры"
    - "Отладчик"
  answer: 0
  explanation: "P-Code — IR Ghidra, удобный для автоматического анализа."
- question: "Какой инструмент IDA для скриптов?"
  options:
    - "IDAPython"
    - "Jython"
    - "Ghidra API"
    - "Capstone"
  answer: 0
  explanation: "IDAPython — Python API IDA для плагинов/скриптов."
- question: "Как запустить Ghidra для массового анализа без GUI?"
  options:
    - "analyzeHeadless"
    - "gdb"
    - "objdump"
    - "strace"
  answer: 0
  explanation: "analyzeHeadless — headless-режим Ghidra для batch-анализа."
- question: "Что важно при использовании Decompiler API в цикле?"
  options:
    - "Кэшировать результаты (API дорог)"
    - "Вызывать на каждой инструкции"
    - "Отключать типы"
    - "Использовать CPython"
  answer: 0
  explanation: "Декомпиляция дорога; результаты кэшируют."
```

## Где пригодится

- **CTF:** Reversing — автоматизация разбора.
- **Automation/tooling:** собственные пассы.
- **Program analysis:** исследование.
- **Работа:** разработка инструментов анализа.
