---
id: reversing-aot-native
title: ".NET Native / AOT: реверс скомпилированного managed-кода"
category: reversing
parent: reversing-managed-dotnet-java
difficulty: expert
order: 4
tags: [reversing, dotnet, aot, nativeaot, r2r, ready-to-run, coreclr]
prerequisites: [reversing-dotnet-advanced, reversing-static-analysis]
useful_for:
  - "CTF Reversing"
  - "Анализ защищённого .NET-ПО"
  - "Threat intelligence"
estimated_minutes: 60
summary: "Реверс NativeAOT/ReadyToRun .NET: как опознать AOT, восстановить метаданные и анализировать нативный код."
---
Обычный .NET-код компилируется в **IL** и легко декомпилируется. Но **NativeAOT** и **ReadyToRun (R2R)** компилируют managed-код в **нативный** машинный код заранее (ahead-of-time): IL-декомпиляция напрямую не работает, а метаданные либо отсутствуют, либо сильно урезаны. Это усложняет анализ .NET-малвари и защищённого ПО, которое всё чаще собирают именно так. Этот урок — как опознать AOT, выбрать правильный подход и анализировать нативный managed-код через строки, паттерны рантайма и динамику.

## Типы компиляции .NET

| Тип | Что содержит | Декомпиляция |
|-----|--------------|--------------|
| IL-only | IL + полные метаданные | dnSpy/ILSpy — почти исходник |
| ReadyToRun (R2R) | нативный код **+ сохранённые IL/метаданные** | частично: IL можно извлечь |
| NativeAOT | только нативный код, метаданные урезаны | нет; Ghidra/IDA |
| Mixed-mode | managed + native (C++/CLI, Reactor) | гибрид |
| Self-contained | рантайм + сборки (не обязательно AOT) | обычно IL |

Ключевое различие: **R2R сохраняет IL-метаданные** (для fallback-компиляции), а **NativeAOT — нет** (IL скомпилирован и отброшен). Поэтому R2R часто поддаётся .NET-инструментам, а NativeAOT — нет.

## Опознание AOT

```bash
file sample.exe
# NativeAOT: "PE32+ executable (console) x86-64" — НЕ ".NET assembly"
strings -a sample.exe | grep -iE "NativeAOT|System.Private.CoreLib|CoreCLR|Rhp"
# R2R: сохраняет IL/метаданные
strings -a sample.exe | grep -iE "ReadyToRun|R2R|Composite"
# Секции
python3 -c "import lief; e=lief.parse('sample.exe'); [print(s.name) for s in e.sections]"
```

Признаки NativeAOT: нет `.NET`-заголовков (COR20 header), нет строк `mscorlib`/`System.Runtime` в виде сборок, но есть `System.Private.CoreLib`, символы рантайма (`RhpNewFast`, `RhNewArray`, GC-функции), статически слинкованный рантайм, огромный размер, stripped-символы.

## Проблемы реверса AOT

- **Нет IL.** .NET-декомпиляция не работает; нужен нативный дизасм.
- **Нет managed-метаданных** (или минимум): нет имён типов/методов.
- **Инлайн и оптимизации.** Код сильно оптимизирован, не похож на исходный C#.
- **Огромный рантайм.** GC, type system, reflection-машинерия — тысячи функций «шума».
- **Виртуальные вызовы.** Интерфейсы/делегаты компилируются в indirect-вызовы (сложнее отследить).
- **Строки/исключения** остаются — главная точка опоры.

## Подход к анализу

```text
1) Опознать AOT (строки/секции/отсутствие IL).
2) Найти managed-метаданные, если есть (R2R сохраняет).
3) Анализировать нативно в Ghidra/IDA; искать паттерны CLR-рантайма.
4) Использовать строки/исключения для локализации логики.
5) Динамика (gdb/WinDbg) для проверки гипотез.
6) Для R2R: извлечь IL (если сохранён) и декомпилировать.
```

```bash
# Извлечь метаданные/строки
strings -a sample.exe | grep -iE "Exception|System\.|method|type"
# R2R: искать NativeFormat/IL-метаданные
```

## Опоры: строки, исключения, паттерны рантайма

В NativeAOT-бинаре нет символов, но остаются:

- **Строки** — сообщения об ошибках, формат-строки, пути, URL. Это якоря для локализации логики (`strings -a -n 6 | grep -iE "invalid|key|license"`).
- **Исключения** — `System.Exception`, `InvalidOperationException`, `NullReferenceException`: строки исключений ведут к проверкам.
- **Паттерны рантайма** — функции вроде `RhpThrowEx`, `RhpNewFast`, `GCHandle`, `String__ctor`. Они отмечают границы managed-кода.
- **RTTI/typeinfo** — NativeAOT хранит ограниченную информацию о типах (для reflection), иногда с именами.

## Разобранный пример: анализ NativeAOT crackme

```text
1) file: PE32+ executable (НЕ .NET assembly) -> вероятно NativeAOT.
2) strings: "System.Private.CoreLib" -> подтверждение.
3) Ghidra: анализируем main/точки входа; ищем строки-сообщения.
4) По строкам ("invalid key") находим проверку.
5) Динамика: breakpoint на строку -> понимание логики.
```

```bash
# Шаг 1-2: опознать
file sample.exe
strings -a sample.exe | grep -iE "System.Private.CoreLib|NativeAOT|CoreCLR"
python3 -c "import lief; e=lief.parse('sample.exe'); [print(s.name) for s in e.sections]"

# Шаг 3: опора на строки
strings -a -n 6 sample.exe | grep -iE "invalid|error|key|license|flag"

# Шаг 4: динамика — breakpoint на обращение к строке
gdb -q ./sample -ex 'b *0x<addr_обращения_к_строке>' -ex run
```

Точка входа: ищите `main`/`wmain` или старт рантайма (`RhpNewFast`, GC). В Ghidra загружайте как PE/ELF (x86-64), Auto Analyze. По `xref` на строку «invalid key» вы попадёте в функцию проверки.

## R2R (ReadyToRun)

R2R сохраняет IL-метаданные, поэтому его часто можно декомпилировать .NET-инструментами:

```bash
# IL сохранён -> dnSpy/ILSpy могут показать код
dnSpy sample_r2r.exe
# или извлечь R2R-метаданные специализированными инструментами
```

Если dnSpy показывает «пустые» методы (нативная версия подменила IL), ищите секции `.rdata`/`R2R`-заголовки и извлекайте IL вручную. Для R2R-малвари часто достаточно снять метаданные и декомпилировать.

## Гибридизация и обфускация AOT

Продвинутые .NET-протекторы комбинируют AOT с обфускацией:

- **NativeAOT + строковое шифрование.** Строки расшифровываются рантайм-функцией; `strings` видит только зашифрованные блобы. Ищите функцию-декодер по паттерну (XOR/AES в цикле) и вызывайте её динамически.
- **Mixed-mode.** Managed-сборка + нативный стаб (Reactor/ConfuserEx native): стаб расшифровывает IL в памяти. Анализ: сначала native-стаб (Ghidra/x64dbg), затем дамп расшифрованного IL и dnSpy.
- **Reflection-машинерия.** NativeAOT сохраняет метаданные типов для `Reflection`; это можно использовать, чтобы восстановить имена типов/методов (ограниченно).
- **Инлайн-агрессия.** Мелкие методы встраиваются, границы функций размываются; опирайтесь на строки и вызовы рантайма, а не на границы.
- **Self-modifying AOT.** Редко, но встречается: код расшифровывается в памяти (см. `reversing-self-modifying`).

## Практика: восстановление строк и структур

```text
1) strings -a -n 6 sample.exe -> черновой список (может быть обфусцирован).
2) Если строки зашифрованы: найти декодер (паттерн XOR/AES), вызвать его.
3) Найти RTTI/typeinfo: в NativeAOT есть таблицы типов для reflection.
4) По xref строк -> локализовать функции (проверки, парсеры, сеть).
5) Динамика: breakpoint на функцию, чтение аргументов (WinDbg/gdb).
```

Инструмент **ILSpy + NativeAOT-плагины** и **dnSpyEx** иногда частично восстанавливают имена по RTTI. Для малвари соберите IOC (C2, пути, ключи) из строк и структур — это и есть цель анализа.

## Сравнение с нативным C/C++ и с IL

| Признак | NativeAOT | C/C++ | IL-only |
|---------|-----------|-------|---------|
| CLR-заголовок | нет | нет | да |
| Рантайм-строки | `System.Private.CoreLib`, `Rhp*` | нет | `mscorlib` |
| GC-функции | есть (`GCHandle`, `GC`) | нет | нет |
| Метаданные типов | ограниченные (RTTI) | минимум | полные |
| Декомпиляция | нативная | нативная | .NET |

Определение AOT vs C++ важно: в C++ нет `RhpThrowEx`/`GC.Collect`-паттернов и строк `System.Private.CoreLib`. Если видите их — перед вами NativeAOT, и стоит искать typeinfo для восстановления имён.

## Инструменты

| Инструмент | Назначение |
|------------|------------|
| `file`/`lief`/`PE-bear` | опознать AOT (нет CLR-заголовка) |
| `strings`/FLOSS | строки/исключения как якоря |
| Ghidra/IDA | нативный дизасм/декомпиляция |
| dnSpy/ILSpy | для R2R (если IL сохранён) |
| WinDbg/gdb | динамика, breakpoints |
| Frida | перехват managed-функций (частично) |

## Динамика NativeAOT

Нативный managed-код отлаживается обычными средствами, но с оговорками:

```bash
# Linux
gdb -q ./sample
(gdb) info functions            # часто пусто (stripped)
(gdb) b *0x<addr>               # breakpoint по адресу (из Ghidra)
(gdb) run
```

- **Точки останова по адресам** — символов нет, ставьте BP на адреса, найденные в Ghidra (по xref строк).
- **Аргументы** — SysV x64: RDI/RSI/RDX/RCX/R8/R9; Windows x64: RCX/RDX/R8/R9. Managed-строки — это объекты (ptr+len), не C-строки.
- **Исключения** — при падении (panic) вы получите стек с адресами; сопоставьте с Ghidra.
- **Frida** — можно перехватывать native-функции по адресу и логировать аргументы.
- **WinDbg** — для Windows-AOT; BP по адресу, анализ исключений.

Динамика в паре со статикой (Ghidra + строки) — самый быстрый путь к логике проверки.

## Частые ошибки

- **Пытаться декомпилировать AOT как IL.** Не сработает — нужен нативный анализ.
- **Путать R2R и NativeAOT.** R2R сохраняет метаданные/IL; NativeAOT — нет.
- **Игнорировать строки.** В AOT это главная опора для локализации.
- **Ожидать managed-символы.** Их может не быть (stripped).
- **Не использовать динамику.** Нативный анализ без динамики трудоёмок.
- **Забыть про рантайм.** GC/type-system-код шумит — не принимайте его за логику.
- **Не найти точку входа.** Старт рантайма может быть далеко от `main`.

## Что делать дальше / решение

1. Опознайте тип: IL / R2R / NativeAOT (по CLR-заголовку и строкам).
2. Для R2R — попробуйте dnSpy/ILSpy (IL часто сохранён).
3. Для NativeAOT — загрузите в Ghidra/IDA как PE/ELF, найдите точку входа и паттерны рантайма.
4. Соберите якоря: строки, исключения, typeinfo; по `xref` идите к проверкам.
5. Подтвердите гипотезы динамикой (breakpoint на строку/функцию).
6. Для малвари — извлеките конфиг/C2 из строк и структур, оформите IOC.

## Квиз

```quiz
- question: "Что такое NativeAOT?"
  options:
    - "Полная нативная компиляция .NET (без IL)"
    - "Интерпретация IL"
    - "Формат файла"
    - "Тип шифрования"
  answer: 0
  explanation: "NativeAOT компилирует managed-код в нативный, IL отсутствует."
- question: "Как опознать AOT-бинарь?"
  options:
    - "По строкам (System.Private.CoreLib) и отсутствию IL"
    - "По GOT"
    - "По ldd"
    - "По nm"
  answer: 0
  explanation: "Строки рантайма и отсутствие .NET-заголовков указывают на AOT."
- question: "Чем R2R отличается от NativeAOT?"
  options:
    - "R2R сохраняет метаданные/IL, NativeAOT — нет"
    - "R2R только для Linux"
    - "Ничем"
    - "R2R — пакер"
  answer: 0
  explanation: "ReadyToRun частично сохраняет IL/метаданные."
- question: "Что помогает локализовать логику в AOT?"
  options:
    - "Строки и исключения"
    - "GOT"
    - "BTF"
    - "SVD"
  answer: 0
  explanation: "Строки/сообщения — главные ориентиры в нативном коде."
- question: "Какой инструмент для R2R IL?"
  options:
    - "dnSpy/ILSpy или R2R-извлекатели"
    - "nm"
    - "ldd"
    - "objdump -h"
  answer: 0
  explanation: "При сохранённом IL его декомпилируют .NET-инструментами."
```

## Где пригодится

- **CTF:** Reversing — .NET AOT-задачи.
- **Анализ защищённого .NET:** malware/ПО.
- **Threat intelligence:** современные .NET-угрозы.
- **Работа:** malware analysis.
