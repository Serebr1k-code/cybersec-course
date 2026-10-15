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
## Вопрос, с которого всё начинается

У тебя есть `crackme` — бинарник, который просит ключ и печатает `Access granted` или
`Access denied`. Открывать GUI и кликать руками — долго, а если таких файлов сотня (образцы
malware, задачи CTF), то вручную вообще не вариант. Как заставить инструмент **сам** найти
функцию проверки и показать её код?

Ответ — **Ghidra**: бесплатный реверс-фреймворк с открытым API, декомпилятором в комплекте и
**headless-режимом** (работа без графического интерфейса). В этом уроке мы не будем «смотреть
глазами» — мы напишем скрипт, который найдёт проверку за нас.

Опираемся на прошлые уроки: ты уже умеешь смотреть на бинарник (`file`, `strings`) и знаешь, что
декомпилятор превращает ассемблер обратно в псевдо-C. Здесь мы поднимемся на уровень выше —
автоматизации.

## Наш пример

Сначала — что за файл:

```
$ file crackme
crackme: ELF 64-bit LSB executable, x86-64, ... dynamically linked, not stripped
```

`not stripped` — отличная новость: имена функций сохранены. Подтвердим строками:

```
$ strings -a crackme | grep -iE 'access|s3cr3t|usage'
s3cr3t!
usage: crackme <key>
Access granted
Access denied
```

Мы уже видим кандидата в ключи — `s3cr3t!`. Но в реальной задаче строки могут быть
зашифрованы, и «угадывать» нельзя. Нужно найти **функцию**, которая сравнивает ввод с ключом.
Сделаем это скриптом.

## Шаг 1: запускаем Ghidra headless

Headless-запуск — это команда `analyzeHeadless`: она импортирует бинарник в проект, прогоняет
автоанализ и выполняет наши скрипты. Напишем скрипт `FindCheck.java`, который перечислит
функции и декомпилирует ту, что зовётся `check`:

```java
public class FindCheck extends GhidraScript {
    public void run() throws Exception {
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);              // текущий бинарник
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true))
            println("FUNC " + f.getName() + " @ " + f.getEntryPoint());
        Function target = getFunction("check");
        DecompileResults res = dec.decompileFunction(target, 30, mon);
        println(res.getDecompiledFunction().getC());
    }
}
```

Запускаем:

```
$ /opt/ghidra/support/analyzeHeadless /tmp/ghproj CrackmeProj \
    -import ./crackme -scriptPath ./ghscripts -postScript FindCheck.java -deleteProject
...
INFO  FindCheck.java> ### FUNCTIONS ###
INFO  FindCheck.java> FUNC _init @ 00401000
INFO  FindCheck.java> FUNC FUN_00401020 @ 00401020
INFO  FindCheck.java> FUNC strcmp @ 00401040
INFO  FindCheck.java> FUNC check @ 00401136
INFO  FindCheck.java> FUNC main @ 00401162
...
INFO  FindCheck.java> ### DECOMPILE check ###
bool check(char *param_1)
{
  int iVar1;
  iVar1 = strcmp(param_1,"s3cr3t!");
  return iVar1 == 0;
}
```

Разберём флаги команды: `analyzeHeadless <папка_проекта> <имя_проекта>` — куда сохранять;
`-import ./crackme` — что загрузить; `-scriptPath` — где искать скрипты; `-postScript` — что
выполнить после анализа; `-deleteProject` — удалить проект по завершении (для разовых задач).

За один запуск мы получили и список функций, и декомпиляцию нужной. Обрати внимание: скрипт
вызывается с **открытой программой** `currentProgram` — это и есть текущий бинарник.

## Шаг 2: почему декомпиляция получилась читаемой — P-Code

Ghidra не декомпилирует ассемблер напрямую. Сначала каждая инструкция переводится в
**P-Code** — промежуточное представление (IR), не зависящее от архитектуры. Например,
`MOV EAX, [EBX+4]` превращается в пару операций `LOAD` и `INT_ADD`. Из этого IR строится
дерево, а из него — псевдо-C.

Это важно по двум причинам:

- **Переносимость.** Один и тот же анализ работает для x86, ARM, MIPS — P-Code одинаков.
- **Расширяемость.** На P-Code можно навешивать свои анализы: символьное исполнение,
  taint-анализ, деобфускацию.

Посмотреть P-Code можно в листинге: правый клик → `Instruction → P-Code`.

## Шаг 3: что ещё умеет API Ghidra

Скриптинг — главная сила Ghidra. Полезные объекты и вызовы:

| Задача | API |
|---|---|
| Текущая программа | `currentProgram` |
| Менеджер функций | `currentProgram.getFunctionManager()` |
| Функция по имени/адресу | `getFunction("check")` / `getFunctionAt(toAddr(0x401136))` |
| Ссылки на адрес (кто вызывает) | `getReferencesTo(addr)` |
| Таблица символов | `currentProgram.getSymbolTable()` |
| Декомпилятор | `DecompInterface()` |
| Чтение байтов | `getBytes(addr, n)` |
| Дизассемблировать | `disassemble(toAddr(0x401136))` |

Типичный сценарий «найти все проверки» — обойти ссылки на `strcmp`/`memcmp` и декомпилировать
функции-вызыватели. Именно так автоматически локализуют валидацию в crackme и malware.

Ещё приёмы автоматизации:

- **Батч-декомпиляция в текст** — пройти все функции и сохранить псевдо-C, затем
  `grep -n "memcpy" all.c` мгновенно находит опасные копирования.
- **Поиск крипто-констант** — расширение FindCrypt по сигнатурам AES/SHA.
- **BSim** — поиск похожих функций, помогает группировать семейства malware и находить патч
  между версиями.

## Шаг 4: партия образцов и кастомные форматы

Для сотен образцов headless запускают по маске:

```
$ /opt/ghidra/support/analyzeHeadless /tmp/proj Batch \
    -import /samples/*.bin -scriptPath ./ghscripts \
    -postScript dump_strings.java -deleteProject
```

Каждый образец анализируется, скрипт сохраняет строки и импорты в JSON — за минуты получаем
таблицу IOC по всей коллекции.

Если формат проприетарный (прошивка, ROM), Ghidra его не распознает. Тогда импортируют
**Raw Binary**: `File → Import File → Raw Binary`, задав базовый адрес, процессор и
memory block. Для экзотических ISA пишут свой **loader** (наследник `AbstractLoader`) или
даже свой процессор (описание SLEIGH). Для прошивок сначала определяют архитектуру
(`binwalk`, `file`), затем импортируют по нужному адресу.

## Что мы теперь знаем

- **Headless** (`analyzeHeadless`) позволяет анализировать и декомпилировать бинарники без GUI.
- Скрипт Ghidra получает `currentProgram` и может перечислять функции, искать ссылки,
  декомпилировать, читать байты.
- Декомпилятор строит псевдо-C из **P-Code** — архитектурно-независимого IR.
- Типы и структуры (`Data Type Manager`) резко улучшают читаемость: задал `struct packet *` —
  и видишь `p->len` вместо `*(int *)(param + 4)`.
- Для пакетной обработки — headless + postScript; для чужих форматов — raw-импорт или свой loader.

## На что смотреть дальше

- Jython в Ghidra — это **Python 2.7**; если пишешь на Python, следи за `print` без скобок.
  Современные сборки могут требовать PyGhidra — тогда используй Java-скрипты, как здесь.
- Скрипты «падают молча» — включай `Window → Console` и печатай отладочные `println`.
- На упакованных бинарниках автоанализ ошибается: сначала распакуй (UPX и др.), потом анализируй.
- API меняется между релизами — скрипт для Ghidra 10.x может не собраться на 11.x.

## Headless-режим: скрипты для потока образцов

`analyzeHeadless` запускает Ghidra без GUI и идеален для пакетной обработки. Синтаксис:

```bash
$GHIDRA/support/analyzeHeadless /tmp/proj MyProj \
  -import ./sample.bin \
  -postScript MyScript.java \
  -scriptPath ./scripts \
  -deleteProject
```

Ключевые флаги: `-import` (файл или каталог), `-postScript` (запускается после автоанализа), `-preScript` (до), `-processor` (архитектура, если не определяется), `-noanalysis` (только загрузить). Для партии используйте `-import /path/*.bin` — Ghidra обработает каждый. Это основа автоматического триажа: сотни образцов за ночь.

## Скриптинг на Java и Python

Ghidra API доступен из Java и Jython/PyGhidra. Java-скрипты — это класс, наследующий `GhidraScript`:

```java
public class DumpFuncs extends GhidraScript {
    public void run() throws Exception {
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            println(f.getName() + " @ " + f.getEntryPoint());
        }
    }
}
```

PyGhidra (Ghidra 11+) позволяет писать на настоящем CPython:

```python
from ghidra.program.model.symbol import SourceType
fm = currentProgram.getFunctionManager()
for f in fm.getFunctions(True):
    print(f.getName(), f.getEntryPoint())
```

Типовые задачи скриптов: переименование функций по сигнатурам, извлечение строк, поиск криптоконстант, автопометка подозрительных вызовов (`strcpy`, `system`), экспорт декомпилированного кода в файлы.

## P-Code: почему декомпиляция читаема

Ghidra не декомпилирует машинный код напрямую. Она переводит инструкции в **P-Code** — промежуточное представление (SSA-подобное), где сложные архитектуры приводятся к общему виду. Затем применяются упрощения (constant propagation, dead-code elimination, восстановление типов), и только потом генерируется псевдокод C.

Практические следствия:

- Одна и та же логика на x86/ARM/MIPS даёт **похожий** P-Code → кросс-архитектурные скрипты пишутся один раз.
- Сложные инструкции (x86 `rep movsb`, ARM `LDM`) разворачиваются в циклы P-Code, поэтому декомпиляция может выглядеть «многословно».
- Иногда декомпилятор ошибается (особенно на обфусцированном коде); тогда полезно смотреть **листинг P-Code** (`Window → Decompiler → P-Code`) и понимать, где потерялась семантика.

## API Ghidra: что ещё умеет

Помимо перебора функций, API даёт:

- **Символы и ссылки**: `getReferencesTo(addr)` — кто вызывает функцию.
- **Кросс-ссылки**: `getXrefsTo` для трассировки потока данных.
- **Типы**: `HighFunction`/`DataTypeManager` — восстановление структур, применение сигнатур.
- **Скрипты по строкам**: поиск криптоконстант (AES S-box, RC4 init).
- **Патчинг**: `setBytes`/`patchProgram` — изменение инструкций прямо в проекте.
- **Экспорт**: декомпиляция в C, листинг в ASM, граф вызовов.

Для задач вроде «найти функцию, которая проверяет лицензию», удобно искать по строке («invalid license») и трассировать xref'ы до функции-проверки. Для крипто — по S-box в `.rodata`.

## Партия образцов и кастомные форматы

Для прошивок и нестандартных форматов Ghidra нужен **loader** (загрузчик). Если формат неизвестен, используйте `Raw Binary` и вручную задайте базу и архитектуру (`-processor ARM:LE:32:Cortex`). Для известных форматов (ELF, PE, Mach-O) загрузчики встроены.

Пакетная обработка с извлечением результатов:

```bash
analyzeHeadless /tmp/proj Batch -import ./samples \
  -postScript ExtractIOCs.java -scriptPath ./scripts -deleteProject
```

Скрипт может писать отчёт в JSON/CSV: адреса, строки, вызовы API, хэши функций. Это превращает Ghidra в элемент CI-пайплайна: каждый новый образец автоматически разбирается, а результат попадает в базу. Ограничения: тяжёлые образцы замедляют автоанализ, а `-deleteProject` теряет ручные правки — для повторного анализа сохраняйте проект.

## Чек-лист автоматизации

1. Проверьте, что `analyzeHeadless` находит путь к Ghidra (`$GHIDRA`).
2. Загрузите один образец, убедитесь в правильной архитектуре.
3. Напишите скрипт, выводящий нужное (функции/строки/ссылки).
4. Прогоните на партии, соберите отчёт.
5. Для сложных форматов добавьте loader или задайте `-processor`.
6. Сохраняйте проект, если нужны ручные правки между запусками.

## Квиз

Проверь себя.

```quiz
- question: "Что такое P-Code в Ghidra?"
  options:
    - "Исходный код на C"
    - "Промежуточное представление (IR), не зависящее от архитектуры"
    - "Формат проекта"
    - "Плагин для IDA"
  answer: 1
  explanation: "Каждая инструкция транслируется в P-Code, из которого строится декомпиляция."
- question: "Как запустить Ghidra без графического интерфейса?"
  options:
    - "`analyzeHeadless`"
    - "`ghidra -nogui`"
    - "`ghidraRun --batch`"
    - "`ghidraServer`"
  answer: 0
  explanation: "analyzeHeadless импортирует бинарник, прогоняет анализ и выполняет скрипты."
- question: "Какой объект в скрипте Ghidra обозначает текущий бинарник?"
  options:
    - "`currentAddress`"
    - "`currentProgram`"
    - "`monitor`"
    - "`listing`"
  answer: 1
  explanation: "currentProgram — открытая в данный момент программа."
- question: "Формат прошивки Ghidra не распознала. Что делать?"
  options:
    - "Сдаться"
    - "Импортировать как Raw Binary, задав базовый адрес и процессор"
    - "Запустить `strings`"
    - "Переупаковать UPX"
  answer: 1
  explanation: "Raw Binary import позволяет вручную указать адрес загрузки и архитектуру."
- question: "Зачем нужен `-postScript` в headless-запуске?"
  options:
    - "Указать число потоков"
    - "Выполнить скрипт после завершения автоанализа"
    - "Задать таймаут"
    - "Включить отладчик"
  answer: 1
  explanation: "-postScript запускает ваш скрипт по завершении анализа."
```

## Куда дальше

В следующем уроке мы возьмём тот же приём — «найти проверку и прочитать логику» — и применим
его в IDA Pro, где есть свой скриптовый API и микрокод. А пока главное запомни:
**Ghidra — это не только GUI, но и программируемый движок**, и `analyzeHeadless` плюс
несколько строк скрипта заменяют часы ручного кликанья.

## Где пригодится

- **CTF Reversing:** автоматический поиск проверок и крипто-таблиц.
- **Malware analysis:** пакетный headless-анализ сотен образцов, извлечение IOC.
- **Vuln research:** поиск уязвимых паттернов (копирование без проверки, format strings) по коду.
- **Работа (RE-команда):** построение автоматизированных пайплайнов триажа на базе Ghidra.
- **Собес:** вопросы про P-Code, скриптинг и headless отличают продвинутого Ghidra-пользователя.
