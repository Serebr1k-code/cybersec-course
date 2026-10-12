---
id: reversing-decompiler-plugin
title: "Разработка плагинов декомпилятора (Ghidra/IDA)"
category: reversing
parent: reversing-binary-lifting
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
## Вопрос, с которого всё начинается

Ты открыл бинарник в декомпиляторе (Ghidra, IDA) и разобрал одну функцию. А в программе их пятьсот.
Вручную пройти каждую, найти проверки, дать осмысленные имена — недели работы. Хочется
**автоматизировать** это: заставить декомпилятор сам пройти по всем функциям и сделать рутину за тебя.

Для этого у декомпилятора есть **скриптовый API**: ты пишешь программу, которая вызывает внутренние
механизмы анализа. Разберём это на Ghidra — её API открыт и бесплатен. Тот же принцип есть в IDA
(IDAPython) и radare2 (`r2pipe`), так что навык переносится между инструментами.

## Наш пример

Возьмём знакомый `crackme`: функция `check` сравнивает пароль со секретом через `strcmp`. Задача —
автоматически, без кликов мышью, получить декомпилированный код `check` и **найти все функции,
которые вызывают `strcmp`**, чтобы разом их переименовать.

Ghidra умеет работать **headless** — без графического интерфейса, из командной строки:

```
$ analyzeHeadless /tmp/proj proj -import ./crackme -postScript DumpPcode.java -deleteProject
```

Здесь `-import` загружает бинарник, а `-postScript` запускает наш скрипт **после** автоматического
анализа.

## Шаг 1: получаем декомпилированный код скриптом

Скрипт — это класс, наследующий `GhidraScript`. У него есть доступ к `currentProgram` (текущий
бинарник) и к `DecompInterface` (программный доступ к декомпилятору). Вот скрипт, который
декомпилирует функцию `check` и печатает результат:

```java
public class DumpPcode extends GhidraScript {
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals("check")) {
                DecompileResults res = decomp.decompileFunction(f, 60, monitor);
                println("DECOMPILED C:\n" + res.getDecompiledFunction().getC());
            }
        }
    }
}
```

Запускаем — и получаем псевдо-C без единого клика:

```
DECOMPILED C:
{
  int iVar1;
  char *in_local;
  char *secret;
  iVar1 = strcmp(in,"s3cr3t_pw");
  return (int)(iVar1 == 0);
}
```

Скрипт сам нашёл `check`, сам её декомпилировал и показал секрет `s3cr3t_pw`. Тот же приём работает
для **всех** функций: перебирай их в цикле и обрабатывай — так разбирают целые семейства образцов.

Основные точки входа в API Ghidra, которые понадобятся в скриптах:

| API | Назначение |
|---|---|
| `currentProgram` | текущий бинарник |
| `getFunctionAt(addr)` / `getFunctionContaining(addr)` | функция по адресу |
| `currentProgram.getFunctionManager()` | перебор функций |
| `getListing().getInstructions(...)` | инструкции |
| `createFunction(addr, name)` / `f.setName(...)` | создать/переименовать функцию |
| `setPlateComment` / `setComment` | комментарии |
| `getReferencesTo(addr)` | перекрёстные ссылки |
| `DecompInterface` | доступ к декомпилятору |

Этого набора хватает для большинства задач автоаннотации: пройтись по функциям, посмотреть их IR,
найти паттерн и оставить пометку.

## Шаг 2: заглядываем под капот — P-Code

Декомпилятор внутри работает не с ассемблером, а с промежуточным представлением **P-Code** — IR Ghidra
(каждая машинная инструкция разложена на простые операции). Скрипт может читать P-Code напрямую,
через `getHighFunction()`:

```java
HighFunction hf = res.getHighFunction();
java.util.Iterator<PcodeOpAST> it = hf.getPcodeOps();
while (it.hasNext()) {
    PcodeOpAST op = it.next();
    println(op.getMnemonic() + " out=" + op.getOutput());
}
```

Вывод для нашей `check`:

```
PCODE CALL       in[(ram,0x401040,8) ... ]  out=(register,0x0,4)
PCODE COPY       in[(const,0x402004,8)]     out=(unique,0x10000021,8)
PCODE INT_EQUAL  in[(register,0x0,4) (const,0x0,4)] out=(register,0x206,1)
PCODE RETURN     in[(const,0x0,8) (register,0x0,4)] out=null
PCODE INT_ZEXT   in[(register,0x206,1)]     out=(register,0x0,4)
```

Читается так: `CALL` (вызов `strcmp`), `COPY` константы `0x402004` (адрес секрета), `INT_EQUAL`
(сравнение результата с нулём), `RETURN`. На этом уровне удобно писать **автоматические правила**:
искать паттерны вроде «XOR-цикл», «сравнение с константой», «вызов `memcpy`» и подписывать их.

## Шаг 3: автоматизируем рутину — переименование

Теперь самое полезное. Напишем скрипт, который проходит по всем функциям, находит те, что вызывают
`strcmp`, и переименовывает их в осмысленное имя. У Ghidra есть готовый метод
`getCalledFunctions()` — он отдаёт функции, которые вызывает данная:

```java
FunctionManager fm = currentProgram.getFunctionManager();
for (Function f : fm.getFunctions(true)) {
    for (Function callee : f.getCalledFunctions(monitor)) {
        if (callee.getName().contains("strcmp")) {
            println("AUTONAME " + f.getName() + " calls " + callee.getName());
            f.setName("check_strcmp", SourceType.USER_DEFINED);
        }
    }
}
```

Запускаем:

```
AUTONAME strcmp calls strcmp -> renaming to check_strcmp
AUTONAME check calls check_strcmp -> renaming to check_strcmp
AUTONAME main calls check_strcmp -> renaming to check_strcmp
AUTONAME renamed=3
```

Скрипт сам обошёл граф вызовов и переименовал функции. На реальном образце такие скрипты
переименовывают десятки функций разом, подписывают крипто-константы и помечают подозрительные места —
это экономит часы ручной работы.

Второй классический сценарий — поиск **крипто-констант**. У известных алгоритмов есть характерные
числа (например, `0x67452301` из MD5/SHA). Скрипт перебирает константы в IR всех функций и, найдя
совпадение, ставит комментарий «похоже на MD5». Так за минуты находят криптографию в незнакомом
образце, вместо того чтобы листать функции глазами.

## Шаг 4: Java, Python и другие формы расширений

Ghidra расширяется на нескольких уровнях. **Скрипты** (наш случай) — одиночный файл, запускается из
Script Manager или через `-postScript`. **Плагины** — `.jar` с графическими панелями и хуками на
события анализа; для постоянных инструментов. **Loaders / Analyzers / Processors** — расширения для
новых форматов, авт-анализа и архитектур. Писать можно на **Java** и на **Python** (через PyGhidra);
Python удобнее для разовых задач, Java — для производительных плагинов.

Другие декомпиляторы тоже скриптуются: у IDA есть IDAPython (`idaapi`), у radare2/rizin — `r2pipe` /
`rzpipe` (команды фреймворка из Python). Идея одна: скрипт перебирает функции, читает IR и применяет
правила. Так строят **автоаннотацию** (распознать и подписать `memcpy`, XOR-циклы, хеш-константы),
**деобфускацию** (снять мусорные инструкции) и **интеграцию** (вызвать Z3/angr прямо из декомпилятора).

## Что мы теперь знаем

- Скриптовый API декомпилятора автоматизирует анализ: обход функций, декомпиляция, переименование.
- Ghidra работает headless (`analyzeHeadless -import ... -postScript ...`) без GUI.
- `DecompInterface` даёт декомпилированный C, `getHighFunction()` — P-Code (IR).
- `getCalledFunctions()` строит граф вызовов — на нём основана автоаннотация.
- Расширения бывают скриптами, плагинами и анализаторами; пишутся на Java и Python.
- Аналоги: IDAPython, `rzpipe`; идея та же — правила поверх IR.

Стоит помнить о цене автоматизации: скрипт делает именно то, что ты написал, и ошибка в правиле
тихо испортит разбор всего проекта (например, переименует не те функции). Поэтому правила проверяют
на одном образце, а `setName`/комментарии применяют, только когда уверен. Ещё нюанс: скрипты
декомпилятора работают на **уже проанализированном** проекте — если авт-анализ не распознал функцию,
скрипт её не увидит, и иногда её приходится создавать вручную (`createFunction`) перед обработкой.

## Квиз

Проверь себя.

```quiz
- question: 'Что даёт запуск Ghidra в режиме headless?'
  options:
    - 'Работу анализа и скриптов из командной строки без графического интерфейса'
    - 'Ускорение декомпиляции в сто раз'
    - 'Поддержку только ARM'
    - 'Запуск отладчика'
  answer: 0
  explanation: 'analyzeHeadless импортирует бинарник и запускает скрипты без GUI.'
- question: 'Какой API Ghidra даёт программный доступ к декомпилятору?'
  options:
    - 'DecompInterface'
    - 'getFunctionManager'
    - 'Function.getEntryPoint'
    - 'SymbolTable'
  answer: 0
  explanation: 'DecompInterface.decompileFunction возвращает декомпилированный C и P-Code.'
- question: 'Что такое P-Code в Ghidra?'
  options:
    - 'Промежуточное представление (IR), в которое разложены машинные инструкции'
    - 'Формат секции ELF'
    - 'Скриптовый язык Python'
    - 'Плагин отладки'
  answer: 0
  explanation: 'P-Code — IR Ghidra; скрипты читают его через getHighFunction().'
- question: 'Зачем нужен getCalledFunctions() в скрипте автоаннотации?'
  options:
    - 'Чтобы найти функции, вызывающие заданную (например, strcmp), и обработать их'
    - 'Чтобы ускорить анализ'
    - 'Чтобы сохранить проект'
    - 'Чтобы декомпилировать одну функцию'
  answer: 0
  explanation: 'Он даёт граф вызовов — основу для автоматического переименования и подписей.'
```

## Куда дальше

Мы научились автоматизировать декомпилятор скриптами. В следующем уроке разберём **трассировку
процессора** — как записать поток исполнения и найти в нём интересные места. А пока главное запомни:
скрипт декомпилятора = обход функций + чтение IR + правило; это то, что превращает ручной разбор в
масштабируемый, и тот же подход работает в IDA и radare2.

## Где пригодится

- **Malware analysis:** автоаннотация десятков функций в семействе образцов.
- **CTF Reversing:** быстрый поиск проверок и крипто-паттернов по всем функциям.
- **Деобфускация:** правила поверх IR для снятия мусора и восстановления потока.
