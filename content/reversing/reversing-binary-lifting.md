---
id: reversing-binary-lifting
title: "Binary lifting: P-Code и angr IR"
category: reversing
parent: reversing-symbolic-tools
difficulty: expert
order: 2
tags: [reversing, binary-lifting, pcode, ghidra, ir, vex, angr]
prerequisites: [reversing-symbolic-execution, reversing-ghidra-deep]
useful_for:
  - "CTF Reversing"
  - "Automated analysis"
  - "Decompiler/tooling development"
estimated_minutes: 60
summary: "Подъём машинного кода в промежуточное представление: Ghidra P-Code, VEX, angr IR для кастомного анализа."
---
**Binary lifting** — это преобразование машинного кода в **промежуточное представление (IR)**: небольшой набор абстрактных операций над регистрами, памятью и флагами, не зависящий от конкретной ISA. IR — фундамент символьного исполнения, деобфускации, девиртуализации и любого кастомного анализа: вместо того чтобы писать анализ под x86, ARM и MIPS по отдельности, вы работаете с одним универсальным слоем. Ключевые реализации: Ghidra **P-Code**, Valgrind **VEX** (на нём построен angr), LLVM IR (remill/McSema), Miasm, Triton, VTIL. Этот урок — практическая работа с IR от получения P-Code до деобфускации MBA.

## Зачем нужен IR

Машинный код — плохой объект для анализа: инструкции переменной длины, неявные побочные эффекты (флаги), зависимость от ISA. IR решает это:

- **Абстракция.** Одна сложная инструкция (`imul rax, rbx, 3`) превращается в последовательность простых операций (`INT_MULT`, `INT_ADD`).
- **Единый анализ.** Один и тот же пасс работает для x86-64, ARM64, MIPS — только лифтер различается.
- **Символьное исполнение.** Операции IR естественно транслируются в формулы SMT (z3): регистры и память становятся символьными битвекторами.
- **Оптимизация и упрощение.** Свёртка констант, удаление мёртвого кода, распространение копий — как в компиляторе, но для восстановления семантики.
- **Деобфускация.** MBA-обфускация и виртуальные машины восстанавливаются на уровне IR.
- **Рекомпиляция.** IR можно транслировать обратно в C/ассемблер или LLVM IR.

## Ghidra P-Code: структура и API

P-Code — IR Ghidra. Каждая машинная инструкция превращается в список **P-Code-операций** с явными входами/выходами:

| Операция | Смысл |
|----------|-------|
| `COPY` | присваивание |
| `LOAD` / `STORE` | чтение/запись памяти |
| `INT_ADD` / `INT_SUB` / `INT_MULT` | арифметика |
| `INT_AND` / `INT_OR` / `INT_XOR` | битовые операции |
| `INT_LEFT` / `INT_RIGHT` / `INT_SRIGHT` | сдвиги |
| `INT_LESS` / `INT_EQUAL` | сравнения (во флаг) |
| `CBRANCH` | условный переход |
| `BRANCH` / `BRANCHIND` | безусловный/косвенный переход |
| `CALL` / `RETURN` | вызов/возврат |
| `FLOAT_ADD` / `FLOAT_MULT` | плавающая точка |

Получить P-Code функции из Ghidra-скрипта (Python/Java):

```python
# Ghidra Script (Python): дамп P-Code декомпилированной функции
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

decomp = DecompInterface()
decomp.openProgram(currentProgram)
res = decomp.decompileFunction(currentFunction, 60, ConsoleTaskMonitor())
high = res.getHighFunction()
for op in high.getPcodeOps():
    print(op.getMnemonic(), [str(i) for i in op.getInputs()], '->', op.getOutput())
```

Вывод: `INT_ADD (register:RAX, const:0x10) -> register:RAX`, `STORE (register:RBP, const:-0x8, register:RAX) -> None`. Этот поток можно **интерпретировать** (Ghidra P-Code Emulator) или прогонять через собственные пассы.

## VEX и angr IR

Valgrind VEX — IR, на котором построен angr. Каждый basic block транслируется в дерево VEX-инструкций (`Ist_IMark`, `Ist_Put`, `Ist_WrTmp`, `Ist_Store`, `Ist_Exit`) над временными значениями `t0..tN`:

```python
import angr
proj = angr.Project('./binary', auto_load_libs=False)
block = proj.factory.block(proj.entry)
print(block.vex.pp())                     # человекочитаемый VEX
for stmt in block.vex.statements:
    print(stmt.tag, stmt)
print('const jump targets:', block.vex.constant_jump_targets)
print('has indirect jump:', block.vex.jumpkind)
```

VEX-операции (`Iop_Add32`, `Iop_Load`, `Iop_Xor32`, `Iop_CmpLT32U`) — база для символьного и динамического анализа. `block.vex.constant_jump_targets` сразу показывает, куда блок может передать управление (полезно против обфускации с косвенными прыжками).

## Lifting в LLVM IR: remill, McSema, RetDec

Когда нужен весь аппарат оптимизаций LLVM:

- **remill** — лифтит отдельные инструкции в LLVM IR; используется в McSema и в проектах девиртуализации.
- **McSema** — восстанавливает LLVM IR из бинаря целиком; результат можно перекомпилировать или анализировать `opt`-пассами.
- **RetDec** — декомпилятор с собственным LLVM-бэкендом, даёт C-подобный вывод.
- **Miasm** — Python-фреймворк со своим IR и символьным движком; удобен для кастомной эмуляции.
- **Triton** — строит символьные выражения из инструкций (x86/ARM), популярен для concolic-анализа.

```bash
# RetDec
retdec-decompiler ./binary -o out.c
# McSema (через remill)
mcsema-disass --disassembler IDA --binary ./binary --output ./binary.cfg --arch amd64
mcsema-lift-12.0 --arch amd64 --os linux --cfg ./binary.cfg --output ./binary.bc
opt -O2 ./binary.bc -o ./binary.opt.bc
```

## Символьное упрощение и MBA-деобфускация

Mixed Boolean-Arithmetic (MBA) — популярная обфускация: простое выражение переписывают в эквивалентную, но запутанную форму. На IR это упрощается через SMT:

```python
from z3 import *
x, y = BitVecs('x y', 32)
plain = x + y
obf   = (x ^ y) + 2 * (x & y)          # MBA-тождество
print(prove(obf == plain))             # proved -> семантика восстановлена
```

Так же упрощаются `(x & ~y) | (~x & y)` → `x ^ y`, `x - (~y + 1)` → `x + y` и сотни других тождеств. Инструменты: **MBA-Solver**, **SiMBA**, **GAMBA** — они перебирают известные тождества и заменяют обфусцированные подвыражения на простые. В Ghidra есть плагин `SimplifyMBA`.

## Девиртуализация и рекомпиляция

Виртуальные машины (VMProtect, Themida, кастомные VM-обфускаторы) исполняют «свой» байткод через `dispatch`-цикл. Подход:

```text
1) Найти диспетчер (большой switch/indirect jump по handler-таблицам).
2) Лифтнуть handlers в IR.
3) Символически исполнить dispatch-цикл, записывая семантику каждого опкода.
4) Восстановить исходную программу (или транслировать IR -> C).
```

**VTIL** (Virtual-machine Translation Intermediate Language) создан именно для этого: он представляет handlers в едином IR и позволяет перекомпилировать «виртуализированный» код обратно в нативный. Связка VTIL + IDA/Ghidra используется в исследовательских девиртуализаторах.

## Разобранный пример: упрощаем MBA-обфускацию end-to-end

Дана функция с обфусцированной проверкой:

```c
// исходная (после обфускации) — псевдокод декомпилятора
int check(unsigned a, unsigned b) {
    unsigned t = (a | b) - (a & b);       // == a ^ b
    unsigned u = (a + b) - 2 * (a & b);   // == a ^ b
    return t ^ u;                          // == 0 для любых a,b? нет: t^u = 0
}
```

```python
from z3 import *
a, b = BitVecs('a b', 32)
t = (a | b) - (a & b)
u = (a + b) - 2 * (a & b)
# проверяем тождества
print(simplify(t), simplify(u))       # оба -> a ^ b
print(simplify(t ^ u))                # -> 0  => возврат всегда 0
```

Шаги workflow:

```text
1) Получить P-Code/VEX функции (декомпилятор/Ghidra/angr).
2) Перевести операции в z3-выражения (INT_ADD->+, INT_XOR->^, INT_AND->&).
3) Прогнать simplify() и доказать/опровергнуть равенство.
4) Заменить обфусцированное подвыражение на упрощённое.
5) Переписать функцию в понятном виде / пропатчить бинарь.
```

## Сравнение IR-фреймворков

| IR / фреймворк | Хост | Сильные стороны | Применение |
|----------------|------|-----------------|------------|
| Ghidra P-Code | Ghidra | декомпилятор + эмулятор + пассы | кастомный анализ, эмуляция |
| VEX | Valgrind/angr | быстрый, символьный | angr, symbolic execution |
| LLVM IR | remill/McSema | оптимизации `opt` | рекомпиляция, девиртуализация |
| Miasm | Python | IR + символьный движок | кастомная эмуляция |
| Triton | Python/C++ | символьные выражения | concolic, taint |
| VTIL | библиотека | рекомпиляция VM | девиртуализация |
| RetDec | CLI | готовый декомпилятор | быстрый C-вывод |
| BAP | OCaml | формальная семантика | академический анализ |

Практическое правило выбора: для **интерактивного** анализа и декомпиляции берите Ghidra P-Code (там же эмулятор и удобные пассы); для **символьного** исполнения — angr/VEX или Triton; для **рекомпиляции и девиртуализации** — remill/LLVM или VTIL; для **быстрого C-вывода** без установки IDE — RetDec. Часто инструменты комбинируют: lift в IR одним движком, а решение (z3) — другим.

## Частые ошибки

- **Игнорировать флаги.** Корректный IR моделирует EFLAGS/NF/ZF/CF; без этого упрощения ломают условные переходы.
- **Не учитывать архитектуру.** IR абстрагирует, но семантика (порядок байт, поведение сдвигов) зависит от ISA; 32-битные операции в 64-битном контексте ведут себя по-разному.
- **Тяжёлый IR на больших бинарях.** Полный лифтинг всего файла съедает память — ограничивайтесь функцией/блоком.
- **Смешивать IR и «сырой» ассемблер.** Анализируйте в одном слое; прыжки между представлениями порождают ошибки.
- **Забыть про модель памяти.** `LOAD`/`STORE` без модели (кто по какому адресу лежит) дают неверные результаты.
- **Не проверять эквивалентность.** Любое упрощение проверяйте через `prove`/`simplify`, иначе можно «упростить» семантику неверно.
- **Верить декомпилятору безоговорочно.** IR/декомпиляция могут терять детали (UB, alias); критичные места проверяйте динамикой.

## Что делать дальше / решение

1. Определите задачу: символьное исполнение, деобфускация или рекомпиляция — от неё зависит выбор IR.
2. Для Ghidra-пайплайна: получите P-Code функции и прогоните через свой пасс/эмулятор.
3. Для angr: используйте VEX-статистику (`constant_jump_targets`, `jumpkind`) для навигации и символьного исполнения.
4. Для девиртуализации: ищите dispatch-цикл, лифтите handlers (VTIL/remill) и восстанавливайте опкоды.
5. Для MBA: соберите z3-модель и упростите выражения (`simplify`/MBA-Solver).
6. Всегда валидируйте упрощения: `prove` на эквивалентность + динамическая проверка.

## Квиз

```quiz
- question: "Что такое binary lifting?"
  options:
    - "Подъём машинного кода в промежуточное представление (IR)"
    - "Сжатие бинаря"
    - "Шифрование кода"
    - "Загрузка библиотек"
  answer: 0
  explanation: "Lifting переводит инструкции в абстрактные операции IR."
- question: "Какой IR использует Ghidra?"
  options:
    - "P-Code"
    - "VEX"
    - "LLVM IR"
    - "GIMPLE"
  answer: 0
  explanation: "Ghidra использует P-Code для анализа/декомпиляции."
- question: "На каком IR построен angr?"
  options:
    - "VEX"
    - "P-Code"
    - "GIMPLE"
    - "WASM"
  answer: 0
  explanation: "angr использует Valgrind VEX IR."
- question: "Как IR помогает с обфускацией MBA?"
  options:
    - "Позволяет упростить выражения и доказать эквивалентность (z3)"
    - "Удаляет анти-отладку"
    - "Шифрует код"
    - "Сканирует порты"
  answer: 0
  explanation: "MBA-тождества проверяются/упрощаются на IR."
- question: "Что нужно моделировать в IR помимо данных?"
  options:
    - "Флаги (EFLAGS) и модель памяти (LOAD/STORE)"
    - "Только строки"
    - "Только секции"
    - "Только GOT"
  answer: 0
  explanation: "Корректный IR моделирует флаги и память."
```

## Где пригодится

- **CTF:** Reversing — деобфускация.
- **Automated analysis:** символьное исполнение.
- **Tooling development:** кастомные пассы.
- **Работа:** program analysis, research.
