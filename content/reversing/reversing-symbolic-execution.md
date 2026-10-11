---
id: reversing-symbolic-execution
title: "Символьное исполнение (angr)"
category: reversing
parent: reversing-module-symbolic
difficulty: expert
order: 4
tags: [reversing, angr, symbolic-execution, z3, concolic]
prerequisites: [reversing-vm-crackmes]
useful_for:
  - "CTF Reversing (expert)"
  - "Автоматический поиск входов"
  - "Обход сложных проверок"
estimated_minutes: 55
summary: "Как angr и SMT-решатели находят ввод, удовлетворяющий условиям, без полного реверса."
---
**Символьное исполнение** — это техника, при которой вход программы считается символьной переменной, а не конкретным значением, и исполнение исследует все пути, накапливая ограничения. В реверсе это позволяет автоматически найти вход, приводящий к нужному адресу (например, «correct»/флаг), без ручного разбора. Главный инструмент — **angr** (Python). Урок даёт полный workflow: установка, базовый цикл, работа с вводом, хуки, решение crackme и ограничения.

## Что такое символьное исполнение

Обычное исполнение идёт по одному пути с конкретными значениями. Символьное — трактует вход как символ `x` и, дойдя до ветвления `if (x == 5)`, создаёт **два состояния** с ограничениями `x == 5` и `x != 5`, продолжая оба. В конце решатель (SMT, обычно Z3) находит конкретный `x`, удовлетворяющий ограничениям целевого пути.

Применения: crackme, обход проверок, генерация входов для фаззинга, поиск путей к уязвимости.

## Установка angr

```bash
pip install angr
# или в venv (рекомендуется)
python3 -m venv venv && . venv/bin/activate
pip install angr
python3 -c 'import angr; print(angr.__version__)'
```

angr работает с ELF (Linux), PE (Windows), Mach-O, а также с raw-байтами и firmware. Для не-Linux — используйте `angr.Project` с нужным loader.

## Базовый workflow

```python
import angr

proj = angr.Project("./crackme", auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234, avoid=0x401250)
if simgr.found:
    s = simgr.found[0]
    print(s.posix.dumps(0))   # stdin, который привёл к цели
```

`auto_load_libs=False` — ключевая опция: не грузить системные библиотеки (иначе анализ взорвётся по путям). `explore` — главный метод: искать `find`, избегать `avoid`.

## Поиск и избегание адресов

Адреса `find`/`avoid` находятся статически (в Ghidra/IDA): адрес успеха и адрес ошибки.

```python
# find/avoid могут быть списками или функциями-предикатами
simgr.explore(find=lambda s: b"correct" in s.posix.dumps(1),
              avoid=lambda s: b"wrong" in s.posix.dumps(1))
```

Предикат по выводу (`stdout`) удобнее, чем жёсткие адреса: он не ломается при пересборке.

## Работа с вводом: stdin, argv, файлы

```python
# stdin
state = proj.factory.entry_state(stdin=angr.SimFile)
# argv
state = proj.factory.entry_state(args=["./crackme", angr.claripy.BVS("arg", 8*32)])
# ограничения на формат
for b in arg.chop(8):
    state.solver.add(b >= ord('0'))
    state.solver.add(b <= ord('9'))
```

`claripy.BVS` создаёт символьную переменную; `state.solver.add` — ограничения (например, «флаг начинается с `flag{`»).

## Хуки и SimProcedures

Внешние функции (libc) нужно **хукать**, иначе angr будет исполнять их код или упадёт.

```python
# заменить функцию на константу
proj.hook(0x401100, angr.SIM_PROCEDURES["libc"]["strlen"]())
# своя реализация
class MyHook(angr.SimProcedure):
    def run(self, arg):
        return self.state.solver.BVV(0, 32)
proj.hook(0x401200, MyHook())
```

angr имеет встроенные SimProcedures для libc (`strlen`, `strcmp`, `memcpy`, `printf`...). Если функция «неизвестна» и замедляет анализ — хукайте.

## Решение crackme: полный пример

**Шаг 1. Найти адреса.** В Ghidra: `check` — функция проверки; строка `Correct!` на адресе `0x402010`.

**Шаг 2. Скрипт.**

```python
import angr, claripy

proj = angr.Project("./crackme", auto_load_libs=False)
# 32-байтный ввод через argv[1]
arg = claripy.BVS("arg", 8*32)
state = proj.factory.entry_state(args=["./crackme", arg])
for b in arg.chop(8):
    state.solver.add(b >= 0x20, b <= 0x7e)   # печатные
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=lambda s: b"Correct" in s.posix.dumps(1),
              avoid=lambda s: b"Wrong" in s.posix.dumps(1))
if simgr.found:
    print(simgr.found[0].solver.eval(arg, cast_to=bytes))
```

**Шаг 3. Проверить** полученный ввод на реальном бинарнике:

```bash
./crackme "$(python3 solve.py)"
```

## Ограничения: path explosion

Символьное исполнение страдает от **взрыва путей**: число состояний растёт экспоненциально с числом ветвлений (циклы особенно опасны).

Приёмы борьбы:

- **Хуки** внешних/сложных функций.
- **Ограничения** на вход (формат, длина, алфавит).
- **`avoid`** — отсекать бесполезные пути.
- **`veritesting`** — техника слияния путей (`angr.options`).
- **Разбиение задачи** на части (анализировать функцию отдельно).

```python
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
```

## Инструменты и альтернативы

| Инструмент | Особенность |
|---|---|
| angr | Python, самый популярный |
| manticore (Trail of Bits) | Python, EVM/native |
| Triton | C++/Python, символьный + taint |
| KLEE | LLVM IR (нужны исходники) |
| Z3 (SMT) | решатель под капотом |
| S2E | QEMU-based |

## Частые ошибки и подводные камни

- **Забыть `auto_load_libs=False`** — анализ уходит в std/libc и висит.
- **Не хукать libc** — angr исполняет `strlen`/`strcmp` по коду и замедляется/ломается.
- **Взрыв путей на циклах** — ограничивайте вход и используйте veritesting.
- **Неверный `find`** — ищите по выводу/строкам, а не только по адресу.
- **Нет ограничений на формат** — решатель вернёт «мусорный» вход; добавьте алфавит/префикс.
- **Символические указатели** — сложные структуры требуют `SimProcedure`/конкретизации.

## Что дальше / решение

Маршрут: **найти `find`/`avoid` → entry_state с символьным вводом → ограничения → explore → проверить вход**. angr незаменим для crackme и обхода проверок; для сложных таргетов комбинируйте с хуками и вертитингом. Дальше — `reversing-symbolic-core`, `reversing-symbolic-tools`, `reversing-z3-advanced` и `reversing-concolic`.

## Продвинутые техники angr

- **Вертитинг** (`veritesting=True`) — слияние похожих путей, снижает взрыв.
- **Конкретизация** — подстановка конкретных значений для сложных указателей.
- **`SimFile`** — символьные файлы (для чтения из файла).
- **Символические указатели** — `state.memory.store`/`load` с символьными адресами (осторожно).
- **`explore` с несколькими find** — поиск любого из целевых состояний.

```python
simgr = proj.factory.simulation_manager(state, veritesting=True)
simgr.explore(find=find_addrs, avoid=avoid_addrs, num_find=1)
```

## Решение задачи с файловым вводом

Многие crackme читают файл. Символьный файл задаётся через `SimFile`.

```python
import angr
proj = angr.Project("./crackme", auto_load_libs=False)
# символьный stdin
state = proj.factory.entry_state(stdin=angr.SimFile)
# или файл по пути
state = proj.factory.entry_state()
state.fs.insert("/tmp/input", angr.SimFile("/tmp/input", size=32))
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=lambda s: b"OK" in s.posix.dumps(1))
print(simgr.found[0].posix.dumps(0))
```

## Работа с циклами и хешами

Циклы — главная причина взрыва. Если внутри цикла хеш/шифр, angr будет медленным. Решения: хукать хеш-функцию (заменить на `SimProcedure`, вычисляющий конкретно), либо разбить задачу — сначала найти вход через `explore`, потом отдельно проверить.

```python
# хукнуть хеш-функцию и вернуть конкретное значение
class MD5Hook(angr.SimProcedure):
    def run(self, data, out):
        # конкретизировать data и вычислить реальный md5
        self.state.memory.store(out, self.state.solver.BVV(0xdeadbeef, 32))
proj.hook(0x401500, MD5Hook())
```

## angr для обхода анти-отладки/проверок

Символьное исполнение может «перепрыгнуть» проверки: задайте цель **после** анти-отладочной ветки, и angr найдёт путь (или докажет недостижимость).

```python
simgr.explore(find=0x402000)   # цель за всеми проверками
if simgr.found:
    print("достижимо, вход:", simgr.found[0].posix.dumps(0))
```

Это дополняет ручной обход: angr подскажет, какие ограничения нужно удовлетворить.

## Отладка angr-скриптов

- **Слишком медленно** — уменьшите вход, включите veritesting, хукайте libc.
- **Нет found** — неверный `find`; проверьте адреса/строки, добавьте `avoid`.
- **Ошибка загрузки** — неверный loader/архитектура; укажите вручную.
- **Unconstrained** — символические указатели; добавьте ограничения/конкретизацию.

```python
# визуализировать пути
for s in simgr.active[:5]:
    print(s.addr, s.history.bbl_addrs.hardcopy[-1:])
```

## Практический чеклист angr

1. `Project(..., auto_load_libs=False)`.
2. Найти `find`/`avoid` (по адресам или строкам вывода).
3. `entry_state` с символьным вводом (stdin/argv/файл).
4. Добавить ограничения формата (алфавит, длина, префикс).
5. Хукнуть libc/хеши, включить veritesting.
6. `explore` → извлечь вход → **проверить на реальном бинарнике**.

## Управление памятью и контекстом в angr

Для реалистичных бинарников важно правильно настроить память и окружение.

- **Аргументы окружения** — `entry_state(env={...})`, если программа зависит от переменных.
- **Рабочий каталог и файлы** — через `state.fs`.
- **Стек/куча** — angr создаёт их автоматически; для сложных структур — конкретизируйте.
- **`state.regs`** — символьные регистры (например, при входе в функцию через `call_state`).

```python
# войти сразу в функцию с символьным аргументом
arg = claripy.BVS("arg", 8*16)
state = proj.factory.call_state(0x401200, arg)
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401260)
print(simgr.found[0].solver.eval(arg, cast_to=bytes))
```

`call_state` экономит время: не нужно исполнять пролог программы до функции проверки.

## Оптимизация и практические советы

- **`auto_load_libs=False`** — обязательно.
- **Хуки** для libc/хешей/крипты.
- **Ограничения входа** — сужают пространство поиска.
- **`veritesting=True`** — против взрыва путей.
- **`num_find=1`** — остановиться на первом решении.
- **Разбиение** — анализируйте функцию проверки отдельно от main.

```python
proj = angr.Project("./bin", auto_load_libs=False)
proj.hook_symbol("strlen", angr.SIM_PROCEDURES["libc"]["strlen"]())
```

## Символьное исполнение как часть конвейера

angr хорошо сочетается с другими инструментами: Ghidra/IDA дают адреса и типы, angr решает ограничения, Z3 проверяет. Для генерации входов в фаззер angr создаёт «интересные» значения, покрывающие новые ветки (concolic). Дальше — `reversing-concolic` и `reversing-symbolic-core`.

## Практический разбор: несколько примеров задач

**Пример 1: пароль фиксированной длины.** `strcmp(input, secret)` — angr найдёт `input`, пройдя `strcmp` (хук libc). Ограничение: длина = N.

**Пример 2: посимвольная проверка.** Цикл `for i: if (input[i] != f(i)) fail` — angr разрешит каждое условие и соберёт строку.

**Пример 3: проверка через хеш.** `md5(input) == const` — angr будет медленным на MD5; хукните хеш, либо решайте перебором (если вход короткий).

**Пример 4: обфускация.** Opaque-предикаты и flattening усложняют angr; иногда проще нормализовать код (deobfuscation) до символьного исполнения.

Во всех случаях финальный шаг один: извлечь вход и **проверить на реальном бинарнике** — символьное исполнение даёт гипотезу, запуск подтверждает.

## Итоговый вывод

Символьное исполнение — самый мощный автоматический метод для crackme и обхода проверок, но требует настройки: `auto_load_libs=False`, хуки libc, ограничения входа, вертитинг. Начинайте с простых задач (фиксированная строка), затем переходите к алгоритмическим проверкам и обфускации. Всегда подтверждайте найденный вход запуском бинарника — это единственное доказательство корректности.

## Квиз

```quiz
- question: "Что такое символьное исполнение?"
  options:
    - "Запуск программы с конкретными значениями"
    - "Исполнение с символическими (неконкретными) значениями и накопление ограничений"
    - "Дешифровка строк"
    - "Упаковка бинарника"
  answer: 1
  explanation: "Вход представлен символами, ограничения решаются SMT-решателем."
- question: "Какой SMT-решатель обычно используется с angr?"
  options:
    - "GNU Solver"
    - "z3"
    - "SAT4J"
    - "MiniSat"
  answer: 1
  explanation: "angr использует z3 через claripy."
- question: "Зачем параметр `avoid` в `explore`?"
  options:
    - "Ускорить загрузку"
    - "Не исследовать нежелательные пути (например, с выводом "Wrong")"
    - "Упаковать бинарник"
    - "Задать длину ввода"
  answer: 1
  explanation: "`avoid` отсекает ненужные ветки, уменьшая взрыв."
- question: "Какая задача плохо подходит для angr?"
  options:
    - "Линейная цепочка сравнений"
    - "Обратная задача XOR"
    - "Решение SHA-256 (поиск прообраза)"
    - "Поиск ввода к `puts("Correct")`"
  answer: 2
  explanation: "Криптохэши непрактичны для символьного решения."
- question: "Что делать, если angr не находит решение?"
  options:
    - "Сдаться"
    - "Добавить `avoid`, ограничить длину/алфавит, хукать тяжёлые функции"
    - "Увеличить таймаут до суток"
    - "Переупаковать бинарник"
  answer: 1
  explanation: "Уточнение ограничений и hooks — правильный путь."
```

## Где пригодится

- **CTF Reversing (expert):** обход длинных цепочек проверок, VM, обфускации.
- **Автоматический поиск входов:** когда ручной реверс дорог, angr экономит часы.
- **Malware analysis:** поиск ввода, активирующего определённое поведение.
- **Vuln research:** генерация ввода, достигающего опасного участка кода.
- **Собес:** вопросы про символьное исполнение, z3, state explosion — маркер продвинутого RE.
