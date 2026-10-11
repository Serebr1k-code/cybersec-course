---
id: reversing-angr-advanced
title: "angr advanced: CFG, veritesting и символьные указатели"
category: reversing
parent: reversing-symbolic-core
difficulty: expert
order: 1
tags: [reversing, angr, symbolic, cfg, veritesting, symbolic-pointers, klee]
prerequisites: [reversing-symbolic-execution]
useful_for:
  - "CTF Reversing"
  - "Automated analysis"
  - "Vulnerability research"
estimated_minutes: 65
summary: "Продвинутый angr: построение CFG, veritesting против path explosion, символьные указатели, exploration techniques."
---
Базовый angr (`explore(find, avoid)`) решает простые задачи, но реальные крэкми и валидаторы требуют продвинутых техник: построения **CFG**, борьбы с **path explosion** (veritesting), работы с **символьными указателями** и кастомных стратегий exploration. Без них angr либо «взрывается» по числу состояний, либо работает бесконечно. Этот урок — продвинутое использование angr на сложных валидаторах с табличными преобразованиями.

## CFG и статический анализ

```python
import angr
proj = angr.Project('./binary', auto_load_libs=False)
cfg = proj.analyses.CFGFast()          # быстрый CFG (эвристический)
cfg_emu = proj.analyses.CFGEmulated()  # точнее, медленнее

# Обход функций
for func in cfg.kb.functions.values():
    print(hex(func.addr), func.name)
# Граф вызовов
cfg.kb.functions.callgraph
# Перекрёстные ссылки (XRefs)
proj.analyses.XRefs()
```

CFG полезен, чтобы найти все пути к цели, отсечь dead code и выделить точки интереса (например, функцию `check`). `CFGFast` строит граф эвристически (быстро), `CFGEmulated` — через символьное исполнение (точно, но дорого). Начните с Fast, уточняйте Emulated при необходимости.

## Path explosion и veritesting

Каждое ветвление удваивает число путей → экспоненциальный рост состояний. **Veritesting** (от «verification» + «testing») склеивает ветвления обратно в символьные условия, резко сокращая число состояний:

```python
proj = angr.Project('./binary')
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state, veritesting=True)
simgr.explore(find=find_addr, avoid=avoid_addr)
```

Дополнительные приёмы против взрыва:

- `LAZY_SOLVES` — не решать ограничения, пока не нужно.
- Ограничение длины ввода и алфавита.
- `avoid` для отсечения ненужных ветвей.
- `num_find=1` — остановиться на первом решении.

## Exploration techniques

```python
from angr.exploration_techniques import DFS, LoopSeer, LengthLimiter, MemoryLimiter

simgr.use_technique(LoopSeer(bound=5))       # ограничить циклы
simgr.use_technique(LengthLimiter(100))      # ограничить длину пути
simgr.use_technique(MemoryLimiter())         # ограничить память
simgr.use_technique(DFS())                   # стратегия обхода (depth-first)
```

- **LoopSeer** — не даёт анализу зациклиться (заменяет бесконечные циклы символическими).
- **LengthLimiter** — режет слишком длинные пути.
- **MemoryLimiter** — останавливает при исчерпании памяти.
- **DFS/BFS** — стратегия обхода состояний.
- **Threading** — `simgr.explore(..., num_workers=4)` для параллелизма.

## Символьные указатели

Когда адрес зависит от ввода (`table[input[i]]`, jump-таблица, S-box), angr должен обрабатывать **символьные указатели**:

```python
state.options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
state.options.add(angr.options.SYMBOLIC_READ_ADDRESSES)
```

Это дорого, но позволяет анализировать табличные преобразования. Обязательно **ограничивайте диапазон** указателей (через `state.solver.add`), иначе решатель «взорвётся»: он будет рассматривать все возможные адреса.

## Разобранный пример: крэкми с таблицей и veritesting

```python
import angr, claripy
proj = angr.Project('./crackme', auto_load_libs=False)
proj.hook_symbol('strcmp', angr.SIM_PROCEDURES['libc']['strcmp']())

N = 32
chars = [claripy.BVS(f'c{i}', 8) for i in range(N)]
flag = claripy.Concat(*chars + [claripy.BVV(b'\n')])

st = proj.factory.full_init_state(stdin=angr.SimFile)
st.posix.stdin.content = [flag]
st.options.add(angr.options.SYMBOLIC_READ_ADDRESSES)
for c in chars:
    st.solver.add(c >= 0x20, c <= 0x7e)

sm = proj.factory.simulation_manager(st, veritesting=True)
sm.use_technique(angr.exploration_techniques.LoopSeer(bound=3))
sm.explore(find=lambda s: b'Correct' in s.posix.dumps(1),
           avoid=lambda s: b'Wrong' in s.posix.dumps(1), num_find=1)
if sm.found:
    print(sm.found[0].posix.dumps(0))
```

Разбор по шагам: `hook_symbol` заменяет `strcmp` быстрой моделью; символьные байты ограничены печатным диапазоном; `SYMBOLIC_READ_ADDRESSES` включает обработку табличных чтений; `veritesting`+`LoopSeer` удерживают число состояний; `explore` ищет путь, печатающий «Correct».

## Утечки и состояние

```python
s = sm.found[0]
s.solver.eval(s.regs.rax)                    # значение регистра
s.solver.eval(s.memory.load(addr, 8), endness='Iend_LE')
s.posix.dumps(0)                             # stdin
s.posix.dumps(1)                             # stdout
s.solver.constraints                         # ограничения (для отладки)
s.solver.eval(c, cast_to=bytes)              # конкретное значение символа
```

Часто удобно извлечь значение по одному символу и собрать строку, если решение неоднозначно.

## Практический рецепт: валидатор с циклом и хешами

Типичный крэкми проверяет ввод побайтово в цикле, иногда с хешем или свёрткой. Стратегия:

```python
import angr, claripy

proj = angr.Project('./crackme', auto_load_libs=False)
# Хукаем тяжёлые/неизвестные функции
proj.hook_symbol('memcmp', angr.SIM_PROCEDURES['libc']['memcmp']())
proj.hook_symbol('strlen', angr.SIM_PROCEDURES['libc']['strlen']())

N = 24
chars = [claripy.BVS(f'c{i}', 8) for i in range(N)]
flag = claripy.Concat(*chars + [claripy.BVV(b'\x00')])

st = proj.factory.full_init_state(stdin=angr.SimFile, add_options={
    angr.options.LAZY_SOLVES,
    angr.options.SYMBOLIC_READ_ADDRESSES,
})
st.posix.stdin.content = [flag]
for c in chars:
    st.solver.add(c >= 0x20, c < 0x7f)         # печатные ASCII

sm = proj.factory.simulation_manager(st, veritesting=True)
sm.use_technique(angr.exploration_techniques.LoopSeer(bound=4))
sm.use_technique(angr.exploration_techniques.LengthLimiter(2000))
sm.explore(find=lambda s: b'correct' in s.posix.dumps(1).lower(),
           avoid=lambda s: b'wrong' in s.posix.dumps(1).lower(),
           num_find=1)

if sm.found:
    print(repr(sm.found[0].posix.dumps(0)))
else:
    print('not found; deadended=%d' % len(sm.deadended))
```

Ключевые настройки: `LAZY_SOLVES` (решать по требованию), `LoopSeer` (циклы), `LengthLimiter` (длинные пути), ограничение алфавита (печатные символы), хуки на `memcmp`/`strlen`. Если `found` пусто — проверьте адрес/строку `find` и не слишком ли узкий алфавит.

## Сравнение инструментов символьного исполнения

| Инструмент | Модель | Плюсы | Минусы |
|------------|--------|-------|--------|
| angr | IR (VEX) + символы | мощный, Python, CFG | медленный, требует настройки |
| KLEE | LLVM IR | быстрый, зрелый | нужен LLVM-байткод (исходники) |
| Manticore | EVM/native | скриптовый, простой | меньше сообщества |
| Triton | x86/ARM | точные символьные выражения | ниже уровень, ручная работа |
| Z3 (напрямую) | SMT | максимальный контроль | нужно самому моделировать код |

Выбор: angr — для бинарей без исходников; KLEE — если есть LLVM-байткод; Z3 напрямую — когда вы уже восстановили алгоритм и нужна только модель. Часто angr используют для поиска пути, а Z3 — для финального решения ограничений.

## Производительность и обход «взрыва»

- **Ограничивайте пространство**: длина ввода, алфавит, диапазон символьных адресов.
- **Хукайте тяжёлое**: `strcmp`, `memcmp`, `strlen`, крипто-функции заменяйте моделями.
- **`veritesting`** против ветвлений; **`LoopSeer`** против циклов; **`LengthLimiter`** против длинных путей.
- **Разбивайте задачу**: если валидатор проверяет по частям, решайте пофрагментно (byte-by-byte) — часто быстрее, чем один большой explore.
- **Параллелизм**: `num_workers` в `explore`.
- **Профилируйте**: `sm.deadended`, число активных состояний, время на шаг.

## Ограничения angr и когда он не подходит

angr — мощный, но не универсальный инструмент. Понимайте границы:

- **Криптография.** Если валидатор использует AES/SHA, символьное исполнение упирается в «крипто-барьер» — модель не решается. Обходите: хук на крипто-функцию, либо реверс алгоритма вручную и решение в z3.
- **Анти-символика.** Некоторые задачи специально «ломают» angr (огромные таблицы, хеши, нелинейность).
- **Библиотеки.** Без хуков символическая libc резко замедляет анализ; с `auto_load_libs=True` — ещё медленнее.
- **Неявные зависимости от среды.** Если код зависит от времени/случайности, моделируйте (подменяйте источник).
- **Большие программы.** angr плохо масштабируется на мегабайтные бинари; анализируйте целевую функцию, а не всё.

Альтернативы: KLEE (если есть LLVM-байткод), ручной реверс + z3 (когда алгоритм понятен), Triton (для точного контроля). Часто angr используют, чтобы найти путь, а затем решают ограничения напрямую в z3.

## Отладка angr

- **`sm.deadended` пусто и `found` пусто** → цель недостижима: проверьте адрес `find` и ограничения (возможно, неверный `find` или слишком узкий алфавит).
- **Медленно** → добавьте хуки на `str*`/`mem*`, ограничьте N/алфавит, включите `veritesting`.
- **Path explosion** → `LoopSeer`, `LengthLimiter`, `avoid`, ограничение символьных указателей.
- **Символические указатели** → обязательно ограничьте диапазон, иначе решатель «висит».
- **`auto_load_libs=True`** → символическая libc сильно замедляет; ставьте `False` и хукайте нужное.

## Частые ошибки

- **Veritesting ломается на сложной памяти.** Пробуйте с/без; для таблиц — с ограничением адресов.
- **Символьные указатели без границ.** Ограничивайте диапазон адресов — иначе взрыв.
- **Нет LoopSeer.** Бесконечные циклы съедают ресурсы.
- **Хуки забыты.** `strcmp`/`memcmp`/`strlen` без хуков резко замедляют анализ.
- **Слишком длинный ввод.** Ограничивайте N и алфавит (печатные символы).
- **`auto_load_libs=True`.** Лишняя символическая libc — медленно и не нужно.
- **Неверный `find`/`avoid`.** Цель может быть недостижима из-за опечатки в адресе.

## Что делать дальше / решение

1. Постройте CFG (`CFGFast`), найдите функцию проверки и точки интереса.
2. Хукайте библиотечные функции (`strcmp`/`memcmp`/`strlen`) для скорости.
3. Включите `veritesting` и `LoopSeer` против path explosion.
4. Для табличных преобразований — `SYMBOLIC_READ_ADDRESSES` + ограничение диапазона.
5. Запустите `explore` с `find`/`avoid`, извлеките решение (`posix.dumps(0)`).
6. Отлаживайте по пустым `found`/`deadended` и по времени работы.

## Квиз

```quiz
- question: "Что такое veritesting в angr?"
  options:
    - "Техника против path explosion, склеивающая ветвления"
    - "Хук на strcmp"
    - "Загрузка libc"
    - "Формат CFG"
  answer: 0
  explanation: "Veritesting сокращает число состояний, объединяя ветвления."
- question: "Что делает LoopSeer?"
  options:
    - "Ограничивает зацикливание при exploration"
    - "Хукает функции"
    - "Строит CFG"
    - "Решает ограничения"
  answer: 0
  explanation: "LoopSeer не даёт анализу застрять в циклах."
- question: "Как включить обработку символьных указателей?"
  options:
    - "SYMBOLIC_READ_ADDRESSES/SYMBOLIC_WRITE_ADDRESSES"
    - "auto_load_libs"
    - "veritesting"
    - "LoopSeer"
  answer: 0
  explanation: "Опции включают символьные адреса чтения/записи."
- question: "Как построить CFG в angr?"
  options:
    - "proj.analyses.CFGFast()"
    - "proj.factory.entry_state()"
    - "simgr.explore()"
    - "state.solver.eval()"
  answer: 0
  explanation: "CFGFast/CFGEmulated строят граф потока управления."
- question: "Почему нужно ограничивать символьные указатели?"
  options:
    - "Иначе решатель взрывается по числу адресов"
    - "Иначе не работает veritesting"
    - "Иначе не строятся хуки"
    - "Иначе отключится ASLR"
  answer: 0
  explanation: "Неограниченные символьные адреса ведут к path explosion."
```

## Где пригодится

- **CTF:** Reversing — сложные валидаторы.
- **Automated analysis:** поиск путей.
- **Vulnerability research:** символьный анализ.
- **Работа:** program analysis.
