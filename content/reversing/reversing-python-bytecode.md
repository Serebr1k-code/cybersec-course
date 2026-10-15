---
id: reversing-python-bytecode
title: "Реверс Python-байткода"
category: reversing
parent: reversing-decompiler-tools
difficulty: medium
order: 1
tags: [reversing, python, bytecode, pyc, marshal, dis]
prerequisites: [reversing-decompiler]
useful_for:
  - "CTF Reversing / Misc"
  - "Анализ Python malware"
  - "Разбор упакованных/скомпилированных скриптов"
estimated_minutes: 45
summary: "Декомпиляция .pyc, анализ marshal-структур, работа с PyInstaller и обфусцированным Python."
lab:
  kind: shell
  title: 'Практика: байткод Python вместо исходника'
  toolset: [core, hex, strings]
  workdir: /home/student/task
  files: [task.md, check.pyc]
  check: 'grep -q ''nto{pyc}'' answer.txt'
  hints:
    - '110=0x6e n, 116=0x74 t, 111=0x6f o, 123=0x7b { ...'
    - 'Собери строку по кодам из константы.'
    - '`echo ''nto{pyc}'' > answer.txt` затем `check`.'
---
## Вопрос, с которого всё начинается

Тебе дали файл `challenge.pyc`. Запускаешь — он просит ключ и отвечает `OK` или `WRONG`.
Исходного `.py` нет. Как понять, что именно он проверяет, и восстановить правильный ключ?

Python кажется «открытым» языком, но его тоже компилируют. Только не в машинный код, а в
**байткод** — компактное представление программы для виртуальной машины Python. И это отличная
новость для реверса: байткод гораздо ближе к исходнику, чем ассемблер, и часто его удаётся
вернуть почти дословно.

Опираемся на предыдущие уроки: ты уже знаешь, что бинарник — это данные плюс логика, и умеешь
смотреть на файлы через `file`/`strings`. Здесь мы применим тот же подход к Python-артефакту.

## Наш пример

Смотрим, что это вообще за файл:

```
$ file challenge.pyc
challenge.pyc: Byte-compiled Python module for CPython 3.14 (magic: 3627), timestamp-based,
.py timestamp: Mon Oct 12 06:57:43 2026 UTC, .py size: 279 bytes
```

Первое, что мы узнали: это **`.pyc`** — скомпилированный модуль для **CPython 3.14**. Версия
критична: байткод у каждой версии Python свой, и инструмент под 3.8 его не прочитает. `file`
даже подсказал «magic: 3627».

Заглянем в начало файла:

```
$ xxd challenge.pyc | head -2
00000000: 2b0e 0d0a 0000 0000 e784 cc6a 1701 0000  +..........j....
00000010: e300 0000 0000 0000 0000 0000 0006 0000  ................
```

Возникает естественный вопрос: где в этом файле собственно код? Первые 16 байт — это
**заголовок**: `2b0e0d0a` (magic number, метка версии), затем флаги, метка времени и размер
исходника. Код начинается только после заголовка.

## Шаг 1: что такое байткод и code object

Уберём заголовок и посмотрим, что лежит дальше:

```
$ python3 -c "import marshal; f=open('challenge.pyc','rb'); f.read(16); print(type(marshal.load(f)).__name__)"
code
```

После 16 байт лежит **code object** — объект Python, описывающий функцию или модуль. Он
хранится в формате **marshal** (встроенный сериализатор CPython). У code object есть поля:
`co_code` (сами инструкции), `co_consts` (константы), `co_names` (имена), `co_varnames`
(локальные переменные).

Сам `co_code` — это поток **опкодов**: команд стековой виртуальной машины. Операнды кладутся
на стек, операции их снимают, результат возвращается на стек. Проще всего читать его
дизассемблером `dis` из стандартной библиотеки:

```
$ python3 -c "
import marshal, dis
f = open('challenge.pyc','rb'); f.read(16)
dis.dis(marshal.load(f))
"
  0           RESUME                   0

  1           LOAD_NAME                0 (bytes)
              PUSH_NULL
              BUILD_LIST               0
              LOAD_CONST               6 ((50, 59, 54, 42, 114, 44, 99, 99))
              LIST_EXTEND              1
              CALL                     1
              STORE_NAME               1 (TARGET)

  3           LOAD_CONST               1 (<code object check at 0x7f62...>)
              MAKE_FUNCTION
              STORE_NAME               2 (check)
```

Читается почти как ассемблер. Разберём по строкам: `LOAD_CONST 6` кладёт на стек кортеж
чисел `(50, 59, 54, 42, 114, 44, 99, 99)`, `CALL` вызывает `bytes`, а `STORE_NAME 1 (TARGET)`
сохраняет результат в переменную `TARGET`. То есть в модуле есть байтовая строка-константа
`TARGET`. Ещё `STORE_NAME 2 (check)` говорит, что определена функция `check` — очевидно,
та самая проверка ключа.

## Шаг 2: читаем функцию проверки

`dis` печатает вложенные функции отдельно. Обойдём code object рекурсивно — так мы увидим и
`check`, и её вложенные генераторы:

```
$ python3 -c "
import marshal, dis, types
f = open('challenge.pyc','rb'); f.read(16)
code = marshal.load(f)
def walk(c, d=0):
    print('  '*d, c.co_name, '| consts:', [x for x in c.co_consts if not isinstance(x, types.CodeType)])
    for k in c.co_consts:
        if isinstance(k, types.CodeType): walk(k, d+1)
walk(code)
"
<module> | consts: [50, '__main__', None, 'OK', 'WRONG', (50, 59, 54, 42, 114, 44, 99, 99)]
   check | consts: [8, False, True]
     <genexpr> | consts: [66, None]
```

Теперь картина ясна. В `check` есть константа `8` (длина ключа) и `True`/`False`. А во
вложенном `<genexpr>` (генераторном выражении) — константа `66`. Это `0x42`. Дизассемблируем
его, чтобы увидеть саму операцию:

```
$ python3 -c "
import marshal, dis, types
f = open('challenge.pyc','rb'); f.read(16)
code = marshal.load(f)
for c in code.co_consts:
    if isinstance(c, types.CodeType):
        for g in c.co_consts:
            if isinstance(g, types.CodeType): dis.dis(g)
"
   6           RETURN_GENERATOR
       ...
       L2:     FOR_ITER                28 (to L3)
               UNPACK_SEQUENCE          2
               STORE_FAST_STORE_FAST   18 (c, t)
               LOAD_GLOBAL              1 (ord + NULL)
               LOAD_FAST_BORROW         1 (c)
               CALL                     1
               LOAD_SMALL_INT          66
               BINARY_OP               12 (^)
               LOAD_FAST_BORROW         2 (t)
               COMPARE_OP              72 (==)
               YIELD_VALUE              0
```

Читаем как ассемблер: взять символ `c`, вызвать `ord(c)`, загрузить `66`, выполнить `BINARY_OP ^`
(XOR), сравнить с `t` из `TARGET`. Складывая всё вместе, логика такая:

```python
TARGET = bytes([0x32, 0x3b, 0x36, 0x2a, 0x72, 0x2c, 0x63, 0x63])

def check(s):
    if len(s) != 8:
        return False
    return all((ord(c) ^ 0x42) == t for c, t in zip(s, TARGET))
```

## Шаг 3: восстанавливаем ключ

Мы знаем и `TARGET`, и операцию. XOR обратен сам себе, поэтому ключ — это `TARGET`, «ксоренный»
с `0x42`. Собираем **keygen** (генератор правильного входа) на чистом Python:

```
$ python3 -c "
T = bytes([0x32,0x3b,0x36,0x2a,0x72,0x2c,0x63,0x63])
print('recovered key:', repr(bytes(b ^ 0x42 for b in T).decode()))
"
recovered key: 'pyth0n!!'
```

Проверяем на настоящем бинарнике — это обязательный шаг, «на глаз» верить нельзя:

```
$ python3 challenge.py aaaaaaaa
WRONG
$ python3 challenge.py 'pyth0n!!'
OK
```

Ключ `pyth0n!!` подошёл. Мы восстановили логику полностью, не имея исходника.

## Если файл — не «чистый» .pyc

Наш пример простой, но на практике Python прячут. Три частых случая:

- **PyInstaller** (`.exe` с одним файлом). Внутри — архив с `.pyc`. Распаковывают
  `pyinstxtractor-ng`, затем декомпилируют извлечённые модули.
- **PyArmor / обфускаторы.** Байткод зашифрован, а расшифровка — в нативном рантайме. Приём:
  подменить `marshal.loads` и печатать расшифрованные code objects в момент загрузки, либо
  перехватить `exec`.
- **Nuitka / Cython.** Python компилируется в C и затем в нативный бинарник. Такой файл
  реверсится уже как обычный бинарник (Ghidra/IDA), но в нём остаются строки и структура
  функций Python.

Декомпиляторы (`uncompyle6` для 3.6–3.8, `pycdc` для новых версий) восстанавливают исходник
автоматически, но привязаны к версии. Когда они падают — работает ручной разбор через `dis`,
как мы сделали выше.

## Что мы теперь знаем

- `.pyc` — это 16-байтовый заголовок плюс **code object** в формате `marshal`.
- **Байткод** — инструкции стековой машины; `dis` печатает их человекочитаемо.
- `co_consts` вложенных функций хранят ключевые константы (в нашем случае — таблицу `TARGET`
  и XOR-маску `66`).
- Читая опкоды `LOAD_CONST`/`BINARY_OP`/`COMPARE_OP`, можно восстановить алгоритм проверки.
- XOR обратим — по таблице и маске восстанавливается вход (keygen).
- Итог всегда проверяем на реальном файле: `OK`, а не «кажется, верно».

## На что смотреть дальше

- Если файл — `.exe`, первым делом проверь, не PyInstaller ли это (`strings | grep -i pyinstaller`).
- Всегда сверяй magic-число с версией: чужой байткод не прочитается. Держи несколько Python
  через `pyenv`.
- Для больших модулей не разбирай всё вручную — начни с `co_consts`: там обычно и строки,
  и подозрительные числа.
- Если `dis` показывает «мусор» (например, неизвестные опкоды) — вероятно, байткод
  модифицирован обфускатором; тогда переходи к динамическому дампу.

## Разбор заголовка `.pyc` вручную: magic и версии

Заголовок `.pyc` — не просто «16 байт мусора», а метка, от которой зависит, прочитает ли файл ваш Python. Первые два байта — **magic number**, зашифрованная версия интерпретатора:

```bash
$ xxd -l 4 challenge.pyc
00000000: 2b0e 0d0a                      +...
```

`0x0e2b` — magic для CPython 3.14 (в файле он в little-endian, плюс `0d 0a` — «CRLF», чтобы файл не приняли за текст). Полный список магии лежит в `Lib/importlib/_bootstrap_external.py`. Быстрая проверка своей версии:

```python
import importlib.util
print(importlib.util.MAGIC_NUMBER.hex())   # 2b0e0d0a на 3.14
```

Дальше в заголовке (для timestamp-based `.pyc`) лежат 4 байта флагов, 4 байта mtime исходника и 4 байта его размера. Хэш-based `.pyc` вместо mtime хранит хэш. Практический вывод: **если magic не совпал — `marshal.load` упадёт или выдаст мусор**. Держите несколько интерпретаторов через `pyenv` или используйте `decompyle3`/`pycdc`, собранные под нужную версию.

## Динамический дамп: перехватываем `marshal.loads`

Когда байткод зашифрован (PyArmor, кастомный загрузчик), статически его не прочитать — но в момент запуска интерпретатор **сам** расшифровывает его, чтобы исполнить. Перехватим это. Создаём `sitecustomize.py`, который подменяет `marshal.loads`:

```python
import marshal, sys
_orig = marshal.loads
def hooked(data, *a, **kw):
    obj = _orig(data, *a, **kw)
    try:
        import dis, types
        if isinstance(obj, types.CodeType):
            sys.stderr.write("=== dumped code object ===\n")
            dis.dis(obj)
    except Exception:
        pass
    return obj
marshal.loads = hooked
```

Кладём файл рядом (или в `PYTHONPATH`) и запускаем целевой скрипт — расшифрованный байткод печатается в момент загрузки. Тот же приём работает с `exec`/`eval`: подмена `builtins.exec` показывает уже декодированный исходник.

## Ограничения и частые ошибки

| Симптом | Причина | Что делать |
|---------|---------|------------|
| `ValueError: bad marshal data` | magic/версия не совпала | взять интерпретатор нужной версии |
| `dis` печатает неизвестные опкоды | байткод модифицирован обфускатором | динамический дамп через hook |
| Декомпилятор «падает» | новая версия Python | ручной разбор через `dis` |
| Строки не находятся | строки зашифрованы в рантайме | перехватить сборку/дешифровку |
| PyInstaller-`.exe` не открывается | это архив, не чистый `.pyc` | `pyinstxtractor-ng` |

**Границы.** Реверс байткода силён, пока код — «честный» Python. Как только логику переносят в нативный модуль (Cython, Nuitka, C-extension), байткод показывает лишь обёртку — дальше нужен обычный бинарный реверс (Ghidra/IDA). И помните: динамический hook меняет поведение процесса, поэтому для malware запускайте его только в изолированной песочнице.

## Квиз

Проверь себя.

```quiz
- question: "Что лежит в файле .pyc после 16-байтового заголовка?"
  options:
    - "Исходный текст .py"
    - "Байткод CPython — code object в формате marshal"
    - "Машинный код x86-64"
    - "Только строки модуля"
  answer: 1
  explanation: "Заголовок (magic, флаги, время, размер) отделяет от marshal-сериализованного code object."
- question: "Какой встроенный инструмент дизассемблирует байткод?"
  options:
    - "`strings`"
    - "`readelf`"
    - "`dis`"
    - "`upx -d`"
  answer: 2
  explanation: "`dis.dis()` печатает инструкции стековой машины."
- question: "Операция XOR в нашей проверке использовала константу 66. Что это в шестнадцатеричном виде?"
  options:
    - "0x2A"
    - "0x42"
    - "0x66"
    - "0x08"
  answer: 1
  explanation: "66 = 0x42 — именно эта маска видна в опкоде LOAD_SMALL_INT."
- question: "Почему keygen для этой проверки возможен, а для лицензии на RSA-подписи — нет?"
  options:
    - "XOR обратим без секрета, а приватный ключ RSA у вендора"
    - "Потому что .pyc короче"
    - "Потому что RSA медленнее"
    - "Потому что Python интерпретируется"
  answer: 0
  explanation: "Обратная операция без секрета = keygen; асимметричная подпись требует приватного ключа."
- question: "Файл оказался .exe, собранным PyInstaller. Что делать?"
  options:
    - "Читать машинный код в Ghidra с нуля"
    - "Распаковать pyinstxtractor, восстановить .pyc и декомпилировать"
    - "Запустить `upx -d`"
    - "Использовать `nm`"
  answer: 1
  explanation: "PyInstaller-архив содержит .pyc, которые извлекает pyinstxtractor."
```

## Куда дальше

В следующем уроке мы возьмём уже скомпилированный нативный бинарник и посмотрим, как та же
идея — «прочитать логику проверки и обратить её» — работает в машинном коде (Ghidra/IDA).
А пока главное запомни: **байткод Python — это тоже ассемблер**, и `dis` плюс разбор
`co_consts` дают полный контроль над любой `.pyc`-программой.

## Где пригодится

- **CTF Reversing / Misc:** `.pyc`-задачи — частый и быстрый тип, решаются `dis`/декомпилятором.
- **Python malware analysis:** обфусцированные stealer/RAT на Python повсеместны.
- **Аудит:** разбор скомпилированных в exe внутренних инструментов.
- **Android/автоматизация:** PyInstaller-бинарники в enterprise-скриптах.
- **Собес:** вопросы про `.pyc`, marshal, PyInstaller — для RE/automation ролей.
