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
---
Python — один из самых «открытых» языков для реверса, но и один из самых коварных: байткод
компилируется в `.pyc`, программы упаковываются в `.exe` (PyInstaller), а коммерческие обфускаторы
(PyArmor, pyobfuscate) превращают читаемый код в кашу. Понимание внутренностей CPython — от `marshal`
до инструкций стековой машины — открывает путь к анализу любого Python-приложения: от CTF-задач
до вредоносов на Python.

## Что такое байткод CPython

Когда Python импортирует модуль, он компилирует `.py` в байткод и кэширует его в `__pycache__/*.pyc`.
Байткод — это поток **инструкций стековой виртуальной машины**: операнды кладутся на стек, операции
их снимают, результат возвращается на стек.

Структура `.pyc` (Python 3.x):
```text
magic number (4 байта, версия Python)
bit field (4 байта, PEP 552 flags)
timestamp/hash (4 или 8 байт)
code object (marshal-сериализованный)
```

Проверить версию и посмотреть байткод:
```bash
python3 -m dis module.py            # дизассемблировать .py
python3 -c "import dis, marshal, importlib.util; \
  f=open('module.pyc','rb'); f.read(16); \
  code=marshal.load(f); dis.dis(code)"
```

## Инструкции: карта байткода

Основные опкоды (Python 3.11+):

| Опкод | Действие |
|---|---|
| `LOAD_CONST` | положить константу |
| `LOAD_FAST` | локальная переменная |
| `LOAD_GLOBAL` | глобальная/встроенная |
| `STORE_FAST` | записать в локальную |
| `BINARY_OP` | арифметика/логика |
| `COMPARE_OP` | сравнение |
| `POP_JUMP_IF_FALSE` | условный переход |
| `CALL` / `PRECALL` | вызов функции |
| `RETURN_VALUE` | возврат |
| `BUILD_STRING` / `BUILD_LIST` | собрать контейнер |

Пример:
```python
def check(p):
    return p == "secret"
```
```text
  LOAD_FAST       0 (p)
  LOAD_CONST      1 ('secret')
  COMPARE_OP      2 (==)
  RETURN_VALUE
```

Понимая стек, вы «читаете» байткод почти как ассемблер.

## Инструменты декомпиляции Python

| Инструмент | Python | Назначение |
|---|---|---|
| `uncompyle6` | 2.7–3.8 | декомпилятор байткода |
| `decompyle3` | 3.7–3.8 | наследник uncompyle6 |
| `pycdc` (Decompyle++) | 3.x (C++) | декомпилятор, живёт дольше |
| `pycdas` | 3.x | дизассемблер (часть pycdc) |
| `dis` (stdlib) | все | дизассемблер |
| `xdis` | все | библиотека для кросс-версий |
| `pyinstxtractor` | — | распаковка PyInstaller |

```bash
uncompyle6 module.pyc > module.py
decompyle3 module.pyc
pycdc module.pyc
pycdas module.pyc        # дизассемблер
```

Важно: **декомпиляторы привязаны к версии**. Байткод 3.11/3.12 часто не декомпилируется — тогда
работаем через `dis`/`pycdas` вручную.

## Разобранный пример: распаковка PyInstaller

Дано: `app.exe`, собранный PyInstaller. Внутри — `PYZ`-архив с `.pyc`.

**Шаг 1. Определить.**
```bash
strings -a app.exe | grep -i pyinstaller
```
Или `die app.exe` → `Python / PyInstaller`.

**Шаг 2. Извлечь.**
```bash
python3 pyinstxtractor.py app.exe
# создаст app.exe_extracted/
ls app.exe_extracted | head
```
Внутри: `PYZ-00.pyz_extracted/` (модули), `app` (главный модуль без расширения), `base_library.zip`.

**Шаг 3. Восстановить `.pyc`.** Главный модуль часто без magic-заголовка. Добавляем:
```bash
python3 - <<'PY'
import struct, sys
magic = importlib.util.MAGIC_NUMBER  # текущей версии
data = open("app.exe_extracted/app","rb").read()
open("app.pyc","wb").write(magic + b"\x00"*12 + data)
PY
```

**Шаг 4. Декомпилировать.**
```bash
pycdc app.pyc > app.py
# или для нужной версии Python:
uncompyle6 app.pyc
```

**Шаг 5. Разобрать.** Теперь видим исходный Python-код: логику, ключи, проверки.

## Разобранный пример: обфускация PyArmor

PyArmor шифрует байткод и добавляет нативный рантайм-декриптор. Приёмы анализа:

- **Дамп байткода в рантайме.** Ставим breakpoint на `marshal.loads` или на функцию декриптора,
  снимаем расшифрованный code object:
  ```python
  import marshal, sys
  _orig = marshal.loads
  def hook(data):
      code = _orig(data)
      print("decrypted:", code.co_name)
      return code
  marshal.loads = hook
  ```
  Или через `sys.settrace`/`sys.setprofile` для перехвата выполнения.
- **`pyarmor-unpacker`** / скрипты сообщества — автоматически снимают старые версии PyArmor.
- **Модификация байткода.** PyArmor хранит зашифрованные code objects; после декрипта можно
  дизассемблировать через `dis`.
- **Anti-debug.** PyArmor проверяет отладчик/`sys.settrace` — обходится патчем проверок.

## Крайние случаи и подводные камни

- **Несовпадение версий.** `.pyc` от 3.12 не декомпилируется инструментами для 3.8. Определяйте
  версию по magic (`xdis`/`importlib`), ставьте нужный Python.
- **Скомпилированный `__pycache__`** может быть единственным артефактом (`.py` удалён) — работаем
  с ним напрямую.
- **Nuitka.** Компилирует Python в C, на выходе — нативный бинарник. Реверсится как C (Ghidra/IDA),
  но сохраняет строки и структуру функций Python.
- **Cython.** Генерирует C, потом нативный код; ищите строки и сигнатуры CPython API.
- **Frozen modules.** В PyInstaller часть модулей «заморожена» в C (`base_library.zip`).
- **Обфускация имён.** pyobfuscate переименовывает переменные в `_0x1234` — не влияет на логику,
  восстанавливайте по потоку данных.
- **Python 3.11+ `adaptive`/`specializing`.** Новые оптимизации меняют опкоды (`CACHE`-записи);
  декомпиляторы отстают — используйте `dis` с `show_caches=False`.
- **Многопоточный код.** `threading` в байткоде не виден как вызовы — анализируйте по целям.

## Что дальше / решение

1. Определить, что перед вами: `.pyc`, PyInstaller, PyArmor, Nuitka.
2. Для `.pyc` — определить версию и декомпилировать (`uncompyle6`/`pycdc`).
3. Для PyInstaller — `pyinstxtractor`, восстановить заголовки, декомпилировать.
4. Если не выходит — `dis`/`pycdas` вручную по опкодам.
5. Для PyArmor/Nuitka — динамический дамп (`marshal.loads` hook) или нативный реверс.
6. Воспроизвести логику на чистом Python.

Приём: **Python-байткод — это ассемблер**. Если декомпилятор не справляется, `dis` даёт точную
картину, а стековая модель читается интуитивно после пары примеров.

## Справочная таблица: артефакт → инструмент

| Артефакт | Инструмент |
|---|---|
| `.pyc` | `uncompyle6`, `decompyle3`, `pycdc` |
| `.py` | `dis` |
| PyInstaller `.exe` | `pyinstxtractor` |
| PyArmor | динамический дамп / unpacker |
| Nuitka | Ghidra/IDA |
| Cython | Ghidra/IDA + строки |
| Marshal-объект | `marshal.loads` |

## Внутренности code object и marshal

Байткод хранится как **code object** — структура, сериализованная модулем `marshal`. Её поля:

- `co_code` — сам байткод (последовательность опкодов и операндов).
- `co_consts` — кортеж констант (числа, строки, вложенные code objects).
- `co_names` — имена глобалов/атрибутов.
- `co_varnames` — имена локальных переменных.
- `co_filename`, `co_name`, `co_firstlineno` — метаданные.
- `co_flags`, `co_argcount`, `co_stacksize` — параметры функции.

Разбор вручную:
```python
import marshal, dis, types
code = marshal.loads(open("module.pyc","rb").read()[16:])
print(code.co_name, code.co_consts[:3], code.co_names)
dis.dis(code)
# рекурсивно обойти вложенные функции
def walk(c, depth=0):
    print("  "*depth, c.co_name)
    for const in c.co_consts:
        if isinstance(const, types.CodeType):
            walk(const, depth+1)
walk(code)
```

Именно `co_consts` часто содержит **зашифрованные строки** и вложенные функции — точка входа для
анализа. В обфусцированном коде `co_code` может быть модифицирован, а константы — вычисляться в рантайме.

## Разобранный пример: CTF-задача с неизвестной версией

Дано: `challenge.pyc`, декомпиляторы падают. Действуем по шагам.

**Шаг 1. Определить версию Python по magic.**
```bash
python3 - <<'PY'
import struct
magic = open("challenge.pyc","rb").read(4)
print(magic.hex())
PY
```
Сверяем magic с таблицей версий (в `importlib._bootstrap_external`). Например, `0x0d0d0a` — 3.8.
Ставим нужный Python (`pyenv install 3.8.x`).

**Шаг 2. Дизассемблировать `dis`.**
```bash
python3.8 -c "import dis,marshal; \
  dis.dis(marshal.loads(open('challenge.pyc','rb').read()[16:]))"
```
Получаем листинг. Видим проверку: сравнение с константой после серии `BINARY_OP`.

**Шаг 3. Восстановить логику.** Читаем опкоды как ассемблер: `LOAD_CONST`, `BINARY_XOR`, `COMPARE_OP`.
Восстанавливаем формулу.

**Шаг 4. Решить.** Пишем обратную функцию на Python и находим вход.

Такой подход («dis + ручной разбор») работает, даже когда ни один декомпилятор не справляется.

## Инструменты: какую версию Python ставить

| Python | Декомпилятор | Заметка |
|---|---|---|
| 2.7 | uncompyle6 | старые CTF |
| 3.6–3.8 | uncompyle6 / decompyle3 | лучшая поддержка |
| 3.9 | decompyle3 (частично) | пробелы |
| 3.10–3.12 | pycdc (частично) | `dis` надёжнее |
| 3.13+ | `dis` вручную | декомпиляторы отстают |

Практический совет: ставьте несколько Python через `pyenv` и переключайтесь под версию `.pyc`.
`xdis` позволяет читать байткод чужих версий без установки самого интерпретатора.

## PyArmor: подробнее о снятии

PyArmor — коммерческий обфускатор, шифрующий code objects и добавляющий нативную защиту. Слои:

1. **Encrypted code objects** — `co_code` зашифрован; расшифровывается нативным рантаймом.
2. **Native bootstrap** — C-расширение, которое расшифровывает и грузит модули.
3. **Anti-debug / anti-tamper** — проверки целостности, детект `sys.settrace`.

Снятие (для исследования):
```python
# hook marshal, чтобы поймать расшифрованные code objects
import marshal, types
_orig = marshal.loads
def patched(data):
    c = _orig(data)
    if isinstance(c, types.CodeType):
        open(f"/tmp/dump_{c.co_name}.pyc","wb").write(
            __import__("importlib").util.MAGIC_NUMBER + b"\x00"*12 + _orig.__module__ and marshal.dumps(c))
    return c
marshal.loads = patched
```
Затем декомпилируем дампы. Для новых версий — `pyarmor` сообщества или ручной разбор нативного
bootstrap.

## Отчёт и воспроизведение

При анализе Python-артефактов фиксируйте:

- Тип артефакта и версию Python (magic).
- Метод распаковки (pyinstxtractor / hook / ручной).
- Декомпилятор и его результат (полный/частичный).
- Ключевые константы/строки/алгоритмы.
- Итоговый воспроизведённый скрипт.

Эти данные позволяют быстро повторить анализ и объяснить вывод коллегам.

## Практические советы по окружению

- Держите под рукой несколько версий Python (`pyenv`) — байткод строго привязан к версии.
- `pip install uncompyle6 decompyle3 xdis pycdc` в отдельном venv.
- Для PyInstaller — `pyinstxtractor-ng` (поддерживает новые версии).
- Для анализа вредоносного Python-кода **не запускайте его на хосте** — используйте контейнер/VM,
  код может скачивать второй стадий, воровать данные и ставить persistence.
- Логируйте каждый шаг (версия, инструмент, вывод), чтобы результат был воспроизводим.

Python-реверс — это «декомпиляция по умолчанию, ручной разбор при обфускации». Освоив `dis` и
`marshal`, вы получаете полный контроль над любым Python-приложением.

## Квиз

```quiz
- question: "Какой инструмент декомпилирует .pyc в исходный Python?"
  options:
    - "`strings`"
    - "uncompyle6 / pycdc"
    - "`upx -d`"
    - "`readelf`"
  answer: 1
  explanation: "uncompyle6 (старые версии), pycdc (новые)."
- question: "Что содержит .pyc?"
  options:
    - "Исходный текст"
    - "Байткод CPython + метаданные (marshal code object)"
    - "Машинный код"
    - "Только строки"
  answer: 1
  explanation: "`.pyc` = magic + marshal-сериализованный code object."
- question: "Какая инструкция байткода кладёт константу на стек?"
  options:
    - "`STORE_NAME`"
    - "`LOAD_CONST`"
    - "`CALL_FUNCTION`"
    - "`POP_TOP`"
  answer: 1
  explanation: "`LOAD_CONST` помещает константу на стек."
- question: "Что делать с exe, собранным PyInstaller?"
  options:
    - "Открыть в Ghidra и читать машинный код"
    - "Распаковать `pyinstxtractor.py`, затем декомпилировать .pyc"
    - "Запустить `upx -d`"
    - "Использовать `readelf`"
  answer: 1
  explanation: "PyInstaller-архив содержит .pyc, извлекаемые pyinstxtractor."
- question: "Как раскрыть обфусцированный код, вызываемый через `exec`?"
  options:
    - "Запустить `nm`"
    - "Подменить `exec` и напечатать его аргумент"
    - "Использовать `objdump`"
    - "Переупаковать UPX"
  answer: 1
  explanation: "Перехват `exec`/breakpoint в pdb покажет расшифрованный код."
```

## Где пригодится

- **CTF Reversing / Misc:** `.pyc`-задачи — частый и быстрый тип, решаются декомпилятором.
- **Python malware analysis:** обфусцированные stealer/RAT на Python повсеместны.
- **Аудит:** разбор скомпилированных в exe внутренних инструментов.
- **Android/автоматизация:** PyInstaller-бинарники в enterprise-скриптах.
- **Собес:** вопросы про .pyc, marshal, PyInstaller — для RE/automation ролей.
