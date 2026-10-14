#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch 2d — tools & CTF methodology stego lessons + tools hub."""
import base64, gzip, io
from _gen_stego_lib import emit, lab_json, write

# ---------------------------------------------------------------------------
# cyberchef: base64(xor(flag, 0x42))
# ---------------------------------------------------------------------------
cc_flag = "nto{cyberchef_recipe_xor}"
cc_blob = base64.b64encode(bytes(b ^ 0x42 for b in cc_flag.encode()))

# ---------------------------------------------------------------------------
# binwalk: junk + gzip(flag)
# ---------------------------------------------------------------------------
bw_flag = "nto{binwalk_signature_offset}"
bw_gz = gzip.compress(bw_flag.encode())
bw_bytes = b"\x00" * 24 + b"JUNKJUNK" + bw_gz

# ---------------------------------------------------------------------------
# decision tree: base64(gzip(flag))
# ---------------------------------------------------------------------------
dt_flag = "nto{decision_tree_chain}"
dt_blob = base64.b64encode(gzip.compress(dt_flag.encode()))

# ---------------------------------------------------------------------------
# multi-layer: base64(gzip(base64(flag)))
# ---------------------------------------------------------------------------
ml_flag = "nto{multi_layer_nested}"
ml_blob = base64.b64encode(gzip.compress(base64.b64encode(ml_flag.encode())))

# ===========================================================================
# stego-tool-cyberchef
# ===========================================================================
cc_body = r"""
## Вопрос, с которого всё начинается
Ты получил файл `blob.txt`: длинная строка из букв, цифр и `=`. Похоже на base64,
но декодирование даёт мусор. Значит, поверх кодирования есть второй слой —
например, XOR. Вручную перебирать комбинации долго; CyberChef делает это
автоматически через операцию **Magic**.

## Наш пример
Возьмём `blob.txt`. Прогоним его через CyberChef-подобную цепочку: base64 →
XOR → текст, и получим метку.

## Шаг 1: что такое CyberChef
CyberChef — браузерный «швейцарский нож» для данных. Ты собираешь **рецепт** из
операций: `From Base64`, `XOR`, `Gunzip`, `Extract LSB`, `Detect File Type`,
`Strings` и сотен других. Каждая операция принимает вход и отдаёт выход; рецепт
применяется слева направо.

## Шаг 2: операция Magic
`Magic` перебирает десятки операций и их параметров, пытаясь превратить вход во
что-то осмысленное. Это быстрый способ «размотать» неизвестную цепочку. Magic
часто сам определяет base64 → gzip → текст.

## Шаг 3: ключевые операции для стего
- **From Base64 / To Base64** — кодирование.
- **XOR / XOR Brute Force** — перебор однобайтового ключа.
- **Gunzip / Zlib Inflate / Raw Inflate** — распаковка.
- **Extract LSB** — извлечение младших битов из изображения.
- **Detect File Type** — определение формата по магии.
- **Strings / Extract** — извлечение строк/подстрок по шаблону.
- **Rot13 / ROT47 / Atbash** — простые шифры.

## Шаг 4: ручной рецепт для нашего файла
Если Magic не сработал, строим цепочку вручную. Наш `blob.txt` — base64, после
декодирования — байты, XOR-нутые ключом `0x42`:

```python
import base64
raw = base64.b64decode(open('blob.txt','rb').read())
print(bytes(b ^ 0x42 for b in raw).decode())
```

Вывод:

```
nto{cyberchef_recipe_xor}
```

В CyberChef то же самое — рецепт `From Base64` → `XOR (0x42)`.

## Шаг 5: автоматизация и CLI
CyberChef — браузерный, но есть CLI-обёртки (`cyberchef-cli`, `node cyberchef`)
для пакетной обработки. Для CTF удобно держать набор готовых рецептов:
`base64→gunzip`, `xor-bruteforce→strings`, `extract-lsb→png`.

## Что мы теперь знаем
- CyberChef — конвейер операций над данными.
- Magic автоматически подбирает цепочку декодирования.
- Ключевые операции: base64, XOR, gunzip, Extract LSB, Detect File Type.
- Рецепт воспроизводим вручную на Python.

## Квиз

Проверь себя.

```quiz
- question: "Что такое рецепт в CyberChef?"
  options:
    - "Последовательность операций, применяемых к данным слева направо"
    - "Пароль"
    - "Тип файла"
    - "Ключ шифрования"
  answer: 0
  explanation: "Рецепт — конвейер операций."
- question: "Что делает операция Magic?"
  options:
    - "Перебирает операции и параметры, пытаясь декодировать вход"
    - "Удаляет файл"
    - "Шифрует данные"
    - "Рисует график"
  answer: 0
  explanation: "Magic — автоматический подбор цепочки."
- question: "Какая операция извлекает младшие биты изображения?"
  options:
    - "Extract LSB"
    - "From Base64"
    - "Gunzip"
    - "ROT13"
  answer: 0
  explanation: "Extract LSB достаёт битовые плоскости."
- question: "Чем полезна 'XOR Brute Force'?"
  options:
    - "Перебирает однобайтовый ключ XOR и показывает осмысленный результат"
    - "Сжимает данные"
    - "Кодирует в base64"
    - "Строит график"
  answer: 0
  explanation: "XOR Brute Force находит ключ по эвристике осмысленности."
```

## Куда дальше
CyberChef — про кодирования. Дальше — binwalk: поиск встроенных сигнатур и
распаковка «матрёшек». О нём — в следующем уроке.

## Где пригодится
- **CTF:** быстрый разбор неизвестных кодирований.
- **Форензика:** декодирование вложений.
- **Blue team:** анализ обфусцированных payload.
""".strip()

cc_parser = (
    "import base64\n"
    "raw = base64.b64decode(open('blob.txt','rb').read())\n"
    "print(bytes(b ^ 0x42 for b in raw).decode())\n"
)
cc_task = ("# Задача: base64 + XOR (рецепт CyberChef)\n\n"
           "`blob.txt` — base64 от XOR-нутых байт (ключ 0x42).\n\n"
           "1. `cat blob.txt`.\n"
           "2. `python3 chef.py` — декодирование.\n"
           "3. `python3 chef.py | grep nto > found.txt`.\n")
emit("stego-tool-cyberchef", """---
id: stego-tool-cyberchef
title: "CyberChef: рецепты, Magic и операции для стего"
category: stego
parent: stego-module-tools-ctf
difficulty: easy
order: 1
tags: [stego, cyberchef, magic, recipe, tooling, ctf]
prerequisites: [stego-tooling-advanced]
useful_for:
  - "CTF Stego: неизвестные кодирования"
  - "Форензика: декодирование вложений"
  - "Blue team: разбор обфускации"
estimated_minutes: 14
summary: "CyberChef как конвейер операций: рецепты, Magic, ключевые операции (From Base64, XOR, Gunzip, Extract LSB, Detect File Type) и воспроизведение рецепта на Python."
lab:
  kind: shell
  title: "Практика: base64 → XOR"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, blob.txt, chef.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Строка похожа на base64 (есть `=` в конце)."
    - "После base64 остаётся XOR с однобайтовым ключом."
    - "`python3 chef.py` декодирует и печатает метку."
    - "`python3 chef.py | grep nto > found.txt`."
---

""" + cc_body + "\n", lab_json(
    "stego-tool-cyberchef", cc_flag, cc_task,
    [("blob.txt", ("b64", cc_blob)), ("chef.py", ("text", cc_parser))],
    [{"match": "chef\\.py", "example": "python3 chef.py", "output": cc_flag + "\n"}]))

# ===========================================================================
# stego-tool-binwalk-deep
# ===========================================================================
bw_body = r"""
## Вопрос, с которого всё начинается
Ты получил файл без расширения. `file` говорит «data». Внутри что-то есть, но
что именно и где — непонятно. **binwalk** сканирует файл на сигнатуры (магии)
известных форматов и показывает, что и по какому смещению встроено. Это первый
инструмент, когда файл — «матрёшка».

## Наш пример
Возьмём `firmware.bin` — кусок данных, в который по смещению 32 встроен gzip.
Найдём его и распакуем.

## Шаг 1: сигнатурное сканирование
binwalk ищет в файле байтовые «магии»: `\x89PNG`, `\x1f\x8b` (gzip), `PK\x03\x04`
(zip), `\xff\xd8\xff` (JPEG), `7z\xbc\xaf` (7z) и тысячи других. Для каждой
находки печатает смещение и описание:

```
$ binwalk firmware.bin
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             (data)
32            0x20            gzip compressed data, ...
```

## Шаг 2: распаковка встроенного
```
$ binwalk -e firmware.bin
$ ls _firmware.bin.extracted/
20  ...
```

binwalk извлекает найденные объекты в каталог `_<файл>.extracted`. Для gzip —
распаковывает.

## Шаг 3: карта энтропии
`binwalk -E firmware.bin` строит график энтропии по блокам. Высокая энтропия
(~1.0) = сжатые/шифрованные данные; скачки — границы встроенных файлов. Это
помогает понять структуру даже без сигнатур.

## Шаг 4: точное извлечение
- `binwalk --dd='gzip:gz' file` — извлечь только gzip.
- `binwalk -M file` — рекурсивно распаковать (matryoshka).
- `binwalk -y 'png' file` — фильтр по типу.
- `dd if=file bs=1 skip=32 | gunzip` — вручную по найденному смещению.

## Шаг 5: извлечение вручную
```python
import gzip
d = open('firmware.bin','rb').read()
i = d.find(b'\x1f\x8b')
print(gzip.decompress(d[i:]).decode())
```

Вывод:

```
nto{binwalk_signature_offset}
```

## Шаг 6: ограничения
- Сигнатуры могут давать **ложные срабатывания** (магия встречается случайно).
- Сжатые/шифрованные вложения без магии binwalk не найдёт — нужна энтропия и
  ручной анализ.
- Рекурсивная распаковка может «зациклиться» на вложенных архивах — следи за
  глубиной.

## Что мы теперь знаем
- binwalk сканирует файл на сигнатуры известных форматов и показывает смещения.
- `-e` извлекает встроенное, `-E` строит карту энтропии.
- `-M` рекурсивно распаковывает «матрёшку».
- Ложные срабатывания и «безмагические» данные — главные ограничения.

## Квиз

Проверь себя.

```quiz
- question: "Что делает binwalk по умолчанию?"
  options:
    - "Сканирует файл на сигнатуры известных форматов и печатает смещения"
    - "Удаляет файл"
    - "Шифрует данные"
    - "Запускает программу"
  answer: 0
  explanation: "Сигнатурный скан — базовая функция binwalk."
- question: "Как извлечь встроенные файлы?"
  options:
    - "binwalk -e file"
    - "binwalk -h"
    - "binwalk -v"
    - "binwalk -q"
  answer: 0
  explanation: "-e извлекает найденное в каталог _<file>.extracted."
- question: "Что показывает 'binwalk -E'?"
  options:
    - "Карту энтропии по блокам"
    - "Пароли"
    - "Исходный код"
    - "Размер файла"
  answer: 0
  explanation: "Энтропия помогает увидеть границы сжатых/шифрованных данных."
- question: "Почему binwalk может ошибаться?"
  options:
    - "Магические байты могут встретиться случайно (ложные срабатывания)"
    - "Он всегда прав"
    - "Он не читает файл"
    - "Он работает только с текстом"
  answer: 0
  explanation: "Сигнатуры бывают ложными; нужна проверка."
```

## Куда дальше
binwalk находит вложенное. Дальше — decision tree: в каком порядке пробовать
инструменты, чтобы не пропустить очевидное.

## Где пригодится
- **CTF:** «матрёшки» и файлы без расширения.
- **Форензика:** разбор прошивок и дампов.
- **Blue team:** анализ составных payload.
""".strip()

bw_parser = (
    "import gzip\n"
    "d = open('firmware.bin','rb').read()\n"
    "i = d.find(b'\\x1f\\x8b')\n"
    "print(gzip.decompress(d[i:]).decode())\n"
)
bw_task = ("# Задача: встроенный gzip\n\n"
           "`firmware.bin` — данные, внутри которых по некоторому смещению встроен\n"
           "gzip-поток (магия 1f 8b).\n\n"
           "1. `xxd -l 64 firmware.bin`.\n"
           "2. `python3 bw.py` — поиск магии и распаковка.\n"
           "3. `python3 bw.py | grep nto > found.txt`.\n")
emit("stego-tool-binwalk-deep", """---
id: stego-tool-binwalk-deep
title: "binwalk глубоко: сигнатуры, энтропия, рекурсия"
category: stego
parent: stego-module-tools-ctf
difficulty: easy
order: 2
tags: [stego, binwalk, signature, entropy, extraction, tooling]
prerequisites: [stego-tool-cyberchef]
useful_for:
  - "CTF Stego: файлы без расширения и матрёшки"
  - "Форензика: разбор прошивок и дампов"
  - "Blue team: анализ составных payload"
estimated_minutes: 15
summary: "binwalk: сигнатурное сканирование, извлечение (-e), карта энтропии (-E), рекурсивная распаковка (-M), точные --dd/-y фильтры и ручное извлечение по смещению."
lab:
  kind: shell
  title: "Практика: встроенный gzip по смещению"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, firmware.bin, bw.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Магия gzip — байты 1f 8b."
    - "Найди смещение и распакуй хвост."
    - "`python3 bw.py` печатает метку."
    - "`python3 bw.py | grep nto > found.txt`."
---

""" + bw_body + "\n", lab_json(
    "stego-tool-binwalk-deep", bw_flag, bw_task,
    [("firmware.bin", ("b64", bw_bytes)), ("bw.py", ("text", bw_parser))],
    [{"match": "bw\\.py", "example": "python3 bw.py", "output": bw_flag + "\n"}]))

# ===========================================================================
# stego-ctf-decision-tree
# ===========================================================================
dt_body = r"""
## Вопрос, с которого всё начинается
На CTF дают файл. Времени мало, инструментов много: zsteg, steghide, binwalk,
exiftool, спектрограмма… С чего начать? Бессистемный перебор сжигает время.
Правильный ответ — **decision tree**: фиксированный порядок проверок от самого
дешёвого и вероятного к сложному. Этот урок — про такой порядок.

## Наш пример
Возьмём `mystery.dat` — файл без расширения. Пройдём по дереву решений и
«размотаем» его до метки.

## Шаг 1: уровень 0 — идентификация
```
$ file mystery.dat
mystery.dat: ASCII text, with very long lines
$ head -c 64 mystery.dat
SGVsbG8sIHRoaXMgaXMg...
```

`file` говорит «ASCII text» — значит, это текстовое кодирование (base64?).
Первый шаг всегда — `file`, `head`, `xxd -l 64`.

## Шаг 2: уровень 1 — кодирования
Пробуем стандартные: base64, base32, hex, ROT13, URL-encode. Онлайн-декодеры или
CyberChef Magic. Если после декодирования видна магия файла (`\x1f\x8b`, `PK`,
`\x89PNG`) — переходим к распаковке.

## Шаг 3: уровень 2 — распаковка/вложенность
```
$ base64 -d mystery.dat > step1
$ file step1
step1: gzip compressed data
$ gunzip -c step1 > step2
$ file step2
step2: ASCII text
```

«Матрёшка»: base64 → gzip → текст. Здесь помогает binwalk и ручной `file` после
каждого шага.

## Шаг 4: уровень 3 — инструменты по типу
- **Изображение:** `zsteg`, `steghide`, `stegsolve`, `exiftool`, `pngcheck`.
- **Аудио:** спектрограмма (`sox`/Audacity), `steghide`, LSB.
- **Архив:** `unzip -l`, `7z l`, пароль-брутфорс (`zip2john`+`john`).
- **Документ:** распаковать как ZIP, посмотреть XML.
- **Бинарник:** `strings`, `readelf`, overlay.

## Шаг 5: уровень 4 — продвинутое
Если ничего не сработало: адаптивные методы, стего в коэффициентах, кастомные
схемы, крипто поверх стего. Здесь нужен анализ кода/структуры, а не перебор.

## Шаг 6: наш файл целиком
```python
import base64, gzip
d = open('mystery.dat','rb').read()
raw = gzip.decompress(base64.b64decode(d))
print(raw.decode())
```

Вывод:

```
nto{decision_tree_chain}
```

## Шаг 7: типичные ошибки
- Пропустить `file` и сразу запускать `steghide` — трата времени.
- Не проверять метаданные (`exiftool`) — там часто флаг.
- Игнорировать хвост файла (overlay) и лишние записи архива.
- Не сохранять промежуточные шаги — теряется цепочка.

## Что мы теперь знаем
- Начинай с `file`/`head`/`xxd`, а не с экзотики.
- Кодирования → распаковка → инструменты по типу → продвинутое.
- После каждого шага заново определяй тип (`file`).
- Сохраняй промежуточные результаты и веди цепочку.

## Квиз

Проверь себя.

```quiz
- question: "С чего начинать разбор неизвестного файла?"
  options:
    - "С file/head/xxd — определить тип и начало"
    - "Сразу с steghide"
    - "С брутфорса пароля"
    - "С переустановки системы"
  answer: 0
  explanation: "Идентификация типа — самый дешёвый и информативный шаг."
- question: "Что означает 'матрёшка' в CTF-стего?"
  options:
    - "Несколько вложенных слоёв кодирования/сжатия"
    - "Игрушка"
    - "Тип шифра"
    - "Формат картинки"
  answer: 0
  explanation: "Слои разматываются по одному, проверяя тип после каждого."
- question: "Какой инструмент показать для изображения в первую очередь?"
  options:
    - "zsteg/steghide/exiftool"
    - "gunzip"
    - "readelf"
    - "john"
  answer: 0
  explanation: "Для картинок — zsteg, steghide, exiftool, stegsolve."
- question: "Что часто упускают новички?"
  options:
    - "Метаданные (exiftool) и хвост файла (overlay)"
    - "Имя файла"
    - "Размер файла"
    - "Дату создания"
  answer: 0
  explanation: "EXIF и overlay — частые места для флагов."
```

## Куда дальше
Дерево решений даёт порядок. Дальше — multi-layer: как системно разматывать
цепочки вложенных слоёв.

## Где пригодится
- **CTF:** системный разбор задач под таймером.
- **Форензика:** методичный анализ неизвестных артефактов.
- **Blue team:** triage подозрительных файлов.
""".strip()

dt_parser = (
    "import base64, gzip\n"
    "d = open('mystery.dat','rb').read()\n"
    "raw = gzip.decompress(base64.b64decode(d))\n"
    "print(raw.decode())\n"
)
dt_task = ("# Задача: base64 → gzip\n\n"
           "`mystery.dat` — base64, внутри которого gzip, внутри — метка.\n\n"
           "1. `file mystery.dat`.\n"
           "2. `python3 tree.py` — разматывание цепочки.\n"
           "3. `python3 tree.py | grep nto > found.txt`.\n")
emit("stego-ctf-decision-tree", """---
id: stego-ctf-decision-tree
title: "Decision tree для CTF-стего: порядок проверок"
category: stego
parent: stego-module-tools-ctf
difficulty: easy
order: 3
tags: [stego, ctf, methodology, decision-tree, triage]
prerequisites: [stego-tool-binwalk-deep]
useful_for:
  - "CTF Stego: системный разбор под таймером"
  - "Форензика: методичный анализ артефактов"
  - "Blue team: triage подозрительных файлов"
estimated_minutes: 15
summary: "Дерево решений CTF-стего: идентификация (file/head/xxd), кодирования, распаковка, инструменты по типу (zsteg/steghide/exiftool/spectrogram), продвинутый уровень. Типичные ошибки."
lab:
  kind: shell
  title: "Практика: размотать base64 → gzip"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, mystery.dat, tree.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Начни с `file mystery.dat`."
    - "Внутри base64 — gzip-поток."
    - "`python3 tree.py` разматывает цепочку."
    - "`python3 tree.py | grep nto > found.txt`."
---

""" + dt_body + "\n", lab_json(
    "stego-ctf-decision-tree", dt_flag, dt_task,
    [("mystery.dat", ("b64", dt_blob)), ("tree.py", ("text", dt_parser))],
    [{"match": "tree\\.py", "example": "python3 tree.py", "output": dt_flag + "\n"}]))

# ===========================================================================
# stego-ctf-multi-layer
# ===========================================================================
ml_body = r"""
## Вопрос, с которого всё начинается
Бывает, что один слой — не предел: base64, внутри gzip, внутри снова base64.
Каждый слой выглядит безобидно, а вместе они прячут сообщение. Разматывать
вложенные слои нужно системно: определить, снять, повторить. Этот урок — про
многослойную стеганографию и как её не потерять.

## Наш пример
Возьмём `layers.txt` — текст. Размотаем его слой за слоем до метки.

## Шаг 1: как выглядит многослойность
Слои бывают разного рода:
- **кодирования** (base64/hex/base32),
- **сжатия** (gzip/zlib/bzip2),
- **шифры** (XOR/ROT),
- **контейнеры** (ZIP/PNG с вложенным файлом),
- **стего** (LSB, appended).

Часто они чередуются: кодирование → сжатие → кодирование → стего.

## Шаг 2: правило «один слой за раз»
После снятия слоя всегда заново определяй результат:
```
$ cat layers.txt | head -c 40
H4sIAAAAAA...
$ base64 -d layers.txt | file -
/dev/stdin: gzip compressed data
$ base64 -d layers.txt | gunzip | head -c 40
bnRve211...
$ base64 -d layers.txt | gunzip | base64 -d
nto{multi_layer_nested}
```

Ключ — проверять `file`/`head` после каждого шага и не «прыгать» на два слоя
сразу.

## Шаг 3: автоматизация разматывания
```python
import base64, gzip
d = open('layers.txt','rb').read()
step1 = base64.b64decode(d)          # base64
step2 = gzip.decompress(step1)       # gzip
step3 = base64.b64decode(step2)      # base64
print(step3.decode())
```

Вывод:

```
nto{multi_layer_nested}
```

## Шаг 4: как понять, что слой снят правильно
- Результат начинается с читаемых ASCII или с известной магии (`\x1f\x8b`, `PK`,
  `\x89PNG`).
- Длина «правдоподобна» (не мусор, не нули).
- Энтропия: сжатые данные ≈ максимальная; текст — низкая.

## Шаг 5: где ломаются многослойные задачи
- **Неверный порядок.** Сначала снять внешний слой, потом внутренний.
- **Потеря промежуточного результата.** Всегда сохраняй каждый шаг в файл.
- **Пропущенный слой.** Проверяй метаданные и хвост на каждом уровне.
- **Ловушка-приманка.** Внутри может быть «фальшивый флаг» — проверяй формат.

## Шаг 6: инструменты
- `file`, `head`, `xxd` — на каждом шаге.
- CyberChef Magic — автоматическая размотка.
- binwalk `-M` — рекурсивная распаковка контейнеров.
- `zsteg`, `steghide` — если слой оказался изображением/аудио.

## Что мы теперь знаем
- Многослойная стего — чередование кодирований, сжатий и контейнеров.
- Правило: один слой за раз, проверка типа после каждого.
- Автоматизация — цикл «определи → сними → повтори».
- Приманки и порядок слоёв — главные ловушки.

## Квиз

Проверь себя.

```quiz
- question: "Какое правило при разматывании многослойной стего?"
  options:
    - "Снимать по одному слою и проверять тип после каждого"
    - "Снять все слои сразу"
    - "Начать с самого сложного"
    - "Удалить файл"
  answer: 0
  explanation: "Один слой за раз с проверкой — иначе теряется цепочка."
- question: "Что говорит о том, что слой снят правильно?"
  options:
    - "Результат начинается с читаемого текста или известной магии"
    - "Результат пустой"
    - "Результат из одних нулей"
    - "Файл стал больше"
  answer: 0
  explanation: "ASCII или магия (1f 8b, PK, 89 PNG) — признак корректного шага."
- question: "Почему важно сохранять промежуточные результаты?"
  options:
    - "Чтобы не потерять цепочку и вернуться на шаг назад"
    - "Чтобы увеличить файл"
    - "Чтобы зашифровать данные"
    - "Это не важно"
  answer: 0
  explanation: "Многослойная задача требует воспроизводимой цепочки."
- question: "Что такое приманка в контексте CTF?"
  options:
    - "Фальшивый флаг, не совпадающий с нужным форматом"
    - "Настоящий флаг"
    - "Пароль"
    - "Инструмент"
  answer: 0
  explanation: "Внутри может лежать ложная метка — проверяй формат."
```

## Куда дальше
Методика разбора исчерпана. Дальше — современные носители: веса ML-моделей,
токены LLM и provenance C2PA. А пока запомни: цепочка слоёв разматывается
терпеливо, по одному шагу.

## Где пригодится
- **CTF:** сложные многослойные задачи.
- **Форензика:** разбор составных артефактов.
- **Blue team:** анализ цепочек обфускации.
""".strip()

ml_parser = (
    "import base64, gzip\n"
    "d = open('layers.txt','rb').read()\n"
    "s1 = base64.b64decode(d)\n"
    "s2 = gzip.decompress(s1)\n"
    "s3 = base64.b64decode(s2)\n"
    "print(s3.decode())\n"
)
ml_task = ("# Задача: base64 → gzip → base64\n\n"
           "`layers.txt` — вложенная цепочка: base64, gzip, снова base64.\n\n"
           "1. `file layers.txt`.\n"
           "2. `python3 layers.py` — размотка всех слоёв.\n"
           "3. `python3 layers.py | grep nto > found.txt`.\n")
emit("stego-ctf-multi-layer", """---
id: stego-ctf-multi-layer
title: "Многослойная стеганография: размотка вложенных слоёв"
category: stego
parent: stego-module-tools-ctf
difficulty: medium
order: 4
tags: [stego, ctf, multi-layer, chaining, nested, methodology]
prerequisites: [stego-ctf-decision-tree]
useful_for:
  - "CTF Stego: многослойные задачи"
  - "Форензика: составные артефакты"
  - "Blue team: цепочки обфускации"
estimated_minutes: 15
summary: "Многослойная стеганография: чередование кодирований, сжатий, контейнеров и стего. Правило одного слоя за раз, автоматизация разматывания, проверка корректности шага, приманки."
lab:
  kind: shell
  title: "Практика: base64 → gzip → base64"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, layers.txt, layers.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Первый слой — base64."
    - "Второй — gzip (проверь `file`)."
    - "Третий — снова base64."
    - "`python3 layers.py | grep nto > found.txt`."
---

""" + ml_body + "\n", lab_json(
    "stego-ctf-multi-layer", ml_flag, ml_task,
    [("layers.txt", ("b64", ml_blob)), ("layers.py", ("text", ml_parser))],
    [{"match": "layers\\.py", "example": "python3 layers.py", "output": ml_flag + "\n"}]))

# ===========================================================================
# tools hub
# ===========================================================================
tools_hub = """---
id: stego-module-tools-ctf
title: "Модуль: Инструменты и методология CTF-стего"
category: stego
parent: stego-tooling-advanced
difficulty: easy
order: 4
tags: [stego, roadmap, cyberchef, binwalk, ctf, methodology]
prerequisites: [stego-tooling-advanced]
useful_for:
  - "CTF Stego: системный разбор задач"
  - "Форензика: triage артефактов"
  - "Blue team: анализ обфускации"
estimated_minutes: 8
summary: "Навигационный модуль по инструментам и методике: CyberChef (рецепты и Magic), binwalk (сигнатуры и энтропия), дерево решений для CTF и размотка многослойных цепочек."
---

## Зачем этот модуль

Знать инструменты мало — важно знать порядок. Этот модуль собирает рабочий
процесс разбора неизвестного файла: как быстро определить тип, чем снять слой,
как не потерять цепочку в многослойной задаче.

## Что разберём

- **stego-tool-cyberchef** — конвейер операций, Magic, ключевые операции.
- **stego-tool-binwalk-deep** — сигнатуры, энтропия, извлечение, рекурсия.
- **stego-ctf-decision-tree** — фиксированный порядок проверок.
- **stego-ctf-multi-layer** — размотка вложенных слоёв.

## Как проходить

По порядку. Сначала инструменты (CyberChef, binwalk), затем методология
(дерево решений, многослойность). В каждом уроке — практический разбор файла.

## Что вы будете уметь

- Строить рецепт декодирования и воспроизводить его на Python.
- Сканировать файл на сигнатуры и извлекать встроенное.
- Действовать по дереву решений под таймер.
- Разматывать многослойные цепочки без потери шагов.
"""
write("content/stego/stego-module-tools-ctf.md", tools_hub + "\n")

print("batch 2d done")
