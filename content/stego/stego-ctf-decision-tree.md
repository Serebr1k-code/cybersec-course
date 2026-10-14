---
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
