---
id: stego-tiff
title: "Стеганография в TIFF: теги, IFD, стрипы и ExtraSamples"
category: stego
parent: stego-exif-xmp
difficulty: medium
order: 1
tags: [stego, tiff, ifd, tags, strips, extrasamples, geotiff]
prerequisites: [stego-png-chunks, stego-exif-xmp]
useful_for:
  - "CTF Stego: задачи на TIFF"
  - "Форензика сканированных документов"
  - "Анализ GeoTIFF и научных изображений"
estimated_minutes: 50
summary: "TIFF как дерево IFD-тегов: приватные теги, множественные изображения, стрипы, ExtraSamples и Geo-теги — где прячут данные и как их извлекать."
lab:
  kind: shell
  title: "Практика: метаданные TIFF"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, image.tif, tiff.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "TIFF хранит метаданные в тегах."
    - "ImageDescription — тег 270."
    - "Прочитай значение тега через PIL."
    - "`python3 tiff.py | grep nto > found.txt`."

---

## Вопрос, с которого всё начинается

В задаче дали `scan.tiff` — скан документа. `zsteg` ничего не находит, `binwalk` тоже. Но `file` пишет не «картинка», а «TIFF image data, direntries=17» — то есть внутри есть **дерево записей**. Что это за записи и где среди них может лежать флаг?

TIFF — не просто картинка, а **контейнер с тегами**. Разберём его на нашем примере.

## Наш пример: scan.tiff

Смотрим, что за файл и как он начинается:

```bash
$ file scan.tiff
scan.tiff: TIFF image data, little-endian, direntries=17, width=64, height=64, ...

$ xxd scan.tiff | head -3
00000000: 4949 2a00 0800 0000 1100 0001 0400 0100  II*.............
00000010: 0000 4000 0000 0101 0400 0100 0000 4000  ..@...........@.
00000020: 0000 0201 0300 0300 0000 da00 0000 0301  ................
```

Первые байты `49 49` — это ASCII `II`, значит порядок байт **little-endian** (младший байт вперёд). Следующие `2a 00` = 42 — «магическое» число TIFF. Дальше `08 00 00 00` — смещение первого **IFD**. «direntries=17» означает: в этом IFD 17 записей.

## Шаг 1: IFD — дерево тегов

**IFD** (Image File Directory) — это таблица описания изображения. Она состоит из:

- 2 байта — число записей;
- по 12 байт на запись: `tag` (номер тега, 2 байта), `type` (тип данных, 2), `count` (число значений, 4), `value/offset` (значение или смещение, 4);
- 4 байта — смещение следующего IFD (0, если это последний).

Каждый **тег** — это параметр: ширина, высота, сжатие, описание, ПО. Гибкость формата в том, что тегов сотни, включая **приватные** (диапазон 32768–65535), назначение которых никто не проверяет. Вот где прячут данные.

Прочитать все теги разом можно через `tiffinfo` или `tiffdump`:

```bash
$ tiffinfo scan.tiff | grep -E 'TIFF directory|ImageDescription|Software|Tag'
=== TIFF directory 0 ===
  ImageDescription: nothing to see here
  Software: TIFF stego 0x41414141
  Tag 65000: 102,108,97,103,123,...
```

Уже видно подозрительное: `ImageDescription: nothing to see here` (дословно «здесь не на что смотреть»), `Software: TIFF stego 0x41414141` и незнакомый `Tag 65000` с длинным списком чисел.

## Шаг 2: приватный тег 65000

Числа в `Tag 65000` — это байты. Переведём их в ASCII:

```bash
$ tiffinfo scan.tiff | grep -oP 'Tag 65000: \K[0-9,]+' \
    | python3 -c "import sys;print(bytes(int(x) for x in sys.stdin.read().strip().split(',')))"
b'flag{tiff_private_tags_win}'
```

Флаг найден в приватном теге `65000` (`0xFDE8`). `tiffdump` покажет его ещё нагляднее — как hex-байты:

```bash
$ tiffdump scan.tiff | grep 65000
65000 (0xfde8) BYTE (1) 27<0x66 0x6c 0x61 0x67 0x7b ...>
```

`0x66 0x6c 0x61 0x67` — это `f l a g`. Приватный тег не отображается ни в одном просмотрщике, но он есть в файле — и `grep` его тоже находит:

```bash
$ grep -aboP 'flag\{[^}]*\}' scan.tiff
320:flag{tiff_private_tags_win}
```

`grep -aboP` (`-a` — бинарный режим, `-b` — смещение) нашёл флаг прямо в байтах, начиная с позиции 320.

## Шаг 3: многопанельный TIFF

TIFF может содержать несколько IFD, связанных полем «следующий IFD». Это страницы документа или отдельные «скрытые» картинки. Проверим:

```bash
$ python3 -c "from PIL import Image; print('n_frames', getattr(Image.open('scan.tiff'),'n_frames',1))"
n_frames 3
```

Три панели. Разбить их на отдельные файлы можно через `tiffsplit scan.tiff` (создаст `scan_aaa.tif`, `scan_aab.tif`, …) или через Pillow в цикле `im.seek(i)`. Всегда проверяй **все** панели: данные могут быть не в первой.

## Шаг 4: «дыры» между стрипами

Пиксели в TIFF лежат в **стрипах** — блоках, на которые указывают теги `StripOffsets` и `StripByteCounts`. Между стрипами или после последнего IFD могут остаться неописанные байты — готовый контейнер. Ищем дописанное:

```bash
$ grep -aboP 'PK\x03\x04|flag\{|Rar!' scan.tiff
$ binwalk scan.tiff
```

Сигнатура `PK\x03\x04` — это начало ZIP; если она есть, вырезай хвост (`dd if=scan.tiff bs=1 skip=OFFSET`) и распаковывай.

## Шаг 5: BigTIFF и GeoTIFF

Два важных варианта формата:

- **BigTIFF** отличается всего одним байтом: magic `43` вместо `42`. Зато все смещения 64-битные, и старые парсеры его не открывают — «слепая зона» для анализа. Проверяй первые байты: `4949 2b00` = BigTIFF.
- **GeoTIFF** добавляет теги `34735` (GeoKeyDirectory), `34736` (GeoDoubleParams), `34737` (GeoAsciiParams) — координаты, проекции, единицы. В `GeoAsciiParams` можно спрятать строку, а в неиспользуемых ключах — бинарные данные.

```bash
$ exiftool -a -u -g1 -GeoTiff:all map.tiff
$ listgeo map.tiff 2>/dev/null | head
```

Прикладной приём: сравни GeoTIFF-ключи с эталонным файлом — «лишние» записи видны по diff.

## Шаг 6: если IFD повреждён

Задачи часто «ломают» TIFF намеренно — портят указатель на первый IFD или поле `count`. `tiffinfo` падает, но данные внутри остаются. Действуй от структуры: прочитай смещение первого IFD из байтов 4–8 и пройди записи вручную:

```python
import struct
d = open("broken.tiff", "rb").read()
off = struct.unpack("<I", d[4:8])[0]
n = struct.unpack("<H", d[off:off+2])[0]
for k in range(min(n, 64)):
    e = off + 2 + k*12
    tag, typ, cnt = struct.unpack("<HHI", d[e:e+8])
    val = struct.unpack("<I", d[e+8:e+12])[0]
    print(hex(tag), "type", typ, "count", cnt, "val/off", hex(val))
```

Повреждение структуры — не приговор: ломается навигация, а сами данные обычно на месте.

## Шаг 7: ExtraSamples и пайплайн

Ещё один интересный тег — `ExtraSamples` (номер 338). Он описывает «лишние» каналы на пиксель: если изображение объявляет больше сэмплов, чем нужно (например, RGBA плюс ещё один), этот дополнительный канал полностью свободен для данных. По умолчанию такие сэмплы помечены как `unspecified` — их никто не отображает.

Практический пайплайн разбора: `file` (порядок байт и direntries) → `exiftool -a -u -g1` (все теги, включая приватные) → `exiftool -b -TAG` или `tiffinfo` для «сырых» значений → `tiffdump` для дерева IFD → `tiffsplit`/Pillow для всех панелей → `binwalk`/`grep -aboP` для дописанных данных. TIFF почти всегда «отдаёт» данные через теги или лишние панели, а не через LSB.

## Что мы теперь знаем

1. TIFF — контейнер с деревом **IFD**; каждый IFD — таблица 12-байтных записей-тегов.
2. Первые байты: `II` (little-endian) или `MM` (big-endian), затем magic 42 (или 43 для BigTIFF).
3. **Приватные теги** (32768–65535) — частый канал; наш флаг лежал в теге 65000.
4. Извлечь значение тега: `tiffinfo`, `tiffdump`, `exiftool -b`, или `grep -aboP` прямо по байтам.
5. Многопанельный TIFF (`n_frames`) — проверяй все страницы.
6. «Дыры» между стрипами и после последнего IFD — ищи `binwalk` и `grep -aboP`.
7. BigTIFF (magic 43) и GeoTIFF-теги — отдельные «слепые зоны».

## Квиз

Проверь себя.

```quiz
- question: "Что описывает структура IFD в TIFF?"
  options:
    - "Дерево тегов с записями tag/type/count/value и указателем на следующий IFD"
    - "Только размер файла"
    - "Только палитру"
    - "Только CRC"
  answer: 0
  explanation: "IFD — таблица 12-байтных записей-тегов плюс ссылка на следующий IFD."
- question: "Что означают первые два байта TIFF `II`?"
  options:
    - "Little-endian порядок байт"
    - "Формат WebP"
    - "Наличие EXIF"
    - "BigTIFF"
  answer: 0
  explanation: "II = Intel = little-endian; MM = Motorola = big-endian."
- question: "Какие теги особенно часто несут скрытые данные?"
  options:
    - "Приватные (диапазон 32768–65535)"
    - "Только ImageWidth"
    - "Только XResolution"
    - "Только StripByteCounts"
  answer: 0
  explanation: "Их назначение не проверяется просмотрщиками."
- question: "Чем BigTIFF отличается от классического TIFF?"
  options:
    - "Magic 43 вместо 42 и 64-битные смещения"
    - "Другой цветовой режим"
    - "Отсутствием тегов"
    - "Обязательным ZIP-сжатием"
  answer: 0
  explanation: "Байт magic 0x2b=43 сигналит BigTIFF; смещения 64-битные."
- question: "Что делать с многопанельным TIFF?"
  options:
    - "Проверить все панели (n_frames), а не только первую"
    - "Удалить лишние панели"
    - "Сжать в JPEG"
    - "Переименовать в PNG"
  answer: 0
  explanation: "Данные могут быть в любой из панелей цепочки IFD."
```

## Куда дальше

Мы разобрали формат-контейнер с деревом тегов. Дальше посмотрим на низкоуровневые **игровые форматы** — TGA и DDS: там данные прячут в заголовках, ID-блоках и дописанных хвостах. А пока запомни: увидел `direntries` в `file` — открывай `tiffinfo -a -u` и смотри приватные теги и все панели.

## Где пригодится

- **CTF Stego:** TIFF-задачи с приватными тегами и панелями.
- **Форензика:** анализ сканов, факсов, документов.
- **Геоанализ:** разбор GeoTIFF и координат.
- **Работа:** обработка научных и медицинских изображений.
