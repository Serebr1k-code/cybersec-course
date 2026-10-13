---
id: stego-heic-avif
title: "Стеганография в HEIF/AVIF: боксы ISOBMFF, тайлы и метаданные"
category: stego
parent: stego-exif-xmp
difficulty: medium
order: 2
tags: [stego, heif, heic, avif, isobmff, boxes, metadata, tiles]
prerequisites: [stego-webp, stego-exif-xmp]
useful_for:
  - "CTF Stego: HEIC/AVIF-задачи"
  - "Анализ медиа с iPhone/Android"
  - "Форензика мобильных фото"
estimated_minutes: 55
summary: "HEIF и AVIF основаны на ISOBMFF: разбираем боксы ftyp/meta/mdat/iloc, встроенные тайлы и превью, EXIF/XMP в item-таблицах и практические приёмы извлечения."

lab:
  kind: shell
  title: "Практика: разбор боксов HEIF/AVIF и MakerNote"
  toolset: [core, python, hex]
  workdir: /home/student/task
  files: [task.md, IMG_0001.heic, boxes.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Карта боксов: `python3 boxes.py`."
    - "Метаданные и неизвестные items: `exiftool -a -u -g1 IMG_0001.heic`."
    - "Извлеки MakerNote: `exiftool -b -MakerNoteUnknown IMG_0001.heic | strings`."
    - "Или сразу: `strings IMG_0001.heic | grep nto > found.txt`."
---

## Вопрос, с которого всё начинается

В задаче дан `IMG_0001.heic` — «фото с телефона». Ты открываешь его `exiftool`, `zsteg`, но обычные инструменты либо не понимают формат, либо показывают кучу непонятных полей. Как разобрать современный формат, если он не похож ни на PNG, ни на JPEG?

Ответ: HEIC (и AVIF) построены на **ISOBMFF** — том же контейнере, что и MP4. Разобравшись в его структуре, ты умеешь работать и с видео, и с новыми форматами фото. Разберём это на нашем файле.

## Наш пример: IMG_0001.heic

**HEIC** (HEIF с кодеком HEVC) — формат фото по умолчанию на iPhone; **AVIF** — наследник на базе AV1. Оба построены на **ISOBMFF** (ISO Base Media File Format). Начнём с определения:

```bash
$ file IMG_0001.heic
IMG_0001.heic: ISO Media, HEIF Image HEVC Main or Main Still Picture Profile
```

**Бокс** — базовая единица ISOBMFF: 4 байта размера, 4 байта типа, затем данные. Всё в файле — это вложенные боксы.

| Бокс | Назначение |
|---|---|
| `ftyp` | тип файла (`heic`, `mif1`, `avif`) |
| `meta` | контейнер метаданных (EXIF/XMP) |
| `mdat` | «медиаданные»: сжатые тайлы/пиксели |
| `iloc` | расположение items в `mdat` |
| `iinf`/`infe` | описания items |
| `idat` | данные мелких items |

## Шаг 1: карта боксов

Перечислим боксы. Инструменты MP4 работают и здесь:

```bash
$ ffprobe -v trace IMG_0001.heic 2>&1 | grep -E "type='|size=" | head -40
$ mp4dump IMG_0001.heic | head -60
```

## Шаг 2: метаданные EXIF/XMP

В отличие от JPEG, EXIF в HEIF — это отдельный **item**, описанный в `iinf`/`iloc`, а не маркер. `exiftool` умеет читать HEIC/AVIF:

```bash
$ exiftool -a -u -g1 IMG_0001.heic | grep -iE "comment|description|unknown|maker"
[ExifIFD] MakerNoteUnknown : (Binary data 96 bytes, use -b option to extract)
```

Видим **неизвестный MakerNote**. Извлечём его (`-b` — бинарное значение):

```bash
$ exiftool -b -MakerNoteUnknown IMG_0001.heic | strings
flag{heic_isobmff_boxes}
```

Флаг был в неизвестной MakerNote — блоке, который обычный просмотр не показывает.

## Шаг 3: тайлы и встроенные превью

Изображение может быть нарезано на **тайлы** (grid item) и содержать уменьшенное **превью** (thmb). Каждый — отдельный item; в «хвостах» тайлов или в неиспользуемых items прячут данные.

```bash
$ exiftool -b -ThumbnailImage IMG_0001.heic > t.jpg && zsteg t.jpg
$ exiftool -b -PreviewImage IMG_0001.heic > p.jpg
```

Каждый item проверяйте отдельно: декодируйте в PNG и прогоняйте `zsteg`.

## Шаг 4: разбор боксов вручную

Если инструменты не справляются — обойдём боксы скриптом:

```python
import struct
d = open('IMG_0001.heic','rb').read()
def boxes(buf, off=0, end=None, depth=0):
    end = len(buf) if end is None else end
    i = off
    while i+8 <= end:
        size = struct.unpack('>I', buf[i:i+4])[0]
        typ = buf[i+4:i+8].decode('latin1')
        print('  '*depth + f'{typ} size={size} @ {hex(i)}')
        if size < 8: break
        if typ in ('meta','iprp','ipco','iinf','moov','trak'):
            boxes(buf, i+8, i+size, depth+1)
        i += size
boxes(d)
```

Обрати внимание: ISOBMFF — **big-endian** (`>I`), в отличие от RIFF/TIFF-LE.

## Шаг 5: AVIF vs HEIC

| Свойство | HEIC | AVIF |
|---|---|---|
| Кодек | HEVC (hvc1) | AV1 (av01) |
| Контейнер | ISOBMFF | ISOBMFF |
| Декодер | heif-convert, pillow-heif | avifdec, Pillow |
| ftyp brand | `heic`/`mif1` | `avif` |

Инструменты разбора боксов (`mp4dump`, `ffprobe`) общие, а декодеры — разные:

```bash
$ heif-convert IMG_0001.heic out.png && zsteg out.png
$ avifdec IMG_0001.avif out.png && zsteg out.png
```

## Шаг 6: мобильная форензика и Live Photo

Фото с iPhone — это HEIC с богатым набором метаданных (GPS, модель, серийник) и иногда «Live Photo» (второй item с видео). Данные могут быть и в Live Photo-дорожке:

```bash
$ exiftool -b -EmbeddedVideoFile IMG_0001.heic > live.mov
$ ffprobe live.mov
```

## Шаг 7: полный разбор — от боксов к данным

Соберём практический маршрут по HEIC/AVIF. На каждом шаге мы либо сужаем область, либо достаём item.

1. **Определи контейнер.** `file` и `ftyp`: `heic`/`mif1` → HEIF; `avif` → AVIF. Дальше набор
   инструментов общий.
2. **Построй карту.** `mp4dump`/`ffprobe` показывают дерево боксов: где `meta`, где `mdat`, сколько
   items.
3. **Выпиши items.** В `iinf`/`infe` каждый item имеет id и тип (`hvc1`, `Exif`, `mime`, `grid`,
   `thmb`). Именно этот список — карта того, что вообще есть в файле.
4. **Найди смещения.** `iloc` говорит, по какому смещению и какой длине лежит каждый item в `mdat`.
   Часто между items остаются **«дыры»** — неиспользуемые байты, куда прячут данные.
5. **Достань каждый item.** `exiftool -b -TAG`, `heif-convert`, либо вручную по смещению из `iloc`.
6. **Проверь каждый отдельно.** Декодируй тайл/превью в PNG и прогони `zsteg`; бинарные items
   (`Exif`, `mime`) смотри `strings`/`xxd`.

Ключевая мысль: HEIC — это **не одно изображение, а набор items**. Флаг может лежать в превью, в
MakerNote, в «мусорном» item или в дыре между items — поэтому проверяют всё, а не только основную
картинку.

## Как это видят защитники

С точки зрения форензики и защиты, HEIF/AVIF интересны тем, что **несут много скрытого**:

- **встроенные превью и Live Photo** — второй контент, который не виден при обычном просмотре;
- **неизвестные MakerNote** — производитель может класть туда что угодно, включая серийники;
- **items, не привязанные к картинке** — по спецификации допустимы, но часто содержат лишнее;
- **дыры в `mdat`** — неиспользуемое место, идеальное для стеганографии;
- **метаданные GPS/модель** — приватность: фото с телефона выдаёт местоположение.

Для защитника вывод: при приёме пользовательских изображений **перепаковывай** файл (декод +
повторное кодирование) — так отбрасываются все посторонние items, MakerNote и «дыры». А для аналитика
те же items являются источником данных.

## Если не сработало

- **64-битные размеры боксов** — если size = 1, реальный размер в следующих 8 байтах; если 0 — до конца файла.
- **HEIC vs AVIF** — контейнер общий, кодеки разные.
- **«Мусорные» items** — спецификация допускает items, не привязанные к изображению.
- **Endianness** — ISOBMFF big-endian.
- **`.avif` от CDN** может быть перепакован — проверь `ftyp` перед выводами.

## Справочные таблицы

| Инструмент | Команда | Назначение |
|---|---|---|
| file | `file x.heic` | определить HEIF/AVIF |
| ffprobe | `-v trace x.avif` | карта боксов |
| mp4dump | `mp4dump x.heic` | дамп дерева боксов |
| exiftool | `-a -u -g1` | метаданные |
| heif-convert | `heif-convert x.heic out.png` | декод в PNG |
| avifdec | `avifdec x.avif out.png` | декод AVIF |

| Бокс | Смысл для стего |
|---|---|
| `ftyp` | определить подтип (heic/avif) |
| `meta` | контейнер метаданных и items |
| `iloc` | где лежат items в mdat |
| `iinf`/`infe` | какие items есть |
| `mdat` | сжатые тайлы + «дыры» |
| `idat` | данные мелких items |

## Практика: извлечение items

```bash
pip install pillow-heif
python3 -c "from pillow_heif import register_heif_opener; from PIL import Image; register_heif_opener(); Image.open('photo.heic').save('out.png')"
exiftool -b -ThumbnailImage photo.heic > t.jpg
```

Каждый item проверяйте отдельно: декодируйте в PNG и прогоняйте `zsteg`. Превью часто меньше по размеру и лучше подходит для LSB.

## Практика: ручное извлечение item по `iloc`

Если `exiftool` не даёт нужный item, его достают вручную по смещению из `iloc`. Общая идея: найти в
`iloc` запись для item, прочитать `offset` и `length`, вырезать эти байты из файла.

```python
d = open('IMG_0001.heic','rb').read()
off, ln = 0x1234, 96          # значения берём из разбора iloc
item = d[off:off+ln]
open('item.bin','wb').write(item)
print(item[:16].hex())
```

Так достают **любой** item: EXIF, XMP, превью, «мусорный» — не полагаясь на то, что инструмент
поддерживает конкретный тег. Полезно, когда `exiftool -b -TAG` возвращает пусто, а данные в файле
явно есть.

## Что мы теперь знаем

1. HEIC/AVIF — это **ISOBMFF**-контейнер, как MP4.
2. Всё в файле — **боксы** (`ftyp`, `meta`, `mdat`, `iloc`).
3. EXIF/XMP лежат в **item-таблицах**, а не в маркере.
4. Изображение нарезано на **тайлы** и **превью** — каждый item проверяй отдельно.
5. `exiftool -a -u -g1` + `-b -TAG` и `mp4dump`/`ffprobe` — базовый набор.
6. Смещения items лежат в `iloc`; между items в `mdat` могут быть «дыры» со скрытыми данными.
7. Перепаковка (декод + re-encode) — простая защита: отбрасывает посторонние items и MakerNote.
8. Ручное извлечение item по `iloc` (offset + length) работает, когда инструмент не знает нужный тег.

## Квиз

Проверь себя.

```quiz
- question: "На каком контейнере основаны HEIF и AVIF?"
  options:
    - "ISOBMFF (как MP4)"
    - "RIFF"
    - "ZIP"
    - "TIFF IFD"
  answer: 0
  explanation: "Оба формата используют ISO Base Media File Format."
- question: "Где в HEIF описан EXIF?"
  options:
    - "Как отдельный item в таблицах meta/iinf/iloc"
    - "В заголовке RIFF"
    - "В теге 0x002A"
    - "В палитре"
  answer: 0
  explanation: "EXIF — отдельный item, описанный в iinf/iloc."
- question: "Какой порядок байт у ISOBMFF?"
  options:
    - "Big-endian"
    - "Little-endian"
    - "Смешанный"
    - "Зависит от ОС"
  answer: 0
  explanation: "ISOBMFF — big-endian, в отличие от RIFF/TIFF."
- question: "Что означает size=1 в боксе?"
  options:
    - "Реальный 64-битный размер в следующих 8 байтах (largesize)"
    - "Бокс пустой"
    - "Конец файла"
    - "Сжатие"
  answer: 0
  explanation: "size=1 указывает на 64-битный размер largesize."
- question: "Чем декодировать HEIC и AVIF соответственно?"
  options:
    - "heif-convert для HEIC, avifdec для AVIF"
    - "zsteg для обоих"
    - "binwalk для обоих"
    - "ttx для обоих"
  answer: 0
  explanation: "Разные кодеки требуют разных декодеров."
```

## Куда дальше

Мы разобрали современные форматы. Дальше — практика: собери полный пайплайн анализа медиа и комбинируй каналы, потому что флаг часто лежит за несколькими слоями. А пока запомни: HEIC/AVIF — это контейнер с несколькими items, проверяй **все**.

## Где пригодится

- **CTF Stego:** задачи на HEIC/AVIF и ISOBMFF-контейнеры.
- **Форензика:** мобильные фото и метаданные камеры.
- **Bug bounty:** обработка нестандартных изображений на сервере.
- **Работа:** разбор медиа из мобильных экосистем.
