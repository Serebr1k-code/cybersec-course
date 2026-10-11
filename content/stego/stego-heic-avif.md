---
id: stego-heic-avif
title: "Стеганография в HEIF/AVIF: боксы ISOBMFF, тайлы и метаданные"
category: stego
parent: stego-image-formats
difficulty: medium
order: 3
tags: [stego, heif, heic, avif, isobmff, boxes, metadata, tiles]
prerequisites: [stego-webp, stego-exif-xmp]
useful_for:
  - "CTF Stego: HEIC/AVIF-задачи"
  - "Анализ медиа с iPhone/Android"
  - "Форензика мобильных фото"
estimated_minutes: 55
summary: "HEIF и AVIF основаны на ISOBMFF: разбираем боксы ftyp/meta/mdat/iloc, встроенные тайлы и превью, EXIF/XMP в item-таблицах и практические приёмы извлечения."
---

HEIC (HEIF с кодеком HEVC) — формат фото по умолчанию на iPhone, AVIF — наследник на базе AV1. Оба построены на **ISOBMFF** (ISO Base Media File Format) — том же контейнере, что и MP4. Для стеганографии это богатая почва: метаданные лежат в item-таблицах, изображения нарезаны на тайлы, а «дыры» между боксами и неописанные области — удобный канал. Разбор требует понимания боксовой иерархии, но после неё вы умеете работать и с MP4, и с HEIC/AVIF одинаково.

## Боксы ISOBMFF

Всё в файле — это боксы: 4-байтный размер, 4-байтный тип, затем данные (вложенные боксы или «сырой» payload).

| Бокс | Уровень | Назначение |
|---|---|---|
| `ftyp` | top | тип файла: `heic`, `mif1`, `avif` |
| `meta` | top | контейнер метаданных (EXIF/XMP) |
| `mdat` | top | «медиаданные»: сжатые тайлы/пиксели |
| `hdlr` | meta | обработчик (pict) |
| `iloc` | meta | расположение items в `mdat` |
| `iinf`/`infe` | meta | описания items (типы: hvc1, av01, Exif, mime) |
| `iprp`/`ipco` | meta | свойства (ispe, pixi, av1C, colr) |
| `idat` | meta | данные мелких items |
| `pitm` | meta | основной item |

```bash
file photo.heic
# photo.heic: ISO Media, HEIF Image HEVC Main or Main Still Picture Profile

# перечислить боксы (mp4-инструменты работают)
ffprobe -v trace photo.heic 2>&1 | grep -E "type='|size=" | head -40
# или универсальный парсер
mp4dump photo.heic | head -60
```

## Метаданные EXIF/XMP в HEIF

В отличие от JPEG, EXIF в HEIF — это отдельный **item**, описанный в `iinf`/`iloc`, а не маркер. Часто рядом лежит и XMP. Всё это лежит в `mdat` по смещениям из `iloc`.

```bash
# exiftool умеет читать HEIC/AVIF
exiftool -a -u -g1 photo.heic
# извлечь встроенное превью (thumbnail) в JPEG
exiftool -b -ThumbnailImage photo.heic > thumb.jpg
# XMP
exiftool -xmp -b photo.heic
```

## Тайлы и встроенные превью

Изображение может быть нарезано на тайлы (`grid` item), а также содержать уменьшенное превью (`thmb`). Каждый тайл — отдельный item; в «хвостах» тайлов или в неиспользуемых items прячут данные.

```bash
# список items и их типов
python3 - <<'PY'
import struct
d=open('photo.heic','rb').read()
def boxes(buf, off=0, end=None, depth=0):
    end = len(buf) if end is None else end
    i=off
    while i+8<=end:
        size=struct.unpack('>I',buf[i:i+4])[0]; typ=buf[i+4:i+8].decode('latin1')
        print('  '*depth+f'{typ} size={size} @ {hex(i)}')
        if size<8: break
        if typ in ('meta','iprp','ipco','iinf','dinf','moov','trak','mdia','stbl'):
            boxes(buf, i+8, i+size, depth+1)
        i+=size
boxes(d)
PY
```

## Разобранный пример

CTF: `IMG_0001.heic` из «телефона».

```bash
$ exiftool -a -u -g1 IMG_0001.heic | grep -iE "comment|description|unknown|maker"
[ExifIFD] MakerNoteUnknown : (Binary data 96 bytes, use -b option to extract)

$ exiftool -b -MakerNoteUnknown IMG_0001.heic | strings
flag{heic_isobmff_boxes}

$ python3 - <<'PY'
import struct
d=open('IMG_0001.heic','rb').read()
# найти mdat и проверить хвост
i=d.find(b'mdat')
print('mdat @', hex(i))
print(d[-64:])
PY
```

Флаг был в неизвестной MakerNote. Если бы там было пусто — следующий шаг: пройти по `iloc`, извлечь все items и проверить `mdat` на «дыры» и хвост.

```bash
# извлечь все items через mp4-инструменты или вручную по iloc
exiftool -b -ThumbnailImage IMG_0001.heic > t.jpg && zsteg t.jpg
# AVIF: конвертировать и проверить пиксели
avifdec IMG_0001.avif out.png && zsteg out.png
```

## Краевые случаи и подводные камни

- **64-битные размеры боксов:** если размер поля = 1, реальный размер в следующих 8 байтах (`largesize`); если 0 — до конца файла. Парсер, игнорирующий это, сломается.
- **HEIC vs AVIF:** одинаковый контейнер, разные кодеки (`hvc1` vs `av01`) — инструменты для боксов общие, для декодирования разные.
- **Куча «мусорных» items:** спецификация допускает items, не привязанные к видимому изображению; их легко пропустить, если смотреть только на основное.
- **Endianness:** ISOBMFF — big-endian, в отличие от RIFF/TIFF-LE. Не перепутай при ручном разборе.
- **Файлы `.avif` от CDN** могут быть перепакованы и урезаны — проверь `ftyp` перед выводами.

## Что дальше / решение

Пайплайн: `file` → `ffprobe`/`mp4dump` для карты боксов → `exiftool -a -u -g1` для метаданных и `-b -TAG` для бинарных → ручной обход `iloc`/`iinf` для всех items → проверка `mdat` на хвост/дыры → декодирование (`avifdec`, `heif-convert`) и `zsteg` по пикселям. HEIC/AVIF стоит уметь читать хотя бы на уровне боксов: это тот же контейнер, что и MP4, и навык переносится на видео.

## Справочные таблицы

| Инструмент | Команда | Назначение |
|---|---|---|
| file | `file x.heic` | определить HEIF/AVIF |
| ffprobe | `-v trace x.avif` | карта боксов |
| mp4dump | `mp4dump x.heic` | дамп дерева боксов |
| exiftool | `-a -u -g1` | метаданные |
| exiftool | `-b -ThumbnailImage` | извлечь превью |
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

## Практика: извлечение всех items по iloc

`iloc` описывает, где в `mdat` лежит каждый item. Чтобы не угадывать, разберём его и вытащим все items — включая те, что не привязаны к видимому изображению.

```python
import struct
d=open('photo.heic','rb').read()
# найти meta-бокс и в нём iloc (упрощённо, для учебного примера)
def find(box):
    i=d.find(box); return i
meta=d.find(b'meta')
print('meta @', hex(meta))
# практичный путь — готовые библиотеки
```

```bash
pip install pillow-heif    # декодирование HEIF/AVIF
python3 -c "from pillow_heif import register_heif_opener; from PIL import Image; register_heif_opener(); Image.open('photo.heic').save('out.png')"
# извлечь все вложенные превью, которые умеет exiftool
exiftool -b -ThumbnailImage photo.heic > t.jpg
exiftool -b -PreviewImage photo.heic > p.jpg
```

Каждый item проверяйте отдельно: декодируйте в PNG и прогоняйте `zsteg`/StegSolve. Превью часто меньше по размеру и лучше подходит для LSB.

## AVIF vs HEIC: кодеки и инструменты

| Свойство | HEIC | AVIF |
|---|---|---|
| Кодек | HEVC (hvc1) | AV1 (av01) |
| Контейнер | ISOBMFF | ISOBMFF |
| Декодер | heif-convert, pillow-heif | avifdec, Pillow |
| Поддержка браузеров | ограниченная | широкая |
| ftyp brand | `heic`/`mif1` | `avif` |

Инструменты разбора боксов (`mp4dump`, `ffprobe`) общие, а декодеры — разные. Если `heif-convert` не берёт файл, проверьте brand в `ftyp`: возможно, это AVIF, и нужен `avifdec`.

## Мобильная форензика HEIC

Фото с iPhone — это HEIC с богатым набором метаданных: GPS, модель, серийный номер, а иногда и «Live Photo» (второй item с видео). Для форензики важны: точная метка времени, ориентация, привязка к устройству. Данные могут быть спрятаны и в Live Photo-дорожке.

```bash
exiftool -a -u -g1 -api largefilesupport=1 photo.heic | head -60
# Live Photo: извлечь вложенное видео
exiftool -b -EmbeddedVideoFile photo.heic > live.mov 2>/dev/null
ffprobe live.mov
```

Практический вывод: HEIC/AVIF — это не «одна картинка», а контейнер с несколькими items. Прогоняйте **все** items, а не только основное изображение.

## Что делать, если инструменты не видят формат

Иногда `file` не распознаёт HEIC, а `exiftool` показывает пустые метаданные. Причины: урезанный/перепакованный файл, нестандартный brand, отсутствие декодера. Решение — читать боксы вручную (`mp4dump`, скрипт выше) и искать `mdat`-хвост. Если файл начинается не с `ftyp`, а с мусора, возможно, это конкатенация или полиглот — проверьте смещение сигнатуры.

## Сравнение HEIC и AVIF на практике

Хотя оба формата основаны на ISOBMFF, практические различия заметны при разборе. HEIC использует HEVC и часто приходит с iPhone, где к метаданным добавляются Apple-специфичные MakerNote. AVIF использует AV1 и чаще встречается на веб-сайтах как оптимизированная картинка, нередко «вычищенная» от метаданных.

```bash
# определить brand
python3 -c "d=open('x.heic','rb').read();print(d[8:16])"   # ftyp + brand
# декодировать в зависимости от brand
case $(python3 -c "d=open('x.heic','rb').read();print(d[8:12].decode())") in
  heic|mif1) heif-convert x.heic out.png ;;
  avif)      avifdec x.avif out.png ;;
esac
zsteg out.png
```

Для AVIF метаданные часто урезаны, поэтому основная ставка — на пиксели (после декода) и на «дыры» в `mdat`. Для HEIC, наоборот, метаданные богатые: начинайте с `exiftool`. Понимание источника файла (телефон vs веб) подсказывает, где искать.

## Итоговый чек-лист по HEIF/AVIF

1. `file` и первые байты — подтвердить `ftyp` и brand (`heic`/`avif`).
2. `ffprobe`/`mp4dump` — карта боксов (`meta`, `mdat`, `iloc`, `iinf`).
3. `exiftool -a -u -g1` — метаданные; `-b -TAG` для бинарных.
4. Обойти `iloc`/`iinf` — извлечь **все** items, включая превью и Live Photo.
5. Проверить хвост `mdat` и «дыры» между боксами.
6. Декодировать (`heif-convert`/`avifdec`/pillow-heif`) и прогнать `zsteg`.
7. Сравнить набор боксов с эталоном: лишний бокс/item — повод копать.

## Квиз

```quiz
- question: "На каком контейнере основаны HEIF и AVIF?"
  options:
    - "ISOBMFF (как MP4)"
    - "RIFF"
    - "ZIP"
    - "TIFF IFD"
  answer: 0
- question: "Где в HEIF описан EXIF?"
  options:
    - "Как отдельный item в таблицах meta/iinf/iloc"
    - "В заголовке RIFF"
    - "В теге 0x002A"
    - "В палитре"
  answer: 0
- question: "Какой порядок байт у ISOBMFF?"
  options:
    - "Big-endian"
    - "Little-endian"
    - "Смешанный"
    - "Зависит от ОС"
  answer: 0
- question: "Что означает size=1 в боксе?"
  options:
    - "Реальный 64-битный размер в следующих 8 байтах (largesize)"
    - "Бокс пустой"
    - "Конец файла"
    - "Сжатие"
  answer: 0
```

## Где пригодится

- **CTF Stego:** задачи на HEIC/AVIF и ISOBMFF-контейнеры.
- **Форензика:** мобильные фото и метаданные камеры.
- **Bug bounty:** обработка нестандартных изображений на сервере.
- **Работа:** разбор медиа из мобильных экосистем.
