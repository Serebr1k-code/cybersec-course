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
---

TIFF — это не «просто картинка», а **контейнер с деревом тегов (IFD, Image File Directory)**. Каждое изображение описывается набором тегов (числовых, ASCII, рациональных), а сами пиксели лежат в «стрипах» или «тайлах». Из-за гибкости формата здесь масса мест для стеганографии: приватные теги, неиспользуемые поля, лишние `ExtraSamples`, множественные вложенные изображения и дописанные данные после последнего IFD. TIFF лежит в основе RAW-фото, GeoTIFF и медицинских форматов, поэтому навык разбора IFD универсален.

## Структура: заголовок и IFD

TIFF начинается с 8-байтного заголовка, за которым следует первое IFD.

| Смещение | Поле | Размер | Описание |
|---|---|---|---|
| 0x00 | ByteOrder | 2 | `II` (little-endian) или `MM` (big-endian) |
| 0x02 | Magic | 2 | `42` (0x002A) — классический TIFF |
| 0x04 | IFD offset | 4 | смещение первого IFD |
| — | IFD | var | count(2) + записи(count×12) + next-IFD(4) |
| — | entry | 12 | tag(2) type(2) count(4) value/offset(4) |

```bash
file image.tiff
xxd image.tiff | head -4
# 00000000: 4949 2a00 0800 0000 ...   II = little-endian, 42 = TIFF, IFD @ 8
```

## Теги как канал

Каждая запись IFD — это `tag`, `type`, `count`, `value`. Полезные для стего теги:

| Тег | Имя | Назначение |
|---|---|---|
| 270 | ImageDescription | ASCII-описание — классический носитель |
| 305 | Software | имя ПО, часто с версией/комментарием |
| 306 | DateTime | дата/время |
| 315 | Artist | автор |
| 33432 | Copyright | строка с данными |
| 339 | SampleFormat | формат сэмплов |
| 338 | ExtraSamples | лишние каналы (часто 0 = unspecified) |
| 34665 | ExifIFD | указатель на EXIF-поддиректорию |
| 34735 | GeoKeyDirectory | GeoTIFF-ключи |

Приватные теги (диапазон 32768–65535) часто содержат «мусорные» данные — там и прячут.

```bash
# все теги в читаемом виде
exiftool -a -u -g1 image.tiff
# только неизвестные/приватные теги
exiftool -a -u -G image.tiff | grep -iE "unknown|private"
# дамп структуры IFD
tiffinfo image.tiff
tiffdump image.tiff        # подробный дамп всех IFD и записей
```

## Стрипы, тайлы и ExtraSamples

Пиксели в TIFF организованы в стрипы (`StripOffsets`/`StripByteCounts`) или тайлы (`TileOffsets`/`TileByteCounts`). Между стрипами могут быть «дыры» — дописанные байты, не описанные ни одним тегом.

```bash
# карта стрипов и их смещений
python3 - <<'PY'
from PIL import Image
im=Image.open('image.tiff')
print('mode',im.mode,'size',im.size,'n_frames',getattr(im,'n_frames',1))
for k,v in im.tag_v2.items():
    print(hex(k), v)
PY
```

`ExtraSamples` — особенно интересный тег: если изображение объявляет больше сэмплов на пиксель, чем нужно (например, RGBA + 1), лишний канал полностью свободен для данных.

## Множественные изображения (многопанельный TIFF)

TIFF может содержать несколько IFD, связанных полем `next IFD`. Это панели документа, страницы факса или отдельные «скрытые» картинки.

```bash
# извлечь все страницы/панели
tiffsplit image.tiff            # создаст image_aaa.tiff, image_aab.tiff, ...
# или через Pillow
python3 - <<'PY'
from PIL import Image
im=Image.open('image.tiff')
n=getattr(im,'n_frames',1)
for i in range(n):
    im.seek(i)
    im.save(f'page_{i}.png')
    print('saved page',i,im.size)
PY
```

## Разобранный пример

CTF: `scan.tiff` — скан документа.

```bash
$ exiftool -a -u -g1 scan.tiff | head -30
[IFD0] ImageDescription : "nothing to see here"
[IFD0] Software         : "TIFF stego 0x41414141"
[IFD0] Unknown 0xc5f0   : (Binary data 64 bytes, use -b option to extract)

$ exiftool -b -Unknown 0xc5f0 scan.tiff
flag{tiff_private_tags_win}

$ python3 - <<'PY'
from PIL import Image
im=Image.open('scan.tiff')
print('n_frames', getattr(im,'n_frames',1))
PY
n_frames 3
```

Флаг прятался в приватном теге `0xc5f0`. `-b` (binary) вытаскивает «сырое» значение тега. Дальше — `tiffsplit`, чтобы посмотреть остальные панели, и проверка «дыр» между стрипами.

```bash
# поиск дописанных данных между/после стрипов
binwalk scan.tiff
# ручной поиск сигнатур
grep -aboP 'PK\x03\x04|flag\{|Rar!' scan.tiff
```

## Краевые случаи и подводные камни

- **Порядок байт:** `II` vs `MM` — неверное чтение сдвигает все смещения. Всегда проверяй первые 2 байта.
- **BigTIFF:** magic `43` вместо `42` — 64-битные смещения, старые парсеры ломаются.
- **Стрипы с паддингом:** длина стрипа может быть больше, чем нужно пикселям; «хвост» свободен.
- **Тег `value` inline vs offset:** если данные ≤4 байт, они лежат прямо в поле value; иначе — по смещению. Ошибка здесь — частая причина «пустого» анализа.
- **Множественные IFD:** не забудь пройти всю цепочку `next IFD`, иначе пропустишь скрытую панель.

## Что дальше / решение

Пайплайн: `file` (порядок байт) → `exiftool -a -u -g1` (все теги, включая приватные) → `exiftool -b -TAG` для бинарных значений → `tiffdump`/Pillow для дерева IFD → `tiffsplit` для панелей → `binwalk`/`grep -aboP` для дописанных данных. TIFF почти всегда «отдаёт» данные через теги или лишние панели, а не через LSB.

## Справочные таблицы

| Инструмент | Флаг | Назначение |
|---|---|---|
| exiftool | `-a -u -g1` | все теги, включая неизвестные |
| exiftool | `-b -TAG` | извлечь бинарное значение тега |
| tiffinfo | — | краткая сводка IFD |
| tiffdump | — | подробный дамп записей IFD |
| tiffsplit | — | разбить многопанельный TIFF |
| binwalk | `-e` | найти и извлечь вложенные данные |

| Тип тега | Размер | Хранение |
|---|---|---|
| BYTE/SHORT/LONG | 1/2/4 | inline если помещается |
| ASCII | var | offset если >4 байт |
| RATIONAL | 8 | всегда offset |
| UNDEFINED | var | offset |

## BigTIFF и 64-битные смещения

BigTIFF отличается от классического TIFF всего одним байтом magic: `43` вместо `42`, плюс дополнительное поле `offset byte size` и `reserved`. Но следствие важное — все смещения 64-битные, а в заголовке после magic идёт `OffsetSize` и два нулевых байта. Старые парсеры, ожидающие `42`, отказываются открывать такой файл или читают мусор.

```bash
xxd image.tiff | head -2
# 4949 2b00 0800 0000 0000  ->  II, 0x2b=43 (BigTIFF), offsetSize=8
tiffinfo image.tiff          # современный libtiff понимает BigTIFF
```

Для стеганографии BigTIFF даёт больше «места» в смещениях и чаще встречается в огромных сканах/картах, где легко спрятать данные в неиспользуемых областях.

## GeoTIFF: геокоординаты как канал

GeoTIFF добавляет тег `34735` (GeoKeyDirectory), `34736` (GeoDoubleParams) и `34737` (GeoAsciiParams). Это десятки ключей с координатами, проекциями и единицами. В `GeoAsciiParams` можно спрятать строку, а в неиспользуемых ключах — бинарные данные.

```bash
exiftool -a -u -g1 -GeoTiff:all map.tiff
# список ключей
listgeo map.tiff 2>/dev/null | head -30
# сырые значения GeoKeyDirectory
exiftool -b -GeoKeyDirectory map.tiff | xxd | head
```

Прикладной приём: проверить, нет ли в GeoTIFF-ключах «лишних» записей, которых нет в эталонном файле — по diff видно кастомные данные.

## Автоматический обход IFD-цепочки

Ручной разбор утомляет; напишем обходчик, который проходит все IFD (включая `SubIFDs` и цепочку `next IFD`) и печатает теги с нестандартными типами.

```python
import struct
def read_ifds(d, off, seen=None):
    seen = seen or set()
    while off and off not in seen and off+2 <= len(d):
        seen.add(off)
        n = struct.unpack('<H', d[off:off+2])[0]
        print('IFD @', hex(off), 'entries', n)
        for k in range(n):
            e = off+2+k*12
            tag, typ, cnt = struct.unpack('<HHI', d[e:e+8])
            val = struct.unpack('<I', d[e+8:e+12])[0]
            if tag in (330, 34665, 34853):
                read_ifds(d, val, seen)   # рекурсия в поддиректории
        nxt = struct.unpack('<I', d[off+2+n*12:off+6+n*12])[0]
        off = nxt
read_ifds(open('image.tiff','rb').read(), struct.unpack('<I', open('image.tiff','rb').read()[4:8])[0])
```

Такой обходчик находит теги, которые пропускает `tiffinfo`, и позволяет увидеть всю картину целиком.

## Диагностика «пустого» TIFF

Если ни теги, ни панели не дали результата, остаются три систематических места: (1) «дыры» между стрипами (сравните `StripOffsets`+`StripByteCounts` с реальными границами), (2) дописанные данные после последнего IFD (`binwalk`), (3) LSB в несжатых пикселях (TIFF часто без сжатия). Прогоняйте их по очереди и фиксируйте результат в отчёте.

## Что делать при повреждённом IFD

Задачи часто «ломают» TIFF намеренно: испорченный указатель на первый IFD, битый тег или неверное поле `count`. `tiffinfo` в этом случае падает, но данные внутри остаются. Действуйте от структуры:

```bash
# где реально начинается IFD
python3 -c "d=open('broken.tiff','rb').read();import struct;print('first IFD @',hex(struct.unpack('<I',d[4:8])[0]))"
# ручной проход по записям даже при битом next-IFD
python3 - <<'PY'
import struct
d=open('broken.tiff','rb').read()
off=struct.unpack('<I', d[4:8])[0]
n=struct.unpack('<H', d[off:off+2])[0]
print('entries', n)
for k in range(min(n,64)):
    e=off+2+k*12
    tag,typ,cnt=struct.unpack('<HHI', d[e:e+8])
    val=struct.unpack('<I', d[e+8:e+12])[0]
    print(hex(tag), 'type', typ, 'count', cnt, 'val/off', hex(val))
PY
```

Так вы увидите все записи, даже если `next IFD` испорчен. Затем ищите ASCII-теги (270, 305, 315, 33432) по всему файлу через `grep -aboP` и проверяйте «дыры» между стрипами. Повреждение структуры — не приговор: данные обычно на месте, ломается лишь навигация.

## Квиз

```quiz
- question: "Что описывает структура IFD в TIFF?"
  options:
    - "Дерево тегов с записями tag/type/count/value и указателем на следующий IFD"
    - "Только размер файла"
    - "Только палитру"
    - "Только CRC"
  answer: 0
- question: "Что означают первые два байта TIFF `II`?"
  options:
    - "Little-endian порядок байт"
    - "Формат WebP"
    - "Наличие EXIF"
    - "BigTIFF"
  answer: 0
- question: "Зачем нужен флаг `-b` у exiftool?"
  options:
    - "Извлечь «сырое»/бинарное значение тега"
    - "Удалить все теги"
    - "Отсортировать теги"
    - "Сжать файл"
  answer: 0
- question: "Как называется тег с лишними каналами?"
  options:
    - "ExtraSamples"
    - "ImageWidth"
    - "StripOffsets"
    - "XResolution"
  answer: 0
```

## Где пригодится

- **CTF Stego:** TIFF-задачи с тегами и панелями.
- **Форензика:** анализ сканов и факсов.
- **Геоанализ:** разбор GeoTIFF и координат.
- **Работа:** обработка научных и медицинских изображений.
