---
id: stego-exif-xmp
title: "Метаданные глубоко: EXIF, XMP, IPTC и стеганография в превью"
category: stego
parent: stego-metadata-watermark
difficulty: easy
order: 1
tags: [stego, exif, xmp, iptc, makernote, gps, thumbnail, metadata]
prerequisites: [stego-image-tools]
useful_for:
  - "CTF Stego/Forensics: метаданные"
  - "OSINT: геолокация по EXIF"
  - "Форензика фотографий"
estimated_minutes: 50
summary: "Полный разбор метаданных: EXIF-теги и MakerNote, XMP и IPTC, GPS, комментарии и стеганография во встроенном EXIF-превью — со всеми флагами exiftool."
---

Метаданные — самый быстрый источник данных в CTF и форензике: `exiftool` одной командой показывает десятки полей, среди которых часто прячется флаг. Но метаданные — это не один блок: JPEG/HEIF используют **EXIF** (теги TIFF/IFD + MakerNote), **XMP** (XML-пакет RDF) и **IPTC** (IMM, для прессы). Плюс почти в каждом JPEG лежит **встроенное EXIF-превью** — отдельная JPEG-картинка, которую тоже можно использовать как носитель. Здесь важно уметь вычитывать всё и не остановиться на первом экране вывода.

## EXIF: где живёт и как читать

EXIF в JPEG — это APP1-маркер (`FFE1`) с заголовком `Exif\0\0`, затем TIFF-структура (IFD). Отсюда и связь с уроком по TIFF: теги те же.

```bash
# всё, включая неизвестные теги, сгруппировано
exiftool -a -u -g1 image.jpg
# только EXIF
exiftool -EXIF:all image.jpg
# конкретные поля
exiftool -Comment -ImageDescription -UserComment -Artist -Copyright image.jpg
# показать теги, которые exiftool не знает (часто там данные)
exiftool -a -u image.jpg | grep -iE "unknown|undef"
```

## XMP и IPTC

XMP — XML-пакет (RDF), может лежать и в JPEG APP1, и в HEIF, и в sidecar-файле `.xmp`. IPTC — бинарный IMM-блок для прессы (автор, заголовок, ключевые слова).

```bash
# весь XMP
exiftool -xmp -b image.jpg
# структурированно
exiftool -XMP:all -g1 image.jpg
# IPTC
exiftool -IPTC:all -g1 image.jpg
# извлечь XMP в файл и посмотреть
exiftool -xmp -b image.jpg > out.xmp && xmllint --format out.xmp
```

## GPS и геолокация

GPS-теги (lat/lon) — прямой путь к геолокации, классика OSINT.

```bash
exiftool -GPS:all image.jpg
# десятичные координаты
exiftool -n -GPSLatitude -GPSLongitude image.jpg
# все GPS-теги в читаемом виде
exiftool -a -u -g1 -GPS:all image.jpg
```

## Стеганография во встроенном превью

Это ключевой «скрытый» слой: EXIF-превью — полноценный JPEG, и в нём можно спрятать сообщение LSB-методом, которое не видно на основном изображении.

```bash
# извлечь встроенное превью
exiftool -b -ThumbnailImage image.jpg > thumb.jpg
exiftool -b -PreviewImage image.jpg > preview.jpg
# проверить его как отдельный файл
zsteg thumb.jpg
steghide info thumb.jpg
```

## MakerNote и «мусорные» теги

MakerNote — приватный блок производителя. Он может содержать вложенные IFD, неиспользуемые поля и просто свободное место.

```bash
# вытащить MakerNote целиком
exiftool -b -MakerNoteCanon image.jpg > mn.bin
strings -n 6 mn.bin | head
# все бинарные теги
exiftool -a -u -b image.jpg | strings -n 6 | grep -i flag
```

## Разобранный пример

CTF: `vacation.jpg`.

```bash
$ exiftool -a -u -g1 vacation.jpg | grep -iE "comment|description|unknown|gps"
[EXIF] ImageDescription : "Mountain trip"
[EXIF] UserComment      : "flag{exif_usercomment}"
[GPS]  GPSPosition      : 48 deg 51' 24.00\" N, 2 deg 17' 40.00\" E

$ exiftool -b -ThumbnailImage vacation.jpg > t.jpg
$ zsteg t.jpg
b1,rgb,lsb,xy .. text: "flag{exif_thumbnail}"
```

Два флага: один в `UserComment`, второй — в LSB встроенного превью. Такой «двойной» приём типичен: беглый `exiftool` находит первый, внимательный анализ — второй.

```bash
# сводный пайплайн поиска строк в метаданных
exiftool -a -u -b image.jpg 2>/dev/null | strings -n 5 | grep -iE 'flag|ctf|secret|pass'
exiftool -xmp -b image.jpg | grep -iE 'flag|secret'
```

## Краевые случаи и подводные камни

- **Дублирование тегов:** JPEG может содержать несколько APP1-блоков (EXIF и XMP) — читай все.
- **`-b` (binary):** нужен для значений, которые exiftool не печатает как текст (MakerNote, Unknown).
- **Обрезанные метаданные:** соцсети вырезают EXIF — если файл «чистый», возможно, его прогнали через re-encode.
- **Кодировки:** `UserComment` может быть UTF-16 — `strings` не всё покажет, используй `-charset`.
- **Встроенное превью vs основное:** превью может остаться от старой версии картинки — это тоже сигнал.

## Что дальше / решение

Пайплайн: `exiftool -a -u -g1` (всё) → `-b -TAG` для бинарных (MakerNote, Unknown, Thumbnail) → `-xmp -b` и `-IPTC:all` → `-GPS:all -n` → извлечь и прогнать **все** встроенные превью через `zsteg`/`steghide` → `strings` по бинарным тегам. Метаданные — обязательный первый шаг: одна команда, а иногда и флаг.

## Справочные таблицы

| Флаг exiftool | Назначение |
|---|---|
| `-a` | показать все теги (включая дубли) |
| `-u` | включить неизвестные теги |
| `-g1` | сгруппировать по таблице |
| `-b` | вывести бинарное значение |
| `-n` | числовые значения (GPS в градусах) |
| `-EXIF:all` | только EXIF |
| `-xmp -b` | весь XMP-пакет |
| `-charset utf8` | корректная кодировка |

| Пакет | Формат | Типичные поля |
|---|---|---|
| EXIF | TIFF/IFD | Make, Model, DateTime, GPS |
| XMP | XML/RDF | CreatorTool, description |
| IPTC | бинарный IMM | By-line, Caption, Keywords |
| MakerNote | приватный | серийники, счётчик затвора |

## EXIF в PNG, WebP и HEIC

EXIF-структура (TIFF/IFD) встречается не только в JPEG. PNG хранит его в чанке `eXIf` (или в `tEXt`/`zTXt` как текст), WebP — в чанке `EXIF`, HEIC — как отдельный item. Инструмент `exiftool` читает всё, но пути разные, и это важно для скриптов.

| Формат | Где EXIF | Где XMP |
|---|---|---|
| JPEG | APP1 (`FFE1`) | APP1 |
| PNG | чанк `eXIf` | чанк `iTXt` |
| WebP | чанк `EXIF` | чанк `XMP ` |
| HEIC | item в meta | item в meta |
| TIFF | IFD | тег 700 |

```bash
# PNG: список чанков и EXIF-чанк
pngcheck -v image.png | grep -i exif
exiftool -a -u -g1 image.png
# WebP
exiftool -EXIF:all image.webp
```

Практический вывод: не ограничивайтесь JPEG — прогоняйте `exiftool` по любому формату, метаданные есть почти везде.

## Анонимизация и что она не удаляет

Типовая «очистка» метаданных (`exiftool -all=`) не всегда полна: остаются миниатюры, MakerNote, комментарии в нестандартных чанках, XMP-дубликаты и «мусор» после перепаковки. В CTF это как раз то, что ищут.

```bash
# полная очистка (для понимания, что исчезнет)
cp image.jpg clean.jpg && exiftool -all= clean.jpg
# сравнить до/после
exiftool -a -u -g1 image.jpg > before.txt
exiftool -a -u -g1 clean.jpg > after.txt
diff before.txt after.txt
# принудительно сохранить группу
exiftool -all= -tagsfromfile image.jpg -EXIF:all clean.jpg
```

Обратите внимание: `-all=` убирает теги, но не «дыры» в файле и не встроенные превью, оставшиеся от старой версии. Проверяйте и их.

## Автоматический пайплайн метаданных

Скрипт собирает все текстовые метаданные и ищет подозрительные строки — экономит время на больших наборах файлов.

```python
import subprocess, re
def scan(path):
    out=subprocess.run(['exiftool','-a','-u','-g1','-charset','utf8',path],
                       capture_output=True,text=True).stdout
    hits=[l for l in out.splitlines()
          if re.search(r'flag|ctf|secret|pass|key|hidden', l, re.I)]
    # бинарные теги
    raw=subprocess.run(['exiftool','-a','-u','-b',path],capture_output=True).stdout
    strs=re.findall(rb'[ -~]{6,}', raw)
    return hits, [s.decode() for s in strs if re.search(rb'flag|ctf|secret', s, re.I)]
for f in ['a.jpg','b.png','c.webp']:
    print(f, scan(f))
```

Скрипт закрывает и обычные теги, и бинарные значения (MakerNote, Unknown), которые `exiftool` не печатает как текст.

## Ловушки метаданных

- **Несколько APP1:** JPEG может содержать и EXIF, и XMP; `-a` покажет оба, а обычный `exiftool` — только первый.
- **Кодировки:** `UserComment` бывает UTF-16 — используйте `-charset`.
- **«Пустые» теги:** тег присутствует, но значение пустое; проверяйте `-b` для бинарных.
- **Метаданные в миниатюре:** у встроенного превью свои метаданные — читайте и его тоже.

## Разобранный пример 2: GPS и XMP

Задача: `city.jpg`, найти скрытую информацию.

```bash
$ exiftool -GPS:all -n city.jpg
GPS Latitude  : 55.755826
GPS Longitude : 37.617300

$ exiftool -xmp -b city.jpg > out.xmp
$ grep -iE 'flag|secret|hidden' out.xmp
<rdf:li>flag{xmp_packet_stego}</rdf:li>
```

Первый слой — GPS-координаты (в CTF это может быть подсказкой «место»), второй — XMP-пакет, в котором лежит флаг. XMP — это XML, поэтому его удобно читать и `grep`-ать. Если XMP «пуст», проверьте `-IPTC:all` и `UserComment`; если и там пусто — извлеките встроенное превью и прогоните `zsteg`.

Обратите внимание: `exiftool` по умолчанию показывает только один XMP-блок. Используйте `-a` (все) и `-g1` (группировка), чтобы увидеть дубликаты: злоумышленник мог записать данные во второй XMP-блок, который обычный просмотр не покажет. Разница между блоками — сама по себе сигнал.

## Частые ошибки и как их избежать

- **Остановиться на первом экране `exiftool`:** без `-a -u` вы не увидите неизвестные теги и дубликаты, а данные часто именно там.
- **Не использовать `-b`:** бинарные значения (MakerNote, Unknown, Thumbnail) не печатаются как текст; без `-b` вы их пропустите.
- **Игнорировать встроенное превью:** это отдельный носитель; прогоняйте его через `zsteg`/`steghide`.
- **Проблемы с кодировкой:** `UserComment` бывает UTF-16; используйте `-charset utf8` и `strings` с `-e l`.
- **Вера в «очистку»:** `-all=` не убирает «дыры» и старые превью; проверяйте их отдельно.
- **Один формат:** метаданные есть в PNG/WebP/HEIC/TIFF, не только в JPEG; применяйте `exiftool` ко всему.

Практический порядок: `exiftool -a -u -g1` → `-b -TAG` для бинарных → `-xmp -b`, `-IPTC:all`, `-GPS:all -n` → извлечь и проверить **все** встроенные превью → `strings` по бинарным тегам. Такой проход закрывает подавляющее большинство метаданных-задач за один цикл.

## Квиз

```quiz
- question: "В каком маркере JPEG обычно лежит EXIF?"
  options:
    - "APP1 (FFE1)"
    - "APP0 (FFE0)"
    - "SOI (FFD8)"
    - "EOI (FFD9)"
  answer: 0
- question: "Зачем нужен флаг exiftool -b?"
  options:
    - "Вывести бинарное/сырое значение тега"
    - "Отсортировать теги"
    - "Удалить метаданные"
    - "Сжать файл"
  answer: 0
- question: "Что такое EXIF-превью и почему оно важно?"
  options:
    - "Встроенная JPEG-картинка, которая сама может быть носителем"
    - "Пароль от файла"
    - "CRC-сумма"
    - "Аудиодорожка"
  answer: 0
- question: "Каким форматом чаще всего является XMP?"
  options:
    - "XML/RDF"
    - "бинарный IMM"
    - "RIFF"
    - "ISOBMFF"
  answer: 0
```

## Где пригодится

- **CTF:** быстрый поиск флагов в метаданных.
- **OSINT:** геолокация и идентификация камеры.
- **Форензика:** установление источника и истории файла.
- **Bug bounty:** утечки через метаданные загружаемых изображений.
