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

## Вопрос, с которого всё начинается

В задаче дан `vacation.jpg` — обычная фотография гор. Ты открываешь её, смотришь на пиксели — ничего. `zsteg` пусто. Но у любой фотографии с телефона есть **метаданные**: модель камеры, дата, координаты. Может, флаг прямо там?

Ответ: часто да. Метаданные — самый быстрый источник данных в CTF: одна команда `exiftool` показывает десятки полей. Разберём это на нашей фотографии.

## Наш пример: vacation.jpg

**Метаданные** — служебная информация о файле, которая не является частью изображения. У фотографий это несколько пакетов: **EXIF** (теги камеры, TIFF/IFD + MakerNote), **XMP** (XML-пакет), **IPTC** (для прессы). Плюс почти в каждом JPEG лежит **встроенное превью** — отдельная маленькая картинка.

## Шаг 1: читаем всё сразу

Первое правило — не останавливаться на первом экране вывода. Флаг может быть в «неизвестном» теге:

```bash
$ exiftool -a -u -g1 vacation.jpg | grep -iE "comment|description|unknown|gps"
[EXIF] ImageDescription : "Mountain trip"
[EXIF] UserComment      : "flag{exif_usercomment}"
[GPS]  GPSPosition      : 48 deg 51' 24.00" N, 2 deg 17' 40.00" E
```

Флаги `exiftool`: `-a` показывает **все** теги (включая дубли), `-u` включает **неизвестные**, `-g1` группирует по таблице. Уже нашли флаг в `UserComment`.

## Шаг 2: XMP и IPTC

**XMP** — XML-пакет (RDF), **IPTC** — бинарный блок для прессы:

```bash
$ exiftool -xmp -b vacation.jpg > out.xmp && xmllint --format out.xmp
$ exiftool -IPTC:all -g1 vacation.jpg
```

XMP — это XML, поэтому его удобно читать и `grep`-ать:

```bash
$ exiftool -xmp -b vacation.jpg | grep -iE 'flag|secret|hidden'
```

## Шаг 3: GPS и геолокация

GPS-теги — прямой путь к геолокации, классика OSINT:

```bash
$ exiftool -n -GPSLatitude -GPSLongitude vacation.jpg
GPS Latitude  : 48.856
GPS Longitude : 2.297
```

Флаг `-n` выводит координаты числами (десятичные градусы), а не в формате «градусы-минуты-секунды».

## Шаг 4: стеганография во встроенном превью

Ключевой «скрытый» слой: **EXIF-превью** — полноценный JPEG, и в нём можно спрятать сообщение LSB-методом, которое не видно на основном изображении.

```bash
$ exiftool -b -ThumbnailImage vacation.jpg > t.jpg
$ zsteg t.jpg
[+] b1,rgb,lsb,xy .. text: "flag{exif_thumbnail}"
```

`-b` выводит **бинарное** значение тега. Извлекли превью, прогнали `zsteg` — второй флаг. Такой «двойной» приём типичен: беглый `exiftool` находит первый, внимательный анализ — второй.

## Шаг 5: MakerNote и бинарные теги

**MakerNote** — приватный блок производителя с вложенными IFD и свободным местом. Его надо извлекать через `-b` и смотреть `strings`:

```bash
$ exiftool -b -MakerNoteCanon vacation.jpg > mn.bin
$ strings -n 6 mn.bin | head
$ exiftool -a -u -b vacation.jpg | strings -n 6 | grep -i flag
```

## Шаг 6: EXIF в PNG, WebP и HEIC

EXIF-структура есть не только в JPEG:

| Формат | Где EXIF | Где XMP |
|---|---|---|
| JPEG | APP1 (`FFE1`) | APP1 |
| PNG | чанк `eXIf` | чанк `iTXt` |
| WebP | чанк `EXIF` | чанк `XMP ` |
| HEIC | item в meta | item в meta |

```bash
$ pngcheck -v image.png | grep -i exif
$ exiftool -a -u -g1 image.png
```

Практический вывод: прогоняй `exiftool` по **любому** формату, метаданные есть почти везде.

## Полный прогон на vacation.jpg

Соберём всё в один воспроизводимый прогон. Возьмём `vacation.jpg`, впишем в него теги и посмотрим, что вернёт `exiftool`:

```bash
$ exiftool -overwrite_original \
    -EXIF:UserComment="flag{exif_usercomment}" \
    -ImageDescription="Mountain trip" \
    -GPSLatitude=48.856 -GPSLatitudeRef=N \
    -GPSLongitude=2.297 -GPSLongitudeRef=E \
    -ThumbnailImage'<='thumb.jpg vacation.jpg

$ exiftool -a -u -g1 vacation.jpg | grep -iE "comment|description|gps|thumbnail"
Image Description               : Mountain trip
User Comment                    : flag{exif_usercomment}
GPS Latitude                    : 48 deg 51' 21.60" N
GPS Position                    : 48 deg 51' 21.60" N, 2 deg 17' 49.20" E
Thumbnail Offset                : 450
Thumbnail Length                : 633
Thumbnail Image                 : (Binary data 633 bytes, use -b option to extract)
```

Обрати внимание на две вещи. Во-первых, `User Comment` — это тот самый «неизвестный» тег, который пропускают, если читать только первый экран вывода. Во-вторых, строка `Thumbnail Image` — не картинка, а *ссылка*: чтобы получить сами байты, нужен `-b`.

Вытащим превью и прогоним по нему отдельный анализ — это самостоятельный носитель:

```bash
$ exiftool -b -ThumbnailImage vacation.jpg > t.jpg && ls -l t.jpg
-rw-r--r-- 1 user user 633 ... t.jpg
```

Теперь XMP. Он же XML, поэтому его видно глазами и удобно `grep`-ать:

```bash
$ exiftool -xmp -b vacation.jpg | head -3
<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>
<x:xmpmeta xmlns:x='adobe:ns:meta/' x:xmptk='Image::ExifTool 13.55'>
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
```

Порядок действий в задаче получается такой: `exiftool -a -u -g1` (все теги) → `-b` по подозрительным (превью, MakerNote, Unknown) → прогон вытащенного файла через `zsteg`/`strings`. Три шага покрывают почти все CTF-задачи на метаданные.

## Если не сработало

- **Остановился на первом экране** — без `-a -u` не увидишь неизвестные теги и дубликаты.
- **Не использовал `-b`** — бинарные значения (MakerNote, Unknown, Thumbnail) не печатаются как текст.
- **Игнорировал встроенное превью** — это отдельный носитель.
- **Проблемы с кодировкой** — `UserComment` бывает UTF-16; используй `-charset utf8`.
- **Вера в «очистку»** — `-all=` не убирает «дыры» и старые превью.
- **Один формат** — метаданные есть в PNG/WebP/HEIC/TIFF.

## Справочные таблицы

| Флаг exiftool | Назначение |
|---|---|
| `-a` | показать все теги (включая дубли) |
| `-u` | включить неизвестные теги |
| `-g1` | сгруппировать по таблице |
| `-b` | вывести бинарное значение |
| `-n` | числовые значения (GPS в градусах) |
| `-xmp -b` | весь XMP-пакет |

| Пакет | Формат | Типичные поля |
|---|---|---|
| EXIF | TIFF/IFD | Make, Model, DateTime, GPS |
| XMP | XML/RDF | CreatorTool, description |
| IPTC | бинарный IMM | By-line, Caption, Keywords |
| MakerNote | приватный | серийники, счётчик затвора |

## Анонимизация и что она не удаляет

Типовая «очистка» (`exiftool -all=`) не всегда полна: остаются миниатюры, MakerNote, комментарии в нестандартных чанках и XMP-дубликаты. В CTF это как раз то, что ищут.

```bash
$ cp image.jpg clean.jpg && exiftool -all= clean.jpg
$ exiftool -a -u -g1 image.jpg > before.txt
$ exiftool -a -u -g1 clean.jpg > after.txt
$ diff before.txt after.txt
```

Обрати внимание: `-all=` убирает теги, но не «дыры» в файле и не встроенные превью, оставшиеся от старой версии.

## Автоматический пайплайн

```python
import subprocess, re
def scan(path):
    out = subprocess.run(['exiftool','-a','-u','-g1','-charset','utf8',path],
                         capture_output=True, text=True).stdout
    hits = [l for l in out.splitlines()
            if re.search(r'flag|ctf|secret|pass|key', l, re.I)]
    raw = subprocess.run(['exiftool','-a','-u','-b',path], capture_output=True).stdout
    strs = re.findall(rb'[ -~]{6,}', raw)
    return hits, [s.decode() for s in strs if re.search(rb'flag|ctf', s, re.I)]
```

Скрипт закрывает и обычные теги, и бинарные значения (MakerNote, Unknown), которые `exiftool` не печатает как текст.

## Практика: пишем и читаем EXIF сами

Проверим метаданные на живом файле. Сделаем обычный JPEG и впишем в него теги через exiftool — ровно так, как это делают, когда прячут данные:

```bash
$ exiftool -overwrite_original -UserComment='flag{exif_usercomment}' \
    -ImageDescription='Mountain trip' -XMP-dc:Description='flag{xmp_hidden}' \
    -GPSLatitude=48.856 -GPSLatitudeRef=N -GPSLongitude=2.297 -GPSLongitudeRef=E vacation.jpg
$ exiftool -a -u -g1 vacation.jpg | grep -iE "comment|description|gps"
[EXIF] Image Description             : Mountain trip
[EXIF] User Comment                  : flag{exif_usercomment}
---- GPS ----
[GPS]  GPS Latitude Ref              : North
[GPS]  GPS Latitude                  : 48 deg 51' 21.60"
[GPS]  GPS Longitude                 : 2 deg 17' 49.20"
[XMP]  Description                   : flag{xmp_hidden}
```

Здесь видно ключевое: один и тот же `exiftool` отдаёт данные из **разных пакетов** — `User Comment` живёт в EXIF, а `Description` в XMP, и это два разных тега с похожими именами. Если запустить просто `exiftool vacation.jpg` без `-a -u -g1`, второй тег может перекрыть первый и остаться незамеченным. Отсюда правило: сначала `-a -u -g1`, потом `grep`.

## Что мы теперь знаем

1. Метаданные — **быстрый первый шаг** любой стего-задачи.
2. `exiftool -a -u -g1` показывает всё, включая неизвестные теги.
3. **XMP** (XML) и **IPTC** — отдельные пакеты, читаются `-xmp -b`/`-IPTC:all`.
4. **GPS** даёт геолокацию; `-n` — числовые координаты.
5. **Встроенное превью** — отдельный носитель для LSB-стего.

## Квиз

Проверь себя.

```quiz
- question: "В каком маркере JPEG обычно лежит EXIF?"
  options:
    - "APP1 (FFE1)"
    - "APP0 (FFE0)"
    - "SOI (FFD8)"
    - "EOI (FFD9)"
  answer: 0
  explanation: "EXIF хранится в APP1-сегменте с заголовком Exif."
- question: "Зачем нужен флаг exiftool -b?"
  options:
    - "Вывести бинарное/сырое значение тега"
    - "Отсортировать теги"
    - "Удалить метаданные"
    - "Сжать файл"
  answer: 0
  explanation: "Без -b бинарные теги (MakerNote, Thumbnail) не печатаются как текст."
- question: "Что такое EXIF-превью и почему оно важно?"
  options:
    - "Встроенная JPEG-картинка, которая сама может быть носителем"
    - "Пароль от файла"
    - "CRC-сумма"
    - "Аудиодорожка"
  answer: 0
  explanation: "Превью — отдельный JPEG, в нём можно спрятать LSB-данные."
- question: "Каким форматом чаще всего является XMP?"
  options:
    - "XML/RDF"
    - "бинарный IMM"
    - "RIFF"
    - "ISOBMFF"
  answer: 0
  explanation: "XMP — это XML-пакет, удобно читать и grep-ать."
- question: "Что выводит флаг exiftool -n для GPS?"
  options:
    - "Числовые (десятичные) координаты"
    - "Название места"
    - "Часовой пояс"
    - "Высоту над уровнем моря"
  answer: 0
  explanation: "-n переводит координаты в десятичные градусы."
```

## Куда дальше

Мы разобрали метаданные. Дальше — **файловые системы** и служебные области, где данные прячут в «пустом» месте диска. А пока запомни: перед любым анализом прогони `exiftool -a -u -g1`.

## Где пригодится

- **CTF:** быстрый поиск флагов в метаданных.
- **OSINT:** геолокация и идентификация камеры.
- **Форензика:** установление источника и истории файла.
- **Bug bounty:** утечки через метаданные загружаемых изображений.
