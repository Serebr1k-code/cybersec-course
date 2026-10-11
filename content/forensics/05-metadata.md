---
id: forensics-metadata
title: "Метаданные: exiftool и скрытые свойства файлов"
category: forensics
parent: forensics-file-magic
difficulty: easy
order: 2
tags: [exiftool, metadata, exif, gps, document, ctf]
prerequisites: [forensics-file-magic]
useful_for:
  - "CTF Forensics категория"
  - "OSINT (геолокация по EXIF)"
  - "Анализ документов"
estimated_minutes: 40
summary: "Извлечение и анализ метаданных изображений, документов, PDF и медиа: exiftool, идентификация автора и геолокации."
---

## Что такое метаданные

Метаданные — это «данные о данных»: кто создал файл, когда, на каком устройстве, где (GPS), каким ПО, с какими настройками. Они встраиваются в контейнеры изображений (EXIF, IPTC, XMP), документов (PDF Info, Office core properties), медиа (ID3, QuickTime atoms). Для форензики метаданные — источник **атрибуции** и **контекста**: они могут выдать автора, устройство, место и время.

## EXIF в изображениях

EXIF (Exchangeable Image File Format) в JPEG/TIFF содержит: Make/Model (устройство), DateTimeOriginal, GPS (широта/долгота/высота), Software, а также Thumbnail (иногда с исходным изображением!).

```bash
exiftool image.jpg
exiftool -a -u -g1 image.jpg        # все теги, включая дубликаты и неизвестные
exiftool -GPS* image.jpg            # только GPS
exiftool -DateTimeOriginal image.jpg
```

**GPS-геолокация:** теги `GPSLatitude`, `GPSLongitude` (в формате DMS), `GPSLatitudeRef` (N/S), `GPSLongitudeRef` (E/W). Конвертация:

```python
def dms_to_dec(dms, ref):
    d, m, s = [float(x) for x in dms]
    dec = d + m/60 + s/3600
    return -dec if ref in ("S", "W") else dec
```

## Скрытые угрозы в метаданных

- **Thumbnail** может содержать исходное (необрезанное) изображение — утечка.
- **XMP** — расширяемый формат (Adobe), часто содержит историю редактирования.
- **Стеганография** в метаданных (скрытые поля, комментарии).
- **Вредоносный EXIF** (эксплуатация парсеров).

```bash
exiftool -b -ThumbnailImage image.jpg > thumb.jpg   # извлечь встроенный thumbnail
exiftool -xmp:all image.jpg
```

## Документы и PDF

- **PDF:** Info-словарь (Author, Creator, Producer, CreationDate), XMP-метаданные, встроенные файлы.
- **Office (docx/xlsx):** `docProps/core.xml`, `docProps/app.xml` — автор, компания, время, редакции.
- **ODF:** `meta.xml`.

```bash
exiftool document.pdf
exiftool document.docx
# PDF: подробнее через pdfinfo
pdfinfo document.pdf
# Office: распаковать и посмотреть XML
unzip -p document.docx docProps/core.xml
```

## Медиа: ID3, QuickTime, MP4

```bash
exiftool audio.mp3        # ID3: artist, album, comment, embedded art
exiftool video.mp4        # QuickTime atoms: creation time, GPS, device
mediainfo video.mp4
ffprobe video.mp4         # метаданные потоков
```

**ffprobe** показывает кодеки, длительность, метаданные потоков; в MP4 может быть GPS (для дронов/камер).

## Практический пример: OSINT по фото

```bash
# 1. Извлекаем все метаданные
exiftool -a -u -g1 photo.jpg > meta.txt
# 2. Ищем GPS
grep -i gps meta.txt
# 3. Если GPS есть — конвертируем в десятичные и смотрим на карте
# 4. Смотрим Make/Model/Software — устройство и ПО
# 5. Дата/время — хронология
```

Даже без GPS устройство и время могут локализовать событие (например, часовой пояс в дате, модель камеры).

## Инструменты и команды

```bash
sudo apt install exiftool mediainfo ffmpeg
exiftool -csv -r /evidence > all_meta.csv    # рекурсивно по папке
exiftool -all= image.jpg                     # УДАЛИТЬ все метаданные (для приватности)
```

## EXIF детально: структура и теги

EXIF хранится в JPEG в APP1-сегменте, в TIFF (отдельный блок), в PNG — редко (XMP в `iTXt`). Основные IFD: `IFD0` (Make, Model, Software, DateTime), `ExifIFD` (DateTimeOriginal, ExposureTime, FNumber, ISO, LensModel), `GPSIFD`.

```bash
exiftool -G1 -a -s image.jpg          # с именами групп
exiftool -json image.jpg | jq .       # JSON-вывод для скриптов
exiftool -Make -Model -DateTimeOriginal -GPSPosition image.jpg
```

Тонкости:

- **`-a`** показывает дубликаты тегов (разные группы).
- **`-u`** — неизвестные теги.
- **`-g1`** — группировка.
- **`-b -ThumbnailImage`** — извлечь thumbnail.
- **`-XMP:all`** — XMP.

## OSINT-workflow по фото

1. **`exiftool -a -u -g1`** — полный дамп.
2. **GPS** → конвертировать в десятичные → карта.
3. **Make/Model** → устройство.
4. **Software** → редактор/версия (может выдать).
5. **DateTimeOriginal** → время и часовой пояс.
6. **Thumbnail** → сравнить с основным (обрезка?).
7. **Перекрёстная проверка** с другими источниками.

Если GPS вырезан, но остался **thumbnail с GPS** — утечка. Если GPS удалён из EXIF, но есть в XMP — тоже.

## Анти-форензика метаданных

- **`exiftool -all=`** — удалить все теги (но thumbnail/структура могут остаться).
- **Пересохранение** в редакторе (часто **добавляет** свои метаданные!).
- **Подделка**: `exiftool -DateTimeOriginal="..." -Make="..." image.jpg`.
- **Стриппинг при загрузке** (соцсети удаляют EXIF, но добавляют свои).

Признаки подделки: несоответствие Software и стиля файла, странные даты, несовпадение thumbnail и основного изображения, GPS не соответствует сцене.

## Метаданные в других форматах

- **Видео (MP4/MOV):** QuickTime atoms — `©mak` (производитель), `©mod` (модель), `©day` (дата), `©xyz` (GPS). `ffprobe -show_format -show_streams video.mp4`.
- **Аудио (MP3):** ID3v2 (TIT2, TPE1, COMM, APIC — обложка), `id3v2 -l audio.mp3`.
- **Изображения WebP/HEIC:** EXIF внутри RIFF/ISO-BMFF.
- **Архивы:** комментарии ZIP/RAR, timestamps файлов.
- **Git:** автор/коммиттер в объектах (`git log --format=fuller`).
- **Docker:** `LABEL`, `MAINTAINER` в образе (`docker inspect`).

## Инструменты и команды

```bash
sudo apt install exiftool mediainfo ffmpeg libimage-exiftool-perl
exiftool -csv -r /evidence > meta.csv
exiftool -json -r /evidence > meta.json
exiftool -a -u -g1 -s image.jpg
exiftool -b -ThumbnailImage image.jpg > thumb.jpg
# Пакетно: удалить метаданные
exiftool -all= -r /evidence/photos/
# PDF
pdfinfo doc.pdf; exiftool doc.pdf
# Office
unzip -p doc.docx docProps/core.xml
```

## Метаданные и приватность: практические риски

- **Фото с телефона** содержат GPS по умолчанию — публикация выдаёт адрес.
- **Документы Office** содержат автора, организацию, пути (`C:\Users\...`), историю редакций.
- **PDF** — Producer/Creator, иногда имя пользователя и ПО.
- **Скриншоты** могут содержать имя пользователя в пути.
- **Соцсети** обычно стриппят EXIF, но **не всегда** (исторически были утечки).
- **Архивы** сохраняют timestamps и имена.

Для защиты: `exiftool -all= file`, проверка перед публикацией, использование редакторов без записи метаданных.

## XMP: расширяемые метаданные

XMP (Extensible Metadata Platform, Adobe) — RDF/XML-метаданные, встраиваемые в JPEG/TIFF/PDF/PNG. Часто **богаче** EXIF: содержит историю редактирования, инструменты, ключевые слова, автора, рейтинги.

```bash
exiftool -xmp:all image.jpg
exiftool -XMP-xmpMM:History image.jpg    # история редактирования
```

XMP может содержать `xmpMM:DerivedFrom` (из какого файла создан), `photoshop:History` — цепочку изменений. Это ключ к вопросу «редактировалось ли фото».

## Итог

Метаданные — быстрый и часто недооценённый источник: они дают автора, устройство, время, место и историю редактирования без сложного анализа. Начинайте любую задачу с файлами с `exiftool -a -u -g1`, проверяйте GPS и thumbnail, не забывайте про документы и медиа. Помните: метаданные **подделываемы**, поэтому важны перекрёстные подтверждения.

## Частые ошибки

- **Смотреть только базовые теги.** Используйте `-a -u -g1` для полного вывода.
- **Игнорировать thumbnail.** Там может быть исходное изображение.
- **Забывать про XMP.** Часто богаче EXIF.
- **Не проверять документы/PDF.** Там тоже метаданные.
- **Путать CreationDate и ModifyDate.** Разные события.
- **Доверять метаданным без проверки.** Их можно подделать (`exiftool -tagsfromfile`).

## Как не застрять

- **`exiftool -a -u -g1`** — полный дамп.
- **GPS** — сразу конвертируйте в десятичные.
- **Thumbnail** — извлеките и сравните.
- **Документы** — распакуйте и посмотрите XML.
- **Медиа** — ffprobe/mediainfo.
- **Помните:** метаданные подделываемы — нужны перекрёстные подтверждения.

## Квиз

```quiz
- question: "Какой инструмент извлекает метаданные изображений?"
  options:
    - "exiftool"
    - "nmap"
    - "john"
    - "sqlmap"
  answer: 0
- question: "Что может содержать встроенный thumbnail?"
  options:
    - "ничего"
    - "уменьшенную копию, иногда исходное (необрезанное) изображение"
    - "только цвет"
    - "вирус"
  answer: 1
- question: "В каком теге EXIF хранится геолокация?"
  options:
    - "DateTime"
    - "GPSLatitude/GPSLongitude"
    - "Make"
    - "Software"
  answer: 1
- question: "Где метаданные в docx?"
  options:
    - "в самом тексте"
    - "в docProps/core.xml и docProps/app.xml"
    - "в images/"
    - "нет метаданных"
  answer: 1
- question: "Как удалить все метаданные из файла exiftool-ом?"
  options:
    - "exiftool -read"
    - "exiftool -all= file"
    - "exiftool -gps"
    - "exiftool -csv"
  answer: 1
```

## Где пригодится

- **CTF Forensics** — флаги в метаданных, геолокация.
- **OSINT** — определение места/времени/устройства по фото.
- **DFIR** — атрибуция документов, поиск следов редактирования.
- **Журналистика** — проверка подлинности медиа.
- **Пентест** — утечки через метаданные (авторы, пути, ПО).
