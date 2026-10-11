---
id: osint-metadata
title: "Метаданные файлов и документов"
category: osint
parent: osint-infra-artifacts
difficulty: medium
order: 3
tags: [exiftool, metadata, exif, pdf, office, forensics]
prerequisites: [osint-infrastructure]
useful_for:
  - "Извлечение скрытых данных из файлов"
  - "CTF-задачи с вложенными метаданными"
estimated_minutes: 40
summary: "EXIF изображений, метаданные PDF/Office, GPS, имена авторов, скрытые комментарии и очистка метаданных."
---

Почти каждый файл несёт «невидимую» информацию о том, **кто, когда и чем** его создал. Для OSINT это один из самых быстрых источников фактов: имя автора, GPS-координаты, модель камеры, версия ПО, внутренние пути. В этом уроке — практические приёмы извлечения и очистки метаданных.

## exiftool — главный инструмент

```bash
# всё, что есть в файле
exiftool image.jpg

# только GPS
exiftool -gps:all image.jpg

# конкретные поля
exiftool -Make -Model -Software -DateTimeOriginal -Artist image.jpg

# рекурсивно по директории
exiftool -r -csv ./photos > metadata.csv
```

`exiftool` поддерживает **сотни** форматов: JPEG, PNG, TIFF, HEIC, PDF, DOCX/XLSX/PPTX, MP3/MP4 и многое другое.

## Что искать в изображениях (EXIF)

| Поле | Значение |
|---|---|
| `GPSLatitude`/`GPSLongitude` | координаты съёмки |
| `Make`/`Model` | модель камеры/телефона |
| `Software` | чем обрабатывали (Photoshop, приложение) |
| `DateTimeOriginal` | время съёмки |
| `Artist`/`Copyright` | имя автора |
| `SerialNumber` | серийный номер камеры (уникален!) |
| `LensModel` | объектив |
| `ImageDescription`/`UserComment` | произвольный текст (часто флаг/заметка) |

**GPS** — самый ценный: даёт точные координаты. **SerialNumber** может связать все фото с одной камеры (если публикуются с метаданными).

## PDF и Office-документы

- **PDF**: `exiftool doc.pdf` покажет `Author`, `Creator`, `Producer`, `CreateDate`, а иногда — исходный путь (`/C/Users/...`).
- **DOCX/XLSX** — это ZIP: распакуйте и посмотрите `docProps/core.xml` (автор, ревизии) и `docProps/app.xml` (версия Office, время правок).
- **Удалённый текст**: в Office-файлах иногда остаются удалённые правки и комментарии.

```bash
exiftool report.pdf
unzip -o report.docx -d docx_x/ && cat docx_x/docProps/core.xml
# PDF-вложения и картинки
pdfinfo report.pdf; pdfimages -list report.pdf; pdfdetach -list report.pdf
```

## Скрытые данные и «контейнеры»

Метаданные — не единственное скрытое содержимое файла:

- **Конкатенация**: данные, дописанные после EOF (`binwalk file`, `strings file | tail`).
- **ZIP в изображении**: `binwalk -e image.png`.
- **Стеганография**: LSB, скрытые архивы (см. категорию Stego).
- **Комментарии**: в JPEG-комментарий, в PNG-чанк `tEXt`.
- **Thumbnail**: старый эскиз может показать **предыдущее** содержимое (например, лицо на отредактированном фото).

```bash
exiftool -b -ThumbnailImage image.jpg > thumb.jpg
strings image.jpg | grep -iE 'password|secret|flag'
binwalk image.png
```

## Цепочка анализа файла

1. **Идентификация**: `file suspicious` — что это на самом деле.
2. **Хеши**: `sha256sum suspicious` → проверка на VirusTotal.
3. **Метаданные**: `exiftool suspicious`.
4. **Скрытые слои**: `binwalk -e`, `strings`, `foremost`.
5. **Вложения**: для PDF — `pdfinfo`, `pdfimages`, `pdfdetach`.

## Практический сценарий (типичный CTF)

```bash
file photo.jpg          # JPEG image data
exiftool photo.jpg       # ... Comment: flag{exif_is_fun}
```

или

```bash
exiftool -Comment photo.jpg
strings photo.jpg | grep -i flag
```

## Защита: очистка метаданных

Перед публикацией любых файлов:

```bash
exiftool -all= image.jpg          # удалить все метаданные
exiftool -all= -overwrite_original image.jpg
# для PDF/Office — "Save As" + проверить заново
```

Помните: **вы тоже** оставляете метаданные — скриншоты, документы, фото с телефона. Чистите свои артефакты (см. урок про OPSEC).

## Частые ошибки

- **Смотреть только EXIF изображения** — PDF/Office дают не меньше.
- **Забыть про thumbnail** — он часто хранит «до» редактирования.
- **Не проверять конкатенацию/стего** — данные могут быть после EOF.
- **Верить метаданным как доказательству** — их легко подделать.
- **Не очищать свои файлы** — утечка собственных данных.
- **Не пробовать несколько инструментов** — `exiftool` не всё показывает; нужен `binwalk`/`strings`.

## Продвинутые метаданные и форматы

- **Видео** (MP4/MOV): `exiftool` покажет `CreateDate`, устройство, GPS, а иногда и **software** (чем монтировали).
- **Аудио** (MP3/M4A): теги (ID3) содержат исполнителя, альбом, а иногда комментарии с внутренней информацией.
- **HEIC** (Apple): метаданные богаче JPEG (портрет, глубина, GPS).
- **SVG**: XML-файл, может содержать комментарии и скрипты.
- **Шрифты/PDF-шрифты**: иногда встраивают имена авторов.

```bash
exiftool video.mp4 | grep -iE 'create|gps|software|model'
exiftool -id3:all song.mp3
```

## Сравнение и «отпечаток» камеры

- **SerialNumber**: одинаковый на всех фото с одной камеры — связывает изображения.
- **LensModel + Make/Model**: узкий профиль устройства.
- **Дата/время**: последовательность фото восстанавливает таймлайн.
- **PRNU/шум**: «отпечаток» сенсора (экспертный уровень, forensics).

```bash
# серийник камеры (если есть)
exiftool -SerialNumber -Make -Model *.jpg | sort -u
```

## Очистка и OPSEC

```bash
# удалить все метаданные
exiftool -all= image.jpg
exiftool -all= -overwrite_original image.jpg

# проверить, что осталось
exiftool image.jpg | head
```

Помните: соцсети обычно чистят EXIF при загрузке, но **не всегда** (и не все поля). Скачанные «оригиналы» могут сохранить GPS. Свои файлы чистите **до** публикации.

## exiftool: полный арсенал флагов

`exiftool` — основной инструмент метаданных; важно знать не только базовый вывод.

```bash
exiftool file.jpg                 # все теги (сгруппированные)
exiftool -a -u -g1 file.jpg       # -a: все теги (вкл. дубли), -u: неизвестные, -g1: по группам
exiftool -json file.jpg           # машиночитаемо
exiftool -csv -r ./photos > meta.csv   # рекурсивно в CSV
exiftool -b -ThumbnailImage file.jpg > thumb.jpg   # бинарный тег
exiftool -if '$GPSLatitude' -r ./photos            # только файлы с GPS
exiftool -GPSPosition -n file.jpg  # десятичные координаты
exiftool -G -s -FileName -Model -DateTimeOriginal -r ./dir  # только нужные поля
```

Ключ `-n` печатает числа без форматирования (удобно для скриптов), `-if` фильтрует по условию.

## GPS → карта

```bash
# координаты в десятичном виде
exiftool -n -GPSLatitude -GPSLongitude -GPSAltitude file.jpg
# сгенерировать ссылку на карту
exiftool -GPSPosition -p '$GPSLatitude,$GPSLongitude' file.jpg | \
  awk -F, '{print "https://www.google.com/maps?q="$1","$2}'
# направление съёмки (компас)
exiftool -GPSImgDirection -GPSImgDirectionRef file.jpg
```

GPS-высоту и направление съёмки используют для хроно- и геолокации (osint-chronolocation): по направлению камеры и теням уточняют точку.

## Office, OOXML и PDF

```bash
# Office: автор, организация, шаблон, последний сохранивший
exiftool document.docx | grep -Ei 'author|company|lastModifiedBy|Template|Manager'
# макросы: искать VBA
pip install oletools
olevba suspicious.docm          # извлечь и проанализировать макросы
oleid suspicious.doc            # быстрая оценка «опасности» файла
# PDF
pdfinfo report.pdf
exiftool report.pdf | grep -Ei 'Producer|Creator|Author|CreateDate'
strings report.pdf | grep -Ei 'http|@|key|token' | head
```

В OOXML (`docx/xlsx/pptx` — это zip) метаданные лежат в `docProps/core.xml` и `docProps/app.xml`:

```bash
unzip -p document.docx docProps/core.xml
unzip -p document.docx docProps/app.xml
```

Часто утекают: реальные ФИО авторов, внутренние пути (`C:\Users\<user>\...`), названия шаблонов компании, версии ПО.

## Скрытые данные и контейнеры

Метаданные — не единственное «дно» файла:

```bash
# встроенные/добавленные данные после конца изображения
binwalk file.jpg
# строки в бинарнике
strings -n 8 file.pdf | less
# вложенные файлы в PDF
pdfdetach -list report.pdf
# архивы, склеенные с картинкой (polyglot)
file polyglot.png        # покажет, если это zip/png одновременно
```

Polyglot-файлы (валидные как два формата сразу) — типичный приём в CTF (см. категорию stego).

## Отпечаток камеры и PRNU

Каждый сенсор оставляет слабый шумовой паттерн (**PRNU**), а ПО — свои артефакты. Практически:

- Одинаковый `Make/Model/Software` + `SerialNumber` (если есть) связывает фото с одной камерой.
- `ImageUniqueID`/`DocumentID` — идентификатор конкретного снимка.
- Одинаковые дефектные пиксели/шумовые отпечатки (forensic PRNU-анализ) связывают серию даже после удаления EXIF.

```bash
# извлечь «личность» камеры
exiftool -Make -Model -SerialNumber -Software -LensModel -r ./photos | sort | uniq -c
```

Это ключ для атрибуции: одно устройство → один источник.

## Продвинутые форматы

| Формат | Что искать |
|--------|-----------|
| JPEG | EXIF, XMP, IPTC, комментарии, thumbnail |
| PNG | tEXt/iTXt/zTXt чанки (иногда с паролями/флагами) |
| HEIC/HEIF | Apple-метаданные, Live Photo ссылки |
| MP4/MOV | GPS-трек, устройство, creation_time |
| WAV/FLAC | теги, комментарии |
| SVG | комментарии, скрипты, метаданные редактора |

```bash
# все PNG-чанки
pngcheck -v image.png
# теги PNG текстовых чанков
exiftool -PNG:all image.png
```

## Очистка и OPSEC

Перед публикацией удаляйте метаданные:

```bash
exiftool -all= -overwrite_original file.jpg     # снести все теги
mat2 --inplace document.pdf                     # глубокая очистка (libmat2)
mat2 --show file.jpg                            # что будет удалено
```

`mat2` очищает не только EXIF, но и скрытые структуры; для документов — предпочтительнее. Помните: удаление метаданных — необратимо, делайте копию.

## Частые ошибки

- **Смотреть только EXIF картинки** — забыть XMP/IPTC, встроенный thumbnail (там старая версия фото), Office/PDF.
- **Путать `DateTime` и `DateTimeOriginal`** — второе — время съёмки, первое — правки.
- **Игнорировать `-a -u`** — дублированные и нестандартные теги теряются.
- **Считать отсутствие метаданных безопасностью** — их мог удалить загрузчик соцсети, но PRNU остаётся.
- **Забыть про OPSEC своих файлов** — ваши собственные документы выдают вас (osint-opsec).

## Квиз

```quiz
- question: "Какой командой вытащить GPS из фото?"
  options:
    - "`exiftool -gps:all image.jpg`"
    - "`nmap image.jpg`"
    - "`dig image.jpg`"
    - "`strings -gps image.jpg`"
  answer: 0
- question: "Что такое DOCX с точки зрения структуры?"
  options:
    - "Бинарный формат"
    - "ZIP-архив с XML внутри"
    - "Простой текст"
    - "База данных"
  answer: 1
- question: "Где в DOCX хранится автор?"
  options:
    - "В имени файла"
    - "В `docProps/core.xml`"
    - "В `word/document.xml`"
    - "В EXIF"
  answer: 1
- question: "Что может показать старый thumbnail в JPEG?"
  options:
    - "Пароль камеры"
    - "Предыдущее (отредактированное) содержимое"
    - "GPS-координаты"
    - "Серийный номер"
  answer: 1
- question: "Как очистить метаданные перед публикацией?"
  options:
    - "`exiftool -all= image.jpg`"
    - "Сменить расширение"
    - "Открыть в Paint"
    - "Переименовать файл"
  answer: 0
```

## Где пригодится

- **CTF:** категории OSINT/Forensics — флаг часто в метаданных.
- **Bug bounty:** утёкшие документы выдают имена, пути, версии ПО.
- **Пентест:** реконструкция внутренней инфраструктуры по документам.
- **OPSEC:** очистка своих артефактов перед публикацией.
