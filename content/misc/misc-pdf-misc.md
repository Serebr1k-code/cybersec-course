---
id: misc-pdf-misc
title: "PDF-задачи: текст, объекты и OCR"
category: misc
parent: misc-encoding-media
difficulty: medium
order: 3
tags: [pdf, ocr, forensics, pdftotext, qpdf, ctf]
prerequisites: [misc-encoding]
useful_for:
  - "CTF Misc: задачи на PDF-файлах"
  - "Пентест: анализ PDF в фишинге и утечках"
  - "Работа: разбор документов и метаданных"
estimated_minutes: 35
summary: "Разбор PDF в misc: структура файла, извлечение текста и изображений, работа с объектами и потоками, OCR отсканированных документов и поиск скрытых данных."
---
## Вопрос, с которого всё начинается

Мы разобрали картинки и звук. Теперь дают **PDF-документ** `challenge.pdf`. На вид обычный файл, но где-то в нём спрятан флаг. С чего начать?

PDF — не «страница с текстом», а **контейнер объектов**: словари, массивы, потоки сжатых данных. Секрет может лежать в метаданных, в тексте, в картинке, во вложенном файле или в отдельном объекте. Значит, снова работает каскад — от простого к сложному. Разберём его на одном документе.

## Шаг 1: метаданные — за секунды

Служебные поля PDF смотрит `pdfinfo`:

```bash
$ pdfinfo challenge.pdf
Title:           Quarterly Report
Author:          admin
Keywords:        VGhlIGZsYWcgaXMgaGVyZQ==
Pages:           1
```

Поле `Keywords` выглядит как **Base64** (помните `misc-encoding`?). Декодируем:

```bash
$ echo 'VGhlIGZsYWcgaXMgaGVyZQ==' | base64 -d
The flag is here
```

Это подсказка, а не флаг: «флаг здесь». Значит, ищем дальше. Урок: **всегда сначала `pdfinfo` и `exiftool`** — они бесплатны по времени.

## Шаг 2: текст — и почему его может не быть

Извлекаем текст из документа утилитой `pdftotext`:

```bash
$ pdftotext challenge.pdf - | grep -oE "FLAG\{[^}]*\}"
$
```

Пусто. Причина ясна: если PDF — **скан** (отсканированные страницы), то «текста» в файле нет, есть только картинка. `pdftotext` читает текстовые объекты, а не распознаёт изображение. Для сканов нужен OCR — к нему вернёмся.

## Шаг 3: картинки внутри PDF

Даже обычный PDF часто содержит встроенные изображения. Извлекаем их `pdfimages`:

```bash
$ pdfimages -all challenge.pdf img
$ ls img*
img-000.png
```

`-all` сохраняет картинки в исходных форматах, `-list` только показал бы их список без извлечения. Полученную картинку прогоняем через знакомый по прошлым урокам каскад:

```bash
$ zsteg -a img-000.png
b1,rgb,lsb,xy .. text: "FLAG{pdf_hides_everywhere}"
```

Флаг найден — он был в LSB картинки внутри PDF. Итог: метаданные дали подсказку, картинка — сам флаг.

## Шаг 4: заглядываем в объекты и потоки

Если картинок нет или они «пустые», PDF можно **распаковать до объектов**. Потоки в PDF часто сжаты (`FlateDecode`), и `qpdf --qdf` их разжимает, делая файл читаемым:

```bash
$ qpdf --qdf --object-streams=disable challenge.pdf out.pdf
$ grep -a "stream" out.pdf | head
stream
stream
```

`--qdf` — «нормализовать в читаемый вид», `--object-streams=disable` — вынести объекты из сжатых контейнеров. После этого `strings out.pdf | grep -iE "FLAG|base64"` часто вытаскивает закодированные строки.

Мощный разбор даёт `mutool`:

```bash
$ mutool show challenge.pdf trailer     # корневой объект
$ mutool show challenge.pdf pages       # дерево страниц
```

А низкоуровневый разбор — `pdf-parser.py` (Didier Stevens): `pdf-parser.py -s "JavaScript" doc.pdf` находит встроенные скрипты.

## Шаг 5: вложения и встроенные файлы

PDF умеет носить внутри себя другие файлы. Их перечисляет `pdfdetach`:

```bash
$ pdfdetach -list challenge.pdf
$ pdfdetach -saveall challenge.pdf
```

А `binwalk challenge.pdf` покажет вложенные ZIP/изображения, если они есть.

## Шаг 6: OCR для сканов

Если `pdftotext` пуст, а `pdfimages` дал «страницу», — это скан, и текст с него распознаёт **OCR** (`tesseract`). Сначала рендерим страницы в картинки с хорошим разрешением:

```bash
$ mutool draw -r 300 -o page-%d.png challenge.pdf
$ tesseract page-1.png - | grep -oE "FLAG\{[^}]*\}"
```

`-r 300` — 300 dpi, стандарт качества для распознавания. Есть и сквозной вариант: `ocrmypdf --sidecar out.txt doc.pdf out.pdf`.

## Шаг 7: JavaScript, формы и шифрование в PDF

PDF умеет носить внутри **JavaScript** (`/JS`, `/JavaScript`), **формы** (`/AcroForm`) и **шифрование** (`/Encrypt`). В CTF скрипт внутри PDF бывает источником логики (проверка пароля), а в реальных атаках — вектором эксплойта в ридере.

Найти скрипты:

```bash
$ pdf-parser.py -s "JavaScript" challenge.pdf
$ pdf-parser.py -s "/JS" challenge.pdf
```

Если документ зашифрован, сначала попробуйте пустой пароль или пароль из подсказки:

```bash
$ qpdf --decrypt challenge.pdf out.pdf
$ qpdf --password=PASS --decrypt challenge.pdf out.pdf
```

Не помогло — берите `pdfcrack` или `pdf2john`+`john` (превращает пароль PDF в хеш для `john`).

Поля формы вытаскивает `pdftk doc.pdf dump_data_fields`. А быстрый способ увидеть «опасные» объекты — `pdfid.py`: он сразу показывает `/JS`, `/OpenAction`, `/EmbeddedFile`, что подсказывает, где искать.

## Шаг 8: невидимый текст и слои

Бывает, что текст в PDF есть, но `pdftotext` его «не видит» — потому что он белый на белом фоне, спрятан за картинкой или лежит в отдельном слое (OCG). Проверить просто: `pdftotext` извлекает **весь** текстовый слой, включая невидимый.

```bash
$ pdftotext -raw challenge.pdf - | grep -oE "FLAG\{[^}]*\}"
```

Флаг `-raw` сохраняет текст без попытки восстановить вёрстку — иногда так вылезает то, что `-layout` прячет. Ещё путь — отрендерить страницы в картинки и посмотреть глазами: `mutool draw -o page-%d.png challenge.pdf`. Текст может быть в аннотации или комментарии — их тоже стоит просмотреть.

## Быстрый старт: шесть команд

Если не хочется читать каскад целиком, вот он в шести строках:

```bash
pdfinfo challenge.pdf | head                                  # метаданные
pdftotext challenge.pdf - | grep -oE "FLAG\{[^}]*\}"          # текст
pdfimages -all challenge.pdf img && zsteg img-000.png         # картинки + стего
qpdf --qdf --object-streams=disable challenge.pdf out.pdf     # распаковать потоки
pdfdetach -list challenge.pdf                                 # вложения
binwalk -e challenge.pdf                                      # встроенные файлы
```

Этого набора хватает для большинства PDF-задач. Текст пуст → OCR. Документ зашифрован → `qpdf --decrypt` или `pdf2john`+`john`.

## Что мы теперь знаем

- PDF — контейнер объектов; флаг прячут в метаданных, тексте, картинках, вложениях или потоках.
- Каскад: `pdfinfo`/`exiftool` → `pdftotext` → `pdfimages`+`zsteg` → `qpdf --qdf`/`mutool` → `pdfdetach` → OCR → `binwalk`.
- Пустой `pdftotext` не значит «пусто» — скорее всего, это скан (нужен OCR).
- Потоки в PDF сжаты; `qpdf --qdf` их разжимает для анализа.
- Вложения извлекает `pdfdetach`, встроенные файлы ищет `binwalk`.

## На что смотреть дальше

- **Только `pdftotext`** — если текст пуст, это скан (OCR) или картинка.
- **Забыть про метаданные** — `pdfinfo`/`exiftool` за секунды дают подсказку или флаг.
- **Не распаковать потоки** — `qpdf --qdf` вскрывает скрытые объекты и JavaScript.
- **Игнорировать картинки** — стего/QR внутри PDF — частый путь.
- **Не проверить вложения** — `pdfdetach` часто отдаёт нужный файл.
- **Зашифрованный PDF** — попробуйте `qpdf --decrypt`, пустой пароль или `pdf2john`+`john`.

## Справочная таблица: что где искать

| Где | Инструмент |
|-----|-----------|
| Текст | `pdftotext` |
| Картинки | `pdfimages` |
| Метаданные | `pdfinfo`, `exiftool` |
| Вложения | `pdfdetach` |
| Объекты/потоки | `qpdf --qdf`, `mutool show`, `pdf-parser` |
| Сканы | `tesseract`, `ocrmypdf` |
| Встроенные файлы | `binwalk`, `foremost` |
| Стего в картинках | `zsteg`, `stegsolve` |

## Квиз

Проверь себя.

```quiz
- question: "Какой инструмент извлекает изображения из PDF?"
  options:
    - "pdfimages"
    - "pdftotext"
    - "pdfinfo"
    - "qpdf"
  answer: 0
  explanation: "pdfimages вытаскивает встроенные картинки."
- question: "Что делает qpdf с флагом --qdf?"
  options:
    - "Распаковывает и нормализует PDF для анализа"
    - "Шифрует PDF"
    - "Удаляет страницы"
    - "Конвертирует в DOCX"
  answer: 0
  explanation: "--qdf даёт распакованный, читаемый PDF."
- question: "Что нужно для PDF, где текст — картинка?"
  options:
    - "OCR (tesseract/ocrmypdf)"
    - "Только strings"
    - "Только pdfinfo"
    - "Только qpdf"
  answer: 0
  explanation: "OCR распознаёт текст с изображения."
- question: "Где в PDF часто прячут флаг?"
  options:
    - "В метаданных, невидимом тексте и вложенных объектах"
    - "В размере файла"
    - "В расширении"
    - "В имени пользователя"
  answer: 0
  explanation: "Метаданные, скрытые слои, вложенные объекты."
- question: "Какой DPI рекомендуется для OCR PDF?"
  options:
    - "300 dpi"
    - "20 dpi"
    - "72 dpi"
    - "1000 dpi"
  answer: 0
  explanation: "300 dpi — стандарт качества для OCR."
```

## Куда дальше

В следующем уроке мы возьмём не документ, а **бинарный файл** и разберём байтовые головоломки — где данные спрятаны в самих байтах. А пока главное запомни: **PDF — это контейнер; иди по каскаду метаданные → текст → картинки → потоки → вложения → OCR, и пустой текст не значит «пусто».**

## Где пригодится

- **CTF Misc:** задачи на PDF-файлах.
- **Пентест:** анализ PDF в фишинге (встроенный JS, вложения).
- **Работа:** разбор документов и метаданных.
- **Дальше по дереву:** `misc-image-misc`, `misc-encoding-media`.
