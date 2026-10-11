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
## Структура PDF

PDF — не картинка, а контейнер объектов: словари, массивы, потоки (`stream ... endstream`), часто сжатые `FlateDecode`. Ключевые части: **xref** (таблица смещений объектов), **trailer** (корневой объект `/Root`), дерево страниц `Catalog → Pages → Page → Contents`, **XObject** (изображения/формы), шрифты. В CTF флаг прячут в метаданных, слоях, невидимом тексте, картинке (OCR) или внутри потока.

Ментальная модель: PDF можно «распаковать» до объектов и потоков, и почти всегда секрет лежит в одном из них. Инструменты либо извлекают текст/картинки, либо дают доступ к сырым объектам.

## Базовые инструменты

| Инструмент | Назначение |
|------------|-----------|
| `pdftotext` | извлечение текста |
| `pdfinfo` | метаданные |
| `pdfimages` | извлечение картинок |
| `qpdf` | разбор/дешифровка/распаковка потоков |
| `mutool` | мощный разбор (MuPDF) |
| `pdf-parser` | низкоуровневый разбор (Didier Stevens) |
| `tesseract` | OCR |
| `binwalk` | поиск встроенных файлов |
| `exiftool` | метаданные |

## Извлечение текста

```bash
pdftotext doc.pdf -            # в stdout
pdftotext -layout doc.pdf out.txt   # сохранить верстку
# поиск флага
pdftotext doc.pdf - | grep -oE "FLAG\{[^}]*\}"
```

Если текст не извлекается — он может быть в виде изображения (нужен OCR) или «нарисован» через шрифты/кривые.

## Извлечение изображений

```bash
pdfimages -all doc.pdf img        # все изображения (png/jpg/...)
pdfimages -list doc.pdf           # список без извлечения
# затем смотрим картинки, zsteg/stegsolve/binwalk
```

В картинках бывает стего (LSB), скрытый текст, QR. Прогоните `zsteg`, `binwalk`, откройте в редакторе.

## Работа с объектами и потоками

```bash
# qpdf: распаковать потоки и посмотреть структуру
qpdf --qdf --object-streams=disable doc.pdf doc_qdf.pdf
grep -a "stream" doc_qdf.pdf | head
# mutool: показать объекты и текст
mutool show doc.pdf trailer
mutool show doc.pdf pages
mutool draw -F txt doc.pdf
# pdf-parser: детальный разбор
pdf-parser.py -a doc.pdf
pdf-parser.py -s "stream" doc.pdf
```

Распакованные потоки (`--qdf`) часто содержат скрытые объекты, JavaScript, вложения.

## Невидимый текст и слои

Флаг может быть текстом белого цвета на белом фоне, под другим слоем, или «спрятан» за картинкой. Решения:

```bash
# извлечь текст (в т.ч. белый)
pdftotext doc.pdf - | cat -A | head
# отрендерить и посмотреть
mutool draw -o page-%d.png doc.pdf
# изменить цвет фона/текста (редактор) или извлечь все строки
pdftotext -raw doc.pdf -
```

Также проверяйте «слои» (OCG) и аннотации: текст может быть в аннотации/комментарии.

## OCR отсканированных документов

```bash
# конвертировать страницы в изображения
mutool draw -r 300 -o page-%d.png doc.pdf
# OCR
tesseract page-1.png - | grep -oE "FLAG\{[^}]*\}"
# или напрямую OCR PDF
ocrmypdf --sidecar out.txt doc.pdf out.pdf && grep FLAG out.txt
```

Для сканов качество важно: увеличьте DPI (`-r 300+`), при необходимости предобработайте (бинаризация, поворот).

## Метаданные и вложения

```bash
pdfinfo doc.pdf | head -20        # Title, Author, Keywords, Custom
exiftool doc.pdf | head
# вложения
pdfdetach -list doc.pdf
pdfdetach -saveall doc.pdf
```

Часто флаг лежит в `Keywords`, `Author`, `Subject` или во вложенном файле.

## Скрытые данные (binwalk, стего)

```bash
binwalk doc.pdf                   # встроенные zip/изображения
binwalk -e doc.pdf
# если в потоке base64/hex — декодировать
strings doc_qdf.pdf | grep -iE "FLAG|base64|==" | head
```

Внутри PDF могут быть встроены ZIP (с паролем), изображения со стего, закодированные строки. Прогоняйте `binwalk`, `foremost`, `zsteg`.

## Разобранный пример

```bash
$ pdfinfo challenge.pdf | grep -i keyword
Keywords:        VGhlIGZsYWcgaXMgaGVyZQ==
$ echo 'VGhlIGZsYWcgaXMgaGVyZQ==' | base64 -d
The flag is here
$ pdfimages -all challenge.pdf img && zsteg img-000.png
b1,rgb,lsb,xy .. text: "FLAG{pdf_hides_everywhere}"
```

Флаг нашёлся и в метаданных (подсказка), и в стего картинки.

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

## Типовые ошибки новичка

- **Только `pdftotext`.** Если текст пуст — это скан (OCR) или картинка.
- **Забыть про метаданные.** `pdfinfo`/`exiftool` — за секунды.
- **Не распаковать потоки.** `qpdf --qdf` вскрывает скрытые объекты.
- **Игнорировать картинки.** Стего/QR — частый путь.
- **Не проверить вложения.** `pdfdetach` часто даёт нужный файл.

## Практический чек-лист

1. `pdfinfo`/`exiftool` — метаданные.
2. `pdftotext` — текст; `grep FLAG`.
3. `pdfimages` — картинки; `zsteg`/`binwalk`.
4. `qpdf --qdf` + `mutool show` — объекты/потоки.
5. `pdfdetach` — вложения.
6. OCR, если текст не извлекается.
7. `binwalk -e` — встроенные файлы.
8. Зафиксировать найденный флаг/данные.

## Что дальше / решение

Порядок: метаданные → текст → картинки → объекты/потоки → вложения → OCR → binwalk. Связанные уроки: `misc-encoding` (кодировки/QR), `misc-image-misc` (стего), `forensics-*` (анализ документов). Решение — когда флаг найден.

## Продвинутый разбор: JavaScript, формы и шифрование в PDF

PDF может содержать **JavaScript** (`/JS`, `/JavaScript`), формы (`/AcroForm`), аннотации и **шифрование** (`/Encrypt`). JavaScript встречается в CTF как источник логики (проверка пароля, генерация данных) или как вектор в реальных атаках (эксплойты в ридерах). Разбор:

```bash
# найти JS-объекты
pdf-parser.py -s "JavaScript" doc.pdf
pdf-parser.py -s "/JS" doc.pdf
mutool show doc.pdf grep | head
# дешифровать (если пустой пароль или известен)
qpdf --decrypt doc.pdf out.pdf
qpdf --password=PASS --decrypt doc.pdf out.pdf
```

Если документ зашифрован, попробуйте пустой пароль, пароль из подсказки или брут (`pdfcrack`, `john` с `pdf2john`). Формы (`/AcroForm`) могут содержать значения полей — извлеките их (`pdftk doc.pdf dump_data_fields`). Аннотации (`/Annots`) иногда прячут текст/ссылки. Также проверяйте `/EmbeddedFile` (вложения) и `/OpenAction` (автодействие при открытии) — там бывает и полезная логика, и вредоносный JS.

## Материалы и связанные техники

Инструменты: Didier Stevens (`pdf-parser.py`, `pdfid.py`), `qpdf`, `mutool`, `pdftk`, `pdfcrack`, `john` (`pdf2john`). Полезно держать под рукой `pdfid.py` — он быстро показывает опасные объекты (`/JS`, `/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`), что сразу подсказывает, где искать. В CTF комбинируйте: `pdfinfo`/`exiftool` для метаданных, `pdftotext`/OCR для текста, `pdfimages`+`zsteg` для картинок, `qpdf --qdf`+`pdf-parser` для объектов. Связанные уроки: `misc-encoding`, `misc-image-misc`, `misc-binary-misc`, `forensics-*`.

## Быстрый старт: первые команды

```bash
pdfinfo challenge.pdf | head            # метаданные (часто флаг/подсказка)
pdftotext challenge.pdf - | grep -oE "FLAG\{[^}]*\}"   # текст
pdfimages -all challenge.pdf img && zsteg img-000.png  # картинки + стего
qpdf --qdf --object-streams=disable challenge.pdf out.pdf   # распаковать потоки
pdfdetach -list challenge.pdf           # вложения
binwalk -e challenge.pdf                # встроенные файлы
```

Этот набор из шести команд решает большинство PDF-задач. Если текст пуст — переходите к OCR (`mutool draw -r 300` + `tesseract`). Если документ зашифрован — `qpdf --decrypt` или `pdf2john`+`john`.

## Квиз

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
  explanation: "Метаданные, скрытые слои, dangling-объекты."
- question: "Какой DPI рекомендуется для OCR PDF?"
  options:
    - "300 dpi"
    - "20 dpi"
    - "72 dpi"
    - "1000 dpi"
  answer: 0
  explanation: "300 dpi — стандарт качества для OCR."
```

## Где пригодится

- **CTF Misc:** задачи на PDF-файлах.
- **Пентест:** анализ PDF в фишинге (встроенный JS, вложения).
- **Работа:** разбор документов и метаданных.
- **Дальше по дереву:** `misc-image-misc`, `misc-encoding-media`.
