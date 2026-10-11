---
id: stego-pdf
title: "Стеганография в PDF: объекты, потоки и невидимые слои"
category: stego
parent: stego-document-carriers
difficulty: medium
order: 2
tags: [stego, pdf, objects, streams, javascript, layers]
prerequisites: [stego-appended]
useful_for:
  - "CTF Stego/Forensics — PDF-задачи"
  - "Анализ документов на скрытые данные"
  - "Bug bounty: вредоносные PDF"
estimated_minutes: 30
summary: "Каналы сокрытия в PDF: невидимые/наложенные объекты, метаданные, JavaScript, встроенные потоки и файлы, whitespace после %%EOF; практические инструменты и извлечение."
---

## Структура PDF: объекты, xref и потоки

PDF — не «текстовый документ», а контейнер из **объектов** (числа, строки, словари, массивы, потоки), на которые ссылаются по номерам. Ключевые части:

- **Тело** — последовательность объектов `N 0 obj … endobj`.
- **xref** — таблица смещений объектов (нужна для навигации).
- **Trailer** — корневой объект (`/Root`) и ссылка на `/Info`.
- **Потоки (`stream … endstream`)** — сжатые данные (контент страницы, картинки, шрифты). Часто `FlateDecode` (zlib).

Флаг или скрытые данные могут лежать в **любом** из этих мест, поэтому ручной разбор нужен наравне с инструментами.

```bash
$ file doc.pdf
doc.pdf: PDF document, version 1.7
$ strings -n 6 doc.pdf | grep -iE 'flag|base64|http' | head
```

## Невидимые и наложенные объекты

Классика PDF-стего — контент, который есть в файле, но не виден при рендеринге:

- **Белый текст на белом фоне** (`1 1 1 rg` перед текстом).
- **Текст вне MediaBox** — координаты за пределами видимой страницы.
- **Прозрачный слой** (ExtGState с `CA`/`ca` = 0).
- **Наложенный объект** — второй текст поверх первого, перекрытый картинкой.
- **OCR-слой** поверх скана, содержащий иной текст.

Ищите текстовые операторы `Tj`/`TJ` и цветовые `rg`:

```bash
$ qpdf --qdf --object-streams=disable doc.pdf decoded.pdf   # «нормализовать» PDF
$ strings -n 6 decoded.pdf | grep -A2 'Tj'
```

`qpdf --qdf` декодирует потоки и раскрывает объектные потоки — после него текст и данные видны «как есть».

## Метаданные и Info-словарь

Trailer ссылается на `/Info` со словарём полей: `/Title`, `/Author`, `/Subject`, `/Keywords`, `/Creator`, `/Producer`. Туда часто кладут флаг или base64.

```bash
$ exiftool doc.pdf
Title    : Report
Author   : admin
Keywords : ZmxhZ3twZGZfbWV0YX0=
$ pdfinfo doc.pdf
```

Также бывает **XMP-метаданные** (XML-блок) с произвольными полями — их читает `exiftool` и `pdfx`.

## JavaScript и авто-действия

PDF умеет исполнять JavaScript и выполнять действия при открытии (`/OpenAction`, `/AA`). В CTF это реже флаг, чаще — вектор атаки, но полезно знать:

```bash
$ strings doc.pdf | grep -iE 'javascript|/JS|/OpenAction'
/OpenAction 5 0 R
/JS (app.alert('flag{js_in_pdf}'))
```

Инструмент `peepdf` показывает структуру и опасные элементы:

```bash
peepdf -f doc.pdf
```

## Встроенные потоки и файлы (EmbeddedFiles)

В PDF можно вложить **произвольные файлы** (ZIP, exe, другой PDF) через `/EmbeddedFiles` в `/Names`. Это полноценный контейнер внутри контейнера.

```bash
$ pdfdetach -list doc.pdf
2 embedded files
1: secret.zip
2: note.txt
$ pdfdetach -saveall doc.pdf
$ unzip -l secret.zip
```

`binwalk` тоже находит вложенное:

```bash
binwalk doc.pdf
```

## Whitespace после %%EOF и инкрементальные обновления

PDF заканчивается маркером `%%EOF`, но **после** него можно дописать данные — парсеры их игнорируют. Также PDF поддерживает **инкрементальные обновления**: файл содержит несколько версий объектов, и старые (перезаписанные) объекты остаются в теле.

```bash
$ grep -abo '%%EOF' doc.pdf          # смещения всех EOF
$ xxd doc.pdf | tail -5              # что после последнего %%EOF
$ grep -abo 'obj' doc.pdf | tail     # все объекты, включая старые версии
```

Старые объекты — отличный канал: «удалённый» текст остаётся в файле и извлекается по смещению.

## Инструменты: pdf-parser, pdftk, exiftool, peepdf

- **`pdf-parser`** (Didier Stevens) — низкоуровневый разбор объектов и потоков.
- **`qpdf`** — декодирование потоков, линейная нормализация, разбор структуры.
- **`pdftk`/`pdfdetach`** — извлечение вложенных файлов.
- **`exiftool`/`pdfinfo`** — метаданные.
- **`peepdf`** — структура и опасные элементы.
- **`mutool clean -d`** — декодирование потоков (MuPDF).
- **`strings`/`xxd`/`binwalk`** — быстрые проверки.

```bash
pdf-parser --search flag doc.pdf
pdf-parser -o 7 -d doc.pdf | head       # выгрузить объект 7 и декодировать
```

## Разобранный пример: от PDF до флага

```bash
$ exiftool challenge.pdf | grep -i keyword
Keywords : flag{hidden_in_info}
$ pdfdetach -list challenge.pdf
1 embedded file
1: data.bin
$ pdfdetach -saveall challenge.pdf && file data.bin
data.bin: gzip compressed data
$ zcat data.bin
flag{pdf_embedded_stream}
$ xxd challenge.pdf | tail -2
0000f000: 666c 6167 7b61 6674 6572 5f65 6f66 7d0a  flag{after_eof}
```

Маршрут: `exiftool` → `pdfdetach` → `binwalk`/`zcat` → `xxd | tail`. Каждый слой в PDF-задачах независим, поэтому проходите их по порядку.

## Частые ошибки и подводные камни

- **Открывать PDF в ридере и «сохранять»** — структура и скрытые объекты перезапишутся.
- **Игнорировать `%%EOF`-хвост** — данные после маркера парсерами не видны.
- **Не декодировать потоки** — текст в `stream` сжат; нужен `qpdf --qdf` или `pdf-parser -d`.
- **Забывать про инкрементальные версии** — старые объекты остаются в теле.
- **Смотреть только видимую страницу** — невидимый/внеполосный текст легко пропустить.
- **Путать `%%EOF` с концом файла** — их может быть несколько.

## Декодирование потоков вручную (zlib/deflate)

Даже если `qpdf` недоступен, поток PDF можно распаковать вручную. Поток начинается после `stream\r\n` (или `stream\n`) и заканчивается `endstream`. Содержимое сжато `FlateDecode` (zlib), реже `LZWDecode`, `ASCIIHexDecode`, `ASCII85Decode`.

```python
import re, zlib
raw = open('doc.pdf', 'rb').read()
for m in re.finditer(rb'stream\r?\n(.*?)\r?\nendstream', raw, re.S):
    blob = m.group(1)
    try:
        dec = zlib.decompress(blob)
        print('--- decoded stream ---')
        print(dec[:400])
    except Exception:
        pass  # не flate или обрезан
```

Если zlib падает — попробуйте `zlib.decompressobj()` (поток может быть обрезан) или `zlib.decompress(blob[2:])` (иногда пропущен zlib-заголовок). Декодированные потоки содержат операторы контента страницы: `BT … ET`, `Tj`, `TJ`, `Tf`, цвета `rg`. Именно там ищут скрытый текст.

## Сравнение инструментов PDF-анализа

| Инструмент | Назначение | Сильная сторона |
|---|---|---|
| `pdf-parser` | разбор объектов/потоков | точечный доступ к объекту N |
| `qpdf --qdf` | нормализация | декодирует потоки и object streams |
| `mutool clean -d` | декодирование | быстрый, из MuPDF |
| `pdfdetach` | вложения | `/EmbeddedFiles` |
| `exiftool` | метаданные | Info + XMP |
| `peepdf` | структура/JS | опасные элементы |
| `binwalk` | вложенное | сигнатуры файлов |

Практическое правило: `qpdf --qdf` даёт «читаемый» PDF, после которого `strings` и `grep` работают эффективно; `pdf-parser` нужен для точечного доступа, когда объект большой.

## Защита: как PDF-стего детектируют

С точки зрения blue team полезно знать признаки:

- Текст вне MediaBox или с прозрачностью (ExtGState `ca 0`).
- Несколько `%%EOF` и «висячие» объекты старых версий.
- Данные после последнего `%%EOF`.
- Большие вложения в `/EmbeddedFiles`.
- JavaScript в `/OpenAction`/`/AA`.

Для сканеров существуют эвристики на аномальную структуру, но стеганография по определению задумана незаметной. Поэтому в CTF и в реальном анализе одинаково важны **ручные проверки** структуры и метаданных.

## Практический чек-лист команд для PDF

Собранная последовательность, которую стоит прогонять на любом «подозрительном» PDF:

```bash
file doc.pdf                                   # реальный формат
exiftool doc.pdf                               # Info + XMP метаданные
pdfinfo doc.pdf                                # базовая информация
strings -n 6 doc.pdf | grep -iE 'flag|base64|http|/JS'
qpdf --qdf --object-streams=disable d.pdf out.pdf   # декодировать потоки
strings -n 6 out.pdf | grep -A2 -E 'Tj|TJ'     # текст контента
pdfdetach -list doc.pdf && pdfdetach -saveall doc.pdf
binwalk -e doc.pdf                             # вложенные/дописанные
grep -abo '%%EOF' doc.pdf                      # все маркеры конца
xxd doc.pdf | tail -6                          # данные после последнего EOF
pdf-parser --search flag doc.pdf
```

Такой прогон закрывает подавляющее большинство PDF-задач: метаданные, скрытый текст, вложения, дописанный хвост и старые объекты проверяются последовательно, от дешёвого к сложному.

## Полезные однострочники и хитрости

- Быстро найти все URL и домены: `strings doc.pdf | grep -oE 'https?://[^ ]+'`.
- Найти все вложения по имени: `strings doc.pdf | grep -iE '/F\('`.
- Проверить, сжимаются ли данные: если после `qpdf --qdf` размер резко вырос — поток был сжат и теперь виден.
- Оценить «подозрительность»: число объектов, несколько `%%EOF`, объекты без ссылок в xref — всё это поводы копать глубже.
- Запускать разбор на копии: `cp doc.pdf work.pdf`, оригинал не трогать.

## Что делать дальше / решение

- `exiftool` + `pdfinfo` — метаданные и Info.
- `qpdf --qdf`/`mutool clean -d` — декодировать потоки, искать текст и цвета.
- `pdfdetach -saveall`/`binwalk` — вложения и встроенные файлы.
- `grep -abo '%%EOF'` + `xxd | tail` — данные после конца.
- `grep -abo 'obj'` — старые версии объектов.
- Всё пусто — проверьте XMP-метаданные и JavaScript (`peepdf`).

## Квиз

```quiz
- question: "Каким тегом PDF помечается встроенный файл?"
  options:
    - "/EmbeddedFile"
    - "/Font"
    - "/Page"
    - "/Catalog"
  answer: 0
  explanation: "/EmbeddedFile описывает вложение в PDF."
- question: "Какая утилита извлекает изображения и потоки из PDF?"
  options:
    - "mutool extract"
    - "jadx"
    - "apktool"
    - "zsteg"
  answer: 0
  explanation: "mutool умеет показывать объекты и извлекать потоки."
- question: "Что делает команда qpdf --qdf?"
  options:
    - "Распаковывает потоки в читаемый вид"
    - "Удаляет пароль"
    - "Сжимает PDF"
    - "Меняет метаданные"
  answer: 0
  explanation: "qdf-режим делает потоки несжатыми и анализируемыми."
- question: "Где могут лежать данные после конца PDF?"
  options:
    - "После маркера %%EOF"
    - "В /Catalog"
    - "В начале файла"
    - "В шрифтах"
  answer: 0
  explanation: "Дописанные байты после %%EOF — классический канал."
- question: "Как отображается невидимый текст в PDF?"
  options:
    - "Режимом рендеринга Tr 3"
    - "Тегом /Font"
    - "Сжатием FlateDecode"
    - "Тегом /URI"
  answer: 0
  explanation: "Tr 3 означает invisible rendering."
```

## Где пригодится

- **CTF Stego/Forensics:** PDF-задачи с секретами.
- **Malware analysis:** вредоносные PDF (JS, эксплойты).
- **Bug bounty:** скрытые данные в документах.
- **Работа:** анализ документов в IR.
