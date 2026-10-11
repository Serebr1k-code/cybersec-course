---
id: stego-docx
title: "Стеганография в Office-документах: DOCX, XLSX, OOXML"
category: stego
parent: stego-document-carriers
difficulty: medium
order: 3
tags: [stego, docx, xlsx, ooxml, zip, metadata, custom-xml]
prerequisites: [stego-appended, stego-pdf]
useful_for:
  - "CTF Stego/Forensics — офисные документы"
  - "Анализ макросов и скрытых данных"
  - "Bug bounty: вредоносные документы"
estimated_minutes: 31
summary: "Как прячут данные в DOCX/XLSX/PPTX: OOXML — это ZIP с XML; скрытый текст, метаданные, кастомные части, макросы, вложенные объекты и дописанные данные."
---

## OOXML = ZIP: вскрываем контейнер

Файлы `.docx`, `.xlsx`, `.pptx` — это **не** бинарные форматы, а ZIP-архивы с набором XML-частей (стандарт OOXML, ECMA-376). Поэтому первое действие с любым Office-документом — распаковать его как архив:

```bash
$ file report.docx
report.docx: Microsoft Word 2007+
$ unzip -l report.docx
  Length      Date    Time    Name
---------  ---------- -----   ----
      1234  2024-01-01 00:00   [Content_Types].xml
       567  2024-01-01 00:00   _rels/.rels
       890  2024-01-01 00:00   word/document.xml
       234  2024-01-01 00:00   word/_rels/document.xml.rels
       456  2024-01-01 00:00   docProps/core.xml
       789  2024-01-01 00:00   docProps/app.xml
```

Типовые части Word: `word/document.xml` (текст), `word/styles.xml`, `word/media/` (картинки), `word/embeddings/` (вложенные объекты), `word/settings.xml`, `word/_rels/document.xml.rels` (связи). У Excel — `xl/worksheets/sheet1.xml`, `xl/sharedStrings.xml`; у PowerPoint — `ppt/slides/slide1.xml`.

Именно поэтому DOCX-стеганография — это «стеганография в ZIP»: скрытые данные могут лежать в любом из XML, в лишних частях или в дописанном хвосте архива.

## Метаданные: docProps/core.xml и app.xml

Метаданные — дешёвый источник утечек. `docProps/core.xml` содержит автора, дату, заголовок, компанию; `docProps/app.xml` — приложение-создатель и статистику.

```bash
$ unzip -p report.docx docProps/core.xml | xmllint --format -
<?xml version="1.0"?>
<cp:coreProperties ...>
  <dc:creator>john.doe</dc:creator>
  <cp:lastModifiedBy>admin</cp:lastModifiedBy>
  <dcterms:created>2024-01-01T10:00:00Z</dcterms:created>
  <dc:title>Q1 Report</dc:title>
  <cp:keywords>secret_key=ABC123</cp:keywords>
</cp:coreProperties>
```

`exiftool` умеет читать это без распаковки:

```bash
$ exiftool report.docx
Creator         : john.doe
Last Modified By: admin
Keywords        : secret_key=ABC123
```

Часто флаг или пароль лежит прямо в `Keywords`, `Comments`, `Subject` или `Author`.

## Скрытый текст и белый текст

Классика Word-стеганографии — текст, сделанный «невидимым»:

- **Белый текст на белом фоне** — просто задан цвет шрифта.
- **Скрытый текст** (`<w:vanish/>` в `document.xml`) — режим «hidden», не отображается и не печатается.
- **Текст в колонтитулах/сносках**, который не виден при беглом чтении.
- **`w:sz` = 2** (размер 1 pt) — микроскопический текст.

```bash
# вытащить весь текст из document.xml
$ unzip -p report.docx word/document.xml | \
  sed -e 's/<[^>]*>/ /g' | tr -s ' '
The visible sentence.  flag{h1dd3n_t3xt}
```

Пометки `<w:vanish/>` и цвет ищутся так:

```bash
unzip -p report.docx word/document.xml | grep -o 'w:vanish' | wc -l
unzip -p report.docx word/document.xml | grep -o 'w:color w:val="[^"]*"'
```

## Пользовательские XML-части и скрытые листы

OOXML позволяет добавлять **произвольные** части. Автор задачи кладёт флаг в кастомный XML и регистрирует его в `[Content_Types].xml` и `.rels`:

```bash
$ unzip -l report.docx | grep -v -E 'word/|docProps|_rels|Content_Types'
   1234  2024-01-01 00:00   customXml/item1.xml
```

В Excel прячут данные в **скрытых листах** (`state="hidden"`/`"veryHidden"`) и в именованных диапазонах. В `xl/workbook.xml` ищите `<sheet state="hidden">`; в `sheet*.xml` — значения вне видимой области.

```bash
unzip -p report.xlsx xl/workbook.xml | grep -o 'state="[^"]*"'
```

## Вложенные объекты, макросы и external links

- **`word/embeddings/`** — вложенные OLE-объекты (второй документ, exe, архив). `unzip -l` покажет `oleObject1.bin`; это старый бинарный формат — смотрите `olevba`, `oletools`.
- **Макросы (`.docm`)** — `word/vbaProject.bin`. Разбирается `olevba` из набора `oletools`.
- **External links / OLE DDE** — связи, которые тянут данные с внешнего ресурса (фишинг/утечка).
- **`word/settings.xml`** — иногда там прячут подсказки в комментариях.

```bash
sudo apt install -y oletools
olevba report.docm           # извлечь и проанализировать VBA
oleid report.docm            # быстрый «светофор» угроз
```

## Дописанные данные после ZIP

ZIP-формат читается с конца (End of Central Directory), поэтому данные, дописанные **после** архива, не мешают его открытию. Это удобный канал: `unzip` откроет документ, а «хвост» никто не заметит.

```bash
$ binwalk report.docx
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             Zip archive data
12345         0x3039          Zip archive data, at offset 12345
$ xxd report.docx | tail -5
00003000: 666c 6167 7b7a 6970 5f74 6169 6c7d 0a   flag{zip_tail}
```

Для поиска «лишнего» архива удобен `binwalk -e` (extract) и `foremost`/`scalpel`.

## Инструменты: oletools, exiftool, unzip, python

- **`unzip -l/-p`** — список и выгрузка частей.
- **`exiftool`** — метаданные без распаковки.
- **`oletools`** (`olevba`, `oleid`, `mraptor`) — макросы и старый OLE.
- **`zipdetails`** (Perl) — низкоуровневый разбор структуры ZIP.
- **`binwalk`/`foremost`** — вложенные и дописанные файлы.
- **Python `zipfile`** — для скриптового перебора частей и поиска аномалий (лишние записи, `flag` в имени).

```python
import zipfile
z = zipfile.ZipFile('report.docx')
for i in z.infolist():
    print(i.filename, i.file_size, i.compress_type)
    if 'flag' in i.filename.lower():
        print(z.read(i.filename))
```

## Разобранный пример: от DOCX до флага

```bash
$ exiftool invoice.docx | grep -i -E 'comment|keyword|subject'
Subject   : Base64: ZmxhZ3tkb2N4X21ldGF9
$ echo ZmxhZ3tkb2N4X21ldGF9 | base64 -d
flag{docx_meta}
$ unzip -l invoice.docx | tail -3
   1234  2024-01-01 00:00   word/embeddings/oleObject1.bin
$ binwalk -e invoice.docx    # извлечёт вложенные данные
```

Маршрут: `exiftool` → метаданные; `unzip -l` → лишние части; `olevba` → макросы; `binwalk` → дописанное. Так закрываются почти все DOCX-задачи.

## Частые ошибки и подводные камни

- **Открывать документ в Word/LibreOffice и «сохранять»** — метаданные и скрытые части перезапишутся.
- **Проверять только `word/document.xml`** — флаг часто в `docProps`, `customXml`, скрытых листах, вложениях.
- **Забыть про хвост после ZIP** — `unzip` его не покажет, нужен `binwalk`/`xxd | tail`.
- **Путать «скрытый текст» (vanish) и белый текст** — это разные механизмы.
- **Игнорировать макросы** в `.docm` — там может быть и флаг, и целая цепочка.
- **Не смотреть `.rels`** — там видны связи на кастомные части и external-ссылки.

## Разница между форматами и общий чек-лист

Все OOXML-форматы устроены одинаково, различаются лишь внутренние каталоги:

| Формат | Основной XML | Метаданные | Особые места |
|---|---|---|---|
| `.docx` | `word/document.xml` | `docProps/core.xml` | `word/embeddings/`, `word/media/`, макросы в `.docm` |
| `.xlsx` | `xl/worksheets/sheet1.xml` | `docProps/core.xml` | скрытые листы, `xl/sharedStrings.xml` |
| `.pptx` | `ppt/slides/slide1.xml` | `docProps/core.xml` | заметки в `ppt/notesSlides/`, медиа |
| `.doc` (старый) | OLE-структура | — | `olevba`, `oleid`, поток `WordDocument` |

Единый чек-лист разбора любого Office-файла:

1. `file file` — убедиться, что это действительно OOXML (или старый OLE).
2. `exiftool file` — метаданные.
3. `unzip -l file` — список частей, поиск лишних.
4. `unzip -p file word/document.xml | sed 's/<[^>]*>/ /g'` — весь видимый+скрытый текст.
5. `grep -r flag <распакованный каталог>` — прямой поиск.
6. `binwalk file` / `xxd | tail` — дописанный хвост.
7. `olevba` — макросы (для `.docm`/`.doc`).

## Автоматизация: перебор всех частей

Ручной обход утомителен; для больших документов быстрее прогнать скрипт, который ищет подозрительное во **всех** частях:

```python
import zipfile, re
z = zipfile.ZipFile('report.docx')
for name in z.namelist():
    data = z.read(name)
    if re.search(rb'flag\{', data) or b'base64' in data.lower():
        print('HIT', name, len(data))
    # очень маленькие XML-части часто кастомные
    if name.endswith('.xml') and len(data) < 200:
        print('small xml:', name, data[:200])
```

Такой проход ловит флаг в `customXml/`, в `settings.xml`, в `docProps`, в `media`-файлах и в нестандартных частях, которые легко пропустить глазами.

## Стеганография в media-частях и вложенных файлах

Картинки внутри `word/media/` — это обычные PNG/JPEG, и к ним применим весь арсенал стеганографии: `zsteg`, `steghide`, `binwalk`. Логика двухслойной задачи: сначала распаковать DOCX, затем разобрать картинку из `media/` как обычный стего-контейнер.

```bash
unzip report.docx -d report_unpacked
find report_unpacked -type f | xargs file
zsteg report_unpacked/word/media/image1.png
```

Вложенные `word/embeddings/oleObject*.bin` — старые OLE-документы; их разбирают `olevba`/`oletools` и `binwalk`. Часто там лежит второй документ или архив, а флаг — глубже.

## Защита и «следы» (что видно защитнику)

С точки зрения blue team, Office-файлы — вектор как для стеганографии, так и для доставки малвари. Полезно знать признаки:

- Макросы `AutoOpen`/`Document_Open` — автозапуск.
- Внешние ссылки (external relationships) — тянут контент из сети.
- OLE-объекты с расширением `.exe`/`.js` внутри `embeddings`.
- Аномальные размеры `document.xml` при малом видимом тексте — признак скрытого контента.

Инструменты защиты: `oleid` (светофор), `mraptor` (детект подозрительных макросов), статический анализ в sandbox. Для CTF достаточно `olevba` и `exiftool`.

## Ссылки на стандарты и полезные материалы

- ECMA-376 (Office Open XML) — официальная спецификация структуры частей.
- RFC 1952 (gzip) и PKWARE APPNOTE — для разбора вложенных архивов.
- Проект `oletools` — набор скриптов для анализа OLE/OOXML-документов.
- `zipdetails` из `libarchive-zip-perl` — низкоуровневый дамп ZIP-структуры.

## Что делать дальше / решение

- `exiftool file` и `unzip -l file` — с этого начинайте всегда.
- Нашли подозрительную часть — `unzip -p file part` и смотрите XML/base64.
- Хвост после архива — `binwalk -e` или `dd`.
- Макросы — `olevba`. Старый формат — `oletools`.
- Скрытые листы Excel — `grep state="hidden"`.
- Ничего в XML — проверьте `word/media/` (картинки могут сами быть стего-контейнерами) и вложения.

## Квиз

```quiz
- question: "Что такое DOCX с точки зрения формата?"
  options:
    - "ZIP-архив с XML и медиа"
    - "Бинарный формат без сжатия"
    - "Текстовый файл"
    - "Исполняемый файл"
  answer: 0
  explanation: "OOXML — это ZIP-контейнер с XML-частями."
- question: "Каким тегом помечается скрытый текст в DOCX?"
  options:
    - "w:vanish"
    - "w:color"
    - "w:sz"
    - "w:b"
  answer: 0
  explanation: "w:vanish делает текст скрытым."
- question: "Где лежат макросы в документе?"
  options:
    - "word/vbaProject.bin"
    - "word/document.xml"
    - "docProps/core.xml"
    - "[Content_Types].xml"
  answer: 0
  explanation: "VBA-проект хранится в vbaProject.bin."
- question: "Чем извлечь дописанный после ZIP архив?"
  options:
    - "binwalk -e / foremost"
    - "jadx"
    - "apktool"
    - "nm"
  answer: 0
  explanation: "binwalk/foremost находят и извлекают данные после конца архива."
- question: "Какой инструмент анализирует VBA-макросы?"
  options:
    - "olevba (oletools)"
    - "zsteg"
    - "steghide"
    - "exiftool"
  answer: 0
  explanation: "olevba извлекает и анализирует VBA-код."
```

## Где пригодится

- **CTF Stego/Forensics:** офисные документы с секретами.
- **Malware analysis:** разбор вредоносных макросов.
- **Bug bounty:** скрытые данные в документах.
- **Работа:** IR и анализ фишинговых вложений.
