#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch 2b — document/office container stego lessons + office hub."""
import io, zipfile, base64
from _gen_stego_lib import emit, lab_json, write


def make_zip(entries):
    """entries: list of (name, bytes)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()


# ===========================================================================
# stego-epub
# ===========================================================================
epub_body = r"""
## Вопрос, с которого всё начинается
EPUB — самый распространённый формат электронных книг. Ты открываешь его в
читалке, видишь текст. Но EPUB — это **ZIP-архив** со строго заданной структурой,
и внутри него легко спрятать файл, который ни одна читалка не покажет. Задача:
найти в книге то, чего в тексте нет.

## Наш пример
Возьмём `book.epub` — минимальную книгу. Разберём её как ZIP и найдём
непронумерованный файл.

## Шаг 1: EPUB — это ZIP
```
$ file book.epub
book.epub: EPUB document
$ unzip -l book.epub
  Length      Name
        20  mimetype
       250  META-INF/container.xml
      1024  OEBPS/content.opf
      2048  OEBPS/chapter1.xhtml
       120  OEBPS/secret.txt
```

Первая запись обязана быть `mimetype` со строкой `application/epub+zip` и
**без сжатия** — иначе валидатор EPUB отклонит файл. Всё остальное — обычные
ZIP-записи.

## Шаг 2: как устроена книга
- `META-INF/container.xml` — указывает путь к OPF-файлу (пакету).
- `OEBPS/content.opf` — манифест (список ресурсов), spine (порядок глав),
  метаданные (автор, ISBN, обложка).
- `OEBPS/*.xhtml` — сам текст.
- `OEBPS/*.css`, картинки — оформление.

Читалка показывает только то, что перечислено в spine/manifest. Файл, которого
там нет, остаётся невидимым.

## Шаг 3: где прячут данные в EPUB
- **Непронумерованные файлы.** Любая запись ZIP, не упомянутая в OPF, — невидима
  для читалки.
- **Метаданные OPF.** `<dc:description>`, `<meta property="dcterms:...">` —
  произвольные строки.
- **CSS-комментарии.** `/* ... */` в таблице стилей.
- **Обложка.** Данные в пикселях или в EXIF обложки.
- **Пустые/служебные записи.** `META-INF/encryption.xml` и подобное.

## Шаг 4: извлечение вручную
```python
import zipfile
z = zipfile.ZipFile('book.epub')
opf = z.read('OEBPS/content.opf').decode()
for name in z.namelist():
    if 'secret' in name or name not in opf:
        print(name, z.read(name))
```

Вывод:

```
OEBPS/secret.txt b'nto{epub_unreferenced_file}'
```

## Шаг 5: инструменты
- `unzip -l book.epub` — список записей.
- `epubcheck book.epub` — валидатор (лишние файлы выдаст предупреждением).
- `zipinfo -v` — детали записей.

## Что мы теперь знаем
- EPUB — ZIP с обязательным `mimetype` и OPF-манифестом.
- Непронумерованные файлы невидимы для читалки.
- Метаданные, CSS-комментарии, обложка — дополнительные каналы.
- Разбор начинается с `unzip -l` и чтения OPF.

## Квиз

Проверь себя.

```quiz
- question: "Что представляет собой EPUB-файл на уровне контейнера?"
  options:
    - "ZIP-архив с обязательным mimetype и OPF-манифестом"
    - "Простой текстовый файл"
    - "JPEG-изображение"
    - "Исполняемый файл"
  answer: 0
  explanation: "EPUB — это ZIP со строго заданной структурой."
- question: "Почему файл, не упомянутый в OPF, невидим читалке?"
  options:
    - "Читалка отображает только ресурсы из манифеста/spine"
    - "Он зашифрован"
    - "Он удалён"
    - "Он слишком большой"
  answer: 0
  explanation: "Показ определяется манифестом; прочие записи игнорируются."
- question: "Каким должно быть первое вхождение ZIP в EPUB?"
  options:
    - "`mimetype` без сжатия со строкой application/epub+zip"
    - "Обложка JPEG"
    - "content.opf"
    - "container.xml"
  answer: 0
  explanation: "Спецификация требует несжатый mimetype первым."
- question: "Где ещё в EPUB можно спрятать данные?"
  options:
    - "В метаданных OPF, CSS-комментариях, обложке"
    - "Только в названии книги"
    - "Только в ISBN"
    - "Нигде"
  answer: 0
  explanation: "Метаданные и оформление — дополнительные носители."
```

## Куда дальше
EPUB — ZIP с манифестом. Родственный формат — OpenDocument (ODT), где канал
живёт в `meta.xml`. О нём — в следующем уроке.

## Где пригодится
- **CTF:** задачи с книгами и архивами документов.
- **Форензика:** анализ вложений-книг.
- **Blue team:** носители данных в безобидных документах.
""".strip()

epub_flag = "nto{epub_unreferenced_file}"
epub_zip = make_zip([
    ("mimetype", b"application/epub+zip"),
    ("META-INF/container.xml",
     b'<?xml version="1.0"?><container><rootfiles><rootfile full-path="OEBPS/content.opf"/></rootfiles></container>'),
    ("OEBPS/content.opf",
     b'<?xml version="1.0"?><package><manifest><item id="c1" href="chapter1.xhtml"/></manifest><spine><itemref idref="c1"/></spine></package>'),
    ("OEBPS/chapter1.xhtml", b'<html><body><h1>Chapter 1</h1><p>Hello.</p></body></html>'),
    ("OEBPS/secret.txt", epub_flag.encode()),
])
epub_parser = (
    "import zipfile\n"
    "z = zipfile.ZipFile('book.epub')\n"
    "opf = z.read('OEBPS/content.opf').decode()\n"
    "for name in z.namelist():\n"
    "    if name.endswith('secret.txt'):\n"
    "        print(z.read(name).decode())\n"
)
epub_task = ("# Задача: необъявленный файл в EPUB\n\n"
             "`book.epub` — ZIP-архив. Один файл не упомянут в OPF-манифесте.\n\n"
             "1. `unzip -l book.epub`.\n"
             "2. `python3 epub.py` — чтение скрытого файла.\n"
             "3. `python3 epub.py | grep nto > found.txt`.\n")
emit("stego-epub", """---
id: stego-epub
title: "EPUB-стеганография: непронумерованные файлы и метаданные"
category: stego
parent: stego-module-office-adv
difficulty: medium
order: 1
tags: [stego, epub, zip, opf, container, document]
prerequisites: [stego-document-carriers]
useful_for:
  - "CTF Stego: книги и архивы документов"
  - "Форензика: анализ вложений-книг"
  - "Blue team: носители в безобидных документах"
estimated_minutes: 15
summary: "Разбираем EPUB как ZIP: mimetype, META-INF/container.xml, OPF-манифест, spine. Где прячут данные (непронумерованные файлы, метаданные, CSS) и как извлекать их."
lab:
  kind: shell
  title: "Практика: скрытый файл в EPUB"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, book.epub, epub.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "EPUB — это ZIP: `unzip -l book.epub`."
    - "Скрытый файл не упомянут в content.opf."
    - "`python3 epub.py` печатает его содержимое."
    - "`python3 epub.py | grep nto > found.txt`."
---

""" + epub_body + "\n", lab_json(
    "stego-epub", epub_flag, epub_task,
    [("book.epub", ("b64", epub_zip)), ("epub.py", ("text", epub_parser))],
    [{"match": "epub\\.py", "example": "python3 epub.py", "output": epub_flag + "\n"}]))

# ===========================================================================
# stego-odf
# ===========================================================================
odf_body = r"""
## Вопрос, с которого всё начинается
OpenDocument (ODT/ODS/ODP) — открытый формат LibreOffice и многих госструктур.
Как и EPUB, это ZIP. Но у него есть особенность: служебные XML-файлы, которые
редактор не показывает. Один из них — `meta.xml` — принимает **пользовательские
поля** произвольной длины. Идеальное место для закладки.

## Наш пример
Возьмём `doc.odt` — минимальный документ. Разберём его ZIP-структуру и найдём
закладку в `meta.xml`.

## Шаг 1: структура ODF
```
$ unzip -l doc.odt
  Length      Name
        39  mimetype
       900  META-INF/manifest.xml
      1200  content.xml
       600  styles.xml
       420  meta.xml
       300  settings.xml
```

`mimetype` — `application/vnd.oasis.opendocument.text` (первая запись, без
сжатия). Далее — XML-файлы:
- `content.xml` — текст и разметка;
- `styles.xml` — стили;
- `meta.xml` — метаданные (автор, дата, **пользовательские поля**);
- `settings.xml` — настройки окна;
- `META-INF/manifest.xml` — список файлов и типов.

## Шаг 2: пользовательские поля в meta.xml
Стандарт ODF определяет элемент `meta:user-defined` с атрибутом `meta:name` и
произвольным текстовым значением. Никто его не отображает — это «техническое»
поле:

```xml
<meta:user-defined meta:name="BuildID">bnRve29kZl9tZXRhX2ZpZWxkfQ==</meta:user-defined>
```

Значение — base64. Редактор сохранит его, читатель не увидит.

## Шаг 3: другие каналы в ODF
- **Лишние файлы.** Запись ZIP, не указанная в `manifest.xml`, — невидима.
- **`content.xml` пробелы.** Как в JSON: незначащие пробелы между тегами.
- **Встроенные объекты.** `Thumbnails/thumbnail.png` — картинка, в пикселях
  которой можно спрятать данные.
- **`settings.xml`.** Произвольные пары ключ-значение.

## Шаг 4: извлечение вручную
```python
import zipfile, base64, re
z = zipfile.ZipFile('doc.odt')
meta = z.read('meta.xml').decode()
m = re.search(r'meta:user-defined[^>]*>([^<]+)<', meta)
print(base64.b64decode(m.group(1)).decode())
```

Вывод:

```
nto{odf_meta_field}
```

## Шаг 5: инструменты
- `unzip -l doc.odt`, `unzip -p doc.odt meta.xml`.
- `odfpy` / `python3 -c 'from odf.opendocument import load'` — программный разбор.
- `libreoffice --headless --convert-to` — нормализация (перезапись файла убивает
  лишние поля).

## Что мы теперь знаем
- ODF — ZIP с `mimetype` и XML-файлами (`content`, `styles`, `meta`, `settings`).
- `meta:user-defined` — штатное поле для произвольных данных.
- Лишние файлы и встроенные миниатюры — дополнительные каналы.
- Пересохранение в LibreOffice — нормализация.

## Квиз

Проверь себя.

```quiz
- question: "Что такое ODF на уровне контейнера?"
  options:
    - "ZIP с mimetype и набором XML-файлов"
    - "Один бинарный файл без структуры"
    - "Текстовый файл"
    - "База данных SQLite"
  answer: 0
  explanation: "ODT/ODS/ODP — это ZIP-контейнеры с XML."
- question: "Какой элемент ODF предназначен для произвольных полей?"
  options:
    - "meta:user-defined с meta:name"
    - "content:text"
    - "office:body"
    - "style:default"
  answer: 0
  explanation: "Пользовательские метаданные хранятся в meta.xml."
- question: "Почему файл, отсутствующий в manifest.xml, невидим?"
  options:
    - "Редактор ориентируется на манифест при чтении"
    - "Он зашифрован"
    - "Он слишком маленький"
    - "Он в другой кодировке"
  answer: 0
  explanation: "Манифест перечисляет содержимое; лишние записи игнорируются."
- question: "Что убивает закладку в meta.xml?"
  options:
    - "Пересохранение документа в редакторе (нормализация)"
    - "Открытие на просмотр"
    - "Смена имени файла"
    - "Копирование"
  answer: 0
  explanation: "Редактор перезаписывает служебные поля по своей схеме."
```

## Куда дальше
ODF и EPUB — «документные» ZIP-контейнеры. Дальше — OOXML (XLSX/PPTX), где
каналов ещё больше: скрытые листы, заметки, вынесенные за пределы слайда фигуры.

## Где пригодится
- **CTF:** задачи с офисными документами.
- **Форензика:** разбор документов-улик.
- **Blue team:** данные в служебных XML офисных файлов.
""".strip()

odf_flag = "nto{odf_meta_field}"
odf_b64 = base64.b64encode(odf_flag.encode()).decode()
odf_zip = make_zip([
    ("mimetype", b"application/vnd.oasis.opendocument.text"),
    ("META-INF/manifest.xml", b'<?xml version="1.0"?><manifest:manifest><manifest:file-entry manifest:full-path="content.xml"/></manifest:manifest>'),
    ("content.xml", b'<?xml version="1.0"?><office:document-content><office:body><office:text><text:p>Hello</text:p></office:text></office:body></office:document-content>'),
    ("styles.xml", b'<?xml version="1.0"?><office:document-styles/>'),
    ("meta.xml", ('<?xml version="1.0"?><office:document-meta><meta:meta>'
                  f'<meta:user-defined meta:name="BuildID">{odf_b64}</meta:user-defined>'
                  '</meta:meta></office:document-meta>').encode()),
    ("settings.xml", b'<?xml version="1.0"?><office:document-settings/>'),
])
odf_parser = (
    "import zipfile, base64, re\n"
    "z = zipfile.ZipFile('doc.odt')\n"
    "meta = z.read('meta.xml').decode()\n"
    "m = re.search(r'meta:user-defined[^>]*>([^<]+)<', meta)\n"
    "print(base64.b64decode(m.group(1)).decode())\n"
)
odf_task = ("# Задача: пользовательское поле в meta.xml\n\n"
            "`doc.odt` — ODF-документ. В `meta.xml` есть base64 в meta:user-defined.\n\n"
            "1. `unzip -l doc.odt`.\n"
            "2. `python3 odf.py` — декодирование.\n"
            "3. `python3 odf.py | grep nto > found.txt`.\n")
emit("stego-odf", """---
id: stego-odf
title: "OpenDocument (ODT/ODS/ODP): meta.xml и лишние файлы"
category: stego
parent: stego-module-office-adv
difficulty: medium
order: 2
tags: [stego, odf, odt, meta-xml, zip, document]
prerequisites: [stego-epub]
useful_for:
  - "CTF Stego: офисные документы"
  - "Форензика: документы-улики"
  - "Blue team: служебные XML офисных файлов"
estimated_minutes: 15
summary: "OpenDocument как ZIP: mimetype, content/styles/meta/settings.xml, пользовательские поля meta:user-defined, лишние файлы и встроенные миниатюры как каналы."
lab:
  kind: shell
  title: "Практика: base64 в meta:user-defined"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, doc.odt, odf.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "ODT — это ZIP: `unzip -l doc.odt`."
    - "Ищи `meta:user-defined` в meta.xml."
    - "`python3 odf.py` декодирует base64."
    - "`python3 odf.py | grep nto > found.txt`."
---

""" + odf_body + "\n", lab_json(
    "stego-odf", odf_flag, odf_task,
    [("doc.odt", ("b64", odf_zip)), ("odf.py", ("text", odf_parser))],
    [{"match": "odf\\.py", "example": "python3 odf.py", "output": odf_flag + "\n"}]))

# ===========================================================================
# stego-xlsx-hidden
# ===========================================================================
xlsx_body = r"""
## Вопрос, с которого всё начинается
Excel-файл `.xlsx` выглядит как таблица. Но внутри это OOXML-архив, и Excel умеет
**скрывать** листы, строки, столбцы и целые XML-части. Скрытый лист не показывается
на вкладках, но данные в нём живут. Задача: найти то, что Excel не показывает.

## Наш пример
Возьмём `report.xlsx` — книгу с одним видимым листом и одним `veryHidden`.

## Шаг 1: XLSX — это ZIP
```
$ unzip -l report.xlsx
       120  [Content_Types].xml
       380  xl/workbook.xml
       520  xl/worksheets/sheet1.xml
       540  xl/worksheets/sheet2.xml
       210  xl/sharedStrings.xml
       300  xl/_rels/workbook.xml.rels
```

- `[Content_Types].xml` — типы частей;
- `xl/workbook.xml` — список листов и их состояние;
- `xl/worksheets/sheetN.xml` — сами ячейки;
- `xl/sharedStrings.xml` — общие строки;
- `xl/_rels/...` — связи.

## Шаг 2: состояния листов
В `workbook.xml` у каждого `<sheet>` есть атрибут `state`:
- `visible` (по умолчанию),
- `hidden`,
- `veryHidden` — лист нельзя показать через меню Excel, только через VBA или
  правку XML.

```xml
<sheets>
  <sheet name="Report" sheetId="1" state="visible"/>
  <sheet name="nto{xlsx_veryhidden_sheet}" sheetId="2" state="veryHidden"/>
</sheets>
```

Имя листа `veryHidden` — уже носитель: его не видно в интерфейсе.

## Шаг 3: скрытые строки и столбцы
В `sheetN.xml` строки и столбцы могут иметь `hidden="1"`:

```xml
<row r="5" hidden="1"><c r="A5" t="s"><v>7</v></c></row>
<col min="7" max="7" hidden="1"/>
```

Значение `t="s"` означает индекс в `sharedStrings.xml`. Скрытые данные — там.

## Шаг 4: ещё каналы в XLSX
- **Определённые имена** (`definedNames`) — произвольные строки-формулы.
- **`customXml/` части** — прикреплённые XML-данные, невидимые в сетке.
- **Комментарии и примечания** — `xl/comments1.xml`.
- **Внешние связи** (`externalLinks`) — URL с данными.

## Шаг 5: извлечение вручную
```python
import zipfile, re
z = zipfile.ZipFile('report.xlsx')
wb = z.read('xl/workbook.xml').decode()
for m in re.finditer(r'name="([^"]+)"[^>]*state="veryHidden"', wb):
    print(m.group(1))
```

Вывод:

```
nto{xlsx_veryhidden_sheet}
```

## Шаг 6: инструменты
- `unzip -l report.xlsx`.
- `python3 -c 'import openpyxl'` — программный разбор (может не показать
  veryHidden без явного доступа).
- `libreoffice --headless --convert-to xlsx` — нормализация.

## Что мы теперь знаем
- XLSX — ZIP с `[Content_Types].xml`, `workbook.xml`, листами и строками.
- `state="veryHidden"` делает лист невидимым для интерфейса Excel.
- Скрытые строки/столбцы, definedNames и customXml — дополнительные каналы.
- Разбор начинается с `workbook.xml`.

## Квиз

Проверь себя.

```quiz
- question: "Что такое XLSX на уровне контейнера?"
  options:
    - "ZIP с XML-частями OOXML"
    - "Один бинарный файл"
    - "CSV с расширением"
    - "SQLite-база"
  answer: 0
  explanation: "OOXML-документы — это ZIP с XML-частями."
- question: "Чем `veryHidden` отличается от `hidden`?"
  options:
    - "Лист нельзя показать через меню Excel, только через VBA/правку XML"
    - "Он зашифрован"
    - "Он пустой"
    - "Он только для чтения"
  answer: 0
  explanation: "veryHidden не отображается в диалоге показа скрытых листов."
- question: "Где в sheetN.xml указано, что строка скрыта?"
  options:
    - "Атрибут hidden=\"1\" у <row> или <col>"
    - "Тег <secret>"
    - "Комментарий"
    - "Цвет заливки"
  answer: 0
  explanation: "Скрытые строки/столбцы помечаются атрибутом hidden."
- question: "Какой ещё элемент OOXML может быть каналом?"
  options:
    - "definedNames, customXml-части, комментарии"
    - "Только имя файла"
    - "Только шрифт"
    - "Только число листов"
  answer: 0
  explanation: "Имена, прикреплённый XML и комментарии не видны в сетке."
```

## Куда дальше
XLSX прячет данные в скрытых листах. PPTX идёт дальше: заметки докладчика,
комментарии и фигуры за пределами слайда.

## Где пригодится
- **CTF:** задачи с электронными таблицами.
- **Форензика:** скрытые данные в финансовых книгах.
- **Blue team:** эксфильтрация через «пустые» листы.
""".strip()

xlsx_flag = "nto{xlsx_veryhidden_sheet}"
xlsx_zip = make_zip([
    ("[Content_Types].xml", b'<?xml version="1.0"?><Types/>'),
    ("xl/workbook.xml",
     ('<?xml version="1.0"?><workbook><sheets>'
      '<sheet name="Report" sheetId="1" state="visible"/>'
      f'<sheet name="{xlsx_flag}" sheetId="2" state="veryHidden"/>'
      '</sheets></workbook>').encode()),
    ("xl/worksheets/sheet1.xml", b'<?xml version="1.0"?><worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData></worksheet>'),
    ("xl/worksheets/sheet2.xml", b'<?xml version="1.0"?><worksheet><sheetData/></worksheet>'),
    ("xl/sharedStrings.xml", b'<?xml version="1.0"?><sst><si><t>Report</t></si></sst>'),
])
xlsx_parser = (
    "import zipfile, re\n"
    "z = zipfile.ZipFile('report.xlsx')\n"
    "wb = z.read('xl/workbook.xml').decode()\n"
    "for m in re.finditer(r'name=\"([^\"]+)\"[^>]*state=\"veryHidden\"', wb):\n"
    "    print(m.group(1))\n"
)
xlsx_task = ("# Задача: veryHidden лист в XLSX\n\n"
             "`report.xlsx` — книга OOXML. Один лист скрыт как veryHidden.\n\n"
             "1. `unzip -l report.xlsx`.\n"
             "2. `python3 xlsx.py` — имя скрытого листа.\n"
             "3. `python3 xlsx.py | grep nto > found.txt`.\n")
emit("stego-xlsx-hidden", """---
id: stego-xlsx-hidden
title: "XLSX: скрытые листы, строки и customXml как канал"
category: stego
parent: stego-module-office-adv
difficulty: medium
order: 3
tags: [stego, xlsx, ooxml, veryhidden, zip, document]
prerequisites: [stego-odf]
useful_for:
  - "CTF Stego: электронные таблицы"
  - "Форензика: скрытые данные в книгах"
  - "Blue team: эксфильтрация через листы"
estimated_minutes: 16
summary: "XLSX как OOXML-ZIP: workbook.xml, состояния листов visible/hidden/veryHidden, скрытые строки и столбцы, definedNames и customXml-части как носители данных."
lab:
  kind: shell
  title: "Практика: veryHidden лист"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, report.xlsx, xlsx.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "XLSX — это ZIP: `unzip -l report.xlsx`."
    - "Состояния листов — в xl/workbook.xml."
    - "`python3 xlsx.py` печатает имя veryHidden-листа."
    - "`python3 xlsx.py | grep nto > found.txt`."
---

""" + xlsx_body + "\n", lab_json(
    "stego-xlsx-hidden", xlsx_flag, xlsx_task,
    [("report.xlsx", ("b64", xlsx_zip)), ("xlsx.py", ("text", xlsx_parser))],
    [{"match": "xlsx\\.py", "example": "python3 xlsx.py", "output": xlsx_flag + "\n"}]))

# ===========================================================================
# stego-pptx
# ===========================================================================
pptx_body = r"""
## Вопрос, с которого всё начинается
Презентация `.pptx` — это слайды, картинки, заметки. Показываешь её — видишь
слайды. Но внутри OOXML-архива есть заметки докладчика, комментарии, фигуры,
вынесенные за пределы слайда, и скрытые слайды. Всё это не отображается при
показе, но остаётся в файле. Идеальный носитель.

## Наш пример
Возьмём `talk.pptx` — презентацию с одним слайдом и заметкой докладчика, в
которой спрятана метка.

## Шаг 1: PPTX — это ZIP
```
$ unzip -l talk.pptx
       120  [Content_Types].xml
       420  ppt/presentation.xml
       620  ppt/slides/slide1.xml
       540  ppt/notesSlides/notesSlide1.xml
       280  ppt/_rels/presentation.xml.rels
```

- `ppt/presentation.xml` — список слайдов;
- `ppt/slides/slideN.xml` — содержимое слайда;
- `ppt/notesSlides/notesSlideN.xml` — заметки докладчика;
- `ppt/comments/` — комментарии;
- `ppt/media/` — картинки, видео.

## Шаг 2: скрытые слайды
В `presentation.xml` у слайда может быть `show="0"` — слайд скрыт при показе:

```xml
<p:sldId id="256" r:id="rId2" show="0"/>
```

Слайд есть, но в режиме презентации не показывается.

## Шаг 3: заметки докладчика
`notesSlideN.xml` содержит текст заметок. Их не видно на экране презентации, но
они полностью сохраняются:

```xml
<a:t>nto{pptx_notes_slide}</a:t>
```

## Шаг 4: фигуры за пределами слайда
Элемент `<a:off x="..." y="..."/>` задаёт позицию. Если `x` или `y` больше
размера слайда (например, 9999999 EMU), фигура «уезжает» за край и не видна.
Данные в ней сохраняются.

## Шаг 5: ещё каналы
- **Комментарии** (`ppt/comments/comment1.xml`) — невидимы при показе.
- **Медиа** — данные в пикселях картинки или в её метаданных.
- **`docProps/app.xml`** — служебные поля (Title, Company) произвольной длины.
- **`customXml/`** — прикреплённые данные.

## Шаг 6: извлечение вручную
```python
import zipfile, re
z = zipfile.ZipFile('talk.pptx')
for name in z.namelist():
    if 'notesSlide' in name:
        txt = z.read(name).decode()
        m = re.search(r'nto\{[^}]*\}', txt)
        if m:
            print(m.group(0))
```

Вывод:

```
nto{pptx_notes_slide}
```

## Шаг 7: инструменты
- `unzip -l talk.pptx`.
- `python-pptx` — программный разбор.
- `libreoffice --headless --convert-to pptx` — нормализация.

## Что мы теперь знаем
- PPTX — ZIP с `presentation.xml`, слайдами, заметками и медиа.
- `show="0"` скрывает слайд, заметки и комментарии не видны при показе.
- Фигуры за пределами слайда — простой способ спрятать контент.
- Разбор начинается с `presentation.xml` и заметок.

## Квиз

Проверь себя.

```quiz
- question: "Что такое PPTX на уровне контейнера?"
  options:
    - "ZIP с XML-частями OOXML"
    - "Один бинарный файл"
    - "Текстовый файл"
    - "Изображение"
  answer: 0
  explanation: "PPTX — OOXML-ZIP с частями presentation/slides/notes."
- question: "Как скрыть слайд при показе?"
  options:
    - "Атрибут show=\"0\" у sldId в presentation.xml"
    - "Удалить файл слайда"
    - "Зашифровать слайд"
    - "Сменить фон"
  answer: 0
  explanation: "show=\"0\" помечает слайд как скрытый."
- question: "Где хранятся заметки докладчика?"
  options:
    - "ppt/notesSlides/notesSlideN.xml"
    - "ppt/slides/slideN.xml"
    - "docProps/app.xml"
    - "[Content_Types].xml"
  answer: 0
  explanation: "Заметки — отдельные XML-части notesSlides."
- question: "Как спрятать фигуру на слайде?"
  options:
    - "Вынести её за пределы слайда (большие x/y в a:off)"
    - "Сделать её прозрачной только"
    - "Уменьшить шрифт"
    - "Скрыть слайд"
  answer: 0
  explanation: "Координаты за границей слайда делают фигуру невидимой при показе."
```

## Куда дальше
Офисные документы разобраны. Дальше — двоичные форматы: Git-объекты, слои Docker
и ELF/Mach-O. А пока запомни: контейнер-архив — это всегда много «невидимых» мест.

## Где пригодится
- **CTF:** задачи с презентациями.
- **Форензика:** данные в заметках и комментариях.
- **Blue team:** эксфильтрация через офисные вложения.
""".strip()

pptx_flag = "nto{pptx_notes_slide}"
pptx_zip = make_zip([
    ("[Content_Types].xml", b'<?xml version="1.0"?><Types/>'),
    ("ppt/presentation.xml",
     b'<?xml version="1.0"?><p:presentation><p:sldIdLst><p:sldId id="256" r:id="rId2" show="0"/></p:sldIdLst></p:presentation>'),
    ("ppt/slides/slide1.xml", b'<?xml version="1.0"?><p:sld><p:cSld><p:spTree/></p:cSld></p:sld>'),
    ("ppt/notesSlides/notesSlide1.xml",
     ('<?xml version="1.0"?><p:notes><p:cSld><p:spTree><a:t>'
      f'{pptx_flag}</a:t></p:spTree></p:cSld></p:notes>').encode()),
    ("docProps/app.xml", b'<?xml version="1.0"?><Properties/>'),
])
pptx_parser = (
    "import zipfile, re\n"
    "z = zipfile.ZipFile('talk.pptx')\n"
    "for name in z.namelist():\n"
    "    if 'notesSlide' in name:\n"
    "        txt = z.read(name).decode()\n"
    "        m = re.search(r'nto\\{[^}]*\\}', txt)\n"
    "        if m:\n"
    "            print(m.group(0))\n"
)
pptx_task = ("# Задача: заметка докладчика в PPTX\n\n"
             "`talk.pptx` — презентация OOXML. Метка спрятана в notesSlide.\n\n"
             "1. `unzip -l talk.pptx`.\n"
             "2. `python3 pptx.py` — извлечение метки.\n"
             "3. `python3 pptx.py | grep nto > found.txt`.\n")
emit("stego-pptx", """---
id: stego-pptx
title: "PPTX: заметки, скрытые слайды и фигуры за краем"
category: stego
parent: stego-module-office-adv
difficulty: medium
order: 4
tags: [stego, pptx, ooxml, notes, hidden-slide, zip, document]
prerequisites: [stego-xlsx-hidden]
useful_for:
  - "CTF Stego: презентации"
  - "Форензика: заметки и комментарии"
  - "Blue team: эксфильтрация в офисных вложениях"
estimated_minutes: 16
summary: "PPTX как OOXML-ZIP: presentation.xml, скрытые слайды (show=0), заметки докладчика, комментарии, фигуры за пределами слайда и docProps как носители данных."
lab:
  kind: shell
  title: "Практика: метка в notesSlide"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, talk.pptx, pptx.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "PPTX — это ZIP: `unzip -l talk.pptx`."
    - "Заметки лежат в ppt/notesSlides/."
    - "`python3 pptx.py` печатает метку."
    - "`python3 pptx.py | grep nto > found.txt`."
---

""" + pptx_body + "\n", lab_json(
    "stego-pptx", pptx_flag, pptx_task,
    [("talk.pptx", ("b64", pptx_zip)), ("pptx.py", ("text", pptx_parser))],
    [{"match": "pptx\\.py", "example": "python3 pptx.py", "output": pptx_flag + "\n"}]))

# ===========================================================================
# office hub
# ===========================================================================
office_hub = """---
id: stego-module-office-adv
title: "Модуль: Офисные контейнеры (EPUB, ODF, XLSX, PPTX)"
category: stego
parent: stego-document-carriers
difficulty: medium
order: 5
tags: [stego, roadmap, epub, odf, xlsx, pptx, zip, document]
prerequisites: [stego-document-carriers]
useful_for:
  - "CTF Stego: документы и книги"
  - "Форензика: разбор офисных вложений"
  - "Blue team: эксфильтрация через документы"
estimated_minutes: 8
summary: "Навигационный модуль по офисным ZIP-контейнерам: EPUB (OPF-манифест), OpenDocument (meta.xml), XLSX (veryHidden-листы) и PPTX (заметки, скрытые слайды). Общий приём — разобрать архив и найти непронумерованное."
---

## Зачем этот модуль

Офисные форматы — это ZIP-архивы с XML внутри. У каждого есть элементы, которые
редактор не отображает: непронумерованные файлы, пользовательские метаданные,
скрытые листы, заметки докладчика. Всё это — носители данных, и искать их нужно
одинаково: распаковать, прочитать манифест, найти «лишнее».

## Что разберём

- **stego-epub** — EPUB: `mimetype`, `META-INF/container.xml`, OPF-манифест,
  непронумерованные файлы.
- **stego-odf** — OpenDocument: `meta.xml`, `meta:user-defined`, лишние записи.
- **stego-xlsx-hidden** — XLSX: состояния листов (veryHidden), скрытые строки,
  `definedNames`, `customXml`.
- **stego-pptx** — PPTX: заметки, скрытые слайды (`show=0`), фигуры за краем.

## Как проходить

По порядку. В каждом уроке — реальный контейнер (`book.epub`, `doc.odt`,
`report.xlsx`, `talk.pptx`) и короткий Python-парсер на `zipfile`.

## Что вы будете уметь

- Разбирать ZIP-структуру офисного документа.
- Находить непронумерованные/скрытые части.
- Читать манифест и служебные XML.
- Нормализовать документ, чтобы убить канал.
"""
write("content/stego/stego-module-office-adv.md", office_hub + "\n")

print("batch 2b done")
