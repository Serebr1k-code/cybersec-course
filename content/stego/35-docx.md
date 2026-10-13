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
lab:
  kind: shell
  title: "Практика: достать скрытую часть DOCX"
  toolset: [core, unzip]
  workdir: /home/student/task
  files: [task.md, notes.txt, report.docx]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Определи тип: `file report.docx` (это ZIP)."
    - "Посмотри части: `unzip -l report.docx`."
    - "Обрати внимание на `docProps/custom.xml`."
    - "Достань флаг: `unzip -p report.docx docProps/custom.xml > found.txt`."

---

## Вопрос, с которого всё начинается

Тебе дали `invoice.docx` — обычный Word-документ. Флаг спрятан внутри. Но это не бинарный формат, который надо «парсить» — тут всё гораздо проще, если знать один секрет.

Секрет такой: `.docx`, `.xlsx`, `.pptx` — это **ZIP-архивы** с набором XML-частей (стандарт OOXML). Значит, первое действие — распаковать документ как архив.

## Наш пример: invoice.docx

Начнём с того, что видит `unzip`:

```
$ file invoice.docx
invoice.docx: Microsoft Word 2007+
$ unzip -l invoice.docx
  Length      Name
       1234   [Content_Types].xml
        567   _rels/.rels
        890   word/document.xml
        456   word/_rels/document.xml.rels
        456   docProps/core.xml
        789   docProps/app.xml
```

Внутри — XML-части. `word/document.xml` содержит текст, `docProps/core.xml` — метаданные. Разберём по порядку.

## Шаг 1: метаданные (docProps/core.xml)

Метаданные — самый дешёвый источник. Проверим их без распаковки через `exiftool`:

```
$ exiftool invoice.docx
Creator          : john.doe
Last Modified By : admin
Subject          : Base64: ZmxhZ3tkb2N4X21ldGF9
```

Поле `Subject` содержит base64. Декодируем:

```
$ echo ZmxhZ3tkb2N4X21ldGF9 | base64 -d
flag{docx_meta}
```

Флаг в метаданных — очень частая закладка. Часто он лежит прямо в `Keywords`, `Comments`, `Subject` или `Author`.

## Шаг 2: текст документа (word/document.xml)

Если метаданные чисты, вытащим текст. Можно просто убрать все XML-теги:

```
$ unzip -p invoice.docx word/document.xml | sed -e 's/<[^>]*>/ /g' | tr -s ' '
The visible sentence.  flag{h1dd3n_t3xt}
```

Флаг оказался в тексте, но не виден в Word. Почему? Классика Word-стего:

- **белый текст на белом фоне** (задан цвет шрифта);
- **скрытый текст** — тег `<w:vanish/>` (режим «hidden», не отображается и не печатается);
- **микроскопический текст** — `<w:sz w:val="2"/>` (размер 1 pt);
- **текст в колонтитулах/сносках**.

Ищем теги:

```
$ unzip -p invoice.docx word/document.xml | grep -o 'w:vanish' | wc -l
$ unzip -p invoice.docx word/document.xml | grep -o 'w:color w:val="[^"]*"'
```

## Шаг 3: лишние и кастомные части

OOXML позволяет добавлять **произвольные** части. Автор кладёт флаг в кастомный XML и регистрирует его в `[Content_Types].xml` и `.rels`. Ищем части, которых «не должно быть»:

```
$ unzip -l invoice.docx | grep -v -E 'word/|docProps|_rels|Content_Types'
   1234  customXml/item1.xml
```

В Excel прячут в **скрытых листах** (`state="hidden"`/`"veryHidden"`):

```
$ unzip -p report.xlsx xl/workbook.xml | grep -o 'state="[^"]*"'
```

## Шаг 4: вложенные объекты и макросы

- **`word/embeddings/`** — вложенные OLE-объекты (второй документ, exe, архив);
- **макросы (`.docm`)** — `word/vbaProject.bin`, разбирается `olevba`;
- **внешние ссылки** — тянут контент из сети.

```
$ unzip -l invoice.docx | grep embeddings
   1234  word/embeddings/oleObject1.bin
$ olevba invoice.docm
$ oleid invoice.docm
```

## Шаг 5: дописанные данные после ZIP

ZIP читается с конца (End of Central Directory), поэтому данные, дописанные **после** архива, не мешают открытию:

```
$ binwalk invoice.docx
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             Zip archive data
12345         0x3039          Zip archive data, at offset 12345
$ xxd invoice.docx | tail -3
00003000: 666c 6167 7b7a 6970 5f74 6169 6c7d 0a   flag{zip_tail}
```

## Шаг 6: автоматизация перебора частей

Ручной обход утомителен. Прогоним скрипт, который ищет подозрительное во **всех** частях:

```python
import zipfile, re
z = zipfile.ZipFile('invoice.docx')
for name in z.namelist():
    data = z.read(name)
    if re.search(rb'flag\{', data) or b'base64' in data.lower():
        print('HIT', name, len(data))
    if name.endswith('.xml') and len(data) < 200:
        print('small xml:', name, data[:200])
```

Такой проход ловит флаг в `customXml/`, `settings.xml`, `docProps`, `media`-файлах.

## Шаг 7: картинки внутри как отдельные контейнеры

Картинки в `word/media/` — обычные PNG/JPEG, к ним применим весь арсенал стеганографии:

```
$ unzip invoice.docx -d unpacked
$ zsteg unpacked/word/media/image1.png
```

## Если не сработало

- Не открывай документ в Word/LibreOffice и не сохраняй — части перезапишутся.
- Проверь не только `word/document.xml`, но и `docProps`, `customXml`, скрытые листы, вложения.
- Не забудь хвост после ZIP — `unzip` его не покажет, нужен `binwalk`/`xxd | tail`.
- Не путай «скрытый текст» (`vanish`) и белый текст — это разные механизмы.

## Что мы теперь знаем

1. DOCX/XLSX/PPTX — это ZIP с XML-частями (OOXML).
2. Метаданные (`docProps/core.xml`) — дешёвый источник флагов.
3. Текст бывает «невидимым»: белый цвет, `<w:vanish/>`, размер 1 pt.
4. Есть кастомные части, скрытые листы, вложения и макросы.
5. После ZIP можно дописать данные — их находит `binwalk`.

## Шаг 8: разница форматов и общий чек-лист

Все OOXML-форматы устроены одинаково, различаются лишь внутренние каталоги:

| Формат | Основной XML | Метаданные | Особые места |
|---|---|---|---|
| `.docx` | `word/document.xml` | `docProps/core.xml` | `word/embeddings/`, `media/`, макросы (`.docm`) |
| `.xlsx` | `xl/worksheets/sheet1.xml` | `docProps/core.xml` | скрытые листы, `xl/sharedStrings.xml` |
| `.pptx` | `ppt/slides/slide1.xml` | `docProps/core.xml` | заметки в `ppt/notesSlides/`, медиа |
| `.doc` (старый) | OLE-структура | — | `olevba`, `oleid`, поток `WordDocument` |

Единый чек-лист разбора любого Office-файла:

1. `file file` — убедиться, что это OOXML (или старый OLE).
2. `exiftool file` — метаданные.
3. `unzip -l file` — список частей, поиск лишних.
4. `unzip -p file word/document.xml | sed 's/<[^>]*>/ /g'` — весь видимый и скрытый текст.
5. `grep -r flag <распакованный каталог>` — прямой поиск.
6. `binwalk file` / `xxd | tail` — дописанный хвост.
7. `olevba` — макросы (для `.docm`/`.doc`).

## Шаг 9: защита и «следы»

С точки зрения blue team Office-файлы — вектор и для стеганографии, и для доставки малвари. Признаки:

- макросы `AutoOpen`/`Document_Open` — автозапуск;
- внешние ссылки (external relationships) — тянут контент из сети;
- OLE-объекты с расширением `.exe`/`.js` внутри `embeddings`;
- аномальный размер `document.xml` при малом видимом тексте — признак скрытого контента.

Инструменты защиты: `oleid` (светофор), `mraptor` (детект подозрительных макросов), статический анализ в sandbox. Для CTF достаточно `olevba` и `exiftool`.

## Шаг 10: стеганография в media-частях

Картинки внутри `word/media/` — это обычные PNG/JPEG, и к ним применим весь арсенал стеганографии: `zsteg`, `steghide`, `binwalk`. Логика двухслойной задачи: сначала распаковать DOCX, затем разобрать картинку из `media/` как обычный стего-контейнер.

```
$ unzip invoice.docx -d unpacked
$ find unpacked -type f | xargs file
$ zsteg unpacked/word/media/image1.png
```

Вложенные `word/embeddings/oleObject*.bin` — старые OLE-документы; их разбирают `olevba`/`oletools` и `binwalk`. Часто там лежит второй документ или архив, а флаг — глубже.

## Почему OOXML — идеальный контейнер для сокрытия

DOCX/XLSX/PPTX — это не «бинарные» форматы, а **ZIP-архивы с XML внутри**. Файл `document.docx` — обычный zip: `[Content_Types].xml`, папки `word/`, `docProps/`, `_rels/` и так далее. Такая структура даёт сразу несколько каналов сокрытия, и все они «законны» с точки зрения формата.

Первый — **скрытые части**. ZIP может содержать любые дополнительные записи, которые офисный редактор просто игнорирует: лишние XML, картинки, файлы в нестандартных папках. Их не видно в интерфейсе, но `unzip -l` их покажет. Второй — **метаданные** в `docProps/core.xml` и `app.xml`: автор, компания, комментарии, ревизии — туда пишут произвольные строки. Третий — **скрытый текст** в `word/document.xml`: текст с флагом `w:vanish` не отображается, но лежит в файле. Четвёртый — **вложенные объекты и макросы**: OLE-объекты и `vbaProject.bin` (в `.docm`) — это отдельные бинарные файлы внутри ZIP. Пятый — **дописанные данные** после конца ZIP-архива.

Общий принцип тот же, что и с другими контейнерами: **сравнивайте заявленную структуру с фактическим содержимым**. `unzip -l`, `zipinfo`, `binwalk`, `exiftool` и `strings` быстро показывают лишнее. Часто задача сводится к «найти нестандартную часть и прочитать её».

## Частые вопросы

**Как перебрать все части документа?** `unzip -l file.docx`, затем `unzip -p file.docx word/document.xml` для конкретной части; или распакуйте всё в папку и ищите `grep -r`.

**Почему DOCX, а не старый DOC?** Старый `.doc` — бинарный OLE-формат (Compound File), там другой набор приёмов; OOXML проще анализировать из-за XML.

**Где искать скрытый текст?** В `word/document.xml` ищите атрибуты `w:vanish`, `w:color` с цветом фона, текст в `w:instrText` (поля) и в колонтитулах.

**Что делать с макросами?** Если это `.docm`, распакуйте `word/vbaProject.bin` и анализируйте `olevba`/`oletools`; макросы часто содержат полезную нагрузку.

## Квиз

Проверь себя.

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
    - "`binwalk -e` / `foremost`"
    - "`jadx`"
    - "`apktool`"
    - "`nm`"
  answer: 0
  explanation: "binwalk/foremost находят и извлекают данные после конца архива."
- question: "Какой инструмент анализирует VBA-макросы?"
  options:
    - "`olevba` (oletools)"
    - "`zsteg`"
    - "`steghide`"
    - "`exiftool`"
  answer: 0
  explanation: "olevba извлекает и анализирует VBA-код."
```

## Куда дальше

Дальше — **стеганография на диске**: slack space, ADS и скрытые разделы, где данные прячут на уровне файловой системы. А пока запомни: Office-документ — это ZIP, и разбирать его надо как архив.

## Где пригодится

- **CTF (Stego/Forensics):** офисные документы с секретами.
- **Malware-анализ:** разбор вредоносных макросов.
- **Bug bounty:** скрытые данные в документах.
- **Работа:** IR и анализ фишинговых вложений.
