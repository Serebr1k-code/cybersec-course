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
lab:
  kind: shell
  title: "Практика: невидимый текст в PDF"
  toolset: [core]
  workdir: /home/student/task
  files: [task.md, notes.txt, hidden.pdf]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`file hidden.pdf` — PDF."
    - "Content stream PDF читается как текст: `strings hidden.pdf`."
    - "Ищи оператор `3 Tr` (невидимый текст) и строку с флагом."
    - "Запиши флаг: `strings hidden.pdf | grep nto > found.txt`."

---

## Вопрос, с которого всё начинается

Тебе дали `challenge.pdf` — на вид обычный документ с парой абзацев. Но флаг где-то внутри. PDF — не «текстовый документ», а **контейнер из объектов**: строк, словарей, потоков. Данные могут лежать в любом из них. Как пройти по слоям и не утонуть?

Разберём один PDF по шагам.

## Наш пример: challenge.pdf

Сначала — что это за файл и что видно «на поверхности».

```
$ file challenge.pdf
challenge.pdf: PDF document, version 1.7
$ strings -n 6 challenge.pdf | grep -iE 'flag|base64|http' | head
(пусто)
```

Открываем в ридере — видим обычный текст, ничего подозрительного. Значит, данные спрятаны в структуре. Начнём с самого дешёвого — метаданных.

## Шаг 1: метаданные (Info-словарь)

У PDF есть словарь `/Info` с полями `/Title`, `/Author`, `/Subject`, `/Keywords`. Туда часто кладут флаг или base64.

```
$ exiftool challenge.pdf
Title    : Report
Author   : admin
Keywords : ZmxhZ3toaWRkZW5faW5faW5mb30=
```

Поле `Keywords` выглядит как base64. Декодируем:

```
$ echo ZmxhZ3toaWRkZW5faW5faW5mb30= | base64 -d
flag{hidden_in_info}
```

Флаг найден на первом шаге. Метаданные — самая частая и самая дешёвая закладка в PDF.

## Шаг 2: структура PDF

Чтобы двигаться дальше, нужно понимать устройство. PDF состоит из:

- **тела** — объектов `N 0 obj … endobj`;
- **xref** — таблицы смещений объектов;
- **trailer** — корневого объекта (`/Root`) и ссылки на `/Info`;
- **потоков** (`stream … endstream`) — сжатых данных: контент страницы, картинки, шрифты.

Потоки обычно сжаты `FlateDecode` (zlib). Чтобы их прочитать, нужно **декодировать**. Лучший инструмент — `qpdf --qdf`:

```
$ qpdf --qdf --object-streams=disable challenge.pdf decoded.pdf
$ strings -n 6 decoded.pdf | grep -A2 'Tj'
```

`qdf`-режим делает потоки несжатыми и раскрывает объектные потоки, после чего текст и данные видны «как есть».

## Шаг 3: невидимый и наложенный текст

Классика PDF-стего — текст, который есть в файле, но не виден при рендеринге:

- **белый текст на белом фоне** (`1 1 1 rg` перед текстом);
- **текст вне MediaBox** — координаты за пределами страницы;
- **прозрачный слой** (`ExtGState` с `ca 0`);
- **режим рендеринга `Tr 3`** — invisible rendering.

Ищи текстовые операторы `Tj`/`TJ` и цвета `rg` в декодированном PDF:

```
$ strings -n 6 decoded.pdf | grep -A2 -E 'Tj|TJ'
(flag{h1dd3n_text} в белом цвете)
```

## Шаг 4: встроенные файлы (EmbeddedFiles)

В PDF можно вложить **произвольный файл** через `/EmbeddedFiles`. Это контейнер внутри контейнера.

```
$ pdfdetach -list challenge.pdf
2 embedded files
1: secret.zip
2: note.txt
$ pdfdetach -saveall challenge.pdf
$ unzip -l secret.zip
```

`binwalk` тоже находит вложения и дописанное:

```
$ binwalk challenge.pdf
```

## Шаг 5: данные после %%EOF

PDF заканчивается маркером `%%EOF`, но после него можно дописать данные — парсеры их игнорируют. Плюс PDF поддерживает **инкрементальные обновления**: в файле остаются старые версии объектов.

```
$ grep -abo '%%EOF' challenge.pdf
$ xxd challenge.pdf | tail -3
0000f000: 666c 6167 7b61 6674 6572 5f65 6f66 7d0a  flag{after_eof}
```

А старые («перезаписанные») объекты извлекают по смещениям — «удалённый» текст никуда не исчезает.

## Шаг 6: JavaScript

PDF умеет исполнять JavaScript (`/OpenAction`, `/AA`). В CTF это реже флаг, но проверить стоит:

```
$ strings challenge.pdf | grep -iE 'javascript|/JS|/OpenAction'
/JS (app.alert('flag{js_in_pdf}'))
```

Инструмент `peepdf` показывает структуру и опасные элементы: `peepdf -f challenge.pdf`.

## Полный чек-лист команд для PDF

```bash
file doc.pdf
exiftool doc.pdf
pdfinfo doc.pdf
strings -n 6 doc.pdf | grep -iE 'flag|base64|http|/JS'
qpdf --qdf --object-streams=disable doc.pdf out.pdf
strings -n 6 out.pdf | grep -A2 -E 'Tj|TJ'
pdfdetach -list doc.pdf && pdfdetach -saveall doc.pdf
binwalk -e doc.pdf
grep -abo '%%EOF' doc.pdf
xxd doc.pdf | tail -6
pdf-parser --search flag doc.pdf
```

Такой прогон закрывает большинство PDF-задач: метаданные, скрытый текст, вложения, дописанный хвост, старые объекты.

## Если не сработало

- Не открывай PDF в ридере и не сохраняй — структура и скрытые объекты перезапишутся.
- Не игнорируй хвост после `%%EOF` — данных там не видно без `xxd`.
- Декодируй потоки (`qpdf --qdf`, `pdf-parser -d`) — иначе текст в `stream` сжат.
- Помни: `%%EOF` может быть несколько (инкрементальные версии).

## Что мы теперь знаем

1. PDF — контейнер из объектов, потоков и метаданных.
2. `/Info` (метаданные) — самая частая закладка.
3. Невидимый текст (белый цвет, `Tr 3`, вне MediaBox) — классика.
4. `/EmbeddedFiles` и хвост после `%%EOF` — контейнеры внутри контейнера.
5. `qpdf --qdf` декодирует потоки, `pdfdetach` извлекает вложения.

## Шаг 7: декодирование потоков вручную (zlib)

Даже если `qpdf` недоступен, поток PDF можно распаковать вручную. Поток начинается после `stream\r\n` и заканчивается `endstream`; содержимое сжато `FlateDecode` (zlib), реже `LZWDecode`/`ASCIIHexDecode`/`ASCII85Decode`.

```python
import re, zlib
raw = open('challenge.pdf', 'rb').read()
for m in re.finditer(rb'stream\r?\n(.*?)\r?\nendstream', raw, re.S):
    blob = m.group(1)
    try:
        dec = zlib.decompress(blob)
        print('--- decoded stream ---')
        print(dec[:400])
    except Exception:
        pass   # не flate или обрезан
```

Если zlib падает — попробуй `zlib.decompressobj()` (поток может быть обрезан) или `zlib.decompress(blob[2:])` (иногда пропущен zlib-заголовок). В декодированных потоках видны операторы контента: `BT … ET`, `Tj`, `TJ`, цвета `rg` — именно там ищут скрытый текст.

## Шаг 8: сравнение инструментов PDF-анализа

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

## Шаг 9: защита — как PDF-стего детектируют

С точки зрения blue team полезно знать признаки:

- текст вне MediaBox или с прозрачностью (ExtGState `ca 0`);
- несколько `%%EOF` и «висячие» объекты старых версий;
- данные после последнего `%%EOF`;
- большие вложения в `/EmbeddedFiles`;
- JavaScript в `/OpenAction`/`/AA`.

Для сканеров существуют эвристики на аномальную структуру, но стеганография по определению задумана незаметной. Поэтому в CTF и в реальном анализе одинаково важны ручные проверки структуры и метаданных.

## Шаг 10: полезные однострочники

- Быстро найти все URL и домены: `strings doc.pdf | grep -oE 'https?://[^ ]+'`.
- Найти вложения по имени: `strings doc.pdf | grep -iE '/F\('`.
- Проверить, сжимались ли данные: если после `qpdf --qdf` размер резко вырос — поток был сжат и теперь виден.
- Оценить «подозрительность»: число объектов, несколько `%%EOF`, объекты без ссылок в xref — всё это поводы копать глубже.
- Всегда запускай разбор на копии: `cp doc.pdf work.pdf`, оригинал не трогай.

Эти проверки занимают секунды, но часто экономят целый цикл анализа.

## Квиз

Проверь себя.

```quiz
- question: "Каким тегом PDF помечается встроенный файл?"
  options:
    - "/EmbeddedFile"
    - "/Font"
    - "/Page"
    - "/Catalog"
  answer: 0
  explanation: "/EmbeddedFile описывает вложение в PDF."
- question: "Какая утилита извлекает вложения из PDF?"
  options:
    - "pdfdetach"
    - "jadx"
    - "apktool"
    - "zsteg"
  answer: 0
  explanation: "pdfdetach работает с /EmbeddedFiles."
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

## Куда дальше

Дальше — **Office-документы**: DOCX/XLSX, которые на самом деле ZIP с XML. А пока запомни: PDF разбирай по слоям — метаданные, потоки, вложения, хвост.

## Где пригодится

- **CTF (Stego/Forensics):** PDF-задачи с секретами.
- **Malware-анализ:** вредоносные PDF (JS, эксплойты).
- **Bug bounty:** скрытые данные в документах.
- **Работа:** анализ документов в IR.
