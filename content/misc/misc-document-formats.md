---
id: misc-document-formats
title: "Документы: OOXML, ODF и метаданные"
category: misc
parent: misc-fileformats
difficulty: medium
order: 4
tags: [docx, xlsx, odf, ooxml, metadata, exiftool, macros, ctf]
prerequisites: [misc-fileformats]
useful_for:
  - "CTF Misc/Forensics категория"
  - "Анализ документов"
  - "OSINT и метаданные"
estimated_minutes: 28
summary: "docx/xlsx как ZIP+XML, скрытый текст и макросы, метаданные через exiftool, восстановление удалённого содержимого и ODF-трюки."
lab:
  kind: shell
  title: "Практика: документ OOXML изнутри"
  toolset: [core, unzip]
  workdir: /home/student/task
  files: [task.md, report.docx]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "DOCX — это zip. Посмотри части: `unzip -l report.docx`."
    - "Обрати внимание на служебную часть `docProps/`. Свойства документа иногда содержат лишнее."
    - "Напечатай скрытое свойство: `unzip -p report.docx docProps/custom.xml`."
---
## Вопрос, с которого всё начинается

В прошлом уроке мы вскрывали архивы. Теперь дают **офисный документ** `invoice.docx`, при открытии — обычный счёт, ничего лишнего. Но флаг где-то спрятан.

Ключевое наблюдение: современный `.docx` — это **не** «текстовый файл», а ZIP-архив с XML-файлами внутри. То есть всё, что мы знаем про архивы и про XML, здесь работает. Разберём документ по слоям.

## Наш пример: invoice.docx

Проверяем сигнатуру и вскрываем как архив:

```bash
$ file invoice.docx
invoice.docx: Microsoft Word 2007+

$ mkdir inv && cd inv && unzip -o ../invoice.docx
$ find . -type f
./[Content_Types].xml
./_rels/.rels
./word/document.xml
./word/media/image1.png
./word/settings.xml
./docProps/core.xml
./docProps/app.xml
```

Видим структуру **OOXML** (Open Packaging Convention): папки `word/`, служебный `[Content_Types].xml`, метаданные в `docProps/`.

## Шаг 1: ищем текст — и скрытый текст

Основной текст лежит в `word/document.xml`. Быстрый поиск флага по всем частям:

```bash
$ grep -roE 'flag\{[^}]*\}' .
$ grep -rl 'secret' .
word/document.xml
```

Флага в тексте нет. Но текст можно **спрятать**. Частые способы:

- **белый на белом** — в XML есть `<w:color w:val="FFFFFF">`;
- **`w:vanish`** — атрибут «скрытый текст», не отображается, но есть в XML;
- **комментарии и заметки** — `<w:comment>`;
- **колонтитулы и текстовые поля** — отдельные XML-части.

Ищем признаки:

```bash
$ grep -o 'w:vanish' word/document.xml
$ grep -o 'w:color w:val="FFFFFF"' word/document.xml
```

Так «невидимый» текст в редакторе оказывается обычными байтами в XML.

## Шаг 2: метаданные

Служебные поля документа читает `exiftool`:

```bash
$ exiftool ../invoice.docx | grep -iE 'author|company|last'
Author          : ctf-player
Company         : SecretCorp
Last Modified By: admin
```

Метаданные — классический источник: имена авторов, внутренние пути, версии ПО. В CTF там бывает пароль или часть флага. Ключ `-a -u -g1` показывает все группы, включая неизвестные поля.

Прямо в ZIP метаданные лежат в `docProps/core.xml` (автор, даты) и `docProps/app.xml` (приложение, версия).

## Шаг 3: вложенные медиа

В `word/media/` лежат встроенные картинки. Их тоже проверяем на вложенное:

```bash
$ binwalk word/media/image1.png
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             PNG image
4096          0x1000          Zip archive data
$ unzip -o word/media/image1.png -d img
$ cat img/flag.txt
flag{d0cum3nts_4r3_z1ps}
```

Внутри картинки — снова архив. Документ раскрывается «матрёшкой»: ZIP → XML → метаданные → вложенные медиа → вложенный архив.

## Шаг 4: макросы

Документ с макросами имеет расширение `.docm`/`.xlsm`, а код лежит в `word/vbaProject.bin`. Извлекает его `oletools`:

```bash
$ pip install oletools
$ olevba word/vbaProject.bin
VBA MACRO ThisDocument
...
Sub AutoOpen()
    Shell "powershell -c ..."
End Sub
```

`olevba` печатает исходник VBA и помечает автозапуск (`AutoOpen`) — потенциально вредоносный. В CTF макрос часто содержит флаг или подсказку. Для быстрой оценки опасности есть `mraptor`.

**Важно:** не открывайте документ в офисном пакете до анализа — макрос может сработать.

## Шаг 5: удалённый текст и правки

В отличие от PDF с инкрементальными обновлениями, OOXML-редакторы обычно **пересобирают** ZIP, поэтому физически удалённых данных там нет. Но есть исключение: **помеченный** удалённый текст (`w:del`) и вставки (`w:ins`) остаются в `document.xml`. Если задача про «удалённый» фрагмент — ищите:

```bash
$ grep -o '<w:del[^>]*>' word/document.xml
```

## Шаг 6: другие документные форматы

Кроме OOXML есть родственники — и у каждого свои места для сокрытия:

- **ODF** (`.odt`, `.ods`) — тоже ZIP, но внутри `content.xml`, `styles.xml`, `meta.xml`. Метаданные лежат в `meta.xml`, а миниатюра — в `Thumbnails/`.
- **Бинарный `.doc`/`.xls`** (старый формат) — это **не** ZIP, а составной файл OLE/CFB с потоками. Для него нужны `oletools`, `oledump.py`, `libolecf`; `oledump.py -s <stream> -d` извлекает содержимое потока.
- **RTF** — текстовый формат с управляющими словами; данные прячут в объектах (`\object`) и hex-escape-последовательностях.
- **EPUB** — ZIP с `META-INF` и XHTML; смотрите навигацию и метаданные.

Полезный инструмент для OLE — `oleid`: он быстро показывает, есть ли макросы, шифрование и подозрительные элементы.

```bash
$ oledump.py document.doc | head
$ oledump.py -s 8 -d document.doc > stream.bin
```

## Шаг 7: порядок действий для любого документа

1. `file` — понять формат (OOXML? OLE? RTF?).
2. `exiftool -a -u -g1` — метаданные.
3. Если OOXML/ODF — `unzip` и `find`, затем `grep -roE 'flag\{[^}]*\}'`.
4. Проверить `media/` через `binwalk` (вложенный архив).
5. Если есть `vbaProject.bin` — `olevba`.
6. Искать скрытый текст: `w:vanish`, белый цвет, `<w:del`.

Этот порядок раскрывает большинство документов за минуты. И помните: `grep` не найдёт UTF-16-текст — используйте `strings -el`.

## PDF: родственник по духу

PDF — не ZIP, но тоже структурирован: объекты, потоки, часто сжатые (`FlateDecode`). Разбирается так:

```bash
$ pdftotext file.pdf -            # извлечь текст
$ pdfimages -all file.pdf out     # извлечь картинки
$ qpdf --qdf file.pdf out.pdf     # разжать потоки
$ strings file.pdf | grep -i flag
```

Важное отличие от OOXML: PDF поддерживает **инкрементальные обновления** — старые версии объектов остаются в файле, поэтому «удалённый» текст там реально можно найти. Инструмент `pdf-parser.py` помогает обойти объекты. То есть в docx ищите помеченные правки (`w:del`), а в PDF — старые объекты.

## Что мы теперь знаем

- `.docx`/`.xlsx`/`.pptx` — это ZIP-архивы с XML (OOXML); `.odt`/`.ods` устроены похоже.
- Основной текст — `word/document.xml`; метаданные — `docProps/core.xml` и `app.xml`.
- Текст прячут белым цветом, атрибутом `w:vanish`, в комментариях и колонтитулах.
- Встроенные картинки (`word/media/`) проверяем `binwalk` — внутри бывает архив.
- Макросы лежат в `word/vbaProject.bin`, извлекаются `olevba`.
- `exiftool` даёт автора, компанию, даты — источник для OSINT.
- В `_rels`-файлах бывают внешние ссылки (`TargetMode="External"`) — вектор SSRF, когда сервер подгружает ресурсы документа.

## На что смотреть дальше

- **Открывать документ в офисном пакете** — рискуете выполнить макрос; сначала анализ.
- **Искать флаг только в `document.xml`** — проверяйте `media/`, `_rels/`, `docProps/`.
- **Игнорировать метаданные** — часто там и ответ.
- **UTF-16 текст** — `strings` без `-el` его не покажет.
- **`_rels`** — там внешние ссылки (`TargetMode="External"`), вектор SSRF.
- **Бинарные `.doc`/`.xls`** — это OLE/CFB, не ZIP; нужны `olevba`, `oledump.py`.

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| Распаковать docx | `unzip report.docx` |
| Метаданные | `exiftool -a -u -g1` |
| VBA-макросы | `olevba`, `mraptor` |
| PDF-текст | `pdftotext`, `pdfimages` |
| Разжать PDF | `qpdf --qdf` |
| Скрытый текст | `grep`, `strings -el` |
| Связи/ссылки | `word/_rels/*.rels` |

## Квиз

Проверь себя.

```quiz
- question: "Чем является файл docx на уровне формата?"
  options:
    - "ZIP-архивом с XML-частями (OOXML)"
    - "Бинарным blob'ом без структуры"
    - "PDF-документом"
    - "Текстовым CSV"
  answer: 0
  explanation: "Open Packaging Convention: zip + XML."
- question: "Какой инструмент извлекает VBA-макросы из документов?"
  options:
    - "olevba (oletools)"
    - "nmap"
    - "ffmpeg"
    - "sqlmap"
  answer: 0
  explanation: "olevba парсит vbaProject.bin и печатает исходник."
- question: "Где в docx хранится основной текст?"
  options:
    - "word/document.xml"
    - "docProps/app.xml"
    - "xl/workbook.xml"
    - "ppt/slides/"
  answer: 0
  explanation: "Основной контент Word — document.xml."
- question: "Почему удалённый текст обычно НЕ находится в docx?"
  options:
    - "Редакторы пересобирают ZIP, старых данных не остаётся"
    - "Текст шифруется"
    - "Он хранится в реестре"
    - "Он удаляется антивирусом"
  answer: 0
  explanation: "В отличие от PDF с incremental updates."
- question: "Какой инструмент показывает автора и даты документа?"
  options:
    - "exiftool"
    - "gdb"
    - "tcpdump"
    - "john"
  answer: 0
  explanation: "exiftool читает метаданные docProps и других форматов."
```

## Куда дальше

Мы закончили блок про форматы файлов. В следующем уроке мы перейдём к **форензике** — разберём, как восстанавливать артефакты и строить таймлайн. А пока главное запомни: **любой офисный документ — это ZIP; распакуй его, посмотри XML, метаданные и вложенные медиа.**

## Где пригодится

- **CTF:** misc/forensics — документы со скрытым содержимым.
- **OSINT:** метаданные как источник имён и внутренних путей.
- **Forensics:** анализ офисных артефактов, макросов.
- **Работа:** безопасная обработка документов, детект макросов.
