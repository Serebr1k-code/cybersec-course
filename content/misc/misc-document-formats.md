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
---

Офисные документы — это контейнеры поверх XML. `docx`, `xlsx`, `pptx` (формат OOXML) — обычные ZIP-архивы с папками `word/`, `xl/`, `ppt/` и XML-файлами. `odt`, `ods`, `odp` (OpenDocument) устроены похоже. В CTF документ — это «матryoshka»: внутри XML могут быть спрятаны данные, картинки, комментарии и целые файлы. Плюс метаданные, которые часто содержат имена, пути и пароли.

## docx/xlsx — это ZIP

Переименуйте `report.docx` в `report.zip` — и распакуйте:

```bash
mkdir x && cd x
unzip ../report.docx
find . -type f
# ./[Content_Types].xml
# ./_rels/.rels
# ./word/document.xml
# ./word/media/image1.png
# ./word/settings.xml
# ./docProps/core.xml
# ./docProps/app.xml
```

Ключевые файлы:

| Путь | Содержимое |
|------|-----------|
| `word/document.xml` | основной текст документа |
| `word/media/` | встроенные картинки |
| `word/settings.xml` | настройки, иногда скрытый текст |
| `docProps/core.xml` | автор, даты создания/изменения |
| `docProps/app.xml` | приложение, версия |
| `word/_rels/document.xml.rels` | связи, включая внешние ссылки |

## Скрытый текст

Текст может быть скрыт несколькими способами:

- **White-on-white** — белый текст на белом фоне (в XML есть `<w:color w:val="FFFFFF">`).
- **`w:vanish`** — атрибут «скрытый текст», не отображается, но есть в XML.
- **Комментарии и заметки** — `<w:comment>`.
- **Колонтитулы и текстовые поля** — отдельные XML.
- **Удалённый текст** — остаётся в XML, если не была пересобрана структура (в OOXML редакторы обычно пересобирают ZIP).

Поиск:

```bash
grep -roE 'flag\{[^}]*\}' x/word/
strings x/word/document.xml | grep -i flag
```

## Макросы

Формат с макросами — `docm`/`xlsm` (или VBA внутри OOXML). Макросы лежат в `word/vbaProject.bin`. Их извлекают `oletools`:

```bash
pip install oletools
olevba x/word/vbaProject.bin
# выводит исходник VBA, IOCs, авто-запуск (AutoOpen)
mraptor document.docm    # детект вредоносных макросов
```

VBA может исполнять команды (`Shell`), загружать полезную нагрузку и красть данные. В CTF макрос часто содержит флаг или подсказку.

## Метаданные

`exiftool` — основной инструмент:

```bash
exiftool report.docx
# Author         : Ivan Petrov
# Creator        : Microsoft Word
# Create Date    : 2024:01:01 10:00:00
# Modify Date    : 2024:01:02 11:30:00
# Company        : SecretCorp
# Last Modified By: admin
```

Метаданные встречаются в PDF, JPEG, docx, odt. Это классический OSINT-источник: имена авторов, внутренние пути, версии ПО. В CTF там может быть пароль или часть флага.

```bash
exiftool -a -u -g1 report.docx   # все группы, включая неизвестные
```

## PDF: краткий разбор

PDF — не ZIP, но тоже структурирован: объекты, потоки, иногда сжатые (`FlateDecode`). Инструменты:

```bash
pdftotext file.pdf -            # извлечь текст
pdfimages -all file.pdf out     # извлечь картинки
qpdf --qdf file.pdf out.pdf     # разжать потоки
strings file.pdf | grep -i flag
```

Инкрементальные обновления (incremental updates) оставляют «старые» версии объектов — удалённый текст может остаться. Инструмент `pdf-parser.py` помогает найти объекты.

## Разобранный пример

Дано: `invoice.docx`, при открытии — обычный счёт. Флаг спрятан.

```bash
unzip -o invoice.docx -d inv
grep -roE 'flag\{[^}]*\}' inv/ || echo "нет в тексте"
# нет в тексте
exiftool invoice.docx | grep -iE 'author|comment|company'
# Author: ctf-player
binwalk inv/word/media/*
# в одной из картинок — zip
unzip -o inv/word/media/image1.png -d img
cat img/flag.txt
```

Так документ раскрывается по слоям: XML → метаданные → вложенные медиа → вложенный архив.

## Частые ошибки и подводные камни

- Открывать документ в офисном пакете — рискуете выполнить макрос (и не увидите скрытое).
- Искать флаг только в `document.xml`, забывая про `media/`, `_rels/`, `docProps/`.
- Игнорировать метаданные — они часто и есть ответ.
- Пытаться достать удалённый текст из OOXML: редакторы пересобирают ZIP, старых данных там нет (в отличие от PDF).
- Забывать про кодировку: `strings` не покажет UTF-16 без `-el`.
- Не смотреть `_rels` — там внешние ссылки (SSRF/утечка).

## Что дальше / решение

Практикуйтесь: создайте docx со скрытым текстом и макросом, извлеките. Прогоняйте любые документы через `exiftool`, `oletools`, `binwalk`. Дальше — `misc-archive-tricks` (тот же ZIP) и forensics-ветка про офисные артефакты.

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

## Дополнительная теория: отношения, контент-типы и внешние ссылки

OOXML-документ — это не просто папка XML, а граф **отношений**. Файл `[Content_Types].xml` объявляет, как интерпретировать части по расширению. Папки `_rels` содержат `.rels`-файлы, описывающие связи между частями: `document.xml` ссылается на картинки, стили, а иногда на **внешние** ресурсы (`TargetMode="External"`). Именно внешние связи — вектор SSRF/утечки: если документ загружается на сервер, который подгружает внешние ресурсы (например, для превью), можно заставить его обратиться к внутреннему адресу. В CTF это встречается как «документ с внешней картинкой на internal service».

Ещё одна деталь — **альтернативные представления**: `docx` может хранить несколько версий одного текста (revisions, `w:ins`/`w:del`), комментарии (`w:comment`), сноски, поля. Удалённый текст может остаться в виде `w:del` (помеченный как удалённый), а не исчезнуть физически. Это ключевое отличие от простого «удалить и сохранить»: редактор может сохранить историю правок. Поиск по `<w:del` и `<w:ins` в `document.xml` часто вскрывает удалённые фрагменты.

## Другие форматы и их quirks

Кроме OOXML есть **ODF** (`.odt`, `.ods`) — тоже ZIP, но с `content.xml`, `styles.xml`, `meta.xml`. Старый бинарный `.doc`/`.xls` (OLE/CFB) — это **не** ZIP, а составной файл с потоками; для него нужны `oletools`, `officedissector`, `libolecf`. RTF — текстовый формат с управляющими словами, где тоже прячут данные (`\object`, hex-escapes). EPUB — ZIP с `META-INF` и XHTML. Каждый формат имеет свои места для сокрытия: в ODF — `meta.xml` и `Thumbnails/`, в RTF — объекты, в EPUB — навигация и метаданные.

Для бинарных форматов используйте `olevba`, `oleid`, `oledump.py` — они показывают потоки, макросы и подозрительные элементы. `oledump.py -s <stream> -d` извлекает содержимое потока.

## Разбор ошибок и отладка

Если `unzip report.docx` падает с ошибкой — файл может быть повреждён или это не OOXML (проверьте `file`). Если `document.xml` нечитаем — он может быть сжат неверно; попробуйте `qpdf` (для PDF) или пересобрать ZIP. Если `grep` не находит флаг в UTF-16-тексте, используйте `strings -el` или перекодируйте (`iconv`). Если макрос не виден — он может быть в `vbaProject.bin` внутри `word/`, но зашифрован (`Project Lock`); тогда `olevba` с паролем или ручной разбор. Если метаданные пусты — смотрите `docProps/core.xml` напрямую, `exiftool` может не показать кастомные поля. И помните: любой документ — это ZIP, начните с `binwalk` и `unzip`.

## Практический разбор: скрытый текст и вложенный архив

Дано: `secret.docx`, подозрительный. Полный цикл:

```bash
mkdir x && cd x && unzip -o ../secret.docx
grep -rl 'flag{' . ; grep -rl 'secret' . ; grep -rl 'password' .
# находим подозрительные части
cat word/document.xml | grep -o '<w:t>[^<]*</w:t>' | head
# текст с разметкой; ищем скрытый (w:vanish, белый цвет)
grep -o 'w:vanish' word/document.xml
grep -o 'w:color w:val="FFFFFF"' word/document.xml
```

Если в `word/media/` лежит картинка — проверьте её `binwalk` (внутри может быть архив). Если `docProps/core.xml` содержит `Author`/`Last Modified By` — это метаданные для OSINT. Если есть `word/vbaProject.bin` — прогоните `olevba`. Если задача про «удалённый» текст — ищите `<w:del` в `document.xml`. Полный цикл занимает минуты и раскрывает большинство документов. Не открывайте файл в офисном пакете до анализа — макрос может сработать.

## Квиз

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

## Где пригодится

- **CTF:** misc/forensics — документы со скрытым содержимым.
- **OSINT:** метаданные как источник имён и внутренних путей.
- **Forensics:** анализ офисных артефактов, макросов.
- **Работа:** безопасная обработка документов, детект макросов.
