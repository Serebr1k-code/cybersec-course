---
id: osint-document-analysis
title: "Глубокий анализ документов: PDF, Office, скрытые данные"
category: osint
parent: osint-metadata
difficulty: medium
order: 2
tags: [pdf, office, docx, xlsx, metadata, exiftool, strings]
prerequisites: [osint-metadata]
useful_for:
  - "CTF категория OSINT"
  - "Forensics и расследования"
  - "Поиск скрытых данных в документах"
estimated_minutes: 55
summary: "Разбор PDF и Office-файлов: внутренняя структура, метаданные, скрытые слои, вложения, редакционные правки и извлечение полезных данных."
---

Документ — это не картинка текста, а **контейнер**: PDF хранит объекты и потоки, DOCX/XLSX — это ZIP с XML. Внутри остаются метаданные, история правок, скрытые слои и вложения. Этот урок — про то, как заглянуть внутрь.

## Инструменты первого ряда

- **exiftool** — универсальный извлекатель метаданных.
- **pdfinfo / pdftotext / pdfimages / qpdf** — работа с PDF.
- **strings / binwalk** — поиск текста и вложенных файлов.
- **unzip** — распаковка Office (это ZIP).
- **oletools** (`olevba`, `oleid`) — анализ старых `.doc`/`.xls` и макросов.

```bash
exiftool document.pdf
pdfinfo document.pdf
strings -n 6 document.pdf | less
```

## PDF: что внутри

PDF — набор объектов. Часто содержит:

- **метаданные** (`/Author`, `/Producer`, `/Creator`, `/CreationDate`);
- **текстовые потоки** (сжатые FlateDecode);
- **вложенные файлы** (`/EmbeddedFiles`);
- **скрытые слои** (OCG — optional content groups);
- **аннотации и комментарии**.

Полезные команды:

```bash
# Метаданные
exiftool file.pdf

# Распаковать сжатые потоки и посмотреть объекты
qpdf --qdf --object-streams=disable file.pdf unpacked.pdf
strings unpacked.pdf | grep -iE 'author|producer|http|password|flag'

# Вложенные файлы
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf

# Картинки внутри
pdfimages -all file.pdf out/img
```

**Красные флаги**: `Producer`/`Creator` раскрывают ПО и версию; `Author` — имя; разница `CreationDate`/`ModDate` — когда правили.

## Office: DOCX/XLSX/PPTX — это ZIP

```bash
unzip -l report.docx
# ключевые части:
#   docProps/core.xml   — автор, даты, заголовок
#   docProps/app.xml    — приложение, компания
#   word/document.xml   — основной текст
#   word/comments.xml   — комментарии
#   word/media/         — изображения
```

Извлечение метаданных и скрытого:

```bash
exiftool report.docx
unzip -o report.docx -d docx_unpacked
grep -riE 'author|company|lastModifiedBy|revision' docx_unpacked/docProps/
```

**Скрытое в Office**:

- **комментарии** и **отслеживаемые правки** — удалённый текст виден;
- **свойства** (`Company`, `Manager`, `LastModifiedBy`) — внутренние имена;
- **скрытые листы/строки** в Excel (`xl/worksheets`, hidden rows);
- **встроенные объекты** и макросы (`.docm`/`.xlsm`).

## Какое поле что раскрывает

| Поле | Что выдаёт |
|---|---|
| `Author` / `LastModifiedBy` | имена сотрудников |
| `Company` / `Manager` | организацию и руководителя |
| `Producer` / `Creator` | ПО и версию (уязвимости) |
| `CreationDate` / `ModDate` | таймлайн работы |
| `Revision` | число правок |
| Пути (`/Users/<имя>`) | внутренние имена и ОС |
| `Template` | корпоративный шаблон |

Совокупность этих полей — «отпечаток» автора и организации; часто именно по ним связывают документы между собой.

## Старые форматы и макросы

Форматы `.doc`/`.xls` (OLE) анализируются `oletools`:

```bash
oleid suspicious.doc
olevba suspicious.doc        # извлечь макросы VBA
oledump.py suspicious.doc
```

Макросы часто содержат URL C2, команды PowerShell, обфускацию.

## binwalk и вложения

Если документ «подозрительно большой», внутри может быть спрятан другой файл:

```bash
binwalk document.pdf
# извлечь найденное
binwalk -e document.pdf
```

Так достают встроенные ZIP, изображения, другие документы.

## Редакционные правки (redaction)

Иногда «зачёркнутый» текст **не удалён**, а только закрыт чёрным прямоугольником поверх. Извлеките текст и поищите скрытое:

```bash
pdftotext file.pdf - | grep -i 'secret\|confidential\|password'
```

Если текст реально удалён — попробуйте восстановить из потоков (`qpdf --qdf`).

## Извлечение и восстановление текста

```bash
# весь текст PDF
pdftotext -layout document.pdf - | head -50

# текст с сохранением разметки
pdftotext -layout document.pdf out.txt

# вложения и картинки
pdfimages -all document.pdf img/
pdfdetach -saveall document.pdf
```

Если текст «удалён», но потоки остались, `qpdf --qdf` распаковывает структуру:

```bash
qpdf --qdf --object-streams=disable document.pdf unpacked.pdf
strings unpacked.pdf | grep -iE 'password|confidential|internal|@'
```

## Скрытые данные и стеганография в документах

- **Скрытые слои (OCG)**: слой может быть выключен, но содержать текст.
- **Белый текст на белом фоне**: визуально пусто, но текст присутствует.
- **Метаданные приложений**: `Producer`, `Creator` раскрывают ПО и версию.
- **Встроенные файлы**: PDF может содержать ZIP/EXE/другой PDF.
- **Thumbnail**: миниатюра первой страницы может отличаться от содержимого.

```bash
binwalk document.pdf        # найти встроенные сигнатуры
binwalk -e document.pdf     # извлечь
```

## Обезличивание документов (что утекает)

Даже «обезличенные» документы часто содержат следы:

- **Автор/LastModifiedBy** в свойствах — имена сотрудников.
- **Пути** (`/C/Users/<имя>/...`) — внутренняя структура.
- **Компания/Manager** в `docProps/app.xml`.
- **Стиль форматирования** — уникальный «отпечаток» редактора.
- **Метаданные изображений** внутри документа — GPS/устройство.

Практика: перед публикацией всегда `exiftool -all=` и проверка `docProps/`.

## Разобранный пример

Задача: найти скрытые данные в `invoice.pdf`.

1. `exiftool invoice.pdf` → `/Author: J. Smith`, `/Producer: LibreOffice`.
2. `pdfdetach -list` → найден вложенный `notes.txt`.
3. `pdfdetach -saveall` → читаем `notes.txt` с внутренним email.
4. `qpdf --qdf` + `strings` → в потоке видна скрытая строка с суммой.
5. Фиксируем: артефакты, хэши, источник.

## Инструменты и флаги

| Инструмент | Команда | Назначение |
|---|---|---|
| exiftool | `exiftool f.pdf` | метаданные |
| pdfinfo | `pdfinfo f.pdf` | свойства PDF |
| pdftotext | `pdftotext -layout f.pdf -` | текст |
| pdfdetach | `-list` / `-saveall` | вложения |
| pdfimages | `-all f.pdf img/` | картинки |
| qpdf | `--qdf --object-streams=disable` | распаковка структуры |
| binwalk | `-e f.pdf` | встроенные файлы |
| oletools | `olevba`/`oleid` | макросы OLE |

## Частые ошибки

- **Открывать недоверенный документ** в полном Office/браузере (риск макроса/эксплойта).
- **Забывать про вложения PDF.**
- **Смотреть только видимый текст**, игнорируя метаданные и комментарии.
- **Не проверять старые OLE-форматы** на макросы.
- **Игнорировать разницу дат** создания/изменения.
- **Считать удалённый текст недоступным** — он может остаться в потоках.

## Что делать дальше / решение

- **Нужны метаданные** → `exiftool` + `docProps/` + `pdfinfo`.
- **Нужны вложения** → `pdfdetach -saveall` + `binwalk -e`.
- **Нужен «удалённый» текст** → `qpdf --qdf` + `strings`/`grep`.
- **Нужны макросы** → `olevba`/`oleid` для OLE.

## Работа с таблицами Excel

XLSX — самый «протекающий» формат: таблицы часто содержат скрытые данные, которые не видны в печати.

```bash
unzip -l budget.xlsx
unzip -o budget.xlsx -d xlsx
ls xlsx/xl/worksheets/
grep -riE 'hidden|veryHidden' xlsx/xl/worksheets/*.xml
```

Что искать:

- **Скрытые листы/строки/столбцы** — данные есть, но не отображаются.
- **Формулы вместо значений** — раскрывают бизнес-логику и ссылки на другие листы.
- **Именованные диапазоны** — часто содержат чувствительные имена.
- **Комментарии и примечания** — авторские заметки.
- **Внешние ссылки** (`xl/externalLinks/`) — на какие серверы/шаблоны ссылается файл.

```bash
# все строки листа (включая скрытые) через libreoffice
libreoffice --headless --convert-to csv --outdir out budget.xlsx
```

## Метаданные изображений внутри документов

Документы встраивают изображения, а те несут свои метаданные:

```bash
pdfimages -all file.pdf img/
exiftool img/* | grep -iE 'gps|make|model|software'
```

- **GPS** в фото — точная локация съёмки.
- **Модель камеры/телефона** — устройство автора.
- **Software** — чем обрабатывали (Photoshop, сканер).
- **Дата съёмки** — таймлайн, отличный от даты документа.

Часто изображение «утекло» из внутренней системы со скриншотом, где видны URL и версии.

## Типичные CTF-сценарии

В CTF документы — частый источник флага:

- **Флаг в метаданных**: `exiftool` → `Author`, `Comment`, `Producer`.
- **Флаг во вложении**: `pdfdetach -saveall` / `binwalk -e`.
- **Флаг в скрытом слое**: OCG в PDF или белый текст.
- **Флаг в «удалённом» тексте**: `qpdf --qdf` + `strings`.
- **Флаг в скрытом листе Excel**: распаковать и посмотреть `xl/worksheets`.

Алгоритм один: определить формат → `exiftool` → распаковать/декомпилировать → `strings`/`grep` по ключевым словам (`flag`, `secret`, `key`).

## Квиз

```quiz
- question: "Чем на самом деле является файл DOCX?"
  options:
    - "ZIP-архивом с XML-частями"
    - "Обычным текстовым файлом"
    - "Бинарным дампом"
    - "Картинкой"
  answer: 0
- question: "Как извлечь вложенные файлы из PDF?"
  options:
    - "`pdfdetach -list` / `pdfdetach -saveall`"
    - "`unzip`"
    - "`nmap`"
    - "`sqlmap`"
  answer: 0
- question: "Что раскрывает метаданное поле `/Author` в PDF?"
  options:
    - "Имя автора документа"
    - "Пароль файла"
    - "IP сервера"
    - "Версию ОС"
  answer: 0
- question: "Чем анализируют макросы в старых .doc/.xls?"
  options:
    - "oletools (olevba, oleid)"
    - "exiftool"
    - "pdfinfo"
    - "curl"
  answer: 0
- question: "Что делать с «зачёркнутым» текстом в PDF?"
  options:
    - "Попробовать извлечь текст — он может быть не удалён, а только закрыт"
    - "Считать его недоступным"
    - "Удалить файл"
    - "Распечатать"
  answer: 0
```

## Где пригодится

- **CTF (OSINT/Forensics):** найти флаг в метаданных или вложении.
- **Расследования:** восстановить удалённые правки и авторов.
- **Пентест:** извлечь внутренние имена/почты из корпоративных документов.
- **Работа:** анализ вложений в фишинге.
