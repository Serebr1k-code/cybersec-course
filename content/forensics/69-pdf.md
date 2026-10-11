---
id: forensics-pdf
title: "Форензика PDF"
category: forensics
parent: forensics-file-magic
difficulty: medium
order: 4
tags: [pdf, forensics, javascript, incremental-update, metadata, malware]
prerequisites: [forensics-file-magic, forensics-metadata]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ документов"
estimated_minutes: 45
summary: "Разбор PDF: структура объектов и xref, инкрементальные обновления, извлечение JavaScript/вложений, метаданные и восстановление скрытого содержимого."
---
PDF — сложный формат с объектами, потоками, инкрементальными обновлениями и возможностью встраивать JavaScript, вложения и скрытые данные. Атакующие используют PDF для доставки эксплойтов и фишинга, а CTF — для сокрытия флагов. Этот урок — про структуру PDF, xref, инкрементальные обновления, извлечение JavaScript/вложений и метаданные.

## Структура PDF

PDF состоит из:
- **объектов** (словари, массивы, строки, потоки);
- **xref** — таблица смещений объектов;
- **trailer** — ссылка на корневой объект (`/Root`) и `startxref`;
- **потоков** (`stream ... endstream`), часто сжатых (`/Filter /FlateDecode`).

```bash
$ head -c 200 invoice.pdf
%PDF-1.7
...
$ grep -aboP 'startxref' invoice.pdf
$ tail -c 100 invoice.pdf        # покажет startxref и %%EOF
```

**Инкрементальные обновления**: PDF можно дописывать — новые объекты добавляются в конец, старая версия остаётся. Это значит, что «предыдущая» версия документа может содержать удалённый текст/объекты.

```bash
$ grep -aboP '%%EOF' invoice.pdf      # несколько %%EOF = несколько обновлений
%PDF-1.7 ... %%EOF ... %%EOF ... %%EOF
```

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `pdf-parser.py` | разбор объектов/потоков (Didier Stevens) |
| `pdfid.py` | быстрый обзор (наличие JS, OpenAction) |
| `peepdf` | интерактивный анализ, автоматика |
| `qpdf` | декодирование/перестройка |
| `pdftotext` | извлечь текст |
| `mutool` | разбор, извлечение |
| `pdfimages` | извлечь изображения |

```bash
$ pdfid.py invoice.pdf
/JS           1
/JavaScript   1
/OpenAction   1
/Launch       1
/EmbeddedFile 1
```

Ключевые маркеры опасности: `/JS`, `/JavaScript`, `/OpenAction`, `/AA` (additional actions), `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA`.

## Извлечение JavaScript и действий

```bash
# найти и вывести JS-объекты
$ pdf-parser.py --search javascript invoice.pdf
$ pdf-parser.py --object 12 --filter --raw invoice.pdf > js.txt
# декодировать поток и извлечь скрипт
$ qpdf --qdf --object-streams=disable invoice.pdf decoded.pdf
$ grep -A20 '/JS' decoded.pdf | head
```

JS в PDF часто обфусцирован: строки в hex, `unescape`, разбиение. Инструменты: `pdf-parser.py --decode`, `peepdf` (авто-обфускация), `spidermonkey`/`quickjs` для эмуляции.

```bash
$ peepdf -f -i invoice.pdf
PPDF> js_unescape
PPDF> decode
```

## Вложения и встроенные файлы

```bash
# извлечь вложения
$ pdf-parser.py --search embedded --raw invoice.pdf
$ qpdf --show-attachments invoice.pdf
$ mutool extract invoice.pdf        # извлечёт изображения/вложения
# или через pdfdetach
$ pdfdetach -list invoice.pdf && pdfdetach -saveall invoice.pdf
```

Встроенные файлы (`.exe`, `.docm`) — типичная нагрузка; хешируйте и анализируйте.

## Метаданные и скрытое

```bash
$ exiftool invoice.pdf | grep -iE 'author|creator|producer|title'
$ pdfinfo invoice.pdf
$ strings -n 8 invoice.pdf | grep -iE 'flag|secret|password'
```

Метаданные (`/Author`, `/Creator`, `/Producer`) дают атрибуцию; в старых версиях (инкрементальных обновлениях) могут остаться удалённые данные.

## Разобранный пример

Дан `mal.pdf`. Нужно найти JS и нагрузку.

```bash
# 1. Обзор
$ pdfid.py mal.pdf
/JS 1  /OpenAction 1  /EmbeddedFile 1
# 2. Инкрементальные обновления
$ grep -aboP '%%EOF' mal.pdf
# 3. Найти JS
$ pdf-parser.py --search javascript mal.pdf
obj 5 0 /JS
# 4. Извлечь и декодировать
$ pdf-parser.py --object 5 --filter --raw mal.pdf > js.txt
$ head js.txt
var s = unescape('%u0048%u0065...');
# 5. Вложение
$ pdfdetach -saveall mal.pdf && file *.bin
# 6. Метаданные
$ exiftool mal.pdf | grep -i producer
```

## Справочная таблица маркеров

| Маркер | Значение |
|--------|----------|
| `/JS`, `/JavaScript` | скрипт |
| `/OpenAction` | выполнить при открытии |
| `/AA` | доп. действия |
| `/Launch` | запуск программы |
| `/EmbeddedFile` | вложение |
| `/RichMedia` | Flash/видео |
| `/XFA` | динамическая форма |

## Частые ошибки

- **Читать PDF как текст** — объекты бинарные/сжатые.
- **Не проверять инкрементальные обновления** — старая версия скрывает данные.
- **Игнорировать `/OpenAction`** — авто-выполнение JS.
- **Не извлекать вложения** — нагрузка внутри.
- **Забывать про метаданные** — атрибуция и скрытое.
- **Открывать PDF в просмотрщике** — риск выполнения; анализируйте статически.

## Что дальше / решение

Конвейер: `pdfid.py` (обзор) → `pdf-parser.py`/`peepdf` (объекты/JS) → `pdfdetach`/`mutool` (вложения) → `exiftool` (метаданные) → хеши. Связка: `forensics-file-magic` (тип), `forensics-email` (доставка), `forensics-office-macros` (нагрузки), `forensics-carving`.

## Эмуляция JS и эксплойты

PDF может содержать эксплойт (heap spray, уязвимость в рендерере) или JS, загружающий нагрузку. Статический разбор + эмуляция.

```bash
# извлечь и декодировать JS
$ pdf-parser.py --search javascript --raw mal.pdf
$ peepdf -f -i mal.pdf
PPDF> js_unescape
PPDF> extract js
# эмуляция JS (Node/quickjs)
$ node js_extracted.js 2>/dev/null | head
```

Частые приёмы: `heapspray`, `unescape('%u...')`, `eval`, `Collab.collectEmailInfo`, `this.exportDataObject`. Ищите строки с большими массивами, `%u`-последовательностями и вызовами API.

## Ручной разбор xref

Если инструменты не справляются (битый xref), разбирайте объекты вручную.

```bash
# найти все объекты
$ grep -aboP '[0-9]+ 0 obj' mal.pdf | head
# декодировать поток FlateDecode
$ python3 -c "import zlib,sys;print(zlib.decompress(open('stream.bin','rb').read()))"
# qpdf: перестроить и линеаризовать
$ qpdf --qdf mal.pdf qdf.pdf
```

`qpdf --qdf` создаёт «читаемую» версию с несжатыми потоками и явным xref — удобно для ручного анализа. Если PDF обрезан, `qpdf` может восстановить (`--recover`).

## Сводный чек-лист

1. `pdfid.py` — маркеры опасности.
2. `grep -aboP '%%EOF'` — инкрементальные обновления.
3. `pdf-parser.py --search javascript` — JS.
4. `peepdf` — декодировать/эмулировать.
5. `pdfdetach`/`mutool` — вложения.
6. `exiftool` — метаданные.
7. Хеши вложений — IOC.
8. Проверить каждую «предыдущую» версию (обновления).

## Ограничения

- **Шифрование PDF** (`/Encrypt`) — нужен пароль; `qpdf --password=`.
- **Повреждённый xref** — `qpdf --recover`, ручной поиск объектов.
- **Обфускация JS** — несколько слоёв; `peepdf` помогает.
- **Онлайн-песочницы** — для полной картины эксплойта.
- **Встроенные файлы с паролем** — нужен отдельный разбор.

## Структура объектов в деталях

PDF-объекты бывают: словари (`<< ... >>`), массивы (`[ ... ]`), строки (`(...)` или `<hex>`), имена (`/Name`), числа, потоки. Поток — словарь + `stream ... endstream`. Сжатие задаётся `/Filter` (`FlateDecode`, `LZWDecode`, `ASCIIHexDecode`, `DCTDecode` для JPEG).

```bash
# найти все потоки и их фильтры
$ pdf-parser.py --stats mal.pdf
# декодировать поток вручную
$ pdf-parser.py --object 7 --filter --raw mal.pdf > stream.bin
$ xxd -l 64 stream.bin
```

Множественные фильтры применяются по порядку (`/Filter [/ASCIIHexDecode /FlateDecode]`); декодируйте в обратном.

## Линеаризация и потоки

Линеаризованный PDF (для быстрого веб-просмотра) имеет специальную структуру с `linearized`-словарём и кросс-таблицами в начале. Это не меняет содержимое, но усложняет ручной разбор.

```bash
# проверить линеаризацию
$ pdfinfo mal.pdf | grep -i linearized
# перестроить (убрать линеаризацию) для анализа
$ qpdf --qdf mal.pdf qdf.pdf
$ qpdf --linearize mal.pdf linear.pdf
```

`qpdf --qdf` — лучший друг аналитика: он делает PDF «читаемым» (несжатые потоки, явный xref, комментарии со смещениями).

## Инструменты: сводка

| Инструмент | Задача |
|-----------|--------|
| `pdfid.py` | маркеры опасности |
| `pdf-parser.py` | объекты/потоки |
| `peepdf` | интерактив, JS |
| `qpdf` | декодирование/перестройка |
| `pdfdetach` | вложения |
| `mutool` | извлечение |
| `pdfimages` | изображения |

## Практические приёмы

- **Инкрементальные обновления** — несколько `%%EOF`; разбирайте каждую версию.
- **`/OpenAction`/`/AA`** — авто-выполнение.
- **Обфускация JS** — `peepdf js_unescape`, `--decode`.
- **Вложения** — `pdfdetach -saveall`.
- **Метаданные** — атрибуция (`exiftool`).
- **Битый xref** — `qpdf --recover` или ручной поиск `obj`.
- **Шифрование** — `qpdf --password=... --decrypt`.

## Квиз

```quiz
- question: "Что означает инкрементальное обновление в PDF?"
  options:
    - "файл перезаписывается целиком"
    - "новые данные дописываются, старые объекты остаются в файле"
    - "PDF сжимается"
    - "PDF шифруется"
  answer: 1
- question: "Какая команда декомпрессирует потоки PDF в читаемый вид?"
  options:
    - "qpdf --qdf --object-streams=disable"
    - "pdftotext"
    - "pdfinfo"
    - "file"
  answer: 0
- question: "Какой ключ PDF указывает на встроенный файл?"
  options:
    - "/URI"
    - "/EmbeddedFile"
    - "/OpenAction"
    - "/GoTo"
  answer: 1
- question: "Как извлечь вложения из PDF?"
  options:
    - "pdfdetach -saveall"
    - "pdftotext"
    - "pdfinfo"
    - "strings"
  answer: 0
- question: "Почему опасно открывать подозрительный PDF в ридере?"
  options:
    - "он станет больше"
    - "может сработать JavaScript/Launch и выполнится код"
    - "он удалится"
    - "ничего не произойдёт"
  answer: 1
```

## Где пригодится

- **CTF:** поиск скрытого текста, вложений, JS в PDF.
- **DFIR:** анализ фишинговых PDF и цепочек заражения.
- **Threat Hunting:** индикаторы (/Launch, /JS, вложения) для детекта.
- **Судебная экспертиза:** восстановление изменённого содержимого.
- **Анализ документов:** извлечение метаданных и вложений.
