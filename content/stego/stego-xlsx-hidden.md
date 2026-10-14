---
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
