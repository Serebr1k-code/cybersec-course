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

## XLSX как ZIP: структура

XLSX — ZIP-контейнер (OOXML). Структура: `[Content_Types].xml`, `_rels/`, `xl/workbook.xml` (список листов), `xl/worksheets/sheetN.xml` (данные листов), `xl/sharedStrings.xml` (строки), `xl/styles.xml`, `xl/media/` (изображения), `docProps/` (метаданные), `customXml/`.

```bash
unzip -l book.xlsx
unzip -o book.xlsx -d xlsx/
grep -rniE "nto\{|flag" xlsx/ | head
```

Каналы сокрытия. Первый — **скрытые листы**: атрибут `state="hidden"` или `state="veryHidden"` в `xl/workbook.xml` (или в `sheetN.xml`). `veryHidden` не отображается даже в меню «Показать скрытые». Второй — **скрытые строки/столбцы**: атрибуты `hidden="1"` в определениях строк/столбцов. Третий — **невидимый текст**: белый цвет шрифта (`font color`), крошечный размер.

Четвёртый — **customXml** (произвольные XML-части). Пятый — **комментарии/примечания** к ячейкам. Шестой — **метаданные** в `docProps/`. Седьмой — **определённые имена** (`definedNames`), которые могут ссылаться на скрытые ячейки. Восьмой — **лишние медиа** в `xl/media/`.

## Извлечение скрытых данных

```bash
grep -rn "state=\"hidden\"\|state=\"veryHidden\"" xlsx/xl/workbook.xml
grep -rn "hidden=\"1\"" xlsx/xl/worksheets/
grep -rn "FFFFFF" xlsx/xl/styles.xml
ls xlsx/customXml/ 2>/dev/null
cat xlsx/docProps/core.xml
```

Порядок: листинг архива → скрытые листы (`state`) → скрытые строки/столбцы (`hidden`) → невидимый текст (`styles.xml`) → customXml → комментарии → метаданные → лишние медиа → вложенность (`binwalk`).

Если лист `veryHidden`, его данные всё равно в `xl/worksheets/sheetN.xml` — читай файл напрямую, не полагаясь на Excel. Если данные закодированы (base64/hex в ячейках), декодируй. Помни, что `sharedStrings.xml` хранит строки отдельно: значения ячеек — индексы в этот файл, поэтому текст ищи и там.

Инструменты: `unzip`, `grep`, `python3` (XML-парсер, `openpyxl` для чтения с `data_only`), `exiftool`, `binwalk`. Но `openpyxl` покажет только «видимые» данные, поэтому архив всегда проверяй вручную.

## Сравнение с PPTX и DOCX

Все OOXML-форматы (XLSX, DOCX, PPTX) — ZIP + XML + `[Content_Types].xml`. Каналы совпадают: файлы вне манифеста, скрытые элементы (листы/слайды/строки), невидимый текст, комментарии, customXml, метаданные, лишние медиа. Различается только, где хранятся «скрытые» состояния: в XLSX — `state` листа и `hidden` строк, в PPTX — `show=0` слайда, в DOCX — скрытый текст (`w:vanish`).

Поэтому, освоив один формат, ты разбираешь остальные. Ключ — знать структуру частей и места, где хранятся состояния видимости. И всегда работать с архивом, а не с офисным приложением, которое скрывает каналы.

## Практика: разбор скрытого листа

Сценарий: флаг на листе `veryHidden`. Шаг первый — посмотреть список листов и их состояния:

```bash
grep -o "<sheet [^>]*>" xlsx/xl/workbook.xml
# <sheet name="Data" sheetId="1" state="veryHidden" r:id="rId1"/>
```

Шаг второй — найти соответствующий файл листа по `r:id` в `_rels/workbook.xml.rels` (обычно `xl/worksheets/sheetN.xml`). Шаг третий — прочитать значения ячеек. Текст ячеек хранится либо инлайн (`<is><t>...`), либо в `sharedStrings.xml` (значение ячейки — индекс `<v>N</v>`). Читай оба.

```bash
cat xlsx/_rels/workbook.xml.rels
grep -o "<t>[^<]*</t>" xlsx/xl/sharedStrings.xml | head
```

Шаг четвёртый — если значения закодированы (base64/hex), декодируй. Шаг пятый — проверь скрытые строки/столбцы: `grep -o "<row [^>]*hidden[^>]*>" sheetN.xml`. Шаг шестой — customXml: `ls xlsx/customXml/`.

## Практика: невидимый текст и метаданные

Невидимый текст задаётся в `xl/styles.xml`: шрифт белого цвета (`<color rgb="FFFFFFFF"/>`) или нулевого размера (`<sz val="1"/>`). Найти: `grep -n "FFFFFFFF" xlsx/xl/styles.xml`. Но нужно сопоставить стиль с ячейками — сложнее; на практике проще выгрузить все строки из `sharedStrings.xml` и просмотреть их.

```bash
grep -o "<t>[^<]*</t>" xlsx/xl/sharedStrings.xml | sed "s/<[^>]*>//g" | head -50
cat xlsx/docProps/core.xml
cat xlsx/docProps/app.xml
```

Метаданные (`docProps/core.xml`, `app.xml`) могут содержать данные в `dc:creator`, `dc:title`, `Company`, `cp:keywords`. Проверь их на подозрительные значения. Дополнительно — `xl/workbook.xml` может содержать `definedNames` со ссылками на скрытые ячейки.

Лишние изображения: `ls xlsx/xl/media/` и сравнение с используемыми. Вложенность: `binwalk book.xlsx`. Инструменты: `unzip`, `grep`, `python3`, `exiftool`, `binwalk`.

## Итог по XLSX

XLSX — ZIP + XML. Каналы: скрытые листы (`state="hidden"/"veryHidden"`), скрытые строки/столбцы (`hidden="1"`), невидимый текст, customXml, комментарии, метаданные, лишние медиа. Инструменты: `unzip`, `grep`, `python3`, `binwalk`. Работай с архивом напрямую — Excel/`openpyxl` показывают только видимое.

## Разбор примера: скрытая строка

Сценарий: данные в скрытой строке листа. Шаг первый — найти строки с `hidden="1"`:

```bash
grep -o "<row [^>]*hidden=[^>]*>" xlsx/xl/worksheets/sheet1.xml | head
```

Шаг второй — прочитать значения этих строк. Ячейки внутри строки содержат `<v>` (значение) или `<is><t>` (инлайн-текст); для строковых значений `<v>` — индекс в `sharedStrings.xml`. Шаг третий — сопоставить индекс со строкой:

```bash
grep -o "<t>[^<]*</t>" xlsx/xl/sharedStrings.xml | sed "s/<[^>]*>//g" | nl | head
```

Шаг четвёртый — если значения закодированы, декодировать. Шаг пятый — проверить скрытые столбцы (`<col ... hidden="1"/>`) — там та же логика.

## Разбор примера: customXml

Сценарий: данные в `customXml/`. Это каталог с произвольными XML-частями, которые приложение не показывает. Шаг первый — проверить наличие: `ls xlsx/customXml/`. Шаг второй — прочитать содержимое: `cat xlsx/customXml/item1.xml`. Часто там лежит флаг или base64-строка.

```bash
ls -la xlsx/customXml/ 2>/dev/null
grep -rniE "nto\{|flag" xlsx/customXml/ 2>/dev/null
```

Дополнительно проверь `_rels/` — связи могут указывать на customXml. И `docProps/` — метаданные с нестандартными полями. Если ничего не найдено, проверь вложенность (`binwalk`) и лишние медиа (`xl/media/`).

Инструменты: `unzip`, `grep`, `python3` (XML-парсер), `exiftool`, `binwalk`. Помни: Excel и `openpyxl` показывают только видимое, поэтому архив проверяй вручную.

## Дополнительные каналы XLSX

Помимо скрытых листов и строк, проверь **скрытые столбцы** (`<col ... hidden="1"/>` в `sheetN.xml`), **скрытые формулы** (ячейка показывает одно, а формула возвращает другое), **определённые имена** (`definedNames`) со ссылками на далёкие ячейки, **защиту листа** (protected — но данные видны). Также **внешние ссылки** (`externalLinks`) могут указывать на скрытые книги.

Ещё каналы: **условное форматирование** (правило может скрывать содержимое), **диаграммы** с данными из скрытых диапазонов, **встроенные объекты** в `xl/embeddings/`, **колонтитулы** и **примечания** к ячейкам. Все они лежат в XML и не видны при обычном просмотре.

## Сводка по XLSX

Порядок разбора: листинг архива → `workbook.xml` (состояния листов) → `sheetN.xml` (скрытые строки/столбцы, значения) → `sharedStrings.xml` (текст) → `styles.xml` (невидимый текст) → `customXml/` → `docProps/` → `xl/media/` → вложенность. Инструменты: `unzip`, `grep`, `python3`, `exiftool`, `binwalk`. Работай с архивом напрямую.

## Последнее замечание по XLSX

Не забывай про `[Content_Types].xml`: там перечислены типы всех частей. Если есть часть, тип которой нестандартен (например, `application/x-secret`), это сигнал — проверь соответствующий файл. И про связи `_rels/`: нестандартная связь может указывать на внешний или скрытый ресурс. Составь список всех частей архива и пройдись по каждой: скрытое часто лежит в части, которую «обычные» инструменты не читают.

## Резюме

XLSX — ZIP+XML: скрытые листы (`state`), скрытые строки/столбцы (`hidden`), невидимый текст, customXml, метаданные, лишние медиа. Разбирай архив напрямую, сверяй части и читай `sharedStrings.xml` — текст ячеек лежит там.

## Что мы теперь знаем
- XLSX — ZIP с `[Content_Types].xml`, `workbook.xml`, листами и строками.
- `state="veryHidden"` делает лист невидимым для интерфейса Excel.
- Скрытые строки/столбцы, definedNames и customXml — дополнительные каналы.
- Разбор начинается с `workbook.xml`.

Держи этот чек-лист под рукой — он покрывает большинство задач на XLSX.

Проверяй все части архива, а не только видимые листы.

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
    - "Атрибут hidden='1' у <row> или <col>"
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
