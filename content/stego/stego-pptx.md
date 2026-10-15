---
id: stego-pptx
title: "PPTX: заметки, скрытые слайды и фигуры за краем"
category: stego
parent: stego-module-office-adv
difficulty: medium
order: 4
tags: [stego, pptx, ooxml, notes, hidden-slide, zip, document]
prerequisites: [stego-xlsx-hidden]
useful_for:
  - "CTF Stego: презентации"
  - "Форензика: заметки и комментарии"
  - "Blue team: эксфильтрация в офисных вложениях"
estimated_minutes: 16
summary: "PPTX как OOXML-ZIP: presentation.xml, скрытые слайды (show=0), заметки докладчика, комментарии, фигуры за пределами слайда и docProps как носители данных."
lab:
  kind: shell
  title: "Практика: метка в notesSlide"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, talk.pptx, pptx.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "PPTX — это ZIP: `unzip -l talk.pptx`."
    - "Заметки лежат в ppt/notesSlides/."
    - "`python3 pptx.py` печатает метку."
    - "`python3 pptx.py | grep nto > found.txt`."
---

## Вопрос, с которого всё начинается
Презентация `.pptx` — это слайды, картинки, заметки. Показываешь её — видишь
слайды. Но внутри OOXML-архива есть заметки докладчика, комментарии, фигуры,
вынесенные за пределы слайда, и скрытые слайды. Всё это не отображается при
показе, но остаётся в файле. Идеальный носитель.

## Наш пример
Возьмём `talk.pptx` — презентацию с одним слайдом и заметкой докладчика, в
которой спрятана метка.

## Шаг 1: PPTX — это ZIP
```
$ unzip -l talk.pptx
       120  [Content_Types].xml
       420  ppt/presentation.xml
       620  ppt/slides/slide1.xml
       540  ppt/notesSlides/notesSlide1.xml
       280  ppt/_rels/presentation.xml.rels
```

- `ppt/presentation.xml` — список слайдов;
- `ppt/slides/slideN.xml` — содержимое слайда;
- `ppt/notesSlides/notesSlideN.xml` — заметки докладчика;
- `ppt/comments/` — комментарии;
- `ppt/media/` — картинки, видео.

## Шаг 2: скрытые слайды
В `presentation.xml` у слайда может быть `show="0"` — слайд скрыт при показе:

```xml
<p:sldId id="256" r:id="rId2" show="0"/>
```

Слайд есть, но в режиме презентации не показывается.

## Шаг 3: заметки докладчика
`notesSlideN.xml` содержит текст заметок. Их не видно на экране презентации, но
они полностью сохраняются:

```xml
<a:t>nto{pptx_notes_slide}</a:t>
```

## Шаг 4: фигуры за пределами слайда
Элемент `<a:off x="..." y="..."/>` задаёт позицию. Если `x` или `y` больше
размера слайда (например, 9999999 EMU), фигура «уезжает» за край и не видна.
Данные в ней сохраняются.

## Шаг 5: ещё каналы
- **Комментарии** (`ppt/comments/comment1.xml`) — невидимы при показе.
- **Медиа** — данные в пикселях картинки или в её метаданных.
- **`docProps/app.xml`** — служебные поля (Title, Company) произвольной длины.
- **`customXml/`** — прикреплённые данные.

## Шаг 6: извлечение вручную
```python
import zipfile, re
z = zipfile.ZipFile('talk.pptx')
for name in z.namelist():
    if 'notesSlide' in name:
        txt = z.read(name).decode()
        m = re.search(r'nto\{[^}]*\}', txt)
        if m:
            print(m.group(0))
```

Вывод:

```
nto{pptx_notes_slide}
```

## Шаг 7: инструменты
- `unzip -l talk.pptx`.
- `python-pptx` — программный разбор.
- `libreoffice --headless --convert-to pptx` — нормализация.

## Полный разбор PPTX

PPTX — ZIP-контейнер (OOXML). Структура: `[Content_Types].xml`, `_rels/`, `ppt/presentation.xml`, `ppt/slides/slideN.xml`, `ppt/notesSlides/notesSlideN.xml`, `ppt/slideLayouts/`, `ppt/slideMasters/`, `ppt/media/` (изображения), `docProps/` (метаданные).

```bash
unzip -l deck.pptx
unzip -o deck.pptx -d pptx/
grep -rniE "nto\{|flag" pptx/ | head
```

Каналы сокрытия. Первый — **скрытые слайды**: атрибут `show="0"` на слайде означает, что при показе он пропускается, но содержимое остаётся в файле. Ищи `show="0"` в `slideN.xml`.

Второй — **заметки докладчика** (`notesSlide`): текст заметок не виден в режиме показа, но лежит в файле. Третий — **фигуры за пределами слайда**: элемент с координатами вне области (например, `x="-5000000"`) не виден, но существует. Четвёртый — **невидимый текст**: белый цвет, нулевой размер шрифта, прозрачность.

Пятый — **изображения в `ppt/media/`**, не используемые ни одним слайдом (лишние файлы). Шестой — **метаданные** в `docProps/core.xml` и `docProps/app.xml`. Седьмой — **заметки/комментарии** (comments). Восьмой — **кастомные XML-части** (`customXml/`), которые не отображаются.

## Извлечение и инструменты

```bash
grep -rn "show=\"0\"" pptx/ppt/slides/
grep -rniE "nto\{|flag|secret" pptx/ppt/notesSlides/ pptx/customXml/ 2>/dev/null
unzip -l deck.pptx | grep media
```

Порядок: листинг архива → скрытые слайды (`show="0"`) → заметки → фигуры за пределами → невидимый текст → лишние медиа → метаданные → customXml → вложенность (`binwalk`). Инструменты: `unzip`, `zipinfo`, `grep`, `python3` (XML-парсер), `exiftool`, `binwalk`.

PPTX близок к DOCX/XLSX: ZIP + XML + `[Content_Types].xml`. Освоив один OOXML-формат, разбираешь остальные. Ключевое — файлы и атрибуты, которые не отображаются: скрытые слайды, заметки, фигуры за краем, customXml.

## customXml, связи и дополнительные каналы

Помимо скрытых слайдов и заметок, в PPTX есть ещё каналы. Первый — **customXml**: каталог `customXml/`, содержащий произвольные XML-части, которые не отображаются. Второй — **связи** (`_rels/*.rels`): списки отношений между частями; лишние связи могут указывать на скрытые ресурсы. Третий — **комментарии** (comments): текст комментариев к слайдам.

Четвёртый — **теги** (`ppt/tags/`): метаданные слайдов. Пятый — **`docProps/`**: `core.xml` (автор, заголовок, даты) и `app.xml` (приложение, версия, статистика). Шестой — **`[Content_Types].xml`**: описания типов; нестандартные типы могут указывать на скрытые части.

Седьмой — **`ppt/media/`**: изображения, среди которых могут быть неиспользуемые. Восьмой — **`ppt/embeddings/`**: встроенные объекты (OLE), которые могут содержать другие документы. Девятый — **`ppt/notesMasters/`**: мастера заметок.

```bash
unzip -l deck.pptx | grep -E "customXml|embeddings|media|tags"
grep -rniE "nto\{|flag" pptx/ 2>/dev/null | head
```

Практика: пройдись по всем частям архива, а не только по слайдам. Наиболее частые каналы — скрытые слайды, заметки и customXml.

## Практика: извлечение скрытого слайда

Разберём сценарий со скрытым слайдом. Шаг первый — найти атрибут `show="0"`:

```bash
grep -rn "show=\"0\"" pptx/ppt/slides/
# pptx/ppt/slides/slide7.xml: <p:sld ... show="0">
```

Шаг второй — прочитать содержимое этого слайда: `grep -A50 "show=\"0\"" pptx/ppt/slides/slide7.xml` или открыть файл и найти текст (`<a:t>...</a:t>`). Шаг третий — если текст закодирован (base64/hex), декодировать.

Второй сценарий — заметки: `grep -rn "nto" pptx/ppt/notesSlides/`. Третий — фигуры за краем: ищи в `slideN.xml` координаты с большими отрицательными значениями (`<a:off x="-...")`. Четвёртый — невидимый текст: `srgbClr val="FFFFFF"` (белый) или `<a:rPr sz="100"/>` (крошечный шрифт).

Пятый — лишние медиа: сравни список файлов в `ppt/media/` с теми, что упомянуты в слайдах. Неиспользуемые — канал. Шестой — customXml: `ls pptx/customXml/`.

Инструменты: `unzip`, `grep`, `python3` (XML-парсер), `zipinfo`, `exiftool`. Помни, что PowerPoint показывает только видимые слайды и текст, поэтому все каналы находятся только при работе с архивом.

## Вложенные медиа и метаданные

Изображения внутри PPTX (`ppt/media/`) — отдельные контейнеры, и их нужно проверять на стего-каналы отдельно: `zsteg` для PNG, `exiftool` для метаданных, `binwalk` для вложенного. Часто флаг лежит именно в картинке, а PPTX — просто «обёртка», которую пронесли мимо внимания.

```bash
unzip -o deck.pptx "ppt/media/*" -d media/
for f in media/ppt/media/*; do echo "== $f"; exiftool "$f" | head -5; done
zsteg media/ppt/media/image1.png 2>/dev/null | head
```

Метаданные (`docProps/core.xml`, `docProps/app.xml`) могут содержать данные в нестандартных полях: `dc:creator`, `dc:title`, `cp:keywords`, `Company`. Проверь их на подозрительные значения.

Отдельно — `ppt/presentation.xml`: там список слайдов (`<p:sldIdLst>`) с их идентификаторами. Если слайд есть в архиве, но не в списке — он скрыт не атрибутом, а отсутствием в презентации. Сравни список `sldIdLst` с фактическими файлами `slideN.xml`.

Итог: PPTX — многослойный контейнер. Проверяй слайды, заметки, customXml, связи, медиа, метаданные и список слайдов. Наиболее частые каналы — скрытые слайды и заметки, но вложенные изображения тоже стоит проверять.

## Что мы теперь знаем
- PPTX — ZIP с `presentation.xml`, слайдами, заметками и медиа.
- `show="0"` скрывает слайд, заметки и комментарии не видны при показе.
- Фигуры за пределами слайда — простой способ спрятать контент.
- Разбор начинается с `presentation.xml` и заметок.

## Квиз

Проверь себя.

```quiz
- question: "Что такое PPTX на уровне контейнера?"
  options:
    - "ZIP с XML-частями OOXML"
    - "Один бинарный файл"
    - "Текстовый файл"
    - "Изображение"
  answer: 0
  explanation: "PPTX — OOXML-ZIP с частями presentation/slides/notes."
- question: "Как скрыть слайд при показе?"
  options:
    - "Атрибут show='0' у sldId в presentation.xml"
    - "Удалить файл слайда"
    - "Зашифровать слайд"
    - "Сменить фон"
  answer: 0
  explanation: "show='0' помечает слайд как скрытый."
- question: "Где хранятся заметки докладчика?"
  options:
    - "ppt/notesSlides/notesSlideN.xml"
    - "ppt/slides/slideN.xml"
    - "docProps/app.xml"
    - "[Content_Types].xml"
  answer: 0
  explanation: "Заметки — отдельные XML-части notesSlides."
- question: "Как спрятать фигуру на слайде?"
  options:
    - "Вынести её за пределы слайда (большие x/y в a:off)"
    - "Сделать её прозрачной только"
    - "Уменьшить шрифт"
    - "Скрыть слайд"
  answer: 0
  explanation: "Координаты за границей слайда делают фигуру невидимой при показе."
```

## Куда дальше
Офисные документы разобраны. Дальше — двоичные форматы: Git-объекты, слои Docker
и ELF/Mach-O. А пока запомни: контейнер-архив — это всегда много «невидимых» мест.

## Где пригодится
- **CTF:** задачи с презентациями.
- **Форензика:** данные в заметках и комментариях.
- **Blue team:** эксфильтрация через офисные вложения.
