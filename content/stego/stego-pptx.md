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
    - "Атрибут show=\"0\" у sldId в presentation.xml"
    - "Удалить файл слайда"
    - "Зашифровать слайд"
    - "Сменить фон"
  answer: 0
  explanation: "show=\"0\" помечает слайд как скрытый."
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
