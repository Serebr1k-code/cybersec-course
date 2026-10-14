---
id: stego-epub
title: "EPUB-стеганография: непронумерованные файлы и метаданные"
category: stego
parent: stego-module-office-adv
difficulty: medium
order: 1
tags: [stego, epub, zip, opf, container, document]
prerequisites: [stego-document-carriers]
useful_for:
  - "CTF Stego: книги и архивы документов"
  - "Форензика: анализ вложений-книг"
  - "Blue team: носители в безобидных документах"
estimated_minutes: 15
summary: "Разбираем EPUB как ZIP: mimetype, META-INF/container.xml, OPF-манифест, spine. Где прячут данные (непронумерованные файлы, метаданные, CSS) и как извлекать их."
lab:
  kind: shell
  title: "Практика: скрытый файл в EPUB"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, book.epub, epub.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "EPUB — это ZIP: `unzip -l book.epub`."
    - "Скрытый файл не упомянут в content.opf."
    - "`python3 epub.py` печатает его содержимое."
    - "`python3 epub.py | grep nto > found.txt`."
---

## Вопрос, с которого всё начинается
EPUB — самый распространённый формат электронных книг. Ты открываешь его в
читалке, видишь текст. Но EPUB — это **ZIP-архив** со строго заданной структурой,
и внутри него легко спрятать файл, который ни одна читалка не покажет. Задача:
найти в книге то, чего в тексте нет.

## Наш пример
Возьмём `book.epub` — минимальную книгу. Разберём её как ZIP и найдём
непронумерованный файл.

## Шаг 1: EPUB — это ZIP
```
$ file book.epub
book.epub: EPUB document
$ unzip -l book.epub
  Length      Name
        20  mimetype
       250  META-INF/container.xml
      1024  OEBPS/content.opf
      2048  OEBPS/chapter1.xhtml
       120  OEBPS/secret.txt
```

Первая запись обязана быть `mimetype` со строкой `application/epub+zip` и
**без сжатия** — иначе валидатор EPUB отклонит файл. Всё остальное — обычные
ZIP-записи.

## Шаг 2: как устроена книга
- `META-INF/container.xml` — указывает путь к OPF-файлу (пакету).
- `OEBPS/content.opf` — манифест (список ресурсов), spine (порядок глав),
  метаданные (автор, ISBN, обложка).
- `OEBPS/*.xhtml` — сам текст.
- `OEBPS/*.css`, картинки — оформление.

Читалка показывает только то, что перечислено в spine/manifest. Файл, которого
там нет, остаётся невидимым.

## Шаг 3: где прячут данные в EPUB
- **Непронумерованные файлы.** Любая запись ZIP, не упомянутая в OPF, — невидима
  для читалки.
- **Метаданные OPF.** `<dc:description>`, `<meta property="dcterms:...">` —
  произвольные строки.
- **CSS-комментарии.** `/* ... */` в таблице стилей.
- **Обложка.** Данные в пикселях или в EXIF обложки.
- **Пустые/служебные записи.** `META-INF/encryption.xml` и подобное.

## Шаг 4: извлечение вручную
```python
import zipfile
z = zipfile.ZipFile('book.epub')
opf = z.read('OEBPS/content.opf').decode()
for name in z.namelist():
    if 'secret' in name or name not in opf:
        print(name, z.read(name))
```

Вывод:

```
OEBPS/secret.txt b'nto{epub_unreferenced_file}'
```

## Шаг 5: инструменты
- `unzip -l book.epub` — список записей.
- `epubcheck book.epub` — валидатор (лишние файлы выдаст предупреждением).
- `zipinfo -v` — детали записей.

## Что мы теперь знаем
- EPUB — ZIP с обязательным `mimetype` и OPF-манифестом.
- Непронумерованные файлы невидимы для читалки.
- Метаданные, CSS-комментарии, обложка — дополнительные каналы.
- Разбор начинается с `unzip -l` и чтения OPF.

## Квиз

Проверь себя.

```quiz
- question: "Что представляет собой EPUB-файл на уровне контейнера?"
  options:
    - "ZIP-архив с обязательным mimetype и OPF-манифестом"
    - "Простой текстовый файл"
    - "JPEG-изображение"
    - "Исполняемый файл"
  answer: 0
  explanation: "EPUB — это ZIP со строго заданной структурой."
- question: "Почему файл, не упомянутый в OPF, невидим читалке?"
  options:
    - "Читалка отображает только ресурсы из манифеста/spine"
    - "Он зашифрован"
    - "Он удалён"
    - "Он слишком большой"
  answer: 0
  explanation: "Показ определяется манифестом; прочие записи игнорируются."
- question: "Каким должно быть первое вхождение ZIP в EPUB?"
  options:
    - "`mimetype` без сжатия со строкой application/epub+zip"
    - "Обложка JPEG"
    - "content.opf"
    - "container.xml"
  answer: 0
  explanation: "Спецификация требует несжатый mimetype первым."
- question: "Где ещё в EPUB можно спрятать данные?"
  options:
    - "В метаданных OPF, CSS-комментариях, обложке"
    - "Только в названии книги"
    - "Только в ISBN"
    - "Нигде"
  answer: 0
  explanation: "Метаданные и оформление — дополнительные носители."
```

## Куда дальше
EPUB — ZIP с манифестом. Родственный формат — OpenDocument (ODT), где канал
живёт в `meta.xml`. О нём — в следующем уроке.

## Где пригодится
- **CTF:** задачи с книгами и архивами документов.
- **Форензика:** анализ вложений-книг.
- **Blue team:** носители данных в безобидных документах.
