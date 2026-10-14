---
id: stego-odf
title: "OpenDocument (ODT/ODS/ODP): meta.xml и лишние файлы"
category: stego
parent: stego-module-office-adv
difficulty: medium
order: 2
tags: [stego, odf, odt, meta-xml, zip, document]
prerequisites: [stego-epub]
useful_for:
  - "CTF Stego: офисные документы"
  - "Форензика: документы-улики"
  - "Blue team: служебные XML офисных файлов"
estimated_minutes: 15
summary: "OpenDocument как ZIP: mimetype, content/styles/meta/settings.xml, пользовательские поля meta:user-defined, лишние файлы и встроенные миниатюры как каналы."
lab:
  kind: shell
  title: "Практика: base64 в meta:user-defined"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, doc.odt, odf.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "ODT — это ZIP: `unzip -l doc.odt`."
    - "Ищи `meta:user-defined` в meta.xml."
    - "`python3 odf.py` декодирует base64."
    - "`python3 odf.py | grep nto > found.txt`."
---

## Вопрос, с которого всё начинается
OpenDocument (ODT/ODS/ODP) — открытый формат LibreOffice и многих госструктур.
Как и EPUB, это ZIP. Но у него есть особенность: служебные XML-файлы, которые
редактор не показывает. Один из них — `meta.xml` — принимает **пользовательские
поля** произвольной длины. Идеальное место для закладки.

## Наш пример
Возьмём `doc.odt` — минимальный документ. Разберём его ZIP-структуру и найдём
закладку в `meta.xml`.

## Шаг 1: структура ODF
```
$ unzip -l doc.odt
  Length      Name
        39  mimetype
       900  META-INF/manifest.xml
      1200  content.xml
       600  styles.xml
       420  meta.xml
       300  settings.xml
```

`mimetype` — `application/vnd.oasis.opendocument.text` (первая запись, без
сжатия). Далее — XML-файлы:
- `content.xml` — текст и разметка;
- `styles.xml` — стили;
- `meta.xml` — метаданные (автор, дата, **пользовательские поля**);
- `settings.xml` — настройки окна;
- `META-INF/manifest.xml` — список файлов и типов.

## Шаг 2: пользовательские поля в meta.xml
Стандарт ODF определяет элемент `meta:user-defined` с атрибутом `meta:name` и
произвольным текстовым значением. Никто его не отображает — это «техническое»
поле:

```xml
<meta:user-defined meta:name="BuildID">bnRve29kZl9tZXRhX2ZpZWxkfQ==</meta:user-defined>
```

Значение — base64. Редактор сохранит его, читатель не увидит.

## Шаг 3: другие каналы в ODF
- **Лишние файлы.** Запись ZIP, не указанная в `manifest.xml`, — невидима.
- **`content.xml` пробелы.** Как в JSON: незначащие пробелы между тегами.
- **Встроенные объекты.** `Thumbnails/thumbnail.png` — картинка, в пикселях
  которой можно спрятать данные.
- **`settings.xml`.** Произвольные пары ключ-значение.

## Шаг 4: извлечение вручную
```python
import zipfile, base64, re
z = zipfile.ZipFile('doc.odt')
meta = z.read('meta.xml').decode()
m = re.search(r'meta:user-defined[^>]*>([^<]+)<', meta)
print(base64.b64decode(m.group(1)).decode())
```

Вывод:

```
nto{odf_meta_field}
```

## Шаг 5: инструменты
- `unzip -l doc.odt`, `unzip -p doc.odt meta.xml`.
- `odfpy` / `python3 -c 'from odf.opendocument import load'` — программный разбор.
- `libreoffice --headless --convert-to` — нормализация (перезапись файла убивает
  лишние поля).

## Что мы теперь знаем
- ODF — ZIP с `mimetype` и XML-файлами (`content`, `styles`, `meta`, `settings`).
- `meta:user-defined` — штатное поле для произвольных данных.
- Лишние файлы и встроенные миниатюры — дополнительные каналы.
- Пересохранение в LibreOffice — нормализация.

## Квиз

Проверь себя.

```quiz
- question: "Что такое ODF на уровне контейнера?"
  options:
    - "ZIP с mimetype и набором XML-файлов"
    - "Один бинарный файл без структуры"
    - "Текстовый файл"
    - "База данных SQLite"
  answer: 0
  explanation: "ODT/ODS/ODP — это ZIP-контейнеры с XML."
- question: "Какой элемент ODF предназначен для произвольных полей?"
  options:
    - "meta:user-defined с meta:name"
    - "content:text"
    - "office:body"
    - "style:default"
  answer: 0
  explanation: "Пользовательские метаданные хранятся в meta.xml."
- question: "Почему файл, отсутствующий в manifest.xml, невидим?"
  options:
    - "Редактор ориентируется на манифест при чтении"
    - "Он зашифрован"
    - "Он слишком маленький"
    - "Он в другой кодировке"
  answer: 0
  explanation: "Манифест перечисляет содержимое; лишние записи игнорируются."
- question: "Что убивает закладку в meta.xml?"
  options:
    - "Пересохранение документа в редакторе (нормализация)"
    - "Открытие на просмотр"
    - "Смена имени файла"
    - "Копирование"
  answer: 0
  explanation: "Редактор перезаписывает служебные поля по своей схеме."
```

## Куда дальше
ODF и EPUB — «документные» ZIP-контейнеры. Дальше — OOXML (XLSX/PPTX), где
каналов ещё больше: скрытые листы, заметки, вынесенные за пределы слайда фигуры.

## Где пригодится
- **CTF:** задачи с офисными документами.
- **Форензика:** разбор документов-улик.
- **Blue team:** данные в служебных XML офисных файлов.
