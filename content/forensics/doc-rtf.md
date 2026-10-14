---
id: doc-rtf
title: 'RTF в форензике: объекты и скрытая нагрузка'
category: forensics
parent: forensics-doc-formats
difficulty: medium
order: 3
tags: [forensics, rtf, ole, exploit, documents]
prerequisites: [forensics-file-magic]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как читать RTF, находить в нём встроенные OLE-объекты и эксплойты, и почему RTF — популярный вектор.'
lab:
  kind: shell
  title: 'Практика: RTF в форензике'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

RTF — «Rich Text Format», текстовый формат с разметкой. Его легко создать и он
поддерживает **встроенные объекты**, поэтому часто используется для доставки
эксплойтов. Разберём.

## Наш пример: подозрительный .rtf

## Шаг 1: это текст

```
$ file invoice.rtf
invoice.rtf: Rich Text Format data
$ head -c 200 invoice.rtf
{\rtf1\ansi ...
```

RTF читается как текст, но внутри — управляющие последовательности (`\objdata`, `\object`).

## Шаг 2: встроенный OLE-объект

Ключевое — `\object` + `\objdata`, где лежит OLE-объект в hex:

```
{\object\objemb{\*\objclass Package}\objw100\objh100
{\*\objdata 0105000002000000...}}
```

`objclass Package` — встроенный файл (например, `.exe`). `\objdata` — его hex-представление.

## Шаг 3: извлекаем

```
$ python3 -c "import re;d=open('invoice.rtf').read();h=re.search(r'objdata ([0-9a-fA-F]+)',d).group(1);open('obj.bin','wb').write(bytes.fromhex(h))"
$ file obj.bin
obj.bin: OLE 2 Compound Document
```

Дальше разбираем OLE-объект.

## Шаг 4: эксплойты

RTF известен эксплойтами (например, Equation Editor, OLE-уязвимости). Признаки:

- большие `\objdata` блоки;
- ссылки на уязвимые объекты;
- `\objupdate` (авто-обновление).

## Шаг 5: что искать

- встроенные OLE-объекты;
- hex-блоки (`\objdata`);
- внешние ссылки;
- необычно большой RTF.

## Что мы теперь знаем

- RTF — текстовый формат с разметкой.
- `\object`/`\objdata` несут встроенные объекты (hex).
- Объект извлекается декодированием hex.
- RTF — известный вектор эксплойтов.
- Признак — большие objdata-блоки.

## Если не сработало

- Несколько объектов? Извлекай все.
- Сжатый объект? Распакуй после декода.
- Нужен анализ? Открой OLE-парсером.

## Квиз

Проверь себя.

```quiz
- question: Что такое RTF?
  options:
    - 'бинарный формат'
    - 'текстовый формат с разметкой'
    - 'образ диска'
    - 'протокол'
  answer: 1
  explanation: 'RTF — текстовый Rich Text Format.'
- question: Что несёт \objdata?
  options:
    - 'пароль'
    - 'встроенный объект в hex'
    - 'сеть'
    - 'обои'
  answer: 1
  explanation: 'objdata содержит hex-представление встроенного OLE-объекта.'
- question: Почему RTF популярен у атакующих?
  options:
    - 'он красивый'
    - 'поддерживает встроенные объекты и известен эксплойтами'
    - 'он быстрый'
    - 'он новый'
  answer: 1
  explanation: 'Встроенные объекты и уязвимости делают RTF удобным вектором.'
- question: Как извлечь объект из objdata?
  options:
    - 'grep'
    - 'декодировать hex в бинарь'
    - 'открыть в браузере'
    - 'никак'
  answer: 1
  explanation: 'objdata — hex; после декода получаем OLE-объект.'
```

## Куда дальше

Дальше — **XPS**: ещё один «контейнерный» формат документов. А пока запомни: RTF — это
текст, но текст с командами, и `\object` — главный красный флаг.

## Где пригодится

- **CTF Forensics** — задачи с RTF и вложенными объектами.
- **Анализ малвари** — разбор фишинговых вложений.
- **DFIR / Incident Response** — исследование подозрительных документов.
