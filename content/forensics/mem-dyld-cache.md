---
id: mem-dyld-cache
title: 'dyld-кэш: разделяемый код macOS'
category: forensics
parent: forensics-memory-extra
difficulty: hard
order: 2
tags: [forensics, memory, macos, dyld, cache]
prerequisites: [forensics-memory-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Что такое dyld shared cache, где он живёт, как извлекать из него библиотеки и почему это важно для анализа macOS.'
lab:
  kind: shell
  title: 'Практика: dyld-кэш'
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

На macOS системные библиотеки лежат не отдельными файлами, а в одном большом
**dyld shared cache**. Это важно и для анализа памяти, и для реверса. Разберём.

## Наш пример: dyld-кэш

## Шаг 1: что это

`dyld` — динамический загрузчик macOS. Чтобы ускорить запуск, все системные
библиотеки объединены в единый файл — shared cache:

```
/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
```

Отдельных `.dylib` на диске может не быть — они внутри кэша.

## Шаг 2: извлечение

```
$ dyld-shared-cache-extractor dyld_shared_cache_arm64e ./out
```

Или `dyldex`. После извлечения появляются обычные `.dylib`, пригодные для анализа.

## Шаг 3: зачем это форензике

- **анализ памяти** — адреса библиотек в дампе указывают в кэш;
- **реверс** — нужно получить «чистые» библиотеки;
- **сравнение** — подменённая библиотека в кэше = компромисс;
- **символы** — кэш хранит отладочную информацию.

## Шаг 4: в дампе памяти

В памяти библиотеки замаплены из кэша по определённым адресам. По смещениям можно
понять, какая библиотека и какая функция выполнялась:

```
$ strings mac.raw | grep -i 'libsystem' | head
```

## Шаг 5: практика

- извлекай кэш для целевой версии ОС;
- сопоставляй адреса дампа с кэшем;
- проверяй целостность (подпись).

## Что мы теперь знаем

- dyld shared cache — объединённый файл системных библиотек macOS.
- Отдельных dylib может не быть.
- Извлекается dyld-shared-cache-extractor/dyldex.
- Нужен для анализа памяти и реверса.
- Подмена кэша = компромисс.

## Если не сработало

- Кэш не извлекается? Проверь версию инструмента.
- Нужна другая ОС? Бери кэш этой версии.
- Символы отсутствуют? Используй отдельные symbol-файлы.

## Квиз

Проверь себя.

```quiz
- question: Что такое dyld shared cache?
  options:
    - 'сетевой кэш'
    - 'объединённый файл системных библиотек macOS'
    - 'реестр'
    - 'образ'
  answer: 1
  explanation: 'Все системные dylib объединены в один кэш-файл.'
- question: Почему отдельных .dylib может не быть?
  options:
    - 'они удалены'
    - 'они внутри dyld-кэша'
    - 'они в облаке'
    - 'они в реестре'
  answer: 1
  explanation: 'Библиотеки хранятся внутри shared cache.'
- question: Чем полезен кэш для анализа памяти?
  options:
    - 'ничем'
    - 'адреса библиотек в дампе указывают в кэш'
    - 'шифрует'
    - 'сжимает'
  answer: 1
  explanation: 'Сопоставление адресов дампа и кэша даёт контекст.'
- question: Как извлечь библиотеки из кэша?
  options:
    - 'unzip'
    - 'dyld-shared-cache-extractor/dyldex'
    - 'grep'
    - 'cp'
  answer: 1
  explanation: 'Эти инструменты распаковывают кэш в отдельные dylib.'
```
