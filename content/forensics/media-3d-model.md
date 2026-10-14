---
id: media-3d-model
title: '3D-модели в форензике: форматы и встроенные данные'
category: forensics
parent: forensics-media-analysis
difficulty: medium
order: 3
tags: [forensics, 3d, stl, obj, gltf, metadata]
prerequisites: [forensics-file-magic]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 40
summary: 'Как разбирать 3D-форматы (STL/OBJ/GLTF/3MF): геометрия, метаданные и скрытые данные.'
lab:
  kind: shell
  title: "Практика: метаданные 3D-модели"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, model_meta.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "OBJ хранит комментарии (`#`) и ссылки на .mtl — туда можно спрятать данные."
    - "Комментарий с меткой — цель."
    - "`grep nto model_meta.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

Пришла 3D-модель — для печати, дизайна или как улика (например, оружие). Нужно понять
формат и что в нём. Разберём.

## Наш пример: STL

## Шаг 1: форматы

- **STL** — только геометрия (треугольники), без цвета;
- **OBJ** — геометрия + материалы;
- **GLTF/GLB** — современный (JSON + бинарь), с анимацией;
- **3MF** — ZIP-контейнер (как OOXML).

## Шаг 2: STL

```
$ file part.stl
part.stl: ASCII text
```
или бинарный:
```
$ file part.stl
part.stl: data
```

ASCII-STL читается глазами (`facet normal ...`), бинарный — 80-байтовый заголовок +
число треугольников.

```
$ head -c 80 part.stl | strings
```

Заголовок часто содержит имя/комментарий — иногда с данными.

## Шаг 3: GLTF/GLB

GLB — бинарный контейнер с JSON-чанком:

```
$ python3 -c "import json,struct;d=open('m.glb','rb').read();print(d[20:20+struct.unpack('<I',d[12:16])[0]])"
```

JSON содержит метаданные: генератор, автор, лицензию.

## Шаг 4: 3MF

3MF — ZIP:

```
$ unzip -l model.3mf
  3D/3dmodel.model
  Metadata/...
```

Внутри XML с геометрией и метаданными.

## Шаг 5: что искать

- метаданные (генератор, автор, время);
- лишние чанки/файлы;
- аномалии геометрии (скрытые объекты);
- встроенные текстуры/скрипты (GLTF может ссылаться на внешние данные).

## Что мы теперь знаем

- STL — только геометрия; OBJ/GLTF/3MF богаче.
- Бинарный STL имеет 80-байтовый заголовок.
- GLB — JSON+бинарь; 3MF — ZIP.
- Метаданные выдают генератор/автора.
- Скрытые объекты/чанки — признак модификации.

## Если не сработало

- Формат неизвестен? Используй `file`/`binwalk`.
- Нужен рендер? Импортируй в Blender.
- Данные сжаты? Смотри контейнер.

## Квиз

Проверь себя.

```quiz
- question: Что хранит STL?
  options:
    - 'цвет и текстуры'
    - 'только геометрию (треугольники)'
    - 'сеть'
    - 'скрипты'
  answer: 1
  explanation: 'STL описывает поверхность треугольниками, без цвета.'
- question: Что такое 3MF?
  options:
    - 'бинарный файл'
    - 'ZIP-контейнер с XML'
    - 'сеть'
    - 'кодек'
  answer: 1
  explanation: '3MF — zip-формат, похожий по идее на OOXML.'
- question: Что содержит заголовок бинарного STL?
  options:
    - 'ничего'
    - '80 байт комментария/имени'
    - 'пароль'
    - 'сеть'
  answer: 1
  explanation: '80-байтовый заголовок может содержать текст.'
- question: Чем полезен GLB для анализа?
  options:
    - 'ничем'
    - 'содержит JSON с метаданными'
    - 'шифрует'
    - 'сжимает'
  answer: 1
  explanation: 'JSON-чанк GLB описывает сцену и метаданные.'
```
