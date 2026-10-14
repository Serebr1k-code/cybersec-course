---
id: mobile-unreal
title: 'Реверс Unreal Engine на мобильных'
category: mobile
parent: mobile-game-reversing
difficulty: hard
order: 2
tags: [unreal, ue4, ue5, pak, uasset, iostore, fmodel]
prerequisites: [mobile-unity]
useful_for:
  - 'Реверс мобильных игр'
  - 'Пентест мобильных приложений'
  - 'CTF Game Hacking'
estimated_minutes: 48
summary: 'Как устроена мобильная игра на Unreal: нативная libUE4/libUnreal, контейнеры .pak и IoStore (.utoc/.ucas), извлечение ассетов через FModel и поиск логики в нативном коде.'
lab:
  kind: shell
  title: 'Практика: распаковка Unreal .pak'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, pak_listing.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`pak_listing.txt` — листинг содержимого `.pak`.'
    - 'Ищи ассеты с секретами (DataTable/StringTable).'
    - 'В одном ассете лежит флаг `nto{...}` — запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

В игре на Unreal нет ни `Assembly-CSharp.dll`, ни `libil2cpp.so` — логика целиком нативная, а
ресурсы лежат в непонятном `pakchunk0-Android_ASTC.pak`. С чего начать и как достать ассеты и
код? Разберём анатомию мобильной сборки Unreal.

## Наш пример: игра «SkyForge»

```bash
$ unzip -l skyforge.apk | grep -E 'libUE4|libUnreal|pak|utoc|ucas' | head
  43219876  lib/arm64-v8a/libUE4.so
  12003456  assets/pakchunk0-Android_ASTC.pak
   9876543  assets/pakchunk1-Android_ASTC.pak
```

`libUE4.so` — сердце движка (в UE5 встречается `libUnreal.so`), а `.pak` — контейнер с
ассетами. В новых сборках вместо `.pak` используется IoStore: файлы `.utoc` (таблица
содержимого) и `.ucas` (данные). Наличие `.pak` — хорошая новость: их проще распаковать.

## Шаг 1: определяем версию и ключ упаковки

Формат `.pak` начинается с сигнатуры `FPakInfo` и содержит версию. Если ассеты зашифрованы,
ключ AES лежит **внутри** `libUE4.so` — его находят поиском 32-байтовых кандидатов или
известными сигнатурами. Для незашифрованных pak ключ не нужен.

```bash
$ strings -n 8 libUE4.so | grep -iE 'pak|aes|key' | head
```

## Шаг 2: распаковка .pak

Для распаковки используют UnrealPak, `repak`, quickbms или FModel. Результат — дерево
`.uasset`/`.uexp`/`.ubulk`. `.uasset` — сам ассет, `.uexp` — вынесенные данные экспорта.

```bash
$ repak unpack pakchunk0-Android_ASTC.pak --output ./unpacked
Unpacking 8123 entries...
Done.
```

## Шаг 3: просмотр ассетов в FModel

FModel открывает `.uasset` и показывает текстуры, звуки, а иногда и тексты/локализацию. Через
него же можно экспортировать ресурсы. Ищите строки с ключами, токенами и флагами — разработчики
часто кладут их в `DataTable` или `StringTable`.

## Шаг 4: логика в нативном коде

Игровая логика Unreal — это нативный C++ в `libUE4.so`. Идентификация функций идёт по строкам
и по отражению (UE reflection): имена UFunction/UClass видны в бинарнике как строки, а
метаданные — в структурах `FName`. Практический путь:

```bash
$ strings -n 8 libUE4.so | grep -iE 'Verify|Purchase|Unlock|Cheat' | head
```

Затем в IDA/Ghidra ищут ссылки на эти строки и анализируют вызывающие функции. Символы часто
сохранены частично — это облегчает навигацию.

## Шаг 5: динамика

На устройстве можно подключаться Frida к нативным функциям и перехватывать проверки по
адресу из `libUE4.so` (с учётом ASLR — по смещению от базы модуля). Так же ловят расшифровку
pak-ассетов в памяти.

## Таблица: форматы Unreal

| Файл | Что это | Инструмент |
|---|---|---|
| libUE4.so / libUnreal.so | движок и логика | IDA, Ghidra |
| .pak | контейнер ассетов | repak, UnrealPak, FModel |
| .utoc / .ucas | IoStore (UE5) | FModel, ZenTools |
| .uasset / .uexp | отдельный ассет | FModel, UAssetGUI |

## Крайние случаи и подводные камни

- Зашифрованный `.pak` без ключа бесполезен: ключ ищут в движке или в сопутствующем `.sig`.
- IoStore (`.utoc/.ucas`) не поддерживается старыми распаковщиками — нужна свежая версия FModel.
- `.uasset` содержит ссылки на `.uexp`; открывать их по отдельности нельзя.
- Обфускация движка переименовывает символы, но строки проверок обычно остаются.
- Часть логики может быть в Blueprint, скомпилированном в нативный код — тогда ищите по
  строкам свойств и по отражению.

## Что дальше / решение

Итог: Unreal — нативный движок; код в `libUE4.so`, ассеты — в `.pak`/IoStore. Начните с
определения формата контейнера, затем распакуйте ассеты и перейдите к строкам нативного кода.
В следующем уроке — Godot с единственным файлом `.pck`.


## Квиз

Проверь себя.

```quiz
- question: Что содержит .pak в игре на Unreal?
  options:
    - Нативный код
    - Игровые ассеты
    - Метаданные C#
    - Сертификаты
  answer: 1
  explanation: .pak — контейнер ассетов (текстуры, звуки, данные).
- question: Где может лежать ключ шифрования .pak?
  options:
    - В AndroidManifest
    - Внутри libUE4.so
    - В resources.arsc
    - В META-INF
  answer: 1
  explanation: Ключ AES обычно вшит в бинарник движка.
- question: Чем IoStore отличается от .pak?
  options:
    - Ничем
    - Это формат UE5 с .utoc/.ucas
    - Это формат Godot
    - Это формат Unity
  answer: 1
  explanation: IoStore хранит данные в .ucas и индекс в .utoc.
- question: Где искать игровую логику в Unreal-игре?
  options:
    - В Assembly-CSharp.dll
    - В нативном libUE4.so
    - В global-metadata.dat
    - В .pck
  answer: 1
  explanation: Логика Unreal — нативный C++ в движке.
```

## Где пригодится

- **Реверс мобильных игр:** разбор UE-игр и их ассетов.
- **Пентест мобильных приложений:** поиск секретов в DataTable/StringTable.
- **Game Hacking:** анализ нативной логики движка.
- **CTF:** Unreal-задачи на контейнеры ассетов.
