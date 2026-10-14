---
id: mobile-godot
title: 'Реверс Godot: .pck и GDScript'
category: mobile
parent: mobile-game-reversing
difficulty: medium
order: 3
tags: [godot, pck, gdscript, gdsdecomp, gdre, game]
prerequisites: [mobile-unity]
useful_for:
  - 'Реверс мобильных игр'
  - 'Пентест мобильных приложений'
  - 'CTF Game Hacking'
estimated_minutes: 40
summary: 'Как устроена мобильная игра на Godot: единственный контейнер .pck, скомпилированный GDScript (.gdc), извлечение ресурсов через gdsdecomp/godotpcktool и восстановление скриптов.'
lab:
  kind: shell
  title: 'Практика: разбор Godot .pck'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, pck_manifest.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`pck_manifest.txt` — листинг распакованного `.pck`.'
    - 'Ищи скрипты (.gd/.gdc) с игровой логикой.'
    - 'В одном скрипте лежит флаг `nto{...}` — запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

В APK на движке Godot нет ни папки `assets`, ни `.pak`, зато есть один файл `.pck` на десятки
мегабайт. Где логика игры и как её достать? Godot хранит **всё** — ресурсы и скрипты — в одном
контейнере, и это делает разбор особенно аккуратным. Разберём.

## Наш пример: игра «TinyRogue»

```bash
$ unzip -l tinyrogue.apk | grep -iE 'pck|godot' | head
  18874368  assets/game.pck
   3145728  lib/arm64-v8a/libgodot_android.so
```

`.pck` — это пакет ресурсов Godot. Он может быть **незашифрованным** или зашифрованным
(тогда в начале лежит признак шифрования и нужен ключ). `libgodot_android.so` — движок; если
игра использует C# (Godot Mono), рядом будут управляемые сборки, но чаще это GDScript.

## Шаг 1: смотрим заголовок .pck

Первые байты `.pck` начинаются с магического числа `GDPC` (Godot Pack). Проверить:

```bash
$ xxd -l 16 game.pck
00000000: 4744 5043 0000 0002 0000 0000 0000 0000  GDPC............
```

`GDPC` подтверждает формат. Если после него стоит флаг шифрования — пакет защищён, и ключ
надо искать в `libgodot_android.so` (или в скриптах сборки).

## Шаг 2: распаковка gdsdecomp / godotpcktool

Для извлечения используют **gdsdecomp** (GDRE Tools) или `godotpcktool`:

```bash
$ godotpcktool game.pck -a extract -o ./out
Extracting 1240 files...
Done: ./out
```

В результате получаем дерево `.tscn` (сцены), `.gd`/`.gdc` (скрипты), `.png`, `.tres`.
Файлы `.gdc` — это скомпилированный GDScript-байткод; gdsdecomp умеет восстанавливать из него
читаемый `.gd`.

## Шаг 3: восстановление скриптов

Если скрипты скомпилированы, GDRE Tools декомпилирует байткод:

```bash
$ gdre_tools --headless --decompile out/
Decompiling 87 scripts...
```

После этого ищем игровую логику и секреты:

```bash
$ grep -rn "unlock\|premium\|secret\|flag" out/*.gd | head
```

## Шаг 4: если пакет зашифрован

Зашифрованный `.pck` использует AES; ключ вшит в бинарник движка. Его ищут в
`libgodot_android.so` по сигнатурам или через динамический анализ (в момент расшифровки в
памяти). После получения ключа `godotpcktool` принимает его флагом.

## Таблица: артефакты Godot

| Артефакт | Что это | Инструмент |
|---|---|---|
| game.pck | контейнер ресурсов | godotpcktool, gdsdecomp |
| .tscn | сцена | редактор/текст |
| .gd / .gdc | скрипт / байткод | gdsdecomp, gdre_tools |
| libgodot_android.so | движок | IDA, Ghidra |

## Крайние случаи и подводные камни

- Версия `.pck` должна поддерживаться инструментом; для новых Godot нужна свежая GDRE Tools.
- Скомпилированный GDScript восстанавливается не идеально — имена переменных могут теряться.
- Шифрование `.pck` без ключа делает пакет бесполезным; ключ ищите в движке.
- Игры на Godot Mono содержат и C#-сборки — их разбирают как Unity Mono (ILSpy).

## Что дальше / решение

Итог: Godot упаковывает всё в `.pck`; проверьте `GDPC`, распакуйте `godotpcktool`, декомпилируйте
`.gdc` через gdsdecomp. Если пакет зашифрован — ищите AES-ключ в движке. Это завершает модуль по
игровым движкам: Unity, Unreal, Godot.


## Квиз

Проверь себя.

```quiz
- question: Какая сигнатура у контейнера Godot .pck?
  options:
    - GDPC
    - PK
    - RAR
    - FPakInfo
  answer: 0
  explanation: Пакет Godot начинается с магического числа GDPC.
- question: Что такое .gdc?
  options:
    - Текстура
    - Скомпилированный GDScript-байткод
    - Нативная библиотека
    - Манифест
  answer: 1
  explanation: .gdc — байткод GDScript, восстанавливается gdsdecomp.
- question: Где искать ключ зашифрованного .pck?
  options:
    - В AndroidManifest
    - В libgodot_android.so
    - В .tscn
    - В META-INF
  answer: 1
  explanation: Ключ вшит в движок и извлекается из него.
- question: Чем разбирать C#-сборку на Godot Mono?
  options:
    - Il2CppDumper
    - ILSpy/dnSpy
    - FModel
    - repak
  answer: 1
  explanation: Godot Mono использует управляемые сборки .NET.
```

## Где пригодится

- **Реверс мобильных игр:** быстрый разбор Godot-проектов.
- **Пентест мобильных приложений:** поиск секретов в ресурсах и скриптах.
- **Game Hacking:** анализ игровой логики на GDScript.
- **CTF:** Godot-задачи на `.pck`.
