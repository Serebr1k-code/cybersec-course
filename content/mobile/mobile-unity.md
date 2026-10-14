---
id: mobile-unity
title: 'Реверс Unity: Mono и IL2CPP'
category: mobile
parent: mobile-game-reversing
difficulty: hard
order: 1
tags: [unity, il2cpp, mono, il2cppdumper, assembly-csharp, game]
prerequisites: [mobile-crossplatform]
useful_for:
  - 'Реверс мобильных игр'
  - 'Пентест мобильных приложений'
  - 'CTF Game Hacking'
estimated_minutes: 50
summary: 'Как определить бэкенд Unity-игры, разобрать управляемый код (Mono) или восстановить структуру IL2CPP по libil2cpp.so и global-metadata.dat, найти секреты и хукнуть логику.'
lab:
  kind: shell
  title: 'Практика: дамп IL2CPP'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, il2cpp_strings.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`il2cpp_strings.txt` — строки из `libil2cpp.so` и метаданных.'
    - 'Ищи URL, ключи и названия методов.'
    - 'Одна строка содержит флаг `nto{...}` — запиши её в `found.txt`.'
---

## Вопрос, с которого всё начинается

Открываешь APK мобильной игры в jadx — там почти нет логики: только тонкая обёртка вокруг
нативной библиотеки. Где же сам геймплей, магазин, проверки покупок? Он внутри движка **Unity**,
и способ достать его зависит от того, на каком бэкенде собрана игра. Разберём оба.

## Наш пример: игра «PixelQuest»

В APK находим папку `lib/arm64-v8a/` и видим два разных мира:

```bash
$ unzip -l pixelquest.apk | grep -E 'libmono|libil2cpp|Managed|metadata'
  1234567  lib/arm64-v8a/libil2cpp.so
    54321  lib/arm64-v8a/libmono.so
  9876543  assets/bin/Data/Managed/Metadata/global-metadata.dat
```

Наличие `libil2cpp.so` вместе с `global-metadata.dat` означает бэкенд **IL2CPP**: C#-код
скомпилирован в C++ и затем в машинный код, а метаданные (имена классов, методов, полей)
вынесены в отдельный файл. Если бы был `libmono.so` и `assets/bin/Data/Managed/*.dll` — это
бэкенд **Mono**, где код лежит в управляемых сборках.

## Шаг 1: отличаем Mono от IL2CPP

Правило простое:

- `libmono.so` + `Assembly-CSharp.dll` в `Managed/` → **Mono** (код читается почти как исходник).
- `libil2cpp.so` + `global-metadata.dat` → **IL2CPP** (нужен дампер).

Проверить `Assembly-CSharp.dll` можно так:

```bash
$ unzip -l pixelquest.apk | grep Assembly-CSharp
  2097152  assets/bin/Data/Managed/Assembly-CSharp.dll
```

## Шаг 2: путь Mono — dnSpy/ILSpy

Для Mono достаточно декомпилировать DLL:

```bash
$ ilspycmd Assembly-CSharp.dll -o ./src
$ grep -rn "isPremium\|UnlockAll\|CheckPurchase" ./src | head
```

Управляемый код почти читаем: видно классы магазина, проверки покупок, а иногда и вшитые
секреты. Правка возможна обратной компиляцией DLL и пересборкой APK.

## Шаг 3: путь IL2CPP — Il2CppDumper

Для IL2CPP имена и структуры восстанавливают дампером:

```bash
$ Il2CppDumper libil2cpp.so global-metadata.dat out/
Initializing metadata...
Detected metadata version 29
Dumping... 48213 methods
Output: out/dump.cs, out/script.json, out/il2cpp.h
```

`dump.cs` содержит имена классов и методов с адресами; `script.json` подключают к IDA/Ghidra,
чтобы нативные функции получили читаемые имена. После этого ищем игровую логику:

```bash
$ grep -n "IsPremium\|UnlockAll\|VerifyPurchase" out/dump.cs | head
```

## Шаг 4: ассеты и строки

Помимо кода интересны ресурсы: `strings` по `libil2cpp.so` и `global-metadata.dat` часто
выдаёт URL, ключи, названия флагов. Ассеты (текстуры, тексты) лежат в `assets/bin/Data/` и
распаковываются AssetRipper/AssetStudio.

```bash
$ strings -n 6 global-metadata.dat | grep -iE 'http|secret|flag|token' | head
```

## Шаг 5: хукинг через Frida

Динамически можно перехватывать методы движка. Для IL2CPP удобны экспорты `il2cpp_*`:
находят класс по имени, метод по имени, затем ставят хук. Для Mono проще цепляться к
управляемым методам через уже готовые скрипты. Смысл один: увидеть аргументы проверки
(например, `VerifyPurchase`) в момент вызова.

## Таблица: что где лежит

| Бэкенд | Код | Метаданные | Инструмент |
|---|---|---|---|
| Mono | Assembly-CSharp.dll | в DLL | dnSpy / ILSpy |
| IL2CPP | libil2cpp.so | global-metadata.dat | Il2CppDumper |
| Ассеты | assets/bin/Data | — | AssetRipper |

## Крайние случаи и подводные камни

- Версия метаданных должна поддерживаться дампером; для новых Unity нужна свежая версия
  Il2CppDumper, иначе имена не восстановятся.
- Обфускация (Beebyte, Obfuscar) заменяет имена на `a`, `b`, `c` — придётся идти по строкам и
  поведению, а не по именам.
- Часть игр шифрует `global-metadata.dat` — тогда его сначала расшифровывают в памяти.
- Проверки покупок часто дублируются на сервере: патч клиента может не дать результата.

## Что дальше / решение

Итог: сначала определите бэкенд, затем выберите инструмент — ILSpy для Mono, Il2CppDumper для
IL2CPP. Секреты ищите не только в коде, но и в строках метаданных и ассетах. В следующем уроке
разберём Unreal — полностью нативный движок с контейнерами `.pak`.


## Квиз

Проверь себя.

```quiz
- question: Как отличить IL2CPP-сборку Unity?
  options:
    - По наличию libmono.so
    - По libil2cpp.so и global-metadata.dat
    - По файлу .pak
    - По размеру APK
  answer: 1
  explanation: IL2CPP компилирует C# в нативный код и выносит метаданные отдельно.
- question: Что делает Il2CppDumper?
  options:
    - Расшифровывает .pak
    - Восстанавливает имена классов/методов из libil2cpp.so и метаданных
    - Удаляет обфускацию
    - Собирает APK
  answer: 1
  explanation: Дампер сопоставляет нативный код с метаданными и даёт dump.cs/script.json.
- question: Где в Unity-игре лежат ассеты (текстуры, тексты)?
  options:
    - assets/bin/Data
    - lib/
    - res/raw
    - META-INF
  answer: 0
  explanation: Игровые ассеты находятся в assets/bin/Data и распаковываются AssetRipper.
- question: Почему патч клиента может не дать бесплатных покупок?
  options:
    - Клиент неважен
    - Проверка дублируется на сервере
    - Покупки хранятся в libmono
    - Игра не использует сеть
  answer: 1
  explanation: Серверная проверка чека делает клиентский патч бесполезным.
```

## Где пригодится

- **Реверс мобильных игр:** основной рабочий инструмент для Unity.
- **Пентест мобильных приложений:** разбор покупок и защитных проверок.
- **Game Hacking:** поиск клиентской логики и секретов.
- **CTF:** Unity-задачи на метаданные и ассеты.
