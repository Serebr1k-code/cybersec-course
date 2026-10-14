#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch MOB-GAP-5: cross-platform game reversing (1 hub + Unity/Unreal/Godot)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson, _dir, _f  # noqa: E402

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"


def lab(title, files, hints, flag, fs, toolset=None):
    return {
        'title': title, 'toolset': toolset or ['core', 'grep'],
        'workdir': WD, 'files': files, 'check': CHECK, 'hints': hints,
        'expect': {'file': WD + '/found.txt', 'contains': flag},
        'fs': fs, 'tools': None,
    }


def quiz(qs):
    out = ['```quiz']
    for q, opts, a, exp in qs:
        out.append('- question: ' + q)
        out.append('  options:')
        for o in opts:
            out.append('    - ' + o)
        out.append('  answer: ' + str(a))
        if exp:
            out.append('  explanation: ' + exp)
    out.append('```')
    return '\n'.join(out)


# ===========================================================================
# HUB: mobile-game-reversing
# ===========================================================================
m = dict(
    id='mobile-game-reversing', title='Модуль: реверс мобильных игр и движков',
    category='mobile', parent='mobile-crossplatform', difficulty='hard', order=1,
    tags=['unity', 'unreal', 'godot', 'il2cpp', 'game', 'roadmap'],
    prerequisites=['mobile-crossplatform'],
    estimated_minutes=22,
    summary='Навигационный модуль: как устроены мобильные игры на популярных движках, где лежит игровая логика и как её достать — Unity (Mono/IL2CPP), Unreal (.pak/.uasset) и Godot (.pck).',
    useful_for=['Реверс мобильных игр', 'Пентест мобильных приложений', 'CTF Mobile/Game Hacking'],
)
body = '''Обычное приложение на Kotlin/Swift мы уже разбирали. Но значительная часть мобильных
приложений — игры и «супер-приложения» — собрана на игровых движках, и их логика лежит **не** в
DEX, а в отдельном формате. Этот модуль показывает, где именно искать код в трёх самых
распространённых движках.

## Что покрывает модуль

1. **Unity** — два бэкенда: Mono (`Assembly-CSharp.dll`) и IL2CPP (`libil2cpp.so` +
   `global-metadata.dat`).
2. **Unreal Engine** — нативные `libUE4.so`/`libUnreal.so` и контейнеры ассетов `.pak`,
   `.uasset`, IoStore (`.utoc`/`.ucas`).
3. **Godot** — контейнер `.pck` с ресурсами и (опционально) скомпилированным GDScript.

## Почему такой порядок

Сначала Unity — самый частый случай, и у него два принципиально разных пути (управляемый
Mono и нативный IL2CPP), поэтому он задаёт обе базовые техники. Потом Unreal — полностью
нативный движок с собственными контейнерами ассетов. Затем Godot — маленький движок с одним
файлом ресурсов, отличная тренировка на «найти ключ и распаковать».

## Как проходить ступень

Начните с `mobile-unity`. В каждом уроке есть лаборатория: разберите строки/метаданные
движка до флага и ответьте на квиз. Не пропускайте лаборатории — именно на них закрепляется
навык распознавания формата.

## Связь с другими ветками

Это продолжение `mobile-crossplatform` (Flutter/React Native) и `mobile-native-reversing`.
Общие приёмы хукинга — в `mobile-dynamic-frida`; работа с нативным кодом — в `mobile-native-so-deep`.
'''

write_lesson(m, body + '''

## Квиз

Проверь себя.

''' + quiz([
    ('Какой файл содержит управляемый код в Mono-сборке Unity?',
     ['libil2cpp.so', 'Assembly-CSharp.dll', 'global-metadata.dat', 'libmono.so'], 1,
     'Mono хранит C# в управляемых сборках, главная — Assembly-CSharp.dll.'),
    ('Что нужно Il2CppDumper для разбора IL2CPP-игры?',
     ['Только APK', 'libil2cpp.so и global-metadata.dat', 'Только .pak', 'Онлайн-сервис'], 1,
     'Дампер сопоставляет нативный код и метаданные, поэтому нужны оба файла.'),
    ('В каком контейнере Unreal лежат игровые ассеты?',
     ['.pck', '.pak', '.dex', '.so'], 1,
     'Ассеты Unreal упакованы в .pak (или IoStore .utoc/.ucas).'),
    ('Что даёт разбор .pck в Godot?',
     ['Список IP-адресов', 'Ресурсы и, возможно, скрипты игры', 'Пароль Wi-Fi', 'Ничего'], 1,
     '.pck — это контейнер ресурсов движка Godot.'),
]))


# ===========================================================================
# mobile-unity
# ===========================================================================
m = dict(
    id='mobile-unity', title='Реверс Unity: Mono и IL2CPP',
    category='mobile', parent='mobile-game-reversing', difficulty='hard', order=1,
    tags=['unity', 'il2cpp', 'mono', 'il2cppdumper', 'assembly-csharp', 'game'],
    prerequisites=['mobile-crossplatform'],
    estimated_minutes=50,
    summary='Как определить бэкенд Unity-игры, разобрать управляемый код (Mono) или восстановить структуру IL2CPP по libil2cpp.so и global-metadata.dat, найти секреты и хукнуть логику.',
    useful_for=['Реверс мобильных игр', 'Пентест мобильных приложений', 'CTF Game Hacking'],
)
body = '''## Вопрос, с которого всё начинается

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
$ grep -rn "isPremium\\|UnlockAll\\|CheckPurchase" ./src | head
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
$ grep -n "IsPremium\\|UnlockAll\\|VerifyPurchase" out/dump.cs | head
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

''' + quiz([
    ('Как отличить IL2CPP-сборку Unity?',
     ['По наличию libmono.so', 'По libil2cpp.so и global-metadata.dat',
      'По файлу .pak', 'По размеру APK'], 1,
     'IL2CPP компилирует C# в нативный код и выносит метаданные отдельно.'),
    ('Что делает Il2CppDumper?',
     ['Расшифровывает .pak', 'Восстанавливает имена классов/методов из libil2cpp.so и метаданных',
      'Удаляет обфускацию', 'Собирает APK'], 1,
     'Дампер сопоставляет нативный код с метаданными и даёт dump.cs/script.json.'),
    ('Где в Unity-игре лежат ассеты (текстуры, тексты)?',
     ['assets/bin/Data', 'lib/', 'res/raw', 'META-INF'], 0,
     'Игровые ассеты находятся в assets/bin/Data и распаковываются AssetRipper.'),
    ('Почему патч клиента может не дать бесплатных покупок?',
     ['Клиент неважен', 'Проверка дублируется на сервере',
      'Покупки хранятся в libmono', 'Игра не использует сеть'], 1,
     'Серверная проверка чека делает клиентский патч бесполезным.'),
]), lab=lab(
    'Практика: дамп IL2CPP',
    ['task.md', 'il2cpp_strings.txt'],
    ['`il2cpp_strings.txt` — строки из `libil2cpp.so` и метаданных.',
     'Ищи URL, ключи и названия методов.',
     'Одна строка содержит флаг `nto{...}` — запиши её в `found.txt`.'],
    'nto{1l2cpp_m3t4d4t4_str1ngs}',
    [
        _dir(WD),
        _f(WD + '/task.md', '# Задача: реверс Unity IL2CPP\n\nНайди секрет в строках метаданных.\n'),
        _f(WD + '/il2cpp_strings.txt',
           'UnityEngine.Application\n'
           'https://api.pixelquest.example/v1/purchase\n'
           'VerifyPurchase\n'
           'IsPremium\n'
           'secret_key=nto{1l2cpp_m3t4d4t4_str1ngs}\n'),
    ],
))


# ===========================================================================
# mobile-unreal
# ===========================================================================
m = dict(
    id='mobile-unreal', title='Реверс Unreal Engine на мобильных',
    category='mobile', parent='mobile-game-reversing', difficulty='hard', order=2,
    tags=['unreal', 'ue4', 'ue5', 'pak', 'uasset', 'iostore', 'fmodel'],
    prerequisites=['mobile-unity'],
    estimated_minutes=48,
    summary='Как устроена мобильная игра на Unreal: нативная libUE4/libUnreal, контейнеры .pak и IoStore (.utoc/.ucas), извлечение ассетов через FModel и поиск логики в нативном коде.',
    useful_for=['Реверс мобильных игр', 'Пентест мобильных приложений', 'CTF Game Hacking'],
)
body = '''## Вопрос, с которого всё начинается

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

''' + quiz([
    ('Что содержит .pak в игре на Unreal?',
     ['Нативный код', 'Игровые ассеты', 'Метаданные C#', 'Сертификаты'], 1,
     '.pak — контейнер ассетов (текстуры, звуки, данные).'),
    ('Где может лежать ключ шифрования .pak?',
     ['В AndroidManifest', 'Внутри libUE4.so', 'В resources.arsc', 'В META-INF'], 1,
     'Ключ AES обычно вшит в бинарник движка.'),
    ('Чем IoStore отличается от .pak?',
     ['Ничем', 'Это формат UE5 с .utoc/.ucas', 'Это формат Godot', 'Это формат Unity'], 1,
     'IoStore хранит данные в .ucas и индекс в .utoc.'),
    ('Где искать игровую логику в Unreal-игре?',
     ['В Assembly-CSharp.dll', 'В нативном libUE4.so',
      'В global-metadata.dat', 'В .pck'], 1,
     'Логика Unreal — нативный C++ в движке.'),
]), lab=lab(
    'Практика: распаковка Unreal .pak',
    ['task.md', 'pak_listing.txt'],
    ['`pak_listing.txt` — листинг содержимого `.pak`.',
     'Ищи ассеты с секретами (DataTable/StringTable).',
     'В одном ассете лежит флаг `nto{...}` — запиши в `found.txt`.'],
    'nto{unr34l_p4k_4ss3t_dump}',
    [
        _dir(WD),
        _f(WD + '/task.md', '# Задача: Unreal .pak\n\nНайди ассет с секретом.\n'),
        _f(WD + '/pak_listing.txt',
           'pakchunk0-Android_ASTC.pak\n'
           '  SkyForge/Content/UI/MainMenu.uasset\n'
           '  SkyForge/Content/Data/StoreSecrets.uasset   # nto{unr34l_p4k_4ss3t_dump}\n'
           '  SkyForge/Content/Data/StoreSecrets.uexp\n'),
    ],
))


# ===========================================================================
# mobile-godot
# ===========================================================================
m = dict(
    id='mobile-godot', title='Реверс Godot: .pck и GDScript',
    category='mobile', parent='mobile-game-reversing', difficulty='medium', order=3,
    tags=['godot', 'pck', 'gdscript', 'gdsdecomp', 'gdre', 'game'],
    prerequisites=['mobile-unity'],
    estimated_minutes=40,
    summary='Как устроена мобильная игра на Godot: единственный контейнер .pck, скомпилированный GDScript (.gdc), извлечение ресурсов через gdsdecomp/godotpcktool и восстановление скриптов.',
    useful_for=['Реверс мобильных игр', 'Пентест мобильных приложений', 'CTF Game Hacking'],
)
body = '''## Вопрос, с которого всё начинается

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
$ grep -rn "unlock\\|premium\\|secret\\|flag" out/*.gd | head
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

''' + quiz([
    ('Какая сигнатура у контейнера Godot .pck?',
     ['GDPC', 'PK', 'RAR', 'FPakInfo'], 0,
     'Пакет Godot начинается с магического числа GDPC.'),
    ('Что такое .gdc?',
     ['Текстура', 'Скомпилированный GDScript-байткод', 'Нативная библиотека', 'Манифест'], 1,
     '.gdc — байткод GDScript, восстанавливается gdsdecomp.'),
    ('Где искать ключ зашифрованного .pck?',
     ['В AndroidManifest', 'В libgodot_android.so', 'В .tscn', 'В META-INF'], 1,
     'Ключ вшит в движок и извлекается из него.'),
    ('Чем разбирать C#-сборку на Godot Mono?',
     ['Il2CppDumper', 'ILSpy/dnSpy', 'FModel', 'repak'], 1,
     'Godot Mono использует управляемые сборки .NET.'),
]), lab=lab(
    'Практика: разбор Godot .pck',
    ['task.md', 'pck_manifest.txt'],
    ['`pck_manifest.txt` — листинг распакованного `.pck`.',
     'Ищи скрипты (.gd/.gdc) с игровой логикой.',
     'В одном скрипте лежит флаг `nto{...}` — запиши в `found.txt`.'],
    'nto{g0d0t_pck_gdscr1pt_dump}',
    [
        _dir(WD),
        _f(WD + '/task.md', '# Задача: Godot .pck\n\nНайди скрипт с секретом.\n'),
        _f(WD + '/pck_manifest.txt',
           'GDPC v2 (unencrypted)\n'
           '  res://scenes/Main.tscn\n'
           '  res://scripts/GameState.gdc\n'
           '  res://scripts/Secrets.gd   # premium_key = nto{g0d0t_pck_gdscr1pt_dump}\n'),
    ],
))

print('done b5')
