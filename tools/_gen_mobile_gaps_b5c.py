#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MOB-GAP-5c: Objective-C runtime + dyld lessons (compact; deepened later)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson, _dir, _f  # noqa: E402

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"


def lab(title, files, hints, flag, fs):
    return {'title': title, 'toolset': ['core', 'grep'], 'workdir': WD,
            'files': files, 'check': CHECK, 'hints': hints,
            'expect': {'file': WD + '/found.txt', 'contains': flag}, 'fs': fs}


def quiz(qs):
    out = ['```quiz']
    for q, opts, a, exp in qs:
        out.append('- question: ' + q)
        out.append('  options:')
        for o in opts:
            out.append('    - ' + o)
        out.append('  answer: ' + str(a))
        out.append('  explanation: ' + exp)
    out.append('```')
    return '\n'.join(out)


# LESSON: objc-runtime
m = dict(
    id='mobile-ios-objc-runtime',
    title='Objective-C runtime deep: классы, метаклассы и swizzling',
    category='mobile', parent='mobile-ios-ipc', difficulty='hard', order=3,
    tags=['ios', 'objc', 'runtime', 'swizzling', 'method-dispatch', 'class-dump'],
    prerequisites=['mobile-ios-basics'],
    estimated_minutes=44,
    summary='Как устроен Objective-C runtime: объекты и isa, классы и метаклассы, диспетчеризация методов (objc_msgSend), method swizzling и что это значит для реверса.',
    useful_for=['Реверс iOS', 'Пентест мобильных приложений (iOS)', 'Анализ iOS-приложений'],
)
body = '''## Вопрос, с которого всё начинается

В iOS-приложении можно «подменить» метод класса, не меняя исходный код — этим пользуются и
легитимные фреймворки, и атакующие. Как это возможно? Потому что Objective-C — динамический
язык: вызов метода — это поиск функции **во время выполнения**. Разберём рантайм и почему
динамика создаёт уязвимости.

## Наш пример: объект и его класс

В отладчике (на джейлбрейке) посмотрим класс объекта:

```text
(lldb) po [0x10a200000 class]
ExampleViewController
```

Каждый объект ObjC начинается с указателя `isa` — на его класс. Класс описывает методы и
переменные. Тип объекта — не то, что «зашито» в код, а то, на что указывает `isa`.

## Шаг 1: объекты, классы и метаклассы

- **Объект** — структура, первое поле которой `isa` (указатель на класс).
- **Класс** — тоже объект; его `isa` указывает на **метакласс**.
- **Метакласс** хранит методы класса (вызываемые через `[ClassName method]`).

Эти три уровня позволяют языку быть полностью динамическим: даже методы класса ищутся в
таблицах во время выполнения.

## Шаг 2: диспетчеризация методов

Вызов `[obj doThing]` компилируется в `objc_msgSend(obj, @selector(doThing))`. Рантайм:

1. берёт класс объекта по `isa`;
2. ищет селектор в таблице методов класса;
3. если не нашёл — идёт по цепочке наследования до корня;
4. если и там нет — динамическое разрешение (`resolveInstanceMethod:`) и `forwardInvocation:`.

Именно шаг 4 делает язык расширяемым: метод можно добавить «на лету».

## Шаг 3: swizzling

**Method swizzling** — замена реализации одного метода реализацией другого через
`method_exchangeImplementations`. Легитимно это применяют для логирования или патчей; атакующие
— чтобы перехватить проверку (например, jailbreak-детект или pinning) и вернуть «всё хорошо».

```text
Method orig = class_getInstanceMethod(cls, @selector(isJailbroken));
Method fake = class_getInstanceMethod(cls, @selector(alwaysFalse));
method_exchangeImplementations(orig, fake);
```

После этого `isJailbroken` всегда возвращает «нет». Защита, реализованная одним методом,
обходится одной строкой.

## Шаг 4: class-dump и реверс

Из-за динамической природы ObjC метаданные классов и методов остаются в бинарнике. Их можно
извлечь:

```bash
$ class-dump --arch arm64 ExampleBinary > headers.h
$ grep -i 'isJailbroken' headers.h
- (BOOL)isJailbroken;
```

Это даёт карту классов и методов до дизассемблирования — большое преимущество при реверсе
ObjC-приложений.

## Шаг 5: уязвимости, связанные с рантаймом

- **Swizzling-обход** — защита в одном методе подменяется.
- **Динамическое разрешение** — `resolveInstanceMethod:` может подгрузить неожиданный код.
- **Type confusion** — неверный каст объекта приводит к вызову чужого метода.
- **Инъекция через категории** — категории могут переопределять методы базового класса.

## Шаг 6: защита

- Не строить защиту на одном методе — комбинировать проверки.
- Проверять целостность рантайма (список методов, таблицы классов).
- Использовать Swift/статические вызовы там, где динамика не нужна.
- Детектировать swizzling (сравнение реализаций с ожидаемыми).

## Что мы теперь знаем

- Объект ObjC начинается с `isa`; класс тоже объект с `isa` на метакласс.
- Вызов метода — динамический поиск (`objc_msgSend`).
- Swizzling подменяет реализацию метода в рантайме.
- Метаданные классов извлекаются `class-dump`.
- Защита на одном методе обходится swizzling.

## Квиз

Проверь себя.

''' + quiz([
    ('Что такое `isa`?',
     ['Название класса', 'Указатель объекта на его класс', 'Пароль', 'Метод'], 1,
     '`isa` — первое поле объекта, указывает на класс.'),
    ('Во что компилируется `[obj doThing]`?',
     ['Прямой вызов', 'objc_msgSend(obj, @selector(doThing))', 'syscall', 'jump'], 1,
     'Вызов метода — динамический поиск в рантайме.'),
    ('Что делает method swizzling?',
     ['Шифрует код', 'Подменяет реализацию метода другой', 'Сжимает бинарник', 'Ставит root'], 1,
     'Swizzling меняет реализации методов местами.'),
    ('Почему защита на одном методе слаба?',
     ['Она медленная', 'Её обходят swizzling-подменой', 'Она дорогая', 'Её нет в Swift'], 1,
     'Один метод легко подменить в рантайме.'),
])
write_lesson(m, body + '''
## Куда дальше

Рантайм объясняет динамику языка. Дальше — dyld: как в процесс попадают библиотеки и почему
это важно для инъекций.

## Где пригодится

- Реверс iOS-приложений (class-dump, метаданные).
- Обход jailbreak-детекта и pinning через swizzling.
- Понимание динамических уязвимостей ObjC.
''', lab=lab(
    'Практика: поиск swizzling-обхода',
    ['task.md', 'runtime_log.txt'],
    ['`runtime_log.txt` — лог swizzling-операций.',
     'Найди метод защиты, который подменили.',
     'Рядом с подменённым методом — флаг `nto{...}`.'],
    'nto{sw1zzl3_jb_d3t3ct}',
    [_dir(WD),
     _f(WD + '/task.md', '# Задача: аудит swizzling\n\nНайди подменённый метод защиты.\n'),
     _f(WD + '/runtime_log.txt',
        'swizzle: -[Security isDebuggerAttached] -> -[Hook alwaysFalse]  OK\n'
        'swizzle: -[Security isJailbroken] -> -[Hook alwaysFalse]  '
        '# flag: nto{sw1zzl3_jb_d3t3ct}\n')],
))

# LESSON: dyld
m = dict(
    id='mobile-ios-dyld',
    title='dyld и загрузка библиотек: как код попадает в процесс',
    category='mobile', parent='mobile-ios-ipc', difficulty='hard', order=4,
    tags=['ios', 'dyld', 'macho', 'dylib', 'injection', 'shared-cache'],
    prerequisites=['mobile-ios-mach-ports'],
    estimated_minutes=42,
    summary='Как dyld загружает бинарник и библиотеки: Mach-O load commands, dyld shared cache, LC_LOAD_DYLIB и почему DYLD_INSERT_LIBRARIES — инструмент инъекции.',
    useful_for=['Реверс iOS', 'Пентест мобильных приложений (iOS)', 'Анализ iOS-приложений'],
)
body = '''## Вопрос, с которого всё начинается

Вы запускаете iOS-приложение, и прежде чем выполнится ваш код, система уже загрузила десятки
библиотек — UIKit, Foundation, libSystem. Кто это делает и как? За загрузку отвечает **dyld**
(dynamic linker). Понимание dyld объясняет и реверс, и инъекции, и то, почему на джейлбрейке
можно подсунуть процессу свою библиотеку.

## Наш пример: смотрим зависимости бинарника

```bash
$ otool -L Example.app/Example | head -5
Example.app/Example:
	/System/Library/Frameworks/UIKit.framework/UIKit
	/System/Library/Frameworks/Foundation.framework/Foundation
	/usr/lib/libSystem.B.dylib
```

`otool -L` показывает список динамических библиотек, которые нужны бинарнику. Именно их dyld
должен найти и загрузить до запуска `main`.

## Шаг 1: Mach-O и load commands

Бинарник iOS — формат **Mach-O**. В его заголовке есть **load commands** — инструкции для dyld:
где точка входа, какие сегменты, какие библиотеки грузить. Команда `LC_LOAD_DYLIB` перечисляет
зависимости:

```bash
$ otool -l Example.app/Example | grep -A2 LC_LOAD_DYLIB | head -6
          cmd LC_LOAD_DYLIB
      cmdsize 56
         name /usr/lib/libSystem.B.dylib
```

Каждая такая команда — просьба «загрузи эту библиотеку». dyld обрабатывает их по порядку.

## Шаг 2: dyld shared cache

Загружать каждую системную библиотеку с диска при каждом запуске — дорого. Поэтому Apple
объединила системные библиотеки в **dyld shared cache** — один большой файл, отображённый в
память. Приложения используют оттуда общий код.

```bash
$ ls /System/Library/Caches/com.apple.dyld/
dyld_shared_cache_arm64e
```

Для реверса это важно: системные библиотеки не лежат отдельными файлами, а находятся в кэше,
и их нужно извлекать специальными инструментами (dyld_shared_cache_util, jtool2).

## Шаг 3: порядок загрузки

При запуске dyld:

1. читает главный бинарник и его load commands;
2. рекурсивно загружает зависимости (`LC_LOAD_DYLIB`);
3. выполняет **fixups** — связывает адреса символов;
4. вызывает инициализаторы библиотек;
5. передаёт управление в `main`.

Именно на шаге 2 и 4 и происходит инъекция: если добавить в список свою библиотеку, dyld её
загрузит и выполнит её инициализатор **до** кода приложения.

## Шаг 4: инъекция dylib

Классический приём на джейлбрейке — заставить dyld загрузить вашу библиотеку:

```bash
$ DYLD_INSERT_LIBRARIES=/tmp/hook.dylib Example.app/Example
```

Переменная окружения `DYLD_INSERT_LIBRARIES` добавляет библиотеку в список загрузки. На
джейлбрейке также патчат сам бинарник (добавляют `LC_LOAD_DYLIB`) — тогда инъекция работает
без переменных окружения, что и делают твики.

## Шаг 5: защита и её обход

Apple ограничивает инъекцию: переменные `DYLD_*` игнорируются для подписанных приложений с
включённой защитой, а на чистом устройстве патч бинарника ломает подпись. Поэтому инъекция
требует джейлбрейка или переподписи. Понимание этого объясняет, почему многие атаки на iOS
начинаются с вопроса «есть ли джейлбрейк».

## Шаг 6: что проверять при аудите

- Какие библиотеки грузит приложение (`otool -L`, `LC_LOAD_DYLIB`).
- Есть ли `@rpath`-зависимости, которые можно подменить.
- Проверяет ли приложение целостность своих библиотек.
- Есть ли анти-инъекционные проверки (`dyld` image list).

## Что мы теперь знаем

- dyld — динамический загрузчик iOS.
- Mach-O load commands перечисляют зависимости (`LC_LOAD_DYLIB`).
- Системные библиотеки — в dyld shared cache.
- Инъекция dylib возможна через `DYLD_INSERT_LIBRARIES` или патч бинарника.
- На чистом устройстве инъекция ограничена подписью.

## Квиз

Проверь себя.

''' + quiz([
    ('Что такое dyld?',
     ['Редактор', 'Динамический загрузчик iOS', 'Компилятор', 'Отладчик'], 1,
     'dyld загружает бинарник и его библиотеки.'),
    ('Какая команда перечисляет зависимости Mach-O?',
     ['LC_LOAD_DYLIB', 'LC_MAIN', 'LC_UUID', 'LC_SEGMENT'], 0,
     'LC_LOAD_DYLIB просит dyld загрузить библиотеку.'),
    ('Что такое dyld shared cache?',
     ['Кэш браузера', 'Объединённые системные библиотеки в одном файле', 'Пароль', 'Лог'], 1,
     'Кэш ускоряет загрузку общих библиотек.'),
    ('Как называется переменная для инъекции dylib?',
     ['LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'PATH', 'JAVA_HOME'], 1,
     'DYLD_INSERT_LIBRARIES добавляет библиотеку в загрузку.'),
])
write_lesson(m, body + '''
## Куда дальше

Мы разобрали IPC и рантайм iOS. Дальше — практическая сторона мобильного пентеста: перехват
трафика, обход защит и отчётность.

## Где пригодится

- Реверс iOS-приложений и анализ зависимостей.
- Разработка и понимание твиков (инъекция dylib).
- Аудит анти-инъекционных защит.
''', lab=lab(
    'Практика: анализ зависимостей и инъекции',
    ['task.md', 'dyld_info.txt'],
    ['`dyld_info.txt` — список загружаемых библиотек.',
     'Найди библиотеку, загруженную не из системного пути.',
     'Рядом с подозрительной библиотекой — флаг `nto{...}`.'],
    'nto{dyld_1nj3ct3d_dyl1b}',
    [_dir(WD),
     _f(WD + '/task.md', '# Задача: аудит dyld\n\nНайди подозрительную библиотеку.\n'),
     _f(WD + '/dyld_info.txt',
        '/System/Library/Frameworks/UIKit.framework/UIKit\n'
        '/usr/lib/libSystem.B.dylib\n'
        '/tmp/hook.dylib  # injected  flag: nto{dyld_1nj3ct3d_dyl1b}\n')],
))
print('done b5c')
