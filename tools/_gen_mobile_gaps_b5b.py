#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MOB-GAP-5b: XPC lesson (compact body; deepened later)."""
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


m = dict(
    id='mobile-ios-xpc',
    title='XPC-сервисы iOS: поверхность атаки',
    category='mobile', parent='mobile-ios-ipc', difficulty='expert', order=2,
    tags=['ios', 'xpc', 'launchd', 'mach-service', 'sandbox', 'privileged-helper'],
    prerequisites=['mobile-ios-mach-ports'],
    estimated_minutes=46,
    summary='XPC — высокоуровневая обёртка над Mach: сервисы, соединения, проверка клиента и типичные уязвимости привилегированных helper-процессов.',
    useful_for=['Пентест мобильных приложений (iOS)', 'Исследование iOS-платформы', 'Анализ расширений и демонов'],
)
body = '''## Вопрос, с которого всё начинается

Приложение хранит сообщения в шифрованном виде, но системный сервис умеет их синхронизировать.
Как приложение просит сервис о работе, не имея доступа к его памяти? Через **XPC** — механизм,
который прячет Mach-порты за удобным API и потому чаще встречается в реальных атаках.

## Наш пример: XPC-сервис

В бандле находим описание XPC-сервиса:

```xml
<key>XPCService</key>
<dict>
  <key>ServiceType</key><string>Application</string>
  <key>ServiceName</key><string>com.example.app.helper</string>
</dict>
```

Приложение общается с `com.example.app.helper` через `NSXPCConnection`. Сервис — отдельный
процесс со своими правами. Если он привилегированнее приложения, ошибки в нём дают повышение
привилегий.

## Шаг 1: XPC поверх Mach

XPC — слой над Mach IPC. Вместо ручной работы с портами вы открываете соединение по имени и
вызываете методы удалённого объекта. Внутри — тот же Mach: bootstrap находит порт сервиса,
сообщения ходят через порты. Но API удобнее, поэтому XPC-сервисы повсеместны — от системных
демонов до расширений.

## Шаг 2: типы XPC

| Тип | Где живёт | Кто может подключиться |
|---|---|---|
| Application XPC | внутри бандла | само приложение |
| Mach service | системный, через launchd | по правилам sandbox/entitlement |
| System XPC | системные демоны | ограниченно |
| Launch agent/daemon | отдельный процесс | по конфигу |

Наибольший интерес — **Mach services** и привилегированные helper-процессы: к ним можно
подключиться из другого процесса, если права позволяют.

## Шаг 3: проверка клиента

Ключевой вопрос: **проверяет ли сервер, кто подключился**. У клиента есть audit token, из
которого видна его подпись и entitlements:

```text
listener.shouldAcceptNewConnection = { conn in
    let token = conn.auditToken
    return validateSignature(token) && validateEntitlement(token)
}
```

Если проверки нет — любой процесс, дотянувшийся до порта, отдаёт команды. Это самая частая
уязвимость XPC.

## Шаг 4: поверхность атаки

- **Нет проверки клиента** — сервис доверяет любому подключившемуся.
- **Слабая проверка** — проверяется bundle id, который подделывается.
- **Опасные операции** — сервис выполняет привилегированные действия без валидации.
- **Type confusion** — сервер принимает объект не того класса при десериализации.

## Шаг 5: как искать XPC-сервисы

```bash
$ plutil -p /System/Library/LaunchDaemons/com.apple.example.plist | grep -i mach
  "MachServices" => { "com.apple.example.service" => 1 }
```

`MachServices` в plist показывает имя сервиса. Дальше проверяем, какие entitlements нужны для
подключения и проверяет ли сервис клиента.

## Шаг 6: пример атаки

Приложение находит привилегированный helper, подключается к его XPC-сервису и вызывает метод,
доступный только «своему» клиенту. Если сервис не проверил подпись, он выполнит привилегированную
операцию — и приложение получает то, чего не должно было.

## Шаг 7: защита

- Проверять audit token клиента на **каждом** соединении.
- Сверять подпись, а не только bundle id.
- Требовать конкретные entitlements у клиента.
- Валидировать все аргументы.
- Минимизировать привилегии сервиса.

## Что мы теперь знаем

- XPC — обёртка над Mach IPC.
- Сервисы: Application/Mach/System.
- Главная проверка — валидация клиента по audit token.
- Ошибки: нет проверки, слабая проверка, type confusion.
- MachServices в plist — карта поверхности атаки.

## Квиз

Проверь себя.

''' + quiz([
    ('Что такое XPC?',
     ['Облачный сервис', 'Обёртка над Mach IPC для взаимодействия процессов', 'Антивирус', 'Браузер'], 1,
     'XPC прячет работу с Mach-портами за API.'),
    ('Что должен проверять XPC-сервер при подключении?',
     ['Цвет иконки', 'Audit token клиента (подпись/entitlements)', 'Батарею', 'Язык'], 1,
     'Без проверки клиента подключится кто угодно.'),
    ('Где в plist указано имя Mach-сервиса?',
     ['CFBundleName', 'MachServices', 'UIBackgroundModes', 'LSApplicationQueries'], 1,
     'Ключ MachServices перечисляет имена сервисов.'),
    ('Чем опасен привилегированный helper без проверки клиента?',
     ['Он медленный', 'Любой подключившийся получит привилегированные действия', 'Он ест батарею', 'Он большой'], 1,
     'Это прямой путь к повышению привилегий.'),
])
write_lesson(m, body + '''
## Куда дальше

Мы разобрали IPC. Дальше — рантайм ObjC и загрузка кода: как язык создаёт свои уязвимости и
как в процесс попадают библиотеки.

## Где пригодится

- Аудит привилегированных helper-процессов iOS.
- Поиск повышения привилегий через XPC.
- Анализ системных демонов и расширений.
''', lab=lab(
    'Практика: аудит XPC-сервиса',
    ['task.md', 'xpc_listener.txt'],
    ['`xpc_listener.txt` — псевдокод обработчика соединений.',
     'Найди проверку, которая пропущена.',
     'Рядом с пропущенной проверкой — флаг `nto{...}`.'],
    'nto{xpc_n0_cl13nt_ch3ck}',
    [_dir(WD),
     _f(WD + '/task.md', '# Задача: аудит XPC\n\nНайди пропущенную проверку клиента.\n'),
     _f(WD + '/xpc_listener.txt',
        'listener.shouldAcceptNewConnection = { conn in\n'
        '    // validateSignature(conn.auditToken)  <-- MISSING  flag: nto{xpc_n0_cl13nt_ch3ck}\n'
        '    return true\n'
        '}\n')],
))
print('done b5b')
