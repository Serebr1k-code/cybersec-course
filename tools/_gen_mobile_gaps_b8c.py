#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MOB-GAP-8c: Android enterprise/MDM — hub mobile-android-mdm +
enterprise / work-profile / kiosk / zero-touch."""
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


# ============================================================ HUB
m = dict(
    id='mobile-android-mdm',
    title='Модуль: Android Enterprise и MDM',
    category='mobile', parent='mobile-platforms-android', difficulty='hard', order=5,
    tags=['android', 'enterprise', 'mdm', 'work-profile', 'kiosk', 'zero-touch', 'dpc', 'module'],
    prerequisites=['mobile-platforms-android'],
    estimated_minutes=16,
    summary='Навигационный модуль: как корпоративные Android-устройства управляются политиками (Android Enterprise, MDM, Device Policy Controller) и где искать границы и обходы.',
    useful_for=['Пентест корпоративных устройств', 'Анализ мобильных приложений', 'BYOD-безопасность'],
)
body = '''## Зачем пентестеру корпоративный Android

Телефон сотрудника — уже не личный гаджет, а управляемый корпоративный актив. Им управляет
**MDM** (Mobile Device Management) через политики: запрет камеры, обязательный пароль,
удалённое стирание, разделение личных и рабочих данных. Для пентестера это отдельная
поверхность: где заканчивается управление, что можно обойти, какие данные утекают через
границу «рабочее/личное».

Этот модуль — про Android Enterprise: как устроено корпоративное управление и где искать
слабые места.

## Что покрывает модуль

1. **Android Enterprise** — модель управления: Device Policy Controller, режимы работы,
   управляемые конфигурации.
2. **Work Profile** — отдельный «рабочий» профиль на личном устройстве (BYOD): как он
   изолирован и где границы протекают.
3. **Kiosk / Lock Task** — режим «одного приложения»: где он применяется и как из него
   выходят.
4. **Zero-touch** — массовая настройка устройств по QR/NFC без рук: как токены попадают в
   чужие руки.

## Почему такой порядок

Сначала общая модель (`mobile-android-enterprise`) — без неё остальное непонятно. Затем два
самых распространённых сценария: рабочий профиль (BYOD, самая частая конфигурация) и kiosk
(терминалы, склады). В конце — zero-touch: он объясняет, откуда на устройстве вообще
появились корпоративные политики.

## Чему вы научитесь

- Понимать роли Device Owner и Profile Owner и что каждая может.
- Анализировать изоляцию work profile и искать утечки между профилями.
- Проверять режим lock task и искать обход kiosk.
- Понимать zero-touch enrollment и риски утечки токенов.

## С чего начать

Опираемся на `mobile-platforms-android` (устройство Android) и `mobile-android-ipc-attacks`
(межпроцессное взаимодействие). Если база есть — идите по порядку, начиная с
`mobile-android-enterprise`.
'''
write_lesson(m, body)

# ============================================================ ENTERPRISE
m = dict(
    id='mobile-android-enterprise',
    title='Android Enterprise: Device Owner и Profile Owner',
    category='mobile', parent='mobile-android-mdm', difficulty='hard', order=1,
    tags=['android', 'enterprise', 'mdm', 'dpc', 'device-owner', 'profile-owner', 'managed-config'],
    prerequisites=['mobile-platforms-android'],
    estimated_minutes=46,
    summary='Как устроено корпоративное управление Android: Device Policy Controller, роли Device Owner и Profile Owner, управляемые конфигурации и их поверхность атаки.',
    useful_for=['Пентест корпоративных устройств', 'Анализ мобильных приложений', 'BYOD-безопасность'],
)
body = '''## Вопрос, с которого всё начинается

На телефоне сотрудника камера отключена «политикой», а пароль требует 8 символов — хотя
пользователь ничего такого не настраивал. Кто это сделал и какие у него права? Ответ —
корпоративный **Device Policy Controller**. Разберём, как устроено управление Android и где
у него границы.

## Наш пример: снимок политик

```bash
$ adb shell dumpsys device_policy | head -20
Current Device Policy Manager state:
  Device Owner:
    admin=ComponentInfo{com.acme.mdm/com.acme.mdm.AdminReceiver}
    name=Acme MDM
    UserControlDisabled=false
  Enabled Device Admins (User 0, uid 10123):
    com.acme.mdm/com.acme.mdm.AdminReceiver
```

Здесь видно, кто управляет устройством и какие политики активны. Весь урок ведём этот снимок.

## Шаг 1: что такое DPC и Device Admin

**DPC** (Device Policy Controller) — приложение-агент MDM, которое получает права
администратора устройства. Старый механизм — **Device Admin** (ограниченные права). Новый —
**Device Owner** и **Profile Owner**. Device Owner назначается при первичной настройке и
управляет **всем** устройством; Profile Owner управляет только **рабочим профилем**.

## Шаг 2: Device Owner vs Profile Owner

| Роль | Область | Пример прав |
|---|---|---|
| Device Owner | всё устройство | сброс, запрет камеры, обязательный пароль |
| Profile Owner | только work profile | удаление рабочих данных, политики в профиле |

Ключевое: Device Owner назначается только на «чистом» устройстве при provisioning, поэтому
получить его постфактум нельзя. Это важная граница — пентестер проверяет, не получил ли
Device Owner кто-то лишний (например, через zero-touch, см. `mobile-android-zero-touch`).

## Шаг 3: управляемые конфигурации

MDM передаёт приложению настройки через **managed configurations** — пары ключ-значение,
которые админ задаёт централизованно (сервер, адрес VPN, правила). Приложение читает их через
`RestrictionsManager`. Смотрим, что задано:

```bash
$ adb shell dumpsys restrictions | grep -A4 'com.example.app'
  com.example.app:
    server_url = https://vpn.acme.example
    allow_screenshots = false
```

Это и есть атакуемая поверхность: если в конфиге есть секреты (токены, адреса внутренних
сервисов), они читаемы на устройстве.

## Шаг 4: что может админ

Device Owner может: отключить камеру (`DISALLOW_CAMERA`), запретить установку приложений,
обязать шифрование, стереть устройство, скрыть настройки. Profile Owner — то же, но в
пределах профиля. Проверяем список активных ограничений:

```bash
$ adb shell dumpsys device_policy | grep -i 'UserRestrictions\|DISALLOW'
  mUserRestrictions: no_camera, no_debugging_features
```

## Шаг 5: поверхность атаки

Практические векторы: (а) утечка managed config с секретами; (б) обход политик приложением,
которое не проверяет `UserManager`; (в) получение Device Owner через zero-touch;
(г) злоупотребление правами DPC, если само MDM-приложение уязвимо (оно — самый
привилегированный агент на устройстве). Отдельно: `dpm`/`dumpsys` доступны через adb, но на
управляемом устройстве adb обычно выключен — это тоже часть модели доверия.

## Шаг 6: в отчёте

Для пентеста корпоративного устройства фиксируют: роль управления, назначенного админа,
активные ограничения, содержимое managed configs и то, какие из них содержат чувствительные
данные. Это даёт заказчику понятную картину «что корпоративная политика реально защищает».

## Что мы теперь знаем

- DPC — приложение-администратор, управляющее устройством.
- Device Owner управляет всем устройством, Profile Owner — только рабочим профилем.
- Managed configurations — канал настроек от MDM к приложению.
- Ограничения задаются через UserRestrictions.
- Поверхность атаки: утечка конфигов, обход политик, захват Device Owner, уязвимый DPC.

## Квиз

Проверь себя.

''' + quiz([
    ('Что такое DPC?',
     ['Библиотека графики', 'Device Policy Controller — агент управления', 'Протокол сети', 'Формат базы'], 1,
     'DPC — приложение-администратор от MDM.'),
    ('Чем Device Owner отличается от Profile Owner?',
     ['Ничем', 'Device Owner управляет всем устройством, Profile Owner — профилем', 'Profile Owner мощнее', 'Device Owner только для iOS'], 1,
     'Device Owner назначается при provisioning и управляет всем.'),
    ('Что такое managed configuration?',
     ['Пароль Wi-Fi', 'Пары ключ-значение настроек от MDM приложению', 'Список контактов', 'Лог сети'], 1,
     'Приложение читает их через RestrictionsManager.'),
    ('Почему managed config интересен пентестеру?',
     ['Он ускоряет приложение', 'В нём бывают секреты и адреса внутренних сервисов', 'Он шифрует диск', 'Он ставит root'], 1,
     'Конфиги читаемы на устройстве.'),
    ('Когда можно назначить Device Owner?',
     ['В любой момент', 'Только при первичной настройке устройства', 'Из Play Store', 'Через браузер'], 1,
     'Постфактум Device Owner не назначается.'),
])

write_lesson(m, body + '''
## Куда дальше

Мы разобрали модель управления. Дальше — самый частый сценарий BYOD: рабочий профиль и его
границы.

## Где пригодится

- Пентест корпоративных устройств: аудит политик MDM.
- BYOD-безопасность: оценка границы рабочее/личное.
- Анализ приложений: разбор managed configurations.
''', lab=lab(
    'Практика: найди секрет в managed config',
    ['task.md', 'device_policy.txt'],
    ['`device_policy.txt` — снимок dumpsys device_policy и restrictions.',
     'Определи роль управления (`grep` по Device Owner).',
     'В managed config есть секрет — запиши его в `found.txt`.'],
    'nto{4ndr01d_3nt3rpr1s3_p0l1cy_byp4ss}',
    [_dir(WD),
     _f(WD + '/task.md',
        '# Задача: аудит корпоративной политики\\n\\n'
        '## Повторение (mobile-platforms-android)\\n\\n'
        'Как в уроке про платформу Android, сначала осмотри артефакт: `ls -la` и `head device_policy.txt`.\\n\\n'
        'Определи Device Owner и найди секрет в managed configuration.\\n'
        'Запиши секрет в `found.txt` и набери `check`.\\n'),
     _f(WD + '/device_policy.txt',
        'Current Device Policy Manager state:\\n'
        '  Device Owner:\\n'
        '    admin=ComponentInfo{com.acme.mdm/com.acme.mdm.AdminReceiver}\\n'
        '    name=Acme MDM\\n'
        '  mUserRestrictions: no_camera, no_debugging_features\\n'
        '  com.example.app:\\n'
        '    server_url = https://vpn.acme.example\\n'
        '    bootstrap_token = nto{4ndr01d_3nt3rpr1s3_p0l1cy_byp4ss}\\n')],
))

# ============================================================ WORK PROFILE
m = dict(
    id='mobile-android-work-profile',
    title='Work Profile: изоляция рабочего профиля и её границы',
    category='mobile', parent='mobile-android-mdm', difficulty='hard', order=2,
    tags=['android', 'work-profile', 'byod', 'cross-profile', 'user-id', 'isolation', 'dpc'],
    prerequisites=['mobile-android-enterprise'],
    estimated_minutes=46,
    summary='Как устроен рабочий профиль Android (отдельный пользователь), как он изолирован, где протекает граница «рабочее/личное» и как это проверять.',
    useful_for=['Пентест корпоративных устройств', 'BYOD-безопасность', 'Анализ мобильных приложений'],
)
body = '''## Вопрос, с которого всё начинается

Сотрудник установил корпоративный почтовик — и на телефоне появился «рабочий» набор
приложений с отдельным значком. Рабочие данные должны быть изолированы от личных. Но так ли
это? И что мешает приложению из одного профиля прочитать данные другого?

## Наш пример: два профиля — два пользователя

```bash
$ adb shell pm list users
Users:
    UserInfo{0:Owner:13} running
    UserInfo{10:Work profile:30} running
```

Android реализует work profile как **отдельного пользователя** (здесь id 10). Значит, у
рабочих приложений своя песочница `/data/user/10/`. Весь урок ведём эти два «пользователя».

## Шаг 1: как устроен work profile

Android Enterprise создаёт управляемый профиль как отдельного пользователя с отдельным
набором данных. Рабочие приложения живут в `/data/user/10/`, личные — в `/data/user/0/`.
Разделение на уровне UID и файловой системы — это и есть изоляция. Profile Owner управляет
именно профилем 10.

## Шаг 2: как выглядит изоляция

```bash
$ adb shell ls /data/user/10/
com.acme.mail  com.acme.portal
$ adb shell ls /data/user/0/ | head
com.android.chrome  com.whatsapp  ...
```

Личные приложения не видят `/data/user/10` без root, и наоборот. Это базовая гарантия BYOD:
личные данные не смешиваются с рабочими.

## Шаг 3: где граница «протекает»

Изоляция не абсолютна — есть легальные каналы между профилями:

| Канал | Что переносится |
|---|---|
| Share intent | файлы/текст по выбору пользователя |
| Cross-profile intents | явные вызовы между профилями |
| Уведомления | тексты рабочих уведомлений на личном экране |
| Буфер обмена | при разрешении политикой |
| `crossProfileApps` | запуск приложения другого профиля |

Если приложение обрабатывает share-intent небрежно, оно может принять файл из другого
профиля и записать его в общий кэш — утечка. Проверяем, какие каналы включены:

```bash
$ adb shell dumpsys device_policy | grep -i 'CrossProfile\|clipboard'
  mCrossProfileCopyPasteEnabled: true
```

## Шаг 4: интенты через границу

Ключевой вектор — **cross-profile intent**. Приложение может запустить активность в другом
профиле или отправить туда данные, если система разрешит. Опасность: приложение из личного
профиля получает рабочий файл и сохраняет его туда, откуда он потом утечёт. Смотрим
`android:crossProfile` в манифесте и фильтры:

```bash
$ aapt dump xmltree app.apk AndroidManifest.xml | grep -i 'crossProfile\|permission'
```

## Шаг 5: буфер обмена и уведомления

Политика может разрешать копирование между профилями (`CROSS_PROFILE_COPY_PASTE`). Если
разрешено — текст из рабочего почтовика можно вставить в личное приложение. Аналогично
уведомления рабочего профиля показываются на личном экране и могут содержать чувствительные
данные. Это не баг, а осознанный компромисс, но пентестер обязан его отметить.

## Шаг 6: как проверять

Практический чек: (1) какие приложения в профиле 10; (2) какие каналы между профилями
включены; (3) есть ли приложения с `crossProfile`-фильтрами; (4) пробрасываются ли секреты
через share/clipboard. Всё это доступно через `pm list users`, `dumpsys device_policy` и
разбор манифестов — без root.

## Что мы теперь знаем

- Work profile — отдельный пользователь Android (обычно id 10).
- Данные изолированы на уровне UID и файловой системы.
- Между профилями есть легальные каналы (share, intents, clipboard, уведомления).
- Небрежная обработка share-intent ведёт к утечке.
- Каналы проверяются через dumpsys и разбор манифестов.

## Квиз

Проверь себя.

''' + quiz([
    ('Чем технически является work profile в Android?',
     ['Отдельным приложением', 'Отдельным пользователем ОС', 'Папкой на sdcard', 'VPN'], 1,
     'Это отдельный пользователь (например, id 10).'),
    ('Где лежат данные рабочего профиля?',
     ['/data/user/0/', '/data/user/10/', '/sdcard/', '/system/etc'], 1,
     'У каждого пользователя своя песочница.'),
    ('Что из перечисленного — легальный канал между профилями?',
     ['Прямое чтение /data', 'Share intent', 'Root', 'ptrace'], 1,
     'Share intent переносит данные по выбору пользователя.'),
    ('Чем опасна небрежная обработка share-intent?',
     ['Замедлением', 'Утечкой рабочего файла в общий кэш', 'Сбросом устройства', 'Потерей root'], 1,
     'Файл может попасть туда, откуда утечёт.'),
    ('Где смотреть разрешён ли copy-paste между профилями?',
     ['В манифесте', 'В dumpsys device_policy', 'В Keychain', 'В облаке'], 1,
     'Политика видна в dumpsys device_policy.'),
])

write_lesson(m, body + '''
## Куда дальше

Мы разобрали изоляцию профилей. Дальше — kiosk: устройство, запертое в одном приложении, и
как из этого режима выходят.

## Где пригодится

- Пентест корпоративных устройств: оценка BYOD-изоляции.
- BYOD-безопасность: аудит каналов между профилями.
- Анализ приложений: разбор cross-profile фильтров.
''', lab=lab(
    'Практика: найди утечку через границу профиля',
    ['task.md', 'profiles.txt'],
    ['`profiles.txt` — список пользователей и каналов между профилями.',
     'Определи id рабочего профиля и включённые каналы.',
     'Один файл помечен как утёкший — в нём секрет. Запиши его в `found.txt`.'],
    'nto{w0rk_pr0f1l3_d4t4_l34k}',
    [_dir(WD),
     _f(WD + '/task.md',
        '# Задача: граница work profile\\n\\n'
        '## Повторение (mobile-android-enterprise)\\n\\n'
        'Как в уроке про Android Enterprise, начни с `ls -la` и `head profiles.txt`.\\n\\n'
        'Определи id рабочего профиля и найди утёкший файл с секретом.\\n'
        'Запиши секрет в `found.txt` и набери `check`.\\n'),
     _f(WD + '/profiles.txt',
        'Users:\\n'
        '  UserInfo{0:Owner:13} running\\n'
        '  UserInfo{10:Work profile:30} running\\n'
        'mCrossProfileCopyPasteEnabled: true\\n'
        'leaked: /data/user/0/com.personal.notes/files/work_doc.txt '
        '=> nto{w0rk_pr0f1l3_d4t4_l34k}\\n')],
))

# ============================================================ KIOSK
m = dict(
    id='mobile-android-kiosk',
    title='Kiosk-режим (Lock Task): назначение и обход',
    category='mobile', parent='mobile-android-mdm', difficulty='hard', order=3,
    tags=['android', 'kiosk', 'lock-task', 'cosu', 'escape', 'mdm', 'dpc'],
    prerequisites=['mobile-android-work-profile'],
    estimated_minutes=44,
    summary='Как Android запирает устройство в одном приложении (Lock Task / kiosk), где этот режим применяется и какие техники позволяют из него выйти.',
    useful_for=['Пентест корпоративных устройств', 'Анализ мобильных приложений', 'Безопасность терминалов'],
)
body = '''## Вопрос, с которого всё начинается

Терминал на складе показывает только одно приложение: сканирование товара. Кнопок «домой» и
«назад» нет. Это **kiosk-режим**. Но действительно ли из него нельзя выйти? Проверим, как
устроена блокировка и где у неё слабые места.

## Наш пример: снимок lock task

```bash
$ adb shell dumpsys activity activities | grep -i 'lockTask\|LockTask'
  mLockTaskModeState=LOCKED
  mLockTaskPackages=[com.acme.scanner]
```

Видно, что устройство в режиме Lock Task и заперто на пакете `com.acme.scanner`. Весь урок
ведём этот снимок.

## Шаг 1: что такое Lock Task / kiosk

**Kiosk** (или **COSU** — Corporate Owned, Single Use) — устройство, запертое в одном
приложении. В Android это реализует **Lock Task mode**: система скрывает системный UI,
блокирует кнопки «домой»/«недавние» и запускает только разрешённые пакеты. Включает его DPC
(Device Owner) — сам пользователь так устройство не запрёт.

## Шаг 2: уровни блокировки

| Уровень | Кто может выйти |
|---|---|
| Screen pinning | пользователь (жест/кнопки) |
| Lock Task (не pinned) | только через DPC/настройки |
| Lock Task + Device Owner | только DPC/перезагрузка с политикой |

Разница принципиальна: обычный screen pinning — временная заморозка для пользователя, а
Lock Task под управлением Device Owner — настоящий киоск.

## Шаг 3: как проверять состояние

```bash
$ adb shell dumpsys activity activities | grep -i 'LockTask'
  mLockTaskModeState=LOCKED
  mLockTaskPackages=[com.acme.scanner]
$ adb shell dumpsys device_policy | grep -i 'LOCK_TASK\|kiosk'
```

`mLockTaskModeState=LOCKED` означает, что режим активен. Список пакетов показывает, что
разрешено запускать. Это база для аудита.

## Шаг 4: классические обходы

Обходы kiosk — это про то, как вырваться из запертого приложения к системным функциям:

| Вектор | Суть |
|---|---|
| Share/intent из приложения | открыть чужой компонент, если он разрешён |
| Уведомление | тап по уведомлению открывает другое приложение |
| URL/веб-ссылка | переход в браузер или системный диалог |
| Помощник/голос | запуск Google Assistant поверх киоска |
| Экстренный вызов | системный экран, из которого бывают выходы |
| Настройки через намерение | если пакет настроек не запрещён |

Ключевая причина успеха — приложение само предоставляет «дверь» (share, ссылку, deep link).
Поэтому пентест kiosk начинается с аудита **всех интентов и внешних ссылок** приложения.

## Шаг 5: проверка на практике

```bash
$ aapt dump badging com.acme.scanner.apk | grep -i 'intent\|scheme'
$ adb shell am start -a android.intent.action.VIEW -d 'https://example.com'
```

Если команда открывает браузер поверх киоска — блокировка дырявая. Также проверяют,
разрешён ли системный UI (`STATUS_BAR`, `HOME`, `OVERVIEW` restrictions).

## Шаг 6: правильный kiosk

Хороший киоск запрещает всё лишнее через Device Owner: `DISALLOW_CREATE_WINDOWS`,
`LOCK_TASK_FEATURE_*`, скрывает уведомления и запрещает системные интенты. Аудит показывает
именно разницу между «заперли иконку» и «заперли устройство».

## Что мы теперь знаем

- Kiosk = Lock Task mode, включается DPC (Device Owner).
- Состояние видно в `dumpsys` (`mLockTaskModeState`, список пакетов).
- Screen pinning и Lock Task — разные уровни.
- Обходы используют «двери» самого приложения (share, ссылки, уведомления).
- Правильный kiosk запрещает системные функции через restrictions.

## Квиз

Проверь себя.

''' + quiz([
    ('Что такое kiosk-режим в Android?',
     ['Режим энергосбережения', 'Lock Task — запуск только одного приложения', 'Гостевой режим', 'VPN'], 1,
     'Kiosk реализуется через Lock Task mode.'),
    ('Кто включает Lock Task?',
     ['Пользователь', 'DPC (Device Owner)', 'Play Store', 'Браузер'], 1,
     'Настоящий киоск включает управляющее приложение.'),
    ('Чем screen pinning отличается от Lock Task?',
     ['Ничем', 'Pinning временный и выходится пользователем', 'Pinning мощнее', 'Lock Task только на iOS'], 1,
     'Pinning — заморозка для пользователя, Lock Task — управляемый киоск.'),
    ('Что чаще всего позволяет выйти из киоска?',
     ['Отключение Wi-Fi', '«Дверь» в самом приложении (share/ссылка/уведомление)', 'Перезагрузка', 'Смена SIM'], 1,
     'Аудитируют все интенты и внешние ссылки.'),
    ('Что показывает mLockTaskModeState=LOCKED?',
     ['Сеть отключена', 'Режим киоска активен', 'Идёт загрузка', 'Пароль истёк'], 1,
     'Это состояние Lock Task.'),
])

write_lesson(m, body + '''
## Куда дальше

Мы разобрали, как устройство запирают. Дальше — zero-touch: как корпоративные политики
вообще попадают на устройство без рук, и почему это риск.

## Где пригодится

- Пентест корпоративных устройств и терминалов.
- Анализ приложений: аудит интентов и внешних ссылок.
- Безопасность COSU/kiosk-развёртываний.
''', lab=lab(
    'Практика: найди дыру в kiosk',
    ['task.md', 'locktask.txt'],
    ['`locktask.txt` — снимок состояния Lock Task и разрешённых компонентов.',
     'Определи, заперт ли режим и какие «двери» оставлены.',
     'В разрешённом компоненте есть секрет — запиши в `found.txt`.'],
    'nto{k10sk_m0d3_3sc4p3_c0nf1rm3d}',
    [_dir(WD),
     _f(WD + '/task.md',
        '# Задача: аудит kiosk-режима\\n\\n'
        '## Повторение (mobile-android-work-profile)\\n\\n'
        'Как в уроке про work profile, сначала `ls -la` и `head locktask.txt`.\\n\\n'
        'Определи состояние Lock Task и найди разрешённую «дверь» с секретом.\\n'
        'Запиши секрет в `found.txt` и набери `check`.\\n'),
     _f(WD + '/locktask.txt',
        'mLockTaskModeState=LOCKED\\n'
        'mLockTaskPackages=[com.acme.scanner]\\n'
        'allowed_intent: VIEW https://escape.example/x?t=nto{k10sk_m0d3_3sc4p3_c0nf1rm3d}\\n'
        'restrictions: HOME, OVERVIEW (missing) STATUS_BAR (missing)\\n')],
))

# ============================================================ ZERO-TOUCH
m = dict(
    id='mobile-android-zero-touch',
    title='Zero-touch enrollment: токены и риски автонастройки',
    category='mobile', parent='mobile-android-mdm', difficulty='medium', order=4,
    tags=['android', 'zero-touch', 'enrollment', 'provisioning', 'qr', 'nfc', 'token', 'mdm'],
    prerequisites=['mobile-android-kiosk'],
    estimated_minutes=42,
    summary='Как работает zero-touch enrollment Android: настройка устройств по QR/NFC без рук, роль enrollment-токена и типичные риски утечки и злоупотребления.',
    useful_for=['Пентест корпоративных устройств', 'BYOD-безопасность', 'Анализ мобильных приложений'],
)
body = '''## Вопрос, с которого всё начинается

Компания заказала 500 планшетов. Их не настраивают вручную — при включении они сами
скачивают корпоративные политики и приложения. Как это происходит и что помешает злоумышленнику
сделать то же самое со своим устройством?

## Наш пример: provisioning по QR

При первом включении устройство показывает мастер настройки. Если ввести `afw#setup` или
отсканировать QR, начинается **zero-touch**-настройка. Сам QR содержит полезную нагрузку:

```json
{
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": "com.acme.mdm/.AdminReceiver",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION": "https://mdm.acme.example/dpc.apk",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM": "abc123..."
}
```

Весь урок ведём эту нагрузку: она объясняет, как устройство становится управляемым.

## Шаг 1: что такое provisioning

**Provisioning** — первичная настройка устройства. Zero-touch — способ сделать её
автоматически: производитель или реселлер заранее привязывает устройство к аккаунту
организации, и при включении оно само получает политики. Это экономит время на больших
парках, но переносит доверие на канал настройки.

## Шаг 2: QR и NFC

Два способа передать нагрузку: **QR-код** (сканируется камерой) и **NFC** (тег). Оба
содержат одни и те же поля: какой DPC установить, откуда скачать APK, как проверить его
подпись. Устройство скачивает DPC, назначает его Device Owner и дальше управляется им.

## Шаг 3: enrollment-токен

Ключевой секрет — **enrollment-токен** (или привязка устройства к организации). Он
связывает конкретное устройство с аккаунтом MDM. Если токен утёк, злоумышленник может
привязать своё устройство к организации и получить корпоративные политики/приложения.

```bash
$ grep -r 'enrollment' /sdcard/Download/ 2>/dev/null
prov_token=nto{...}
```

## Шаг 4: риски

| Риск | Последствие |
|---|---|
| Утечка enrollment-токена | чужое устройство в корпоративном парке |
| QR с непроверенным DPC | установка поддельного админа |
| Нет проверки подписи DPC | подмена агента управления |
| NFC-тег в публичном месте | перенастройка устройства |

Поле `SIGNATURE_CHECKSUM` существует именно для того, чтобы устройство приняло только
подписанный DPC. Если его нет или проверка отключена — это находка.

## Шаг 5: проверка

Практический аудит: (1) есть ли в QR/NFC проверка подписи DPC; (2) где хранится
enrollment-токен и не утёк ли он (лог, файл, скриншот); (3) можно ли выполнить provisioning
на уже настроенном устройстве. Всё это — конфигурационные проверки, без эксплуатации.

## Шаг 6: в отчёте

Для заказчика важно: насколько канал zero-touch защищён. Хорошая практика — привязка только
через аккаунт организации, проверка подписи DPC, хранение токена в защищённом хранилище и
ротация при утечке.

## Что мы теперь знаем

- Zero-touch — автоматическая первичная настройка Android.
- Нагрузка (QR/NFC) указывает DPC и адрес его загрузки.
- Enrollment-токен связывает устройство с организацией.
- Утечка токена или отсутствие проверки подписи DPC — риск.
- Аудит zero-touch — это конфигурационные проверки.

## Квиз

Проверь себя.

''' + quiz([
    ('Что такое zero-touch enrollment?',
     ['Способ оплаты', 'Автоматическая первичная настройка устройств', 'Протокол сети', 'Формат базы'], 1,
     'Устройство само получает корпоративные политики при включении.'),
    ('Что передаётся через QR/NFC при provisioning?',
     ['Только Wi-Fi', 'Какой DPC установить и откуда скачать', 'Пароль пользователя', 'Список контактов'], 1,
     'Нагрузка указывает DPC, адрес загрузки и проверку подписи.'),
    ('Что делает enrollment-токен?',
     ['Шифрует диск', 'Связывает устройство с организацией', 'Ставит root', 'Ускоряет сеть'], 1,
     'Токен привязывает устройство к аккаунту MDM.'),
    ('Зачем нужен SIGNATURE_CHECKSUM?',
     ['Для красоты', 'Чтобы принять только подписанный DPC', 'Для сжатия', 'Для логирования'], 1,
     'Это защита от подмены агента управления.'),
    ('Главный риск утечки enrollment-токена?',
     ['Медленная сеть', 'Чужое устройство попадёт в корпоративный парк', 'Потеря root', 'Смена языка'], 1,
     'Устройство злоумышленника получит корпоративные политики.'),
])

write_lesson(m, body + '''
## Куда дальше

Мы закончили ветвь Android Enterprise. Дальше логично перейти к iOS-безопасности на уровне
платформы — подписи, песочница, jailbreak — и к тому, как там устроено корпоративное
управление (MDM на iOS).

## Где пригодится

- Пентест корпоративных устройств: аудит канала развёртывания.
- BYOD-безопасность: оценка привязки устройств.
- Анализ приложений: понимание provisioning-настроек.
''', lab=lab(
    'Практика: проверь provisioning-нагрузку',
    ['task.md', 'provisioning.json', 'notes.txt'],
    ['`provisioning.json` — нагрузка QR-provisioning.',
     'Проверь, есть ли проверка подписи DPC (`SIGNATURE_CHECKSUM`).',
     'В `notes.txt` утёк enrollment-токен — запиши его в `found.txt`.'],
    'nto{z3r0_t0uch_3nr0llm3nt_t0k3n}',
    [_dir(WD),
     _f(WD + '/task.md',
        '# Задача: аудит zero-touch\\n\\n'
        '## Повторение (mobile-android-kiosk)\\n\\n'
        'Как в уроке про kiosk, сначала `ls -la` и осмотри файлы.\\n\\n'
        'Проверь нагрузку provisioning и найди утёкший enrollment-токен в `notes.txt`.\\n'
        'Запиши токен в `found.txt` и набери `check`.\\n'),
     _f(WD + '/provisioning.json',
        '{\\n'
        '  "PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": "com.acme.mdm/.AdminReceiver",\\n'
        '  "PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION": "https://mdm.acme.example/dpc.apk"\\n'
        '}\\n'),
     _f(WD + '/notes.txt',
        'setup notes\\n'
        'enrollment_token=nto{z3r0_t0uch_3nr0llm3nt_t0k3n}\\n'
        'SIGNATURE_CHECKSUM: (not set)\\n')],
))

print('done b8c')
