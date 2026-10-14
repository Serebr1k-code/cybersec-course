#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch MOB-GAP-1: Android IPC/component attacks (1 hub + 4 lessons)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson, _dir, _f  # noqa: E402

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"


def lab(title, files, hints, flag, fs, tools=None, toolset=None):
    return {
        'title': title, 'toolset': toolset or ['core', 'grep'],
        'workdir': WD, 'files': files, 'check': CHECK, 'hints': hints,
        'expect': {'file': WD + '/found.txt', 'contains': flag},
        'fs': fs, 'tools': tools,
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


TAIL = '''

## Что мы теперь знаем

- ...
'''


# ===========================================================================
# HUB: mobile-android-ipc-attacks
# ===========================================================================
m = dict(
    id='mobile-android-ipc-attacks',
    title='Модуль: углублённые атаки на Android-компоненты',
    category='mobile', parent='mobile-android-components', difficulty='hard', order=5,
    tags=['android', 'ipc', 'pendingintent', 'fileprovider', 'contentprovider', 'roadmap'],
    prerequisites=['mobile-exported-components'],
    estimated_minutes=20,
    summary='Навигационный модуль: PendingIntent-хайджекинг, злоупотребление Accessibility, path traversal в FileProvider и SQL-инъекции в Content Provider.',
    useful_for=['Пентест мобильных приложений (Android)', 'Bug bounty Android', 'CTF Mobile'],
)
body = '''Мы уже прошли базовые экспортированные компоненты: Activity, Service, Broadcast, Provider.
Но самые сочные находки живут на уровень глубже — там, где компонент формально защищён,
а данные всё равно утекают. Этот модуль собирает четыре таких класса.

## Что покрывает модуль

1. **PendingIntent: mutable-флаги и захват** — токен, который приложение отдаёт системе, и что
   происходит, если он мутабельный и неявный.
2. **Accessibility Service: злоупотребление** — сервис, изначально созданный для людей с
   ограничениями, а на деле читающий экран и нажимающий кнопки за пользователя.
3. **FileProvider: path traversal и URI-утечки** — обёртка над `content://`, которая при
   неверном конфиге отдаёт любой файл приложения.
4. **Content Provider SQL-инъекции deep** — когда провайдер собирает SQL из того, что ему
   передал вызывающий, вместо параметров.

## Почему такой порядок

Все четыре темы опираются на одну идею: **граница доверия проходит не там, где кажется**.
Сначала разберём PendingIntent — там доверие передаётся вместе с токеном. Потом
Accessibility — доверие, которое пользователь выдал руками. Затем FileProvider и Provider —
доверие к аргументам, которые приходят из чужого процесса. Идите по порядку: каждый урок
строится на понятиях предыдущего (Intent, Parcel, URI).

## Чему вы научитесь

- Читать флаги `PendingIntent` и понимать, когда они дают хайджекинг.
- Находить в манифесте злоупотребляемые Accessibility/notification-сервисы.
- Строить `content://`-запросы, выходящие за пределы задуманного каталога.
- Замечать инъекцию в `ContentProvider.query()` и подтверждать её.

## Как проходить ступень

Начните с `mobile-android-pendingintent`. В каждом уроке есть лаборатория: разберите дамп
анализа до флага, ответьте на квиз. Лаборатории — не украшение, а основной навык.

## Связь с другими ветками

Компонентные атаки часто комбинируются в цепочки (см. `mobile-exploit-chains`), а защита от
них — тема `mobile-app-protection`. Если хочется глубже в IPC — после этого модуля смотрите
`mobile-android-binder` и `mobile-ipc-fuzzing`.

## Квиз

Проверь себя.

''' + quiz([
    ('Что даёт злоумышленнику мутабельный PendingIntent с неявным базовым Intent?',
     ['Ничего, PendingIntent всегда приватный',
      'Возможность заполнить незаданные поля и перенаправить вызов в своё приложение',
      'Только чтение логов системы', 'Доступ к root-шеллу'], 1,
     'Мутабельный PendingIntent позволяет получателю дозаполнить поля; при неявном Intent это даёт редирект.'),
    ('Почему Accessibility Service опасен как поверхность атаки?',
     ['Он не имеет разрешений', 'Он читает содержимое экрана и может выполнять действия за пользователя',
      'Он работает только в эмуляторе', 'Он не может быть экспортирован'], 1,
     'Сервис видит дерево UI и может кликать/вводить текст — идеальный кейлоггер и overlay.'),
    ('В чём суть path traversal в FileProvider?',
     ['Файлы шифруются неверным ключом',
      '`root-path`/`path` в file_paths.xml слишком широкий и позволяет выйти за каталог',
      'Провайдер не поддерживает content://', 'Он отдаёт файлы только root-пользователю'], 1,
     'Слишком широкий путь (или `..`) позволяет читать файлы вне задуманного каталога.'),
    ('Когда `ContentProvider.query()` становится SQL-инъекцией?',
     ['Когда провайдер использует параметризованные запросы',
      'Когда selection/selectionArgs конкатенируются в SQL вместо использования `?`',
      'Когда провайдер не экспортирован', 'Когда таблица пуста'], 1,
     'Подстановка пользовательской строки прямо в SQL вместо bind-параметров = инъекция.'),
])

write_lesson(m, body)

# ===========================================================================
# mobile-android-pendingintent
# ===========================================================================
m = dict(
    id='mobile-android-pendingintent',
    title='PendingIntent: mutable-флаги и захват',
    category='mobile', parent='mobile-android-ipc-attacks', difficulty='hard', order=1,
    tags=['android', 'pendingintent', 'ipc', 'intent', 'hijacking', 'android12'],
    prerequisites=['mobile-exported-components', 'mobile-intents-deeplinks'],
    estimated_minutes=40,
    summary='Что такое PendingIntent, зачем нужны флаги мутабельности, как мутабельный неявный PendingIntent превращается в перехват вызова и как это искать в коде.',
    useful_for=['Пентест мобильных приложений (Android)', 'Bug bounty Android', 'CTF Mobile'],
)
body = '''## Вопрос, с которого всё начинается

Приложение показывает уведомление «Ваш заказ №42» — и по тапу открывает экран заказа.
Само приложение при этом не запущено. Кто же открывает Activity, если процесс спит? За это
отвечает **PendingIntent**. И именно вокруг него живёт целый класс уязвимостей. Разберёмся.

## Наш пример: уведомление со ссылкой на заказ

В декомпилированном коде приложения доставки находим создание уведомления:

```java
Intent open = new Intent("com.example.delivery.OPEN_ORDER");
open.putExtra("order_id", orderId);
PendingIntent pi = PendingIntent.getActivity(
        context, 0, open, PendingIntent.FLAG_MUTABLE);
```

Строка `FLAG_MUTABLE` — красный флаг. Но почему? Чтобы понять, надо сначала разобраться,
что такое PendingIntent и что делает этот флаг.

## Шаг 1: что такое PendingIntent

Обычный `Intent` — это описание того, что надо сделать: «открой Activity X» или «отправь
broadcast Y». Но вызвать его можно только от имени того процесса, который это делает.

**PendingIntent** — это *токен*: приложение заранее создаёт Intent и отдаёт его системе
(например, `NotificationManager`). Когда пользователь тапает уведомление, систему просит
выполнить этот Intent **от имени создателя**, даже если само приложение уже не запущено.
Именно поэтому уведомления и виджеты работают без активного процесса.

Другими словами: PendingIntent — это «право выполнить действие моими полномочиями».

## Шаг 2: флаги мутабельности

Исторически у PendingIntent были флаги `FLAG_ONE_SHOT`, `FLAG_NO_CREATE`, `FLAG_UPDATE_CURRENT`.
С Android 12 (API 31) появились два важных:

- `FLAG_IMMUTABLE` — получатель **не может** менять содержимое Intent. Безопасный вариант.
- `FLAG_MUTABLE` — получатель **может** дозаполнить незаданные поля.

`FLAG_MUTABLE` нужен для легитимных сценариев: пузырьки чатов (bubbles), прямые ответы из
уведомления, где система сама вписывает текст ответа в Intent. Но если базовый Intent
**неявный** (задан action, но не задан конкретный component), то «незаданное поле» — это и
есть component. Кто угодно может его вписать.

## Шаг 3: как выглядит уязвимость

В нашем примере базовый Intent неявный: задан только action `com.example.delivery.OPEN_ORDER`
и extra `order_id`, но не указан пакет. Приложение-атакующий объявляет у себя Activity с
таким же intent-filter:

```xml
<activity android:name=".EvilActivity" android:exported="true">
    <intent-filter>
        <action android:name="com.example.delivery.OPEN_ORDER"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```

Когда система резолвит PendingIntent, она может выбрать **нашу** Activity — и получить
`order_id` из extra, а также выполнить вызов с правами приложения-жертвы. Это и есть
**PendingIntent hijacking**: перехват вызова и утечка данных, которые создатель считал
безопасными.

## Шаг 4: эксплуатация через adb и логи

В лабораторных условиях поведение проверяют так. Смотрим, какие PendingIntent-и создаёт
приложение, по логам или через Frida-хук на `PendingIntent.getActivity`:

```bash
$ adb shell dumpsys activity intents | grep -i pendingintent
  PendingIntentRecord{... action=com.example.delivery.OPEN_ORDER flags=0x02000000}
```

Здесь `0x02000000` — это `FLAG_MUTABLE`. Дальше атакующее приложение просто регистрирует
совпадающий intent-filter и ждёт, пока жертва тапнет уведомление.

## Шаг 5: что искать в коде и манифесте

При статическом анализе ищем связку из двух условий:

1. `PendingIntent.getActivity/getBroadcast/getService` с `FLAG_MUTABLE`;
2. базовый Intent без `setPackage()` / `setComponent()` (то есть неявный).

Инструментально это делается так:

```bash
$ grep -rn "FLAG_MUTABLE" decompiled/ | head
decompiled/smali/com/example/delivery/Notify.smali: ... FLAG_MUTABLE
```

И проверяем, что рядом нет `setPackage`. Если есть — риск снимается: пакет фиксирует
получателя.

## Шаг 6: как это чинится

- Использовать `FLAG_IMMUTABLE` всегда, когда мутабельность не нужна.
- Если нужна мутабельность — задать явный `setPackage()` или `setComponent()`.
- Не класть в мутабельный PendingIntent чувствительные extra, которые получатель может
  прочитать.

## Что мы теперь знаем

- PendingIntent — токен на выполнение действия от имени создателя.
- `FLAG_MUTABLE` разрешает получателю дозаполнять поля.
- Мутабельный **неявный** PendingIntent = перехват вызова чужой Activity.
- Искать надо пару «FLAG_MUTABLE + нет setPackage/setComponent».

## Квиз

Проверь себя.

''' + quiz([
    ('Что такое PendingIntent по сути?',
     ['Обычный Intent, лежащий в файле',
      'Токен, позволяющий другому процессу выполнить Intent от имени создателя',
      'Разрешение на доступ к сети', 'Способ хранения пароля'], 1,
     'PendingIntent делегирует право выполнить действие с полномочиями создателя.'),
    ('Какой флаг делает PendingIntent уязвимым к дозаполнению полей?',
     ['FLAG_IMMUTABLE', 'FLAG_MUTABLE', 'FLAG_ONE_SHOT', 'FLAG_CANCEL_CURRENT'], 1,
     'FLAG_MUTABLE позволяет получателю заполнить незаданные поля, включая component.'),
    ('При каком базовом Intent мутабельность особенно опасна?',
     ['Явный, с setComponent()', 'Неявный, без setPackage()/setComponent()',
      'Пустой Intent без action', 'Intent только с extra'], 1,
     'У неявного Intent незаданный component и есть то поле, которое впишет атакующий.'),
    ('Как нейтрализовать риск при необходимости мутабельности?',
     ['Убрать extra', 'Задать явный setPackage()/setComponent()',
      'Использовать FLAG_ONE_SHOT', 'Уменьшить размер Intent'], 1,
     'Явный получатель фиксирует, кому достанется вызов.'),
])

write_lesson(m, body, lab=lab(
    'Практика: найти мутабельный PendingIntent',
    ['task.md', 'notify_dump.txt'],
    ['`notify_dump.txt` — выжимка из `dumpsys activity intents`.',
     'Ищи строки с action и флагом в hex; вспомни, что `0x02000000` — это FLAG_MUTABLE.',
     'Рядом с одной из записей лежит строка `secret: nto{...}` — запиши её в `found.txt`.'],
    'nto{p3nd1ng1nt3nt_mut4bl3_h1j4ck}',
    [
        _dir(WD),
        _f(WD + '/task.md', '# Задача: PendingIntent hijacking\n\nРазбери дамп `dumpsys` и найди мутабельный PendingIntent с утечкой.\n'),
        _f(WD + '/notify_dump.txt',
           'PendingIntentRecord{4f2a com.example.delivery uid=10123}\n'
           '  action=android.intent.action.VIEW\n'
           '  flags=0x04000000 (FLAG_IMMUTABLE)\n'
           'PendingIntentRecord{9c11 com.example.delivery uid=10123}\n'
           '  action=com.example.delivery.OPEN_ORDER\n'
           '  flags=0x02000000 (FLAG_MUTABLE)  package=(none)\n'
           '  extra order_id=42\n'
           '  secret: nto{p3nd1ng1nt3nt_mut4bl3_h1j4ck}\n'
           'PendingIntentRecord{1b77 com.example.delivery uid=10123}\n'
           '  action=com.example.delivery.SYNC\n'
           '  flags=0x04000000 (FLAG_IMMUTABLE)\n'),
    ],
))

# ===========================================================================
# mobile-android-accessibility
# ===========================================================================
m = dict(
    id='mobile-android-accessibility',
    title='Accessibility Service: злоупотребление',
    category='mobile', parent='mobile-android-ipc-attacks', difficulty='hard', order=2,
    tags=['android', 'accessibility', 'keylogger', 'overlay', 'a11y', 'malware'],
    prerequisites=['mobile-android-pendingintent'],
    estimated_minutes=40,
    summary='Как Accessibility Service видит экран и выполняет действия за пользователя, почему это идеальная база для кейлоггеров и банковских троянов и как распознать злоупотребление.',
    useful_for=['Анализ Android-малвари', 'Пентест мобильных приложений', 'Bug bounty Android'],
)
body = '''## Вопрос, с которого всё начинается

Банковское приложение требует подтвердить перевод, а мошенник получает доступ к счёту, не
зная пароля. Как? Через сервис, который сам Google позиционирует как инструмент доступности
для людей с ограничениями — **Accessibility Service**. Разберём, почему он стал любимым
оружием мобильной малвари.

## Наш пример: приложение-«помощник»

На устройстве жертвы установлено приложение, которое при первом запуске просит включить
«специальные возможности». В декомпилированном манифесте видим:

```xml
<service android:name=".HelperService"
         android:exported="true"
         android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
    <intent-filter>
        <action android:name="android.accessibilityservice.AccessibilityService"/>
    </intent-filter>
    <meta-data android:name="android.accessibilityservice"
               android:resource="@xml/accessibility_config"/>
</service>
```

Само по себе объявление легально. Опасность — в том, что делает `HelperService`.

## Шаг 1: что видит Accessibility Service

Обычное приложение видит только себя. Accessibility Service получает от системы **дерево
доступности** активного окна: все видимые элементы, их текст, координаты, а иногда и
содержимое полей ввода. Метод `onAccessibilityEvent` вызывается при каждом изменении UI.

Это значит:

- **Что видно:** заголовки экранов, тексты кнопок, значения полей, уведомления.
- **Что можно:** выполнять `ACTION_CLICK`, `ACTION_SET_TEXT`, скроллить, нажимать «Назад».

Формально это ровно то, что нужно человеку, который не может вести пальцем по экрану.
Фактически — это доступ к содержимому любого приложения.

## Шаг 2: почему это кейлоггер

Если сервис фильтрует события по `TYPE_VIEW_TEXT_CHANGED`, он получает каждый введённый
символ. В коде это выглядит безобидно:

```java
public void onAccessibilityEvent(AccessibilityEvent e) {
    if (e.getEventType() == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
        log(e.getText().toString());
    }
}
```

Так реализуется **кейлоггинг**: логин, пароль, номер карты, OTP — всё, что пользователь
печатает, попадает к атакующему. Никаких root-прав для этого не нужно.

## Шаг 3: overlay и «автоклик»

Второй сценарий — **overlay-атаки**. Сервис может рисовать поверх банковского приложения
свой экран (или, если доступна `SYSTEM_ALERT_WINDOW`, накладывать окно). Жертва думает, что
вводит данные в банк, а на деле — в форму атакующего.

Третий сценарий — **автоматические нажатия**: получив событие «открылся экран подтверждения
перевода», сервис сам вызывает `ACTION_CLICK` на кнопке «Подтвердить». Жертва даже не
успевает понять, что произошло.

## Шаг 4: как искать злоупотребление

Статически — ищем объявление accessibility-сервиса и смотрим, какие события он обрабатывает
и что делает:

```bash
$ grep -rn "onAccessibilityEvent" decompiled/smali/ | head
decompiled/smali/com/evil/HelperService.smali: ...
$ grep -rn "TYPE_VIEW_TEXT_CHANGED\|ACTION_CLICK\|setText" decompiled/smali/com/evil/HelperService.smali
```

Динамически — через `adb` смотрим, какие сервисы доступности включены:

```bash
$ adb shell settings get secure enabled_accessibility_services
com.evil/.HelperService
```

Любой accessibility-сервис, который не является известным помощником (TalkBack, Switch
Access), — повод присмотреться.

## Шаг 5: как защищаются приложения

С Android 12+ банки используют `AccessibilityService`-detection: приложение проверяет,
включён ли подозрительный сервис, и блокирует чувствительные операции. Также помогает
`setFilterTouchesWhenObscured(true)` против tapjacking и `FLAG_SECURE` против скриншотов.

Но защита неполна: сервис доступности всё равно видит дерево, если пользователь его включил.
Поэтому последняя линия — информировать пользователя и не полагаться только на технику.

## Шаг 6: вывод для пентеста

В отчёте злоупотребление Accessibility описывают как **«небезопасное использование
специальных возможностей»**: приложение не проверяет, кто именно включил сервис, и
доверяет вводу/нажатиям, пришедшим из дерева доступности. Для малвари это способ обойти
sandbox без root.

## Что мы теперь знаем

- Accessibility Service получает дерево UI активного окна и может действовать за пользователя.
- `TYPE_VIEW_TEXT_CHANGED` = кейлоггер без root.
- Overlay и автоклики превращают его в инструмент банковского фрода.
- Искать: объявление сервиса + `onAccessibilityEvent` + чувствительные действия.

## Квиз

Проверь себя.

''' + quiz([
    ('Что получает Accessibility Service от системы?',
     ['Только имя активного приложения', 'Дерево доступности активного окна с текстом и координатами',
      'Полный root-доступ', 'Только уведомления'], 1,
     'Сервис видит элементы UI: текст, кнопки, поля ввода.'),
    ('Какое событие превращает сервис в кейлоггер?',
     ['TYPE_WINDOW_STATE_CHANGED', 'TYPE_VIEW_TEXT_CHANGED', 'TYPE_VIEW_CLICKED', 'TYPE_NOTIFICATION_STATE_CHANGED'], 1,
     'Изменение текста в поле = введённый символ.'),
    ('Как сервис может подтвердить перевод без участия жертвы?',
     ['Через root-шелл', 'Вызвав ACTION_CLICK на кнопке подтверждения',
      'Перезагрузив устройство', 'Через Bluetooth'], 1,
     'Сервис может выполнять действия, включая клики, за пользователя.'),
    ('Где посмотреть включённые сервисы доступности?',
     ['adb shell settings get secure enabled_accessibility_services',
      'adb shell ls /sdcard', 'adb logcat -c', 'adb shell pm list packages'], 0,
     'Эта настройка перечисляет активные accessibility-сервисы.'),
])

write_lesson(m, body, lab=lab(
    'Практика: разобрать accessibility-сервис',
    ['task.md', 'helper_smali.txt'],
    ['`helper_smali.txt` — фрагмент smali подозрительного сервиса.',
     'Ищи обработку `TYPE_VIEW_TEXT_CHANGED` и куда уходит текст.',
     'В комментарии к одному из методов спрятан флаг `nto{...}` — запиши в `found.txt`.'],
    'nto{4cc3ss1b1l1ty_k3yl0gg3r}',
    [
        _dir(WD),
        _f(WD + '/task.md', '# Задача: accessibility-кейлоггер\n\nНайди, как сервис собирает вводимый текст.\n'),
        _f(WD + '/helper_smali.txt',
           '.class public Lcom/evil/HelperService;\n'
           '.super Landroid/accessibilityservice/AccessibilityService;\n'
           '\n'
           '.method public onAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)V\n'
           '    invoke-virtual {p1}, Landroid/view/accessibility/AccessibilityEvent;->getEventType()I\n'
           '    move-result v0\n'
           '    const/16 v1, 0x10   # TYPE_VIEW_TEXT_CHANGED\n'
           '    if-ne v0, v1, :cond_0\n'
           '    # each keystroke exfiltrated to c2\n'
           '    # flag: nto{4cc3ss1b1l1ty_k3yl0gg3r}\n'
           '    :cond_0\n'
           '    return-void\n'
           '.end method\n'),
    ],
))

# ===========================================================================
# mobile-android-fileprovider
# ===========================================================================
m = dict(
    id='mobile-android-fileprovider',
    title='FileProvider: path traversal и URI-утечки',
    category='mobile', parent='mobile-android-ipc-attacks', difficulty='hard', order=3,
    tags=['android', 'fileprovider', 'contentprovider', 'traversal', 'uri', 'xml'],
    prerequisites=['mobile-exported-provider'],
    estimated_minutes=40,
    summary='Зачем нужен FileProvider, как file_paths.xml определяет отдаваемые каталоги и как слишком широкий path (или `..`) превращается в чтение произвольных файлов.',
    useful_for=['Пентест мобильных приложений (Android)', 'Bug bounty Android', 'CTF Mobile'],
)
body = '''## Вопрос, с которого всё начинается

С Android 7 приложение больше не может просто отдать файл по `file://` — система бросает
`FileUriExposedException`. Вместо этого используют **FileProvider** и `content://`-URI.
Задумано это ради безопасности. Но если конфиг написан неаккуратно, провайдер начинает
отдавать **любой** файл приложения. Разберём, как это происходит.

## Наш пример: «поделиться PDF»

Приложение-сканер умеет делиться отсканированным PDF. В манифесте:

```xml
<provider android:name="androidx.core.content.FileProvider"
          android:authorities="com.example.scanner.fileprovider"
          android:exported="false"
          android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
               android:resource="@xml/file_paths"/>
</provider>
```

Провайдер не экспортирован — напрямую его никто не вызовет. Но `grantUriPermissions="true"`
означает, что приложению можно выдать разовое право на конкретный URI. А какие URI он
умеет отдавать — определяет `file_paths.xml`.

## Шаг 1: как устроен file_paths.xml

Файл описывает соответствия «псевдоним → реальный путь внутри приложения»:

```xml
<paths>
    <files-path name="scans" path="scans/"/>
    <cache-path name="cache" path="."/>
    <external-path name="ext" path="."/>
</paths>
```

- `files-path` → `/data/data/<pkg>/files/`
- `cache-path` → `/data/data/<pkg>/cache/`
- `external-path` → внешнее хранилище приложения

Поле `path` — это подкаталог. `path="."` означает **весь** соответствующий каталог. Вот тут
и начинаются проблемы.

## Шаг 2: где возникает traversal

FileProvider сам по себе фильтрует `..` в запрошенном URI — наивный `../` через URI не
пройдёт. Но ошибка обычно в **конфиге**: слишком широкий `path` делает доступным больше, чем
задумано. Например, `<external-path path="."/>` отдаёт всё внешнее хранилище, включая чужие
файлы, если они оказались в области приложения.

Второй вариант — `root-path`:

```xml
<root-path name="root" path="."/>
```

`root-path` указывает на корень файловой системы `/`. Если провайдер отдаёт по нему файлы и
приложение (или атакующий через grant) может запросить произвольный путь — читаются файлы
вне песочницы. Это классическая конфигурационная ошибка.

## Шаг 3: эксплуатация через grant

Сценарий: жертвенное приложение само вызывает `Intent` с `FLAG_GRANT_READ_URI_PERMISSION` и
подставляет URI, которым управляет атакующий (например, через deeplink или экспортированную
Activity). Если URI указывает на `root-path`-псевдоним, атакующий получает чтение файла,
который не должен был покидать приложение.

Проверка конфига — первый шаг анализа:

```bash
$ cat res/xml/file_paths.xml
<paths>
    <root-path name="root" path="."/>
</paths>
```

Такая запись — почти гарантированная находка.

## Шаг 4: как искать в APK

Распаковываем и ищем провайдеры FileProvider и их конфиги:

```bash
$ grep -rn "FileProvider" decompiled/AndroidManifest.xml
$ aapt2 dump xmltree app.apk --file res/xml/file_paths.xml | grep -i path
```

Дальше — проверить, какие Activity/Service умеют принимать внешний URI и передавать его
дальше с grant-флагом. Именно эта цепочка превращает конфиг в уязвимость.

## Шаг 5: как чинится

- Указывать **конкретный** подкаталог, а не `path="."`.
- Никогда не использовать `root-path`, если в этом нет острой необходимости.
- Не принимать URI от внешних компонентов и не передавать их дальше с grant.
- Проверять `getCanonicalPath()` результата на принадлежность разрешённому корню.

## Что мы теперь знаем

- FileProvider отдаёт файлы по `content://`, список — в `file_paths.xml`.
- `path="."` и `root-path` расширяют доступ до небезопасного уровня.
- Уязвимость раскрывается в связке «широкий конфиг + grant чужому URI».
- Искать: FileProvider в манифесте + конфиг путей + передача URI с grant-флагом.

## Квиз

Проверь себя.

''' + quiz([
    ('Зачем появился FileProvider?',
     ['Чтобы ускорить чтение файлов', 'Чтобы заменить небезопасный file://-обмен на content://',
      'Чтобы шифровать файлы', 'Чтобы запретить доступ к SD-карте'], 1,
     'С Android 7 прямой file://-обмен запрещён; FileProvider даёт безопасный content://.'),
    ('Какой конфиг file_paths.xml наиболее опасен?',
     ['<files-path name="scans" path="scans/"/>', '<root-path name="root" path="."/>',
      '<cache-path name="c" path="cache/"/>', '<files-path name="f" path="f/"/>'], 1,
     'root-path с path="." открывает корень файловой системы.'),
    ('Почему провайдер с exported=false всё равно может быть уязвим?',
     ['Он не может быть уязвим', 'Из-за grantUriPermissions он получает разовое право на URI',
      'Потому что он root', 'Потому что он кэширует файлы'], 1,
     'Grant-право открывает доступ к конкретному URI даже неэкспортированному провайдеру.'),
    ('Как корректно ограничить FileProvider?',
     ['Использовать root-path', 'Указать конкретный подкаталог и не использовать root-path',
      'Отключить content://', 'Дать путь "/"'], 1,
     'Конкретный подкаталог + проверка canonical path = безопасный минимум.'),
])

write_lesson(m, body, lab=lab(
    'Практика: конфиг FileProvider',
    ['task.md', 'manifest.xml', 'file_paths.xml'],
    ['`file_paths.xml` описывает, что отдаёт провайдер.',
     'Сравни `root-path`, `external-path` и конкретные подкаталоги.',
     'В комментарии рядом с опасным правилом — флаг `nto{...}`.'],
    'nto{f1l3pr0v1d3r_p4th_tr4v3rs4l}',
    [
        _dir(WD),
        _f(WD + '/task.md', '# Задача: FileProvider\n\nНайди небезопасное правило в конфиге провайдера.\n'),
        _f(WD + '/manifest.xml',
           '<provider android:name="androidx.core.content.FileProvider"\n'
           '    android:authorities="com.example.scanner.fileprovider"\n'
           '    android:exported="false"\n'
           '    android:grantUriPermissions="true">\n'
           '  <meta-data android:name="android.support.FILE_PROVIDER_PATHS"\n'
           '      android:resource="@xml/file_paths"/>\n'
           '</provider>\n'),
        _f(WD + '/file_paths.xml',
           '<paths>\n'
           '  <files-path name="scans" path="scans/"/>\n'
           '  <!-- dangerous: full filesystem root exposed -->\n'
           '  <!-- flag: nto{f1l3pr0v1d3r_p4th_tr4v3rs4l} -->\n'
           '  <root-path name="root" path="."/>\n'
           '</paths>\n'),
    ],
))

# ===========================================================================
# mobile-android-contentprovider-sql
# ===========================================================================
m = dict(
    id='mobile-android-contentprovider-sql',
    title='Content Provider SQL-инъекции deep',
    category='mobile', parent='mobile-android-ipc-attacks', difficulty='expert', order=4,
    tags=['android', 'contentprovider', 'sqli', 'provider', 'uri', 'sqlite'],
    prerequisites=['mobile-exported-provider', 'mobile-android-fileprovider'],
    estimated_minutes=45,
    summary='Как ContentProvider строит SQL-запросы, где появляется инъекция через projection/selection/sortOrder, как её подтвердить через adb и как защититься параметрами.',
    useful_for=['Пентест мобильных приложений (Android)', 'Bug bounty Android', 'CTF Mobile'],
)
body = '''## Вопрос, с которого всё начинается

Content Provider — это «API к базе» внутри Android. Приложение вызывает
`getContentResolver().query(uri, projection, selection, selectionArgs, sortOrder)`. Казалось
бы, параметры — это безопасный bind. Но многие провайдеры собирают SQL **строками**, и тогда
`selection` становится точкой инъекции. Разберём, как это увидеть и подтвердить.

## Наш пример: провайдер заметок

В декомпилированном коде находим метод `query`:

```java
public Cursor query(Uri uri, String[] projection, String selection,
                    String[] selectionArgs, String sortOrder) {
    String q = "SELECT " + (projection != null ? projection[0] : "*")
             + " FROM notes WHERE " + selection
             + " ORDER BY " + sortOrder;
    return db.rawQuery(q, null);
}
```

Обратите внимание: `selection` и `sortOrder` подставлены в строку напрямую, а `rawQuery`
вызывается с `null` вместо аргументов. Значит, никакой параметризации нет — это SQL-инъекция.

## Шаг 1: как вызывается провайдер

Content Provider доступен по `content://<authority>/<path>`. Если он экспортирован (или
доступен другому приложению), вызвать его можно из любого приложения или через `adb`:

```bash
$ adb shell content query --uri content://com.example.notes.provider/notes
Row: 0 _id=1, title=Hello, body=world
```

`adb shell content` — встроенный инструмент, который умеет query/insert/update/delete.

## Шаг 2: точки инъекции

В `query` есть три потенциально опасных аргумента:

- **projection** — список колонок;
- **selection** — условие `WHERE`;
- **sortOrder** — `ORDER BY`.

В нашем коде инъекционен `selection`. Пробуем классическое условие, которое всегда истинно:

```bash
$ adb shell content query --uri content://com.example.notes.provider/notes \
    --where "1=1"
Row: 0 _id=1, title=Hello, body=world
Row: 1 _id=2, title=Secret, body=nto{...}
```

Мы получили строку, которую обычный фильтр не отдал бы. Дальше — UNION-запросы, чтобы вытащить
соседние таблицы (например, `users` с токенами).

## Шаг 3: подтверждение через UNION

Зная число колонок, добавляем `UNION SELECT`:

```bash
$ adb shell content query --uri content://com.example.notes.provider/notes \
    --where "1=0 UNION SELECT username,password,3 FROM users--"
Row: 0 _id=admin, title=admin, body=s3cr3t
```

`--` в SQLite — начало комментария, поэтому хвост запроса отбрасывается. Так из соседней
таблицы утекают логины и пароли.

## Шаг 4: инъекция в sortOrder и projection

Даже если `selection` параметризован, `sortOrder` и `projection` часто забывают. Инъекция в
`ORDER BY` подтверждается булевым тестом: разный порядок при истинном и ложном условии.
`projection` иногда позволяет подставить подзапрос вместо имени колонки.

Проверяем, как провайдер валидирует вход:

```bash
$ grep -rn "SQLiteQueryBuilder\|rawQuery\|selectionArgs" decompiled/smali/com/example/
```

Если видим `rawQuery` с `null` аргументами — почти наверняка инъекция.

## Шаг 5: как чинится

- Использовать `SQLiteQueryBuilder.setSelection()` и передавать `selectionArgs` — тогда
  значение уходит как bind-параметр, а не как SQL-код.
- Белый список допустимых колонок для `projection` и `sortOrder`.
- Не экспортировать провайдер без необходимости; защищать permission'ом.

## Шаг 6: почему это важно в отчёте

SQL-инъекция в провайдере — это утечка всей локальной базы приложения: токены, сессии,
переписка. При этом эксплуатируется тривиально через `adb`, а в реальном мире — из
установленного рядом приложения без каких-либо прав.

## Что мы теперь знаем

- Content Provider — «API к базе» по `content://`.
- Инъекция появляется, когда `selection`/`sortOrder`/`projection` конкатенируются в SQL.
- Подтверждается через `adb shell content query --where`.
- Защита — `selectionArgs` (bind) + белый список колонок.

## Квиз

Проверь себя.

''' + quiz([
    ('Что делает Content Provider?',
     ['Отправляет SMS', 'Предоставляет доступ к базе данных приложения через content:// URI',
      'Управляет сетью', 'Хранит пароли в Keystore'], 1,
     'Провайдер — это фасад над SQLite/файлами, доступный по URI.'),
    ('Какой аргумент query() становится точкой инъекции при конкатенации?',
     ['Только uri', 'selection и/или sortOrder (иногда projection)',
      'Только selectionArgs', 'Никакой'], 1,
     'Строки, попадающие в SQL напрямую, позволяют инъекцию.'),
    ('Какая команда подтверждает SQLi в провайдере через adb?',
     ['adb shell content query --uri ... --where "1=1"',
      'adb logcat', 'adb install', 'adb reboot'], 0,
     '`content query --where` позволяет подставить произвольное условие.'),
    ('Как правильно защититься?',
     ['Отключить провайдер', 'Использовать selectionArgs (bind-параметры) и белый список колонок',
      'Шифровать базу', 'Уменьшить размер таблиц'], 1,
     'Bind-параметры отделяют данные от кода SQL.'),
])

write_lesson(m, body, lab=lab(
    'Практика: SQLi в провайдере',
    ['task.md', 'provider_query.txt', 'schema.txt'],
    ['`provider_query.txt` — серия ответов `adb shell content query`.',
     'Сравни обычный фильтр и условие `1=1` — одна строка лишняя.',
     'В вытащенной строке лежит флаг `nto{...}`.'],
    'nto{pr0v1d3r_sql1_pr0j3ct10n}',
    [
        _dir(WD),
        _f(WD + '/task.md', '# Задача: SQLi в ContentProvider\n\nПодтверди инъекцию и вытащи скрытую строку.\n'),
        _f(WD + '/schema.txt',
           'TABLE notes(_id, title, body)\nTABLE users(_id, username, password)\n'),
        _f(WD + '/provider_query.txt',
           '$ adb shell content query --uri content://com.example.notes.provider/notes --where "title=Hello"\n'
           'Row: 0 _id=1, title=Hello, body=world\n'
           '\n'
           '$ adb shell content query --uri content://com.example.notes.provider/notes --where "1=1"\n'
           'Row: 0 _id=1, title=Hello, body=world\n'
           'Row: 1 _id=2, title=Secret, body=nto{pr0v1d3r_sql1_pr0j3ct10n}\n'
           '\n'
           '$ adb shell content query --uri content://com.example.notes.provider/notes --where "1=0 UNION SELECT username,password,3 FROM users--"\n'
           'Row: 0 _id=admin, title=admin, body=s3cr3t\n'),
    ],
))

print('done')
