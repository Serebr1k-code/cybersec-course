#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch MOB-GAP-2: Android privilege & hardware trust (1 hub + 4 lessons)."""
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


# ===========================================================================
# HUB: mobile-android-trust
# ===========================================================================
m = dict(
    id='mobile-android-trust',
    title='Модуль: привилегии и аппаратное доверие Android',
    category='mobile', parent='mobile-platforms', difficulty='hard', order=5,
    tags=['android', 'deviceadmin', 'notification', 'selinux', 'attestation', 'roadmap'],
    prerequisites=['mobile-android-root'],
    estimated_minutes=22,
    summary='Навигационный модуль: Device Admin/Owner, перехват уведомлений, SELinux в Android и Key Attestation — как устройство выдаёт доверие и как это доверие злоупотребляется.',
    useful_for=['Пентест мобильных приложений (Android)', 'Анализ Android-малвари', 'Android-платформенная безопасность'],
)
body = '''Мы разобрали root и модификацию устройства. Но значительная часть привилегий в Android
выдаётся **без** root — через особые роли и API. Этот модуль собирает четыре механизма, где
доверие передаётся приложению, а вместе с ним и большой объём полномочий.

## Что покрывает модуль

1. **Device Admin и Device Owner** — роли, которые управляют устройством целиком: сброс,
   блокировка, установка политик.
2. **NotificationListenerService** — сервис, который читает все уведомления, включая OTP-коды.
3. **SELinux в Android** — мандатный контроль доступа, его режимы и типичные попытки обхода.
4. **Key Attestation** — аппаратное подтверждение, что ключ рождён в TEE/StrongBox, и способы
   подделки проверки.

## Почему такой порядок

Каждая тема — следующий уровень «кто и что может». Сначала роли управления устройством
(приложение управляет системой). Потом чтение потока уведомлений (приложение читает то, что
видит пользователь). Затем SELinux (что вообще разрешено процессу на уровне ядра). И в конце
attestation (как доказать, что ключ аппаратный, и как эта проверка ломается). Все четыре
темы регулярно всплывают при анализе банковских троянов и MDM.

## Чему вы научитесь

- Отличать Device Admin от Device Owner и понимать, что даёт каждая роль.
- Находить злоупотребление `NotificationListenerService` и оценивать утечку OTP.
- Читать режимы SELinux и замечать попытки обхода.
- Проверять attestation-цепочку и понимать, где она подделывается.

## Как проходить ступень

Начните с `mobile-android-device-admin`. В каждом уроке — лаборатория: разберите артефакт до
флага и ответьте на квиз. Не пропускайте лаборатории: именно на них навык закрепляется.

## Связь с другими ветками

Эти привилегии — строительные блоки для персистентности (см. `mobile-android-persistence`) и
эскалации (см. `mobile-android-privesc`). Защита и детект — тема `mobile-app-protection`.

## Квиз

Проверь себя.

''' + quiz([
    ('Чем Device Owner отличается от Device Admin?',
     ['Ничем, это синонимы', 'Device Owner назначается при провижининге и даёт полное управление устройством',
      'Device Admin работает только на root', 'Device Owner не может стирать данные'], 1,
     'Device Owner — более сильная роль, обычно назначается через провижининг или adb на чистом устройстве.'),
    ('Почему NotificationListenerService опасен?',
     ['Он не имеет доступа к данным', 'Он читает все уведомления, включая OTP-коды банков',
      'Он требует root', 'Он работает только на Wear OS'], 1,
     'Чтение уведомлений = перехват одноразовых кодов и чувствительных сообщений.'),
    ('Что делает SELinux?',
     ['Шифрует диск', 'Ограничивает доступ процессов к ресурсам по политике',
      'Управляет сетью', 'Сканирует APK'], 1,
     'SELinux — мандатный контроль доступа на уровне ядра.'),
    ('Зачем нужен Key Attestation?',
     ['Чтобы ускорить TLS', 'Чтобы доказать, что ключ создан в аппаратном TEE/StrongBox',
      'Чтобы сжать APK', 'Чтобы обновить приложение'], 1,
     'Attestation подтверждает аппаратное происхождение ключа и целостность устройства.'),
])

write_lesson(m, body)

# ===========================================================================
# mobile-android-device-admin
# ===========================================================================
m = dict(
    id='mobile-android-device-admin',
    title='Device Admin и Device Owner: полномочия и злоупотребление',
    category='mobile', parent='mobile-android-trust', difficulty='hard', order=1,
    tags=['android', 'deviceadmin', 'deviceowner', 'dpm', 'mdm', 'wipe'],
    prerequisites=['mobile-android-root'],
    estimated_minutes=42,
    summary='Как работают роли Device Admin, Profile Owner и Device Owner, что позволяет DevicePolicyManager и как эти полномочия эксплуатируются и детектируются.',
    useful_for=['Пентест мобильных приложений (Android)', 'Android Enterprise', 'Анализ малвари'],
)
body = '''## Вопрос, с которого всё начинается

Приложение «Корпоративная почта» при установке просит права администратора устройства: может
заблокировать экран, стереть данные, сменить пароль. Зачем программе для почты такие права?
Обычно — чтобы IT-отдел мог управлять корпоративным телефоном. Но тот же механизм, попав в
руки малвари, превращает приложение в «руку» злоумышленника. Разберём роли и их границы.

## Наш пример: MDM-клиент

На тестовом устройстве установлен клиент корпоративного управления. В его манифесте находим:

```xml
<receiver android:name=".AdminReceiver"
          android:permission="android.permission.BIND_DEVICE_ADMIN"
          android:exported="true">
    <meta-data android:name="android.app.device_admin"
               android:resource="@xml/device_admin"/>
    <intent-filter>
        <action android:name="android.app.action.DEVICE_ADMIN_ENABLED"/>
    </intent-filter>
</receiver>
```

`AdminReceiver` — это `DeviceAdminReceiver`, точка входа для событий администрирования. Рядом
лежит `device_admin.xml` со списком запрашиваемых политик. Именно этот файл определяет, что
приложение сможет делать.

## Шаг 1: что такое Device Admin

Device Admin — это устаревшая, но всё ещё рабочая роль. Приложение объявляет receiver и
политики, а пользователь подтверждает их включение на системном экране. После этого
приложение получает объект `DevicePolicyManager` (DPM) и может:

- блокировать экран (`lockNow`);
- требовать пароль и его сложность;
- стирать данные (`wipeData`);
- отключать камеру;
- наблюдать попытки ввода неверного пароля.

Важно: Device Admin **не даёт** root. Он даёт ровно те политики, которые перечислены в XML и
подтверждены пользователем. Но `wipeData` уже достаточно, чтобы уничтожить данные телефона.

## Шаг 2: Device Owner и Profile Owner

Три роли часто путают, поэтому разложим их по возрастанию силы:

- **Device Admin** — набор политик, подтверждается пользователем, снимается пользователем.
- **Profile Owner** — владеет рабочим профилем: политики применяются только к профилю, а не
  ко всему устройству.
- **Device Owner** — владеет **всем** устройством. Назначается только на устройстве без
  аккаунтов, через провижининг (QR, NFC, zero-touch) или `adb shell dpm set-device-owner`.

Device Owner может ставить приложения молча, запрещать сброс, управлять VPN и сетью, отключать
USB-отладку. Это максимальная власть без root.

## Шаг 3: как назначают и проверяют роли

Device Owner настраивают так (устройство должно быть «чистым»):

```bash
$ adb shell dpm set-device-owner com.example.mdm/.AdminReceiver
Success: Device owner set to package com.example.mdm
```

Проверить текущие роли:

```bash
$ adb shell dpm list-owners
Device Owner: com.example.mdm/.AdminReceiver
Profile Owner: (none)
```

А посмотреть список активных admin-компонентов:

```bash
$ adb shell dumpsys device_policy | grep -i "admin"
```

## Шаг 4: как этим злоупотребляют

Сценарии злоупотребления в реальной малвари:

1. **Принудительный сброс** — `wipeData(0)` стирает телефон, если пользователь пытается
   удалить вредоносное приложение (шантаж).
2. **Блокировка экрана** — ransom-логика: экран блокируется, пока не заплатят.
3. **Смена пароля** — приложение задаёт свой PIN через `resetPassword`.
4. **Запрет удаления** — Device Owner может включить `setUninstallBlocked` для самого себя.
5. **Скрытая установка** — Device Owner ставит полезную нагрузку без участия пользователя.

Все эти действия формально «легальны» с точки зрения API, потому что пользователь когда-то
подтвердил роль. Поэтому защита — в контроле над тем, кто и когда получает роль.

## Шаг 5: как аудировать приложение

При статическом анализе ищем receiver с `BIND_DEVICE_ADMIN` и читаем `device_admin.xml`:

```bash
$ grep -rn "BIND_DEVICE_ADMIN" decompiled/AndroidManifest.xml
$ cat decompiled/res/xml/device_admin.xml
<device-admin>
    <uses-policies>
        <wipe-data/>
        <force-lock/>
        <reset-password/>
    </uses-policies>
</device-admin>
```

Каждая политика — потенциальная возможность. Дальше смотрим код: вызывает ли приложение
`wipeData`, `lockNow`, `resetPassword`, и при каких условиях. Если это не MDM-продукт, а
«фонарик», требующий `wipe-data`, — перед нами явное злоупотребление.

## Шаг 6: как удалить и что мешает

Обычного удаления может не хватить: сначала снимают роль администратора, потом удаляют
приложение. Но если приложение — Device Owner, оно может блокировать снятие роли и удаление.
Тогда помогает только `adb`:

```bash
$ adb shell dpm remove-active-admin com.example.mdm/.AdminReceiver
$ adb uninstall com.example.mdm
```

На заблокированном устройстве иногда требуется сброс к заводским настройкам. Это и есть
показатель силы роли: Device Owner переживает попытки пользователя от него избавиться.

## Шаг 7: что писать в отчёте

Опишите: какие роли запрашивает приложение, какие политики перечислены, соответствуют ли они
назначению, есть ли код, использующий опасные вызовы. Отдельно — можно ли снять роль без
сброса устройства. Для малвари добавьте MITRE-маппинг: Device Administration как техника
персистентности и уклонения от удаления.

## Шаг 8: рекомендации

- Минимизировать политики: запрашивать только необходимое.
- Для корпоративных сценариев использовать **Profile Owner**, а не Device Owner, где возможно.
- Пользователю — проверять, зачем приложению права администратора, прежде чем подтверждать.
- Платформе — ограничивать назначение Device Owner провижинингом на чистом устройстве (что
  и делает современный Android).

## Что мы теперь знаем

- Device Admin, Profile Owner и Device Owner — три роли с разной силой.
- DevicePolicyManager даёт блокировку, сброс, смену пароля, запрет удаления.
- Малварь использует эти права для шантажа и персистентности.
- Аудит: receiver с `BIND_DEVICE_ADMIN` + `device_admin.xml` + вызовы DPM.

## Квиз

Проверь себя.

''' + quiz([
    ('Что определяет, какие политики сможет применять Device Admin?',
     ['Манифест-разрешения', 'Файл device_admin.xml с тегом uses-policies',
      'Код приложения без ограничений', 'Настройки пользователя'], 1,
     'Именно XML перечисляет запрашиваемые политики, подтверждаемые пользователем.'),
    ('Какая роль даёт власть над всем устройством?',
     ['Device Admin', 'Profile Owner', 'Device Owner', 'Никакая без root'], 2,
     'Device Owner назначается на чистом устройстве и управляет им целиком.'),
    ('Как малварь использует wipeData?',
     ['Ускоряет работу', 'Стирает данные как рычаг шантажа или уничтожения следов',
      'Шифрует диск', 'Улучшает батарею'], 1,
     'Принудительный сброс — типичная ransom/anti-removal техника.'),
    ('Как проверить текущего Device Owner через adb?',
     ['adb shell dpm list-owners', 'adb logcat', 'adb shell ls', 'adb shell pm list packages'], 0,
     '`dpm list-owners` показывает Device/Profile Owner.'),
])

write_lesson(m, body, lab=lab(
    'Практика: политики Device Admin',
    ['task.md', 'device_admin.xml', 'manifest.xml'],
    ['`device_admin.xml` перечисляет запрашиваемые политики.',
     'Найди самую опасную политику для приложения-фонарика.',
     'Рядом с ней в комментарии — флаг `nto{...}`.'],
    'nto{d3v1c3_0wn3r_w1p3_p0w3r}',
    [
        _dir(WD),
        _f(WD + '/task.md', '# Задача: аудит Device Admin\n\nНайди несоответствие назначению приложения.\n'),
        _f(WD + '/manifest.xml',
           '<receiver android:name=".AdminReceiver"\n'
           '    android:permission="android.permission.BIND_DEVICE_ADMIN"\n'
           '    android:exported="true">\n'
           '  <meta-data android:name="android.app.device_admin"\n'
           '      android:resource="@xml/device_admin"/>\n'
           '</receiver>\n'),
        _f(WD + '/device_admin.xml',
           '<device-admin>\n'
           '  <uses-policies>\n'
           '    <force-lock/>\n'
           '    <!-- flashlight app should NOT need this -->\n'
           '    <wipe-data/>   <!-- flag: nto{d3v1c3_0wn3r_w1p3_p0w3r} -->\n'
           '    <reset-password/>\n'
           '  </uses-policies>\n'
           '</device-admin>\n'),
    ],
))

# ===========================================================================
# mobile-android-notification-listener
# ===========================================================================
m = dict(
    id='mobile-android-notification-listener',
    title='NotificationListenerService: перехват уведомлений и OTP',
    category='mobile', parent='mobile-android-trust', difficulty='hard', order=2,
    tags=['android', 'notification', 'otp', 'sms', 'interception', 'malware'],
    prerequisites=['mobile-android-device-admin'],
    estimated_minutes=40,
    summary='Как NotificationListenerService получает все уведомления, почему это прямой путь к перехвату OTP, как злоупотребление выглядит в коде и как его обнаружить.',
    useful_for=['Анализ Android-малвари', 'Пентест мобильных приложений', 'Bug bounty Android'],
)
body = '''## Вопрос, с которого всё начинается

Банк присылает код подтверждения в уведомлении. Через секунду деньги уходят, хотя жертва
ничего не подтверждала. Как атакующий узнал код? Через сервис, который создан ровно для
чтения уведомлений — **NotificationListenerService**. Разберём, как это работает.

## Наш пример: приложение «Оптимизатор батареи»

Пользователь ставит «оптимизатор», тот просит доступ к уведомлениям — «чтобы не беспокоить
вас лишним». В декомпилированном коде находим:

```java
public class Listener extends NotificationListenerService {
    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        Bundle e = sbn.getNotification().extras;
        String title = e.getString(Notification.EXTRA_TITLE);
        String text  = e.getString(Notification.EXTRA_TEXT);
        upload(title + ": " + text);
    }
}
```

Метод `onNotificationPosted` вызывается на **каждое** новое уведомление в системе. `extras`
содержит заголовок и текст. Всё, что приходит в уведомлении, уходит на сервер атакующего.

## Шаг 1: как сервис получает доступ

NotificationListenerService подключается к системному `NotificationManagerService`. Чтобы он
начал получать уведомления, пользователь должен включить его в «Доступе к уведомлениям»
(Settings → Notifications → Device & app notifications). Это отдельное согласие, не
разрешение из манифеста.

В манифесте объявление выглядит так:

```xml
<service android:name=".Listener"
         android:exported="true"
         android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">
    <intent-filter>
        <action android:name="android.service.notification.NotificationListenerService"/>
    </intent-filter>
</service>
```

## Шаг 2: что именно видно

Сервис видит уведомления **всех** приложений, которые их показывают: SMS, мессенджеры, почта,
банки, менеджеры паролей. Если приложение показывает OTP в уведомлении, код попадает к
слушателю. Это делает сервис идеальным инструментом для перехвата одноразовых кодов —
основного способа подтверждения операций.

Дополнительно сервис может **отменять** уведомления (`cancelNotification`), то есть скрывать
от пользователя сообщения о списании средств. Пользователь не видит тревожного уведомления,
пока деньги уже ушли.

## Шаг 3: фильтрация по нужному приложению

Малварь редко читает всё подряд — она фильтрует по пакету:

```java
if (sbn.getPackageName().equals("com.bank.app")) {
    String otp = extractDigits(e.getString(Notification.EXTRA_TEXT));
    sendOtp(otp);
}
```

Так из потока уведомлений вычленяется только банковский OTP. Полезно искать в коде сравнение
`getPackageName()` с конкретными пакетами банков.

## Шаг 4: как обнаружить включённый слушатель

Проверяем настройку доступа к уведомлениям:

```bash
$ adb shell settings get secure enabled_notification_listeners
com.evil/.Listener:com.evil
```

В норме там либо пусто, либо только системные/легитимные сервисы. Посторонний пакет —
красный флаг. Также полезен `dumpsys notification`:

```bash
$ adb shell dumpsys notification | grep -i listener
```

## Шаг 5: отличие от чтения SMS

Исторически малварь читала SMS напрямую (permission `READ_SMS`). Но с Android 4.4 это
разрешение доступно только приложению по умолчанию для SMS, поэтому атакующие перешли на
два обходных пути: `READ_SMS` при получении роли default-SMS, и чтение уведомлений. Второй
путь тише: не нужно становиться SMS-приложением, достаточно «доступа к уведомлениям».

## Шаг 6: как аудировать приложение

Шаги анализа:

1. Найти в манифесте сервис с `BIND_NOTIFICATION_LISTENER_SERVICE`.
2. Прочитать `onNotificationPosted`/`onNotificationRemoved`.
3. Проверить, фильтрует ли он по банковским пакетам и куда отправляет данные.
4. Посмотреть, вызывает ли `cancelNotification` (сокрытие уведомлений).
5. Оценить, оправдан ли доступ назначением приложения.

## Шаг 7: что писать в отчёте

Формулировка: приложение читает уведомления всех приложений и передаёт их на внешний сервер,
что позволяет перехватывать OTP и скрывать сообщения о транзакциях. MITRE: Collection через
Notifications, Input Capture. Отдельно отметьте, что согласие даётся пользователем вручную и
может быть отозвано — это ограничение радиуса поражения.

## Шаг 8: рекомендации

- Не выдавать доступ к уведомлениям приложениям, которым он не нужен.
- Банкам — не полагаться только на OTP из уведомлений; использовать push с криптографией.
- Платформе — показывать явное предупреждение о том, что слушатель увидит все уведомления.
- Приложениям — не показывать чувствительные коды в открытом виде в уведомлении.

## Что мы теперь знаем

- NotificationListenerService читает уведомления всех приложений.
- Это прямой путь к перехвату OTP и сокрытию уведомлений банка.
- Включается отдельным согласием в настройках, а не разрешением манифеста.
- Обнаруживается через `enabled_notification_listeners`.

## Квиз

Проверь себя.

''' + quiz([
    ('Что читает NotificationListenerService?',
     ['Только свои уведомления', 'Уведомления всех приложений, показываемые в статус-баре',
      'Только SMS', 'Только логи системы'], 1,
     'Слушатель получает уведомления всех приложений.'),
    ('Почему это опасно для банковского OTP?',
     ['OTP шифруется', 'Код приходит в уведомлении и попадает к слушателю',
      'OTP хранится в Keystore', 'OTP не показывается'], 1,
     'Уведомление с кодом читается и может быть перехвачено.'),
    ('Как проверить включённые слушатели через adb?',
     ['adb shell settings get secure enabled_notification_listeners',
      'adb shell pm list packages', 'adb logcat -c', 'adb reboot'], 0,
     'Эта настройка перечисляет активные слушатели уведомлений.'),
    ('Что ещё умеет слушатель кроме чтения?',
     ['Шифровать данные', 'Отменять уведомления (cancelNotification)',
      'Удалять APK', 'Менять пароль устройства'], 1,
     'Слушатель может отменять уведомления, скрывая их от пользователя.'),
])

write_lesson(m, body, lab=lab(
    'Практика: слушатель уведомлений',
    ['task.md', 'listener_smali.txt', 'settings.txt'],
    ['`listener_smali.txt` — smali слушателя; `settings.txt` — вывод настройки.',
     'Найди фильтр по банковскому пакету и куда уходит текст уведомления.',
     'В одной из строк — флаг `nto{...}`.'],
    'nto{n0t1f1c4t10n_0tp_1nt3rc3pt}',
    [
        _dir(WD),
        _f(WD + '/task.md', '# Задача: перехват уведомлений\n\nНайди перехват OTP.\n'),
        _f(WD + '/settings.txt',
           '$ adb shell settings get secure enabled_notification_listeners\n'
           'com.evil.battery/.Listener:com.evil.battery\n'),
        _f(WD + '/listener_smali.txt',
           '.method public onNotificationPosted(Landroid/service/notification/StatusBarNotification;)V\n'
           '    invoke-virtual {p1}, Landroid/service/notification/StatusBarNotification;->getPackageName()Ljava/lang/String;\n'
           '    move-result-object v0\n'
           '    const-string v1, "com.bank.app"\n'
           '    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
           '    if-eqz v0, :done\n'
           '    # exfil OTP -> c2\n'
           '    # flag: nto{n0t1f1c4t10n_0tp_1nt3rc3pt}\n'
           '    :done\n'
           '    return-void\n'
           '.end method\n'),
    ],
))

# ===========================================================================
# mobile-android-selinux
# ===========================================================================
m = dict(
    id='mobile-android-selinux',
    title='SELinux в Android: политики и обход',
    category='mobile', parent='mobile-android-trust', difficulty='expert', order=3,
    tags=['android', 'selinux', 'mac', 'enforcing', 'context', 'kernel'],
    prerequisites=['mobile-android-notification-listener'],
    estimated_minutes=45,
    summary='Как SELinux защищает Android, что означают режимы enforcing/permissive, как читать контексты и почему обход SELinux — обязательная часть современной эксплуатации Android.',
    useful_for=['Эксплуатация Android-ядра', 'Пентест мобильных устройств', 'Android-платформенная безопасность'],
)
body = '''## Вопрос, с которого всё начинается

Вы получили root на Android-устройстве, но команда `mount` не срабатывает: «Permission
denied». Пользователь root, а доступа нет. Так работает **SELinux** — мандатный контроль
доступа, который ограничивает даже root. Разберём, как это устроено и как обходят.

## Наш пример: попытка записи в system

На устройстве с root пытаемся смонтировать `/system` на запись:

```bash
$ adb shell
$ su
# mount -o rw,remount /system
mount: '/system' not in /proc/mounts
# echo test > /system/x
/system/x: Permission denied
```

UID у нас 0 (root), но ядро всё равно запрещает запись. Причина — не UNIX-права, а политика
SELinux: домену процесса не разрешено писать в этот тип файла.

## Шаг 1: что такое SELinux

SELinux (Security-Enhanced Linux) — механизм **мандатного** контроля доступа (MAC). В отличие
от классических UNIX-прав, которые проверяют «кто ты» (UID/GID), SELinux проверяет «в каком
контексте ты и к чему обращаешься». Каждому процессу и файлу присвоен **контекст** вида:

```
u:r:untrusted_app:s0:c512,c768
```

Разбор: `u` — пользователь, `r` — роль, `untrusted_app` — домен (тип процесса), `s0` — уровень
MLS. Файл имеет свой контекст, например `u:object_r:system_file:s0`. Политика разрешает
пересечение домена и типа — или запрещает.

## Шаг 2: режимы работы

SELinux работает в одном из режимов:

- **enforcing** — запрещает всё, что не разрешено, и логирует.
- **permissive** — разрешает, но логирует нарушения.
- **disabled** — выключен.

Проверить текущий режим:

```bash
$ adb shell getenforce
Enforcing
```

На современных устройствах Android режим по умолчанию — enforcing. Именно поэтому root сам по
себе не даёт полной власти: нужно ещё подобрать домен, которому политика разрешает нужное
действие.

## Шаг 3: контексты и как их смотреть

Посмотреть контекст процесса и файла:

```bash
$ adb shell ps -Z | grep untrusted
u:r:untrusted_app:s0:c512,c768 u0_a123 ... com.example.app
$ adb shell ls -Z /system/bin/sh
u:object_r:shell_exec:s0 /system/bin/sh
```

Искать типичные домены, полезные для эксплуатации: `su`, `init`, `shell`, `kernel`. Каждый
домен имеет свой набор разрешений. Например, домен `su` шире, чем `untrusted_app`.

## Шаг 4: почему обход SELinux обязателен

Получив уязвимость в ядре или root-доступ, исследователь почти всегда упирается в SELinux.
Например, чтобы изменить системный файл или загрузить модуль, нужен домен с соответствующими
разрешениями. Отсюда две классические техники:

1. **Переход в другой домен** (`domain transition`) через эксплуатацию процесса, который уже
   имеет широкий домен (init, system_server).
2. **Загрузка модуля/политики** при наличии доступа к ядру.

Именно поэтому цепочки эксплуатации Android почти всегда включают шаг «обход SELinux».

## Шаг 5: типичные ошибки конфигурации

Иногда производитель оставляет устройство в **permissive** или добавляет слишком широкие
правила. Проверить это можно так:

```bash
$ adb shell getenforce
Permissive
```

Permissive на пользовательском устройстве — серьёзная находка: любое нарушение политики не
блокируется. Также ищут нестандартные домены в `/sys/fs/selinux/` и правила, разрешающие
`untrusted_app` больше обычного.

## Шаг 6: как аудировать

При пентесте устройства:

1. Проверить `getenforce` — не permissive ли.
2. Посмотреть, какие домены доступны приложению.
3. Проверить, есть ли кастомные политики производителя.
4. Оценить, можно ли из уязвимого процесса перейти в привилегированный домен.

## Шаг 7: что писать в отчёте

Опишите: режим SELinux, найденные широкие правила, возможность обхода и последствия. Для
эксплуатации ядра укажите, какой домен удалось получить и что это дало. MITRE: Exploitation
for Privilege Escalation, с пометкой о платформенных ограничениях.

## Шаг 8: рекомендации

- Держать SELinux в enforcing на всех пользовательских устройствах.
- Не добавлять кастомные правила, расширяющие `untrusted_app`.
- При разработке — тестировать в enforcing, чтобы не зависеть от permissive.

## Что мы теперь знаем

- SELinux ограничивает даже root через мандатный контроль доступа.
- Домены и типы задают, что кому разрешено.
- Enforcing/permissive — режимы; permissive на устройстве пользователя — находка.
- Обход SELinux — обязательный шаг современной эксплуатации Android.

## Квиз

Проверь себя.

''' + quiz([
    ('Почему root может получить Permission denied в Android?',
     ['Из-за антивируса', 'Из-за политики SELinux, ограничивающей домен процесса',
      'Из-за нехватки места', 'Из-за батареи'], 1,
     'SELinux проверяет контексты и может запретить даже UID 0.'),
    ('Что показывает команда getenforce?',
     ['Версию Android', 'Режим SELinux: Enforcing/Permissive/Disabled',
      'Список процессов', 'Свободное место'], 1,
     'getenforce возвращает текущий режим.'),
    ('Чем permissive опасен на пользовательском устройстве?',
     ['Ничем', 'Нарушения политики не блокируются, только логируются',
      'Ускоряет телефон', 'Шифрует данные'], 1,
     'Permissive пропускает запрещённые политикой действия.'),
    ('Зачем обходить SELinux после получения root?',
     ['Чтобы сэкономить батарею', 'Чтобы домен процесса получил нужные разрешения',
      'Чтобы установить тему', 'Чтобы включить Wi-Fi'], 1,
     'Многие действия требуют домена с соответствующими правами.'),
])

write_lesson(m, body, lab=lab(
    'Практика: режим и контексты SELinux',
    ['task.md', 'selinux_state.txt'],
    ['`selinux_state.txt` — вывод команд getenforce и ls -Z.',
     'Найди домен процесса и его тип; обрати внимание на режим.',
     'В строке с небезопасным режимом — флаг `nto{...}`.'],
    'nto{s3l1nux_p3rm1ss1v3_byp4ss}',
    [
        _dir(WD),
        _f(WD + '/task.md', '# Задача: аудит SELinux\n\nНайди проблему в конфигурации.\n'),
        _f(WD + '/selinux_state.txt',
           '$ adb shell getenforce\n'
           'Permissive   # flag: nto{s3l1nux_p3rm1ss1v3_byp4ss}\n'
           '\n'
           '$ adb shell ps -Z | grep untrusted\n'
           'u:r:untrusted_app:s0:c512,c768 u0_a123 com.example.app\n'
           '\n'
           '$ adb shell ls -Z /system/bin/sh\n'
           'u:object_r:shell_exec:s0 /system/bin/sh\n'),
    ],
))

# ===========================================================================
# mobile-android-attestation
# ===========================================================================
m = dict(
    id='mobile-android-attestation',
    title='Key Attestation: проверка и обход',
    category='mobile', parent='mobile-android-trust', difficulty='expert', order=4,
    tags=['android', 'attestation', 'keystore', 'tee', 'strongbox', 'integrity'],
    prerequisites=['mobile-android-selinux', 'mobile-keystore'],
    estimated_minutes=45,
    summary='Как Key Attestation подтверждает аппаратное происхождение ключа, как читать цепочку сертификатов, что проверяет сервер и где проверка обходится.',
    useful_for=['Пентест мобильных приложений', 'Bug bounty Android', 'Безопасность мобильных платежей'],
)
body = '''## Вопрос, с которого всё начинается

Банковское приложение отказывается работать на «недоверенном» устройстве. Как оно узнаёт, что
устройство не скомпрометировано? Один из главных механизмов — **Key Attestation**: сервер
просит доказать, что ключ рождён в аппаратном хранилище. Разберём, как устроено это
доказательство и где оно ломается.

## Наш пример: ключ, подписанный аттестацией

Приложение генерирует ключ в Android Keystore с требованием аттестации:

```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
        "payment_key", KeyProperties.PURPOSE_SIGN)
    .setAttestationChallenge(challengeBytes)
    .setDigests(KeyProperties.DIGEST_SHA256)
    .build();
keyStore.generateKeyPair(spec);
```

Параметр `setAttestationChallenge` заставляет систему вернуть **сертификат аттестации**:
X.509-цепочку, где корень — ключ Google, а лист описывает свойства ключа и устройства.

## Шаг 1: что доказывает аттестация

Сертификат аттестации содержит расширения с утверждениями:

- `attestationSecurityLevel` — в каком окружении рождён ключ: Software, TEE или StrongBox.
- `verifiedBootState` — состояние verified boot (Verified/Unverified).
- `deviceLocked` — заблокировано ли устройство.
- `attestationChallenge` — тот самый nonce, который прислал сервер.
- отпечаток приложения и другие свойства.

Сервер проверяет: подпись цепочки ведёт к Google root, challenge совпадает (защита от replay),
securityLevel = TEE/StrongBox, verifiedBootState = Verified. Если всё сходится — ключ настоящий
и устройство не рутовано.

## Шаг 2: как читать цепочку

Цепочку получают и разбирают так:

```bash
$ keytool -printcert -file attestation_chain.pem | head -40
Certificate chain length: 3
Subject: CN=Android Keystore Key
...
```

Более удобно — скриптами на Python (`cryptography`) или готовым инструментом вроде
`android-key-attestation`. Важно проверить, что цепочка действительно ведёт к известному
Google root, а не к самоподписанному сертификату.

## Шаг 3: где проверка слабая

Основные ошибки серверной проверки:

1. **Не проверяется корень.** Сервер смотрит только на лист, не строит цепочку до Google
   root — тогда достаточно подсунуть свой сертификат.
2. **Не проверяется challenge.** Без сверки nonce атакующий переиспользует чужой валидный
   сертификат (replay).
3. **Не проверяется securityLevel.** Сертификат с `Software` проходит как аппаратный.
4. **Не проверяется отпечаток приложения.** Ключ валиден, но сгенерирован в другом
   приложении.

Каждая из этих ошибок делает всю конструкцию бессмысленной.

## Шаг 4: как обходят

На рутованном устройстве с инструментами вроде Magisk + специализированных модулей можно
подменить результат аттестации: хук на уровне Keystore/провайдера возвращает сертификат,
сгенерированный с «правильными» утверждениями, либо перехватывает challenge и подставляет
заранее подготовленную цепочку. Если сервер не сверяет challenge или корень, обход проходит.

На эмуляторах цепочка вообще может отсутствовать или быть поддельной — это отдельный признак
для сервера.

## Шаг 5: как проверить на устройстве

Практические шаги:

```bash
$ adb shell pm list packages | grep -i attest
$ adb shell dumpsys keystore2 | head
```

Затем перехватить сетевой запрос с challenge и посмотреть, что именно отправляет приложение
и что проверяет сервер. Если ответ сервера зависит только от факта наличия сертификата, а не
от его содержимого, — есть обход.

## Шаг 6: как аудировать

При пентесте:

1. Найти генерацию ключа с `setAttestationChallenge`.
2. Снять цепочку и проверить её расширения.
3. Понять, что именно валидирует сервер (по ответам и поведению).
4. Попробовать подменить цепочку/результат и посмотреть, примет ли сервер.

## Шаг 7: что писать в отчёте

Опишите: как приложение использует аттестацию, что проверяет сервер, какие проверки
отсутствуют, можно ли обойти и что это даёт атакующему. MITRE: Subvert Trust Controls /
Impair Defenses. Укажите рекомендации: сверять корень, challenge, securityLevel и отпечаток.

## Шаг 8: рекомендации

- Проверять полную цепочку до Google root на сервере.
- Всегда сверять challenge (nonce) и отклонять повтор.
- Требовать `attestationSecurityLevel` = TEE/StrongBox и `verifiedBootState` = Verified.
- Сверять отпечаток приложения и срок действия.

## Что мы теперь знаем

- Key Attestation — аппаратное доказательство происхождения ключа.
- Сертификат содержит securityLevel, verifiedBootState, challenge.
- Слабая серверная проверка (без корня/challenge) обходится.
- Аудит: найти генерацию с challenge → снять цепочку → проверить, что валидирует сервер.

## Квиз

Проверь себя.

''' + quiz([
    ('Что подтверждает Key Attestation?',
     ['Скорость устройства', 'Что ключ создан в аппаратном хранилище (TEE/StrongBox)',
      'Что приложение не содержит багов', 'Что сеть зашифрована'], 1,
     'Аттестация доказывает аппаратное происхождение ключа.'),
    ('Зачем нужен attestationChallenge?',
     ['Для сжатия сертификата', 'Как nonce против повторного использования чужой цепочки',
      'Для ускорения TLS', 'Для обновления приложения'], 1,
     'Challenge связывает ответ с конкретным запросом сервера.'),
    ('Какая серверная ошибка делает аттестацию бесполезной?',
     ['Проверка корня Google', 'Проверка challenge', 'Отсутствие проверки корня цепочки',
      'Проверка securityLevel'], 2,
     'Без проверки корня можно подсунуть самоподписанный сертификат.'),
    ('Что показывает поле verifiedBootState?',
     ['Версию Android', 'Состояние verified boot устройства',
      'Свободную память', 'Имя приложения'], 1,
     'Оно говорит, целостна ли загрузочная цепочка.'),
])

write_lesson(m, body, lab=lab(
    'Практика: разбор цепочки аттестации',
    ['task.md', 'attestation_chain.txt'],
    ['`attestation_chain.txt` — разбор расширений сертификата аттестации.',
     'Проверь securityLevel и verifiedBootState.',
     'В строке с признаком подделки — флаг `nto{...}`.'],
    'nto{k3y_4tt3st4t10n_sp00f}',
    [
        _dir(WD),
        _f(WD + '/task.md', '# Задача: аудит аттестации\n\nНайди слабое место проверки.\n'),
        _f(WD + '/attestation_chain.txt',
           'Certificate chain length: 3\n'
           'Subject: CN=Android Keystore Key\n'
           'Extension: attestationSecurityLevel = Software   # should be TEE/StrongBox\n'
           'Extension: verifiedBootState = Unverified\n'
           'Extension: attestationChallenge = (not checked by server)  # flag: nto{k3y_4tt3st4t10n_sp00f}\n'),
    ],
))

print('done')
