---
id: mobile-adb-fastboot
title: "ADB и fastboot: атаки, эскалация и утечки"
category: mobile
parent: mobile-android-root
difficulty: medium
order: 1
tags: [adb, fastboot, android, debugging, backup, shell, escalation, usb]
prerequisites: [mobile-platforms]
useful_for:
  - "Пентест мобильных приложений"
  - "Bug bounty (debug-сборки)"
  - "Форензика (извлечение данных)"
estimated_minutes: 50
summary: "ADB как атакующий интерфейс: включённая отладка, `adb shell`, backup, content-провайдеры, fastboot и извлечение данных; как это используется в пентесте и что искать."
---

## Вопрос, с которого всё начинается

У тебя в руках телефон с установленным тестовым приложением, и по условиям задания к нему можно подключиться по USB. Это уже половина успеха: Android даёт разработчику штатный канал управления устройством — **ADB** (Android Debug Bridge, «отладочный мост»). Через него можно выполнять команды на телефоне, читать логи и вытаскивать данные приложения.

Как из «подключён по USB» превратиться в «читаю приватные файлы приложения»?

## Наш пример: fdroid.apk

Возьмём реальное приложение — `fdroid.apk` (клиент каталога F-Droid). Сначала посмотрим, что оно о себе заявляет, ещё не трогая телефон. APK — это ZIP-архив, а манифест внутри него сжат в бинарный формат. Декодируем его тем же `apktool`, что и раньше:

```
$ java -jar apktool.jar d -f -s -o fdroid_src fdroid.apk
I: Copying original files...
```

Ключ `-s` означает «не декодировать `classes.dex`» — манифест декодируется в любом случае. Откроем `fdroid_src/AndroidManifest.xml` и посмотрим на тег `<application>`:

```xml
<application android:allowBackup="true"
             android:usesCleartextTraffic="true"
             android:networkSecurityConfig="@xml/network_security_config"
             android:name="org.fdroid.App" ...>
```

Два атрибута сразу важны для нас. `android:allowBackup="true"` разрешает системе делать резервную копию данных приложения — значит, часть данных можно вытащить **без root**. `android:usesCleartextTraffic="true"` разрешает незашифрованный HTTP — при перехвате трафика это упрощает жизнь.

## Шаг 1: проверяем сам канал ADB

ADB — это клиент-сервер: на компьютере работает `adb`, на телефоне — демон `adbd`. Прежде чем что-то делать, убедимся, что связь есть:

```
$ adb devices -l
List of devices attached
```

Пусто — типичная ситуация. Это значит, что либо на телефоне не включена **USB-отладка** (Developer options → USB debugging), либо устройство не подтвердило наш ключ. ADB использует аутентификацию по ключу: при первом подключении телефон показывает диалог «Allow USB debugging?», и без нажатия «Allow» список остаётся пустым. Проверим версии:

```
$ adb version
Android Debug Bridge version 1.0.41
Version 37.0.0-14910828
```

После подтверждения устройство появится, и мы получим shell на телефоне:

```
$ adb shell id
uid=2000(shell) gid=2000(shell) context=u:r:shell:s0
```

Обрати внимание: пользователь `shell`, а не `root`. Обычный ADB даёт права непривилегированного отладчика. Но даже этого хватает для многого.

## Шаг 2: смотрим свойства сборки

Свойства (`prop`) — это пары «ключ-значение», которые описывают сборку. Две из них — маркеры «инженерных» сборок:

```
$ adb shell getprop ro.debuggable
0
$ adb shell getprop ro.secure
1
```

`ro.debuggable=0` и `ro.secure=1` — это нормальная пользовательская (user) сборка. Если бы мы увидели `ro.debuggable=1`, то `adbd` мог бы работать от root, и `adb root` дал бы полный доступ без всякого эксплойта. Такие сборки встречаются в тестовых устройствах и кастомных прошивках — это находка сама по себе.

## Шаг 3: находим и вытаскиваем APK

Приложение установлено из APK, который лежит в системе. Найдём его путь:

```
$ adb shell pm list packages | grep fdroid
package:org.fdroid.fdroid
$ adb shell pm path org.fdroid.fdroid
package:/data/app/~~qK3...==/org.fdroid.fdroid-YY==/base.apk
```

Теперь можно скачать сам APK и работать с ним локально (jadx, apktool, поиск секретов):

```
$ adb pull /data/app/~~qK3...==/org.fdroid.fdroid-YY==/base.apk ./fdroid.apk
```

Это законный способ получить APK установленного приложения — не нужен сторонний магазин.

## Шаг 4: резервная копия — главный приз

Раз в манифесте `allowBackup="true"`, приложение разрешает бэкап. Команда `adb backup` просит систему собрать данные приложения в архив:

```
$ adb backup -f fdroid.ab -apk org.fdroid.fdroid
Now unlock your device and confirm the backup operation...
```

На экране телефона появляется диалог с паролем (можно оставить пустым) — снова требуется подтверждение пользователя. Полученный `fdroid.ab` — не обычный tar: это собственный формат ADB, распаковать его можно утилитой `abe.jar` (Android Backup Extractor):

```
$ java -jar abe.jar unpack fdroid.ab fdroid.tar
$ tar xf fdroid.tar && ls apps/org.fdroid.fdroid/
```

Внутри — `shared_prefs/`, `databases/`, `files/`. Именно здесь часто лежат токены сессий и настройки. Если бы `allowBackup="false"`, этот путь был бы закрыт.

## Шаг 5: content-провайдеры и dumpsys

Провайдеры (`content://`) — это способ отдавать данные другим приложениям. Если провайдер экспортирован, ADB может его опросить:

```
$ adb shell content query --uri content://org.fdroid.fdroid.provider/...
```

`dumpsys` — ещё один богатый источник: он показывает, что сейчас происходит в системе.

```
$ adb shell dumpsys activity activities | grep -i mResumedActivity
    mResumedActivity: ActivityRecord{... org.fdroid.fdroid/.views.main.MainActivity}
$ adb shell dumpsys package org.fdroid.fdroid | grep -A2 -i 'exported'
```

Из `dumpsys` видно активную activity, её extras, запущенные сервисы, разрешения. Это помогает понять, что делает приложение прямо сейчас.

## Шаг 6: fastboot — уровень выше ADB

ADB работает, когда система уже загрузилась. **Fastboot** — это протокол загрузчика (`bootloader`), работающий до старта Android. Переходим в него:

```
$ adb reboot bootloader
$ fastboot devices
XXXXXXXX    fastboot
$ fastboot getvar unlocked
unlocked: no
```

Если загрузчик разблокирован (`unlocked: yes`), можно прошить произвольный образ и получить root. На заблокированном устройстве большинство команд вернут `not allowed` — это защита, а не ошибка. Забегая вперёд: разблокировка загрузчика и root подробно разбираются в уроках `mobile-android-rooting` и `mobile-magisk-modules`.

## Шаг 7: беспроводная отладка

ADB умеет работать по сети. На Android 10 и ниже достаточно:

```
$ adb tcpip 5555
$ adb connect 192.168.1.50:5555
connected to 192.168.1.50:5555
```

После этого порт `5555` остаётся открытым — и любой в той же сети, кто знает IP, может подключиться, если устройство уже авторизовало ключ. На Android 11+ включили **pairing**: без одноразового кода по TCP подключиться нельзя.

```
$ adb pair 192.168.1.50:37000      # вводим 6-значный код с экрана
$ adb connect 192.168.1.50:5555
```

Проверить снаружи, не торчит ли порт, можно обычным сканером:

```
$ nmap -p 5555 192.168.1.50
5555/tcp open  adb
```

Это классическая находка при аудите корпоративных устройств.

## Что мы теперь знаем

- ADB — штатный канал разработчика; он даёт shell, чтение логов, установку/снятие APK и бэкап.
- `allowBackup="true"` в манифесте = путь к данным приложения без root.
- `run-as` и `ro.debuggable=1` дают доступ к песочнице приложения без root.
- `dumpsys` и `content` — недооценённые источники данных.
- Fastboot работает до загрузки ОС; на заблокированном загрузчике он безопасен для владельца.
- Wireless debugging без pairing (Android ≤10) — реальная сетевая находка.

## Квиз

Проверь себя.

```quiz
- question: Какой атрибут манифеста разрешает извлечь данные приложения через `adb backup`?
  options:
    - "android:debuggable"
    - "android:allowBackup"
    - "android:usesCleartextTraffic"
    - "android:exported"
  answer: 1
  explanation: "allowBackup=true разрешает системный бэкап данных приложения без root."
- question: Что означает `ro.debuggable=1`?
  options:
    - "Приложение помечено debuggable"
    - "adbd может работать от root, `adb root` даст полный доступ"
    - "Устройство разблокировано"
    - "Включена беспроводная отладка"
  answer: 1
  explanation: "Это маркер инженерной сборки: демон ADB может стать root без эксплойта."
- question: Какая команда показывает путь к APK установленного приложения?
  options:
    - "adb shell ls"
    - "adb shell pm path <pkg>"
    - "adb shell dumpsys apk"
    - "adb pull <pkg>"
  answer: 1
  explanation: "pm path возвращает путь к base.apk внутри /data/app."
- question: Почему на Android 11+ нельзя просто сделать `adb connect`?
  options:
    - "ADB удалён из Android"
    - "Нужен одноразовый pairing-код с экрана устройства"
    - "Порт 5555 закрыт навсегда"
    - "Нужен root"
  answer: 1
  explanation: "Wireless debugging требует pairing — защита от подключения по TCP без физического доступа."
- question: Что делает `fastboot getvar unlocked`?
  options:
    - "Разблокирует загрузчик"
    - "Показывает статус разблокировки загрузчика"
    - "Стирает данные"
    - "Загружает Android"
  answer: 1
  explanation: "Это read-only проверка; сама разблокировка — отдельная команда, стирающая данные."
```

## Куда дальше

Мы научились вытаскивать APK и данные через ADB. Но что делать, если приложение **защищено** — например, проверяет, не изменён ли код, или требует доверенный CA-сертификат? Для этого нужен root. В следующем уроке мы разберём, как устроен root на Android и как его получить легально на своём устройстве. А пока главное запомни: ADB — это не «дыра», а штатный инструмент, и его безопасность целиком зависит от того, включена ли отладка и подтверждён ли ключ.

## Где пригодится

- **Пентест:** первичный доступ к данным приложения и его логам без root.
- **Bug bounty:** доказательство утечки данных из `allowBackup`-сборок.
- **Форензика:** логическое извлечение данных с устройства (ADB-дампы).
- **Аудит:** проверка, что в релизе отключены `debuggable` и `allowBackup`, а wireless debugging не оставлен открытым.
