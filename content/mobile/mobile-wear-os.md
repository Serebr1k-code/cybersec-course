---
id: mobile-wear-os
title: "Wear OS: приложения, коммуникация и данные"
category: mobile
parent: mobile-emerging
difficulty: medium
order: 2
tags: [wear-os, wearable, data-layer, bluetooth, watch, apk, sync, android]
prerequisites: [mobile-intro, mobile-android-components]
useful_for:
  - "Пентест носимых устройств"
  - "Анализ мобильных платформ"
  - "Bug bounty"
estimated_minutes: 50
summary: "Безопасность Wear OS: структура приложений для часов, Data Layer API, каналы Bluetooth/Wi-Fi, утечки синхронизируемых данных и методика тестирования."
---
## Вопрос, с которого всё начинается

Смарт-часы на Wear OS синхронизируются с телефоном: сообщения, токены, данные о здоровье, настройки. Часто часы — это «уменьшенная копия» телефонного приложения, и то, что на телефоне спрятано за несколькими слоями защиты, на часах лежит проще. Где именно хранятся и передаются эти данные и как найти утечку? Чтобы ответить, надо понять, чем Wear-приложение отличается от обычного Android-приложения.

## Наш пример: учебный Wear-APK

Возьмём небольшой APK и превратим его в Wear-приложение, чтобы разобрать, из чего складывается «прописка» на часах. Итоговый файл — `wear.apk`. Сначала посмотрим, что вообще лежит внутри архива:

```
$ unzip -l wear.apk
Archive:  wear.apk
  Length      Date    Time    Name
---------  ---------- -----   ----
    22801  2026-10-12 16:17   res/mipmap-xxxhdpi/ic_launcher.png
     3044  2026-10-12 16:17   AndroidManifest.xml
     2836  2026-10-12 16:17   resources.arsc
     5488  2026-10-12 16:17   classes.dex
      500  2026-10-12 16:17   assets/google-services.json
---------                     -------
    65157                     11 files
```

Это обычный APK: манифест, ресурсы, код в `classes.dex` и файлы в `assets`. **Wear OS — это Android**, а не отдельная ОС, поэтому приложение для часов — такой же APK. Отличают его несколько записей в манифесте и способ общения с телефоном. Обрати внимание на `assets/google-services.json` — конфиг, который часто содержит ключи; он попадает на часы вместе с приложением.

## Шаг 1: что делает APK «приложением для часов»

Декодируем манифест:

```
$ java -jar apktool.jar d -f wear.apk -o wear
$ cat wear/AndroidManifest.xml
<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="owasp.mstg.uncrackable1">
    <application android:allowBackup="true" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
        <activity android:label="@string/app_name" android:name="sg.vantagepoint.uncrackable1.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <meta-data android:name="com.google.android.wearable.standalone" android:value="true"/>
        <service android:exported="true" android:name="com.example.uncrackable1.DataLayerListenerService">
            <intent-filter>
                <action android:name="com.google.android.gms.wearable.DATA_CHANGED"/>
                <data android:host="*" android:pathPrefix="/sync" android:scheme="wear"/>
            </intent-filter>
        </service>
    </application>
    <uses-feature android:name="android.hardware.type.watch" android:required="false"/>
    <uses-library android:name="com.google.android.wearable" android:required="false"/>
</manifest>
```

Разберём по строчкам:

- `<uses-feature android:name="android.hardware.type.watch"/>` — приложение рассчитано на **часы**. Это первый признак Wear-приложения.
- `<uses-library android:name="com.google.android.wearable"/>` — приложение использует библиотеку Wear, то есть механизмы связи с телефоном.
- `<meta-data android:name="com.google.android.wearable.standalone" android:value="true"/>` — приложение работает **самостоятельно**, без телефона.

Заметь: `android:required="false"` означает «не обязательно», поэтому такой APK может поставиться и на телефон. Именно поэтому нельзя определять Wear-приложение только по имени файла — надо читать манифест.

## Шаг 2: сервис, который слушает данные с телефона

Самое важное для безопасности — `<service ... name="...DataLayerListenerService">`. Это сервис, который принимает данные, приходящие с телефона, и объявлен **экспортированным** (`android:exported="true"`).

Экспортированный компонент — тот, к которому может обратиться другое приложение на том же устройстве. А `intent-filter` с action `com.google.android.gms.wearable.DATA_CHANGED` означает: сервис подписан на события изменения данных в **Data Layer** (о нём ниже). Схема `scheme="wear"` и `pathPrefix="/sync"` показывают, какой именно путь данных его интересует.

Ключевой вопрос тестировщика: проверяет ли сервис, *кто* прислал данные? Если сервис доверяет любому сообщению, пришедшему по этому пути, злоумышленник может подделать данные.

## Шаг 3: Data Layer API

**Data Layer API** — механизм синхронизации между телефоном и часами через сервисы Google Play. Он состоит из нескольких частей:

- **DataClient** — синхронизируемые пары «ключ → значение» (`DataItem`).
- **MessageClient** — одноразовые сообщения.
- **ChannelClient** — потоки и файлы.
- **CapabilityClient** — обнаружение узлов (какие устройства доступны).

Данные Data Layer хранятся в аккаунте Google и доступны приложениям с тем же **application id** (именем пакета) и подписью. Отсюда типичная утечка: приложение кладёт в Data Layer токен или ключ, а его же модуль на часах (или скомпрометированное приложение с тем же id) читает эти данные. На часах защита слабее, чем на телефоне, — и секрет «протекает» туда.

Как посмотреть, что синхронизируется:

```
$ adb shell dumpsys activity service com.google.android.gms/.wearable.service.WearableService | head -50
```

Эта команда выводит состояние службы Wear в Google Play Services. В выводе ищут ключи, которые приложение записывает: `token`, `session`, `config`. Если там секреты — это находка.

Динамически то же самое удобнее ловить через Frida — это инструмент, который внедряется в процесс приложения и перехватывает вызовы. Хукаем отправку данных и логирование:

```javascript
Java.perform(function() {
  var Log = Java.use("android.util.Log");
  Log.d.overload("java.lang.String", "java.lang.String").implementation = function(t, m) {
    if (/token|session|secret/i.test(m)) console.log("[sync] " + t + ": " + m);
    return this.d(t, m);
  };
});
```

Если в лог приложения попадает токен, он же может попасть и в Data Layer — а оттуда на часы.

## Шаг 4: companion-приложение

Wear-приложение почти всегда идёт в паре с **companion-приложением** на телефоне: часы — это «спутник», основная логика на телефоне. Уязвимость может быть именно на телефонной стороне. Проверяем оба пакета:

```
$ adb shell pm list packages | grep -i target
$ adb shell dumpsys package com.target.phone | grep -iE 'permission|exported|provider'
```

Если companion экспортирует провайдер или сервис и обменивается данными с часами без проверки — это вход. Общий application id/подпись означает, что Data Layer доступен обоим; проверь, не читает ли часовое приложение то, что не должно.

## Шаг 5: проверяем, на чём тестировать

Прежде чем идти дальше, убедимся, что есть устройство:

```
$ adb devices -l
List of devices attached

```

Пусто. Значит, нужно поднять эмулятор Wear OS (в Android Studio) или подключить реальные часы. Без устройства динамика недоступна, и остаётся статика.

Когда устройство есть, смотрят логи синхронизации и канал:

```
$ adb logcat | grep -iE 'wearable|DataItem|putDataItem|MessageClient|token'
```

Если синхронизация идёт по Bluetooth, включи HCI snoop log, сними bugreport и открой `btsnoop_hci.log` в Wireshark (подробнее — в уроке про Bluetooth LE). Незашифрованный канал — находка.

## Если не сработало

Если в Data Layer ничего подозрительного не видно, не делай вывод «всё чисто» сразу. Возможны три причины. Первая: приложение синхронизирует не Data Layer, а собственный канал — например, шифрует данные и гоняет их по BLE или через облако производителя; тогда смотри сетевой трафик и Bluetooth. Вторая: данные лежат в защищённом хранилище на устройстве, а на часы передаётся только ссылка на них. Третья: ты смотришь на телефон, а интересное — на часах; проверь оба APK. И помни: если приложение использует `android:required="false"`, тот же APK ставится и на телефон, поэтому «часовой» код может выполняться и там.

## Что мы теперь знаем

1. Wear OS — это Android; приложение для часов — обычный APK, а не отдельный формат.
2. Wear-приложение выдаёт `uses-feature android.hardware.type.watch` и `uses-library com.google.android.wearable`.
3. Связь с телефоном идёт через Data Layer API: DataClient, MessageClient, ChannelClient, CapabilityClient.
4. Данные Data Layer доступны приложениям с тем же application id и подписью — здесь и утекают секреты.
5. Уязвимость часто не на часах, а в companion-приложении на телефоне.
6. Без устройства (эмулятор Wear или часы) динамический анализ недоступен.

## Квиз

Проверь себя.

```quiz
- question: "Какой API синхронизирует данные между Wear OS и телефоном?"
  options:
    - "Data Layer API (DataClient/MessageClient)"
    - "Keychain API"
    - "Network Security Config"
    - "CarPropertyManager"
  answer: 0
  explanation: "Data Layer связывает часы и телефон через сервисы Google Play."
- question: "Какая uses-feature указывает на приложение для часов?"
  options:
    - "android.hardware.type.watch"
    - "android.hardware.camera"
    - "android.software.leanback"
    - "android.hardware.bluetooth"
  answer: 0
  explanation: "Этот признак отличает Wear-приложение от обычного."
- question: "Чем ограничен доступ к Data Layer?"
  options:
    - "Application id и подписью приложения"
    - "IP-адресом"
    - "Паролем пользователя"
    - "Root-правами"
  answer: 0
  explanation: "Данные видны приложениям с тем же пакетом и подписью."
- question: "Где помимо часов часто находится уязвимость?"
  options:
    - "В companion-приложении на телефоне"
    - "В head unit"
    - "В Keychain"
    - "В Manifest.db"
  answer: 0
  explanation: "Основная логика обычно на телефоне, там и вход."
- question: "Что означает android:exported=true у сервиса?"
  options:
    - "К сервису может обратиться другое приложение на устройстве"
    - "Сервис работает только на часах"
    - "Сервис зашифрован"
    - "Сервис не имеет разрешений"
  answer: 0
  explanation: "Экспортированный компонент доступен снаружи своего приложения."
```

## Куда дальше

В следующем уроке мы расширим картину до всей экосистемы **wearable**: часы, телефон и облако производителя — и посмотрим, где в этой цепочке теряется привязка к устройству. А пока запомни главное: Wear-приложение — это обычный APK с признаками часов, а секреты утекают через Data Layer и companion-приложение.

## Где пригодится

- **Пентест носимых устройств:** новая поверхность с малым числом исследователей.
- **Анализ платформ:** понимание экосистемы Android.
- **Bug bounty:** синхронизация секретов через Data Layer.
- **CTF Mobile:** задачи про часы и companion-канал.
