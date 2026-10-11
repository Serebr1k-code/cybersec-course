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
## Введение

Wear OS — Android для носимых устройств (часы). Приложения — обычные APK, но с ограничениями (маленький экран, батарея, сенсоры) и особыми механизмами синхронизации с телефоном. Поскольку часы часто содержат данные, синхронизируемые с телефоном (токены, сообщения, здоровье), ошибки в каналах связи и в обработке данных на часах дают находки. Этот урок — про структуру, коммуникацию и тестирование Wear OS.

Ментальная модель: Wear OS-приложение — «спутник» телефонного приложения. Они обмениваются данными через Data Layer API (Bluetooth/Wi-Fi), и граница доверия между устройствами — ключевая поверхность атаки.

## Структура Wear OS-приложения

```bash
# APK для часов объявляет feature
aapt dump xmltree wear.apk AndroidManifest.xml | grep -i "type.watch"
# uses-feature android.hardware.type.watch
# uses-library com.google.android.wearable
```

Особенности:
- `com.google.android.wearable` библиотека.
- Сервисы `WearableListenerService`, `MessageApi`, `DataClient`.
- Companion-приложение на телефоне (отдельный APK) с общим application id или связанный.

```bash
adb devices -l
adb shell pm list packages | grep -iE 'wear|watch'
adb shell dumpsys package com.target.wear | grep -iE 'permission|service'
```

## Data Layer API

Механизм синхронизации телефон↔часы:

- **DataClient** — синхронизируемые `DataItem` (ключ-значение).
- **MessageClient** — сообщения (одноразовые).
- **ChannelClient** — потоки (файлы).
- **CapabilityClient** — обнаружение узлов.

Данные хранятся в `Data Layer` и доступны приложениям с тем же application id/подписью. Уязвимость: если приложение пишет в Data Layer секреты (токены, ключи), их может прочитать любое приложение на часах с тем же id — либо перехватить на канале.

```bash
# посмотреть data items (на устройстве с инструментами)
adb shell dumpsys activity service com.google.android.gms/.wearable.service.WearableService
```

## Каналы связи и перехват

Связь телефон↔часы идёт по Bluetooth (часто BLE) или Wi-Fi. Тестирование:

- перехват BLE (см. `mobile-wearable-iot`), если данные не шифруются на уровне приложения;
- логирование Data Layer (Frida-хуки на `DataClient`/`MessageClient`);
- проверка, что секреты не передаются в открытом виде.

```javascript
// Frida: логировать putDataItem
Java.perform(function() {
  var DataClient = Java.use("com.google.android.gms.wearable.DataClient");
  // хуки зависят от версии GMS; логируем ключи/значения
});
```

## Полный сквозной пример: утечка токена через Data Layer

```bash
# 1. Ставим wear-приложение и companion на телефон
adb install wear.apk
# 2. Логируем синхронизацию
adb logcat | grep -iE 'wearable|datalayer|DataItem'
# 3. Находим запись токена в Data Layer
#    putDataItem /Token -> "eyJ..."
# 4. Проверяем, доступен ли он другим приложениям (capability/scope)
adb shell dumpsys activity service com.google.android.gms/.wearable.service.WearableService | grep -i token
```

Если токен пишется в Data Layer и доступен другим приложениям — находка (утечка через синхронизацию).

## Частые ошибки

- **Искать отдельную ОС**: Wear OS — это Android; те же техники.
- **Забыть companion-приложение**: уязвимость может быть на телефоне, а не на часах.
- **Не проверять Data Layer**: там часто лежат секреты.
- **Игнорировать Bluetooth**: BLE-перехват может вскрыть незашифрованный канал.
- **Тестировать без часов**: нужен эмулятор Wear или реальные часы.
- **Не проверять подпись/scope**: Data Layer ограничен подписью/id.

## Что дальше / решение

Проверяйте: что синхронизируется, шифруется ли канал, доступны ли данные другим приложениям. Свяжите с `mobile-wearable-iot` (IoT/Bluetooth), `mobile-insecure-storage`. Дальше — `mobile-banking-trojan`. Рекомендация: Wear OS-эмулятор + Frida-хуки на Data Layer.

## Справочная таблица

| API | Назначение |
|-----|-----------|
| DataClient | синхронизация ключ-значение |
| MessageClient | сообщения |
| ChannelClient | потоки/файлы |
| CapabilityClient | обнаружение узлов |

| Проверка | Команда |
|----------|---------|
| Wear-пакеты | `pm list packages \| grep wear` |
| Feature | `aapt dump xmltree` |
| Сервис | `dumpsys ... WearableService` |

## Полный разбор Wear OS-приложения

Разберём типовое приложение «часы + телефон» и его данные.

**Шаг 1. Идентификация.**

```bash
aapt dump xmltree wear.apk AndroidManifest.xml | grep -iE 'uses-feature|wearable|package'
# package="com.target.wear", uses-feature android.hardware.type.watch
adb install wear.apk
adb shell pm list packages | grep -i wear
```

**Шаг 2. Компоненты и сервисы.**

```bash
adb shell dumpsys package com.target.wear | grep -iE 'service|permission|exported'
# ищем WearableListenerService
grep -rn "WearableListenerService\|MessageClient\|DataClient" out/ | head
```

**Шаг 3. Data Layer — что синхронизируется.**

```bash
adb logcat | grep -iE 'wearable|DataItem|putDataItem|MessageClient'
# на телефонной стороне
adb shell dumpsys activity service com.google.android.gms/.wearable.service.WearableService | head -50
```

Ищем ключи, которые приложение пишет: `token`, `session`, `config`. Если там секреты — находка.

**Шаг 4. Перехват через Frida.**

```javascript
Java.perform(function() {
  try {
    var DataClient = Java.use("com.google.android.gms.wearable.DataClient");
    // методы зависят от версии GMS; логируем putDataItem/putDataItemAsync
  } catch (e) {}
  var Log = Java.use("android.util.Log");
  Log.d.overload("java.lang.String","java.lang.String").implementation = function(t,m){
    if (/token|session|secret/i.test(m)) console.log("[log] "+t+": "+m);
    return this.d(t,m);
  };
});
```

**Шаг 5. Проверка канала.** Если синхронизация идёт по BLE и данные не шифруются на уровне приложения, перехват возможен (см. `mobile-wearable-iot`). Проверьте, использует ли приложение шифрование поверх Data Layer.

## Companion-приложение и общий application id

Часто уязвимость на телефонной стороне. Проверьте:

```bash
adb shell pm list packages | grep -i target
adb shell dumpsys package com.target.phone | grep -iE 'permission|exported|provider'
```

Если companion экспортирует provider/service и обменивается данными с часами без проверки — это вход. Общий application id/подпись означает, что Data Layer доступен обоим; проверьте, не читает ли часовое приложение данные, которые не должно.

## Типичные находки Wear OS

| Находка | Severity | Почему |
|---------|----------|--------|
| Секреты в Data Layer | High | доступны другим приложениям с тем же id |
| Незашифрованный BLE | Medium | перехват канала |
| Экспортированный companion-компонент | High | вход в приложение |
| Токены в логах | Medium | утечка |
| Отсутствие проверки подписи Data Layer | Medium | подмена данных |

## Методический чек-лист

1. Определить wear-приложение и companion.
2. Перечислить компоненты и сервисы обоих.
3. Зафиксировать, что синхронизируется через Data Layer.
4. Проверить шифрование канала и доступность данных.
5. Построить PoC утечки/подмены.
6. Оформить рекомендации.

## Рекомендации в отчёте

- Не синхронизировать секреты через Data Layer; хранить их в защищённом хранилище на устройстве.
- Проверять подпись/application id при обмене данными.
- Шифровать чувствительные данные поверх канала.
- Минимизировать экспорт компонентов companion-приложения.
- Не логировать токены и ПДн.

## Тестирование канала Wear OS

Связь телефон↔часы идёт по Bluetooth (часто BLE) или Wi-Fi. Если приложение передаёт данные в открытом виде, канал можно перехватить. Для BLE используйте аппаратный сниффер (nRF Sniffer, Ubertooth) или встроенный HCI snoop log Android:

```bash
# включить Bluetooth HCI snoop log в developer options
adb bugreport ./bugreport.zip
# внутри — btsnoop_hci.log, открывается в Wireshark
unzip bugreport.zip
tshark -r btsnoop_hci.log | head
```

Так вы видите BLE-трафик. Если данные шифруются на уровне приложения (что правильно), перехват даст шифротекст — тогда переходите к хукам на стороне приложения.

## Data Layer: детальный анализ

Data Layer хранит данные в аккаунте Google и синхронизирует их между устройствами с тем же application id. Это значит, что любое приложение на часах с тем же id (или скомпрометированное) может читать данные. Проверяйте, что именно пишется: `DataMap` с ключами, `Asset` с файлами. Если там токены — находка. Хукайте `DataClient.putDataItem` и логируйте содержимое.

## Companion и общие ресурсы

Wear-приложение и телефонное часто делят общий модуль (shared). Уязвимость в общем модуле влияет на оба. Проверяйте оба APK. Общие ресурсы (строки, конфиги) могут содержать секреты, которые попадают на часы, где защита слабее.

## Рекомендации

Не синхронизировать секреты, шифровать чувствительные данные поверх канала, проверять подпись/application id, минимизировать данные на часах. Wear OS — расширение поверхности: данные, доступные на телефоне, могут быть менее защищены на часах.

## Практикум: перехват Data Layer

Разберём, как увидеть, что синхронизируется между телефоном и часами.

Шаг 1. Устанавливаем wear-приложение и companion. Подключаем часы (эмулятор Wear или реальные).

Шаг 2. Логируем:

```bash
adb logcat | grep -iE 'wearable|DataItem|putDataItem|MessageClient|DataMap'
```

Шаг 3. Ищем секреты в синхронизации:

```bash
adb logcat | grep -iE 'token|session|secret|password' | head
```

Если приложение пишет токен в Data Layer, он будет в логах (при debug) или в хуке.

Шаг 4. Хук через Frida на стороне GMS:

```javascript
Java.perform(function() {
  try {
    var Log = Java.use("android.util.Log");
    Log.d.overload("java.lang.String","java.lang.String").implementation = function(t,m){
      if (/token|session/i.test(m)) console.log("[sync] "+t+": "+m);
      return this.d(t,m);
    };
  } catch(e) {}
});
```

Шаг 5. Проверяем доступность данных. Data Layer ограничен application id/подписью; если данные чувствительные и синхронизируются, это риск при компрометации любого приложения с тем же id.

## BLE-канал

Если данные идут по BLE, включите HCI snoop log, снимите bugreport, откройте `btsnoop_hci.log` в Wireshark. Незашифрованный канал — находка.

## Что писать в отчёте

Какие данные синхронизируются, шифруется ли канал, доступны ли секреты другим приложениям. Рекомендация: не синхронизировать секреты, шифровать поверх канала, проверять подпись.

## Квиз

```quiz
- question: "Какой API синхронизирует данные между Wear OS и телефоном?"
  options:
    - "Data Layer API (DataClient)"
    - "Keychain API"
    - "NSC API"
    - "CarPropertyManager"
  answer: 0
- question: "Какая uses-feature указывает на приложение для часов?"
  options:
    - "android.hardware.type.watch"
    - "android.hardware.camera"
    - "android.software.leanback"
    - "android.hardware.bluetooth"
  answer: 0
- question: "Чем ограничен доступ к Data Layer?"
  options:
    - "Application id/подписью"
    - "IP-адресом"
    - "Паролем"
    - "Root"
  answer: 0
- question: "Где может быть уязвимость помимо часов?"
  options:
    - "В companion-приложении на телефоне"
    - "В head unit"
    - "В Keychain"
    - "В Manifest.db"
  answer: 0
- question: "Какая находка типична для Wear OS?"
  options:
    - "Секреты в Data Layer, доступные другим приложениям"
    - "Открытый SSH"
    - "Cleartext в NSC"
    - "Отсутствие подписи APK"
  answer: 0
```

## Где пригодится

- **Пентест носимых устройств:** новая поверхность.
- **Анализ платформ:** экосистема Android.
- **Bug bounty:** синхронизация секретов.
- **CTF:** Mobile/wearable-задачи.
