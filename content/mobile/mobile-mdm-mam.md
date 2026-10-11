---
id: mobile-mdm-mam
title: "MDM и MAM: корпоративное управление мобильными устройствами"
category: mobile
parent: mobile-platform-integration
difficulty: hard
order: 3
tags: [mobile, mdm, mam, enterprise, work-profile, byod]
prerequisites: [mobile-android-components]
useful_for:
  - "Пентест: корпоративные приложения и BYOD"
  - "Работа: аудит мобильного контура предприятия"
estimated_minutes: 42
summary: "Как работают MDM и MAM, управляемые конфигурации, work profile и изоляция данных, что видит администратор, какие есть границы доверия и типовые ошибки корпоративной мобильной безопасности."
---

## Что такое MDM и MAM

**MDM (Mobile Device Management)** — управление устройствами целиком: администратор может навязывать пароль, шифрование, запрещать камеру, устанавливать приложения, удалённо стирать данные. **MAM (Mobile Application Management)** — управление конкретными приложениями без управления устройством: политики применяются к приложению (запрет копирования в личные приложения, требование PIN, шифрование данных приложения). В модели BYOD («принеси своё устройство») чаще используют MAM, чтобы не трогать личные данные сотрудника.

Технически на Android это реализуется через **DevicePolicyManager** и **work profile** (управляемый профиль). На iOS — через **MDM-протокол** (APNs-команды) и **managed app configuration** / **per-app VPN**. Приложение, получившее статус managed, читает конфигурацию из `RestrictionsManager` (Android) или `UserDefaults` с ключом `com.apple.configuration.managed` (iOS).

## Android: work profile и DPM

Work profile — это отдельный пользователь (`user 10`) с флагом managed. Приложения в нём изолированы: личные и рабочие данные разделены. Администратор (profile owner) управляет только рабочим профилем.

Проверка на устройстве:

```bash
adb shell dumpsys user | grep -i "UserInfo\|Managed"
adb shell dumpsys device_policy | head -50
adb shell pm list users
```

Что видит profile owner:
- список managed-приложений;
- политики пароля/шифрования;
- возможность `wipeData` только рабочего профиля;
- запрет камеры, скриншотов, Bluetooth, USB.

Что **не** видит: содержимое личных приложений и личных файлов (в норме).

## Android: managed configurations

Приложение получает конфигурацию от MDM:

```java
RestrictionsManager rm = (RestrictionsManager) getSystemService(Context.RESTRICTIONS_SERVICE);
Bundle appRestrictions = rm.getApplicationRestrictions();
String server = appRestrictions.getString("server_url");
boolean allowPaste = appRestrictions.getBoolean("allow_clipboard", true);
```

Проверить можно через `dumpsys` или установив `TestDPC` (Google) — референсный DPC для теста политик.

```bash
# посмотреть restrictions для приложения
adb shell dumpsys package com.example.corp | grep -A5 "Restrictions"
```

Ошибки: приложение игнорирует политику (`allow_clipboard=false`, но копирование работает) — находка, потому что конфиденциальные данные утекают в личные приложения.

## iOS: MDM-профиль и managed app config

MDM-профиль — это подписанный `.mobileconfig` (plist), который ставит политики. Для приложения важна секция `com.apple.configuration.managed`:

```xml
<key>com.apple.configuration.managed</key>
<dict>
  <key>server_url</key><string>https://corp.example.com</string>
  <key>require_pin</key><true/>
</dict>
```

Приложение читает:

```swift
let config = UserDefaults.standard.dictionary(forKey: "com.apple.configuration.managed")
```

Проверка managed-статуса:

```swift
if #available(iOS 13.0, *) {
    let managed = FileManager.default.ubiquityIdentityToken // не то
}
// правильнее — через MDM-флаг в UserDefaults или MCProfile
```

## Границы доверия и атаки

Корпоративный контур интересен тем, что приложение доверяет конфигурации от MDM, а MDM доверяет устройству. Точки атаки:

- **Подделка managed config** — если приложение читает конфиг из незащищённого места, можно подсунуть свои значения (например, `server_url` на атакующий сервер).
- **Побег из work profile** — данные рабочего приложения утекают в личное через общий storage, буфер обмена, intent'ы.
- **Обход политики копирования** — приложение не проверяет `allow_clipboard`.
- **Root/jailbreak на managed устройстве** — ломает всю модель (MDM может детектить, но не всегда).
- **Перехват MDM-коммуникации** — если канал к серверу MDM слабо защищён.

## Проверка изоляции work profile

Практические тесты:

```bash
# 1) может ли рабочее приложение читать личные файлы? (должно быть нет)
adb shell run-as com.example.corp ls /sdcard/   # доступ к внешнему хранилищу
# 2) общий буфер обмена между профилями
# скопировать в рабочем, вставить в личном приложении — должно быть запрещено
# 3) shared intent между профилями
adb shell am start --user 0 -a android.intent.action.SEND ...
```

На Android 11+ есть **cross-profile** ограничения: приложения из разных профилей не видят друг друга напрямую. Проверяйте, не выставлены ли у корпоративного приложения избыточные разрешения (`MANAGE_EXTERNAL_STORAGE`, `QUERY_ALL_PACKAGES`).

## DPC и Device Owner

Кроме profile owner есть **device owner** — управляет всем устройством (обычно корпоративные «выданные» телефоны). Он может: запретить factory reset, навязать Wi-Fi, установить системные сертификаты. Для теста:

```bash
# установить TestDPC как device owner (на чистом устройстве)
adb shell dpm set-device-owner com.afwsamples.testdpc/.DeviceAdminReceiver
adb shell dpm set-profile-owner --user 10 com.afwsamples.testdpc/.DeviceAdminReceiver
```

С device owner вы можете воспроизвести корпоративные политики и проверить, как приложение на них реагирует.

## Частые ошибки и подводные камни

- **Тест на личном профиле** — многие проверки работают только в managed-профиле; настраивайте TestDPC.
- **`dumpsys` без прав** — часть данных требует root или DPC.
- **Профиль не создаётся** — на устройстве уже есть managed profile; удалите старый.
- **Политики не применяются** — приложение кеширует конфиг при первом запуске.
- **Ложные срабатывания** — некоторые OEM по-своему реализуют изоляцию.

## Справочная таблица

| Понятие | Android | iOS |
|---------|---------|-----|
| Управление устройством | device owner / DPM | MDM-профиль |
| Управление приложением | managed config (RestrictionsManager) | managed app config |
| Изоляция | work profile | managed apps + per-app VPN |
| Стирание | wipeData (профиль/устройство) | remote wipe |
| Политики | Password, Camera, Clipboard | restrictions payload |

## Что дальше / решение

Настройте тестовую среду с TestDPC, создайте work profile, задайте managed config и проверьте, как приложение читает и соблюдает политики. Ищите: подделку конфига, обход clipboard/camera-политики, утечки между профилями. Дальше — `mobile-app-cloning` (изоляция данных) и `mobile-data-leakage`.

## Практическая настройка TestDPC

TestDPC — референсный DPC от Google, который позволяет воспроизвести любую корпоративную политику. Установка:

```bash
# скачать TestDPC (com.afwsamples.testdpc) из Play или APK
adb install TestDPC.apk
# назначить как profile owner для нового пользователя
adb shell pm create-user CorpUser
adb shell dpm set-profile-owner --user 10 com.afwsamples.testdpc/.DeviceAdminReceiver
# или как device owner на чистом устройстве (до добавления аккаунтов!)
adb shell dpm set-device-owner com.afwsamples.testdpc/.DeviceAdminReceiver
```

После этого в TestDPC доступны все политики: пароль, шифрование, камера, буфер обмена, managed configurations. Задайте `allow_clipboard=false` и проверьте, соблюдает ли целевое приложение это ограничение. Если копирование всё равно работает — приложение игнорирует политику, и конфиденциальные данные могут утечь в личные приложения.

## Managed configurations: end-to-end проверка

Чтобы приложение получило конфигурацию, её нужно задать через DPC:

```bash
# TestDPC: Manage app restrictions -> выбрать приложение -> задать ключи
# либо через am (не всегда работает для restrictions)
adb shell dumpsys restrictions | grep -A10 com.example.corp
```

В приложении конфигурация читается через `RestrictionsManager`. Проверьте в Frida, какие значения реально пришли:

```javascript
Java.perform(function () {
  var RM = Java.use("android.content.RestrictionsManager");
  RM.getApplicationRestrictions.implementation = function () {
    var b = this.getApplicationRestrictions();
    console.log("[restrictions] " + b.toString());
    return b;
  };
});
```

Если приложение читает `server_url` из restrictions и ходит на него — попробуйте подменить значение на свой сервер. Если приложение не проверяет источник конфига или доверяет любому URL без pinning — возможен перехват трафика корпоративных данных.

## iOS: установка MDM-профиля и проверка

`.mobileconfig` можно поставить вручную на устройство (Settings > Profile Downloaded) или через MDM. Для теста удобно подготовить профиль с managed app config:

```bash
# подписать профиль (для реальной установки требуется подпись/шифрование)
openssl smime -sign -signer cert.pem -inkey key.pem \
  -nodetach -outform der -in profile.mobileconfig -out profile-signed.mobileconfig
# установить на устройство
# Settings -> General -> VPN & Device Management -> Install
```

Приложение читает config так:

```swift
if let managed = UserDefaults.standard.dictionary(forKey: "com.apple.configuration.managed") {
    let server = managed["server_url"] as? String
}
```

Проверьте, что приложение не принимает конфиг извне (например, через URL scheme или файл), иначе атакующий подменит `server_url`.

## Изоляция данных: что реально проверять

Модель MDM/MAM обещает изоляцию, но реализация зависит от ОС и приложения. Тестируйте:

- **Буфер обмена:** скопировать в рабочем приложении, вставить в личном — должно блокироваться.
- **Общий storage:** пишет ли рабочее приложение в `/sdcard/` (виден личным).
- **Intent/sharing:** можно ли поделиться рабочим файлом в личное приложение.
- **Скриншоты:** запрещены ли на рабочих экранах.
- **Backup:** попадают ли рабочие данные в adb backup/iCloud.
- **Логи:** не пишет ли приложение корпоративные данные в logcat.

```bash
adb logcat | grep -i "com.example.corp" | grep -iE "token|password|http"
```

Утечка токена в логи на managed-устройстве — серьёзная находка, потому что логи может читать другое приложение или сборщик диагностики.

## Корпоративные сертификаты и Wi-Fi

MDM часто разворачивает корпоративный Wi-Fi с сертификатом и per-app VPN. Проверьте:

- Корректно ли валидируется сертификат сервера (нет ли отключённой проверки).
- Изолирован ли VPN-туннель (не утекает ли трафик вне туннеля — VPN leak).
- Доступны ли корпоративные ресурсы без аутентификации внутри периметра.

Эти проверки выходят за рамки APK, но именно они определяют реальную защищённость корпоративного мобильного контура.

## Квиз

```quiz
- question: "Чем MAM отличается от MDM?"
  options:
    - "MAM управляет приложениями, MDM — устройством целиком"
    - "MAM работает только на iOS"
    - "MDM не требует интернета"
    - "MAM шифрует диск"
  answer: 0
- question: "Как на Android изолируются рабочие данные?"
  options:
    - "Через work profile — отдельный пользователь с управляемым профилем"
    - "Через отдельный APK"
    - "Через VPN"
    - "Через SharedPreferences"
  answer: 0
- question: "Откуда Android-приложение читает managed-конфигурацию?"
  options:
    - "RestrictionsManager.getApplicationRestrictions()"
    - "BuildConfig"
    - "AndroidManifest.xml"
    - "/proc/self/environ"
  answer: 0
- question: "Какой инструмент позволяет воспроизвести корпоративные политики для теста?"
  options:
    - "TestDPC (dpm set-profile-owner/device-owner)"
    - "sqlmap"
    - "nmap"
    - "apktool"
  answer: 0
```

## Где пригодится

- **Пентест:** аудит корпоративных приложений и BYOD-контура.
- **Работа:** настройка и проверка MDM/MAM-политик.
- **Bug bounty:** обход политик копирования и утечки между профилями.
