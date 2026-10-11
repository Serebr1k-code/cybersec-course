---
id: mobile-universal-links
title: "Universal Links и App Links: ассоциация домена и перехват ссылок"
category: mobile
parent: mobile-advanced-ios
difficulty: hard
order: 2
tags: [mobile, ios, android, deeplink, universal-links, applinks]
prerequisites: [mobile-deeplink-deep]
useful_for:
  - "CTF Mobile: перехват и подмена ссылок"
  - "Bug bounty: open redirect и кража токенов"
estimated_minutes: 42
summary: "Как работают Universal Links (iOS) и App Links (Android), проверка ассоциации домена, типовые ошибки конфигурации, перехват и подмена ссылок, кража OAuth-кода через редирект."
---

## Чем Universal Links отличаются от custom scheme

Custom URL scheme (`myapp://path`) — это произвольная схема, которую приложение регистрирует. Проблема: схему может зарегистрировать **любое** приложение, и система не знает, какое настоящее. Universal Links (iOS) и App Links (Android) решают это: они привязывают обычные `https://` ссылки к приложению через файл ассоциации на домене. Если ссылка `https://example.com/product/42` открывается — система сначала проверит, ассоциировано ли приложение с `example.com`, и только потом откроет приложение, иначе — браузер.

Это важное отличие для безопасности: Universal Links нельзя перехватить чужим приложением, если ассоциация настроена корректно. Но ассоциация настраивается на **сервере** (домене), и ошибки там приводят к тому, что защита не работает.

## iOS: apple-app-site-association (AASA)

iOS забирает файл `https://example.com/.well-known/apple-app-site-association` (без расширения, `Content-Type: application/json`). Формат:

```json
{
  "applinks": {
    "apps": [],
    "details": [
      {
        "appIDs": ["TEAMID.com.example.app"],
        "components": [
          { "/": "/product/*", "comment": "product pages" },
          { "/": "/oauth/*" }
        ]
      }
    ]
  }
}
```

Проверка на стороне iOS:
1. При установке приложения iOS скачивает AASA (по HTTPS, без редиректов).
2. Сопоставляет `appIDs` с entitlements приложения (`associated-domains`).
3. Регистрирует соответствие домен↔приложение.
4. При открытии ссылки — отдаёт её приложению, если домен ассоциирован.

Entitlements приложения:

```xml
<key>com.apple.developer.associated-domains</key>
<array>
  <string>applinks:example.com</string>
</array>
```

Проверяем: `codesign -d --entitlements :- MyApp`.

## Android: App Links и assetlinks.json

Android использует `https://example.com/.well-known/assetlinks.json`:

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.app",
    "sha256_cert_fingerprints": [
      "AA:BB:CC:...:FF"
    ]
  }
}]
```

В `AndroidManifest.xml` intent-filter должен иметь `android:autoVerify="true"`:

```xml
<intent-filter android:autoVerify="true">
  <action android:name="android.intent.action.VIEW"/>
  <category android:name="android.intent.category.DEFAULT"/>
  <category android:name="android.intent.category.BROWSABLE"/>
  <data android:scheme="https" android:host="example.com" android:pathPrefix="/product"/>
</intent-filter>
```

Проверка ассоциации на устройстве:

```bash
adb shell pm get-app-links com.example.app
# com.example.app:
#   User 0:
#     https://example.com: verified
```

## Типовые ошибки конфигурации

- **AASA отдаётся с редиректом** — iOS не следует редиректам при скачивании, ассоциация не встанет.
- **Неверный Content-Type** — файл должен быть `application/json`.
- **Пропущены `components`** — старая форма `paths` работает, но менее гибкая.
- **assetlinks с устаревшим отпечатком** — после смены ключа подписи ассоциация ломается.
- **`autoVerify` отсутствует** — ссылка открывается в диалоге выбора, а не сразу.
- **Домен в `associated-domains` не совпадает** с доменом в AASA.
- **Ссылка ведёт на чужой домен** — приложение обрабатывает URL без проверки хоста.

## Перехват и подмена

Даже корректная ассоциация не спасает, если приложение доверяет параметрам ссылки. Основные векторы:

1. **Open redirect на ассоциированном домене.** Если `https://example.com/r?url=https://evil.com` делает редирект, злоумышленник может провести пользователя через доверенный домен.
2. **Обработка произвольного URL.** Приложение берёт `target` из ссылки и грузит его в WebView — классический путь к XSS/краже токена.
3. **Подмена custom scheme fallback.** Если приложение поддерживает и `myapp://`, и Universal Link, а custom scheme перехватывается, fallback открывает дыру.
4. **Path traversal в маршрутизации.** `/product/../../admin` может обойти проверки путей.

Проверка на устройстве:

```bash
# iOS Simulator: открыть ссылку
xcrun simctl openurl booted "https://example.com/product/../../admin"
# Android
adb shell am start -a android.intent.action.VIEW \
  -d "https://example.com/product/../../admin" com.example.app
```

## Кража OAuth-кода через редирект

Самый ценный сценарий. OAuth-поток на мобильном использует `redirect_uri`. Если это custom scheme (`myapp://oauth`) — его может перехватить другое приложение. Если Universal Link (`https://example.com/oauth`) — перехват сложнее, но:

- Если `redirect_uri` **не проверяется** на сервере строго, можно подставить свой.
- Если приложение открывает `redirect_uri` из ответа без валидации хоста — код утечёт.
- Если используется **implicit flow** (токен в fragment), он утекает в WebView/логи.

Проверьте:

```bash
# перехватить редирект через прокси и посмотреть redirect_uri
# убедиться, что code привязан к PKCE code_verifier
```

PKCE обязателен: без него перехваченный `code` можно обменять на токен. Проверяйте, что приложение отправляет `code_challenge` и `code_verifier`.

## Динамический анализ ссылок

Frida-хук на обработку открытия URL (iOS):

```javascript
// AppDelegate: application:openURL:options:
var AppDelegate = ObjC.classes.AppDelegate;
if (AppDelegate && AppDelegate['- application:openURL:options:']) {
  Interceptor.attach(AppDelegate['- application:openURL:options:'].implementation, {
    onEnter: function (args) {
      var url = new ObjC.Object(args[2]);
      console.log("[openURL] " + url.absoluteString().toString());
    }
  });
}
```

Android — хук `onNewIntent`/`getIntent().getData()`:

```javascript
Java.perform(function () {
  var Activity = Java.use("android.app.Activity");
  Activity.onNewIntent.implementation = function (intent) {
    console.log("[onNewIntent] data=" + intent.getData());
    return this.onNewIntent(intent);
  };
});
```

Так вы видите, какие ссылки реально приходят и как парсятся.

## Частые ошибки и подводные камни

- **AASA не кешируется сразу** — после правки может пройти время или нужна переустановка.
- **Симулятор iOS не проверяет ассоциацию строго** — тестируйте на устройстве.
- **Android может показать диалог выбора** — если несколько приложений претендуют на домен.
- **`assetlinks` по http** — не сработает, только https.
- **Ссылка без `pathPrefix`** перехватывает весь домен — риск.

## Справочная таблица

| Платформа | Файл ассоциации | Проверка | Manifest/entitlement |
|-----------|-----------------|----------|----------------------|
| iOS | /.well-known/apple-app-site-association | codesign entitlements | associated-domains |
| Android | /.well-known/assetlinks.json | pm get-app-links | intent-filter autoVerify |

## Что дальше / решение

Проверьте ассоциацию (AASA/assetlinks), затем — обработку параметров ссылки: open redirect, загрузку URL в WebView, path traversal, OAuth redirect_uri. Любая обработка URL без валидации хоста — находка. Дальше — `mobile-ios-oauth-sso` (OAuth/SSO) и `mobile-deeplink-rce` (RCE через deep link).

## Глубокая проверка ассоциации домена

Проверку ассоциации стоит делать по шагам, потому что ошибка может быть на любом из них.

Шаг 1 — доступность и формат файла:

```bash
curl -sI https://example.com/.well-known/apple-app-site-association
# HTTP/2 200, content-type: application/json
curl -s  https://example.com/.well-known/assetlinks.json | jq .
```

Шаг 2 — соответствие teamID/package:

```bash
# iOS: appID в AASA = TEAMID.bundle_id из entitlements
codesign -d --entitlements :- MyApp | grep -A2 application-identifier
# Android: fingerprint в assetlinks = SHA-256 подписи APK
keytool -printcert -jarfile app.apk | grep SHA256
```

Если отпечаток в `assetlinks.json` не совпадает с подписью установленного APK — ассоциация не встанет, и ссылки будут открываться в браузере (а значит, deep link не работает как задумано — иногда это находка сама по себе).

Шаг 3 — проверка на устройстве:

```bash
adb shell pm get-app-links --user 0 com.example.app
# если "verified" — ассоциация есть; если "none"/"disabled" — нет
```

## Атаки на маршрутизацию ссылок

Universal Links ведут на маршрутизатор приложения, который разбирает путь и решает, какой экран открыть. Ошибки в маршрутизации — главный источник уязвимостей.

- **Path traversal:** `https://example.com/product/../../admin` — если роутер нормализует не полностью, можно открыть привилегированный экран.
- **Подмена параметра:** `?url=https://evil.com` — если приложение грузит URL из параметра, получаем open redirect и потенциальный XSS в WebView.
- **Утечка токена в path:** `https://example.com/reset/TOKEN` — токен попадает в логи прокси, Referer, историю.
- **Case-sensitivity:** `/Admin` может не совпасть с проверкой `/admin`, но сервер обработает.

Пример проверки через adb:

```bash
for p in "product/../../admin" "product/%2e%2e%2fadmin" "product/..%2fadmin"; do
  echo "== $p"
  adb shell am start -a android.intent.action.VIEW \
    -d "https://example.com/$p" com.example.app
done
```

## Логирование, Referer и утечки

Universal Links — это ещё и канал утечки: URL может содержать токен или PII, а система логирует открытие. Проверяйте:

```bash
# iOS: смотреть логи открытия ссылок
xcrun simctl spawn booted log stream --predicate 'eventMessage CONTAINS "openURL"'
# Android: logcat по ActivityManager
adb logcat -s ActivityManager:I | grep -i "VIEW"
```

Если в логи попадает полный URL с токеном — это утечка. Также проверяйте, что `Referer` при переходе на внешние ресурсы не содержит чувствительный путь.

## Сравнение iOS и Android поведения

| Аспект | iOS (Universal Links) | Android (App Links) |
|--------|----------------------|---------------------|
| Файл | apple-app-site-association | assetlinks.json |
| Content-Type | application/json | application/json |
| Редиректы | не следуют | не следуют |
| Проверка | при установке | при установке / периодически |
| Отпечаток | teamID | SHA-256 сертификата |
| Fallback | браузер Safari | браузер / диалог |

Знание различий важно при кроссплатформенных приложениях: одна и та же ссылка может вести себя по-разному на двух платформах, и ошибка конфигурации на одной из них остаётся незамеченной.

## Итоговый чек-лист проверки ссылок

Практическая последовательность: получить файл ассоциации и убедиться в корректном Content-Type и отсутствии редиректов; сверить teamID или отпечаток сертификата с подписью приложения; проверить `autoVerify`/`associated-domains`; на устройстве подтвердить статус ассоциации; перебрать маршруты на path traversal и подмену параметров; проверить `redirect_uri` в OAuth-потоке; посмотреть логи и `Referer` на предмет утечки токенов. Любой шаг, который ломается, — кандидат в находку: либо нарушенная ассоциация (ссылка уходит в браузер), либо обработка URL без валидации хоста.

## Квиз

```quiz
- question: "Почему Universal Links безопаснее custom URL scheme?"
  options:
    - "Домен ассоциируется с приложением через файл на сервере, схему нельзя перехватить чужим приложением"
    - "Они шифруют трафик"
    - "Они работают без интернета"
    - "Они хранят пароли в Keychain"
  answer: 0
- question: "Какой файл проверяет iOS для ассоциации домена?"
  options:
    - "/.well-known/apple-app-site-association"
    - "/.well-known/assetlinks.json"
    - "/robots.txt"
    - "/manifest.json"
  answer: 0
- question: "Что делает атрибут autoVerify в Android intent-filter?"
  options:
    - "Заставляет Android проверить ассоциацию домена с приложением"
    - "Шифрует intent"
    - "Включает Bluetooth"
    - "Подписывает APK"
  answer: 0
- question: "Что критично для защиты OAuth-кода при мобильном редиректе?"
  options:
    - "PKCE (code_challenge/code_verifier) и строгая проверка redirect_uri"
    - "Публичный client_secret в APK"
    - "Отключение TLS"
    - "Длинный User-Agent"
  answer: 0
```

## Где пригодится

- **CTF:** задачи с перехватом ссылок и OAuth.
- **Bug bounty:** open redirect, кража токена через custom scheme.
- **Пентест:** аудит deep link / Universal Links конфигурации.
