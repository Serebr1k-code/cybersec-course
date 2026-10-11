---
id: mobile-app2app
title: "App-to-app атаки: intent spoofing, Custom Tabs и кража редиректов"
category: mobile
parent: mobile-api-security-deep
difficulty: hard
order: 4
tags: [mobile, android, ios, intent, custom-tabs, oauth, app2app]
prerequisites: [mobile-exported-components, mobile-intent-redirection]
useful_for:
  - "Bug bounty: перехват OAuth-редиректов и токенов"
  - "Пентест: взаимодействие приложений"
estimated_minutes: 45
summary: "Как приложения взаимодействуют друг с другом и где возникает доверие: intent spoofing, подмена результата Activity, Custom Tabs и перехват OAuth-редиректов, кража токенов между приложениями."
---

## Что такое app-to-app и почему это важно

Мобильные приложения редко работают в вакууме: они открывают браузер, делятся файлами, вызывают платёжные и авторизационные приложения, получают результат. Взаимодействие идёт через механизмы ОС: **intent'ы** (Android), **URL schemes и Universal Links** (обе платформы), **Custom Tabs / ASWebAuthenticationSession** (браузерный компонент). Каждый такой канал — это граница доверия: если приложение доверяет тому, кто ответит на его запрос, атакующий может ответить вместо легитимного приложения.

Классический пример — OAuth: приложение открывает браузер для авторизации, браузер редиректит на `redirect_uri`, приложение получает `code`. Если `redirect_uri` — custom scheme, другое приложение может зарегистрировать ту же схему и перехватить код.

## Intent spoofing: подмена отправителя

Android intent'ы бывают **явные** (с указанием компонента) и **неявные** (по action/category). Неявный intent может перехватить любое приложение, зарегистрировавшее фильтр. Если получатель доверяет отправителю (проверяет только action, но не package), атакующий может послать поддельный intent.

Пример уязвимости: приложение ожидает intent от своего же компонента, но принимает его от любого:

```java
// уязвимый приёмник
@Override
protected void onNewIntent(Intent intent) {
    if ("com.example.ACTION_PAY".equals(intent.getAction())) {
        String amount = intent.getStringExtra("amount");
        performPayment(amount);   // доверяем без проверки отправителя
    }
}
```

Атакующее приложение:

```java
Intent i = new Intent("com.example.ACTION_PAY");
i.putExtra("amount", "1000000");
i.setPackage("com.example.app");   // явная доставка
startActivity(i);
```

Защита — проверка отправителя через `getCallingActivity()`/`getCallingPackage()` и подпись:

```java
String caller = getCallingPackage();
if (caller == null || !verifySignature(caller, expectedSha256)) {
    return; // отклонить
}
```

## Кража результата Activity (result hijacking)

Если приложение вызывает `startActivityForResult` с **неявным** intent, результат (`setResult`) может прийти от любого приложения. Пример: приложение просит «выбрать фото» неявным intent'ом, а злоумышленник возвращает свой файл. Или приложение просит «подтвердить оплату» и получает фальшивое `RESULT_OK`.

```java
// уязвимо: неявный intent
Intent i = new Intent("com.example.ACTION_CONFIRM");
startActivityForResult(i, REQ_CONFIRM);
// onActivityResult примет результат от любого
```

Защита: явный intent с указанием компонента и проверка `getCallingActivity()` в получателе.

## Custom Tabs и OAuth-редирект

Android Custom Tabs — это системный браузер внутри приложения. Он безопаснее WebView, но `redirect_uri` остаётся слабым звеном. Если `redirect_uri=myapp://callback`, любое приложение может зарегистрировать `myapp` и получить `code`.

Проверка:

```bash
# найти redirect_uri в APK
grep -rn "redirect_uri\|oauth\|callback" out/sources | head
# посмотреть зарегистрированные схемы
adb shell dumpsys package com.example.app | grep -A20 "Schemes"
```

Атакующее приложение регистрирует схему и логирует входящий URL:

```xml
<intent-filter>
  <action android:name="android.intent.action.VIEW"/>
  <category android:name="android.intent.category.DEFAULT"/>
  <category android:name="android.intent.category.BROWSABLE"/>
  <data android:scheme="myapp" android:host="callback"/>
</intent-filter>
```

Если PKCE не enforced, перехваченный `code` обменивается на токен — захват аккаунта.

## App-to-app на iOS

На iOS аналогичные проблемы:
- **Custom URL schemes** (`myapp://`) — перехватываются другим приложением.
- **Universal Links** — безопаснее (ассоциация домена), но ошибки конфигурации ломают защиту.
- **`openURL:options:`** — приложение может открыть произвольный URL, если доверяет параметру.
- **Shared Keychain / App Groups** — если группа настроена слабо, другое приложение того же разработчика читает данные.

Проверка scheme hijack на iOS: зарегистрировать ту же схему в тестовом приложении и посмотреть, кто получит ссылку. Система отдаёт её непредсказуемо (зависит от порядка установки), что само по себе — проблема для безопасности.

## Практика: полный сценарий перехвата

1. Декомпилируйте жертву, найдите `redirect_uri` и PKCE.
2. Соберите приложение-ловушку с той же схемой.
3. Установите оба приложения.
4. Запустите OAuth-поток в жертве.
5. Перехватите callback в ловушке (`adb logcat`).
6. Обменяйте `code` (если нет PKCE).

```bash
adb install victim.apk trap.apk
adb logcat -s TrapApp:D | grep -i "callback\|code="
```

Если код пришёл в ловушку и обменялся — находка критична.

## Защитные меры

- Использовать **Universal Links / App Links** вместо custom scheme для `redirect_uri`.
- Обязательный **PKCE** (S256) и проверка `state`.
- **Проверять отправителя** intent'а (`getCallingPackage` + подпись).
- Для `startActivityForResult` — **явные intent'ы**.
- Не доверять данным из intent без валидации.
- На iOS — не использовать custom scheme для чувствительных редиректов.

## Частые ошибки и подводные камни

- **Проверка только action** — intent может послать кто угодно; проверяйте package и подпись.
- **`getCallingPackage` возвращает null** для неявных вызовов — это не защита.
- **Схема уже зарегистрирована** системным приложением — перехват сложнее, но возможен.
- **Custom Tabs vs WebView** — проверьте, что используется именно Custom Tabs.
- **iOS отдаёт scheme непредсказуемо** — тестируйте на реальном устройстве.

## Справочная таблица

| Канал | Платформа | Риск | Защита |
|-------|-----------|------|--------|
| Неявный intent | Android | spoofing | явный intent + проверка отправителя |
| startActivityForResult | Android | result hijacking | явный intent |
| Custom scheme redirect | обе | кража OAuth-кода | Universal/App Links + PKCE |
| Custom Tabs | Android | открытый редирект | валидация redirect_uri |
| Shared Keychain | iOS | утечка между приложениями | строгая группа |

## Что дальше / решение

Проверьте все каналы app-to-app: неявные intent'ы, result hijacking, custom scheme в OAuth, Custom Tabs. Каждый непроверенный отправитель/редирект — находка. Дальше — `mobile-ios-oauth-sso` и `mobile-push-security`.

## Практический разбор: перехват результата платежа

Рассмотрим приложение, которое инициирует оплату через неявный intent и ждёт результата:

```java
Intent pay = new Intent("com.example.ACTION_PAY");
pay.putExtra("amount", "500");
startActivityForResult(pay, REQ_PAY);
```

Обработчик:

```java
@Override
protected void onActivityResult(int req, int res, Intent data) {
    if (req == REQ_PAY && res == RESULT_OK) {
        String txn = data.getStringExtra("txn_id");
        confirmOrder(txn);   // подтверждаем заказ
    }
}
```

Уязвимость: любой может ответить на неявный intent. Приложение-ловушка:

```java
Intent result = new Intent();
result.putExtra("txn_id", "FAKE-" + System.currentTimeMillis());
setResult(RESULT_OK, result);
finish();
```

Если оно перехватит action, заказ подтвердится без оплаты. Проверка: соберите ловушку, зарегистрируйте action, запустите поток оплаты и посмотрите, подтвердится ли заказ.

## Проверка отправителя: подпись

Правильная защита — проверять не только package, но и подпись вызывающего (package можно подделать в некоторых сценариях, подпись — нет):

```java
private boolean isTrustedCaller() {
    String caller = getCallingPackage();
    if (caller == null) return false;
    try {
        PackageInfo pi = getPackageManager().getPackageInfo(caller, PackageManager.GET_SIGNATURES);
        Signature sig = pi.signatures[0];
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(sig.toByteArray());
        String hex = toHex(hash);
        return EXPECTED_HASH.equalsIgnoreCase(hex);
    } catch (Exception e) { return false; }
}
```

В уязвимом приложении такой проверки нет — вы это увидите статически (`grep getCallingPackage`) и подтвердите динамически.

## Custom Tabs vs WebView: как отличить

Оба показывают веб-контент, но безопасность разная. Проверка:

```javascript
// Android: если используется Custom Tabs — есть Intent с action android.support.customtabs.ACTION_VIEW
Java.perform(function () {
  var CT = Java.use("androidx.browser.customtabs.CustomTabsIntent$Builder");
  CT.build.implementation = function () {
    console.log("[customtabs] build()");
    return this.build();
  };
  var WV = Java.use("android.webkit.WebView");
  WV.loadUrl.overload('java.lang.String').implementation = function (u) {
    console.log("[webview] loadUrl " + u);
    return this.loadUrl(u);
  };
});
```

Если авторизация идёт через `WebView.loadUrl(authUrl)` — приложение видит вводимые данные и cookie. Это отдельная находка, даже если redirect_uri корректен.

## iOS: перехват URL scheme в деталях

На iOS custom scheme hijack менее предсказуем, но возможен. Механика: при открытии `myapp://callback` система выбирает приложение, зарегистрировавшее схему. Если зарегистрированы оба, выбор зависит от внутренней логики iOS (часто — последнее установленное или системное). Практический тест:

```bash
# установить ловушку с той же схемой
# запустить OAuth в жертве
# смотреть, кто получил callback
xcrun simctl openurl booted "myapp://callback?code=test"
```

Для Universal Links перехват невозможен при корректной ассоциации, но ошибки конфигурации (см. `mobile-universal-links`) возвращают нас к custom scheme fallback.

## Чек-лист app-to-app

- [ ] Есть ли неявные intent'ы с привилегированными action'ами?
- [ ] Проверяет ли приёмник отправителя (package + подпись)?
- [ ] Использует ли `startActivityForResult` неявный intent?
- [ ] Какой `redirect_uri` в OAuth — custom scheme или Universal/App Link?
- [ ] Enforced ли PKCE?
- [ ] Используется ли WebView вместо Custom Tabs для авторизации?
- [ ] Проверяются ли параметры из входящих intent/URL?
- [ ] Есть ли shared Keychain/App Groups с широким доступом?

## Итоговая модель доверия

App-to-app безопасность сводится к одному вопросу: доверяет ли приложение тому, кто на другом конце канала. Для каждого канала — intent, результат Activity, custom scheme, Custom Tabs, shared storage — выясните, проверяется ли отправитель и валидируются ли данные. Отсутствие проверки отправителя при привилегированном действии и есть уязвимость. Соберите матрицу «канал → проверка → вердикт»: она делает отчёт системным и помогает увидеть, что один и тот же приём (подмена отправителя) эксплуатируется в нескольких местах.

## Квиз

```quiz
- question: "Почему неявный intent опасен для приёмника?"
  options:
    - "Его может послать любое приложение, если получатель не проверяет отправителя"
    - "Он не доставляется"
    - "Он шифрует данные"
    - "Он работает только на iOS"
  answer: 0
- question: "Что защищает от кражи OAuth-кода при редиректе?"
  options:
    - "Universal/App Links для redirect_uri + PKCE"
    - "Скрытие client_id"
    - "Отключение HTTPS"
    - "Длинный state"
  answer: 0
- question: "Как проверить отправителя intent в Android?"
  options:
    - "getCallingPackage() + проверка подписи вызывающего"
    - "Проверить User-Agent"
    - "Прочитать SharedPreferences"
    - "Сравнить версию ОС"
  answer: 0
- question: "Чем startActivityForResult с неявным intent уязвим?"
  options:
    - "Результат может вернуть любое приложение (result hijacking)"
    - "Он не возвращает результат"
    - "Он блокирует UI"
    - "Он требует root"
  answer: 0
```

## Где пригодится

- **Bug bounty:** кража OAuth-кода, intent spoofing, подмена результата.
- **Пентест:** аудит взаимодействия приложений и границ доверия.
- **Работа:** безопасная интеграция приложений и SSO.
