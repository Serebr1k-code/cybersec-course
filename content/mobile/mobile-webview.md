---
id: mobile-webview
title: "WebView: XSS, JS-интерфейсы и утечки через встроенный браузер"
category: mobile
parent: mobile-android-components
difficulty: hard
order: 3
tags: [android, webview, xss, javascript-interface, file-access, ssrf]
prerequisites: [mobile-android-anatomy, mobile-intents-deeplinks]
useful_for:
  - "CTF Mobile (XSS в WebView, доступ к флагу через JS-мост)"
  - "Bug bounty (утечка токенов через WebView)"
  - "Пентест мобильных приложений"
estimated_minutes: 14
summary: "Как Android WebView открывает сайты и локальные страницы, чем опасны addJavascriptInterface, setAllowFileAccess и file://, и как эксплуатировать XSS/загрузку произвольного URL в контексте приложения."
lab:
  kind: shell
  title: 'Практика: WebView и доступ к файлам'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, decoded]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Опасные настройки WebView: `setAllowFileAccess`, `setJavaScriptEnabled`.'
    - 'При включённом file-доступе страница может прочитать локальные файлы.'
    - 'Секрет лежит в `assets/` — найди `nto{` и запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

Многие приложения показывают веб-контент прямо внутри себя — страницу оплаты, справку, вход через соцсеть. Для этого используется **WebView**, встроенный браузер. Но WebView — это не отдельное окно браузера: у него есть доступ к приложению через JavaScript-мосты. Ошибка в настройках превращает веб-страницу в способ выполнить код. Как это проверить?

## Наш пример: WebView в lichess.apk

Возьмём `lichess.apk` и посмотрим, есть ли в нём WebView. Декомпилировать большой APK долго, но строки DEX покажут классы:

```
$ unzip -o lichess.apk 'classes*.dex' -d lcx
$ strings lcx/classes.dex | grep -iE 'WebView|loadUrl|setJavaScriptEnabled' | sort -u | head
Landroid/webkit/WebView;
Landroid/webkit/WebViewClient;
loadUrl
setJavaScriptEnabled
setWebView
setWebViewClient
```

Вот и признаки: приложение создаёт WebView, включает JavaScript и загружает URL. Дальше вопрос — какие настройки включены и есть ли мост в нативный код.

## Шаг 1: что такое WebView и чем он опасен

WebView — компонент `android.webkit.WebView`, который рендерит HTML/CSS/JS внутри приложения. Он опасен по трём причинам:

- **JavaScript по умолчанию выключен**, но приложения его включают (`setJavaScriptEnabled(true)`) — и тогда любой XSS становится выполнимым.
- **JavaScript-мосты** (`addJavascriptInterface`) дают JS-коду доступ к методам Java.
- **Доступ к локальным файлам** (`file://`, `setAllowFileAccess`) может открыть приватные данные.

## Шаг 2: опасные настройки

Смотрим, что включено:

```java
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowFileAccess(true);
webView.getSettings().setAllowFileAccessFromFileURLs(true);
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
webView.getSettings().setJavaScriptCanOpenWindowsAutomatically(true);
```

Каждая строка добавляет риск:

- `setAllowUniversalAccessFromFileURLs(true)` — страница из `file://` может читать другие `file://` (утечка файлов).
- `setJavaScriptCanOpenWindowsAutomatically(true)` — открытие окон без участия пользователя.
- Комбинация `setAllowFileAccess` + JS = доступ к приватным файлам приложения.

## Шаг 3: XSS через WebView

Если WebView грузит URL, куда попадает пользовательский ввод, возможен XSS. Например, приложение подставляет параметр deep link в адрес:

```java
webView.loadUrl("https://app.example.com/page?q=" + getIntent().getData().getQueryParameter("q"));
```

Тогда ссылка `app://open?q=<script>...</script>` исполнит скрипт в контексте приложения. А если есть мост в Java — этот скрипт вызовет нативные методы.

## Шаг 4: addJavascriptInterface — прямой RCE-класс

Самый опасный паттерн — регистрация Java-объекта, доступного из JS:

```java
webView.addJavascriptInterface(new Bridge(), "Android");
```

Теперь любой JS на странице вызывает `Android.someMethod()`. Если метод делает что-то привилегированное (читает файлы, отправляет данные), XSS превращается в выполнение кода/утечку. До Android 4.2 через `getClass()` можно было дойти до `Runtime.exec` — классический WebView RCE.

## Шаг 5: загрузка произвольного URL

Проверьте, может ли внешний ввод задать адрес:

```java
webView.loadUrl(getIntent().getStringExtra("url"));
```

Если да — приложение превращается в открытый редирект и может грузить фишинговые страницы, а через мост — звать нативные методы. Правильно — белый список доменов.

## Шаг 6: отладка WebView

Отдельная находка — включённая отладка WebView:

```java
WebView.setWebContentsDebuggingEnabled(true);
```

Тогда к WebView можно подключиться через `chrome://inspect` и выполнять JS в контексте приложения. В release-сборке это должно быть выключено.

## Шаг 7: защита и её обход

Безопасные настройки:

- JS включать только при необходимости; грузить только доверенный контент.
- Не использовать `addJavascriptInterface`; вместо него — `WebViewCompat.postWebMessage`.
- Отключить `setAllowFileAccess`, `setAllowUniversalAccessFromFileURLs`.
- Белый список доменов в `shouldOverrideUrlLoading`.
- Выключить `setWebContentsDebuggingEnabled` в release.

Обход защиты обычно идёт через **нестрогую валидацию URL** (`startsWith`, подстрока) — см. урок про deep links.

## Чем XSS в WebView отличается от веб-XSS

В обычном веб-приложении XSS ограничен «миром браузера»: cookie, DOM, запросы. В WebView тот же XSS получает **мост в приложение**. Если разработчик зарегистрировал Java-объект через `addJavascriptInterface`, скрипт из веб-страницы вызывает нативные методы так же свободно, как JavaScript вызывает функции. Это стирает границу между «веб-уязвимостью» и «выполнением кода в приложении».

Именно поэтому WebView-XSS считается гораздо серьёзнее: то, что на сайте было бы отражённым XSS средней важности, внутри приложения превращается в кражу токенов, чтение файлов и выполнение команд. Пентестер должен всегда проверять, есть ли мост, прежде чем оценивать severity.

## Разбор реального сценария

Приложение открывает страницу справки, подставляя параметр в URL:

```java
webView.loadUrl("https://app.example.com/help?topic=" + getIntent().getStringExtra("topic"));
```

Deep link `app://help?topic=<img src=x onerror=Android.steal()>` исполняет скрипт. Если есть мост `Android.steal()`, который отправляет данные на сервер, токен сессии утекает. Цепочка: deep link → XSS в WebView → вызов моста → кража. Каждое звено по отдельности может выглядеть безобидно, но вместе они дают полный захват аккаунта.

## Частые вопросы

**«JavaScript по умолчанию включён?»** — нет, но приложения его включают. **«Что опаснее: file:// или мост?»** — мост, потому что даёт доступ к нативному коду. **«Как найти мост?»** — grep по `addJavascriptInterface`. **«Нужен ли root?»** — нет, достаточно заставить приложение открыть ваш URL. **«Как защитить?»** — белый список доменов, `WebMessage` вместо моста, отключение файлового доступа.

## Практический совет

Проверяйте WebView в два шага. Сначала настройки: JS, файловый доступ, отладка. Потом — источники URL: может ли внешний ввод задать адрес или его часть. Именно сочетание «опасная настройка + контролируемый URL» даёт рабочую уязвимость. Не забывайте и про отладочный WebView: если `setWebContentsDebuggingEnabled(true)` включён в release, вы можете выполнить JS прямо из `chrome://inspect`.

## Полный прогон от начала до конца

Соберём проверку WebView в один сценарий. Сначала находим WebView в коде: `grep -rn "WebView" out/` и смотрим, какие настройки включаются рядом. Затем проверяем, есть ли `addJavascriptInterface` — если да, выписываем методы моста. Дальше ищем, откуда берётся URL для `loadUrl`: константа (безопасно), ресурс приложения (безопасно), внешний ввод (опасно). Если URL контролируется снаружи, строим страницу с XSS и смотрим, выполняется ли она. Наконец проверяем `setWebContentsDebuggingEnabled`. Итог — либо подтверждённая цепочка, либо список замечаний по конфигурации.

## Ещё один вектор: доступ к `content://`

WebView может грузить не только `file://` и `https://`, но и `content://`. Если настройки разрешают, а приложение само выдаёт себе доступ к своим провайдерам, страница может прочитать данные через `content://`. Это особенно опасно в связке с `grantUriPermissions`: WebView получает грант и читает файлы, которые не должны быть доступны вебу. Проверяйте `shouldOverrideUrlLoading` — фильтрует ли он схемы `file` и `content`, или пропускает всё.

## Что мы теперь знаем

По-простому:

1. WebView — встроенный браузер с доступом к приложению.
2. JS включают явно; вместе с XSS это уже опасно.
3. `addJavascriptInterface` даёт JS доступ к Java — прямой путь к RCE.
4. Доступ к `file://` и произвольный URL — источники утечек.
5. Защита: белый список, WebMessage вместо моста, отключение файлового доступа.

## На что смотреть дальше

- **Ищите `setJavaScriptEnabled`** и другие опасные настройки.
- **Ищите `addJavascriptInterface`** — самый серьёзный паттерн.
- **Проверяйте, откуда берётся URL** для `loadUrl`.
- **Смотрите `setWebContentsDebuggingEnabled`** — отладка в release.

## Отладка и инспекция

Если WebView в release-сборке оставили с включённой отладкой, вы можете подключиться к нему из Chrome по `chrome://inspect`, увидеть DOM и выполнить произвольный JavaScript в контексте приложения. Это делает ненужной всю работу по достижению XSS: вы уже внутри. Поэтому проверка `setWebContentsDebuggingEnabled` — обязательный шаг, а находка «отладка включена в release» фиксируется отдельно.

## Квиз

Проверь себя.

```quiz
- question: "Что такое WebView?"
  options:
    - "Встроенный в приложение браузер"
    - "База данных"
    - "Нативная библиотека"
    - "Тип сертификата"
  answer: 0
- question: "Почему `addJavascriptInterface` опасен?"
  options:
    - "Даёт JS-коду доступ к методам Java, вплоть до RCE"
    - "Замедляет загрузку"
    - "Требует root"
    - "Шифрует трафик"
  answer: 0
- question: "Какая настройка открывает доступ к локальным файлам из `file://`?"
  options:
    - "setAllowUniversalAccessFromFileURLs(true)"
    - "setJavaScriptEnabled(true)"
    - "setSupportZoom(true)"
    - "setBuiltInZoomControls(true)"
  answer: 0
- question: "Что включает отладку WebView через chrome://inspect?"
  options:
    - "WebView.setWebContentsDebuggingEnabled(true)"
    - "setJavaScriptEnabled(true)"
    - "loadUrl()"
    - "setWebViewClient()"
  answer: 0
- question: "Как правильно ограничить загружаемые URL?"
  options:
    - "Белым списком доменов в shouldOverrideUrlLoading"
    - "Проверкой startsWith по подстроке"
    - "Отключением JavaScript"
    - "Использованием HTTPS"
  answer: 0
```

## Куда дальше

Мы разобрали базовые опасности WebView. В следующем уроке — **кросс-платформенные фреймворки**: Cordova, React Native, Flutter, и как их структура меняет подход к анализу. А пока запомни главное: WebView — это мост между вебом и приложением, и его настройки решают, будет ли этот мост безопасным.

## Где пригодится

- **CTF Mobile:** XSS в WebView → выполнение кода.
- **Bug bounty:** мост JS→Java — серьёзная находка.
- **Пентест:** проверка OWASP MASVS-PLATFORM.
- **Работа:** ревью встроенного браузера и его настроек.
