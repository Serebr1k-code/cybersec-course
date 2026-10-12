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

## Вопрос, с которого всё начинается

В уроке про WebView мы разобрали основы: JS, файловый доступ, отладка. Но у WebView есть куда более тонкие настройки, и именно они превращают безобидный встроенный браузер в канал выполнения кода. Что нужно проверить, чтобы не пропустить серьёзную уязвимость?

## Наш пример: WebView в lichess.apk

Возьмём `lichess.apk` — приложение на Flutter, но с нативной WebView для открытия внешних ссылок. Признаки видны по строкам DEX:

```
$ unzip -o lichess.apk 'classes*.dex' -d lcx
$ strings lcx/classes.dex | grep -iE 'WebView|loadUrl|setJavaScriptEnabled|WebViewClient' | sort -u
Landroid/webkit/WebView;
Landroid/webkit/WebViewClient;
loadUrl
setJavaScriptEnabled
setWebView
setWebViewClient
```

Приложение создаёт WebView, включает JavaScript, ставит клиент и грузит URL. Разберём, какие настройки и переопределения надо читать.

## Шаг 1: полный список опасных настроек

Настройки WebView, которые чаще всего приводят к уязвимостям:

- `setJavaScriptEnabled(true)` — без JS многие атаки невозможны, с ним — возможны.
- `setAllowFileAccess(true)` — доступ к `file://`.
- `setAllowFileAccessFromFileURLs(true)` — страница из `file://` читает другие `file://`.
- `setAllowUniversalAccessFromFileURLs(true)` — то же, но без ограничения источника.
- `setJavaScriptCanOpenWindowsAutomatically(true)` — открытие окон без пользователя.
- `setDomStorageEnabled(true)` — хранилище в вебе (полезно, но расширяет поверхность).

Комбинация `setAllowUniversalAccessFromFileURLs(true)` + JS — прямой путь к чтению приватных файлов приложения.

## Шаг 2: JS-мост — ядро атаки

`addJavascriptInterface(obj, "Name")` регистрирует Java-объект, доступный из JS как `Name`. Это мост между вебом и приложением. Если объект даёт доступ к файлам, сети или другим данным, XSS на странице вызывает его методы.

Смотрим, что именно открыто:

```java
webView.addJavascriptInterface(new FileBridge(), "File");
```

Если `FileBridge` умеет читать файлы по имени, скрипт `File.read("/data/data/.../token")` вернёт секрет. С Android 17 (API 17) методы помечают `@JavascriptInterface`, но это лишь ограничивает набор доступных методов, а не делает мост безопасным.

## Шаг 3: доступ к `file://` и universal access

Опасная комбинация — грузить локальную страницу (`file:///android_asset/page.html`) и разрешать universal access. Тогда любая страница может читать файлы через `file://`. Ещё опаснее — когда приложение подставляет в локальную страницу внешние данные: тогда атакующий управляет содержимым, читающим файлы.

Проверяйте, грузит ли приложение `file://`-страницы и включён ли доступ к файлам. В связке с мостом это даёт полный контроль над данными приложения.

## Шаг 4: спуфинг URL

Иногда приложение само рисует «адресную строку» или доверяет `getUrl()`. Атака — подсунуть URL, который выглядит доверенным, но ведёт на чужой сайт:

- `https://trusted.com@evil.com` — фактический хост `evil.com`.
- `https://trusted.com.evil.com` — поддомен.
- `https://evil.com/?trusted.com` — в query.

Если приложение проверяет URL по подстроке или `startsWith`, это обходится. Задача — найти, где приложение решает «это доверенный URL» и обмануть проверку.

## Шаг 5: опасные переопределения клиентов

`WebViewClient.shouldOverrideUrlLoading` и `WebChromeClient` управляют навигацией. Опасные паттерны:

- **Возврат `false` без фильтра** — грузится любой URL.
- **Открытие новых окон** через `onCreateWindow` без проверки.
- **Обработка `intent://`** — WebView может запустить внешний Intent.

Если `shouldOverrideUrlLoading` не проверяет схему и хост, ссылка из веба открывает что угодно, включая `intent://` для запуска Activity.

## Шаг 6: как тестировать

План:

1. Найти WebView и прочитать все `set*`-настройки рядом.
2. Найти `addJavascriptInterface` и выписать методы моста.
3. Найти источники URL для `loadUrl` — контролируются ли снаружи.
4. Проверить `shouldOverrideUrlLoading` на фильтрацию схем.
5. Попробовать подсунуть XSS и вызвать мост.
6. Проверить `setWebContentsDebuggingEnabled` в release.

## Разбор реального сценария

Приложение грузит локальную страницу `file:///android_asset/help.html` и включает `setAllowUniversalAccessFromFileURLs(true)`. В страницу подставляется параметр deep link без экранирования. Атакующий передаёт `<script>` с чтением `file:///data/data/com.app/shared_prefs/token.xml` и отправкой содержимого на свой сервер. Из-за universal access скрипт читает приватный файл, а из-за отсутствия экранирования — вообще исполняется. Три настройки по отдельности «нормальны», вместе — утечка токена.

## Полный прогон от начала до конца

Соберём проверку WebView в один сценарий. Сначала `grep` по коду: все вызовы `WebView`, `setJavaScriptEnabled`, `setAllow*`, `addJavascriptInterface`. Читаем настройки и выписываем опасные. Дальше ищем источники URL для `loadUrl` и `loadDataWithBaseURL`. Проверяем `shouldOverrideUrlLoading`: фильтрует ли он схемы. Пробуем подсунуть XSS через внешний параметр и вызвать мост. Проверяем `setWebContentsDebuggingEnabled`. Итог — либо подтверждённая цепочка, либо список замечаний.

## Частые вопросы

**«JavaScript всегда включён?»** — нет, но большинство приложений его включает. **«Что опаснее: мост или `file://`?»** — мост, потому что даёт нативный доступ. **«Как найти мост?»** — grep по `addJavascriptInterface`. **«Что такое спуфинг URL?»** — подмена адреса, чтобы пройти проверку доверия. **«Как защитить?»** — белый список доменов, экранирование, отключение файлового доступа и universal access.

## Практический совет

Оценивайте WebView по совокупности, а не по одной настройке. Опасна не `setJavaScriptEnabled(true)` сама по себе, а её сочетание с контролируемым контентом и мостом. Составьте таблицу: настройка → риск → есть ли источник внешнего контента. Так вы быстро отделите реальные цепочки от безобидных конфигураций и не утонете в деталях.

## Ещё один нюанс: WebView и нативный код

WebView — только один канал. Если приложение на Flutter или React Native, встроенный браузер может быть обёрткой плагина (`flutter_inappwebview`, `react-native-webview`), и настройки задаются в JS/Dart, а не в Java. Тогда `grep` по Java-коду ничего не найдёт, и надо смотреть конфигурацию плагина в бандле или в `libapp.so`. Правило то же: сначала определите фреймворк, потом ищите настройки в правильном слое.

## Связь с другими уроками

WebView deep — промежуточный уровень между базовым WebView и цепочками RCE. Здесь важны детали настроек; в следующем уроке мы разберём, как эти детали складываются в вызов нативного метода через мост. Держите в голове общую картину: вход (deep link), транспорт (WebView), sink (мост). Этот урок — про транспорт и его слабые места.

## Итог

WebView — это отдельная поверхность атаки внутри приложения, и её опасность складывается из настроек, источников контента и переопределений клиента. Ни одна настройка сама по себе не критична, но их комбинация с контролируемым URL даёт реальные цепочки. Поэтому читайте WebView целиком, а не по одной строке.

## Что мы теперь знаем

По-простому:

1. WebView имеет десятки опасных настроек; читать надо все.
2. `addJavascriptInterface` — мост, через который XSS зовёт Java.
3. `file://` + universal access — чтение приватных файлов.
4. Спуфинг URL обходит наивные проверки хоста.
5. `shouldOverrideUrlLoading` без фильтра пускает любой URL.

## На что смотреть дальше

- **Читайте все настройки** WebView рядом с его созданием.
- **Ищите мост** `addJavascriptInterface` и его методы.
- **Проверяйте источники URL** и фильтрацию схем.
- **Тестируйте отладку** WebView в release-сборке.

## iOS: WKWebView

На iOS аналог WebView — `WKWebView`. Многие настройки отличаются: вместо `setJavaScriptEnabled` JS включён по умолчанию, а мосты делаются через `WKScriptMessageHandler`. Но принципы те же: недоверенный контент, доступ к файлам, спуфинг URL. Ищите `addScriptMessageHandler` и `loadFileURL` — это iOS-аналоги `addJavascriptInterface` и `file://`. Проверяйте настройки `WKWebViewConfiguration`, в частности `allowFileAccessFromFileURLs` и `allowUniversalAccessFromFileURLs`, которые в WKWebView тоже есть.

Итог простой: читайте WebView послойно — настройки, мосты, источники контента, переопределения клиента. Опасность почти всегда в комбинации, а не в отдельной строке.

## Квиз

Проверь себя.

```quiz
- question: "Какой метод регистрирует Java-объект, доступный из JS?"
  options:
    - "addJavascriptInterface"
    - "loadUrl"
    - "setWebViewClient"
    - "setJavaScriptEnabled"
  answer: 0
- question: "Что даёт `setAllowUniversalAccessFromFileURLs(true)`?"
  options:
    - "Страница из `file://` читает другие локальные файлы"
    - "Ускоряет загрузку"
    - "Включает JavaScript"
    - "Шифрует трафик"
  answer: 0
- question: "Какая строка URL обманывает наивную проверку по подстроке `trusted.com`?"
  options:
    - "https://evil.com/?x=trusted.com"
    - "https://trusted.com/path"
    - "https://trusted.com"
    - "ни одна"
  answer: 0
- question: "Что делает `shouldOverrideUrlLoading`?"
  options:
    - "Управляет навигацией WebView"
    - "Шифрует URL"
    - "Включает JS"
    - "Читает файлы"
  answer: 0
- question: "Что включает отладку WebView в release?"
  options:
    - "setWebContentsDebuggingEnabled(true)"
    - "setJavaScriptEnabled(true)"
    - "addJavascriptInterface"
    - "loadUrl"
  answer: 0
```

## Куда дальше

Мы разобрали глубокие настройки WebView. В следующем уроке сфокусируемся на **JS-bridge abuse**: как именно злоупотребляют мостами и как достичь недоверенного контента. А пока запомни главное: WebView — это мост, и его настройки решают, что по этому мосту можно пронести.

## Где пригодится

- **CTF Mobile:** XSS в WebView → вызов моста.
- **Bug bounty:** мост с доступом к файлам — серьёзная находка.
- **Пентест:** глубокий аудит WebView.
- **Работа:** ревью встроенного браузера.
