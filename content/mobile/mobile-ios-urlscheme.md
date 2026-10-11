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
---
## Введение

iOS-приложения принимают внешние ссылки двумя способами: **custom URL scheme** (`myapp://...`, регистрируется в `Info.plist`) и **Universal Links** (`https://myapp.example.com/...`, привязывается к домену через `apple-app-site-association`). Обе — точки входа, через которые другое приложение, Safari или веб-страница передают приложению произвольные параметры. Ошибки в обработке приводят к open redirect, краже OAuth-кода и захвату аккаунта.

## Custom URL schemes: регистрация и перехват

Схема объявляется в `Info.plist`:

```xml
<key>CFBundleURLTypes</key>
<array><dict>
  <key>CFBundleURLName</key><string>com.example.app</string>
  <key>CFBundleURLSchemes</key><array><string>myapp</string></array>
</dict></array>
```

Проблема: схемы **не защищены** — любое приложение может зарегистрировать `myapp://`, и система не гарантирует, кто откроет ссылку. Если два приложения заявили одну схему, победит установленное последним. Поэтому всё, что приходит по scheme, нельзя считать доверенным.

## Universal Links: надёжнее, но с нюансами

Universal Links используют `https://` и ассоциацию домена:

```json
// https://myapp.example.com/.well-known/apple-app-site-association
{ "applinks": { "apps": [], "details": [
  { "appID": "TEAMID.com.example.app", "paths": ["/open/*", "/oauth/*"] } ] } }
```

Плюсы: схему нельзя «украсть», ссылка работает только для вашего домена. Минусы: `paths` могут быть слишком широкими (`*`), а обработчик — доверять параметрам. Приложение должно проверять, что входящий `NSUserActivity` действительно с ожидаемого домена (`activity.webpageURL.host`).

## Hijacking и open redirect

Классические сценарии:

- Приложение A обрабатывает `myapp://redirect?url=https://evil.com` и открывает `url` в WebView — open redirect / фишинг.
- `myapp://oauth?code=...` — если злоумышленник зарегистрирует ту же схему, он перехватит OAuth-код.
- x-callback-url (`myapp://x-callback-url/action?x-success=evil://...`) — успешный колбэк уводится на чужую схему.
- Universal Link с широким `paths` + параметр-редирект → кража токена.

## Как тестировать

1. Извлечь схемы и домены из `Info.plist`:

```bash
unzip app.ipa -d out
plutil -p out/Payload/*.app/Info.plist | grep -A6 CFBundleURLTypes
plutil -p out/Payload/*.app/Info.plist | grep -i "applinks\|associated"
```

2. Проверить `apple-app-site-association` домена:

```bash
curl -s https://myapp.example.com/.well-known/apple-app-site-association | jq .
```

3. В динамике перечислить обработанные URL через Frida (хук `application:openURL:options:` и `scene:openURLContexts:`), затем вызывать их:

```bash
xcrun simctl openurl booted "myapp://redirect?url=https://evil.com"
```

4. Проверить редиректы: подставлять внешние URL в параметры `url`, `redirect`, `next`, `callback`, `returnUrl`, `continue`.
5. Проверить `paths` на избыточность и обработку `*`.

## Frida: перечисление обработчиков

```javascript
// перехват входа по URL
var AppDelegate = ObjC.classes.AppDelegate;
AppDelegate['- application:openURL:options:'].implementation =
  ObjC.implement(AppDelegate['- application:openURL:options:'], function (h, sel, app, url, opts) {
    console.log('[openURL] ' + new ObjC.Object(url).absoluteString().toString());
    return h(app, url, opts);
  });

// universal links
var SceneDelegate = ObjC.classes.SceneDelegate;
if (SceneDelegate) {
  SceneDelegate['- scene:openURLContexts:'].implementation =
    ObjC.implement(SceneDelegate['- scene:openURLContexts:'], function (h, sel, scene, ctxs) {
      console.log('[scene openURL] ' + ctxs.description().toString());
      return h(scene, ctxs);
    });
}
```

Так вы видите все ссылки, которые приложение реально принимает, и какие из них ведут к опасным действиям.

## Разобранный пример

Приложение использует `myapp://oauth/callback?code=<code>&state=<state>`. Обработчик не валидирует `state` и принимает `code` откуда угодно. Пентестер:

1. Регистрирует схему `myapp://` своим PoC-приложением (или перехватывает через `openURL`-хук).
2. Инициирует OAuth в жертве, код уходит атакующему.
3. Меняет код на токен → захват аккаунта. Отчёт: ATO через hijacking custom scheme + отсутствие `state`.

## Частые ошибки и подводные камни

- Считать Universal Links полностью безопасными: широкий `paths` и доверие параметрам ломают модель.
- Проверять только запуск схемы, но не обработку параметров (redirect/url/callback).
- Забывать про `state` в OAuth — без него hijacking легко эксплуатируется.
- Игнорировать x-callback-url: `x-success`/`x-error` уводят управление.
- Не проверять, что Universal Link приходит именно с ожидаемого домена (подмена host).

## Справочная таблица

| Параметр | Где искать | Риск |
|----------|-----------|------|
| `url` | обработчик scheme | open redirect |
| `next`/`redirect` | deep-link | SSRF/redirect |
| `callback`/`x-success` | x-callback-url | увод управления |
| `code`/`state` | OAuth callback | ATO |
| `paths:["*"]` | AASA | избыточный охват |
| `webpageURL.host` | NSUserActivity | подмена домена |

## Что дальше / решение

- **Найден open redirect** → попробуйте цепочку с OAuth-кодом или токеном → ATO.
- **Схема без `state` в OAuth** → оформите как ATO-цепочку.
- **Universal Link с `paths: ["*"]`** → ищите параметры-редиректы и поддельные домены.
- **Всё закрыто** → проверьте deep-link в WebView-контекст и intent-redirect на Android-версии приложения.
- Severity: перехват OAuth-кода → High/Critical; open redirect без цепочки → Medium.

## x-callback-url: детальный разбор

x-callback-url — неофициальный, но распространённый паттерн межприложенческого вызова: приложение A открывает `b://x-callback-url/action?...&x-success=a://done`, и B обязан вернуть управление по `x-success`. Уязвимости:

- **Подмена `x-success`/`x-error`:** приложение B слепо открывает переданную схему → атакующий перехватывает результат (в том числе OAuth-код).
- **Отсутствие проверки вызывающего:** результат уходит любому, кто вызвал действие.
- **Утечка данных в параметрах:** чувствительные данные передаются в URL и попадают в логи/историю.

Проверка:

```bash
xcrun simctl openurl booted "b://x-callback-url/action?x-success=evil://steal&data=secret"
```

Если `evil://` открывается с данными — вектор подтверждён.

## Проверка AASA: подводные камни

- Файл должен отдаваться с `Content-Type: application/json` и без редиректов; редирект ломает ассоциацию.
- Должен быть доступен по HTTPS без CDN, который меняет содержимое.
- `appID` = `<TeamID>.<BundleID>`; опечатка → ассоциация не работает, и ссылку перехватит другое приложение.
- `paths`/`components` шире, чем нужно, → лишние экраны доступны снаружи.
- Проверьте, что обработчик сверяет `webpageURL.host` — иначе поддельный домен с валидным путём приведёт на внутренний экран.

```bash
curl -sI https://myapp.example.com/.well-known/apple-app-site-association
curl -s https://myapp.example.com/.well-known/apple-app-site-association | jq '.applinks.details'
```

## Таблица тест-кейсов

| Тест | Payload | Ожидаемый риск |
|------|---------|----------------|
| Open redirect | `myapp://open?url=https://evil` | фишинг/утечка |
| OAuth hijack | `myapp://oauth?code=x` | ATO |
| x-callback | `...x-success=evil://` | увод результата |
| Широкий path | `https://myapp.example/anything` | доступ к экрану |
| Подмена host | `https://evil/?path=/open/x` | обход ассоциации |
| Отсутствие state | OAuth без `state` | CSRF/ATO |

## Что делать с находками

Каждый тест-кейс оформляйте отдельно с запросом/ссылкой и наблюдаемым эффектом. Если удаётся собрать цепочку «ссылка → утечка токена → доступ к аккаунту», это High/Critical. Если только open redirect без последствий — Medium. Для iOS особенно ценно доказать, что внешняя ссылка открывает внутренний экран, который не должен быть доступен снаружи.

## Universal Links vs App Links (Android)

Обе технологии решают одну задачу — привязать `https://`-ссылку к приложению через домен, но детали различаются:

| Аспект | iOS Universal Links | Android App Links |
|--------|--------------------|-------------------|
| Файл | `apple-app-site-association` | `assetlinks.json` |
| Путь | `/.well-known/apple-app-site-association` | `/.well-known/assetlinks.json` |
| Проверка | ассоциация домена | `autoVerify=true` |
| Охват | `paths`/`components` | `pathPrefix`/`pathPattern` |
| Слабые места | широкий `paths`, доверие host | `autoVerify` выключен, широкий prefix |

Для Android-версии ищите:

```bash
curl -s https://app.example/.well-known/assetlinks.json | jq .
grep -i "autoVerify\|intent-filter\|pathPrefix" out/AndroidManifest.xml
```

Если `autoVerify` не включён, любую `https`-ссылку перехватит другое приложение.

## Защита: как правильно

- Использовать только Universal/App Links для чувствительных действий; custom scheme — лишь для нечувствительных.
- Сузить `paths`/`pathPrefix` до конкретных префиксов.
- Валидировать `state` в OAuth и проверять `webpageURL.host`.
- Никогда не открывать произвольный URL/схему из параметра; использовать allowlist.
- Проверять вызывающего для x-callback-url.
- Для Android — `autoVerify="true"` и строгий `pathPrefix`.

## Примеры реальных багов

- **Open redirect через deep link** в почтовом/соцприложении: `app://web?url=` открывал произвольный сайт → фишинг.
- **OAuth-код через custom scheme без `state`:** перехват кода сторонним приложением → ATO.
- **Universal Link с `paths:["*"]`:** внешняя ссылка открывала внутренний экран администрирования.
- **x-callback-url без проверки вызывающего:** результат действия утекал на чужую схему.

Общий паттерн: разработчики относятся к ссылкам как к «своим», тогда как их может сформировать кто угодно.

## Что делать дальше

- Для каждой найденной ссылки постройте цепочку до последствия (утечка/ATO/действие).
- Проверьте симметрию: то, что закрыто в Universal Links, может быть открыто в custom scheme и наоборот.
- Отдельно протестируйте WebView-обработчик ссылок: он часто открывает внешние URL с доступом к JS-мосту (см. `mobile-webview`).

## Квиз

```quiz
- question: "Чем Universal Links надёжнее custom URL scheme?"
  options:
    - "Привязаны к домену через apple-app-site-association"
    - "Их нельзя перехватить вообще"
    - "Они не используют https"
    - "Они не требуют параметров"
  answer: 0
  explanation: "Ассоциация домена мешает чужому приложению заявить ту же ссылку."
- question: "Какой файл на домене подтверждает Universal Links?"
  options:
    - "/.well-known/apple-app-site-association"
    - "/robots.txt"
    - "/assetlinks.json (без .well-known)"
    - "/apple-touch-icon.png"
  answer: 0
  explanation: "AASA лежит в /.well-known/apple-app-site-association."
- question: "Почему custom URL scheme уязвима к hijacking?"
  options:
    - "Любое приложение может зарегистрировать ту же схему"
    - "Она шифруется"
    - "Она работает только в Safari"
    - "Она требует jailbreak"
  answer: 0
  explanation: "Схемы не защищены; система не гарантирует, кто откроет ссылку."
- question: "Какое поле OAuth-потока особенно важно при deep-link callback?"
  options:
    - "state (анти-CSRF)"
    - "user-agent"
    - "Accept-Language"
    - "Content-Length"
  answer: 0
  explanation: "Без валидации state перехват кода ведёт к захвату аккаунта."
- question: "Где объявлены custom URL schemes в iOS-приложении?"
  options:
    - "В Info.plist (CFBundleURLTypes)"
    - "В Mach-O заголовке"
    - "В Keychain"
    - "В entitlements"
  answer: 0
  explanation: "Схемы регистрируются в CFBundleURLTypes файла Info.plist."
```

## Где пригодится

- **CTF Mobile:** задачи с перехватом ссылки и извлечением токена/флага.
- **Bug bounty:** open redirect, ATO через deep-link — одни из самых дорогих находок в iOS.
- **Пентест:** проверка OAuth-потоков и межприложенческого взаимодействия.
- **Работа:** ревью обработчиков ссылок и AASA перед релизом.
