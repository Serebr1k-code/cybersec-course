---
id: mobile-universal-links
title: "Universal Links и App Links: ассоциация домена и перехват ссылок"
category: mobile
parent: mobile-advanced-ios
difficulty: hard
order: 2
tags: [mobile, ios, android, deeplink, universal-links, applinks]
prerequisites: [mobile-deeplink-deep]
useful_for:
  - "CTF Mobile: перехват и подмена ссылок"
  - "Bug bounty: open redirect и кража токенов"
estimated_minutes: 42
summary: "Как работают Universal Links (iOS) и App Links (Android), проверка ассоциации домена, типовые ошибки конфигурации, перехват и подмена ссылок, кража OAuth-кода через редирект."
---

## Вопрос, с которого всё начинается

Приложение хочет, чтобы ссылка `https://demo.example/app/open?id=1` открывалась именно в нём, а не в Safari. Для этого Apple придумала **Universal Links** — механизм, который привязывает обычный `https`-домен к приложению. Но если привязка настроена неправильно, ссылка либо не сработает, либо откроет то, что не должна.

Как проверить, что Universal Links настроены корректно и безопасно?

## Наш пример: DemoApp и домен demo.example

В `Info.plist` нашего `DemoApp` есть права на Universal Links (в реальном приложении они задаются через entitlement `associated-domains`). Логика такая: iOS открывает `https://demo.example/...` в приложении только если домен подтвердил связь через специальный файл **AASA** (`apple-app-site-association`).

## Шаг 1: что такое AASA

AASA — это JSON-файл, который домен отдаёт по строгому пути:

```
https://<domain>/.well-known/apple-app-site-association
```

Важные требования: отдаётся по **HTTPS**, **без редиректов**, с `Content-Type: application/json`, и **без** расширения `.json` в имени. Посмотрим содержимое:

```
$ curl -s https://demo.example/.well-known/apple-app-site-association | jq .
{
  "applinks": {
    "details": [
      { "appID": "TEAMID.com.demo.secapp",
        "paths": ["/app/*", "/pay/*"] }
    ]
  }
}
```

`appID` — это `TeamID.BundleID`, идентификатор приложения. `paths` — список путей домена, которые открывают приложение. Проверять заголовки тоже нужно:

```
$ curl -sI https://demo.example/.well-known/apple-app-site-association
HTTP/2 200
content-type: application/json
```

Если видишь `301`/`302` или `text/html` — iOS проигнорирует файл, и Universal Links не заработают.

## Шаг 2: как проверить связь

Проверка связи (association) кэшируется устройством, поэтому после изменений AASA её иногда нужно сбрасывать. Быстрый способ проверить поведение — открыть ссылку в симуляторе:

```
$ xcrun simctl openurl booted "https://demo.example/app/open?id=1"
```

Если приложение открылось и показало нужный экран — связь работает. Если открылся Safari — привязка не прошла (проверь AASA и entitlement).

## Шаг 3: сравнение с Android App Links

Android-аналог Universal Links называется **App Links** и настраивается файлом `assetlinks.json`:

```
$ curl -s https://demo.example/.well-known/assetlinks.json | jq .
[
  { "relation": ["delegate_permission/common.handle_all_urls"],
    "target": { "namespace": "android_app",
                "package_name": "com.demo.secapp",
                "sha256_cert_fingerprints": ["AB:CD:..."] } }
]
```

Ключевое отличие: App Links привязывают домен к **отпечатку сертификата** приложения (`sha256_cert_fingerprints`). Если приложение переподписано другим ключом (например, для теста), привязка ломается. В манифесте Android это включается флагом `android:autoVerify="true"` в intent-filter:

```
<intent-filter android:autoVerify="true">
  <data android:scheme="https" android:host="demo.example" android:pathPrefix="/app"/>
</intent-filter>
```

## Шаг 4: типичные ошибки настройки

Разберём, что ломает Universal Links и что при этом создаёт риск:

- **AASA недоступен или за редиректом** — привязка не проходит, ссылки открываются в Safari.
- **Слишком широкий `paths`** (например, `"*"`) — приложение перехватывает все ссылки домена, включая те, что должны вести на сайт.
- **`appID` с опечаткой** — неверный TeamID/BundleID, связь не подтверждается.
- **Отсутствие entitlement `associated-domains`** — приложение не заявляет домен, iOS его не открывает.
- **Обработка без валидации** — даже получив ссылку, приложение должно проверить параметры.

Широкий `paths` — это находка: он расширяет поверхность атаки, позволяя открывать в приложении неожиданные URL.

## Шаг 5: отладка привязки

Если Universal Links не работают, привязку нужно отладить. iOS кэширует AASA, поэтому после правок файла на устройстве может остаться старая копия. Сбросить привязку можно, переустановив приложение или изменив версию сборки. Проверить, видит ли устройство ассоциацию, помогает консоль: в системном логе появляются записи о скачивании AASA и об ошибках парсинга. На Linux вместо консоли используют `idevicesyslog`, отфильтровав по имени домена.

Практический порядок отладки такой. Сначала проверяем AASA через `curl` — доступен, 200, JSON. Затем сверяем `appID` с реальным `TeamID.BundleID` приложения. Потом убеждаемся, что в приложении есть entitlement `associated-domains` с доменом вида `applinks:demo.example`. И только затем тестируем `simctl openurl`. Если всё верно, но ссылка открывается в Safari — сбрасываем кэш ассоциации. Не забывай проверять и то, что ссылка открывается именно с нужным действием: привязка может работать, а обработчик — игнорировать параметры.

## Шаг 6: таблица тест-кейсов

Соберём короткий чек-лист проверки Universal Links:

| Что проверяем | Как |
|---------------|-----|
| AASA доступен | `curl -sI .../apple-app-site-association` |
| Без редиректа | код ответа 200, не 3xx |
| `Content-Type` JSON | заголовок ответа |
| `appID` корректен | сравнить с BundleID |
| `paths` не слишком широки | анализ шаблонов |
| Открытие работает | `simctl openurl booted` |
| Android-аналог | `curl .../assetlinks.json` |

## Шаг 7: что делать с находками

Если Universal Links настроены с широким `paths` или приложение обрабатывает ссылки без проверки — это цепочка: внешняя ссылка → приложение → опасное действие. Свяжи находку с `mobile-ios-urlscheme` (open redirect) и `mobile-ios-oauth-sso` (перехват OAuth-колбэка). В отчёте покажи конкретный URL и последствие.

## Шаг 8: безопасность на стороне домена

Universal Links — это ещё и вопрос инфраструктуры. Если злоумышленник получит контроль над доменом (например, через поддомен-приложение с ошибкой или устаревший DNS-запись), он сможет отдавать свой AASA и перехватывать ссылки. Поэтому в аудите проверяют: кто владеет доменом, нет ли «висящих» CNAME, отдаётся ли AASA с того же хоста, что и приложение. Отдельно смотрят на CDN: если AASA кэшируется слишком долго, изменения политики безопасности не вступят в силу вовремя. Всё это — часть общей модели: связка домена и приложения держится на доверии к домену.

## Шаг 9: проверяем AASA перед публикацией

Файл `apple-app-site-association` должен лежать в корне домена по HTTPS, **без** расширения `.json`, с `Content-Type: application/json`. Перед публикацией его полезно распарсить локально — ошибки в `appID` и в исключениях `NOT` встречаются постоянно:

```
$ python3 -c "import json; d=json.load(open('apple-app-site-association')); det=d['applinks']['details'][0]; print('appID =', det['appID']); print('paths =', det['paths'])"
appID = ABCDE12345.com.demo.sec
paths = ['/open/*', 'NOT /admin/*']
```

`appID` — это Team ID (`ABCDE12345`) и bundle id через точку; если Team ID чужой, система не свяжет домен с приложением, и ссылки уйдут в Safari. `NOT /admin/*` исключает чувствительные пути — их приложению отдавать не нужно. Помни, что AASA кешируется: после правки проверяй привязку на реальном устройстве, а не только в браузере.

## Что мы теперь знаем

- Universal Links привязывают `https`-домен к приложению через AASA.
- AASA отдаётся по `/.well-known/apple-app-site-association` по HTTPS, без редиректов.
- `appID` — это `TeamID.BundleID`, а `paths` — список путей.
- Android-аналог — App Links (`assetlinks.json`), привязка по отпечатку сертификата.
- Широкий `paths` и отсутствие валидации — типичные уязвимости.
- Проверять связь удобно через `simctl openurl`.

## Квиз

Проверь себя.

```quiz
- question: По какому пути домен отдаёт AASA?
  options:
    - "/apple-app-site-association.json"
    - "/.well-known/apple-app-site-association"
    - "/applinks.json"
    - "/aasa.xml"
  answer: 1
  explanation: "Файл должен лежать в /.well-known/ и без расширения .json."
- question: Что означает поле appID в AASA?
  options:
    - "Имя приложения"
    - "TeamID.BundleID приложения"
    - "Версию iOS"
    - "Пароль"
  answer: 1
  explanation: "appID связывает домен с конкретным приложением по Team ID и Bundle ID."
- question: Почему редирект на AASA ломает Universal Links?
  options:
    - "Файл становится больше"
    - "iOS ожидает прямой ответ 200 без редиректов"
    - "Меняется Content-Type"
    - "Он не ломает"
  answer: 1
  explanation: "Apple требует отдавать AASA напрямую, без 3xx-редиректов."
- question: Чем Android App Links отличается от Universal Links?
  options:
    - "Он использует assetlinks.json и привязку по отпечатку сертификата"
    - "Он не использует HTTPS"
    - "Он не проверяет домен"
    - "Он работает только на iOS"
  answer: 0
  explanation: "App Links проверяют sha256_cert_fingerprints приложения через assetlinks.json."
- question: Чем опасен слишком широкий paths в AASA?
  options:
    - "Замедляет приложение"
    - "Приложение перехватывает больше ссылок, чем нужно, расширяя поверхность атаки"
    - "Ломает HTTPS"
    - "Ничем"
  answer: 1
  explanation: "Шаблон вроде '*' открывает в приложении все ссылки домена, включая неожиданные."
```

## Куда дальше

Universal Links — это «вход» в приложение. Дальше разберём, как в приложение внедрить собственный код: в следующем уроке `mobile-ios-dylib-injection` мы подгрузим свою библиотеку через `insert_dylib`. А пока главное запомни: Universal Links держатся на AASA, и любая ошибка в нём либо ломает ссылки, либо создаёт уязвимость.

## Где пригодится

- **Пентест:** анализ deep link-поверхности и привязки доменов.
- **Bug bounty:** широкий paths и отсутствие валидации — частые находки.
- **CTF:** задачи, где флаг приходит через Universal Link.
- **Аудит:** проверка корректности AASA и App Links.
