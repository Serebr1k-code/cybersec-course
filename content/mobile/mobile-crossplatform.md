---
id: mobile-crossplatform
title: "Гибридные фреймворки: Cordova, Ionic, Xamarin, .NET MAUI"
category: mobile
parent: mobile-webview
difficulty: medium
order: 1
tags: [cordova, ionic, xamarin, maui, hybrid, webview, ilspy, dotnet]
prerequisites: [mobile-static-analysis, mobile-webview]
useful_for:
  - "CTF Mobile (реверс гибридных приложений)"
  - "Bug bounty (секреты в www/, .NET-логика)"
  - "Пентест мобильных приложений"
estimated_minutes: 30
summary: "Как устроены Cordova/Ionic (HTML/JS в WebView) и Xamarin/.NET MAUI (C#/IL), где искать их код и секреты и как реверсить .NET-сборки."
---

## Вопрос, с которого всё начинается

Открываешь APK — а там нет привычных `classes.dex` с логикой. Вместо Java-кода — огромный `libapp.so` или `libreactnative.so`. Значит, приложение написано на **кросс-платформенном фреймворке**: один код собирается и под Android, и под iOS. Как это определить и где искать логику и секреты?

## Наш пример: три реальных APK

Возьмём три приложения и посмотрим, чем они отличаются изнутри.

**Flutter** (lichess, fluffychat) — логика в нативной библиотеке:

```
$ unzip -l fluffychat.apk | grep -E 'libflutter|libapp.so'
25887624  lib/arm64-v8a/libapp.so
11747864  lib/arm64-v8a/libflutter.so
```

**React Native** (mattermost) — движок Hermes и нативный рантайм:

```
$ unzip -l mattermost.apk | grep -iE 'hermes|reactnative'
2141744  lib/arm64-v8a/libhermesvm.so
6314224  lib/arm64-v8a/libreactnative.so
```

**Классический нативный Android** — обычные `classes.dex` и Java-код (как `uncrack1.apk`).

По этим признакам фреймворк определяется за секунды.

## Шаг 1: почему фреймворки меняют анализ

В классическом APK логика — в DEX, и `jadx` показывает её как Java. В кросс-платформенных приложениях бизнес-логика уезжает:

- **Flutter** компилирует Dart в **AOT-машинный код** (`libapp.so`). `jadx` покажет только обёртку; логику надо реверсить в Ghidra/IDA, а строки — искать `strings`.
- **React Native** держит JS в бандле (`index.android.bundle`) или компилирует в Hermes-байткод. Его декомпилируют обратно в JS (`hbctool`, `hermes-dec`).
- **Cordova/Ionic** кладут HTML/JS в `assets/www/` — их читают как обычный веб.

## Шаг 2: Cordova / Ionic

Самый простой случай: приложение — это WebView, который грузит локальную веб-страницу. В APK видно:

```
$ unzip -l app.apk | grep 'assets/www'
   12345  assets/www/index.html
   45678  assets/www/js/app.js
```

Читаем `app.js` как обычный JavaScript: там и API-эндпоинты, и ключи, и логика. Дополнительно смотрим `config.xml` — в нём настройки WebView и белые списки.

## Шаг 3: React Native

Логика в JS-бандле. Если бандл не скомпилирован в Hermes:

```
$ unzip -o app.apk 'assets/index.android.bundle' -d rn
$ grep -nE 'api|token|secret' rn/assets/index.android.bundle | head
```

Если скомпилирован в Hermes (признак — `libhermesvm.so`), нужен `hbctool disasm` для обратного разбора в байткод и ассемблер. Строки при этом всё равно видны:

```
$ strings rn/assets/index.android.bundle | grep -iE 'https://|token' | head
```

## Шаг 4: Flutter

Flutter-приложение содержит `libflutter.so` (движок) и `libapp.so` (ваш код). Реверс `libapp.so` — задача для Ghidra с плагином `reFlutter`, но часто хватает `strings`:

```
$ strings libapp.so | grep -iE 'https://|api_key|secret' | head
```

Важно: Dart-код компилируется AOT, поэтому «декомпилировать в исходники» нельзя — только анализировать машинный код и строки. `flutter_assets/` при этом лежит в APK и содержит ресурсы:

```
$ unzip -l lichess.apk | grep flutter_assets | head
   217223  assets/flutter_assets/AssetManifest.bin
   143124  assets/flutter_assets/NOTICES.Z
```

## Шаг 5: Xamarin / .NET MAUI

Здесь код — .NET-сборки. В APK лежат:

```
$ unzip -l app.apk | grep -E 'assemblies|\.dll'
  1234567  assemblies/MyApp.dll
   234567  assemblies/Mono.Android.dll
```

Их разбирают `dnSpy`/`ilspycmd` — это уже не Java, а CIL-байткод.

## Шаг 6: где искать секреты

Общее правило для всех фреймворков:

- **Строки.** `strings` по `.so` и бандлам — ключи, URL, токены.
- **Ресурсы.** `assets/` и `flutter_assets/` хранят конфиги.
- **Нативный код.** Реверс `libapp.so`/`libreactnative.so`.
- **Обфускация.** Часто бандл/сборку обфусцируют (Flutter — строки, RN — JS-обфускация).

## Почему фреймворки усложняют аудит

Кросс-платформенные приложения экономят разработчикам время, но ломают привычный план анализа. В классическом APK `jadx` показывает логику как Java, и вы читаете её почти как исходники. Во Flutter и React Native логика уезжает в нативный код или бандл, и стандартные инструменты бессильны: `jadx` покажет лишь обёртку, а настоящая работа спрятана глубже.

Хуже того, многие проверки безопасности (pinning, root-детект, обфускация) реализуются на уровне фреймворка и потому лежат в `.so` или в бандле. Это значит, что «обычные» хуки на Java-методы не сработают — придётся работать с нативным кодом. Поэтому первый шаг любого аудита — определить фреймворк, и уже от этого строить план.

## Разбор реального сценария

Дано приложение-мессенджер на Flutter (`fluffychat.apk`). В APK — `libapp.so` на 25 МБ и `libflutter.so` на 11 МБ, а `classes.dex` почти пуст. Логика, включая обращение к API и шифрование сообщений, — в Dart-коде, скомпилированном AOT. `jadx` бесполезен: он покажет только загрузчик. План меняется: `strings libapp.so` для URL и ключей, Ghidra с `reFlutter` для функций, анализ `flutter_assets` для конфигов. Тот же APK, но методика — совсем другая.

## Частые вопросы

**«Можно ли декомпилировать Flutter в Dart?»** — нет, Dart компилируется AOT в машинный код. **«React Native проще?»** — да, если бандл не в Hermes: тогда это читаемый JS. **«Как определить фреймворк?»** — по наличию `libapp.so`, `libhermesvm.so`, `assets/www`, `assemblies/`. **«Где искать секреты?»** — `strings` по `.so` и бандлам, `assets/`. **«Обфускация мешает?»** — да, но строки часто остаются.

## Практический совет

Не начинайте с `jadx`, не определив фреймворк, — потеряете время. Сначала `unzip -l` и взгляд на `lib/` и `assets/`. Если видите `libapp.so` — это Flutter, готовьтесь к нативному реверсу. Если `libhermesvm.so` или `index.android.bundle` — React Native, работайте с бандлом. Если `assets/www` — Cordova, читайте как веб. Правильный выбор инструмента в самом начале экономит часы.

## Полный прогон от начала до конца

Соберём анализ кросс-платформенного приложения в один сценарий. Сначала `unzip -l app.apk` и взгляд на `lib/` и `assets/`. По признакам определяем фреймворк: `libapp.so` — Flutter, `libhermesvm.so`/`index.android.bundle` — React Native, `assets/www` — Cordova, `assemblies/` — Xamarin. Затем выбираем инструмент: для Flutter — `strings` и Ghidra, для RN — разбор бандла, для Cordova — чтение JS, для Xamarin — `dnSpy`. Ищем URL, ключи и логику. Итог — либо найденные секреты, либо карта того, где искать дальше.

## Ещё один нюанс: общие библиотеки

Кросс-платформенные приложения тянут за собой большие общие библиотеки (`libflutter.so`, `libreactnative.so`). Их размер может вводить в заблуждение: 11 МБ `libflutter.so` — это движок, а не ваш код. Не тратьте время на его реверс: логика приложения лежит в `libapp.so` или в бандле. Отличайте «движок» от «кода приложения» — это экономит дни работы.

## Что мы теперь знаем

По-простому:

1. Фреймворк определяется по содержимому APK (`libapp.so`, `libhermesvm.so`, `assets/www`).
2. Flutter: логика в AOT-нативном `libapp.so`; строки через `strings`.
3. React Native: JS-бандл или Hermes-байткод; строки доступны.
4. Cordova/Ionic: HTML/JS в `assets/www`, читается как веб.
5. Xamarin: .NET-сборки в `assemblies/`, разбираются `dnSpy`.

## На что смотреть дальше

- **Сначала определите фреймворк** — от этого зависит весь план анализа.
- **Flutter и RN** требуют нативного реверса и работы со строками.
- **Cordova** — самый простой: логика как веб.
- **Не забывайте про `assets/`** — там конфиги и базы.

## Квиз

Проверь себя.

```quiz
- question: "Как определить, что APK написан на Flutter?"
  options:
    - "Наличием `libflutter.so` и `libapp.so`"
    - "Наличием `classes.dex`"
    - "Наличием `assets/www`"
    - "Наличием `assemblies/`"
  answer: 0
- question: "Где логика в React Native-приложении?"
  options:
    - "В JS-бандле (`index.android.bundle`) или Hermes-байткоде"
    - "В `res/values/strings.xml`"
    - "В `AndroidManifest.xml`"
    - "В META-INF"
  answer: 0
- question: "Как читать Cordova-приложение?"
  options:
    - "Как обычный веб: HTML/JS в `assets/www`"
    - "Через Ghidra"
    - "Через dnSpy"
    - "Через `service call`"
  answer: 0
- question: "Как разбирают Xamarin-приложения?"
  options:
    - "`dnSpy`/`ilspycmd` по .NET-сборкам в `assemblies/`"
    - "`jadx` по DEX"
    - "`strings` по `.so`"
    - "`content query`"
  answer: 0
- question: "Что даёт `strings libapp.so` в Flutter-приложении?"
  options:
    - "Строки: URL, ключи, подсказки"
    - "Исходный Dart-код"
    - "Java-классы"
    - "XML-ресурсы"
  answer: 0
```

## Куда дальше

Мы научились определять фреймворк и адаптировать анализ. В следующем уроке разберём **tapjacking и task hijacking** — атаки, где злоумышленник перекрывает интерфейс или перехватывает задачу. А пока запомни главное: сначала пойми, на чём написано приложение, — от этого зависит, где искать логику.

## Где пригодится

- **CTF Mobile:** анализ Flutter/RN-приложений.
- **Bug bounty:** поиск секретов в бандлах и `.so`.
- **Пентест:** адаптация методики под фреймворк.
- **Работа:** ревью кросс-платформенных сборок.
