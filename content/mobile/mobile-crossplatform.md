---
id: mobile-crossplatform
title: "Гибридные фреймворки: Cordova, Ionic, Xamarin, .NET MAUI"
category: mobile
parent: mobile-reverse-native
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
## Что такое кросс-платформенные приложения

Значительная часть мобильных приложений написана не на «нативных» Java/Kotlin или Swift, а на кросс-платформенных фреймворках: Cordova/PhoneGap, Ionic, Capacitor, React Native, Flutter, Xamarin/.NET MAUI, Unity. Они позволяют писать один код и собирать под Android и iOS. Для пентеста это важно, потому что **структура пакета и точки анализа отличаются** от обычного APK: вместо чистого DEX вы часто видите веб-ассеты (`www/`), JavaScript-бандл, Hermes-байткод, Dart-snapshot или .NET-сборки.

Общее правило: чем больше логики в JS/Dart/.NET, тем проще её читать (часто без полной декомпиляции), но тем важнее проверить **мосты между «скриптовым» миром и нативным** — именно там исторически возникают уязвимости.

## Cordova / PhoneGap / Ionic

Cordova-приложение — это WebView, загружающий локальные веб-ассеты из `assets/www/`, плюс набор нативных плагинов.

```bash
unzip app.apk -d apk
ls apk/assets/www/            # HTML/JS/CSS приложения
cat apk/assets/www/cordova.js | head
ls apk/assets/www/plugins/    # нативные плагины
```

Ключевые места: `config.xml` (список плагинов, разрешённые домены в `<access origin>`), `whitelist`-плагин (какие URL можно грузить), JS-мост `cordova.exec`. Опасности: слишком широкий whitelist (`<access origin="*">`), кастомные плагины с небезопасными нативными методами, `InAppBrowser` с `_system`/`_blank`. Ищите `grep -rn "exec\|addJavascriptInterface" apk/assets/www`.

## React Native

React Native-приложение содержит JS-бандл и нативную обвязку. В старых версиях бандл лежит как `assets/index.android.bundle` (читаемый JS), в новых — компилируется в **Hermes bytecode** (`*.hbc`), который нужно дизассемблировать.

```bash
unzip app.apk -d apk
ls apk/assets/ | grep -i bundle
file apk/assets/index.android.bundle          # JS или Hermes?
# для Hermes: hbctool / hermes-dec
pip install hermes-dec
hermes-dec apk/assets/index.android.bundle > bundle.js
grep -nE "api[_-]?key|secret|token|https?://" bundle.js | head
```

Бизнес-логика (валидация, проверки ролей) часто в JS — её можно прочитать и найти обходы. Секреты тоже нередко «зашиты» прямо в бандл.

## Xamarin / .NET MAUI

Xamarin-приложения компилируются в .NET-сборки (`assemblies/` или `assemblies.blob`), а код — в IL, который легко декомпилируется.

```bash
unzip app.apk -d apk
ls apk/assemblies/            # .dll или assemblies.blob
# инструменты: ILSpy, dnSpy, dotPeek; для blob — xamarin-assembly-unpacker
ilspycmd app.dll -o out_src
grep -rn "ApiKey\|Password\|Secret" out_src | head
```

Плюс: получаете почти исходный C#. Минус: часть кода может быть AOT-скомпилирована в native — тогда смотрите `.so` (`mobile-android-native`).

## Flutter

Flutter-приложение содержит `libflutter.so` (движок) и `libapp.so` (ваш Dart-код, скомпилированный AOT в snapshot). Строки и логика в `libapp.so` зашифрованы/скомпилированы.

```bash
unzip app.apk -d apk
ls apk/lib/arm64-v8a/         # libapp.so, libflutter.so
# инструменты: reFlutter (патч движка для дампа), blutter (декомпилятор Dart AOT)
git clone https://github.com/worawit/blutter
python blutter.py apk/lib/arm64-v8a out_dir
# в out_dir — дизассемблированный Dart, строки, список классов
grep -rn "FLAG\|secret\|https://" out_dir/ | head
```

`reFlutter` патчит `libflutter.so` так, чтобы движок дампил трафик и объекты — удобно для динамики и обхода pinning во Flutter.

## Общие слабости кросс-платформенных приложений

| Слабость | Cordova/Ionic | React Native | Flutter | Xamarin |
|----------|---------------|--------------|---------|---------|
| Логика в открытом виде | JS в `www/` | JS/Hermes | Dart snapshot | IL |
| Секреты в бандле | часто | часто | в `libapp.so` | в .dll |
| Мост к нативу | `cordova.exec` | NativeModules | MethodChannel | JNI |
| Обход pinning | правка whitelist | Frida | reFlutter | Frida |
| Где искать секреты | `www/`, `config.xml` | `bundle`/`hbc` | `libapp.so` | `assemblies/` |

Ключевое: **проверяйте мосты** (NativeModules, MethodChannel, JNI) — там приложение вызывает нативный код с параметрами из скриптового мира, и именно там ищут инъекции.

## Разобранный пример: секрет в React Native

```bash
$ unzip app.apk -d apk
$ ls apk/assets/
index.android.bundle
$ file apk/assets/index.android.bundle
... Hermes JavaScript bytecode ...
$ hermes-dec apk/assets/index.android.bundle > bundle.js
$ grep -nE "apiKey|Bearer|secret" bundle.js | head
41203: const API_KEY = "sk_live_51H...";   // Stripe live key
41204: const BASE = "https://api.target.example/v1";
```

Секрет извлечён без запуска приложения. Дальше — проверить, что ключ валиден и что он позволяет (часто это прямой доступ к платёжному/облачному API).

## Разобранный пример: реверс Flutter

```bash
$ python blutter.py apk/lib/arm64-v8a out
[*] Dart version: 3.x
[*] Dumping objects, strings, classes...
$ grep -rn "FLAG{" out/strings.txt
FLAG{flutter_snapshot_is_readable}
$ grep -rn "checkLicense\|isPremium" out/asm/ | head
```

Логика проверки лицензии видна в дизассемблированном Dart — можно найти обход или понять, что проверка клиентская.

## Справочная таблица инструментов

| Фреймворк | Артефакт | Инструмент | Команда |
|-----------|----------|-----------|---------|
| Cordova/Ionic | `www/` JS | grep, beautifier | `grep -rn secret apk/assets/www` |
| React Native | `bundle`/`.hbc` | hermes-dec | `hermes-dec bundle > bundle.js` |
| Flutter | `libapp.so` | blutter | `python blutter.py lib/arm64-v8a out` |
| Flutter (dyn) | `libflutter.so` | reFlutter | `reflutter app.apk` |
| Xamarin | `.dll`/blob | ILSpy, dnSpy | `ilspycmd app.dll -o out` |
| Unity | `assets/bin/Data` | Il2CppDumper | `Il2CppDumper libil2cpp.so global-metadata.dat` |

## Типовые ошибки новичка

- **Искать только Java.** В RN/Flutter/Xamarin основной код не в DEX — `jadx` покажет лишь обвязку.
- **Не дизассемблировать Hermes/Dart.** «Нечитаемый» бандл всё равно дизассемблируется; не сдавайтесь на `file`.
- **Игнорировать мосты.** NativeModules/MethodChannel — главный источник уязвимостей.
- **Забыть про iOS-сборку.** Логика та же, но артефакты другие (`.app`, `Frameworks/`).
- **Пропустить whitelist.** В Cordova широкий whitelist = загрузка чужого контента в WebView.

## Что дальше / решение

Определите фреймворк по структуре APK (`assets/www` → Cordova; `index.android.bundle` → RN; `libapp.so` → Flutter; `assemblies/` → Xamarin), извлеките код подходящим инструментом, ищите секреты и логику. Затем проверьте мосты к нативу и переходите к динамике (`mobile-dynamic-frida`) и трафику (`mobile-mitm-burp`). Связанные уроки: `mobile-flutter` (углублённо), `mobile-static-analysis`, `mobile-hardcoded-secrets`, `mobile-android-native`. Решение — когда вы прочитали логику и/или извлекли секреты, недоступные через «обычный» Java-анализ.

## Как быстро определить фреймворк

Прежде чем выбирать инструмент, определите фреймворк по «отпечатку» пакета:

```bash
unzip app.apk -d apk
# Cordova/Ionic/Capacitor
ls apk/assets/www 2>/dev/null && echo "CORDOVA/IONIC"
# React Native
ls apk/assets/index.android.bundle 2>/dev/null && echo "REACT NATIVE"
# Flutter
ls apk/lib/*/libapp.so 2>/dev/null && echo "FLUTTER"
# Xamarin/.NET MAUI
ls apk/assemblies* 2>/dev/null && echo "XAMARIN"
# Unity
ls apk/assets/bin/Data/Managed 2>/dev/null && echo "UNITY"
```

Дальше по таблице выбираете инструмент и читаете код. Если в пакете несколько признаков (например, RN + нативные модули), анализируйте оба слоя. На iOS те же фреймворки дают `.app/Frameworks/` (Flutter → `Flutter.framework`, RN → `main.jsbundle`, Cordova → `www/`), а логика извлекается теми же инструментами (hermes-dec, blutter, ILSpy работают с файлами, не с платформой).

## Квиз

```quiz
- question: "Где лежит логика Cordova/Ionic приложения в APK?"
  options:
    - "В assets/www/ (HTML/JS)"
    - "В classes.dex"
    - "В AndroidManifest.xml"
    - "В libapp.so"
  answer: 0
  explanation: "Cordova/Capacitor хранят веб-приложение в assets."
- question: "Во что компилируется Xamarin-приложение?"
  options:
    - ".NET-сборки (IL) в assemblies/"
    - "Только DEX"
    - "libapp.so (Dart)"
    - "WASM"
  answer: 0
  explanation: "Xamarin кладёт .NET-сборки, которые декомпилируются в C#."
- question: "Каким инструментом декомпилировать .NET-сборку?"
  options:
    - "ILSpy / dnSpy / ilspycmd"
    - "jadx"
    - "apktool"
    - "binwalk"
  answer: 0
  explanation: "ILSpy/dnSpy восстанавливают C# из IL."
- question: "Где объявлены Cordova-плагины?"
  options:
    - "В res/xml/config.xml"
    - "В build.gradle"
    - "В strings.xml"
    - "В Info.plist"
  answer: 0
  explanation: "config.xml перечисляет feature/plugin и их доступ."
- question: "Почему гибридные приложения часто проще анализировать?"
  options:
    - "Логика в читаемых JS или декомпилируемом IL"
    - "В них нет кода"
    - "Они не используют API"
    - "Они не компилируются"
  answer: 0
  explanation: "Исходная логика восстанавливается легче, чем нативный код."
```

## Где пригодится

- **CTF Mobile:** быстрый реверс, секреты в JS/IL.
- **Bug bounty:** зашитые ключи и слабые WebView-мосты.
- **Пентест:** аудит гибридных приложений.
- **Работа:** ревью кросс-платформенных клиентов.
