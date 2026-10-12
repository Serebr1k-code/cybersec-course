---
id: mobile-flutter
title: "Flutter и React Native: реверс кросс-платформенных приложений"
category: mobile
parent: mobile-reverse-native
difficulty: hard
order: 2
tags: [flutter, react-native, dart, hermes, index.android.bundle, reversing, blutter]
prerequisites: [mobile-static-analysis]
useful_for:
  - "CTF Mobile (реверс Flutter/RN)"
  - "Bug bounty (секреты и логика в JS/Dart)"
  - "Пентест мобильных приложений"
estimated_minutes: 40
summary: "Чем Flutter (Dart/AOT) и React Native (JS/Hermes) отличаются от нативного Android, как извлекать и анализировать их код, находить секреты и хукать логику."
---

## Вопрос, с которого всё начинается

Открываешь APK в jadx — а там почти нет кода: пара классов-обёрток, и всё. Основная логика где-то в другом месте. Приложение собрано на кроссплатформенном фреймворке — Flutter или React Native. Обычные мобильные инструменты (jadx, apktool) здесь показывают почти пустую картину. Как понять, что перед тобой, и с чего начать реверс?

## Наш пример: шахматный клиент на Flutter

Возьмём реальное открытое приложение — **Lichess** для Android (клиент шахмат). Оно собрано на Flutter. Проследим, как от APK дойти до Dart-кода, и что вообще доступно для анализа.

## Шаг 1: как распознать Flutter

Flutter-приложения узнаются по содержимому `lib/`. Посмотрим список файлов внутри APK:

```
$ unzip -l lichess.apk | grep -E 'libapp|libflutter'
 18744200  lib/arm64-v8a/libapp.so
 11747864  lib/arm64-v8a/libflutter.so
 20824648  lib/armeabi-v7a/libapp.so
  8615900  lib/armeabi-v7a/libflutter.so
 19006344  lib/x86_64/libapp.so
 13051424  lib/x86_64/libflutter.so
```

Два имени выдают фреймворк:

- **`libflutter.so`** — движок Flutter (сам рантайм);
- **`libapp.so`** — скомпилированный код *твоего* приложения на языке Dart.

Если видишь эту пару — приложение на Flutter. У React Native было бы иначе: JS-бандл `index.android.bundle` в `assets/` и библиотеки `libhermes.so`/`libjsc.so`.

## Шаг 2: почему jadx здесь бессилен

Java/Kotlin-код Flutter-приложения — тонкая обёртка: `MainActivity` просто запускает движок. Вся бизнес-логика написана на Dart и скомпилирована **AOT** (ahead-of-time, заранее) в машинный код внутри `libapp.so`. В `classes.dex` её нет — потому jadx и показывает пустоту.

Посмотрим, что за файл `libapp.so`:

```
$ file lib/x86_64/libapp.so
libapp.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
    dynamically linked, BuildID[md5/uuid]=ec7cbe18..., stripped
```

`ELF`, `x86-64`, `stripped`. Как и обычная нативная библиотека, но это не C/C++ — внутри машинный код, порождённый Dart-компилятором.

## Шаг 3: что можно вытащить без специальных инструментов

Первое, что даёт `strings` — имена пакетов и файлов Dart. Они остаются в снапшоте, потому что используются для отладки и трассировок:

```
$ strings -n 6 libapp.so | grep -E 'dart|package:|\.dart' | head
_kDartSnapshotText
_kDartSnapshotData
package:flutter_local_notifications/src/callback_dispatcher.dart
package:material_symbols_icons/symbols.dart
file:///home/runner/work/mobile/mobile/.dart_tool/flutter_build/dart_plugin_registrant.dart
dart:convert
package:lichess_mobile/src/model/notifications/notification_service.dart
```

Разберём, что мы видим:

- **`_kDartSnapshotText`**, **`_kDartSnapshotData`** — маркеры того, что это Dart-снапшот (отдельно текст программы и данные);
- **`package:.../notification_service.dart`** — имена исходных файлов приложения. По ним восстанавливается карта: какие модули есть и что они делают;
- **`file:///home/runner/work/mobile/mobile/...`** — путь сборки на CI-сервере сборщика. Мелочь, но выдаёт пайплайн.

Попробуем получить символы функций:

```
$ nm libapp.so
nm: libapp.so: no symbols
```

Символов нет — Dart-компилятор их не сохраняет. То есть привычный путь «`nm -D` → найти функцию → дизассемблировать» здесь не работает: имён функций Dart в бинарнике нет.

## Шаг 4: как всё-таки реверсить Dart

Поскольку символьной информации нет, для Flutter применяют специальные инструменты, понимающие формат Dart-снапшота:

- **`blutter`** — восстанавливает из `libapp.so` список Dart-классов, функций и даже пересобирает псевдо-исходники на C. Работает с конкретной версией Dart, поэтому сначала определяют версию снапшота (по строке-маркеру или по `libflutter.so`).
- **`reFlutter`** — пропатчивает `libflutter.so`, чтобы включить отладочные возможности движка, и позволяет подключаться к приложению как к отлаживаемому.
- **Frida** — работает поверх всего: можно перехватывать нативные функции движка и сетевой слой, не понимая структуру Dart-кода.

Ключевая мысль: реверс Flutter — это не «открыть Ghidra и читать», а сначала восстановить имена (blutter), а потом уже смотреть логику.

Важная деталь: `blutter` жёстко привязан к версии Dart, которой собран снапшот. Версию определяют по строке-маркеру в `libapp.so` или по хэшу `libflutter.so` — у каждой сборки Flutter он свой. Если взять blutter от другой версии Dart, он не разберёт снапшот и упадёт с ошибкой формата. Поэтому первым делом фиксируют версию движка, и уже под неё берут инструмент.

## Шаг 5: чем React Native отличается на практике

React Native устроен иначе: логика на JavaScript, которая либо компилируется в **Hermes bytecode** (файл `index.android.bundle`), либо исполняется через JavaScriptCore. В нашем разборе APK Mattermost видно характерные имена:

```
lib/arm64-v8a/libhermesvm.so
lib/arm64-v8a/libhermestooling.so
```

Наличие `libhermesvm.so` говорит: это React Native на движке Hermes. Бандл извлекается из `assets/index.android.bundle`:

```
$ unzip -o mattermost.apk assets/index.android.bundle -d mm
$ strings -n 8 mm/assets/index.android.bundle | grep -E '\.tsx' | head
/(authenticated)/code.tsx
/(authenticated)/(home)/index.tsx
/(authenticated)/channel.tsx
/(modals)/(settings)/settings_display_theme.tsx
```

Это реальный вывод из бандла: пути исходных экранов приложения сохранились как строки. То есть для RN `strings` по бандлу сразу даёт карту приложения — гораздо больше, чем для Flutter. По этим путям видно структуру навигации: экраны аутентификации, домашний, каналы, модальные окна.

Разница по сути: **Flutter → машинный код Dart (нужен blutter), React Native → байткод JS (читается инструментами для Hermes)**.

## Шаг 6: динамика поверх обоих фреймворков

Что делать, если статика упирается? Frida работает на уровне нативных вызовов, а значит, подходит и для Flutter, и для React Native. Для RN можно перехватывать методы Java-мостов (`Java.use("com.facebook.react.bridge.CatalystInstanceImpl")`) и смотреть, какие данные ходят между JS и нативным кодом. Для Flutter — перехватывать нативные функции движка и сетевой слой: Dart-код в итоге упирается в вызовы `libc` и `libflutter.so`, которые Frida видит.

Практический порядок такой: сначала статически определить фреймворк и вытащить строки (`strings` по `libapp.so` или бандлу), затем, если логика неясна, переходить к динамике — там уже не важно, Dart это или JS, потому что хуки ставятся на нативном уровне.

## Шаг 7: разделённые APK и выбор ABI

Современные приложения часто распространяются как **split APK** (App Bundle): базовый APK плюс отдельные файлы под каждую архитектуру. Тогда `libapp.so` может отсутствовать в основном APK — его надо взять из `split_config.arm64_v8a.apk`. При анализе берите ту архитектуру, на которой будете запускать: `arm64-v8a` для телефона, `x86_64` для эмулятора. Если взять не ту, приложение просто не запустится, а дизассемблер покажет чужой код.

## Что мы теперь знаем

По-простому:

1. Пара `libflutter.so` + `libapp.so` в APK = приложение на Flutter.
2. Логика Flutter — Dart-код, скомпилированный AOT в `libapp.so`; в jadx его нет.
3. `strings` по `libapp.so` даёт имена Dart-пакетов и файлов, но не имена функций.
4. Для реверса Dart нужен `blutter`; для динамики — `reFlutter` и Frida.
5. React Native узнаётся по `libhermes.so`/`libjsc.so` и бандлу `index.android.bundle`.

## На что смотреть дальше

- **Сначала определите фреймворк.** От этого зависит весь инструментарий.
- **Версия Dart критична.** `blutter` работает не со всеми версиями — сверяйтесь с `libflutter.so`.
- **`strings` не выбрасывайте.** Имена файлов и пакетов часто прямо указывают, где искать секрет.
- **Сравните с RN.** Если есть `index.android.bundle` — вы в React Native, и путь другой.

## Квиз

Проверь себя.

```quiz
- question: "По какому признаку в APK опознают Flutter-приложение?"
  options:
    - "Наличие пары libflutter.so и libapp.so"
    - "Наличие classes.dex"
    - "Наличие AndroidManifest.xml"
    - "Наличие resources.arsc"
  answer: 0
- question: "Что такое libapp.so во Flutter-приложении?"
  options:
    - "Скомпилированный AOT-код приложения на Dart"
    - "Движок Flutter"
    - "Библиотека шрифтов"
    - "Кэш ресурсов"
  answer: 0
- question: "Почему jadx почти не показывает код Flutter-приложения?"
  options:
    - "Логика вынесена в Dart AOT внутри libapp.so, а не в DEX"
    - "Приложение зашифровано"
    - "jadx не поддерживает APK"
    - "DEX удалён"
  answer: 0
- question: "Зачем нужен blutter?"
  options:
    - "Восстанавливает классы и функции Dart из libapp.so"
    - "Подписывает APK"
    - "Перехватывает сеть"
    - "Читает SharedPreferences"
  answer: 0
- question: "Что указывает на React Native, а не Flutter?"
  options:
    - "libhermesvm.so и бандл index.android.bundle"
    - "libapp.so"
    - "libflutter.so"
    - "res/values/strings.xml"
  answer: 0
```

## Куда дальше

В следующем уроке мы возьмём `libapp.so` и разберём реверс Dart-снапшота подробно: как определить версию, что именно восстанавливает `blutter` и как из Dart-проверки достать секрет. А пока главное: увидел `libflutter.so` + `libapp.so` — значит, перед тобой Dart AOT, и обычные инструменты Android тут не помогут.

## Где пригодится

- **CTF Mobile:** Flutter-приложения как отдельный класс задач с проверкой внутри Dart.
- **Bug bounty:** анализ кроссплатформенных приложений, где секреты лежат в Dart/JS.
- **Пентест:** оценка защиты (обфускация Dart, анти-анализ) в мобильных клиентах.
- **Работа:** понимание архитектуры кроссплатформенных приложений при разборе инцидентов.
