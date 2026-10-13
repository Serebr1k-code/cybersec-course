---
id: mobile-react-native-reversing
title: "Реверс React Native: Hermes-байткод и JS-бандлы"
category: mobile
parent: mobile-native-reversing
difficulty: hard
order: 2
tags: [react-native, hermes, bytecode, hbc, index.android.bundle, jsc, reversing, frida]
prerequisites: [mobile-flutter, mobile-static-analysis]
useful_for:
  - "Реверс-инжиниринг мобильных приложений"
  - "Пентест мобильных приложений"
  - "CTF Mobile"
estimated_minutes: 50
summary: "Как реверсить React Native: JS-бандл, Hermes bytecode (HBC), инструменты hermes-dec/hbctool, поиск секретов и хуки через Frida."
lab:
  kind: shell
  title: 'Практика: реверс React Native'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, hermes_strings.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`hermes_strings.txt` — строки из Hermes-байткода.'
    - 'Hermes компилирует JS; строки извлекаются `hbctool`/`strings`.'
    - 'Среди строк есть флаг — найди `nto{` и запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

Открываешь APK в jadx — и снова почти нет логики: обёртки, мост между JavaScript и нативным кодом, а сам код приложения где-то в `assets/`. Приложение на React Native. Где лежит логика, как её прочитать и чем она отличается от Flutter?

## Наш пример: Mattermost

Возьмём реальное приложение — **Mattermost** для Android (клиент корпоративного мессенджера). Оно собрано на React Native. Проследим путь от APK до JavaScript-кода.

## Шаг 1: определяем движок

Сначала смотрим библиотеки внутри APK. React Native использует один из двух JS-движков: JavaScriptCore (`libjsc.so`) или Hermes (`libhermes.so`/`libhermesvm.so`). Для Mattermost видно:

```
$ unzip -l mattermost.apk | grep -E 'hermes|jsc'
 138824  lib/arm64-v8a/libhermestooling.so
2141744  lib/arm64-v8a/libhermesvm.so
```

`libhermesvm.so` — это движок Hermes. Значит, JS-код приложения скомпилирован в **Hermes bytecode** (сокращённо HBC) — компактное представление JavaScript, которое движок исполняет без парсинга текста.

## Шаг 2: находим и опознаём бандл

Код приложения лежит в `assets/index.android.bundle`. Извлечём и посмотрим, что это за файл:

```
$ unzip -o mattermost.apk assets/index.android.bundle -d mm
$ file mm/assets/index.android.bundle
mm/assets/index.android.bundle: Hermes JavaScript bytecode, version 96
$ ls -la mm/assets/index.android.bundle | awk '{print $5}'
22587012
```

Файл 22 МБ, и `file` прямо говорит: **Hermes JavaScript bytecode, version 96**. Первые байты подтверждают формат — это магическая сигнатура Hermes:

```
$ xxd mm/assets/index.android.bundle | head -1
00000000: c61f bc03 c103 191f 6000 0000 284f c293  ........`...(O..
```

`c6 1f bc 03` — magic-заголовок, дальше `c1 03` — версия HBC. Если бы бандл был не скомпилирован (режим JSC), это был бы обычный текстовый JS, и `strings` показал бы читаемый код сразу.

## Шаг 3: что даёт `strings` по бандлу

Даже без специальных инструментов HBC-бандл отдаёт много информации — имена модулей, строки, пути исходных файлов. Вытащим пути экранов:

```
$ strings -n 8 index.android.bundle | grep -oE '/\([a-z_]+\)[a-zA-Z0-9_/().-]*\.tsx' | sort -u | head
/(authenticated)/(home)/_layout.tsx
/(authenticated)/(home)/account.tsx
/(authenticated)/(home)/channel_list.tsx
/(authenticated)/(home)/index.tsx
/(authenticated)/(home)/mentions.tsx
/(authenticated)/(home)/search.tsx
/(authenticated)/_layout.tsx
```

Всего таких путей в бандле — **123**. Это карта навигации приложения: видно группу `(authenticated)` (экраны после входа), `(modals)` (модальные окна), `(settings)` (настройки). То есть для React Native `strings` даёт заметно больше, чем для Flutter: сохраняются пути исходных `.tsx`-файлов.

Плюс находятся имена нативных модулей и API (`RCTDeviceEventEmitter`, `NativeModules`, `TurboModule`), строки UI, названия функций. По ним восстанавливается структура приложения.

## Шаг 4: дизассемблируем Hermes bytecode

Чтобы получить из HBC осмысленный код, нужны инструменты, понимающие формат байткода:

- **`hermes-dec`** — дизассемблер и декомпилятор HBC: показывает байткод-инструкции и восстанавливает читаемый JS.
- **`hbctool`** — позволяет разобрать HBC на инструкции и собрать обратно (после патча).
- **`hermesc`** — компилятор Hermes из комплекта RN; умеет дизассемблировать (`-dump-bytecode`).

Выглядит это так:

```
$ hermes-dec disassemble index.android.bundle > out.hasm
$ hermes-dec decompile index.android.bundle > out.js
```

На выходе — поток байткод-инструкций (`GetGlobalObject`, `Call`, `LoadConstString`) или восстановленный JS. Имена функций при компиляции с `--minify` урезаны, но строки и структура остаются.

## Шаг 5: ищем секреты и логику

Типичные находки в RN-бандлах:

- **Ключи API и токены** — часто прямо в JS как строки. Ищем по шаблонам: `strings index.android.bundle | grep -iE 'api[_-]?key|secret|token|bearer'`.
- **URL бэкенда** — `https://...` в строках; по ним видно, куда приложение ходит.
- **Флаги фич и конфиги** — строки вида `FEATURE_*`, `ENABLE_*`.
- **Логика проверок** — в декомпилированном JS находятся функции валидации.

Если строки зашифрованы или имена обфусцированы, помогает динамика: Frida перехватывает методы Java-моста (`Java.use("com.facebook.react.bridge.CatalystInstanceImpl")`) и видит данные, которые JS передаёт в нативную часть.

Триаж по строкам делается одной командой — прогоняем бандл через регулярные выражения для типовых секретов:

```
$ strings index.android.bundle | grep -iE 'api[_-]?key|secret|bearer|firebaseio|amazonaws' | head
```

Даже если имена функций минифицированы, эти строки остаются читаемыми, потому что нужны самому коду в рантайме.

## Шаг 5б: Hermes vs JavaScriptCore

Полезно понимать, почему движок вообще важен. Если приложение собрано с **JavaScriptCore** (JSC), в `assets/` лежит обычный текстовый JavaScript — его можно открыть редактором, и `strings`/`grep` работают по нему напрямую. Если с **Hermes**, тот же код скомпилирован в байткод: текст инструкций заменён на числовые опкоды, а часть исходных имён и комментариев потеряна. Поэтому:

- **JSC** — «повезло»: ищите секреты прямо `grep`-ом по бандлу.
- **Hermes** — нужен дизассемблер (`hermes-dec`), потому что «как есть» байткод не читается.

Определить движок можно по `file` (Hermes выдаёт свой формат) и по наличию `libhermes*.so`. Стоит помнить: современный React Native по умолчанию использует Hermes — именно ради скорости и размера бандла.

## Шаг 5в: отладка JS в рантайме

Для Hermes-бандла есть и динамический путь: движок поддерживает отладку через Chrome DevTools. Если в приложении не отключён debug-режим, можно подключиться к `chrome://inspect` и увидеть JS-контекст: поставить точки останова, посмотреть переменные, выполнить выражения. Это дополняет статику: вы не читаете байткод, а наблюдаете выполнение. На релизных сборках отладка обычно отключена, тогда остаются Frida-хуки на мост и на сетевой слой.

## Шаг 6: патч бандла

Иногда нужно изменить поведение: убрать проверку, развернуть редирект. Порядок такой:

1. `hbctool disasm index.android.bundle out_dir` — разобрать HBC.
2. Внести правку в ассемблер (например, заменить условный переход).
3. `hbctool asm out_dir index.android.bundle` — собрать обратно.
4. Положить бандл назад в APK и подписать (`apksigner`).

⚠️ Важно: патчить нужно тот же HBC, что и в APK, иначе приложение упадёт при загрузке. И учитывайте **CodePush** — механизм обновления JS-бандла «на лету»: приложение может подтянуть новый бандл с сервера, и правка в APK окажется неактуальной.

## Что мы теперь знаем

По-простому:

1. React Native узнаётся по `libhermes.so`/`libjsc.so` и бандлу `assets/index.android.bundle`.
2. Hermes-бандл — это байткод (`file` скажет «Hermes JavaScript bytecode, version N»), magic начинается с `c6 1f bc 03`.
3. `strings` по бандлу даёт пути `.tsx`, имена модулей и часто — секреты.
4. Для чтения кода нужны `hermes-dec`/`hbctool`/`hermesc`.
5. Патч бандла возможен, но мешает CodePush (обновление бандла по сети).

## На что смотреть дальше

- **`file` — первая команда.** Она сразу скажет, HBC это или обычный JS.
- **Ищите `.tsx`-пути.** Они дают карту приложения бесплатно.
- **Строки не минифицируются.** Даже при обфускации ищите ключи и URL по строкам.
- **Проверьте CodePush.** Иначе патч APK не даст эффекта.

## Квиз

Проверь себя.

```quiz
- question: "Как опознать Hermes-бандл по команде file?"
  options:
    - "Он сообщит: Hermes JavaScript bytecode, version N"
    - "Он покажет ELF shared object"
    - "Он покажет ZIP archive"
    - "Он покажет HTML document"
  answer: 0
- question: "Где в React Native APK лежит код приложения?"
  options:
    - "assets/index.android.bundle"
    - "classes.dex"
    - "lib/<abi>/libapp.so"
    - "res/values/strings.xml"
  answer: 0
- question: "Что такое Hermes bytecode (HBC)?"
  options:
    - "Скомпилированное представление JavaScript для движка Hermes"
    - "Формат картинок"
    - "Тип сертификата"
    - "Архив ресурсов"
  answer: 0
- question: "Что даёт strings по RN-бандлу?"
  options:
    - "Пути .tsx, имена модулей и часто ключи/URL"
    - "Пароли Wi-Fi"
    - "Исходники на C"
    - "Схему платы"
  answer: 0
- question: "Почему патч бандла в APK может не сработать?"
  options:
    - "CodePush подтягивает обновлённый бандл с сервера"
    - "APK нельзя распаковать"
    - "Hermes запрещает патч"
    - "Нужен root на устройстве"
  answer: 0
```

## Куда дальше

Теперь ты видишь оба кросс-платформенных пути: Flutter (Dart AOT в `libapp.so`, реверс через blutter) и React Native (Hermes-байткод в `index.android.bundle`, реверс через hermes-dec). Дальше мы перейдём к тому, что объединяет их — динамическому анализу и хукам. А пока главное: у React Native `strings` по бандлу сразу даёт карту приложения, а для чтения логики нужен дизассемблер HBC.

## Где пригодится

- **Реверс-инжиниринг:** разбор React Native-приложений, восстановление JS-логики.
- **Пентест:** поиск секретов и ключей в бандле, оценка клиентских проверок.
- **CTF Mobile:** задачи с Hermes-байткодом и патчем JS.
- **Bug bounty:** анализ кроссплатформенных клиентов, где логика вынесена в JS.
