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
---
## Введение

React Native-приложения выполняют JavaScript в бандле `index.android.bundle` (или `main.jsbundle` на iOS). С движком JavaScriptCore бандл — обычный JS (читается глазами). С **Hermes** бандл компилируется в Hermes bytecode (HBC) — компактный байткод, который нельзя прочитать как текст, но можно дизассемблировать/декомпилировать. Логика, API-ключи, эндпоинты и даже секреты часто лежат в бандле — это ключевой источник находок.

Задача пентеста: извлечь бандл, определить движок, дизассемблировать HBC, найти строки и функции, при необходимости — хукать через Frida.

## Определение движка и извлечение бандла

```bash
unzip -l app.apk | grep -iE 'bundle|hermes|jsc|react'
# assets/index.android.bundle
# lib/arm64-v8a/libhermes.so     -> Hermes
# lib/arm64-v8a/libjsc.so        -> JavaScriptCore
unzip app.apk 'assets/*' -d out
file out/assets/index.android.bundle
head -c 8 out/assets/index.android.bundle | xxd
# HBC magic: начинается с 0xC61FBC03 (или 'hbc' версии)
```

Если `head -c` показывает читаемый JS — движок JSC, читайте напрямую. Если бинарь с магией HBC — Hermes.

## Hermes bytecode: инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `hermes-dec` | дизассемблер/декомпилятор HBC |
| `hbctool` | дизасм/патч HBC |
| `hermes` CLI | официальные утилиты (`-dump-bytecode`) |
| `jadx` | помогает найти мост Java↔JS |
| Frida | рантайм-хуки JS/нативы |

```bash
# hermes-dec
pip install hermes-dec
hbc-disassembler index.android.bundle out.hasm
hbc-decompiler index.android.bundle out.js

# hbctool
hbctool disasm index.android.bundle /tmp/hbc_out
ls /tmp/hbc_out   # инструкции + строки
```

## Поиск секретов и логики

```bash
# строки из дизасма
strings -n 6 out/assets/index.android.bundle | grep -iE 'api|key|token|secret|firebase|http' | head
grep -oiE 'https?://[^"]+' /tmp/hbc_out/*.json 2>/dev/null | sort -u | head
```

React Native часто хранит конфиг в JS (`Config.js`), URL API, ключи Firebase, а иногда и бизнес-логику валидации. Всё это доступно после декомпиляции.

## Полный сквозной пример: обход проверки в JS

```bash
# 1. Извлекаем и декомпилируем бандл
unzip app.apk assets/index.android.bundle -d out
hbc-decompiler out/assets/index.android.bundle app.js
# 2. Ищем проверку
grep -n "isRooted\|isJailbroken\|integrity\|checkLicense" app.js | head
# 3. Находим функцию, например:
#    const isRooted = () => DeviceInfo.isRooted();
# 4. Хукаем нативно через Frida (метод моста React Native)
```

Frida-хук JS-функции через Hermes сложен, но часто проверка идёт через нативный модуль:

```javascript
Java.perform(function() {
  var DeviceInfo = Java.use("com.learnium.RNDeviceInfo.RNDeviceInfo");
  DeviceInfo.isRooted.implementation = function() { return false; };
});
```

Либо патчим HBC (`hbctool disasm` → правка инструкции возврата → `hbctool asm`) и переупаковываем.

## Патч Hermes-бандла

```bash
hbctool disasm index.android.bundle /tmp/hbc
# правим /tmp/hbc/instructions/... (например, OpCode возврата true->false)
hbctool asm /tmp/hbc index.android.bundle.patched
# заменяем в APK, zipalign, apksigner, устанавливаем
```

## Частые ошибки

- **Считать бандл текстом**: при Hermes это байткод — нужны инструменты.
- **Неверная версия HBC**: hermes-dec/hbctool должны поддерживать версию байткода; обновите.
- **Искать только в assets**: мосты Java↔JS в DEX (`ReactNativeHost`, `ReactPackage`).
- **Патч HBC ломает выравнивание**: после правки обязательны zipalign+sign.
- **Игнорировать source maps**: в debug-сборках есть `.map` — даёт исходники.
- **Забыть про iOS**: `main.jsbundle` — тот же подход.

## Что дальше / решение

Порядок: извлечь бандл → определить Hermes/JSC → декомпилировать → найти строки/функции → хукать или патчить. Свяжите с `mobile-flutter` (кросс-платформы), `mobile-native-so-deep` (нативные модули), `mobile-static-analysis`. Дальше — ветвь `mobile-forensics`.

## Справочная таблица

| Признак | Движок |
|---------|--------|
| libhermes.so + HBC magic | Hermes |
| libjsc.so + читаемый JS | JavaScriptCore |
| index.android.bundle | Android бандл |
| main.jsbundle | iOS бандл |

| Инструмент | Роль |
|-----------|------|
| hermes-dec | декомпиляция HBC |
| hbctool | дизасм/патч HBC |
| Frida | хуки мостов |
| jadx | Java-мост |

## Полный разбор RN-приложения

**Шаг 1. Идентификация движка.**

```bash
unzip -l app.apk | grep -iE 'bundle|hermes|jsc|react'
unzip app.apk 'assets/*' 'lib/*' -d out
file out/assets/index.android.bundle
head -c 16 out/assets/index.android.bundle | xxd
```

Если `libhermes.so` есть и файл начинается с HBC-магии — Hermes. Если `libjsc.so` и бандл текстовый — JavaScriptCore.

**Шаг 2. Декомпиляция (Hermes).**

```bash
pip install hermes-dec
hbc-decompiler out/assets/index.android.bundle app.js
wc -l app.js
head -50 app.js
```

**Шаг 3. Поиск логики и секретов.**

```bash
grep -nE 'https?://|apiKey|firebase|token|secret' app.js | head -30
grep -nE 'isRooted|isJailbroken|integrity|checkLicense|DeviceInfo' app.js | head
```

React Native часто держит конфиг в одном файле (`Config.js`/`constants.js`), что делает поиск быстрым.

**Шаг 4. Мост Java↔JS.**

```bash
jadx -d out app.apk
grep -rn "ReactPackage\|ReactNativeHost\|ReactContextBaseJavaModule\|@ReactMethod" out/sources/ | head
```

Нативные модули (`@ReactMethod`) — точка, где JS вызывает Java. Если модуль делает что-то опасное (файлы, exec), это sink.

**Шаг 5. Патч HBC.**

```bash
hbctool disasm out/assets/index.android.bundle /tmp/hbc
ls /tmp/hbc
# правим инструкцию возврата (например, в функции проверки)
hbctool asm /tmp/hbc out/assets/index.android.bundle.patched
# кладём обратно, zipalign, sign, install
```

## RN-специфика: Hermes vs JSC

| Аспект | Hermes | JavaScriptCore |
|--------|--------|----------------|
| Бандл | HBC (байткод) | JS (текст) |
| Инструмент | hermes-dec/hbctool | текстовый редактор |
| Скорость | выше | ниже |
| Читаемость | низкая | высокая |

Если бандл текстовый — читайте напрямую, ищите секреты и логику; патчить можно правкой JS и перепаковкой.

## Типичные находки

| Находка | Severity |
|---------|----------|
| API-ключи в бандле | Medium/High |
| Секреты Firebase | High |
| Клиентская проверка лицензии | Medium |
| URL внутренних API | Low/Medium |
| Логика авторизации в JS | зависит |

## Методический чек-лист

1. Определить движок (Hermes/JSC).
2. Извлечь и декомпилировать бандл.
3. Найти секреты, URL, логику проверок.
4. Найти нативные мосты (`@ReactMethod`).
5. Построить обход (патч HBC или Frida-хук моста).
6. Оформить рекомендации.

## Рекомендации в отчёте

- Не хранить секреты в JS-бандле (выносить на сервер).
- Клиентские проверки дублировать серверными.
- Минимизировать опасные `@ReactMethod` (файлы, exec).
- Обфусцировать/шифровать бандл, использовать Hermes (усложняет чтение).
- Не полагаться на обфускацию как на защиту.

## Инструменты сообщества и типичные секреты

Помимо hermes-dec и hbctool, в сообществе есть `hermes-dec` (разные форки), `hbc-decompiler`, а также плагины для Ghidra/IDA, понимающие Hermes. Для извлечения строк можно использовать `hbctool disasm` и читать таблицу строк напрямую. Если бандл на JavaScriptCore, он читается текстовым редактором, а source maps (в debug) дают исходные файлы — это самый быстрый путь к логике.

Типичные секреты в RN-бандле: ключи Firebase (`AIza...`), токены платёжных провайдеров (`sk_live_...`), ключи карт (Google Maps, Mapbox), URL внутренних API, ключи шифрования, а иногда и учётные данные тестовых аккаунтов. React Native часто хранит конфиг в `Config.js`/`env.js`, который компилируется в бандл целиком.

## Мосты и нативные модули

Ключевая точка — нативные модули (`@ReactMethod`). Если модуль выполняет файловые операции, сетевые вызовы или `exec`, и JS-код может быть подменён (например, через обновляемый бандл или MITM), это sink. Проверяйте, откуда загружается бандл: если по HTTP или из внешнего источника, возможна подмена кода. Также смотрите `getJSBundleFile`/`getBundleAssetName` — они показывают источник бандла.

## Патч и переупаковка

После правки HBC или JS обязательно выравнивание и подпись. Если приложение проверяет целостность бандла (хэш), патч сломает проверку — тогда хукайте в рантайме (Frida на нативном модуле) вместо патча. Для обновляемых бандлов (CodePush) возможен отдельный вектор: подмена источника обновления.

## Практикум: извлечение и разбор RN-бандла

Разберём конкретный бандл шаг за шагом.

```bash
unzip app.apk assets/index.android.bundle -d out
file out/assets/index.android.bundle
# если HBC — декомпилируем
hbc-decompiler out/assets/index.android.bundle app.js
grep -nE 'firebase|apiKey|https?://' app.js | head
```

Если бандл текстовый (JSC), читаем напрямую. Ищем конфиг:

```bash
grep -nA5 'Config' app.js | head -40
```

Часто весь конфиг (URL, ключи) в одном месте. Находим `apiKey`, `projectId` (Firebase), `baseUrl`. Проверяем, доступны ли эти ключи злоупотреблению (Firebase REST, если правила слабые).

Ищем мосты:

```bash
jadx -d out app.apk
grep -rn "@ReactMethod" out/sources/ | head
```

Каждый `@ReactMethod` — нативная функция, вызываемая из JS. Если она делает файловые операции или `exec`, это sink. Фиксируем путь «вход (бандл/обновление) → мост → sink».

## Продвинутый реверс Hermes: патч и отладка

Патч Hermes-бандла требует понимания структуры HBC: заголовок, таблица функций, таблица строк, байткод. `hbctool disasm` разбирает бандл на читаемые инструкции (`.hasm`) и метаданные. Чтобы изменить поведение, найдите функцию проверки, определите инструкцию условного перехода или возврата и измените её. Например, замените `Jmp` на `JmpTrue`/`JmpFalse` или поменяйте константу. После правки `hbctool asm` собирает бандл обратно.

Важная тонкость: смещения в HBC должны остаться согласованными. hbctool пересчитывает их при сборке, но если вы правите байты вручную, легко сломать бандл. Всегда проверяйте, что приложение запускается после патча, и держите оригинал.

## Отладка JS в рантайме

Для JavaScriptCore можно подключаться отладчиком (Safari/Chrome remote debugging, если приложение его включает). Для Hermes отладка ограничена, но можно логировать через Frida хуки на нативных мостах. Часто проще не отлаживать JS, а обходить проверку на нативной стороне (мост) или патчить бандл.

## Обновляемые бандлы (CodePush)

Некоторые RN-приложения загружают обновлённый JS-бандл по сети (CodePush). Если источник обновления не защищён (HTTP, слабая подпись), возможна подмена кода — серьёзная находка (RCE на уровне JS). Проверяйте `getJSBundleFile`, URL обновления, проверку подписи бандла.

## Что писать в отчёте

Для найденных секретов — путь в бандле и тип. Для обходов — какая проверка и как обойдена. Для обновляемых бандлов — риск подмены. Рекомендации: выносить секреты на сервер, подписывать обновления, дублировать проверки серверными, обфусцировать бандл.

## Квиз

```quiz
- question: "Как отличить Hermes-бандл от обычного JS?"
  options:
    - "По магии HBC в начале файла (байткод, не текст)"
    - "По размеру"
    - "По имени файла"
    - "По подписи APK"
  answer: 0
- question: "Какой инструмент декомпилирует Hermes bytecode?"
  options:
    - "hermes-dec"
    - "apktool"
    - "nmap"
    - "frida-ios-dump"
  answer: 0
- question: "Где обычно лежит React Native-бандл на Android?"
  options:
    - "assets/index.android.bundle"
    - "classes.dex"
    - "res/xml"
    - "lib/arm64-v8a/libapp.so"
  answer: 0
- question: "Что даёт hbctool?"
  options:
    - "Дизасм и патч HBC"
    - "Сетевой перехват"
    - "Дамп Keychain"
    - "Сканирование портов"
  answer: 0
- question: "Почему после патча бандла нужен zipalign+sign?"
  options:
    - "Изменённый APK теряет корректную подпись/выравнивание"
    - "Иначе не будет интернета"
    - "Иначе сработает SELinux"
    - "Иначе удалится Keychain"
  answer: 0
```

## Где пригодится

- **Реверс:** React Native — массовый стек.
- **Пентест:** обход JS-проверок, поиск секретов.
- **Bug bounty:** ключи/эндпоинты в бандле.
- **CTF:** Mobile-задачи на RN.
