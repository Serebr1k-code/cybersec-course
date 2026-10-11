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
## Введение

Всё больше приложений пишут на кросс-платформенных фреймворках: **Flutter** (Dart) и **React Native** (JavaScript). Внутри APK нет привычного Java-кода с бизнес-логикой — она упакована в AOT-скомпилированный Dart (`libapp.so`) или в JS-бандл (`index.android.bundle`, часто Hermes bytecode). Обычные jadx-подходы дают лишь «обвязку». Этот урок — про то, как реверсить такие приложения и находить в них секреты и логику.

Продолжение `mobile-static-analysis` (общий разбор APK) и `mobile-obfuscation`.

## Как отличить Flutter/RN от нативного приложения

```bash
unzip app.apk -d apk

# Flutter-маркеры:
ls apk/lib/arm64-v8a/
# -> libflutter.so, libapp.so   (libapp.so = AOT-скомпилированный Dart)

# React Native-маркеры:
ls apk/assets/
# -> index.android.bundle        (JS-бандл, иногда Hermes bytecode)
ls apk/lib/arm64-v8a/
# -> libhermes.so, libjsc.so, libreactnativejni.so
```

| Фреймворк | Ключевой артефакт | Язык логики |
|-----------|-------------------|-------------|
| Flutter | `libapp.so` (+`libflutter.so`) | Dart (AOT) |
| React Native | `assets/index.android.bundle` | JavaScript / Hermes |
| Cordova/Ionic | `assets/www/*.js` | JavaScript |
| Xamarin | `assemblies/*.dll` | .NET (IL) |
| Unity | `assets/bin/Data/Managed/*.dll` | C# (IL) |

## Flutter: анализ Dart AOT

`libapp.so` содержит снапшот Dart VM с AOT-кодом. Строки есть, но структуры классов Dart не читаются стандартными инструментами.

```bash
# 1. Строки — быстрый первый шаг
strings -a apk/lib/arm64-v8a/libapp.so | grep -iE 'http|api|key|secret|flag|token'

# 2. Blutter — восстановление структур Dart-объектов и функций
python3 blutter.py apk/lib/arm64-v8a/ libapp_out/
ls libapp_out/
# -> asm/ (дизассемблер функций), pp.txt (структуры объектов Dart)

# 3. reFlutter — патч libflutter.so для перехвата трафика
reFlutter app.apk
```

Важный факт: **Flutter по умолчанию не использует системный proxy и не доверяет пользовательским CA**. Перехват HTTPS требует reFlutter либо Frida-хуков на `libflutter.so`.

```javascript
var base = Module.findBaseAddress('libflutter.so');
Interceptor.attach(Module.findExportByName('libflutter.so', 'ssl_verify_result'), {
  onLeave: function (retval) { retval.replace(0); }
});
```

## React Native: анализ JS-бандла

`index.android.bundle` — либо обычный JS (текст), либо Hermes bytecode (бинарный).

```bash
file apk/assets/index.android.bundle
# -> "JavaScript source" ИЛИ "Hermes JavaScript bytecode"

# обычный JS — читаем и форматируем
grep -niE 'api|key|secret|http' apk/assets/index.android.bundle | head
npx prettier apk/assets/index.android.bundle > bundle.pretty.js

# Hermes bytecode — декомпилируем
hermes-dec apk/assets/index.android.bundle > bundle.js
hbctool disasm apk/assets/index.android.bundle hermes_out
```

Логика RN — это JS: ищите endpoint-ы, схемы авторизации, «секретные» проверки и токены.

## Динамический анализ RN/Flutter

- **RN:** хук на `Java.use('com.facebook.react.bridge.*')` для перехвата вызовов из JS в native; либо включить Hermes debugger и поставить брейкпоинты в JS.
- **Flutter:** Frida по адресам из Blutter-вывода; либо `reFlutter` для MITM.
- **Общее:** ищите строки в нативных библиотеках — там часто лежат API-ключи и URL.

## Разобранный пример

```bash
# Flutter
unzip challenge.apk -d apk
strings -a apk/lib/arm64-v8a/libapp.so | grep -iE 'flag|secret'
# -> 'FLAG{flutter_hardcoded}'

# React Native
file apk/assets/index.android.bundle
# -> Hermes JavaScript bytecode
hbctool disasm apk/assets/index.android.bundle rn_out
grep -rniE 'flag|secret|api[_-]?key' rn_out/ | head
# -> функция validateFlag сравнивает с константой в бандле
```

Если логика — не константа, а проверка: в RN читаем JS и находим алгоритм; в Flutter используем Blutter, чтобы найти функцию и её ASM, либо хукаем по адресу.

## Частые ошибки и подводные камни

- **Искать Java-логику в Flutter/RN** — в jadx видна только обвязка.
- **Перехватывать Flutter-трафик обычным proxy** — Flutter игнорирует системный прокси/CA.
- **Читать Hermes-бандл как текст** — он бинарный, нужна декомпиляция.
- **Забывать про секреты в строках нативной библиотеки** — `strings libapp.so` самый быстрый шаг.
- **Не проверить `assets/` у RN** — бандл может быть не в `lib/`.
- **Игнорировать split ABI** — `libapp.so` может лежать в `split_config.arm64_v8a.apk` (Android App Bundle).

## Справочная таблица

| Артефакт | Инструмент |
|----------|-----------|
| `libapp.so` | strings, Blutter |
| `libflutter.so` | reFlutter, Frida |
| `index.android.bundle` (JS) | prettier, grep |
| `index.android.bundle` (Hermes) | hermes-dec, hbctool |
| `assets/www` | grep |
| `assemblies/*.dll` | dnSpy/ILSpy |

## Что дальше / решение

- **Секрет в строках** → фиксируйте находку.
- **Логика-проверка** → реверс алгоритма (Blutter/JS) или хук.
- **Нужен трафик** → reFlutter / Frida-хук на `libflutter.so`.
- **Обфускация Dart** → сложнее; ищите символы и строки, стройте граф вызовов.

## Flutter: работа с split APK и ABI

Современные приложения поставляются как Android App Bundle и на устройстве распаковываются в split APK. `libapp.so` может лежать не в базовом APK:

```bash
# получить все split-ы
adb shell pm path com.target.app
# -> base.apk, split_config.arm64_v8a.apk, split_config.xxhdpi.apk ...
adb pull /data/app/.../split_config.arm64_v8a.apk
unzip split_config.arm64_v8a.apk -d split
ls split/lib/arm64-v8a/   # libapp.so здесь
```

Если анализируете из магазина — скачивайте через `bundletool`/`apkeep` с учётом нужного ABI.

## Hermes bytecode: версии и инструменты

Hermes меняет формат между версиями, поэтому подбирайте инструмент под байткод:

```bash
head -c 8 apk/assets/index.android.bundle | xxd
# -f0000000 (Hermes magic)
hermes-dec --version
hbctool disasm apk/assets/index.android.bundle out
# при несовпадении версии — hermes-dec или hbctool соответствующих релизов
```

После дизассемблирования ищите строки и функции: `validate`, `verify`, `secret`, `apiKey`, `token`. Многие RN-приложения держат «секретную» логику прямо в JS.

## Обфускация Dart и JS

- **Dart:** имена классов могут быть переименованы; ориентируйтесь на строки и структуру (Blutter даёт `pp.txt` с объектами).
- **JS:** минификация + `react-native-obfuscating-transformer`; помогает beautify и поиск по строкам.
- **Общее:** ищите криптопримитивы (`AES`, `CryptoJS`), сравнения хэшей, константы.

## Практический чек-лист

| Шаг | Команда/инструмент |
|-----|--------------------|
| Определить фреймворк | `ls lib/ assets/` |
| Flutter строки | `strings libapp.so` |
| Flutter структуры | Blutter |
| Flutter MITM | reFlutter / Frida |
| RN определить тип | `file index.android.bundle` |
| RN текст | `prettier` + grep |
| RN Hermes | `hermes-dec` / `hbctool` |
| Динамика RN | Hermes debugger / Frida |

## Что делать дальше

- Секрет в строках — фиксируйте сразу.
- Проверка-алгоритм — реверс (Blutter/JS) или хук.
- Трафик Flutter — reFlutter, затем обычный анализ API.
- Не забывайте про split APK — иначе не найдёте нужную библиотеку.

## React Native: динамический анализ Hermes

Если бандл в Hermes bytecode, включите встроенный debugger Hermes:

```bash
# на устройстве: включить Hermes debugging
adb shell am broadcast -a com.facebook.react.devsupport.RELOAD
# либо через Metro: адрес debugger по умолчанию localhost:8081
```

Затем можно ставить брейкпоинты в JS-коде, инспектировать переменные и переопределять функции проверки. Дополнительно Frida-хук на мост React Native:

```javascript
Java.perform(function () {
  var B = Java.use('com.facebook.react.bridge.ReactContext');
  // либо хук на JavaModuleWrapper для перехвата вызовов из JS
});
```

## Flutter: патч проверки по смещению

Если Blutter показал функцию проверки, её можно пропатчить в памяти:

```javascript
var base = Module.findBaseAddress('libapp.so');
var addr = base.add(0x<offset>);        // смещение из дизассемблера Blutter
Memory.protect(addr, 4, 'rwx');
addr.writeByteArray([0x00, 0x00, 0x80, 0xD2]);  // mov x0,#0 / ret-подобная заглушка
```

Либо, если функция возвращает bool, захукать её и заменить возврат:

```javascript
Interceptor.attach(base.add(0x<offset>), {
  onLeave: function (ret) { ret.replace(ptr(1)); }
});
```

## Таблица «фреймворк → артефакт → инструмент → что искать»

| Фреймворк | Артефакт | Инструмент | Ищем |
|-----------|----------|-----------|------|
| Flutter | libapp.so | Blutter, strings | секреты, URL, проверки |
| Flutter | libflutter.so | reFlutter, Frida | TLS, MITM |
| RN (JS) | index.android.bundle | prettier | ключи, логика |
| RN (Hermes) | index.android.bundle | hermes-dec/hbctool | строки, функции |
| Xamarin | assemblies/*.dll | dnSpy/ILSpy | C#-логика |
| Unity | Managed/*.dll | dnSpy | C#-логика |

## Что делать дальше

- Секреты — в строки нативной библиотеки/бандла в первую очередь.
- Алгоритмы проверок — реверс или рантайм-хук.
- Трафик Flutter — reFlutter, затем обычный анализ API.
- Учитывайте split APK: нужный `libapp.so` может быть в отдельном split-е.

## Квиз

```quiz
- question: "Какой файл содержит скомпилированный Dart-код Flutter-приложения?"
  options:
    - "libapp.so"
    - "index.android.bundle"
    - "classes.dex"
    - "libhermes.so"
  answer: 0
- question: "Почему перехват HTTPS у Flutter сложнее, чем у нативных Android-приложений?"
  options:
    - "Flutter не использует системный прокси и не доверяет пользовательским CA"
    - "Flutter не поддерживает HTTPS"
    - "Flutter шифрует весь трафик своим ключом"
    - "Flutter работает только офлайн"
  answer: 0
- question: "Как определить, что index.android.bundle — это Hermes bytecode, а не текст?"
  options:
    - "Командой file / по бинарному виду, затем декомпилировать hermes-dec или hbctool"
    - "Открыть в блокноте"
    - "Он всегда текстовый"
    - "По расширению .so"
  answer: 0
- question: "Какой инструмент восстанавливает структуры Dart-объектов из libapp.so?"
  options:
    - "Blutter"
    - "jadx"
    - "apktool"
    - "sqlmap"
  answer: 0
- question: "Где у React Native-приложения лежит основной JS-бандл?"
  options:
    - "assets/index.android.bundle"
    - "lib/arm64-v8a/libapp.so"
    - "res/values/strings.xml"
    - "AndroidManifest.xml"
  answer: 0
```

## Где пригодится

- **CTF Mobile:** флаг/секрет в Dart-снапшоте или JS-бандле, реверс алгоритма проверки.
- **Bug bounty:** анализ логики и секретов кросс-платформенных клиентов, перехват Flutter-трафика.
- **Пентест:** оценка MASVS для Flutter/RN, обход клиентских проверок.
- **Работа:** понимание, где реально живёт логика гибридных приложений.
