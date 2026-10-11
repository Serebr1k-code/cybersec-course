---
id: mobile-ios-basics
title: "Основы iOS: IPA, class-dump, Hopper и особенности тестирования"
category: mobile
parent: mobile-platforms
difficulty: medium
order: 3
tags: [ios, ipa, mach-o, class-dump, hopper, keychain, jailbreak]
prerequisites: [mobile-intro]
useful_for:
  - "CTF Mobile (реверс iOS-приложений)"
  - "Bug bounty (iOS-приложения)"
  - "Пентест мобильных приложений"
estimated_minutes: 35
summary: "Чем iOS-приложение отличается от Android: структура IPA, Mach-O, Objective-C/Swift, class-dump, Hopper/IDA, jailbreak и Frida на iOS, Keychain, а также типовые уязвимости и ограничения тестирования."
---

Android встречается в CTF чаще, но настоящий мобильный пентест требует и iOS. Приложения для iOS устроены иначе: другой формат бинарника (Mach-O), другой язык (Objective-C/Swift), другая среда (jailbreak вместо root), другой инструментарий. Этот урок — вход в iOS-ветвь: после него вы поймёте, как разобрать IPA, чем пользоваться и какие ограничения есть у тестирования iOS.

Этот урок — отдельная ветвь от `mobile-intro` (не продолжение Android-цепочки): iOS — самостоятельное направление со своими инструментами.

## Структура IPA

**IPA** — это zip-архив iOS-приложения (аналог APK). Внутри:

```
Payload/
  MyApp.app/
    MyApp                 <- Mach-O бинарник (главный объект анализа)
    Info.plist            <- метаданные (аналог AndroidManifest.xml)
    Frameworks/           <- встроенные фреймворки (.dylib)
    Assets.car            <- скомпилированные ресурсы
    *.storyboardc         <- скомпилированные UI
    embedded.mobileprovision  <- профиль подписи (данные о разработчике)
```

```bash
# Распаковать IPA
unzip MyApp.ipa -d ipa_extracted
ls ipa_extracted/Payload/MyApp.app/

# Метаданные
plutil -p ipa_extracted/Payload/MyApp.app/Info.plist
```

`Info.plist` (аналог манифеста) содержит: `CFBundleIdentifier` (bundle id), `CFBundleURLTypes` (deep links/schemes), `NSAppTransportSecurity` (ATS — аналог network security config), `UIBackgroundModes`, список разрешений и их описания.

```bash
# Deep links
plutil -p .../Info.plist | grep -A10 CFBundleURLTypes
# Настройки ATS (разрешён ли cleartext)
plutil -p .../Info.plist | grep -A5 NSAppTransportSecurity
```

## Mach-O и языки

Главный бинарник — **Mach-O** (аналог ELF). Он содержит код Objective-C/Swift. Ключевое отличие от Android: **iOS-бинарники не «декомпилируются в исходники» так же чисто**, потому что Objective-C/Swift компилируются в машинный код. Поэтому инструменты работают иначе:

- **Class-dump** — извлекает объявления классов/методов Objective-C из бинарника (не тела методов, а заголовки — как `.h`-файлы).
- **Hopper / IDA / Ghidra** — дизассемблеры/декомпиляторы для просмотра кода методов.
- **Frida / Objection** — динамический анализ и хукинг (работает так же, как на Android, но через `-U` к устройству/симулятору).

```bash
# Определить тип бинарника
file .../MyApp.app/MyApp
# -> Mach-O 64-bit arm64 executable

# Извлечь классы/методы Objective-C
class-dump .../MyApp.app/MyApp -o classes_dump/
ls classes_dump/
# -> .h-файлы с объявлениями @interface/@property/@selector

# Строки (быстрый поиск секретов)
strings .../MyApp.app/MyApp | grep -iE 'api|key|secret|token|http'
```

## Дизассемблирование: Hopper / IDA / Ghidra

Для просмотра логики метода:

1. Открыть бинарник в **Hopper** (удобен для Mach-O, есть GUI) или **IDA/Ghidra** (бесплатный Ghidra).
2. Найти интересующий метод (по имени из class-dump).
3. Читать псевдокод (Hopper/IDA дают декомпиляцию).
4. Искать проверки (сравнения, `isEqual:`, `strcmp`) и строковые константы.

```bash
# Открыть в Ghidra (headless-скрипт для быстрого просмотра строк/функций)
# или использовать radare2
r2 .../MyApp.app/MyApp
[0x100000000]> aaa
[0x100000000]> izz~flag
[0x100000000]> afl~check
```

Для Swift ситуация сложнее: имена методов «манглятся» (name mangling). Инструмент **swift-demangle** (или встроенный в Hopper/IDA) восстанавливает читаемые имена.

## Jailbreak и Frida на iOS

Чтобы запускать Frida/отлаживать, устройство обычно должно быть **jailbroken** (аналог root). Варианты:

- **Checkra1n / unc0ver / palera1n** — инструменты jailbreak (зависит от версии iOS/устройства).
- После jailbreak ставится **Cydia/Sileo**, откуда — `frida`, `objection`, `Cydia Substrate`.
- **Frida на iOS** работает через `frida-server` (для jailbreak) или `frida-gadget` (встраивается в приложение, работает и без jailbreak на переподписанном IPA).

```bash
# Установить frida на устройство (через Cydia/Sileo) и подключиться
frida-ps -U
frida -U -f com.example.app -l hook.js

# Objection на iOS
objection -g com.example.app explore
> ios sslpinning disable
> ios jailbreak disable
> ios keychain dump
```

Без jailbreak: переподписать IPA с встроенным Frida Gadget (`objection patchipa`, `insert_dylib` + `codesign`), установить через `ios-deploy`/AltStore.

## Хранилище: Keychain и файлы

iOS-аналог SharedPreferences — **NSUserDefaults** (plist) и **Keychain** (для секретов). Ключевые артефакты:

| Путь | Что |
|------|-----|
| `Library/Preferences/*.plist` | NSUserDefaults (настройки, иногда токены) |
| `Library/Keychain` | Keychain (правильное место для секретов) |
| `Documents/` | Пользовательские данные, часто бэкапятся |
| `Library/Caches/` | Кэш (в т.ч. ответы API, изображения) |
| `tmp/` | Временные файлы |

```bash
# На jailbroken-устройстве доступ к данным приложения
ssh root@device
find /var/containers/Bundle/Application -name "MyApp.app"
# данные: /var/mobile/Containers/Data/Application/<uuid>/

# Плисты настроек
plutil -p .../Library/Preferences/com.example.app.plist
```

**Проблема с Keychain**: если приложение использует слабую accessibility-опцию (`kSecAttrAccessibleAlways`), секреты доступны даже при заблокированном экране и попадают в бэкапы. Правильная опция — `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.

## Типовые уязвимости iOS

Многие классы совпадают с Android, но с иными инструментами:

- **Небезопасное хранение** — секреты в NSUserDefaults/plist вместо Keychain, доступные в бэкапе.
- **SSL pinning** — обходится через Objection/Frida (`ios sslpinning disable`) или патч ATS.
- **Jailbreak-детект** — проверки файлов (`/Applications/Cydia.app`), `fork()`, `system()`. Обход — Frida-хуки или `ios jailbreak disable`.
- **Deep links / URL schemes** — hijacking (custom scheme), незащищённые обработчики.
- **WebView** — `WKWebView` с `evaluateJavaScript`, загрузка произвольного URL.
- **API-тестирование** — тот же подход, что и на Android (см. `mobile-api-testing`).

```bash
# Быстрый статический проход
strings MyApp | grep -iE 'http://|api[_-]?key|secret'
class-dump MyApp | grep -iE 'token|password|flag'
# Проверить ATS
plutil -p Info.plist | grep -A5 NSAppTransportSecurity
```

## Ограничения тестирования iOS

- **Требуется Apple-устройство** (или симулятор, но он не даёт реального рантайма для многих проверок).
- **Подпись**: любой патч требует переподписи, что ломает integrity-проверки.
- **Jailbreak**: современные iOS-версии сложно джейлбрейкнуть; часто используют `frida-gadget` в переподписанном IPA.
- **App Store-сборки зашифрованы** (FairPlay/`cryptid`). Перед анализом нужно **дешифровать бинарник** (снять `cryptid`) — например, через `frida-ios-dump` на jailbroken-устройстве.

```bash
# Проверить, зашифрован ли бинарник (cryptid=1 -> зашифрован)
otool -l MyApp | grep -A4 LC_ENCRYPTION_INFO
# Дешифровать дампом из памяти (jailbreak)
frida-ios-dump -o decrypted.ipa com.example.app
```

## Разобранный пример: поиск секрета в IPA

```bash
# 1. Распаковать и дешифровать (если нужно)
unzip app.ipa -d ipa
otool -l ipa/Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO  # cryptid
frida-ios-dump -o dec.ipa com.example.app   # если зашифрован

# 2. Строки и классы
strings dec/Payload/App.app/App | grep -iE 'flag|KubSTU|secret'
class-dump dec/Payload/App.app/App -o dump/
grep -rniE 'flag|secret' dump/

# 3. Если логика в методе — открываем в Hopper, ищем метод по имени из dump
# 4. Динамика: Frida-хук на метод проверки
```

## Частые ошибки

- **Ожидать «декомпиляцию в исходник» как на Android.** iOS-бинарники — машинный код; работают дизассемблеры и class-dump.
- **Забыть дешифровать App Store-сборку.** Зашифрованный (`cryptid=1`) бинарник не даст строк и классов — сначала дамп из памяти.
- **Искать хранилище по Android-привычке.** На iOS — plist/Keychain, а не `shared_prefs`.
- **Игнорировать переподпись при патче.** Изменённый IPA нужно подписать, иначе не установится.
- **Тестировать только на симуляторе.** Часть проверок (jailbreak, Keychain) работают иначе; лучше реальное устройство.

## Квиз

```quiz
- question: "Что такое IPA?"
  options:
    - "Zip-архив iOS-приложения, содержащий Mach-O бинарник и Info.plist"
    - "Формат базы данных iOS"
    - "Инструмент для jailbreak"
    - "Протокол передачи данных"
  answer: 0
- question: "Чем class-dump полезен при анализе iOS-приложения?"
  options:
    - "Извлекает объявления классов и методов Objective-C из бинарника"
    - "Дешифрует бинарник"
    - "Перехватывает HTTPS"
    - "Ставит jailbreak"
  answer: 0
- question: "Что нужно сделать с App Store-сборкой перед анализом бинарника?"
  options:
    - "Дешифровать (снять FairPlay/`cryptid`) дампом из памяти"
    - "Переустановить приложение"
    - "Отключить Wi-Fi"
    - "Запустить на симуляторе"
  answer: 0
- question: "Где iOS-приложение должно хранить секреты?"
  options:
    - "В Keychain"
    - "В NSUserDefaults"
    - "В `Documents/` как открытый текст"
    - "В `Info.plist`"
  answer: 0
- question: "Какой инструмент на iOS обходит SSL pinning одной командой?"
  options:
    - "jadx"
    - "Objection (`ios sslpinning disable`)"
    - "apktool"
    - "binwalk"
  answer: 1
```

## Где пригодится

- **CTF Mobile:** реверс iOS-приложений, поиск флагов в бинарнике и хранилище.
- **Bug bounty:** анализ iOS-клиентов, утечки секретов, обход pinning.
- **Пентест:** оценка OWASP MASVS для iOS-приложений.
- **Работа:** понимание отличий iOS от Android при планировании тестирования.
