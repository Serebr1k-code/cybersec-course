---
id: mobile-ios-ipa-analysis
title: "Анализ IPA и Mach-O: otool, codesign, class-dump"
category: mobile
parent: mobile-advanced-ios
difficulty: hard
order: 1
tags: [mobile, ios, ipa, macho, otool, codesign, reverse]
prerequisites: [mobile-ios-basics]
useful_for:
  - "CTF Mobile: iOS-задачи"
  - "Пентест iOS-приложений: статический анализ"
estimated_minutes: 45
summary: "Структура IPA и Mach-O, работа с otool/nm/class-dump/codesign, entitlements, fat-бинарники, встроенные фреймворки и извлечение секретов из iOS-приложения."
---

## Что такое IPA и как он устроен

IPA (iOS App Store Package) — это zip-архив, внутри которого лежит каталог `Payload/<AppName>.app/`. В нём находится скомпилированный бинарник (Mach-O), ресурсы, `Info.plist`, `embedded.mobileprovision`, а также встроенные фреймворки и динамические библиотеки. В отличие от Android, где код — байткод DEX, здесь код — машинный (ARM64), а значит, для анализа нужен дизассемблер, а не декомпилятор.

```
Payload/MyApp.app/
├── MyApp                      # Mach-O бинарник
├── Info.plist                 # метаданные, URL-схемы, разрешения
├── embedded.mobileprovision   # provisioning profile
├── Frameworks/
│   ├── Alamofire.framework/
│   └── MySDK.framework/
├── Assets.car                 # сжатые ресурсы
└── en.lproj/                  # локализации
```

IPA можно получить из App Store (`Apple Configurator` + дамп), из тестовой сборки (TestFlight/Ad-Hoc) или из файловой системы джейлбрейкнутого устройства. Для анализа он не требует джейлбрейка — статика полностью возможна на компьютере.

## Распаковка и первичный осмотр

```bash
unzip -o MyApp.ipa -d /tmp/ipa
cd /tmp/ipa/Payload/MyApp.app
file MyApp
# MyApp: Mach-O 64-bit executable arm64
```

`file` сразу показывает, тонкий это бинарник (одна архитектура) или fat (несколько). Fat-бинарник содержит слайсы для armv7/arm64/x86_64 (последний — для симулятора). Разделить слайсы:

```bash
lipo -info MyApp
# Architectures in the fat file: MyApp are: armv7 arm64
lipo -thin arm64 MyApp -output MyApp_arm64
```

Для анализа берите arm64: это актуальная архитектура реальных устройств. x86_64-слайс полезен, если хотите запустить приложение в симуляторе.

## Mach-O: заголовок, сегменты, секции

```bash
otool -h MyApp           # заголовок Mach-O
otool -l MyApp           # все load commands (сегменты, dylib, rpath)
otool -L MyApp           # слинкованные библиотеки
otool -hv MyApp          # заголовок + флаги
```

Ключевые load commands:
- **`LC_SEGMENT_64`** — сегменты `__TEXT` (код, read-only), `__DATA` (данные), `__LINKEDIT` (символы, подписи).
- **`LC_LOAD_DYLIB`** — какие библиотеки грузятся при старте.
- **`LC_RPATH`** — пути поиска dylib.
- **`LC_CODE_SIGNATURE`** — подпись.
- **`LC_ENCRYPTION_INFO`** — флаг шифрования App Store (cryptid).

Флаг шифрования критичен: если `cryptid = 1`, код зашифрован, и дизассемблирование даст мусор. Расшифровка возможна только на устройстве (дамп из памяти) — этим занимаются инструменты вроде `frida-ios-dump` или `Clutch`.

```bash
otool -l MyApp | grep -A4 LC_ENCRYPTION_INFO
# cryptoff 16384
# cryptsize 8192
# cryptid 1        <- зашифрован
```

## Символы и классы

```bash
nm -a MyApp | head            # все символы
nm -u MyApp                   # неопределённые (импорты)
strings -a MyApp | grep -i "http\|api\|key\|token" | head
```

Для Objective-C приложений мощный инструмент — `class-dump` (или `dsc_extractor`/`class-dump-z`): он восстанавливает объявления классов и методов из рантайм-метаданных:

```bash
class-dump -H MyApp -o /tmp/headers
ls /tmp/headers | head
# MyApp.h  AppDelegate.h  NetworkClient.h ...
```

Заголовки показывают методы классов, что даёт карту приложения. Для Swift `class-dump` бесполезен (другая ABI) — там помогают `swift-demangle` и Ghidra с плагинами.

## Info.plist и entitlements

```bash
plutil -convert xml1 -o - Info.plist | less
# или
python3 -c "import plistlib;print(plistlib.load(open('Info.plist','rb')))"
```

В `Info.plist` ищите:
- `CFBundleURLTypes` — custom URL-схемы (вход для deep links).
- `UIBackgroundModes`, `NSAppTransportSecurity` (`NSAllowsArbitraryLoads` — отключённый ATS!).
- `NS*UsageDescription` — какие разрешения запрашивает.

Entitlements — права приложения (push, keychain sharing, app groups):

```bash
codesign -d --entitlements :- MyApp
# <key>application-identifier</key><string>TEAMID.com.example.app</string>
# <key>keychain-access-groups</key>
# <key>aps-environment</key><string>production</string>
```

`app groups` и `keychain-access-groups` особенно интересны: они описывают общие хранилища между приложениями одного разработчика.

## Подпись и валидация

```bash
codesign -dvvv MyApp              # детали подписи
codesign --verify --deep --strict MyApp
security cms -D -i embedded.mobileprovision > /tmp/prov.plist
plutil -p /tmp/prov.plist | head
```

Provisioning profile показывает, на какие устройства ставится сборка, какой сертификат использован и какие entitlements разрешены. При re-sign (для инъекции dylib) именно профиль определяет, что можно.

## Извлечение секретов из ресурсов

```bash
# .car — сжатые ассеты, распаковываются acextract/AssetCatalogTinkerer
# но секреты чаще в коде и plist:
grep -rIl "api_key\|secret\|password" . 2>/dev/null
strings -a MyApp | grep -Ei "sk_live|AIza|-----BEGIN" | head
```

Часто ключи зашиты в бинарник как строки или в `Info.plist`. Если бинарник зашифрован (`cryptid=1`), сначала нужно снять дамп с устройства, иначе `strings` покажет только метаданные.

## Встроенные фреймворки и SDK

Приложения часто содержат десятки `.framework` — аналитика, реклама, платежи. Каждый — отдельный Mach-O:

```bash
for fw in Frameworks/*.framework; do
  bin="$fw/$(basename "$fw" .framework)"
  [ -f "$bin" ] && echo "== $bin" && otool -L "$bin" | head -3
done
```

Это важно для поиска уязвимостей в сторонних SDK (например, старых версий с известными CVE) и для понимания, какие данные уходят в аналитику.

## Частые ошибки и подводные камни

- **Дизассемблер показывает мусор** — бинарник зашифрован (`cryptid=1`); нужен дамп с устройства.
- **`class-dump` пусто** — приложение на Swift; используйте `swift-demangle`/Ghidra.
- **`lipo -thin` падает** — бинарник уже тонкий; проверьте `lipo -info`.
- **`codesign` не находит подпись** — бинарник из jailbroken-дампа уже пропатчен.
- **`Info.plist` бинарный** — конвертируйте через `plutil -convert xml1`.

## Справочная таблица инструментов

| Инструмент | Назначение |
|------------|-----------|
| `unzip` | распаковка IPA |
| `file`/`lipo` | определение и разделение архитектур |
| `otool -l/-L/-h` | заголовок, сегменты, зависимости |
| `nm`/`strings` | символы и строки |
| `class-dump` | заголовки Objective-C классов |
| `codesign` | подпись и entitlements |
| `plutil` | работа с plist |
| Ghidra/Hopper/IDA | дизассемблирование Mach-O |

## Что дальше / решение

Статический анализ IPA даёт карту приложения: классы, URL-схемы, entitlements, встроенные SDK. Дальше: проверьте custom URL scheme и Universal Links (`mobile-universal-links`), найдите OAuth-редиректы (`mobile-ios-oauth-sso`) и, если нужно заглянуть в рантайм, инжектируйте dylib (`mobile-ios-dylib-injection`). Для динамики — Frida на джейлбрейкнутом устройстве (`mobile-ios-dynamic`).

## Работа с зашифрованным бинарником (cryptid=1)

Если `LC_ENCRYPTION_INFO` показывает `cryptid=1`, статический дизассемблер бесполезен: страницы кода зашифрованы и расшифровываются только в памяти на устройстве. Есть два пути снять дамп.

Первый — **frida-ios-dump**: подключается к запущенному приложению и выгружает расшифрованные страницы:

```bash
# на джейлбрейкнутом устройстве, frida-server запущен
pip install frida-tools
python3 dump.py -o /tmp/decrypted com.example.app
# появится Payload/MyApp.app с расшифрованным бинарником
```

Второй — **Clutch** (старый, но иногда работает) или **bagbak** (современный). После дампа проверьте, что `cryptid` стал 0:

```bash
otool -l /tmp/decrypted/Payload/MyApp.app/MyApp | grep -A4 LC_ENCRYPTION_INFO
# cryptid 0   <- расшифрован
```

Теперь можно грузить бинарник в Ghidra/Hopper и дизассемблировать. Помните: дамп снимается с конкретной версии приложения; при обновлении процедуру повторяют.

## Swift и приватные API

Swift-приложения не поддаются `class-dump`, потому что Swift использует манглинг имён и собственную ABI. Полезные приёмы:

```bash
# демагглинг Swift-символов
nm MyApp | grep -i ' _T' | swift-demangle | head
# извлечение строк Swift
strings -a MyApp | grep -E '\$s[A-Za-z0-9]+' | swift-demangle | head
```

В Ghidra установите плагин `Swift` (или используйте `swiftd`), чтобы имена методов читались. Для приватных API ищите вызовы `NSClassFromString` с динамическими именами: они часто скрывают использование непубличных классов, что важно и для security-аудита (App Store запрещает, но приложения иногда хитрят).

## Автоматизация статического анализа

Для большого объёма приложений соберите конвейер:

```bash
#!/usr/bin/env bash
IPA="$1"
D="/tmp/ipa_analysis"
rm -rf "$D"; mkdir -p "$D"
unzip -q "$IPA" -d "$D"
APP="$D/Payload/"*.app
BIN="$APP/$(basename "$APP" .app)"

# артефакты
lipo -info "$BIN"                 > "$D/arch.txt"
otool -L "$BIN"                   > "$D/libs.txt"
otool -l "$BIN" | grep -A4 ENCRYPT > "$D/encrypt.txt"
codesign -dvvv "$BIN"             > "$D/codesign.txt" 2>&1
codesign -d --entitlements :- "$BIN" > "$D/entitlements.plist" 2>&1
strings -a "$BIN" | grep -Ei 'http|token|key|secret' > "$D/secrets.txt"
class-dump -H "$BIN" -o "$D/headers" 2>/dev/null

echo "done: $D"
```

Такой прогон за минуты даёт: архитектуры, зависимости, статус шифрования, entitlements, заголовки классов и подозрительные строки. Дальше — ручной разбор в Ghidra.

## Извлечение ассетов и локализаций

Ресурсы в `Assets.car` распаковываются `acextract`:

```bash
acextract -i Assets.car -o /tmp/assets
```

Локализации лежат в `<lang>.lproj/Localizable.strings`; иногда там встречаются внутренние сообщения об ошибках с деталями серверной логики. Ищите строки вида `error`, `debug`, `internal`:

```bash
grep -rIi "debug\|internal\|stack" *.lproj/*.strings | head
```

Часто в ресурсах остаются тестовые endpoint'ы (`staging.example.com`), которые открывают доступ к небоевой среде.

## Чек-лист статического анализа IPA

Итоговая последовательность действий, которой удобно придерживаться при каждом новом IPA: распаковать архив; определить архитектуры через `lipo`; проверить `cryptid` и при необходимости снять дамп; собрать зависимости через `otool -L`; извлечь entitlements и provisioning profile; получить заголовки классов через `class-dump` (или `swift-demangle` для Swift); прогнать `strings` по ключевым словам; разобрать `Info.plist` на URL-схемы и ATS; перечислить встроенные фреймворки и их версии. Каждый пункт даёт артефакт, который пригодится на следующих этапах — от поиска секретов до анализа OAuth.

## Квиз

```quiz
- question: "Что означает cryptid=1 в LC_ENCRYPTION_INFO?"
  options:
    - "Бинарник зашифрован (App Store), дизассемблирование даст мусор"
    - "Приложение подписано разработчиком"
    - "Бинарник собран для симулятора"
    - "Код на Swift"
  answer: 0
- question: "Каким инструментом восстановить заголовки Objective-C классов?"
  options:
    - "class-dump"
    - "apktool"
    - "jadx"
    - "frida-dexdump"
  answer: 0
- question: "Где в IPA описаны custom URL-схемы приложения?"
  options:
    - "В Info.plist (CFBundleURLTypes)"
    - "В embedded.mobileprovision"
    - "В Assets.car"
    - "В InfoPlist.strings"
  answer: 0
- question: "Что показывает codesign -d --entitlements :- ?"
  options:
    - "Права приложения: push, keychain groups, app groups"
    - "Список классов"
    - "Исходный код Swift"
    - "Адрес сервера"
  answer: 0
```

## Где пригодится

- **CTF:** iOS-задачи, где нужно найти ключ или логику в бинарнике.
- **Пентест:** статический аудит iOS-приложения до динамики.
- **Bug bounty:** поиск отключённого ATS, утечек ключей, уязвимых SDK.
