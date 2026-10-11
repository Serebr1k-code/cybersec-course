---
id: mobile-ios-static
title: "iOS static analysis: class-dump, Hopper, Swift и дешифровка"
category: mobile
parent: mobile-ios-analysis
difficulty: hard
order: 1
tags: [ios, static, class-dump, hopper, ghidra, swift, mach-o, frida-ios-dump]
prerequisites: [mobile-ios-basics]
useful_for:
  - "CTF Mobile (реверс iOS-бинарника)"
  - "Bug bounty (анализ iOS-клиента)"
  - "Пентест мобильных приложений"
estimated_minutes: 40
summary: "Глубокий статический анализ iOS: структура Mach-O, извлечение Objective-C/Swift, дешифровка App Store-сборок, работа в Hopper/Ghidra и поиск секретов/логики."
---
## Что анализировать в iOS-приложении

iOS-приложение — это `.app`-bundle внутри `.ipa` (zip). В отличие от Android, где код в DEX, здесь **нативные Mach-O бинарники** (arm64), плюс ресурсы, `Info.plist`, `entitlements`, фреймворки. Статический анализ даёт: список классов и методов (ObjC runtime), строки, встроенные секреты, конфигурацию (plist), список URL-схем и прав (entitlements), а также точки проверки jailbreak/pinning. Сложность: бинарники из App Store **зашифрованы** (FairPlay) и требуют дешифровки перед анализом.

Ментальная модель: у iOS нет «декомпиляции в исходники», как с Java. Вы работаете с дизассемблером (Hopper/IDA/Ghidra) + метаданными ObjC/Swift. Поэтому важна точность: сначала дешифровка, потом `class-dump`/`nm`/`strings`, и лишь затем чтение логики в дизассемблере.

## Получение IPA и распаковка

```bash
# IPA: из iTunes/Apple Configurator, из .ipa-бэкапа, или через frida-ios-dump с устройства
unzip app.ipa -d app_ipa
ls app_ipa/Payload/AppName.app/
# ключевые файлы:
#   AppName          — Mach-O бинарник (main)
#   Info.plist       — конфигурация
#   embedded.mobileprovision — профиль подписи
#   Frameworks/      — встроенные фреймворки (часто с логикой)
```

```bash
# дешифровка main-бинарника прямо с устройства (нужен jailbreak + frida)
pip install frida-tools
git clone https://github.com/AloneMonkey/frida-ios-dump
python3 dump.py com.target.app      # создаёт decrypted .ipa
```

Без дешифровки бинарник содержит только «loader»-часть, а код лежит в зашифрованном сегменте `__TEXT` — `class-dump` покажет пустые методы.

## class-dump и ObjC runtime

ObjC-классы хранят метаданные (имена классов, методов, типов) в бинарнике — их можно извлечь даже без дешифровки кода, если сегмент не зашифрован (после дешифровки — точно).

```bash
class-dump -H AppName -o headers/     # сгенерировать .h для каждого класса
ls headers/ | head
# в заголовках видно интерфейсы:
# @interface AuthManager : NSObject
# - (NSString *)getToken;
# - (BOOL)isJailbroken;
```

Так вы получаете карту классов и методов — основу для динамики (что хукать) и для чтения логики. Аналоги: `nm -U AppName` (символы), `otool -L` (зависимости), `strings -a AppName | grep -i secret`.

## Swift: деманглинг и метаданные

Swift-символы манглируются (`_$s...`). Их читают через `swift-demangle` или инструменты дизассемблера.

```bash
nm -U AppName | swift-demangle | grep -i "Auth\|Token\|Key"
# $s6MyApp11AuthManagerC8getTokenSSyF -> MyApp.AuthManager.getToken() -> Swift.String
```

Swift-логика в дизассемблере читается сложнее ObjC: много встроенных проверок, значение-типы. Помогают: восстановление типов в Hopper/IDA (плагины), поиск строк-констант и вызовов крипто/сетевых API. Для SwiftUI логика в основном в коде, а не в storyboard.

## Дизассемблеры: Hopper, IDA, Ghidra

```bash
# Ghidra (бесплатно, headless)
analyzeHeadless /tmp/proj MyProj -import AppName -postScript DumpStrings.java
# Hopper: GUI, удобен для ObjC; IDA: лучший для сложных бинарников
```

Что искать: вызовы `SecKeyChain*` (Keychain), `NSURLSession` (сеть), `CCCrypt`/`SecKeyEncrypt` (крипта), `fork`/`stat("/bin/bash")` (jailbreak-детект), `SSL_pin`/`SecTrustEvaluate` (pinning). Строки и кросс-ссылки — быстрый путь к интересным функциям.

## Дешифровка App Store бинарников

FairPlay-шифрование: сегмент `__TEXT` зашифрован, ключ выдаётся только на устройстве при запуске. Инструменты дешифровки работают на jailbreak-устройстве, снимая расшифрованный образ из памяти:

```bash
# frida-ios-dump (см. выше), Clutch, bfdecrypt
Clutch -i                       # список приложений
Clutch -d com.target.app        # дешифровать
# проверить, зашифрован ли бинарник
otool -l AppName | grep -A4 LC_ENCRYPTION_INFO
# cryptid 1 = зашифрован, 0 = расшифрован
```

Без этого шага статический анализ кода невозможен — вы увидите только строки/метаданные.

## Info.plist и entitlements

```bash
plutil -p Info.plist | head -40        # конфигурация: URL-схемы, ATS, ключи
plutil -p Info.plist | grep -i -A3 "CFBundleURLSchemes\|NSAppTransportSecurity"
codesign -d --entitlements - AppName   # права: keychain-access-groups, app groups
```

Смотрите: `NSAppTransportSecurity` (разрешён ли HTTP — `NSAllowsArbitraryLoads`), URL-схемы (deep links), `get-task-allow` (разрешена ли отладка), Keychain-группы. `NSAllowsArbitraryLoads=true` — разрешён незашифрованный HTTP.

## Поиск секретов

```bash
strings -a AppName | grep -iE "api[_-]?key|secret|token|password" | head
grep -rInE "AIza|AKIA|firebaseio|sk_live" app_ipa/ | head
# встроенные сертификаты/pinning
ls AppName.app/*.cer AppName.app/*.crt 2>/dev/null
```

Часто в бандл встроены `.cer`/`.der` (публичные ключи для pinning) — их наличие указывает на pinning, а не на секрет. Настоящие секреты (ключи API) ищите теми же регулярками, что и на Android.

## Разобранный пример: карта приложения за 10 минут

```bash
$ unzip -q app.ipa -d app_ipa
$ cd app_ipa/Payload/App.app
$ otool -l App | grep -A4 LC_ENCRYPTION_INFO   # cryptid 1 -> нужна дешифровка
$ python3 ~/frida-ios-dump/dump.py com.target.app   # -> decrypted ipa
$ class-dump -H App -o headers/
$ grep -rn "isJailbroken\|SecTrustEvaluate\|SecItemCopyMatching" headers/ | head
AuthManager.h: - (BOOL)isJailbroken;
NetworkManager.h: - (void)URLSession:(...)didReceiveChallenge:...;
$ strings -a App | grep -iE "FLAG|secret|api_key" | head
```

За 10 минут получены: список классов, методы jailbreak-детекта, кастомный `didReceiveChallenge` (признак pinning) и строки-кандидаты. Дальше — динамика (`mobile-ios-dynamic`) для обхода проверок.

## Справочная таблица инструментов

| Задача | Инструмент | Команда |
|--------|-----------|---------|
| Распаковка IPA | unzip | `unzip app.ipa -d out` |
| Дешифровка | frida-ios-dump | `python3 dump.py com.target.app` |
| Заголовки ObjC | class-dump | `class-dump -H App -o headers/` |
| Swift-символы | swift-demangle | `nm -U App \| swift-demangle` |
| Дизассемблер | Hopper/IDA/Ghidra | GUI / `analyzeHeadless` |
| Плист | plutil | `plutil -p Info.plist` |
| Права | codesign | `codesign -d --entitlements - App` |
| Строки | strings | `strings -a App \| grep -i key` |

## Типовые ошибки новичка

- **Анализировать зашифрованный бинарник.** `cryptid 1` = сначала дешифровка, иначе `class-dump` бесполезен.
- **Искать «исходники».** На iOS нет декомпиляции в код; работайте с метаданными + дизассемблером.
- **Забыть про фреймворки.** Логика часто в `Frameworks/*.framework`, а не только в main-бинарнике.
- **Путать встроенный сертификат pinning с секретом.** `.cer` — публичный ключ, не утечка.
- **Игнорировать `Info.plist`.** Там URL-схемы, ATS и ключи — быстрые находки.

## Что дальше / решение

Порядок: получить IPA → дешифровать (`cryptid 0`) → `class-dump`/`swift-demangle` для карты → `strings`/`plutil`/`codesign` для конфигурации и секретов → чтение логики в Hopper/IDA → динамика (`mobile-ios-dynamic`) для обхода проверок. Связанные уроки: `mobile-ios-basics`, `mobile-ios-keychain`, `mobile-ios-urlscheme`, `mobile-ssl-pinning`. Решение — когда у вас есть карта классов, найденные секреты/проверки и понимание, что хукать дальше.

## Что искать в дизассемблере: чек-лист

Ищите кросс-ссылки на строки и вызовы системных API — это самые «горячие» точки:

- **Крипта:** `CCCrypt`, `CCCryptorCreate`, `SecKeyEncrypt`, `SecKeyRawSign`, `CCHmac`, `CC_MD5` — ищите захардкоженные ключи/IV рядом.
- **Keychain:** `SecItemAdd`, `SecItemCopyMatching`, `kSecAttrAccessible` — какой уровень защиты (`WhenUnlocked`, `Always`, `ThisDeviceOnly`).
- **Сеть:** `NSURLSession`, `NSURLConnection`, `CFStream`, `nw_connection` — где формируются запросы и токены.
- **TLS/pinning:** `SecTrustEvaluate`, `SecTrustEvaluateWithError`, `SSL_set_verify`, `AFSecurityPolicy` — признак pinning.
- **Jailbreak:** `stat`, `access`, `fork`, `canOpenURL:`, `fileExistsAtPath:` со строками `/bin/bash`, `/Applications/Cydia.app`, `cydia://`.
- **Anti-debug:** `ptrace`, `sysctl`, `task_get_exception_ports`, строка `PT_DENY_ATTACH`.
- **Deep links:** обработчики `application:openURL:options:`, `application:continueUserActivity:` и строки URL-схем.

Практика: в Ghidra/Hopper найдите строку (`FLAG`, `https://`, `key`), посмотрите References — оттуда переходите к функциям. Это быстрее, чем читать бинарник линейно.

## Справочная таблица: артефакты iOS-бандла

| Файл | Что содержит | Как читать |
|------|--------------|------------|
| `AppName` (Mach-O) | код, строки, символы | `otool`, `nm`, Hopper/IDA |
| `Info.plist` | конфиг, URL-схемы, ATS | `plutil -p` |
| `embedded.mobileprovision` | профиль подписи, entitlements | `security cms -D -i` |
| `Frameworks/*` | встроенные фреймворки | `class-dump`, дизассемблер |
| `Assets.car` | ассеты, строки | `acextract`, `AssetCatalogTinkerer` |
| `*.cer`/`*.der` | ключи pinning | `openssl x509 -inform der -text` |
| `*.strings` | локализация (строки) | `plutil -p`/`grep` |

## Типовые ошибки (продолжение)

- **Пропустить `Assets.car`.** Ассеты и строки могут быть там, а не в `Info.plist`.
- **Не проверить entitlements.** `keychain-access-groups` и App Groups показывают, куда пишутся секреты.
- **Считать, что Swift «нечитаем».** `swift-demangle` + кросс-ссылки дают много; не отказывайтесь от Swift-логики.
- **Забыть про фреймворки.** Пользовательский код часто в отдельном `.framework`, а не в main-бинарнике.

## Квиз

```quiz
- question: "Как понять, зашифрован ли App Store-бинарник?"
  options:
    - "LC_ENCRYPTION_INFO с cryptid=1"
    - "Отсутствие Info.plist"
    - "Наличие libSystem"
    - "Размер > 10 МБ"
  answer: 0
  explanation: "cryptid=1 означает FairPlay-шифрование, символы недоступны."
- question: "Какой инструмент восстанавливает объявления Objective-C-классов?"
  options:
    - "class-dump"
    - "jadx"
    - "apktool"
    - "binwalk"
  answer: 0
  explanation: "class-dump извлекает @interface из runtime-метаданных."
- question: "Чем расшифровать App Store-сборку на джейлбрейке?"
  options:
    - "frida-ios-dump / bagbak"
    - "apktool"
    - "upx"
    - "ghidra"
  answer: 0
  explanation: "Они снимают расшифрованный образ из памяти процесса."
- question: "Что такое Swift-mangling и зачем demangle?"
  options:
    - "Кодировка имён Swift; demangle делает их читаемыми"
    - "Способ шифрования"
    - "Формат Mach-O"
    - "Тип подписи"
  answer: 0
  explanation: "Swift искажает имена; demangle восстанавливает читаемый вид."
- question: "Где посмотреть entitlements iOS-приложения?"
  options:
    - "codesign -d --entitlements :-"
    - "plutil -p Info.plist"
    - "otool -L"
    - "nm -U"
  answer: 0
  explanation: "codesign показывает entitlements (keychain-access-groups и др.)."
```

## Где пригодится

- **CTF Mobile/Reversing:** реверс iOS-бинарников и извлечение флага.
- **Bug bounty:** анализ клиента на секреты и слабые проверки.
- **Пентест:** подготовка к динамике (какие методы хукать).
- **Работа:** reverse engineering в anti-fraud и threat intel.
