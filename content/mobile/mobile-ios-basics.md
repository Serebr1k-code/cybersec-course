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

## Вопрос, с которого всё начинается

На Android ты уже умеешь распаковывать APK и читать DEX. Но мобильный пентест — это не только Android: клиент iOS устроен совсем иначе. Здесь другой формат бинарника, другой язык, другой инструментарий и другой способ получать доступ к системе.

Тебе дали файл `DemoApp.ipa`. Как его разобрать и что вообще внутри?

## Наш пример: DemoApp.ipa

Наш объект — `DemoApp.ipa`, сборка учебного приложения для iOS. Начнём с самого простого: `ipa` — это ZIP-архив (как APK). Посмотрим его содержимое:

```
$ unzip -l DemoApp.ipa
  Length      Name
    32976   Payload/DemoApp.app/DemoApp
      752   Payload/DemoApp.app/Info.plist
    32888   Payload/DemoApp.app/DemoApp.dylib
```

Внутри — каталог `Payload/`, а в нём `.app`-бандл. Это «пакет приложения»: главный бинарник `DemoApp`, файл настроек `Info.plist` и динамическая библиотека `DemoApp.dylib`. Запомним три слоя: бинарник (код), plist (конфигурация), библиотеки.

## Шаг 1: определяем формат бинарника

На Android код лежит в DEX и декомпилируется в Java. На iOS код — это **нативный** бинарник формата **Mach-O** (аналог ELF на Linux). Проверим:

```
$ file Payload/DemoApp.app/DemoApp
Payload/DemoApp.app/DemoApp: Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
```

`arm64` — архитектура процессоров Apple (Apple Silicon). `executable` — это главный бинарник приложения. `PIE` означает, что код грузится по случайному адресу (защита от эксплуатации). Mach-O, в отличие от DEX, **не декомпилируется в исходник** так чисто: Objective-C и Swift компилируются в машинный код, поэтому работают дизассемблеры и метаданные, а не «обратная сборка в .swift».

## Шаг 2: смотрим структуру Mach-O

Разберём бинарник послойно — как сегменты. Сегменты — это крупные блоки файла с разным назначением. Выведем заголовок и load-команды (записи о том, как загружать файл):

```
$ python3 macho_lc.py Payload/DemoApp.app/DemoApp.dylib
Mach-O 64-bit  cputype=16777228  filetype=6  ncmds=11  flags=0x100085
  LC_SEGMENT_64            __TEXT       vmaddr=0x0 filesize=0x8000
  LC_SEGMENT_64            __LINKEDIT   vmaddr=0x8000 filesize=0x78
  LC_DYLD_EXPORTS_TRIE
  LC_ID_DYLIB              DemoApp.dylib
```

`__TEXT` — сегмент с кодом (только чтение и исполнение), `__LINKEDIT` — таблицы символов и подписей. Load-команды описывают, откуда грузить код. На практике чаще пользуются `otool -l` на macOS, но принцип тот же.

## Шаг 3: читаем конфигурацию (Info.plist)

`Info.plist` — это XML с настройками приложения. На macOS его смотрят `plutil -p`, но формат обычный XML, и его можно разобрать любым plist-парсером:

```
$ python3 -c "import plistlib;d=plistlib.load(open('Payload/DemoApp.app/Info.plist','rb'));print(d['CFBundleIdentifier'], d['CFBundleShortVersionString'])"
com.demo.secapp 2.4.1
```

`CFBundleIdentifier` — идентификатор приложения (аналог имени пакета в Android). Дальше — самое интересное для атакующего:

```
$ python3 -c "import plistlib;d=plistlib.load(open('Payload/DemoApp.app/Info.plist','rb'));print('URL schemes:',d['CFBundleURLTypes'][0]['CFBundleURLSchemes']);print('ATS:',d['NSAppTransportSecurity'])"
URL schemes: ['demosec']
ATS: {'NSAllowsArbitraryLoads': True}
```

Две находки. Схема `demosec` означает, что приложение открывается по ссылке `demosec://...` — потенциальный вход для атак (см. `mobile-ios-urlscheme`). А `NSAllowsArbitraryLoads: True` в `NSAppTransportSecurity` — это разрешение на незашифрованный HTTP (обход правил ATS). Каждое из этих полей — зацепка.

## Шаг 4: ищем строки и символы

В нативном коде часто остаются строки — URL, ключи, подсказки. Извлечём их из библиотеки:

```
$ strings Payload/DemoApp.app/DemoApp.dylib | grep -iE 'api|secret|s3cr3t|validate'
s3cr3t
https://api.demo.example/v2
validate_pin
api_base
```

Вот и секрет: строка `s3cr3t` и адрес API. Символы `validate_pin` и `api_base` — это имена функций. Из `strings` мы получили и логику (есть проверка `validate_pin`), и данные (базовый URL).

## Шаг 5: дешифровка — главное отличие iOS

Есть одна важная особенность. Бинарники, скачанные из App Store, **зашифрованы** (технология FairPlay), чтобы их нельзя было просто разобрать. В таком бинарнике есть load-команда `LC_ENCRYPTION_INFO_64` с полем `cryptid`:

```
$ python3 macho_lc.py Payload/DemoApp.app/DemoApp.dylib | grep -i encryption
  LC_ENCRYPTION_INFO_64
```

Если `cryptid=1`, сегмент `__TEXT` зашифрован, и `strings`/`class-dump` покажут пустоту. Тогда сначала **дешифруют** — прямо с jailbreak-устройства утилитой `frida-ios-dump` (или `bagbak`, `Clutch`). Наш `DemoApp` — локальная сборка, поэтому `cryptid=0` и анализ сразу работает.

## Шаг 6: jailbreak вместо root

На Android для доступа к песочнице нужен root. На iOS аналог — **jailbreak**: снятие программных ограничений, после которого появляется менеджер пакетов (Cydia/Sileo) и можно ставить инструменты (`frida`, `objection`). Без jailbreak многие техники недоступны: нельзя встроиться в чужой процесс, читать чужую песочницу или дампить Keychain. Альтернатива — переподписать IPA со встроенным `frida-gadget` и поставить через sideload.

## Шаг 7: Keychain — хранилище секретов

На Android секреты лежат в `SharedPreferences` и SQLite. На iOS — в **Keychain**: защищённом хранилище, где приложение складывает токены и пароли. Достать их можно с jailbreak-устройства через Objection:

```
$ objection -g com.demo.secapp explore
com.demo.secapp # ios keychain dump
```

Об этом — отдельный урок `mobile-ios-keychain`. Пока важно запомнить: Keychain — это не файл, а база, и её содержимое — цель анализа.

## Шаг 8: карта классов и права

Прежде чем лезть в дизассемблер, полезно получить «карту» приложения — список классов и методов. Для Objective-C это делает `class-dump`: он читает метаданные runtime прямо из бинарника и генерирует заголовочные файлы `.h`.

```
$ class-dump -H Payload/DemoApp.app/DemoApp -o headers/
$ ls headers/ | head
DemoApp.h  AuthManager.h  CryptoUtil.h
```

Теперь видно, какие классы есть: `AuthManager`, `CryptoUtil`. Это подсказывает, где искать логику авторизации и шифрования. Для Swift-классов `class-dump` помогает меньше (методы часто не экспонированы в ObjC-runtime), поэтому имена символов «деманглируют»:

```
$ nm -U Payload/DemoApp.app/DemoApp | swift-demangle | grep -i 'Auth\|Token'
```

Ещё один слой — **entitlements**: права, выданные приложению. Они показывают, к каким группам Keychain и App Groups приложение имеет доступ:

```
$ codesign -d --entitlements - Payload/DemoApp.app/DemoApp
```

Если приложение состоит в App Group, данные могут быть доступны другим приложениям той же группы — это ещё один вектор. Наконец, проверь зависимости от фреймворков (`otool -L`): встроенные библиотеки и сторонние SDK часто содержат собственные секреты.

## Шаг 9: смотрим состав IPA

Разберём `.ipa` до того, как трогать бинарник:

```
$ file DemoApp.ipa
DemoApp.ipa: iOS App
$ unzip -l DemoApp.ipa | head -8
Archive:  DemoApp.ipa
  Length      Date    Time    Name
---------  ---------- -----   ----
      452  2026-10-12 18:10   Payload/DemoApp.app/Info.plist
     4096  2026-10-12 18:10   Payload/DemoApp.app/DemoApp
```

`file` узнаёт IPA по структуре `Payload/*.app`. `unzip -l` показывает содержимое без распаковки: видно `Info.plist` и исполняемый файл `DemoApp`. Дальше `Info.plist` парсят (`plutil` или `python3 plistlib`) и читают `CFBundleIdentifier`, `CFBundleURLTypes`, `NSAppTransportSecurity`. Так за минуту получаешь bundle id, схемы и настройки сетевой безопасности — с них начинается любой разбор iOS-приложения.

## Что мы теперь знаем

- IPA — ZIP с `Payload/<App>.app/`, внутри — Mach-O бинарник, `Info.plist` и библиотеки.
- Mach-O — нативный формат; iOS-код не «декомпилируется в исходник», работают `strings`, `class-dump`, дизассемблеры.
- `Info.plist` хранит конфигурацию: URL-схемы, ATS, версии.
- `strings` по бинарнику часто выдаёт секреты и имена функций.
- App Store-бинарники зашифрованы (`cryptid=1`) — нужна дешифровка (`frida-ios-dump`).
- Jailbreak — аналог root; без него многие техники недоступны.
- Keychain — хранилище секретов приложения.

## Квиз

Проверь себя.

```quiz
- question: Что такое IPA?
  options:
    - "Язык программирования iOS"
    - "ZIP-архив приложения: Payload/<App>.app с Mach-O, Info.plist и ресурсами"
    - "Формат подписи"
    - "Хранилище Keychain"
  answer: 1
  explanation: "IPA — это упакованный .app-бандл, по сути ZIP-архив."
- question: Чем Mach-O отличается от DEX?
  options:
    - "Это тот же формат"
    - "Это нативный машинный код; он не декомпилируется в исходник так же чисто"
    - "Он текстовый"
    - "Он только для Android"
  answer: 1
  explanation: "Objective-C/Swift компилируются в машинный код; работают дизассемблеры, а не декомпиляция в исходники."
- question: Что означает `cryptid=1` в бинарнике?
  options:
    - "Бинарник подписан"
    - "Бинарник зашифрован (App Store/FairPlay) и требует дешифровки"
    - "Бинарник 64-битный"
    - "Приложение отлаживаемое"
  answer: 1
  explanation: "Зашифрованный __TEXT делает class-dump/strings бесполезными, пока не снимешь шифрование."
- question: Какое поле Info.plist задаёт URL-схему приложения?
  options:
    - "CFBundleIdentifier"
    - "CFBundleURLSchemes внутри CFBundleURLTypes"
    - "NSAppTransportSecurity"
    - "CFBundleExecutable"
  answer: 1
  explanation: "CFBundleURLTypes перечисляет схемы, по которым открывается приложение."
- question: Что такое jailbreak в контексте iOS-пентеста?
  options:
    - "Тип шифрования"
    - "Снятие программных ограничений iOS, аналог root на Android"
    - "Формат IPA"
    - "Инструмент для подписи"
  answer: 1
  explanation: "Jailbreak даёт доступ к системе и позволяет ставить инструменты вроде Frida."
```

## Куда дальше

Мы разобрали IPA поверхностно. Дальше — **статический анализ**: `class-dump` для карты классов Objective-C, `swift-demangle` для Swift, поиск секретов и проверок jailbreak/pinning прямо в бинарнике. Это следующий урок (`mobile-ios-static`). А пока главное запомни: IPA → Mach-O + Info.plist, а секреты и логику ищут через `strings`, `class-dump` и дизассемблер, предварительно сняв шифрование.

## Где пригодится

- **Пентест:** первичный разбор iOS-приложения и поиск зацепок.
- **Bug bounty:** анализ IPA для поиска секретов и опасных URL-схем.
- **CTF:** Mobile-задачи на iOS, где флаг спрятан в бинарнике или plist.
- **Аудит:** проверка ATS и entitlements в релизной сборке.
