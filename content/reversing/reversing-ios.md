---
id: reversing-ios
title: "Реверс iOS: Mach-O, Frida и jailbreak"
category: reversing
parent: reversing-android-apk
difficulty: expert
order: 2
tags: [reversing, ios, macho, frida, jailbreak, arm64, ipa]
prerequisites: [reversing-android-apk, reversing-architectures]
useful_for:
  - "CTF Reversing / Mobile"
  - "Анализ iOS-малвари"
  - "Bug bounty (iOS-приложения)"
estimated_minutes: 55
summary: "Разбор iOS-приложений: Mach-O, IPA, класс-дамп, Hopper/Ghidra, Frida и обход jailbreak/SSL-pinning."
---
**Реверс iOS** — это анализ Mach-O бинарников приложений, фреймворков и системных процессов Apple. Особенности: формат Mach-O, Objective-C/Swift рантайм, шифрование App Store бинарников (FairPlay), закрытая экосистема и необходимость jailbreak для полноценного анализа. Урок даёт полный практический workflow: структура Mach-O, инструменты (`otool`, `class-dump`, Hopper, IDA), дешифровка FairPlay, разбор Objective-C/Swift, Frida на iOS и полный разобранный пример.

## Зачем реверсить iOS

- **Анализ приложений** — логика, секреты, API-ключи, защита от копирования.
- **Мобильная безопасность** — поиск уязвимостей, обход jailbreak/отладки-детекции.
- **Malware** — анализ iOS-малвари (редкой, но существующей).
- **CTF** — задачи на Mach-O, Swift, iOS-специфику.
- **Исследования** — понимание системных фреймворков.

## Формат Mach-O

Mach-O — аналог ELF/PE для Apple. Состоит из **заголовка**, **load commands** и **сегментов** (`__TEXT`, `__DATA`, `__LINKEDIT`). Ключевые структуры:

- **`LC_SEGMENT_64`** — сегменты памяти (`__TEXT` — код, `__DATA` — данные).
- **`LC_SYMTAB`** — таблица символов.
- **`LC_DYLD_INFO`** / **`LC_DYLD_CHAINED_FIXUPS`** — информация для динамической линковки (dyld).
- **`LC_LOAD_DYLIB`** — зависимости (аналог `NEEDED`).
- **`LC_CODE_SIGNATURE`** — подпись кода.

```bash
file MyApp            # Mach-O 64-bit arm64 executable
otool -h MyApp        # Mach-O header
otool -l MyApp | head # load commands
otool -L MyApp        # динамические библиотеки
```

## Инструменты

| Инструмент | Назначение | Команда |
|---|---|---|
| `otool` | разбор Mach-O | `otool -l/-L/-tV bin` |
| `class-dump` | дамп ObjC-интерфейсов | `class-dump bin` |
| `Hopper` | дизассемблер/декомпилятор | GUI |
| `IDA` | дизассемблер | GUI |
| `Ghidra` | бесплатный дизассемблер | Mach-O loader |
| `jtool2` | расширенный Mach-O | `jtool2 -l bin` |
| `Frida` | динамический хукинг | `frida -U app` |
| `ipsw` | разбор прошивок/кеша | `ipsw dyld extract` |

## Дешифровка App Store бинарников (FairPlay)

Бинарники из App Store **зашифрованы** (FairPlay DRM): секция `__TEXT.__text` зашифрована, а ключ расшифровки доступен только на устройстве при запуске. Поэтому «скачанный» бинарник нужно **расшифровать на устройстве**.

```bash
# на jailbroken устройстве
# 1) найти app
frida-ps -Uai | grep -i target
# 2) снять дамп расшифрованного __TEXT из памяти
# инструменты: frida-ios-dump, bagbak, Clutch
frida-ios-dump -u <udid> com.target.app
# результат: decrypted .ipa с расшифрованным бинарником
```

Проверка: `otool -l MyApp | grep cryptid` — `cryptid 1` = зашифрован, `cryptid 0` = расшифрован.

## Objective-C и Swift

**Objective-C** использует динамический рантайм: методы вызываются через `objc_msgSend`, а классы/селекторы хранятся в секциях `__objc_*`. `class-dump` восстанавливает интерфейсы.

```bash
class-dump -H MyApp -o headers/
# генерирует .h с @interface/@property
otool -oV MyApp | head    # ObjC-метаданные
```

**Swift** использует манглированные имена (name mangling), например `$s4MyApp7LoginVC...`. Деманглинг — `swift demangle` или `xcrun swift-demangle`:

```bash
echo '$s4MyApp7LoginVCC6verifySbSSF' | xcrun swift-demangle
# MyApp.LoginVC.verify(Swift.String) -> Swift.Bool
```

Swift-структуры и методы разбираются в IDA/Ghidra/Hopper; ищите `swift_`-символы.

## Frida на iOS

```bash
# устройство должно быть jailbroken (или использовать frida-gadget)
# подключение
frida-ps -U
frida -U -f com.target.app -l hook.js --no-pause
```

Пример хука ObjC-метода:

```javascript
if (ObjC.available) {
  var Login = ObjC.classes.LoginVC;
  Interceptor.attach(Login['- verify:'].implementation, {
    onEnter(args) {
      var s = new ObjC.Object(args[2]);
      console.log("verify called with: " + s.toString());
    },
    onLeave(ret) { console.log("return: " + ret); }
  });
}
```

Swift-методы хукаются по символу: `Module.enumerateSymbols` → найти манглированное имя → `Interceptor.attach`.

## Jailbreak и среда анализа

- **Palera1n** (checkm8-совместимые устройства) — jailbreak без подписи.
- **Dopamine/TrollStore** — для современных версий.
- **На устройстве** нужны `openssh`, `frida-server`, `Cydia`/`Sileo`.
- **Без jailbreak** — работа с `frida-gadget` внутри перепакованного IPA (требует подписи/устройства разработчика) или анализ «на диске» (нерасшифрованный код).

```bash
ssh root@<device-ip>       # пароль alpine по умолчанию
scp frida-server root@<ip>:/usr/sbin/
```

## Разобранный пример: обход проверки jailbreak

**Шаг 1. class-dump → найти проверку.**

```objc
@interface JailbreakDetector : NSObject
- (BOOL)isJailbroken;
@end
```

**Шаг 2. Хук через Frida.**

```javascript
var Det = ObjC.classes.JailbreakDetector;
Interceptor.attach(Det['- isJailbroken'].implementation, {
  onLeave(ret) { ret.replace(ptr(0)); }   // всегда false
});
```

**Шаг 3. Если проверка Swift/native** — найти символ, `Interceptor.replace` вернуть 0.

**Шаг 4. Патч бинарника** (офлайн): в IDA/Hopper изменить `mov w0, #1` → `mov w0, #0`, переподписать (`ldid -S`, `codesign`).

## Работа с dyld shared cache

Системные библиотеки iOS собраны в **dyld shared cache** — один большой файл, а не отдельные `.dylib`.

```bash
ipsw dyld extract /path/to/dyld_shared_cache_arm64e
# извлекает отдельные dylib для анализа
jtool2 -e UIKit /path/cache
```

Это нужно, чтобы анализировать системные фреймворки (Foundation, UIKit) в дизассемблере.

## Частые ошибки и подводные камни

- **Анализ зашифрованного бинарника.** `cryptid 1` — код зашифрован; без дампа с устройства ничего не разберёте.
- **Путаница ObjC/Swift.** Swift-символы манглированы; используйте `swift-demangle`.
- **Отсутствие jailbreak.** Многие динамические техники недоступны; используйте frida-gadget.
- **Подпись после патча.** Изменённый бинарник не запустится без переподписи (`codesign`/`ldid`).
- **dyld cache.** Системные библиотеки не лежат отдельными файлами — извлекайте из кеша.
- **Версии iOS.** API/пути меняются; учитывайте версию устройства.

## Что дальше / решение

Маршрут: **расшифровать бинарник (FairPlay dump) → class-dump/otool → декомпиляция (Hopper/IDA/Ghidra) → Frida для динамики → обход защит**. Для CTF — ищите проверки и флаги в ObjC/Swift. Дальше — `reversing-swift-objc`, `reversing-frida-advanced` и `mobile-app-security-testing`.

## Структура Mach-O глубже: сегменты и секции

Каждый сегмент содержит секции; для реверса важны:

- **`__TEXT,__text`** — машинный код (шифруется FairPlay).
- **`__TEXT,__cstring`** — C-строки.
- **`__TEXT,__objc_methname`** / **`__objc_methtype`** — имена/типы ObjC-методов.
- **`__DATA,__objc_classlist`** — список классов.
- **`__DATA,__objc_data`** — данные классов.
- **`__DATA_CONST,__got`** — GOT-таблица (аналог ELF).
- **`__LINKEDIT`** — символы, релокации, подпись.

```bash
otool -l MyApp | grep -A4 'segname __TEXT'
otool -s __TEXT __objc_methname MyApp | head
jtool2 -d MyApp        # разбор секций с аннотациями
```

Понимание раскладки нужно, чтобы вручную находить строки, селекторы и классы, когда `class-dump` не справляется (например, при обфускации имён).

## Разбор Swift: от манглинга к логике

Swift компилируется в нативный код, но с богатыми метаданными. Манглированные имена несут типы и методы.

```bash
# найти swift-символы
nm -U MyApp | grep '\$s'
# деманглировать пачкой
nm -U MyApp | grep '\$s' | sed 's/.*\($s[0-9A-Za-z_]*\).*/\1/' | while read s; do
  echo -n "$s -> "; echo "$s" | xcrun swift-demangle
done | head
```

Вывод вроде `MyApp.AuthManager.validateToken(token: Swift.String) -> Swift.Bool` сразу даёт карту методов. В Ghidra/IDA есть плагины Swift-деманглинга; в противном случае имена вручную сопоставляются через `swift-demangle`. Отдельно ищите строки ошибок (`Swift runtime failure`, `Fatal error`) — они выдают места проверок.

## Динамический анализ: Frida-скрипты для iOS

```javascript
// перехват всех вызовов objc_msgSend к конкретному селектору
if (ObjC.available) {
  var sel = 'checkJailbreak';
  var selPtr = ObjC.selector(sel);
  Interceptor.attach(ObjC.classes.NSObject['- respondsToSelector:'].implementation, {
    onEnter(args) {
      var s = ObjC.selectorAsString(args[2]);
      if (s && s.indexOf('Jailbreak') !== -1) console.log('probe: ' + s);
    }
  });
}
// перебор классов и методов
Object.keys(ObjC.classes).forEach(function (c) {
  if (c.indexOf('Target') !== -1) {
    var methods = ObjC.classes[c].$ownMethods;
    methods.forEach(m => console.log(c + ' ' + m));
  }
});
```

Так можно быстро нанести на карту интересующие классы и их методы, а затем точечно хукать проверки. Для Swift используйте `Module.enumerateSymbolsSync('MyApp')` и фильтруйте по деманглированному имени.

## Работа с entitlements и песочницей

iOS-приложения изолированы (sandbox) и имеют **entitlements** — права, вшитые в подпись. Их анализ важен для понимания возможностей и потенциальных злоупотреблений.

```bash
codesign -d --entitlements :- MyApp      # показать entitlements
ldid -e MyApp                            # альтернатива (jailbreak)
```

Интересные entitlements: `get-task-allow` (отладка), `platform-application`, доступ к keychain, сетевые исключения. При перепаковке IPA нужно сохранить/подменить entitlements корректно, иначе приложение не запустится.

## Символьный анализ и восстановление типов

Без исходников восстановить типы помогают: `class-dump` для ObjC, `swift-demangle` для Swift, а также инструменты вроде `class-dump-z`/`dyldinfo`. В IDA/Ghidra применяйте плагины автотипизации. Для C-функций — читайте соглашения вызова ARM64 (x0-x7 — аргументы, x0 — возврат) и восстанавливайте сигнатуры вручную.

## Подписи кода и перепаковка IPA

После любого патча бинарник нужно переподписать, иначе iOS его не запустит. Для jailbroken-устройства — `ldid`; для устройства разработчика — `codesign` с вашим сертификатом.

```bash
# перепаковка IPA
unzip -o app.ipa -d appdir
# ... патч Payload/MyApp.app/MyApp ...
zip -r patched.ipa appdir
# подпись (jailbreak)
ldid -S patched.ipa
# подпись (устройство разработчика)
codesign -f -s "Apple Development: you" --entitlements ent.plist MyApp.app
```

Важно сохранить `entitlements`: их удаление/искажение сломает функции (keychain, сеть, push). Проверяйте `codesign -d --entitlements` после перепаковки.

## Итог: маршрут реверса iOS

Последовательность: **jailbreak → frida-ios-dump (расшифровка) → class-dump/otool → Hopper/IDA/Ghidra → Frida для проверок → перепаковка при необходимости**. Всегда проверяйте `cryptid` (расшифрован ли код) и entitlements. Для системных фреймворков извлекайте dylib из dyld shared cache.

## Проверка результата анализа

После всех шагов убедитесь, что: `otool -l | grep cryptid` даёт `0` (код расшифрован), `class-dump`/`nm` выдают осмысленные символы, а `codesign -d --entitlements` показывает ожидаемые права. Только при расшифрованном коде дизассемблер даст корректные инструкции в `__TEXT,__text` — иначе вы будете смотреть на шифрованные байты и «мусорные» инструкции.

## Квиз

```quiz
- question: "В каком формате исполняемые файлы iOS?"
  options:
    - "ELF"
    - "PE"
    - "Mach-O"
    - "DEX"
  answer: 2
  explanation: "Apple использует Mach-O вместо ELF/PE."
- question: "Что означает cryptid=1 у бинарника из App Store?"
  options:
    - "Файл сжат"
    - "Сегмент __TEXT зашифрован (FairPlay), нужен дамп с устройства"
    - "Это fat-бинарь"
    - "Бинарник подписан"
  answer: 1
  explanation: "App Store-бинарники зашифрованы FairPlay, пока не дампнут с памяти."
- question: "Какой инструмент даёт заголовки Objective-C классов?"
  options:
    - "readelf"
    - "dsdump / class-dump"
    - "upx"
    - "jadx"
  answer: 1
  explanation: "ObjC runtime-таблицы читают dsdump/class-dump."
- question: "Зачем хукать SecTrustEvaluate в Frida?"
  options:
    - "Чтобы ускорить приложение"
    - "Чтобы обойти SSL pinning и читать трафик"
    - "Чтобы расшифровать IPA"
    - "Чтобы включить jailbreak"
  answer: 1
  explanation: "Подмена результата доверия снимает certificate pinning."
- question: "Что нужно, чтобы патченный Mach-O запустился?"
  options:
    - "Ничего"
    - "Переподписать (codesign/ldid) или использовать jailbreak"
    - "Сжать UPX"
    - "Сконвертировать в DEX"
  answer: 1
  explanation: "iOS проверяет подпись кода; патч требует переподписи."
```

## Где пригодится

- **CTF Reversing/Mobile:** iOS-крэкми, jailbreak-детект, скрытые флаги в ObjC.
- **Bug bounty:** анализ iOS-клиентов банков и приложений для обхода client-side проверок.
- **Malware analysis:** iOS-шпионы (Pegasus-подобные) — Mach-O + Frida-трейсинг.
- **Работа:** mobile security в финтехе, обход pinning и защит на устройстве.
