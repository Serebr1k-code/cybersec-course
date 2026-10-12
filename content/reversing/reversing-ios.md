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
summary: "Реверс iOS-приложений: Mach-O внутри IPA, arm64, class-dump, Frida и обход SSL-pinning — на реальном arm64-бинарнике."
---

## Вопрос, с которого всё начинается

После Android логично посмотреть на iOS. Здесь всё иначе: приложение — это Mach-O внутри архива IPA, код скомпилирован под **ARM64**, а логика на Objective-C/Swift. Плюс два барьера, которых нет на Android: бинарники из App Store **зашифрованы**, а система защищена jailbreak-детектами. С чего начать разбор iOS-приложения?

## Наш пример

Возьмём настоящий arm64-бинарник `ios_demo`, собранный под macOS/iOS:

```bash
$ file ios_demo
ios_demo: Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
```

Как в уроке про Mach-O, разберём заголовок: магия `feedfacf`, `cputype=0x100000c` — это **ARM64**, `ftype=2` (`MH_EXECUTE`). Внутри, в `__TEXT,__text`, лежит код. Дизассемблируем (через capstone для ARM64):

```text
  0x1000002f0: sub    sp, sp, #0x10
  0x1000002fc: mov    w9, #0x1337
  0x100000300: subs   w8, w8, w9
  0x100000304: b.ne   0x100000318
  0x10000030c: mov    w8, #1
```

Функция `check` сравнивает аргумент с `0x1337` — та же логика, что мы видели везде, но под ARM64. iOS-бинарники — это Mach-O + ARM64, и оба навыка у нас уже есть.

## Шаг 1: IPA — контейнер приложения

Приложения распространяются как **IPA** (по сути ZIP). Внутри — знакомая структура:

```text
Payload/App.app/
    App                  <- главный Mach-O (код)
    Info.plist           <- метаданные приложения
    Frameworks/          <- динамические библиотеки (.dylib)
    embedded.mobileprovision  <- профиль подписи
```

Разбирают так: распаковать ZIP, взять главный Mach-O из `Payload/*.app/`, положить в дизассемблер. `Info.plist` содержит имя, версию, права — полезно для контекста.

## Шаг 2: шифрование App Store (важно!)

Бинарники, скачанные из App Store, **зашифрованы** (Apple шифрует `__TEXT` для защиты). В дизассемблере код выглядит мусором. Признак — load-команда **`LC_ENCRYPTION_INFO_64`** с ненулевым `cryptid`:

```text
cmd[7]=0x21 (LC_ENCRYPTION_INFO_64) size=32
```

Чтобы реверсить, бинарник надо **decrypt** — снять шифрование с **jailbroken** устройства (Frida-скрипт `frida-ios-dump`, утилита `Clutch`). Процесс: запустить приложение на устройстве, дождаться расшифровки в памяти и сдампить. На CTF и в малвари-образцах бинарники обычно уже расшифрованы — тогда шаг пропускается.

## Шаг 3: class-dump и Frida

У iOS-бинарников есть то же преимущество, что у Android: **имена классов и методов сохраняются**. Для Objective-C/Swift их вытаскивает **class-dump** (или `dsdump`), получая `.h`-интерфейсы:

```objc
@interface Auth : NSObject
- (BOOL)checkLicense:(NSString *)key;
- (NSString *)decrypt:(NSData *)data;
@end
```

Почти исходники — по ним видно, где проверка. Динамика идёт через **Frida** на jailbroken устройстве:

```js
Interceptor.attach(Module.findExportByName(null, '-[Auth checkLicense:]'), {
  onEnter(args) { console.log('key =', new ObjC.Object(args[2]).toString()); }
});
```

Frida перехватывает метод по имени и печатает аргументы — так находят правильный ключ без статического разбора.

## Шаг 4: SSL-pinning и jailbreak-детект

Реальная работа с iOS-приложением часто упирается в защиту:

- **SSL-pinning** — приложение проверяет сертификат сервера, и MITM-прокси (Burp) не работает. Обход: Frida-скрипт подменяет проверку сертификата (перехват `SecTrustEvaluate`).
- **Jailbreak-детект** — проверки наличия `Cydia`, `frida-server`, прав на файлы. Обход: Frida-хуки на `stat`/`fileExistsAtPath` или патч проверок.
- **Anti-debug** — `ptrace(PT_DENY_ATTACH)`: процесс отказывается отлаживаться. Обход: патч вызова или Frida-хук.

Все три обходятся одинаково: найти проверку (по строкам/символам) и нейтрализовать её хуком или патчем.

## Шаг 5: инструменты iOS-реверса

- **Ghidra / IDA / Hopper** — статика: Mach-O, ARM64, демагглинг ObjC/Swift.
- **class-dump / dsdump** — интерфейсы классов.
- **Frida** (+ `frida-ios-dump`, `objection`) — динамика, дамп расшифрованного бинарника, обход защит.
- **`otool` / `nm`** — заголовки и символы Mach-O.
- **`codesign -dvvv`** — информация о подписи.

Связка «Hopper/Ghidra + class-dump + Frida» покрывает практически все задачи по iOS. Для iOS-задач на CTF ещё пригодится `jtool2` — он умеет печатать заголовок, load-команды и символы Mach-O, а также извлекать конкретную архитектуру из fat-бинарника.

## Шаг 6: полный прогон от начала до конца

Соберём типовой разбор в цепочку:

1. **`unzip app.ipa`** — достали `Payload/App.app/App`.
2. **`file App`** — Mach-O arm64; при необходимости вырезали архитектуру через `lipo`.
3. **Проверили шифрование** — `otool -l App | grep -A3 LC_ENCRYPTION_INFO`; если `cryptid=1`, снимаем дамп на jailbroken устройстве.
4. **`class-dump App`** — получили интерфейсы классов и методы.
5. **Ghidra/Hopper** — открыли нужный метод, прочитали логику (ARM64).
6. **Frida** — перехватили метод, посмотрели аргументы и подтвердили гипотезу.

Если по ходу встречается SSL-pinning или jailbreak-детект — нейтрализуем хуком и продолжаем. Это тот же принцип «найди проверку → обойди», что и на Android.

## Шаг 7: iOS против Android — что проще

Сравним два мобильных реверса, чтобы закрепить:

| | Android | iOS |
|---|---|---|
| Код | Dalvik (dex) | Mach-O (ARM64) |
| Язык | Java/Kotlin | ObjC/Swift |
| Декомпиляция | jadx → Java | class-dump/Ghidra |
| Динамика | Frida на устройстве | Frida на jailbreak |
| Особенность | `debuggable`, exported | шифрование App Store, SSL-pinning |

Android даёт почти исходники через jadx, но прячет логику в `.so`. iOS даёт имена методов через class-dump, но требует снятия шифрования и jailbreak для динамики. Оба навыка опираются на одно: найти проверку по именам/строкам и нейтрализовать её.

## На что смотреть дальше

Разбирая iOS-приложение:

1. **`unzip` + `file`** — достать Mach-O, определить архитектуру (обычно arm64).
2. **Проверить `LC_ENCRYPTION_INFO_64`** — зашифрован ли код; если да, снять дамп.
3. **`class-dump`** — получить имена классов/методов; это карта приложения.
4. **Ghidra/Hopper** — открыть метод, читать ARM64.
5. **Frida** — динамика и обход SSL-pinning/jailbreak-детекта.

Помни про разницу сред: на iOS нет `adb`, а динамика требует jailbreak и установки `frida-server`. Зато имена методов обычно на месте, что компенсирует сложности.

## Шаг 8: типичные сценарии iOS-задач

- **Флаг/проверка в ObjC-методе** — `class-dump` даёт имена; читай метод в Ghidra/Hopper.
- **Swift-логика** — демаггли `_$s...`, ищи нужный тип и метод.
- **Логика в нативном C** — как на Android, это Mach-O + ARM64.
- **Зашифрованный бинарник** — сними дамп на jailbroken устройстве.
- **SSL-pinning** — хук на `SecTrustEvaluate`, чтобы увидеть трафик.
- **Jailbreak-детект** — хук на проверки файлов/`ptrace`.

Общая стратегия та же, что на Android: найти проверку (по именам/строкам) и нейтрализовать её хуком. Разница — в инструментах и барьерах (шифрование, jailbreak).

## Что мы теперь знаем

- iOS-приложение — Mach-O (ARM64) внутри IPA; разбор = Mach-O + ARM64 + ObjC/Swift.
- App Store бинарники зашифрованы (`LC_ENCRYPTION_INFO_64`); нужен decrypt с jailbreak.
- Имена классов/методов сохраняются: `class-dump` даёт почти исходники, Frida — динамику.
- SSL-pinning, jailbreak-детект и anti-debug обходятся хуками/патчами.
- Набор: Ghidra/Hopper + class-dump + Frida.

## Куда дальше

Мы прошли мобильные платформы. Дальше — углубление в managed-мир: обфускация **.NET** (ConfuserEx, de4dot) и **Java** (ProGuard, R8), а затем **AOT**-компиляция, где managed-код превращается в нативный. А пока запомни: iOS — это Mach-O + ARM64 + class-dump + Frida.

## Квиз

```quiz
- question: "Что представляет собой IPA-файл iOS-приложения?"
  options:
    - "Исполняемый ELF"
    - "ZIP-архив с главным Mach-O в `Payload/App.app/`, `Info.plist` и Frameworks"
    - "Текстовый конфиг"
    - "DEX-контейнер"
  answer: 1
  explanation: "IPA — это ZIP; внутри `Payload/*.app/` лежит главный Mach-O, а также Info.plist и библиотеки."
- question: "Почему бинарник из App Store нельзя сразу дизассемблировать?"
  options:
    - "Он на Java"
    - "`__TEXT` зашифрован (LC_ENCRYPTION_INFO_64); нужен decrypt с jailbroken устройства"
    - "У него нет заголовка"
    - "Он в формате DEX"
  answer: 1
  explanation: "Apple шифрует код приложений из App Store; его снимают дампом из памяти (frida-ios-dump/Clutch)."
- question: "Чем полезна `class-dump` для iOS-бинарника?"
  options:
    - "Расшифровывает код"
    - "Извлекает интерфейсы классов Objective-C (`.h`) — имена классов и методов"
    - "Запускает приложение"
    - "Собирает IPA"
  answer: 1
  explanation: "ObjC-метаданные сохраняются; class-dump восстанавливает объявления классов, что резко ускоряет реверс."
- question: "Как обойти SSL-pinning в iOS-приложении?"
  options:
    - "Никак"
    - "Frida-хуком на проверку сертификата (`SecTrustEvaluate`), чтобы MITM заработал"
    - "Удалить `Info.plist`"
    - "Пересобрать Mach-O"
  answer: 1
  explanation: "SSL-pinning проверяет сертификат; хук нейтрализует проверку, и прокси снова видит трафик."
- question: "Какой набор инструментов покрывает типовой iOS-реверс?"
  options:
    - "jadx + apktool"
    - "Ghidra/Hopper + class-dump + Frida"
    - "objdump + readelf"
    - "javap + monodis"
  answer: 1
  explanation: "Статика (Ghidra/Hopper), метаданные (class-dump) и динамика (Frida) — стандартная связка для iOS."
```

## Где пригодится

- **CTF Reversing / Mobile:** iOS-задачи решаются через Mach-O + ARM64 + class-dump.
- **Анализ iOS-малвари:** перехват методов и обход защит — повседневная работа.
- **Bug bounty:** обход SSL-pinning открывает анализ трафика клиента.
- **Инструменты:** Frida на jailbroken устройстве — универсальный ключ к динамике iOS.
