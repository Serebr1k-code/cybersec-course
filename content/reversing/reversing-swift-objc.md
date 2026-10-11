---
id: reversing-swift-objc
title: "Реверс Swift и Objective-C"
category: reversing
parent: reversing-architectures
difficulty: hard
order: 1
tags: [reversing, swift, objective-c, macho, ios, macos, demangle]
prerequisites: [reversing-architectures, reversing-file-formats]
useful_for:
  - "CTF Reversing"
  - "Анализ macOS/iOS-приложений"
  - "Bug bounty (Apple-платформы)"
estimated_minutes: 60
summary: "Реверс Apple-бинарников: Objective-C runtime, Swift-манглинг, демаглинг, Hopper/Ghidra и Frida."
---
**Swift и Objective-C** — основные языки для iOS/macOS. Реверс таких бинарей (Mach-O) имеет свои особенности: динамическая диспетчеризация (objc_msgSend), богатые метаданные (имена классов/методов), Swift-манглинг и ARC. Понимание этих механизмов критично для анализа iOS-приложений, малвари и macOS-ПО. Этот урок — практический реверс Swift/ObjC от распаковки Mach-O до восстановления логики.

## Формат и инструменты

iOS/macOS-бинари — **Mach-O**. Основные инструменты:

| Инструмент | Назначение |
|------------|------------|
| `otool`/`nm`/`jtool2` | заголовки, символы, load commands |
| Hopper / IDA / Ghidra | дизасм/декомпиляция |
| class-dump / `otool -ov` | дамп ObjC-классов/методов |
| `swift-demangle` | демаглинг Swift-символов |
| Frida / lldb | динамика |
| `ipsw`/`jtool2` | работа с ядром/кэшами |

```bash
file App.app/App
otool -L App.app/App            # linked libraries
otool -l App.app/App | grep -A2 LC_ENCRYPTION   # проверка шифрования App Store
nm -m App.app/App | head
```

## Распаковка (decrypt) App Store-бинарей

Бинари из App Store зашифрованы (`cryptid=1`). Для анализа их расшифровывают на джейлбрейк-устройстве:

```bash
# На устройстве: frida-ios-dump / Clutch
frida-ios-dump -u <udid> com.example.app
# Проверка после распаковки
otool -l decrypted | grep -A3 LC_ENCRYPTION_INFO   # cryptid=0
```

## Objective-C: динамическая диспетчеризация

ObjC-вызовы идут через `objc_msgSend(receiver, selector, ...)`. В дизасме это `_objc_msgSend` с загрузкой селектора:

```asm
lea rsi, [rip + sel]        ; селектор ("viewDidLoad")
mov rdi, rbx                ; self
call _objc_msgSend
```

- **Селекторы** (`__objc_methname`) содержат имена методов — бесценны для понимания.
- **Дамп классов**: `class-dump App -H` восстанавливает заголовки; `otool -ov` показывает методы/ivar'ы.
- **Строки селекторов** в `strings` часто прямо описывают функциональность.

## Swift: особенности и демаглинг

Swift-символы манглируются (например, `$s8MyModule9MyClassC...`):

```bash
nm App | grep ' T ' | swift-demangle | head
# или
echo '$s4main3fooSiSSF' | swift-demangle
```

Swift-специфика:

- **Динамическая диспетчеризация** — через vtable (witness tables), не только objc_msgSend; вызовы менее явные.
- **Метаданные типов** (`__swift5_types`, `__swift5_proto`) — описания типов/протоколов.
- **Строки** хранятся с флагами; Swift-строки не всегда видны `strings` (см. `reversing-rust-advanced` для аналогичных идей).
- **Богатый рантайм** — `libswiftCore`, ARC, `swift_retain`/`swift_release`.

## Динамический анализ

```bash
# Frida на джейлбрейк-устройстве
frida-ps -U
frida -U -f com.example.app -l hook.js
# lldb на macOS
lldb ./App
(lldb) image list
(lldb) b objc_msgSend
```

Хуки на ObjC-методы:

```js
// Перехват метода ObjC
if (ObjC.available) {
  var cls = ObjC.classes.MyClass;
  Interceptor.attach(cls['- checkLicense'].implementation, {
    onLeave: function (retval) { console.log('->', retval); }
  });
}
```

Для Swift — перехват по адресу (символы после демаглинга) или через `swift_demangle` + поиск.

## Разобранный пример: iOS-приложение

```text
1) Распаковать IPA (unzip), проверить шифрование (LC_ENCRYPTION).
2) Если зашифровано -> frida-ios-dump/Clutch на джейлбрейк-устройстве.
3) class-dump/otool -ov: получить классы и методы.
4) swift-demangle: осмысленные имена Swift-функций.
5) Найти логику проверки (селекторы/строки "license"/"valid").
6) Frida: перехватить метод, посмотреть аргументы/возврат.
7) Патч/обход (в исследовательском контексте) или keygen.
```

## Строки, крипто и защита

- **Строки**: ObjC — в `__cstring`/`__objc_methname`; Swift — с флагами (иногда зашифрованы).
- **Крипто**: CommonCrypto/CryptoKit; ищите `CCCrypt`, `AES`, `SecKey`.
- **Защита**: анти-отладка (ptrace), проверки джейлбрейка (`/Applications/Cydia.app`), обфускация Swift-символов, шифрование строк.
- **Обход** (research): Frida-хуки на `ptrace`, подмена результатов проверок джейлбрейка.

## Инструменты

| Инструмент | Роль |
|------------|------|
| `otool`/`nm`/`jtool2` | Mach-O, символы |
| class-dump / `otool -ov` | дамп ObjC |
| `swift-demangle` | имена Swift |
| Hopper/IDA/Ghidra | дизасм/декомпиляция |
| Frida / lldb | динамика |
| `frida-ios-dump`/Clutch | распаковка |

## Практика: Frida-скрипты для iOS

Frida — основной инструмент динамики на iOS. Примеры задач:

```js
// 1) Перечислить классы и методы
if (ObjC.available) {
  for (var name in ObjC.classes) {
    if (name.indexOf('License') !== -1) console.log(name, Object.keys(ObjC.classes[name].$ownMethods));
  }
}

// 2) Перехватить метод и увидеть аргументы/возврат
var m = ObjC.classes.LicenseManager['- isValid:'];
Interceptor.attach(m.implementation, {
  onEnter: function (args) { console.log('arg =', new ObjC.Object(args[2])); },
  onLeave: function (retval) { console.log('ret =', retval); }
});

// 3) Обход проверки джейлбрейка
var fopen = Module.findExportByName(null, 'fopen');
Interceptor.replace(fopen, new NativeCallback(function (path, mode) {
  var p = path.readUtf8String();
  if (p.indexOf('Cydia') !== -1 || p.indexOf('/bin/bash') !== -1) return ptr(0);
  return fopen(path, mode);
}, 'pointer', ['pointer', 'pointer']));
```

Для Swift-методов перехват идёт по адресу (символы после `swift-demangle`), так как селекторов нет. Используйте `Module.enumerateSymbols` и фильтр по имени, затем `Interceptor.attach` на адрес. Всегда работайте на **своём** устройстве/образце — обход защит чужих приложений противоправен.

## Частые ошибки

- **Анализ зашифрованного App Store-бинаря.** Сначала распакуйте (cryptid=0).
- **Игнорирование objc_msgSend.** Без расшифровки селекторов код непонятен.
- **Нет демаглинга Swift.** Имена `$s...` бессмысленны без `swift-demangle`.
- **Опора только на статику.** Swift-диспетчеризация неявная — нужна динамика (Frida/lldb).
- **Забыть про метаданные типов.** `__swift5_*` секции описывают типы.
- **Пропуск анти-анализа.** Проверки джейлбрейка/отладки могут ломать динамику.

## Разбор Mach-O детально

Mach-O состоит из заголовка, load commands и сегментов/секций:

```bash
otool -h App.app/App                 # header: cputype, ncmds
otool -l App.app/App                 # load commands (LC_SEGMENT_64, LC_ENCRYPTION_INFO...)
otool -s __TEXT __cstring App.app/App | head    # C-строки
otool -s __DATA __objc_classlist App.app/App    # список ObjC-классов
```

Ключевые секции: `__TEXT` (код, r-x), `__DATA` (данные), `__objc_methname` (селекторы), `__objc_classname`/`__objc_methtype`, `__swift5_types`/`__swift5_proto`/`__swift5_fieldmd` (Swift-метаданные). `LC_ENCRYPTION_INFO` содержит `cryptid` — 1 означает, что бинарь зашифрован (App Store).

## Swift-метаданные и диспетчеризация

Swift использует несколько механизмов вызова:

- **Direct call** — статические функции (видны напрямую).
- **Vtable** — для классов: таблица виртуальных методов в метаданных типа.
- **Witness table** — для протоколов: таблица реализаций методов протокола.
- **objc_msgSend** — для `@objc`-методов (совместимость с ObjC).

Метаданные (`__swift5_*`) описывают типы, поля и протоколы; из них можно восстановить имена и структуры. Демаглинг (`swift-demangle`) даёт осмысленные имена функций, что резко ускоряет анализ. Для восстановления `@objc`-части используйте `class-dump`/`otool -ov`.

## Полезные приёмы и кейсы

- **Проверка джейлбрейка**: ищите строки `Cydia`, `/bin/bash`, `fopen("/private/var/lib/apt")` — обходится Frida-хуком на `fopen`/`stat`.
- **Проверка отладки**: `ptrace(PT_DENY_ATTACH)` — обход через Frida (`Interceptor.replace`).
- **SSL pinning**: `SecTrustEvaluate`/`NSURLSession` с пином — обход через Frida (SSL-kill-switch).
- **Шифрование строк**: Swift-строки могут быть закодированы; ищите декодер в рантайме.
- **Малварь iOS**: Pegasus-класс анализируется по артефактам (профили, процессы), не по коду.
- **macOS-кейсы**: анализ keychain-доступа, TCC-обходов, нотаризации.

## Пошаговый разбор Swift-функции

```text
1) nm App | grep ' T ' | swift-demangle | grep -i check
   -> 'main.MyClass.check(license: Swift.String) -> Swift.Bool'
2) В IDA/Ghidra: перейти по адресу (из неманглированного имени).
3) Увидеть: загрузку метаданных типа, вызовы через vtable/witness table.
4) Найти сравнение строки (Swift.String -> сравнение указателей/буферов).
5) Подтвердить Frida: перехватить функцию по адресу, посмотреть аргумент/возврат.
```

Swift-строки передаются как пара (указатель на буфер, длина) в регистрах; сравнение — не `strcmp`, а вызов Swift-рантайма (`swift_stringEqual`/`_stringCompare`). Ищите эти вызовы как маркеры строковой логики.

## Отличия от реверса C/C++

- **Метаданные богаче** — есть имена типов/методов (даже в release, если не stripped).
- **Диспетчеризация сложнее** — objc_msgSend + vtable + witness table.
- **ARC** — вызовы `swift_retain`/`swift_release` раздувают код; их можно игнорировать при поиске логики.
- **Runtime-функции** — `swift_allocObject`, `swift_bridgeObjectRelease` шумят; фокус на пользовательских вызовах.
- **Строки/массивы** — собственные структуры, а не C-массивы.

## Что делать дальше / решение

1. Определите тип: ObjC / Swift / смешанный (по символам и секциям).
2. Распакуйте бинарь (если зашифрован), дампните классы/методы.
3. Демаглите Swift-символы; найдите точки входа.
4. Локализуйте логику по селекторам/строкам; разберите в декомпиляторе.
5. Подтвердите динамикой (Frida/lldb), перехватите методы.
6. Для малвари — соберите IOC (C2, домены) из строк/трафика.

## Квиз

```quiz
- question: "Как называются метаданные классов в ObjC-бинарнике?"
  options:
    - "Секции __objc_classlist/__objc_methname"
    - "GOT/PLT"
    - "BTF"
    - "SVD"
  answer: 0
  explanation: "ObjC-классы/методы хранятся в objc-секциях Mach-O."
- question: "Чем Swift-имена отличаются от C?"
  options:
    - "Они манглированы (нужен swift-demangle)"
    - "Они всегда читаемы"
    - "Они в GOT"
    - "Они в BTF"
  answer: 0
  explanation: "Swift использует манглинг; swift-demangle восстанавливает имена."
- question: "Как дампить ObjC-интерфейсы?"
  options:
    - "class-dump/dsdump"
    - "nm"
    - "ldd"
    - "objdump -h"
  answer: 0
  explanation: "class-dump извлекает классы/методы ObjC."
- question: "Что такое witness table в Swift?"
  options:
    - "Таблица для вызовов через протоколы"
    - "Формат файла"
    - "Тип шифрования"
    - "Пакер"
  answer: 0
  explanation: "Witness tables реализуют протоколы (косвенные вызовы)."
- question: "Какой инструмент особенно удобен для ObjC/Swift?"
  options:
    - "Hopper"
    - "nm"
    - "ldd"
    - "objdump -d"
  answer: 0
  explanation: "Hopper хорошо восстанавливает ObjC/Swift."
```

## Где пригодится

- **CTF:** Reversing — Apple-задачи.
- **Анализ macOS/iOS:** приложения/малварь.
- **Bug bounty:** Apple-платформы.
- **Работа:** mobile/desktop security.
