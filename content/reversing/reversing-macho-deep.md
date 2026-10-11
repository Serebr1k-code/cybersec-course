---
id: reversing-macho-deep
title: "Mach-O изнутри: load-команды и dyld"
category: reversing
parent: reversing-mod-file-formats
difficulty: medium
order: 3
tags: [reversing, macho, macos, ios, dyld, otool]
prerequisites: [reversing-intro]
useful_for:
  - "CTF Reversing: macOS/iOS бинарники"
  - "Malware analysis: анализ Mach-O образцов"
  - "Mobile: разбор iOS-приложений"
estimated_minutes: 55
summary: "Полный разбор Mach-O: заголовок, load-команды, сегменты __TEXT/__DATA, dyld, разделяемый кэш, fat-бинарники и практический анализ через otool и nm."
---

Mach-O (Mach Object) — формат исполняемых файлов в macOS, iOS, watchOS и tvOS. В отличие от ELF и
PE, Mach-O строится вокруг **load-команд**: каждая команда — это запись переменной длины в
заголовке, описывающая, что делать загрузчику. Сегменты и секции тоже задаются load-командами.
Для реверс-инженера Mach-O важен не только в задачах под Apple, но и в mobile-анализе: приложения
iOS почти всегда поставляются как Mach-O, и без понимания формата их не разобрать.

## Заголовок и магия

Заголовок `mach_header` (или `mach_header_64`) начинается с магии: `0xFEEDFACE` (32-bit),
`0xFEEDFACF` (64-bit), `0xCAFEBABE` (fat binary, big-endian) или `0xBEBAFECA` (fat, little-endian).
Поле `cputype` задаёт архитектуру (x86_64, arm64, arm64e), `filetype` — тип (`MH_EXECUTE`,
`MH_DYLIB`, `MH_BUNDLE`, `MH_OBJECT`, `MH_DYLINKER`), `ncmds` — число load-команд, а `sizeofcmds` —
их суммарный размер.

Магия `0xCAFEBABE` означает **fat/universal binary**: один файл содержит несколько слайсов для
разных архитектур (например, x86_64 и arm64). Это аналог «многоплатформенного» архива. Инструмент
`lipo -info` показывает состав, `lipo -thin arm64 file -output file.arm64` извлекает нужный слайс.
При анализе важно сначала отделить интересующую архитектуру, иначе дизассемблер запутается.

## Load-команды: ядро формата

Каждая load-команда начинается с `cmd` и `cmdsize`. Ключевые типы:

- **LC_SEGMENT / LC_SEGMENT_64** — описывает сегмент: имя, виртуальный адрес, размер в памяти,
  права (`VM_PROT_READ/WRITE/EXECUTE`), число секций внутри.
- **LC_MAIN** — задаёт `entryoff` (смещение точки входа) и размер стека. В старых бинарниках
  использовалась пара LC_UNIXTHREAD, содержащая начальное состояние регистров.
- **LC_LOAD_DYLIB** — зависимость от динамической библиотеки (аналог `DT_NEEDED`).
- **LC_SYMTAB** — смещения таблиц символов и строк.
- **LC_DYSYMTAB** — таблица динамических символов.
- **LC_DYLD_INFO_ONLY** — информация для `dyld` о привязках (bind/rebase).
- **LC_CODE_SIGNATURE** — смещение и размер подписи кода (важно для iOS, где подпись обязательна).
- **LC_RPATH** — пути поиска библиотек (`@rpath`), потенциальный вектор подмены dylib.

В современном macOS появились **chained fixups** (LC_DYLD_CHAINED_FIXUPS), которые заменяют
классические rebase/bind: цепочки указателей кодируют привязки компактно. Это усложняет ручной
анализ и требует свежих инструментов.

## Сегменты и секции: __TEXT и __DATA

В Mach-O сегменты именуются с двойным подчёркиванием: `__TEXT`, `__DATA`, `__DATA_CONST`, `__LINKEDIT`.
Секции внутри — `__text`, `__cstring`, `__const`, `__data`, `__bss`, `__objc_*` (для Objective-C
метаданных). Соответствие с ELF: `__TEXT` ≈ исполняемый сегмент, `__DATA` ≈ RW-данные,
`__LINKEDIT` ≈ таблицы символов и привязок (аналог динамических таблиц).

Сегмент `__TEXT` всегда read-only и содержит код и константы. `__DATA_CONST` содержит указатели,
которые делают read-only после привязки (аналог RELRO). Objective-C метаданные (`__objc_classlist`,
`__objc_methname`, `__objc_selrefs`) дают почти полную информацию о классах и методах даже без
символов — это огромное подспорье при реверсе iOS-приложений.

## dyld и связывание

Динамический загрузчик macOS называется `dyld` (аналог `ld-linux`). Он читает load-команды,
загружает зависимости (`LC_LOAD_DYLIB`), применяет rebase (поправка указателей под ASLR) и bind
(подстановка адресов внешних символов). Пути `@rpath`, `@loader_path`, `@executable_path`
позволяют библиотекам ссылаться друг на друга относительно; `DYLD_INSERT_LIBRARIES` (при отключённом
SIP) работает как `LD_PRELOAD` — перехват функций.

Начиная с macOS 11, многие системные библиотеки вынесены в **dyld shared cache** — большой
предзагруженный образ, из которого бинарники берут системные фреймворки. При реверсе системных
функций иногда приходится извлекать библиотеки из этого кэша (`dyld_shared_cache_util`,
`ipsw`-утилиты).

## Практический разбор: otool, nm, rabin2

Идентификация:

```
$ file ./MyApp
./MyApp: Mach-O 64-bit executable arm64

$ otool -hv ./MyApp
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64   ARM64        ALL  0x00     EXECUTE    38       4072   NOUNDEFS DYLDLINK
```

Список load-команд:

```
$ otool -l ./MyApp | grep -E "cmd |segname|vmaddr|vmsize|initprot"
      cmd LC_SEGMENT_64
  segname __TEXT
   vmaddr 0x0000000100000000
   vmsize 0x0000000000004000
  initprot r-x
      cmd LC_SEGMENT_64
  segname __DATA
   vmaddr 0x0000000100004000
   vmsize 0x0000000000004000
  initprot rw-
      cmd LC_MAIN
      entryoff 16384
```

Сегмент `__TEXT` имеет права `r-x`, `__DATA` — `rw-`. Точка входа задаётся `entryoff` относительно
начала `__TEXT`. Зависимости:

```
$ otool -L ./MyApp
./MyApp:
	/System/Library/Frameworks/Foundation.framework/Foundation (compatibility version 300.0.0, current version 1770.0.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1311.100.3)
```

Символы (если не stripped):

```
$ nm -m ./MyApp | grep -i verify
0000000100003f10 (__TEXT,__text) external _verifyLicense
0000000100003f90 (__TEXT,__text) external _main
```

Дамп секции строк:

```
$ otool -s __TEXT __cstring ./MyApp | head
Contents of (__TEXT,__cstring) section
0000000100004000	436f7272 65637421 0a00      Correct!\n.
```

## Типичные CTF-сценарии и краевые случаи

- **Fat binary**: сначала `lipo -thin`, иначе IDA покажет не тот слайс.
- **Stripped + Objective-C**: даже без символов `__objc_methname` содержит имена селекторов —
  ищите осмысленные строки вида `checkPassword:`.
- **Swift**: имена функций mangled (`$s...`); помогает `swift demangle` или плагин IDA.
- **Подпись кода**: iOS-бинарник подписан; при патче подпись ломается, и на устройстве он не
  запустится без переподписи (`codesign -f -s -`).
- **Разделяемый кэш**: системные функции отсутствуют в файле — они в кэше.
- **Swift ABI**: структуры и протоколы Swift хранятся в отдельных секциях (`__swift5_*`), а имена
  функций mangled; без деманглинга читать код почти невозможно.
- **`__LINKEDIT`**: содержит таблицы символов, строк, привязок и подпись; при ручном дампе
  программы из памяти этот сегмент восстанавливают отдельно, иначе символы теряются.
- **Энтропия секций**: упакованные или зашифрованные сегменты имеют высокую энтропию — полезно
  смотреть распределение байт, чтобы отличить код от сжатых данных.

Ещё одна тонкость: в Mach-O порядок load-команд может быть произвольным, и некоторые инструменты
зависят от того, что `LC_SEGMENT_64 __TEXT` идёт первым. Встречаются образцы, где порядок нарушен
намеренно — это само по себе признак обфускации. Кроме того, поле `flags` заголовка может содержать
`MH_PIE` (позиционно-независимый код) или `MH_NO_HEAP_EXECUTION`; отсутствие `MH_PIE` упрощает
предсказание адресов при эксплуатации.

## Инструменты и флаги

| Задача | Инструмент |
|---|---|
| Идентификация | `file`, `otool -hv`, `rabin2 -I` |
| Load-команды | `otool -l`, `jtool2 -l` |
| Зависимости | `otool -L` |
| Символы | `nm`, `otool -Iv`, `rabin2 -s` |
| Сегменты/секции | `otool -l`, `otool -s <seg> <sect>` |
| Fat-бинарники | `lipo -info`, `lipo -thin` |
| Деманглинг | `swift demangle`, `c++filt` |
| Дизассемблер | Hopper, IDA, Ghidra, `otool -tvV` |

## Разбор метаданных Objective-C

В iOS/macOS приложениях, написанных на Objective-C, большая часть логики привязана к классам и
методам, а метаданные хранятся в открытом виде в секциях `__objc_classlist`, `__objc_classrefs`,
`__objc_methname`, `__objc_selrefs`, `__objc_const`. Даже когда бинарник stripped, эти секции
содержат имена классов (`ViewController`), селекторов (`viewDidLoad`, `verifyLicense:`) и
свойств. Инструмент `class-dump` (или `class-dump-z`) читает их и печатает заголовочные файлы,
восстанавливая интерфейсы классов.

Практическая ценность огромна: увидев селектор `checkPassword:`, вы сразу знаете, где искать логику
проверки, и можете поставить точку останова на соответствующую функцию через Frida:
`Interceptor.attach(ObjC.classes.Validator['- checkPassword:'].implementation, {...})`. Сопоставление
имени селектора и адреса реализации требует анализа структур `__objc_const`, где хранится список
методов с указателями на `__objc_methname` и на код.

## Chained fixups и разделяемый кэш

Начиная с macOS 12/iOS 15, классические rebase/bind заменены на **chained fixups**: указатели
кодируются специальным форматом (target + next-указатель), и `dyld` «прошивает» их цепочкой. Для
аналитика это означает, что старые скрипты, читающие `LC_DYLD_INFO`, ничего не найдут — нужен
разбор `LC_DYLD_CHAINED_FIXUPS`. Инструменты (rabin2, LIEF, dyld_info из состава Xcode) обновлены
для их поддержки.

Второй важный момент — **dyld shared cache**. Системные фреймворки (`Foundation`, `UIKit`,
`libSystem`) не лежат отдельными файлами: они объединены в один большой кэш, отображаемый в память
при старте. Если бинарник вызывает `_objc_msgSend` или `_printf`, реализация находится в кэше, а не
в самом файле. Для реверса системных функций нужно извлекать нужную библиотеку из кэша утилитами
`dyld_shared_cache_util` или `ipsw`. Это существенное отличие от ELF, где библиотеки лежат
отдельными `.so`-файлами.

## Сравнение Mach-O с ELF и PE

| Понятие | ELF | PE | Mach-O |
|---|---|---|---|
| Точка входа | `e_entry` | `AddressOfEntryPoint` | `LC_MAIN`/`LC_UNIXTHREAD` |
| Загрузчик | `ld-linux` | `ntdll`+loader | `dyld` |
| Внешние вызовы | GOT/PLT | IAT | bind + `__la_symbol_ptr` |
| Зависимости | `DT_NEEDED` | Import Directory | `LC_LOAD_DYLIB` |
| Инициализаторы | `.init_array` | TLS callbacks | `__mod_init_func` |
| Подпись | — | Authenticode | `LC_CODE_SIGNATURE` |
| Мультиарх | — | — | fat binary (`lipo`) |

## Подводные камни

Первое: виртуальные адреса в Mach-O для исполняемых файлов начинаются с `0x100000000`, а не с нуля
— не удивляйтесь «странным» адресам. Второе: `entryoff` — это смещение, а не абсолютный адрес.
Третье: chained fixups ломают старые скрипты анализа. Четвёртое: для iOS-приложений из App Store
бинарник зашифрован (FairPlay) — его нужно сначала расшифровать на устройстве. Пятое: секции
`__objc_*` дают имена, но не тела методов — сопоставление имени и кода требует анализа
`__objc_const`.

## Что дальше / решение

Практика: возьмите любой бинарник из `/bin` на macOS или Linux-сборку Mach-O, прогоните `otool -hv`,
`otool -l`, `otool -L`, `nm`. Найдите точку входа и сегменты. Для iOS — установите `frida-ios-dump`
и попробуйте расшифровать приложение. Сравните с ELF/PE по структуре load-команд. Далее —
`reversing-ios` и `reversing-swift-objc` для углубления в Objective-C/Swift.

## Квиз

```quiz
- question: "Что означает магия 0xCAFEBABE в Mach-O?"
  options:
    - "Fat (universal) binary с несколькими архитектурами"
    - "32-битный бинарник"
    - "Зашифрованный файл"
    - "Подписанный код"
  answer: 0
- question: "Какая load-команда задаёт точку входа в современных Mach-O?"
  options:
    - "LC_MAIN"
    - "LC_SEGMENT_64"
    - "LC_SYMTAB"
    - "LC_LOAD_DYLIB"
  answer: 0
- question: "Какие секции дают имена классов и методов в iOS-приложении?"
  options:
    - "__objc_* (метаданные Objective-C)"
    - "__text"
    - "__bss"
    - "__LINKEDIT"
  answer: 0
- question: "Что делает команда lipo -thin arm64?"
  options:
    - "Извлекает из fat-бинарника только слайс arm64"
    - "Удаляет подпись"
    - "Распаковывает файл"
    - "Добавляет отладочные символы"
  answer: 0
```

## Где пригодится

- **CTF Reversing:** macOS/iOS crackme, fat-бинарники, Swift/ObjC задачи.
- **Mobile:** разбор iOS-приложений, работа с dyld shared cache, переподпись.
- **Malware analysis:** анализ macOS-малвари, проверка подписи и зависимостей.
