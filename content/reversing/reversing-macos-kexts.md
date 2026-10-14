---
id: reversing-macos-kexts
title: "Реверс kext/dext macOS"
category: reversing
parent: reversing-mod-kernel2
difficulty: hard
order: 3
tags: [reversing, macos, kext, dext, kernel, driverkit]
prerequisites: [reversing-macos-codesign-entitlements]
useful_for:
  - "Apple platform reversing"
  - "Kernel security"
  - "Malware analysis"
estimated_minutes: 65
summary: "Как устроены драйверы ядра macOS (kext) и пользовательские DriverKit-расширения (dext), и как их разбирать."
lab:
  kind: shell
  title: "Практика: разбор бандла драйвера macOS"
  toolset: [core, hex, strings]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "kext — это бандл: каталог с Info.plist и бинарником в Contents/MacOS."
    - "В Info.plist ключ IOKitPersonalities описывает, какие устройства драйвер берёт."
    - "Запусти `python3 kext_info.py Sample.kext` — скрипт разберёт plist и метаданные."
    - "`python3 kext_info.py Sample.kext | grep nto > found.txt`, затем `check`."
---

## Вопрос, с которого всё начинается

В системе macOS обнаружен незнакомый драйвер. Он лежит в `/Library/Extensions` и грузится в ядро. Как понять, что он делает, и не является ли он руткитом?

## Наш пример

`Sample.kext` — бандл драйвера. Это не один файл, а **каталог** с `Info.plist` и бинарником. Разберём его по частям.

## Шаг 1: kext — это бандл, а не бинарник

В отличие от Windows `.sys` или Linux `.ko`, kext — это директория:

```
Sample.kext/
  Contents/
    Info.plist        ← описание драйвера
    MacOS/Sample      ← сам бинарник (Mach-O)
    _CodeSignature/   ← подпись
```

`Info.plist` — XML/бинарный plist, описывающий драйвер: идентификатор, версию, зависимости и **какие устройства он обслуживает**.

## Шаг 2: IOKit и personalities

macOS-драйверы строятся на фреймворке **IOKit**. Ключ `IOKitPersonalities` в `Info.plist` говорит ядру: «если появится устройство с таким `IOProviderClass`/`IOClass`, загрузи меня». Это механизм привязки драйвера к железу.

```xml
<key>IOKitPersonalities</key>
<dict>
  <key>SampleUSB</key>
  <dict>
    <key>IOProviderClass</key><string>IOUSBDevice</string>
    <key>IOClass</key><string>com_sample_driver</string>
    <key>IOUserClientClass</key><string>com_sample_userclient</string>
  </dict>
</dict>
```

`IOUserClientClass` важен: это интерфейс, через который пользовательский процесс общается с драйвером. Именно там ищут уязвимости.

## Шаг 3: разбор бандла скриптом

Скрипт `kext_info.py` читает plist и печатает метаданные:

```bash
$ python3 kext_info.py Sample.kext
Identifier: com.sample.driver
Version:    2.1.0
Mach-O:     x86_64 + arm64e (fat)
Signed:     yes (Apple notarized)
IOKitPersonalities:
  SampleUSB -> IOUSBDevice / com_sample_driver
  userclient: com_sample_userclient
note: bundle id nto{k3xt_10k1t_p3rs0n4l1t13s}
```

## Шаг 4: современный путь — dext и DriverKit

Apple постепенно вытесняет kext. Новый механизм — **DriverKit** и расширения **dext**: драйверы работают **в пользовательском режиме**, а не в ядре, общаясь с устройством через ограниченный API. Это резко снижает риск: падение драйвера не валит систему.

С точки зрения реверса dext — это Mach-O в бандле `.dext`, но без полного доступа к ядру. Их анализируют теми же инструментами, что и обычные Mach-O: `otool`, `nm`, `Hopper`/`Ghidra`.

## Шаг 5: подпись и entitlements

kext обязан быть подписан. При реверсе смотри:

- **подпись** (`codesign -dv`) — кто выпустил;
- **entitlements** — какие права запрошены (`com.apple.private.kernel.*` — почти всегда красный флаг);
- **notarization** — прошёл ли Apple-проверку.

Неподписанный kext на современной macOS не загрузится без отключения SIP. Поэтому зловредные kext — редкость; чаще злоупотребляют уязвимостями в легитимных драйверах.

## Шаг 6: что искать в бинарнике драйвера

Открыв Mach-O драйвера, обрати внимание на:

- **символы IOKit**: `IOService::start`, `IOUserClient::externalMethod` — точка входа пользовательских запросов;
- **копирование данных из user space**: `copyin`/`copyout` — классическое место для переполнений;
- **обработчики `externalMethod`** — сюда приходят команды от приложения, и здесь чаще всего живут баги.

В `externalMethod` разбирается структура запроса (selector + аргументы) — по ней восстанавливают интерфейс драйвера.

## Что мы теперь знаем

- kext — это бандл с `Info.plist` и Mach-O бинарником.
- IOKitPersonalities привязывает драйвер к устройствам; `IOUserClientClass` — интерфейс к приложению.
- dext/DriverKit — драйверы в пользовательском режиме, безопаснее kext.
- kext обязан быть подписан и нотаризован, иначе не загрузится при SIP.
- Главные точки анализа — `start` и `externalMethod`.

## Шаг 7: Mach-O драйвера и его особенности

Бинарник внутри kext — обычный Mach-O, но с флагами ядра. Открой его `otool`:

```bash
$ otool -hv Sample.kext/Contents/MacOS/Sample
Mach header
      magic  cputype cpusubtype  filetype ncmds sizeofcmds      flags
MH_MAGIC_64  X86_64        ALL  KEXTBUNDLE    16       2400   KEXT
```

Обрати внимание на `filetype = KEXTBUNDLE` и флаг `KEXT` — это отличает драйвер от обычного приложения. Загружаемые символы ядра (`_IOService`, `_kprintf`) видны через `nm -u`.

## Шаг 8: точки входа драйвера

У kext есть жизненный цикл, привязанный к устройству:

- `IOService::init` — создать объект;
- `IOService::start` — драйвер принял устройство;
- `IOUserClient::externalMethod` — обработать запрос от приложения;
- `IOService::stop` — освободить устройство.

Основной интерес — `externalMethod`: туда приходят команды из user space. Структура запроса — `selector` плюс указатели на аргументы. Разобрав её, ты восстановишь **интерфейс драйвера**: какие операции он поддерживает.

## Шаг 9: поиск багов в `externalMethod`

Классическая ошибка драйвера — доверять данным из user space. Опасные паттерны:

- `copyin` без проверки размера;
- арифметика с `selector` без валидации индекса;
- разыменование указателя, пришедшего от пользователя, без проверки.

```c
// уязвимо
IOExternalMethodArguments* args;
kernel_buffer = args->scalarInput[0];   // не проверено
memcpy(dst, kernel_buffer, args->scalarInput[1]);  // размер от юзера
```

Такое приводит к переполнению ядра — самой ценной уязвимости на macOS.

## Шаг 10: подпись и загрузка kext

На современной macOS kext обязан быть подписан и нотаризован, иначе не загрузится при включённом SIP. Проверить:

```bash
$ codesign -dv --entitlements - Sample.kext
Identifier=com.sample.driver
TeamIdentifier=ABCDE12345
[Key] com.apple.private.kernel.override
```

Права `com.apple.private.*` — признак привилегированного компонента. Их аудит — часть анализа: чрезмерные права у стороннего kext подозрительны.

## Шаг 11: dext как современная альтернатива

DriverKit-драйверы (dext) исполняются в user space и общаются с железом через ограниченный API. Анализ похож, но модель безопасности иная: dext не имеет прямого доступа к ядру, а использует `IOUserClient`-подобный интерфейс. Формат — Mach-O в бандле `.dext`, разбирается теми же `otool`/`nm`.

## Шаг 12: таблица инструментов и решение

| Инструмент | Задача |
|---|---|
| `otool -hv/-L` | заголовок, зависимости |
| `nm -u` | импорт символов ядра |
| `codesign -dv` | подпись и entitlements |
| Hopper/Ghidra | декомпиляция Mach-O |
| `kext_info.py` | разбор plist |

Порядок: `Info.plist` → какие устройства; `otool`/`nm` → что вызывает; `externalMethod` → интерфейс и баги; подпись → кто выпустил. Вместе это даёт полный портрет драйвера и его поверхность атаки.

## Шаг 13: как загружается kext

Порядок загрузки: система читает `Info.plist`, сверяет `IOKitPersonalities` с найденными устройствами, проверяет подпись, и, если всё совпало, грузит бинарник и вызывает `IOService::start` для подходящего узла. Значит, `Info.plist` — это не просто метаданные, а **логика активации**: драйвер не запустится, пока не появится нужное устройство.

В реверсе это важно: если драйвер не «срабатывает», проверь, к какому `IOProviderClass` он привязан и есть ли такое устройство в системе.

## Шаг 14: IOKit как объектная модель

IOKit — это C++-фреймворк. Драйвер — класс, наследник `IOService`. Его методы (`start`, `stop`, `probe`, `externalMethod`) вызываются ядром. Значит, реверс драйвера — это чтение vtable его классов, как в обычном C++.

Полезно: `ioreg -l` показывает дерево IOKit-объектов в работающей системе, а `kextstat` — список загруженных kext. Это динамическая сторона; статическая — разбор Mach-O и RTTI.

## Шаг 15: поверхность атаки драйвера

Где искать уязвимости:

- **`externalMethod`** — приём команд от приложения; разбор аргументов;
- **`IOUserClient`** — интерфейс; проверка прав вызывающего;
- **MMIO/PIO** — прямой доступ к регистрам устройства;
- **DMA** — доступ к памяти.

Классические баги: отсутствие проверки `selector`, переполнение при копировании из user space, гонки при доступе к общим структурам. Каждый найденный баг в kext — потенциальный kernel-эксплойт.

## Шаг 16: инструменты и их роль

| Инструмент | Что делает |
|---|---|
| `otool -hv` | тип файла, архитектуры |
| `otool -L` | зависимости от фреймворков |
| `nm -u` | импортируемые символы ядра |
| `codesign -dv` | подпись, entitlements |
| `ioreg` | дерево IOKit (динамика) |
| `kextstat` | загруженные kext |
| Hopper/Ghidra | декомпиляция |

## Шаг 17: итоговый порядок и решение

Начни с `Info.plist`: узнаешь идентификатор, версию и к каким устройствам привязан драйвер. Затем `otool -hv` — формат и архитектуры. `nm -u` — какие символы ядра использует. Подпись и entitlements — кто выпустил и какие права. Затем декомпилируй `start` и `externalMethod` — это логика и поверхность атаки. Для dext путь тот же, но модель безопасности иная: драйвер в user space. Главное: **kext — бандл с plist, а его интерфейс к приложению — главная цель**.

## Шаг 18: разбор `IOUserClient` по слотам

`IOUserClient` — это мост между приложением и драйвером. Приложение открывает сервис и вызывает `IOConnectCallMethod` с номером селектора. В драйвере это приходит в `externalMethod(selector, args, ...)`. Значит, обработчик — это `switch` по `selector`.

В дизассемблере найди функцию, которую вызывает vtable-слот `externalMethod`, и внутри — сравнения `selector` с константами. Каждая константа — отдельная операция драйвера. Сопоставив их, ты восстановишь полный API драйвера: что он умеет и какие данные принимает.

Особое внимание — операциям, которые копируют данные из user space: именно там проверяют границы. Если проверки нет, это кандидат в уязвимость.

## Шаг 19: разбор дерева IOKit динамически

Статический анализ даёт структуру, но понять, как драйвер живёт в системе, помогает `ioreg`. Он печатает дерево IOKit-объектов, их свойства и классы. Найди в дереве узел своего драйвера — увидишь, к какому устройству он привязан и какие у него свойства. Сопоставив это с `IOKitPersonalities`, ты проверишь, что драйвер активировался так, как задумано.

```bash
$ ioreg -l -w 0 | grep -A2 SampleUSB
+-o SampleUSB  <class com_sample_driver>
  "IOProviderClass" = "IOUSBDevice"
```

Если драйвер не появился в дереве, значит, не нашлось подходящего устройства или не прошла проверка подписи.

## Квиз

Проверь себя.

```quiz
- question: "Чем kext отличается от обычного Mach-O бинарника?"
  options:
    - "Это бандл (каталог) с Info.plist и подписью"
    - "Это текстовый файл"
    - "Это DLL"
    - "Это архив"
  answer: 0
  explanation: "kext — директория с Contents/Info.plist и Contents/MacOS/<bin>."
- question: "За что отвечает IOKitPersonalities?"
  options:
    - "Привязка драйвера к устройствам по классам"
    - "Хранение паролей"
    - "Настройка сети"
    - "Обновление системы"
  answer: 0
  explanation: "Он говорит ядру, для каких устройств грузить драйвер."
- question: "Чем dext/DriverKit безопаснее kext?"
  options:
    - "Драйвер работает в пользовательском режиме"
    - "Он быстрее"
    - "Он не требует подписи"
    - "Он работает без ядра вообще"
  answer: 0
  explanation: "Падение dext не валит систему, доступ к ядру ограничен."
- question: "Где чаще всего живут уязвимости драйвера?"
  options:
    - "В обработчике externalMethod и копировании из user space"
    - "В Info.plist"
    - "В подписи"
    - "В имени бандла"
  answer: 0
  explanation: "externalMethod принимает запросы приложения и разбирает данные."
```

## Куда дальше

kext и dext — это ядро ОС. Но есть слой ещё ниже и опаснее: прошивка, включая **SMM/UEFI**-импланты, которые живут вне ОС и переживают переустановку. О них в следующем уроке. Пока главное: **kext — это бандл с plist, а его интерфейс к приложению — главная цель анализа**.

## Где пригодится

- **Apple platform reversing:** аудит драйверов и dext.
- **Kernel security:** поиск руткитов уровня kext.
- **Malware analysis:** разбор UEFI/драйверных имплантов.
