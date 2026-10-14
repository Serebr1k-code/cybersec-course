---
id: mobile-ios-ipa-repack
title: 'Перепаковка IPA: вскрытие, замена и повторная подпись'
category: mobile
parent: mobile-ios-sideloading
difficulty: expert
order: 4
tags: [ios, ipa, repack, codesign, entitlements, frida-gadget, plist]
prerequisites: [mobile-ios-sideload, mobile-ios-macho-deep]
useful_for:
  - 'Реверс iOS-приложений'
  - 'Пентест мобильных приложений (iOS)'
  - 'CTF Mobile'
estimated_minutes: 46
summary: 'Полный цикл перепаковки iOS-приложения: распаковка IPA, правка Info.plist и бинарника, внедрение Frida Gadget, повторная подпись и установка на устройство.'
lab:
  kind: shell
  title: 'Практика: анализ перепакованного бандла'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, bundle_listing.txt, otool_L.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`bundle_listing.txt` и `otool_L.txt` — содержимое бандла и зависимости.'
    - 'Найди внедрённую библиотеку в Frameworks.'
    - 'Рядом с ней — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Иногда нужно не просто поставить чужое приложение, а **изменить** его: добавить свой код,
внедрить Frida Gadget, поправить проверку или подменить ресурс. Для этого IPA вскрывают,
меняют содержимое и подписывают заново. Разберём полный цикл на одном приложении.

## Наш пример: внедряем Frida Gadget

Возьмём `MyApp.ipa` и внедрим в него `FridaGadget.dylib`, чтобы получить хукинг без jailbreak.
Это сквозной пример: от распаковки до запуска на устройстве.

## Шаг 1: распаковка IPA

IPA — это ZIP-архив с каталогом `Payload`:

```bash
$ unzip -o MyApp.ipa -d work
$ ls work/Payload/MyApp.app
MyApp  Info.plist  Frameworks/  embedded.mobileprovision
```

`Info.plist` — метаданные приложения, `MyApp` — бинарник, `Frameworks/` — встроенные
библиотеки.

## Шаг 2: правка Info.plist

Некоторые проверки (например, запрет отладки) живут в `Info.plist`. Править удобно через
`plutil`:

```bash
$ plutil -replace UIFileSharingEnabled -bool YES work/Payload/MyApp.app/Info.plist
$ plutil -p work/Payload/MyApp.app/Info.plist | grep UIFileSharing
  "UIFileSharingEnabled" => 1
```

Так же включают file-sharing, меняют bundle id или добавляют разрешённые схемы.

## Шаг 3: внедрение Frida Gadget

Копируем библиотеку в `Frameworks/` и добавляем её в зависимости бинарника. Для arm64 это
делают инструментом `insert_dylib` или патчем load-команд:

```bash
$ cp FridaGadget.dylib work/Payload/MyApp.app/Frameworks/
$ insert_dylib --strip-codesig --inplace     @executable_path/Frameworks/FridaGadget.dylib work/Payload/MyApp.app/MyApp
Added LC_LOAD_DYLIB to MyApp
```

Проверить, что зависимость появилась, можно через `otool -L` — мы уже видели этот приём в уроке
про Mach-O.

## Шаг 4: повторная подпись

Правка ломает подпись, поэтому бандл подписывают заново. Сначала — все вложенные бинарники и
библиотеки, затем основной:

```bash
$ codesign --force --sign "Apple Development: dev@example.com"     work/Payload/MyApp.app/Frameworks/FridaGadget.dylib
$ codesign --force --deep --sign "Apple Development: dev@example.com"     work/Payload/MyApp.app
```

Затем IPA собирают обратно:

```bash
$ cd work && zip -qr ../MyApp-patched.ipa Payload
```

## Шаг 5: установка и проверка хука

Ставим перепакованный IPA через ideviceinstaller или AltStore. При запуске Gadget ждёт
подключения Frida:

```bash
$ frida-ps -U | grep MyApp
1234  MyApp (Gadget)
```

Если процесс виден с пометкой Gadget — внедрение удалось.

## Что мы теперь знаем

- IPA — ZIP с `Payload/<App>.app`.
- `Info.plist` правится `plutil`; бинарник — внедрением dylib.
- Правка ломает подпись; подпись идёт изнутри наружу (`--deep`).
- Перепакованный IPA ставится как обычный sideload.

## Если не сработало

Если приложение падает сразу после запуска, проверьте, что Gadget подписан тем же сертификатом
и что путь `@executable_path/Frameworks/...` верен. Если `codesign --deep` не помогает на
сложных бандлах, подписывайте вложенные компоненты вручную по порядку. Если установка
отклоняется, сверьте bundle id с provisioning-профилем.

## Частые вопросы

**Зачем `--deep`?** Он рекурсивно подписывает вложенные бинарники; но ручной порядок надёжнее.

**Можно ли внедрить без jailbreak?** Да, через Frida Gadget и переподпись.

**Ломает ли это целостность?** Да, хеши меняются — но подпись накладывается заново.

## Квиз

Проверь себя.

```quiz
- question: Что представляет собой IPA?
  options:
    - Текстовый файл
    - ZIP-архив с каталогом Payload
    - Картинку
    - Базу данных
  answer: 1
  explanation: IPA — это архив бандла .app.
- question: Чем правят Info.plist?
  options:
    - plutil
    - nmap
    - sqlmap
    - curl
  answer: 0
  explanation: plutil читает и меняет plist-файлы.
- question: Что делает insert_dylib?
  options:
    - Удаляет приложение
    - Добавляет зависимость LC_LOAD_DYLIB в бинарник
    - Шифрует IPA
    - Меняет язык
  answer: 1
  explanation: Он встраивает ссылку на библиотеку в load-команды.
- question: Почему после правки нужна повторная подпись?
  options:
    - Изменённые байты ломают исходную подпись
    - Так быстрее
    - Так требует Apple ID
    - Чтобы сменить цвет
  answer: 0
  explanation: Подпись покрывает содержимое бандла.
- question: Как проверить, что Gadget внедрён?
  options:
    - По цвету иконки
    - По frida-ps: процесс виден с пометкой Gadget
    - По размеру экрана
    - По языку
  answer: 1
  explanation: Gadget регистрируется и виден в списке процессов Frida.
```

## Куда дальше

Перепаковка — последний кирпич sideloading: теперь вы можете поставить на устройство любое
изменённое приложение. Дальше логично уйти в данные и приватность iOS — Keychain, App Groups
и privacy-манифесты.

## Где пригодится

- Внедрение Frida Gadget и инструментирование без jailbreak.
- Обход клиентских проверок в банковских приложениях.
- Подготовка PoC-сборок для отчёта.
