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

## Вопрос, с которого всё начинается

Ты получил IPA, но при запуске `strings` по бинарнику — почти ничего. `class-dump` выдаёт пустые интерфейсы. Значит, приложение из App Store **зашифровано**. Как получить «рабочий» бинарник для анализа и, если нужно, собрать из него модифицированную сборку обратно?

## Наш пример: DemoApp.ipa

Наш объект — `DemoApp.ipa`. Начнём с распаковки и проверки состояния бинарника. IPA — это ZIP:

```
$ unzip -q DemoApp.ipa -d ipa_extracted
$ ls ipa_extracted/Payload/DemoApp.app/
DemoApp  DemoApp.dylib  Info.plist  _CodeSignature  embedded.mobileprovision
```

Кроме кода, в бандле есть `_CodeSignature` (подпись) и `embedded.mobileprovision` (профиль распространения). Последний — важный артефакт: в нём записано, на каких устройствах приложение имеет право запускаться.

## Шаг 1: определяем шифрование

Смотрим load-команду шифрования в главном бинарнике:

```
$ python3 macho_lc.py ipa_extracted/Payload/DemoApp.app/DemoApp | grep -i encryption
  LC_ENCRYPTION_INFO_64
```

Наш `DemoApp` — локальная сборка, поэтому `cryptid=0` и код читается сразу. Если бы приложение было из App Store, `cryptid` был бы `1`, а сегмент `__TEXT` — зашифрован. Проверить точнее можно так:

```
$ python3 macho_lc.py ipa_extracted/Payload/DemoApp.app/DemoApp
Mach-O 64-bit  cputype=16777228  filetype=2  ncmds=16
```

`filetype=2` — исполняемый файл (`MH_EXECUTE`), `filetype=6` — динамическая библиотека (`MH_DYLIB`). Наш `DemoApp.dylib` — как раз `6`.

## Шаг 2: дешифровка через frida-ios-dump

Зашифрованный бинарник нужно расшифровать прямо на устройстве. Для этого запускают приложение, и Frida выгружает из памяти уже расшифрованные сегменты:

```
$ git clone https://github.com/AloneMonkey/frida-ios-dump
$ python3 frida-ios-dump/dump.py com.demo.secapp
```

Утилита запускает приложение, находит зашифрованный сегмент, снимает его из памяти (там он уже расшифрован процессором) и собирает новый IPA. Аналоги — `bagbak`, `Clutch`. После дешифровки `cryptid=0`, и можно работать с кодом.

## Шаг 3: что извлекаем из IPA

После распаковки (и, если нужно, дешифровки) доступны все слои бандла:

```
$ file ipa_extracted/Payload/DemoApp.app/DemoApp
DemoApp: Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
$ strings -a ipa_extracted/Payload/DemoApp.app/DemoApp | grep -iE 'api|secret'
s3cr3t
https://api.demo.example/v2
```

Мы видим секрет и URL. Дальше — `class-dump` для карты классов, `plutil`/plistlib для `Info.plist`, `codesign -d --entitlements` для прав. Это стандартный конвейер статики (см. `mobile-ios-static`).

## Шаг 4: профиль распространения

`embedded.mobileprovision` — это CMS-подпись, внутри которой лежит plist с entitlements и списком устройств. Посмотреть его содержимое:

```
$ security cms -D -i embedded.mobileprovision > provision.plist   # на macOS
```

На Linux можно разобрать по маркерам `<?xml ... </plist>` внутри файла. Внутри — `Entitlements`, `ProvisionedDevices` (UDID), `ExpirationDate`. Если приложение — корпоративная (enterprise) сборка, её можно ставить без App Store, но только на устройства из списка.

## Шаг 5: переподпись IPA

Иногда нужно изменить IPA и поставить его снова: добавить инструмент, пропатчить проверку, встроить Frida. Любое изменение ломает подпись, поэтому IPA **переподписывают** своим сертификатом:

```
$ codesign -f -s "Apple Development: You (TEAMID)" --entitlements ent.plist \
    ipa_extracted/Payload/DemoApp.app
$ zip -qr DemoApp-resigned.ipa Payload
```

`codesign -f` принудительно переподписывает, `--entitlements` задаёт права. Установить переподписанную сборку можно через `ios-deploy`, Xcode или AltStore. Важно: переподпись меняет идентичность приложения, поэтому сервер может отличить сборку (по аттестации).

## Шаг 6: что можно и что нельзя менять

Переподпись ограничена:

- **Нельзя** поставить приложение на устройство, если UDID не в профиле (для development/ad-hoc).
- **Нельзя** выдать entitlements, которых нет в твоём сертификате (например, `keychain-access-groups` другого разработчика).
- **Можно** менять код, ресурсы, `Info.plist` — в пределах подписи.

Отсюда практический вывод: переподписанная сборка запускается как «другой разработчик», и её Keychain/App Groups отличаются от оригинала.

## Шаг 7: автоматизация

Ручной цикл «распаковать → поправить → переподписать → установить» долгий. Его автоматизирует `objection patchipa`:

```
$ objection patchipa --source DemoApp.ipa --codesign-signature "Apple Development: You"
```

Он встраивает `frida-gadget`, переподписывает и выдаёт готовый IPA. Для анализа малвари это основной способ инструментировать образец без jailbreak.

## Шаг 8: сравнение сборок и полный прогон

Полезный приём — сравнить официальную сборку с переподписанной. Различия покажут, что именно проверяет приложение. Сравним отпечатки подписей:

```
$ codesign -dv ipa_extracted/Payload/DemoApp.app 2>&1 | grep -i identifier
Identifier=com.demo.secapp
$ codesign -dv DemoApp-resigned/Payload/DemoApp.app 2>&1 | grep -i identifier
Identifier=com.demo.secapp
```

Идентификаторы совпадают, но подписант другой — значит, `TeamID` в entitlement изменился, и Keychain-группа оригинала недоступна. Приложение, которое сверяет `TeamID` или группу Keychain, заметит подмену.

Соберём весь цикл в одну последовательность. Сначала распаковываем и проверяем шифрование, затем дешифруем, если нужно, собираем карту через `class-dump`, ищем секреты, проверяем entitlements. Если требуется модификация — правим, переподписываем и ставим на устройство. На каждом шаге фиксируем вывод, чтобы в отчёте были воспроизводимые команды. Такой конвейер экономит время: ты не возвращаешься к началу, если что-то не сработало. Сохраняй промежуточные артефакты — распакованный бандл, дешифрованный бинарник, дампы классов — чтобы повторный прогон занимал минуты, а не часы. Если после переподписи приложение падает сразу при запуске, чаще всего виноваты несовпадающие entitlements: профиль не выдаёт нужную группу Keychain или App Group. В таком случае возьми entitlements из оригинального профиля и передай их в `codesign --entitlements` явно.

## Шаг 9: entitlements подробнее

Entitlements — это не просто «права», а контракт между приложением и системой. Их стоит выписать в отчёт отдельно:

```
$ codesign -d --entitlements - ipa_extracted/Payload/DemoApp.app 2>/dev/null
[Keychain Access Groups] com.demo.secapp
[App Groups] group.com.demo.shared
[get-task-allow] true
```

`get-task-allow` — признак debug-сборки: он разрешает отладчик и потому опасен в релизе. `App Groups` показывают, какие данные приложение делит с другими приложениями. Каждый пункт — потенциальный вектор: чем больше групп и разрешений, тем шире поверхность. Проверяй entitlements у релизной сборки и сравнивай с dev-версией: лишние права в релизе — находка.

## Шаг 10: структура IPA через unzip

IPA — это ZIP с фиксированной раскладкой. Прежде чем что-то делать, посмотрим состав:

```
$ unzip -l DemoApp.ipa
Archive:  DemoApp.ipa
  Length      Date    Time    Name
---------  ---------- -----   ----
      452  2026-10-12 18:10   Payload/DemoApp.app/Info.plist
     4096  2026-10-12 18:10   Payload/DemoApp.app/DemoApp
       18  2026-10-12 18:10   Payload/DemoApp.app/DemoApp.dylib
---------                     -------
     4566                     3 files
```

Главное — папка `Payload/`, внутри неё `DemoApp.app`. Исполняемый файл называется так же, как `.app`, и его имя задаёт `CFBundleExecutable` в `Info.plist`. Рядом лежат ресурсы, фреймворки, `embedded.mobileprovision` (профиль подписи) и библиотеки. Если увидишь `.dylib`, которого не ждёшь, — это может быть след инъекции. Распаковав IPA, ты получаешь и бинарник для статики, и `Info.plist` для разбора конфигурации.

## Что мы теперь знаем

- IPA — ZIP с `Payload/<App>.app/`, подписью `_CodeSignature` и профилем `embedded.mobileprovision`.
- App Store-бинарники зашифрованы (`cryptid=1`); их дешифруют `frida-ios-dump`/`bagbak`.
- `filetype=2` — исполняемый файл, `6` — dylib.
- Профиль распространения содержит entitlements и список устройств.
- Переподпись делается `codesign`; изменить можно только то, что покрыто твоим сертификатом.
- `objection patchipa` автоматизирует встраивание Frida и переподпись.

## Квиз

Проверь себя.

```quiz
- question: Что нужно сделать перед анализом бинарника из App Store?
  options:
    - "Сжать его"
    - "Дешифровать (снять cryptid), иначе код недоступен"
    - "Переименовать"
    - "Подписать заново"
  answer: 1
  explanation: "App Store-бинарники зашифрованы FairPlay; без дешифровки class-dump/strings бесполезны."
- question: Что такое embedded.mobileprovision?
  options:
    - "Файл подписи кода"
    - "Профиль распространения с entitlements и списком устройств"
    - "Динамическая библиотека"
    - "Файл ресурсов"
  answer: 1
  explanation: "В профиле записаны права и UDID устройств, где приложение может запускаться."
- question: Что означает filetype=6 в Mach-O?
  options:
    - "Исполняемый файл"
    - "Динамическая библиотека (dylib)"
    - "Объектный файл"
    - "Архив"
  answer: 1
  explanation: "MH_DYLIB (6) — динамическая библиотека; MH_EXECUTE (2) — исполняемый файл."
- question: Какой инструмент автоматизирует встраивание Frida и переподпись IPA?
  options:
    - "jadx"
    - "objection patchipa"
    - "apktool"
    - "nm"
  answer: 1
  explanation: "objection patchipa встраивает frida-gadget и переподписывает IPA."
- question: Почему переподписанная сборка ведёт себя как «другое приложение»?
  options:
    - "Она быстрее"
    - "Меняется идентичность подписи, а значит и Keychain/App Groups"
    - "Она не запускается"
    - "У неё другой Mach-O"
  answer: 1
  explanation: "Entitlements и группы привязаны к сертификату; после переподписи они другие."
```

## Куда дальше

Мы научились получать и пересобирать IPA. Дальше — встраивание собственного кода в приложение: `mobile-ios-dylib-injection` покажет, как подгрузить свою библиотеку через `insert_dylib` и `DYLD_INSERT_LIBRARIES`. А пока главное запомни: цикл анализа iOS — распаковать → дешифровать → разобрать → при необходимости переподписать.

## Где пригодится

- **Пентест:** подготовка IPA к динамическому анализу и инструментированию.
- **Bug bounty:** переподпись и установка сборок на тестовые устройства.
- **Анализ малвари:** инструментирование iOS-образца через patchipa.
- **CTF:** распаковка и дешифровка IPA для поиска флага.
