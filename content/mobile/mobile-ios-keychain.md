---
id: mobile-ios-keychain
title: "iOS Keychain и Data Protection: секреты и их защита"
category: mobile
parent: mobile-ios-security
difficulty: hard
order: 2
tags: [ios, keychain, data-protection, accessibility, nsuserdefaults, secrets]
prerequisites: [mobile-ios-basics]
useful_for:
  - "CTF Mobile (извлечение секрета из Keychain)"
  - "Bug bounty (утечка данных iOS)"
  - "Пентест мобильных приложений"
estimated_minutes: 35
summary: "Как iOS хранит секреты (Keychain, Data Protection, NSUserDefaults), какие accessibility-опции делают их уязвимыми и как извлекать/анализировать Keychain на устройстве."
---

## Вопрос, с которого всё начинается

В статике мы нашли, что `DemoApp` хранит токен через какой-то `SecureStore`, а в entitlements увидели `Keychain Access Groups: com.demo.secapp`. Значит, секреты лежат в **Keychain** — защищённом хранилище iOS. Но что это за хранилище физически и как из него достать токен?

## Наш пример: keychain-2.db

Keychain на iOS — это не папка с файлами, а **SQLite-база** `keychain-2.db`, которой управляет системный демон `securityd`. Возьмём реальную базу и разберём её структуру. Сначала посмотрим таблицы:

```
$ sqlite3 keychain-2.db ".tables"
cert     genp     inet     keys
```

Четыре таблицы — по типу хранимых данных:

| Таблица | Что хранит |
|---------|-----------|
| `genp` | общие пароли (generic passwords) |
| `inet` | пароли интернет-аккаунтов (логины/пароли к сайтам) |
| `cert` | сертификаты |
| `keys` | криптографические ключи |

Это и есть карта хранилища. Теперь заглянем внутрь `genp`:

```
$ sqlite3 -header -column keychain-2.db "SELECT rowid, CAST(acct AS TEXT) acct, CAST(svce AS TEXT) svce, CAST(data AS TEXT) data FROM genp;"
rowid  acct                svce          data
1      alice@demo.example  demo.session  {"token":"eyJhbGciOiJIUzI1NiJ9"}
2      alice@demo.example  demo.pin      1234
```

Вот и токен сессии — прямо в открытом виде (в этой учебной базе). `acct` — аккаунт, `svce` — сервис (по нему приложение находит запись), `data` — само значение. В реальности `data` обычно зашифрован ключом, привязанным к устройству и классу защиты.

## Шаг 1: классы защиты (kSecAttrAccessible)

Записи Keychain бывают с разным уровнем доступности. Этот параметр называется **Accessibility** и задаётся при сохранении. Основные значения:

| Значение | Когда доступно |
|----------|----------------|
| `kSecAttrAccessibleWhenUnlocked` | только при разблокированном устройстве |
| `kSecAttrAccessibleAfterFirstUnlock` | после первой разблокировки (доступно в фоне) |
| `kSecAttrAccessibleAlways` | всегда (устарело, небезопасно) |
| `...ThisDeviceOnly` | не попадает в бэкап |

Чем «слабее» значение, тем проще извлечь данные. `AfterFirstUnlock` — частый выбор для токенов синхронизации, и он позволяет читать секреты, даже когда экран заблокирован. Это стоит проверять в отчёте.

## Шаг 2: дамп через Objection

На jailbreak-устройстве проще всего дампить Keychain через Objection:

```
$ objection -g com.demo.secapp explore
com.demo.secapp # ios keychain dump
```

Команда выведет все записи, доступные приложению, с аккаунтом, сервисом и значением. Это самый быстрый способ получить токены. Аналогично работает дамп через Frida-скрипты (`frida-ios-dump` для IPA, `keychain_dumper` для базы).

## Шаг 3: что доступно приложению

Важный момент: приложение видит только **свои** записи и записи своей группы (`Keychain Access Groups` из entitlements). Мы уже видели группу `com.demo.secapp`. Если приложение состоит в нескольких группах, ключи из них тоже доступны — а значит, уязвимость в одном приложении группы компрометирует секреты другого. Именно поэтому App Groups и Keychain Groups проверяют в аудите.

## Шаг 4: бэкап как источник

Даже без jailbreak Keychain частично извлекается из **резервной копии**. Если бэкап сделан в Finder/iTunes и **не зашифрован**, ключи Keychain в него не попадают (они защищены). Но если пользователь включил «шифрованный бэкап», Keychain-записи сохраняются, и при знании пароля бэкапа их можно извлечь. Об этом подробно — в `mobile-ios-backup`.

Проверить, зашифрован ли бэкап, можно по его структуре: в шифрованном есть `Manifest.db` в защищённом виде, а `Manifest.plist` содержит флаг `IsEncrypted`.

## Шаг 5: типичные ошибки хранения

Что ищем в Keychain с точки зрения безопасности:

- **Токены с `AfterFirstUnlock`** — доступны в фоне, риск выше.
- **Пароли в `NSUserDefaults` вместо Keychain** — `NSUserDefaults` это обычный plist, он не защищён.
- **Секреты в файлах** (`Documents/`, `Library/`) — читаются через бэкап или jailbreak.
- **Один общий ключ на всё приложение** — компрометация одной записи = компрометация всех.

Сравнить легко: если после `ios keychain dump` токен найден в Keychain с сильным классом защиты — это хорошо; если он же лежит в `NSUserDefaults` (`ios nsuserdefaults get`) — это находка.

## Шаг 6: проверка через симулятор и device

На симуляторе Keychain ведёт себя иначе (он не привязан к реальному Secure Enclave), поэтому проверять классы защиты нужно на устройстве. Порядок:

1. Установить приложение на устройство.
2. Войти в аккаунт, чтобы появились записи.
3. `objection -g com.demo.secapp explore` → `ios keychain dump`.
4. Сравнить найденное с тем, что приложение могло бы хранить безопаснее.

## Шаг 7: если дампа нет

Иногда `ios keychain dump` ничего не показывает: приложение использует свою обёртку над `SecItem` с нестандартными атрибутами, либо данные лежат в общем доступе (App Group), к которому у нашего процесса нет прав. Тогда:

- хукаем `SecItemCopyMatching` через Frida и логируем результат;
- проверяем entitlements: возможно, нужна другая группа;
- смотрим `keychain-2.db` напрямую с root (jailbreak), фильтруя по `agrp` (access group).

Каждую находку проверяй дважды: сначала посмотри, есть ли запись в Keychain, затем — не дублируется ли то же значение в незащищённых местах. Дублирование в `NSUserDefaults` сводит на нет всю защиту Keychain: секрет, который «правильно» лежит в базе, но ещё и продублирован в plist, утекает через бэкап.

## Шаг 8: как правильно хранить

Если ты на стороне защиты, правил немного, но они важны. Токены — только в Keychain, никогда в `NSUserDefaults` или файлах. Для короткоживущих токенов выбирай `kSecAttrAccessibleWhenUnlocked` (а не `AfterFirstUnlock`), а для привязанных к устройству — вариант `...ThisDeviceOnly`, чтобы запись не попала в бэкап. Включай шифрованный бэкап и не клади в Keychain данные, которые можно перевыпустить. И помни про группы: чем больше приложений делят группу Keychain, тем шире поверхность атаки.

## Шаг 9: читаем keychain-2.db запросом

После дампа базы keychain удобнее смотреть её запросами. Класс защиты лежит в колонке `pdmn`:

```
$ sqlite3 keychain-2.db ".tables"
genp     inet
$ sqlite3 keychain-2.db "SELECT acct,svce,pdmn FROM genp;"
user@demo.example|DemoAppToken|ak
refresh|DemoAppRefresh|ck
```

`genp` — общие пароли/токены, `inet` — сетевые (логины к серверам). `pdmn` расшифровывается как protection domain: `ak` — `AfterFirstUnlock` (доступно после первой разблокировки), `ck` — `WhenUnlocked` (только на разблокированном). Токен с `ak` — находка: он доступен фоновым процессам и при физическом доступе может быть извлечён без пароля. Именно поэтому правильная рекомендация — хранить секреты с `ck`/`ThisDeviceOnly`.

## Что мы теперь знаем

- Keychain — это SQLite-база `keychain-2.db`, управляемая `securityd`.
- Записи делятся по таблицам: `genp` (общие пароли), `inet` (интернет), `cert`, `keys`.
- `acct`/`svce`/`data` — аккаунт, сервис и значение записи.
- Класс защиты (`kSecAttrAccessible`) определяет, когда запись доступна.
- Дамп делается через `objection ios keychain dump` или Frida-хук `SecItemCopyMatching`.
- Шифрованный бэкап сохраняет Keychain; незашифрованный — нет.
- Приложение видит только свои записи и записи своих групп.

## Квиз

Проверь себя.

```quiz
- question: Что физически представляет Keychain на iOS?
  options:
    - "Папку с файлами"
    - "SQLite-базу keychain-2.db под управлением securityd"
    - "Отдельный процесс"
    - "Файл plist"
  answer: 1
  explanation: "Keychain — это база данных, доступ к которой контролирует securityd."
- question: Какая таблица хранит общие пароли приложения?
  options:
    - "inet"
    - "genp"
    - "cert"
    - "keys"
  answer: 1
  explanation: "genp — generic passwords, то есть общие записи приложения."
- question: Какое поле записи определяет, когда она доступна?
  options:
    - "acct"
    - "svce"
    - "kSecAttrAccessible (класс защиты)"
    - "agrp"
  answer: 2
  explanation: "Accessibility задаёт условия доступа, например WhenUnlocked или AfterFirstUnlock."
- question: Какая команда Objection дампит Keychain?
  options:
    - "ios cookies get"
    - "ios keychain dump"
    - "ios nsuserdefaults get"
    - "ios jailbreak disable"
  answer: 1
  explanation: "ios keychain dump выводит доступные приложению записи Keychain."
- question: Попадает ли Keychain в незашифрованный бэкап?
  options:
    - "Да, всегда"
    - "Нет, ключи защищены; они сохраняются только в шифрованном бэкапе"
    - "Только на Android"
    - "Только при root"
  answer: 1
  explanation: "В незашифрованном бэкапе Keychain не сохраняется; нужен шифрованный бэкап."
```

## Куда дальше

Keychain мы разобрали. Но на пути к секретам стоит защита: приложение отказывается работать на jailbreak-устройстве, а трафик прикрыт pinning. В следующем уроке мы разберём, как устроен jailbreak-детект и как его обходить. А пока главное запомни: Keychain — это SQLite-база, и самый быстрый путь к токену — `objection ios keychain dump` на устройстве.

## Где пригодится

- **Пентест:** извлечение токенов и паролей приложения.
- **Bug bounty:** доказательство небезопасного хранения секретов.
- **CTF:** флаг, спрятанный в Keychain.
- **Аудит:** проверка классов защиты записей и групп Keychain.
