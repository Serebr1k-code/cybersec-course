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
## Что такое iOS Keychain

Keychain — системное защищённое хранилище секретов в iOS (пароли, токены, ключи, сертификаты). Приложение пишет туда через Security API (`SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete`), а система шифрует данные и защищает их классом доступности (`kSecAttrAccessible`). В отличие от `NSUserDefaults`/файлов (которые лежат в песочнице открыто), Keychain — правильное место для секретов. Пентест здесь ищет: секреты, которые **не** в Keychain (утечки), слабые классы доступности, доступ из других приложений (access groups), и извлечение при jailbreak.

Ментальная модель: Keychain шифруется системным ключом, привязанным к классу доступности и к устройству/паролю. Класс определяет, **когда** данные доступны (разблокировано, всегда, только это устройство) и переносятся ли они в бэкап.

## Классы доступности (kSecAttrAccessible)

| Класс | Доступность | В бэкапе | Рекомендация |
|-------|-------------|----------|--------------|
| `WhenUnlocked` | только разблокированное | да | базовый |
| `WhenUnlockedThisDeviceOnly` | разблокировано, только устройство | нет | секреты |
| `AfterFirstUnlock` | после первой разблокировки | да | фоновые задачи |
| `AfterFirstUnlockThisDeviceOnly` | то же, только устройство | нет | фоновые секреты |
| `Always` | всегда (устарело) | да | не использовать |
| `AlwaysThisDeviceOnly` | всегда, только устройство | нет | не использовать |
| `WhenPasscodeSetThisDeviceOnly` | разблокировано + есть код | нет | самый строгий |

Слабые варианты: `kSecAttrAccessibleAlways` и `AfterFirstUnlock` для чувствительных секретов (доступны без разблокировки). `...ThisDeviceOnly` исключает перенос в бэкап — важно для токенов.

## Как приложение пишет в Keychain

```objectivec
NSDictionary *q = @{
  (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
  (__bridge id)kSecAttrService: @"com.target.app",
  (__bridge id)kSecAttrAccount: @"sessionToken",
  (__bridge id)kSecValueData:   [token dataUsingEncoding:NSUTF8StringEncoding],
  (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
};
SecItemAdd((__bridge CFDictionaryRef)q, NULL);
```

```bash
grep -rn "SecItemAdd\|SecItemCopyMatching\|kSecAttrAccessible\|kSecClass" out/ | head
```

Проверяйте `kSecAttrAccessible`: если это `Always`/`AfterFirstUnlock` для токена — находка. Проверяйте также `kSecAttrAccessGroup` (общий доступ между приложениями одного разработчика).

## Извлечение при jailbreak

На jailbreak-устройстве Keychain читается инструментами:

```bash
objection -g com.target.app explore
ios keychain dump
ios keychain dump --json    # структурированный вывод
```

Под капотом — чтение `keychain-2.db` (SQLite) из `/private/var/Keychains/` или вызов Security API от имени приложения. При отсутствии jailbreak — только через динамическую инъекцию в само приложение (Frida/Objection), если приложение имеет доступ к своей группе.

## Data Protection (защита файлов)

Отдельно от Keychain, файлы в песочнице защищены классом `NSFileProtection`:

```bash
grep -rn "NSFileProtection\|setAttributes\|kSecAttrAccessible" out/ | head
```

| Класс файла | Доступность |
|-------------|-------------|
| `NSFileProtectionComplete` | только разблокировано |
| `NSFileProtectionCompleteUnlessOpen` | до закрытия файла |
| `NSFileProtectionCompleteUntilFirstUserAuthentication` | после первой разблокировки (дефолт) |
| `NSFileProtectionNone` | всегда |

Если приложение пишет токены в файл с `NSFileProtectionNone` — секрет доступен даже на заблокированном устройстве (и в бэкапе). Это находка.

## Частые ошибки

- **Секреты в `NSUserDefaults`.** Не шифруются, лежат в `.plist` в песочнице — читаются при jailbreak/бэкапе.
- **`kSecAttrAccessibleAlways`.** Доступно без разблокировки; часто на старом коде.
- **Нет `ThisDeviceOnly`.** Токен переносится в бэкап (утечка при восстановлении).
- **Широкий access group.** Другие приложения разработчика читают ваш Keychain.
- **Логирование секретов.** `NSLog(token)` — утечка в syslog.

## Разобранный пример: дамп Keychain

```bash
$ objection -g com.target.app explore
com.target.app # ios keychain dump --json
[
  { "svce": "com.target.app", "acct": "refreshToken",
    "accessibility": "kSecAttrAccessibleAfterFirstUnlock",
    "data": "eyJhbGciOiJIUzI1NiIsInR5cCI6..." }
]
```

Найден `refreshToken` с классом `AfterFirstUnlock` (доступен после первой разблокировки, попадает в бэкап). Impact: при извлечении бэкапа или на разблокированном устройстве токен утекает. Рекомендация — `WhenUnlockedThisDeviceOnly`.

## Справочная таблица: API и риски

| API / атрибут | Назначение | Риск |
|---------------|-----------|------|
| `SecItemAdd` | добавить секрет | слабый `Accessible` |
| `SecItemCopyMatching` | прочитать | доступ из чужой группы |
| `kSecAttrAccessibleAlways` | всегда доступно | утечка на локскрине |
| `kSecAttrAccessibleAfterFirstUnlock` | после разблокировки | в бэкапе |
| `kSecAttrAccessGroup` | общий доступ | cross-app |
| `kSecAttrSynchronizable` | iCloud-синхронизация | утечка в iCloud |
| `NSFileProtectionNone` | файл всегда доступен | утечка |

## Типовые ошибки новичка

- **Считать Keychain «неприступным».** При jailbreak он читается; ошибки классов/групп ослабляют защиту.
- **Путать Keychain и файлы.** Проверяйте оба: `NSUserDefaults`, файлы, БД.
- **Игнорировать бэкап.** `AfterFirstUnlock`/без `ThisDeviceOnly` → утечка через бэкап.
- **Не смотреть access group.** Общий доступ — частый кросс-app вектор.
- **Забыть про синхронизацию.** `kSecAttrSynchronizable` отправляет секрет в iCloud.

## Практический чек-лист

1. Найти обращения к Security API (`SecItemAdd/CopyMatching`).
2. Выписать `kSecAttrAccessible` для каждого секрета.
3. Проверить `kSecAttrAccessGroup` и `kSecAttrSynchronizable`.
4. Проверить, не лежат ли секреты в `NSUserDefaults`/файлах.
5. Проверить классы `NSFileProtection` для файлов с секретами.
6. Дампнуть Keychain (`objection ios keychain dump`).
7. Оценить impact: утечка через бэкап, cross-app, локскрин.

## Что дальше / решение

Порядок: найти Security API → проверить классы доступности и группы → проверить файлы/`NSUserDefaults` на секреты → дампнуть Keychain → оценить impact. Связанные уроки: `mobile-ios-basics`, `mobile-ios-dynamic`, `mobile-insecure-storage`, `mobile-keystore` (Android-аналог). Решение — когда секреты извлечены или подтверждена слабая конфигурация с impact.

## Расширенный разбор: цепочки атак через Keychain

Слабый Keychain почти никогда не бывает изолированной находкой — он звено в цепочке. Типовые сценарии:

- **Утечка через бэкап:** секрет с `AfterFirstUnlock` (без `ThisDeviceOnly`) попадает в незашифрованный/слабозашифрованный бэкап (iTunes/Finder). Злоумышленник с бэкапом читает токен → **захват аккаунта** (`mobile-account-takeover`).
- **Утечка через iCloud:** `kSecAttrSynchronizable=true` синхронизирует секрет в iCloud Keychain; при компрометации Apple ID он утекает.
- **Cross-app через access group:** приложения одного разработчика (или с общей группой) читают секрет друг друга; вредоносное приложение той же группы (или с entitlement) получает доступ.
- **Локскрин:** `Always`/`AlwaysThisDeviceOnly` доступны на заблокированном устройстве — секрет читается без разблокировки.
- **Компромисс устройства:** при jailbreak читается весь Keychain, включая чужие группы (на старых iOS — с известными багами).

Для каждой находки формулируйте impact через цепочку: «токен с классом AfterFirstUnlock → попадает в бэкап → восстанавливается на другом устройстве → захват сессии». Именно цепочка делает находку «high/critical», а не «low».

## Сравнение Keychain и Android Keystore

| Аспект | iOS Keychain | Android Keystore |
|--------|--------------|------------------|
| Что хранит | произвольные секреты (пароли/токены) | криптоключи (операции) |
| Шифрование | системным ключом по классу | TEE/StrongBox |
| Извлечение | дамп при jailbreak | ключ не извлекается (TEE) |
| Классы | `kSecAttrAccessible` | `setUserAuthenticationRequired` |
| Общий доступ | access groups | — (нет аналога) |
| Аналог «бэкапа» | iCloud/локальный бэкап | — |

Практический вывод: на Android вы чаще боретесь с **условиями использования** ключа, на iOS — с **классом доступности и бэкапом**. Оба урока стоит держать рядом.

## Квиз

```quiz
- question: "Какой kSecAttrAccessible правильнее для секретов?"
  options:
    - "kSecAttrAccessibleWhenUnlockedThisDeviceOnly"
    - "kSecAttrAccessibleAlways"
    - "kSecAttrAccessibleAfterFirstUnlock"
    - "kSecAttrAccessibleAlwaysThisDeviceOnly"
  answer: 0
  explanation: "Только это устройство + после разблокировки — максимум защиты и без бэкапа."
- question: "Что делает суффикс ThisDeviceOnly?"
  options:
    - "Запрещает перенос элемента в бэкап/на другое устройство"
    - "Ускоряет доступ"
    - "Шифрует TLS"
    - "Отключает Keychain"
  answer: 0
  explanation: "Элемент не мигрирует через бэкап и iCloud."
- question: "Где НЕ следует хранить токены?"
  options:
    - "В NSUserDefaults"
    - "В Keychain"
    - "В Secure Enclave"
    - "В Keychain с ThisDeviceOnly"
  answer: 0
  explanation: "NSUserDefaults — обычный plist без защиты секретов."
- question: "Чем опасна опция kSecAttrAccessibleAlways?"
  options:
    - "Секрет доступен даже при заблокированном устройстве и попадает в бэкап"
    - "Она замедляет приложение"
    - "Она требует jailbreak"
    - "Она удаляет элемент"
  answer: 0
  explanation: "Always снимает привязку к разблокировке и переносится в бэкап."
- question: "Что показывает keychain-access-groups?"
  options:
    - "Группы доступа к общим элементам Keychain"
    - "Список файлов приложения"
    - "Версию iOS"
    - "Размер бинарника"
  answer: 0
  explanation: "Общая группа позволяет другому приложению читать те же элементы."
```

## Где пригодится

- **CTF Mobile:** извлечение токена/флага из Keychain.
- **Bug bounty:** утечка секретов из-за неверного accessibility-класса.
- **Пентест:** аудит хранения секретов в iOS.
- **Работа:** ревью криптохранилищ приложения.
