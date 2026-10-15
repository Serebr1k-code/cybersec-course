---
id: mobile-ios-app-groups
title: 'App Groups и общие данные: границы песочницы'
category: mobile
parent: mobile-ios-data-privacy
difficulty: hard
order: 1
tags: [ios, app-groups, entitlements, shared-container, keychain, extensions]
prerequisites: [mobile-ios-code-signing, mobile-ios-keychain]
useful_for:
  - 'Пентест мобильных приложений (iOS)'
  - 'Анализ iOS-приложений'
  - 'CTF Mobile'
estimated_minutes: 42
summary: 'Как App Groups позволяют приложению и его расширениям делить контейнер, UserDefaults и Keychain, как это настраивается через entitlements и какие риски создаёт.'
lab:
  kind: shell
  title: 'Практика: поиск секрета в общем контейнере'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, entitlements.xml, shared_defaults.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`entitlements.xml` — entitlements приложения.'
    - '`shared_defaults.txt` — общий UserDefaults.'
    - 'Найди секрет в общих данных — рядом флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Приложение хранит данные в своей песочнице — их не видит никто. Но у приложения есть
**расширения** (share-extension, widget, notification-service), которые запускаются как
отдельные процессы и в свою песочницу доступа не имеют. Как им передать данные? Через App
Groups. И именно они расширяют границу песочницы, а значит — создают риск.

## Наш пример: пароль, доступный расширению

Приложение хранит токен авторизации и хочет, чтобы share-extension тоже мог им
воспользоваться. Разберём, как это делается и почему это опасно.

## Шаг 1: что такое App Group

**App Group** — это общий контейнер, к которому имеют доступ все приложения и расширения,
подписанные с одним и тем же group-идентификатором. Он объявляется в **entitlements**:

```xml
<key>com.apple.security.application-groups</key>
<array>
  <string>group.com.example.shared</string>
</array>
```

Без этой строки в подписи доступ к общему контейнеру невозможен — граница держится на
entitlements, а не на коде.

## Шаг 2: общий файловый контейнер

Файлы общего контейнера лежат по известному пути. Приложение получает его так:

```swift
let url = FileManager.default
    .containerURL(forSecurityApplicationGroupIdentifier: "group.com.example.shared")
```

Любое приложение с тем же App Group видит эти файлы. Если туда положить токен — его увидит и
расширение, и (при компрометации подписи) чужой код с тем же правом.

## Шаг 3: общий UserDefaults

Простейший способ обмена — `UserDefaults` с именем группы:

```swift
let d = UserDefaults(suiteName: "group.com.example.shared")
d?.set("secret-token-123", forKey: "token")
```

Важно: это **не** Keychain. Данные лежат открыто в plist общего контейнера.

## Шаг 4: общий Keychain (access group)

Keychain тоже умеет делиться — через **access group** в entitlements:

```xml
<key>keychain-access-groups</key>
<array>
  <string>$(AppIdentifierPrefix)com.example.shared</string>
</array>
```

Тогда приложение и расширение видят одни и те же элементы Keychain. Это уже защищённое
хранилище, но доступ всё ещё определяется подписью.

## Шаг 5: риски и анализ

- **Слишком широкая группа** — если group id предсказуем и entitlement можно подделать (на
  jailbreak), чужой код прочитает данные.
- **Секреты в общем UserDefaults** — лежат открыто; ищем в `Library/Preferences/` общего
  контейнера.
- **Расширения как поверхность** — скомпрометированное расширение видит все общие данные.

При анализе смотрят entitlements (`codesign -d --entitlements`) и содержимое
`.../Shared/AppGroup/`.

## Шаг 6: Data Protection и общий контейнер

Файлы iOS защищены механизмом **Data Protection**: каждый файл привязан к классу защиты,
который определяет, расшифрован ли он, когда устройство заблокировано. Классы такие:

- `NSFileProtectionComplete` — файл недоступен, пока устройство заблокировано;
- `NSFileProtectionCompleteUnlessOpen` — доступен, если уже открыт;
- `NSFileProtectionCompleteUntilFirstUserAuthentication` — доступен после первой разблокировки;
- `NSFileProtectionNone` — всегда доступен.

Ключевой момент: файлы **общего контейнера App Group** подчиняются тому же механизму. Если
приложение записало токен с классом `None` или `UntilFirstUserAuthentication`, то на устройстве
с включённым резервным копированием (или после первой разблокировки) файл может быть прочитан.
Проверить класс можно через атрибуты:

```bash
$ frida -U -f com.example.app -l fileprot.js
NSFileProtectionKey = NSFileProtectionCompleteUntilFirstUserAuthentication
```

Если секрет лежит в общем контейнере и защита слабее, чем нужно, — это находка аудита.

## Шаг 7: анализ App Group на устройстве

Начинаем с entitlements бандла:

```bash
$ codesign -d --entitlements :- Demo.app | grep -A2 application-groups
<key>com.apple.security.application-groups</key>
<array><string>group.com.example.shared</string></array>
```

Затем смотрим, что лежит в общем контейнере:

```bash
$ find /var/mobile/Containers/Shared/AppGroup/*/ -type f 2>/dev/null | head
.../Library/Preferences/group.com.example.shared.plist
.../Documents/token.cache
```

На jailbreak-устройстве эти пути доступны напрямую, и секреты в `Preferences` читаются как
обычный plist. На обычном устройстве — только через отладку приложения с нужным entitlement.

## Шаг 8: атаки на общий контейнер

Основные сценарии: предсказуемый group id (если entitlement можно подделать на jailbreak,
чужой код получит доступ); скомпрометированное расширение (оно видит все общие данные, а его
поверхность часто шире); секреты в `UserDefaults(suiteName:)`, которые лежат открытым plist.
Отдельно стоит проверить, не попадают ли данные общего контейнера в бэкапы: если файл не
исключён из резервной копии, он может утечь через iTunes-бэкап.

## Таблица: где хранить секреты

| Место | Защита | Общий доступ | Годится для секретов |
|---|---|---|---|
| UserDefaults(suiteName:) | нет | да | нет |
| Файл в контейнере | Data Protection | да | условно |
| Keychain (access group) | шифрование | да | да |
| Keychain (личный) | шифрование | нет | да |

Правило простое: секреты — в Keychain; общий контейнер — только для нечувствительных данных
обмена.

## Практический вывод

App Group — это осознанное расширение границы песочницы. Аудит сводится к трём вопросам: какие
группы объявлены в entitlements; что именно в них лежит; насколько сильна защита этих данных.
Если в общем `UserDefaults` лежит токен авторизации — это прямая утечка. Правильная архитектура
кладёт секреты в Keychain с access group, а общий контейнер использует для файлов обмена без
чувствительных данных.

## Шаг 9: зачем Apple вообще нужны App Groups

Песочница iOS построена так, что каждое приложение и каждое расширение — отдельный процесс со
своим контейнером. Но расширения по определению работают с данными основного приложения:
share-extension получает содержимое для отправки, widget показывает сводку, notification-service
обрабатывает входящее уведомление. Без общего хранилища они не смогли бы ничего сделать. App
Group — это компромисс: Apple разрешает общий доступ, но только явно, через entitlement, который
проверяется при подписи. То есть граница песочницы не исчезает, а расширяется под контролем
подписи.

## Шаг 10: как расширение связано с основным приложением

Расширение лежит внутри бандла основного приложения (`PlugIns/Share.appex`) и подписывается тем
же сертификатом. Проверить это можно так:

```bash
$ codesign -d --entitlements :- Demo.app/PlugIns/Share.appex | grep -A2 groups
<key>com.apple.security.application-groups</key>
<array><string>group.com.example.shared</string></array>
```

Entitlement должен совпадать у приложения и расширения — иначе общий контейнер будет недоступен
одному из них. Именно поэтому при анализе важно смотреть entitlements не только основного
бандла, но и всех вложенных `.appex`.

## Пример анализа: токен в общем контейнере

Пусть приложение кладёт токен в общий `UserDefaults`. На jailbreak-устройстве он читается прямо
из plist:

```bash
$ plutil -p /var/mobile/Containers/Shared/AppGroup/*/Library/Preferences/group.com.example.shared.plist
{
  "token" => "eyJhbGciOiJIUzI1NiIs..."
}
```

Это готовая находка: токен лежит в открытом виде и доступен любому процессу с тем же
entitlement. В отчёте фиксируют путь, значение (или факт наличия) и рекомендацию перенести
секрет в Keychain с access group.

## Почему расширения — особая поверхность

Расширения часто написаны наспех, используют общие библиотеки и имеют доступ к тем же данным,
что и основное приложение. Если в расширении есть уязвимость (например, оно парсит
недоверенный ввод), атакующий получает вход в общий контейнер и, возможно, к секретам. Поэтому
аудит расширений — отдельная задача: проверяют их entitlements, обработку входных данных и то,
какие общие данные они читают.

## Итоговая мысль

App Group — это не дыра, а инструмент, которым часто пользуются неаккуратно. Проблема не в
механизме, а в том, что в общий контейнер кладут секреты, которые там лежать не должны. Аудит
прост: посмотреть entitlements, заглянуть в общий контейнер, оценить чувствительность данных.
Если токены и ключи окажутся в открытом plist — это находка; если только кэш и настройки — риск
ниже.

## Как перенести секреты из общего контейнера

Если аудит показал, что токен лежит в общем `UserDefaults`, рекомендация такая: перенести его в
Keychain с access group. Тогда расширение продолжит получать доступ, но данные будут
зашифрованы и защищены. Пример на Swift:

```swift
let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                        kSecAttrAccessGroup as String: "ABCDE12345.com.example.shared",
                        kSecValueData as String: token.data(using: .utf8)!]
SecItemAdd(q as CFDictionary, nil)
```

`kSecAttrAccessGroup` связывает элемент с группой доступа, объявленной в entitlements. Так секрет
остаётся общим для приложения и расширения, но больше не лежит открытым plist. Для несекретных
данных обмена общий контейнер по-прежнему уместен.

## Чек-лист аудита App Group

- Перечислены все группы из entitlements (основной бандл и вложенные `.appex`).
- Проверено содержимое общего контейнера (`Shared/AppGroup/`).
- Секреты в `UserDefaults(suiteName:)` отмечены как утечка.
- Проверен класс Data Protection у файлов общего контейнера.
- Проверено, не попадают ли данные в резервные копии.
- Рекомендация: секреты — в Keychain с access group.

## Что мы теперь знаем

- App Group — общий контейнер по entitlements, а не по коду.
- Обмен идёт через файлы, UserDefaults(suiteName:) и Keychain access group.
- Секреты в общем UserDefaults лежат открыто.
- Расширения и предсказуемые group id расширяют риск.

## Если не сработало

Если контейнер недоступен, проверьте, что group id совпадает с entitlement и начинается с
`group.`. Если данные «пропали» после обновления, проверьте, что путь берётся через
`containerURL`, а не хардкодом. На jailbreak доступ к чужому контейнеру можно получить при
наличии соответствующего entitlement.

## Частые вопросы

**App Group шифруется?** Файлы — под Data Protection, как и вся песочница.

**UserDefaults общего контейнера безопасен?** Нет, это открытый plist.

**Можно ли создать App Group без Apple?** Нет, нужен подписанный профиль.

## Квиз

Проверь себя.

```quiz
- question: Где объявляется App Group?
  options:
    - В Info.plist
    - В entitlements
    - В коде
    - В базе
  answer: 1
  explanation: Доступ определяется подписанным entitlement.
- question: Как получить путь общего контейнера?
  options:
    - containerURL(forSecurityApplicationGroupIdentifier:)
    - URL(string:)
    - Bundle.main
    - FileHandle
  answer: 0
  explanation: Этот метод возвращает URL общего контейнера.
- question: Чем общий UserDefaults хуже Keychain?
  options:
    - Он медленный
    - Данные лежат открытым plist
    - Он не работает
    - Он платный
  answer: 1
  explanation: UserDefaults не шифрует значения.
- question: Что делит Keychain между приложениями?
  options:
    - Access group в entitlements
    - Wi-Fi
    - Пароль
    - Язык
  answer: 0
  explanation: keychain-access-groups задаёт общий доступ.
- question: Кто может прочитать общие данные?
  options:
    - Только пользователь
    - Любой код с тем же entitlement App Group
    - Только Apple
    - Никто
  answer: 1
  explanation: Граница — в подписи, а не в песочнице процесса.
```

## Куда дальше

App Groups делят данные внутри приложения. Но есть канал, который связывает приложение со всей
системой, — буфер обмена. Разберём его утечки.

## Где пригодится

- Аудит хранения токенов и секретов в iOS.
- Анализ расширений и их поверхности.
- CTF Mobile и поиск секретов в общем контейнере.
