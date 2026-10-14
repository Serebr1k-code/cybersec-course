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
