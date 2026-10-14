---
id: mobile-ios-privacy-manifest
title: 'Privacy Manifest: декларация приватности iOS'
category: mobile
parent: mobile-ios-data-privacy
difficulty: hard
order: 3
tags: [ios, privacy-manifest, privacyinfo, required-reason, tracking, app-store]
prerequisites: [mobile-ios-data-privacy]
useful_for:
  - 'Анализ iOS-приложений'
  - 'Приватность'
  - 'Пентест мобильных приложений'
estimated_minutes: 38
summary: 'Что такое Privacy Manifest (PrivacyInfo.xcprivacy), какие API требуют причины использования, как декларируются трекинг и сбор данных и как анализировать файл.'
lab:
  kind: shell
  title: 'Практика: разбор Privacy Manifest'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, PrivacyInfo.xcprivacy]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`PrivacyInfo.xcprivacy` — манифест приватности.'
    - 'Найди домен трекинга и тип собираемых данных.'
    - 'Рядом с доменом — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Apple требует, чтобы приложения декларировали, какие данные они собирают и зачем используют
некоторые API. Декларация живёт в файле **Privacy Manifest**. Для аналитика это удобная
«карта» приватности приложения: что оно собирает, куда отправляет и какие чувствительные API
трогает. Разберём файл на реальном примере.

## Наш пример: PrivacyInfo.xcprivacy приложения

Открываем IPA и находим файл приватности. Разберём его секции и что каждая означает.

## Шаг 1: что это за файл

**Privacy Manifest** — файл `PrivacyInfo.xcprivacy` в корне бандла (и у каждой сторонней
библиотеки). Это plist со структурированным описанием практик приватности. Apple проверяет его
при ревью и требует у приложений и SDK.

## Шаг 2: collected data types

Секция `NSPrivacyCollectedDataTypes` перечисляет, какие данные собираются:

```xml
<key>NSPrivacyCollectedDataTypes</key>
<array>
  <dict>
    <key>NSPrivacyCollectedDataType</key>
    <string>NSPrivacyCollectedDataTypeDeviceID</string>
    <key>NSPrivacyCollectedDataTypeLinked</key>
    <true/>
    <key>NSPrivacyCollectedDataTypeTracking</key>
    <true/>
  </dict>
</array>
```

Ключ `...Tracking = true` означает, что данные используются для отслеживания — а значит, требует
ATT.

## Шаг 3: tracking domains

`NSPrivacyTrackingDomains` перечисляет домены трекинга:

```xml
<key>NSPrivacyTrackingDomains</key>
<array>
  <string>tracker.example.com</string>
</array>
```

Если приложение шлёт трекинг на домен не из этого списка — это нарушение, и App Store может
отклонить сборку. Для аналитика это список «куда уходят данные».

## Шаг 4: required reason APIs

`NSPrivacyAccessedAPITypes` описывает использование API, требующих обоснования (например,
доступ к файловым меткам, системным аптайму, UserDefaults):

```xml
<key>NSPrivacyAccessedAPITypes</key>
<array>
  <dict>
    <key>NSPrivacyAccessedAPIType</key>
    <string>NSPrivacyAccessedAPICategoryUserDefaults</string>
    <key>NSPrivacyAccessedAPITypeReasons</key>
    <array><string>CA92.1</string></array>
  </dict>
</array>
```

Коды причин (`CA92.1` и подобные) стандартизированы. Их отсутствие или несоответствие —
признак небрежности и потенциального отклонения.

## Шаг 5: как анализировать

- Проверьте, все ли сторонние SDK имеют свой Privacy Manifest.
- Сравните заявленный трекинг с фактическими доменами в трафике.
- Сопоставьте declared data types с реальными запросами.
- Ищите несоответствия: заявлено «не собираем», а в трафике — идентификаторы.

Так манифест становится основой для проверки честности приложения.

## Что мы теперь знаем

- Privacy Manifest — `PrivacyInfo.xcprivacy` в бандле и у SDK.
- `NSPrivacyCollectedDataTypes` — что собирается и для трекинга ли.
- `NSPrivacyTrackingDomains` — домены трекинга.
- `NSPrivacyAccessedAPITypes` — причины использования API; расхождения = красный флаг.

## Если не сработало

Если манифеста нет, приложение/SDK может быть старым — тогда Apple отклоняет обновления.
Файл может лежать и внутри фреймворков, проверьте `Frameworks/*.framework/PrivacyInfo.xcprivacy`.
Для разбора используйте `plutil -p`.

## Частые вопросы

**Обязателен ли манифест?** Да, для новых сборок и популярных SDK.

**Он влияет на работу приложения?** Нет, это декларация.

**Можно ли ему доверять?** Нет, это заявление разработчика; проверяйте фактами.

## Квиз

Проверь себя.

```quiz
- question: Как называется файл Privacy Manifest?
  options:
    - Info.plist
    - PrivacyInfo.xcprivacy
    - manifest.xml
    - privacy.json
  answer: 1
  explanation: Это plist-файл PrivacyInfo.xcprivacy.
- question: Что описывает NSPrivacyTrackingDomains?
  options:
    - Цвета
    - Домены трекинга
    - Язык
    - Версию
  answer: 1
  explanation: Это список доменов, куда уходит трекинг.
- question: Зачем нужны required reason APIs?
  options:
    - Для красоты
    - Чтобы обосновать использование чувствительных API
    - Для сети
    - Для батареи
  answer: 1
  explanation: Apple требует указать причину использования API.
- question: Что означает NSPrivacyCollectedDataTypeTracking=true?
  options:
    - Приложение медленное
    - Данные используются для отслеживания (нужен ATT)
    - Приложение платное
    - Приложение на iPad
  answer: 1
  explanation: Это признак трекинга.
- question: Как проверить честность манифеста?
  options:
    - Поверить на слово
    - Сравнить заявленное с фактическим трафиком
    - Удалить его
    - Открыть в браузере
  answer: 1
  explanation: Расхождения между декларацией и трафиком — красный флаг.
```

## Куда дальше

Privacy Manifest декларирует трекинг. Но контроль пользователя над ним реализует ATT. Разберём
App Tracking Transparency и IDFA.

## Где пригодится

- Аудит приватности iOS-приложений и SDK.
- Проверка соответствия требованиям App Store.
- CTF Mobile и разбор состава приложения.
