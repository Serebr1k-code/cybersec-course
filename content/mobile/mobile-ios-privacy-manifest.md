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

## Полная структура PrivacyInfo.xcprivacy

Файл приватности — обычный plist в XML. У него ровно четыре смысловые секции, и каждая отвечает
на свой вопрос.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
  <key>NSPrivacyTracking</key>
  <false/>
  <key>NSPrivacyTrackingDomains</key>
  <array/>
  <key>NSPrivacyCollectedDataTypes</key>
  <array/>
  <key>NSPrivacyAccessedAPITypes</key>
  <array/>
</dict>
</plist>
```

`NSPrivacyTracking` — булев флаг «использует ли приложение данные для трекинга». Если он `true`,
секция доменов должна быть заполнена, а приложению нужен ATT. `NSPrivacyTrackingDomains` — куда
уходит трекинг. `NSPrivacyCollectedDataTypes` — какие данные собираются. `NSPrivacyAccessedAPITypes`
— какие чувствительные API трогает приложение и почему.

Читать plist удобнее всего через `plutil`, который показывает дерево ключей и значений:

```bash
$ plutil -p PrivacyInfo.xcprivacy
{
  "NSPrivacyTracking" => 0
  "NSPrivacyTrackingDomains" => [
    0 => "tracker.example.com"
  ]
  ...
}
```

## Required Reason API: категории и коды причин

Часть системных API Apple считает «сборщиками отпечатка»: по ним приложение может незаметно
идентифицировать устройство. Чтобы это контролировать, Apple требует указывать причину
использования. Есть пять категорий, и у каждой — свой набор кодов.

| Категория | Что это | Пример кода |
|---|---|---|
| FileTimestamp | время изменения файлов | C617.1 |
| SystemBootTime | время загрузки системы | 35F9.1 |
| DiskSpace | свободное место на диске | 85F4.1 |
| ActiveKeyboards | список клавиатур | 3EC4.1 |
| UserDefaults | доступ к хранилищу настроек | CA92.1 |

Код — не украшение: он означает конкретную разрешённую цель. Например, `CA92.1` для
`UserDefaults` говорит «доступ только к своим настройкам». Если приложение заявляет одну причину,
а фактически читает чужие данные — это несоответствие, которое можно заметить при аудите.

## Как извлечь манифест из IPA

IPA — это zip. Распаковываем и ищем `PrivacyInfo.xcprivacy` в бандле приложения и во всех
встроенных фреймворках.

```bash
$ unzip -o app.ipa -d ipa
$ find ipa/Payload -name 'PrivacyInfo.xcprivacy'
ipa/Payload/App.app/PrivacyInfo.xcprivacy
ipa/Payload/App.app/Frameworks/Analytics.framework/PrivacyInfo.xcprivacy
```

Важно: свой манифест обязана иметь каждая сторонняя библиотека (SDK). Если у какого-то
фреймворка манифеста нет — это либо очень старый SDK, либо нарушение требований App Store.
Наличие отдельного манифеста у SDK означает, что его декларации надо читать отдельно от
деклараций приложения: они не «сливаются» автоматически.

## Сверка декларации с фактами

Манифест — это заявление разработчика, а не гарантия. Поэтому его всегда проверяют на
соответствие реальному поведению.

- Заявлено `NSPrivacyTracking = false`, но в трафике видны рекламные идентификаторы — несоответствие.
- Домен трекинга есть в трафике, но его нет в `NSPrivacyTrackingDomains` — нарушение.
- Приложение заявляет доступ к `UserDefaults` только для себя, а в коде читает чужие suite —
  красный флаг.
- Собирается `DeviceID` с `Tracking = true`, но ATT-запроса в коде нет — противоречие.

Сопоставлять удобно по чек-листу: выписать домены из манифеста, затем перехватить сетевой трафик
(через прокси или Frida-хук сетевых API) и сравнить. Расхождения и есть предмет разбора.

## Таблица: ключи манифеста и их смысл

| Ключ | Тип | Что означает |
|---|---|---|
| NSPrivacyTracking | bool | использует ли трекинг |
| NSPrivacyTrackingDomains | array | домены трекинга |
| NSPrivacyCollectedDataTypes | array | собираемые данные |
| NSPrivacyAccessedAPITypes | array | причины использования API |

Внутри элемента `NSPrivacyCollectedDataTypes` полезны вложенные ключи: `NSPrivacyCollectedDataType`
(какие именно данные), `...Linked` (связаны ли с пользователем) и `...Tracking` (используются ли
для отслеживания). Комбинация `Linked = true` и `Tracking = true` — самая чувствительная.

## Если не сработало

Если `plutil` не открывает файл, он может быть в бинарном формате plist, а не XML. Тогда
конвертируйте: `plutil -convert xml1 PrivacyInfo.xcprivacy`. Если манифеста нет вовсе, приложение
или SDK слишком старое — Apple отклоняет обновления таких сборок, но старые версии в App Store
могут существовать без него.

Если домены в манифесте не совпадают с трафиком, не спешите с выводами: часть запросов может
идти на CDN или аналитику, не связанную с трекингом. Сверяйте назначение домена, а не просто
наличие.

## Ограничения

Манифест не влияет на работу приложения и не проверяется в рантайме — это декларация для ревью.
Поэтому доверять ему как источнику истины нельзя. Его ценность для аналитика в другом: это
готовый список того, куда разработчик сам признал отправку данных, и удобная отправная точка для
проверки честности приложения.

Наконец, манифесты SDK и приложения надо читать вместе: суммарная картина приватности — это
объединение всех деклараций, включая декларации встроенных библиотек.

## Мини-практика: собрать сводку по всем манифестам

У приложения и каждого SDK — свой `PrivacyInfo.xcprivacy`. Чтобы получить полную картину, их
надо объединить.

```bash
$ find ipa/Payload -name 'PrivacyInfo.xcprivacy' | while read f; do
    echo "== $f"
    plutil -p "$f" | grep -E 'Tracking|Domain|CollectedDataType'
  done
```

Так вы сразу видите, какие SDK заявляют трекинг и на какие домены. Дальше удобно свести это в
таблицу: SDK → трекинг → домены → собираемые данные.

Отдельно проверяем главный манифест приложения на предмет `NSPrivacyTracking`:

```bash
$ plutil -extract NSPrivacyTracking raw ipa/Payload/App.app/PrivacyInfo.xcprivacy
false
```

Если `false`, но в трафике видны идентификаторы для рекламы — это несоответствие, ради которого
и делают аудит.

## Частые ошибки

Ошибка первая — читать только манифест приложения. Большая часть сбора данных идёт через SDK, у
которых свои декларации. Смотреть надо всё дерево `Frameworks/`.

Ошибка вторая — считать манифест доказательством. Это заявление разработчика, а не гарантия. Его
надо сверять с фактическим поведением (трафик, обращения к API).

Ошибка третья — путать `Linked` и `Tracking`. `Linked = true` означает, что данные связаны с
личностью пользователя; `Tracking = true` — что они используются для отслеживания и требуют ATT.
Это разные вещи, и обе важны.

## Как это связано с ATT

Privacy Manifest декларирует намерение, а App Tracking Transparency (ATT) реализует контроль
пользователя: приложение обязано спросить разрешение перед трекингом. Если манифест заявляет
`NSPrivacyTracking = true`, а ATT-запроса в коде нет — это нарушение, за которое сборку могут
отклонить.

Проверяют это вместе: сначала смотрят манифест (что заявлено), потом ищут в коде вызов
`ATTrackingManager.requestTrackingAuthorization` (спрашивает ли приложение) и сверяют с трафиком
(действительно ли трекинг идёт). Расхождение на любом из трёх уровней — находка.

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
