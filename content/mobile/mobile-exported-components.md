---
id: mobile-exported-components
title: "Экспортированные компоненты: Activity, Service, Receiver, Provider"
category: mobile
parent: mobile-android-components
difficulty: medium
order: 2
tags: [android, exported, activity, service, receiver, content-provider, ipc]
prerequisites: [mobile-android-anatomy]
useful_for:
  - "CTF Mobile (доступ к скрытой функциональности)"
  - "Bug bounty (неавторизованный доступ через IPC)"
  - "Пентест мобильных приложений"
estimated_minutes: 14
summary: "Как компоненты Android становятся доступны другим приложениям через android:exported, чем это опасно (неавторизованный доступ, обход экранов, утечки через ContentProvider) и как их перечислять и вызывать через adb."
---
## Что такое exported components

Android-приложение состоит из компонентов: Activity (экран), Service (фоновая работа), Broadcast Receiver (обработчик широковещательных сообщений), Content Provider (доступ к данным). Каждый может быть «экспортирован» — доступен другим приложениям. Экспортированный компонент без должной защиты — точка входа: другое приложение (в том числе вредоносное) может запустить его, передать данные или прочитать содержимое. В CTF и на пентестах это классический вектор. Цель модуля — научиться находить и эксплуатировать экспортированные компоненты.

## Как находить экспортированные компоненты

В манифесте ищите `android:exported="true"`:

```bash
grep -nE 'exported="true"|<activity|<service|<receiver|<provider' AndroidManifest.xml
```

Важно: начиная с Android 12, `exported` обязателен для компонентов с intent-filter. Компонент с `<intent-filter>` и без явного `exported` считается экспортированным. Также смотрите `permission` — если компонент защищён permission, эксплуатировать сложнее.

## Эксплуатация Activity

Запустить чужую Activity можно через `adb`:

```bash
adb shell am start -n com.example.app/.SecretActivity
adb shell am start -n com.example.app/.SecretActivity -e "flag" "value"
adb shell am start -a android.intent.action.VIEW -d "myapp://secret?x=1"
```

Если Activity показывает флаг при определённых extras — просто передайте их. Часто «секретный» экран доступен без авторизации.

## Эксплуатация Service

```bash
adb shell am startservice -n com.example.app/.MyService -a com.example.app.ACTION
```

Сервис может выполнять привилегированные операции по команде извне.

## Эксплуатация Broadcast Receiver

```bash
adb shell am broadcast -a com.example.app.SECRET_ACTION --es data "value"
```

Receiver может реагировать на широковещательные сообщения и делать что-то опасное.

## Эксплуатация Content Provider

Content Provider даёт доступ к данным (часто SQLite). Если он экспортирован и не защищён, можно читать/писать:

```bash
adb shell content query --uri content://com.example.app.provider/users
adb shell content read --uri content://com.example.app.provider/secret
```

Через `content` можно перебрать пути и таблицы. SQL-инъекция в `query` тоже возможна, если параметры не экранируются.

## Deep links

Deep link — URI, открывающий приложение на конкретном экране. Формат: `scheme://host/path?params`. Найти их можно в манифесте (`<data android:scheme=...>`). Эксплуатация:

```bash
adb shell am start -W -a android.intent.action.VIEW -d "myapp://profile?id=admin"
```

Частые уязвимости: IDOR через параметры, открытие внутренних экранов в обход авторизации, инъекция в WebView через URL.

## Инструмент drozer

`drozer` — фреймворк для тестирования компонентов:

```bash
drozer console connect
run app.package.attacksurface com.example.app
run app.activity.info -a com.example.app
run app.provider.finduri com.example.app
run app.provider.query content://com.example.app.provider/users
```

Он автоматически находит экспортированные компоненты и уязвимости.

## Типичные ошибки и подводные камни

- **Забыть про `intent-filter`** — компонент может быть экспортирован неявно.
- **Игнорировать permissions** — иногда компонент защищён.
- **Не проверить Content Provider** — частая утечка данных.
- **Путать `am start` и `am startservice`** — разные компоненты.
- **Не передать нужные extras** — Activity может требовать параметры.
- **Забыть про Android 12+** — обязательный `exported`.
- **Не использовать drozer** — он автоматизирует разведку.

## Справочная таблица

| Компонент | Команда |
|-----------|---------|
| Activity | `am start -n pkg/.Act` |
| Service | `am startservice -n pkg/.Svc` |
| Receiver | `am broadcast -a ACTION` |
| Provider | `content query --uri ...` |
| Deep link | `am start -a VIEW -d URI` |
| Разведка | `drozer` |

## Что дальше / решение

План: изучите манифест, найдите экспортированные компоненты (включая неявно экспортированные с intent-filter), проверьте permissions. Затем попробуйте запустить/вызвать каждый через `adb` или drozer. Для Content Provider — перебирайте URI и таблицы. Для deep links — передавайте параметры и ищите IDOR. Экспортированные компоненты — одна из самых частых уязвимостей Android, и находить их нужно в первую очередь.

## Практический пример: утечка через Content Provider

Разберём сквозной сценарий. APK содержит `AndroidManifest.xml`, где объявлен `<provider android:name=".DataProvider" android:authorities="com.example.app.provider" android:exported="true"/>`. Никакого permission нет. Шаг 1: находим authority и смотрим, какие URI поддерживаются. Шаг 2: `adb shell content query --uri content://com.example.app.provider/users` — получаем таблицу пользователей с паролями или токенами. Шаг 3: пробуем другие пути: `.../secret`, `.../flag`, `.../config`. Шаг 4: если прямой запрос не проходит, пробуем SQL-инъекцию в параметре: `--where "1=1"` или `--uri content://.../users/../../secret`. Шаг 5: если провайдер поддерживает запись — можно подменить данные (`content insert`, `content update`).

Это типичный путь: экспортированный провайдер без защиты = прямая утечка данных. Часто в CTF флаг лежит именно в таблице провайдера.

## Практический пример: обход авторизации через Activity

Другой сценарий: приложение требует логин, но «секретный» экран (`SecretActivity`) не проверяет сессию при прямом запуске. Шаг 1: из манифеста узнаём полное имя: `com.example.app/.SecretActivity`. Шаг 2: `adb shell am start -n com.example.app/.SecretActivity`. Экран открывается, минуя логин. Шаг 3: если требуется extras, передаём их: `-e "username" "admin"`. Так обходится клиентская проверка авторизации — классическая ошибка, когда контроль доступа реализован только на уровне навигации, а не в самом компоненте.

## Частые вопросы

«Провайдер защищён permission?» — проверьте `android:permission`; если он `signature`, эксплуатировать из чужого приложения не выйдет. «Не знаю URI?» — перебирайте (`users`, `secret`, `config`) или используйте drozer `app.provider.finduri`. «Activity не открывается?» — неверное имя или требуется intent-filter. «Как автоматизировать?» — drozer.

## Что дальше / решение

Итог: найдите экспортированные компоненты в манифесте, проверьте permissions, затем эксплуатируйте каждый: Activity/Service через `am start`, Receiver через `am broadcast`, Provider через `content`. Для Provider перебирайте URI и пробуйте SQL-инъекцию. Используйте drozer для автоматизации. Экспортированные компоненты — одна из самых частых и легко эксплуатируемых уязвимостей Android.

## Расширенный чек-лист по экспортированным компонентам

Порядок разведки. Первое: `grep -nE 'exported="true"|intent-filter|<activity|<service|<receiver|<provider' AndroidManifest.xml` — соберите список. Второе: для каждого проверьте `android:permission` (если `signature` — эксплуатировать сложно). Третье: для Activity — `adb shell am start -n pkg/.Act`; для Service — `am startservice`; для Receiver — `am broadcast`; для Provider — `content query`. Четвёртое: переберите URI провайдера (`users`, `secret`, `config`, `flag`) и попробуйте SQL-инъекцию через `--where`. Пятое: проверьте `PendingIntent` с `FLAG_MUTABLE` на возможность подмены. Шестое: автоматизируйте через drozer.

## Отдельно про Content Provider

Провайдеры — самая «вкусная» цель, потому что дают прямой доступ к данным. Проверяйте: экспортирован ли, есть ли permission, поддерживает ли запросы/запись, экранируются ли параметры. Пути можно перебирать по словарю (`/data/data/<pkg>/databases/*.db` покажет таблицы, если есть root). SQL-инъекция в `query`/`update` встречается регулярно.

## Частые вопросы

«Компонент защищён permission?» — проверьте тип (`normal` можно запросить, `signature` — нет). «Не знаю URI провайдера?» — `app.provider.finduri` в drozer. «Activity не открывается?» — неверное имя или нужен intent-filter. «Как найти все компоненты сразу?» — drozer `app.package.attacksurface`.

## Что дальше / решение

Итог: соберите список экспортированных компонентов, проверьте permissions, эксплуатируйте каждый доступным способом (`am`, `content`), для провайдеров перебирайте URI и пробуйте инъекцию. Автоматизируйте через drozer. Это одна из самых частых уязвимостей Android и часто самый короткий путь к флагу или данным.

## Квиз

```quiz
- question: "Что означает `android:exported="true"` у компонента?"
  options:
    - "Компонент доступен другим приложениям на устройстве"
    - "Компонент зашифрован"
    - "Компонент требует root"
    - "Компонент отключён"
  answer: 0
- question: "Какой компонент даёт доступ к данным через SQL-подобный интерфейс?"
  options:
    - "Activity"
    - "Service"
    - "Broadcast Receiver"
    - "Content Provider"
  answer: 3
- question: "Как запустить экспортированную Activity из adb?"
  options:
    - "`adb start activity`"
    - "`adb shell am start -n com.app/.Activity`"
    - "`adb shell content query`"
    - "`adb logcat`"
  answer: 1
- question: "Чем опасен экспортированный ContentProvider без permission?"
  options:
    - "Другие приложения могут читать (и иногда писать) его данные"
    - "Он замедляет приложение"
    - "Он ломает HTTPS"
    - "Он требует перезагрузки"
  answer: 0
- question: "Какой инструмент автоматизирует перечисление поверхности атаки Android-приложения?"
  options:
    - "exiftool"
    - "binwalk"
    - "Drozer"
    - "sqlmap"
  answer: 2
```

## Где пригодится

- **CTF Mobile:** обход экранов логина, чтение флага из экспортированного провайдера.
- **Bug bounty:** неавторизованный доступ к данным/функциям через IPC — валидные находки с высоким импактом.
- **Пентест:** проверка OWASP MASVS-PLATFORM (безопасность межпроцессного взаимодействия).
- **Работа:** аудит манифеста на предмет лишних `exported="true"` и отсутствующих permission.
