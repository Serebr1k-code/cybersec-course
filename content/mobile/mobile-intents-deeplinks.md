---
id: mobile-intents-deeplinks
title: "Deep Links, Intents и URI: как открыть внутренний экран снаружи"
category: mobile
parent: mobile-exported-components
difficulty: medium
order: 1
tags: [android, deep-link, intent, uri, scheme, app-links, redirect]
prerequisites: [mobile-exported-components]
useful_for:
  - "CTF Mobile (запуск скрытых экранов по ссылке)"
  - "Bug bounty (deep link hijacking, обход логики)"
  - "Пентест мобильных приложений"
estimated_minutes: 14
summary: "Как работают Intent, deep links (custom scheme) и Android App Links, почему небезопасный deep link открывает внутренние экраны и как использовать adb/браузер для их вызова и эксплуатации."
lab:
  kind: shell
  title: 'Практика: разбор deep-link схемы'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, decoded]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Deep-link схема описана в `AndroidManifest.xml` в `<data android:scheme=...>`.'
    - 'Найди intent-filter, который принимает кастомную схему (не http).'
    - 'Секрет отдаётся на определённом хосте/пути — найди `nto{` в коде обработчика и запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

Мы уже знаем, что экспортированный компонент можно запустить извне. Но как именно «снаружи» в него попадают данные? Ответ — через **Intent** и **deep links**. Ссылка `https://f-droid.org/...` в браузере или мессенджере может открыть внутренний экран приложения с произвольными параметрами. Как найти такие входы и что они позволяют?

## Наш пример: deep links в fdroid.apk

Возьмём реальный `fdroid.apk`. Найдём в манифесте все `<intent-filter>`, которые объявляют схемы и хосты:

```
$ grep -oE '<data android:(scheme|host)[^/]*/>' fdroid_dec/AndroidManifest.xml | head -15
<data android:scheme="content"/>
<data android:scheme="file"/>
<data android:host="details" android:scheme="market"/>
<data android:scheme="https"/>
<data android:host="f-droid.org"/>
<data android:host="staging.f-droid.org"/>
<data android:host="cloudflare.f-droid.org"/>
<data android:scheme="https"/>
<data android:host="fdroid.link"/>
<data android:scheme="fdroidrepos"/>
<data android:scheme="FDROIDREPOS"/>
```

Вот он — список того, что приложение готово принимать снаружи. Разберём по порядку.

## Шаг 1: что такое Intent и deep link

**Intent** — это сообщение, которым Android-приложения обмениваются: «открой такой-то экран», «передай такие-то данные». Бывают явные (указан точный компонент) и неявные (указано действие/схема — система сама выбирает, кто отреагирует).

**Deep link** — это ссылка, которая открывает конкретный экран приложения. Два вида:

- **Custom scheme** — своё имя вместо `http`, например `fdroidrepos://...`. Легко перехватывается чужим приложением.
- **App Links / Universal Links** — обычный `https://` с подтверждением владения доменом. Защищён от перехвата, но требует настройки.

## Шаг 2: как читать intent-filter

Посмотрим на фильтр F-Droid, принимающий `https`:

```xml
<intent-filter android:autoVerify="true">
  <action android:name="android.intent.action.VIEW"/>
  <category android:name="android.intent.category.DEFAULT"/>
  <category android:name="android.intent.category.BROWSABLE"/>
  <data android:scheme="https"/>
  <data android:host="f-droid.org"/>
</intent-filter>
```

Три элемента определяют вход:

- `action VIEW` — «показать».
- `category BROWSABLE` — «можно открывать из браузера» (именно это делает ссылку кликабельной).
- `data scheme/host` — какие URL подходят.

Если есть `android:autoVerify="true"` — это App Links: приложение подтвердило домен, и чужие его не перехватят.

## Шаг 3: запускаем deep link вручную

Проверить, что экран открывается и какие данные принимает, можно из adb:

```
$ adb shell am start -a android.intent.action.VIEW \
    -d "https://f-droid.org/details?id=org.fdroid.fdroid"
Starting: Intent { act=android.intent.action.VIEW dat=https://f-droid.org/... }
```

Параметр `-d` задаёт URI. Дальше экран показывает приложение. Задача пентестера — понять, что оно делает с параметрами: подставляет в WebView, передаёт в запрос к API, использует как путь к файлу.

## Шаг 4: чем опасен deep link

- **IDOR через параметр.** Ссылка вида `app://open?user_id=123` открывает чужой профиль, если сервер не проверяет права.
- **Передача токена.** `app://login?token=...` — токен уходит в URI и оседает в логах, истории, буфере.
- **Intent redirection.** Приложение принимает вложенный Intent и запускает его, позволяя обойти защиту.
- **Открытие WebView на произвольном URL.** Ссылка задаёт адрес, и WebView грузит что угодно.

## Шаг 5: перехват custom scheme

Если приложение использует свою схему (не `https`), её может зарегистрировать злоумышленник. Тогда Android спросит пользователя, какое приложение открыть, — и злой двойник получит данные из ссылки. Это **custom scheme hijacking**. App Links (`https` + `autoVerify`) от этого защищены: домен принадлежит только одному приложению.

## Шаг 6: PendingIntent и его флаги

`PendingIntent` — это «отложенный Intent», который одно приложение передаёт другому для выполнения позже. Опасность в том, что получатель может подменить содержимое. Защита — флаг `FLAG_IMMUTABLE`:

```java
PendingIntent.getActivity(ctx, 0, intent,
    PendingIntent.FLAG_IMMUTABLE);   // содержимое нельзя изменить
```

`FLAG_MUTABLE` (или его отсутствие в старых версиях) позволяет получателю дописать свои поля — классическая уязвимость.

## Полный прогон от начала до конца

Соберём проверку deep links в один сценарий:

1. **`grep <data scheme/host>`** — собираем все входы из манифеста.
2. **Отделяем App Links** (`autoVerify=true`) от custom scheme.
3. **Запускаем ссылку** через `am start -a VIEW -d`.
4. **Наблюдаем**, какой экран открылся и какие параметры он принял.
5. **Проверяем параметры**: подставляются в API, WebView, файловую систему.
6. **Пробуем подменить значения** (id, url, token) и смотрим реакцию.
7. **Фиксируем**, есть ли проверка прав на стороне сервера.

Так deep link превращается из «просто ссылки» в конкретный вектор.

## Если не сработало

- **Ссылка открывает браузер, а не приложение.** Возможно, `autoVerify` не прошёл или хост не совпал — проверьте точный `host`/`path`.
- **Custom scheme открывает диалог выбора.** Это норма: система не знает, кому отдать. Диалог и есть место для hijacking.
- **Параметр игнорируется.** Возможно, экран проверяет формат или подпись — смотрите код.
- **Сервер отклоняет запрос.** Значит, проверка прав есть, и IDOR не сработает. Это правильная модель.
- **Нужен залогиненный пользователь.** Тогда сначала получите валидную сессию, потом повторяйте.

## Что фиксировать в отчёте

- **Какую ссылку** вы использовали (полный URI).
- **Какой экран** открылся и что произошло.
- **Какие данные** утекли или какое действие выполнено.
- **Рекомендации:** проверка прав на сервере, `autoVerify`, `FLAG_IMMUTABLE`, валидация URL.

## Частые вопросы

**«Чем App Link отличается от custom scheme?»** — App Link это `https` с подтверждённым доменом. **«Как перехватить custom scheme?»** — зарегистрировать её в своём приложении. **«Что делать с параметром token в ссылке?»** — это утечка: токен попадает в логи и историю. **«Обязателен ли браузер?»** — нет, ссылку можно открыть из adb или чужого приложения. **«Когда deep link безопасен?»** — когда данные из него проверяются на сервере.

## Практический совет

Проверяйте deep link не в вакууме, а в контексте: подставьте в параметры чужие идентификаторы и посмотрите, вернёт ли сервер данные. Именно сочетание «внешний вход + отсутствие серверной проверки» даёт находку. И не забывайте про PendingIntent — это ещё один вход, который часто остаётся mutable.

## App Links против Universal Links

App Links — это механизм Android, Universal Links — аналогичный механизм iOS. Оба решают одну задачу: привязать обычный `https`-домен к приложению так, чтобы ссылки открывались в нём, а не в браузере. На Android подтверждение делается файлом `assetlinks.json` на домене и флагом `android:autoVerify="true"` в манифесте; на iOS — файлом `apple-app-site-association`.

Для пентестера важны два следствия. Во-первых, если `autoVerify` не указан, ссылка ведёт себя как обычная, и её может перехватить чужое приложение, зарегистрировавшее тот же хост (в пределах custom scheme или через intent). Во-вторых, даже подтверждённый домен не защищает **параметры**: `https://app.example.com/open?id=123` откроется в нужном приложении, но если сервер не проверяет права, `id` можно подменить. То есть App Links решают проблему перехвата ссылки, но не проблему IDOR внутри неё.

## Валидация URL: типичные ошибки

Когда deep link передаёт URL, приложение должно его проверять. Частые ошибки:

- **Проверка `startsWith`.** `https://trusted.com` проходит и для `https://trusted.com.evil.com`.
- **Проверка по подстроке.** `indexOf("trusted")` обходится `https://evil.com/?x=trusted`.
- **Разбор до нормализации.** Разные регистры, `%2e`, `@` в URL меняют фактический хост.

Правильно — разобрать URL парсером, сравнить именно `scheme` и `host` с белым списком, и уже потом решать, грузить ли его. Ошибка в этой проверке превращает deep link в SSRF или открытие WebView на произвольном адресе.

## Что мы теперь знаем

По-простому:

1. Deep link — ссылка, открывающая экран приложения с параметрами.
2. Custom scheme легко перехватить; App Links (`https` + `autoVerify`) — нет.
3. `category BROWSABLE` делает ссылку кликабельной из браузера.
4. Опасности: IDOR, утечка токена, intent redirection, открытие WebView.
5. `PendingIntent` защищают флагом `FLAG_IMMUTABLE`.

## На что смотреть дальше

- **Соберите все `<data scheme/host>`** из манифеста — это входы.
- **Проверяйте `autoVerify`:** без него `https`-ссылка перехватываема.
- **Ищите, куда уходят параметры:** API, WebView, файловая система.
- **Смотрите флаги PendingIntent:** mutable — находка.

## drozer: автоматическая проверка экспорта компонентов

Вручную перебирать intent-filter’ы утомительно. drozer подключается к устройству как агент и перечисляет компоненты, доступные другим приложениям.

```
$ adb forward tcp:31415 tcp:31415
$ drozer console connect
dz> run app.package.attacksurface com.target
Attack Surface:
  3 activities exported
  1 broadcast receivers exported
  2 content providers exported
  1 services exported

dz> run app.activity.info -a com.target -i
  com.target.AdminActivity  (exported=true)
dz> run app.activity.start --component com.target com.target.AdminActivity
```

Если админ-экран открывается по внешнему вызову без проверки прав — это находка. Аналогично:

| Команда | Что проверяет |
|---------|---------------|
| `app.package.attacksurface` | поверхность атаки пакета |
| `app.activity.info -i` | экспортированные активности |
| `app.provider.info` | провайдеры и их разрешения |
| `app.broadcast.info` | ресиверы |
| `app.service.info` | сервисы |
| `scanner.provider.injection` | SQL-инъекции в провайдерах |
| `scanner.provider.traversal` | path traversal в провайдерах |

Особое внимание — `content://` провайдерам: незащищённый `ContentProvider` с `grantUriPermissions` и без `android:exported` часто позволяет читать чужие данные через `adb shell content query --uri content://...`.

Проверка экспорта без drozer — по манифесту: атрибут `android:exported="true"` (или наличие intent-filter до Android 12) плюс отсутствие `android:permission`. Если компонент экспортирован и не требует разрешения — он доступен любому приложению на устройстве.

## Квиз

Проверь себя.

```quiz
- question: "Что делает `category BROWSABLE` в intent-filter?"
  options:
    - "Позволяет открывать ссылку из браузера"
    - "Шифрует ссылку"
    - "Запрещает перехват"
    - "Требует root"
  answer: 0
- question: "Чем App Links (https + autoVerify) лучше custom scheme?"
  options:
    - "Домен подтверждён, и перехватить ссылку чужим приложением нельзя"
    - "Они работают только на iOS"
    - "Они не требуют интернета"
    - "Они шифруют параметры"
  answer: 0
- question: "Как запустить deep link из adb?"
  options:
    - "adb shell am start -a android.intent.action.VIEW -d 'scheme://host/path'"
    - "adb install app.apk"
    - "adb shell pm list packages"
    - "adb reboot"
  answer: 0
- question: "Какая уязвимость возникает, если параметр deep link не проверяется на сервере?"
  options:
    - "IDOR (доступ к чужим данным)"
    - "Переполнение буфера"
    - "SQL-инъекция всегда"
    - "XSS в нативном коде"
  answer: 0
- question: "Какой флаг делает PendingIntent неизменяемым?"
  options:
    - "FLAG_IMMUTABLE"
    - "FLAG_MUTABLE"
    - "FLAG_NEW_TASK"
    - "FLAG_SECURE"
  answer: 0
```

## Куда дальше

Мы разобрали deep links и Intent. В следующем уроке — **Broadcast Receivers**: как экспортированный receiver принимает broadcast извне и почему подделка сообщения приводит к выполнению команды. А пока запомни главное: каждый `<data scheme/host>` в манифесте — это потенциальный вход, и данные из ссылки нельзя доверять.

## Где пригодится

- **CTF Mobile:** открытие внутренних экранов через deep link.
- **Bug bounty:** deep link → IDOR/ATO — частая находка.
- **Пентест:** проверка OWASP MASVS-PLATFORM.
- **Работа:** ревью intent-filter и обработки ссылок.
