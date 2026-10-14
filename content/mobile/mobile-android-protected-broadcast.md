---
id: mobile-android-protected-broadcast
title: 'Protected broadcasts: рассылки «только для системы»'
category: mobile
parent: mobile-android-intents-broadcasts
difficulty: medium
order: 2
tags: [android, broadcast, protected, permission, receiver, security]
prerequisites: [mobile-broadcast-receivers]
useful_for:
  - 'Пентест мобильных приложений (Android)'
  - 'Bug bounty Android'
  - 'CTF Mobile'
estimated_minutes: 38
summary: 'Как устроены protected broadcasts, почему объявленное разрешение не всегда защищает рассылку и как найти receiver без android:permission.'
lab:
  kind: shell
  title: 'Практика: аудит broadcast receiver'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, receivers.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`receivers.txt` — выдержка из манифеста с receiver-ами.'
    - 'Найди receiver, чьё разрешение объявлено как normal.'
    - 'Рядом с этим receiver-ом — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Приложение объявляет receiver, который «принимает команды только от системы». В манифесте стоит
что-то похожее на защиту. Но на деле любой установленный APK может послать эту рассылку и
заставить receiver выполнить действие. Как понять, защита настоящая или декоративная, и где
именно проходит граница?

## Наш пример: receiver в манифесте

Открываем декомпилированный манифест:

```xml
<receiver android:name=".BootReceiver" android:exported="true">
  <intent-filter>
    <action android:name="android.intent.action.BOOT_COMPLETED"/>
  </intent-filter>
</receiver>
```

`BOOT_COMPLETED` — это **protected broadcast**: системное действие, которое по правилам Android
может рассылать только система. Стороннее приложение не может отправить его обычным способом —
framework отбросит такой `sendBroadcast`. Кажется, безопасно. Но защита здесь не в самом
receiver, а в *имени действия*. Разберём, где именно эта граница проходит.

## Шаг 1: что такое broadcast

**Broadcast** — это сообщение «всем, кто слушает», в отличие от `startActivity`, которое
адресовано одному экрану. Receiver регистрируется на действие и получает рассылку. Есть два
способа регистрации: в манифесте (работает, даже когда приложение не запущено) и в коде через
`registerReceiver` (работает, пока живёт процесс). Манифестный receiver — главный кандидат на
атаку, потому что он виден снаружи и переживает перезапуск.

## Шаг 2: что именно защищено

Часть действий (`BOOT_COMPLETED`, `PACKAGE_ADDED`, `SCREEN_ON`, `ACTION_POWER_CONNECTED`)
помечены системой как protected: приложения не могут их отправлять, только framework. Список
protected broadcasts зашит в framework (в `frameworks/base/core/res/AndroidManifest.xml`) и
проверяется в `ActivityManagerService.broadcastIntent` — попытка отправить защищённое действие
из приложения получает отказ. Проверить можно так:

```bash
$ adb shell am broadcast -a android.intent.action.BOOT_COMPLETED
java.lang.SecurityException: Permission Denial: not allowed to send broadcast
android.intent.action.BOOT_COMPLETED from ...
```

Обратите внимание: защита — это **отказ в отправке**, а не проверка отправителя в receiver-е.

## Шаг 3: где защита ломается

Опасность начинается, когда приложение объявляет **своё** действие и *думает*, что оно тоже
защищено. Например:

```xml
<receiver android:name=".ResetReceiver" android:exported="true">
  <intent-filter>
    <action android:name="com.example.app.ACTION_RESET"/>
  </intent-filter>
</receiver>
```

`com.example.app.ACTION_RESET` — не protected. Любое приложение может выполнить:

```bash
$ adb shell am broadcast -a com.example.app.ACTION_RESET
Broadcasting: Intent { act=com.example.app.ACTION_RESET }
Broadcast completed: result=0
```

Если receiver по этой команде сбрасывает данные или выполняет привилегированное действие — это
находка. Часто такие действия ещё и не требуют extras, то есть эксплуатируются одной строкой.

## Шаг 4: как отличить настоящую защиту

Настоящая защита на receiver — это `android:permission`:

```xml
<receiver android:name=".ResetReceiver"
          android:exported="true"
          android:permission="com.example.app.permission.INTERNAL"/>
```

Теперь отправитель обязан обладать разрешением `INTERNAL`. Но разрешение нужно объявить с
уровнем `signature`, иначе любой может его запросить и получить:

```xml
<permission android:name="com.example.app.permission.INTERNAL"
            android:protectionLevel="signature"/>
```

Если уровень `normal` или `dangerous` — приложение-атакующий просто запросит разрешение у
пользователя и снова сможет слать рассылку. Так «защита» превращается в фикцию. Уровень
`signature` требует, чтобы у отправителя была та же подпись, что у объявившего разрешение пакета,
— а подделать подпись нельзя.

## Шаг 5: локальная vs глобальная рассылка

Broadcast может быть отправлен глобально (всем приложениям) или **локально** — только внутри
своего процесса через `LocalBroadcastManager` (или `registerReceiver` без export). Локальные
рассылки нельзя перехватить извне: они не покидают процесс. Если приложение шлёт чувствительные
данные глобально, хотя использует их только внутри, — это тоже утечка, даже без атакующего
receiver-а.

## Шаг 6: ordered и обычные рассылки

`sendOrderedBroadcast` доставляет сообщение получателям по очереди, по убыванию `priority`, и
каждый может изменить результат для следующего. Это даёт ещё одну поверхность: приложение-
атакующий с высоким приоритетом получает сообщение первым и может подменить extras до того, как
дойдёт очередь до легитимного получателя. Обычная (`sendBroadcast`) рассылка доставляется всем
одновременно и порядка не гарантирует.

## Шаг 7: как проверять на практике

- Найти все `<receiver>` с `android:exported="true"` и без `android:permission`.
- Проверить, защищено ли действие (protected broadcast) или это собственное action.
- Убедиться, что разрешение объявлено с `protectionLevel="signature"`.
- Прогнать `am broadcast` и посмотреть на эффект.
- Для ordered-рассылок проверить, кто получает сообщение первым.
- Проверить `android:exported` у сервисов, которые стартуют по рассылке.

## Шаг 8: типичные ошибки разработчиков

- Считать, что любое `com.example.*` действие «защищено по имени» — нет, защищено только то, что
  в списке framework.
- Объявлять разрешение с `protectionLevel="normal"` и думать, что это ограничивает.
- Оставлять `exported="true"` у receiver-а, который нужен только самому приложению.
- Доверять extras рассылки без проверки отправителя.
- Хранить в рассылке токены, которые затем попадают в `dumpsys`.

## Что мы теперь знаем

- Protected broadcast — действие, которое может слать только система.
- Собственное action не защищено автоматически.
- `android:permission` + `protectionLevel="signature"` — настоящая защита.
- `protectionLevel` `normal`/`dangerous` защиту не даёт.
- Ordered-рассылки можно перехватить по приоритету.
- Локальные рассылки безопаснее глобальных.

## Куда дальше

Мы разобрали «защищённые» рассылки. Дальше — их устаревший вариант, который вообще висит в
системе после отправки: sticky broadcast.

## Шаг 9: как это выглядит в реальных приложениях

В реальных APK чаще всего встречаются три паттерна. Первый — «служебный» receiver с
`exported="true"` и своим действием вида `com.app.internal.SYNC` без разрешения: любое
приложение может дёрнуть синхронизацию, сброс или смену настроек. Второй — receiver с
`android:permission`, но разрешение объявлено как `normal`, и защита не работает. Третий —
receiver, который по рассылке стартует сервис, а сервис уже делает что-то опасное; атака
разделяется на два шага, но результат тот же.

Особый случай — `BOOT_COMPLETED`. Приложение просит разрешение `RECEIVE_BOOT_COMPLETED` и
запускает работу при старте устройства. Это не уязвимость само по себе, но если receiver по
рассылке выполняет действия, которые можно подделать (например, загружает конфиг с сервера по
HTTP), появляется поверхность.

## Шаг 10: инструменты и команды

Быстрый аудит манифеста:

```bash
$ aapt dump xmltree app.apk AndroidManifest.xml | grep -A6 receiver
$ drozer console connect
dz> run app.broadcast.info -a com.example.bank
dz> run app.broadcast.send --action com.example.app.ACTION_RESET
```

`drozer` перечисляет receiver-ы и умеет отправлять рассылки, показывая, какие из них
экспортированы и чем защищены. Дополнительно полезно `adb shell dumpsys package com.example.bank`
— там видно зарегистрированные фильтры и объявленные разрешения.

## Шаг 11: receiver vs exported service

Не путайте три похожих механизма:

- **Receiver** — принимает broadcast, живёт в манифесте, может просыпаться приложением.
- **Exported service** — принимает `startService`/`bindService`, живёт как процесс.
- **Content Provider** — отдаёт данные по `content://`.

У каждого своя защита. Receiver защищается `android:permission`; service — тоже
`android:permission`; provider — `android:permission` + `grantUriPermissions`. Правило одно:
разрешение работает только на уровне `signature`.

## Шаг 12: почему «protected» вводит в заблуждение

Слово «protected» относится к **действию**, а не к receiver-у. Разработчик видит
`BOOT_COMPLETED` в списке protected, копирует подход для своего действия — и получает дыру,
потому что его действие в список не входит. Поэтому в отчёте важно чётко писать: «receiver
экспортирован и не защищён разрешением; действие не является protected broadcast, поэтому
отправляется любым приложением». Это снимает возражения «но у нас же protected».

## Частые вопросы

**Достаточно ли `exported="false"`?** Да, это надёжно закрывает receiver от внешних рассылок,
если он нужен только самому приложению.

**Можно ли защитить receiver только именем действия?** Нет. Имя действия ничего не значит, пока
framework не считает его protected.

**Что если разрешение объявлено в другом приложении?** Тогда его уровень и подпись определяет
владелец разрешения; проверьте, что это `signature` и что подпись совпадает.

## Шаг 13: как писать это в отчёте

Хороший отчёт про незащищённый receiver состоит из четырёх частей. Во-первых, точная выдержка из
манифеста с путём к файлу и строками. Во-вторых, команда `am broadcast`, которая демонстрирует
эффект, и её вывод. В-третьих, описание последствий: какие данные или действия доступны
атакующему. В-четвёртых, рекомендация: убрать `exported="true"` либо объявить
`android:permission` с `protectionLevel="signature"`. Такая структура снимает вопросы о
серьёзности и делает находку воспроизводимой.

## Шаг 14: отдельный случай — динамические receiver-ы

Receiver, зарегистрированный в коде через `registerReceiver`, тоже может быть уязвим, но его
поведение зависит от того, с какими флагами он зарегистрирован. На Android 14 (API 34)
манифестные receiver-ы требуют явного `RECEIVER_EXPORTED`/`RECEIVER_NOT_EXPORTED` при
динамической регистрации; отсутствие флага — ошибка. Поэтому при аудите смотрите и код: если
receiver регистрируется без указания экспорта, на новых Android это либо падение, либо
неявный экспорт — и то и другое стоит проверить.

## Шаг 15: связь с другими векторами

Незащищённый receiver редко бывает изолированной находкой. Часто он становится «первой ступенью»:
рассылка включает сервис, сервис открывает сокет, сокет утекает данные. В таких цепочках receiver
ценен тем, что доступен без всякого UI — приложение-жертва даже не должно быть запущено, если
receiver манифестный. Поэтому при построении эксплойт-цепочек (см. `mobile-exploit-chains`)
экспортированные receiver-ы всегда проверяют первыми: это самый дешёвый вход.

## Шаг 16: итоговая формула проверки

Запомните три вопроса, которые нужно задать про каждый receiver. Экспортирован ли он
(`android:exported`)? Защищён ли он разрешением с уровнем `signature`? Является ли его действие
protected broadcast, то есть рассылает ли его только система? Если хотя бы на один вопрос ответ
«нет», receiver — кандидат на находку.

## Квиз

Проверь себя.

```quiz
- question: Что такое protected broadcast?
  options:
    - Рассылка, которую может отправить только система
    - Рассылка с паролем
    - Шифрованная рассылка
    - Рассылка только на root
  answer: 0
  explanation: Такие действия framework отбрасывает при попытке отправить их из приложения.
- question: Какое объявление даёт настоящую защиту receiver-а?
  options:
    - android:exported="false"
    - android:permission с protectionLevel="signature"
    - android:label
    - android:enabled="true"
  answer: 1
  explanation: Разрешение уровня signature требует совпадения подписи, иначе его не получить.
- question: Чем опасен protectionLevel="normal" на разрешении receiver-а?
  options:
    - Ничем
    - Любое приложение может запросить это разрешение и обойти защиту
    - Он шифрует данные
    - Он отключает сеть
  answer: 1
  explanation: normal-разрешение выдаётся без проверки подписи.
- question: Как отправить рассылку только внутри своего процесса?
  options:
    - sendBroadcast
    - LocalBroadcastManager/локальная регистрация
    - sendStickyBroadcast
    - am broadcast
  answer: 1
  explanation: Локальные рассылки не покидают процесс и не перехватываются извне.
- question: Чем ordered-рассылка отличается от обычной?
  options:
    - Она шифруется
    - Доставляется по очереди по приоритету, каждый может изменить результат
    - Она не доставляется
    - Она только системная
  answer: 1
  explanation: Порядок и возможность подмены результата дают дополнительную поверхность.
```

## Где пригодится

- Аудит broadcast receiver-ов в Android-приложении.
- Bug bounty: незащищённые receiver-ы.
- CTF Mobile: принудительная команда через am broadcast.
