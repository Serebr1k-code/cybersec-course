---
id: mobile-broadcast-receivers
title: "Broadcast Receivers и злоупотребление Intent-ами"
category: mobile
parent: mobile-exported-components
difficulty: medium
order: 2
tags: [broadcast, receiver, intent, exported, android, ipc]
prerequisites: [mobile-exported-components]
useful_for:
  - "CTF Mobile (запуск receiver/получение флага)"
  - "Bug bounty (злоупотребление экспортированными receiver)"
  - "Пентест мобильных приложений"
estimated_minutes: 30
summary: "Как экспортированные Broadcast Receivers позволяют другим приложениям запускать логику, отправлять поддельные события и утекать данные, и как это тестировать через adb."
lab:
  kind: shell
  title: 'Практика: незащищённый BroadcastReceiver'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, decoded]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`decoded/` — распакованный APK. Ищи экспортированные receiver-ы.'
    - 'Один receiver принимает действие и возвращает секрет через `putExtra`.'
    - 'Секрет зашит в smali/java этого receiver-а — найди `nto{` и запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

Приложение должно реагировать на события системы: подключили зарядку, пришло уведомление, обновились данные. Для этого служат **Broadcast Receivers** — компоненты, принимающие broadcast-сообщения. Если receiver экспортирован, такое сообщение может послать кто угодно. Что из этого следует?

## Наш пример: receivers в fdroid.apk

Посмотрим, какие receivers объявлены в манифесте `fdroid.apk`:

```
$ grep -oE '<receiver[^>]*android:name="[^"]*"[^>]*' fdroid_dec/AndroidManifest.xml \
    | sed -E 's/.*android:name="([^"]*)".*/\1/' | sort -u
androidx.work.impl.background.systemalarm.RescheduleReceiver
androidx.work.impl.diagnostics.DiagnosticsReceiver
androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver
org.fdroid.fdroid.nearby.UsbDeviceAttachedReceiver
org.fdroid.fdroid.nearby.UsbDeviceDetachedReceiver
org.fdroid.fdroid.nearby.UsbDeviceMediaMountedReceiver
org.fdroid.install.UnarchivePackageReceiver
org.fdroid.updates.SelfUpdateReceiver
```

Большинство из них `exported="false"` — только внутренние. Но один особенный:

```
$ grep -oE '<receiver[^>]*DiagnosticsReceiver[^>]*' fdroid_dec/AndroidManifest.xml
<receiver android:exported="true" android:name="androidx.work.impl.diagnostics.DiagnosticsReceiver"
          android:permission="android.permission.DUMP"/>
```

Разберём, что здесь важно.

## Шаг 1: что такое BroadcastReceiver

Receiver — это «обработчик событий». Приложение объявляет: «я слушаю такие-то broadcast-сообщения». Когда сообщение приходит, вызывается `onReceive()`. Broadcast бывают двух видов:

- **Implicit** — без указания получателя; система доставляет всем, кто слушает действие (`action`).
- **Explicit** — указан конкретный компонент.

Именно implicit-сообщения позволяют чужим приложениям «пинать» чужой receiver.

## Шаг 2: как понять, что receiver экспортирован

Правила те же, что для компонентов вообще:

- `exported="true"` — открыт всем.
- Есть `intent-filter`, а `exported` не указан — считается экспортированным.

У F-Droid `DiagnosticsReceiver` явно `exported="true"`. Но обратим внимание на вторую строку — `android:permission="android.permission.DUMP"`. Это **защита**: чтобы послать broadcast этому receiver, отправитель должен иметь разрешение `DUMP`, которое есть только у привилегированных процессов. То есть формально открытый receiver фактически закрыт.

## Шаг 3: проверяем отправкой broadcast

Убедиться, что receiver реагирует и как, можно из adb:

```
$ adb shell am broadcast -n org.fdroid.fdroid/androidx.work.impl.diagnostics.DiagnosticsReceiver
Broadcasting: Intent { cmp=org.fdroid.fdroid/androidx.work.impl.diagnostics.DiagnosticsReceiver }
java.lang.SecurityException: Permission Denial: ... requires android.permission.DUMP
```

Отлично — система отказала: у оболочки нет `DUMP`. Если бы разрешения не было, команда прошла бы, и мы получили бы поведение receiver без всякой проверки.

## Шаг 4: чем опасен экспортированный receiver

Типичные последствия:

- **Утечка данных.** Receiver отвечает на запрос данными (токен, статус, конфиг) и отправляет их обратно через broadcast или запись в файл.
- **Выполнение действия.** Receiver запускает синхронизацию, удаление, установку — без проверки отправителя.
- **Intent spoofing.** Чужое приложение шлёт поддельное сообщение, прикидываясь системой.
- **Confused deputy.** Receiver сам имеет привилегии и выполняет действие от имени вызывающего.

## Шаг 5: ordered broadcast и priority

Broadcast бывают обычные и **ordered** (по очереди). В ordered-режиме получатели вызываются по приоритету (`android:priority`), и один может «съесть» сообщение, не дав дойти до остальных. Если receiver с высоким приоритетом экспортирован, чужое приложение может перехватить или подавить системные события — например, скрыть уведомление об обновлении.

## Шаг 6: правильная защита

Как делают безопасно:

- `android:exported="false"` — по умолчанию для внутренних receivers.
- `android:permission` — требуют у отправителя конкретное разрешение (как `DUMP` у F-Droid).
- **Локальный broadcast** (`LocalBroadcastManager`) — вообще не покидает процесс.
- **Проверка отправителя** в `onReceive()` по `getSendingUid()`.

Отсутствие любого из этих механизмов у чувствительного receiver — находка.

## Полный прогон от начала до конца

Соберём проверку receiver в один сценарий:

1. **`grep <receiver>`** — собираем все receivers из манифеста.
2. **Отмечаем экспортированные** (`exported="true"` или `intent-filter`).
3. **Проверяем `android:permission`** — есть ли защита.
4. **Пробуем `am broadcast -n`** — реакция или `Permission Denial`.
5. **Читаем `onReceive()`** — какие действия и данные.
6. **Пробуем подделать данные** broadcast, если receiver их принимает.
7. **Фиксируем** результат и severity.

Если receiver защищён разрешением — это не находка; если нет и он что-то делает — находка.

## Если не сработало

- **`Permission Denial`.** Receiver защищён `android:permission`. Проверьте, нет ли у вашего приложения этого разрешения (обычно нет).
- **Receiver не реагирует на explicit broadcast.** Возможно, он слушает implicit `action` — попробуйте `am broadcast -a <action>`.
- **Действие требует авторизации.** Сначала войдите, потом повторяйте.
- **Receiver работает только в foreground.** Некоторые события приходят, лишь когда приложение активно.
- **Ничего не видно в логах.** Добавьте `logcat`-фильтр по имени receiver или хукайте `onReceive` через Frida.

## Что фиксировать в отчёте

- **Имя и тип receiver**, экспортирован ли.
- **Есть ли `android:permission`** — корневой момент.
- **Какое действие выполняется** и с какими данными.
- **Рекомендации:** `exported="false"`, разрешение, `LocalBroadcastManager`, проверка `getSendingUid`.

## Частые вопросы

**«Любой receiver опасен?»** — нет, только экспортированный и выполняющий действие. **«Что если есть intent-filter, а exported не указан?»** — компонент всё равно экспортирован. **«Как защитить?»** — `exported="false"`, `android:permission` или `LocalBroadcastManager`. **«Можно ли перехватить системный broadcast?»** — да, если ваш receiver имеет высокий приоритет в ordered-режиме. **«Как найти цель?»** — grep по `<receiver>` в манифесте и чтение `onReceive()`.

## Практический совет

Receiver — это «удалённый вызов метода» для чужого приложения. Поэтому смотрите на него как на API-эндпоинт: какие данные принимает, что с ними делает, кого проверяет. Если проверки вызывающего нет и действие значимо — фиксируйте. Разрешение `android:permission` — самый частый и самый надёжный барьер; его отсутствие сразу выделяет receiver из списка.

## Confused deputy: почему это важно

Самая интересная атака через receiver — **confused deputy** («сбитый с толку посредник»). Receiver принадлежит приложению с привилегиями: у него есть доступ к файлам, сети, другим компонентам. Если он принимает broadcast извне и выполняет действие, не проверяя, кто его послал, чужое приложение может использовать привилегии receiver в своих целях. Это как если бы у вас был сотрудник, который по любой записке от незнакомца открывает сейф.

Например, receiver, который по broadcast «обнови базу», запускает загрузку по URL из того же сообщения. Атакующий посылает свой URL — и приложение качает и устанавливает его содержимое. Формально у атакующего прав нет, но он действует руками привилегированного компонента.

Защита от confused deputy — всегда проверять источник: `getSendingUid()`, `android:permission` или `LocalBroadcastManager`. Если в `onReceive()` нет ни одной такой проверки, а действие значимо, — это уязвимость класса high.

## Receiver против других компонентов

Сравним каналы: Activity требует явного запуска пользователем или `am start`; Service — привязки или запуска; Provider — запроса по URI. Receiver уникален тем, что срабатывает **сам**, по событию, и не требует ни пользователя, ни соединения. Именно поэтому он удобен для атак: атакующему достаточно один раз послать broadcast, а дальше компонент выполнит действие в своём контексте. Отсюда и правило: receiver — это удалённый вызов метода, доступный другим приложениям.

## Что мы теперь знаем

По-простому:

1. BroadcastReceiver принимает broadcast-сообщения от системы и приложений.
2. Экспортированный receiver можно «пнуть» извне через `am broadcast`.
3. `android:permission` защищает receiver, требуя разрешение у отправителя.
4. Опасности: утечка данных, выполнение действия, spoofing, confused deputy.
5. Правильная защита: `exported="false"`, разрешение, локальный broadcast, проверка отправителя.

## На что смотреть дальше

- **Соберите все receivers** из манифеста и отметьте экспортированные.
- **Проверяйте `android:permission`** — есть ли защита.
- **Смотрите, что делает `onReceive()`** — какие действия и данные.
- **Помните про ordered broadcast** и приоритеты — перехват событий.

## Справочная таблица: флаги и защита receiver

Разные механизмы защиты receiver дают разный уровень стойкости. Сведём их вместе, чтобы быстро оценивать находку:

| Механизм | Что защищает | Обходится ли |
|----------|--------------|--------------|
| `android:exported="false"` | receiver недоступен извне | нет (кроме системных багов) |
| `android:permission="..."` | требует разрешение у отправителя | да, если разрешение слабое/выдаётся всем |
| `LocalBroadcastManager` | broadcast не покидает процесс | нет, но не покрывает системные события |
| проверка `getSendingUid()` в `onReceive` | пускает только доверенных отправителей | да, если сравнивает с константой, а не с реальным uid |
| `android:exported="true"` без всего | ничего | тривиально |

Красный флаг — `exported="true"` **и** отсутствие `android:permission` **и** значимое действие в `onReceive()`. Если разрешение есть, но оно из класса `normal` (выдаётся любому приложению автоматически), защита формальная: смотрите его `protectionLevel` в манифесте объявителя.

## Перехват onReceive через Frida

Когда непонятно, реагирует ли receiver на ваши broadcast'ы и какие данные доходят до `onReceive`, поставьте хук:

```javascript
Java.perform(function () {
  var R = Java.use('android.content.BroadcastReceiver');
  R.onReceive.implementation = function (ctx, intent) {
    console.log('[onReceive] ' + this.getClass().getName() + ' action=' + intent.getAction());
    console.log('  extras=' + intent.getExtras());
    return this.onReceive(ctx, intent);
  };
});
```

Так вы видите, дошёл ли explicit broadcast до конкретного класса, какой `action` пришёл и какие extras содержатся. Если хук не срабатывает — либо receiver не достигнут (не тот `action`, не тот компонент), либо его защищает разрешение. Дополнительно можно логировать `getSendingUid()` внутри `onReceive`, чтобы понять, проверяет ли приложение отправителя вообще.

## Ограничения и ложные срабатывания

Три частые ошибки при оценке receiver. Первая — принять **любой** экспортированный receiver за уязвимость: системные receivers (`BOOT_COMPLETED`, `PACKAGE_ADDED`) экспортированы штатно и ничего не раскрывают, если не выполняют привилегированное действие. Вторая — не проверить `android:permission`: receiver с `permission="android.permission.DUMP"` формально открыт, но фактически недостижим, и `am broadcast` вернёт `Permission Denial` — это не находка. Третья — принять `Permission Denial` за «сломано»: на самом деле это признак корректной защиты. Также помните: начиная с Android 8 implicit broadcast'ы для большинства `action` ограничены, поэтому «отправить любой action и ждать реакции» уже не работает — используйте explicit broadcast с указанием компонента (`-n pkg/.Receiver`). И проверяйте, что действие, выполняемое `onReceive`, реально значимо: receiver, который лишь пишет строку в лог, не даёт impact.

## Квиз

Проверь себя.

```quiz
- question: "Что такое BroadcastReceiver?"
  options:
    - "Компонент, принимающий broadcast-сообщения"
    - "Экран приложения"
    - "База данных"
    - "Нативная библиотека"
  answer: 0
- question: "Как «пнуть» экспортированный receiver из adb?"
  options:
    - "adb shell am broadcast -n pkg/.Receiver"
    - "adb install app.apk"
    - "adb shell pm list packages"
    - "adb push file"
  answer: 0
- question: "Какая защита делает экспортированный receiver фактически закрытым?"
  options:
    - "Атрибут android:permission с привилегированным разрешением"
    - "Длинное имя класса"
    - "Отсутствие кода"
    - "Использование HTTPS"
  answer: 0
- question: "Что может сделать чужое приложение с ordered broadcast высокого приоритета?"
  options:
    - "Перехватить или подавить событие"
    - "Ускорить систему"
    - "Расшифровать трафик"
    - "Подписать APK"
  answer: 0
- question: "Какой механизм broadcast не покидает процесс приложения?"
  options:
    - "LocalBroadcastManager"
    - "Implicit broadcast"
    - "Ordered broadcast"
    - "Sticky broadcast"
  answer: 0
```

## Куда дальше

Мы разобрали Broadcast Receivers. В следующем уроке углубимся в **Content Providers** — самый «данные-ёмкий» компонент, где ошибки в путях и SQL приводят к утечке всей базы. А пока запомни главное: экспортированный receiver без `android:permission` — это открытая дверь, которую проверяют командой `am broadcast`.

## Где пригодится

- **CTF Mobile:** вызов скрытой функциональности через broadcast.
- **Bug bounty:** экспортированный receiver с действием — находка.
- **Пентест:** проверка OWASP MASVS-PLATFORM.
- **Работа:** ревью обработчиков событий в манифесте.
