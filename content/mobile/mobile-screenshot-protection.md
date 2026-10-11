---
id: mobile-screenshot-protection
title: "Защита от скриншотов (FLAG_SECURE) и её обход"
category: mobile
parent: mobile-app-protection
difficulty: medium
order: 1
tags: [mobile, android, flag-secure, screenshot, ui]
prerequisites: [mobile-android-components]
useful_for:
  - "CTF Mobile: обход защит интерфейса"
  - "Пентест: анализ защищённых экранов"
estimated_minutes: 40
summary: "Как работает FLAG_SECURE, зачем приложения запрещают скриншоты и запись экрана, какие есть обходы (хук флагов окна, Magisk-модули, Frida) и как проверить защиту."
---

## Что такое FLAG_SECURE и зачем он нужен

`FLAG_SECURE` — это флаг окна Android (`WindowManager.LayoutParams.FLAG_SECURE`), который запрещает системе делать скриншоты и записывать экран для этого окна, а также прячет содержимое окна в списке недавних приложений (recents) и блокирует передачу на «небезопасные» внешние дисплеи. Когда банковское приложение показывает баланс, оно ставит `FLAG_SECURE`, чтобы данные не попали в скриншот, в запись экрана или в превью таск-менеджера.

С точки зрения безопасности это защита «от случайного» и «от вредоносного скриншотера». Но это **клиентская** защита: приложение просит систему не снимать экран. Значит, на устройстве с рутом или с инструментацией защиту можно снять. Для пентестера задача обычно обратная: не обойти защиту, а **проверить**, что она действительно стоит на всех чувствительных экранах — потому что очень часто разработчик забыл поставить флаг на одном из них, и данные утекают в превью или в запись.

## Как ставится и снимается флаг

```java
// включить защиту
getWindow().setFlags(
    WindowManager.LayoutParams.FLAG_SECURE,
    WindowManager.LayoutParams.FLAG_SECURE);

// выключить
getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
```

В XML темы: `android:windowIsSecure="true"` (устаревшее). В Compose: `window.setFlags(...)` в `Activity`. Часто флаг ставят только на `onResume` и снимают на `onPause`, поэтому важно проверять в разных состояниях.

## Проверка: есть ли защита

Быстрая проверка — попробовать сделать скриншот через adb:

```bash
adb shell screencap -p /sdcard/shot.png
adb pull /sdcard/shot.png
```

Если защита стоит — на месте защищённого окна будет чёрный прямоугольник. Аналогично `adb shell screenrecord /sdcard/rec.mp4` — защищённые окна будут чёрными.

Программная проверка флагов через Frida:

```javascript
Java.perform(function () {
  var Activity = Java.use("android.app.Activity");
  Activity.setFlags.implementation = function (flags, mask) {
    console.log("[setFlags] flags=" + flags + " mask=" + mask +
      " SECURE=" + ((flags & 0x2000) !== 0));
    return this.setFlags(flags, mask);
  };
  var LP = Java.use("android.view.WindowManager$LayoutParams");
  console.log("FLAG_SECURE const = " + LP.FLAG_SECURE.value);
});
```

```bash
frida -U -f com.example.bank -l check_secure.js --no-pause
```

Смотрим, на каких экранах `SECURE=true`. Если банковский экран показывает `SECURE=false` — это находка: чувствительные данные не защищены.

## Обход защиты: хук clearFlags/setFlags

Классический обход — заставить `clearFlags` всегда снимать `FLAG_SECURE`, а `setFlags` — никогда не ставить:

```javascript
Java.perform(function () {
  var Activity = Java.use("android.app.Activity");

  Activity.setFlags.implementation = function (flags, mask) {
    // вырезаем бит FLAG_SECURE (0x2000)
    flags = flags & ~0x2000;
    mask  = mask  & ~0x2000;
    return this.setFlags(flags, mask);
  };

  Activity.clearFlags.implementation = function (flags) {
    return this.clearFlags(flags);
  };

  // некоторые используют Window.addFlags
  var Window = Java.use("android.view.Window");
  Window.addFlags.implementation = function (flags) {
    flags = flags & ~0x2000;
    return this.addFlags(flags);
  };
});
```

Если приложение ставит флаг в конструкторе окна (до того, как Frida успела подключиться), используйте `-f` (spawn) и `--no-pause`, чтобы хук встал до `onCreate`. Для нативных окон (SurfaceView, video) флаг может ставиться через `nativeSetFlags` — тогда хукаем `WindowManager` или пропатчиваем `libandroid_runtime`.

## Обход через Magisk/LSPosed

На рутованном устройстве есть готовые модули, которые глобально снимают `FLAG_SECURE` (например, «Disable FLAG_SECURE»). LSPosed-модуль перехватывает вызовы и убирает бит для выбранных приложений. Это удобно, когда приложение анти-Frida и хуки Frida палятся:

```bash
# установить LSPosed (Zygisk), включить модуль, выбрать target-приложение
# перезапустить приложение
adb shell screencap -p /sdcard/shot.png   # теперь скриншот виден
```

Важно: снятие флага — это не взлом приложения, а снятие барьера для анализа. Данные, которые вы увидите, и так были на экране у пользователя; вы лишь делаете их доступными инструментам.

## Защита от записи экрана и recents

`FLAG_SECURE` покрывает и запись экрана, и превью в recents. Но есть отдельные механизмы:
- **`setRecentsScreenshotEnabled(false)`** (Android 13+) — отдельно отключает превью в недавних.
- **`setHideOverlayWindows(true)`** (Android 12+) — запрещает оверлеи (защита от tapjacking).
- **Блокировка скриншотера через `MediaProjection`** — приложение отказывается давать проекцию экрана.

Проверяйте эти вызовы статически (`grep -r "setRecentsScreenshotEnabled\|setHideOverlayWindows"`) и динамически.

## Утечки вопреки FLAG_SECURE

Даже с флагом данные утекают, если:
- Флаг ставится не на всех экранах (например, на экране логина нет, а на балансе есть).
- Превью генерируется до установки флага (race condition).
- Данные попадают в системный **кэш миниатюр** или в **логи**.
- Приложение показывает данные во **floating-уведомлении**, которое не защищено.
- Внешний дисплей (HDMI/DeX) не покрыт флагом на некоторых OEM-прошивках.

Поэтому корректный тест: пройти по всем экранам, снять скриншот на каждом, проверить recents и запись экрана, и отдельно — уведомления.

## Частые ошибки и подводные камни

- **Хук не сработал** — Frida подключилась после `onCreate`; используйте spawn (`-f`).
- **Скриншот всё равно чёрный** — флаг на нативном уровне или в другом процессе (например, в банковском SDK с собственным Activity).
- **LSPosed не действует** — не выбран target, или модуль не поддерживает Android-версию.
- **Скриншот виден, но recents чёрный** — разные флаги: проверьте `setRecentsScreenshotEnabled`.
- **Путаница с `FLAG_SECURE` vs `FLAG_KEEP_SCREEN_ON`** — второе лишь не даёт экрану гаснуть.

## Справочная таблица

| Механизм | Что защищает | Как проверить | Как снять |
|----------|--------------|---------------|-----------|
| FLAG_SECURE | скриншот, запись, recents | `screencap` | хук setFlags / LSPosed |
| setRecentsScreenshotEnabled(false) | превью в recents | смотреть recents | Android 13+ hook |
| setHideOverlayWindows(true) | оверлеи/tapjacking | попытка оверлея | hook Window |
| MediaProjection-отказ | запись экрана | screenrecord | перехват запроса |

## Что дальше / решение

Проверьте каждый экран на наличие флага, зафиксируйте экраны без защиты как находку (утечка данных через скриншоты/recents). Для обхода на защищённом устройстве используйте Frida-хук `setFlags` (spawn-режим) или LSPosed-модуль. Дальше — `mobile-tapjacking` (защита от оверлеев) и `mobile-data-leakage` (утечки в логах и кэше).

## Защита от скриншотов на iOS

На iOS аналогом `FLAG_SECURE` служит свойство `UITextField` с `isSecureTextEntry` (защищает от записи в буфер), а для полноценной защиты экрана используют обход через `UIScreen.main.isCaptured` и подмену отображения при захвате. Прямого системного флага, как в Android, нет — разработчики прибегают к трюкам:

```swift
// отслеживаем начало записи экрана/зеркалирования
NotificationCenter.default.addObserver(
    forName: UIScreen.capturedDidChangeNotification,
    object: nil, queue: .main) { _ in
    if UIScreen.main.isCaptured {
        self.secureView.isHidden = false   // показать «заглушку»
    } else {
        self.secureView.isHidden = true
    }
}
```

Обход на джейлбрейкнутом устройстве: хукаем `isCaptured` через Frida (iOS) или Cycript, возвращаем `false`, чтобы приложение не прятало данные. На iOS также проверяют `UIScreen.captured` в циклах — тогда хук надо ставить на геттер свойства.

## Скриншоты на уровне системы: adb, scrcpy, MediaProjection

Разные пути получения кадра обходят разные защиты:

- **`adb shell screencap`** — читает framebuffer; `FLAG_SECURE` даёт чёрный кадр.
- **`scrcpy`** — использует `MediaProjection`-подобный поток; защищённые окна тоже чёрные.
- **`MediaProjection` API** — приложение может само запрашивать проекцию, но `FLAG_SECURE` запрещает захват защищённых окон даже через него.
- **Root-скриншотеры** — читают `/dev/graphics/fb0` напрямую, но на новых Android framebuffer недоступен и защита сохраняется.

Вывод для теста: если вам нужно доказательство утечки, недостаточно показать скриншот — покажите, что защита не стояла, или снимите её хуком.

## Проверка recents и уведомлений

Отдельная зона утечек — превью в списке недавних и уведомления. С Android 13 `setRecentsScreenshotEnabled(false)` отключает превью отдельно от `FLAG_SECURE`. Проверяем так:

```bash
# открыть недавние и посмотреть, видно ли содержимое
adb shell input keyevent KEYCODE_APP_SWITCH
adb shell screencap -p /sdcard/recents.png
adb pull /sdcard/recents.png
```

Уведомления с чувствительными данными (сумма перевода, код подтверждения) часто не защищены: `setVisibility(VISIBILITY_SECRET)` скрывает их на локскрине, но не в шторке. Проверяйте, что показывает приложение в `Notification`.

## Что делать, если защита мешает анализу

Иногда флаг мешает именно вам: нужно посмотреть экран, а он чёрный. Тогда порядок действий такой:
1. Подключиться Frida в spawn-режиме с хуком `setFlags`.
2. Если анти-Frida — использовать LSPosed-модуль «Disable FLAG_SECURE».
3. Если и это блокируется — запустить приложение в multi-user или в эмуляторе, где защита может не действовать.
4. В крайнем случае — снимать данные не со скриншота, а из хранилища/памяти (что и есть настоящая цель анализа).

## Резюме по защите экрана

`FLAG_SECURE` — это барьер удобства, а не безопасности. Он полезен против скриншотеров-малвари и против случайных утечек, но полностью обходится на рутованном/инструментированном устройстве. Для пентестера главная задача — проверить полноту покрытия: все ли чувствительные экраны защищены, не утекают ли данные в recents, уведомления и логи. Найденный экран без флага — это подтверждённая находка об утечке информации.

## Квиз

```quiz
- question: "Что делает FLAG_SECURE?"
  options:
    - "Запрещает скриншоты, запись экрана и превью окна в recents"
    - "Шифрует базу данных приложения"
    - "Блокирует сетевой доступ"
    - "Ускоряет рендеринг"
  answer: 0
- question: "Почему Frida-хук setFlags надо ставить в spawn-режиме (-f)?"
  options:
    - "Чтобы хук встал до вызова onCreate, где ставится флаг"
    - "Иначе Frida не установится"
    - "Иначе телефон перезагрузится"
    - "Иначе не будет работать adb"
  answer: 0
- question: "Как проверить наличие защиты на конкретном экране?"
  options:
    - "Сделать скриншот через adb screencap и посмотреть, чёрный ли кадр"
    - "Запустить nmap"
    - "Посмотреть SHA-1 сертификата"
    - "Открыть приложение в браузере"
  answer: 0
- question: "Что из перечисленного НЕ покрывается FLAG_SECURE по умолчанию?"
  options:
    - "Содержимое стороннего floating-уведомления"
    - "Основное окно Activity"
    - "Запись экрана этой Activity"
    - "Превью окна в recents"
  answer: 0
```

## Где пригодится

- **CTF:** задачи, где флаг прячется на «защищённом» экране.
- **Пентест:** проверка, что чувствительные данные не утекают в скриншоты и recents.
- **Bug bounty:** отчёт об утечке банковских данных через превью недавних приложений.
