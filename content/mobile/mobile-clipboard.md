---
id: mobile-clipboard
title: "Утечки через буфер обмена и другие side-channels"
category: mobile
parent: mobile-sidechannels
difficulty: easy
order: 1
tags: [clipboard, side-channel, leak, keyboard, android, ios, privacy]
prerequisites: [mobile-insecure-storage]
useful_for:
  - "CTF Mobile (перехват секрета через clipboard)"
  - "Bug bounty (утечка данных между приложениями)"
  - "Пентест мобильных приложений"
estimated_minutes: 20
summary: "Как буфер обмена, сторонние клавиатуры и системные side-channels раскрывают пароли/токены, как это эксплуатировать и как находить в приложениях."
lab:
  kind: shell
  title: 'Практика: утечка через буфер обмена'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, decoded]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Ищи в коде `ClipboardManager.setPrimaryClip` — данные копируются в общий буфер.'
    - 'Любое приложение может прочитать буфер обмена.'
    - 'Найди строку с секретом и запиши `nto{` в `found.txt`.'
---

## Вопрос, с которого всё начинается

В прошлом уроке мы искали секреты на диске. Но есть данные, которые на диск не попадают вообще — они живут в **буфере обмена**. Скопировал пользователь seed-фразу или пароль — и эта строка стала доступна другим приложениям. Как понять, кладёт ли приложение секрет в буфер, и как это доказать?

## Наш пример: fdroid.apk

Возьмём реальный APK `fdroid.apk` и его функцию копирования в буфер. Декодируем APK и найдём, кто вызывает `setPrimaryClip`:

```
$ apktool d -f -o fdroid_dec fdroid.apk
I: Baksmaling classes.dex...
I: Baksmaling classes2.dex...

$ grep -rl "setPrimaryClip" fdroid_dec/smali*
fdroid_dec/smali/androidx/compose/ui/platform/AndroidClipboardManager.smali
fdroid_dec/smali_classes2/org/fdroid/fdroid/Utils.smali
```

Нас интересует второй файл — это код самого приложения. Откроем метод `copyToClipboard`:

```
.method public static copyToClipboard(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;I)V
    ...
    invoke-static {p1, p2}, Landroid/content/ClipData;->newPlainText(...)Landroid/content/ClipData;
    move-result-object p1
    invoke-virtual {v0, p1}, Landroid/content/ClipboardManager;->setPrimaryClip(Landroid/content/ClipData;)V
    .line 405
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I
    const/16 p2, 0x21
    if-ge p1, p2, :cond_1
```

Разберём, что тут происходит.

## Шаг 1: как устроен буфер обмена

Буфер обмена в Android — это системный сервис, доступный через `ClipboardManager`. В буфер кладут объект `ClipData` (в нашем примере созданный `ClipData.newPlainText(...)` — обычный текст). Затем `setPrimaryClip(...)` отправляет его в системный буфер.

Ключевое свойство: **буфер общий для всего устройства**. Строка, которую положило одно приложение, может быть прочитана другим. Именно поэтому в буфер нельзя класть секреты.

## Шаг 2: почему в этом коде есть проверка версии

`0x21` — это 33, то есть Android 13. Смотрим условие: `if-ge p1, p2, :cond_1` — «если версия меньше 33, перейти в `cond_1`». Значит, для Android 13+ выполняется дополнительный код, который помечает клип как чувствительный. Это стандартный приём:

```java
ClipData clip = ClipData.newPlainText(label, text);
clip.getDescription().setExtras(new PersistableBundle());
// на Android 13+ помечаем как sensitive:
clip.getDescription().getExtras().putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
```

`EXTRA_IS_SENSITIVE` подсказывает системе, что содержимое не надо показывать в превью буфера. Это **правильная практика**. Если приложение копирует токены, но не ставит этот флаг — уже находка.

## Шаг 3: ищем опасную запись в своём коде

Чтобы проверить конкретное приложение, ищем все места записи в буфер:

```
$ grep -rn "setPrimaryClip\|ClipData.newPlainText" fdroid_dec/smali*
```

Смотрим, что именно копируется: `p2` в нашем примере — это переданная строка. Если приложение вызывает `copyToClipboard(context, "seed", seedPhrase)` — секрет уходит в общий буфер. Если это безобидный URL репозитория — не находка.

Дальше проверяем, **помечен ли клип как чувствительный**. Отсутствие `EXTRA_IS_SENSITIVE` при копировании пароля/seed — валидная проблема.

## Шаг 4: подтверждаем в динамике

Статики мало: надо доказать, что секрет реально попадает в буфер. Проще всего — хуком Frida на запись:

```javascript
Java.perform(function () {
  var CM = Java.use('android.content.ClipboardManager');
  CM.setPrimaryClip.implementation = function (clip) {
    try {
      var t = clip.getItemAt(0).coerceToText(
        Java.use('android.app.ActivityThread').currentApplication()
      ).toString();
      console.log('[clipboard write] ' + t);
    } catch (e) { console.log('[clipboard write] <non-text>'); }
    return this.setPrimaryClip(clip);
  };
});
```

Хук печатает всё, что приложение кладёт в буфер. Если там оказывается токен — находка подтверждена. Параллельно смотрим логи:

```
$ adb logcat | grep -iE 'password|token|otp|secret|clipboard'
```

## Шаг 5: соседние каналы — экран и уведомления

Буфер — не единственный «боковой канал». Проверим ещё два.

**Скриншоты.** Флаг `FLAG_SECURE` (`WindowManager.LayoutParams.FLAG_SECURE`) запрещает снимки экрана и превью в переключателе задач. Если на экране с CVV или seed его нет — содержимое можно снять:

```
$ adb shell screencap -p /sdcard/s.png
$ adb pull /sdcard/s.png
```

Если на чувствительном экране видно данные — `FLAG_SECURE` не выставлен.

**Уведомления.** Текст уведомлений виден на экране блокировки. Проверяем, что в них попадает:

```
$ adb shell dumpsys notification --noredact | grep -iE 'text|title' | head
```

OTP или сумма операции в уведомлении, видимом на локскрине, — утечка.

## Шаг 6: iOS — UIPasteboard

На iOS аналог буфера — `UIPasteboard.general`. Запись открыта всем, чтение чужого буфера с iOS 16 требует подтверждения пользователя. Ищем в бинарнике:

```
$ strings Payload/App.app/App | grep -i "UIPasteboard"
```

Запись секрета (`[UIPasteboard generalPasteboard].string = @"seed";`) — такая же находка, как на Android.

## Полный прогон от начала до конца

Соберём проверку буфера в один сценарий на нашем `fdroid.apk`:

1. **`apktool d`** — декодируем APK и ищем `setPrimaryClip`.
2. **Читаем найденный метод** — понимаем, что именно копируется и есть ли `EXTRA_IS_SENSITIVE`.
3. **Запускаем приложение** под Frida с хуком на `setPrimaryClip` — видим реальные строки.
4. **Нажимаем «копировать»** в интерфейсе — в консоли хука появляется содержимое клипа.
5. **Оцениваем чувствительность** — токен/пароль/seed → находка; URL → нет.
6. **Дополняем** проверкой `FLAG_SECURE` и уведомлений на локскрине.

Так статика (что ищем) соединяется с динамикой (что реально утекло), и находка становится доказуемой.

## Если не сработало

Иногда канал закрыт или условия другие — вот что проверять:

- **С Android 10 фоновое чтение буфера ограничено.** Приложение, которое просто сидит в фоне, чужой клип не прочитает — ему нужен фокус. Если ваш PoC-наблюдатель ничего не ловит, выведите его на передний план.
- **Клип помечен `EXTRA_IS_SENSITIVE`.** Тогда система не покажет содержимое в превью, но строка всё ещё лежит в буфере. Проверяйте не превью, а сам клип хуком.
- **Буфер очищается.** Хорошие приложения сами чистят клип через `clearPrimaryClip()` после вставки. Если чистит — окно утечки меньше, но запись всё равно была.
- **Секрета нет в буфере — ищите в логах и снапшотах.** Side-channels многоканальны: `logcat`, превью задач, уведомления. Если буфер чист, переходите к ним.
- **На iOS чтение чужого буфера требует подтверждения.** Поэтому на iOS чаще ищут именно **запись** секрета, а не чтение.

## Другие side-channels вокруг буфера

- **Клавиатуры.** Сторонняя IME видит все нажатия. Пароль, введённый в поле без `isSecureTextEntry`/`textContentType=password`, может попасть в словарь клавиатуры.
- **Accessibility-сервисы.** Служба спецвозможностей читает содержимое экрана — это легальный API, которым злоупотребляют.
- **Кэш и снапшоты.** `cacheDir` и превью задач без `FLAG_SECURE` хранят картинку экрана.
- **Тайминги.** По времени ответа иногда угадывают корректность OTP — микро-утечка, но в CTF встречается.

## Что мы теперь знаем

По-простому:

1. Буфер обмена общий для устройства — запись видят другие приложения.
2. `ClipData.newPlainText` + `setPrimaryClip` кладут строку в буфер.
3. `EXTRA_IS_SENSITIVE` (Android 13+) помечает клип как секрет — его отсутствие при копировании пароля это проблема.
4. `FLAG_SECURE` защищает экран от скриншотов и превью задач.
5. Хук Frida на `setPrimaryClip` — простой способ подтвердить утечку.

## На что смотреть дальше

- **Ищите, что копируется:** URL — норма, пароль/seed/OTP — нет.
- **Проверяйте `EXTRA_IS_SENSITIVE`:** если флага нет, клип видно в превью буфера.
- **Снимайте скриншоты** чувствительных экранов: нет `FLAG_SECURE` — нет защиты.
- **Смотрите уведомления на локскрине:** OTP и суммы там лишние.

## Квиз

Проверь себя.

```quiz
- question: "Почему буфер обмена опасен для секретов?"
  options:
    - "Он общий и доступен другим приложениям"
    - "Он шифруется"
    - "Он очищается сам через минуту"
    - "Он хранит только картинки"
  answer: 0
- question: "Какой флаг Android защищает экран от скриншотов и превью задач?"
  options:
    - "FLAG_SECURE"
    - "FLAG_KEEP_SCREEN_ON"
    - "FLAG_NOT_TOUCHABLE"
    - "FLAG_ACTIVITY_NEW_TASK"
  answer: 0
- question: "Какой API помечает чувствительный клип в Android 13+?"
  options:
    - "ClipDescription.EXTRA_IS_SENSITIVE"
    - "ClipData.SECRET"
    - "EXTRA_SECURE"
    - "setSensitive()"
  answer: 0
- question: "Какой командой смотреть логи приложения на предмет секретов?"
  options:
    - "adb logcat | grep -iE 'password|token|otp'"
    - "adb install app.apk"
    - "adb reboot"
    - "adb devices"
  answer: 0
- question: "Что такое сторонняя клавиатура как канал утечки?"
  options:
    - "Она видит все нажатия при вводе"
    - "Она шифрует ввод"
    - "Она не имеет доступа к экрану"
    - "Она работает только офлайн"
  answer: 0
```

## Куда дальше

Мы разобрали буфер обмена и защиту экрана. В следующем уроке — **биометрия**: как приложения используют `BiometricPrompt` и почему проверку «свой/чужой» часто можно обойти, потому что результат возвращается в клиент, а не на сервер. А пока запомни главное: буфер общий, и всё, что в него кладут, надо помечать как sensitive — или не класть вовсе.

## Где пригодится

- **CTF Mobile:** задачи, где флаг проходит через буфер обмена или логи.
- **Bug bounty:** утечка данных между приложениями — валидная находка (privacy).
- **Пентест:** проверка защищённости секретов в клиенте.
- **Работа:** ревью приватности приложений (банки, кошельки, мессенджеры).
