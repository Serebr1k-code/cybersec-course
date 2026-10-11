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
---
## Введение

Буфер обмена — общий системный ресурс: то, что одно приложение туда положило, потенциально читают другие. Если приложение кладёт в буфер пароль, OTP, номер карты или seed-фразу криптокошелька, вредоносное (или просто любопытное) приложение может это забрать. К этой же категории side-channels относятся пользовательские клавиатуры, логи, снапшоты задач в переключателе, уведомления и флаг `FLAG_SECURE`. Цель тестирования — найти канал, по которому секрет покидает защищённый контекст.

## Clipboard на Android

Чтение буфера требует фокуса окна (с Android 10 фоновое чтение ограничено), но вредоносное приложение может подписаться на `OnPrimaryClipChangedListener` и считать данные при следующем копировании, либо дождаться, когда получит фокус. Запись доступна всегда.

```java
// чтение буфера
ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
if (cm.hasPrimaryClip()) {
    ClipData clip = cm.getPrimaryClip();
    Log.d("leak", clip.getItemAt(0).getText().toString());
}
```

Ищите в коде приложения запись чувствительных данных:

```bash
apktool d app.apk -o out
grep -rn "setPrimaryClip\|ClipData.newPlainText\|ClipboardManager" out/smali*
```

Если банк копирует номер карты или пароль — это находка. Рекомендация: помечать клипы `ClipDescription.EXTRA_IS_SENSITIVE` (Android 13+) и не копировать секреты вовсе.

## Clipboard на iOS

`UIPasteboard.general` — общий буфер. С iOS 16 система запрашивает подтверждение при чтении чужого буфера, но запись открыта, и приложение может положить туда секрет.

```objc
[UIPasteboard generalPasteboard].string = @"secret";
NSString *s = [UIPasteboard generalPasteboard].string; // требует согласия пользователя
```

Ищите в Swift/ObjC:

```bash
strings out/Payload/*.app/* | grep -i "UIPasteboard\|pasteboard"
```

Проверьте также `UIPasteboard.general.setItems:options:` и использование `localOnly`/`expirationDate`.

## Клавиатуры, логи и снапшоты

- **Сторонние клавиатуры** имеют полный доступ к нажатиям. Ввод пароля в поле без `textContentType`/`isSecureTextEntry` может логироваться клавиатурой.
- **Логи:** `Log.d`/`NSLog` с секретами; читайте через `adb logcat` или Frida-хук `android.util.Log`.
- **Снапшоты задач:** приложение без `FLAG_SECURE` попадает в превью переключателя задач; `adb shell screencap` покажет экран.
- **Уведомления:** текст уведомления виден на локскрине (см. `mobile-notifications`).

## Обнаружение в динамике

```bash
# логи приложения на предмет секретов
adb logcat | grep -iE "password|token|otp|secret|clipboard|flag"
# дамп буфера через service call (зависит от версии Android)
adb shell service call clipboard 2 i32 1 i32 0 s16 com.android.shell
```

Frida-хук на запись/чтение clipboard:

```javascript
// Android: перехват записи
var CM = Java.use('android.content.ClipboardManager');
CM.setPrimaryClip.implementation = function (clip) {
  try {
    console.log('[clipboard write] ' + clip.getItemAt(0).getText());
  } catch (e) {}
  return this.setPrimaryClip(clip);
};
// iOS: перехват записи в pasteboard
var PB = ObjC.classes.UIPasteboard;
PB['- setString:'].implementation = ObjC.implement(PB['- setString:'], function (h, sel, s) {
  console.log('[pasteboard write] ' + new ObjC.Object(s).toString());
  return h(s);
});
```

## FLAG_SECURE и защита экрана

`FLAG_SECURE` (`WindowManager.LayoutParams.FLAG_SECURE`) запрещает скриншоты, запись экрана и снапшоты задачи. Проверка:

```bash
# сделать скриншот и посмотреть, чёрный ли он
adb shell screencap -p /sdcard/s.png
adb pull /sdcard/s.png
# если на чувствительном экране видно содержимое -> FLAG_SECURE не выставлен
```

Отсутствие `FLAG_SECURE` на экране с секретом (CVV, seed, баланс) — это находка, особенно в связке с вредоносным приложением, снимающим скриншоты.

## Разобранный пример

Приложение криптокошелька показывает seed-фразу и по кнопке «копировать» кладёт её в `ClipData`. Пентестер:

1. `grep setPrimaryClip` находит вызов.
2. Пишет listener-приложение и подтверждает, что seed попадает в общий буфер.
3. Отчёт: утечка секрета через clipboard; рекомендация — `EXTRA_IS_SENSITIVE`, автоочистка буфера, не копировать вовсе.

## Частые ошибки и подводные камни

- Считать clipboard безобидным: для seed/паролей это critical.
- Забыть про `FLAG_SECURE`: без него скриншоты и превью задач раскрывают экран.
- Проверять только факт записи, не оценивая, что именно попало в буфер.
- Игнорировать кастомные клавиатуры как отдельный канал утечки.
- Не учитывать, что на новых Android фоновое чтение ограничено — PoC нужен с фокусом.

## Справочная таблица

| Канал | Платформа | Проверка |
|-------|-----------|----------|
| Clipboard | обе | grep setPrimaryClip / UIPasteboard |
| Логи | обе | `adb logcat`, `NSLog` |
| Снапшот задачи | обе | FLAG_SECURE, screencap |
| Уведомления | обе | локскрин |
| Клавиатура | обе | сторонняя IME |
| Буфер | iOS | confirm-диалог при чтении |

## Что дальше / решение

- **Секрет в clipboard** → зафиксируйте PoC, оцените чувствительность (токен/пароль/seed).
- **Нет FLAG_SECURE на чувствительных экранах** → проверьте снапшот и `screencap`.
- **Секреты в логах** → выгрузите `logcat`, найдите строки, оформите находку.
- **Всё закрыто** → переходите к другим side-channels: уведомления, снапшоты, тайминги.
- Severity: seed/приватный ключ в буфере — High/Critical; токен/OTP — High; общий текст — Low.

## Практический PoC: listener буфера обмена

На Android можно написать минимальное приложение-наблюдатель, которое подписывается на изменения буфера и логирует содержимое. В тестовой среде это доказывает утечку:

```java
ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
cm.addPrimaryClipChangedListener(() -> {
    if (cm.hasPrimaryClip() && cm.getPrimaryClip().getItemCount() > 0) {
        CharSequence t = cm.getPrimaryClip().getItemAt(0).coerceToText(this);
        Log.d("clipwatch", "captured: " + t);
    }
});
```

На iOS проверка записи делается через Frida-хук `setString:`/`setItems:options:` (см. выше) — этого достаточно, чтобы показать, что секрет попадает в общий pasteboard.

## Другие side-channels

Помимо clipboard и логов, секреты утекают через:

- **Кэш клавиатуры и автодополнение:** ввод секрета в поле без `isSecureTextEntry`/`textContentType=password` может попасть в словарь клавиатуры.
- **Тайминги:** по времени ответа иногда можно угадать корректность секрета (например, поэтапная проверка OTP). Микро-утечка, но в CTF встречается.
- **Кэш/снапшоты:** `cacheDir`, превью задач, «recent apps» без `FLAG_SECURE`.
- **Буфер между профилями/приложениями:** общий pasteboard доступен всем приложениям устройства.
- **Clipboard через accessibility:** сервис специальных возможностей может читать содержимое экрана и буфера.
- **Логи системы:** `logcat -b all` иногда содержит больше, чем основной буфер.

## Проверка чувствительных полей

```bash
# ищем поля без защиты от копирования/скриншотов
grep -rn "setTextIsSelectable\|isSecureTextEntry\|textContentType" out/ | head
```

Правильная практика: для паролей/seed — запрет копирования, `FLAG_SECURE` на экране, очистка буфера после использования, отсутствие логирования. Отсутствие любого из этих пунктов — потенциальная находка, которую надо подтвердить PoC.

## Уведомления и локскрин

Текст уведомления часто виден на экране блокировки, а в push-уведомлениях нередко оказываются OTP, суммы операций, имена отправителей. Проверка:

```bash
# Android: содержимое уведомлений (иногда с --noredact)
adb shell dumpsys notification --noredact | grep -iE "text|title|ticker" | head -40
```

Если приложение помещает OTP или чувствительные данные в уведомление, которое видно на локскрине, — это утечка. Правильная практика: `setVisibility(VISIBILITY_SECRET)`, скрытие текста на локскрине, использование публичной версии уведомления.

## Снимки экрана, запись экрана и кэш

- **Скриншоты:** без `FLAG_SECURE` любой экран можно снять (`screencap`) или записать (media projection). Проверьте чувствительные экраны (CVV, seed, баланс).
- **Recent apps:** превью в переключателе задач формируется системой; `FLAG_SECURE` исключает его.
- **Кэш:** секреты могут оседать в `cacheDir`, в изображениях/`SharedPreferences` бэкапа.
- **Автозаполнение:** сохранённые пароли в менеджере паролей/клавиатуре.

```bash
adb shell screencap -p /sdcard/s.png && adb pull /sdcard/s.png
adb shell dumpsys window | grep -i "FLAG_SECURE" | head
```

## Матрица severity для side-channels

| Канал | Пример секрета | Severity |
|-------|----------------|----------|
| Clipboard | seed, приватный ключ | Critical |
| Clipboard | OTP, токен | High |
| Логи | пароль/токен | High |
| Уведомление на локскрине | OTP/сумма | Medium |
| Отсутствие FLAG_SECURE | баланс/CVV | Medium |
| Сторонняя клавиатура | ввод пароля | Medium/High |

## Что делать дальше

- Подтвердите каждый канал PoC-ом (listener/хук/скриншот).
- Оцените, может ли вредоносное приложение на устройстве этим воспользоваться без дополнительных условий.
- Оформите рекомендации: запрет копирования секретов, `EXTRA_IS_SENSITIVE`, автоочистка буфера, `FLAG_SECURE`, отказ от логирования секретов, защита от скриншотов на всех чувствительных экранах.

## Квиз

```quiz
- question: "Почему буфер обмена опасен для секретов?"
  options:
    - "Он общий и доступен другим приложениям"
    - "Он шифруется"
    - "Он очищается сам через минуту"
    - "Он хранит только картинки"
  answer: 0
  explanation: "Clipboard — общий ресурс; запись видят другие приложения."
- question: "Какой флаг Android защищает экран от скриншотов и превью задач?"
  options:
    - "FLAG_SECURE"
    - "FLAG_KEEP_SCREEN_ON"
    - "FLAG_NOT_TOUCHABLE"
    - "FLAG_ACTIVITY_NEW_TASK"
  answer: 0
  explanation: "FLAG_SECURE блокирует скриншоты и снапшоты задачи."
- question: "Какой API помечает чувствительный клип в Android 13+?"
  options:
    - "ClipDescription.EXTRA_IS_SENSITIVE"
    - "ClipData.SECRET"
    - "EXTRA_SECURE"
    - "setSensitive()"
  answer: 0
  explanation: "Extra-флаг подсказывает системе скрыть содержимое превью."
- question: "Что такое сторонняя клавиатура как канал утечки?"
  options:
    - "Она видит все нажатия при вводе"
    - "Она шифрует ввод"
    - "Она не имеет доступа к экрану"
    - "Она работает только офлайн"
  answer: 0
  explanation: "Клавиатура с полным доступом может логировать вводимые данные."
- question: "Какой командой смотреть логи приложения на предмет секретов?"
  options:
    - "adb logcat | grep -iE 'password|token|otp'"
    - "adb install app.apk"
    - "adb reboot"
    - "adb devices"
  answer: 0
  explanation: "logcat отдаёт логи; фильтр по ключевым словам выявляет утечки."
```

## Где пригодится

- **CTF Mobile:** задачи, где секрет/флаг проходит через буфер обмена или логи.
- **Bug bounty:** утечка данных между приложениями — валидная находка (privacy).
- **Пентест:** проверка защищённости секретов в клиенте.
- **Работа:** ревью приватности приложения (банки, кошельки, мессенджеры).
