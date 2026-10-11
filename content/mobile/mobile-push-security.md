---
id: mobile-push-security
title: "Безопасность push-уведомлений: FCM, APNs и подмена payload"
category: mobile
parent: mobile-api-security-deep
difficulty: medium
order: 1
tags: [mobile, push, fcm, apns, notifications, firebase]
prerequisites: [mobile-firebase, mobile-notifications]
useful_for:
  - "Пентест: аудит push-канала"
  - "Bug bounty: подмена и утечка через уведомления"
estimated_minutes: 40
summary: "Как работают push-уведомления (FCM/APNs), где хранится токен, как проверить доверие к payload, подменить уведомление и найти утечки данных через push-канал."
---

## Как работает push

Push-уведомления доставляются через сервис платформы: **FCM** (Firebase Cloud Messaging) для Android, **APNs** (Apple Push Notification service) для iOS. Схема: приложение регистрируется у сервиса и получает **токен устройства** (device token / registration token); приложение отправляет токен на свой сервер; сервер при событии шлёт уведомление через FCM/APNs на этот токен; сервис доставляет его на устройство; система будит приложение или показывает уведомление.

С точки зрения безопасности интересны четыре вещи:
1. **Токен** — уникален для устройства и приложения; если утечёт, атакующий может слать push от имени сервера (в некоторых конфигурациях).
2. **Payload** — данные внутри уведомления; клиент может доверять им без проверки.
3. **Отображение** — чувствительные данные в уведомлении видны на локскрине.
4. **Обработка** — приложение может выполнять действия по данным из push (например, открывать deep link).

## FCM: настройка и токен

Android-приложение получает токен так:

```java
FirebaseMessaging.getInstance().getToken().addOnCompleteListener(task -> {
    if (!task.isSuccessful()) return;
    String token = task.getResult();
    sendTokenToServer(token);
});
```

Токен меняется (переустановка, очистка данных), поэтому приложение шлёт его на сервер при каждом изменении. Проверьте, как хранится токен и что сервер делает с ним.

Уязвимости FCM часто связаны с **Firebase-проектом**: если `google-services.json` в APK содержит API-ключ, а Realtime Database/Cloud Messaging настроены слабо, можно отправлять уведомления напрямую. Проверка:

```bash
unzip -p app.apk google-services.json | jq .
# project_id, api_key, mobilesdk_app_id
```

Если Realtime Database открыта на запись, можно подписаться на топики или читать данные (см. `mobile-firebase`).

## APNs: токен и сертификаты

На iOS приложение регистрируется:

```swift
UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) { ok, _ in
    DispatchQueue.main.async { UIApplication.shared.registerForRemoteNotifications() }
}
func application(_ app: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
    let token = deviceToken.map { String(format: "%02x", $0) }.joined()
    sendTokenToServer(token)
}
```

Сервер отправляет push через APNs, используя **ключ (p8)** или **сертификат**. Если ключ/сертификат утечёт из серверной части, атакующий может слать push от имени приложения.

## Доверие к payload

Классическая уязвимость — приложение выполняет действие по данным push без проверки источника. Например, push содержит deep link, и приложение открывает его:

```json
{
  "notification": {"title": "New message"},
  "data": {"deeplink": "myapp://open?url=https://evil.com"}
}
```

Если обработчик без валидации открывает `url` в WebView — XSS/кража токена. Проверьте, какие действия выполняет приложение по данным из push.

Frida-хук на обработку FCM:

```javascript
Java.perform(function () {
  var FCM = Java.use("com.google.firebase.messaging.FirebaseMessagingService");
  FCM.onMessageReceived.implementation = function (msg) {
    console.log("[push] from=" + msg.getFrom() + " data=" + msg.getData());
    return this.onMessageReceived(msg);
  };
});
```

Смотрите, какие ключи приходят и как они используются.

## Подмена уведомления

Если сервер использует FCM Legacy API с API-ключом из APK (или ключ утёк), можно отправить push от имени приложения:

```bash
curl -X POST https://fcm.googleapis.com/fcm/send \
  -H "Authorization: key=AIzaSy...API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "<DEVICE_TOKEN>",
    "notification": {"title": "Банк", "body": "Подтвердите перевод"},
    "data": {"deeplink": "myapp://confirm?amount=1000"}
  }'
```

Если API-ключ из APK принимается — критическая находка: любой может слать push пользователям (фишинг). Проверьте, ограничен ли ключ по package name/API.

## Утечки через уведомления

Чувствительные данные в уведомлении видны:
- на локскрине (если `setVisibility` не `SECRET`);
- в шторке;
- в истории уведомлений;
- в логах системы.

```bash
adb logcat | grep -i "NotificationManager\|statusbar"
```

Рекомендации: не включать PII/коды в текст уведомления, использовать `VISIBILITY_SECRET` на локскрине, не логировать payload.

## Топики и broadcast-уведомления

FCM поддерживает **топики** — подписка на групповые уведомления. Если приложение подписывается на топик по имени, которое можно угадать/подделать, злоумышленник может получить чужие уведомления. Проверьте:

```javascript
Java.perform(function () {
  var FCM = Java.use("com.google.firebase.messaging.FirebaseMessaging");
  FCM.subscribeToTopic.implementation = function (t) {
    console.log("[push] subscribe to " + t);
    return this.subscribeToTopic(t);
  };
});
```

Если подписка на топик возможна без аутентификации (через Firebase SDK с публичным ключом), можно получать уведомления, предназначенные группе.

## Частые ошибки и подводные камни

- **Путать FCM-ключ и server key** — из APK обычно достаётся API-ключ; проверьте, принимает ли он отправку.
- **Тест только через приложение** — отправляйте push напрямую через API.
- **Игнорировать iOS** — APNs настраивается иначе, но доверие к payload такое же.
- **Не проверять локскрин** — уведомление может светить данные на заблокированном экране.
- **Забыть про deep link в push** — это частый путь к RCE/краже токена.

## Справочная таблица

| Аспект | Android (FCM) | iOS (APNs) |
|--------|---------------|------------|
| Токен | registration token | device token |
| Отправка | HTTP v1 / legacy | HTTP/2 + p8/сертификат |
| Топики | есть | нет (есть каналы) |
| Обработка | FirebaseMessagingService | UNUserNotificationCenter |
| Риск | ключ в APK, доверие к data | доверие к payload |

## Что дальше / решение

Проверьте: как приложение получает и хранит токен; доверяет ли payload; можно ли отправить push напрямую (ключ из APK); что видно на локскрине; куда ведёт deep link из push. Подмена уведомления или выполнение действия по данным push — находка. Дальше — `mobile-deeplink-deep` и `mobile-firebase`.

## Разбор FCM-конфигурации из APK

Первый шаг — извлечь и проанализировать `google-services.json` и строковые ресурсы:

```bash
unzip -p app.apk google-services.json | jq '{project_id, api_key, mobilesdk_app_id}'
unzip -p app.apk resources.arsc | strings | grep -i "AIza" | head
```

`api_key` (`AIza...`) — это ключ, используемый клиентом для доступа к Firebase. Он не является server key, но проверьте, не ограничен ли он и не позволяет ли читать/писать в Realtime Database или Firestore. Ограничения задаются в Google Cloud Console; если их нет — база может быть открыта.

Проверка открытой базы:

```bash
curl -s "https://<project-id>.firebaseio.com/.json"
# если возвращает данные без auth — база открыта
```

## Отправка push через FCM HTTP v1

Современный FCM использует OAuth2 (service account), а не server key. Если в приложении (или на сервере) утёк service account JSON, можно отправить push:

```bash
# получить access token из service account
gcloud auth activate-service-account --key-file sa.json
TOKEN=$(gcloud auth print-access-token)
curl -X POST \
  "https://fcm.googleapis.com/v1/projects/<project-id>/messages:send" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "token": "<DEVICE_TOKEN>",
      "notification": {"title":"Update","body":"Tap to open"},
      "data": {"deeplink":"myapp://open?url=https://evil.com"}
    }
  }'
```

Если `deeplink` открывается без валидации — вы контролируете навигацию пользователя (фишинг/кража токена).

## Динамический анализ обработки уведомления

Помимо FCM-хука, перехватите обработку нажатия и deep link:

```javascript
Java.perform(function () {
  var Activity = Java.use("android.app.Activity");
  Activity.getIntent.implementation = function () {
    var i = this.getIntent();
    if (i) console.log("[intent] action=" + i.getAction() + " data=" + i.getData());
    return i;
  };
});
```

iOS — хук `userNotificationCenter:didReceiveNotificationResponse:`:

```javascript
var UN = ObjC.classes.UNUserNotificationCenter;
Interceptor.attach(UN['- userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:'].implementation, {
  onEnter: function (args) {
    var resp = new ObjC.Object(args[3]);
    console.log("[push tap] " + resp.notification().request().content().userInfo());
  }
});
```

## Утечки токена и его использование

Device token — чувствительный идентификатор. Если он утекает (логи, бэкап, сеть без TLS), атакующий может слать пользователю уведомления (если у него есть способ отправки) или связать устройство со своим аккаунтом при ошибках серверной привязки. Проверяйте:
- передаётся ли токен по HTTPS;
- не логируется ли он;
- привязывается ли он к аккаунту с проверкой владельца.

Ошибка «токен привязывается к аккаунту, который его прислал, без проверки сессии» позволяет атакующему получать уведомления чужого аккаунта.

## Резюме по push-безопасности

Push — это канал доставки управляемых данных на устройство. Проверяйте четыре точки: получение/хранение токена, доверие к payload (особенно deep link), возможность отправки от имени сервера, отображение на локскрине. Самая частая критичная находка — выполнение привилегированного действия по данным push без проверки источника.

## Итог и приоритеты проверок

Начните с извлечения `google-services.json` и проверки, не открыта ли Firebase-база и не принимается ли ключ для отправки. Затем проверьте доверие к payload: выполняется ли действие по данным push, куда ведёт deep link, валидируется ли источник. Далее — отображение на локскрине и хранение токена. Приоритет по влиянию: подмена уведомления от имени сервера и выполнение привилегированного действия по payload — критично; утечка PII на локскрине — средне. Эти четыре проверки покрывают подавляющее большинство реальных проблем push-канала.

## Квиз

```quiz
- question: "Что приложение получает от FCM/APNs для доставки уведомлений?"
  options:
    - "Токен устройства (registration/device token)"
    - "Пароль пользователя"
    - "Приватный ключ TLS"
    - "Сертификат подписи APK"
  answer: 0
- question: "Чем опасен API-ключ FCM, извлечённый из APK?"
  options:
    - "Если он принимается для отправки, можно слать push от имени приложения (фишинг)"
    - "Он замедляет доставку"
    - "Он меняет язык уведомлений"
    - "Он отключает интернет"
  answer: 0
- question: "Почему deep link внутри push-payload опасен?"
  options:
    - "Приложение может открыть произвольный URL из данных без валидации"
    - "Он увеличивает размер уведомления"
    - "Он ломает Bluetooth"
    - "Он требует root"
  answer: 0
- question: "Как защитить чувствительные данные в уведомлении на локскрине?"
  options:
    - "Установить visibility SECRET и не включать PII в текст"
    - "Увеличить шрифт"
    - "Отключить вибрацию"
    - "Сменить обои"
  answer: 0
```

## Где пригодится

- **Bug bounty:** подмена push, утечка токена, выполнение действия по payload.
- **Пентест:** аудит push-инфраструктуры мобильного приложения.
- **Работа:** безопасная настройка FCM/APNs и обработка уведомлений.
