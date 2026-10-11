---
id: mobile-notifications
title: "Push-уведомления и FCM: перехват, подделка и утечки"
category: mobile
parent: mobile-api-testing
difficulty: medium
order: 1
tags: [push, fcm, firebase, notifications, deep-link, android, ios]
prerequisites: [mobile-api-testing]
useful_for:
  - "CTF Mobile (утечка через уведомления)"
  - "Bug bounty (подделка push, утечка данных)"
  - "Пентест мобильных приложений"
estimated_minutes: 30
summary: "Как работают push-уведомления (FCM/APNs), какие данные в них утекают, как перехватывать и подделывать уведомления и эксплуатировать обработчики/глубокие ссылки в payload."
---
## Зачем анализировать push-уведомления

Push-уведомления — недооценённая поверхность атаки мобильных приложений. Через них приходят одноразовые коды, ссылки на сброс пароля, платёжные подтверждения, чувствительные данные. Ошибки в обработке уведомлений дают: **перехват** (если данные утекают в логи/на экран блокировки), **подделку** (если приложение доверяет данным уведомления без проверки), **утечку** (если пуш-токен или payload содержат секреты), **открытие произвольных экранов** (deep link из payload). В bug bounty это частый путь к захвату аккаунта.

Ментальная модель: push — это **недоверенный ввод**, доставляемый платформой (FCM/APNs). Всё, что приложение делает на основе payload, нужно проверять так же строго, как обычный пользовательский ввод.

## Как устроены push: FCM и APNs

Android использует Firebase Cloud Messaging (FCM), iOS — Apple Push Notification service (APNs). Приложение регистрируется, получает **токен устройства**, отправляет его на свой сервер. Сервер шлёт уведомления через FCM/APNs. Payload содержит `notification` (заголовок/текст) и/или `data` (произвольные пары ключ-значение, обрабатываемые приложением).

```bash
# найти обработчики
grep -rn "FirebaseMessagingService\|onMessageReceived\|onNewToken\|getToken\|subscribeToTopic" out_jadx | head
grep -rn "google-services.json\|gcm_defaultSenderId\|firebase" out_jadx | head
```

Файл `google-services.json` (в `assets/` или ресурсах) содержит `api_key`, `project_id`, `gcm_defaultSenderId` — их можно использовать для отправки пушей в приложение.

## Классы уязвимостей

- **Утечка данных в уведомлении:** OTP/токен показывается на экране блокировки (без `VISIBILITY_SECRET`).
- **Секреты в payload:** пуш содержит чувствительные данные в открытом виде (логгируются, видны в MITM/через FCM-отладку).
- **Подделка уведомления:** приложение доверяет `data`-полям, пришедшим откуда угодно (например, через локальный broadcast или экспортированный receiver).
- **Deep link из payload:** уведомление открывает произвольный экран/URL → intent-redirect/ATO.
- **Слабый топик:** подписка на `topic` (напр. `news`) позволяет отправить пуш всем подписчикам.
- **Токен в логах:** FCM-токен/данные пишутся в logcat.

## Разобранный пример: OTP на экране блокировки

```bash
$ grep -rn "setVisibility\|NotificationCompat.Builder\|setContentText" out_jadx | head
NotifHelper.java: builder.setContentText("Your code: " + otp);   // без VISIBILITY_SECRET
$ # на экране блокировки виден OTP -> перехват второго фактора
```

Если OTP приходит в `contentText` без `setVisibility(NotificationCompat.VISIBILITY_SECRET)`, он виден любому, кто держит устройство. В связке со слабым логином это обходит 2FA.

## Подделка уведомления через экспортированный receiver

Иногда приложение само отображает «уведомление» по broadcast. Если receiver экспортирован, вы шлёте свой broadcast и приложение показывает поддельное уведомление (например, «сессия истекла, войдите здесь: evil.com»).

```bash
adb shell am broadcast -a com.target.SHOW_NOTIFICATION \
  --es title "Session expired" --es url "https://evil.com/login"
```

Это классический фишинг изнутри приложения. Смотрите `mobile-broadcast-receivers`.

## Deep link из уведомления

Если `data`-payload содержит URL, который приложение открывает (`loadUrl`, `startActivity`), вы контролируете навигацию. Комбинируется с `mobile-deeplink-deep` и `mobile-intent-redirect`.

```json
{ "data": { "url": "myapp://open?screen=transfer&to=attacker" } }
```

## Инструменты анализа

```bash
# перехват пушей на устройстве (logcat)
adb logcat | grep -iE "FirebaseMessaging|GCM|notification"
# FCM-отладка через собственный сервер (нужен api_key из google-services.json)
# отправка тестового пуша через FCM HTTP v1 API
curl -X POST "https://fcm.googleapis.com/v1/projects/PROJECT/messages:send" \
  -H "Authorization: Bearer $OAUTH" -d '{"message":{"token":"DEVICE_TOKEN","data":{"url":"myapp://..."}}}'
# mitmproxy для перехвата трафика приложения (если пуш приходит по HTTP)
```

Для iOS — APNs требует сертификат/ключ; часто проще тестировать через официальный APNs-провайдер с вашим dev-сертификатом.

## Справочная таблица: векторы через push

| Вектор | Признак | Impact |
|--------|---------|--------|
| OTP на экране блокировки | нет `VISIBILITY_SECRET` | перехват 2FA |
| Секреты в payload | данные в `data` | утечка при MITM/логах |
| Экспортированный receiver | `exported=true` | подделка уведомления |
| Deep link из payload | `url` в `data` | навигация/ATO |
| Слабый топик | публичный `topic` | массовая рассылка |
| Токен в логах | `Log.d` | кража токена |
| Отсутствие проверки отправителя | доверие `data` | инъекция |

## Типовые ошибки новичка

- **Игнорировать push как «не-интересное».** Именно через пуши утекают OTP и токены.
- **Не смотреть `google-services.json`.** Он даёт ключ для отправки пушей.
- **Путать `notification` и `data`.** Обрабатывается приложением только `data` (в фоне — `onMessageReceived`).
- **Не проверять `VISIBILITY_SECRET`.** Это простая и частая находка.
- **Забыть про iOS.** APNs имеет свои особенности (payload `aps`, background modes).

## Что дальше / решение

Порядок: найти обработчик (`FirebaseMessagingService`), разобрать `onMessageReceived`, проверить видимость на экране блокировки, проверить доверие к `data` (deep link, URL), проверить экспортированные receiver-ы, посмотреть `google-services.json`. Связанные уроки: `mobile-broadcast-receivers`, `mobile-deeplink-deep`, `mobile-firebase`, `mobile-account-takeover`. Решение — когда подтверждена утечка/подделка/навигация через уведомление с воспроизводимым PoC.

## Практический чек-лист анализа push

1. Найти `FirebaseMessagingService`/`onMessageReceived`/`onNewToken` в коде.
2. Проверить `google-services.json` (api_key, project_id, sender id).
3. Пройти путь payload: какие поля (`data`) обрабатываются и что с ними делают.
4. Проверить видимость: `setVisibility` (должен быть `SECRET` для OTP/секретов).
5. Проверить, логируется ли payload (`Log.d`) — утечка в logcat.
6. Проверить, доверяет ли приложение `data`-полям (deep link, URL, действия).
7. Проверить экспортированные receiver-ы, показывающие уведомления (подделка).
8. Проверить топики (`subscribeToTopic`) — не подписан ли пользователь на публичный.
9. Зафиксировать PoC: скриншот OTP на локскрине или поддельное уведомление.

## Расширенный разбор: payload FCM

FCM-сообщение имеет вид:

```json
{
  "message": {
    "token": "DEVICE_TOKEN",
    "notification": { "title": "Bank", "body": "Transfer received" },
    "data": { "action": "open", "screen": "history", "amount": "100" }
  }
}
```

`notification`-часть отображается системой, когда приложение в фоне; `data`-часть передаётся в `onMessageReceived` только в foreground (или через high-priority в фоне). Опасности: если `data.action`/`data.screen` напрямую управляют навигацией, вы можете открыть любой экран; если `data` содержит OTP/токен и попадает в `contentText` без `VISIBILITY_SECRET` — утечка; если приложение проверяет только `notification`, а логику ведёт по `data` — обход.

## Справочная таблица: инструменты push-анализа

| Задача | Инструмент | Команда |
|--------|-----------|---------|
| Найти обработчик | jadx/grep | `grep -rn "FirebaseMessagingService"` |
| Конфиг FCM | apktool | `cat assets/google-services.json` |
| Логи пушей | adb | `adb logcat \| grep -i GCM` |
| Отправка теста | FCM HTTP v1 | `curl .../messages:send` |
| Перехват | mitmproxy | `mitmdump -p 8080` |
| Подделка | adb | `am broadcast -a com.target.SHOW_NOTIFICATION` |
| iOS payload | APNs | `aps`-структура |

## Быстрый старт: первые команды

```bash
# найти обработчик
grep -rn "FirebaseMessagingService\|onMessageReceived\|onNewToken" out_jadx
# посмотреть конфиг FCM
cat apk/assets/google-services.json 2>/dev/null | head -20
# логи пушей на устройстве
adb logcat | grep -iE "FirebaseMessaging|GCM|notification"
# проверить видимость (SECRET?)
grep -rn "setVisibility\|VISIBILITY_SECRET" out_jadx
# подделать уведомление через экспортированный receiver
adb shell am broadcast -a com.target.SHOW_NOTIFICATION --es title "x" --es url "https://evil.com"
```

Этого набора достаточно для первичного триажа: находите обработчик, смотрите, что делается с payload, и проверяете видимость и доверие к данным. Далее — по чек-листу выше.

## Квиз

```quiz
- question: "Чем опасен legacy FCM server key, найденный в клиенте?"
  options:
    - "Позволяет отправлять push кому угодно с любым payload"
    - "Он шифрует трафик"
    - "Он ускоряет приложение"
    - "Он нужен для TLS"
  answer: 0
  explanation: "Серверный ключ даёт право отправлять уведомления от имени приложения."
- question: "Где видно содержимое push без разблокировки?"
  options:
    - "В блоке notification на локскрине"
    - "В data-секции payload"
    - "В AndroidManifest.xml"
    - "В build.gradle"
  answer: 0
  explanation: "Блок notification показывается на экране блокировки."
- question: "Какой сервис доставляет push на Android?"
  options:
    - "FCM (Firebase Cloud Messaging)"
    - "APNs"
    - "SMTP"
    - "SMB"
  answer: 0
  explanation: "FCM — транспорт push для Android."
- question: "Что может сделать обработчик deep-link в payload?"
  options:
    - "Открыть произвольный URL/компонент при клике"
    - "Зашифровать данные"
    - "Удалить приложение"
    - "Сменить язык"
  answer: 0
  explanation: "Незащищённый обработчик ведёт к deep-link/redirect-цепочкам."
- question: "Как перехватить payload в рантайме?"
  options:
    - "Frida-хук на onMessageReceived"
    - "Сменить SIM"
    - "Удалить Firebase"
    - "Отключить Wi-Fi"
  answer: 0
  explanation: "Хук логирует данные, пришедшие в сервис."
```

## Где пригодится

- **CTF Mobile:** утечка через уведомления/подделка push.
- **Bug bounty:** утечка server key и спуфинг push — критичные находки.
- **Пентест:** аудит канала уведомлений.
- **Работа:** безопасность push-инфраструктуры.
