---
id: mobile-wearable-iot
title: "Wearable и companion-приложения: поверхность атаки"
category: mobile
parent: mobile-special-topics
difficulty: expert
order: 3
tags: [wearable, wear-os, watchos, companion, ble, iot, android, ios]
prerequisites: [mobile-intro, mobile-api-testing]
useful_for:
  - "CTF Mobile (атака на companion-канал)"
  - "Bug bounty (утечки через wearable-канал)"
  - "Пентест мобильных приложений и IoT"
estimated_minutes: 40
summary: "Как устроены wearable и companion-приложения (Wear OS, watchOS), какие каналы (BLE, Data Layer, cloud) они используют и где искать уязвимости в связке часы-телефон-облако."
---
## Введение

Wearable-устройства (смарт-часы, фитнес-браслеты, медицинские сенсоры) редко работают автономно. Они образуют связку «носимое устройство → телефон (companion-приложение) → облако производителя», и вся эта цепочка представляет собой единую распределённую поверхность атаки. Типичная ошибка тестировщика — смотреть только на HTTPS-API телефона, забывая про BLE, проприетарный Data Layer и облачную синхронизацию. Именно эти каналы дают находки: подделка команд, утечка токенов, BOLA на API синхронизации, слабая привязка устройства (device-binding).

Ключевая идея: у wearable нет «одной точки входа». Доверие распределено между тремя узлами, и компромисс любого из них ломает модель. Часто часы доверяют телефону, телефон доверяет часам, а облако доверяет обоим — и ни одна из сторон не проверяет источник данных криптографически. Это и есть благодатная почва для атак.

## Архитектура экосистемы wearable

Разберём типовую экосистему:

- **Носимое устройство (watch/band).** Ограниченный CPU, BLE-радио, иногда Wi-Fi/LTE. Хранит минимум данных, полагается на телефон.
- **Companion-приложение (телефон).** Основная логика, UI, доступ к API, аккаунту пользователя. Именно здесь чаще всего лежат токены.
- **Облако производителя.** Долговременное хранилище, синхронизация между устройствами, аналитика, push.
- **Промежуточные сервисы.** Google Fit, Apple Health, сторонние SDK (аналитика, реклама), которые тоже получают данные.

Данные текут по нескольким протоколам одновременно: BLE GATT, Wear OS Data Layer, WatchConnectivity (watchOS), а также по обычному HTTPS. Задача рекона — составить карту потоков и понять, где заканчивается аутентификация и начинается доверие к непроверенным данным.

## Каналы связи и их доверительные границы

| Канал | Платформа | Что передаётся | Типичная слабость |
|-------|-----------|----------------|-------------------|
| BLE GATT | обе | команды, телеметрия, ключи | нет аутентификации характеристики |
| Data Layer | Wear OS | сообщения, элементы данных | не проверяется отправитель |
| WatchConnectivity | watchOS | словари, файлы | доверие к контенту с часов |
| Cloud sync | обе | профиль, история, токены | слабый device-binding, BOLA |
| Companion API | обе | всё остальное | IDOR, отсутствие rate-limit |

Каждая граница — точка, где надо спросить: «а проверяет ли принимающая сторона, кто отправил эти данные и не подделаны ли они?». Если ответ «нет» — перед нами вектор.

## BLE GATT: практическое тестирование

Bluetooth Low Energy — основной транспорт носимых устройств. Модель данных: сервисы (services) → характеристики (characteristics) → дескрипторы. Чтение и запись идут по handle.

```bash
# 1) включить адаптер и сканировать
sudo hciconfig hci0 up
sudo hcitool lescan
# пример вывода:
# AA:BB:CC:DD:EE:FF MyBand-1234
# 24:6F:28:11:22:33 (unknown)

# 2) подключиться и перечислить GATT
sudo gatttool -b AA:BB:CC:DD:EE:FF -I
> connect
> primary                 # список сервисов
> characteristics         # список характеристик с handle и UUID
> char-read-hnd 0x0010    # прочитать значение
> char-write-req 0x0012 01  # записать команду
```

Для более удобного анализа используйте `bluetoothctl`:

```bash
bluetoothctl
> scan on
> connect AA:BB:CC:DD:EE:FF
> menu gatt
> list-attributes
> select-attribute /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service000a/char000b
> read
> write 0x01
```

Перехват и спуфинг BLE удобно делать через Bettercap:

```bash
sudo bettercap -iface hci0
> ble.recon on
> ble.show
> ble.enum AA:BB:CC:DD:EE:FF
> ble.write AA:BB:CC:DD:EE:FF 0000fff1-0000-1000-8000-00805f9b34fb 01
```

Что искать:

- **Характеристики без аутентификации.** Можно записать команду (открыть замок, разблокировать дверь, стереть данные).
- **Фиксированный ключ/пароль.** Часто `0000`, `1234` или ключ в прошивке.
- **Just Works pairing.** Не аутентифицирует стороны → MITM-перехват и модификация.
- **Отсутствие привязки (bonding).** Любое устройство рядом может подключиться.

## Wear OS Data Layer: перехват и подделка

Wear OS использует Data Layer API: `MessageClient` (одноразовые сообщения), `DataClient` (синхронизируемые элементы), `ChannelClient` (потоки). Сообщения ходят между телефоном и часами через Play Services.

Если приложение принимает данные с часов и доверяет им, подделка сообщения даёт эскалацию. Ищите в декомпилированном коде вызовы `sendMessage`, `putDataItem`, `onMessageReceived`, а также проверку `getSourceNodeId()`.

```javascript
// Frida: перехват отправки сообщения Wear OS
Java.perform(function () {
  var MessageClient = Java.use('com.google.android.gms.wearable.MessageClient');
  // в конкретном приложении обычно обёртка; ищем свой класс
  var Wrapper = Java.use('com.target.app.WearBridge');
  Wrapper.sendToWatch.overload('java.lang.String', 'byte[]').implementation = function (path, data) {
    console.log('[wear->] path=' + path + ' data=' + Java.array('byte', data));
    return this.sendToWatch(path, data);
  };
});
```

Проверяйте: валидируется ли payload, проверяется ли отправитель, есть ли криптоподпись сообщения. Если нет — можно отправить с часов «оплата подтверждена» или «пользователь авторизован».

## watchOS / WatchConnectivity

На iOS связка iPhone ↔ Apple Watch идёт через `WCSession` (`sendMessage`, `transferUserInfo`, `updateApplicationContext`). Watch-приложение и телефон обмениваются словарями (`[String: Any]`).

Тестирование: Xcode + два симулятора (iPhone + Watch) для логики, либо реальная пара с Frida на iPhone (хук на `WCSession` делегаты). Проверьте, доверяет ли iPhone данным, пришедшим с часов, и наоборот. Частая ошибка разработчиков — считать часы «доверенным источником», тогда как часы легко подделать.

## Облачный канал companion-приложения

Часто часы не имеют прямого интернета — данные идут через телефон в облако производителя. Здесь классические API-уязвимости:

- **Device-binding.** Привязан ли токен к конкретному устройству, или можно подставить чужой `device_id`?
- **Привязка часов к аккаунту.** Можно ли привязать свои часы к чужому аккаунту (или наоборот) без подтверждения?
- **BOLA/IDOR на синхронизации.** Меняется ли идентификатор пользователя/устройства в запросе → чужие данные.
- **Массовая выгрузка.** Есть ли лимиты на объём синхронизируемых данных.

## Разобранный сквозной пример: BOLA через device-id

Дано: фитнес-браслет, companion-приложение синхронизирует данные через API, передавая `deviceId`, полученный из BLE.

```bash
# 1) находим MAC/device-id через BLE
sudo hcitool lescan
# AA:BB:CC:DD:EE:FF MyBand-1234

# 2) смотрим, как приложение зовёт API
# POST /v2/sync  {"deviceId":"AA:BB:CC:DD:EE:FF","since":0}
curl -s -X POST https://api.vendor.example/v2/sync \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"deviceId":"AA:BB:CC:DD:EE:FF","since":0}' | jq '.records|length'
# 42

# 3) подставляем чужой device-id
curl -s -X POST https://api.vendor.example/v2/sync \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"deviceId":"11:22:33:44:55:66","since":0}' | jq '.records|length'
# 1337  -> данные другого пользователя!
```

Результат: API доверяет `deviceId` из тела запроса без проверки владения → BOLA. Отчёт: «Слабая привязка устройства в API синхронизации wearable позволяет читать данные чужих пользователей».

## Справочная таблица инструментов

| Задача | Инструмент | Команда/флаг |
|--------|-----------|--------------|
| Скан BLE | hcitool | `hcitool lescan` |
| GATT-доступ | gatttool | `-b MAC -I`, `primary`, `char-read-hnd` |
| Современный BLE | bluetoothctl | `menu gatt`, `select-attribute`, `read` |
| Перехват/спуфинг BLE | bettercap | `ble.recon on`, `ble.enum`, `ble.write` |
| Сниффер BLE | Wireshark + nRF Sniffer | фильтр `btle` |
| Wear Data Layer | Frida | хук `MessageClient`/`DataClient` |
| watchOS | Xcode-симуляторы | два таргета |
| API-синхронизация | curl/Burp | подмена `deviceId`/`userId` |

## Частые ошибки и подводные камни

- Игнорировать BLE как отдельный канал — многие тестируют только HTTP.
- Не проверять, валидирует ли телефон данные, пришедшие с часов.
- Считать pairing защитой: Just Works уязвим к MITM.
- Забывать про облачный канал, когда «часы работают по BLE».
- Путать MAC-адрес и application-level device-id: атакуется именно последний.
- Не учитывать, что часть логики может быть в прошивке часов (её тоже реверсят).

## Что дальше / решение

- **BLE без аутентификации** → попробуйте записать команду или прочитать данные; задокументируйте handle и эффект.
- **Данные с часов принимаются без проверки** → подделайте сообщение → эскалация привилегий.
- **Слабая привязка в облаке** → тестируйте BOLA/IDOR на API синхронизации.
- **Всё закрыто** → зафиксируйте поверхность и переходите к API/companion-приложению и его SDK.
- Для отчёта: severity BOLA/device-binding — High/Critical, отсутствие BLE-аутентификации — Medium/High в зависимости от последствий.

## Квиз

```quiz
- question: "Какой канал чаще всего связывает wearable и телефон?"
  options:
    - "Bluetooth Low Energy (GATT)"
    - "SMB"
    - "RDP"
    - "Kerberos"
  answer: 0
  explanation: "BLE — основной транспорт для носимых устройств."
- question: "Чем опасен pairing Just Works для BLE?"
  options:
    - "Не защищает от MITM"
    - "Слишком медленный"
    - "Требует root"
    - "Не поддерживает GATT"
  answer: 0
  explanation: "Just Works не аутентифицирует стороны, возможен перехват."
- question: "Какой API Wear OS передаёт сообщения между устройствами?"
  options:
    - "MessageClient / DataClient (Data Layer)"
    - "SMS Manager"
    - "MediaRecorder"
    - "Camera2"
  answer: 0
  explanation: "Data Layer API связывает телефон и часы Wear OS."
- question: "Почему доверие к данным с часов опасно?"
  options:
    - "Их можно подделать, если нет проверки отправителя/подписи"
    - "Они всегда зашифрованы"
    - "Они не содержат данных"
    - "Часы нельзя взломать"
  answer: 0
  explanation: "Без валидации поддельный источник может эскалировать привилегии."
- question: "Что тестировать в облачном канале wearable?"
  options:
    - "Привязку к устройству и BOLA/IDOR"
    - "Только TLS-версию"
    - "Только размер APK"
    - "Только язык интерфейса"
  answer: 0
  explanation: "Слабая device-binding и BOLA дают доступ к чужим данным."
```

## Где пригодится

- **CTF Mobile/IoT:** задачи с BLE и companion-каналом.
- **Bug bounty:** утечки через wearable-API — ниша с малой конкуренцией.
- **Пентест:** аудит экосистемы устройств (часы-телефон-облако).
- **Работа:** безопасность IoT/wearable продуктов.
