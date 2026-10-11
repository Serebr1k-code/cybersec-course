---
id: mobile-android-auto
title: "Android Auto и Automotive: поверхность атаки"
category: mobile
parent: mobile-emerging
difficulty: medium
order: 1
tags: [android-auto, automotive, car, projection, bluetooth, usb, aosp, api]
prerequisites: [mobile-intro, mobile-android-components]
useful_for:
  - "Пентест автомобильных систем"
  - "Анализ мобильных платформ"
  - "Bug bounty"
estimated_minutes: 50
summary: "Безопасность Android Auto и Android Automotive: как работает проекция, automotive-API, каналы USB/Bluetooth, риски и методика тестирования."
---
## Введение

Android Auto проецирует интерфейс телефона на дисплей автомобиля; Android Automotive (AAOS) — это полноценная ОС Android внутри авто. Обе платформы расширяют поверхность атаки: появляются automotive-API, мессенджеры-расширения, каналы связи (USB, Bluetooth, Wi-Fi), доступ к датчикам и настройкам автомобиля. Для пентестера это новая область с меньшим числом исследователей и реальными находками.

Ментальная модель: Android Auto — «клиент-сервер», где телефон — сервер приложений, а головное устройство (head unit) — клиент-дисплей. AAOS — обычный Android с automotive-разрешениями и особыми сервисами (Vehicle HAL, CarPropertyManager).

## Как работает Android Auto

- Телефон подключается к head unit по USB или Bluetooth/Wi-Fi.
- Протокол проекции (Android Auto Protocol) передаёт видеопоток интерфейса и принимает ввод.
- Приложения-мессенджеры используют `Car App Library` / `androidx.car.app` для отрисовки на дисплее.
- Разрешения и `app category` (media, navigation, messaging) определяют доступные возможности.

Тестирование требует: телефона с Android Auto, head unit (или эмулятора `DHU` — Desktop Head Unit), adb.

```bash
# Desktop Head Unit (DHU) для эмуляции head unit
# включить Android Auto developer mode (10 тапов по версии)
adb forward tcp:5277 tcp:5277
./desktop-head-unit
```

## Android Automotive (AAOS)

AAOS — Android в машине. Особенности:

- `CarPropertyManager`/`VehiclePropertyIds` — доступ к свойствам авто (скорость, двери, климат).
- `CarService` и Vehicle HAL.
- Отдельные разрешения (`android.car.permission.*`), часть — privileged.
- Приложения предустанавливаются OEM.

```bash
# на AAOS-устройстве/эмуляторе
adb shell dumpsys car_service | head -100
adb shell cmd car_service get-property-value 291504647   # пример VehicleProperty
adb shell pm list packages | grep -i car
```

Риски: небезопасный доступ к свойствам авто, слабые разрешения, небезопасные сервисы.

## Разведка поверхности

```bash
# Automotive-приложения и их компоненты
adb shell dumpsys package | grep -iE 'car|automotive|android.auto'
# разрешения
adb shell dumpsys package com.target.car | grep -i permission
# экспортированные компоненты
adb shell dumpsys activity activities | grep -i car
# DHU-логи
adb logcat -s CarApp:* CarService:*
```

## Полный сквозной пример: тестирование Car App

```bash
# 1. Ставим приложение-мессенджер для Android Auto
adb install car-messenger.apk
# 2. Запускаем DHU
adb forward tcp:5277 tcp:5277
./desktop-head-unit &
# 3. Взаимодействуем с приложением через DHU (ввод сообщений)
# 4. Перехватываем трафик (приложение шлёт на бэкенд)
mitmproxy --mode transparent -p 8080
# 5. Проверяем обработку ввода: инъекции в шаблоны сообщений, утечки
adb logcat | grep -iE 'car|message'
```

Проверяйте: валидацию ввода из автомобильного интерфейса, экспорт сервисов Car App, утечки в логах, доступ к чувствительным автомобильным свойствам.

## Частые ошибки

- **Нет DHU**: без эмулятора head unit тестировать проекцию неудобно.
- **Игнорировать automotive-разрешения**: часть доступна только privileged-приложениям.
- **Путать Auto и Automotive**: это разные платформы.
- **Забыть про Bluetooth/USB-каналы**: не только проекция, но и связь.
- **Не проверять `VehicleProperty`**: доступ к свойствам авто — ключевой риск.
- **Логировать реальные данные**: используйте тестовые аккаунты.

## Что дальше / решение

Начните с DHU и разведки компонентов. Для AAOS — проверяйте CarService и свойства. Свяжите с `mobile-android-components` (экспорт), `mobile-emulator-detection`. Дальше — `mobile-wear-os`, `mobile-banking-trojan`. Рекомендация: тестировать на эмуляторе/DHU с тестовыми данными.

## Справочная таблица

| Платформа | Ключевой сервис | Инструмент |
|-----------|-----------------|-----------|
| Android Auto | проекция | DHU + adb |
| Automotive | CarService | dumpsys car_service |
| Оба | Car App Library | logcat CarApp |

| Проверка | Команда |
|----------|---------|
| Automotive-пакеты | `pm list packages \| grep car` |
| Свойства авто | `cmd car_service get-property-value` |
| Логи | `logcat -s CarService:*` |

## Полный разбор Android Auto-приложения

**Шаг 1. Подготовка DHU.**

```bash
# включить Android Auto developer mode: 10 тапов по версии в настройках приложения
# затем в developer settings включить "Start head unit server"
adb forward tcp:5277 tcp:5277
./desktop-head-unit   # подключение к телефону
```

**Шаг 2. Разведка Car App.**

```bash
adb shell pm list packages | grep -iE 'auto|car'
adb shell dumpsys package com.target.car | grep -iE 'permission|service|category'
grep -rn "CarAppService\|Session\|Screen\|Template" out/ | head
```

Car App Library использует `CarAppService` и `Session`; шаблоны (`MessageTemplate`, `ListTemplate`) рендерятся на head unit.

**Шаг 3. Проверка ввода.** Взаимодействуйте через DHU: отправьте сообщение, выберите пункт. Смотрите, как приложение обрабатывает ввод.

```bash
adb logcat -s CarApp:* CarService:* | head -50
mitmproxy --mode transparent -p 8080
```

Проверяйте инъекции в шаблоны сообщений, утечки в логи, SSRF через URL в сообщениях.

**Шаг 4. Automotive-свойства (AAOS).**

```bash
adb shell dumpsys car_service | head -100
adb shell cmd car_service get-property-value 291504647
```

Если приложение читает/пишет свойства авто (двери, климат) без должных разрешений — находка.

## Desktop Head Unit: детали

DHU — это AOSP-утилита, эмулирующая головное устройство. Установка: скачать из Android Studio SDK (`extras/google/auto`). Запуск требует `adb forward tcp:5277 tcp:5277` и включённого «head unit server» на телефоне. Без DHU тестировать проекцию крайне неудобно.

## Типичные находки Android Auto/Automotive

| Находка | Severity |
|---------|----------|
| Экспортированный CarAppService | Medium/High |
| Инъекция через шаблон сообщения | зависит |
| Доступ к VehicleProperty без разрешения | High |
| Утечки в логах CarApp | Medium |
| Слабые automotive-разрешения | Medium |

## Методический чек-лист

1. Подготовить DHU и developer mode.
2. Разведка Car App и automotive-пакетов.
3. Проверить обработку ввода из автомобильного UI.
4. Проверить доступ к VehicleProperty и разрешения.
5. Построить PoC.
6. Оформить рекомендации.

## Рекомендации в отчёте

- Валидировать весь ввод из автомобильного интерфейса.
- Ограничивать доступ к VehicleProperty строгими разрешениями.
- Не логировать чувствительные данные CarApp.
- Минимизировать экспорт Car App-компонентов.
- Проверять безопасность Bluetooth/USB-каналов связи с head unit.

## Эмуляция head unit без Android Studio

DHU можно получить без полной Android Studio: скачайте только command-line tools и через `sdkmanager` установите `extras;google;auto`. Утилита `desktop-head-unit` лежит в `extras/google/auto/`. Она требует libusb и работающего `adb forward tcp:5277 tcp:5277`. На телефоне включите developer mode Android Auto (10 тапов по версии) и «Start head unit server» в developer settings.

Если DHU не запускается, проверьте: установлен ли libusb, доступен ли порт 5277, включён ли head unit server. Часто проблема в версии DHU и Android Auto — обновите оба. Для воспроизводимости фиксируйте версии.

Альтернатива DHU — эмулятор AAOS (Android Automotive OS) в Android Studio: он даёт полноценную automotive-систему с CarService и позволяет тестировать автомобильные приложения без физического авто. Для AAOS-эмулятора доступны `dumpsys car_service` и VehicleProperty.

## Практические проверки Car App

При тестировании Car App обращайте внимание на шаблоны: `MessageTemplate`, `ListTemplate`, `NavigationTemplate`. Ввод пользователя (текст сообщения, выбор) попадает в приложение и может быть использован небезопасно. Проверяйте, как обрабатываются длинные строки, спецсимволы, URL в сообщениях. Логи CarApp (`adb logcat -s CarApp:*`) часто содержат данные, которые не должны утекать.

## Разграничение Auto и Automotive

Помните: Android Auto — проекция с телефона, Automotive — ОС в авто. Методики тестирования разные: для Auto важнее приложение на телефоне и канал проекции, для Automotive — приложение, разрешения и доступ к свойствам авто. Не смешивайте их в отчёте.

## Практикум: запуск Android Auto-приложения в DHU

Разберём конкретный запуск.

```bash
# включить developer mode Android Auto: 10 тапов по версии
# в developer settings -> Start head unit server
adb forward tcp:5277 tcp:5277
# запустить DHU из SDK
~/Android/Sdk/extras/google/auto/desktop-head-unit
```

В DHU появляется экран проекции. Устанавливаем целевое приложение, запускаем, взаимодействуем (выбираем пункт, отправляем сообщение). Наблюдаем:

```bash
adb logcat -s CarApp:* CarService:* | head -50
mitmproxy --mode transparent -p 8080
```

Проверяем обработку ввода: длинные строки, спецсимволы, URL. Если приложение принимает URL из сообщения и грузит его — SSRF/утечка. Фиксируем находки. Для AAOS-эмулятора дополнительно смотрим `dumpsys car_service` и доступ к VehicleProperty.

## Тестирование AAOS и automotive-разрешений

Android Automotive OS (AAOS) — полноценная ОС в автомобиле. Ключевые поверхности: `CarService`, Vehicle HAL, `CarPropertyManager`, automotive-разрешения (`android.car.permission.*`). Часть разрешений доступна только privileged/системным приложениям, но предустановленные OEM-приложения могут иметь широкий доступ.

Проверяйте: какие automotive-разрешения запрашивает приложение, к каким VehicleProperty обращается, есть ли валидация. Через `dumpsys car_service` и `cmd car_service get-property-value` можно читать свойства. Если приложение с недостаточными привилегиями получает доступ к свойствам авто — находка.

Эмулятор AAOS в Android Studio даёт полноценную automotive-среду без физического авто. Установите приложение, проверьте компоненты (`dumpsys package`), automotive-сервисы, доступ к свойствам. Логи `logcat -s CarService:*` показывают работу с CarService.

## Границы доверия в автомобиле

Автомобильная экосистема включает head unit, телефон, шину CAN (через шлюз). Приложение обычно не имеет прямого доступа к CAN, но через VehicleProperty может влиять на функции. Проверяйте, не позволяет ли приложение выполнять привилегированные действия (открытие дверей, климат) без должной авторизации. Это критичные находки для automotive-безопасности.

## Что писать в отчёте

Для Android Auto: обработка ввода, утечки в CarApp-логах, экспортированные компоненты. Для AAOS: automotive-разрешения, доступ к VehicleProperty, привилегированные операции. Рекомендации: строгие разрешения, валидация ввода, минимизация экспорта, проверка целостности.

## Квиз

```quiz
- question: "Что такое DHU?"
  options:
    - "Desktop Head Unit — эмулятор головного устройства"
    - "Дампер Hermes"
    - "Протокол Bluetooth"
    - "Формат APK"
  answer: 0
- question: "Чем Android Automotive отличается от Android Auto?"
  options:
    - "Automotive — полноценная ОС в авто, Auto — проекция телефона"
    - "Ничем"
    - "Automotive только для iOS"
    - "Auto — это ОС в авто"
  answer: 0
- question: "Какой API даёт доступ к свойствам авто?"
  options:
    - "CarPropertyManager / VehiclePropertyIds"
    - "Data Layer API"
    - "Keychain API"
    - "NSC API"
  answer: 0
- question: "Как включить developer mode Android Auto?"
  options:
    - "10 тапов по версии в настройках"
    - "Через fastboot"
    - "Через jailbreak"
    - "Через Keychain"
  answer: 0
- question: "Что проверять в Car App?"
  options:
    - "Валидацию ввода, экспорт сервисов, утечки в логах"
    - "Только подпись"
    - "Только размер APK"
    - "Только версию Android"
  answer: 0
```

## Где пригодится

- **Пентест авто:** новая поверхность с реальными находками.
- **Анализ платформ:** понимание экосистемы Android.
- **Bug bounty:** automotive-приложения.
- **CTF:** Mobile-задачи на проекцию/авто.
