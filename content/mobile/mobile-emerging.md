---
id: mobile-emerging
title: "Модуль: Новые платформы и мобильные угрозы"
category: mobile
parent: mobile-special-topics
difficulty: medium
order: 2
tags: [android-auto, wear-os, banking-trojan, iot, automotive, malware, emerging]
prerequisites: [mobile-intro]
useful_for:
  - "Пентест мобильных платформ"
  - "Анализ малвари"
  - "Реагирование на инциденты"
estimated_minutes: 25
summary: "Навигационный модуль: Android Auto, Wear OS и анализ банковских троянов — расширение поверхности мобильных атак за пределы телефона."
---
## Зачем смотреть за пределы телефона

Мобильная экосистема не ограничивается смартфоном. Android Auto/Android Automotive — мультимедиа автомобилей; Wear OS — носимые устройства с отдельными приложениями и каналами; банковские трояны — доминирующий класс мобильной малвари, эксплуатирующий IPC, accessibility и overlay. Эта ветвь расширяет поверхность атаки и учит анализировать реальные мобильные угрозы. Базовый урок `mobile-special-topics` даёт обзор; здесь — конкретика.

Ментальная модель: каждая новая платформа добавляет каналы (Bluetooth, автомобильные шины, сенсоры) и новые границы доверия между устройствами. Ошибки в этих границах дают новые классы находок.

## Карта ветви

| Урок | Что закрывает |
|------|---------------|
| `mobile-android-auto` | Android Auto/Automotive: интерфейсы, каналы, атаки |
| `mobile-wear-os` | Wear OS: приложения, коммуникация с телефоном, данные |
| `mobile-banking-trojan` | анализ банковских троянов: overlay, accessibility, C2 |
| `mobile-on-device-ml` | ML/AI на устройстве: NNAPI, TFLite, ONNX, извлечение моделей |

Смежные: `mobile-wearable-iot` (обзор IoT/wearables), `mobile-malware` (общий анализ), `mobile-task-hijacking`, `mobile-tapjacking`.

## Android Auto и Automotive

Android Auto — проекция телефона на экран авто; Android Automotive — полноценная ОС в автомобиле. Поверхность: API для медиа/навигации/сообщений, Bluetooth/USB-связь, automotive-разрешения. Риски: небезопасные мессенджеры-расширения, утечки через проекцию, доступ к датчикам авто. Разбираем в `mobile-android-auto`.

## Wear OS

Wear OS — Android для часов. Приложения — те же APK (с `uses-feature android.hardware.type.watch`), но с ограничениями (батарея, экран). Каналы: Bluetooth, Wi-Fi, `Data Layer API` (синхронизация с телефоном), `MessageClient`, `ChannelClient`. Утечки: секреты в синхронизируемых данных, небезопасная связь. Разбираем в `mobile-wear-os`.

## Банковские трояны

Доминирующий класс мобильной малвари (Cerberus, Anatsa, Hook, Ermac). Механики: accessibility-service для чтения экрана и нажатий, overlay поверх банковских приложений, SMS-перехват, скрытый VNC, обход Play Integrity, C2. Анализ — сочетание статики (манифест, разрешения) и динамики (Frida, сетевой перехват). Разбираем в `mobile-banking-trojan`.

## Что дальше / решение

Порядок: `mobile-android-auto` → `mobile-wear-os` → `mobile-banking-trojan`. Если интересует только малварь — сразу `mobile-banking-trojan` + `mobile-malware`. Для ML-приложений — ветка `mobile-on-device-ml`. Решение по умолчанию: изолированный эмулятор/устройство для анализа малвари (без реальных аккаунтов).

## Справочная таблица

| Платформа | Канал | Риск |
|-----------|-------|------|
| Android Auto | USB/BT/проекция | утечка данных авто |
| Wear OS | Data Layer/Bluetooth | секреты в синхронизации |
| Троян | accessibility/overlay | кража денег/данных |

| Инструмент | Роль |
|-----------|------|
| adb + эмулятор | динамика |
| Frida | хуки троянов |
| Wireshark/mitmproxy | C2-трафик |
| jadx/apktool | статика |

## Квиз

```quiz
- question: "Что такое Android Automotive?"
  options:
    - "Полноценная ОС Android в автомобиле"
    - "Приложение навигации"
    - "Формат бэкапа"
    - "Протокол шины"
  answer: 0
- question: "Какой API синхронизирует данные между Wear OS и телефоном?"
  options:
    - "Data Layer API"
    - "Intent API"
    - "Keychain API"
    - "NSC API"
  answer: 0
- question: "Какая механика характерна для банковских троянов?"
  options:
    - "Accessibility-service и overlay поверх банковских приложений"
    - "Только SQL-инъекции"
    - "Только brute force"
    - "Только phishing-email"
  answer: 0
- question: "Как анализировать C2-трафик трояна?"
  options:
    - "mitmproxy/Wireshark + Frida"
    - "jadx только"
    - "apktool только"
    - "nmap"
  answer: 0
- question: "Где безопасно анализировать малварь?"
  options:
    - "В изолированном эмуляторе/устройстве без реальных аккаунтов"
    - "На рабочем телефоне"
    - "На личном ноутбуке с токенами"
    - "На прод-сервере"
  answer: 0
```

## Где пригодится

- **Пентест:** расширение поверхности на авто/wearables.
- **Анализ малвари:** реальные мобильные угрозы.
- **IR:** понимание векторов мобильных атак.
- **CTF:** Mobile-задачи за пределами телефона.
