---
id: mobile-forensics
title: "Модуль: Мобильная форензика"
category: mobile
parent: mobile-storage-deep
difficulty: medium
order: 2
tags: [forensics, android, ios, extraction, aleapp, ileapp, artifacts, mobile]
prerequisites: [mobile-insecure-storage]
useful_for:
  - "Цифровая форензика"
  - "Реагирование на инциденты"
  - "Пентест мобильных приложений"
estimated_minutes: 25
summary: "Навигационный модуль: извлечение и анализ данных Android/iOS — образы, дампы, артефакты, облачные синхронизации."
---
## Зачем мобильная форензика пентестеру

Мобильная форензика — извлечение и анализ данных с устройства: сообщений, приложений, геолокаций, токенов, истории подключений. Для пентестера это (а) источник учётных данных и токенов, найденных в артефактах, (б) понимание, какие данные приложение оставляет на устройстве, (в) часть отчёта о защите данных. Для IR — восстановление картины инцидента. Эта ветвь даёт практический набор методов и инструментов.

Ментальная модель: форензика = «извлечь как можно больше данных, не изменив их, и разложить по артефактам». Уровни извлечения: логическое (ADB/бэкап, без root), файловая система (root/дамп), полный образ (chip-off/JTAG, аппаратно), облако (синхронизированные данные). Чем выше уровень, тем больше данных и тем выше требования к оборудованию.

## Уровни извлечения

| Уровень | Метод | Данные | Root |
|---------|-------|--------|------|
| Логический | ADB, бэкап, `content` | приложения, файлы | нет |
| Файловая система | root-дамп `/data` | полная песочница | да |
| Полный образ | chip-off/JTAG/checkm8 | весь раздел | нет (аппаратно) |
| Облако | API сервисов | синхронизации | нет |

## Карта ветви

| Урок | Что закрывает |
|------|---------------|
| `mobile-forensics-android` | извлечение и ALEAPP-анализ Android |
| `mobile-forensics-ios` | дампы iOS, checkm8, iLEAPP |
| `mobile-forensics-cloud` | облачные артефакты (iCloud, Google) |

Смежные: `mobile-backup` (ADB-бэкап), `mobile-ios-backup` (iTunes-бэкап), `mobile-insecure-storage`.

## Android: ключевые артефакты

- `/data/data/<pkg>/` — SharedPreferences, SQLite, кэши, файлы.
- `/data/system/` — accounts, `packages.xml`, `usagestats`.
- `/data/misc/` — Wi-Fi конфиги, VPN.
- `dumpsys` — состояние системы, активные сессии.
- Логи (`logcat`, `/data/anr`).
- Внешнее хранилище `/sdcard/`.

```bash
# быстрый логический дамп (root)
adb shell su -c 'tar czf /sdcard/data.tgz /data/data/com.target.app'
adb pull /sdcard/data.tgz
```

## iOS: ключевые артефакты

- Песочницы приложений (`Containers/Data/Application/<uuid>`).
- `KeychainDomain/keychain-2.db` (при шифрованном бэкапе).
- `Library/Cookies`, `Library/Caches`, `Library/Preferences`.
- `Manifest.db` (бэкап) / полный файловый дамп (checkm8).
- Базы сообщений, геолокаций (`Cache.sqlite`, `consolidated.db`).

## Инструменты анализа

`ALEAPP` (Android) и `iLEAPP` (iOS) парсят дампы/бэкапы и строят отчёт по артефактам. `Autopsy`/`Sleuth Kit` — общий форензик. `Magnet AXIOM`/`Cellebrite` — коммерческие.

```bash
python3 aleapp.py -t tar -i data.tgz -o ./aleapp_out
python3 ileapp.py -t itunes -i ./backup -o ./ileapp_out
```

## Что дальше / решение

Порядок: определить доступ (root/jailbreak) → выбрать уровень извлечения → собрать артефакты → прогнать через ALEAPP/iLEAPP → выписать находки (токены, аккаунты, геолокации). Свяжите с `mobile-insecure-storage`, `mobile-backup`, `mobile-ios-backup`. Решение по умолчанию: ALEAPP/iLEAPP (бесплатно) + root-дамп `/data`.

## Справочная таблица

| ОС | Инструмент | Вход |
|----|-----------|------|
| Android | ALEAPP | tar/дамп/бэкап |
| iOS | iLEAPP | iTunes-бэкап/дамп |
| Оба | Autopsy/SleuthKit | образ |
| Оба | Cellebrite/AXIOM | устройство |

| Артефакт | Где |
|----------|-----|
| SharedPreferences | /data/data/<pkg>/shared_prefs |
| SQLite | /data/data/<pkg>/databases |
| Cookies | Library/Cookies |
| Аккаунты | /data/system/accounts.db |

## Квиз

```quiz
- question: "Какой уровень извлечения требует root?"
  options:
    - "Логический (ADB/бэкап)"
    - "Файловая система (/data)"
    - "Облако"
    - "Никакой"
  answer: 1
- question: "Какой инструмент анализирует Android-дамп?"
  options:
    - "ALEAPP"
    - "iLEAPP"
    - "Burp"
    - "jadx"
  answer: 0
- question: "Что такое checkm8 в контексте iOS-форензики?"
  options:
    - "Аппаратный эксплойт для полного дампа"
    - "Формат бэкапа"
    - "Менеджер паролей"
    - "Протокол сети"
  answer: 0
- question: "Где Android хранит SharedPreferences приложения?"
  options:
    - "/data/data/<pkg>/shared_prefs"
    - "/system/etc"
    - "/sdcard/prefs"
    - "Keychain"
  answer: 0
- question: "Что даёт облачный уровень извлечения?"
  options:
    - "Синхронизированные данные сервисов"
    - "Полный образ диска"
    - "Root"
    - "Расшифровку TLS"
  answer: 0
```

## Где пригодится

- **Форензика/IR:** восстановление картины инцидента.
- **Пентест:** поиск токенов и секретов в артефактах.
- **Bug bounty:** оценка остаточных данных приложения.
- **CTF:** Mobile-задачи с дампами.
