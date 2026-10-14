#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gB forensics gaps: mobile Android family (hub + 6 lessons)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _fgaps_common import emit  # noqa: E402

HUBS = {}
LESSONS = {}

HUBS["forensics-mobile-android-deep"] = r'''---
id: forensics-mobile-android-deep
title: "Модуль: Android — геолокация, уведомления, GMS и реверс"
category: forensics
parent: forensics-mobile
difficulty: hard
order: 4
tags: [forensics, mobile, android, location, notifications, gms, baseband, roadmap]
prerequisites: [forensics-mobile]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Мобильная форензика"
estimated_minutes: 13
summary: "Этап ветки «мобильные»: глубокий Android — история геолокации, уведомления, сервисы Google, базовая станция и реверс приложений."
---

Базовый Android мы разобрали. Теперь — глубокие источники, которые дают максимум в
расследовании: где был телефон, что приходило в уведомления, что делали сервисы Google,
к какой соте подключался и как устроено приложение.

## Что покрывает этот модуль

- **Геолокация** — история местоположений.
- **Уведомления** — тексты и источники.
- **GMS** — сервисы Google и их данные.
- **Baseband/соты** — подключения к сети.
- **Реверс приложений** — разбор APK.

## Рекомендуемый порядок изучения

1. `mobile-android-location` — где был телефон.
2. `mobile-android-notifications` — что приходило.
3. `mobile-gms` — сервисы Google.
4. `mobile-baseband` — соты и модем.
5. `mobile-android-strongbox` — аппаратные ключи.
6. `mobile-app-reversing` — разбор приложения.

## Что вы будете уметь

- Извлекать историю геолокации.
- Читать уведомления.
- Анализировать данные GMS.
- Сопоставлять с сотовой сетью.
- Разбирать APK.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Путь |
|----------|--------------------|------|
| `cache.cell`/`cache.wifi` | где был | Google Maps |
| `notification_log.db` | что приходило | system |
| GMS-базы | активность сервисов | GMS |
| `modem`-логи | соты | baseband |
| APK | логика приложения | `jadx` |

## Куда дальше

Открывай урок **«Android-геолокация»** — начнём с местоположения.
'''

LESSONS["mobile-android-location"] = dict(
parent="forensics-mobile-android-deep", order=1, diff="hard", mins=50,
title="Android-геолокация: история местоположений",
tags="[forensics, mobile, android, location, gps]",
prereq="[forensics-mobile]",
summary="Где Android хранит историю местоположений и как её извлечь: Google Maps, system-базы и кэш вышек/Wi-Fi.",
body=r'''
## Вопрос, с которого всё начинается

Нужно установить, где был человек. Android хранит историю локаций в нескольких местах,
даже если «История местоположений» выключена. Разберём.

## Наш пример: извлечение Android

## Шаг 1: где искать

- **Google Maps** — `cache.cell`, `cache.wifi`, `local_time_line`;
- **система** — базы `com.google.android.gms`;
- **приложения** — треки, чекины;
- **фото** — EXIF с GPS.

## Шаг 2: Google Maps

```
$ find /data/data -iname '*cache*' | grep -i maps
/data/data/com.google.android.apps.maps/databases/cache.cell
```

`cache.cell` — привязка к сотам, `cache.wifi` — к Wi-Fi-точкам. Оба дают грубую
геолокацию, даже без GPS.

## Шаг 3: timeline

`local_time_line` хранит хронологию перемещений:

```
$ sqlite3 local_time_line 'SELECT * FROM timeline LIMIT 3;'
```

Это фактически дневник поездок.

## Шаг 4: EXIF в фото

```
$ exiftool /sdcard/DCIM/Camera/IMG_001.jpg | grep -i gps
GPS Latitude : 55.75
```

Фото — независимый источник локации с точным временем.

## Шаг 5: что искать

- кластеры точек (где останавливался);
- маршруты (перемещения);
- время (когда был);
- сопоставление с другими артефактами.

## Что мы теперь знаем

- Maps хранит `cache.cell`/`cache.wifi`/timeline.
- Системные базы GMS тоже содержат локации.
- EXIF фото — независимый источник.
- Даже без GPS есть геолокация по сотам/Wi-Fi.
- Сопоставляй источники.

## Если не сработало

- История удалена? Смотри кэш и фото.
- Нет доступа к /data? Нужен root/извлечение.
- Нужна точность? Комбинируй GPS и соты.

## Квиз

Проверь себя.

```quiz
- question: Что хранит cache.cell?
  options:
    - 'обои'
    - 'привязку к сотовым вышкам (геолокация)'
    - 'пароли'
    - 'сеть'
  answer: 1
  explanation: 'cache.cell связывает устройство с сотами для локации.'
- question: Где история перемещений Google Maps?
  options:
    - 'в local_time_line'
    - 'в /etc'
    - 'в браузере'
    - 'в шрифтах'
  answer: 0
  explanation: 'local_time_line хранит таймлайн перемещений.'
- question: Какой независимый источник GPS-локации?
  options:
    - 'обои'
    - 'EXIF фотографий'
    - 'сеть'
    - 'шрифты'
  answer: 1
  explanation: 'Фото с GPS несут координаты и время.'
- question: Можно ли определить локацию без GPS?
  options:
    - 'нет'
    - 'да, по сотам и Wi-Fi'
    - 'только по IP'
    - 'никак'
  answer: 1
  explanation: 'Привязка к сотам/Wi-Fi даёт грубую геолокацию.'
```
''')

LESSONS["mobile-android-notifications"] = dict(
parent="forensics-mobile-android-deep", order=2, diff="medium", mins=45,
title="Android-уведомления: журнал и тексты",
tags="[forensics, mobile, android, notifications, logs]",
prereq="[forensics-mobile]",
summary="Как Android хранит уведомления и как извлечь их тексты, источники и время.",
body=r'''
## Вопрос, с которого всё начинается

Что приходило на телефон: сообщения, коды, оповещения? Android логирует уведомления.
Разберём, где и как их читать.

## Наш пример: извлечение Android

## Шаг 1: notification log

Современный Android хранит историю уведомлений:

```
$ find /data -iname 'notification*'
/data/system/users/0/notification_log.db
```

База `notification_log.db` — история отображённых уведомлений.

## Шаг 2: читаем

```
$ sqlite3 notification_log.db '.tables'
$ sqlite3 notification_log.db 'SELECT * FROM notification LIMIT 3;'
```

Текст уведомления может лежать в сжатом/бинарном виде — извлекается парсерами (ALEAPP).

## Шаг 3: источники

Каждое уведомление привязано к **пакету** (приложению):

```
pkg: com.whatsapp
```

Так понимаешь, откуда пришло.

## Шаг 4: что искать

- OTP-коды (двухфакторка);
- имена отправителей;
- тексты сообщений;
- банковские оповещения;
- ошибки приложений.

## Шаг 5: сопоставление

Уведомления дублируют данные приложений. Если база мессенджера удалена, уведомления
могут сохранить текст.

## Что мы теперь знаем

- Android хранит `notification_log.db`.
- Уведомления привязаны к пакету.
- Тексты извлекаются парсерами.
- Могут сохранить OTP и сообщения.
- Дублируют данные приложений.

## Если не сработало

- База пуста? Смотри кэши приложений.
- Текст закодирован? Используй ALEAPP.
- Нет доступа? Нужен root/извлечение.

## Квиз

Проверь себя.

```quiz
- question: Где Android хранит историю уведомлений?
  options:
    - 'в /etc'
    - 'в notification_log.db'
    - 'в браузере'
    - 'в шрифтах'
  answer: 1
  explanation: 'Системная база notification_log.db ведёт журнал.'
- question: К чему привязано уведомление?
  options:
    - 'к обои'
    - 'к пакету приложения'
    - 'к сети'
    - 'к шрифту'
  answer: 1
  explanation: 'Пакет указывает источник уведомления.'
- question: Чем полезны уведомления при удалённых сообщениях?
  options:
    - 'ничем'
    - 'могут сохранить текст/OTP'
    - 'шифруют'
    - 'сеть'
  answer: 1
  explanation: 'Журнал уведомлений хранит отображаемый текст.'
- question: Как разобрать уведомления?
  options:
    - 'grep'
    - 'парсерами (ALEAPP)'
    - 'ping'
    - 'ssh'
  answer: 1
  explanation: 'Тексты часто в спец-формате; нужен парсер.'
```
''')

LESSONS["mobile-gms"] = dict(
parent="forensics-mobile-android-deep", order=3, diff="hard", mins=45,
title="Google Mobile Services: данные сервисов и аккаунты",
tags="[forensics, mobile, android, gms, google, accounts]",
prereq="[forensics-mobile]",
summary="Какие данные хранят Google Mobile Services, где их искать и как они помогают в расследовании.",
body=r'''
## Вопрос, с которого всё начинается

Google-сервисы (GMS) знают о телефоне больше всех: аккаунты, синхронизация, локации,
поиск. Их данные — ценный источник. Разберём.

## Наш пример: GMS-данные

## Шаг 1: что такое GMS

GMS — набор сервисов Google (Play, аккаунты, синхронизация, безопасность). Они хранят
данные в собственных базах под `com.google.android.gms`.

## Шаг 2: где искать

```
$ find /data/data/com.google.android.gms -name '*.db' | head
```

Внутри: аккаунты, настройки, кэши, данные безопасности.

## Шаг 3: аккаунты

```
$ sqlite3 /data/data/com.google.android.gms/databases/accounts.db '.tables'
```

Даёт список Google-аккаунтов, связанных с устройством — идентификация владельца.

## Шаг 4: данные безопасности

GMS ведёт:
- **Find My Device** (последние локации);
- **Safe Browsing** (предупреждения);
- **Play Protect** (обнаружения).

```
$ grep -ri 'playprotect\|safebrowsing' /data/data/com.google.android.gms/ | head
```

## Шаг 5: что искать

- список аккаунтов;
- историю синхронизации;
- локации Find My Device;
- обнаружения Play Protect;
- установки из Play.

## Что мы теперь знаем

- GMS хранит аккаунты, синхронизацию, локации.
- Базы — под `com.google.android.gms`.
- Аккаунты идентифицируют владельца.
- Play Protect/Find My Device дают данные безопасности.
- Данные синхронизируются с облаком Google.

## Если не сработало

- Данные в облаке? Нужен доступ к аккаунту.
- Нет root? Используй извлечение.
- Нужен контекст? Смотри другие приложения.

## Квиз

Проверь себя.

```quiz
- question: Что такое GMS?
  options:
    - 'игра'
    - 'набор сервисов Google на Android'
    - 'формат файла'
    - 'сеть'
  answer: 1
  explanation: 'GMS — Google Mobile Services.'
- question: Что хранит accounts.db GMS?
  options:
    - 'обои'
    - 'список Google-аккаунтов устройства'
    - 'пароль Wi-Fi'
    - 'шрифты'
  answer: 1
  explanation: 'База аккаунтов связывает устройство с владельцем.'
- question: Что даёт Find My Device?
  options:
    - 'обои'
    - 'последние локации устройства'
    - 'шрифты'
    - 'музыку'
  answer: 1
  explanation: 'Сервис хранит местоположения устройства.'
- question: Где искать данные GMS?
  options:
    - 'в /etc'
    - 'в com.google.android.gms'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'Данные GMS лежат в каталоге своего пакета.'
```
''')

LESSONS["mobile-baseband"] = dict(
parent="forensics-mobile-android-deep", order=4, diff="hard", mins=50,
title="Baseband и соты: подключения к сети",
tags="[forensics, mobile, baseband, modem, cell-tower]",
prereq="[forensics-mobile]",
summary="Что хранит baseband (модем) телефона: подключения к сотам, SIM-события и почему это сложный источник.",
body=r'''
## Вопрос, с которого всё начинается

Телефон подключался к сотовой сети — значит, остались данные о **сотах**. Это отдельный
процессор (**baseband**), и получить его данные сложнее, чем из ОС. Разберём.

## Наш пример: сотовые данные

## Шаг 1: что такое baseband

Baseband — процессор, отвечающий за радиосвязь. Он работает независимо от ОС, со своей
прошивкой. Хранит:

- историю подключений к сотам;
- события SIM;
- журналы сети.

## Шаг 2: где искать в ОС

Часть данных доступна из Android:

```
$ find /data -iname '*cell*' -o -iname '*modem*' | head
```

Плюс `cache.cell` (Maps), логи RIL (Radio Interface Layer).

## Шаг 3: логи RIL

RIL-логи фиксируют взаимодействие ОС с модемом:

```
$ grep -i 'cellinfo\|registration' /data/logs/ril.log | tail
```

`cellinfo` даёт идентификаторы сот (MCC/MNC/LAC/CID), по которым определяют локацию.

## Шаг 4: получение данных baseband

Полные логи модема требуют:

- инженерного режима (инженерное меню);
- специального оборудования/диагностического порта;
- прошивочных инструментов.

Это «глубокая» мобильная форензика, доступная не всегда.

## Шаг 5: зачем это нужно

- локация **без GPS** (по сотам);
- подтверждение перемещений;
- подключения к «левым» сетям (IMSI-catcher);
- связь SIM с устройством.

## Что мы теперь знаем

- Baseband — отдельный процессор радиосвязи.
- Хранит подключения к сотам и события SIM.
- Часть данных доступна из ОС (RIL, cache.cell).
- Полные логи модема — через инженерный режим/оборудование.
- Соты дают локацию без GPS.

## Если не сработало

- Нет доступа к модему? Используй cache.cell и RIL-логи.
- Нужны соты? Сопоставь с картами покрытия.
- Нужен SIM? Смотри `mobile-sim-usim`.

## Квиз

Проверь себя.

```quiz
- question: Что такое baseband?
  options:
    - 'браузер'
    - 'процессор радиосвязи (модем)'
    - 'формат файла'
    - 'сеть'
  answer: 1
  explanation: 'Baseband управляет сотовой связью независимо от ОС.'
- question: Что хранит baseband?
  options:
    - 'обои'
    - 'подключения к сотам и события SIM'
    - 'шрифты'
    - 'музыку'
  answer: 1
  explanation: 'Модем ведёт журналы сети и SIM.'
- question: Что даёт cellinfo?
  options:
    - 'обои'
    - 'идентификаторы сот для локации'
    - 'пароль'
    - 'шелл'
  answer: 1
  explanation: 'MCC/MNC/LAC/CID определяют положение по сотам.'
- question: Как получить полные логи модема?
  options:
    - 'grep'
    - 'через инженерный режим/оборудование'
    - 'браузером'
    - 'никак'
  answer: 1
  explanation: 'Глубокие логи требуют специального доступа.'
```
''')

LESSONS["mobile-android-strongbox"] = dict(
parent="forensics-mobile-android-deep", order=5, diff="hard", mins=45,
title="Android StrongBox и аппаратные ключи",
tags="[forensics, mobile, android, strongbox, keystore, tee]",
prereq="[forensics-mobile]",
summary="Что такое StrongBox/TEE на Android, как хранятся ключи и что это значит для форензики.",
body=r'''
## Вопрос, с которого всё начинается

Современные Android-устройства хранят ключи в аппаратной защите (TEE/StrongBox). Извлечь
их обычными методами нельзя. Разберём, как это устроено и что доступно.

## Наш пример: Android Keystore

## Шаг 1: уровни защиты

- **software** — ключи в файле (слабый);
- **TEE** (Trusted Execution Environment) — защищённое окружение в SoC;
- **StrongBox** — отдельный чип (strongest).

```
$ adb shell dumpsys keystore | grep -i 'strongbox\|tee'
```

## Шаг 2: где ключи

Ключи Android Keystore привязаны к аппаратной защите. Файлы в `/data/misc/keystore`
содержат **зашифрованные** блобы — расшифровать без чипа нельзя.

```
$ ls /data/misc/keystore/user_0/
10001_USRPKEY_...
```

## Шаг 3: что это значит

- приложения (банки, мессенджеры) хранят ключи в StrongBox/TEE;
- ключи **не покидают** защищённую зону;
- извлечь их «в лоб» невозможно;
- можно использовать ключ **только на устройстве** через API.

## Шаг 4: что доступно

- метаданные ключей (алиасы, типы);
- факт использования (логи);
- при наличии эксплойта/root — ограниченный доступ;
- на разблокированном устройстве — через API.

## Шаг 5: практика

- для расследования важнее **данные приложений**, а не сами ключи;
- если ключ нужен — извлекай через живое устройство (API);
- фиксируй версию/модель (влияет на защиту).

## Что мы теперь знаем

- Ключи хранятся в software/TEE/StrongBox.
- StrongBox — отдельный чип (максимальная защита).
- Файлы keystore содержат зашифрованные блобы.
- Ключи не покидают защищённую зону.
- Доступны метаданные и использование через API.

## Если не сработало

- Нужен ключ? Работай через живое устройство.
- Есть root? Доступ всё равно ограничен TEE.
- Нужны данные? Читай базы приложений.

## Квиз

Проверь себя.

```quiz
- question: Что такое StrongBox?
  options:
    - 'браузер'
    - 'отдельный защищённый чип для ключей'
    - 'сеть'
    - 'формат'
  answer: 1
  explanation: 'StrongBox — аппаратный модуль хранения ключей.'
- question: Где Android хранит ключи Keystore?
  options:
    - 'в /etc/passwd'
    - 'в /data/misc/keystore (зашифрованные блобы)'
    - 'в браузере'
    - 'в шрифтах'
  answer: 1
  explanation: 'Ключи лежат зашифрованными в каталоге keystore.'
- question: Можно ли извлечь ключ StrongBox обычными методами?
  options:
    - 'да'
    - 'нет, ключ не покидает защищённую зону'
    - 'иногда'
    - 'всегда'
  answer: 1
  explanation: 'TEE/StrongBox не отдают ключи наружу.'
- question: Что доступно при расследовании?
  options:
    - 'сами ключи'
    - 'метаданные и использование ключей'
    - 'ничего'
    - 'обои'
  answer: 1
  explanation: 'Доступны алиасы/типы и факт использования.'
```
''')

LESSONS["mobile-app-reversing"] = dict(
parent="forensics-mobile-android-deep", order=6, diff="hard", mins=50,
title="Реверс мобильных приложений: APK, DEX и нативные библиотеки",
tags="[forensics, mobile, android, reversing, apk, native]",
prereq="[forensics-mobile]",
summary="Как разбирать мобильные приложения: структура APK, декомпиляция DEX, нативные библиотеки и защита.",
body=r'''
## Вопрос, с которого всё начинается

Нужно понять логику приложения: куда оно ходит, как хранит данные, есть ли вредонос.
Разберём реверс Android-приложений.

## Наш пример: APK

## Шаг 1: структура

APK — ZIP:

```
$ unzip -l app.apk | head
  classes.dex
  lib/arm64-v8a/libnative.so
  res/
  AndroidManifest.xml
```

`classes.dex` — байткод, `lib/` — нативные библиотеки (C/C++).

## Шаг 2: декомпиляция DEX

```
$ jadx -d out app.apk
$ grep -rE 'http|token|encrypt' out/sources/ | head
```

`jadx` даёт Java-подобный код. Ищем URL, ключи, логику.

## Шаг 3: манифест

```
$ apktool d app.apk -o out_apktool
$ grep -E 'activity|permission|service' out_apktool/AndroidManifest.xml | head
```

Манифест показывает компоненты и разрешения.

## Шаг 4: нативный код

Сложную логику прячут в `.so`:

```
$ file lib/arm64-v8a/libnative.so
ELF 64-bit LSB shared object, ARM aarch64
```

Анализ — как обычного ARM-бинарника (Ghidra/IDA).

## Шаг 5: защита

- **обфускация** (ProGuard/R8);
- **шифрование DEX** (загрузчик расшифрует в рантайме);
- **anti-debug/anti-Frida**;
- **проверка целостности**.

## Что мы теперь знаем

- APK = ZIP с DEX, lib, res, манифестом.
- `jadx` декомпилирует DEX.
- Нативный код в `.so` (ARM).
- Манифест даёт компоненты/разрешения.
- Защита: обфускация, шифрование DEX, anti-debug.

## Если не сработало

- DEX зашифрован? Ищи загрузчик, снимай дамп из памяти.
- Обфускация? Деобфусцируй/динамически.
- Anti-Frida? Обходи проверки.

## Квиз

Проверь себя.

```quiz
- question: Что содержит classes.dex?
  options:
    - 'картинки'
    - 'байткод приложения'
    - 'шрифты'
    - 'сеть'
  answer: 1
  explanation: 'DEX — исполняемый байткод Android.'
- question: Какой инструмент декомпилирует DEX?
  options:
    - 'grep'
    - 'jadx'
    - 'nmap'
    - 'ssh'
  answer: 1
  explanation: 'jadx восстанавливает Java-подобный код.'
- question: Где прячут сложную логику?
  options:
    - 'в res'
    - 'в нативных .so библиотеках'
    - 'в манифесте'
    - 'в обои'
  answer: 1
  explanation: 'Нативный код (C/C++) сложнее анализировать.'
- question: Что за защита «шифрование DEX»?
  options:
    - 'обои'
    - 'DEX расшифровывается загрузчиком в рантайме'
    - 'сеть'
    - 'шрифт'
  answer: 1
  explanation: 'Обфускатор шифрует DEX; код появляется только при запуске.'
```
''')

emit(HUBS, LESSONS)
