---
id: mobile-android-root
title: "Модуль: Root, загрузчик и модификация устройства"
category: mobile
parent: mobile-platforms-android
difficulty: easy
order: 2
tags: [android, root, magisk, kernelsu, bootloader, xposed, lsposed, zygisk]
prerequisites: [mobile-platforms]
useful_for:
  - "Пентест мобильных приложений"
  - "Анализ мобильного малвари"
  - "Bug bounty (обход root- и integrity-детекта)"
estimated_minutes: 25
summary: "Навигационный модуль ветви: как устроен root на Android, bootloader unlock, Magisk/KernelSU/APatch, Xposed/LSPosed и зачем всё это пентестеру."
---
## Зачем root в пентесте

Root-устройство (или правильно подготовленный эмулятор) — это рабочий полигон тестировщика мобильных приложений. Без него нельзя прикрепиться Frida к защищённым процессам, установить системный CA-сертификат в доверенные (начиная с Android 7 пользовательские сертификаты не принимаются большинством приложений), прочитать `/data/data/<pkg>/` любого приложения, снять полный дамп памяти процесса, обойти часть проверок целостности и root-детекта. В bug bounty root нужен, чтобы воспроизводить сценарии, требующие доверенного хранилища, отладки или обхода аттестации (Play Integrity). В анализе малвари root даёт изоляцию и возможность перехватить поведение образца до того, как он нанесёт вред.

Ментальная модель: Android-безопасность — это слоёный пирог (песочница UID, SELinux, dm-verity, verified boot, keystore, attestation), а «root» — это набор изменений, которые аккуратно пробивают каждый слой, сохраняя загрузку системы работоспособной. Современный root (Magisk) не трогает `/system` физически, а подменяет его на этапе загрузки через ramdisk — поэтому dm-verity остаётся валидным, а систему можно обновлять.

## Модель безопасности Android и что именно ломает root

| Слой | Назначение | Что даёт root |
|------|-----------|----------------|
| Sandbox (UID на приложение) | изоляция данных | чтение `/data/data/*`, чужие SharedPreferences/SQLite |
| SELinux (enforcing) | мандатный контроль | политики `su`/`magisk`, обход ограничений домена |
| dm-verity | целостность system | обход через overlay/systemless |
| Verified Boot (AVB) | подпись загрузки | разблокировка загрузчика, свои образы |
| Keystore/TEE | аппаратные ключи | частично (extraction требует уязвимостей) |
| Play Integrity | аттестация устройства | обход через Zygisk-модули/PIF |
| App sandbox hardening | `debuggable`, `allowBackup` | отладка, бэкапы, инъекции |

Важно различать **root** (UID 0 + `su`), **bootloader unlock** (разрешение прошивать неофициальные образы) и **systemless**-модификации (Magisk). Только unlock без root уже ломает AVB и часто достаточно для прошивки тестового образа.

## Bootloader unlock

Производители ограничивают unlock через fastboot. У Pixel это:

```bash
adb reboot bootloader
fastboot flashing unlock        # стирает все данные (wipe)
fastboot getvar unlocked        # проверка статуса
```

У Samsung — `OEM unlock` в Developer Options + `Download mode` и `Odin`, у Xiaomi — привязка аккаунта и ожидание (до 168 часов). Проверка текущего состояния:

```bash
adb shell getprop ro.boot.verifiedbootstate   # green / orange / yellow / red
adb shell getprop ro.boot.flash.locked        # 1 = locked
adb shell getprop ro.boot.veritymode          # enforcing / disabled
```

`ro.boot.verifiedbootstate=orange` означает разблокированный загрузчик — часть банковских приложений это детектит (см. `mobile-root-detection`).

## Семейство решений: SuperSU → Magisk → KernelSU/APatch

Исторически root ставился через SuperSU (запись в `/system`). Сегодня стандарт — **systemless**:

| Решение | Принцип | Плюсы | Минусы |
|---------|---------|-------|--------|
| SuperSU | патч `/system` | простой | ломает OTA/verity |
| Magisk | ramdisk + overlay | systemless, модули, Zygisk | патчит boot-образ |
| KernelSU | патч ядра (GKI) | скрытнее, ядро-уровень | нужен совместимый kernel |
| APatch | kernel + KPM | очень скрытный | сложнее, менее популярен |

Magisk устанавливается патчем `boot.img`:

```bash
# скачать boot.img под свою сборку, затем в приложении Magisk: Install → Patch a file
adb pull /sdcard/Download/magisk_patched-*.img
adb reboot bootloader
fastboot flash boot magisk_patched.img
fastboot reboot
adb shell su -c id          # uid=0(root)
```

## Xposed и LSPosed

Xposed — фреймворк для хукинга Java-методов **без пересборки APK**: модули перехватывают вызовы в других приложениях через Zygote. Оригинальный Xposed устарел; современный аналог — **LSPosed** (работает поверх Magisk/Zygisk, изолирует модули по scope). Для пентеста Xposed/LSPosed полезны, чтобы:

- перехватывать и подменять возвращаемые значения (например, «устройство не рутнуто»);
- обходить root/jailbreak-детект, не патча код приложения;
- логировать вызовы конкретных API (root-detection библиотеки).

```bash
# LSPosed ставится как Magisk-модуль; проверка активных модулей:
adb shell ls /data/adb/modules/ | grep -i lsposed
```

## Magisk-модули и Zygisk

Magisk-модули живут в `/data/adb/modules/<name>/` и подмешивают файлы/скрипты в систему на этапе `post-fs-data`. Zygisk запускает код внутри Zygote (как старый Xposed), что позволяет инжектить в каждый процесс. Модуль `system.prop` может переопределить свойства (например, снять признак root), а `service.sh` — запускать демон. Детально — в уроке `mobile-magisk-modules`.

## Root-детект и его обход

Приложения проверяют root десятками способов: наличие `su` в `PATH`, `test-keys` в `Build.TAGS`, Magisk-пакеты, `/proc/mounts`, системные свойства, SafetyNet/Play Integrity, `ro.debuggable`, Zygisk-следы. Обход — комбинация: DenyList/Zygisk-скрытие, модуль Play Integrity Fix (PIF), патч проверок через Frida (см. `mobile-root-detection`, `mobile-frida-detection`, `mobile-integrity`). Ключевой принцип: детект почти всегда клиентский, а значит обходится на клиенте.

## Риски и безопасность

Root снижает защиту устройства: вредоносное приложение с запросом `su` может получить полный доступ, если пользователь подтвердит. Отсюда — рекомендация использовать отдельное тестовое устройство/эмулятор, не хранить на нём личные токены, а также делать снапшоты. Для изоляции применяйте `adb shell am start-user`/work profile или отдельные AVD. Всегда фиксируйте версии: несоответствие прошивки и патча Magisk ломает загрузку.

## Что дальше / решение

Порядок прохождения ветви: `mobile-android-rooting` (как получить root) → `mobile-magisk-modules` (модули и Zygisk) → `mobile-adb-fastboot` (ADB/fastboot как вектор) → `mobile-app-repackaging` (перепаковка и клонирование). Если нужен только обход детекта, после `mobile-android-rooting` сразу переходите к `mobile-root-detection` и `mobile-integrity`. Решение по умолчанию для пентеста: **эмулятор с root + Magisk + Zygisk + LSPosed**, потому что он воспроизводим и не требует физического устройства.

## Справочная таблица решений

| Задача | Инструмент | Где искать след |
|--------|-----------|-----------------|
| Получить root | Magisk (patch boot.img) | `/data/adb/magisk` |
| Скрыть root | Zygisk DenyList, PIF | `/data/adb/modules` |
| Хук Java без пересборки | LSPosed/Xposed | scope модулей |
| Root на уровне ядра | KernelSU/APatch | `/data/adb/ksu` |
| Проверить unlock | `getprop ro.boot.*` | verified boot state |
| Тестовая среда | AVD (Google APIs) | `emulator -avd` |

## Квиз

```quiz
- question: "Что такое systemless root в Magisk?"
  options:
    - "Запись su-бинаря прямо в /system"
    - "Подмена /system через ramdisk на этапе загрузки без физического изменения раздела"
    - "Отключение SELinux"
    - "Удаление dm-verity"
  answer: 1
  explanation: "Magisk патчит boot-образ и подмешивает overlay, поэтому dm-verity остаётся валидным, а OTA-обновления не ломаются."
- question: "Какой prop указывает, что загрузчик разблокирован?"
  options:
    - "ro.debuggable"
    - "ro.boot.verifiedbootstate=orange"
    - "ro.build.tags"
    - "ro.product.model"
  answer: 1
  explanation: "orange — разблокированный загрузчик; green — штатная подписанная загрузка."
- question: "Чем LSPosed отличается от оригинального Xposed?"
  options:
    - "Работает поверх Zygisk/Magisk и изолирует модули по scope"
    - "Не требует root вообще"
    - "Работает только на iOS"
    - "Это статический анализатор"
  answer: 0
- question: "Почему для пентеста часто берут эмулятор вместо телефона?"
  options:
    - "Он быстрее приложений"
    - "Воспроизводимость, снапшоты и лёгкий root без риска для личных данных"
    - "Эмулятор невозможно детектить"
    - "На эмуляторе нет SELinux"
  answer: 1
- question: "Что стирается при `fastboot flashing unlock`?"
  options:
    - "Только кэш"
    - "Все пользовательские данные (wipe)"
    - "Ничего"
    - "Только system-раздел"
  answer: 1
```

## Где пригодится

- **Пентест:** подготовка тестового устройства/эмулятора — база для динамического анализа, MITM и обхода детектов.
- **Bug bounty:** обход root/integrity-проверок для доступа к защищённому функционалу.
- **Анализ малвари:** изоляция образца, перехват его поведения, снятие дампов.
- **CTF:** Mobile-задачи, где нужен доступ к закрытым данным приложения.
