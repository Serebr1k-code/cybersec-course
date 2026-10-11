---
id: mobile-android-rooting
title: "Root на Android: Magisk, KernelSU, Xposed и LSPosed"
category: mobile
parent: mobile-android-root
difficulty: hard
order: 3
tags: [android, root, magisk, kernelsu, apatch, xposed, lsposed, boot.img, fastboot]
prerequisites: [mobile-platforms]
useful_for:
  - "Пентест мобильных приложений"
  - "Анализ малвари"
  - "Bug bounty (обход root-детекта)"
estimated_minutes: 55
summary: "Практическое получение root: разблокировка загрузчика, патч boot.img через Magisk, KernelSU/APatch, установка Xposed/LSPosed и проверка результата."
---
## Введение

Этот урок — практическая часть ветви `mobile-android-root`: как из обычного устройства сделать root-полигон для динамического анализа. Мы разберём полный цикл: проверка состояния → разблокировка загрузчика → патч `boot.img` в Magisk → прошивка → установка Xposed/LSPosed → проверка. Отдельно рассмотрим KernelSU/APatch (kernel-based root) и почему они скрытнее. Все команды выполняются с ПК, где установлены `adb` и `fastboot` (platform-tools).

Ключевой риск: неверный `boot.img` (от другой сборки) ломает загрузку — сначала всегда бекапьте оригинал и держите под рукой сток-прошивку. Разблокировка загрузчика **стирает все данные**, поэтому делайте её на чистом тестовом устройстве.

## Проверка окружения и состояния устройства

```bash
adb version && fastboot --version
adb devices -l                      # список устройств
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release   # версия Android
adb shell getprop ro.boot.verifiedbootstate  # green = locked
adb shell getprop ro.boot.flash.locked       # 1 = locked
adb shell getprop ro.boot.veritymode
adb shell getprop ro.build.tags              # test-keys = признак root/инженерки
```

`ro.build.tags` со значением `test-keys` (вместо `release-keys`) — классический признак нестандартной прошивки, который проверяют приложения. `ro.boot.verifiedbootstate` должен быть `orange` после unlock.

## Разблокировка загрузчика

Pixel (fastboot-протокол):

```bash
adb reboot bootloader
fastboot flashing unlock
# на экране устройства подтвердить (Volume + Power)
fastboot reboot
```

Xiaomi/Redmi: `Developer Options → Mi Unlock Status` (привязка аккаунта, ожидание до 168 ч), затем `fastboot oem unlock`. Samsung: `Developer Options → OEM unlocking`, далее Odin в Download mode. Проверка:

```bash
fastboot getvar unlocked
adb shell getprop ro.boot.verifiedbootstate
```

## Патч boot.img через Magisk (systemless root)

1. Скачайте сток-`boot.img` (или `init_boot.img` на Android 13+) строго под вашу сборку.
2. Установите приложение Magisk, откройте `Install → Select and Patch a File`, выберите `boot.img`.
3. Заберите пропатченный образ и прошейте:

```bash
adb pull /sdcard/Download/magisk_patched-27000_xxxxx.img
adb reboot bootloader
fastboot flash boot magisk_patched-27000_xxxxx.img
fastboot reboot
adb shell su -c id          # uid=0(root) gid=0(root) — root есть
```

Для Android 13+ с раздельным `init_boot`:

```bash
fastboot flash init_boot magisk_patched.img
```

После загрузки в приложении Magisk должен быть статус **Installed** и версия Zygisk. Проверка из шелла:

```bash
adb shell su -c 'magisk -V'
adb shell su -c 'ls /data/adb/modules'
```

## KernelSU и APatch (kernel-based root)

KernelSU патчит ядро (GKI) и предоставляет `su` через модуль ядра — это скрытнее, потому что нет пользовательского `su`-бинаря в привычном месте и меньше видимых следов. Установка зависит от устройства (патч `boot.img` с KSU-ядром либо через `fastboot`). Проверка:

```bash
adb shell su -c id
adb shell ls /data/adb/ksu
```

APatch использует KPM (Kernel Patch Module) и также работает на уровне ядра. Минус обоих — нужен совместимый kernel, и они детектирутся иначе (по версии ядра, по `/proc/kallsyms`, по монтированиям). Выбор: Magisk — универсальнее; KernelSU/APatch — когда нужно пройти продвинутый root-детект.

## Xposed и LSPosed

LSPosed ставится как Magisk-модуль (Zygisk). После установки и перезагрузки в менеджере LSPosed включайте модули и задавайте scope (какие пакеты хукать). Пример простого Xposed-модуля (Java) для подмены root-детекта:

```java
public class Bypass implements IXposedHookLoadPackage {
  public void handleLoadPackage(LoadPackageParam lpp) {
    XposedHelpers.findAndHookMethod("com.target.RootChecker", lpp.classLoader,
        "isRooted", new XC_MethodReplacement() {
          @Override protected Object replaceHookedMethod(MethodHookParam p) {
            return Boolean.FALSE;
          }
        });
  }
}
```

LSPosed-модули не пересобирают APK цели и работают во всех процессах, где включён scope. Для пентеста это удобно, когда пересборка/перепаковка приложения нежелательна (детект целостности APK).

## Полный сквозной пример

Цель: обойти `isRooted()` в тестовом APK на эмуляторе.

```bash
# 1. Проверяем, что приложение падает/блокируется на root
adb install app-debug.apk
adb shell am start -n com.target/.MainActivity

# 2. Ставим Magisk (эмулятор Google APIs позволяет root через adb root)
adb root && adb remount
# на AVD: Settings → System → Developer options → включить root (adb only / apps+adb)

# 3. Устанавливаем LSPosed-модуль, включаем scope com.target, перезагружаем
adb reboot
adb shell am start -n com.target/.MainActivity   # экран больше не блокируется
```

Альтернатива без Xposed — Frida (см. `mobile-dynamic-frida`), но Xposed/LSPosed выигрывает в случаях, когда Frida-сервер детектится.

## Частые ошибки

- **Неверный boot.img** → bootloop. Всегда бекап оригинала: `adb pull` не поможет (нужен образ из прошивки), держите сток-rom.
- **Android 13+**: патчить не `boot.img`, а `init_boot.img` — иначе root не появится.
- **Пропущен OEM unlock**: `fastboot flashing unlock` вернёт `not allowed` — включите `OEM unlocking` в Developer Options.
- **Magisk «Installed» но `su` нет**: не выдан доступ в приложении (Superuser-запрос) или DenyList случайно скрыл `su`.
- **Zygisk не включён**: LSPosed не запустится; проверьте переключатель Zygisk в настройках Magisk.
- **OTA-обновление**: после обновления прошивки root слетает — патчить boot заново.

## Что дальше / решение

После получения root переходите к `mobile-magisk-modules` (свои модули и Zygisk-инъекции) и `mobile-adb-fastboot` (ADB/fastboot как атакующий интерфейс). Если цель — пройти аттестацию, смотрите `mobile-integrity` и `mobile-frida-detection`. Решение по умолчанию: Magisk + Zygisk + LSPosed + PIF-модуль на выделенном устройстве.

## Справочная таблица команд

| Действие | Команда |
|----------|---------|
| Список устройств | `adb devices -l` |
| В bootloader | `adb reboot bootloader` |
| Unlock | `fastboot flashing unlock` |
| Проверка unlock | `fastboot getvar unlocked` |
| Прошивка boot | `fastboot flash boot magisk_patched.img` |
| Проверка root | `adb shell su -c id` |
| Версия Magisk | `magisk -V` |
| Модули | `ls /data/adb/modules` |
| KernelSU | `ls /data/adb/ksu` |

## Root на разных вендорах (OEM-специфика)

Процедура root сильно зависит от вендора. Ниже — практические отличия.

**Google Pixel.** Самый дружелюбный вариант: `fastboot flashing unlock` без ожидания, `boot.img`/`init_boot.img` доступны в factory image, установка Magisk тривиальна. Проверка: `adb shell getprop ro.boot.flash.locked` (1/0).

**Xiaomi/Redmi/POCO.** Требуется привязка Mi-аккаунта и ожидание 168 часов в Mi Unlock Tool, затем `fastboot oem unlock`. `boot.img` извлекается из recovery-образа (payload.bin) через `payload-dumper-go`:

```bash
payload-dumper-go -o out mi_recovery.img
ls out | grep -E 'boot|init_boot'
```

**Samsung.** Root через патч `AP`-образа (magisk_patched) и прошивку Odin в Download mode; обязательно `OEM unlocking`. KNOX при этом срабатывает необратимо (0x1) — Samsung Pay/Pass навсегда отключаются. Это важно учитывать на тестовом устройстве.

**OnePlus/Oppo/Realme.** `fastboot flashing unlock` (у части моделей `fastboot oem unlock`), возможна потеря Widevine L1. Проверка widevine: приложение DRM может перестать работать — тоже детектируемый признак.

**Huawei.** Современные модели не имеют официального unlock; root практически невозможен без аппаратных методов. Для пентеста берите другое устройство.

## Проверка, откат и удаление root

Иногда root нужно временно снять, чтобы вернуть «чистое» состояние (например, перед тестом детекта). Порядок отката Magisk:

```bash
# 1. В приложении Magisk: Uninstall -> Complete Uninstall
# 2. Либо вернуть сток-boot вручную
adb reboot bootloader
fastboot flash boot stock_boot.img
fastboot reboot
# 3. Проверить
adb shell getprop ro.boot.verifiedbootstate   # green
adb shell su -c id                            # su не найден
```

Полный возврат к стоку — перепрошивка factory image (Pixel: `flash-all.sh`, Xiaomi: MiFlash). Для Pixel это надёжнее всего: стирает все следы root и возвращает загрузчик (при `fastboot flashing lock`) в зелёное состояние.

```bash
# Pixel: lock загрузчик обратно (стирает данные!)
fastboot flashing lock
```

## Диагностика bootloop и восстановление

Самая частая проблема — неверный `boot.img` или несовместимый модуль. Признаки: устройство циклически перезагружается, логотип виснет. Что делать:

```bash
# 1. Зайти в bootloader (Vol Down + Power)
adb reboot bootloader
# 2. Вернуть стоковый boot
fastboot flash boot stock_boot.img
# 3. Если модуль ломает загрузку — Magisk safe mode:
#    зажать Vol Down при загрузке -> все модули отключаются
```

Magisk safe mode автоматически отключает модули, если предыдущая загрузка не завершилась дважды. После входа в систему отключите проблемный модуль в приложении. Всегда держите `stock_boot.img` и factory image под рукой — это спасает от «кирпича».

## Сравнение решений по рискам и скрытности

| Решение | Скрытность | Риск «кирпича» | OTA-совместимость | Сложность |
|---------|-----------|----------------|-------------------|-----------|
| Magisk (boot) | средняя | низкий | есть (после перепатча) | низкая |
| KernelSU | высокая | средний | зависит от ядра | средняя |
| APatch | высокая | средний | зависит | высокая |
| SuperSU (legacy) | низкая | средний | нет | низкая |

Для пентеста оптимален Magisk + Zygisk + DenyList + PIF: он даёт максимум инструментов при минимальном риске. KernelSU/APatch выбирайте, когда приложение проходит Magisk-детект. Если приложение использует аппаратную аттестацию (Strong Integrity), ни один программный root не поможет — нужен «чистый» телефон или серверная подмена.

## Сводный чек-лист получения root

1. Проверить `ro.boot.verifiedbootstate`, `ro.debuggable`, `ro.build.tags`.
2. Включить Developer Options → OEM unlocking.
3. Разблокировать загрузчик (с потерей данных).
4. Скачать сток-образ, извлечь `boot.img`/`init_boot.img`.
5. Патчить в Magisk, прошить, проверить `su -c id`.
6. Установить Zygisk + LSPosed + PIF.
7. Зафиксировать состояние (версии, свойства) для воспроизводимости.

## Квиз

```quiz
- question: "На каком разделе патчится boot.img при установке Magisk на Android 13+?"
  options:
    - "boot"
    - "init_boot"
    - "system"
    - "vendor"
  answer: 1
  explanation: "Начиная с Android 13 generic ramdisk вынесен в init_boot, поэтому патчится именно он."
- question: "Что произойдёт при прошивке boot.img от другой сборки?"
  options:
    - "Ничего, образ универсален"
    - "Устройство уйдёт в bootloop"
    - "Появится второй root"
    - "Сработает SELinux"
  answer: 1
- question: "Чем KernelSU принципиально отличается от Magisk?"
  options:
    - "Работает на уровне ядра, а не через ramdisk-патч"
    - "Требует iOS"
    - "Не даёт root"
    - "Это графический анализатор"
  answer: 0
- question: "Для чего нужен LSPosed при обходе root-детекта?"
  options:
    - "Хукать методы Java в целевых процессах без пересборки APK"
    - "Сканировать порты"
    - "Расшифровывать TLS"
    - "Делать бэкап"
  answer: 0
- question: "Как проверить, что root действительно получен?"
  options:
    - "getprop ro.build.tags"
    - "adb shell su -c id и увидеть uid=0"
    - "adb devices"
    - "fastboot getvar unlocked"
  answer: 1
```

## Где пригодится

- **Пентест:** подготовка root-устройства для Frida, MITM, чтения приватных данных.
- **Bug bounty:** обход клиентских root-проверок на устройстве.
- **Анализ малвари:** контролируемая среда для наблюдения за образцом.
- **CTF:** Mobile-задачи, требующие доступа к защищённому хранилищу.
