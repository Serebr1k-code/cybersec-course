---
id: mobile-magisk-modules
title: "Magisk-модули и Zygisk: разработка и обход детекта"
category: mobile
parent: mobile-android-root
difficulty: hard
order: 4
tags: [magisk, zygisk, module, system.prop, denylist, pif, android, hooking]
prerequisites: [mobile-android-rooting]
useful_for:
  - "Пентест мобильных приложений"
  - "Bug bounty (обход root/attestation-детекта)"
  - "Анализ малвари"
estimated_minutes: 50
summary: "Как устроены Magisk-модули, что такое Zygisk, как писать свой модуль (system.prop, service.sh, zygisk-код) и как скрывать root от приложений."
---
## Введение

Magisk-модуль — это каталог со скриптами и файлами, который подмешивается в систему на этапе загрузки, не изменяя физически `/system`. Модули дают пентестеру огромную власть: подмена системных свойств, монтирование файлов поверх, запуск демонов, инъекция кода в Zygote через Zygisk. Этот урок — про то, как читать и писать модули, и как использовать их для обхода root-детекта (DenyList, Play Integrity Fix).

Понимание модулей критично: многие «магические» обходы детекта, которые вы найдёте в интернете, — это именно Magisk-модули. Уметь разобрать их по частям = уметь адаптировать под конкретное приложение.

## Структура модуля

Минимальный модуль:

```
/data/adb/modules/<name>/
├── module.prop          # метаданные
├── post-fs-data.sh      # скрипт ранней загрузки
├── service.sh           # скрипт позднего запуска (демон)
├── system.prop          # свойства, подмешиваемые в build.prop
├── system/              # файлы, монтируемые поверх /system
└── zygisk/              # нативная .so для Zygisk
```

`module.prop`:

```
id=pif
name=PlayIntegrityFix
version=v15.9
versionCode=15900
author=chiteroman
description=Fixes Play Integrity verdicts
```

Скрипты выполняются от root в контексте Magisk; `system.prop` парсится и применяется через `resetprop`.

## Zygisk: инъекция в каждый процесс

Zygisk — это встроенная в Magisk возможность загружать нативную библиотеку в Zygote, а значит — в каждый процесс приложения. Из неё делаются хуки на уровне нативного кода (аналог Xposed, но на C++/Rust). Точка входа:

```cpp
#include "zygisk.hpp"
class MyModule : public zygisk::ModuleBase {
 public:
  void onLoad(zygisk::Api *api, JNIEnv *env) override { api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY); }
  void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
    // подмена свойств до специализации процесса
  }
};
REGISTER_ZYGISK_MODULE(MyModule)
```

Проверка, что Zygisk включён:

```bash
adb shell su -c 'magisk --sqlite "SELECT * FROM settings"' | grep zygisk
adb shell ls /data/adb/modules/*/zygisk 2>/dev/null
```

## Обход root-детекта: DenyList и PIF

Два основных подхода:

1. **Zygisk DenyList (Enforce DenyList)** — Magisk скрывает root-следы (монтирования, `su`, `magisk`) от выбранных пакетов. Включается в настройках Magisk; в DenyList добавляются `com.bank.app`, `com.google.android.gms` и т.п.
2. **Play Integrity Fix (PIF)** — модуль, подменяющий свойства устройства и fingerprint на «чистые», чтобы пройти `MEETS_DEVICE_INTEGRITY`/`MEETS_STRONG_INTEGRITY`.

```bash
# проверить, что свойства подменены
adb shell getprop ro.build.fingerprint
adb shell getprop ro.product.model
```

PIF использует `system.prop` и `service.sh` для `resetprop`:

```bash
# фрагмент service.sh модуля PIF
resetprop -n ro.build.fingerprint "google/husky/husky:14/UQ1A.240205.004/..."
resetprop -n ro.product.model "Pixel 8 Pro"
```

## Полный сквозной пример: свой модуль скрытия root

Сделаем модуль, который (а) подменяет свойство, (б) скрывает `su` от конкретного пакета.

```bash
adb shell su -c 'mkdir -p /data/adb/modules/hide-root'
adb shell su -c 'cat > /data/adb/modules/hide-root/module.prop <<EOF
id=hide-root
name=HideRoot
version=1.0
versionCode=1
author=pentester
description=Hide root traces from target
EOF'
adb shell su -c 'cat > /data/adb/modules/hide-root/system.prop <<EOF
ro.build.tags=release-keys
ro.debuggable=0
EOF'
adb shell su -c 'cat > /data/adb/modules/hide-root/service.sh <<EOF
#!/system/bin/sh
resetprop -n ro.boot.verifiedbootstate green
EOF'
adb shell su -c 'chmod 755 /data/adb/modules/hide-root/service.sh'
adb reboot
adb shell getprop ro.build.tags   # release-keys
```

Обратите внимание: подмена `ro.build.tags`/`verifiedbootstate` — лишь первый слой. Продвинутый детект проверяет `/proc/self/mountinfo` на Magisk-монтирования, наличие `zygote`-инъекций, версии ядра. Поэтому PIF + DenyList + LSPosed обычно комбинируют.

## Частые ошибки

- **Модуль не появился в списке**: `module.prop` с опечаткой в обязательных полях (`id`, `version`, `versionCode`).
- **service.sh не выполняется**: забыли `chmod 755` или shebang.
- **`resetprop` не работает для read-only**: некоторые свойства применяются только до `post-fs-data`; используйте `resetprop -n` и правильную фазу.
- **DenyList без «Enforce»**: список добавлен, но скрытие не включено.
- **Детект по Zygisk-следам**: часть приложений ищет `zygisk`/`lsposed` в карте памяти — помогает `ZygiskNext`/скрытие.
- **Конфликт модулей**: два модуля патчат одно свойство — выигрывает порядок загрузки.

## Что дальше / решение

Комбинируйте: Magisk (root) + Zygisk (инъекция) + LSPosed (Java-хуки) + PIF (attestation) + DenyList (скрытие). Если приложение детектит Zygisk, переходите на KernelSU/APatch или на Frida с `frida-gadget`. Следующий урок — `mobile-adb-fastboot`: как использовать ADB/fastboot для атак и утечек. Для аттестации см. `mobile-integrity`.

## Справочная таблица

| Файл/скрипт | Назначение | Фаза |
|-------------|-----------|------|
| `module.prop` | метаданные | — |
| `post-fs-data.sh` | ранняя инициализация | post-fs-data |
| `service.sh` | запуск демона | late_start |
| `system.prop` | свойства build.prop | resetprop |
| `system/` | overlay поверх /system | mount |
| `zygisk/` | нативный хук | Zygote |

| Проблема | Решение |
|----------|---------|
| root виден приложению | DenyList Enforce + PIF |
| Play Integrity red | PIF, свежий fingerprint |
| Zygisk детектится | ZygiskNext / скрытие |
| su не найден | проверить Superuser-запрос |

## Продвинутый Zygisk-модуль на C++

Zygisk-модуль — это нативная `.so`, которую Magisk загружает в Zygote. Минимальный проект собирается через CMake с заголовком `zygisk.hpp`. Пример, который хукает нативную функцию во всех процессах:

```cpp
#include "zygisk.hpp"
#include <android/log.h>
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "MyMod", __VA_ARGS__)

class MyModule : public zygisk::ModuleBase {
 public:
  void onLoad(zygisk::Api *api, JNIEnv *env) override {
    this->api = api;
    this->env = env;
    api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
  }
  void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
    LOG("specializing %s", (*env)->GetStringUTFChars(env, args->nice_name, 0));
  }
 private:
  zygisk::Api *api; JNIEnv *env;
};
REGISTER_ZYGISK_MODULE(MyModule)
```

Сборка (Android NDK):

```bash
$ANDROID_NDK/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk
# кладём libzygisk-module.so в modules/<id>/zygisk/arm64-v8a.so
```

Такой модуль может перехватывать нативные вызовы (например, `fopen` на строки `su`, `frida`) во всех процессах, что делает его мощнее Java-хуков.

## DenyList против ZygiskNext и HideMyApplist

- **DenyList (Enforce)** — встроенный механизм Magisk: скрывает монтирования и `su` от выбранных пакетов. Работает на уровне `zygote`, но часть детектов (по maps, по `__system_property`) проходит.
- **ZygiskNext** — альтернативная реализация Zygisk (часто нужна на KernelSU/APatch), совместима с LSPosed и PIF, скрытнее штатного.
- **HideMyApplist (HMA)** — модуль LSPosed, который скрывает от приложения список установленных пакетов (обход детекта по наличию `com.topjohnwu.magisk`, `de.robv.android.xposed`).

Комбинация: ZygiskNext + HMA + PIF + DenyList даёт максимальное сокрытие. Проверка, что скрытие работает:

```bash
adb shell su -c 'magisk --denylist ls'    # список пакетов в DenyList
adb shell dumpsys package | grep -c magisk
```

## Отладка и логирование модулей

Модули молча падают при ошибках. Диагностика:

```bash
adb shell su -c 'cat /cache/magisk.log | tail -50'
adb logcat -s Magisk:* Zygisk:*
adb shell su -c 'ls -l /data/adb/modules/<id>/'
```

Частые причины: неверный `module.prop` (нет `versionCode`), `service.sh` без `chmod 755`, несовместимая ABI `.so` (нужна `arm64-v8a`), конфликт с другим модулем. Всегда проверяйте `magisk.log` после перезагрузки.

## Кейс: обход Play Integrity шаг за шагом

```bash
# 1. Проверяем текущий вердикт
#    (используйте тестовое приложение Integrity Checker)
#    -> MEETS_BASIC_INTEGRITY: fail
# 2. Включаем DenyList и добавляем com.google.android.gms + com.google.android.gms.unstable
adb shell su -c 'magisk --denylist add com.google.android.gms'
adb shell su -c 'magisk --denylist add com.google.android.gms.unstable'
# 3. Устанавливаем PlayIntegrityFix (PIF) как модуль
#    (свежий fingerprint внутри system.prop)
# 4. Перезагружаем
adb reboot
# 5. Проверяем вердикт
#    -> MEETS_DEVICE_INTEGRITY: pass
```

Strong Integrity (аппаратный) программно не обходится — только подменой на сервере или «чистым» устройством. Это важно донести в отчёте: клиентская аттестация сильна ровно настолько, насколько сервер ей доверяет.

## Чек-лист безопасной работы с модулями

1. Ставьте модули только из доверенных источников (модуль = root-код).
2. Перед установкой нового модуля делайте бекап boot/модулей.
3. После каждого модуля — перезагрузка и проверка `magisk.log`.
4. Держите Magisk safe mode под рукой (Vol Down при загрузке).
5. Не совмещайте конфликтующие модули (два патча одного свойства).

## Практикум: разработка и установка своего модуля

Разберём создание Magisk-модуля шаг за шагом.

Шаг 1. Создайте структуру:

```bash
mkdir -p mod/system/etc mod/zygisk
```

Шаг 2. `module.prop`:

```
id=hideprops
name=HideProps
version=1.0
versionCode=1
author=pentester
description=Hide device props from target
```

Шаг 3. `system.prop` (подмена свойств через resetprop):

```
ro.build.tags=release-keys
ro.debuggable=0
```

Шаг 4. `service.sh` (поздний запуск):

```bash
#!/system/bin/sh
resetprop -n ro.boot.verifiedbootstate green
```

Шаг 5. Упаковка и установка:

```bash
chmod 755 mod/service.sh
cd mod && zip -r ../hideprops.zip .
adb push ../hideprops.zip /sdcard/
# в Magisk: Modules -> Install from storage
adb reboot
```

Шаг 6. Проверка:

```bash
adb shell getprop ro.build.tags   # release-keys
adb shell su -c 'ls /data/adb/modules/hideprops'
```

## Отладка

Если модуль не работает — смотрите `magisk.log` (`adb shell su -c 'cat /cache/magisk.log'`). Частые ошибки: нет `versionCode`, `service.sh` без chmod, неверная структура. Помните: модуль — root-код, ставьте только из доверенных источников.

## Что писать в отчёте

Модули — механизм обхода детекта. Рекомендация: не полагаться только на клиентский детект, дублировать серверными проверками (Play Integrity).

## Квиз

```quiz
- question: "Какой файл модуля содержит метаданные (id, version)?"
  options:
    - "service.sh"
    - "module.prop"
    - "system.prop"
    - "zygisk.so"
  answer: 1
- question: "Что делает Zygisk?"
  options:
    - "Загружает нативную библиотеку в Zygote, инжектя код в процессы приложений"
    - "Сканирует порты"
    - "Расшифровывает диск"
    - "Делает бэкап данных"
  answer: 0
- question: "Для чего нужен модуль Play Integrity Fix?"
  options:
    - "Ускоряет приложение"
    - "Подменяет fingerprint/свойства для прохождения attestation"
    - "Скрывает su"
    - "Отключает SELinux"
  answer: 1
- question: "Где Magisk-модули хранятся на устройстве?"
  options:
    - "/system/modules"
    - "/data/adb/modules"
    - "/sdcard/modules"
    - "/vendor/modules"
  answer: 1
- question: "Чем `system.prop` модуля отличается от правки /system/build.prop?"
  options:
    - "Ничем"
    - "Подмешивается systemless через resetprop, не меняя раздел физически"
    - "Работает только на iOS"
    - "Требует пересборки ядра"
  answer: 1
```

## Где пригодится

- **Пентест:** скрытие root и обход клиентских проверок для доступа к функционалу.
- **Bug bounty:** воспроизведение сценариев, требующих «чистого» устройства.
- **Анализ малвари:** изоляция и подмена окружения при наблюдении за образцом.
- **CTF:** Mobile-задачи с root/integrity-детектом.
