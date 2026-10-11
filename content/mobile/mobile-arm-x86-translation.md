---
id: mobile-arm-x86-translation
title: "Трансляция ARM↔x86: нативный код на эмуляторе и в эмуляторах"
category: mobile
parent: mobile-platform-integration
difficulty: hard
order: 3
tags: [mobile, arm, x86, native, houdini, emulator, qemu]
prerequisites: [mobile-android-native]
useful_for:
  - "Пентест: запуск ARM-приложений на x86-эмуляторе"
  - "Reverse: анализ нативного кода разных архитектур"
estimated_minutes: 42
summary: "Как Android запускает ARM-бинарники на x86: native bridge, libhoudini, libndk_translation, QEMU-эмуляция, почему нативный код ведёт себя иначе и как правильно тестировать ARM-приложения."
---

## Почему это важно

Большинство реальных Android-устройств — ARM (arm64). Но лаборатории часто крутят x86_64-эмуляторы: они быстрее и работают без KVM для ARM. Возникает конфликт: APK содержит `lib/arm64-v8a/*.so`, а процессор эмулятора — x86_64. Чтобы приложение всё-таки запустилось, Android использует **native bridge** — слой трансляции ARM-инструкций в x86. Именно из-за этого слоя нативный код на эмуляторе ведёт себя иначе: падает, тормозит, детектит эмуляцию или вовсе не запускается.

Понимание трансляции нужно и для тестирования (почему приложение падает на эмуляторе), и для анализа (как дизассемблировать ARM-код), и для обхода детектов (почему проверка «эмулятор/не эмулятор» срабатывает).

## Как работает native bridge

Android определяет ABI приложения и, если он не совпадает с ABI устройства, ищет подходящий **native bridge** (`ro.dalvik.vm.native.bridge`). Для ARM на x86 это:
- **libhoudini** (Intel) — проприетарный транслятор, использовался на устройствах с Intel Atom.
- **libndk_translation** (Google) — современный транслятор для x86-эмуляторов (Android 11+).
- **QEMU-эмуляция** — полноценная эмуляция инструкций, медленная, используется в некоторых образах.

Проверка на устройстве:

```bash
adb shell getprop ro.product.cpu.abi           # x86_64
adb shell getprop ro.product.cpu.abilist        # x86_64,x86,arm64-v8a,armeabi-v7a
adb shell getprop ro.dalvik.vm.native.bridge    # libndk_translation.so
adb shell getprop ro.enable.native.bridge.exec  # 1
```

Если в `abilist` есть ARM-архитектуры, но `native.bridge` не задан — ARM-код не запустится, и приложение упадёт с `UnsatisfiedLinkError`.

## Что происходит при загрузке .so

Когда приложение вызывает `System.loadLibrary("native")`:
1. VM ищет `libnative.so` в `lib/<abi>/` для ABI устройства.
2. Если есть только ARM-вариант, включается native bridge.
3. Bridge загружает ARM-бинарник и транслирует инструкции по мере выполнения (JIT-трансляция).
4. Системные вызовы проксируются; не все поддерживаются.

Практическое следствие: **не всякий ARM-код транслируется корректно**. Некоторые инструкции, SIMD-расширения, вызовы специфичных syscall'ов могут не поддерживаться, и библиотека падает. Также трансляция замедляет код в разы.

## Типовые ошибки при запуске на эмуляторе

- **`UnsatisfiedLinkError: dlopen failed: ... is 64-bit instead of 32-bit`** — несовпадение разрядности ABI.
- **`couldn't find "libfoo.so"`** — в APK нет библиотеки под ABI эмулятора и нет bridge.
- **`SIGILL` (Illegal instruction)** — bridge не поддерживает инструкцию.
- **Краш в нативном коде** — несовместимость с трансляцией или анти-эмуляция.
- **Приложение детектит эмулятор** — проверки `Build.FINGERPRINT`, `ro.kernel.qemu`, отсутствие сенсоров.

## Решения: как всё-таки запустить ARM-приложение

1. **Использовать ARM-эмулятор.** На Apple Silicon и ARM-серверах доступны ARM-образы; на x86 — медленно, но возможно через QEMU.
2. **Включить native bridge** на x86-образе (в новых AVD с Android 11+ `libndk_translation` есть).
3. **Извлечь ARM-библиотеку и запустить отдельно** под QEMU-user для анализа:
   ```bash
   qemu-aarch64 -L /usr/aarch64-linux-gnu/ ./libnative.so
   ```
4. **Тестировать на физическом устройстве** — самый надёжный путь для нативного кода.

## Анализ нативного кода разных архитектур

Для реверса `.so` нужен дизассемблер с поддержкой архитектуры:
- **Ghidra** — ARM/ARM64/Thumb, x86/x64, MIPS, RISC-V (через плагины).
- **IDA** — все популярные, лучший декомпилятор.
- **radare2/rizin** — открытый, скриптуемый.

```bash
# определение архитектуры .so
file libnative.so
# libnative.so: ELF 64-bit LSB shared object, ARM aarch64
# дизассемблирование в rizin
rizin -A libnative.so
[0x0]> afl        # список функций
[0x0]> pdf @ sym.Java_com_example_NativeLib_check
```

Если библиотека только ARM, а вы хотите запустить её на x86 для динамического анализа — используйте QEMU-user с нужным rootfs:

```bash
# aarch64 rootfs (например, из debian multiarch)
qemu-aarch64 -L /usr/aarch64-linux-gnu -strace ./libnative.so
```

## Анти-эмуляция и трансляция

Приложения детектят трансляцию по признакам:
- `ro.dalvik.vm.native.bridge` непустой;
- `ro.kernel.qemu=1`;
- CPU-инструкции/`/proc/cpuinfo` показывают x86 при ARM-приложении;
- отсутствие `libhoudini`/`libndk_translation` там, где ожидается;
- несоответствие `Build.SUPPORTED_ABIS` и фактического процессора.

Обход — Frida-хуки на `Build`-поля и `System.getProperty`:

```javascript
Java.perform(function () {
  var Build = Java.use("android.os.Build");
  Build.FINGERPRINT.value = "google/sdk_gphone64_arm64/...:user/release-keys";
  var SP = Java.use("java.lang.System");
  SP.getProperty.overload('java.lang.String').implementation = function (k) {
    if (k === "ro.dalvik.vm.native.bridge") return "";
    return this.getProperty(k);
  };
});
```

Нативный детект (чтение `/proc/cpuinfo`) обходится `Interceptor` на `open`/`fopen` с подменой содержимого.

## Практический сценарий: ARM-приложение в x86 AVD

```bash
# 1) создаём x86_64 AVD с Android 13 (есть libndk_translation)
avdmanager create avd -n x86_13 -k "system-images;android-33;google_apis;x86_64"
emulator -avd x86_13 -no-window &
adb wait-for-device
# 2) проверяем bridge
adb shell getprop ro.dalvik.vm.native.bridge    # libndk_translation.so
# 3) ставим ARM-приложение
adb install app-arm64.apk
# 4) смотрим логи при краше
adb logcat | grep -iE "UnsatisfiedLink|SIGILL|native"
```

Если bridge отсутствует, а приложение нативно — переходите на ARM-эмулятор или физическое устройство.

## Частые ошибки и подводные камни

- **Путаница `abilist` и `abi`** — `abilist` показывает поддерживаемые (включая транслируемые), `abi` — нативную.
- **Ожидание нативной скорости** — трансляция в разы медленнее; тайминги в тестах не показательны.
- **Тест криптографии** — нативный крипто-код под трансляцией может дать другой результат (редко, но бывает).
- **Bridge есть, но не для этой версии** — `libndk_translation` не поддерживает старые ARM-инструкции.
- **Детект эмулятора** — не путайте с крашем; смотрите логи.

## Справочная таблица

| Bridge | Платформа | Особенности |
|--------|-----------|-------------|
| libhoudini | Intel Atom | проприетарный, устаревший |
| libndk_translation | x86 AVD (11+) | современный, поддерживается Google |
| QEMU | универсально | медленно, полная эмуляция |
| qemu-user | Linux | запуск ARM-бинарника вне Android |

## Что дальше / решение

Если нативный код обязателен — тестируйте на ARM (эмулятор или устройство). Для анализа ARM-библиотек используйте Ghidra/IDA, для изолированного запуска — QEMU-user. Проверьте, не детектит ли приложение трансляцию, и при необходимости обходите хуками. Дальше — `mobile-native-so-deep` и `mobile-emulator-detection`.

## ABI, разрядность и как их читать

Android ABI кодируется строками: `arm64-v8a` (64-бит ARM), `armeabi-v7a` (32-бит ARM), `x86_64`, `x86`. В APK библиотеки лежат в `lib/<abi>/`. Устройство объявляет свои ABI через `Build.SUPPORTED_ABIS` (в порядке приоритета). Приложение выбирает первую поддерживаемую. Если у приложения только ARM, а устройство x86 — нужен bridge.

```bash
# какие ABI у установленного приложения
adb shell dumpsys package com.example.app | grep -A3 "primaryCpuAbi\|secondaryCpuAbi"
# посмотреть, какие .so в APK
unzip -l app.apk | grep '\.so$'
```

Ошибки разрядности частая причина краха: 32-битная библиотека на 64-битном процессе и наоборот дают `dlopen failed: ... is 64-bit instead of 32-bit`. Проверяйте `file libfoo.so`.

## QEMU-user: запуск ARM-бинарника вне Android

Для анализа удобно запустить ARM-библиотеку или утилиту на Linux через `qemu-user`:

```bash
sudo apt install qemu-user qemu-user-static
# aarch64 rootfs
sudo apt install libc6-arm64-cross gcc-aarch64-linux-gnu
# запуск ARM-бинарника
qemu-aarch64 -L /usr/aarch64-linux-gnu ./arm_tool --help
# с трассировкой системных вызовов
qemu-aarch64 -strace -L /usr/aarch64-linux-gnu ./arm_tool
# с gdb-сервером для отладки
qemu-aarch64 -g 1234 -L /usr/aarch64-linux-gnu ./arm_tool
# в другом окне
gdb-multiarch ./arm_tool -ex "target remote :1234"
```

Это позволяет отлаживать ARM-код без устройства — незаменимо, когда под рукой только x86-машина, а приложение нативно-ARM.

## Статический анализ: от x86 к ARM и обратно

Если нужно сравнить поведение одной и той же логики на разных архитектурах, помните о различиях:
- **Соглашения о вызовах:** ARM64 передаёт первые 8 аргументов в регистрах x0–x7, x86_64 — в rdi, rsi, rdx, rcx, r8, r9.
- **Выравнивание:** ARM64 требует выравнивания SP по 16 байт.
- **Порядок байт:** обе little-endian, но ARM поддерживает big-endian режим.
- **SIMD:** NEON (ARM) vs SSE/AVX (x86) — векторные операции различаются.

При реверсе ARM-библиотеки в Ghidra включите правильный языковой модуль (`AARCH64:LE:64:v8A`). Для Thumb-кода (ARM32) язык другой (`ARM:LE:32:v7`) — не перепутайте, иначе дизассемблер покажет мусор.

## Динамический анализ через Frida на разных ABI

Frida-сервер должен совпадать с ABI процесса. Для ARM-приложения на ARM-устройстве — `frida-server-arm64`; для x86-эмулятора — `frida-server-x86_64`. Если приложение ARM, а эмулятор x86 с bridge, Frida всё равно подключается к процессу, но хуки на нативные ARM-функции могут не срабатывать из-за трансляции — используйте `Module.findExportByName` и проверяйте адреса.

```bash
# определить ABI процесса
frida-ps -U -a | grep target
adb shell "cat /proc/$(pidof com.target.app)/maps | head"
```

## Что важно помнить

Трансляция — это компромисс между совместимостью и точностью. Для security-теста нативного кода она не заменяет реальное устройство: тайминги, криптография и анти-эмуляция могут вести себя иначе. Используйте эмулятор для быстрой итерации, но финальные выводы подтверждайте на ARM-устройстве. Это особенно важно для уязвимостей, зависящих от памяти и таймингов (race conditions, heap-эксплуатация).

## Квиз

```quiz
- question: "Что такое native bridge в Android?"
  options:
    - "Слой трансляции ARM-инструкций в x86 для запуска ARM-библиотек"
    - "Протокол Bluetooth"
    - "Формат подписи APK"
    - "Схема шифрования"
  answer: 0
- question: "Какое свойство указывает активный транслятор?"
  options:
    - "ro.dalvik.vm.native.bridge"
    - "ro.product.model"
    - "ro.build.version.sdk"
    - "persist.sys.locale"
  answer: 0
- question: "Почему ARM-приложение может упасть на x86-эмуляторе?"
  options:
    - "Bridge не поддерживает часть инструкций или отсутствует"
    - "APK слишком большой"
    - "Нет интернета"
    - "Не хватает памяти"
  answer: 0
- question: "Чем анализировать ARM64 .so на компьютере?"
  options:
    - "Ghidra или IDA с поддержкой ARM"
    - "jadx"
    - "apktool"
    - "exiftool"
  answer: 0
```

## Где пригодится

- **Пентест:** запуск нативных приложений в лаборатории.
- **Reverse:** анализ ARM-библиотек и понимание трансляции.
- **CTF:** задачи с нативным кодом на эмуляторе.
