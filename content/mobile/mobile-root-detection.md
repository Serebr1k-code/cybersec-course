---
id: mobile-root-detection
title: "Обход root-детекта и anti-Frida/anti-debug защит"
category: mobile
parent: mobile-runtime-bypass
difficulty: medium
order: 2
tags: [android, root-detection, anti-debug, frida, magisk, bypass]
prerequisites: [mobile-dynamic-frida]
useful_for:
  - "CTF Mobile (запуск защищённых приложений)"
  - "Bug bounty (анализ приложений с защитой)"
  - "Пентест мобильных приложений"
estimated_minutes: 30
summary: "Почему приложение отказывается работать на root-устройстве или падает при Frida, и как обойти проверки root, отладчика, целостности и anti-Frida."
---

Многие приложения (банки, платёжные, DRM, антифрод) отказываются работать на **root-устройстве** или при наличии **Frida/отладчика**. Это не баг, а защита: разработчик предполагает, что root = враждебная среда, где клиент можно подменить. Ваша задача в пентесте — обойти эти проверки, чтобы добраться до реальной логики.

Этот урок — продолжение `mobile-dynamic-frida`. Обход root/anti-Frida почти всегда предшествует `mobile-ssl-pinning` и динамическому анализу упакованных приложений. Пока вы не «прикинетесь чистым устройством», Frida будет падать, а приложение — крашиться.

## Что именно проверяет приложение

Прежде чем обходить, классифицируйте проверки:

| Проверка | Как реализована | Признак |
|----------|-----------------|---------|
| Root-детект | Наличие `su`, `busybox`, тестовых ключей, `Magisk`, RW-система | Отказ запуска, «root detected» |
| Anti-Frida | Поиск порта 27042, именованных потоков `gum-js-loop`, `frida-server` в `/proc` | Краш при подключении Frida |
| Anti-debug | `ptrace(PTRACE_TRACEME)`, `Debug.isDebuggerConnected()`, `/proc/self/status` | Краш/отказ при отладчике |
| Integrity | Проверка подписи APK, хэша DEX | Краш после патча/переподписи |
| Emulator-детект | `Build.FINGERPRINT`, `ro.hardware`, сенсоры | Отказ работать в эмуляторе |

Ключевой принцип: **все эти проверки выполняются в клиенте**, а значит, поддаются перехвату. Вопрос лишь в том, где именно они находятся.

## Root-детект: обход

### Уровень 1: Frida-хуки на Java-проверки

Стандартные методы root-детекта в Java: `Runtime.exec("su")`, проверка `File.exists("/system/xbin/su")`, `Build.TAGS` на `test-keys`. Перехват:

```javascript
Java.perform(function () {
  // 1. Блокируем Runtime.exec для su/which
  var Runtime = Java.use('java.lang.Runtime');
  Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
    if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
      console.log('[+] Заблокирован exec: ' + cmd);
      throw Java.use('java.io.IOException').$new('not found');
    }
    return this.exec(cmd);
  };

  // 2. Подменяем File.exists для путей root
  var File = Java.use('java.io.File');
  File.exists.implementation = function () {
    var p = this.getAbsolutePath();
    if (/su|magisk|busybox|xbin|superuser/i.test(p)) {
      console.log('[+] Скрыт путь: ' + p);
      return false;
    }
    return this.exists();
  };

  // 3. Build.TAGS -> release-keys
  var Build = Java.use('android.os.Build');
  Build.TAGS.value = 'release-keys';
});
```

Objection делает это одной командой:

```bash
objection -g com.target.app explore
> android root disable
```

### Уровень 2: Magisk + DenyList / Zygisk

Frida-хуки на Java не помогут против **нативных** проверок (JNI). Тогда используется сокрытие root на уровне системы:

- **Magisk DenyList** (или старый MagiskHide): добавляете приложение в список — Magisk скрывает от него следы root, `su`, `Magisk`-монтирования.
- **Zygisk + Shamiko**: модуль, который делает DenyList ещё эффективнее, скрывая Zygisk-инъекции.
- **Смена имени пакета Magisk** (restore/rename): `com.topjohnwu.magisk` → случайное имя, чтобы не детектилось по пакету.

```bash
# Проверка, что root скрыт от целевого приложения
adb shell su -c 'ls /system/xbin/su'   # есть для shell, но скрыто для app через DenyList
```

### Уровень 3: нативный root-детект

Если проверка в `.so`, ищите её и хукайте нативно:

```bash
# Символы, связанные с проверками
nm -D lib/arm64-v8a/libnative.so | grep -iE 'root|detect|check|jailbreak'
strings lib/arm64-v8a/libnative.so | grep -iE 'su|magisk|xbin'
```

```javascript
// Хук нативного open() — прячем доступ к root-файлам
var openPtr = Module.findExportByName(null, 'open');
Interceptor.attach(openPtr, {
  onEnter: function (args) {
    this.path = args[0].readCString();
  },
  onLeave: function (retval) {
    if (this.path && /su|magisk|xbin/.test(this.path)) {
      console.log('[*] Скрыт нативный open: ' + this.path);
      retval.replace(ptr(-1)); // ошибка
    }
  }
});
```

## Anti-Frida и anti-debug: обход

### Anti-Frida

Frida легко обнаружить по нескольким признакам. Обход:

1. **Переименовать frida-server.** Frida-сервер по умолчанию — процесс `frida-server`, слушает порт `27042`. Переименуйте бинарник и запустите на нестандартном порту:

```bash
adb push frida-server-16.x-android-arm64 /data/local/tmp/fs
adb shell "su -c '/data/local/tmp/fs -l 0.0.0.0:1234 &'"
frida -H 127.0.0.1:1234 -f com.target.app
```

2. **Патчить frida-gadget / использовать frida-gadget в обфусцированном виде.** Gadget внедряется в APK как библиотека — сложнее детектится, чем сервер.

3. **Скрыть потоки и память Frida.** Anti-Frida часто сканирует `/proc/self/maps` на `frida`/`gum` и потоки `gum-js-loop`. Хук на чтение этих файлов:

```javascript
// Прячем следы Frida при чтении /proc/self/maps
var fopen = Module.findExportByName(null, 'fopen');
Interceptor.attach(fopen, {
  onEnter: function (args) { this.path = args[0].readCString(); },
  onLeave: function (retval) { /* сложно фильтровать содержимое; чаще патчат сам детект */ }
});
```

На практике эффективнее **найти саму функцию детекта** и её отключить: ищите строки `frida`, `gum-js-loop`, `27042`, `REJECTED` и перекрестные ссылки на них.

### Anti-debug

```javascript
Java.perform(function () {
  // Отключаем Java-проверку отладчика
  var Debug = Java.use('android.os.Debug');
  Debug.isDebuggerConnected.implementation = function () { return false; };
  Debug.waitingForDebugger.implementation = function () { return false; };
});
```

Нативный `ptrace(PTRACE_TRACEME)` (защита от подключения отладчика) обходится патчем или хуком на `ptrace`:

```javascript
var ptracePtr = Module.findExportByName(null, 'ptrace');
Interceptor.replace(ptracePtr, new NativeCallback(function (req) {
  return 0; // притворяемся, что всё ок
}, 'long', ['int', 'int', 'pointer', 'pointer']));
```

## Integrity-проверки

Проверка подписи APK ломает патч+переподпись. Обход:

- **Хук `PackageManager.getPackageInfo`** — подменить `signatures` на оригинальные.
- **Хук вычисления хэша DEX** — вернуть ожидаемое значение.
- **Отключить проверку целиком**, найдя её по строкам.

```javascript
Java.perform(function () {
  var PM = Java.use('android.app.ApplicationPackageManager');
  PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
    var info = this.getPackageInfo(pkg, flags);
    if (pkg === 'com.target.app') {
      console.log('[*] Подмена подписи в getPackageInfo');
      // подменяем info.signatures на заранее сохранённые оригинальные
    }
    return info;
  };
});
```

## Разобранный пример: приложение падает при Frida

```bash
# 1. Подключаем Frida -> приложение мгновенно крашится (anti-Frida)
frida -U -f com.bank.app -l unpin.js
# -> "Process terminated"

# 2. Ищем строки anti-Frida
jadx -d src app.apk
grep -rniE 'frida|27042|gum-js-loop|ptrace|isDebuggerConnected' src/sources | head
# -> класс com.bank.app.RootChecker с методами checkFrida/checkDebug

# 3. Хукаем сами методы детекта (проще всего — вернуть false)
cat > bypass.js <<'EOF'
Java.perform(function () {
  var RC = Java.use('com.bank.app.RootChecker');
  RC.checkFrida.implementation = function () { console.log('[+] checkFrida->false'); return false; };
  RC.checkDebug.implementation = function () { console.log('[+] checkDebug->false'); return false; };
  RC.isRooted.implementation = function () { console.log('[+] isRooted->false'); return false; };
});
EOF

# 4. Запускаем с обходом
frida -U -f com.bank.app -l bypass.js --no-pause
# -> приложение работает, теперь можно снимать pinning
```

Ключ: **найти конкретную функцию детекта и обезвредить её**, а не пытаться спрятать Frida «в общем». Ищите по строкам-маркерам, по именам классов (`RootChecker`, `SecurityCheck`, `AntiTamper`) и по вызовам API.

## Частые ошибки

- **Хукать только Java, когда проверка нативная.** JNI-детект (`ptrace`, `open("su")`) требует нативных хуков или сокрытия root на уровне системы.
- **Пытаться спрятать Frida вместо отключения детекта.** Гораздо проще вернуть `false` из найденной функции проверки.
- **Забыть про integrity-проверку после патча APK.** Переподписанный APK падает — нужен хук на проверку подписи.
- **Игнорировать эмулятор-детект.** Некоторые приложения проверяют `ro.hardware`/сенсоры — работайте на реальном устройстве или патчьте проперти.
- **Не перезапускать приложение после смены DenyList.** Нужен полный рестарт (иногда перезагрузка).

## Квиз

```quiz
- question: "Почему приложение может крашиться сразу при подключении Frida?"
  options:
    - "В нём есть anti-Frida/anti-debug проверки, которые его останавливают"
    - "Frida несовместима с Android"
    - "Приложение не поддерживает HTTPS"
    - "Закончилась память"
  answer: 0
- question: "Что из перечисленного НЕ является признаком root-детекта?"
  options:
    - "Проверка наличия `/system/xbin/su`"
    - "Проверка `Build.TAGS` на `test-keys`"
    - "Проверка `Content-Type` в HTTP-запросе"
    - "Проверка пакета `com.topjohnwu.magisk`"
  answer: 2
- question: "Какой инструмент скрывает root от приложения на уровне системы?"
  options:
    - "Magisk DenyList (Zygisk + Shamiko)"
    - "apktool"
    - "exiftool"
    - "jadx"
  answer: 0
- question: "Самый надёжный способ обезвредить проверку `RootChecker.isRooted()` — это…"
  options:
    - "переустановить приложение"
    - "найти функцию и через Frida заставить её возвращать `false`"
    - "выключить Wi-Fi"
    - "запустить эмулятор"
  answer: 1
- question: "Если Java-хуки не помогают против root-детекта, где искать проверку?"
  options:
    - "В AndroidManifest.xml"
    - "В ресурсах `res/`"
    - "В нативном коде (`.so`), например через `open`/`ptrace`"
    - "В настройках Gradle"
  answer: 2
```

## Где пригодится

- **CTF Mobile:** запуск защищённых приложений, которые иначе отказываются работать на тестовом устройстве.
- **Bug bounty:** анализ банковских/платёжных приложений с антифродом и anti-tamper.
- **Пентест:** оценка реальной стойкости клиентских защит и их обходимости.
- **Работа:** консультирование по усилению анти-реверс защит (что реально работает, а что нет).
