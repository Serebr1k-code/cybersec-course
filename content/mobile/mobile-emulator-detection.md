---
id: mobile-emulator-detection
title: "Детект эмулятора, прокси и отладки: обход"
category: mobile
parent: mobile-network-security
difficulty: hard
order: 3
tags: [android, emulator, detection, anti-frida, proxy, qemu, bypass, frida, attestation]
prerequisites: [mobile-frida-detection, mobile-network-security]
useful_for:
  - "Пентест мобильных приложений"
  - "Bug bounty (обход детекта)"
  - "Анализ малвари"
estimated_minutes: 50
summary: "Как приложения детектят эмулятор, прокси, отладчик и Frida, и как это обходить: Frida-хуки Build/System properties, сокрытие портов, патч проверок, аппаратные устройства."
---
## Введение

Даже обойдя pinning и NSC, вы можете упереться в детект окружения: приложение понимает, что запущено на эмуляторе, за прокси или под отладкой, и отказывается работать. Это стандартная защита банков, платёжных и DRM-приложений. Задача пентестера — обойти эти проверки, чтобы дойти до бизнес-логики. Урок продолжает `mobile-frida-detection` (анти-Frida) и фокусируется на детекте эмулятора и прокси.

Ментальная модель: детект — это чтение «отпечатков» окружения (свойства, файлы, порты, датчики, тайминги). Обход — либо подмена отпечатков (хуки), либо устранение самих признаков (скрыть порты, переименовать файлы), либо переход на реальное устройство.

## Что проверяют приложения

| Категория | Признаки |
|-----------|----------|
| Эмулятор | `Build.FINGERPRINT` (generic/sdk), `ro.kernel.qemu`, `/dev/qemu_pipe`, файлы `goldfish` |
| Прокси | `System.getProperty("http.proxyHost")`, `ProxySelector`, `NetworkInterface` |
| Отладчик | `Debug.isDebuggerConnected()`, `ptrace`, `TracerPid` |
| Frida | порты 27042/27043, строки `frida`, `gum-js-loop`, maps |
| Root | `su`, `test-keys`, Magisk-пакеты |
| Датчики/железо | отсутствие акселерометра, странные значения сенсоров |

## Разведка детекта

```bash
# ищем проверки в коде
jadx -d out app.apk
grep -rn "FINGERPRINT\|isDebuggerConnected\|qemu\|proxyHost\|TracerPid\|27042" out/sources/ | head
# динамически: трассируем вызовы System.getProperty
frida -U -f com.target.app -l trace-props.js --no-pause
```

`trace-props.js`:

```javascript
Java.perform(function() {
  var Sys = Java.use("java.lang.System");
  Sys.getProperty.overload("java.lang.String").implementation = function(k) {
    var v = this.getProperty(k);
    console.log("getProperty " + k + " = " + v);
    return v;
  };
});
```

Так вы увидите, какие именно свойства читает приложение.

## Полный сквозной пример: обход детекта эмулятора и прокси

```javascript
// bypass-env.js
Java.perform(function() {
  var Build = Java.use("android.os.Build");
  Build.FINGERPRINT.value = "google/husky/husky:14/UQ1A.240205.004/11228891:user/release-keys";
  Build.MODEL.value = "Pixel 8 Pro";
  Build.MANUFACTURER.value = "Google";
  Build.PRODUCT.value = "husky";
  Build.HARDWARE.value = "husky";
  Build.TAGS.value = "release-keys";

  // скрыть прокси
  var Sys = Java.use("java.lang.System");
  Sys.getProperty.overload("java.lang.String").implementation = function(k) {
    if (k.indexOf("proxy") >= 0) return null;
    return this.getProperty(k);
  };
  var ProxySelector = Java.use("java.net.ProxySelector");
  ProxySelector.getDefault.implementation = function() { return null; };

  // отключить детект отладчика
  var Debug = Java.use("android.os.Debug");
  Debug.isDebuggerConnected.implementation = function() { return false; };
  Debug.waitingForDebugger.implementation = function() { return false; };

  console.log("[+] environment bypass active");
});
```

```bash
frida -U -f com.target.app -l bypass-env.js --no-pause
```

Приложение «думает», что работает на реальном Pixel без прокси и отладки.

## Сокрытие Frida и портов

```bash
# переименовать frida-server (обход строкового детекта)
mv /data/local/tmp/frida-server /data/local/tmp/fs
./fs -l 0.0.0.0:31337 &    # нестандартный порт
# подключение
frida -H 127.0.0.1:31337 -f com.target.app -l bypass.js
```

Также помогает модуль `frida-gadget` внутри приложения (без серверного процесса) и `frida-server` в stealth-сборках. Для продвинутого детекта (по карте памяти) — патчите `fopen`/`openat` на строки `frida`/`gum`.

## Переход на реальное устройство

Если детект слишком сильный (проверка сенсоров, TEE, аппаратной аттестации), единственный надёжный путь — **реальное root-устройство**. Эмулятор палится по сенсорам, GPU, таймингам и `Build`. Для финансовых приложений часто нужно: реальное устройство + Magisk + PIF + DenyList.

## Частые ошибки

- **Хукать `Build.FINGERPRINT` через `.value =` не всегда работает**: используйте `Java.use(...).FINGERPRINT.value = ...` в `Java.perform`.
- **Забыть про нативные проверки**: часть детекта — в .so (`/proc/self/maps`, `openat`); Java-хук не поможет, нужен `Interceptor` на нативных функциях.
- **Не скрыть порт Frida**: строковый детект `27042` ловит сервер — меняйте порт.
- **Только Java-детект**: проверяйте и `Debug.isDebuggerConnected`, и `TracerPid`.
- **Игнорировать сенсоры**: эмулятор без акселерометра легко детектится — используйте `-sensor` AVD-флаги.
- **Не перезапускать приложение**: хуки применяются на старте — используйте `-f`.

## Что дальше / решение

Обходите слоями: сокройте Frida → подмените Build/System properties → отключите proxy/detector-хуки → при сильном детекте уйдите на реальное устройство. Свяжите с `mobile-frida-detection`, `mobile-root-detection`, `mobile-integrity`. Дальше — `mobile-mitm-advanced`. Рекомендация в отчёте: детект — не замена серверной защите; полагаться только на клиентский детект нельзя.

## Справочная таблица

| Детект | Java-хук | Нативный |
|--------|----------|----------|
| FINGERPRINT | `Build.FINGERPRINT.value` | — |
| Прокси | `System.getProperty`, `ProxySelector` | — |
| Отладчик | `Debug.isDebuggerConnected` | `TracerPid` |
| Frida | — | `openat`, `maps` |
| Root | `File.exists` | `stat`, `su` |

| Приём | Эффект |
|-------|--------|
| stealth frida-server | обход строкового детекта |
| frida-gadget | без серверного процесса |
| реальное устройство | обход аппаратного детекта |

## Нативные детекты и их обход

Часть детекта живёт в `.so`: проверка `ptrace`, чтение `/proc/self/maps` на `frida`/`magisk`, `openat` на `su`, проверка `TracerPid`. Java-хуки тут не работают — нужен `Interceptor` на нативных функциях:

```javascript
// скрыть строки frida/magisk из maps
var openat = Module.findExportByName(null, "openat");
Interceptor.attach(openat, {
  onEnter: function(args) { this.path = args[1].readCString(); },
  onLeave: function(ret) {
    if (this.path && /maps|\/proc\/self\/status/.test(this.path)) {
      // можно подменить содержимое или результат
    }
  }
});

// обход ptrace-антидебага
var ptrace = Module.findExportByName(null, "ptrace");
Interceptor.replace(ptrace, new NativeCallback(function(){ return 0; }, 'long',
  ['int','int','pointer','pointer']));
```

Для детекта по `TracerPid` хукайте `fopen`/`fgets` на `/proc/self/status` и подменяйте значение на 0.

## Детект через сенсоры и железо

Эмулятор палится отсутствием/подозрительными значениями датчиков: акселерометр, гироскоп, магнитометр, проксимити, барометр. Проверка в коде — `SensorManager.getDefaultSensor`, чтение `SensorEvent`. Признаки: сенсор отсутствует, значения всегда одинаковые, обновления нет.

Обход на эмуляторе: AVD с включёнными сенсорами (`-sensor`/GUI), либо хук `SensorManager`:

```javascript
Java.perform(function() {
  var SM = Java.use("android.hardware.SystemSensorManager");
  // подмена getDefaultSensor / значений событий (сложно — зависит от версии)
});
```

Наиболее надёжно — реальное устройство. Также проверяют `Build.HARDWARE` (`ranchu`/`goldfish`), `ro.hardware`, GPU (`GL_RENDERER` = SwiftShader/Bluestacks).

## Скрипт комплексного обхода

```javascript
// bypass-all.js — комбинированный обход окружения
Java.perform(function() {
  var Build = Java.use("android.os.Build");
  Build.FINGERPRINT.value = "google/husky/husky:14/UQ1A.240205.004/11228891:user/release-keys";
  Build.HARDWARE.value = "husky"; Build.MODEL.value = "Pixel 8 Pro";
  Build.MANUFACTURER.value = "Google"; Build.TAGS.value = "release-keys";
  var Sys = Java.use("java.lang.System");
  Sys.getProperty.overload("java.lang.String").implementation = function(k){
    if (k.indexOf("proxy") >= 0) return null; return this.getProperty(k);
  };
  var Debug = Java.use("android.os.Debug");
  Debug.isDebuggerConnected.implementation = function(){ return false; };
});
// + нативные хуки ptrace/openat выше
```

## Сравнение: эмулятор vs реальное устройство

| Признак | Эмулятор | Реальное устройство |
|---------|----------|---------------------|
| Build.FINGERPRINT | generic/sdk | реальный |
| Сенсоры | часто нет | есть |
| GPU | SwiftShader | Adreno/Mali |
| Widevine L1 | нет | есть |
| TEE/attestation | нет | есть |
| Детект-стойкость | низкая | высокая |

Вывод: для сильного детекта нужен реальный root-телефон. Эмулятор удобен для быстрых тестов, но палится.

## Кейс: обход банковского детекта

```bash
# 1. Запускаем приложение, видим экран «устройство не поддерживается»
# 2. Логируем проверки
frida -U -f com.bank.app -l trace-all.js --no-pause | grep -iE 'fingerprint|proxy|debug|qemu'
# 3. Применяем bypass-all.js + нативные хуки
# 4. Приложение запускается
# 5. Далее — pinning/NSC (см. соответствующие уроки)
```

## Рекомендации в отчёте

Детект окружения — эшелонированная, но обходимая защита. Рекомендации: не полагаться только на клиентский детект, комбинировать с серверной аттестацией (Play Integrity/App Attest), проверять целостность в нативном коде с обфускацией, использовать hardware-backed проверки. Клиентский детект повышает стоимость атаки, но не исключает её.

## Продвинутый обход: сенсоры и нативные проверки

Детект по сенсорам требует либо реального устройства, либо подмены на уровне `SensorManager`. Хук событий сложен, потому что данные приходят через нативный канал. Практичнее — использовать AVD с включёнными виртуальными сенсорами (в GUI эмулятора) или реальное устройство. Если приложение проверяет конкретные значения (например, акселерометр «в покое»), подмена возможна через хук `SensorEvent.values`, но зависит от версии.

Нативные проверки (чтение `/proc/self/maps` на `frida`, `openat` на `su`) обходятся `Interceptor` на соответствующих функциях: перехватывайте `open`/`openat`/`fopen` и, если путь содержит `/proc/self/maps` или `/proc/self/status`, подменяйте содержимое. Для `maps` проще перехватить `open` и вернуть дескриптор на очищенный файл.

## Комплексный подход

Соберите один скрипт, который: подменяет Build-свойства, скрывает прокси, отключает `Debug.isDebuggerConnected`, хукает `ptrace`, фильтрует `maps`/`status`. Запускайте через `frida -f` (spawn), чтобы хуки встали до инициализации приложения. Проверяйте результат по логам приложения: прошло ли детект.

## Когда сдаваться

Если детект аппаратный (TEE, Secure Enclave, Strong Integrity), программный обход бесполезен — переходите на реальное «чистое» устройство или серверную подмену. Это важный вывод для отчёта: не все проверки обходятся инструментированием.

## Итоговый чек-лист обхода детекта окружения

1. Определите, что именно проверяется: `Build.FINGERPRINT`, прокси, отладка, сенсоры, Frida, root.
2. Запустите приложение под логирующим Frida-скриптом, соберите список проверок.
3. Обойдите Java-проверки хуками (`Build`, `System.getProperty`, `Debug`).
4. Обойдите нативные проверки (`ptrace`, `openat` на `su`, `maps`) через `Interceptor`.
5. Сокройте Frida (переименование, нестандартный порт, gadget).
6. При аппаратном детекте перейдите на реальное устройство.

Комбинируйте слои: сокрытие Frida + подмена Build + отключение proxy/debug-проверок. Проверяйте результат по логам приложения: прошло ли детект.

## Квиз

```quiz
- question: "Какое свойство Build чаще всего выдает эмулятор?"
  options:
    - "FINGERPRINT (generic/sdk)"
    - "VERSION.SDK_INT"
    - "MODEL"
    - "DEVICE"
  answer: 0
- question: "Как скрыть прокси от приложения через Frida?"
  options:
    - "Хук System.getProperty и ProxySelector.getDefault"
    - "Переустановить Burp"
    - "Сменить CA"
    - "Включить HTTP/2"
  answer: 0
- question: "Почему строковый детект Frida ловит сервер?"
  options:
    - "По стандартному порту 27042 и строкам frida"
    - "По размеру бинарника"
    - "По подписи APK"
    - "По версии Android"
  answer: 0
- question: "Что делать при аппаратном детекте эмулятора?"
  options:
    - "Перейти на реальное root-устройство"
    - "Отключить интернет"
    - "Сменить пароль"
    - "Обновить Burp"
  answer: 0
- question: "Где искать нативные проверки окружения?"
  options:
    - "В .so (openat, /proc/self/maps)"
    - "В AndroidManifest"
    - "В NSC"
    - "В Info.plist"
  answer: 0
```

## Где пригодится

- **Пентест:** обход детекта для доступа к функционалу.
- **Bug bounty:** демонстрация обхода защиты.
- **Анализ малвари:** сокрытие песочницы от образца.
- **CTF:** Mobile-задачи с детектом.
