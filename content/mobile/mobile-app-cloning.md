---
id: mobile-app-cloning
title: "Клонирование приложений, параллельные копии и обход детекта клона"
category: mobile
parent: mobile-insecure-storage
difficulty: medium
order: 2
tags: [mobile, android, cloning, dual-app, isolation]
prerequisites: [mobile-android-anatomy, mobile-insecure-storage]
useful_for:
  - "CTF Mobile: обход проверок окружения"
  - "Пентест: тестирование на клонированном экземпляре"
estimated_minutes: 38
summary: "Как работают клонирование и параллельные копии приложений (dual apps, Island, Shelter), почему приложения их детектят, как устроена изоляция данных и как обходить детект клона."
---

## Что такое клонирование приложения

Клонирование (app cloning, dual apps, parallel space) — это запуск второй копии одного и того же приложения на устройстве. Обычная установка одного и того же package name дважды невозможна: Android идентифицирует приложение по `packageName`, и система не даст поставить два APK с одинаковым именем. Клонирование обходит это, создавая «второй профиль»: либо отдельного пользователя Android (`user 10`, `user 999`), либо виртуальную среду, где приложение запускается под изменённым UID и с изолированным хранилищем.

Зачем это нужно тестировщику:
- **Несколько аккаунтов** одновременно (для проверки IDOR/BOLA между пользователями).
- **Изоляция** — запуск подозрительного APK без риска для основного профиля.
- **Проверка детекта клона** — многие банки и DRM-приложения отказываются работать в клоне, и это надо уметь обойти.

Механизмов клонирования несколько. Первый — **Multi-user**: Android поддерживает нескольких пользователей, у каждого свой набор приложений и своё `/data/user/<id>/`. Второй — **Work Profile** (Android for Work): отдельный профиль с изоляцией, создаётся через MDM или приложение вроде Island/Shelter. Третий — **VirtualApp-подобные** решения (Parallel Space, Dual Space, VirtualXposed): они запускают чужой APK внутри себя, подменяя контекст.

## Как приложение детектит клон

Приложения используют несколько признаков:
- **UID** — `Process.myUid()` не совпадает с ожидаемым диапазоном (в виртуальных средах UID чужой).
- **Путь к данным** — `getFilesDir()` возвращает не `/data/data/<pkg>/`, а путь виртуальной среды.
- **Список процессов** — наличие процессов `com.lbe.parallel`, `com.excean.dualaid`, `io.va` и т.п.
- **Multi-user** — `UserManager.getUserCount() > 1` или `getUserHandle`.
- **Work profile** — `DevicePolicyManager` и `isProfileOwnerApp`.
- **Свой package в списке** — `PackageManager.getPackageInfo(getPackageName())` возвращает чужой путь установки.

Пример детекта на Java:

```java
// грубый детект виртуальной среды по пути данных
String dataDir = getApplicationInfo().dataDir;
if (!dataDir.equals("/data/data/" + getPackageName())) {
    // запущено в клоне
}
// детект по UID
int uid = android.os.Process.myUid();
// ожидаемый диапазон приложений: 10000..19999
```

## Настройка клона: multi-user

Самый «чистый» способ — второй пользователь Android:

```bash
adb shell pm create-user tester
# -> Success: created user id 10
adb shell am switch-user 10
# установить APK во второго пользователя
adb install --user 10 app.apk
# запустить
adb shell am start --user 10 -n com.example.app/.MainActivity
```

Минус: в multi-user среде приложение видит, что пользователей больше одного, и может это детектить. Зато данные полностью изолированы, и это честное системное окружение.

## Настройка клона: work profile / Island

`Island` (или `Shelter`) создаёт managed profile через `DevicePolicyManager`:

```bash
# после установки Island: создать рабочую область, клонировать приложение
adb shell dumpsys user | grep -i "UserInfo"
# появляется user 10 с флагом Managed Profile
```

Приложения в work profile работают в отдельном профиле, с отдельным UID и хранилищем. Для теста это удобно: можно держать «личный» и «рабочий» аккаунт одного приложения.

## Обход детекта клона через Frida

Основной приём — вернуть «правильные» значения для проверок:

```javascript
Java.perform(function () {
  var AppInfo = Java.use("android.content.pm.ApplicationInfo");
  // не даём увидеть чужой dataDir — перехватываем чтение поля
  var pkg = "com.example.app";
  var correct = "/data/data/" + pkg;

  var ActivityThread = Java.use("android.app.ActivityThread");
  ActivityThread.getPackageName.implementation = function () {
    return pkg;
  };

  // Process.myUid() -> ожидаемый UID
  var Process = Java.use("android.os.Process");
  Process.myUid.implementation = function () {
    return 10123; // любой из диапазона приложений
  };

  // UserManager: притворяемся, что пользователь один
  var UM = Java.use("android.os.UserManager");
  UM.getUserCount.implementation = function () { return 1; };
  UM.isUserAGoat.implementation = function () { return false; };

  // PackageManager: путь установки = обычный
  var PM = Java.use("android.app.ApplicationPackageManager");
  var GIP = PM.getPackageInfo.overload('java.lang.String', 'int');
  GIP.implementation = function (name, flags) {
    var info = GIP.call(this, name, flags);
    if (name === pkg) {
      info.applicationInfo.value.dataDir.value = correct;
      info.applicationInfo.value.sourceDir.value = "/data/app/" + pkg + "-1/base.apk";
    }
    return info;
  };
});
```

Для нативных проверок (чтение `/proc/self/cmdline`, `maps`) подключайте `Interceptor` к `open`/`openat` и подменяйте пути (`mobile-native-so-deep`). Иногда проще запустить приложение в **multi-user**, где проверки на виртуальную среду не срабатывают, а проверку `getUserCount` нейтрализовать точечно.

## Клонирование как атака

Клонирование не только защитный барьер, но и вектор:
- **Клон-приложения собирают данные** — Parallel Space видит буфер обмена и файлы склонированного приложения.
- **Изоляция не абсолютна** — приложения в виртуальной среде могут читать чужое хранилище внутри этой среды.
- **Intent-перехват** — клон может перехватить implicit intent'ы оригинала.
- **Обход FLAG_SECURE** — некоторые клоны не пробрасывают защиту экрана.

## Частые ошибки и подводные камни

- **`adb install --user 10` падает** — APK уже установлен у user 0; используйте `-r` или другой package.
- **Приложение падает в клоне** — нативная библиотека не находит своё хранилище; проверьте `dataDir` хук.
- **Frida не видит процесс клона** — процесс в другом user; `frida-ps -U` покажет, но спавн может требовать `--user`.
- **Детект остаётся** — проверка идёт из нативного кода или из другого процесса; расширяйте хуки.
- **Work profile не создаётся** — на устройстве уже есть managed profile или OEM блокирует.

## Сравнение способов клонирования

| Способ | Изоляция данных | Детект приложением | Сложность |
|--------|-----------------|--------------------|-----------|
| Multi-user | полная (свой /data) | средний (userCount) | низкая |
| Work profile (Island) | полная | средний (DPM) | низкая |
| VirtualApp (Parallel Space) | внутри среды | высокий (UID/путь) | низкая |
| Ручной второй APK (патч packageName) | нет (общий /data) | низкий | средняя |

## Что дальше / решение

Выберите способ клонирования под задачу: для теста API между пользователями хватит multi-user или Island; для обхода виртуального детекта — Frida-хуки на UID, dataDir и UserManager. Зафиксируйте, какие проверки окружения использует приложение (это само по себе полезно для отчёта об anti-analysis). Дальше — `mobile-emulator-detection` (проверки эмулятора) и `mobile-root-detection`.

## Детект клона в нативном коде

Хуки на Java-уровне обходят далеко не всё: проверки часто реализованы в C/C++ и вызываются через JNI. Тогда Frida-хук `UserManager.getUserCount` не поможет, потому что нативный код читает `/proc/self/status`, `getuid()`, `readlink("/proc/self/exe")` напрямую.

```c
// пример нативной проверки пути данных
char path[256];
ssize_t n = readlink("/proc/self/exe", path, sizeof(path)-1);
if (n > 0) {
    path[n] = 0;
    if (strstr(path, "virtual") || strstr(path, "parallel")) {
        return JNI_TRUE; // детект клона
    }
}
```

Обход — перехват нативных функций через Frida `Interceptor`:

```javascript
["readlink", "open", "openat", "stat", "lstat"].forEach(function (name) {
  var addr = Module.findExportByName(null, name);
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.path = args[1].isNull() ? "" : args[1].readCString();
    },
    onLeave: function (retval) {
      // подменяем результат, если путь выдаёт среду клона
      if (this.path && this.path.indexOf("virtual") !== -1) {
        retval.replace(-1);
      }
    }
  });
});
```

Такой подход универсален: любая проверка, основанная на файловой системе, обходится подменой пути. Аналогично перехватывают `getuid`, `getpid`, `getppid`, если проверка идёт по идентификаторам процесса.

## Клонирование для анализа API

Одно из самых практичных применений клона — тестирование API между двумя пользователями. Многие уязвимости (IDOR, BOLA, горизонтальная эскалация) видны только при наличии двух валидных сессий одновременно. Порядок работы:

1. Создайте второго пользователя (`pm create-user`).
2. Установите приложение во второго пользователя (`adb install --user 10`).
3. Настройте прокси (Burp/mitmproxy) с пользовательским CA для обоих профилей.
4. Зафиксируйте токены обеих сессий.
5. В Repeater подменяйте идентификаторы (order_id, user_id) и наблюдайте ответ.

Важный нюанс: сетевые настройки и пользовательские сертификаты привязаны к пользователю. Для второго профиля может понадобиться отдельная установка CA (`adb install --user 10 ca-cert`), иначе трафик второго аккаунта не перехватится.

## Изоляция и границы доверия

С точки зрения модели угроз клонирование размывает границу между «моими» и «чужими» данными. В multi-user и work profile изоляция честная: у каждого пользователя свой каталог `/data/user/<id>/` и свои права. В VirtualApp-подобных средах изоляция реализована внутри одного процесса-хоста, и это регулярно приводит к утечкам: хост видит буфер обмена, может читать файлы гостевых приложений и перехватывать их intent'ы.

Для тестировщика вывод такой: если приложение хранит секреты (токены, ключи) во внешнем хранилище или в общедоступном месте, клон-среда может их прочитать. Проверяйте, куда именно приложение пишет данные (`getExternalFilesDir`, `MediaStore`, `Environment.getExternalStorageDirectory`), и не попадают ли туда токены.

## Что фиксировать в отчёте

При тестировании детекта клона фиксируйте:
- какие проверки окружения использует приложение (UID, dataDir, userCount, DPM);
- какие из них обходятся, а какие нет;
- падает ли приложение при обходе или просто показывает ошибку;
- есть ли обход через штатное multi-user без патчей.

Это формирует оценку устойчивости анти-клон защиты и показывает, насколько легко злоумышленник запустит приложение в подконтрольной среде для автоматизации атак.

## Квиз

```quiz
- question: "Почему нельзя просто установить один APK дважды под одним package name?"
  options:
    - "Android идентифицирует приложение по packageName, второй экземпляр не встанет"
    - "APK слишком большой"
    - "Google Play запрещает"
    - "Нет места на диске"
  answer: 0
- question: "Какой признак чаще всего выдаёт виртуальную среду клонирования?"
  options:
    - "Путь dataDir или UID отличаются от ожидаемых"
    - "Цвет иконки"
    - "Версия Android"
    - "Размер шрифта"
  answer: 0
- question: "Как запустить второй экземпляр приложения без виртуальных сред?"
  options:
    - "Через multi-user: pm create-user и adb install --user"
    - "Скопировать APK на SD-карту"
    - "Сменить обои"
    - "Отключить Wi-Fi"
  answer: 0
- question: "Что делает Frida-хук UserManager.getUserCount?"
  options:
    - "Возвращает 1, скрывая наличие второго пользователя"
    - "Ускоряет приложение"
    - "Включает Bluetooth"
    - "Подписывает APK"
  answer: 0
```

## Где пригодится

- **CTF:** обход проверок окружения в защищённых приложениях.
- **Пентест:** тестирование IDOR/BOLA между двумя аккаунтами одновременно.
- **Работа:** оценка устойчивости анти-клон защиты банковского приложения.
