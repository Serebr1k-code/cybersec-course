---
id: mobile-native-so-deep
title: "Реверс .so: ARM64, JNI и нативные проверки"
category: mobile
parent: mobile-native-reversing
difficulty: expert
order: 3
tags: [android, native, so, arm64, jni, ghidra, ida, radare2, frida, register-natives]
prerequisites: [mobile-android-native]
useful_for:
  - "Реверс-инжиниринг"
  - "Пентест мобильных приложений"
  - "CTF Mobile"
estimated_minutes: 50
summary: "Углублённый реверс нативных библиотек Android: определение архитектуры, разбор JNI (Java_* и RegisterNatives), Ghidra/IDA/r2, динамические хуки, снятие строковой обфускации."
---
## Введение

Когда приложение переносит проверку (root, лицензия, крипто) в нативный `.so`, Java-инструменты бессильны. Нужно реверсить ARM64-ассемблер, находить JNI-точки входа, восстанавливать логику и — часто быстрее — хукать её в рантайме. Этот урок — практическое руководство по нативному реверсу Android: от выбора архитектуры до снятия обфускации.

Цель — уметь: (1) найти нужную библиотеку и функцию, (2) понять JNI-связь с Java, (3) прочитать/хукнуть логику, (4) обойти анти-анализ.

## Определение архитектуры и извлечение

```bash
unzip -l app.apk | grep -E 'lib/.*\.so'
# lib/arm64-v8a/libnative.so
# lib/armeabi-v7a/libnative.so
unzip app.apk 'lib/arm64-v8a/*' -d out
file out/lib/arm64-v8a/libnative.so
# ELF 64-bit LSB shared object, ARM aarch64
```

Выбирайте arm64-v8a (современные устройства). Проверка символов:

```bash
nm -D out/lib/arm64-v8a/libnative.so | head
readelf -d out/lib/arm64-v8a/libnative.so | grep NEEDED
strings -n 6 out/lib/arm64-v8a/libnative.so | grep -iE 'root|verify|license|key'
```

## JNI: точки входа

Два способа привязки Java→нативный:

1. **Именованные символы** `Java_<pkg>_<Class>_<method>`:
```bash
nm -D libnative.so | grep Java_
# Java_com_target_app_NativeChecker_check
```
2. **RegisterNatives** (динамическая регистрация, часто в release):
```cpp
// ищем в JNI_OnLoad вызов RegisterNatives с таблицей {name, sig, fnPtr}
```

В Ghidra: открыть `libnative.so`, найти `JNI_OnLoad`, перейти по `RegisterNatives`, восстановить таблицу (имена + указатели на функции).

## Статический анализ: Ghidra/IDA/r2

```bash
# Ghidra headless
analyzeHeadless /tmp/ghidra_proj proj -import libnative.so -postScript decompile.py
# radare2
r2 -A libnative.so
[0x...]> afl            # список функций
[0x...]> pdf @ sym.Java_com_target_app_NativeChecker_check
[0x...]> axt @ str.root_check
```

Читая декомпилированный код, ищите: сравнения строк (root-пути, «/su», «test-keys»), вызовы `strcmp`, `access`, `fopen`, крипто (`AES_*`, `SHA*`), проверки `getpid`/`ptrace`.

## Динамика: Frida на JNI и нативных функциях

Хук нативной функции по адресу/имени:

```javascript
// hook-native.js
var base = Module.findBaseAddress("libnative.so");
var check = base.add(0x1A2C);   // смещение из Ghidra
Interceptor.attach(check, {
  onEnter: function(args) { console.log("check called, arg0=" + args[0]); },
  onLeave: function(retval) {
    console.log("original ret=" + retval);
    retval.replace(0x1);   // принудительно "true"
  }
});
```

Хук JNI-метода через Java-мост:

```javascript
Java.perform(function() {
  var Checker = Java.use("com.target.app.NativeChecker");
  Checker.check.implementation = function() { return true; };
});
```

## Полный сквозной пример: обход нативной root-проверки

```bash
# 1. Находим библиотеку и функцию
nm -D lib/arm64-v8a/libnative.so | grep -i Java_
# Java_com_target_app_NativeChecker_isRooted
# 2. Смотрим в Ghidra -> функция возвращает bool, внутри strcmp с "/su"
# 3. Быстрый обход через Frida по символу
frida -U -f com.target.app -l - <<'EOF'
var f = Module.findExportByName("libnative.so", "Java_com_target_app_NativeChecker_isRooted");
Interceptor.replace(f, new NativeCallback(function(env, thiz) {
  return 0;   // false
}, 'jboolean', ['pointer', 'pointer']));
EOF
# 4. Приложение больше не блокируется
```

Если символы удалены и используется `RegisterNatives`, найдите адрес через Frida-перечисление:

```javascript
// перечислить зарегистрированные нативы (через art)
// либо трассировать JNI_OnLoad и перехватить RegisterNatives
var rn = Module.findExportByName(null, "RegisterNatives");
Interceptor.attach(rn, { onEnter: function(a){ /* dump таблицы a[2] */ } });
```

## Снятие строковой обфускации и анти-анализ

- **Зашифрованные строки**: строки расшифровываются в рантайме — хукайте функцию-декриптор или дампните память после инициализации.
- **OLLVM (control-flow flattening)**: Ghidra декомпилирует плохо; используйте плагины деобфускации или динамическую трассировку.
- **Anti-debug/anti-Frida**: `ptrace(PTRACE_TRACEME)`, проверка `/proc/self/status` (TracerPid), поиск `frida` в maps — обходится Frida-хуками (см. `mobile-frida-detection`).

```javascript
// обход ptrace-антидебага
var ptrace = Module.findExportByName(null, "ptrace");
Interceptor.replace(ptrace, new NativeCallback(function() { return 0; }, 'long', ['int','int','pointer','pointer']));
```

## Частые ошибки

- **Реверсить не ту архитектуру**: берёте arm64, а устройство/эмулятор — x86_64.
- **Искать только `Java_*`**: в release используется `RegisterNatives`.
- **Хукать по имени, которого нет**: используйте `findExportByName` либо базу+смещение.
- **Забыть про thumb/arm переключение** (armeabi-v7a): младший бит адреса.
- **Игнорировать обфускацию строк**: `strings` пуст, потому что строки шифрованы.
- **Смещение из другой версии .so**: адреса меняются между сборками — пересчитывайте.

## Что дальше / решение

Порядок: определить архитектуру → найти JNI-вход → статически понять логику (Ghidra) → динамически подтвердить/обойти (Frida). Свяжите с `mobile-android-native` (основы JNI), `mobile-frida-detection` (анти-анализ), `mobile-android-packers`. Дальше — `mobile-dart-reversing`, `mobile-react-native-reversing`.

## Справочная таблица

| Задача | Инструмент/команда |
|--------|--------------------|
| Список .so | `unzip -l app.apk \| grep .so` |
| Символы JNI | `nm -D lib.so \| grep Java_` |
| Дизасм | `r2 -A lib.so; pdf @ sym.X` |
| Декомпиляция | Ghidra headless |
| Хук натива | `Interceptor.attach(base.add(off))` |
| Хук JNI | `Java.use(...).method` |

| Анти-анализ | Обход |
|-------------|-------|
| ptrace | Interceptor.replace |
| TracerPid | хук чтения /proc |
| строки шифрованы | дамп памяти/хук декриптора |
| OLLVM | плагины/трассировка |

## Сквозной кейс: обход нативной проверки целостности

Разберём полный цикл на примере библиотеки `libprotect.so`, которая проверяет целостность APK и подпись.

Первый этап — разведка. Извлекаем библиотеку, смотрим символы:

```bash
unzip app.apk 'lib/arm64-v8a/*' -d out
nm -D out/lib/arm64-v8a/libprotect.so | grep -iE 'Java_|verify|check|integrity'
strings out/lib/arm64-v8a/libprotect.so | grep -iE 'signature|hash|tamper'
```

Находим `Java_com_target_app_Security_verifyIntegrity`. Смотрим в Ghidra: функция считает хэш APK и сравнивает с зашитым значением, возвращает bool.

Второй этап — динамика. Быстрее всего — хук нативной функции по имени:

```javascript
var f = Module.findExportByName("libprotect.so", "Java_com_target_app_Security_verifyIntegrity");
Interceptor.replace(f, new NativeCallback(function(env, thiz){ return 1; }, 'jboolean', ['pointer','pointer']));
```

Если символы удалены (strip), находим адрес через Ghidra (база + смещение) и хукаем `Interceptor.attach(base.add(0x1234))`.

Третий этап — обход анти-анализа. Часто проверка защищена: `ptrace`, чтение `/proc/self/maps` на Frida, проверка `TracerPid`. Обходим нативными хуками (см. `mobile-emulator-detection`). Иногда проверка вызывается из конструктора (`JNI_OnLoad`), поэтому хук нужно ставить до загрузки — используйте `frida -f` (spawn) и `Interceptor` на `dlopen`.

## JNI и RegisterNatives

В release-сборках методы часто регистрируются через `RegisterNatives`. Находим таблицу в `JNI_OnLoad`: перехватываем `RegisterNatives` и дампим массив (имя, сигнатура, указатель). Это даёт адреса всех нативных методов — базу для хуков.

## Строковая обфускация

Если `strings` пуст, строки шифрованы. Находим функцию-декриптор (вызывается при инициализации), хукаем её и логируем возвращаемые строки. Так восстанавливаем root-пути, C2, ключи.

## Чек-лист

Извлечь .so, найти JNI-вход, понять логику в Ghidra, подтвердить/обойти через Frida, обойти анти-анализ, оформить. Для strip-бинарей использовать базу+смещение.

## Рекомендации в отчёте

Нативная защита усложняет реверс, но обходится хуком. Рекомендации: комбинировать нативную проверку с серверной, обфусцировать (OLLVM), использовать hardware-backed аттестацию. Клиентская проверка целостности — барьер, не гарантия.

## Практические советы по нативному реверсу

Начинайте с разведки, а не с декомпиляции: `nm -D`, `strings`, `readelf -d` дают карту символов и зависимостей за секунды. Если символы есть — хукайте по имени; если нет — переходите к Ghidra и база+смещение. Всегда фиксируйте версию библиотеки (хэш), потому что смещения меняются между сборками.

Для ARM64 помните про ABI: аргументы в `x0..x7`, возврат в `x0`/`w0`. В JNI первый аргумент — `JNIEnv*`, второй — `jobject`/`jclass`. Это помогает читать Ghidra-декомпиляцию.

## Обфускация и анти-анализ

OLLVM делает декомпиляцию тяжёлой — не тратьте часы на статику, идите динамикой. Строковое шифрование обходится хуком декриптора. Anti-debug (ptrace) — хуком `ptrace`. Anti-Frida — сокрытием портов и строк. Комбинируйте статику и динамику: статика даёт точки интереса, динамика подтверждает и обходит.

## Итог

Нативный реверс Android — итеративный процесс: разведка → Ghidra → Frida → обход анти-анализа. Часто быстрее обойти проверку хуком, чем полностью её понять. Документируйте найденные смещения и версии для воспроизводимости.

## Продвинутые приёмы нативного реверса

Разберём тонкости, которые экономят часы. Во-первых, всегда начинайте с определения точки входа JNI. Если символы есть, `nm -D | grep Java_` даёт их сразу. Если нет — ищите `JNI_OnLoad` (экспортируется всегда) и в нём вызов `RegisterNatives`, где таблица `{name, signature, fnPtr}` связывает Java-методы с нативными функциями. Дампните эту таблицу через Frida:

```javascript
var rn = Module.findExportByName(null, "RegisterNatives");
Interceptor.attach(rn, { onEnter: function(a){
  var env = a[0], clazz = a[1], methods = a[2], n = a[3].toInt32();
  for (var i=0;i<n;i++){
    var name = methods.add(i*12).readPointer().readCString();
    var fn   = methods.add(i*12+8).readPointer();
    console.log(name, fn);
  }
}});
```

Так вы получаете адреса всех нативных методов — базу для хуков даже без символов.

Во-вторых, для ARM64 помните про соглашения: аргументы в `x0..x7`, возврат в `x0`/`w0`, JNIEnv — `x0`, jobject/jclass — `x1`. В Ghidra это помогает читать сигнатуры.

В-третьих, обфускация: OLLVM (control-flow flattening) делает декомпиляцию нечитаемой — не тратьте часы, идите динамикой. Строковое шифрование обходится хуком декриптора (логируйте возвращаемые строки). Anti-debug/anti-Frida обходится хуками `ptrace`/`openat`.

## Практика хуков

Для проверки, которая возвращает bool, `Interceptor.replace` с `NativeCallback`, возвращающим 1, — самый быстрый обход. Для функций, возвращающих сложные типы, используйте `onLeave` и `retval.replace`. Всегда проверяйте, что хук встал до вызова (spawn, а не attach, если проверка в конструкторе).

## Итог

Нативный реверс — итеративный: разведка → Ghidra → Frida → обход. Фиксируйте хэши библиотек и смещения. Комбинируйте статику и динамику.

## Квиз

```quiz
- question: "Как называется именованная JNI-функция для метода isRooted класса NativeChecker пакета com.target.app?"
  options:
    - "Java_com_target_app_NativeChecker_isRooted"
    - "com.target.app.NativeChecker.isRooted"
    - "jni_NativeChecker_isRooted"
    - "NativeChecker_isRooted"
  answer: 0
- question: "Что делает RegisterNatives?"
  options:
    - "Динамически регистрирует нативные методы (имена не видны в символах)"
    - "Загружает APK"
    - "Сканирует порты"
    - "Меняет подпись"
  answer: 0
- question: "Как принудительно вернуть false из нативной функции через Frida?"
  options:
    - "Interceptor.replace/NativeCallback с return 0"
    - "adb uninstall"
    - "Сменить CA"
    - "Переустановить Burp"
  answer: 0
- question: "Что такое OLLVM?"
  options:
    - "Обфускация control-flow, усложняющая декомпиляцию"
    - "Тип сертификата"
    - "Формат бэкапа"
    - "Протокол сети"
  answer: 0
- question: "Как обойти ptrace-антидебаг?"
  options:
    - "Interceptor.replace(ptrace, ...) вернуть 0"
    - "Отключить Wi-Fi"
    - "Сменить пароль"
    - "Обновить Android"
  answer: 0
```

## Где пригодится

- **Реверс:** нативные проверки — ядро защиты приложений.
- **Пентест:** обход нативного root/лицензии.
- **Bug bounty:** понимание крипто/логики.
- **CTF:** Mobile-задачи с .so.
