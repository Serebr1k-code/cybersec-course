---
id: reversing-android-native
title: "Android native: JNI, .so и обфускация"
category: reversing
parent: reversing-android-apk
difficulty: hard
order: 1
tags: [reversing, android, jni, native, so, arm64, ghidra]
prerequisites: [reversing-android-apk, reversing-architectures]
useful_for:
  - "CTF Reversing / Mobile"
  - "Анализ Android-малвари"
  - "Bug bounty (мобильные клиенты)"
estimated_minutes: 65
summary: "Реверс нативных .so в Android: JNI-биндинг, arm64, декомпиляция, обфускация и динамика."
---
Современные Android-приложения выносят критичную логику — криптографию, проверки лицензии, анти-анализ, работу с токенами — в **нативные библиотеки** `.so` (ARM64/ARM). Java-часть становится лишь обёрткой, а реальные секреты живут в машинном коде. Реверс JNI-библиотек — обязательный навык для анализа Android-малвари и bug bounty мобильных клиентов. Здесь нет привычного байткода: вы работаете с ARM64-ассемблером, JNI-биндингом и обфускацией OLLVM. В этом уроке — структура APK, JNI-механизм, инструменты и полный разбор нативной проверки.

## Структура APK и загрузка нативных библиотек

APK — это ZIP с `classes.dex` (Java/DEX), `lib/<abi>/*.so` (нативные библиотеки для разных архитектур: `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`), `AndroidManifest.xml`, ресурсами. Java-код загружает `.so` через `System.loadLibrary("native")` или `System.load("/data/.../libnative.so")`. Точка входа — `JNI_OnLoad`, где библиотека может динамически регистрировать функции. Просмотр содержимого:

```bash
unzip -l app.apk | grep -E '\.so|\.dex'
unzip -o app.apk 'lib/arm64-v8a/*' -d extracted/
file extracted/lib/arm64-v8a/libnative.so
readelf -d extracted/lib/arm64-v8a/libnative.so
```

## JNI-биндинг: экспорты и RegisterNatives

Есть два способа связать Java-метод с нативной функцией. Первый — **соглашение об именах**: функция экспортируется как `Java_<package>_<Class>_<method>` с заменой `.` на `_`. Например, `com.example.App.check(String)` → `Java_com_example_App_check`. Второй — **динамическая регистрация** через `RegisterNatives`, где таблица `{name, signature, fnPtr}` передаётся в JNI. Динамическая регистрация часто используется для обфускации: имена не экспортируются, и связь скрыта. Поиск экспортов:

```bash
nm -D extracted/lib/arm64-v8a/libnative.so | grep Java_
readelf --dyn-syms extracted/lib/arm64-v8a/libnative.so | grep -i java
```

Если экспортов `Java_*` нет — ищите `RegisterNatives` в дизассемблере и таблицу методов рядом.

## Инструменты анализа

- **Ghidra** с процессором `AARCH64` (или ARMv7) — основной дизассемблер; скрипты для JNI (`JNIAnalyzer`), восстановление типов JNIEnv.
- **IDA Pro** с Hex-Rays (декомпилятор ARM64) — лучшая декомпиляция; плагины `JNI Helper`.
- **radare2/rizin** — `r2 -a arm -b 64 libnative.so`, `aa`, `afl`, `pdf`.
- **JADX** — декомпиляция Java-обёртки, чтобы увидеть вызовы `native` методов и `loadLibrary`.
- **objdump/readelf** — секции, экспорты, релокации.
- **Frida** — динамика: хук JNI-функций, чтение аргументов.
- **Unicorn** — эмуляция фрагментов нативной функции без устройства.

## ARM64 ABI и соглашения вызовов

В ARM64 (AArch64) первые восемь аргументов передаются в `X0`–`X7`, возврат — в `X0`. `JNIEnv*` — первый аргумент (`X0`), `jobject`/`jclass` — второй (`X1`), далее пользовательские. `JNIEnv` — указатель на таблицу функций (`JNINativeInterface`); вызов `env->GetStringUTFChars(env, str, 0)` — это косвенный вызов через смещение в таблице. Понимание этого критично: в дизассемблере вы увидите `LDR X8, [X0, #offset]` и `BLR X8`. Для `armeabi-v7a` аргументы — в `R0`–`R3` и на стеке. Точки входа: `JNI_OnLoad(JavaVM*, void*)` — `X0` = JavaVM.

## Обфускация native: OLLVM, строки, индирекция

- **OLLVM (Obfuscator-LLVM)** — control-flow flattening (диспетчер-свитч вместо нормального потока), bogus control flow (мёртвые блоки), instruction substitution. Признаки: огромный switch в начале функции, «плоский» граф.
- **Строковое шифрование** — строки хранятся зашифрованными и расшифровываются в рантайме. Ищите функции-декрипторы и хукайте их Frida.
- **JNI-индирекция** — вызовы JNI через собственные обёртки, чтобы спрятать `GetStringUTFChars`.
- **Anti-debug/anti-Frida** — проверки `ptrace`, `/proc/self/maps` на наличие `frida`, `TracerPid`.
- **Упаковка** — сам `.so` зашифрован и распаковывается в памяти (см. кастомные пакеры).

## Динамика: Frida и хуки JNI

Frida позволяет перехватить нативную функцию по адресу или экспорту и прочитать аргументы:

```javascript
// hook экспортированной JNI-функции
var addr = Module.findExportByName("libnative.so", "Java_com_example_App_check");
Interceptor.attach(addr, {
  onEnter: function (args) {
    console.log("env=", args[0], "obj=", args[1], "str=", args[2]);
    var s = Java.vm.getEnv().getStringUtfChars(args[2], null).readCString();
    console.log("input =", s);
  },
  onLeave: function (retval) {
    console.log("return =", retval);
  }
});
```

Запуск: `frida -U -f com.example.app -l hook.js --no-pause`. Для обхода анти-Frida используют `frida-server` с переименованием или патч проверок. Также работает хукинг `RegisterNatives` для перехвата динамически зарегистрированных функций.

## Полный разбор: проверка лицензии в .so

**Шаг 1 — Java-обёртка.** JADX показывает: `native boolean checkLicense(String key)` и `System.loadLibrary("license")`.

**Шаг 2 — экспорты.** `nm -D liblicense.so | grep Java_` → `Java_com_example_License_checkLicense`. Если пусто — ищем `RegisterNatives`.

**Шаг 3 — декомпиляция.** В Ghidra/IDA анализируем функцию: она вызывает `GetStringUTFChars`, затем проверяет строку посимвольно, сравнивая с зашифрованной константой. Видим цикл XOR/сложение.

**Шаг 4 — извлечение.** Восстанавливаем алгоритм и решаем: либо инвертируем проверку в Z3, либо хукаем Frida и читаем расшифрованную строку в рантайме.

**Шаг 5 — проверка.** Собираем ключ и проверяем на приложении.

## Шпаргалка

| Задача | Команда/инструмент |
|---|---|
| Список .so | `unzip -l app.apk \| grep .so` |
| Экспорты JNI | `nm -D lib.so \| grep Java_` |
| Динамическая регистрация | поиск `RegisterNatives` |
| Дизассемблер | Ghidra (AARCH64), IDA, r2 |
| Java-обёртка | JADX |
| Динамика | Frida `Interceptor.attach` |
| Аргументы JNI | X0=env, X1=obj, X2+=args |
| Обход анти-Frida | переименование server, патч |

## Что дальше / решение

Маршрут: распакуйте APK, найдите `.so`, определите экспорты JNI (или `RegisterNatives`), декомпилируйте функцию в Ghidra/IDA, разберите алгоритм (часто XOR/таблицы), извлеките ключ статически или через Frida-хук, проверьте на устройстве. Учитывайте ARM64 ABI и JNIEnv-таблицу. Дальше изучайте OLLVM-деобфускацию, распаковку нативных протекторов и anti-Frida обходы.

## Anti-Frida, anti-debug и обход

Нативные библиотеки часто защищаются от анализа. Типичные проверки:

- **ptrace self-attach**: `ptrace(PTRACE_TRACEME, 0, 0, 0)` — если вернёт ошибку, уже под отладчиком. Обход: патч вызова или Frida-хук, возвращающий 0.
- **Проверка `/proc/self/status`** на `TracerPid != 0` — ищем открытие файла и чтение строки. Обход: хук `fopen`/`open` с подменой содержимого.
- **Поиск «frida» в `/proc/self/maps`** — библиотеки Frida (`frida-agent`, `libfrida`) видны в отображённых сегментах. Обход: переименовать `frida-server`, использовать `--realm`, патчить проверку.
- **Проверка порта 27042** (порт по умолчанию frida-server) через `connect`. Обход: запустить server на другом порту.
- **Сканирование памяти на паттерны** (строки «frida», «gum-js-loop»). Обход: кастомная сборка Frida с изменёнными строками.

Практически: сначала определяют наличие проверок (по строкам `ptrace`, `frida`, `/proc/self`), затем ставят хуки до запуска anti-анализа. `frida -U -f com.app --no-pause -l bypass.js`, где `bypass.js` перехватывает `ptrace` и `open`.

## Эмуляция и трассировка без устройства

Когда устройство недоступно или функция самодостаточна, применяют эмуляцию:

- **Unicorn Engine** — эмуляция ARM64-кода с ручной настройкой регистров и памяти:
  ```python
  from unicorn import *
  from unicorn.arm64_const import *
  mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
  mu.mem_map(0x1000, 0x10000)
  mu.mem_write(0x1000, code_bytes)
  mu.reg_write(UC_ARM64_REG_X0, 0x2000)   # JNIEnv / аргумент
  mu.emu_start(0x1000, 0x1000 + len(code_bytes))
  print(mu.reg_read(UC_ARM64_REG_X0))     # результат
  ```
- **QBDI** — динамическая инструментация в процессе (см. отдельный урок).
- **gdb-multiarch** — отладка `.so` через `qemu-arm64` или на устройстве: `gdb-multiarch libnative.so`, `set architecture aarch64`, `target remote :1234`.
- **radare2** — `r2 -a arm -b 64 -e asm.cpu=cortex-a53 libnative.so`, затем `aaa`, `pdf @ sym.func`.

Эмуляция особенно полезна для функций-декрипторов: подставляем зашифрованную строку и читаем результат.

## Разбор OLLVM-функции

Функция, «уплощённая» OLLVM (control-flow flattening), начинается с инициализации переменной-состояния и бесконечного цикла со switch:

```
MOV W8, #0x1A1B           ; начальное состояние
loop:
  MOV W9, W8
  CMP W9, #0x1A1B
  B.EQ case_A
  CMP W9, #0x5F3C
  B.EQ case_B
  ...
case_A:
  ; реальный блок 1
  MOV W8, #0x5F3C          ; следующее состояние
  B loop
```

Реальный поток восстанавливают, отслеживая, какое состояние присваивается в конце каждого блока: получается цепочка блоков. Инструменты `de-flattener` для Ghidra/IDA автоматизируют это, но вручную тоже реально: строится граф «блок → следующее состояние» и линеаризуется. Bogus control flow (мёртвые блоки) отсекают по недостижимости. Instruction substitution (например, `a+b` через `-( -a - b )`) упрощают алгебраически.

| Защита | Признак | Обход |
|---|---|---|
| ptrace | вызов `ptrace` | хук/патч |
| TracerPid | чтение `/proc/self/status` | подмена файла |
| frida-строки | `frida` в maps | переименование/патч |
| port 27042 | `connect` на порт | сменить порт |
| OLLVM flattening | switch-диспетчер | de-flattener |
| строковое шифрование | декриптор | хук/эмуляция |

## Сборка и проверка модифицированного APK

После патча нативной библиотеки или Java-обёртки APK нужно пересобрать и подписать. Процесс: декомпилировать (`apktool d app.apk`), заменить `.so` или `classes.dex`, собрать (`apktool b app -o app_mod.apk`), выровнять (`zipalign -v 4 app_mod.apk app_aligned.apk`) и подписать (`apksigner sign --ks debug.keystore --out app_signed.apk app_aligned.apk`). Если приложение проверяет подпись (SafetyNet/Play Integrity), модифицированный APK не запустится — тогда проверку обходят через Frida-хук или патч. Для тестов удобен `uber-apk-signer`. После установки (`adb install -r app_signed.apk`) проверяют поведение и логи (`adb logcat | grep -i native`). Важно держать исходную копию APK и подписывать одним и тем же ключом, чтобы обновление прошло поверх.

## Частые подводные камни при реверсе native

Отдельно стоит упомянуть типичные грабли. Во-первых, `.so` может быть собран с оптимизацией `-O2`, из-за чего инлайн-функции исчезают, а регистры переиспользуются — не ищите красивые вызовы, следите за данными. Во-вторых, строки часто хранятся не как `const char*`, а как массивы на стеке, собираемые посимвольно (`MOVB` + `STRB`), поэтому `strings` их не видит. В-третьих, `JNIEnv`-вызовы идут через таблицу, и Ghidra без типов показывает их как `(*(code*)(env+0x...))` — заведите тип `JNINativeInterface` для читаемости. В-четвёртых, ARM64 и ARM32 ветки кода могут быть в одном APK под разные ABI, и анализировать нужно ту, что реально грузится на устройстве. Наконец, часть логики может оставаться в Java, а `.so` лишь проверяет результат — всегда смотрите обе стороны.

## Квиз

```quiz
- question: "Где в Android-приложении лежит native-код?"
  options:
    - "В lib/<abi>/*.so внутри APK"
    - "В classes.dex"
    - "В ресурсах"
    - "В манифесте"
  answer: 0
  explanation: "Нативные библиотеки лежат в lib/<abi>/."
- question: "Как называются JNI-функции при static binding?"
  options:
    - "Java_<class>_<method>"
    - "main"
    - "_start"
    - "JNI_Init"
  answer: 0
  explanation: "Имя кодирует класс/метод (или регистрируется через RegisterNatives)."
- question: "Что делает RegisterNatives?"
  options:
    - "Динамически регистрирует JNI-методы (таблица)"
    - "Сканирует порты"
    - "Шифрует строки"
    - "Собирает APK"
  answer: 0
  explanation: "Динамический биндинг через JNI_OnLoad/RegisterNatives."
- question: "Что такое OLLVM?"
  options:
    - "Обфускатор LLVM (control-flow flattening и др.)"
    - "Формат APK"
    - "Рантайм"
    - "Пакер"
  answer: 0
  explanation: "OLLVM обфусцирует native-код."
- question: "Какой инструмент для динамики Android-native?"
  options:
    - "Frida"
    - "nm"
    - "ldd"
    - "objdump -h"
  answer: 0
  explanation: "Frida перехватывает native-функции на устройстве."
```

## Где пригодится

- **CTF:** Reversing/Mobile.
- **Анализ Android-малвари:** native-логика.
- **Bug bounty:** мобильные клиенты.
- **Работа:** mobile security.
