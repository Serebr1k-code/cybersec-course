---
id: mobile-hooking-internals
title: "Внутренности хукинга: ART, JVMTI и RegisterNatives"
category: mobile
parent: mobile-app-protection
difficulty: expert
order: 2
tags: [mobile, android, art, hooking, jvmti, native, frida]
prerequisites: [mobile-dynamic-frida, mobile-android-native]
useful_for:
  - "CTF Mobile: обход анти-Frida и перехват методов"
  - "Пентест: глубокая инструментация приложения"
estimated_minutes: 50
summary: "Как на самом деле работает перехват методов в Android: байткод Dalvik, JIT/AOT в ART, точки входа JVMTI, RegisterNatives для JNI, и почему Frida иногда не может захукать метод."
---

## Зачем понимать внутренности хукинга

Frida и Xposed дают «магический» перехват: `Java.use("...").method.implementation = function(){}`. Но как только вы встречаете приложение с анти-Frida, VMP или нативным кодом, магия перестаёт работать, и нужно понимать, что происходит под капотом. Тогда вы сможете:
- писать хукеры, которые не палятся;
- перехватывать методы, которые Frida не видит (нативные, JNI, инлайновые);
- обходить проверки, реализованные на уровне ART.

## Dalvik и ART: две VM

Исторически Android использовал **Dalvik** — регистровую VM, исполняющую DEX-байткод через интерпретатор и JIT. Современный Android использует **ART** (Android Runtime): при установке приложения байткод компилируется в машинный код (AOT, `odex`/`vdex`/`oat`), а динамика дополняется JIT. Для хукинга это означает: метод может существовать в трёх видах — интерпретируемый байткод, JIT-код и AOT-скомпилированный машинный код. Frida умеет перехватывать все три, подменяя точки входа в структурах ART (`ArtMethod`), но детект может заметить подмену.

Ключевая структура — `ArtMethod` (ранее `Method`): она содержит указатели на entrypoint'ы (`quick_entry_point`, `interpreter_entry_point`), `dex_code_item_offset`, флаги. Хук метода в ART сводится к подмене entrypoint на трамплин. Именно поэтому проверки целостности ART (сравнение `ArtMethod` с эталоном) могут детектить Frida.

## Три уровня перехвата

1. **Java-уровень (Frida/Xposed)** — перехват `ArtMethod`, виден как обычный Java-вызов. Работает для методов, загруженных в VM.
2. **JNI/нативный уровень (Interceptor, PLT-hook)** — перехват нативных функций `lib*.so`, включая JNI-функции. Нужен, когда логика ушла в C/C++.
3. **JVMTI-уровень** — стандартный интерфейс инструментации JVM, доступный в ART через `libopenjdkjvmti`. Позволяет ставить события на загрузку класса, вход/выход метода, без модификации байткода.

Понимание этих уровней важно, потому что анти-Frida обычно детектит именно **Java-уровень** (порты Frida, потоки, `frida-agent`), а обход через JVMTI или нативный Interceptor остаётся незамеченным.

## RegisterNatives: как JNI связывает методы

Когда нативный код регистрирует свои реализации Java-методов, он вызывает `RegisterNatives`:

```c
static JNINativeMethod methods[] = {
  {"checkRoot", "()Z", (void*)nativeCheckRoot},
  {"decrypt",   "([B)[B", (void*)nativeDecrypt},
};

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
  JNIEnv* env;
  vm->GetEnv((void**)&env, JNI_VERSION_1_6);
  jclass cls = env->FindClass("com/example/app/NativeLib");
  env->RegisterNatives(cls, methods, 2);
  return JNI_VERSION_1_6;
}
```

Чтобы перехватить такой метод, можно:
- **хукнуть `RegisterNatives`** до его вызова и подменить указатель функции на свой;
- **найти адрес функции** по имени символа (`nativeCheckRoot`) и захукать через `Interceptor.attach`;
- **заменить саму нативную функцию** в `.so` (патч или `PLT`).

Frida-скрипт для перехвата регистрации:

```javascript
var RegisterNatives = Module.findExportByName("libart.so", "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi");
// либо по libnative-lib.so, если регистрация там
Interceptor.attach(RegisterNatives, {
  onEnter: function (args) {
    var cls = args[1], methods = args[2], count = args[3].toInt32();
    console.log("RegisterNatives class=" + cls + " count=" + count);
    for (var i = 0; i < count; i++) {
      var m = methods.add(i * Process.pointerSize * 3);
      var name = m.readPointer().readCString();
      var sig  = m.add(Process.pointerSize).readPointer().readCString();
      var fn   = m.add(Process.pointerSize * 2).readPointer();
      console.log("  " + name + sig + " @ " + fn);
    }
  }
});
```

Затем хукаем найденный адрес: `Interceptor.attach(fn, { onEnter... })`.

## JVMTI: инструментация без подмены байткода

JVMTI-агент получает уведомления от VM. Пример на C: агент подписывается на `ClassFileLoadHook` и `MethodEntry`. В Android JVMTI включается при отлаживаемом приложении (`android:debuggable="true"`) или через патч. Такой подход сложнее, но не оставляет следов Frida. В CTF редко нужен, на реальном пентесте — да, против анти-хука.

```c
static jvmtiEnv* jvmti;
JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM* vm, char* opts, void* reserved) {
  (*vm)->GetEnv(vm, (void**)&jvmti, JVMTI_VERSION_1_2);
  jvmtiCapabilities caps = {0};
  caps.can_generate_method_entry_events = 1;
  (*jvmti)->AddCapabilities(jvmti, &caps);
  jvmtiEventCallbacks cb = {0};
  cb.MethodEntry = &on_method_entry;
  (*jvmti)->SetEventCallbacks(jvmti, &cb, sizeof(cb));
  (*jvmti)->SetEventNotificationMode(jvmti, JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY, NULL);
  return JNI_OK;
}
```

## Инлайновые хуки и self-modifying code

Некоторые методы компилируются AOT в машинный код и инлайнятся. Их перехват на Java-уровне может не сработать, потому что вызова метода как такового нет — код «вшит» в вызывающего. Тогда помогает:
- **инлайновый хук** (Frida `Interceptor` по адресу скомпилированного кода, если его найти);
- **патч байткода** через `dalvik.system.DexFile` и перезагрузку;
- **перехват на уровне интерпретатора** (подмена `ExecuteSwitchImpl` в ART) — используется продвинутыми фреймворками.

## Обход анти-хукинга

Приложение может проверять:
- **Порты Frida** (`27042`, `27043`) — используйте `frida-server` на нестандартном порту или gadget.
- **Потоки/имена** (`gum-js-loop`, `frida`) — переименуйте или используйте JVMTI.
- **Целостность `ArtMethod`** — не подменяйте entrypoint, используйте JVMTI.
- **`/proc/self/maps` на frida-agent** — спрячьте библиотеку (gadget + переименование).
- **Отладчик** (`ptrace`) — обходится патчем или gadget-режимом.

## Частые ошибки и подводные камни

- **Java.use не находит класс** — класс ещё не загружен; используйте `Java.perform` и `Java.enumerateLoadedClasses`.
- **Хук нативного метода не срабатывает** — метод зарегистрирован через `RegisterNatives`; хукайте саму регистрацию.
- **Interceptor падает** — адрес не выровнен или это thumb-режим (ARM32): добавляйте `|1` к адресу.
- **Приложение падает после хука** — вы подменили слишком много; восстанавливайте оригинал (`this.method.call`).
- **Анти-хук срабатывает** — Java-хук виден; переходите на JVMTI/gadget.

## Справочная таблица

| Уровень | Инструмент | Видимость для анти-хука | Когда применять |
|---------|------------|-------------------------|-----------------|
| Java | Frida `Java.use` | высокая | обычные методы |
| Нативный | Frida `Interceptor` | средняя | JNI, C/C++ |
| JNI-регистрация | hook `RegisterNatives` | низкая | методы через `RegisterNatives` |
| JVMTI | агент на C | очень низкая | против анти-хука |
| Байткод | патч DEX | средняя | инлайн/компилированный код |

## Что дальше / решение

Начинайте всегда с Java-уровня (быстро), при противодействии переходите к нативному и JNI-хуку, а против сильного анти-хука — к JVMTI или gadget. Разберите `libart.so` и `libnative-lib.so` в Ghidra, чтобы найти точки входа. Дальше — `mobile-frida-detection` (как приложение вас ловит) и `mobile-runtime-bypass`.

## Практика: перехват метода с диспетчеризацией

Рассмотрим полный сценарий: приложение проверяет лицензию в нативном методе, зарегистрированном через `RegisterNatives`, и возвращает `boolean`. Задача — сделать так, чтобы метод всегда возвращал `true`, но не палить Frida.

Шаг 1 — находим нативную библиотеку и экспорт:

```bash
unzip -l app.apk | grep 'lib/arm64-v8a'
# lib/arm64-v8a/liblicense.so
```
```bash
nm -D liblicense.so | grep -i license
# 0000000000012a40 T Java_com_example_app_NativeLib_checkLicense
```

Шаг 2 — если символ экспортирован, хукаем его напрямую:

```javascript
var fn = Module.findExportByName("liblicense.so",
         "Java_com_example_app_NativeLib_checkLicense");
Interceptor.attach(fn, {
  onLeave: function (retval) {
    retval.replace(1);   // всегда true
  }
});
```

Шаг 3 — если символ скрыт (динамическая регистрация), ловим `RegisterNatives` и подменяем указатель до вызова:

```javascript
var RN = Module.findExportByName("libart.so",
  "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi");
var target = null;
Interceptor.attach(RN, {
  onEnter: function (args) {
    var methods = args[2];
    var count = args[3].toInt32();
    for (var i = 0; i < count; i++) {
      var m = methods.add(i * Process.pointerSize * 3);
      var name = m.readPointer().readCString();
      if (name === "checkLicense") {
        target = m.add(Process.pointerSize * 2);
      }
    }
  }
});
// после прогрева — подменяем записанный указатель
```

Шаг 4 — против анти-хука (проверка целостности `.so` по хешу) патчим саму функцию в файле, а не в памяти, либо используем JVMTI-агент, который не трогает код.

## Обратная инженерия ArtMethod в Ghidra

Чтобы хукнуть метод «по-настоящему», нужно понимать раскладку `ArtMethod`. В современном ART (Android 8+) это структура из ~8 полей:

```
struct ArtMethod {
  GcRoot<mirror::Class> declaring_class_;  // 4
  uint32_t access_flags_;                  // 4
  uint32_t dex_method_index_;              // 4
  uint16_t method_index_;                  // 2
  uint16_t hotness_count_;                 // 2
  struct PtrSizedFields {
    void* data_;                           // профиль/данные
    void* entry_point_from_quick_compiled_code_;
  } ptr_sized_fields_;
};
```

Зная смещение `entry_point_from_quick_compiled_code_`, можно читать и подменять точку входа вручную. Продвинутые фреймворки (Pine, YAHFA) именно это и делают: конструируют трамплин на ассемблере и записывают его адрес в `ArtMethod`. Преимущество ручного подхода — он не оставляет следов в виде `frida-agent` в `/proc/self/maps`, а потому не детектится базовыми проверками.

## Байткод-манипуляции и перезагрузка классов

Иногда проще не хукать рантайм, а изменить байткод до загрузки. Инструмент `dexlib2` (из smali/baksmali) позволяет патчить DEX программно:

```java
DexFile dex = new DexFile(new File("classes.dex"));
for (Method m : dex.getClasses().stream()
        .flatMap(c -> c.getMethods().stream())
        .collect(Collectors.toList())) {
    if (m.getName().equals("isLicensed")) {
        // заменить тело метода на "return true"
        m.replace((MethodImplementation) new BuilderMethodImplementation(...));
    }
}
```

Патч применяют к APK, пересобирают через `apktool b`, подписывают (`apksigner`) и устанавливают. Это грубо (видно по хешу APK и подписи), но надёжно и не требует Frida. Для обхода подписи-чека — пересоберите с самоподписанным сертификатом и нейтрализуйте проверку подписи хуком.

## Диагностика: почему хук не работает

Типовые причины и решения:

| Симптом | Причина | Решение |
|---------|---------|---------|
| `Java.use` бросает ClassNotFoundException | класс ещё не загружен | `Java.perform` + дождаться загрузки |
| Метод найден, но не вызывается | инлайн/AOT | JVMTI или патч байткода |
| `Interceptor.attach` падает | ARM thumb-адрес | добавить `|1` к адресу |
| Приложение падает после хука | подменён entrypoint без трамплина | использовать `this.method.call` |
| Хук виден античитом | frida-agent в памяти | gadget + переименование, JVMTI |
| Нативная функция не находится | символ скрыт (stripped) | hook `RegisterNatives`, поиск по строкам |

## Что дальше / решение

Практический алгоритм: начните с Java-хука, проверьте, ловится ли анти-хук; при детекте перейдите на нативный `Interceptor`; если символы скрыты — хукайте `RegisterNatives`; против сильного анти-хука — JVMTI-агент или патч байткода. Для каждой техники ведите лог того, что сработало, — это ускорит повторный анализ похожих приложений. Дальше — `mobile-frida-detection` и `mobile-native-so-deep`.

## Квиз

```quiz
- question: "Что хранит ArtMethod и почему подмена entrypoint ломает целостность?"
  options:
    - "Указатели на точки входа метода; анти-хук может сравнить их с эталоном"
    - "Только имя класса"
    - "Только размер APK"
    - "Только строковые ресурсы"
  answer: 0
- question: "Как JNI связывает нативную реализацию с Java-методом?"
  options:
    - "Через RegisterNatives, регистрируя таблицу JNINativeMethod"
    - "Через HTTP-запрос"
    - "Через SharedPreferences"
    - "Через Bluetooth"
  answer: 0
- question: "Чем JVMTI-инструментация отличается от Frida-хука?"
  options:
    - "Она использует события VM и не подменяет байткод/entrypoint"
    - "Она работает только на iOS"
    - "Она быстрее компилирует"
    - "Она не требует устройства"
  answer: 0
- question: "Почему AOT-скомпилированный и инлайненный метод может не перехватываться на Java-уровне?"
  options:
    - "Вызов метода инлайнён в вызывающий код, отдельного вызова нет"
    - "Метод удалён из APK"
    - "Метод написан на Python"
    - "Он не существует"
  answer: 0
```

## Где пригодится

- **CTF:** обход анти-Frida и перехват «невидимых» методов.
- **Пентест:** глубокая инструментация защищённого приложения.
- **Малварь-анализ:** перехват JNI-функций и обход обфускации VM.
