---
id: mobile-android-binder
title: "Android Binder и IPC: атаки на межпроцессное взаимодействие"
category: mobile
parent: mobile-exported-components
difficulty: expert
order: 4
tags: [binder, ipc, aidl, service, parcel, android, exploit]
prerequisites: [mobile-exported-components, mobile-android-anatomy]
useful_for:
  - "CTF Mobile (атака на bound service)"
  - "Bug bounty (IPC-уязвимости, подмена Parcel)"
  - "Пентест мобильных приложений"
estimated_minutes: 45
summary: "Как работает Binder IPC, чем опасны экспортированные bound services и AIDL-интерфейсы, как исследовать и эксплуатировать их через adb/Frida, включая подмену Parcel."
---
## Что такое Binder и почему он важен

Binder — ядро межпроцессного взаимодействия (IPC) в Android. Через него приложения общаются с системными сервисами (ActivityManager, PackageManager, LocationManager) и друг с другом. Каждый вызов проходит через ядро: клиент вызывает метод прокси-объекта, аргументы упаковываются в `Parcel`, ядро доставляет их серверу, сервер выполняет метод. Для пентеста это критично, потому что **экспортированный bound Service или AIDL-интерфейс позволяет другому приложению вызывать методы процесса жертвы** — в том числе привилегированные.

Модель угроз: если сервис проверяет только «кто ты по имени» или вообще не проверяет вызывающего (`getCallingUid`), атакующее приложение вызывает его методы напрямую. Если сервис десериализует недоверенный `Parcel` без валидации — это утечки, падения, иногда переполнения. Если через Binder передаётся ссылка на объект (`IBinder`), можно получить доступ к другим интерфейсам.

## Как найти bound service

Начинайте с манифеста и AIDL.

```bash
apktool d app.apk -o out
grep -n -A3 "<service" out/AndroidManifest.xml | head -60
# ищем android:exported="true" + intent-filter с action (bind)
```

```xml
<service android:name=".RemoteService" android:exported="true"
         android:permission="com.target.BIND">
  <intent-filter><action android:name="com.target.REMOTE"/></intent-filter>
</service>
```

Если `android:permission` задан — другой процесс должен иметь это разрешение (проверьте, не является ли оно `normal`/`dangerous` и не выдаётся ли автоматически). Затем ищите AIDL-интерфейс в smali: он описывает методы, которые можно вызвать.

```bash
ls out/smali*/com/target/ | grep -i "IRemote\|AIDL\|Stub"
grep -rn "extends IInterface\|Stub\b" out/smali*/com/target/*.smali | head
```

На устройстве смотрите, какие сервисы реально запущены:

```bash
adb shell dumpsys activity services com.target.app
adb shell service list | grep -i target
adb shell dumpsys package com.target.app | grep -A2 -i service
```

## Чтение AIDL-интерфейса

AIDL-файл после компиляции превращается в `Stub` (сервер) и `Proxy` (клиент). В smali/декомпилированном виде видно список методов и их номера транзакций (`FIRST_CALL_TRANSACTION + n`). Декомпилируйте jadx и откройте интерфейс:

```java
// IRemoteService.aidl → после сборки
public interface IRemoteService extends IInterface {
    String getSecret() throws RemoteException;
    void setConfig(String key, String value) throws RemoteException;
    void exec(String cmd) throws RemoteException;   // вот это уже опасно
}
```

Методы, принимающие строку и выполняющие что-то системное (`exec`, `runCommand`, `writeFile`), — прямые кандидаты на RCE/утечку.

## Вызов Binder через adb (service call)

Простейший способ пощупать транзакции — `service call`, если сервис зарегистрирован в `servicemanager` (обычно только системные). Для прикладных сервисов используется `am`/собственный клиент.

```bash
# посмотреть зарегистрированные сервисы
adb shell service list | head
# вызвать транзакцию у системного сервиса: service call <name> <code> [args]
adb shell service call iphonesubinfo 1 i32 1
```

Для прикладных bound services удобнее написать маленький клиент (см. ниже) — это надёжнее, чем угадывать коды транзакций.

## Взаимодействие через собственное приложение-клиент

Самый практичный метод: собрать APK-клиент, который биндится к сервису и вызывает методы.

```java
// в своём приложении (или через Frida/апплет)
Intent i = new Intent("com.target.REMOTE");
i.setPackage("com.target.app");
bindService(i, new ServiceConnection() {
    public void onServiceConnected(ComponentName n, IBinder b) {
        IRemoteService svc = IRemoteService.Stub.asInterface(b);
        try { Log.d("PWN", "secret=" + svc.getSecret()); }
        catch (RemoteException e) { Log.e("PWN", "denied", e); }
    }
    public void onServiceDisconnected(ComponentName n) {}
}, BIND_AUTO_CREATE);
```

Если сервис не защищён permission — вызов проходит. Если защищён — вы увидите `SecurityException`, что тоже информативно (подтверждает наличие границы).

## Атака на недоверенный Parcel

Binder передаёт данные как `Parcel`. Если сервис читает `Parcel` без проверки типа/длины, возможны: чтение «чужих» полей, `ClassCastException`, утечки памяти, а в нативных сервисах — переполнения. Ищите `readString`, `readInt`, `createTypedArrayList`, `readParcelable` в коде сервиса.

```java
// сервер читает строку без проверки длины
String name = data.readString();   // может быть null/огромной
doPrivileged(name);                // → path traversal / инъекция
```

Отдельный класс — **передача IBinder-ссылок**: если сервис возвращает `IBinder` на другой интерфейс, вы получаете доступ к нему (иногда к системному) без явного разрешения.

## getCallingUid и обход проверок

Сервисы обязаны проверять вызывающего через `Binder.getCallingUid()`/`getCallingPid()`. Частые ошибки:

- проверка имени пакета по `getPackageForUid`, но без учёта спуфинга;
- проверка только в `onBind`, но не в каждом методе;
- сравнение с константой UID, которая меняется на разных устройствах;
- доверие `getCallingUid()` в асинхронном колбэке (там он уже не тот).

```bash
grep -rn "getCallingUid\|getCallingPid\|checkCallingPermission\|enforceCalling" out_jadx | head
```

Если проверка есть только в одном методе — ищите другие методы интерфейса без неё.

## Frida для перехвата Binder-транзакций

Frida позволяет видеть и модифицировать Binder-вызовы в рантайме: хукать `android.os.BinderProxy.transact`, `android.os.Parcel.readString`, методы `Stub`. Это удобно, когда вы не хотите собирать клиент.

```javascript
Java.perform(function () {
  var BinderProxy = Java.use('android.os.BinderProxy');
  BinderProxy.transact.overload('int','android.os.Parcel','android.os.Parcel','int')
    .implementation = function (code, data, reply, flags) {
      console.log('transact code=' + code + ' iface=' + this);
      var r = this.transact(code, data, reply, flags);
      return r;
    };
});
```

Хук на `getCallingUid` позволяет обойти проверку вызывающего — подменяем UID на доверенный (например, system `1000`).

## Разобранный пример: вызов незащищённого сервиса

```bash
# 1. в манифесте нашли exported service без permission
# <service android:name=".AdminService" android:exported="true">
#   <intent-filter><action android:name="com.target.ADMIN"/></intent-filter>

# 2. декомпилировали AIDL — метод resetPassword(String)
# 3. запускаем приложение-клиент (или Frida) и биндимся к сервису
# 4. вызываем метод
IRemoteService svc = IRemoteService.Stub.asInterface(binder);
svc.resetPassword("attacker123");   // сервис выполнил без проверки → захват аккаунта
```

Результат — обход авторизации: административная функция доступна любому приложению на устройстве.

## Справочная таблица: векторы через Binder

| Вектор | Признак | Последствие |
|--------|---------|-------------|
| Exported service без permission | `exported=true`, нет `android:permission` | вызов привилегированных методов |
| Слабое permission | `normal`/авто-выдача | тот же вызов |
| Проверка только в onBind | `getCallingUid` в одном месте | обход остальных методов |
| Недоверенный Parcel | `readString` без валидации | утечки/падения/переполнения |
| Возврат IBinder | `readStrongBinder` | доступ к чужому интерфейсу |
| Метод `exec`/`runCommand` | строка → система | RCE |

## Типовые ошибки новичка

- **Не собирать клиент.** Без реального вызова вы не знаете, проходит ли запрос (permission может блокировать).
- **Путать bound и started service.** Атака через bind требует `onBind`; started-сервисы работают иначе.
- **Игнорировать permission-уровни.** `normal`-разрешение часто выдаётся автоматически — проверяйте `protectionLevel`.
- **Забывать про API-level.** Поведение `exported` по умолчанию менялось (явное указание обязательно с API 31).
- **Тестировать только на одном устройстве.** UID/имена пакетов различаются.

## Что дальше / решение

Порядок: (1) найти exported services и AIDL; (2) определить permission и способ проверки вызывающего; (3) собрать клиент/Frida-хук и вызвать методы; (4) при недоверенном Parcel — фаззить параметры; (5) при наличии нативной части — реверс `.so`. Связанные уроки: `mobile-exported-components` (общая карта точек входа), `mobile-android-anatomy`, `mobile-frida-scripting`. Решение — воспроизводимый вызов защищённого метода (например, сброс пароля) из другого приложения.

## Практический чек-лист тестирования Binder

1. Собрать все `<service>` из манифеста, отметить `exported="true"`.
2. Для каждого — выяснить `android:permission` и его `protectionLevel` (`normal` = автоматически, `signature` = только свой ключ).
3. Декомпилировать AIDL/`Stub` и выписать методы и номера транзакций.
4. Определить, где именно проверяется вызывающий (`getCallingUid`/`checkCallingPermission`).
5. Собрать минимальный клиент (или Frida-хук) и вызвать каждый метод.
6. Для методов со строковыми/байтовыми аргументами — проверить инъекции (path traversal, команды).
7. Проверить, возвращает ли сервис `IBinder` на другие интерфейсы.
8. Оценить impact: чтение данных, изменение конфигурации, привилегированные действия.

## Материалы и связанные техники

Для углубления: `mobile-exported-components` (Activity/Service/Receiver/Provider в целом), `mobile-frida-scripting` (хуки на `BinderProxy.transact` и `Parcel`), `mobile-android-native` (если логика сервиса в `.so`), `mobile-exported-provider` (похожие ошибки в content providers). Полезно держать под рукой `adb shell dumpsys activity services` — быстрый способ увидеть живые bound-сервисы и их интерфейсы. В реальном пентесте Binder-находки часто ведут к обходу авторизации и утечке данных, поэтому их стоит приоритизировать наравне с API-уязвимостями.

## Почему это важный, но недооценённый класс

Большинство мобильных пентестов фокусируются на хранилище, трафике и API, а Binder-поверхность остаётся неисследованной. Между тем именно через IPC реализуются внутренние административные функции: сброс пароля, смена настроек, экспорт данных, платёжные операции в companion-приложениях. Если сервис экспортирован без проверки вызывающего, любое приложение на устройстве (в том числе вредоносное) может вызвать эти функции — без root и без перехвата трафика. В bug bounty такие находки ценятся высоко, потому что дают локальную атаку с серьёзным impact. Проверяйте Binder-поверхность системно: не только «очевидные» exported-сервисы, но и сервисы, доступные через `android:permission` уровня `normal`, и те, что проверяют вызывающего лишь частично.

## Квиз

```quiz
- question: "Что такое Binder в Android?"
  options:
    - "Механизм IPC между процессами и системными сервисами"
    - "Формат изображения"
    - "Тип шифрования"
    - "Сетевой протокол"
  answer: 0
  explanation: "Binder — основа межпроцессного взаимодействия Android."
- question: "Как проверить, кто вызывает Binder-метод?"
  options:
    - "Binder.getCallingUid()"
    - "System.currentTimeMillis()"
    - "getPackageName()"
    - "Runtime.exec()"
  answer: 0
  explanation: "getCallingUid позволяет отклонить чужие вызовы."
- question: "Чем опасна небезопасная десериализация Parcel?"
  options:
    - "Утечки памяти, type confusion, падения"
    - "Ускорение IPC"
    - "Смена темы"
    - "Очистка кэша"
  answer: 0
  explanation: "Неверный порядок/типы чтения Parcel ведут к утечкам и сбоям."
- question: "Где перечислены методы bound service?"
  options:
    - "В AIDL-интерфейсе (Stub)"
    - "В strings.xml"
    - "В Info.plist"
    - "В build.gradle"
  answer: 0
  explanation: "AIDL описывает методы, доступные через Binder."
- question: "Как биндиться к сервису из другого приложения?"
  options:
    - "bindService с Intent и BIND_AUTO_CREATE"
    - "startActivity"
    - "sendBroadcast"
    - "query provider"
  answer: 0
  explanation: "bindService возвращает IBinder для вызова методов."
```

## Где пригодится

- **CTF Mobile:** вызов bound service для получения флага.
- **Bug bounty:** IPC-уязвимости — редкие, но ценные находки.
- **Пентест:** аудит межпроцессного взаимодействия.
- **Работа:** ревью AIDL/HAL-интерфейсов.
