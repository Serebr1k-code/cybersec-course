---
id: mobile-android-device-admin
title: 'Device Admin и Device Owner: полномочия и злоупотребление'
category: mobile
parent: mobile-android-trust
difficulty: hard
order: 1
tags: [android, deviceadmin, deviceowner, dpm, mdm, wipe]
prerequisites: [mobile-android-root]
useful_for:
  - 'Пентест мобильных приложений (Android)'
  - 'Android Enterprise'
  - 'Анализ малвари'
estimated_minutes: 42
summary: 'Как работают роли Device Admin, Profile Owner и Device Owner, что позволяет DevicePolicyManager и как эти полномочия эксплуатируются и детектируются.'
lab:
  kind: shell
  title: 'Практика: политики Device Admin'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, device_admin.xml, manifest.xml]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`device_admin.xml` перечисляет запрашиваемые политики.'
    - 'Найди самую опасную политику для приложения-фонарика.'
    - 'Рядом с ней в комментарии — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Приложение «Корпоративная почта» при установке просит права администратора устройства: может
заблокировать экран, стереть данные, сменить пароль. Зачем программе для почты такие права?
Обычно — чтобы IT-отдел мог управлять корпоративным телефоном. Но тот же механизм, попав в
руки малвари, превращает приложение в «руку» злоумышленника. Разберём роли и их границы.

## Наш пример: MDM-клиент

На тестовом устройстве установлен клиент корпоративного управления. В его манифесте находим:

```xml
<receiver android:name=".AdminReceiver"
          android:permission="android.permission.BIND_DEVICE_ADMIN"
          android:exported="true">
    <meta-data android:name="android.app.device_admin"
               android:resource="@xml/device_admin"/>
    <intent-filter>
        <action android:name="android.app.action.DEVICE_ADMIN_ENABLED"/>
    </intent-filter>
</receiver>
```

`AdminReceiver` — это `DeviceAdminReceiver`, точка входа для событий администрирования. Рядом
лежит `device_admin.xml` со списком запрашиваемых политик. Именно этот файл определяет, что
приложение сможет делать.

## Шаг 1: что такое Device Admin

Device Admin — это устаревшая, но всё ещё рабочая роль. Приложение объявляет receiver и
политики, а пользователь подтверждает их включение на системном экране. После этого
приложение получает объект `DevicePolicyManager` (DPM) и может:

- блокировать экран (`lockNow`);
- требовать пароль и его сложность;
- стирать данные (`wipeData`);
- отключать камеру;
- наблюдать попытки ввода неверного пароля.

Важно: Device Admin **не даёт** root. Он даёт ровно те политики, которые перечислены в XML и
подтверждены пользователем. Но `wipeData` уже достаточно, чтобы уничтожить данные телефона.

## Шаг 2: Device Owner и Profile Owner

Три роли часто путают, поэтому разложим их по возрастанию силы:

- **Device Admin** — набор политик, подтверждается пользователем, снимается пользователем.
- **Profile Owner** — владеет рабочим профилем: политики применяются только к профилю, а не
  ко всему устройству.
- **Device Owner** — владеет **всем** устройством. Назначается только на устройстве без
  аккаунтов, через провижининг (QR, NFC, zero-touch) или `adb shell dpm set-device-owner`.

Device Owner может ставить приложения молча, запрещать сброс, управлять VPN и сетью, отключать
USB-отладку. Это максимальная власть без root.

## Шаг 3: как назначают и проверяют роли

Device Owner настраивают так (устройство должно быть «чистым»):

```bash
$ adb shell dpm set-device-owner com.example.mdm/.AdminReceiver
Success: Device owner set to package com.example.mdm
```

Проверить текущие роли:

```bash
$ adb shell dpm list-owners
Device Owner: com.example.mdm/.AdminReceiver
Profile Owner: (none)
```

А посмотреть список активных admin-компонентов:

```bash
$ adb shell dumpsys device_policy | grep -i "admin"
```

## Шаг 4: как этим злоупотребляют

Сценарии злоупотребления в реальной малвари:

1. **Принудительный сброс** — `wipeData(0)` стирает телефон, если пользователь пытается
   удалить вредоносное приложение (шантаж).
2. **Блокировка экрана** — ransom-логика: экран блокируется, пока не заплатят.
3. **Смена пароля** — приложение задаёт свой PIN через `resetPassword`.
4. **Запрет удаления** — Device Owner может включить `setUninstallBlocked` для самого себя.
5. **Скрытая установка** — Device Owner ставит полезную нагрузку без участия пользователя.

Все эти действия формально «легальны» с точки зрения API, потому что пользователь когда-то
подтвердил роль. Поэтому защита — в контроле над тем, кто и когда получает роль.

## Шаг 5: как аудировать приложение

При статическом анализе ищем receiver с `BIND_DEVICE_ADMIN` и читаем `device_admin.xml`:

```bash
$ grep -rn "BIND_DEVICE_ADMIN" decompiled/AndroidManifest.xml
$ cat decompiled/res/xml/device_admin.xml
<device-admin>
    <uses-policies>
        <wipe-data/>
        <force-lock/>
        <reset-password/>
    </uses-policies>
</device-admin>
```

Каждая политика — потенциальная возможность. Дальше смотрим код: вызывает ли приложение
`wipeData`, `lockNow`, `resetPassword`, и при каких условиях. Если это не MDM-продукт, а
«фонарик», требующий `wipe-data`, — перед нами явное злоупотребление.

## Шаг 6: как удалить и что мешает

Обычного удаления может не хватить: сначала снимают роль администратора, потом удаляют
приложение. Но если приложение — Device Owner, оно может блокировать снятие роли и удаление.
Тогда помогает только `adb`:

```bash
$ adb shell dpm remove-active-admin com.example.mdm/.AdminReceiver
$ adb uninstall com.example.mdm
```

На заблокированном устройстве иногда требуется сброс к заводским настройкам. Это и есть
показатель силы роли: Device Owner переживает попытки пользователя от него избавиться.

## Шаг 7: что писать в отчёте

Опишите: какие роли запрашивает приложение, какие политики перечислены, соответствуют ли они
назначению, есть ли код, использующий опасные вызовы. Отдельно — можно ли снять роль без
сброса устройства. Для малвари добавьте MITRE-маппинг: Device Administration как техника
персистентности и уклонения от удаления.

## Шаг 8: рекомендации

- Минимизировать политики: запрашивать только необходимое.
- Для корпоративных сценариев использовать **Profile Owner**, а не Device Owner, где возможно.
- Пользователю — проверять, зачем приложению права администратора, прежде чем подтверждать.
- Платформе — ограничивать назначение Device Owner провижинингом на чистом устройстве (что
  и делает современный Android).

## Что мы теперь знаем

- Device Admin, Profile Owner и Device Owner — три роли с разной силой.
- DevicePolicyManager даёт блокировку, сброс, смену пароля, запрет удаления.
- Малварь использует эти права для шантажа и персистентности.
- Аудит: receiver с `BIND_DEVICE_ADMIN` + `device_admin.xml` + вызовы DPM.

## Шаг 9: DevicePolicyManager — что реально можно

Роль сама по себе — только ярлык. Полномочия даёт **DevicePolicyManager (DPM)** — системный
сервис, к которому приложение обращается через `getSystemService(DEVICE_POLICY_SERVICE)`.
Набор доступных методов зависит от роли: Device Admin получает меньше, Device Owner — почти
всё. Ключевые методы, которые чаще всего интересуют и атакующего, и аудитора:

- `lockNow()` — мгновенная блокировка экрана.
- `wipeData(flags)` — полное стирание устройства (с флагом `WIPE_EXTERNAL_STORAGE`).
- `resetPassword(password, flags)` — смена пароля/PIN (на старых API).
- `setPasswordQuality()` / `setPasswordMinimumLength()` — политика пароля.
- `setCameraDisabled(true)` — запрет камеры.
- `setScreenCaptureDisabled(true)` — запрет скриншотов (FLAG_SECURE на уровне политики).
- `installCaCert()` — установка корневого сертификата (прозрачный MITM!).
- `setApplicationHidden()` — скрытие/блокировка приложений.
- `addUserRestriction(USER_RESTRICTION)` — запрет установки APK, USB-отладки и т.п.

Из этого списка видно главное: **Device Owner — это фактически админ устройства**, и он может
тихо включить MITM через `installCaCert` или заблокировать защитные функции. Поэтому находка
«приложение запрашивает Device Owner» почти всегда критична.

## Шаг 10: практика — назначение и инвентаризация

Device Owner обычно назначается при первоначальной настройке (provisioning) или через ADB на
устройстве без добавленных аккаунтов. Пример легитимного сценария (и ровно того же — для
малвари, если ей дали такую возможность):

```bash
$ adb shell dpm set-device-owner com.example.mdm/.DeviceAdminReceiver
Success: Device owner set to package com.example.mdm
Active admin set to component {com.example.mdm/com.example.mdm.DeviceAdminReceiver}

$ adb shell dpm list-owners
Device Owner:
  admin=ComponentInfo{com.example.mdm/com.example.mdm.DeviceAdminReceiver}
  name=Corporate MDM
  package=com.example.mdm
Profile Owner: (none)
```

Команда `dpm list-owners` — самый быстрый способ понять, кто управляет устройством. Если
устройство позиционируется как «личное», а в списке есть незнакомый пакет, — это красный флаг.

## Шаг 11: детект и удаление

Признаки злоупотребления:

- Пакет объявляет `BIND_DEVICE_ADMIN` и запрашивает `USES_POLICY_WIPE_DATA`/`RESET_PASSWORD`.
- Активного админа невозможно удалить обычным способом: система блокирует деинсталляцию, пока
  роль не снята (`dpm remove-active-admin`).
- Приложение требует «активации» под предлогом защиты/оптимизации.

Снять роль без потери данных можно командой `dpm remove-active-admin`, но для Device Owner она
часто требует `--user` и особых условий; на практике приходится сбрасывать устройство. Именно
поэтому Device Owner — мощный инструмент персистентности.

## Таблица: роли и их возможности

| Роль | Как назначается | Стирание данных | Смена пароля | Установка CA |
|---|---|---|---|---|
| Device Admin | Пользователь вручную | да | да | нет |
| Profile Owner | Work-профиль / provisioning | только профиль | политика профиля | в профиле |
| Device Owner | Provisioning / `dpm set-device-owner` | да | да | да |
| Managed Profile | Work-профиль | только профиль | нет | в профиле |

## Крайние случаи и подводные камни

- `set-device-owner` работает только когда на устройстве **нет** аккаунтов и не настроен другой
  owner — иначе ошибка `Not allowed to set the device owner`.
- На Android 10+ часть `resetPassword`-методов устарела; смена пароля идёт через
  `setPasswordQuality` + системный запрос.
- Некоторые вендорские прошивки дают скрытые роли через `DevicePolicyManager` OEM-приложениям —
  их домены в SELinux тоже стоит проверять.
- Удаление активного админа не всегда убирает оставленные политики (например, установленный CA).

## Что дальше / решение

Итог: Device Admin — ограниченная роль, Device Owner — фактически админ устройства. В аудите
ищите объявление `BIND_DEVICE_ADMIN`, запросы `USES_POLICY_*` и результат `dpm list-owners`.
В следующем уроке разберём `NotificationListenerService` — механизм, который даёт не власть
над устройством, а чтение того, что пользователь видит на экране.

## Шаг 12: инвентаризация на устройстве

Полный чек-лист аудита ролей на живом устройстве:

```bash
$ adb shell dumpsys device_policy | grep -iE 'admin|owner|Active'
Active Admins:
  com.example.mdm/.DeviceAdminReceiver (active)
Device Owner: com.example.mdm/.DeviceAdminReceiver
$ adb shell pm list packages -d | grep mdm
```

`dumpsys device_policy` показывает и активных админов, и владельца профиля/устройства. Если
приложение, которое «просто читает почту», оказалось Device Owner — это уже критичная находка,
даже без эксплуатации: оно может стереть устройство или подменить доверенный CA.

## Шаг 13: что писать в отчёте

Опишите роль (`admin` / `profile owner` / `device owner`), назначенные политики и конкретные
последствия: стирание данных, смена пароля, установка CA (перехват TLS), запрет камеры.
Отметьте, требуется ли для снятия роли factory reset. MITRE ATT&CK: T1626 (Abuse Elevation
Control Mechanism) / T1485-подобное стирание данных.

## Квиз

Проверь себя.

```quiz
- question: Что определяет, какие политики сможет применять Device Admin?
  options:
    - Манифест-разрешения
    - Файл device_admin.xml с тегом uses-policies
    - Код приложения без ограничений
    - Настройки пользователя
  answer: 1
  explanation: Именно XML перечисляет запрашиваемые политики, подтверждаемые пользователем.
- question: Какая роль даёт власть над всем устройством?
  options:
    - Device Admin
    - Profile Owner
    - Device Owner
    - Никакая без root
  answer: 2
  explanation: Device Owner назначается на чистом устройстве и управляет им целиком.
- question: Как малварь использует wipeData?
  options:
    - Ускоряет работу
    - Стирает данные как рычаг шантажа или уничтожения следов
    - Шифрует диск
    - Улучшает батарею
  answer: 1
  explanation: Принудительный сброс — типичная ransom/anti-removal техника.
- question: Как проверить текущего Device Owner через adb?
  options:
    - adb shell dpm list-owners
    - adb logcat
    - adb shell ls
    - adb shell pm list packages
  answer: 0
  explanation: `dpm list-owners` показывает Device/Profile Owner.
```

## Где пригодится

- **Пентест Android:** оценка приложения, требующего роли администратора устройства.
- **Android Enterprise:** аудит MDM/DPC и назначенных политик.
- **Анализ малвари:** выявление Device Owner как механизма персистентности.
- **CTF:** Mobile-задачи на роли управления устройством.
