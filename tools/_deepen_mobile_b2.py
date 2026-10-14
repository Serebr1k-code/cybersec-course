#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deepen the 5 MOB-GAP-2 outputs (hub + 4 lessons) to >=1200 real words and
add the missing '## Где пригодится' tail. Idempotent-ish: refuses to re-insert
if the marker section already exists."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOB = os.path.join(ROOT, 'content', 'mobile')

def add_before_quiz(lid, extra):
    p = os.path.join(MOB, lid + '.md')
    t = open(p, encoding='utf-8').read()
    first = next((ln.strip() for ln in extra.splitlines() if ln.strip()), '')
    if first and first in t:
        print('skip (already deepened):', lid)
        return
    marker = '\n## Квиз'
    i = t.index(marker)
    t = t[:i] + '\n' + extra.strip() + '\n' + t[i:]
    open(p, 'w', encoding='utf-8').write(t)
    print('deepened:', lid)

def add_where(lid, where):
    p = os.path.join(MOB, lid + '.md')
    t = open(p, encoding='utf-8').read()
    if '## Где пригодится' in t:
        print('skip (where present):', lid)
        return
    t = t.rstrip() + '\n\n## Где пригодится\n\n' + where.strip() + '\n'
    open(p, 'w', encoding='utf-8').write(t)
    print('where added:', lid)

# --------------------------------------------------------------------------
DEVADMIN = '''
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
'''

NOTIF = '''
## Шаг 9: как читается поток уведомлений

`NotificationListenerService` получает колбэки от системы:

```java
@Override
public void onNotificationPosted(StatusBarNotification sbn) {
    Notification n = sbn.getNotification();
    Bundle ex = n.extras;
    String title = ex.getString(Notification.EXTRA_TITLE);
    String text  = ex.getString(Notification.EXTRA_TEXT);
    String pkg   = sbn.getPackageName();
    // ...
}
```

`StatusBarNotification` даёт имя пакета и время; `extras` — заголовок, текст и (иногда) большие
текстовые блоки (`EXTRA_BIG_TEXT`). Для OTP-перехвата злоумышленнику достаточно вызвать
`onNotificationPosted` и регуляркой вытащить цифры.

## Шаг 10: практика — вылавливание OTP

Минимальный фильтр по коду подтверждения выглядит так (smali-эквивалент для статического
анализа — ищите `Pattern.compile` рядом с `EXTRA_TEXT`):

```java
Matcher m = Pattern.compile("(\\\\d{4,8})").matcher(text);
if (m.find()) {
    String otp = m.group(1);
    exfil(pkg, otp);          // куда-нибудь в сеть
}
```

Обратите внимание: сервис не просит доступ к SMS и не читает другие приложения напрямую — он
просто читает то, что **сама система** показала пользователю. Именно поэтому такой перехват
почти не требует разрешений и плохо заметен.

## Шаг 11: как включить и как это детектится

Включение — только с согласия пользователя: `Settings > Notifications > Device & app
notifications > <app>`. Включённые слушатели хранятся в настройке:

```bash
$ adb shell settings get secure enabled_notification_listeners
com.example.helper/.NotifListener:com.example.helper
```

Проверка списка — базовый детект. Ещё один признак — сервис объявляет
`BIND_NOTIFICATION_LISTENER_SERVICE` в манифесте. В новых версиях Android Google ужесточает
правила для сайдлоаженных слушателей, но на устройствах с более старым API поверхность остаётся.

## Шаг 12: защита

- Не кладите OTP в текст уведомления, если можете показать его только внутри приложения.
- Используйте `setLocalOnly(true)`, чтобы уведомление не уходило на часы/в облако.
- Для банков — показывайте код в самом приложении, а в шторку выводите нейтральный текст.
- При аудите ищите слушатели, которые пересылают содержимое уведомлений в сеть.

## Таблица: ключевые поля и методы

| Поле/метод | Значение |
|---|---|
| `onNotificationPosted` | вызывается на каждое новое уведомление |
| `sbn.getPackageName()` | источник уведомления |
| `EXTRA_TITLE` / `EXTRA_TEXT` | заголовок и текст |
| `onNotificationRemoved` | уведомление снято (для скрытия следов) |
| `settings get secure enabled_notification_listeners` | список активных слушателей |

## Крайние случаи и подводные камни

- Уведомление может приходить в `EXTRA_BIG_TEXT`, а не в `EXTRA_TEXT` — фильтр только по
  одному полю пропускает данные.
- Некоторые приложения используют `setPublicVersion`, и в шторку попадает урезанный текст.
- Слушатель видит уведомления **до** того, как пользователь их открыл, — задержки нет.
- Отмена уведомления слушателем (`cancelNotification`) скрывает его от жертвы.

## Что дальше / решение

Итог: `NotificationListenerService` — легальный API доступности, который превращается в
перехватчик OTP, если приложение-владелец недобросовестно. Детект прост: проверьте список
активных слушателей. В следующем уроке спустимся ещё ниже — к SELinux, который решает, что
вообще разрешено процессу на уровне ядра.
'''

SELINUX = '''
## Шаг 9: политика изнутри — allow-правила

Политика SELinux — это набор правил вида:

```
allow <домен> <тип>:<класс> <разрешения>;
```

Например:

```
allow untrusted_app app_data_file:file { read write open };
```

Читается так: домену `untrusted_app` разрешено читать/писать/открывать файлы типа
`app_data_file`. Работает принцип **default deny**: чего нет в правилах — запрещено. Кроме
`allow` есть `neverallow` — инварианты, которые компилятор политики не даст нарушить даже
производителю (именно они защищают критичные границы, и именно их чаще всего пытаются обойти
эксплойтом).

## Шаг 10: инструменты анализа политики

- `seinfo` / `sesearch` (пакет `setools`) — поиск типов, доменов и правил по политике.
- `audit2allow` — превращает запись об отказе (`avc: denied`) в готовое allow-правило.
- `magiskpolicy` / `supolicy` — правка политики прямо на устройстве с root.

Разбор реального отказа:

```bash
$ adb shell dmesg | grep avc
avc: denied { write } for pid=1234 comm="sh" name="x" dev="dm-0" ino=42 \
  scontext=u:r:shell:s0 tcontext=u:object_r:system_file:s0 tclass=file permissive=0
```

Читаем: процесс в домене `shell` (scontext) пытался писать (write) в файл типа `system_file`
(tcontext). `permissive=0` значит отказ реальный, а не просто лог. Прогнав строку через
`audit2allow`, получаем ровно то правило, которое нужно было бы добавить:

```
allow shell system_file:file write;
```

## Шаг 11: domain transition по шагам

**Domain transition** — переход процесса в другой (обычно более привилегированный) домен. Он
требует выполнения трёх условий в политике: у исходного домена есть `transition` на новый тип,
у исполняемого файла проставлен `entrypoint`, и есть `allow <старый> <новый>:process transition`.
Классический пример — `init` запускает `su` и тот получает домен `su`, у которого больше прав,
чем у `shell`. Атакующий, получивший управление над процессом с широким доменом, получает и
его права — обходить SELinux «с нуля» не нужно.

## Шаг 12: практика на устройстве с root

С Magisk можно ослабить политику вживую (в исследовательской среде):

```bash
# magiskpolicy --live 'allow untrusted_app system_file:file write'
# getenforce
Enforcing
# echo test > /system/x && echo OK
OK
```

Здесь мы не выключили SELinux, а добавили точечное правило — так обход выглядит «чище» и
меньше заметен, чем перевод устройства в permissive.

## Таблица: команды и файлы

| Что | Команда / путь |
|---|---|
| Режим | `getenforce`, `setenforce 0/1` |
| Контекст процесса | `ps -Z` |
| Контекст файла | `ls -Z` |
| Отказы | `dmesg` (фильтр `grep avc`) |
| Генерация правила | `audit2allow` |
| Правка политики | `magiskpolicy`, `supolicy` |
| Псевдо-ФС политики | `/sys/fs/selinux/` |

## Крайние случаи и подводные камни

- **Per-domain permissive**: отдельный домен может быть permissive, даже когда вся система в
  enforcing. Такой домен — приоритетная цель (`seinfo` покажет).
- Категории **MCS** (`s0:c512,c768`) изолируют приложения друг от друга — два приложения с
  разными категориями не прочитают файлы друг друга, даже если тип совпадает.
- `isolated_app` — ещё более узкий домен, чем `untrusted_app` (для isolatedProcess).
- На кастомных сборках SELinux иногда **выключен** — тогда проверка `getenforce` не работает,
  и ограничения нет вовсе.
- Полагаться только на `getenforce` нельзя: enforcing + слишком широкие кастомные правила даёт
  тот же эффект, что permissive.

## Что дальше / решение

Итог: SELinux — это default-deny MAC поверх UNIX-прав; root без подходящего домена бесполезен.
В аудите проверяйте режим, домены и кастомные правила производителя. Следующий урок — про
аппаратное доверие: как ключ «доказывает», что он рождён в TEE, и как эта проверка ломается.
'''

ATTEST = '''
## Шаг 9: структура attestation-сертификата

Аттестация возвращает цепочку X.509, в которой листовой сертификат содержит расширение с OID
`1.3.6.1.4.1.11129.2.1.17` — это структура `KeyDescription`. Внутри два набора:

- **softwareEnforced** — то, что заявлено в софте: `purpose`, `origin`, `attestationChallenge`,
  `allApplications`.
- **teeEnforced** — то, что гарантировано железом: `rootOfTrust` (`verifiedBootState`,
  `deviceLocked`, `verifiedBootHash`), `attestationSecurityLevel` (`Software` / `TrustedEnvironment`
  / `StrongBox`), `keymasterSecurityLevel`, `uniqueId`.

Именно `rootOfTrust.verifiedBootState = Verified` и `attestationSecurityLevel = TrustedEnvironment`
означают, что ключ действительно аппаратный и устройство загружено в проверенном состоянии.

## Шаг 10: разбор сертификата инструментами

Посмотреть расширение можно так:

```bash
$ openssl x509 -in leaf.pem -text -noout | sed -n '/1.3.6.1.4.1.11129.2.1.17/,+20p'
    X509v3 Android Key Attestation:
        attestationVersion: 300
        attestationSecurityLevel: TrustedEnvironment
        keymasterSecurityLevel: TrustedEnvironment
        attestationChallenge: 0x...  (nonce)
        verifiedBootState: Verified
        deviceLocked: true
```

Если в выводе `attestationSecurityLevel: Software` — ключ мог быть создан без аппаратной
поддержки, и сервер, доверяющий такому сертификату, можно обмануть. Ещё один быстрый способ —
`openssl asn1parse` по DER-сертификату.

## Шаг 11: Play Integrity как современная замена

Classic Attestation сегодня чаще заменяют **Play Integrity API**. Приложение просит у Google
«вердикт» и получает набор полей: `MEETS_DEVICE_INTEGRITY`, `MEETS_BASIC_INTEGRITY`,
`MEETS_STRONG_INTEGRITY`, а также `PLAY_RECOGNIZED`. Сервер должен запрашивать вердикт
(**standard request**) и проверять `requestDetails`/`nonce`, а не только сам факт успеха. Слабая
проверка — когда сервер доверяет клиенту и не сверяет nonce или не валидирует подпись вердикта.

## Таблица: поля и их смысл

| Поле | Значения | Что доказывает |
|---|---|---|
| `attestationSecurityLevel` | Software / TEE / StrongBox | где рождён ключ |
| `verifiedBootState` | Verified / SelfSigned / Unverified | целостность загрузки |
| `deviceLocked` | true / false | включена ли блокировка |
| `attestationChallenge` | nonce | привязка к запросу |
| `origin` | generated / imported / unknown | происхождение ключа |

## Крайние случаи и подводные камни

- Проверка **только** факта наличия сертификата (без сверки корня Google) обходится
  самоподписанным сертификатом.
- Отсутствие сверки `attestationChallenge` позволяет переиспользовать чужую (валидную) цепочку.
- `verifiedBootState` может быть `Unverified` на устройствах с разблокированным загрузчиком —
  строгие приложения должны это отклонять.
- StrongBox есть не на всех устройствах; требовать его безусловно — ломать совместимость.
- Play Integrity вердикт — тоже ответ, который можно проксировать с легитимного устройства,
  если сервер не привязывает его к nonce/сессии.

## Что дальше / решение

Итог: аттестация — это криптографическое доказательство происхождения ключа и состояния
устройства; ломается она не в криптографии, а в **проверке на сервере**. В аудите ищите
`setAttestationChallenge`, снимайте цепочку и проверяйте, что именно валидирует сервер.
'''

WHERE = {
 'mobile-android-trust': '''- **Пентест Android:** оценка привилегий без root — Device Owner, слушатели уведомлений, SELinux, аттестация.
- **Android Enterprise / MDM:** аудит политик и ролей управления устройством.
- **Анализ малвари:** распознавание злоупотребления доверенными API (OTP-перехват, скрытый admin).
- **CTF:** Mobile-задачи на привилегии и аппаратное доверие.''',
 'mobile-android-device-admin': '''- **Пентест Android:** оценка приложения, требующего роли администратора устройства.
- **Android Enterprise:** аудит MDM/DPC и назначенных политик.
- **Анализ малвари:** выявление Device Owner как механизма персистентности.
- **CTF:** Mobile-задачи на роли управления устройством.''',
 'mobile-android-notification-listener': '''- **Пентест Android:** проверка приложения на перехват OTP и уведомлений.
- **Bug bounty:** злоупотребление доверенными API для обхода 2FA.
- **Анализ малвари:** банковские трояны почти всегда читают уведомления.
- **CTF:** Mobile-задачи на перехват одноразовых кодов.''',
 'mobile-android-selinux': '''- **Эксплуатация Android:** обход MAC-ограничений после получения root.
- **Пентест устройств:** оценка кастомных политик производителя.
- **Анализ прошивок:** поиск permissive-доменов и слабых правил.
- **CTF:** Mobile-задачи на kernel/root с SELinux-ограничениями.''',
 'mobile-android-attestation': '''- **Пентест Android:** аудит серверной проверки аппаратного доверия.
- **Bug bounty:** обход integrity/attestation-проверок.
- **Реверс банковских приложений:** понимание, на чём держится защита.
- **CTF:** Mobile-задачи на подмену аттестации.''',
}

add_before_quiz('mobile-android-device-admin', DEVADMIN)
add_before_quiz('mobile-android-notification-listener', NOTIF)
add_before_quiz('mobile-android-selinux', SELINUX)
add_before_quiz('mobile-android-attestation', ATTEST)

for lid, w in WHERE.items():
    add_where(lid, w)

print('done')
