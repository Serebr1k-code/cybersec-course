#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Second deepening pass for MOB-GAP-2 lessons: push all four over 1200 real words."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOB = os.path.join(ROOT, 'content', 'mobile')

def add_before_quiz(lid, extra):
    p = os.path.join(MOB, lid + '.md')
    t = open(p, encoding='utf-8').read()
    first = next((ln.strip() for ln in extra.splitlines() if ln.strip()), '')
    if first and first in t:
        print('skip:', lid); return
    i = t.index('\n## Квиз')
    open(p, 'w', encoding='utf-8').write(t[:i] + '\n' + extra.strip() + '\n' + t[i:])
    print('deepened:', lid)

DEVADMIN = '''
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
'''

NOTIF = '''
## Шаг 13: эволюция ограничений

Google постепенно сужает возможности слушателей: начиная с Android 15 запрос на роль
notification listener через `ACTION_NOTIFICATION_LISTENER_SETTINGS` для сайдлоаженных
приложений ограничивается, а явная выдача требует дополнительных условий. Но на устройствах с
более старым API и на кастомных прошивках поверхность остаётся, поэтому техника актуальна для
ретро-аудита и анализа уже установленной малвари.

## Шаг 14: чек-лист аудита приложения

1. Есть ли в манифесте `<service>` с `BIND_NOTIFICATION_LISTENER_SERVICE`?
2. Просит ли приложение `ACTION_NOTIFICATION_LISTENER_SETTINGS` при запуске?
3. Что делает `onNotificationPosted` — читает `extras`, логирует, шлёт в сеть?
4. Есть ли фильтр по пакетам банков/SMS-приложений?
5. Отменяет ли сервис уведомления (`cancelNotification`), скрывая их от жертвы?

Отрицательный ответ на 3–5 — обычный «уборщик уведомлений». Положительный хотя бы на один —
повод считать приложение потенциально вредоносным.

## Шаг 15: пример записи в отчёте

«Приложение `com.example.helper` регистрирует `NotificationListenerService`, который в
`onNotificationPosted` извлекает `EXTRA_TEXT` и отправляет совпадения регулярного выражения
`(\\d{4,8})` на внешний хост. Это позволяет перехватывать одноразовые коды подтверждения
(OTP) без SMS-разрешений. Рекомендация: удалить слушателя, не размещать OTP в тексте
уведомлений.»
'''

SELINUX = '''
## Шаг 13: MLS/MCS и категории приложений

Android использует **MCS** (Multi-Category Security) поверх MLS. Каждому приложению выдаётся
уникальная пара категорий (`s0:c512,c768`), и политика запрещает домену одного приложения
читать файлы другого, даже если тип совпадает. Поэтому «одного root» недостаточно: чтобы
прочитать данные чужого приложения, нужно либо подобрать домен, либо снять категории.

```bash
$ adb shell ps -Z | grep com.bank
u:r:untrusted_app:s0:c100,c256 u0_a201 ... com.bank.app
```

Категории `c100,c256` — это «метка» приложения. Файлы в его песочнице имеют тот же набор
категорий, и другое приложение (`c512,c768`) их не увидит.

## Шаг 14: типичные ошибки аудита SELinux

- Считать, что `getenforce = Enforcing` гарантирует защиту: кастомные `allow`-правила могут
  делать enforcing бессмысленным.
- Забывать про per-domain permissive: часть доменов может быть ослаблена.
- Игнорировать MLS-категории: «root, но нет доступа» — это почти всегда MCS.
- Не проверять `neverallow`-инварианты, которые производитель мог ослабить.
- Оценивать только политику AOSP, не глядя на вендорские дополнения в `/sys/fs/selinux/`.
'''

ATTEST = '''
## Шаг 12: сценарий полного аудита

1. **Найти** в APK вызов `KeyGenParameterSpec.Builder(...).setAttestationChallenge(challenge)`.
2. **Снять** цепочку с устройства (или из перехваченного TLS-запроса).
3. **Разобрать** расширение `1.3.6.1.4.1.11129.2.1.17`: securityLevel, verifiedBootState,
   challenge.
4. **Определить**, что именно валидирует сервер: сверяет ли корень до Google root, challenge и
   отпечаток приложения.
5. **Проверить обход**: подсунуть самоподписанный сертификат / переиспользовать чужую цепочку
   и посмотреть, примет ли сервер.

Если на шаге 4 выясняется, что сервер доверяет клиентскому «true» без проверки подписи — это
эквивалент отсутствия аттестации.

## Шаг 13: подводные камни Play Integrity

- **Classic request** возвращает вердикт, который легко проксировать; **standard request** с
  `nonce` и серверной валидацией — нет.
- Вердикт имеет срок годности и привязан к `requestHash`/`nonce`; сервер обязан их сверять.
- `MEETS_BASIC_INTEGRITY` выполняется даже на эмуляторах с GMS — не путать с
  `MEETS_STRONG_INTEGRITY`.
- Вердикт приходит подписанным Google; без проверки подписи его можно подделать на клиенте.
'''

for lid, extra in [
    ('mobile-android-device-admin', DEVADMIN),
    ('mobile-android-notification-listener', NOTIF),
    ('mobile-android-selinux', SELINUX),
    ('mobile-android-attestation', ATTEST),
]:
    add_before_quiz(lid, extra)

print('done')
