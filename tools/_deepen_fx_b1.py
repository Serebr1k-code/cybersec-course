#!/usr/bin/env python3
"""Batch 1 deepening for thin forensics lessons (mobile cluster).
Applies additive '## ' sections before the '## Квиз' heading.
"""
from __future__ import annotations
import re, sys

ADDS = {}

ADDS["mobile-android-notifications"] = """## Как устроена база notification_log.db

Начиная с Android 9 системный сервис `NotificationManagerService` ведёт журнал
показанных уведомлений в `notification_log.db`. Файл лежит в
`/data/system/users/<id>/notification_log.db` (для основного пользователя `<id>` = 0),
поэтому в одном телефоне с рабочим профилем таких баз может быть две. Базу создаёт
модуль `NotificationHistoryDatabase`, и в ней есть несколько таблиц:

- `notification` — сами записи о показанных уведомлениях;
- `notification_channel` — каналы уведомлений приложений;
- `notification_group` — сгруппированные уведомления.

Ключевые столбцы таблицы `notification`:

| Столбец | Что содержит |
|---|---|
| `uid` | идентификатор приложения-владельца |
| `package` | имя пакета, например `com.whatsapp` |
| `channel_id` | канал («messages», «otp», «promo») |
| `notification_id` | id уведомления внутри пакета |
| `sbn_key` | уникальный ключ StatusBarNotification |
| `post_time` | время показа (мс, epoch UTC) |
| `notification` | **сериализованный blob** StatusBarNotification |

Обрати внимание: столбец `notification` — это не текст, а сериализованный
protobuf-объект. Поэтому запрос `SELECT text FROM ...` ничего не даёт: заголовок и
текст нужно декодировать.

## Формат blob и декодирование

Blob содержит структуру `Notification`: заголовок (`title`), текст (`text`),
`tickerText`, иконку и `extras` (например, BigText или InboxStyle для мессенджеров).
Прямое чтение строк иногда даёт обрывки, но надёжнее работать парсерами:

```
$ aleapp -i notification_log.db -o out/          # ALEAPP
$ mvt-android --backup backup.ab --iocs iocs.txt # MVT
```

ALEAPP знает схему и распаковывает proto, выдавая готовую таблицу «пакет — заголовок —
текст — время». В CTF-задачах тот же результат часто получается через `strings`:

```
$ strings notification_log.db | grep -iE 'otp|код|password|nto\\{'
```

Важно: `strings` найдёт текст, но потеряет привязку к времени и пакету — для отчёта
всё равно сопоставляй со столбцами `package` и `post_time`.

## Каналы и важность (importance)

Таблица `notification_channel` описывает канал: `id`, `name`, `importance` (0–5),
`sound`, `vibration`, `lights`. По `importance` видно, был ли канал «тихим»: тихий
канал с именем `otp` у стороннего приложения — типичный признак перехвата SMS-кодов
вредоносным APK. Сравни `importance` канала с ожидаемым поведением приложения.

## Справочная таблица артефактов уведомлений

| Артефакт | Путь | Что даёт |
|---|---|---|
| notification_log.db | /data/system/users/0/ | история уведомлений |
| notification_policy.xml | /data/system/ | настройки каналов, отключённые |
| `dumpsys notification` | live | активные и recent уведомления |
| кэши приложений | /data/data/<pkg>/ | дубли текстов |
| база лаунчера | /data/data/<launcher>/ | счётчики непрочитанных |

## Срок хранения и что теряется

Историю уведомлений система чистит автоматически: базовое окно небольшое (исторически
около суток, у части вендоров и версий дольше), а пользователь может очистить её вручную
в настройках. Значит, если расследование начато поздно, `notification_log.db` может быть
пуст — это не значит «уведомлений не было». В таком случае смотри кэши приложений, ранее
снятый `logcat` и живой вывод `dumpsys notification --noredact`.

## Тонкие места

- Рабочий профиль и личный — это разные `users/<id>/`.
- Недекодированный blob выглядит мусором; вывод «данных нет» делать нельзя.
- `post_time` хранится в UTC — переводи в таймзону устройства перед сопоставлением.
- Кастомные лаунчеры пишут собственные копии уведомлений, иногда полнее системных.
- Отозванные (dismissed) уведомления могут ещё лежать в базе до плановой очистки."""

ADDS["mobile-ios-location"] = """## Где iOS хранит геолокацию

Основной источник — служба **routined** («Значимые места» и визиты). Её база лежит в
`/private/var/mobile/Library/Caches/com.apple.routined/`. В `Cache.sqlite` есть
Core-Data-таблицы с префиксом `ZRT`:

| Таблица | Смысл |
|---|---|
| `ZRTVISITMO` | визиты: приход/уход, привязка к месту |
| `ZRTLEARNEDLOCATIONOFINTERESTMO` | выученные «значимые места» (дом, работа) |
| `ZRTLOCATIONMO` | координаты с точностью и временем |

Столбцы `ZRTLOCATIONMO` включают `ZLATITUDE`, `ZLONGITUDE`,
`ZHORIZONTALACCURACY`, `ZTIMESTAMP`; `ZRTVISITMO` — `ZARRIVALDATE`,
`ZDEPARTUREDATE` и ссылку `ZLOCATION`. Core Data хранит время как **секунды с
2001-01-01** (Apple epoch), а не Unix epoch — при переводе прибавляй 978307200.

## Другие артефакты геолокации

- `com.apple.routined/Cloud.sqlite` — то, что синхронизируется через iCloud;
- `com.apple.locationd/` — кэши `locationd`, список клиентов геолокации;
- `com.apple.Maps/History.mapsdata` — история поиска и маршрутов в Картах;
- `com.apple.wifi-networks.plist` / `.backup` — известные Wi-Fi и последняя сеть;
- `consolidated.db` — старый артефакт (iOS ≤ 6), сейчас неактуален, но встречается
  в старых образах и в бэкапах.

## Разбор на практике

```
$ sqlite3 Cache.sqlite '.tables'
$ sqlite3 Cache.sqlite 'SELECT ZLATITUDE, ZLONGITUDE, ZTIMESTAMP FROM ZRTLOCATIONMO LIMIT 5;'
$ sqlite3 Cache.sqlite 'SELECT ZARRIVALDATE, ZDEPARTUREDATE FROM ZRTVISITMO;'
```

Перевод времени и координат в человекочитаемый вид:

```
$ python3 - <<'PY'
import datetime
apple = 978307200
t = 700000000            # ZTIMESTAMP из базы
print(datetime.datetime.utcfromtimestamp(t + apple))
PY
```

Точность (`ZHORIZONTALACCURACY`) в метрах: значение 5–10 м — GPS, 500–1500 м —
сотовая сеть. По разбросу точности видно, как именно определялось место.

## Что искать и как это связывать

- Хронологию перемещений: последовательность визитов даёт маршрут дня.
- Привязку устройств: одинаковые координаты в разных базах (routined + Карты).
- Совпадение с событиями: время визита сопоставляй с логами приложений.
- Удалённые приложения не удаляют историю routined сразу.

## Тонкие места

- Apple epoch, а не Unix — самая частая ошибка пересчёта.
- Без пароля устройства `Cache.sqlite` в бэкапе может быть пустой заглушкой.
- «Значимые места» можно отключить в настройках — тогда база пуста законно.
- iCloud-синхронизация означает, что часть истории есть в облаке, а не на диске.
- Не путай визиты (visit) и значимые места (learned location): это разные таблицы."""

ADDS["mobile-gms"] = """## Что такое GMS и где его данные

Google Mobile Services (GMS) — набор сервисов Google на Android: Play Services,
Play Store, аккаунты, Firebase, SafeBrowsing, Nearby. Почти всё живёт под
`/data/data/com.google.android.gms/`, а учётные записи — в системных базах
AccountManager:

- `/data/system_ce/0/accounts_ce.db` — таблица `accounts`: `name` (email),
  `type` (`com.google`), пароли там не хранятся;
- `/data/system_de/0/accounts_de.db` — device-encrypted версия;
- `/data/data/com.google.android.gms/databases/` — десятки баз `gms_*`,
  `phenotype.db` (флаги экспериментов), `droidguard`, `safebrowsing`;
- `/data/data/com.google.android.gms/shared_prefs/` — `GoogleSettings`,
  предпочтения аккаунта и рекламного id;
- `/data/data/com.google.android.gms/files/` — кэши, логи, загрузки.

## Идентификаторы и аккаунты

GMS связывает несколько идентификаторов, полезных при расследовании:

| Идентификатор | Где искать | Смысл |
|---|---|---|
| Android ID | `settings_secure.xml` (`android_id`) | id устройства для Google |
| Advertising ID | shared_prefs GMS | рекламный id (сбрасывается) |
| Google account | accounts_ce.db | email пользователя |
| Gaia id | базы GMS | внутренний id аккаунта |
| Device name | accounts / GMS prefs | имя устройства |

Сопоставление email ↔ устройство ↔ активность часто и есть цель: по `accounts_ce.db`
видно, какие Google-аккаунты были добавлены, а по базам GMS — какие сервисы
использовались и когда.

## Разбор на практике

```
$ sqlite3 accounts_ce.db 'SELECT name,type FROM accounts;'
$ sqlite3 /data/data/com.google.android.gms/databases/phenotype.db '.tables'
$ grep -r 'android_id' /data/system/users/0/settings_secure.xml
```

Firebase-приложения хранят `google_app_id` и `firebase_database_url` в
`/data/data/<pkg>/shared_prefs/` — это помогает связать мобильное приложение с
бэкендом и проектом Google Cloud.

## Что искать

- какие Google-аккаунты и когда добавлены;
- какие сервисы GMS включены (Nearby, Location Sharing, Find My Device);
- следы Play Store: установки, обновления, отзывы;
- рекламный id и настройки персонализации;
- токены push (FCM registration id) в prefs приложений.

## Тонкие места

- Базы GMS часто зашифрованы на уровне приложения — читаются только на живом или
  разблокированном устройстве.
- Часть данных синхронизирована в облако; на диске остаётся кэш.
- Имена баз зависят от версии GMS — не удивляйся, если `gms_*.db` отличается.
- `accounts_ce.db` содержит только метаданные, паролей там нет — это норма.
- Advertising ID уважает «удалить рекламный идентификатор»: пустое значение законно."""

ADDS["mobile-app-reversing"] = """## Анатомия APK

APK — это ZIP-архив с предсказуемой структурой:

| Элемент | Что это |
|---|---|
| `AndroidManifest.xml` | манифест (бинарный XML), права, компоненты |
| `classes.dex` | байткод Dalvik (может быть `classes2.dex`, `classes3.dex`…) |
| `resources.arsc` | скомпилированные ресурсы |
| `res/` | картинки, layout, строки |
| `lib/<abi>/*.so` | нативные библиотеки (arm64-v8a, armeabi-v7a) |
| `assets/` | произвольные файлы, часто шифрованные конфиги |
| `META-INF/` | подписи (`CERT.RSA`, `MANIFEST.MF`) |

`classes.dex` начинается с магии `dex\\n035\\0` — по ней файл опознаётся даже без
расширения. Нативные `.so` — обычный ELF (см. раздел reversing), их анализируют
дизассемблером, а не декомпилятором DEX.

## Инструменты и рабочий процесс

```
$ unzip -l app.apk
$ apktool d app.apk -o app_src        # smali + ресурсы
$ jadx-gui app.apk                    # Java-декомпиляция
$ d2j-dex2jar classes.dex             # DEX -> JAR для JD-GUI
$ file lib/arm64-v8a/libnative.so
```

Порядок разумный такой: сначала `jadx` — быстро получить читаемый Java; затем
`apktool` — если нужно править smali и пересобирать; затем нативные `.so` — если
логика вынесена в C/C++ (анти-анализ, крипто, проверки).

## Обфускация и упаковщики

Коммерческие приложения обфусцируют ProGuard/R8: имена классов и методов
превращаются в `a.a.a`. Есть и **упаковщики** (Bangcle, Qihoo Jiagu, Tencent
Legu): настоящий DEX зашифрован, а в APK лежит загрузчик, который расшифровывает
код в памяти. Признаки упаковщика:

- `classes.dex` крошечный, но в `assets/` большой бинарный блоб;
- строки вроде `libjiagu.so`, `libDexHelper.so`;
- манифест ссылается на `StubApp`/`ApplicationWrapper`.

Для разбора упакованного APK нужен дамп из памяти (Frida, `frida-dexdump`) на
запущенном устройстве.

## Динамика и анти-анализ

Типичные защиты: проверка подписи, детект root/эмулятора, проверка целостности
DEX. Обход — Frida:

```
$ frida-ps -U
$ frida -U -f com.example.app -l hook.js
```

В `hook.js` перехватывают проверки (например, функцию, возвращающую `false` для
root) и выводят расшифрованные строки.

## Что искать в CTF

- строки флага в `resources.arsc` и `assets/`;
- ключи и URL в `.so` (шифрование часто там);
- скрытые файлы в `assets/`, названные нейтрально;
- проверки, которые сравнивают ввод с хешем — там и лежит ответ.

## Тонкие места

- `AndroidManifest.xml` бинарный — читай `apktool`, а не `cat`.
- Multipart DEX: не забудь `classes2.dex` и далее.
- React Native/Flutter: логика в `index.android.bundle`/`libapp.so`, а не в DEX.
- Пароли часто в нативном коде — декомпиляция DEX их не покажет.
- Проверка подписи ломает пересобранный APK — иногда нужно патчить smali."""

ADDS["mobile-android-location"] = """## Откуда берётся история местоположений

Android определяет место через GPS, Wi-Fi и соты, а хранит результат в нескольких
местах в зависимости от приложения и версии. Самое полезное на устройстве:

| Артефакт | Путь | Что даёт |
|---|---|---|
| Карты (Google Maps) | `/data/data/com.google.android.apps.maps/databases/` | поиск, «Мои места» |
| GMS | `/data/data/com.google.android.gms/databases/` | кэш геолокации, Nearby |
| `dumpsys location` | live | текущие и недавние фиксации |
| `com.google.android.gms/files/` | кэши | черновые записи о местах |
| системный провайдер | `settings_secure.xml` | включён ли доступ к геолокации |

В Google Maps база `gmm_myplaces.db` хранит сохранённые и «домашний/рабочий»
адреса, а `gmm_storage.db` и таблицы поиска — историю запросов. По ним видно, где
пользователь был и что искал рядом.

## Живой срез: dumpsys location

```
$ adb shell dumpsys location
Location Providers:
  passive: ...
  network: ...
  gps: ...
Last Known Locations:
  Location[fused 55.7558,37.6173 hAcc=12 et=+1d2h ...]
```

`Last Known Locations` даёт последние координаты от каждого провайдера с точностью
(`hAcc`) и временем (`et`). Это быстрый способ подтвердить место без разбора баз.

## Формат и перевод

Координаты — WGS-84 (десятичные градусы). Время фиксаций — Unix-эпоха в
миллисекундах. Если база от приложения хранит собственный формат, смотри схему:

```
$ sqlite3 gmm_storage.db '.tables'
$ sqlite3 gmm_storage.db 'SELECT * FROM search_history LIMIT 3;'
```

## Что искать

- маршруты: последовательность точек с временем;
- «дом/работа»: сохранённые ярлыки с координатами;
- частые места: кластеры координат;
- совпадение с другими артефактами (Wi-Fi, уведомления, фото с геотегами);
- включён ли доступ к геолокации у конкретного приложения.

## Тонкие места

- Google Timeline в основном в облаке, а не на диске; локально — кэш и Maps.
- Имена таблиц зависят от версии приложения.
- При отключённой геолокации базы пусты законно — не считай это удалением следов.
- Точность (`hAcc`) показывает источник: маленькая — GPS, большая — сеть.
- Часовой пояс: время в UTC, а «дом» пользователь видит в своей зоне."""

ADDS["mobile-ios-keychain-deep"] = """## Как устроен keychain внутри

На устройстве keychain — это SQLite-база `keychain-2.db` в `/var/Keychains/`. Её
таблицы отражают классы элементов:

| Таблица | Класс | Что хранит |
|---|---|---|
| `genp` | generic password | пароли приложений, Wi-Fi, токены |
| `inet` | internet password | логины сайтов (домен, порт, протокол) |
| `cert` | certificate | сертификаты |
| `keys` | cryptographic key | ключи (в т.ч. привязанные к SEP) |
| `ckperm` | access control | права доступа приложений к элементу |

Ключевой атрибут — **доступность** (`kSecAttrAccessible`), определяющая, можно ли
прочитать секрет при заблокированном экране:

- `WhenUnlocked` — только при разблокированном;
- `AfterFirstUnlock` — после первой разблокировки (часто у фоновых сервисов);
- `Always` — всегда (в бэкап попадает);
- `...ThisDeviceOnly` — не переносится и не уходит в бэкап/iCloud.

Значение `always` и отсутствие `ThisDeviceOnly` — красный флаг: секрет извлекается
даже из бэкапа.

## Защита: классовые ключи и Secure Enclave

Сами данные зашифрованы не одним ключом. Каждый элемент шифруется уникальным ключом,
а тот — «классовым» ключом, который выводится из пароля устройства и
аппаратного UID Secure Enclave. Поэтому:

- без пароля устройства классовые ключи не выводятся;
- ключи, помеченные как SEP-привязанные (P-256), **неэкспортируемы** — извлечь их
  копию невозможно в принципе;
- смена пароля переворачивает классовую иерархию, часть элементов становится
  недоступна.

## Извлечение: бэкап vs живое устройство

Из шифрованного бэкапа keychain лежит в `keychain-backup.plist`, но только те
элементы, что не помечены `ThisDeviceOnly`:

```
$ iphone_backup_decrypt -i Backup/<UDID> -o out -p <password>
$ plutil -p out/keychain-backup.plist | head
```

На живом разблокированном устройстве с jailbreak:

```
$ ssh root@iphone
# sqlite3 /var/Keychains/keychain-2.db 'SELECT svce,acct FROM genp LIMIT 10;'
```

Даже с root значения полей зашифрованы — нужен `keychain_dumper` с правами и
разблокированным экраном, чтобы расшифровать доступные классы.

## Что искать

- пароли Wi-Fi (`genp` с `svce=AirPort`) — восстановление сети;
- токены сессий и OAuth-токены приложений;
- сертификаты и приватные ключи (`cert`, `keys`);
- записи с `always` — потенциальная утечка;
- элементы `ThisDeviceOnly`, которых в бэкапе нет — признак, что смотрели не тот
  источник.

## Тонкие места

- Без пароля устройства keychain не расшифровывается — это норма, а не тупик.
- В iCloud Keychain часть элементов синхронизируется — они есть в облаке.
- Имена служб (`svce`) и аккаунтов (`acct`) читаемы даже без расшифровки.
- Приложение может ограничить элемент `access control` — доступ получит только оно.
- Старые бэкапы (iOS 9-) имеют другую схему классов — сверяй версию."""

def main() -> int:
    base = "content/forensics/"
    for lid, add in ADDS.items():
        path = base + lid + ".md"
        s = open(path, encoding="utf-8").read()
        m = re.search(r"^## Квиз\s*$", s, re.MULTILINE)
        if not m:
            print("SKIP (no quiz):", lid); continue
        if "## Квиз" in add or "## Где пригодится" in add:
            raise SystemExit("bad add for " + lid)
        out = s[:m.start()] + add + "\n\n" + s[m.start():]
        open(path, "w", encoding="utf-8").write(out)
        print("deepened", lid, "+", len(add.split()), "tokens")
    return 0

if __name__ == "__main__":
    sys.exit(main())
