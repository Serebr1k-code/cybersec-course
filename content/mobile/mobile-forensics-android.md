---
id: mobile-forensics-android
title: "Android-форензика: извлечение и анализ артефактов"
category: mobile
parent: mobile-forensics
difficulty: medium
order: 1
tags: [forensics, android, adb, extraction, aleapp, sqlite, artifacts, root]
prerequisites: [mobile-insecure-storage, mobile-backup]
useful_for:
  - "Цифровая форензика"
  - "Реагирование на инциденты"
  - "Пентест мобильных приложений"
estimated_minutes: 50
summary: "Практическое извлечение данных Android: логический и root-дамп, сбор артефактов, анализ через ALEAPP и SQLite, поиск токенов и учётных данных."
---
## Введение

Android-форензика начинается с выбора метода извлечения (логический, файловая система, образ), затем — сбор артефактов и их анализ. Для пентестера цель — найти учётные данные, токены, историю и оценить, какие данные приложение оставляет. В этом уроке — практический конвейер: от `adb` до отчёта ALEAPP, с фокусом на артефакты, полезные для безопасности.

Принцип: сначала копия, потом анализ. Не работайте на «живом» устройстве, если нужна целостность; фиксируйте хэши.

## Логическое извлечение (без root)

```bash
adb devices -l
# список пакетов
adb shell pm list packages | sed 's/package://' | sort > packages.txt
# APK каждого пакета
for p in $(cat packages.txt); do
  ap=$(adb shell pm path $p | sed 's/package://' | tr -d '\r')
  echo "$p -> $ap"
done > apk_paths.txt
# бэкап приложения (если allowBackup)
adb backup -f app.ab -apk com.target.app
# content-провайдеры
adb shell content query --uri content://com.target.app.provider/users
# системная информация
adb shell dumpsys > dumpsys.txt
adb shell getprop > getprop.txt
adb logcat -d > logcat.txt
```

Логически доступны: APK, бэкапы, данные через провайдеры, логи, `dumpsys`.

## Root-дамп файловой системы

```bash
# на root-устройстве
adb root 2>/dev/null || adb shell su -c 'id'
# копируем /data/data целевого приложения
adb shell su -c 'tar czf /sdcard/target_data.tgz /data/data/com.target.app'
adb pull /sdcard/target_data.tgz
# или всю /data (большой размер!)
adb shell su -c 'tar czf /sdcard/data_full.tgz /data'
```

Хэширование для целостности:

```bash
sha256sum target_data.tgz > target_data.tgz.sha256
```

## Артефакты и где их искать

| Артефакт | Путь |
|----------|------|
| SharedPreferences | `/data/data/<pkg>/shared_prefs/*.xml` |
| SQLite-базы | `/data/data/<pkg>/databases/*.db` |
| Кэш API | `/data/data/<pkg>/cache/` |
| Cookies (WebView) | `/data/data/<pkg>/app_webview/Cookies` |
| Логи | `/data/data/<pkg>/files/*.log`, logcat |
| Аккаунты | `/data/system/accounts.db` |
| Wi-Fi | `/data/misc/wifi/WifiConfigStore.xml` |
| Использование | `/data/system/usagestats/` |
| Внешние данные | `/sdcard/Android/data/<pkg>/` |

## Полный сквозной пример: поиск токена

```bash
# 1. Извлекаем данные приложения (root)
adb shell su -c 'tar czf /sdcard/t.tgz /data/data/com.target.app'
adb pull /sdcard/t.tgz && tar xzf t.tgz
# 2. Ищем секреты в prefs и базах
grep -rIl "token\|password\|secret" data/data/com.target.app/shared_prefs/
sqlite3 data/data/com.target.app/databases/app.db ".tables"
sqlite3 data/data/com.target.app/databases/app.db "SELECT * FROM session;"
# 3. Cookies
sqlite3 data/data/com.target.app/app_webview/Cookies "SELECT host_key,name,value FROM cookies;"
# 4. JWT в кэше
grep -rIl "eyJ" data/data/com.target.app/cache/ | head
```

Результат: сессионный токен, cookie, кэшированные ответы API — всё, что можно использовать для анализа.

## ALEAPP: автоматический анализ

```bash
pip install aleapp
python3 aleapp.py -t tar -i target_data.tgz -o ./aleapp_out
# открыть aleapp_out/index.html
```

ALEAPP разберёт: аккаунты, Bluetooth/Wi-Fi, историю звонков, SMS, приложения, cookies, базы, геолокации. Для больших дампов используйте `-t fs` (файловая система) или `-t ab` (ADB-бэкап).

## Частые ошибки

- **Работать без копии**: изменения на живом устройстве портят доказательства.
- **Забыть хэш**: без `sha256sum` целостность не доказать.
- **Не проверить allowBackup**: `adb backup` пуст при `allowBackup=false`.
- **Игнорировать `/sdcard/Android/data`**: там тоже данные приложения.
- **Забыть про `dumpsys`**: активные сессии/сервисы видны только там.
- **Пытаться прочитать зашифрованные prefs**: часть данных шифруется Keystore — без ключа не прочитать.

## Что дальше / решение

Порядок: выбрать метод → извлечь копию → собрать артефакты → ALEAPP → выписать находки. Свяжите с `mobile-backup`, `mobile-keystore` (шифрование), `mobile-forensics-cloud`. Рекомендация: root-дамп `/data/data/<pkg>` + ALEAPP для отчёта.

## Справочная таблица

| Метод | Команда |
|-------|---------|
| Список пакетов | `pm list packages` |
| Путь APK | `pm path <pkg>` |
| Бэкап | `adb backup -f a.ab <pkg>` |
| Root-дамп | `tar czf /sdcard/t.tgz /data/data/<pkg>` |
| Логи | `adb logcat -d` |
| Состояние | `adb shell dumpsys` |
| Анализ | `aleapp.py -t tar -i t.tgz` |

## Сквозной кейс Android-форензики

Разберём полный цикл извлечения данных тестового приложения с root-устройства.

Начинаем с фиксации: модель, версия Android, наличие root, состояние блокировки. От этого зависит метод. Логическое извлечение доступно всегда (если включена отладка или есть физический доступ), root-дамп — только при наличии root, полный образ — при разблокированном загрузчике и специальных средствах.

Дальше — сбор. Первым делом делаем копию, а не читаем живые файлы. С root-доступом копируем `/data/data/<pkg>` целиком, плюс интересующие системные пути: `/data/system/accounts.db`, `/data/system/usagestats`, `/data/misc/wifi`. Для каждого архива считаем SHA-256. Логи (`logcat`, `/data/anr`, `/data/tombstones`) сохраняем отдельно — они дают временную шкалу и краши.

Анализ начинаем с артефактов приложения. SharedPreferences (XML) часто содержат токены, флаги, конфиги. SQLite-базы — бизнес-данные и кэши. WebView Cookies (`app_webview/Cookies`) — сессии веб-представлений. Кэши API (`cache/`) — ответы сервера с потенциальными ПДн. Прогоняем grep по JWT-паттернам (`eyJ`) и по ключевым словам (`token`, `password`, `secret`).

Затем системные артефакты: `accounts.db` даёт учётные записи устройства; `usagestats` — какие приложения и когда запускались; Wi-Fi-конфиги — сети и, иногда, PSK. Это связывает активность пользователя с приложением.

Автоматизация: запускаем ALEAPP на архиве, получаем HTML-отчёт. Он агрегирует десятки артефактов и строит временные линии. Для больших дампов используем `-t fs`. Отчёт — основа для выводов о том, какие данные приложение оставляет и насколько они защищены.

## Шифрование и Keystore

Часть данных приложения зашифрована ключами Android Keystore (hardware-backed). Их нельзя прочитать, вытащив файл: ключ хранится в TEE и не экспортируется. Такие артефакты помечаем как «зашифровано, ключ недоступен». Это не упущение форензики, а корректная защита — важный вывод для отчёта. Попытка обхода требует эксплуатации TEE, что выходит за рамки типового пентеста.

## Цепочка сохранности и правовые аспекты

Каждое действие фиксируем: команда, время, хэш до/после. Копии храним с ограниченным доступом. Данные третьих лиц (переписка, фото) не анализируем вне задачи. По завершении удаляем копии. Это стандарт цифровой форензики и требование приватности.

## Типовые находки и их severity

Незащищённые токены в Preferences — High. Пароли в SQLite открытым текстом — High. Секреты в logcat — Medium. Cookies сессий — Medium/High. Кэш с ПДн — Medium. Каждая находка маппится на OWASP MASVS-STORAGE и подкрепляется цитатой из артефакта.

## Инструменты и автоматизация Android-форензики

Помимо ALEAPP, полезны `Autopsy`/`Sleuth Kit` для работы с образами и `Magnet AXIOM`/`Cellebrite` (коммерческие). Для быстрого разбора SQLite удобен `sqlitebrowser` или `sqlite3` из командной строки. Для WebView Cookies (`Cookies` в SQLite) есть `chrome-cookie-decrypt`-подобные утилиты. Для геолокаций — `MVT` (Mobile Verification Toolkit), который проверяет устройство/дамп на индикаторы компрометации.

Автоматизируйте сбор: скрипт, который копирует `/data/data/<pkg>`, системные базы, логи, считает хэши и складывает в структуру папок. Затем прогоняйте ALEAPP/MVT. Это экономит часы ручной работы и снижает риск пропустить артефакт.

## Проверка на индикаторы компрометации

MVT (Mobile Verification Toolkit) — важный инструмент для IR: он сверяет артефакты iOS/Android с индикаторами известных шпионских программ (Pegasus и др.). Для Android MVT работает с дампом/бэкапом, для iOS — с бэкапом. Это дополняет обычный форензик-анализ проверкой на заражение.

## Итог

Android-форензика — конвейер: извлечь копию, зафиксировать хэш, собрать артефакты, прогнать через ALEAPP/MVT, выписать находки. Для пентеста приложения фокус на песочнице (`/data/data/<pkg>`), для IR — на всём устройстве и индикаторах.

## Полный конвейер Android-форензики на практике

Разберём пошагово, как организовать извлечение и анализ с нуля, чтобы результат был воспроизводим и защищён.

Шаг 1. Идентификация. Зафиксируйте модель, версию Android, состояние root и блокировки. Проверьте `ro.boot.verifiedbootstate`, наличие `su`. От этого зависит метод извлечения: логический (ADB), файловая система (root), образ (разблокированный загрузчик + dd).

Шаг 2. Копирование. Не работайте с живой ФС. С root скопируйте `/data/data/<pkg>` и нужные системные пути (`/data/system/accounts.db`, `/data/misc/wifi`, `/data/system/usagestats`). Используйте `tar` с сохранением атрибутов. Считайте SHA-256 каждого архива. Логи (`logcat`, `/data/anr`) — отдельно.

Шаг 3. Артефакты. Разбирайте: SharedPreferences (XML, часто с токенами), SQLite (бизнес-данные, кэш), WebView Cookies, кэш API, внешнее хранилище `/sdcard/Android/data/<pkg>`. Grep по `eyJ` (JWT) и ключевым словам.

Шаг 4. Автоматизация. Прогоните архив через ALEAPP (`-t tar`) и MVT (проверка на компрометацию). Отчёт ALEAPP агрегирует десятки артефактов и строит временные линии.

Шаг 5. Шифрование. Отметьте данные, зашифрованные Keystore (ключ в TEE, недоступен). Это корректная защита, а не упущение.

Шаг 6. Отчёт. Для каждой находки — путь, тип данных, severity, рекомендация. Связывайте с OWASP MASVS-STORAGE.

## Инструменты

ALEAPP, MVT, Autopsy/SleuthKit, sqlitebrowser, iphone/aleapp-плагины. Для WebView Cookies — парсеры binarycookies. Для геолокаций — MVT/ileapp-модули.

## Правовые аспекты

Фиксируйте каждое действие (команда, время, хэш). Не анализируйте данные третьих лиц вне задачи. Удаляйте копии по завершении. Это стандарт и требование приватности.

## Квиз

```quiz
- question: "Что нужно сделать перед анализом данных для целостности?"
  options:
    - "Снять копию и зафиксировать хэш"
    - "Перезагрузить устройство"
    - "Удалить логи"
    - "Обновить приложение"
  answer: 0
- question: "Какой инструмент автоматически разбирает Android-дамп?"
  options:
    - "ALEAPP"
    - "iLEAPP"
    - "blutter"
    - "jadx"
  answer: 0
- question: "Где хранятся SharedPreferences приложения?"
  options:
    - "/data/data/<pkg>/shared_prefs"
    - "/sdcard/prefs"
    - "/system/etc"
    - "Keychain"
  answer: 0
- question: "Где искать cookies WebView?"
  options:
    - "/data/data/<pkg>/app_webview/Cookies"
    - "/data/data/<pkg>/shared_prefs"
    - "/sdcard/DCIM"
    - "/system/bin"
  answer: 0
- question: "Почему `adb backup` может быть пустым?"
  options:
    - "allowBackup=false"
    - "Нет интернета"
    - "Нет root"
    - "Устройство выключено"
  answer: 0
```

## Где пригодится

- **Форензика/IR:** стандартный конвейер извлечения.
- **Пентест:** поиск токенов/секретов.
- **Bug bounty:** остаточные данные приложения.
- **CTF:** Mobile-задачи с дампами.
