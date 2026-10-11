---
id: mobile-banking-trojan
title: "Анализ банковских троянов Android"
category: mobile
parent: mobile-emerging
difficulty: expert
order: 3
tags: [malware, banking-trojan, overlay, accessibility, c2, cerberus, anatsa, analysis, android]
prerequisites: [mobile-malware, mobile-dynamic-frida]
useful_for:
  - "Анализ малвари"
  - "Реагирование на инциденты"
  - "Threat intelligence"
estimated_minutes: 50
summary: "Анализ банковских троянов Android: механики (overlay, accessibility, SMS-перехват, C2), статический и динамический разбор, извлечение индикаторов."
---
## Введение

Банковские трояны (banking trojans) — доминирующий класс мобильной малвари: Cerberus, Anatsa, Hook, Ermac, Xenomorph. Они крадут деньги и данные через overlay поверх банковских приложений, злоупотребление accessibility-service, перехват SMS/уведомлений, скрытый удалённый доступ (VNC) и C2. Этот урок — практический разбор: как распознать троян, какие механики искать, как извлечь индикаторы (IOC). Продолжает `mobile-malware`.

Безопасность: анализируйте только в изолированной среде (эмулятор/отдельное устройство без реальных аккаунтов, без SIM). Никогда не запускайте образец на рабочем телефоне.

## Признаки банковского трояна

| Признак | Где смотреть |
|---------|--------------|
| accessibility-service | манифест, `BIND_ACCESSIBILITY_SERVICE` |
| overlay / `SYSTEM_ALERT_WINDOW` | манифест, `TYPE_APPLICATION_OVERLAY` |
| список банковских пакетов | строки/ресурсы (target list) |
| SMS-перехват | `RECEIVE_SMS`, `READ_SMS` |
| скрытая иконка | `activity-alias`, отсутствие launcher |
| C2-URL | строки/сеть |
| анти-анализ | emulator/root/Frida-детект |
| Play Integrity обход | цепочки, PIF-подобное |

## Статический анализ

```bash
# манифест: разрешения и сервисы
apktool d sample.apk -o sample
grep -nE 'permission|BIND_ACCESSIBILITY|SYSTEM_ALERT|service|receiver' sample/AndroidManifest.xml
# строки: банки, C2, ключи
strings sample.apk | grep -iE 'bank|sber|tinkoff|https?://|token|bot' | head
# список целевых пакетов часто в ресурсах/строках
grep -rIoE 'com\.[a-z0-9_.]+' sample/res/ 2>/dev/null | sort -u | head -40
# IOC-сканирование
yara -r rules/banking_trojan.yar sample/ 2>/dev/null
```

## Динамический анализ

```bash
# запуск на изолированном эмуляторе с сетевым перехватом
mitmproxy --mode transparent -p 8080
adb install sample.apk
# логируем поведение
adb logcat | grep -iE 'accessibility|overlay|sms|c2|http'
# Frida: перехват ключевых API
```

Frida-скрипт для логирования overlay и SMS:

```javascript
Java.perform(function() {
  var WM = Java.use("android.view.WindowManager");
  WM.addView.implementation = function(v, p) {
    console.log("[overlay] addView flags=" + p.flags);
    return this.addView(v, p);
  };
  var SMS = Java.use("android.telephony.SmsManager");
  SMS.sendTextMessage.implementation = function(dst, sc, text, a, b) {
    console.log("[sms] to=" + dst + " text=" + text);
    return this.sendTextMessage(dst, sc, text, a, b);
  };
});
```

## Полный сквозной пример: разбор Anatsa-подобного образца

```bash
# 1. Статика
apktool d sample.apk -o s
grep -c 'BIND_ACCESSIBILITY_SERVICE' s/AndroidManifest.xml       # accessibility
grep -rIoE 'https?://[a-z0-9./_-]+' s/ | sort -u | head          # C2-кандидаты
strings s/classes*.dex | grep -iE 'sber|tinkoff|revolut|bank' | head   # target list
# 2. Динамика
mitmproxy --mode transparent -p 8080 &
adb install sample.apk
adb shell monkey -p com.evil.bank -c android.intent.category.LAUNCHER 1
adb logcat -d | grep -iE 'c2|beacon|panel|register' | head
# 3. IOC
#    - домены C2, User-Agent, пути (/gate, /panel)
#    - целевые пакеты банков
#    - accessibility-конфиг
```

Результат: набор IOC (домены, пути, пакеты-цели, разрешения) и понимание механик.

## Извлечение индикаторов (IOC)

- **Сетевые**: C2-домены/IP, URL-пути, User-Agent, сертификаты.
- **Хостовые**: разрешения, accessibility-конфиг, скрытые activity, имена пакетов.
- **Поведенческие**: overlay поверх банков, перехват SMS, скрытая иконка.
- **Крипто**: ключи шифрования C2-трафика.

Формат — STIX/YARA для обмена с TI-платформами.

## Частые ошибки

- **Запускать образец на реальном устройстве**: риск потери денег/данных.
- **Игнорировать accessibility**: это ядро современных троянов.
- **Не изолировать сеть**: C2 может навредить.
- **Пропустить обфускацию**: строки шифрованы — нужен динамический дамп.
- **Не фиксировать IOC**: без них анализ бесполезен для защиты.
- **Забыть про anti-analysis**: троян детектит эмулятор/Frida — обходите.

## Что дальше / решение

Комбинируйте статику (манифест, строки, YARA) и динамику (Frida, mitmproxy) в изолированной среде. Свяжите с `mobile-malware` (общий анализ), `mobile-emulator-detection` (обход детекта), `mobile-task-hijacking`/`mobile-tapjacking` (overlay). Рекомендация: эмулятор без аккаунтов + mitmproxy + Frida.

## Справочная таблица

| Механика | Индикатор |
|----------|-----------|
| Overlay | SYSTEM_ALERT_WINDOW, addView |
| Accessibility | BIND_ACCESSIBILITY_SERVICE |
| SMS-перехват | RECEIVE_SMS/READ_SMS |
| Скрытая иконка | activity-alias |
| C2 | домены/пути в трафике |

| Инструмент | Роль |
|-----------|------|
| apktool/jadx | статика |
| Frida | динамика/хуки |
| mitmproxy | C2-трафик |
| YARA | сигнатуры |

## Сквозной кейс: разбор образца от манифеста до IOC

Разберём анализ банковского трояна пошагово, с акцентом на практические выводы.

Начинаем со статики манифеста. Первым делом смотрим разрешения: `BIND_ACCESSIBILITY_SERVICE` (ядро современных троянов — даёт чтение экрана и нажатия), `SYSTEM_ALERT_WINDOW` (overlay поверх банковских приложений), `RECEIVE_SMS`/`READ_SMS` (перехват OTP), `REQUEST_INSTALL_PACKAGES` (установка дропперов), `FOREGROUND_SERVICE`. Набор этих разрешений в сочетании — сильный признак трояна. Далее ищем сервисы: accessibility-service объявляется в манифесте с meta-data и `android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"`.

Смотрим список целевых банков. Он часто хранится в ресурсах или строках: массив `com.sberbank...`, `com.revolut...`. Извлекаем через `grep -oE 'com\.[a-z0-9_.]+'` по ресурсам и строкам. Это даёт список банков-целей — ценный IOC.

Ищем C2. Домены и пути часто в строках, но могут быть зашифрованы. Прогоняем `strings` и YARA-правила. Если строки зашифрованы, переходим к динамике: запускаем в изолированной среде с mitmproxy и наблюдаем регистрацию на C2, пути `/gate`, `/panel`, User-Agent.

Динамика: под Frida логируем `WindowManager.addView` (overlay), `SmsManager.sendTextMessage`, работу accessibility. Фиксируем, как троян реагирует на запуск банковского приложения — показывает overlay с фейковым логином. Собираем IOC: домены, пути, пакеты-цели, конфиг accessibility, хэши.

## Обход анти-анализа трояна

Трояны детектят эмулятор, root, Frida. Проверки: `Build.FINGERPRINT`, `ro.kernel.qemu`, порты Frida, `ptrace`, карта памяти. Обход — комбинированный скрипт (см. `mobile-emulator-detection`). Если троян проверяет сенсоры, используйте реальное устройство. Часто образец отказывается работать в песочнице — это ожидаемо и не должно останавливать анализ: статики достаточно для IOC.

## Шифрование C2 и строк

Продвинутые трояны шифруют C2-трафик и строки. Стратегия: найти функцию-декриптор (часто XOR/AES с зашитым ключом) и дампнуть расшифрованные строки в рантайме. Хукаем функцию-декриптор, логируем возвращаемые значения. Так восстанавливается список банков, C2, команды.

## Формирование IOC

Сетевые: домены/IP C2, URL-пути, User-Agent, сертификаты. Хостовые: разрешения, accessibility-конфиг, имена пакетов, скрытые activity. Поведенческие: overlay, перехват SMS, скрытая иконка. Крипто: ключи. Формат — STIX/YARA для обмена с TI.

## Чек-лист анализа

Зафиксировать хэш образца, изолировать среду, разобрать манифест, найти целевые банки, найти C2, запустить под Frida, собрать IOC, оформить отчёт. Не запускать на реальном устройстве, не подключать реальные аккаунты, не давать сети выходить за пределы контроля.

## Рекомендации в отчёте

Для защиты: не выдавать accessibility-разрешения подозрительным приложениям, использовать Play Protect, обновлять устройство, не ставить APK из неизвестных источников, включать 2FA на банковских операциях. Для разработчиков банков: защита от overlay, проверка accessibility, аттестация устройства, серверная проверка операций.

## Автоматизация извлечения IOC

Для больших образцов ручной разбор медленный. Соберите скрипт: распаковка APK, извлечение строк, фильтрация URL/доменов/пакетов по паттернам, прогон YARA. Пример пайплайна: `apktool d` → `strings` → grep по `https?://`, `com\.[a-z0-9_.]+`, `AIza` → сортировка уникальных → YARA. Это даёт черновой набор IOC за минуты, который затем уточняется динамикой.

Для сетевых IOC запускайте образец в изолированной среде с mitmproxy и логируйте все запросы. Домены C2, пути, User-Agent, сертификаты — всё фиксируется автоматически. Сопоставляйте статические строки с динамическими запросами: так отсеиваются ложные.

## TI-обмен

Оформляйте IOC в STIX/OpenIOC или простой JSON/CSV для загрузки в TI-платформу (MISP). YARA-правила — для детекта на хостах. Для сетевого детекта — Suricata/Snort-правила по доменам и User-Agent.

## Итог

Анализ банковского трояна — комбинация статики (манифест, строки, YARA) и динамики (Frida, mitmproxy) в изоляции, с обязательным сбором IOC. Цель — не только понять механики, но и дать защите конкретные индикаторы и рекомендации.

## Практикум: извлечение IOC из образца

Разберём конкретный конвейер извлечения индикаторов.

Шаг 1. Хэшируем образец (`sha256sum`) и фиксируем метаданные (размер, имя, источник).

Шаг 2. Распаковываем (`apktool d`) и читаем манифест. Выписываем разрешения (`BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`, `RECEIVE_SMS`, `REQUEST_INSTALL_PACKAGES`) — это поведенческие индикаторы. Ищем сервисы и receivers.

Шаг 3. Извлекаем строки (`strings classes*.dex`, `strings resources.arsc`). Грепаем по URL, доменам, ключевым словам банков, путям C2 (`/gate`, `/panel`, `/register`). Дедуплицируем.

Шаг 4. Прогоняем YARA-правила. Пишем/используем правила для банковских троянов (например, комбинация разрешений + строк банков).

Шаг 5. Динамика. В изолированной среде запускаем под mitmproxy, логируем C2-запросы, под Frida — overlay/SMS. Сопоставляем статику и динамику.

Шаг 6. Оформляем IOC: сетевые (домены, пути, UA), хостовые (разрешения, пакеты-цели, accessibility-конфиг), крипто (ключи). Формат — STIX/YARA.

## Что важно

Не запускать на реальном устройстве, изолировать сеть, фиксировать всё. IOC без контекста бесполезны — добавляйте описание поведения. Комбинируйте статику и динамику: строки могут быть зашифрованы, тогда динамика даёт C2.

## Квиз

```quiz
- question: "Какая механика — ядро современных банковских троянов?"
  options:
    - "Злоупотребление accessibility-service и overlay"
    - "Только SQL-инъекции"
    - "Только brute force"
    - "Только phishing-email"
  answer: 0
- question: "Какое разрешение нужно для overlay поверх банковских приложений?"
  options:
    - "SYSTEM_ALERT_WINDOW"
    - "INTERNET"
    - "CAMERA"
    - "BLUETOOTH"
  answer: 0
- question: "Где безопасно анализировать образец?"
  options:
    - "В изолированном эмуляторе без реальных аккаунтов"
    - "На рабочем телефоне"
    - "На личном ноутбуке с токенами"
    - "На прод-сервере"
  answer: 0
- question: "Что такое IOC?"
  options:
    - "Индикаторы компромисса (домены, пакеты, поведение)"
    - "Формат APK"
    - "Протокол сети"
    - "Тип сертификата"
  answer: 0
- question: "Каким инструментом перехватывают C2-трафик?"
  options:
    - "mitmproxy/Wireshark"
    - "apktool"
    - "jadx"
    - "nmap"
  answer: 0
```

## Где пригодится

- **Анализ малвари:** основной класс мобильных угроз.
- **IR:** распознавание и реагирование.
- **Threat intelligence:** извлечение IOC.
- **CTF:** Mobile-задачи с малварью.
