---
id: mobile-data-leakage
title: "Утечки данных на устройстве: логи, буфер обмена, кэш и дампы памяти"
category: mobile
parent: mobile-api-security-deep
difficulty: medium
order: 2
tags: [mobile, leakage, logs, clipboard, memory, privacy]
prerequisites: [mobile-insecure-storage]
useful_for:
  - "Пентест: поиск утечек чувствительных данных"
  - "Bug bounty: утечка PII/токенов на устройстве"
estimated_minutes: 42
summary: "Где мобильное приложение светит чувствительные данные: logcat и консоль, буфер обмена, клавиатурный кэш, превью, дампы памяти, бэкапы и кэш — как искать и как доказывать утечку."
---

## Почему утечки на устройстве важны

Даже если API защищён, TLS пинится, а хранилище зашифровано, данные могут утекать «сбоку»: в логи, буфер обмена, клавиатурный кэш, превью, кэш сети, дамп памяти. Эти каналы не защищены моделью угроз приложения, потому что считаются «внутренними». Но на устройстве есть другие приложения (в том числе вредоносные), сборщики диагностики и сам пользователь. Для пентестера утечка PII/токена/пароля — самостоятельная находка.

## Логи (logcat / console)

Самая частая утечка — приложение логирует чувствительные данные. Проверка:

```bash
# весь лог по приложению
adb logcat | grep -i "com.example.app"
# фильтр по ключевым словам
adb logcat | grep -iE "token|password|authorization|bearer|otp|pin|cvv"
# сохранить и проанализировать
adb logcat -d > /tmp/logs.txt && wc -l /tmp/logs.txt
```

Опасные практики: `Log.d("token", token)`, `printStackTrace()`, логирование полного HTTP-ответа, `NSLog` в iOS. Проверьте, что приложение не логирует запросы/ответы целиком.

iOS:

```bash
xcrun simctl spawn booted log stream --predicate 'processImagePath CONTAINS "MyApp"'
```

## Буфер обмена

Приложение может класть в буфер обмена пароли, токены, номера карт. Другое приложение читает буфер. Проверка:

```bash
# Android: следить за изменениями буфера (root/эмулятор)
adb shell service call clipboard 1   # старый способ
# iOS: UIPasteboard
```

Frida-хук на запись в буфер (Android):

```javascript
Java.perform(function () {
  var CM = Java.use("android.content.ClipboardManager");
  CM.setPrimaryClip.implementation = function (clip) {
    console.log("[clipboard] " + clip.getText());
    return this.setPrimaryClip(clip);
  };
});
```

Если приложение копирует секрет в буфер без очистки — находка (данные доступны другим приложениям и синхронизируются через облако на некоторых устройствах).

## Клавиатурный кэш и автозаполнение

Пользовательский ввод в поля (пароли, PIN, номера карт) может попадать в кэш клавиатуры или в сервис автозаполнения, если поле не помечено как sensitive. Проверьте атрибуты полей:

```xml
<!-- Android: запрет автозаполнения и suggestion -->
<EditText android:importantForAutofill="no" android:inputType="textPassword" />
```

iOS: `textContentType = .oneTimeCode` для OTP и `isSecureTextEntry` для паролей. Если поле не помечено — данные могут попасть в облачную клавиатуру.

## Кэш сети и ресурсов

HTTP-клиенты кэшируют ответы на диск (OkHttp `Cache`, `NSURLCache`). Если в кэше лежат ответы с PII/токенами, они доступны после выхода из аккаунта. Проверка:

```bash
# Android: кэш OkHttp
adb shell run-as com.example.app ls cache/
adb shell run-as com.example.app ls cache/http_cache/
# iOS: Library/Caches
```

Также проверяйте:
- **`WebView` кэш** — страницы с токенами в URL.
- **`WKWebView` кэш** — `Library/Caches/WebKit`.
- **Скриншоты приложения** — системные снапшоты в `/data/system_ce/`.

## Дампы памяти и крэш-логи

Чувствительные данные живут в памяти: расшифрованные токены, пароли, ключи. При крэше приложение может записать дамп (или система — tombstone), и данные утекут.

```bash
# tombstone-дампы на устройстве (root)
adb shell ls /data/tombstones/
adb shell cat /data/tombstones/tombstone_00 | strings | grep -iE "token|password"
# краш-логи в каталоге приложения
adb shell run-as com.example.app ls files/
```

Если включён `android:debuggable` в релизе — дамп памяти делается тривиально (`adb shell am dumpheap`), и все секреты в heap доступны.

## Бэкапы

```bash
adb backup -f app.ab com.example.app
# распаковать (dd + zlib или abe)
java -jar abe.jar unpack app.ab app.tar
tar -tf app.tar
```

Если `android:allowBackup="true"` (по умолчанию) и приложение не исключило данные, секреты попадают в бэкап. Проверьте `backup_rules.xml`/`dataExtractionRules`.

## Превью и recents

Превью окна в списке недавних может показать чувствительный экран, если не стоит `FLAG_SECURE` (см. `mobile-screenshot-protection`). Проверка:

```bash
adb shell input keyevent KEYCODE_APP_SWITCH
adb shell screencap -p /sdcard/recents.png
```

## Инструментальные проверки

Комплексный проход:

```bash
# 1) логи
adb logcat -c && adb shell monkey -p com.example.app 200 && adb logcat -d | grep -iE "token|pass|secret"
# 2) файлы приложения
adb shell run-as com.example.app find . -type f -exec ls -la {} \;
# 3) бэкап
adb backup -f /tmp/app.ab com.example.app
# 4) буфер обмена (Frida)
# 5) память (если debuggable)
adb shell am dumpheap com.example.app /data/local/tmp/heap.hprof
adb pull /data/local/tmp/heap.hprof
strings heap.hprof | grep -iE "bearer|token"
```

## Частые ошибки и подводные камни

- **Логи очищаются** — снимайте сразу после действий (`adb logcat -c` перед).
- **`run-as` не работает на релизе** — нужен debuggable APK или root.
- **Буфер обмена пуст** — приложение очищает его; проверьте в момент действия.
- **Дамп heap недоступен** — не debug-сборка; используйте Frida или root.
- **Кэш зашифрован** — проверьте, не лежат ли ключи рядом.

## Справочная таблица

| Канал | Инструмент | Что искать |
|-------|-----------|-----------|
| Логи | `adb logcat` | токены, пароли, ответы API |
| Буфер обмена | Frida | секреты, PII |
| Кэш сети | `run-as ls cache` | ответы с PII |
| Память | `am dumpheap`, Frida | расшифрованные секреты |
| Бэкап | `adb backup` | файлы с секретами |
| Превью | `screencap` recents | чувствительные экраны |

## Что дальше / решение

Пройдите по всем каналам: логи, буфер, кэш, память, бэкап, превью. Каждая утечка токена/PII — находка с описанием канала и доказательством. Рекомендации: не логировать секреты, очищать буфер, исключать данные из бэкапа, ставить `FLAG_SECURE`, отключать debug в релизе. Дальше — `mobile-storage-deep` и `mobile-screenshot-protection`.

## Инструменты автоматизации поиска утечек

Ручной перебор каналов утомителен; полезно автоматизировать:

```bash
#!/usr/bin/env bash
PKG="$1"
echo "=== logs ==="
adb logcat -c; adb shell monkey -p "$PKG" 200 >/dev/null 2>&1
adb logcat -d | grep -iE "token|pass|secret|bearer|otp|pin|cvv" | head -50

echo "=== files ==="
adb shell run-as "$PKG" find . -type f 2>/dev/null | head -100

echo "=== shared_prefs ==="
adb shell run-as "$PKG" cat shared_prefs/*.xml 2>/dev/null | grep -iE "token|key|pass" | head

echo "=== backup ==="
adb backup -f /tmp/$PKG.ab "$PKG" 2>/dev/null
ls -la /tmp/$PKG.ab
```

Прогон после типового пользовательского сценария (логин, оплата, выход) покажет, что осталось в логах и файлах.

## Memory dump через Frida

Если приложение не debuggable, дамп памяти можно снять через Frida: ищем строки-секреты в памяти процесса.

```javascript
// поиск строк по паттерну в heap
var pattern = "Bearer ";
Process.enumerateRanges('r--').forEach(function (range) {
  try {
    Memory.scanSync(range.base, range.size, "42 65 61 72 65 72 20").forEach(function (m) {
      console.log("[mem] " + m.address + " " + m.address.readCString(80));
    });
  } catch (e) {}
});
```

Так можно найти токены, которые приложение держит в памяти, даже если они не пишутся на диск.

## Шифрование кэша и его границы

Некоторые приложения шифруют кэш/файлы, но ключ хранят рядом (в SharedPreferences или зашитым в APK). Проверьте:

```bash
adb shell run-as com.example.app cat shared_prefs/*.xml | grep -i "key\|iv\|salt"
```

Если ключ рядом с шифротекстом — шифрование бесполезно. Часто используется AES с ключом, выведенным из константы в APK, что делает расшифровку тривиальной (`grep -rn "AES\|SecretKeySpec" out/sources`).

## Приватность и регуляторные требования

Утечки PII — это не только техническая, но и регуляторная проблема (GDPR, 152-ФЗ). В отчёте разделяйте:
- **Security** — утечка токена/пароля даёт доступ к аккаунту.
- **Privacy** — утечка PII (телефон, адрес, номер карты) в логи/кэш.

Для privacy-находок опишите, какие данные, в каком канале и как долго доступны. Это повышает ценность отчёта для заказчика.

## Что фиксировать и как доказывать

Доказательство утечки должно быть воспроизводимым:
- точная команда/скрипт, которым вы получили данные;
- фрагмент вывода с секретом (замаскируйте реальные значения в публичном отчёте);
- шаги сценария, после которых данные появились;
- оценка влияния (что можно сделать с утёкшим значением).

Для логов удобно приложить `adb logcat` с таймстемпом; для файлов — `ls -la` и содержимое; для памяти — скриншот Frida-вывода.

## Приоритизация каналов утечки

Не все каналы равнозначны. Наибольший приоритет — логи и память: там чаще всего оказываются живые токены и пароли, которые сразу дают доступ. Буфер обмена и клавиатурный кэш важны для приватности (PII), но требуют присутствия вредоносного приложения. Кэш и бэкап опасны после выхода из аккаунта (данные остаются доступны). Начинайте с логов и памяти, затем файлы и бэкап, затем превью и буфер. Такой порядок по убыванию влияния позволяет быстро найти самое ценное и не тратить время на второстепенное, если бюджет ограничен.

## Квиз

```quiz
- question: "Какой канал чаще всего выдаёт токены при тесте приложения?"
  options:
    - "Логи (logcat/console)"
    - "Градиенты интерфейса"
    - "Шрифты"
    - "Анимации"
  answer: 0
- question: "Почему буфер обмена — риск утечки?"
  options:
    - "Его содержимое доступно другим приложениям и может синхронизироваться"
    - "Он шифрует данные"
    - "Он работает только на iOS"
    - "Он требует root"
  answer: 0
- question: "Что позволяет исключить данные приложения из adb backup?"
  options:
    - "android:allowBackup=false и правила backup_rules"
    - "Увеличение версии"
    - "Смена иконки"
    - "Отключение Wi-Fi"
  answer: 0
- question: "Где живут расшифрованные секреты во время работы приложения?"
  options:
    - "В памяти процесса (heap)"
    - "В градиентах"
    - "В шрифтах"
    - "В разрешении экрана"
  answer: 0
```

## Где пригодится

- **Пентест:** поиск утечек PII/токенов на устройстве.
- **Bug bounty:** доказательство утечки чувствительных данных.
- **Работа:** приватность и защита данных в мобильном приложении.
