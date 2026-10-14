#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gB forensics gaps: macOS system family (hub + 5 lessons)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _fgaps_common import emit  # noqa: E402

HUBS = {}
LESSONS = {}

HUBS["forensics-macos-system"] = r'''---
id: forensics-macos-system
title: "Модуль: система macOS — Apple Silicon, память, бэкапы и защита"
category: forensics
parent: forensics-macos-artifacts
difficulty: hard
order: 3
tags: [macos, apple-silicon, memory, timemachine, xprotect, icloud, forensics, roadmap]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ macOS-хостов"
estimated_minutes: 13
summary: "Этап ветки «macOS»: чем отличается современный Mac — ARM-процессоры и унифицированная память, локальные снимки, встроенная защита и синхронизация iCloud."
---

Пользовательские артефакты мы разобрали. Теперь — системный уровень macOS: архитектура
Apple Silicon, особенности сбора памяти, снимки Time Machine и встроенная защита
(XProtect). Плюс облачная синхронизация iCloud, которая «уводит» данные с устройства.

## Что покрывает этот модуль

- **Apple Silicon** — ARM, Secure Enclave и что это значит для форензики.
- **Память macOS** — как снимать и что в ней искать.
- **Time Machine** — локальные снимки как источник удалённых версий.
- **XProtect** — встроенный антивирус и его журналы.
- **iCloud** — синхронизация и её следы.

## Рекомендуемый порядок изучения

1. `macos-apple-silicon` — понять архитектуру и её ограничения.
2. `macos-memory` — сбор и анализ памяти.
3. `macos-timemachine` — удалённые версии из снимков.
4. `macos-xprotect` — что обнаружила защита.
5. `macos-icloud` — синхронизация данных.

## Что вы будете уметь

- Учитывать особенности ARM/Secure Enclave при сборе.
- Снимать и анализировать память macOS.
- Доставать удалённые файлы из снимков Time Machine.
- Читать журналы XProtect.
- Оценивать, что ушло в iCloud.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| Secure Enclave | где ключи и защита | архитектура |
| `*.vmem` / `memory_pressure` | что было в памяти | osxpmem, Volatility |
| `/.MobileBackups`, APFS snapshots | удалённые версии | `tmutil` |
| `XProtect.log` | что нашла защита | `log show` |
| `~/Library/Mobile Documents` | что в iCloud | `brctl` |

## Куда дальше

Открывай урок **«Apple Silicon и Secure Enclave»** — начнём с того, чем
современный Mac отличается от Intel.
'''

LESSONS["macos-apple-silicon"] = dict(
parent="forensics-macos-system", order=1, diff="hard", mins=45,
title="Apple Silicon и Secure Enclave: что меняется для форензики",
tags="[macos, apple-silicon, arm, secure-enclave, forensics]",
prereq="[forensics-macos-artifacts]",
summary="Чем Apple Silicon отличается от Intel: ARM, унифицированная память, Secure Enclave и влияние на сбор и анализ данных.",
body=r'''
## Вопрос, с которого всё начинается

Старые инструкции по форензике macOS писались для Intel. На новых Mac — **Apple
Silicon** (M1/M2/M3), и многое изменилось: другая архитектура, другой способ защиты
ключей, даже память устроена иначе. Разберём, что именно.

## Наш пример: определяем платформу

## Шаг 1: архитектура

```
$ uname -m
arm64
```

`arm64` (он же `aarch64`) означает ARM-процессор. Это не просто «другая ISA»: у ARM
другая модель памяти и загрузки. Скомпилированные под x86 инструменты работают через
Rosetta 2 — и могут оставлять свои артефакты.

## Шаг 2: унифицированная память

На Apple Silicon память **общая** для CPU и GPU (UMA). Практическое следствие:
разделение «память CPU» и «видеопамять» исчезает. При сборе дампа это меняет то, что
вообще доступно.

```
$ system_profiler SPHardwareDataType | grep -E 'Chip|Memory'
      Chip: Apple M2
      Memory: 16 GB
```

## Шаг 3: Secure Enclave

**Secure Enclave** — отдельный защищённый сопроцессор. Он хранит ключи шифрования
диска, ключи Touch ID и ключи iCloud. Из него ключи **не извлекаются** обычными
методами.

```
$ system_profiler SPiBridgeDataType 2>/dev/null | head
```

Это значит: снять ключ шифрования диска напрямую нельзя. Приходится либо знать
пароль пользователя, либо использовать живую систему с разблокированным ключом.

## Шаг 4: что это меняет для сбора

- **Шифрование диска по умолчанию**: на Apple Silicon всё шифруется аппаратно.
- **Без разблокировки** прочитать диск нельзя даже с физическим доступом.
- **Загрузка только подписанного ПО** (Secure Boot) — сложнее загрузить внешний
  форензик-образ.
- **Память**: сбор возможен, но требует отключённого SIP или особых привилегий.

## Шаг 5: проверяем защиту

```
$ csrutil status
System Integrity Protection status: enabled.
$ nvram boot-args
(none)
```

`enabled` означает, что SIP защищает системные файлы. Для живой форензики часто
требуется временно отключить SIP — но это меняет состояние системы, поэтому фиксируй
это в отчёте.

## Что мы теперь знаем

- Apple Silicon = ARM (`arm64`), x86 через Rosetta 2.
- Унифицированная память меняет модель сбора.
- Secure Enclave хранит ключи и не отдаёт их наружу.
- Диск шифруется аппаратно; без разблокировки чтения нет.
- SIP и Secure Boot ограничивают живой сбор.

## Если не сработало

- Нужен диск без разблокировки? Только официальные средства Apple (не сработает).
- Нужна память? Отключи SIP в recovery-режиме и зафиксируй это.
- Нужны ключи iCloud? Только через аккаунт пользователя.

## Квиз

Проверь себя.

```quiz
- question: Какая архитектура у Apple Silicon?
  options:
    - 'x86_64'
    - 'arm64/aarch64'
    - 'mips'
    - 'riscv'
  answer: 1
  explanation: 'Чипы M-серии используют ARM64; x86 идёт через Rosetta 2.'
- question: Что такое Secure Enclave?
  options:
    - 'сетевой адаптер'
    - 'защищённый сопроцессор, хранящий ключи'
    - 'файловая система'
    - 'браузер'
  answer: 1
  explanation: 'Secure Enclave изолированно хранит ключи и не отдаёт их наружу.'
- question: Почему на Apple Silicon диск нельзя прочитать без разблокировки?
  options:
    - 'он медленный'
    - 'шифрование аппаратное, ключ в Secure Enclave'
    - 'нет драйверов'
    - 'диск только для чтения'
  answer: 1
  explanation: 'Ключ шифрования защищён Secure Enclave и недоступен извне.'
- question: Что проверяет csrutil status?
  options:
    - 'сеть'
    - 'System Integrity Protection'
    - 'батарею'
    - 'реестр'
  answer: 1
  explanation: 'SIP защищает системные файлы и процессы.'
```
''')

LESSONS["macos-memory"] = dict(
parent="forensics-macos-system", order=2, diff="hard", mins=50,
title="Сбор и анализ памяти macOS",
tags="[macos, memory, volatility, osxpmem, forensics]",
prereq="[forensics-macos-artifacts]",
summary="Как снимать память macOS (osxpmem, специальные средства), какие артефакты в ней искать и как их анализировать.",
body=r'''
## Вопрос, с которого всё начинается

Память — самый быстро исчезающий источник улик: пароли, ключи, расшифрованные данные,
следы вредоносного ПО. Но на macOS снять память сложнее, чем на Windows/Linux.
Разберёмся, как и что искать.

## Наш пример: сбор памяти

## Шаг 1: инструменты

Классический путь — **osxpmem** (Portable Memory):

```
$ sudo osxpmem -o /evidence/mac.raw
Acquiring memory...
```

Альтернативы: `AVML`, средства коммерческих платформ. На Apple Silicon вариантов
меньше — часть ограничена Secure Boot/SIP.

## Шаг 2: что сразу видно

Даже простой `strings`/`grep` по дампу даёт результаты:

```
$ strings mac.raw | grep -i 'http://' | head
http://203.0.113.5/upd.bin
```

Адрес C2, команды, URL — всё это живёт в памяти, даже если файлы на диске подчищены.

## Шаг 3: артефакты в памяти

- **процессы** и их командные строки;
- **открытые файлы и сокеты**;
- **пароли и ключи** (особенно в незашифрованном виде);
- **расшифрованные данные** из шифрованных томов;
- **код вредоносного ПО**, который был только в памяти (fileless).

## Шаг 4: анализ

Для macOS-дампов используют Volatility (профили macOS ограничены) и платформенные
парсеры. Базовый подход — извлечь строки, процессы и сетевые индикаторы:

```
$ strings mac.raw | grep -E 'POST /|Authorization:' | head
```

А ещё — `bstrings` для UTF-16 и поиск конкретных IOC.

## Шаг 5: фиксируй порядок

Сбор памяти меняет систему (запускает инструмент). Поэтому:

1. зафиксируй время и версию ОС;
2. снимай память **до** выключения;
3. считай хеш дампа сразу;
4. опиши, отключал ли SIP и почему.

## Что мы теперь знаем

- Память даёт пароли, ключи и fileless-код.
- `osxpmem`/`AVML` — средства сбора на macOS.
- `strings`/`grep` дают быстрые IOC.
- Volatility поддерживает macOS ограниченно.
- Сбор меняет систему — фиксируй это в отчёте.

## Если не сработало

- Apple Silicon ограничивает сбор? Используй живые средства и логи.
- Нет прав? Нужен root и отключённый SIP.
- Дамп огромный? Сначала `strings`, потом целевой анализ.

## Квиз

Проверь себя.

```quiz
- question: Чем ценна память для форензики?
  options:
    - 'она большая'
    - 'в ней пароли, ключи и fileless-код'
    - 'она на диске'
    - 'она шифрует'
  answer: 1
  explanation: 'Память хранит то, что не пишется на диск и исчезает при выключении.'
- question: Какой инструмент снимает память macOS?
  options:
    - 'ls'
    - 'osxpmem / AVML'
    - 'cp'
    - 'grep'
  answer: 1
  explanation: 'osxpmem и AVML — средства сбора дампа памяти.'
- question: Почему сбор памяти требует фиксации в отчёте?
  options:
    - 'он быстрый'
    - 'он меняет состояние системы'
    - 'он бесплатный'
    - 'он шифрует'
  answer: 1
  explanation: 'Запуск инструмента изменяет систему — это надо задокументировать.'
- question: Что делать в первую очередь с дампом?
  options:
    - 'удалить'
    - 'снять хеш и сделать strings/grep по IOC'
    - 'зашифровать'
    - 'сжать в zip'
  answer: 1
  explanation: 'Хеш доказывает неизменность, strings даёт быстрые зацепки.'
```
''')

LESSONS["macos-timemachine"] = dict(
parent="forensics-macos-system", order=3, diff="medium", mins=45,
title="Time Machine и локальные снимки APFS: удалённые версии файлов",
tags="[macos, timemachine, apfs, snapshots, recovery, forensics]",
prereq="[forensics-macos-artifacts]",
summary="Как использовать снимки Time Machine и APFS для восстановления удалённых или изменённых файлов и построения истории.",
body=r'''
## Вопрос, с которого всё начинается

Файл удалён, диск зашифрован, индексы подчищены. Но macOS **сама** хранит снимки:
локальные снимки APFS и бэкапы Time Machine. Из них можно достать версии файлов,
которых уже нет. Это один из самых недооценённых источников.

## Наш пример: локальный снимок

## Шаг 1: список локальных снимков

```
$ tmutil listlocalsnapshots /
com.apple.TimeMachine.2026-01-14-020000.local
com.apple.TimeMachine.2026-01-14-030000.local
```

Локальные снимки создаются ежечасно и хранят состояние диска. Их можно монтировать
только для чтения.

## Шаг 2: монтируем снимок

```
$ mkdir /tmp/snap
$ mount_apfs -s com.apple.TimeMachine.2026-01-14-030000.local / /tmp/snap
$ ls /tmp/snap/Users/user/Downloads/
payload.dmg
```

Мы видим файл `payload.dmg`, который в текущей системе, возможно, уже удалён. Снимок
зафиксировал состояние на 03:00.

## Шаг 3: сравниваем версии

```
$ diff /tmp/snap/Users/user/.bash_history ~/.bash_history
```

Разница покажет, что злоумышленник дописал (или удалил) после снимка. Это прямые улики.

## Шаг 4: внешний Time Machine

Если есть внешний диск:

```
$ tmutil listbackups
/Volumes/Backup/Backups.backupdb/mac/2026-01-14-030000
$ tmutil compare
```

Бэкапы хранят историю за недели. Из них восстанавливают и файлы, и целые системы.

## Шаг 5: что это даёт

- **удалённые файлы** — версии из снимка;
- **timestomping** — сравнение меток между снимками;
- **история правок** — что менялось между снимками;
- **доказательство** — снимок нельзя изменить задним числом.

## Что мы теперь знаем

- macOS хранит локальные снимки APFS ежечасно.
- `tmutil listlocalsnapshots` и `mount_apfs` дают доступ.
- Внешние бэкапы Time Machine хранят историю за недели.
- Сравнение версий ловит удаления и подделки.
- Снимки — доказательство, которое трудно подделать.

## Если не сработало

- Снимков нет? Проверь `tmutil listlocalsnapshots` по всем томам.
- Снимок повреждён? Пробуй соседние.
- Нужен бэкап с другого Mac? Смотри `Backups.backupdb`.

## Квиз

Проверь себя.

```quiz
- question: Как часто macOS создаёт локальные снимки APFS?
  options:
    - 'раз в год'
    - 'примерно ежечасно'
    - 'никогда'
    - 'раз в месяц'
  answer: 1
  explanation: 'Time Machine делает локальные снимки примерно каждый час.'
- question: Как смонтировать локальный снимок?
  options:
    - 'mount /dev/sda1'
    - 'mount_apfs -s <snapshot>'
    - 'cp'
    - 'grep'
  answer: 1
  explanation: 'mount_apfs -s монтирует снимок только для чтения.'
- question: Чем полезно сравнение снимков?
  options:
    - 'экономит место'
    - 'показывает удаления и подделки меток'
    - 'ускоряет систему'
    - 'шифрует диск'
  answer: 1
  explanation: 'Diff версий выявляет изменения между моментами снимков.'
- question: Какая команда перечисляет бэкапы Time Machine?
  options:
    - 'ls'
    - 'tmutil listbackups'
    - 'df'
    - 'stat'
  answer: 1
  explanation: 'tmutil управляет Time Machine и показывает список бэкапов.'
```
''')

LESSONS["macos-xprotect"] = dict(
parent="forensics-macos-system", order=4, diff="medium", mins=40,
title="XProtect: встроенная защита macOS и её журналы",
tags="[macos, xprotect, malware, gatekeeper, logs, forensics]",
prereq="[forensics-macos-artifacts]",
summary="Что такое XProtect и Gatekeeper, как читать их журналы и использовать версии сигнатур для оценки угроз.",
body=r'''
## Вопрос, с которого всё начинается

macOS не нуждается в стороннем антивирусе — у неё есть **XProtect** и **Gatekeeper**.
Они не только блокируют, но и **логируют**, что видели. Это готовый источник: что за
образцы приходили и были ли они распознаны.

## Наш пример: проверяем XProtect

## Шаг 1: версия сигнатур

```
$ system_profiler SPInstallHistoryDataType | grep -i xprotect | tail -2
      XProtectPlistConfigData: 2178
      XProtectRemediator: 138
```

Номер версии позволяет оценить, насколько свежа защита. Если он старый — система
могла пропустить свежий образец.

## Шаг 2: журналы обнаружений

```
$ log show --predicate 'process == "XProtect"' --last 1d | grep -i 'detected\|blocked'
2026-01-14 03:30:12 XProtect[300]: Detected malware: OSX.Suspicious.A
```

XProtect пишет в unified log. `Detected`/`Blocked` — конкретные срабатывания.

## Шаг 3: Gatekeeper

Gatekeeper проверяет подпись приложений:

```
$ log show --predicate 'process == "syspolicyd"' --last 1d | grep -i 'denied\|quarantine' | head
2026-01-14 03:30:05 syspolicyd: Denied launch of SuspiciousApp (unsigned)
```

`Denied launch` означает, что неподписанное приложение не запустили. Если пользователь
обошёл защиту (правый клик → Open), в логе будет запись о разрешении.

## Шаг 4: список известных вредоносов

XProtect хранит список в plist:

```
$ plutil -p /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist | head
```

Отсюда видно, какие семейства он знает. Если образец в списке — можно проверить,
почему он не был пойман (версия сигнатур).

## Шаг 5: что это даёт расследованию

- **факт присутствия** образца (детект);
- **время** контакта;
- **вердикт** защиты (блокирован/пропущен);
- **версия сигнатур** — контекст, почему пропустил.

## Что мы теперь знаем

- XProtect — встроенная сигнатурная защита; Gatekeeper — проверка подписи.
- Версии сигнатур видны через `system_profiler`.
- Обнаружения — в unified log (`XProtect`, `syspolicyd`).
- `Denied launch` = попытка запуска неподписанного приложения.
- Версия сигнатур объясняет пропуски.

## Если не сработало

- Логи ротированы? Проверь архив unified log.
- XProtect отключён? Это само по себе улика.
- Нужны детали образца? Ищи в карантине и кэше.

## Квиз

Проверь себя.

```quiz
- question: Что проверяет Gatekeeper?
  options:
    - 'сеть'
    - 'подпись приложений перед запуском'
    - 'батарею'
    - 'файлы на диске'
  answer: 1
  explanation: 'Gatekeeper не даёт запускать неподписанное/непроверенное ПО.'
- question: Где искать обнаружения XProtect?
  options:
    - 'в /etc/passwd'
    - 'в unified log'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'XProtect пишет детекты в unified log (log show).'
- question: Что означает Denied launch у syspolicyd?
  options:
    - 'приложение обновилось'
    - 'попытка запуска неподписанного приложения отклонена'
    - 'диск заполнен'
    - 'сеть упала'
  answer: 1
  explanation: 'syspolicyd блокирует запуск, не прошедший проверку подписи.'
- question: Зачем знать версию сигнатур XProtect?
  options:
    - 'для отчёта'
    - 'чтобы объяснить, почему образец не был пойман'
    - 'для ускорения'
    - 'для сети'
  answer: 1
  explanation: 'Старые сигнатуры пропускают свежие образцы — это контекст.'
```
''')

LESSONS["macos-icloud"] = dict(
parent="forensics-macos-system", order=5, diff="medium", mins=45,
title="iCloud-синхронизация: что уходит с устройства",
tags="[macos, icloud, sync, bird, cloud, forensics]",
prereq="[forensics-macos-artifacts]",
summary="Что синхронизирует iCloud, где лежат локальные следы (bird, Mobile Documents) и как оценить, какие данные ушли в облако.",
body=r'''
## Вопрос, с которого всё начинается

Файла на диске нет — возможно, он уже в iCloud. macOS синхронизирует документы, фото,
заметки, переписку. Для расследования это значит: часть данных **вне устройства**, но
локальные следы синхронизации остаются. Разберём их.

## Наш пример: iCloud Drive

## Шаг 1: где локальные данные

```
$ ls ~/Library/Mobile\ Documents/
com~apple~CloudDocs  com~apple~Notes  ...
```

Каталог `Mobile Documents` — локальное зеркало iCloud-контейнеров. Файлы могут быть
«выгружены» (только заглушка) или полными, в зависимости от статуса.

## Шаг 2: статус синхронизации

```
$ brctl status | head
iCloud Drive: enabled
```

`brctl` (bird control) управляет синхронизацией. Из его вывода видно, что включено,
что синхронизируется и есть ли ошибки.

## Шаг 3: журнал bird

Процесс синхронизации — `bird`. Он логирует:

```
$ log show --predicate 'process == "bird"' --last 1d | grep -i 'upload\|download' | head
2026-01-14 03:29:00 bird[400]: upload /Users/user/Documents/report.pdf
```

Отсюда видно, что и когда уходило в облако. Это критично: данные, ушедшие в iCloud,
находятся вне зоны вашего контроля.

## Шаг 4: заметки, фото, сообщения

Помимо файлов, iCloud синхронизирует:

- **Notes** (`~/Library/Group Containers/group.com.apple.notes/`);
- **Photos** (`~/Pictures/Photos Library.photoslibrary`);
- **Messages** (при включённом «Messages in iCloud»).

Локальные базы остаются, даже если контент выгружен.

## Шаг 5: оценка утечки

Ключевой вопрос расследования: ушли ли данные наружу? Проверяем:

```
$ brctl log --short | grep -i 'uploaded' | tail
```

И сопоставляем время загрузки с событиями инцидента. Файл, загруженный в iCloud за
минуту до удаления, — явный признак подготовки.

## Что мы теперь знаем

- `~/Library/Mobile Documents` — локальное зеркало iCloud.
- `brctl` управляет и показывает статус синхронизации.
- `bird` логирует загрузку/скачивание.
- Notes/Photos/Messages тоже синхронизируются.
- Загрузка перед удалением — признак эксфильтрации через облако.

## Если не сработало

- Данные выгружены? Заглушки сохраняют имена и метаданные.
- Нужно содержимое? Только через аккаунт Apple ID.
- Логи ротированы? Смотри архив unified log.

## Квиз

Проверь себя.

```quiz
- question: Где macOS хранит локальное зеркало iCloud?
  options:
    - 'в /etc'
    - 'в ~/Library/Mobile Documents'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'Mobile Documents содержит контейнеры iCloud-приложений.'
- question: Какой процесс отвечает за синхронизацию iCloud?
  options:
    - 'cron'
    - 'bird'
    - 'nginx'
    - 'sshd'
  answer: 1
  explanation: 'bird (brctl) управляет синхронизацией iCloud.'
- question: Что логирует bird?
  options:
    - 'пароли'
    - 'загрузку и скачивание файлов'
    - 'сетевые маршруты'
    - 'обои'
  answer: 1
  explanation: 'Журнал bird фиксирует upload/download операций.'
- question: Почему загрузка файла в iCloud перед удалением подозрительна?
  options:
    - 'это норма'
    - 'может быть эксфильтрацией данных в облако'
    - 'экономит место'
    - 'ускоряет систему'
  answer: 1
  explanation: 'Данные уходят с устройства и становятся недоступны локально.'
```
''')

emit(HUBS, LESSONS)
