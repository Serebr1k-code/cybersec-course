---
id: mobile-jailbreak-artifacts
title: "Артефакты джейлбрейка iOS: следы модификации системы"
category: forensics
parent: forensics-mobile-ios
difficulty: hard
order: 6
tags: [forensics, mobile, ios, jailbreak, cydia, sileo, substrate, forensics]
prerequisites: [forensics-mobile-ios]
useful_for:
  - "CTF Forensics категория"
  - "Mobile Forensics"
  - "DFIR / Incident Response"
estimated_minutes: 50
summary: "Как по образцу iPhone понять, что он был джейлбрейкнут: раздел rootfs на запись, менеджеры пакетов Cydia/Sileo, Substrate и tweaks, и какие следы остаются после снятия."
lab:
  kind: shell
  title: "Практика: следы джейлбрейка"
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md, jb_artifacts.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - 'Прочитай список артефактов: `cat jb_artifacts.txt`.'
    - 'Вспомни prerequisite forensics-mobile-ios: джейлбрейк меняет файловую систему.'
    - 'Найди менеджеры пакетов: `grep -iE "cydia|sileo|substrate" jb_artifacts.txt`.'
    - 'Собери метку: `grep nto jb_artifacts.txt > found.txt`.'
---

## Вопрос, с которого всё начинается

У тебя образ iPhone. Подозрение: устройство было **джейлбрейкнуто** — то есть с него
сняли защиту Apple, чтобы ставить неофициальные программы. Такое устройство могло
нести шпионский софт или быть инструментом для обхода ограничений. Как доказать
факт джейлбрейка по файлам, если его «убрали» перед изъятием?

Этот урок продолжает iOS-ветку. Мы уже умеем читать бэкап и понимаем защиту; теперь
ищем следы модификации системы.

## Наш пример: список артефактов из образа

Перед нами `jb_artifacts.txt` — выдержка путей и признаков, собранных из
файловой системы.

```
$ cat jb_artifacts.txt
/private/var/lib/dpkg/status            -> contains Package: mobilesubstrate
/private/var/jb/usr/bin/sileo           -> Sileo package manager present
/Applications/Cydia.app                 -> Cydia app bundle
/Library/MobileSubstrate/MobileSubstrate.dylib -> tweak injection
/private/etc/apt/sources.list.d/*.list  -> third-party repos
/private/var/mobile/Library/Preferences/com.saurik.Cydia.plist
note: jailbreak marker nto{1os_jb_substr4t3}
```

Разберём, что именно выдаёт джейлбрейк.

## Шаг 1: раздел rootfs становится записываемым

В обычном iOS системный раздел (`rootfs`) только для чтения и защищён подписью.
Джейлбрейк монтирует его на запись или создаёт «фейковый» корень (`/private/var/jb`)
через **rootless**-схему. Поэтому первый признак — наличие каталога `/private/var/jb`
и монтирования rootfs в режиме `rw`:

```
$ cat /proc/mounts | grep -E ' / | /private/var/jb '
/dev/disk1s1 / apfs ro
/dev/disk1s5 /private/var/jb apfs rw
```

Строка `ro` у `/` — норма; появление `rw` или отдельного `jb`-монтирования —
аномалия.

## Шаг 2: менеджеры пакетов

Джейлбрейк ставит пакетный менеджер: исторически **Cydia** (Saurik), современнее —
**Sileo** (rootless). Их наличие — прямой признак:

- `/Applications/Cydia.app` — бандл Cydia;
- `/private/var/jb/usr/bin/sileo` — бинарник Sileo;
- `/private/var/lib/dpkg/status` — база пакетов, где видно установленные твики.

В `dpkg/status` ищем пакет `mobilesubstrate` или `ellekit` — это «движки», которые
позволяют внедрять сторонний код в системные процессы.

## Шаг 3: Substrate / ElleKit и твики

**MobileSubstrate** (сейчас чаще **ElleKit**) — механизм инъекции, который
подгружает **твики** — сторонние модификации в процессы. Твики лежат в
`/Library/MobileSubstrate/DynamicLibraries/` (или `/private/var/jb/Library/...`).
Каждый твик — это `.dylib` плюс `.plist` с указанием, в какие процессы он
встраивается.

Для следователя твик — это потенциальный шпион: он может перехватывать ввод,
читать буфер обмена, скрывать своё присутствие.

## Шаг 4: следы после снятия джейлбрейка

Даже если джейлбрейк «сняли», остаются следы:

- пустые каталоги `/private/var/jb` или `/Library/MobileSubstrate`;
- записи в `dpkg/status` и `log`-файлах пакетов;
- сторонние репозитории в `/private/etc/apt/sources.list.d/`;
- plist-файлы настройки (`com.saurik.Cydia.plist`);
- несоответствие хешей системных бинарников эталону iOS.

Сверка хешей системных файлов с эталонным образом той же версии iOS — самый
надёжный способ: джейлбрейк меняет подписи и содержимое.

## Шаг 5: что это даёт следствию

Факт джейлбрейка меняет оценку:

- устройство могло исполнять неподписанный код;
- часть улик может быть **сфальсифицирована** твиками;
- на устройстве вероятны шпионские твики (кейлоггеры, перехват мессенджеров);
- целостность системы нарушена — нужна осторожность с выводами.

## Что мы теперь знаем

- Джейлбрейк делает rootfs записываемым или создаёт `/private/var/jb`.
- Менеджеры пакетов (Cydia/Sileo) и `dpkg/status` — прямые признаки.
- Substrate/ElleKit + твики — механизм внедрения стороннего кода.
- После снятия остаются каталоги, plist, репозитории и следы в логах.
- Сверка хешей с эталоном — надёжный способ подтвердить модификацию.

## Если не сработало

- Нет `/private/var/jb`? Ищи старые пути `/Library/MobileSubstrate`.
- Всё «чисто», но есть сомнения? Сверь хеши системных бинарников.
- Джейлбрейк был, но снят? Смотри plist и apt-репозитории.

## Квиз

Проверь себя.

```quiz
- question: Какой каталог создаёт современный rootless-джейлбрейк?
  options:
    - '/System'
    - '/private/var/jb'
    - '/Applications'
    - '/tmp'
  answer: 1
  explanation: 'Rootless-джейлбрейк использует /private/var/jb как корень.'
- question: Что такое MobileSubstrate/ElleKit?
  options:
    - 'браузер'
    - 'движок инъекции твиков'
    - 'пароль'
    - 'база данных'
  answer: 1
  explanation: 'Он подгружает сторонний код (твики) в процессы.'
- question: Где хранится список установленных пакетов?
  options:
    - 'Manifest.db'
    - '/private/var/lib/dpkg/status'
    - 'keychain-2.db'
    - 'Cache.sqlite'
  answer: 1
  explanation: 'dpkg/status — база пакетов джейлбрейка.'
- question: Какой надёжный способ подтвердить модификацию системы?
  options:
    - 'спросить пользователя'
    - 'сверить хеши системных бинарников с эталоном'
    - 'посмотреть обои'
    - 'запустить игру'
  answer: 1
  explanation: 'Хеши системных файлов отличаются от эталонного iOS.'
- question: Почему факт джейлбрейка важен для следствия?
  options:
    - 'это красиво'
    - 'на устройстве мог исполняться неподписанный/шпионский код'
    - 'ускоряет зарядку'
    - 'меняет цвет'
  answer: 1
  explanation: 'Твики могли перехватывать данные и фальсифицировать улики.'
```

## Куда дальше

Мы научились находить джейлбрейк. Дальше — мессенджеры: как извлекать сообщения
WhatsApp, Signal и Telegram из их баз. А пока запомни: `/private/var/jb`, Cydia/Sileo
и `dpkg/status` — три самых быстрых индикатора джейлбрейка.

## Где пригодится

- Mobile forensics: оценка доверия к данным с модифицированного iPhone.
- DFIR: поиск шпионских твиков и кейлоггеров на iOS.
- CTF Forensics: задания с артефактами джейлбрейка и `dpkg/status`.
