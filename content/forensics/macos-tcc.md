---
id: macos-tcc
title: 'TCC.db: база согласий приватности macOS'
category: forensics
parent: forensics-macos-deep
difficulty: medium
order: 2
tags: [macos, tcc, privacy, permissions, sqlite, full-disk-access, forensics]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'macOS forensics'
estimated_minutes: 50
summary: 'Как устроена база TCC (Transparency, Consent, Control): где лежат пользовательская и системная копии, какие services отслеживаются (камера, микрофон, экран, полный доступ к диску), и как по ней понять, что malware сам себе выписал разрешения.'
lab:
  kind: shell
  title: 'Практика: разбор TCC.db'
  toolset: [core, grep, hex]
  workdir: /home/student/task
  files: [task.md, TCC.db]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Начни с `ls -la TCC.db` и `file TCC.db`.'
    - 'TCC.db — SQLite с таблицей access (service, client, auth_value).'
    - 'Ищи сервисы вида kTCCService* через `strings TCC.db | grep -Ei "kTCCService|nto"`.'
    - 'Флаг лежит в текстовой метке: `strings TCC.db | grep nto > found.txt`.'
---

## Вопрос, с которого всё начинается

На Mac нашли подозрительное приложение. Вредоносное или нет? Один из самых показательных
артефактов — **база TCC**: она фиксирует, какие приложения получили доступ к камере,
микрофону, экрану и «полному доступу к диску». Если приложение само себе выписало доступ
к диску — это очень плохой знак.

## Что такое TCC

**TCC (Transparency, Consent, Control)** — механизм приватности macOS. Каждое приложение,
которому нужен чувствительный ресурс (камера, микрофон, геолокация, контакты, экран,
полный доступ к диску), должно получить **согласие пользователя**. Эти согласия хранятся
в базе:

- **`~/Library/Application Support/com.apple.TCC/TCC.db`** — пользовательская база;
- **`/Library/Application Support/com.apple.TCC/TCC.db`** — системная база (защищена SIP).

Формат — **SQLite**. Главная таблица — **`access`**, где каждая строка это одно согласие:

- **service** — какой ресурс (`kTCCServiceCamera`, `kTCCServiceMicrophone`,
  `kTCCServiceScreenCapture`, `kTCCServiceAccessibility`, `kTCCServiceSystemPolicyAllFiles`
  — это и есть Full Disk Access);
- **client** — идентификатор приложения (bundle id или путь);
- **auth_value** — разрешено/запрещено;
- **auth_reason** — почему (пользователь, политика, установщик);
- **last_modified** — когда.

## Наш пример: база согласий

```
$ ls -la
-rw-r--r-- 1 student student 24576 TCC.db
$ file TCC.db
TCC.db: SQLite 3.x database
```

Смотрим содержимое:

```
$ strings TCC.db | grep -Ei 'kTCCService|access|nto'
CREATE TABLE access (service TEXT, client TEXT, auth_value INTEGER)
kTCCServiceCamera
kTCCServiceMicrophone
kTCCServiceSystemPolicyAllFiles
EVIDENCE: nto{mac0s_tcc_fulld1sk4cc3ss}
```

Мы видим, что базе известны сервисы камеры, микрофона и **SystemPolicyAllFiles** (полный
доступ к диску). Последнее — самое опасное: оно позволяет читать все файлы пользователя.

## Шаг 1: почему TCC — цель malware

TCC стоит на страже приватности, и malware macOS регулярно пытается его обойти:

- **социальная инженерия** — уговорить пользователя выдать Full Disk Access;
- **подмена доверенного приложения** — вклиниться в подписанное приложение;
- **abuse accessibility** — получить доступ через Accessibility API (управление вводом);
- **установщики** — запросить права под видом обновления.

В базе это видно как **`auth_value` разрешено для подозрительного `client`**. Особенно
подозрительно, если клиент — не в `/Applications`, а во временном каталоге.

## Шаг 2: что смотреть в таблице

| Поле | Значение | На что обратить внимание |
|------|----------|--------------------------|
| service | ресурс | FullDiskAccess, ScreenCapture, Accessibility |
| client | приложение | путь/bundle id, временные каталоги |
| auth_value | разрешено/нет | разрешения у незнакомых клиентов |
| auth_reason | причина | «пользователь» vs «политика» |
| last_modified | когда | совпадение с временем инцидента |

Приём: сгруппируй разрешения по `client` — приложение с пачкой чувствительных сервисов
заслуживает внимания.

## Шаг 3: разбор через SQL

```
$ sqlite3 TCC.db 'SELECT service, client, auth_value FROM access;'
kTCCServiceCamera|com.apple.FaceTime|2
kTCCServiceSystemPolicyAllFiles|/tmp/helper|2
```

`auth_value = 2` обычно означает «разрешено». Клиент `/tmp/helper` с полным доступом к
диску — очевидная аномалия.

## Шаг 4: системная база и SIP

Системная `TCC.db` защищена **SIP (System Integrity Protection)**: её нельзя изменить даже
root-ом без отключения SIP. Поэтому malware чаще работает с **пользовательской** базой или
уговорами. При расследовании смотри обе базы, но помни о разнице прав.

Ещё нюанс: с некоторых версий macOS база **шифруется/защищена** и доступна только при
отключённом SIP или через специальные средства. Тогда анализируют **бэкапы** и **дампы
памяти**.

## Шаг 5: связка с другими артефактами

- **Keychain** — давал ли клиент доступ к секретам;
- **unified logs** — записи о выдаче/использовании разрешений;
- **quarantine** — откуда пришло приложение;
- **LaunchAgents** — закрепилось ли приложение как автозапуск.

Полный доступ к диску + автозапуск — почти наверняка недружественное ПО.

## Мини-практика: найти аномальное разрешение

```
$ sqlite3 TCC.db 'SELECT client, service FROM access WHERE auth_value=2;'
/Applications/Safari.app|kTCCServiceCamera
/tmp/helper|kTCCServiceSystemPolicyAllFiles
```

Второй клиент — из `/tmp`, с полным доступом к диску. Это готовый вывод для отчёта:
приложение, запущенное из временного каталога, получило максимальный доступ.

## Частые ошибки и подводные камни

- **Только пользовательская база.** Системная тоже важна (если доступна).
- **Путать auth_value.** Значения зависят от версии macOS; сверяйся со схемой.
- **Игнорировать клиентов из /tmp.** Это сильный признак malware.
- **Забыть про SIP.** Системную базу изменить нельзя без отключения защиты.
- **Не сопоставить время.** `last_modified` связывает разрешение с инцидентом.

## Что мы теперь знаем

- TCC.db — SQLite-база согласий приватности (пользовательская и системная).
- Таблица `access`: service/client/auth_value/auth_reason/last_modified.
- FullDiskAccess (SystemPolicyAllFiles) — самый опасный ресурс.
- Аномалия: незнакомый клиент из /tmp с широкими правами.
- Сопоставляй с Keychain, quarantine и автозапуском.

## Что фиксировать в отчёте

| Что | Зачем |
|-----|-------|
| Список разрешений по клиентам | аномалии |
| Путь/bundle id клиента | подлинность |
| FullDiskAccess у несистемных | признак malware |
| last_modified | хронология |
| Связка с другими артефактами | подтверждение |

## Расширенный пример: malware и обход TCC

Разберём, как вредоносное ПО обходит TCC и как это выглядит в базе. Классическая схема:
пользователю показывают «обновление» или «полезную утилиту», которая просит доступ к
«полному диску» (SystemPolicyAllFiles). Если пользователь соглашается, malware получает
чтение всех файлов.

В базе это выглядит так:

```
access|kTCCServiceSystemPolicyAllFiles|/Users/alice/Downloads/Update.app|2|1
```

`auth_value = 2` (разрешено), `auth_reason = 1` (пользователь). Клиент — приложение в
`Downloads`, что уже подозрительно: системные разрешения обычно не нужны загрузкам.

Другой вектор — **Accessibility API**: приложение с `kTCCServiceAccessibility` может
управлять вводом (нажимать кнопки за пользователя) и обходить другие защиты. Ещё один —
**подмена подписанного приложения**: malware встраивается в доверенное ПО, которому доступ
уже выдан.

Признаки компрометации в TCC:

- незнакомый `client` (путь вне `/Applications`);
- несовпадение `client` и ожидаемого bundle id;
- разрешения, выданные **в момент инцидента** (`last_modified`);
- пачка чувствительных сервисов у одного клиента.

## Схема базы и типовые значения

Таблица `access` в разных версиях macOS менялась, но ключевые колонки устойчивы:

| Колонка | Значение |
|---------|----------|
| service | идентификатор ресурса (`kTCCService*`) |
| client | bundle id или путь приложения |
| client_type | 0 — bundle id, 1 — абсолютный путь |
| auth_value | 0 запрещено, 2 разрешено (зависит от версии) |
| auth_reason | 1 — пользователь, 4 — политика/система |
| last_modified | время изменения записи |

Чувствительные сервисы, которые чаще всего интересуют: `SystemPolicyAllFiles`,
`SystemPolicyDesktopFolder`, `SystemPolicyDocumentsFolder`, `Camera`, `Microphone`,
`ScreenCapture`, `Accessibility`, `ListenEvent`, `SystemPolicyNetworkVolumes`.

При разборе группируй по `client` и смотри на **совокупность**: клиент с доступом к камере,
микрофону и диску одновременно — почти наверняка недружественный. В отчёте фиксируй путь
клиента и время выдачи, чтобы связать с инцидентом.

## Чек-лист разбора TCC

1. Найди **обе** базы: пользовательскую и системную.
2. Открой `access` через SQLite и перечисли `service`/`client`.
3. Сгруппируй разрешения **по клиенту** — увидишь приложения с широким доступом.
4. Отметь клиентов **вне /Applications** (особенно `/tmp`, `/Users/.../Downloads`).
5. Сверь `last_modified` с временем инцидента.
6. Сопоставь с quarantine, LaunchAgents и unified logs.

## Ограничения и что делать, если база недоступна

На новых версиях macOS пользовательская TCC.db может быть **защищена** и недоступна даже
для чтения без специальных прав. Тогда работают обходные пути:

- **бэкапы** (Time Machine) — там база может лежать в открытом виде;
- **полное извлечение** с отключённым SIP (в лабораторных условиях);
- **unified logs** — события выдачи разрешений дублируются в журнале;
- **системная база** — если доступна, показывает системные разрешения.

Даже без полного доступа к базе выводы можно сделать по журналам: событие TCC в unified
log фиксирует факт выдачи. Это ещё раз показывает ценность **комбинации артефактов** —
когда один недоступен, работает другой.

## Квиз

Проверь себя.

```quiz
- question: "Что такое TCC в macOS?"
  options:
    - "Файловая система"
    - "Механизм приватности и согласий на доступ к ресурсам"
    - "Антивирус"
    - "Резервное копирование"
  answer: 1
  explanation: "TCC (Transparency, Consent, Control) управляет разрешениями приложений."
- question: "Какой service соответствует полному доступу к диску?"
  options:
    - "kTCCServiceCamera"
    - "kTCCServiceSystemPolicyAllFiles"
    - "kTCCServiceMicrophone"
    - "kTCCServiceContacts"
  answer: 1
  explanation: "Full Disk Access — это kTCCServiceSystemPolicyAllFiles."
- question: "Что подозрительно в записи TCC для клиента из /tmp?"
  options:
    - "Ничего"
    - "Приложение из временного каталога получило чувствительные разрешения"
    - "Слишком маленький размер"
    - "Неверный часовой пояс"
  answer: 1
  explanation: "Клиент из /tmp с широкими правами — типичный признак вредоносного ПО."
- question: "Чем защищена системная TCC.db?"
  options:
    - "Паролем"
    - "SIP (System Integrity Protection)"
    - "EFS"
    - "BitLocker"
  answer: 1
  explanation: "Системная TCC.db защищена SIP; её нельзя изменить даже root-ом без отключения защиты."
```

## Куда дальше

Мы разобрали TCC. Дальше возьмём **unified logs** — бинарный журнал macOS, где видно
подробную хронологию событий. А пока главное запомни: **разрешения TCC — это карта того,
что приложению позволили, и аномалии там бросаются в глаза**.

## Где пригодится

- **CTF Forensics:** образы macOS с анализом приватности.
- **DFIR:** обнаружение malware, получившего доступ.
- **macOS forensics:** аудит разрешений.
- **Threat hunting:** поиск аномальных клиентов TCC.
