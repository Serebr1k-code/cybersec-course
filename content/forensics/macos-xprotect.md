---
id: macos-xprotect
title: 'XProtect: встроенная защита macOS и её журналы'
category: forensics
parent: forensics-macos-system
difficulty: medium
order: 4
tags: [macos, xprotect, malware, gatekeeper, logs, forensics]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Что такое XProtect и Gatekeeper, как читать их журналы и использовать версии сигнатур для оценки угроз.'
lab:
  kind: shell
  title: 'Практика: XProtect'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

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

## Что именно защищает XProtect

XProtect — это **сигнатурный антивирус** Apple, встроенный в систему. У него несколько
компонентов:

- **XProtect.plist** — правила по хешам и путям известных вредоносов;
- **XProtect.yara** — YARA-правила для более гибкого поиска;
- **XProtect Remediator (XPR)** — современный сканер-«лечильщик», пришедший на смену MRT.

```
$ ls /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/
XProtect.plist  XProtect.yara  ...
$ plutil -p XProtect.plist | head
```

Файл `XProtect.plist` содержит список правил: имя малвари и её признаки (часто хеши, иногда
regex по содержимому). Обновления приходят отдельно от системы, поэтому версия правил —
важный факт для расследования.

## Версии сигнатур и обновления

Версия XProtect показывается через `system_profiler` и в системных настройках:

```
$ system_profiler SPInstallHistoryDataType | grep -A4 XProtect
$ defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString
2178
```

Если сигнатуры старые (например, 2150 при актуальной 2178), это объясняет, почему образец не
был пойман. В отчёте указывай версию на момент инцидента — иначе вывод «антивирус не
сработал» без контекста бессмыслен.

## Журналы обнаружений

XProtect пишет в системный лог через `log`. Ищем события сканирования и блокировок:

```
$ log show --predicate 'process == "XProtect" OR process == "XProtect Remediator"' --last 24h --style compact | tail -30
... XProtect ... detected malware: OSX.Example.A ...
... XProtectRemediator ... scan complete, 1 detection ...
```

Записи содержат путь до файла и имя правила. Это позволяет понять, что именно было
заблокировано и когда — даже если файл уже удалён. Сопоставь время с другими артефактами.

## Gatekeeper: что он делает

Gatekeeper — это проверка при **первом запуске** приложения, а не постоянное сканирование.
Он сверяет подпись и нотаризацию. Управляется через `spctl`:

```
$ spctl --status
assessments enabled
$ spctl -a -vv /Applications/Some.app
/Applications/Some.app: accepted
source=Notarized Developer ID
```

Если приложение запускается, обойдя Gatekeeper (например, правый клик → «Открыть»), система
запоминает это решение. Такие «одобренные вручную» приложения — важный артефакт: они
показывают, что пользователь сознательно разрешил подозрительный запуск.

## Карантин и его связь

Когда файл приходит из интернета, macOS ставит метку `com.apple.quarantine`. Gatekeeper и
XProtect используют её при проверке. Проверяем:

```
$ xattr -p com.apple.quarantine /Applications/Some.app
0083;65a1b2c3;Chrome;1B2C...
$ spctl -a -t open --context context:primary-signature /Applications/Some.app
```

Сочетание метки карантина (откуда скачано) и результата `spctl` (подписано ли) даёт полную
картину: файл пришёл из интернета и **не** имеет валидной подписи — типичный сценарий
заражения.

## Таблица: компоненты защиты macOS

| Компонент | Роль | Где смотреть |
|---|---|---|
| XProtect | сигнатурный AV | `log show`, XProtect.bundle |
| XProtect Remediator | активный сканер | `log show`, периодические прогоны |
| Gatekeeper | проверка запуска | `spctl`, логи `syspolicyd` |
| Notarization | облачная проверка Apple | результат `spctl` |
| Quarantine | метка источника | `xattr` |
| TCC | контроль доступа | база `TCC.db` |
| SIP | целостность системы | `csrutil status` |

`csrutil status` показывает, включён ли SIP. Если атакующий его отключил — это серьёзный
признак компромисса на уровне системы.

## Ограничения

Во-первых, XProtect **реактивен**: он ловит только известное. Новый образец (zero-day)
пройдёт мимо. Во-вторых, правила обновляются, но **не мгновенно**, и в момент атаки версия
могла быть устаревшей. В-третьих, логи `log show` имеют ограниченный срок хранения —
старые события недоступны. В-четвёртых, XProtect Remediator работает **периодически**, а не
постоянно, поэтому между заражением и обнаружением есть окно. И помни: отсутствие
обнаружений — не доказательство отсутствия малвари.

## Если сработало: что фиксировать

Запиши: версию сигнатур на момент инцидента, имя сработавшего правила, путь файла и время.
Если XProtect **не** сработал, зафиксируй это как отдельный факт с указанием версии — это
часть оценки защищённости, а не пробел в расследовании.

## XProtect Remediator: как он работает

XProtect Remediator (внутреннее имя `XProtectRemediator*`) запускается системой **периодически**
(обычно раз в сутки и при пробуждении) и сканирует ключевые каталоги: `/Applications`, `/tmp`,
`~/Library`, автозагрузку. В отличие от XProtect (пассивная проверка при запуске), Remediator
**активно ищет и удаляет** малварь.

```
$ log show --predicate 'process CONTAINS "XProtectRemediator"' --last 24h --style compact | head
... XProtectRemediatorShell ... scanning ...
... XProtectRemediatorShell ... completed, no detections ...
```

Имена модулей намекают на семейства (`Shell`, `SnowDrift`, `Adload`). Если в логах есть
`remediated` или `removed` — малварь была найдена и удалена; тогда оригинального файла на
диске уже не будет, и единственная улика — **запись в логе**.

## Восстановление после «лечения»

Когда Remediator удалил образец, расследование опирается на:

- **лог-запись** с именем правила и путём;
- **карантинные копии**, если они остались;
- **временные метки** создания/изменения удалённого файла (иногда сохраняются);
- **другие артефакты** (запуски, сеть, автозагрузка), которые не были удалены.

```
$ ls -la /var/folders/*/*/T/ 2>/dev/null | grep -i quarantine
```

Иногда «вылеченный» файл перемещается в защищённый каталог, а не стирается полностью — стоит
проверить.

## Логи syspolicyd и Gatekeeper

Решения Gatekeeper пишет демон `syspolicyd`. Его логи показывают, **что** пользователь
разрешил запустить вручную:

```
$ log show --predicate 'process == "syspolicyd"' --last 2h | grep -i 'allow\|reject' | head
... syspolicyd ... GK evaluate: /Applications/Some.app -> allow (user override)
```

Пометка `user override` — прямое указание, что пользователь обошёл защиту. Это ключевой факт
при разборе фишинговой атаки: файл не прошёл проверку, но был запущен вручную.

## Проверка целостности системы

Компромисс часто включает отключение защит. Проверяем их состояние:

```
$ csrutil status            # SIP
$ spctl --status            # Gatekeeper
$ sudo nvram boot-args      # не отключены ли защиты при загрузке
```

Если SIP отключён или `boot-args` содержат `amfi_get_out_of_my_way=1`, значит атакующий
понизил защиту — это уже не «пользователь запустил файл», а **системный компромисс**.

## Таблица: где искать следы защит

| След | Команда | Что показывает |
|---|---|---|
| Детект XProtect | `log show --predicate 'process=="XProtect"'` | что заблокировано |
| Прогон Remediator | `log show ... XProtectRemediator` | что удалено |
| Решение Gatekeeper | `log show ... syspolicyd` | ручной обход |
| Состояние SIP | `csrutil status` | отключена ли защита |
| Подпись приложения | `codesign -dv --verbose` | валидна ли подпись |
| Нотаризация | `spctl -a -vv` | принято ли Apple |

## Ограничения

Логи ограничены по времени (обычно часы-дни), поэтому старые инциденты могут не иметь
записей. Remediator не логирует **всё** — только результат прогона. XProtect не является
EDR: он не отслеживает поведение и не даёт полного таймлайна. И, наконец, версия сигнатур на
момент инцидента могла быть устаревшей — без неё вывод о «пропуске» некорректен.

## Если сработало: что писать

Отчёт должен разделять три исхода: **заблокировано** (XProtect/Gatekeeper), **удалено**
(Remediator) и **пропущено** (нет записей). Для каждого указывай версию защит и время. Это
даёт честную картину: где защита сработала, а где нет.

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
