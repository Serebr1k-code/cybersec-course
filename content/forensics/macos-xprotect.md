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
estimated_minutes: 40
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
