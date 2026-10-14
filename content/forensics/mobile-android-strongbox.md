---
id: mobile-android-strongbox
title: 'Android StrongBox и аппаратные ключи'
category: forensics
parent: forensics-mobile-android-deep
difficulty: hard
order: 4
tags: [forensics, mobile, android, strongbox, keystore, tee]
prerequisites: [forensics-mobile]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Что такое StrongBox/TEE на Android, как хранятся ключи и что это значит для форензики.'
lab:
  kind: shell
  title: 'Практика: Android StrongBox и аппаратные ключи'
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

Современные Android-устройства хранят ключи в аппаратной защите (TEE/StrongBox). Извлечь
их обычными методами нельзя. Разберём, как это устроено и что доступно.

## Наш пример: Android Keystore

## Шаг 1: уровни защиты

- **software** — ключи в файле (слабый);
- **TEE** (Trusted Execution Environment) — защищённое окружение в SoC;
- **StrongBox** — отдельный чип (strongest).

```
$ adb shell dumpsys keystore | grep -i 'strongbox\|tee'
```

## Шаг 2: где ключи

Ключи Android Keystore привязаны к аппаратной защите. Файлы в `/data/misc/keystore`
содержат **зашифрованные** блобы — расшифровать без чипа нельзя.

```
$ ls /data/misc/keystore/user_0/
10001_USRPKEY_...
```

## Шаг 3: что это значит

- приложения (банки, мессенджеры) хранят ключи в StrongBox/TEE;
- ключи **не покидают** защищённую зону;
- извлечь их «в лоб» невозможно;
- можно использовать ключ **только на устройстве** через API.

## Шаг 4: что доступно

- метаданные ключей (алиасы, типы);
- факт использования (логи);
- при наличии эксплойта/root — ограниченный доступ;
- на разблокированном устройстве — через API.

## Шаг 5: практика

- для расследования важнее **данные приложений**, а не сами ключи;
- если ключ нужен — извлекай через живое устройство (API);
- фиксируй версию/модель (влияет на защиту).

## Что мы теперь знаем

- Ключи хранятся в software/TEE/StrongBox.
- StrongBox — отдельный чип (максимальная защита).
- Файлы keystore содержат зашифрованные блобы.
- Ключи не покидают защищённую зону.
- Доступны метаданные и использование через API.

## Если не сработало

- Нужен ключ? Работай через живое устройство.
- Есть root? Доступ всё равно ограничен TEE.
- Нужны данные? Читай базы приложений.

## Квиз

Проверь себя.

```quiz
- question: Что такое StrongBox?
  options:
    - 'браузер'
    - 'отдельный защищённый чип для ключей'
    - 'сеть'
    - 'формат'
  answer: 1
  explanation: 'StrongBox — аппаратный модуль хранения ключей.'
- question: Где Android хранит ключи Keystore?
  options:
    - 'в /etc/passwd'
    - 'в /data/misc/keystore (зашифрованные блобы)'
    - 'в браузере'
    - 'в шрифтах'
  answer: 1
  explanation: 'Ключи лежат зашифрованными в каталоге keystore.'
- question: Можно ли извлечь ключ StrongBox обычными методами?
  options:
    - 'да'
    - 'нет, ключ не покидает защищённую зону'
    - 'иногда'
    - 'всегда'
  answer: 1
  explanation: 'TEE/StrongBox не отдают ключи наружу.'
- question: Что доступно при расследовании?
  options:
    - 'сами ключи'
    - 'метаданные и использование ключей'
    - 'ничего'
    - 'обои'
  answer: 1
  explanation: 'Доступны алиасы/типы и факт использования.'
```
