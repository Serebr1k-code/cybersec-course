---
id: mobile-android-tee-attacks
title: 'Атаки на TEE и TrustZone: извлечение ключей'
category: mobile
parent: mobile-android-hardware-trust
difficulty: expert
order: 1
tags: [android, tee, trustzone, trusty, qsee, keymaster, fuzzing, side-channel]
prerequisites: [mobile-android-trustzone]
useful_for:
  - 'Android-безопасность'
  - 'Реверс Android'
  - 'Мобильный research'
estimated_minutes: 46
summary: 'Как устроен TrustZone и доверенный мир Android (Trusty, QSEE), какие у него бывают уязвимости и как через них извлекают ключи шифрования и подписи.'
lab:
  kind: shell
  title: 'Практика: разбор отчёта по TEE'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, tee_report.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`tee_report.txt` — отчёт анализа TEE.'
    - 'Найди уязвимый TA и извлечённый ключ.'
    - 'Рядом с ключом — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Ключи шифрования диска и аппаратной аттестации Android живут не в обычной ОС, а в
**доверенной среде** — TEE. Идея в том, что даже если атакующий получил root в Android, он не
должен дотянуться до этих ключей. Но TEE — тоже код, и в нём находят уязвимости. Разберём, как
устроена эта среда и как из неё извлекают секреты.

## Наш пример: ключ, который «нельзя достать»

Возьмём диск-шифрующий ключ (DEK), обёрнутый мастер-ключом внутри TEE. Задача — понять, как
атакующий подходит к этому ключу и на каком этапе защита ломается.

## Шаг 1: что такое TrustZone

**TrustZone** — аппаратный механизм ARM, который делит процессор на два мира: **Normal World**
(Android) и **Secure World** (TEE). Переключение между ними — через специальную инструкцию
`smc`. Код Secure World недоступен Normal World напрямую: другая память, другие права.

## Шаг 2: из чего состоит TEE Android

На типичном устройстве TEE — это отдельная ОС:

- **Trusty** (Google) — TEE-ОС с приложениями (TA, Trusted Applications);
- **QSEE** (Qualcomm Secure Execution Environment) — проприетарный TEE Qualcomm;
- **TEEGRIS** (Samsung) — TEE Samsung.

Приложения (`TA`) реализуют Keymaster, Gatekeeper и DRM. Именно они держат ключи.

## Шаг 3: типичные уязвимости TEE

Классы уязвимостей TEE:

- **переполнения буфера** в парсерах команд SMC;
- **непроверенные указатели** из Normal World;
- **логические ошибки** в Keymaster (неверная проверка авторизации ключа);
- **side-channel** (кэш-атаки, тайминги) для извлечения ключей.

Многие исторические CVE Qualcomm (например, серия в QSEE) позволяли выполнить код в Secure
World.

## Шаг 4: как извлекают ключи

Сценарий атаки: Normal World шлёт в TA команду с некорректными параметрами, парсер TA
переполняется, и атакующий получает выполнение в Secure World. Оттуда он может прочитать
Keymaster-ключи напрямую:

```text
[exploit] smc -> TA_KEYMASTER, cmd=0x1234, malformed params
[exploit] secure world code execution
[exploit] keymaster_key_blob = DEK-wrapped-key  # extracted
```

Именно так работают публичные цепочки эксплойтов на устройствах с непропатченным TEE.

## Шаг 5: почему это трудно

TEE-эксплуатация требует глубоких знаний конкретного чипа, отладки через hardware (JTAG), а
иногда и физического доступа. Часто проще атаковать **интерфейс**: неверную логику Keymaster
(когда ключ можно использовать, не имея права), чем сам Secure World.

## Что мы теперь знаем

- TrustZone делит CPU на Normal и Secure World.
- TEE-ОС (Trusty/QSEE/TEEGRIS) держат ключи через TA.
- Уязвимости TEE — переполнения, непроверенные указатели, логические ошибки, side-channel.
- Из Secure World ключи извлекаются напрямую; часто проще ломать интерфейс Keymaster.

## Если не сработало

Если нет hardware-доступа, начните с логических ошибок Keymaster и с анализа того, какие TA
доступны из Normal World. Проверьте патч-уровень TEE (`ro.boot.veritymode`, даты security
patch). Иногда ключ можно извлечь не из TEE, а из плохо защищённого кэша в Android.

## Частые вопросы

**TEE взломать реально?** Да, но это research-уровень; публичных цепочек мало.

**Что даёт root в Android?** Не даёт доступ к Secure World.

**Есть ли программные TEE?** Да, но они слабее аппаратных.

## Квиз

Проверь себя.

```quiz
- question: Что делит TrustZone?
  options:
    - Диск на разделы
    - Процессор на Normal и Secure World
    - Сеть на подсети
    - Память на кэши
  answer: 1
  explanation: TrustZone изолирует два мира исполнения.
- question: Что такое TA?
  options:
    - Тип сети
    - Trusted Application внутри TEE
    - Язык
    - Файл
  answer: 1
  explanation: TA — приложение доверенной среды.
- question: Какая уязвимость типична для TEE?
  options:
    - Медленный Wi-Fi
    - Переполнение буфера в парсере SMC-команд
    - Разряд батареи
    - Смена языка
  answer: 1
  explanation: Парсеры команд из Normal World — частая цель.
- question: Что держит Keymaster?
  options:
    - Обои
    - Ключи шифрования и подписи внутри TEE
    - Сеть
    - Экран
  answer: 1
  explanation: Keymaster управляет ключами в доверенной среде.
- question: Что часто проще, чем ломать Secure World?
  options:
    - Купить телефон
    - Использовать логическую ошибку интерфейса Keymaster
    - Сменить оператора
    - Обновить iOS
  answer: 1
  explanation: Логические ошибки API доступнее, чем эксплуатация TEE.
```

## Куда дальше

Ключи в TEE — часть системы аппаратных ключей Android. Дальше разберём, как Keystore
привязывает ключи приложений к железу и что даёт StrongBox.

## Где пригодится

- Оценка стойкости защит банковских приложений.
- Research TEE и мобильных SoC.
- Понимание границ модели угроз Android.
