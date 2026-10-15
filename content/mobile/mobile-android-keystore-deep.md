---
id: mobile-android-keystore-deep
title: 'Android Keystore deep: KeyGenParameterSpec и извлечение ключей'
category: mobile
parent: mobile-android-keys-deep
difficulty: hard
order: 1
tags: [android, keystore, keygenparameterspec, crypto, keys]
prerequisites: [mobile-android-random]
useful_for:
  - 'Пентест мобильных приложений'
  - 'Аудит криптографии'
  - 'Анализ мобильных приложений'
estimated_minutes: 44
summary: 'Как Android генерирует и хранит ключи через KeyGenParameterSpec, какие параметры важны для безопасности и почему ключ иногда всё-таки извлекается.'
lab:
  kind: shell
  title: 'Практика: разбери дамп Keystore'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, keystore_dump.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`keystore_dump.txt` — параметры ключей и их свойства.'
    - 'Найди ключ с небезопасными параметрами.'
    - 'Найди секрет в описании уязвимого ключа и запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

Приложение шифрует данные «ключом в Keystore». Звучит надёжно: ключ не покидает устройство.
Но если ключ сгенерирован с `setUserAuthenticationRequired(false)`, экспортируемым или на
программном бэкенде — он не так уж защищён. Как прочитать параметры ключа и понять, насколько
он на самом деле защищён?

## Наш пример: параметры ключа

Разбираем код генерации ключа:

```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("data_key",
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(false)
    .build();
```

Ключ с алиасом `data_key`. Весь урок ведём этот пример.

## Шаг 1: что такое Android Keystore

**Android Keystore** — системное хранилище криптографических ключей. Приложение не хранит
ключ само: оно просит систему сгенерировать ключ с алиасом и потом использовать его по
алиасу. Ключ может быть привязан к аппаратному модулю (TEE/StrongBox) — тогда его нельзя
извлечь даже с root. Это принципиально отличается от «сохранить ключ в SharedPreferences».

## Шаг 2: KeyGenParameterSpec — что задаём

`KeyGenParameterSpec` описывает ключ: алгоритм, назначение (`PURPOSE_ENCRYPT`/`DECRYPT`),
режим блока (`GCM`/`CBC`), паддинг, требования к аутентификации пользователя, случайность
IV. Каждый параметр влияет на безопасность:

| Параметр | Безопасно | Опасно |
|---|---|---|
| Block mode | GCM | ECB |
| Padding | NONE (для GCM) | PKCS7 в связке с ошибками |
| User auth | required | not required |
| Randomized IV | true | false |
| Exportable | false | true |

## Шаг 3: где живёт ключ

Приложение может узнать, аппаратный ли ключ, через `KeyInfo`:

```bash
$ grep -rn 'getKeyInfo\|isInsideSecureHardware\|KeyProperties' smali/ | head
```

Если ключ «в secure hardware» — извлечь его нельзя. Если нет — он в программном хранилище и
теоретически достижим на root-устройстве. Это первое, что проверяют при аудите.

## Шаг 4: привязка к аутентификации

`setUserAuthenticationRequired(true)` означает: ключ можно использовать только после
разблокировки (PIN/биометрия). При этом можно задать `setUserAuthenticationValidityDurationSeconds`
— окно, в течение которого ключ доступен после аутентификации. Если стоит `false` — ключ
доступен всегда, и вся защита сводится к песочнице приложения.

## Шаг 5: экспорт ключей

`setKeyGenParameterSpec` без явных ограничений для симметричных ключей не даёт экспорт, но
асимметричные публичные ключи экспортируемы всегда. Ошибка — генерировать **секретный** ключ
так, чтобы его можно было выгрузить (`KeyStore.getKey` и сохранение), или импортировать чужой
ключ в хранилище. Импортированный ключ извлекаем.

```bash
$ grep -rn 'setEntry\|importKey\|getEncoded' smali/
```

## Шаг 6: как извлекают ключи

Если ключ не в hardware и не привязан к аутентификации, на root-устройстве можно попробовать:
- дамп памяти приложения в момент использования ключа;
- вызов `Keystore`-API от имени приложения (хук);
- поиск импортированных ключей (они хранятся извлекаемо).

Правильный тест — определить бэкенд ключа и требования аутентификации, а не «взломать шифр».

## Шаг 7: типичные ошибки Keystore

- Ключ с `setUserAuthenticationRequired(false)` для секретов.
- Импорт ключа вместо генерации (ключ извлекаем).
- Использование `CBC` без проверки целостности (padding oracle).
- Фиксированный IV.
- Ключ в программном бэкенде там, где нужен StrongBox.
- Один ключ на всё (нет разделения).

## Шаг 8: StrongBox и Titan M

Современные устройства дают **StrongBox** — отдельный защищённый чип для ключей, недоступный
даже ядру. Если ключ там, его извлечение практически невозможно. Проверяют `isInsideSecureHardware`
и `setIsStrongBoxBacked(true)`. Для высокоценных секретов (платежи) это ожидаемый уровень.

## Шаг 9: как защищают правильно

Генерировать ключ (не импортировать), привязывать к аутентификации для секретов, использовать
GCM со случайным IV, хранить в StrongBox, разделять ключи по назначению, не выводить ключ
наружу. Keystore — это про то, чтобы ключ никогда не покидал защищённую зону.

## Что мы теперь знаем

- Keystore хранит ключи вне памяти приложения, аппаратно на части устройств.
- Параметры `KeyGenParameterSpec` определяют реальную защиту.
- `setUserAuthenticationRequired(false)` ослабляет ключ.
- Импортированные и программные ключи извлекаемы.
- Правильно — генерация, аутентификация, GCM, StrongBox.

Проверь себя на практике — собери нужный артефакт в терминале:

<!-- lab -->

## Квиз

Проверь себя.

```quiz
- question: Где Android хранит ключи приложения?
  options:
    - В SharedPreferences
    - В Android Keystore (возможно, в TEE/StrongBox)
    - В логе
    - В манифесте
  answer: 1
  explanation: Keystore держит ключи вне памяти приложения.
- question: Что ослабляет ключ в KeyGenParameterSpec?
  options:
    - setBlockModes(GCM)
    - setUserAuthenticationRequired(false) для секрета
    - Случайный IV
    - PURPOSE_ENCRYPT
  answer: 1
  explanation: Без привязки к аутентификации ключ доступен всегда.
- question: Чем опасен импортированный ключ?
  options:
    - Он медленный
    - Он хранится извлекаемо
    - Он не поддерживает GCM
    - Он длиннее
  answer: 1
  explanation: Импортированный ключ известен приложению, значит, извлекаем.
- question: Что даёт StrongBox?
  options:
    - Ускорение шифрования
    - Отдельный защищённый чип, ключ недоступен даже ядру
    - Больше памяти
    - Wi-Fi
  answer: 1
  explanation: StrongBox — аппаратная изоляция ключей.
- question: Какой режим блока безопасен для шифрования?
  options:
    - ECB
    - GCM со случайным IV
    - NONE
    - RAW
  answer: 1
  explanation: GCM даёт шифрование и целостность, IV должен быть случайным.
```

## Куда дальше

Мы разобрали хранилище ключей. Дальше — биометрия: как ключ привязывают к BiometricPrompt и
где проверку обходят.

## Где пригодится

- Пентест мобильных приложений: аудит хранения ключей.
- Аудит криптографии и платежей.
- Разбор утечек секретов.
