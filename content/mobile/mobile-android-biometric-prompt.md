---
id: mobile-android-biometric-prompt
title: 'BiometricPrompt: привязка ключа и обход проверки'
category: mobile
parent: mobile-android-keys-deep
difficulty: hard
order: 2
tags: [android, biometric, fingerprint, keystore, cryptoobject]
prerequisites: [mobile-android-keystore-deep]
useful_for:
  - 'Пентест мобильных приложений'
  - 'Аудит аутентификации'
  - 'Анализ банковских приложений'
estimated_minutes: 42
summary: 'Как связать ключ с биометрией через BiometricPrompt и CryptoObject, почему обход callback открывает доступ и как это проверить.'
lab:
  kind: shell
  title: 'Практика: найди ошибку в биометрической проверке'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, biometric_log.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`biometric_log.txt` — разбор биометрического потока приложения.'
    - 'Смотри, привязан ли ключ к аутентификации или проверка только в callback.'
    - 'Найди секрет в описании ошибки и запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

Приложение показывает запрос отпечатка пальца перед входом. Ты думаешь: без моего пальца
внутрь не попасть. Но если проверка — это просто вызов `onAuthenticationSucceeded`, который
переключает экран, то хук, вызывающий этот метод, открывает приложение без биометрии. Как
отличить настоящую защиту от декорации?

## Наш пример: поток биометрии

Разбираем код входа:

```java
biometricPrompt.authenticate(promptInfo,
    new BiometricPrompt.CryptoObject(cipher));
// ...
@Override public void onAuthenticationSucceeded(Result r) {
    startActivity(new Intent(this, VaultActivity.class));
}
```

Ключевой вопрос: что делает приложение в `onAuthenticationSucceeded` — использует `cipher` из
`CryptoObject` или просто открывает экран? Весь урок ведём этот пример.

## Шаг 1: что такое BiometricPrompt

**BiometricPrompt** — системный диалог проверки биометрии (отпечаток, лицо). Он изолирует
проверку: приложение не видит сам отпечаток, только результат. Диалог показывает систему, а не
приложение, — поэтому подделать его из приложения нельзя.

## Шаг 2: CryptoObject — настоящая привязка

`BiometricPrompt.authenticate` может принимать **CryptoObject** — объект `Cipher`/`Mac`,
инициализированный ключом из Keystore. Тогда ключ сгенерирован с
`setUserAuthenticationRequired(true)`, и **система** не даст использовать его без успешной
биометрии. Это настоящая защита: без пальца `cipher.doFinal()` выбросит исключение.

```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("vault_key", ...)
    .setUserAuthenticationRequired(true)
    .build();
```

## Шаг 3: фальшивая защита

Если приложение создаёт `CryptoObject`, но **не использует** его результат, а просто реагирует
на callback — защита декоративная:

```java
@Override public void onAuthenticationSucceeded(Result r) {
    // cipher из r не используется; ключ не привязан
    unlockVault();
}
```

Тогда хук на `onAuthenticationSucceeded` открывает доступ. Это самая частая находка в
биометрических проверках.

## Шаг 4: обход через хук

```javascript
Java.perform(function () {
  const Cb = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
  // вызываем успех, не дожидаясь биометрии
  // (в реальном скрипте — переопределение реализации колбэка)
});
```

Если после хука приложение открывает хранилище — ключ не привязан к аутентификации, и вся
защита была в UI.

## Шаг 5: проверка привязки ключа

Как понять, привязан ли ключ:
- Посмотреть параметры `KeyGenParameterSpec`: `setUserAuthenticationRequired(true)`.
- Посмотреть, используется ли `CryptoObject` (результат `r.getCryptoObject()`).
- Попробовать использовать ключ без аутентификации — должно быть исключение.

```bash
$ grep -rn 'setUserAuthenticationRequired\|CryptoObject' smali/ | head
```

## Шаг 6: ошибки привязки

- `setUserAuthenticationRequired(true)`, но ключ не используется в операции.
- `setUserAuthenticationValidityDurationSeconds` слишком большое (ключ доступен долго).
- Биометрия как «дополнительный» фактор при уже открытой сессии.
- Проверка `isDeviceSecure` вместо реальной аутентификации.
- Откат на пароль/PIN при недоступной биометрии без привязки ключа.

## Шаг 7: почему callback-проверка не защищает

Callback — это код в приложении. Всё, что живёт в приложении, можно изменить (хук, пересборка).
Защита работает только тогда, когда решение принимает система (Keystore) на основе
недоступного приложению секрета. Поэтому ключ обязан быть привязан к аутентификации.

## Шаг 8: как проверить на пентесте

1. Найти код биометрической проверки.
2. Посмотреть, есть ли `CryptoObject` и `setUserAuthenticationRequired`.
3. Если привязки нет — попробовать вызвать успех хуком.
4. Если привязка есть — попробовать использовать ключ без аутентификации.
5. Проверить длительность validity.

## Шаг 9: как защищают правильно

Ключ генерируется с `setUserAuthenticationRequired(true)`, используется через `CryptoObject` в
реальной криптооперации, привязан к StrongBox, validity минимальна. Тогда без биометрии
криптография просто не сработает, и обход callback ничего не даст. Это принцип: **секрет
защищён системой, а не UI**.

## Что мы теперь знаем

- BiometricPrompt показывает системный диалог проверки.
- Настоящая привязка — через CryptoObject и ключ с auth-required.
- Проверка только в callback обходится хуком.
- Признак привязки — использование результата CryptoObject.
- Правильно — ключ привязан к аутентификации в Keystore/StrongBox.

Проверь себя на практике — собери нужный артефакт в терминале:

<!-- lab -->

## Квиз

Проверь себя.

```quiz
- question: Что изолирует BiometricPrompt?
  options:
    - Ключ
    - Проверку биометрии: приложение видит только результат
    - Экран
    - Сеть
  answer: 1
  explanation: Диалог показывает система, отпечаток приложению не доступен.
- question: Что даёт CryptoObject?
  options:
    - Красоту
    - Привязку криптооперации к успешной аутентификации
    - Кэш
    - Логи
  answer: 1
  explanation: Ключ из CryptoObject нельзя использовать без аутентификации.
- question: Когда биометрическая защита декоративна?
  options:
    - Когда есть CryptoObject
    - Когда проверка только в callback и ключ не привязан
    - Когда включён StrongBox
    - Когда ключ в TEE
  answer: 1
  explanation: Callback можно вызвать хуком, если он не использует ключ.
- question: Какая настройка привязывает ключ к аутентификации?
  options:
    - setBlockModes(GCM)
    - setUserAuthenticationRequired(true)
    - PURPOSE_DECRYPT
    - setRandomizedEncryptionRequired
  answer: 1
  explanation: Она требует аутентификации перед использованием ключа.
- question: Как понять, что привязка настоящая?
  options:
    - По размеру APK
    - Ключ не работает без аутентификации, используется результат CryptoObject
    - По цвету диалога
    - По версии Android
  answer: 1
  explanation: Настоящая привязка — криптооперация не проходит без биометрии.
```

## Куда дальше

Мы разобрали биометрию. Дальше — слабая случайность: почему даже правильный Keystore бесполезен
при предсказуемом ключе.

## Где пригодится

- Аудит банковских и платёжных приложений.
- Пентест аутентификации на устройстве.
- Разбор биометрических обходов.
