---
id: mobile-android-hardware-keys
title: 'Аппаратные ключи и StrongBox: границы Keystore'
category: mobile
parent: mobile-android-hardware-trust
difficulty: expert
order: 2
tags: [android, keystore, strongbox, titan-m, keymaster, attestation, keygenparameter]
prerequisites: [mobile-android-attestation, mobile-keystore]
useful_for:
  - 'Android-безопасность'
  - 'Пентест мобильных приложений'
  - 'Реверс Android'
estimated_minutes: 44
summary: 'Как Android Keystore привязывает ключи к железу: уровни безопасности (software/TEE/StrongBox), Keymaster, Titan M, key attestation и практические границы защиты ключей.'
lab:
  kind: shell
  title: 'Практика: классификация ключа Keystore'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, keystore_dump.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`keystore_dump.txt` — дамп метаданных ключей.'
    - 'Определи уровень безопасности и найди слабый ключ.'
    - 'Рядом со слабым ключом — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Приложение хранит ключ шифрования в Android Keystore и считает, что он в безопасности: ключ
«нельзя извлечь». Но насколько это правда? Зависит от того, где именно живёт ключ — в
программе, в TEE или в отдельном чипе. Разберём уровни аппаратной защиты и их реальные границы.

## Наш пример: ключ в Keystore

Приложение создаёт AES-ключ для шифрования локальных данных. Мы хотим понять, где этот ключ
физически находится и что нужно, чтобы им воспользоваться или его извлечь.

## Шаг 1: уровни безопасности ключа

При генерации ключа задаётся **уровень безопасности**:

- `KeyProperties.SECURITY_LEVEL_SOFTWARE` — ключ в памяти процесса/системы;
- `SECURITY_LEVEL_TRUSTED_ENVIRONMENT` — ключ внутри TEE;
- `SECURITY_LEVEL_STRONGBOX` — ключ в отдельном защищённом чипе.

```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("k", PURPOSE_ENCRYPT)
    .setIsStrongBoxBacked(true)
    .build();
```

`setIsStrongBoxBacked(true)` просит хранить ключ в StrongBox — если устройство это умеет.

## Шаг 2: Keymaster и KeyMint

Работой с ключами управляет HAL **Keymaster** (новые версии — **KeyMint**). Приложение не
держит ключевой материал: оно просит Keymaster выполнить операцию. Ключ никогда не покидает
защищённую среду — наружу возвращается только результат.

## Шаг 3: StrongBox и Titan M

**StrongBox** — отдельный микроконтроллер с собственным хранилищем и защитой от физических
атак. В устройствах Google он реализован чипом **Titan M**. Он даёт:

- изоляцию ключей от основной ОС и TEE;
- защиту от отката версий (rollback);
- аппаратный счётчик попыток.

Именно StrongBox используют для самых критичных ключей (платежи, банки).

## Шаг 4: key attestation

Keystore умеет выдавать **attestation** — подписанный сертификат, доказывающий свойства ключа
(уровень безопасности, привязан ли к железу, разрешённые операции). Сервер проверяет его, чтобы
убедиться, что ключ действительно аппаратный. Слабые приложения проверяют только факт наличия
сертификата — это и есть типичная ошибка.

## Шаг 5: границы защиты

Что важно понимать:

- Ключ **нельзя извлечь** из TEE/StrongBox напрямую — но можно **заставить** его использовать,
  если приложение не проверяет контекст (например, не требует биометрию на каждую операцию).
- На **root**-устройстве можно подсунуть свой Keymaster-реализацию (HAL) и обмануть проверки.
- `setUserAuthenticationRequired(true)` и `setInvalidatedByBiometricEnrollment(true)` повышают
  стойкость, но требуют правильной логики в приложении.

## Что мы теперь знаем

- Keystore-ключи бывают software, TEE и StrongBox.
- Keymaster/KeyMint выполняет операции, не выдавая ключевой материал.
- StrongBox/Titan M — отдельный чип для критичных ключей.
- Извлечь ключ нельзя, но можно злоупотребить его использованием; на root можно подменить HAL.

## Если не сработало

Если приложение использует `SECURITY_LEVEL_SOFTWARE`, ключ фактически в памяти — его можно
искать дампом. Если `setIsStrongBoxBacked` бросает исключение, устройство не поддерживает
StrongBox. Проверяйте `attestation` на сервере: без проверки challenge сертификат можно
переиграть.

## Частые вопросы

**Можно ли экспортировать ключ?** Нет, если он TEE/StrongBox-backed.

**Что даёт root?** Возможность подменить HAL и обойти клиентские проверки.

**Titan M только у Google?** Да, но аналогов много (Samsung Knox Vault и др.).

## Квиз

Проверь себя.

```quiz
- question: Что означает SECURITY_LEVEL_STRONGBOX?
  options:
    - Ключ в облаке
    - Ключ в отдельном защищённом чипе
    - Ключ в файле
    - Ключ в Wi-Fi
  answer: 1
  explanation: StrongBox хранит ключ вне основной ОС и TEE.
- question: Кто выполняет криптооперации с ключом Keystore?
  options:
    - Приложение
    - Keymaster/KeyMint в защищённой среде
    - Браузер
    - Сервер
  answer: 1
  explanation: HAL Keymaster работает с ключом, не выдавая его.
- question: Что даёт key attestation?
  options:
    - Скорость
    - Подписанное подтверждение свойств ключа
    - Wi-Fi
    - Батарею
  answer: 1
  explanation: Attestation-сертификат описывает уровень и привязку ключа.
- question: Что может атакующий с root?
  options:
    - Извлечь StrongBox-ключ напрямую
    - Подменить Keymaster HAL и обойти проверки
    - Ускорить телефон
    - Сменить язык
  answer: 1
  explanation: Root позволяет подсунуть свою реализацию HAL.
- question: Какая настройка повышает стойкость?
  options:
    - setUserAuthenticationRequired(true)
    - setBlockModes
    - setKeySize
    - setRandomizedEncryptionRequired
  answer: 0
  explanation: Требование аутентификации привязывает использование ключа к пользователю.
```

## Куда дальше

Аппаратные ключи защищают секреты приложения. Но платформа ниже — `init` и свойства — тоже
поверхность атаки, особенно для персистентности. Разберём её.

## Где пригодится

- Аудит хранения ключей в банковских и платёжных приложениях.
- Оценка устойчивости к root-атакам.
- Понимание границ KeyStore и attestation.
