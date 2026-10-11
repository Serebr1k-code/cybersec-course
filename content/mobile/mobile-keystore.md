---
id: mobile-keystore
title: "Android Keystore и аппаратно-защищённые ключи"
category: mobile
parent: mobile-storage-deep
difficulty: hard
order: 3
tags: [keystore, tee, strongbox, hardware-backed, crypto, android, keychain]
prerequisites: [mobile-insecure-storage]
useful_for:
  - "CTF Mobile (работа с Keystore)"
  - "Bug bounty (проверка защиты ключей)"
  - "Пентест мобильных приложений"
estimated_minutes: 35
summary: "Как Android Keystore хранит ключи, чем hardware-backed (TEE/StrongBox) отличается от software, как их инспектировать и какие ошибки конфигурации делают ключи извлекаемыми."
---
## Что такое Android Keystore

Android Keystore — системный сервис для хранения криптографических ключей. Ключи генерируются внутри «хранилища» и **не покидают его**: приложение получает лишь дескриптор и может выполнять операции (шифрование, подпись, HMAC) через него. На устройствах с TEE/StrongBox ключи хранятся в аппаратно-защищённой среде и не извлекаются даже при root. Это правильный способ защитить секреты — и одновременно интересная цель пентеста: неправильное использование Keystore даёт обходы.

Ментальная модель: если ключ в Keystore — вы не можете его «украсть» (в идеале). Но вы можете: (1) вызвать операции с ключом из-под приложения, (2) обойти аутентификацию пользователя, привязанную к ключу, (3) найти ошибки конфигурации, снижающие защиту, (4) атаковать слабые устройства без TEE.

## Как приложение использует Keystore

```java
KeyGenerator kg = KeyGenerator.getInstance("AES", "AndroidKeyStore");
kg.init(new KeyGenParameterSpec.Builder("myKey", PURPOSE_ENCRYPT | PURPOSE_DECRYPT)
    .setBlockModes(BLOCK_MODE_GCM)
    .setEncryptionPaddings(ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)          // ключ требует аутентификации
    .setUserAuthenticationValidityDurationSeconds(30)
    .build());
kg.generateKey();
```

```bash
grep -rn "AndroidKeyStore\|KeyGenParameterSpec\|setUserAuthenticationRequired\|setIsStrongBoxBacked\|setInvalidatedByBiometricEnrollment" out_jadx | head
```

Что смотреть: `setUserAuthenticationRequired`, `setUserAuthenticationValidityDurationSeconds`, `setUnlockedDeviceRequired`, `setIsStrongBoxBacked`, `setInvalidatedByBiometricEnrollment`, `setKeyValidityForOriginationEnd`. Слабые настройки (`userAuthenticationRequired=false` при чувствительных данных) снижают защиту.

## Типы ключей и их защита

| Тип | Ключ в Keystore | TEE/StrongBox | Извлекаем? |
|-----|-----------------|---------------|-----------|
| Symmetric AES | да | да | нет (в идеале) |
| HMAC | да | да | нет |
| RSA/EC (подпись) | да | да | нет |
| Ключ из пароля (PBKDF) | может быть вне | — | возможно |
| «Сырой» ключ (импортированный) | нет | — | да |

Ключи, **импортированные** в Keystore (`setKeyEntry`), менее защищены, чем сгенерированные внутри. Также ищите ключи, которые приложение хранит вне Keystore (в файле/SharedPreferences) — это уже находка (`mobile-insecure-storage`).

## Аутентификация пользователя и её обход

`setUserAuthenticationRequired(true)` требует, чтобы пользователь аутентифицировался (PIN/биометрия) перед использованием ключа. `setUserAuthenticationValidityDurationSeconds(N)` даёт «окно» на N секунд. Атаки:

- **Биометрический обход:** если проверка только через `BiometricPrompt`, её можно подменить (Frida/Objection) — но если ключ реально требует auth, операция упадёт. Различайте «UI-проверка» и «криптографическая привязка к auth».
- **Окно валидности:** в течение N секунд ключ доступен без повторной аутентификации — если злоумышленник получил устройство в этот момент, он может выполнить операцию.
- **Обход через подмену результата биометрии** (`onAuthenticationSucceeded`) — работает, только если приложение не привязало ключ к auth криптографически.

```javascript
// проверить, требуется ли auth для ключа
Java.perform(function () {
  var K = Java.use('android.security.keystore.KeyGenParameterSpec');
  // смотреть флаги при генерации в коде
});
```

## Ошибки конфигурации

- **`setUserAuthenticationRequired(false)`** для чувствительных ключей.
- **Отсутствие `setInvalidatedByBiometricEnrollment(true)`** — ключ остаётся валиден после добавления нового отпечатка (злоумышленник добавляет свой палец).
- **Использование Keystore для ключа, который потом выгружается** (обёртка снаружи) — теряется смысл.
- **Хранение ключа рядом с данными** (пароль в SharedPreferences + ключ там же).
- **`setIsStrongBoxBacked(true)` без fallback** — на устройствах без StrongBox генерация падает (функциональный баг, не безопасность).

## Атака: извлечение ключа на устройстве без TEE

На старых/дешёвых устройствах или эмуляторах Keystore может не иметь аппаратной защиты. Тогда ключи хранятся в файле (`/data/misc/keystore/`) и извлекаются при root:

```bash
adb shell su -c "ls -la /data/misc/keystore/user_0/"
# файлы .key/.mst содержат материал; на устройствах без TEE он может быть восстановлен
```

Также на эмуляторах `AndroidKeyStore` иногда «программный» — ключи извлекаются. Проверяйте, есть ли `Keymaster`/`StrongBox` (`adb shell getprop | grep -i keymaster`).

## Разобранный пример: обход auth-привязки

```bash
$ grep -rn "setUserAuthenticationRequired" out_jadx
Vault.java: .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(3600)   // окно 1 час!
$ # приложение считает, что ключ защищён, но окно 1 час позволяет операцию без повторного auth
$ objection -g com.target.app explore
com.target.app # android hooking watch class_method com.target.Vault.decrypt --dump-args --dump-return
(agent) [watch] decrypt("...") -> "FLAG{keystore_with_long_window}"
```

Длинное окно валидности + отсутствие `InvalidatedByBiometricEnrollment` ослабляют защиту; в связке с доступом к устройству это даёт расшифровку.

## Справочная таблица: настройки и риски

| Настройка | Значение | Риск, если неверно |
|-----------|----------|--------------------|
| `setUserAuthenticationRequired` | true/false | false = ключ без auth |
| `setUserAuthenticationValidityDurationSeconds` | N сек | большое окно = обход |
| `setInvalidatedByBiometricEnrollment` | true | false = новый отпечаток не инвалидирует |
| `setUnlockedDeviceRequired` | true | false = доступ на заблокированном |
| `setIsStrongBoxBacked` | true | без fallback = падение |
| `setKeyEntry` (импорт) | — | импортированный ключ слабее |

## Типовые ошибки новичка

- **Искать «извлечение» ключа.** В TEE ключ не извлекается — цель в другом: обход auth, ошибки конфигурации, слабые устройства.
- **Путать UI-биометрию и крипто-привязку.** Первую обойти легко, вторую — нет.
- **Игнорировать окно валидности.** Большое окно = реальный обход.
- **Не проверять, импортирован ли ключ.** Импортированные ключи слабее.
- **Тестировать только на эмуляторе.** На реальном устройстве с TEE поведение иное.

## Что дальше / решение

Порядок: найти использование Keystore (`AndroidKeyStore`), проверить флаги защиты, оценить окно auth и инвалидацию биометрии, проверить наличие TEE/StrongBox, при слабом устройстве — попробовать извлечь материал. Связанные уроки: `mobile-insecure-storage`, `mobile-biometric`, `mobile-crypto-misuse`, `mobile-ios-keychain` (аналог на iOS). Решение — когда вы обошли auth-привязку или нашли конфигурацию, снижающую защиту, и подтвердили impact.

## Аппаратная привязка: TEE, StrongBox и что они значат

Android Keystore опирается на Keymaster/KeyMint в TEE (Trusted Execution Environment) или в StrongBox (отдельный чип). Ключ, созданный с `setIsStrongBoxBacked(true)`, никогда не покидает чип, а операции выполняются внутри. Что это значит для пентеста:

- **С TEE/StrongBox** извлечь ключ нельзя; но можно обойти **условия его использования** (auth, окно валидности) или заставить приложение выполнить операцию.
- **Без TEE** (эмулятор, старые устройства) Keystore программный: материал ключа лежит в файлах и может быть извлечён при root.

```bash
# проверить наличие аппаратной поддержки
adb shell getprop | grep -iE "keymaster|strongbox|keystore"
adb shell dumpsys android.hardware.security.keymint 2>/dev/null | head
# на эмуляторе часто keymaster=software
```

Если поддержки нет — считайте Keystore «мягким» и ищите файлы ключей. Если есть — смещайте фокус на обход условий использования.

## Практический чек-лист тестирования Keystore

1. Найти использование (`AndroidKeyStore`, `KeyGenParameterSpec`, `KeyStore.getEntry`).
2. Выписать флаги: `userAuthenticationRequired`, окно валидности, `InvalidatedByBiometricEnrollment`, `UnlockedDeviceRequired`, `IsStrongBoxBacked`.
3. Оценить, привязан ли ключ к аутентификации **криптографически** (тогда UI-обход бесполезен) или только UI.
4. Проверить, не импортирован ли ключ (`setKeyEntry`) — это слабее.
5. Проверить, нет ли рядом с ключом его «обёртки»/пароля в файлах.
6. Определить наличие TEE/StrongBox.
7. При слабом устройстве — попробовать извлечь материал (`/data/misc/keystore`).
8. Зафиксировать: обход (если есть) или подтверждение стойкости.

## Справочная таблица: API Keystore и риск

| API | Назначение | Слабый случай |
|-----|-----------|---------------|
| `KeyGenerator` + `AndroidKeyStore` | генерация ключа в хранилище | ключ извлекаем вне TEE |
| `setUserAuthenticationRequired` | требовать auth | false при секретах |
| `setUserAuthenticationValidityDurationSeconds` | окно | большое окно |
| `setInvalidatedByBiometricEnrollment` | инвалидация | false |
| `setUnlockedDeviceRequired` | только разблокированное | false |
| `setIsStrongBoxBacked` | чип | без fallback |
| `KeyStore.setKeyEntry` | импорт ключа | импортированный слабее |
| `KeyInfo` | проверка возможностей | — |

## Квиз

```quiz
- question: "Чем hardware-backed ключ лучше software?"
  options:
    - "Материал не покидает TEE/StrongBox"
    - "Он быстрее"
    - "Он не требует аутентификации"
    - "Он переносится в бэкап"
  answer: 0
  explanation: "Аппаратная защита не даёт извлечь ключевой материал."
- question: "Какой флаг привязывает ключ к аутентификации пользователя?"
  options:
    - "setUserAuthenticationRequired(true)"
    - "setBlockModes"
    - "setKeySize"
    - "setIsStrongBoxBacked"
  answer: 0
  explanation: "Ключ нельзя использовать без успешной аутентификации."
- question: "Чем опажен setUserAuthenticationValidityDurationSeconds?"
  options:
    - "Создаёт окно, в котором ключ доступен без повторной проверки"
    - "Замедляет шифрование"
    - "Требует root"
    - "Удаляет ключ"
  answer: 0
  explanation: "В течение окна аутентификация не перепроверяется."
- question: "Как обойти логику, доверяющую Keystore, без извлечения ключа?"
  options:
    - "Хукать операции Cipher/Signature"
    - "Переустановить приложение"
    - "Сменить устройство"
    - "Отключить Wi-Fi"
  answer: 0
  explanation: "Перехват операций позволяет влиять на результат."
- question: "Что такое StrongBox?"
  options:
    - "Отдельный защищённый чип для ключей"
    - "Формат APK"
    - "Тип сети"
    - "Режим шифрования"
  answer: 0
  explanation: "StrongBox — аппаратный модуль хранения ключей."
```

## Где пригодится

- **CTF Mobile:** работа с Keystore и обход доверия к нему.
- **Bug bounty:** слабая конфигурация ключей — валидная находка.
- **Пентест:** аудит хранения и использования ключей.
- **Работа:** ревью крипто-хранилищ Android.
