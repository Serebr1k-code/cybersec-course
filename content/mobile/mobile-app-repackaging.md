---
id: mobile-app-repackaging
title: "Repackaging и клонирование приложений: патч, подпись, инъекция"
category: mobile
parent: mobile-android-root
difficulty: medium
order: 2
tags: [repackaging, apktool, apksigner, cloning, smali, patch, android, tamper]
prerequisites: [mobile-android-anatomy, mobile-static-analysis]
useful_for:
  - "Пентест мобильных приложений"
  - "Анализ малвари (обфускация/клоны)"
  - "CTF Mobile"
estimated_minutes: 50
summary: "Перепаковка APK: декомпиляция, патч smali, добавление кода, повторная подпись и установка; клонирование, dual-app и защита от подмены."
---
## Введение

Repackaging (перепаковка) — изменение APK и его повторная сборка: правка smali-кода, внедрение собственного кода, замена ресурсов, добавление логирующих вызовов. Это базовый навык для обхода клиентских проверок (root-детект, pinning), для инструментирования без Frida, а также для анализа того, как устроены «клоны» и модифицированные версии популярных приложений. Клонирование (dual-app) — установка второй копии приложения под другим package name, чтобы запускать несколько аккаунтов или обходить singleton-ограничения.

Ключевая сложность — **подпись**: Android требует, чтобы APK был подписан, и обновление поверх установленного приложения требует той же подписи. При перепаковке подпись меняется, поэтому приложение нельзя «обновить», только удалить и поставить заново; а некоторые приложения детектят смену подписи (signature check).

## Инструментарий

| Инструмент | Назначение |
|-----------|-----------|
| `apktool` | декомпиляция/сборка ресурсов и smali |
| `apksigner` | подпись APK (v1/v2/v3) |
| `zipalign` | выравнивание перед подписью |
| `jadx` | декомпиляция в Java (для чтения) |
| `keytool` | генерация keystore |
| `uber-apk-signer` | автоматическая подпись |
| `objection` | патч APK (patching) без ручной smali-правки |

## Полный сквозной пример: патч проверки и подпись

Цель: заставить метод `isRooted()` всегда возвращать `false`.

```bash
# 1. Декомпиляция
apktool d target.apk -o target_src
# 2. Находим метод в smali
grep -rn "isRooted" target_src/smali*/ | head
```

Смотрим smali:

```smali
.method public isRooted()Z
    .locals 1
    const/4 v0, 0x1
    return v0
.endmethod
```

Меняем `const/4 v0, 0x1` на `const/4 v0, 0x0` (или возвращаем рано):

```smali
.method public isRooted()Z
    .locals 1
    const/4 v0, 0x0
    return v0
.endmethod
```

```bash
# 3. Сборка
apktool b target_src -o target_patched.apk
# 4. Генерация ключа (один раз)
keytool -genkey -v -keystore test.keystore -alias t -keyalg RSA -keysize 2048 -validity 10000 -storepass pass123 -keypass pass123 -dname "CN=test"
# 5. Выравнивание и подпись
zipalign -v 4 target_patched.apk target_aligned.apk
apksigner sign --ks test.keystore --ks-pass pass:pass123 --out target_signed.apk target_aligned.apk
apksigner verify --verbose target_signed.apk
# 6. Установка
adb uninstall com.target.app
adb install target_signed.apk
```

`apksigner verify` должен показать `Verifies` и схему подписи v2/v3. Если приложение падает — вероятно, сработал signature check (см. ниже).

## Альтернатива: objection patchapk

Когда нужно только встроить Frida-gadget (для динамики без root):

```bash
objection patchapk --source target.apk
adb install target.objection.apk
```

Objection перепаковывает APK, встраивая `frida-gadget`, и подписывает. Это быстрее ручной smali-правки, но меняет размер и подпись — детектится anti-tamper.

## Клонирование и dual-app

Чтобы поставить вторую копию, меняем `package` в `AndroidManifest.xml` и все ссылки:

```bash
apktool d target.apk -o clone
# правим package="com.target.app" -> "com.target.app.clone"
sed -i 's/com\.target\.app/com.target.app.clone/g' clone/AndroidManifest.xml
# правим provider authorities (иначе конфликт установки)
grep -n "android:authorities" clone/AndroidManifest.xml
apktool b clone -o clone.apk
zipalign -v 4 clone.apk clone_a.apk && apksigner sign --ks test.keystore --out clone_s.apk clone_a.apk
adb install clone_s.apk
```

Частая ошибка: конфликт `android:authorities` (FileProvider, content providers) — их нужно уникализировать, иначе установка второй копии падает с `INSTALL_FAILED_CONFLICTING_PROVIDER`.

## Внедрение собственного кода

Можно добавить логгер в `onCreate` главной Activity:

```smali
# в target_src/smali/com/target/app/MainActivity.smali, после .locals
const-string v0, "PWN"
const-string v1, "onCreate called"
invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
```

Это полезно для трассировки логики без отладчика. Для более сложной инъекции встраивают smali-обёртку или Frida-gadget.

## Защита от перепаковки (что искать в отчёте)

- **Signature check** — сравнение `PackageManager.getPackageInfo(..., GET_SIGNATURES)` с ожидаемым хэшем; при несовпадении приложение завершается.
- **Integrity check** — хэш APK/DEX (см. `mobile-integrity`, `mobile-android-packers`).
- **SafetyNet/Play Integrity** — серверная аттестация.
- **Anti-tamper** — проверка контрольной суммы классов/ресурсов.
- **Split APKs / App Bundle** — базовый APK зависит от конфигов, ручная перепаковка усложняется.

Обход signature check — через Frida-хук `getPackageInfo`/`checkSignature` или через патч самого метода сравнения.

## Частые ошибки

- **`INSTALL_PARSE_FAILED_NO_CERTIFICATES`**: забыли подписать после `apktool b`.
- **`INSTALL_FAILED_UPDATE_INCOMPATIBLE`**: подпись не совпадает с установленной — сначала `adb uninstall`.
- **`INSTALL_FAILED_CONFLICTING_PROVIDER`**: конфликт authorities у клона.
- **zipalign после подписи**: порядок неверный — сначала `zipalign`, потом `apksigner` (иначе подпись ломается).
- **Не тот smali**: несколько методов с одинаковым именем в разных классах — проверяйте контекст.
- **V1-only подпись на Android 11+**: нужно v2/v3 (apksigner делает по умолчанию).

## Что дальше / решение

Если приложение детектит перепаковку — переходите на Frida/LSPosed (инъекция без изменения APK) или патчьте signature-check. Свяжите с `mobile-android-packers` (распаковка) и `mobile-obfuscation`. Для динамического анализа без root используйте `objection patchapk`. Следующая ветвь — `mobile-android-ipc-deep`.

## Справочная таблица

| Шаг | Команда |
|-----|---------|
| Декомпиляция | `apktool d app.apk -o src` |
| Сборка | `apktool b src -o app_patched.apk` |
| Выравнивание | `zipalign -v 4 in.apk out.apk` |
| Подпись | `apksigner sign --ks k.keystore app.apk` |
| Проверка | `apksigner verify --verbose app.apk` |
| Патч-инструмент | `objection patchapk --source app.apk` |
| Установка | `adb install -r app.apk` |

## Автоматизация перепаковки скриптом

Ручные шаги (декомпиляция → патч → сборка → подпись → установка) удобно завернуть в скрипт, чтобы повторять на каждой новой версии APK. Пример bash-функции:

```bash
#!/usr/bin/env bash
set -euo pipefail
APK="$1"; KS="$2"; KS_PASS="$3"

apktool d -f "$APK" -o src
# ... здесь ваши патчи (sed/python по smali) ...
apktool b src -o patched.apk
zipalign -f -v 4 patched.apk aligned.apk
apksigner sign --ks "$KS" --ks-pass "pass:$KS_PASS" --out signed.apk aligned.apk
apksigner verify --verbose signed.apk | head -1
adb install -r signed.apk
```

Такой скрипт особенно полезен в CI (например, автосборка тестовой сборки для fuzzing). Для objecttion-подобного патча:

```bash
objection patchapk --source "$APK" --ignore-vpn --skip-resources
```

## Работа со Split APKs и App Bundle

Современные приложения поставляются как split APK (base + config.* + feature). Перепаковывать нужно корректно: base нельзя просто «пересобрать» без config-частей, иначе приложение упадёт.

```bash
# получить splits установленного приложения
adb shell pm path com.target.app
# -> base.apk, split_config.arm64_v8a.apk, split_config.xxhdpi.apk
# собрать из splits единый APK
apkeep -a com.target.app .
# либо
APKEditor merge -i ./splits -o merged.apk
```

`APKEditor` умеет merge/split; для патча base достаточно править base и переустанавливать через `adb install-multiple`. Учтите: подпись всех splits должна совпадать.

```bash
apksigner sign --ks test.keystore base_patched.apk split_config.arm64_v8a.apk
adb install-multiple base_patched.apk split_config.arm64_v8a.apk split_config.xxhdpi.apk
```

## Обход signature check через Frida

Если после перепаковки приложение закрывается (signature mismatch), есть два пути: патчить сам метод проверки в smali или хукать его в рантайме. Быстрее — Frida:

```javascript
Java.perform(function() {
  var PM = Java.use("android.app.ApplicationPackageManager");
  PM.getPackageInfo.overload("java.lang.String", "int").implementation = function(pkg, flags) {
    var info = this.getPackageInfo(pkg, flags);
    // подменяем подпись на ожидаемую хэшем, если приложение сравнивает
    return info;
  };
  var MessageDigest = Java.use("java.security.MessageDigest");
  MessageDigest.digest.overload("[B").implementation = function(b) {
    var r = this.digest(b);
    // при необходимости вернуть заранее вычисленный хэш
    return r;
  };
});
```

На практике проще найти метод `checkSignature`/`verifySignature` и заменить его реализацию на возврат `true` — это делается и в smali, и через Frida.

## Сквозной кейс: патч лицензионной проверки

Дано: приложение проверяет лицензию через `LicenseChecker.checkAccess()` и завершается при неудаче.

```bash
# 1. Декомпилируем
apktool d app.apk -o src
# 2. Находим метод
grep -rn "checkAccess\|license" src/smali*/ | head
# 3. Патчим smali: возвращаем true
#    .method public checkAccess()Z -> const/4 v0, 0x1; return v0
# 4. Сборка, выравнивание, подпись, установка
apktool b src -o p.apk && zipalign -f 4 p.apk a.apk
apksigner sign --ks test.keystore --out s.apk a.apk && adb install -r s.apk
```

Проверяем: приложение больше не завершается и открывает платный функционал. Аналогично патчатся root-детект, проверки эмулятора и триал-таймеры.

## Что проверять в отчёте

Перепаковка — это демонстрация обхода клиентской защиты. В отчёте фиксируйте: (1) какой метод проверялся и как патчился, (2) почему защита оказалась нестойкой (нет серверной валидации, нет signature check, нет integrity), (3) рекомендации: серверная проверка лицензии, Play Integrity, проверка подписи, R8/обфускация. Клиентский патч не должен давать доступ к платному функционалу — это корневая рекомендация.

## Итоговый чек-лист перепаковки

1. Декомпилируйте (`apktool d`), найдите целевой метод/ресурс.
2. Внесите патч (smali, ресурсы, манифест).
3. Соберите (`apktool b`), выровняйте (`zipalign`), подпишите (`apksigner`).
4. Проверьте подпись (`apksigner verify`) и установите (`adb install -r`).
5. При краше из-за signature/integrity check — обойдите хуком или патчем проверки.
6. Для split APK используйте merge/install-multiple.

Автоматизируйте шаги скриптом для повторяемости. Помните: перепаковка меняет подпись, поэтому обновление «поверх» невозможно — только переустановка. В отчёте фиксируйте, какая именно защита обойдена и почему (клиентская проверка без серверного дублирования).

## Квиз

```quiz
- question: "Почему при перепаковке нельзя обновить приложение поверх старого?"
  options:
    - "Меняется подпись APK"
    - "Меняется package name автоматически"
    - "Android запрещает apktool"
    - "Меняется версия SDK"
  answer: 0
- question: "Какой правильный порядок перед публикацией/установкой?"
  options:
    - "подпись → zipalign"
    - "zipalign → подпись"
    - "только подпись"
    - "только zipalign"
  answer: 1
  explanation: "Сначала выравнивают, затем подписывают — подпись ломается при выравнивании после неё."
- question: "Что делает `objection patchapk`?"
  options:
    - "Сканирует сеть"
    - "Встраивает frida-gadget в APK и подписывает его"
    - "Извлекает Keychain"
    - "Патчит ядро"
  answer: 1
- question: "Какая ошибка установки типична для клона с тем же FileProvider?"
  options:
    - "INSTALL_FAILED_CONFLICTING_PROVIDER"
    - "INSTALL_PARSE_FAILED_NO_CERTIFICATES"
    - "Permission denied"
    - "SELinux denied"
  answer: 0
- question: "Чем защищаются приложения от перепаковки?"
  options:
    - "Signature/integrity check и anti-tamper"
    - "Только HTTPS"
    - "Только root-детект"
    - "Только обфускацией строк"
  answer: 0
```

## Где пригодится

- **Пентест:** обход клиентских проверок, инструментирование, клонирование.
- **Bug bounty:** демонстрация обхода подписи/целостности.
- **Анализ малвари:** разбор клонов и модифицированных сборок.
- **CTF:** Mobile-задачи с проверкой подписи или анти-тампером.
