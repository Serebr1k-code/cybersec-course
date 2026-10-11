---
id: mobile-network-security-config
title: "Network Security Config: атаки и обход доверия"
category: mobile
parent: mobile-network-security
difficulty: hard
order: 2
tags: [android, network-security-config, nsc, cleartext, trust-anchors, mitm, pinning, xml]
prerequisites: [mobile-ssl-pinning, mobile-static-analysis]
useful_for:
  - "Пентест мобильных приложений (Android)"
  - "Bug bounty Android"
  - "Анализ трафика"
estimated_minutes: 50
summary: "Как читать Network Security Config, почему пользовательский CA не работает, как обходить trust-anchors, cleartext-политику и config-level pinning."
---
## Введение

Network Security Config (NSC) — декларативный XML, управляющий сетевым доверием Android-приложения. Он решает, каким CA доверять (системным/пользовательским), разрешён ли cleartext, применяется ли pinning на уровне конфига и по каким доменам. Для пентестера NSC — первый барьер после pinning: даже если вы поставили Burp CA, приложение с `trust-anchors → system` его проигнорирует. Этот урок — про чтение NSC, атаки (переход на cleartext, MITM, downgrade) и обход доверия.

Ключевая мысль: NSC — **клиентская** конфигурация. Её можно прочитать в APK, понять политику и либо обойти (патч/хук), либо использовать слабости (cleartext-исключения для доменов, debug-overrides).

## Где лежит NSC

```xml
<!-- AndroidManifest.xml -->
<application android:networkSecurityConfig="@xml/network_security_config" ...>
```

Файл: `res/xml/network_security_config.xml`. После `apktool d`:

```bash
grep -n "networkSecurityConfig" AndroidManifest.xml
cat res/xml/network_security_config.xml
```

## Чтение и разбор

```xml
<network-security-config>
  <!-- дефолт для всех доменов -->
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system"/>
    </trust-anchors>
  </base-config>

  <!-- исключение: домен разрешает пользовательские CA и cleartext -->
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">legacy.target.com</domain>
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </domain-config>

  <!-- debug-переопределения (только debuggable-сборки) -->
  <debug-overrides>
    <trust-anchors><certificates src="user"/></trust-anchors>
  </debug-overrides>
</network-security-config>
```

Что искать:
- `<certificates src="user"/>` — пользовательский CA разрешён (MITM возможен без обхода).
- `cleartextTrafficPermitted="true"` — HTTP в открытом виде (перехват/подмена тривиальны).
- `<pin-set>` — pinning на уровне NSC.
- `<debug-overrides>` — доверие user-CA в debug-сборках (частая утечка).

## Полный сквозной пример: обход trust-anchors

Дано: приложение с `base-config → system` и pinning в коде. Обычный Burp не работает.

```bash
# 1. Читаем NSC
cat res/xml/network_security_config.xml
# -> base-config: trust-anchors system only  (user CA игнорируется)
# 2. Вариант A: патчим NSC в APK
#    добавляем <certificates src="user"/> в base-config
apktool d app.apk -o src
# правим src/res/xml/network_security_config.xml: добавить user
apktool b src -o patched.apk
zipalign -v 4 patched.apk aligned.apk
apksigner sign --ks test.keystore --out signed.apk aligned.apk
adb uninstall com.target.app && adb install signed.apk
# 3. Теперь пользовательский CA (Burp) принимается
```

Вариант B (без перепаковки) — Frida-хук проверки доверия (см. `mobile-ios-ssl-killswitch` для iOS-аналога; на Android хукают `X509TrustManager`/`SSLContext`). Вариант C — системный CA на root-устройстве (см. ниже).

## Системный CA вместо пользовательского

Если NSC доверяет `system`, положите Burp CA в системное хранилище (нужен root):

```bash
# хэшируем сертификат по subject
openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1
# -> 9a5ba575
cp burp.pem 9a5ba575.0
adb push 9a5ba575.0 /sdcard/
adb shell su -c 'mount -o rw,remount /system 2>/dev/null || magisk --clone /system/etc/security/cacerts'
adb shell su -c 'cp /sdcard/9a5ba575.0 /system/etc/security/cacerts/ && chmod 644 /system/etc/security/cacerts/9a5ba575.0'
adb reboot
```

На Android 14+ системный раздел read-only — используйте Magisk-модуль `cert-fix` или `movecert`.

## Cleartext-политика как находка

`cleartextTrafficPermitted="true"` для домена означает, что трафик идёт по HTTP. Это находка (перехват, MITM, инъекция) и удобный вектор: можно подменить ответ без всякого TLS. Проверяйте также `<domain>` с `includeSubdomains` — поддомены могут быть забыты.

## Config-level pinning (`<pin-set>`)

```xml
<domain-config>
  <domain includeSubdomains="true">api.target.com</domain>
  <pin-set expiration="2026-01-01">
    <pin digest="SHA-256">AAAA...=</pin>
    <pin digest="SHA-256">BBBB...=</pin>
  </pin-set>
</domain-config>
```

`pin-set` реализуется фреймворком (Conscrypt) — обход через Frida-хук проверки pin или патч конфига. Истёкший `expiration` означает, что pinning отключён — тоже полезная деталь.

## Частые ошибки

- **Не найти NSC**: путь указан в манифесте; ищите `networkSecurityConfig`.
- **Забыть про `debug-overrides`**: в debug-сборке user-CA доверяется, в релизе — нет; не делайте вывод по debug.
- **Патч без подписи**: после `apktool b` обязательны `zipalign` + `apksigner`.
- **`/system` read-only**: используйте Magisk-модуль вместо ручного монтирования.
- **Игнорировать `<pin-set>`**: config-pinning не виден в коде, только в XML.
- **Не проверить поддомены**: `includeSubdomains=true` расширяет политику.

## Что дальше / решение

Сначала прочитайте NSC. Если user-CA разрешён — MITM тривиален. Если нет — системный CA (root) или патч/Frida. Если есть `pin-set` — хукайте. Свяжите с `mobile-ssl-pinning`, `mobile-emulator-detection`, `mobile-mitm-advanced`. Рекомендация в отчёте: `cleartextTrafficPermitted=false`, `trust-anchors` только system, актуальный `pin-set`.

## Справочная таблица

| Тег | Значение | Риск |
|-----|----------|------|
| certificates src=user | доверие пользовательским CA | MITM возможен |
| cleartextTrafficPermitted=true | HTTP разрешён | перехват/подмена |
| debug-overrides | user-CA в debug | утечка конфигурации |
| pin-set | config-pinning | нужен обход |
| domain includeSubdomains | политика на поддомены | расширение |

| Обход | Когда |
|-------|-------|
| системный CA | NSC доверяет system, есть root |
| патч NSC | нет root, можно перепаковать |
| Frida-хук | нельзя менять APK |

## Полный разбор тегов NSC

Разберём каждый тег и его влияние на тестирование.

**`<base-config>`** — дефолт для всех соединений. Атрибут `cleartextTrafficPermitted` (true/false) определяет HTTP-политику. Внутри — `<trust-anchors>`.

**`<domain-config>`** — переопределение для конкретных доменов (`<domain>`). Часто содержит исключения, которые и есть находки: cleartext для legacy-домена, доверие user-CA.

**`<trust-anchors>`** — какие CA доверенные: `<certificates src="system"/>`, `src="user"/>`, `src="system,user"/>`. Только `system` = MITM без обхода невозможен.

**`<pin-set>`** — pinning на уровне фреймворка (Conscrypt). Атрибут `expiration` (дата) — после неё pinning отключается (важная деталь для теста).

**`<debug-overrides>`** — применяется только к debuggable-сборкам; обычно добавляет `user`-CA. В debug MITM проходит, в release — нет.

```bash
# найти и распарсить
apktool d app.apk -o s 2>/dev/null
f=$(grep -o 'network_security_config' s/AndroidManifest.xml | head -1)
cat s/res/xml/network_security_config.xml 2>/dev/null
```

## NSC + pinning: комбинированная защита

Продвинутая защита сочетает NSC и pinning:

```xml
<domain-config>
  <domain includeSubdomains="true">api.target.com</domain>
  <trust-anchors><certificates src="system"/></trust-anchors>
  <pin-set expiration="2027-01-01">
    <pin digest="SHA-256">AAAA...=</pin>
  </pin-set>
</domain-config>
```

Здесь недостаточно системного CA — нужен и обход pinning. Порядок: (1) NSC доверяет только system → положить системный CA; (2) есть `pin-set` → хук проверки pin; (3) в коде может быть ещё один pinning → общий Frida-обход.

## Автоматический анализ NSC

Скрипт извлекает политику из всех APK в папке:

```bash
for apk in *.apk; do
  d=$(mktemp -d)
  apktool d -f -s "$apk" -o "$d" >/dev/null 2>&1
  nsc=$(grep -o 'res/xml/[a-z_]*\.xml' "$d/AndroidManifest.xml" 2>/dev/null | head -1)
  [ -n "$nsc" ] && { echo "== $apk =="; grep -oE 'cleartextTrafficPermitted="[^"]*"|src="[^"]*"|expiration="[^"]*"' "$d/$nsc"; }
  rm -rf "$d"
done
```

Так быстро выявляются приложения с cleartext или доверием user-CA.

## Кейс: downgrade на cleartext

Дано: NSC разрешает cleartext для `legacy.target.com`.

```bash
# 1. Подтверждаем политику
grep -A3 'legacy.target.com' res/xml/network_security_config.xml
# 2. Заворачиваем трафик (transparent proxy) и наблюдаем HTTP в открытом виде
mitmproxy --mode transparent -p 8080
# 3. Меняем ответ (например, токен/цену) — приложение принимает без проверки целостности
```

Находка: чувствительный трафик по HTTP — перехват и подмена. Severity зависит от данных (аутентификация/платежи = High/Critical).

## Проверка и рекомендации

| Проблема | Рекомендация |
|----------|--------------|
| cleartext=true | запретить, использовать HTTPS |
| trust user-CA | только system |
| debug-overrides | не влияет на release, но проверяйте сборки |
| истёкший pin-set | обновить/убрать |
| нет pin-set | добавить для API-доменов |

Сквозной чек-лист: прочитать NSC → зафиксировать политику → проверить достижимость MITM → при наличии pin-set проверить обход → оформить находки. NSC — «второй эшелон» после pinning, и его ошибки часто дают быстрые находки.

## Практикум: разбор NSC вручную

Возьмём реальный NSC и разберём его по частям.

```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors><certificates src="system"/></trust-anchors>
  </base-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">cdn.target.com</domain>
  </domain-config>
  <debug-overrides>
    <trust-anchors><certificates src="user"/></trust-anchors>
  </debug-overrides>
</network-security-config>
```

Вывод: базово MITM невозможен (только system-анкоры), но `cdn.target.com` разрешает cleartext — трафик к CDN идёт по HTTP. В debug-сборке user-CA доверяется. Действия тестировщика: (1) для релиза — системный CA или патч NSC; (2) проверить, что отдаёт CDN по HTTP (может ли быть подмена контента); (3) не делать выводы по debug-сборке.

Патч NSC для теста: добавить `<certificates src="user"/>` в `base-config`, пересобрать, подписать, установить. Проверка результата — Burp начинает видеть трафик.

## Продвинутый анализ: NSC в разных сборках и автоматизация

NSC может отличаться между сборками (debug/release, разные flavor). Проверяйте каждую доступную сборку: то, что доверяет user-CA в debug, может быть строгим в release. Иногда в release NSC вообще отсутствует, и применяется дефолт Android (на Android 7+ — только system-анкоры). Отсутствие NSC — тоже вывод: поведение определяется платформой.

Автоматизируйте извлечение политики из множества APK. Скрипт распаковывает каждый APK, находит ссылку на NSC в манифесте, печатает релевантные атрибуты (cleartext, src, expiration). Это позволяет быстро сравнить приложения и найти слабые конфигурации в портфеле.

Отдельно проверяйте `pin-set`: его наличие означает config-level pinning. Если `expiration` в прошлом — pinning отключён (находка/упрощение теста). Если дата в будущем — нужен обход. Иногда pin-set содержит только один pin (не backup) — риск потери доступа при ротации сертификата, но для теста это не важно.

## Комбинированный обход

Порядок обхода доверия: (1) если NSC доверяет user — просто установите Burp CA; (2) если только system — положите CA в системное хранилище (root) или патчьте NSC; (3) если есть pin-set — обойдите pinning (Frida); (4) если в коде ещё один pinning — общий обход. На каждом шаге проверяйте, виден ли трафик, чтобы не делать лишнего.

## Что писать в отчёте

Для каждого приложения: политика NSC (cleartext/trust/pin), достижимость MITM, найденные слабости (cleartext, user-CA, истёкший pin), рекомендации (запрет cleartext, только system-анкоры, актуальный pin-set с backup-пином). NSC — второй эшелон после pinning, и его ошибки часто дают быстрые находки.

## Практический пример скрипта

Скрипт проходит по всем APK и выводит сводку по NSC — это экономит время при аудите портфеля приложений и сразу показывает, где MITM возможен без обхода, а где нужен системный CA или патч.

## Квиз

```quiz
- question: "Почему пользовательский CA не работает при `trust-anchors → system`?"
  options:
    - "Приложение доверяет только системным CA"
    - "CA слишком большой"
    - "Android блокирует Burp"
    - "Нужен HTTP/2"
  answer: 0
- question: "Что означает `cleartextTrafficPermitted=true` для домена?"
  options:
    - "Трафик домена может идти по HTTP без шифрования"
    - "Домен зашифрован"
    - "Домен использует pinning"
    - "Домен только для debug"
  answer: 0
- question: "Что такое `pin-set` в NSC?"
  options:
    - "Pinning на уровне конфига (Conscrypt)"
    - "Список портов"
    - "Разрешения"
    - "Сертификат разработчика"
  answer: 0
- question: "Как положить CA в системное хранилище?"
  options:
    - "Скопировать хэш-именованный файл в /system/etc/security/cacerts (root)"
    - "Установить как профиль"
    - "Добавить в Info.plist"
    - "Загрузить в Keychain"
  answer: 0
- question: "Что важно проверить в `<domain-config>`?"
  options:
    - "includeSubdomains и cleartext-исключения"
    - "Версию Burp"
    - "Размер APK"
    - "Подпись"
  answer: 0
```

## Где пригодится

- **Пентест Android:** первый барьер для MITM.
- **Bug bounty:** cleartext и слабый trust как находки.
- **Анализ трафика:** понимание политики доверия.
- **CTF:** Mobile-задачи с сетью.
