---
id: mobile-hardcoded-secrets
title: "Зашитые секреты: охота за API-ключами и токенами в APK"
category: mobile
parent: mobile-static-hardening
difficulty: easy
order: 1
tags: [android, secrets, api-key, strings, trufflehog, gitleaks, static-analysis]
prerequisites: [mobile-static-analysis]
useful_for:
  - "CTF Mobile (секрет/флаг в ресурсах)"
  - "Bug bounty (утечка API-ключей)"
  - "Пентест мобильных приложений"
estimated_minutes: 25
summary: "Как быстро находить зашитые в APK ключи, токены, пароли и внутренние URL: strings, ресурсы, BuildConfig, секрет-сканеры."
---
## Почему зашитые секреты — реальная находка

Секрет в мобильном клиенте — не «теоретическая» проблема. Всё, что попадает в APK/IPA, доступно любому, кто скачал приложение. API-ключи облачных сервисов, токены Firebase, пароли к внутренним сервисам, ключи шифрования — всё это извлекается декомпиляцией за минуты и часто даёт прямой доступ к данным или инфраструктуре. В bug bounty утечка рабочего ключа — это находка с высоким impact, потому что она обходит всю клиентскую логику и серверную авторизацию (ключ уже «легитимен»).

Важно различать: **не все ключи равны**. Публичный Firebase API key (используется в URL) сам по себе не секрет, но если правила БД открыты — это критично. AWS/Stripe/Google server keys — почти всегда настоящие секреты. Поэтому после находки обязательна **валидация**.

## Где искать секреты в APK

- **`classes*.dex`** — код и строковые константы.
- **`resources.arsc` / `res/values/strings.xml`** — строки ресурсов (часто там API-ключи).
- **`assets/`** — конфиги, JS-бандлы, JSON, `.env`.
- **`res/raw/`** — файлы «как есть».
- **`lib/*/lib*.so`** — нативные строки.
- **`AndroidManifest.xml`** — meta-data (напр. `com.google.android.geo.API_KEY`).
- **`META-INF/`** — подпись, иногда оставшиеся файлы.

## Инструменты и команды

```bash
# 1. быстрый автоматический поиск
pip install apkleaks
apkleaks -f app.apk -o apkleaks.txt

# 2. распаковка и grep по всему
unzip app.apk -d apk
grep -rInE "api[_-]?key|secret|token|password|passwd|Bearer|Authorization" apk/ | head -40

# 3. строки из нативных библиотек
for so in apk/lib/arm64-v8a/*.so; do strings -n 6 "$so"; done | grep -iE "key|secret|token" | head

# 4. entropy-поиск по DEX (высокая энтропия = возможный ключ)
trufflehog filesystem apk/ --only-verified 2>/dev/null

# 5. MobSF
# в отчёте секция "Hardcoded Secrets" уже собрана
```

## Регулярки для типовых ключей

```bash
# Google API key
grep -rInE "AIza[0-9A-Za-z_-]{35}" apk/
# AWS Access Key / Secret
grep -rInE "AKIA[0-9A-Z]{16}" apk/
grep -rInE "aws_secret_access_key['\"= :]+[0-9A-Za-z/+=]{40}" apk/
# Firebase URL / database
grep -rInE "https://[a-z0-9-]+\.firebaseio\.com" apk/
grep -rInE "https://[a-z0-9-]+\.firebaseapp\.com" apk/
# JWT
grep -rInE "eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+" apk/
# Stripe
grep -rInE "(sk|pk)_(live|test)_[0-9A-Za-z]{24,}" apk/
# приватные ключи
grep -rIn "BEGIN RSA PRIVATE KEY\|BEGIN PRIVATE KEY" apk/
# Slack / Sendgrid / Twilio
grep -rInE "xox[baprs]-[0-9A-Za-z-]+" apk/
grep -rInE "SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}" apk/
```

## Entropy-поиск

Длинные случайные строки (ключи) отличаются высокой энтропией. `trufflehog`/`gitleaks`/`detect-secrets` применяют это правило. Простой скрипт на Python:

```python
import math, re
def entropy(s):
    if not s: return 0
    return -sum((s.count(c)/len(s))*math.log2(s.count(c)/len(s)) for c in set(s))
text = open('apk/classes.dex','rb').read().decode('latin-1')
for m in re.finditer(r'[A-Za-z0-9+/=_\-]{20,}', text):
    if entropy(m.group()) > 4.0:
        print(m.group())
```

Порог ~4.0 отсекает обычный текст и оставляет похожее на ключи. Комбинируйте с регулярками — так меньше ложных срабатываний.

## Секреты в нативном коде

Строки в `.so` бывают разбиты/обфусцированы. Ищите через `strings` с разными кодировками и через реверс JNI-функций.

```bash
strings -n 5 lib/arm64-v8a/libnative-lib.so | grep -iE "http|key|secret|token"
# обфускация: строки собираются по частям — ищите конкатенации в дизассемблере
r2 -A libnative-lib.so -c 'izz~key' -q
```

Если строки шифруются и расшифровываются в рантайме — ставьте Frida-хук на функцию расшифровки (`mobile-frida-scripting`) или на `strcmp`/`memcpy` и логируйте.

## Секреты в сторонних SDK

Часть секретов принадлежит сторонним SDK (аналитика, реклама, crash-reporting). Иногда это **ключи самого приложения** для этих сервисов (напр. Firebase, Google Maps) — они валидны и их стоит проверить. Иногда — общие ключи SDK, которые не являются находкой. Различайте: если ключ даёт доступ к данным конкретного приложения (Firebase с открытыми правилами) — это находка; если это публичный ключ карт — нет.

## Разобранный пример: утечка Firebase

```bash
$ grep -rInE "firebaseio\.com" apk/ | head
apk/res/values/strings.xml:  <string name="firebase_url">https://acme-prod.firebaseio.com</string>
apk/classes.dex: (строка) https://acme-prod.firebaseio.com

# проверяем правила чтения (REST)
$ curl -s "https://acme-prod.firebaseio.com/.json"
{"users":{"1":{"email":"admin@acme.io","token":"eyJ..."}}}   # открытое чтение!
```

Найдена база с открытым чтением: утекли email и токены пользователей. Impact — критический. Исправление — закрыть правила Firebase; в отчёте это формулируется как «открытая БД, доступная без аутентификации».

## Валидация найденного

Не сообщайте «ключ найден», не проверив его:

- **Google API key** — проверьте, какие API включены (Maps/Places могут быть ограничены по пакету/подписи).
- **AWS** — `aws sts get-caller-identity` с найденными кредами покажет, валидны ли они и какие права.
- **Firebase** — `curl .../.json` проверяет открытость правил.
- **Stripe** — тестовые (`test`) ключи не являются находкой, `live` — да.
- **JWT** — декодируйте (`jwt_analyze`) и проверьте срок/подпись.

Ложные срабатывания: ключи SDK, примеры в документации, отозванные ключи, публичные по дизайну.

## Справочная таблица: где и что искать

| Источник | Что | Инструмент |
|----------|-----|-----------|
| `classes.dex` | строки/константы | `grep`, `strings`, MobSF |
| `res/values/strings.xml` | API-ключи | `grep`, apktool |
| `assets/` | JS/JSON/`.env` | `grep`, hermes-dec |
| `lib/*.so` | нативные секреты | `strings`, r2 |
| `AndroidManifest.xml` | meta-data ключи | apktool, aapt |
| весь APK | авто-поиск | apkleaks, trufflehog, MobSF |

## Типовые ошибки новичка

- **Искать только в DEX.** Ресурсы и `assets/` часто содержат больше.
- **Не проверять валидность.** Половина найденного — публичные/тестовые ключи.
- **Игнорировать натив.** Секреты в `.so` легко пропустить через обычный `grep`.
- **Забыть про обфускацию.** После R8 строки могут быть переставлены; тестируйте несколько сборок.
- **Публиковать сырые секреты.** В отчёте маскируйте (`sk_live_51H...`), чтобы не слить их публично.

## Что дальше / решение

Нашли кандидат — валидируйте его (какой сервис, какие права, реальный ли). Затем оцените impact: доступ к данным, к инфраструктуре, к платежам. Связанные уроки: `mobile-static-analysis` (полный статический разбор), `mobile-firebase` (мисконфиги Firebase), `mobile-hardcoded-secrets` → `mobile-crypto-misuse` (если найден ключ шифрования). Решение — когда секрет подтверждён (не ложное срабатывание) и вы понимаете его impact; для отчёта достаточно воспроизводимого PoC доступа.

## Готовый скрипт для триажа секретов

Соберите распаковку и поиск в один проход:

```bash
#!/usr/bin/env bash
# secret-scan.sh — быстрый поиск секретов в APK
APK="$1"; OUT="$(mktemp -d)"
unzip -q "$APK" -d "$OUT"
echo "=== strings.xml / manifest ==="
grep -rInE "AIza|AKIA|firebaseio|sk_live|xox[baprs]-|SG\.|eyJ" "$OUT" | head -30
echo "=== native strings ==="
for so in "$OUT"/lib/*/*.so; do [ -f "$so" ] && strings -n 6 "$so"; done \
  | grep -iE "api[_-]?key|secret|token|password" | sort -u | head -20
echo "=== assets ==="
find "$OUT/assets" -type f 2>/dev/null | while read -r f; do
  file "$f" | grep -q text && grep -InE "key|secret|token" "$f" | head
done
echo "=== high-entropy (dex) ==="
for d in "$OUT"/*.dex; do strings -n 20 "$d"; done | sort -u | head -20
```

Такой скрипт прогоняет все слои (ресурсы, native, assets, DEX) и выдаёт кандидатов для ручной валидации. Дополните его `apkleaks` и разделом «Hardcoded Secrets» из MobSF — три источника вместе почти не пропускают секреты.

## Квиз

```quiz
- question: "Почему секрет в клиенте считается скомпрометированным?"
  options:
    - "Всё, что попало в APK/IPA, можно извлечь"
    - "Он шифруется"
    - "Он недоступен без root"
    - "Он меняется каждый день"
  answer: 0
  explanation: "Клиент нельзя считать доверенным хранилищем секретов."
- question: "Какая команда ищет Google API-ключи в DEX?"
  options:
    - "strings classes.dex | grep AIza"
    - "adb install"
    - "apktool b"
    - "zipalign"
  answer: 0
  explanation: "Строки DEX содержат ключи вида AIza..."
- question: "Какой сканер специализирован на APK?"
  options:
    - "apkleaks"
    - "nmap"
    - "sqlmap"
    - "hydra"
  answer: 0
  explanation: "apkleaks нацелен на извлечение секретов из APK."
- question: "Где ещё искать секреты кроме classes.dex?"
  options:
    - "В .so, ассетах, ресурсах и BuildConfig"
    - "Только в AndroidManifest.xml"
    - "Только в подписи"
    - "Только в логах"
  answer: 0
  explanation: "Секреты прячут в нативных библиотеках, ресурсах и ассетах."
- question: "Почему OAuth client_secret в публичном клиенте — плохо?"
  options:
    - "Он не может храниться в секрете на клиенте"
    - "Он ускоряет приложение"
    - "Он нужен для TLS"
    - "Он шифрует данные"
  answer: 0
  explanation: "Публичные клиенты должны использовать PKCE без client_secret."
```

## Где пригодится

- **CTF Mobile:** секрет/флаг в ресурсах/строках.
- **Bug bounty:** утечка API-ключей — быстрая и частая находка.
- **Пентест:** разведка и доступ к бэкенду.
- **Работа:** ревью секретов перед релизом.
