---
id: mobile-mitm-burp
title: "MITM мобильного трафика: Burp/mitmproxy и системный CA"
category: mobile
parent: mobile-ssl-pinning
difficulty: medium
order: 1
tags: [mitm, burp, mitmproxy, proxy, ca, android, ios, traffic]
prerequisites: [mobile-ssl-pinning]
useful_for:
  - "CTF Mobile (перехват API-трафика)"
  - "Bug bounty (анализ мобильного API)"
  - "Пентест мобильных приложений"
estimated_minutes: 30
summary: "Пошаговая настройка перехвата мобильного HTTPS: прокси на устройстве, установка CA (пользовательский и системный), настройка Burp/mitmproxy, типичные проблемы."
---
## Зачем перехватывать мобильный трафик

HTTP(S)-трафик мобильного приложения — самый богатый источник находок. Через него видны: API-эндпоинты, параметры и токены, версии и заголовки, ошибки, а иногда — секреты прямо в теле. Перехват (MITM) позволяет **читать и модифицировать** запросы: подменять ответы, менять идентификаторы (IDOR), повторять запросы с другими ролями, обходить клиентские проверки. Это ядро мобильного пентеста: даже идеально защищённый клиент бесполезен, если сервер доверяет его данным.

Ментальная модель: чтобы перехватить HTTPS, нужно встроиться между приложением и сервером — направить приложение на прокси и заставить его доверять сертификату прокси. Два препятствия: (1) на новых Android/iOS пользовательский CA не доверяется приложениям автоматически; (2) certificate pinning заставляет приложение отвергать наш сертификат.

## Схема MITM: прокси, CA, сертификат

```
[App] --HTTPS--> [Proxy (Burp/mitmproxy)] --HTTPS--> [Server]
                     |
               генерирует сертификаты на лету,
               подписанные своим CA
```

Приложение должно доверять CA прокси. Прокси генерирует для каждого домена сертификат, подписанный этим CA. Если приложение доверяет CA — TLS-сессия устанавливается, и прокси видит открытый текст.

## Настройка Burp / mitmproxy

```bash
# Burp: Proxy -> Options -> слушать на всех интерфейсах:8080
# mitmproxy (CLI, удобен для скриптов)
mitmproxy -p 8080 --set block_global=false
# или в режиме прозрачного прокси для всего трафика устройства
mitmproxy --mode transparent -p 8080
```

На устройстве указываем прокси: Wi-Fi → Modify network → Proxy → Manual → `<IP хоста>:8080`. На Android можно через `settings put global http_proxy <ip>:8080` (иногда требует root).

## Установка CA: Android (user vs system)

До Android 7 (API 24) пользовательские CA доверялись приложениям. С Android 7+ **user CA не доверяются** приложениям, если в `network_security_config` явно не разрешено. Варианты:

```bash
# 1. Для отлаживаемых приложений: network_security_config с debug-overrides
# 2. Установить CA как системный (нужен root):
#    конвертировать Burp cert в PEM с хэшем имени
openssl x509 -inform DER -in burp.der -out burp.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1)
cp burp.pem $HASH.0
adb root && adb remount
adb push $HASH.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/$HASH.0
# или через Magisk-модуль (systemless)
```

Magisk-модуль `AlwaysTrustUserCerts` / `MagiskTrustUserCerts` монтирует user CA как системные — часто проще всего.

## iOS: доверие профилю CA

```bash
# экспортировать CA из Burp/mitmproxy (.cer/.der)
# передать на устройство (AirDrop, почта, веб) и установить профиль
# Настройки -> Основные -> VPN и управление устройством -> установить профиль
# ЗАТЕМ обязательно: Настройки -> Основные -> Об этом устройстве -> Доверие сертификатам
#   -> включить доверие для CA прокси
```

Второй шаг (Certificate Trust Settings) часто забывают — без него HTTPS не расшифровывается. После — трафик виден в Burp.

## Проблемы: pinning, QUIC, non-HTTP

- **Certificate pinning** — приложение доверяет только «своему» сертификату/ключу. Решение: обход (`mobile-ssl-pinning`, `mobile-tls-pinning-bypass`, `mobile-cert-pinning-deep`), Frida-скрипты или патч APK.
- **QUIC/HTTP3** — идёт по UDP/443, обычный HTTP-прокси его не видит. Решение: отключить QUIC (`iptables` DROP UDP/443) или использовать прокси с поддержкой QUIC.
- **WebSocket** — mitmproxy видит (ws), Burp — частично.
- **Non-HTTP (свой протокол, gRPC)** — нужны плагины/декодеры.
- **mTLS** — приложение предъявляет клиентский сертификат; прокси должен его поддерживать.

## mitmproxy скрипты для модификации

```python
# addons.py — модифицируем запросы/ответы на лету
from mitmproxy import http
def request(flow: http.HTTPFlow):
    if "api.target.example" in flow.request.pretty_host:
        flow.request.headers["X-Debug"] = "1"
        # подменяем идентификатор (тест IDOR)
        if "user_id=" in flow.request.url:
            flow.request.url = flow.request.url.replace("user_id=1", "user_id=2")
def response(flow: http.HTTPFlow):
    # форсируем premium=true в ответе
    if "isPremium" in flow.response.text:
        flow.response.text = flow.response.text.replace('"isPremium":false', '"isPremium":true')
```

```bash
mitmdump -p 8080 -s addons.py
```

Так вы автоматически тестируете IDOR/логику на всем трафике, не правя каждый запрос руками.

## Разобранный пример: от установки CA до находки IDOR

```bash
# 1. прокси + CA
mitmproxy -p 8080
# 2. на Android: установить CA как системный (Magisk-модуль)
# 3. указать прокси на устройстве
# 4. приложение ходит на api.target.example — видим в mitmproxy
GET /v1/orders?user_id=1001 HTTP/1.1
Authorization: Bearer eyJ...
# 5. Repeater/ручной запрос с user_id=1002
$ curl -s -H "Authorization: Bearer eyJ..." "https://api.target.example/v1/orders?user_id=1002"
{"orders":[{"id":5,"item":"...","address":"..."}]}   # чужие заказы -> IDOR!
```

Трафик дал эндпоинт и токен; модификация параметра выявила IDOR/BOLA. Это классический результат MITM.

## Справочная таблица: настройка по платформам

| Платформа | User CA | System CA | Примечание |
|-----------|---------|-----------|------------|
| Android ≤6 | доверяется | — | всё просто |
| Android 7–9 | не доверяется | root/remount | Magisk-модуль |
| Android 10+ | не доверяется | Magisk systemless | + отключить QUIC |
| iOS (jailbreak) | профиль + Trust | — | два шага |
| iOS (без jailbreak) | профиль + Trust | — | pinning мешает |

## Типовые ошибки новичка

- **Забыть доверие CA на iOS.** Установили профиль, но не включили в Certificate Trust Settings → нет расшифровки.
- **Ставить user CA на Android 7+.** Приложение его не увидит; нужен системный (root/Magisk).
- **Не отключить QUIC.** Часть трафика уходит по UDP/443 и «пропадает».
- **Путать pinning с «приложение не ходит».** Сначала убедитесь, что CA доверен, потом снимайте pinning.
- **Править запросы без учёта токена.** Меняя user_id, убедитесь, что токен другого пользователя даёт другой результат (иначе это не IDOR, а валидация).

## Что дальше / решение

Порядок: поднять прокси → установить CA (user для старых, system/Magisk для Android 7+, профиль+Trust для iOS) → проверить, что HTTPS читается → при pinning перейти в `mobile-ssl-pinning`/`mobile-tls-pinning-bypass` → исследовать эндпоинты, тестировать IDOR/BOLA (`mobile-api-bola`), логику и авторизацию. Связанные уроки: `mobile-api-testing`, `mobile-cert-pinning-deep`, `mobile-dynamic-frida`. Решение — когда трафик расшифрован и вы нашли уязвимость серверной логики (или подтвердили её отсутствие).

## Продвинутая настройка: mTLS, gRPC и не-HTTP

Не весь трафик — это простой HTTP/1.1. Разберём частые исключения.

- **mTLS (взаимный TLS):** приложение предъявляет клиентский сертификат, сервер — свой. Прокси должен уметь подставлять клиентский сертификат. В Burp: `Proxy → Options → TLS → Client TLS certificates`. В mitmproxy: `--set client_certs=/path`. Без этого handshake падает.
- **gRPC:** идёт поверх HTTP/2 с бинарными protobuf-сообщениями. mitmproxy показывает поток, но тело нужно декодировать (`.proto`-схема или `grpcurl`). Burp требует расширения. Полезно: `grpcurl -plaintext -d '{}' host:port list`.
- **WebSocket (ws/wss):** mitmproxy умеет показывать кадры (`ws` view); Burp — через `WebSockets history`. Часто используется для чатов/реалтайма, где встречаются IDOR.
- **Собственный бинарный протокол:** если приложение не использует HTTP, прокси бесполезен — нужен реверс протокола и MITM на уровне сокетов (mitmproxy `tcp`-режим + свой парсер).
- **QUIC/HTTP3:** UDP/443. Отключайте на устройстве или проксируйте через инструмент с QUIC-поддержкой; иначе часть запросов «невидима».

Практический приём: перед анализом выясните, какие протоколы использует приложение (`strings` по бинарнику на `grpc`, `ws`, `h2`), и подготовьте прокси заранее.

## Практический чек-лист MITM-сессии

1. Поднять прокси (Burp/mitmproxy), направить на него устройство.
2. Установить и **доверить** CA (Android: system/Magisk; iOS: профиль + Certificate Trust Settings).
3. Отключить QUIC, если приложение его использует.
4. Проверить, что HTTPS читается (запрос к `https://example.com`).
5. Если нет — снять pinning (`mobile-ssl-pinning`) и повторить.
6. Пройти ключевые сценарии приложения, собрать эндпоинты.
7. Тестировать IDOR/BOLA: менять идентификаторы, роли, токены (`mobile-api-bola`).
8. Автоматизировать повторяющееся через mitmproxy-скрипты; сохранять находки в отчёт.

## Квиз

```quiz
- question: "Почему пользовательский CA не работает на Android 7+?"
  options:
    - "Приложения по умолчанию доверяют только системным CA"
    - "CA нельзя установить"
    - "Прокси запрещён"
    - "TLS отключён"
  answer: 0
  explanation: "С Android 7 user-CA игнорируется приложениями без явной настройки."
- question: "Где прописать прокси на Android через adb?"
  options:
    - "settings put global http_proxy host:port"
    - "pm install proxy"
    - "am start proxy"
    - "dumpsys proxy"
  answer: 0
  explanation: "Глобальная настройка http_proxy направляет трафик на прокси."
- question: "Что нужно сделать на iOS после установки CA?"
  options:
    - "Доверять ему в Certificate Trust Settings"
    - "Перезагрузить"
    - "Удалить профиль"
    - "Сменить язык"
  answer: 0
  explanation: "Без явного доверия профиль CA не принимается."
- question: "Что делать, если приложение игнорирует прокси?"
  options:
    - "Перехватывать через VPN/iptables (invisible proxy)"
    - "Удалить приложение"
    - "Сменить Wi-Fi"
    - "Отключить TLS"
  answer: 0
  explanation: "Сетевой перехват на уровне VPN обходит игнорирование прокси."
- question: "Какой инструмент удобен для headless-перехвата и скриптов?"
  options:
    - "mitmproxy (mitmdump)"
    - "jadx"
    - "apktool"
    - "frida"
  answer: 0
  explanation: "mitmproxy поддерживает скрипты и запись потоков."
```

## Где пригодится

- **CTF Mobile:** перехват API для поиска флага/токена.
- **Bug bounty:** анализ мобильного API.
- **Пентест:** базовый этап тестирования трафика.
- **Работа:** аудит сетевого взаимодействия клиента.
