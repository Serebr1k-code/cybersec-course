---
id: web-tls-certs
title: "TLS, сертификаты и HTTPS-ошибки"
category: web
parent: web-http-basics
difficulty: easy
order: 1
tags: [tls, https, certificate, hsts, mitm, sni]
prerequisites: [web-http-basics]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как работает HTTPS, из чего состоит сертификат, что такое HSTS и какие TLS-ошибки ведут к перехвату трафика."
---

HTTPS — это HTTP внутри TLS-туннеля. TLS даёт три вещи: **шифрование**, **целостность** и **аутентификацию сервера** (через сертификат). Для веб-тестировщика TLS важен потому, что слабая конфигурация или ошибки в сертификатах позволяют перехватывать и подменять трафик, а `-k` в curl, за которым прячутся ошибки проверки, — частая причина «необъяснимых» проблем.

## Теория: рукопожатие и что в сертификате

TLS Handshake (упрощённо, TLS 1.3):

1. Клиент шлёт `ClientHello` со списком поддерживаемых версий/шифров и **SNI** (`Server Name Indication`) — имя запрашиваемого сайта.
2. Сервер отвечает `ServerHello` + **сертификатом** (цепочкой: листовой → промежуточный → корневой).
3. Стороны договариваются о ключах (ECDHE) и переходят к шифрованным записям.

В сертификате важно:

| Поле | Что значит |
|------|-----------|
| Subject / SAN | для каких имён выдан (`CN` устарел, смотрят на `SAN`) |
| Issuer | кто подписал (CA) |
| Not Before / Not After | срок действия |
| Public Key | открытый ключ для проверки подписи |
| Key Usage / EKU | для чего годится (serverAuth и т.д.) |
| Signature Algorithm | SHA-1/MD5 — устаревшие, слабые |

Ошибки, которые ломают доверие: истёкший срок, самоподписанный сертификат, несовпадение имени (hostname mismatch), неизвестный CA, отозванный сертификат (CRL/OCSP), устаревший протокол (SSLv3/TLS1.0) или слабый шифр (RC4, 3DES).

## Теория: HSTS и downgrade

**HSTS (HTTP Strict Transport Security)** — заголовок `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`, который заставляет браузер всегда ходить по HTTPS и не принимать клики по HTTP-ссылкам. Без HSTS первый запрос может уйти по HTTP и быть перехвачен (sslstrip).

**Cookie без `Secure`** шлётся по HTTP → MITM крадёт сессию (см. `web-cookies-sessions`).

**Mixed content:** страница по HTTPS грузит `http://` ресурс — браузер может заблокировать или пометить как небезопасное.

## Инструменты: openssl, curl, sslscan, testssl

Получить сертификат и посмотреть поля:

```bash
echo | openssl s_client -connect target.local:443 -servername target.local 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Полный разбор цепочки и протокола:

```bash
openssl s_client -connect target.local:443 -servername target.local -showcerts </dev/null
```

Проверить, что сертификат валиден (curl вернёт ошибку при проблеме):

```bash
curl -sv https://target.local/ 2>&1 | grep -iE 'SSL|certificate|subject|issuer'
```

Автоматический аудит TLS:

```bash
sslscan target.local:443
# или
testssl.sh --severity HIGH target.local:443
```

`testssl.sh` покажет устаревшие протоколы, слабые шифры, проблемы с сертификатом и отсутствие HSTS.

## Разобранный пример: истёкший сертификат и SNI

Шаг 1. Заходим по IP, минуя DNS:

```bash
curl -sv --resolve target.local:443:203.0.113.10 https://target.local/ 2>&1 | grep -iE 'certificate|expire|verify'
```

Видим: `SSL certificate problem: certificate has expired`. Значит, браузеры покажут предупреждение, а часть клиентов (мобильные приложения) может «пинить» сертификат и сломаться.

Шаг 2. Проверяем виртуальный хостинг через SNI. Один IP может отдавать разные сертификаты по `-servername`:

```bash
echo | openssl s_client -connect 203.0.113.10:443 -servername admin.target.local 2>/dev/null \
  | openssl x509 -noout -subject
```

Если по `admin.target.local` сертификат есть, а DNS этого имени вы не знали — вы обнаружили скрытый виртуальный хост. Это полезно на этапе разведки (ср. `web-recon-fuzzing`).

Шаг 3. Проверяем HSTS и редирект HTTP→HTTPS:

```bash
curl -s -I http://target.local/ | grep -iE '^(location|strict-transport-security)'
```

Если редиректа нет и HSTS отсутствует — первый запрос можно перехватить.

## Разобранный пример: слабые протоколы

```bash
sslscan target.local:443 | grep -iE 'SSLv3|TLSv1\.0|TLSv1\.1|RC4|3DES'
```

Любая строка «Enabled» для SSLv3/TLS1.0/1.1 или RC4/3DES — находка (weak protocol/cipher), обычно Medium. Опишите impact: возможность даунгрейд-атаки и расшифровки.

## Частые ошибки

- **Привыкать к `curl -k`.** `-k` отключает проверку сертификата и прячет реальную проблему. Для теста используйте `-k`, но фиксируйте, что сертификат невалиден.
- **Смотреть только `CN`.** Современные браузеры используют `SAN`; сертификат с `CN=target.local` и пустым SAN может не совпасть.
- **Забывать про SNI.** Без `-servername` вы получите «дефолтный» сертификат и ложное несовпадение имени.
- **Путать TLS-версии.** `TLS 1.2` ещё приемлем, `TLS 1.0/1.1` и `SSLv3` — нет.
- **Игнорировать HSTS-предзагрузку.** Даже с `max-age` без `includeSubDomains` поддомены уязвимы к downgrade.
- **Тестировать только 443.** TLS бывает на 8443, 9443 и других портах (см. результаты сканирования портов).

## Полный разбор: MITM-сценарий и sslstrip (с выводом)

Показываем, как отсутствие HSTS и `Secure` у cookie ведут к перехвату.

Шаг 1. Проверяем HSTS и редирект:

```bash
curl -s -I http://target.local/ | grep -iE '^(location|strict-transport-security)'
# (пусто)   -> ни редиректа, ни HSTS: первый запрос уходит по HTTP
curl -s -I https://target.local/ | grep -iE 'strict-transport-security'
# (пусто)   -> HSTS не включён даже по HTTPS
```

Шаг 2. Проверяем атрибуты cookie:

```bash
curl -s -I https://target.local/login | grep -i 'set-cookie'
# set-cookie: session=abc; Path=/          <- нет Secure, нет HttpOnly, нет SameSite
```

Шаг 3. Сценарий MITM в сети жертвы (свой стенд/авторизованный тест): атакующий отвечает на HTTP-запрос, отдаёт `302` на свой HTTPS-прокси (sslstrip) и проксирует трафик, собирая cookie, ушедшие по HTTP. Поскольку `Secure` не выставлен, cookie отправляется по HTTP и перехватывается.

Шаг 4. Доказательство без реального MITM: покажите, что cookie уходит по HTTP. Используйте OOB-сервер:

```bash
# на нашем сервере: логируем
python3 -m http.server 80
# жертва открывает http://target.local/ (до HSTS) -> cookie уходит; в логе видно Cookie
```

Или проверьте через `--resolve`, что HTTP-запрос с cookie проходит без редиректа:

```bash
curl -s -i http://target.local/ -b 'session=me' --resolve target.local:80:203.0.113.10 | head
```

Если ответ 200 (не 301/302 на HTTPS) — downgrade возможен.

## Reference-таблица: TLS-находки и severity

| Находка | Severity | Impact |
|---------|----------|--------|
| Нет HSTS | Medium | MITM/sslstrip |
| Cookie без `Secure` | Medium | перехват сессии по HTTP |
| SSLv3/TLS1.0/1.1 включены | Medium | downgrade/атаки на протокол |
| Слабый шифр (RC4/3DES/EXPORT) | Medium | расшифровка |
| Истёкший/самоподписанный сертификат | Low–Medium | предупреждения, сломанные клиенты |
| Hostname mismatch | Medium | MITM/путаница |
| SHA-1 подпись сертификата | Low | слабая криптография |
| Нет `includeSubDomains` в HSTS | Low | поддомены уязвимы к downgrade |
| Mixed content | Low–Medium | блокировка/небезопасно |
| Wildcard-сертификат на много доменов | Info | расширяет доверие |

## Certificate Transparency и разведка поддоменов

CT-логи публично фиксируют все выданные сертификаты — это разведка поддоменов и скрытых сервисов:

```bash
curl -s 'https://crt.sh/?q=%25.target.local&output=json' | jq -r '.[].name_value' | sort -u
# admin.target.local
# staging.target.local
# internal-api.target.local
```

Дополнительно: `certspotter`, `censys` (для внешнего периметра). Найденные имена проверяйте DNS-резолвом и SNI-запросом:

```bash
echo | openssl s_client -connect 203.0.113.10:443 -servername internal-api.target.local 2>/dev/null \
  | openssl x509 -noout -subject
```

Часто так вскрываются внутренние панели и dev-среды, доступные по SNI без DNS.

## mTLS, pinning и типичные ошибки приложений

- **mTLS:** клиентский сертификат — проверьте, обязателен ли он, и можно ли обойти (заголовки `X-Client-Cert`, доверие к прокси).
- **Certificate pinning:** мобильные приложения «пинят» сертификат; при проксировании (Burp) запрос падает — обходится Frida (см. `mobile`). Наличие pinning — плюс для приложения, но не для теста; фиксируйте как «hardening».
- **Неправильная проверка хоста:** приложения, доверяющие `X-Forwarded-Host`, могут «сменить» домен (см. `web-host-header`).
- **Самоподписанные сертификаты во внутренней сети:** часто идут в комплекте с отключённой проверкой (`-k`), что расширяет MITM.
- **Устаревший TLS на внутренних портах:** сканируйте не только 443, но и 8443/9443/порты из nmap.

## Что делать дальше / решение

1. **Проверить HSTS** и HTTP→HTTPS редирект.
2. **Проверить атрибуты cookie** (`Secure`/`HttpOnly`/`SameSite`).
3. **Аудит протоколов/шифров** (`sslscan`/`testssl.sh`).
4. **Проверить сертификат** (срок, SAN, CA, подпись).
5. **Разведка через CT-логи** и SNI-виртуалхостинг.
6. **Оценить impact** (MITM/downgrade/перехват) и оформить.
7. **Проверить нестандартные порты** с TLS.

## Инструменты и быстрые команды

```bash
# сертификат и SAN
echo | openssl s_client -connect t:443 -servername t 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# цепочка и протокол
openssl s_client -connect t:443 -servername t -showcerts </dev/null

# HSTS/редирект
curl -s -I http://t/ | grep -iE 'location|strict-transport'

# cookie-атрибуты
curl -s -I https://t/ | grep -i set-cookie

# аудит
sslscan t:443
testssl.sh --severity HIGH t:443

# CT-логи (поддомены)
curl -s 'https://crt.sh/?q=%25.t&output=json' | jq -r '.[].name_value' | sort -u
```

Проверяйте TLS и на нестандартных портах (8443, 9443) — они часто остаются со слабой конфигурацией и вне аудита.

## Итог по TLS-аудиту

Минимальный набор проверок: HSTS + редирект, атрибуты cookie, версии протокола и шифры, валидность/срок/SAN сертификата, нестандартные порты. Каждую находку привязывайте к impact: downgrade/MITM/перехват сессии. Отсутствие `Secure` у сессионной cookie в сочетании с отсутствием HSTS — классическая «средняя» находка, которая в цепочке (публичный Wi-Fi) становится высокой.

## Замечание по сканированию TLS

Сканеры (`sslscan`, `testssl.sh`) проверяют и «информационные» пункты (набор шифров, ALPN, OCSP stapling). Не включайте Info-находки в отчёт как уязвимости — приоритезируйте то, что реально ведёт к перехвату: отсутствие HSTS, отсутствие `Secure` у cookie, устаревшие протоколы/шифры, невалидный сертификат.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что расшифровывается как SNI?"
  options:
    - "Secure Network Interface"
    - "Server Name Indication"
    - "Signed Node Identity"
    - "Session Negotiation Index"
  answer: 1
  explanation: "SNI сообщает серверу, какой виртуальный хост запрашивается."
- question: "Какой заголовок заставляет браузер всегда использовать HTTPS?"
  options:
    - "`Content-Security-Policy`"
    - "`Strict-Transport-Security`"
    - "`X-Frame-Options`"
    - "`Access-Control-Allow-Origin`"
  answer: 1
  explanation: "HSTS (`Strict-Transport-Security`) переводит сайт в режим «только HTTPS»."
- question: "Какое поле сертификата проверяют современные браузеры для соответствия имени?"
  options:
    - "`CN`"
    - "`SAN` (subjectAltName)"
    - "`Issuer`"
    - "`Serial Number`"
  answer: 1
  explanation: "SAN содержит список имён; CN устарел."
- question: "Что означает ошибка `certificate has expired`?"
  options:
    - "Сертификат самоподписан"
    - "Срок действия сертификата истёк"
    - "Неизвестный CA"
    - "Слабый шифр"
  answer: 1
  explanation: "Поле `Not After` в прошлом."
- question: "Зачем в `openssl s_client` указывать `-servername`?"
  options:
    - "Чтобы ускорить handshake"
    - "Чтобы выбрать правильный виртуальный хост через SNI"
    - "Чтобы отключить проверку сертификата"
    - "Чтобы включить HSTS"
  answer: 1
  explanation: "Без SNI сервер может отдать сертификат по умолчанию."
```

## Где пригодится

- **CTF (Web):** SNI-виртуалхостинг часто скрывает «секретный» поддомен с флагом; слабый TLS — часть задач на крипто-конфиг.
- **Bug bounty:** отсутствие HSTS, слабые шифры, истёкшие сертификаты — валидные low/medium находки.
- **Пентест:** аудит TLS — обязательный пункт внешнего сканирования периметра.
- **Работа (SOC/IR):** анализ TLS-сертификатов и SNI помогает в детекте C2-трафика и выявлении фишинговых доменов.
