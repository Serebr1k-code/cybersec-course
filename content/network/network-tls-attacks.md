---
id: network-tls-attacks
title: "Атаки на TLS: downgrade, Heartbleed, POODLE, BEAST и перебор"
category: network
parent: network-tls-inspection
difficulty: hard
order: 4
tags: [network, tls, ssl, heartbleed, poodle, beast, downgrade]
prerequisites: [network-tls-inspection, crypto-hash-basics]
useful_for:
  - "CTF Network/Crypto (TLS-задачи)"
  - "Пентест: аудит TLS-конфигураций"
  - "Работа: безопасная настройка TLS"
estimated_minutes: 55
summary: "Классические атаки на TLS/SSL: даунгрейд версий и шифров, Heartbleed, POODLE, BEAST, перебор параметров — и как защититься."
---
TLS защищает трафик, но его **история** полна атак — от даунгрейда до чтения памяти сервера. Даже сегодня слабая конфигурация (старые версии, экспортные шифры, отсутствие forward secrecy) делает соединение уязвимым. Урок опирается на [`network-tls-inspection`](network-tls-inspection) и [`crypto-hash-basics`](crypto-hash-basics).

## Классы атак

- **Даунгрейд** — принуждение к слабой версии/шифру (SSLv3, EXPORT, RC4).
- **Padding oracle** — POODLE, Lucky13, BEAST (CBC).
- **Утечка памяти** — Heartbleed.
- **Слабые параметры** — короткий RSA/DH, повторное использование nonce (RC4).
- **Реализационные** — некорректная проверка сертификата, отсутствие HSTS.
- **Атаки на доверие** — self-signed, отключённый verify, MITM.

## Heartbleed (CVE-2014-0160)

Уязвимость в расширении **heartbeat** OpenSSL: клиент присылает «heartbeat» с заявленной длиной больше реальной, сервер отвечает **содержимым своей памяти** (ключи, пароли, сессии).

```bash
# Проверка уязвимости
nmap -p443 --script ssl-heartbleed 10.0.0.5
# Или готовый PoC (аккуратно: чтение памяти)
python3 heartbleed.py 10.0.0.5 -p 443
# Wireshark может показать heartbeat-пакеты
tshark -r cap.pcap -Y 'ssl.record.content_type==24'
```

Защита: обновить OpenSSL; отключить heartbeat; TLS 1.3.

## POODLE, BEAST, Lucky13, RC4

- **POODLE** (SSLv3 + CBC): padding oracle, расшифровывает байт за байтом. Митигация — отключить SSLv3 (и TLS 1.0/1.1).
- **BEAST** (TLS 1.0 + CBC): атака на IV в CBC. Митигация — TLS 1.1+ (явный IV) или 1.2+ AEAD.
- **Lucky13** — timing на CBC-MAC. Митигация — AEAD (GCM/ChaCha20).
- **CRIME/BREACH** — сжатие (TLS-level/HTTP) + MITM. Митигация — отключить TLS-сжатие, не сжимать секреты.
- **RC4** — статистические атаки (Bar-Mitzvah, RC4 NOMORE). Митигация — убрать RC4.

## Инструменты и команды

```bash
# Комплексный аудит конфигурации
testssl.sh --severity HIGH https://10.0.0.5
testssl.sh --protocols --ciphers --vulnerable https://10.0.0.5
# Альтернатива: sslscan
sslscan --no-failed 10.0.0.5:443
# NSE-скрипты
nmap -p443 --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle 10.0.0.5
nmap -p443 --script ssl-dh-params 10.0.0.5        # Logjam
nmap -p443 --script ssl-known-key 10.0.0.5
# Ручная проверка версий/шифров
openssl s_client -connect 10.0.0.5:443 -tls1_2 </dev/null 2>&1 | grep -iE 'protocol|cipher'
openssl s_client -connect 10.0.0.5:443 -ssl3 </dev/null 2>&1 | head
# Проверка сертификата
openssl s_client -connect 10.0.0.5:443 -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -text
```

## Разобранный пример: аудит TLS-конфигурации

```bash
# 1. Полный аудит
testssl.sh --vulnerable --protocols --ciphers https://10.0.0.5 | tee tls.txt
# 2. Смотрим проблемы
grep -iE 'VULNERABLE|SSLv3|RC4|EXPORT|expired|self-signed' tls.txt
# 3. NSE для деталей
nmap -p443 --script ssl-enum-ciphers 10.0.0.5
# -> TLSv1.0: ciphers CBC+RC4  (плохо)
# -> TLSv1.3: AEAD             (хорошо)
# 4. Heartbleed
nmap -p443 --script ssl-heartbleed 10.0.0.5
# 5. Сертификат
openssl s_client -connect 10.0.0.5:443 </dev/null 2>/dev/null | openssl x509 -noout -dates -subject
# 6. HSTS
curl -sI https://10.0.0.5/ | grep -i strict-transport-security
```

## Атаки на сертификаты и доверие

- **Self-signed / просроченный / неверный CN** — клиент может не проверять.
- **Некорректная проверка** в приложении (отключённый verify) → MITM.
- **CT log** — проверка прозрачности сертификатов (crt.sh).
- **HSTS** — защита от SSL-strip (но только после первого визита).
- **OCSP stapling** — статус отзыва без отдельного запроса.

```bash
# Проверка HSTS
curl -sI https://example.com/ | grep -i strict-transport-security
# Прозрачность сертификатов
curl -s "https://crt.sh/?q=example.com&output=json" | head
# Полная цепочка
openssl s_client -connect 10.0.0.5:443 -showcerts </dev/null 2>/dev/null | \
  openssl crl2pkcs7 -nocrl -certfile /dev/stdin | openssl pkcs7 -print_certs -noout
# OCSP stapling
openssl s_client -connect 10.0.0.5:443 -status </dev/null 2>/dev/null | grep -i ocsp
```

## Forward secrecy и DH-параметры

- **Forward secrecy (PFS)**: ECDHE/DHE — компрометация долговременного ключа не раскрывает прошлые сессии. Без PFS (статические RSA-шифры) перехваченный трафик можно расшифровать позже.
- **Logjam** — слабые DH-параметры (1024 бит) позволяют предвычислить и расшифровать.
- **Sweet32** — 64-битные блочные шифры (3DES) при больших объёмах.
- **DROWN** — общий ключ с SSLv2-сервисом.

```bash
nmap -p443 --script ssl-dh-params 10.0.0.5     # Logjam/DH-параметры
nmap -p443 --script ssl-enum-ciphers 10.0.0.5 | grep -iE '3DES|RC4|CBC'
# Проверить, есть ли PFS (ECDHE)
openssl s_client -connect 10.0.0.5:443 </dev/null 2>/dev/null | grep -i 'Server Temp Key'
```

## Renegotiation и client-initiated атаки

- **Insecure renegotiation** (CVE-2009-3555) — вставка данных в сессию.
- **Triple Handshake** — атака на renegotiation с клиентскими сертификатами.
- **Client-initiated renegotiation DoS** — истощение CPU сервера.
- Митигация: `SSL_OP_NO_RENEGOTIATION`, ограничение renegotiation.

## Разбор трафика в PCAP

```bash
# Версии/шифры в захвате
tshark -r tls.pcap -Y 'tls.handshake.type==2' -T fields -e tls.handshake.version -e tls.handshake.ciphersuite | head
# SNI (для маршрутизации/фильтрации)
tshark -r tls.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name
# Расшифровка при наличии ключей (SSLKEYLOGFILE)
tshark -r tls.pcap -o tls.keylog_file:keys.log -Y http -T fields -e http.request.uri
# Сертификат сервера из handshake
tshark -r tls.pcap -Y 'tls.handshake.type==11' -V | grep -iE 'CN=|issuer'
```

## Защита

- Только **TLS 1.2/1.3**; отключить SSLv2/v3, TLS 1.0/1.1.
- **AEAD** (AES-GCM, ChaCha20-Poly1305), forward secrecy (ECDHE).
- Современные кривые (X25519, P-256); отключить слабые DH.
- HSTS, OCSP stapling, корректная цепочка, CAA-записи.
- Мониторинг и регулярный аудит (`testssl.sh` в CI).

## Частые ошибки

- **Считать TLS 1.0 «нормальным»** — он уязвим (BEAST и др.).
- **Оставлять RC4/CBC** — статистические атаки.
- **Игнорировать сертификат** — MITM через некорректную проверку.
- **Проверять только «зелёный замочек»** — браузер не покажет downgrade.
- **Забывать про Heartbleed на legacy-устройствах** — старые OpenSSL живут годами.
- **Не проверять DH-параметры** — Logjam.
- **Забывать про сжатие** — CRIME/BREACH.

## Митигации по версиям

| Атака | Митигация |
|-------|-----------|
| BEAST | TLS 1.1+ / AEAD |
| POODLE | отключить SSLv3 |
| Heartbleed | обновить OpenSSL |
| Logjam | DH ≥2048 или ECDHE |
| Sweet32 | убрать 3DES/64-бит блочные |
| CRIME/BREACH | отключить сжатие |
| RC4 | убрать RC4 |
| DROWN | убрать SSLv2 |

## Инструменты для CI

```bash
# Регулярный аудит в пайплайне
testssl.sh --quiet --severity MEDIUM https://target | tee tls_report.txt
# Парсинг для гейта
grep -qE 'VULNERABLE|SSLv3' tls_report.txt && echo "TLS FAIL" && exit 1
```

Автоматизируйте аудит TLS — конфигурации дрейфуют.

## Что дальше / решение

- Нужен **быстрый аудит** → `testssl.sh --vulnerable` + NSE `ssl-enum-ciphers`.
- Нужна **проверка сертификата** → `openssl s_client -showcerts -status`, crt.sh.
- Нужен **разбор трафика** → `tshark` (версии/шифры/SNI), расшифровка через SSLKEYLOGFILE → `network-tls-inspection`.
- Смежные темы → `network-quic` (TLS 1.3 в QUIC), `network-doh-dot` (DNS-over-TLS), `crypto-hash-basics` (криптопримитивы).

Решение (алгоритм): 1) определить версии/шифры; 2) проверить известные уязвимости (Heartbleed/POODLE/Logjam); 3) проверить сертификат/цепочку/HSTS; 4) проверить PFS и DH; 5) устранить слабые места и автоматизировать аудит.

## Атаки на TLS 1.3 и современные риски

TLS 1.3 закрыл большинство старых атак (убрал CBC/RC4/сжатие, обязательный PFS), но появились новые нюансы:

- **0-RTT / early data** — риск replay для неидемпотентных запросов.
- **ECH** — шифрует SNI, снижая видимость middlebox'ов.
- **Проблемы реализации** — некорректная проверка имени/цепочки.
- **Компромисс ключей сессии** — при отсутствии PFS (уже редко) прошлый трафик расшифровывается.
- **Side-channel** — timing/padding в реализациях.

```bash
# Проверить поддержку TLS 1.3 и PFS
openssl s_client -connect 10.0.0.5:443 -tls1_3 </dev/null 2>&1 | grep -iE 'protocol|cipher|server temp key'
# testssl.sh покажет отдельно TLS 1.3
testssl.sh --protocols https://10.0.0.5 | grep -i 'TLS 1.3'
```

## Практический сценарий MITM с отключённым verify

Одна из самых частых реальных проблем — клиент, который **не проверяет** сертификат сервера (в коде `verify=False`, в мобильном приложении `TrustManager` без валидации). Тогда MITM проходит с самоподписанным сертификатом:

```bash
# 1. ARP-spoof/DNS-спуфинг -> трафик жертвы идёт через нас (см. network-mitm)
sudo bettercap -iface eth0 -eval "arp.spoof on; net.sniff on"
# 2. Поднимаем фейковый TLS-сервер с самоподписанным сертификатом
openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 1 -subj "/CN=target"
# 3. Если клиент не проверяет цепочку -> соединение принимается, данные видны
# 4. Ищем в трафике токены/креды
```

Приложение с корректной проверкой отклонит сертификат — это и есть контроль.

## Сравнение сканеров TLS

| Инструмент | Сильные стороны | Вывод |
|------------|-----------------|-------|
| testssl.sh | максимально полный аудит | отчёты, severity |
| sslscan | быстрый, простой | версии/шифры |
| nmap NSE | интеграция со сканом | ssl-* скрипты |
| openssl s_client | ручной контроль | детали handshake |

## Что дальше по TLS

- Нужен **быстрый скан портфеля** → `sslscan`/`nmap ssl-enum-ciphers`.
- Нужен **полный отчёт** → `testssl.sh --vulnerable`.
- Нужен **разбор трафика** → `tshark`, расшифровка через SSLKEYLOGFILE (`network-tls-inspection`).
- Нужна **защита** → TLS 1.2/1.3 + AEAD + HSTS + корректная проверка сертификата на клиентах.

## Ключевые выводы

Большинство «классических» атак на TLS ушли вместе со старыми версиями — но **мисконфигурация** и **некорректная проверка сертификата** остаются главными рисками. Практический аудит начинают с версий/шифров, затем проверяют сертификат/цепочку/HSTS/PFS, и только потом смотрят на исторические уязвимости (Heartbleed/POODLE/Logjam) — они всё ещё встречаются на legacy-устройствах.

## Квиз

```quiz
- question: "Какая атака эксплуатирует heartbeat-расширение OpenSSL?"
  options:
    - "Heartbleed"
    - "POODLE"
    - "BEAST"
    - "Lucky13"
  answer: 0
  explanation: "Heartbleed (CVE-2014-0160) позволяет читать память процесса."
- question: "Какая атака связана с SSLv3 и CBC padding?"
  options:
    - "POODLE"
    - "Heartbleed"
    - "BEAST"
    - "Downgrade"
  answer: 0
  explanation: "POODLE — padding oracle на SSLv3 с CBC."
- question: "Какая версия TLS безопаснее всего сегодня?"
  options:
    - "TLS 1.3"
    - "SSLv3"
    - "TLS 1.0"
    - "TLS 1.1"
  answer: 0
  explanation: "TLS 1.3 — современная версия без устаревших примитивов."
- question: "Что такое даунгрейд-атака на TLS?"
  options:
    - "Принуждение к устаревшей версии/слабому шифру"
    - "Ускорение соединения"
    - "Подмена MAC"
    - "Атака на DNS"
  answer: 0
  explanation: "Атакующий заставляет стороны выбрать слабую версию или шифр."
- question: "Какой инструмент даёт подробный отчёт по TLS-конфигурации?"
  options:
    - "testssl.sh"
    - "macof"
    - "smbmap"
    - "chisel"
  answer: 0
  explanation: "testssl.sh проверяет версии, шифры, уязвимости и сертификаты."
```

## Где пригодится

- **CTF:** задачи на слабую TLS-конфигурацию и старые уязвимости.
- **Пентест:** аудит TLS-конфигураций сервисов.
- **Работа:** безопасная настройка TLS и мониторинг.
- **Compliance:** соответствие требованиям (PCI-DSS и др.).
- **Анализ трафика:** понимание, что видно при MITM.
