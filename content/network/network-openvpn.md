---
id: network-openvpn
title: "OpenVPN: анализ протокола, TLS-handshake и типовых мисконфигураций"
category: network
parent: network-vpn
difficulty: medium
order: 3
tags: [network, openvpn, vpn, tls, certificates]
prerequisites: [network-tcpip, network-tls-inspection]
useful_for:
  - "CTF Network (разбор VPN-трафика)"
  - "Пентест: аудит VPN-периметра"
  - "Работа: диагностика и защита VPN-доступа"
estimated_minutes: 50
summary: "Как OpenVPN прячет трафик в TLS/UDP, что видно на проводе и какие ошибки конфигурации ведут к компрометации."
---
OpenVPN — популярный VPN, работающий поверх TLS. Он прячет весь трафик в UDP (по умолчанию 1194) или TCP, используя собственный control-канал и data-канал. Для пентеста важно понимать, что видно при перехвате и какие мисконфигурации открывают доступ. Урок опирается на [`network-tcpip`](network-tcpip) и [`network-tls-inspection`](network-tls-inspection).

## Как устроен OpenVPN

- **Control-канал** — TLS-handshake (обмен ключами, аутентификация).
- **Data-канал** — шифрование полезной нагрузки (AES-GCM/ChaCha20).
- **Транспорт** — UDP/1194 (типично) или TCP/443 (обход фильтров).
- **Аутентификация** — сертификаты (mTLS) + опционально логин/пароль.
- **tls-auth / tls-crypt** — дополнительная защита control-канала (HMAC/шифрование).

## Что видно в трафике

- **UDP/1194** (или нестандартный порт) — первый признак.
- **TLS-handshake**: версия, шифры, размеры.
- **Без tls-crypt** — видны `P_CONTROL`-пакеты OpenVPN (opcode 7/8), можно отличить от обычного TLS.
- **Сертификаты** в handshake (CN, issuer) — если не зашифрованы.

```bash
# Захват
tcpdump -i eth0 -n udp port 1194 -w vpn.pcap
tshark -r vpn.pcap -Y 'openvpn' -T fields -e openvpn.opcode | head
# Сертификаты
tshark -r vpn.pcap -Y 'tls.handshake.type==11' -V | grep -iE 'CN=|issuer'
# Все OpenVPN-пакеты и их opcode
tshark -r vpn.pcap -Y openvpn -T fields -e openvpn.opcode | sort | uniq -c
```

## Инструменты и команды

```bash
# Определить OpenVPN-сервис
nmap -sU -p1194 --script openvpn-info 10.0.0.5
# Проверить конфигурацию клиента
openvpn --config client.ovpn --verb 4
# Извлечь сертификаты из трафика (без tls-crypt)
tshark -r vpn.pcap -Y 'tls.handshake.type==11' -T fields -e tls.handshake.certificate
# Тест на «нет проверки сертификата» (MITM)
#   клиент без verify-x509-name примет поддельный сервер
```

## Разобранный пример: «самоподписанный CA без проверки»

```bash
# Сценарий: у клиента нет verify-x509-name / remote-cert-tls server
# 1. Перехватываем handshake (нет tls-crypt -> виден control)
tshark -r vpn.pcap -Y 'tls.handshake.type==11' -V | grep -i 'CN='
# -> CN=openvpn-server (самоподписанный)
# 2. Если CA утёк или не проверяется — поднимаем свой сервер
#    с сертификатом, подписанным тем же CA
# 3. Клиент подключается к нам -> полный доступ к его трафику
# 4. Далее — MITM/перехват учётных данных внутренних сервисов
```

## Расшифровка и анализ handshake

OpenVPN использует TLS, поэтому при наличии ключей сессию можно расшифровать:

```bash
# Если control-канал без tls-crypt — виден handshake и сертификаты
tshark -r vpn.pcap -Y 'tls.handshake.type==11' -T fields -e tls.handshake.certificate
# Ключи из сессии (для исследования/лаборатории)
tshark -r vpn.pcap -o tls.keylog_file:keys.log
```

Без `tls-crypt` видны opcode `P_CONTROL_HARD_RESET_*` — трафик легко классифицируется как OpenVPN даже на нестандартном порту.

## Типовые мисконфигурации

- **Нет `verify-x509-name`/`remote-cert-tls server`** — MITM-сервер принимается.
- **Утечка `ca.key`** — можно выпустить произвольного клиента.
- **Слабый data-cipher** (BF-CBC, DES) — устаревшее шифрование.
- **Нет `tls-crypt`** — control-канал виден, DoS/фингерпринт.
- **`comp-lzo`** — уязвимость VORACLE (сжатие + MITM).
- **Логин/пароль без сертификата** — перебор.
- **Долгоживущие клиентские сертификаты без CRL** — украденный сертификат работает годами.

## tls-auth vs tls-crypt

| Свойство | tls-auth | tls-crypt |
|----------|----------|-----------|
| Что делает | HMAC control-пакетов | HMAC **и** шифрование control-канала |
| Видны ли opcode | да | нет |
| Защита от DoS | частичная | сильнее |
| Ключ | статический | статический |
| Рекомендация | устаревает | предпочтительно |

## Практика пентеста VPN

- **Определить VPN** по порту и сигнатуре (`nmap -sU -p1194 --script openvpn-info`).
- **Искать конфиги** клиента на скомпрометированных хостах (`.ovpn`, ключи, `auth-user-pass`).
- **Проверять проверку сертификата** (MITM-сервер).
- **Брутить логин/пароль**, если включён `auth-user-pass` (онлайн, малый список!).
- **Не ломать туннель** — VPN часто критичен для бизнеса; согласовывать действия.

## Сравнение VPN-протоколов

| Протокол | Транспорт | Аутентификация | Особенности |
|----------|-----------|----------------|-------------|
| **OpenVPN** | UDP/1194, TCP | сертификаты + опц. пароль | гибкий, TLS-based |
| **WireGuard** | UDP | ключи (Curve25519) | компактный, без сертификатов |
| **IPsec/IKEv2** | UDP/500,4500 | PSK/сертификаты | стандарт, сложнее |
| **PPTP** | TCP/1723 + GRE | MS-CHAPv2 | устаревший, небезопасный |

PPTP и L2TP без IPsec — устаревшие и легко перехватываются (см. `network-routing-wan`).

## Защита

- **tls-crypt** (или tls-auth) для control-канала.
- **verify-x509-name + remote-cert-tls server** на клиентах.
- **AES-256-GCM / ChaCha20-Poly1305**, отключить BF/DES.
- Хранить `ca.key` оффлайн; короткоживущие клиентские сертификаты + CRL.
- Отключить сжатие (или только безопасное).
- Мониторинг подключений, MFA.

## Логи и диагностика

```bash
# verbose-режим клиента
openvpn --config client.ovpn --verb 4
# Проверить, поднялся ли tun-интерфейс
ip addr show tun0
# Маршруты через VPN
ip route | grep tun0
# Статус (управляющий сокет)
openvpn --config client.ovpn --management 127.0.0.1 7505 &
echo "status" | nc 127.0.0.1 7505
```

Типовые ошибки: `AUTH_FAILED` (сертификат/пароль), `TLS handshake failed` (несовпадение крипто), `Cannot open TUN/TAP` (нет прав/модуля).

## Типовой чек-лист конфигурации

- [ ] `tls-crypt`/`tls-auth` включён
- [ ] `remote-cert-tls server` + `verify-x509-name` на клиентах
- [ ] `data-ciphers` = AES-256-GCM/ChaCha20
- [ ] `ca.key` оффлайн, CRL актуален
- [ ] сжатие отключено
- [ ] нестандартный порт/протокол
- [ ] MFA и логирование

## Частые ошибки

- **Считать «VPN = безопасно»** — конфигурация решает.
- **Игнорировать проверку сертификата** — MITM-сервер принимается.
- **Проверять только data-cipher** — control-канал не менее важен.
- **Путать tls-auth и tls-crypt** — первый добавляет HMAC, второй шифрует.
- **Не менять дефолтный порт** — легко обнаружить.
- **Оставлять `comp-lzo`** — VORACLE.

## Что дальше / решение

- Нужно **определить/проанализировать** OpenVPN → `nmap --script openvpn-info`, `tshark -Y openvpn`.
- Нужен **MITM** → проверьте `verify-x509-name`/`remote-cert-tls server`; при отсутствии — поднимайте сервер с тем же CA.
- Нужны **креды** → ищите `.ovpn`/ключи на хостах, проверьте `auth-user-pass` (малый список).
- Нужна **защита** → tls-crypt + проверка сертификата + современные шифры.
- Смежные темы → `network-vpn` (обзор), `network-wireguard` (альтернатива), `network-tls-inspection` (TLS-анализ).

Решение (алгоритм): 1) найти OpenVPN по порту/сигнатуре; 2) проверить наличие tls-crypt (видны ли opcode); 3) извлечь сертификаты; 4) проверить проверку сертификата на клиенте (MITM); 5) поиск конфигов/кредов; 6) рекомендации по защите.

## Разбор OpenVPN-пакетов по opcode

OpenVPN кодирует тип пакета в **opcode** (первые байты). Без `tls-crypt` они видны и позволяют классифицировать трафик даже на нестандартном порту:

- `P_CONTROL_HARD_RESET_CLIENT_V2/V3` — начало сессии (клиент).
- `P_CONTROL_HARD_RESET_SERVER_V2/V3` — ответ сервера.
- `P_CONTROL_SOFT_RESET`, `P_CONTROL_V1` — управляющие.
- `P_ACK_V1` — подтверждения.
- `P_DATA_V1/V2` — данные (шифрованные).

```bash
# Распределение opcode в захвате
tshark -r vpn.pcap -Y openvpn -T fields -e openvpn.opcode | sort | uniq -c
# Показать сессию
tshark -r vpn.pcap -Y 'openvpn.opcode' -V | head -60
```

Если видите только `P_DATA_V*` (без control) — вероятно, включён `tls-crypt` и control-канал зашифрован.

## Практический сценарий: MITM через утёкший CA

Если `ca.key` утёк (лежит на веб-сервере, в git, в бэкапе), можно выпустить **своего клиента** и/или поднять сервер, которому доверяет клиент:

```bash
# 1. Находим утёкший CA (git/веб/бэкап)
#    ca.crt + ca.key -> можно подписывать сертификаты
# 2. Выпускаем серверный сертификат, подписанный тем же CA
openssl req -new -key srv.key -out srv.csr -subj "/CN=openvpn-server"
openssl x509 -req -in srv.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out srv.crt -days 30
# 3. Поднимаем свой OpenVPN-сервер; клиент (без verify-x509-name) подключается
# 4. Весь трафик клиента идёт через нас -> MITM внутренних сервисов
```

Даже без `ca.key` клиент без `remote-cert-tls server` примет **любой** сертификат — достаточно самоподписанного.

## Проверка конфигурации автоматизацией

```bash
# Грубый аудит .ovpn на опасные директивы
grep -Ei 'verify-x509-name|remote-cert-tls|tls-crypt|tls-auth|comp-lzo|cipher|data-ciphers' client.ovpn
# Проверка, что клиент проверяет сервер
grep -qi 'remote-cert-tls server' client.ovpn || echo "MISSING remote-cert-tls server"
grep -qi 'verify-x509-name' client.ovpn || echo "MISSING verify-x509-name"
# Проверка, что control-канал защищён
grep -qi 'tls-crypt' client.ovpn || echo "no tls-crypt (control visible)"
```

Этот чек можно встроить в аудит конфигураций VPN на хостах.

## Что дальше по OpenVPN

- Нужно **определить** сервис → `nmap --script openvpn-info`, opcode в `tshark`.
- Нужен **MITM** → проверьте `remote-cert-tls server`/`verify-x509-name`; при утечке `ca.key` — выпускайте сертификат.
- Нужны **креды** → ищите `.ovpn`/ключи/`auth-user-pass` на хостах, малый перебор.
- Нужна **защита** → tls-crypt + проверка сертификата + современные шифры + CRL.
- Смежные темы → `network-vpn`, `network-wireguard`, `network-tls-inspection`.

## Ключевые выводы

OpenVPN безопасен ровно настолько, насколько верна конфигурация. **Control-канал** без `tls-crypt` выдаёт протокол и уязвим к DoS; клиент без проверки сертификата принимает MITM-сервер; утёкший `ca.key` равносилен полной компрометации. Для пентеста важны: определение сервиса, поиск клиентских конфигов/ключей и проверка устойчивости к MITM. Для защиты — `tls-crypt`, `remote-cert-tls server`/`verify-x509-name`, современные шифры и оффлайн-хранение `ca.key`.

## Квиз

```quiz
- question: "Какой порт OpenVPN используется по умолчанию?"
  options:
    - "TCP/443"
    - "UDP/1194"
    - "UDP/51820"
    - "TCP/1723"
  answer: 1
  explanation: "Стандартный порт OpenVPN — UDP/1194 (можно сменить или использовать TCP)."
- question: "Зачем нужен tls-crypt в OpenVPN?"
  options:
    - "Ускоряет передачу данных"
    - "Шифрует и аутентифицирует control-канал, скрывая handshake"
    - "Заменяет сертификаты"
    - "Включает IPv6"
  answer: 1
  explanation: "tls-crypt защищает control-канал целиком, скрывая OpenVPN от сканеров и DoS."
- question: "Какая опция заставляет клиент проверять имя сертификата сервера?"
  options:
    - "verify-x509-name"
    - "redirect-gateway"
    - "comp-lzo"
    - "persist-tun"
  answer: 0
  explanation: "verify-x509-name (вместе с remote-cert-tls server) защищает от подмены сервера."
- question: "Что произойдёт при утечке ca.key?"
  options:
    - "Ничего, ключ не важен"
    - "Атакующий сможет выпускать доверенные сертификаты клиентов и войти в VPN"
    - "VPN перестанет шифровать трафик"
    - "Сломается DNS"
  answer: 1
  explanation: "CA-ключ подписывает сертификаты — с ним можно выпустить произвольного клиента."
- question: "Какой режим data-cipher безопасен по современным меркам?"
  options:
    - "BF-CBC"
    - "AES-256-GCM"
    - "DES-CBC"
    - "RC4"
  answer: 1
  explanation: "AES-256-GCM (или ChaCha20-Poly1305) — современный аутентифицированный шифр."
```

## Где пригодится

- **CTF:** разбор VPN-трафика и поиск слабостей.
- **Пентест:** аудит VPN-периметра.
- **Работа:** диагностика и защита VPN-доступа.
- **SOC:** детект аномальных VPN-подключений.
- **Администрирование:** безопасные настройки OpenVPN.
