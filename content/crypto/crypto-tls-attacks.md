---
id: crypto-tls-attacks
title: "Криптоатаки на TLS: downgrade, Heartbleed, POODLE и отпечатки"
category: crypto
parent: crypto-real-world
difficulty: medium
order: 1
tags: [crypto, tls, ssl, downgrade, heartbleed, poodle, beast, crime, ja3, ja4, padding-oracle]
prerequisites: [crypto-rsa-padding, crypto-aes-modes]
useful_for:
  - "Понимать исторические и современные атаки на TLS"
  - "Оценивать конфигурацию TLS и версии"
  - "Использовать отпечатки JA3/JA4 для детекта"
estimated_minutes: 45
summary: "Криптографические атаки на TLS: downgrade и POODLE (padding oracle в CBC), BEAST/CRIME/BREACH (сжатие и IV), Heartbleed (утечка памяти), renegotiation, отпечатки JA3/JA4 и pinning. Практические инструменты и разбор."
lab:
  kind: shell
  title: 'Практика: Heartbleed → расшифровка TLS'
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, leak.bin, capture.bin, decrypt_tls.py]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'В `leak.bin` лежат master secret и randoms.'
    - 'Ключевой блок = PRF(master, "key expansion", server_random+client_random).'
    - 'Из key_block: client_write_key = первые 32 байта, IV — с 64-го.'
    - '`python3 decrypt_tls.py | grep nto > found.txt`.'
---

## Вопрос, с которого всё начинается

TLS — самый распространённый криптографический протокол в мире. Он шифрует веб,
почту, VPN, мессенджеры. Но если он такой стойкий, почему его историю называют
историей атак? Почти каждый класс криптоуязвимостей — padding oracle,
bit-flipping, downgrade, утечка через сжатие — был показан именно на TLS.

Вопрос: как оценить, безопасна ли конкретная TLS-конфигурация, и какие атаки
стоят за рекомендациями «только TLS 1.3, только AEAD»? Разберём это, подняв
реальный TLS-сервер и посмотрев, что он согласует.

## Наш пример: поднимаем TLS-сервер и смотрим версии

Сгенерируем самоподписанный сертификат и запустим локальный сервер, а затем
подключимся к нему с разными версиями протокола:

```
$ openssl s_client -connect 127.0.0.1:14433 -tls1_3
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3

$ openssl s_client -connect 127.0.0.1:14433 -tls1_2
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Protocol: TLSv1.2
```

Мы видим две вещи: сервер согласовал **версию** (1.3 или 1.2) и **набор шифров**
(cipher suite). В TLS 1.3 набор только один — `TLS_AES_256_GCM_SHA384` (AEAD). В
TLS 1.2 набор длинный: `ECDHE-RSA-AES256-GCM-SHA384` — здесь есть и обмен
ключами (ECDHE), и шифр (AES-256-GCM), и MAC (SHA384). Именно от набора зависит,
уязвим сервер или нет.

## Шаг 1: версии и downgrade

TLS прошёл путь SSL 2.0 → SSL 3.0 → TLS 1.0/1.1/1.2/1.3, и каждая версия несёт
свои слабости:

- **SSL 2.0** — нет защиты от downgrade, слабый MAC.
- **SSL 3.0** — уязвим к POODLE (padding не аутентифицирован).
- **TLS 1.0/1.1** — BEAST, поддержка RC4, слабые хэши.
- **TLS 1.2** — современный, но зависит от набора шифров (CBC vs AEAD).
- **TLS 1.3** — только AEAD, только forward secrecy, убраны слабые примитивы.

**Downgrade-атака**: MITM понижает версию до слабой. Защита — сигнальная
cipher suite `TLS_FALLBACK_SCSV` («я умею лучше»), а в TLS 1.3 версия включена в
проверку `Finished`, поэтому незаметно понизить её нельзя. Если сервер принимает
SSL 3.0 или RC4 — это красный флаг.

## Шаг 2: POODLE — padding oracle в CBC

**POODLE** (Padding Oracle On Downgraded Legacy Encryption, 2014) эксплуатирует
padding в CBC-режиме SSL 3.0: padding там **не аутентифицирован**, и проверка
padding даёт **оракул**. Атакующий, понизив соединение до SSL 3.0, побайтово
восстанавливает данные (например, cookie) за ~256 запросов на байт — ровно та
механика, что в `crypto-padding-oracle`. **Lucky13** — timing-вариант для TLS
1.0–1.2 CBC: время проверки MAC/padding утекает информацию.

Вывод: **CBC без аутентификации опасен**, поэтому в TLS 1.3 остались только AEAD.

## Шаг 3: Heartbleed — не крипто, а память

**Heartbleed** (CVE-2014-0160) — ошибка в расширении heartbeat OpenSSL. Клиент
посылает heartbeat с **заявленной длиной больше реального payload**; сервер читает
за пределы буфера и возвращает до 64 КБ памяти — включая приватные ключи, сессии,
пароли. Это чистый buffer over-read, ставший одним из самых громких багов в
истории. Проверка:

```bash
nmap -p 443 --script ssl-heartbleed <target>
```

На CTF задача обычно даёт сервер, возвращающий память, — из неё надо выделить ключ
или флаг. Важно: это не взлом шифра, а утечка реализации.

## Полный прогон от начала до конца

Оценка TLS-конфигурации — это последовательность проверок:

1. `nmap -p 443 --script ssl-enum-ciphers <target>` — версии и наборы шифров.
2. Ищем SSLv3 и CBC (POODLE), RC4 (смещения), экспортные наборы (FREAK/Logjam).
3. `nmap --script ssl-heartbleed` — Heartbleed.
4. `openssl s_client -tls1_3` — поддерживается ли TLS 1.3 и AEAD.
5. Если сервер поддерживает SSLv3 + CBC — уязвим к POODLE; если RC4 — к
   статистическим атакам.

Для CTF-задачи на padding oracle сначала убедитесь, что режим CBC и padding
проверяется отдельно, затем применяйте стандартный эксплойт побайтового
восстановления из `crypto-padding-oracle`.

## Что мы теперь знаем

- Безопасность TLS определяется **версией** и **набором шифров**, а не самим
  фактом «есть TLS».
- POODLE/Lucky13 — padding oracle и timing в CBC; лечатся уходом на AEAD.
- Heartbleed — memory over-read в реализации OpenSSL, а не крипто-атака.
- BEAST, CRIME, BREACH — утечки через IV и сжатие; защита — TLS 1.1+/отключение
  сжатия.
- Downgrade закрывается `TLS_FALLBACK_SCSV` и проверкой версии в TLS 1.3.
- JA3/JA4 — отпечатки ClientHello для детекта и маскировки.

## BEAST, CRIME, BREACH и отпечатки

- **BEAST** — против TLS 1.0 CBC: предсказуемый IV (предыдущий блок) даёт атаку по
  выбранному открытому тексту. Лечится 1/n-1 split или TLS 1.1+.
- **CRIME** — против сжатия TLS: размер шифротекста зависит от содержимого, и
  атакующий угадывает секрет по изменению длины. Защита — отключить сжатие.
- **BREACH** — то же на уровне HTTP-сжатия тела ответа.
- **Renegotiation attack** — если renegotiation не привязана к сессии, MITM
  инжектирует данные в начало; лечится `secure renegotiation` (RFC 5746).
- **JA3/JA4** — это **детект**: хэш параметров ClientHello отличает curl от
  браузера, выдаёт малварь, помогает маскировать трафик под легитимного клиента.

## Почему TLS 1.3 радикален

TLS 1.3 убрал CBC (POODLE/Lucky13), RC4 (смещения), статические RSA-обмены
(вместо них ECDHE — forward secrecy), renegotiation и сжатие (CRIME). Остались
только AEAD и SHA-256/384. Добавились 1-RTT/0-RTT handshake (0-RTT даёт риск
replay), зашифрованный handshake (мешает пассивному fingerprinting) и проверка
версии в `Finished` (защита от downgrade). Практический вывод: сервер с «TLS 1.2
+ CBC + RC4» так же уязвим, как старый, — смотрите не на версию, а на **наборы
шифров**.

## Справочные таблицы

| Атака | Версия/условие | Защита |
|-------|----------------|--------|
| POODLE | SSL 3.0 + CBC | отключить SSLv3 |
| BEAST | TLS 1.0 + CBC | TLS 1.1+/AEAD |
| CRIME | TLS-компрессия | отключить |
| BREACH | HTTP-компрессия | маскировать секреты |
| Heartbleed | OpenSSL heartbeat | обновить OpenSSL |
| Lucky13 | TLS CBC timing | constant-time |

| Инструмент | Назначение |
|-----------|-----------|
| testssl.sh | полная оценка |
| sslscan | наборы шифров |
| nmap ssl-* | точечные проверки |
| ja3/ja4 | отпечатки клиентов |

## Если не сработало

- **Сервер не поддерживает старую версию.** Современные сборки OpenSSL/nginx по умолчанию выключили SSLv3 и TLS 1.0; downgrade-атака требует, чтобы обе стороны её допускали. Проверьте `openssl s_client -ssl3` / `-tls1` — если хендшейк не поднимается, вектор закрыт.
- **POODLE не проходит.** Атака требует CBC-шифра и **padding oracle** (различия в ответе на неверный padding). Если сервер всегда возвращает одинаковую ошибку или включён TLS 1.3 — padding oracle отсутствует.
- **Heartbleed «не отдаёт память».** Уязвимы только конкретные версии OpenSSL 1.0.1–1.0.1f; на пропатченных сборках расширение heartbeat просто игнорирует неверную длину. Проверяйте версию, а не слепо запускайте PoC.
- **BEAST/CRIME/BREACH не срабатывают.** BEAST побеждён 1/n−1 IV, CRIME — отключением TLS-сжатия, BREACH — отключением HTTP-сжатия и добавлением случайности в тело ответа.
- **Отпечаток JA3 не совпадает.** JA3 зависит от порядка и набора шифров/расширений; если клиент обновлён или за прокси, отпечаток меняется.

## Частые вопросы

**Что важнее — версия TLS или набор шифров?** И то и другое: старый шифр (RC4, CBC) в новом TLS всё равно опасен, а новый шифр в TLS 1.0 не спасает от downgrade. Смотрите обе оси.

**Почему TLS 1.3 радикально закрывает список атак?** В нём нет пересогласования (renegotiation), нет CBC-режимов и MAC-then-encrypt, убраны слабые шифры, а handshake подписывается целиком. POODLE, BEAST, CRIME, renegotiation-атаки там просто не существуют.

**Помогает ли HSTS против downgrade?** Против SSL-stripping — да, если HSTS предзагружен; против атаки на версию внутри TLS — только на стороне сервера (минимальная версия).

**Как проверить сервер самому?** `testssl.sh`, `nmap --script ssl-enum-ciphers`, `sslyze` покажут версии, шифры, уязвимости к POODLE/Heartbleed и соответствие.

## Квиз

Проверь себя.

```quiz
- question: "На чём основана атака POODLE?"
  options:
    - "На padding oracle в CBC-режиме SSL 3.0"
    - "На слабом пароле"
    - "На коллизии хэша"
    - "На переполнении буфера"
  answer: 0
- question: "Что эксплуатирует Heartbleed?"
  options:
    - "Переполнение чтения (over-read) в расширении heartbeat OpenSSL"
    - "Слабый RSA-ключ"
    - "Повтор nonce"
    - "Padding oracle"
  answer: 0
- question: "Почему CRIME/BREACH опасны даже при стойком шифровании?"
  options:
    - "Они используют утечку через длину сжатых данных"
    - "Они взламывают AES"
    - "Они крадут ключ"
    - "Они не опасны"
  answer: 0
- question: "Чем защищаются от downgrade-атаки?"
  options:
    - "TLS_FALLBACK_SCSV и проверка версии в Finished (TLS 1.3)"
    - "Большим ключом"
    - "Отключением сертификатов"
    - "Сжатием"
  answer: 0
- question: "Почему в TLS 1.3 остались только AEAD-режимы?"
  options:
    - "Из-за POODLE/Lucky13 и других атак на CBC"
    - "Потому что CBC медленный"
    - "Потому что AEAD короче"
    - "Случайно"
  answer: 0
```

## Куда дальше

TLS — прикладной слой, опирающийся на всё, что мы изучили: `crypto-rsa-padding`
(Bleichenbacher против TLS RSA), `crypto-aes-modes` (CBC/AEAD), `crypto-timing`
(Lucky13). Дальше ветвь идёт в `crypto-wifi-wpa` и `crypto-disk-encryption`. А
главное запомни: **безопасность TLS — это версия плюс набор шифров; «есть TLS» ≠
«безопасно»**.

## Где пригодится

- **CTF** — задачи на padding oracle/CBC и слабые TLS-конфигурации.
- **Bug bounty** — оценка TLS-конфигураций, downgrade, слабых наборов.
- **Пентест** — аудит TLS-терминаторов, VPN, веб-серверов.
- **Работа** — hardening TLS, детект аномальных клиентов по JA3/JA4.
