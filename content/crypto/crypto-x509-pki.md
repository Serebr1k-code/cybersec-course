---
id: crypto-x509-pki
title: "X.509 и PKI: сертификаты, цепочки и типичные ошибки проверки"
category: crypto
parent: crypto-pki-signatures
difficulty: hard
order: 1
tags: [crypto, x509, pki, certificate, chain, san, ct, openssl, validation]
prerequisites: [crypto-rsa-basics]
useful_for:
  - "Разбирать и валидировать X.509-сертификаты"
  - "Находить ошибки проверки цепочек и расширений"
  - "Понимать Certificate Transparency"
estimated_minutes: 40
summary: "Инфраструктура открытых ключей: структура X.509 (поля, расширения SAN/KeyUsage/NameConstraints), цепочки доверия и валидация, Certificate Transparency, а также типичные ошибки проверки (null byte, CN vs SAN, доверие к самоподписанным, отсутствие hostname-проверки), инструменты openssl/ct и разбор."
---

## Вопрос, с которого всё начинается

Браузер доверяет сайту не потому, что «так написано», а потому что сертификат подписан доверенным удостоверяющим центром, и цепочка доверия ведёт к корню в системе. Но стоит проверке цепочки или имени сделать один неверный шаг — и появляется MITM. Разберём структуру X.509 и на живом примере покажем, как ошибка «CN вместо SAN» открывает дверь.

## Наш пример

Сгенерируем сертификат, у которого `CN` и `SAN` указывают на **разные** имена:

```python
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "target.example.com")])
# ... добавляем SAN = attacker.example.com ...
```

Посмотрим, что видит `openssl`:

```bash
openssl x509 -in leaf.pem -noout -subject
openssl x509 -in leaf.pem -noout -ext subjectAltName
```

```
subject=CN=target.example.com
X509v3 Subject Alternative Name:
    DNS:attacker.example.com
```

`CN` говорит `target.example.com`, а `SAN` — `attacker.example.com`. Вопрос: какой из них должен проверять клиент, и что будет, если он ошибётся?

## Шаг 1: структура X.509

Сертификат — подписанная структура ASN.1 DER, содержащая:

- **tbsCertificate** (to-be-signed): версия, серийный номер, алгоритм подписи, **issuer** (кто подписал), **validity** (notBefore/notAfter), **subject** (кому выдан), **subjectPublicKeyInfo** (открытый ключ), **extensions**.
- **signatureAlgorithm** — алгоритм подписи.
- **signatureValue** — сама подпись.

Ключевой момент: сертификат **не содержит** поля «hostname» в явном виде. Имя сервера проверяется через расширение **SAN** (Subject Alternative Name), а **CN** (Common Name) устарел и **не должен** использоваться для проверки. Именно на этом расхождении ломаются наивные клиенты.

## Шаг 2: важные расширения

- **Subject Alternative Name (SAN)** — список имён (DNS, IP, email), которым соответствует сертификат. **Единственный** корректный источник hostname.
- **Basic Constraints** (`CA:TRUE/FALSE`) — является ли сертификат CA (может ли подписывать другие).
- **Key Usage / Extended Key Usage** — для чего годится ключ (serverAuth, clientAuth).
- **Name Constraints** — ограничения на имена, которые может подписывать промежуточный CA. Ошибки здесь — классика: сертификат для `example.com` подписывает `evil.com`.
- **CRL Distribution Points / OCSP** — отзыв.

Полная валидация обязана учитывать **все** эти расширения. Пропуск любого — потенциальный баг.

## Шаг 3: цепочки доверия

Цепочка: `leaf (сервер) → intermediate CA → root CA (в trust store)`. Проверка:

1. Проверить подпись каждого звена вышестоящим.
2. Проверить сроки (validity).
3. Проверить, что leaf соответствует имени (SAN) и назначению (EKU).
4. Проверить Basic Constraints и Name Constraints по всей цепочке.
5. Проверить отзыв (CRL/OCSP) — часто пропускается.
6. Убедиться, что корень в trust store.

```bash
openssl verify -CAfile ca.pem -untrusted intermediate.pem leaf.pem
openssl s_client -connect host:443 -showcerts </dev/null
```

Типичные ошибки: доверие к **любому** сертификату из цепочки как к корню; отсутствие проверки Basic Constraints (лист подписывает другой лист); игнорирование Name Constraints; проверка CN вместо SAN.

## Шаг 4: атака «CN вместо SAN»

Если приложение проверяет hostname по **CN**, атакующий:

1. Выпускает сертификат, где `CN = target.example.com`, но `SAN = attacker.example.com` (или SAN отсутствует).
2. Подставляет его в MITM.
3. Приложение смотрит на CN, видит нужное имя и **принимает** сертификат.

`openssl x509 -text` покажет, что реальный SAN не совпадает. Правильный клиент должен отклонить такой сертификат. Это классическая ошибка мобильных приложений, IoT и самописных клиентов.

Другой пример: промежуточный CA без проверки Name Constraints подписывает сертификат для чужого домена — и цепочка «валидна», хотя должна быть отклонена. Name Constraints существуют именно для того, чтобы ограничить, какие имена вправе подписывать промежуточный CA; если клиент их игнорирует, любой скомпрометированный intermediate может выдать сертификат на любой домен.

## Шаг 5: Certificate Transparency

**Certificate Transparency (CT)** — публичные логи всех выданных сертификатов, построенные на деревьях Меркла (см. `crypto-merkle-tree`). Каждый CA обязан логировать сертификаты; браузеры требуют наличие SCT (Signed Certificate Timestamp). Это позволяет детектировать **misissuance** и атаки на CA.

```bash
curl -s "https://crt.sh/?q=example.com&output=json" | jq '.[].name_value'
```

Для пентеста CT-логи — источник поддоменов и информации о выданных сертификатах.

## Шаг 6: отзыв и soft-fail

Сертификат может быть скомпрометирован до истечения срока, и тогда его нужно **отозвать**. Механизмов два, и оба проблемны.

**CRL** — подписанный CA список отозванных серийных номеров. Проблемы: списки огромны, устаревают, а многие клиенты их **не проверяют**.

**OCSP** — клиент спрашивает у респондера статус сертификата. Проблемы: дополнительный запрос (задержка, приватность), **soft-fail** по умолчанию (если респондер недоступен — сертификат принимается). **OCSP stapling** решает: сервер сам приносит подписанный ответ.

Ключевая уязвимость — **soft-fail**: атакующий блокирует доступ к респондеру и использует отозванный сертификат. Лечится hard-fail или переходом к короткоживущим сертификатам и CRLite.

## Практика: генерация своего CA

Для пентеста и CTF часто нужно поднять свой CA и выпустить сертификаты — для MITM-прокси (mitmproxy, Burp) или evil-twin:

```bash
# корневой ключ и сертификат
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 3650 -nodes -subj "/CN=Test CA"
# ключ и CSR для сервера
openssl req -newkey rsa:2048 -keyout srv.key -out srv.csr -nodes -subj "/CN=target.local"
# подпись с SAN
openssl x509 -req -in srv.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out srv.crt -days 365 -extfile <(printf "subjectAltName=DNS:target.local")
```

Такой сертификат примет клиент, который доверяет `ca.crt`, — но не обычный браузер, пока CA не в trust store. На CTF это используют, когда задача даёт «доверенный» CA и просит подделать сертификат. При аудите клиента проверяйте, не доверяет ли он пользовательскому или самоподписанному CA.

## Что мы теперь знаем

- Имя сервера проверяется **только по SAN**; CN устарел.
- Цепочка доверия: leaf → intermediate → root в trust store.
- Basic Constraints и Name Constraints обязательны для проверки.
- Атака «CN вместо SAN» открывает MITM.
- **Certificate Transparency** — публичный лог сертификатов на деревьях Меркла.
- **Soft-fail** при отзыве — распространённая MITM-уязвимость.

## На что смотреть дальше

- **Проверять CN вместо SAN** — устаревшая и опасная практика.
- **Не проверять hostname вообще** — прямой MITM.
- **Доверять всей цепочке** — любой сертификат как корень.
- **Игнорировать Basic Constraints** — лист подписывает лист.
- **Не проверять отзыв** — отозванные сертификаты принимаются.
- **Wildcard-злоупотребление** — `*.example.com` не должен покрывать `a.b.example.com`.

## Квиз

Проверь себя.

```quiz
- question: "По какому полю правильно проверять имя сервера?"
  options:
    - "Subject Alternative Name (SAN)"
    - "Common Name (CN)"
    - "Serial Number"
    - "Issuer"
  answer: 0
  explanation: "Современные клиенты проверяют hostname только по SAN; CN устарел."
- question: "Что проверяет Basic Constraints?"
  options:
    - "Является ли сертификат CA (может ли подписывать)"
    - "Срок действия"
    - "Имя сервера"
    - "Алгоритм шифрования"
  answer: 0
  explanation: "Basic Constraints CA:TRUE/FALSE определяет право подписи других сертификатов."
- question: "Зачем нужен Certificate Transparency?"
  options:
    - "Чтобы детектировать неправильно выданные сертификаты в публичном логе"
    - "Чтобы ускорить TLS"
    - "Чтобы шифровать трафик"
    - "Чтобы хранить пароли"
  answer: 0
  explanation: "CT-логи позволяют проверить, что сертификат выдан легитимно и залогирован."
- question: "Что такое soft-fail при проверке отзыва?"
  options:
    - "Сертификат принимается, если CRL/OCSP недоступен"
    - "Сертификат всегда отклоняется"
    - "Проверка ускоряется"
    - "Отзыв игнорируется всегда"
  answer: 0
  explanation: "Soft-fail означает принятие сертификата при недоступности респондера."
- question: "Какое расширение ограничивает имена для промежуточного CA?"
  options:
    - "Name Constraints"
    - "Key Usage"
    - "Serial Number"
    - "Validity"
  answer: 0
  explanation: "Name Constraints задают разрешённые имена для подписываемых сертификатов."
```

## Куда дальше

Мы разобрали X.509 и PKI. Дальше — схемы подписей на дискретном логарифме (ElGamal, DSA, Schnorr) и атаки на их nonce. В уроке **crypto-signature-schemes** мы восстановим ключ из двух подписей с одинаковым `r`. А пока главное: **имя проверяется по SAN, цепочка — целиком, а CN и soft-fail — частые источники MITM.**

## Где пригодится

- **CTF:** задачи на подделку/обход сертификатов, CT-логи.
- **Bug bounty:** ошибки проверки сертификатов в мобильных/десктоп-клиентах.
- **Пентест:** анализ TLS/PKI, MITM через слабую валидацию.
- **Работа:** разработка и аудит PKI, TLS, клиентской аутентификации.
