---
id: osint-dnssec-caa
title: "DNSSEC, CAA и DNS-безопасность: проверка и разбор"
category: osint
parent: osint-dns-security
difficulty: medium
order: 1
tags: [osint, dns, dnssec, caa, txt, security, hardening]
prerequisites: [osint-dns-recon]
useful_for:
  - "Bug bounty и пентест"
  - "CTF категория OSINT"
  - "Аудит DNS-гигиены"
estimated_minutes: 25
summary: "Защитные DNS-записи как разведданные: проверка DNSSEC-подписей, разбор CAA, TXT, MTA-STS и оценка гигиены домена."
---
DNS — не только карта инфраструктуры, но и зеркало **гигиены безопасности**. Защитные записи (DNSSEC, CAA, TXT, MTA-STS, DMARC) показывают, насколько владелец заботится о домене. Для OSINT это ценно по двум причинам: во-первых, слабая гигиена — сама по себе находка (вектор для спуфинга, подмены сертификата); во-вторых, эти записи раскрывают используемых вендоров и конфигурацию.

## Теория: какие защитные записи существуют

| Запись | Защищает от | Что раскрывает |
|--------|-------------|----------------|
| DNSSEC (`RRSIG`, `DNSKEY`) | подмены DNS-ответов | наличие/отсутствие подписи |
| CAA | выпуска сертификата чужим CA | список разрешённых CA |
| SPF (`TXT`) | спуфинга email | авторизованные отправители |
| DKIM (`TXT`) | подделки письма | селекторы, вендоры |
| DMARC (`TXT`) | спуфинга | политика, rua-адреса |
| MTA-STS (`TXT`) | downgrade почты | политика TLS |
| TLSA | MITM TLS | отпечатки сертификатов |

Каждая запись — это заявление владельца. Их совокупность = «профиль зрелости» домена.

## DNSSEC: проверка подписи

DNSSEC криптографически подписывает DNS-ответы. Проверка:

```bash
dig +dnssec +multi example.com A
```

Ищем флаг `ad` (Authenticated Data) в ответе:

```
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, ...
```

`ad` — резолвер подтвердил подпись. Если `ad` нет — либо DNSSEC не настроен, либо резолвер не проверяет.

Смотрим цепочку доверия:

```bash
dig +dnssec example.com DNSKEY +short
dig +dnssec example.com DS +short     # у родителя
dig +trace +dnssec example.com        # полная цепочка
```

Признаки проблем:
- `DNSKEY` есть, но `DS` у родителя отсутствует → **незавершённая настройка** (broken DNSSEC) — хуже, чем отсутствие.
- Подпись просрочена (`RRSIG` expired) → зона ломается для проверяющих резолверов.

```bash
dig +dnssec example.com RRSIG +short | grep -i '2026'
```

## CAA: кто может выпускать сертификаты

CAA-запись ограничивает, какие CA вправе выпустить сертификат на домен:

```bash
dig +short example.com CAA
# 0 issue "letsencrypt.org"
# 0 issuewild "letsencrypt.org"
# 0 iodef "mailto:security@example.com"
```

Типы:
- `issue` — кто может выпускать обычные сертификаты;
- `issuewild` — кто может выпускать wildcard;
- `iodef` — куда сообщать о нарушениях (email безопасности — pivot!).

Если CAA отсутствует — любой CA может выпустить сертификат (риск misissuance). Если CAA разрешает только `letsencrypt.org`, а сертификат выдан DigiCert — это аномалия, требующая объяснения.

```bash
dig +short example.com CAA | grep -i issue
dig +short example.com CAA | grep -i iodef
```

## TXT: SPF, DMARC, MTA-STS, верификации

TXT-записи — самая насыщенная разведданными зона. Смотрим все:

```bash
dig +short example.com TXT
```

Пример:

```
"v=spf1 include:_spf.google.com include:mailgun.org -all"
"google-site-verification=abc123"
"MS=ms12345678"
"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
"stripe-verification=..."
"atlassian-domain-verification=..."
```

Разбор:
- **SPF** `include:` раскрывает почтовых провайдеров (Google, Mailgun, SendGrid). `-all` — жёсткая политика; `~all` — мягкая; `+all` — открытый релей (плохо!).
- **DMARC** `p=` — политика (`none`/`quarantine`/`reject`).
- **Верификационные TXT** раскрывают используемые сервисы: Google (`google-site-verification`), Microsoft (`MS=`), Atlassian, Stripe, Facebook и др. Это **прямой список SaaS-вендоров компании**.

```bash
dig +short example.com TXT | grep -iE 'spf1|dmarc|verification|MS=|atlassian|stripe'
```

## MTA-STS и TLS-RPT

```bash
dig +short _mta-sts.example.com TXT
# "v=STSv1; id=20260101T000000;"
dig +short _smtp._tls.example.com TXT
# "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
```

MTA-STS говорит: «мой SMTP требует TLS». TLS-RPT — отчёты о TLS-проблемах. Наличие обеих = зрелая почтовая гигиена; их отсутствие — вектор downgrade-атаки на почту.

## Разобранный пример: профиль гигиены домена

Цель: `example.com`.

```bash
D=example.com
echo "== DNSSEC =="; dig +dnssec +short $D DNSKEY | head -1
echo "== AD flag =="; dig +dnssec $D A | grep -o 'flags:[^;]*'
echo "== CAA =="; dig +short $D CAA
echo "== SPF =="; dig +short $D TXT | grep spf1
echo "== DMARC =="; dig +short _dmarc.$D TXT
echo "== MTA-STS =="; dig +short _mta-sts.$D TXT
```

Вывод:

```
== DNSSEC ==
257 3 13 abc...== (есть)
== AD flag ==
flags: qr rd ra ad;     ← подпись валидна
== CAA ==
(пусто)                  ← нет ограничений CA — риск
== SPF ==
"v=spf1 include:_spf.google.com ~all"   ← softfail
== DMARC ==
"v=DMARC1; p=none; ..."  ← только мониторинг
== MTA-STS ==
(пусто)
```

Итог: DNSSEC настроен (хорошо), но CAA нет, SPF `~all` (мягко), DMARC `p=none` (спуфинг возможен), MTA-STS нет. Профиль: «частично зрелый» — потенциально уязвим к email-спуфингу и misissuance сертификата.

## Таблица: быстрая проверка гигиены

| Проверка | Команда | Хорошо если |
|----------|---------|-------------|
| DNSSEC | `dig +dnssec` | флаг `ad` |
| CAA | `dig CAA` | есть `issue` |
| SPF | `dig TXT \| grep spf1` | `-all` |
| DMARC | `dig _dmarc TXT` | `p=reject` |
| MTA-STS | `dig _mta-sts TXT` | есть запись |
| TLS-RPT | `dig _smtp._tls TXT` | есть rua |

## Ошибки и подводные камни

- **Путать отсутствие DNSSEC с поломкой.** Broken DNSSEC (есть DNSKEY, нет DS) — хуже, чем отсутствие.
- **Считать CAA абсолютной защитой.** CA может проигнорировать CAA при компрометации.
- **Игнорировать верификационные TXT.** Это список SaaS-вендоров — ценный для атаки.
- **Смотреть только SPF.** DMARC без SPF/DKIM бессмысленен; проверяйте связку.
- **Забывать про поддомены.** `_dmarc.sub.example.com` может иметь свою политику.
- **Доверять кэшу резолвера.** Используйте `+trace` для актуальной картины.

## Что дальше / решение

Гигиена DNS — это оценка «слабых мест» домена. Дальше: **dangling CNAME и захват** (`osint-domain-takeover`) — самый опасный класс DNS-ошибок, **email-заголовки** (`osint-email-headers`) для проверки реального спуфинга, и **картирование поверхности атаки** (`osint-attack-surface`). Итог: из защитных записей вы получаете и список вендоров, и оценку уязвимости домена к подмене и спуфингу.

## Разбор DMARC-политики детально

DMARC-запись содержит теги, влияющие на защиту:

```
v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; adkim=s; aspf=r; fo=1
```

| Тег | Значение |
|-----|----------|
| `p` | политика для домена: none/quarantine/reject |
| `sp` | политика для поддоменов |
| `pct` | процент сообщений под политику |
| `rua` | адрес агрегированных отчётов |
| `ruf` | адрес форензик-отчётов |
| `adkim` | выравнивание DKIM (s/r) |
| `aspf` | выравнивание SPF (s/r) |

Опасные конфигурации:
- `p=none` — только мониторинг (спуфинг возможен);
- `pct<100` — часть писем не фильтруется;
- `aspf=r` (relaxed) — позволяет поддомены в `From`;
- отсутствие `rua` — никто не видит атак.

```bash
dig +short _dmarc.example.com TXT | tr ';' '\n' | sed 's/^ *//'
```

## Проверка DKIM-селекторов

DKIM-ключи лежат по адресу `selector._domainkey.domain`. Селекторы перебираются из распространённых:

```bash
for s in default selector1 selector2 google s1 s2 mail dkim k1 20230601; do
  key=$(dig +short "$s._domainkey.example.com" TXT)
  [ -n "$key" ] && echo "$s: ${key:0:60}..."
done
```

Найдя селектор, проверяем длину ключа (1024 бита — слабо, 2048 — норм):

```bash
dig +short default._domainkey.example.com TXT | grep -oE 'p=[A-Za-z0-9+/=]+' | wc -c
```

## Связка гигиены с реальной атакой

Слабая гигиена → вектор:
- `DMARC p=none` + нет SPF `-all` → **email-спуфинг** от имени домена (фишинг сотрудникам/клиентам).
- Нет CAA → **misissuance** сертификата (MITM).
- Broken DNSSEC → **DNS-подмена** для проверяющих резолверов.
- Нет MTA-STS → **downgrade** TLS на почте (перехват).

Эти находки — валидные баги в программах, где спуфинг в scope, или оценки риска для отчёта.

## Инструменты проверки

| Инструмент | Что проверяет |
|-----------|---------------|
| `dig +dnssec` | DNSSEC, флаг `ad` |
| `dig CAA` | CAA-записи |
| `dmarcian` / `MXToolbox` | SPF/DKIM/DMARC |
| `testssl.sh` | TLS-конфигурация |
| `hardenize.com` | полный профиль домена |

```bash
testssl.sh --quiet example.com | grep -iE 'DNSSEC|CAA|OCSP'
```

## Историческая гигиена и тренды

Гигиена меняется во времени. Сравнивая записи через архивы, видно эволюцию:

```bash
# исторические TXT/DMARC через SecurityTrails (API)
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/txt" \
  -H "APIKEY: $KEY" | python3 -m json.tool | grep -iE 'value|first_seen'
```

Пример: год назад DMARC был `p=none`, сейчас `p=reject` → компания усилила почту. Или наоборот — регресс. Такие тренды ценны для отчёта и для оценки зрелости.

## Автоматизация профиля гигиены

Один скрипт — полный профиль:

```bash
#!/usr/bin/env bash
# dns-hygiene.sh — профиль DNS-гигиены домена
D="$1"
echo "== DNSSEC =="; dig +dnssec "$D" A | grep -o 'flags:[^;]*'
echo "== CAA ==";    dig +short "$D" CAA
echo "== SPF ==";    dig +short "$D" TXT | grep -i spf1
echo "== DMARC ==";  dig +short _dmarc."$D" TXT
echo "== MTA-STS ==";dig +short _mta-sts."$D" TXT
echo "== DKIM ==";   for s in default selector1 google; do
  k=$(dig +short "$s._domainkey.$D" TXT); [ -n "$k" ] && echo "$s: есть"
done
```

Запустив по списку доменов, получаете сравнительную таблицу зрелости — удобно для приоритизации целей.

## Квиз

```quiz
- question: "Что означает флаг `ad` в ответе `dig +dnssec`?"
  options:
    - "Домен удалён"
    - "Резолвер подтвердил DNSSEC-подпись (Authenticated Data)"
    - "Запись кэширована"
    - "Ответ пустой"
  answer: 1
- question: "От чего защищает CAA-запись?"
  options:
    - "От подмены DNS"
    - "От выпуска сертификата неавторизованным CA"
    - "От спуфинга email"
    - "От DDoS"
  answer: 1
- question: "Что раскрывают верификационные TXT (`google-site-verification`, `MS=`)?"
  options:
    - "Пароли"
    - "Используемые SaaS-сервисы компании"
    - "DNS-зону"
    - "Порты"
  answer: 1
- question: "Какой SPF-механизм считается жёстким (запрет спуфинга)?"
  options:
    - "`~all`"
    - "`-all`"
    - "`+all`"
    - "`?all`"
  answer: 1
- question: "Чем опасен broken DNSSEC (есть DNSKEY, нет DS у родителя)?"
  options:
    - "Ничем"
    - "Зона ломается для проверяющих резолверов — хуже, чем отсутствие"
    - "Ускоряет сайт"
    - "Скрывает поддомены"
  answer: 1
```

## Где пригодится

- **Bug bounty:** найти слабую email-гигиену (DMARC none) как валидную находку.
- **CTF (OSINT):** в TXT-записях спрятаны верификационные токены/подсказки.
- **Аудит:** оценить зрелость DNS-конфигурации организации.
- **Пентест:** выявить SaaS-вендоров и векторы спуфинга.
- **Blue team:** проверить свою гигиену (CAA, DNSSEC, DMARC).
