---
id: osint-spf-dkim
title: "SPF, DKIM и DMARC: поверхность подделки почты"
category: osint
parent: osint-email-headers
difficulty: medium
order: 2
tags: [email, spf, dkim, dmarc, spoofing]
prerequisites: [osint-email-headers]
useful_for:
  - "Bug bounty: поиск спуфинга домена"
  - "Пентест: оценка фишинг-поверхности"
estimated_minutes: 45
summary: "Как устроены SPF, DKIM и DMARC, как их читать через DNS, как искать подделываемые домены и оценивать политику защиты."
---

Почтовая инфраструктура домена — важная часть поверхности атаки. Слабо настроенные SPF/DKIM/DMARC позволяют отправлять письма «от имени» домена (спуфинг), что открывает фишинг и социальную инженерию. Разведка здесь — это чтение DNS-записей и проверка политик. Всё делается пассивно, через DNS.

## SPF

SPF (`TXT` с `v=spf1`) перечисляет хосты, которым разрешено слать почту от домена:

```bash
dig +short TXT example.com | grep spf1
```

Разбор:

- `v=spf1` — версия.
- `ip4:1.2.3.4`, `include:_spf.google.com` — разрешённые отправители.
- `a`, `mx` — разрешить IP из A/MX-записей.
- `-all` — жёсткий запрет остального (правильно).
- `~all` — softfail (письма помечаются, но проходят).
- `+all` — разрешено всё (**спуфинг возможен**).
- `?all` — нейтрально (нет политики).
- `redirect=`, `exists:`, `ptr` — дополнительные механизмы.

Лимит SPF — 10 DNS- lookup; превышение → `permerror`, защита ломается.

## DKIM

DKIM подписывает письма. Публичный ключ лежит в DNS: `<selector>._domainkey.example.com`.

```bash
dig +short TXT google._domainkey.example.com
dig +short TXT default._domainkey.example.com
dig +short TXT selector1._domainkey.example.com
dig +short TXT s1._domainkey.example.com
```

Селектор заранее неизвестен — перебирайте типовые (`default`, `google`, `mail`, `s1`, `selector1`, `k1`, `dkim`) или читайте из заголовка подписанного письма (`DKIM-Signature: s=`). Слабый/короткий ключ (`p=` из 512 бит, или ключ отозван как `p=`) — уязвимость.

## DMARC

DMARC (`_dmarc.example.com`) задаёт политику для писем, проваливших SPF/DKIM:

```bash
dig +short TXT _dmarc.example.com
```

Разбор `v=DMARC1; p=none; rua=mailto:...; ruf=mailto:...; pct=100; sp=none; adkim=s; aspf=s`:

- `p=none` — только мониторинг, письма не блокируются (**подделка проходит**).
- `p=quarantine` — в спам.
- `p=reject` — блокировка (строгая защита).
- `sp=` — политика для поддоменов.
- `pct=100` — процент применения.
- `rua`/`ruf` — адреса для агрегированных/форензик-отчётов (можно найти контакты команды).
- `adkim`/`aspf` — строгость alignment (`s` строгий, `r` расслабленный).

## Что считаем слабостью

| Находка | Риск |
|---|---|
| Нет SPF/DMARC | свободный спуфинг |
| `+all` или `?all` в SPF | спуфинг |
| `p=none` в DMARC | письма проходят |
| `sp=none` при `p=reject` | поддомены уязвимы |
| Нет DMARC на поддомене | спуфинг поддомена |
| `pct<100` | часть писем проходит |
| Нет DKIM | подпись отсутствует (SPF может спасти) |

Важно: DMARC наследуется поддоменами только при `sp` или org-домене; многие поддомены не защищены.

## Массовая проверка и спуфинг-поверхность

```bash
# проверить домен целиком
checkdmarc example.com

# перебрать поддомены на DMARC/SPF
for h in $(cat subdomains.txt); do
  echo "== $h =="
  dig +short TXT _dmarc.$h
  dig +short TXT $h | grep spf1
done
```

Сервисы: `dmarcian`, `MXToolbox`, `mail-tester`, `EasyDMARC`, `postmarkapp DMARC`. Их отчёты часто показывают, что часть поддоменов не защищена — это и есть валидная находка для bug bounty.

## Разбор кейса

Задача: оценить возможность спуфинга домена `example.com`.

1. `dig TXT example.com` → SPF `-all` (хорошо).
2. `dig TXT _dmarc.example.com` → `p=reject` (хорошо).
3. Перебираем поддомены → `mail.example.com` без DMARC и с `?all` (плохо).
4. Отправляем тестовое письмо «от `ceo@mail.example.com`» на свой ящик (в рамках scope) → проходит SPF и не блокируется DMARC.
5. Фиксируем: поддомен подделываем, рекомендация — добавить `sp=reject`.

## Частые ошибки

- **Проверять только корневой домен**: поддомены — основная дыра.
- **Игнорировать `sp`/`pct`**: `p=reject; pct=50` блокирует лишь половину.
- **Забыть про селекторы DKIM**: один неактивный селектор ≠ отсутствие DKIM.
- **Путать SPF pass и DMARC**: DMARC требует согласованности (alignment) доменов.
- **Не проверять `include`-цепочки**: сторонний сервис в SPF может быть скомпрометирован.

## Практика: массовая проверка домена

```bash
# SPF
dig +short TXT example.com | grep spf1
# DMARC
dig +short TXT _dmarc.example.com
# типовые селекторы DKIM
for s in default google mail s1 selector1 k1 dkim; do
  echo "== $s"
  dig +short TXT $s._domainkey.example.com
done
```

Автоматизация: `checkdmarc example.com`, `dmarcian`, `MXToolbox`, `mail-tester`.

## Спуфинг-поверхность поддоменов

```bash
# перебрать поддомены на DMARC/SPF
for h in $(cat subs.txt); do
  dm=$(dig +short TXT _dmarc.$h)
  sp=$(dig +short TXT $h | grep spf1)
  echo "$h | dmarc:${dm:-none} | spf:${sp:-none}"
done | grep -E 'none|~all|\?all|\+all'
```

Поддомены без DMARC/с мягким SPF — кандидаты на спуфинг. Это валидная находка для bug bounty (domain spoofing).

## Интерпретация и рекомендации

- `-all` + `p=reject` + `sp=reject` + DKIM → надёжная защита.
- `~all`/`?all`/`+all`, `p=none`, отсутствие `sp` → слабые места.
- Рекомендация: ужесточить политику, добавить `sp`, настроить DKIM, включить отчёты `rua`.

## SPF: механики, квалификаторы и лимит 10 запросов

SPF-запись — это TXT с `v=spf1` и списком механизмов. Каждый механизм имеет **квалификатор** результата:

| Квалификатор | Значение | Эффект |
|--------------|----------|--------|
| `+` | pass | разрешено (по умолчанию) |
| `-` | fail | запрещено (жёстко) |
| `~` | softfail | вероятно запрещено (часто «принимаем в спам») |
| `?` | neutral | без мнения |

Механизмы: `ip4:`/`ip6:`, `a`, `mx`, `include:`, `exists:`, `ptr` (устарел). Макросы (`%{i}`, `%{d}`) позволяют динамику.

**Критично:** SPF допускает максимум **10 DNS-запросов** (lookup) на проверку. Каждый `include:`, `a`, `mx` — запрос. Превышение → `permerror` → письмо не проходит SPF. Частая мисконфигурация: нагромождение `include:`.

```bash
# посчитать lookup-ы и развернуть цепочку include
dig +short TXT example.com | grep spf1
# рекурсивно развернуть include
for inc in $(dig +short TXT example.com | grep -oE 'include:[^ ]+'); do
  d=${inc#include:}; echo "$d -> $(dig +short TXT $d)"; done
```

## DKIM: селекторы и слабые ключи

DKIM подписывает письмо доменом через селектор: `<selector>._domainkey.<domain>`.

```bash
# найти селектор (из заголовка DKIM-Signature: s=)
dig +short TXT default._domainkey.example.com
dig +short TXT selector1._domainkey.example.com
dig +short TXT google._domainkey.example.com
```

Что считаем слабостью:

- **Короткий ключ** (`p=` из 1024 бит и меньше) — брутфорс подписи.
- **Отсутствие `p=`** — пустой ключ: домен не подписывает (или ключ отозван).
- **Режим тестирования** (`t=y`) — риск.
- **Слабый селектор** (`default`, `mail`) — предсказуем, но сам по себе не дыра.

## DMARC: политика и агрегаты

DMARC связывает SPF/DKIM с доменом From и задаёт политику: `p=none|quarantine|reject`. Поля `rua`/`ruf` — куда шлют агрегатные/форензик-отчёты.

```bash
dig +short TXT _dmarc.example.com
# пример: v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100; adkim=s; aspf=s
```

`p=none` (только мониторинг) — самая частая слабость: домен **не защищён** от спуфинга, хотя выглядит настроенным. `pct=<100` означает, что фильтр применяется частично — тоже обход.

## Инструменты проверки и спуфинга

```bash
# swaks: отправить письмо с произвольным From (тест доставки)
swaks --to victim@target.com --from ceo@example.com --server mail.example.com --header "Subject: test"
# mailspoof (агрегатор проверки SPF/DKIM/DMARC)
pip install mailspoof && mailspoof -d example.com
# checkdmarc
pip install checkdmarc && checkdmarc example.com
# спуфер-скрипт (только в авторизованном тесте!)
pip install spoofcheck
```

`swaks` показывает, как почтовый сервер реагирует на поддельный From: принимает, помечает в спам или отклоняет — прямая метрика спуфинг-поверхности.

## Байпасы спуфинга

Даже при `p=reject` есть обходы:

- **Поддомен без DMARC** — политика наследуется, но `sp=reject` часто не задан; поддомены с `p=none` слабее.
- **Lookalike-домены** — `examp1e.com`, `example.co` (osint-typosquat) — DMARC родителя их не покрывает.
- **Разные заголовки From/Return-Path** — если DKIM не выравнен (`adkim=r`), спуфинг возможен.
- **Relay через доверенный сервис** — маркетинговые платформы с валидным SPF для своего домена.
- **Смена Envelope-From** — влияет на SPF-выравнивание (`aspf`).

## Массовая проверка и отчёт

```bash
#!/usr/bin/env bash
for d in $(cat domains.txt); do
  spf=$(dig +short TXT "$d" | grep -o 'v=spf1[^"]*' | head -1)
  dmarc=$(dig +short TXT "_dmarc.$d" | grep -o 'v=DMARC1[^"]*' | head -1)
  pol=$(echo "$dmarc" | grep -oE 'p=[a-z]+')
  printf '%-30s SPF:%-6s DMARC:%s\n' "$d" "${spf:+yes}" "${pol:-NONE}"
done
```

Домены без `p=reject` — кандидаты на фишинг. Сводите в таблицу и приоритизируйте по критичности бренда.

## Интерпретация: что реально опасно

| Состояние | Риск | Комментарий |
|-----------|------|-------------|
| Нет SPF | высокий | любой может слать от имени домена |
| SPF `?all`/`~all` | средний | softfail часто не блокирует |
| SPF >10 lookups | средний | permerror ломает легитимную почту |
| Нет DKIM | средний | нет криптоподписи |
| DKIM `p=` пусто/короткий | высокий | подделка подписи |
| DMARC отсутствует | высокий | нет политики |
| DMARC `p=none` | высокий | мониторинг без защиты |
| DMARC `p=reject` + `sp=reject` | низкий | спуфинг практически закрыт |

## Частые ошибки

- **Проверять только корневой домен** — поддомены (`mail.`, `news.`) часто без DMARC.
- **Считать `p=none` защитой** — это лишь отчёты.
- **Игнорировать `sp=`** — без него поддомены берут политику `p`, но с `p=none` это ноль.
- **Не проверять DKIM-селекторы** — у домена их может быть несколько, старые с короткими ключами.
- **Забыть про `rua`-отчёты** — по ним видно, кто уже спуфит домен (мониторинг).

## Квиз

```quiz
- question: "Что означает `+all` в SPF?"
  options:
    - "Разрешены только указанные хосты"
    - "Разрешено отправлять почту с любого хоста (спуфинг)"
    - "Полный запрет"
    - "Мониторинг"
  answer: 1
- question: "Где хранится политика DMARC?"
  options:
    - "В `_dmarc.example.com` (TXT)"
    - "В MX-записи"
    - "В файле robots.txt"
    - "В SPF"
  answer: 0
- question: "Какая политика DMARC НЕ блокирует подделку?"
  options:
    - "p=reject"
    - "p=quarantine"
    - "p=none"
    - "p=strict"
  answer: 2
- question: "Где искать публичный ключ DKIM?"
  options:
    - "`<selector>._domainkey.example.com` (TXT)"
    - "`_dmarc.example.com`"
    - "В MX-записи"
    - "В записи CAA"
  answer: 0
- question: "Почему важно проверять поддомены на DMARC?"
  options:
    - "Они всегда защищены"
    - "Без `sp`/org-политики поддомены могут быть уязвимы к спуфингу"
    - "Так требует SPF"
    - "Это ускоряет доставку"
  answer: 1
```

## Где пригодится

- **CTF:** задачи на спуфинг и чтение почтовых заголовков.
- **Bug bounty:** домены, допускающие подделку отправителя, — валидная находка.
- **Пентест:** оценка фишинг-поверхности и планирование рассылок.
- **Blue team:** аудит собственной почтовой защиты и её ужесточение.
