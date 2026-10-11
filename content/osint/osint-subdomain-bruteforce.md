---
id: osint-subdomain-bruteforce
title: "Перебор поддоменов: словари, инструменты и тактика"
category: osint
parent: osint-dns-core
difficulty: medium
order: 4
tags: [osint, dns, subdomain, brute-force, amass, puredns, recon]
prerequisites: [osint-dns-core, osint-subdomain-tools]
useful_for:
  - "Recon для пентеста"
  - "Bug bounty"
  - "Картирование инфраструктуры"
estimated_minutes: 38
summary: "Перебор поддоменов: пассивные и активные методы, инструменты amass/subfinder/puredns/massdns/dnsx, словари, валидация и wildcard, permutations и vhost."
---

Поддомены — это расширение поверхности атаки: `dev.`, `staging.`, `admin.`, `internal.` часто живут на отдельных IP, с ослабленной защитой и не упомянуты в основной навигации. Пассивные источники (CT, DNS-история) находят многие, но не все; **активный перебор** словарём дополняет картину. Правильная тактика — комбинация пассивного и активного, с обязательной валидацией и учётом wildcard.

## Зачем перебор поддоменов

Каждый найденный поддомен — потенциальная точка входа: забытый тестовый стенд, панель администратора, API без авторизации, S3-бакет. Для пентеста это расширение scope (в рамках договора); для bug bounty — шанс на «лёгкую» находку. Пассивный сбор быстр и тих, активный — полнее, но заметнее (DNS-запросы видны резолверу цели).

## Пассивный vs активный

| Метод | Источники | Заметность |
|---|---|---|
| Пассивный | crt.sh, CT-логи, DNS-архивы, поисковики, GitHub | Низкая |
| Активный | Перебор словарём, permutations, zone transfer | Высокая |

Пассивный: `subfinder`, `amass enum -passive`, `crt.sh`. Активный: `amass enum -active`, `puredns`, `massdns`, `ffuf`.

## Инструменты

- **amass** — самый мощный: пассивные и активные источники, граф, permutations.
- **subfinder** — быстрый пассивный сбор из множества источников.
- **puredns** — высокоскоростной брутфорс с валидацией и wildcard-фильтром.
- **massdns** — массовый резолвинг.
- **dnsx** — быстрый резолв/проверка.
- **ffuf** — брутфорс поддоменов (`-H "Host: FUZZ.domain"`) и vhost.
- **shuffledns** — брутфорс+резолв на massdns.
- **gobuster dns** — простой DNS-брут.

```bash
# Пассивный сбор
subfinder -d target.com -all -silent -o subs.txt
amass enum -passive -d target.com -o amass.txt
# Активный брут с валидацией и wildcard-фильтром
puredns bruteforce wordlist.txt target.com -r resolvers.txt -w found.txt
# Резолв найденных
dnsx -l subs.txt -a -resp -silent
```

## Словари

Качество словаря важнее скорости. Источники: **SecLists** (`Discovery/DNS/`), `dns-Jhaddix.txt`, `subdomains-top1million-5000.txt`, `bitquark-subdomains-top100000.txt`. Плюс **собственные** словари: из найденных пассивно поддоменов генерируют варианты (`dev-`, `-staging`, `api-`). Правило: начинайте с небольшого точного словаря, затем расширяйте.

## Разобранный пример

1. Пассивный сбор:
   ```bash
   subfinder -d target.com -all -silent | sort -u > subs.txt
   ```
2. Подготовка словаря (SecLists):
   ```bash
   wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt
   ```
3. Список резолверов (публичные) и брут:
   ```bash
   puredns bruteforce subdomains-top1million-110000.txt target.com \
     -r resolvers.txt -w brute.txt --wildcard-tests 10
   ```
4. Объединение и резолв:
   ```bash
   cat subs.txt brute.txt | sort -u | dnsx -a -resp -silent -o resolved.txt
   ```
5. HTTP-проверка живых:
   ```bash
   httpx -l resolved.txt -title -status-code -silent -o alive.txt
   ```
6. Проверка vhost (виртуальные хосты на одном IP):
   ```bash
   ffuf -u http://10.0.0.5 -H "Host: FUZZ.target.com" -w wordlist.txt -fs 0
   ```

## Валидация и wildcard

Ключевая проблема — **wildcard DNS**: `*.target.com` резолвится в один IP, и брутфорс даёт тысячи «ложных» поддоменов. Решения:

- **Проверить wildcard:** `dig random1234.target.com` — если резолвится, есть wildcard.
- **Фильтровать по IP/ответу:** отбрасывать имена, резолвящиеся в тот же IP, что и случайное.
- **puredns/shuffledns** делают это автоматически (`--wildcard-tests`).
- Сравнивать CNAME/ответы, а не только факт резолва.

```bash
# Проверка wildcard
dig +short $(head -c8 /dev/urandom | base32).target.com
```

## Permutations и vhost

Когда базовый брут исчерпан, генерируют **перестановки** из известных поддоменов: `api.target.com` → `api-dev`, `dev-api`, `api-staging`, `api2`. Инструменты: `altdns`, `dnsgen`, `gotator`. Затем прогоняют через резолвер.

```bash
cat subs.txt | dnsgen - | puredns resolve -r resolvers.txt -w perms.txt
```

**Vhost-фаззинг** (`ffuf` с `Host:`) ищет виртуальные хосты, не имеющие DNS-записи, — на одном IP может жить несколько сайтов.

## Защита

| Мера | Эффект |
|---|---|
| Wildcard DNS | Снижает ценность брута |
| Не публиковать внутренние имена в CT | Меньше пассивных находок |
| Ограничить DNS-зону (split-horizon) | Внутренние имена не видны |
| Закрыть dev/staging аутентификацией | Нет доступа |
| Мониторинг аномальных DNS-запросов | Детект брута |
| Разделение prod/dev сетей | Ограничение blast radius |

## Подводные камни

- **Wildcard ломает брут.** Без фильтра — тысячи ложных.
- **Публичные резолверы блокируют.** Rate-limit; используйте свой/разные.
- **Медленный брут.** Один поток — часы; используйте massdns/puredns.
- **Забыть про vhost.** Поддомена нет в DNS, но сайт живёт.
- **Только поддомены.** Не забывайте про другие TLD/домены компании (см. `osint-typosquat`).
- **Юридические рамки.** Активный брут — только по авторизации.

## Что дальше / решение

Перебор поддоменов — фундамент recon; свяжите с `osint-subdomain-tools`, `osint-cert-transparency`, `osint-dns-core`, `osint-typosquat`, `osint-cdn-origin`. Дальше — HTTP-проверка (`httpx`) и углубление в найденные сервисы. Для CTF/пентеста постройте пайплайн subfinder → puredns → dnsx → httpx.

## Справочная таблица

| Инструмент | Роль |
|---|---|
| subfinder | Пассивный сбор |
| amass | Пассив+актив+граф |
| puredns | Брут с валидацией |
| massdns | Массовый резолв |
| dnsx | Быстрый резолв |
| ffuf | Vhost/брут |

| Словарь | Размер |
|---|---|
| subdomains-top1million-5000 | 5k |
| subdomains-top1million-110000 | 110k |
| dns-Jhaddix | 2M+ |

## Автоматизация пайплайна

Полный recon-пайплайн для поддоменов автоматизируют скриптом. Типовая цепочка:

```bash
#!/usr/bin/env bash
D=target.com
subfinder -d $D -all -silent > subs.txt
amass enum -passive -d $D -silent >> subs.txt
puredns bruteforce subdomains-top1million-110000.txt $D -r resolvers.txt -w brute.txt --wildcard-tests 10
cat subs.txt brute.txt | sort -u > all.txt
dnsx -l all.txt -a -resp -silent > resolved.txt
httpx -l resolved.txt -title -status-code -tech-detect -silent > alive.txt
```

Результат `alive.txt` — список живых сервисов с заголовками и технологиями, готовый для дальнейшего анализа. Для регулярного мониторинга запускайте по расписанию и диффите результаты (новые поддомены = новые активы). Обязательно добавляйте задержки и уважайте лимиты резолверов.

## Кейс: от поддомена к находке

1. Пассивный сбор даёт `api.target.com`, активный брут — `staging-api.target.com`.
2. `httpx` показывает, что staging отвечает 200 и отдаёт Swagger.
3. Swagger раскрывает эндпоинты без авторизации → потенциальная уязвимость.
4. Другой поддомен `jenkins.target.com` открывает CI-панель (см. `svc-cicd`).
5. `dev.target.com` отдаёт исходники с `.git` (см. `osint-git-history`).

Так один этап recon порождает несколько векторов. Задача аналитика — не «собрать поддомены», а **пройти по ним** и найти слабые сервисы, не забывая о рамках авторизации.

## Резолверы и производительность

Скорость брутфорса определяется резолверами и инструментом. Публичные резолверы (Google 8.8.8.8, Cloudflare 1.1.1.1) быстро отдают ответы, но при массовом переборе могут вас ограничить. Практика:

- Собирайте **большой список** публичных резолверов (репозитории `public-dns`/`resolvers`).
- Используйте `massdns`/`puredns` с параллелизмом — они шлют тысячи запросов/сек.
- Проверяйте резолверы на «открытость» и корректность (некоторые врут/фильтруют).
- Учитывайте **rate-limit**: слишком агрессивно → бан и потеря времени.
- Для тихого recon предпочитайте пассивные источники, активный брут — по необходимости.

```bash
# Проверка списка резолверов (пример с dnsvalidator/puredns)
puredns bruteforce wordlist.txt target.com -r resolvers.txt -w found.txt
```

Оптимальный баланс: сначала пассивно собрать базу, затем точечно добрутить небольшим словарём, а не «долбить» миллионами имён.

## Квиз

```quiz
- question: "Почему wildcard DNS мешает брутфорсу поддоменов?"
  options:
    - "Он замедляет резолв"
    - "Все имена резолвятся, давая тысячи ложных срабатываний"
    - "Он блокирует запросы"
    - "Он меняет TTL"
  answer: 1
  explanation: "При wildcard любое случайное имя резолвится, поэтому нужен фильтр."
- question: "Какой инструмент сочетает брутфорс и валидацию с wildcard-фильтром?"
  options:
    - "subfinder"
    - "puredns"
    - "dnsx"
    - "httpx"
  answer: 1
  explanation: "puredns делает высокоскоростной брут с фильтрацией wildcard."
- question: "Что такое vhost-фаззинг?"
  options:
    - "Перебор DNS-зон"
    - "Поиск виртуальных хостов через заголовок Host"
    - "Сканирование портов"
    - "Поиск сертификатов"
  answer: 1
  explanation: "ffuf с Host: FUZZ находит сайты без DNS-записи на том же IP."
- question: "Какой инструмент — быстрый пассивный сбор поддоменов?"
  options:
    - "massdns"
    - "subfinder"
    - "ffuf"
    - "dnsgen"
  answer: 1
  explanation: "subfinder собирает поддомены из множества пассивных источников."
- question: "Зачем нужны permutations (dnsgen/altdns)?"
  options:
    - "Для резолва"
    - "Чтобы сгенерировать новые варианты из известных поддоменов"
    - "Для сканирования портов"
    - "Для HTTPS"
  answer: 1
  explanation: "Перестановки расширяют список кандидатов из уже найденных имён."
```

## Где пригодится

- **Recon/пентест:** расширение поверхности атаки.
- **Bug bounty:** поиск забытых стендов.
- **Работа/SOC:** инвентаризация внешних активов.
- **CTF:** поиск скрытого поддомена с флагом.
