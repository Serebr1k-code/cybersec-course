---
id: osint-dns-core
title: "Модуль: домены, записи и поддомены"
category: osint
parent: osint-dns-recon
difficulty: medium
order: 2
tags: [osint, dns, whois, subdomains]
prerequisites: [osint-dns-recon]
useful_for:
  - "CTF misc/infra"
  - "Bug bounty"
  - "Пентест"
estimated_minutes: 15
summary: "Первый этап DNS-разведки: WHOIS/ASN, карта инфраструктуры, перечисление поддоменов и реверс-DNS."
lab:
  kind: shell
  title: "Практика: A/MX/NS записи через dig"
  toolset: [core, dig]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q '140.82.121.3' answer.txt"
  hints:
    - "`dig <домен> <ТИП> +noall +answer` печатает только ответ."
    - "A-запись — это IPv4-адрес."
    - "Можно короче: `dig +short github.com A`."
---

Этот модуль — промежуточный этап ветки «DNS-разведка и пассивный поиск поддоменов». Он собирает несколько последовательных уроков в единый учебный шаг и объясняет, зачем и в каком порядке их проходить. Начните с первого урока и двигайтесь по списку.

## Что покрывает модуль

1. **WHOIS, ASN и карта IP-инфраструктуры** (`osint-whois-asn`) — WHOIS, ASN и карта IP-инфраструктуры.
2. **Сканеры интернета: Shodan, Censys, FOFA и Certificate Transparency** (`osint-infrastructure`) — сканирование интернета: Shodan, Censys, FOFA, CT.
3. **Инструменты поддоменного перечисления: subfinder, amass, httpx** (`osint-subdomain-tools`) — поддомены: subfinder, amass, httpx.
4. **Реверс DNS, PTR и разведка по диапазонам IP** (`osint-reverse-dns`) — реверс DNS, PTR и разведка по диапазонам.

## Почему такой порядок

Начинаем с регистрационных данных (WHOIS/ASN), затем строим карту инфраструктуры, перечисляем поддомены и замыкаем реверс-DNS, чтобы расширить найденные диапазоны. Это ядро любой доменной разведки.

## Чему вы научитесь

- читать WHOIS и сопоставлять ASN с диапазонами;
- строить карту инфраструктуры по сканерам;
- перечислять поддомены пассивными и активными методами;
- расширять диапазоны через PTR-записи.

## Инструмент: dig — DNS-запросы

`dig` шлёт DNS-запросы и показывает ответ целиком: записи, авторитетные серверы, флаги. Основной инструмент DNS-разведки.

Ключи, которые пригодятся:
* `dig <имя>` — A-запись; `dig <имя> TXT` — текст (часто там секреты);
* `dig +short <имя> <тип>` — только значение, без «шапки»;
* `dig @<сервер> <имя>` — спросить конкретный резолвер;
* `dig axfr <домен> @<ns>` — попытка переноса зоны.

### Рабочий пример (как в лаборатории)

```
$ dig github.com MX +noall +answer
$ dig github.com MX +noall +answer
github.com.		377	IN	MX	0 github-com.mail.protection.outlook.com.

$ dig github.com TXT +noall +answer
github.com.		39	IN	TXT	"google-site-verification=82Le34Flgtd15ojYhHlGF_6g72muSjamlMVThBOJpks"
github.com.		39	IN	TXT	"jamf-site-verification=XtaPNIYghF_e_xRDI8CjgQ"
github.com.		39	IN	TXT	"TAILSCALE-xOzoDvFUzZr5YYVCQFuD"
github.com.		39	IN	TXT	"serval-domain-verification-ydryhj=qbkiEakpwEpTvHh5fIiCqtaue"
github.com.		39	IN	TXT	"atlassian-domain-verification=jjgw98AKv2aeoYFxiL/VFaoyPkn3undEssTRuMg6C/3Fp/iqhkV4HVV7WjYlVeF8"
github.com.		39	IN	TXT	"MS=6BF03E6AF5CB689E315FB6199603BABF2C88D805"
github.com.		39	IN	TXT	"docusign=087098e3-3d46-47b7-9b4e-8a23028154cd"
github.com.		39	IN	TXT	"google-site-verification=UTM-3akMgubp6tQtgEuAkYNYLyYAvpTnnSrDMWoDR3o"
github.com.		39	IN	TXT	"MS=ms44452932"
github.com.		39	IN	TXT	"miro-verification=d2e174fdb00c71e0bcf58f8e58c3da2dd80dcfa9"
github.com.		39	IN	TXT	"apple-domain-verification=RyQhdzTl6Z6x8ZP4"
github.com.		39	IN	TXT	"shopify-verification-code=t1YPwcmvnxZyBycaCpk1MPyWoFs72o"
github.com.		39	IN	TXT	"openai-domain-verification=dv-3nh33eQwdkotMIAzLrIDVZo1"
github.com.		39	IN	TXT	"cursor-domain-verification-gtfwmt=1rfLOtiTngX5QSxD5HvNKTvm3"
github.com.		39	IN	TXT	"krisp-domain-verification=ZlyiK7XLhnaoUQb2hpak1PLY7dFkl1WE"
github.com.		39	IN	TXT	"00Dd0000000hHE0=1TBKg000000TN2r"
github.com.		39	IN	TXT	"loom-site-verification=f3787154f1154b7880e720a511ea664d"
github.com.		39	IN	TXT	"facebook-domain-verification=39xu4jzl7roi7x0n93ldkxjiaarx50"
github.com.		39	IN	TXT	"anthropic-domain-verification-4az7qn=if8YWuRRqwLycGJDooumzHtxm"
github.com.		39	IN	TXT	"calendly-site-verification=at0DQARi7IZvJtXQAWhMqpmIzpvoBNF7aam5VKKxP"
github.com.		39	IN	TXT	"MS=ms58704441"
github.com.		39	IN	TXT	"adobe-idp-site-verification=b92c9e999aef825edc36e0a3d847d2dbad5b2fc0e05c79ddd7a16139b48ecf4b"
github.com.		39	IN	TXT	"stripe-verification=f88ef17321660a01bab1660454192e014defa29ba7b8de9633c69d6b4912217f"
github.com.		39	IN	TXT	"v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.2" "27.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all"
```

Подсказка из лаборатории: `dig [@сервер] <имя> <тип> [+short|+noall +answer] — DNS-клиент (эмуляция: вывод реального dig)`.

## Квиз

```quiz
- question: "Что даёт связка WHOIS + ASN?"
  options:
    - "Карту владения и IP-диапазонов"
    - "Пароль администратора"
    - "Содержимое бакета"
    - "Приватный ключ"
  answer: 0
  explanation: "ASN группирует диапазоны по владельцу."
- question: "Какой инструмент перечисляет поддомены пассивно и активно?"
  options:
    - "subfinder/amass"
    - "sqlmap"
    - "hydra"
    - "john"
  answer: 0
  explanation: "Это специализированные enumerator-ы."
- question: "Зачем нужен реверс-DNS?"
  options:
    - "Чтобы связать IP обратно с именами и расширить диапазон"
    - "Чтобы получить TLS-сертификат"
    - "Чтобы расшифровать пароль"
    - "Чтобы отключить WAF"
  answer: 0
  explanation: "PTR раскрывает имена хостов на диапазоне."
```

## Где пригодится

- **CTF:** задачи соответствующей категории, где нужен этот этап навыка.
- **Bug bounty:** разведка и эксплуатация в рамках легальной программы.
- **Пентест:** на этапах recon/enumeration/exploitation.
- **Работа:** в задачах SOC/IR и при оценке защищённости.
