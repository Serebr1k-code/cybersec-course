---
id: web-subdomain-takeover
title: "Subdomain Takeover"
category: web
parent: web-recon-surface
difficulty: easy
order: 4
tags: [subdomain-takeover, dns, cname, dangling, cloud, s3, github-pages]
prerequisites: [web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 30
summary: "Как найти «висящий» CNAME на заброшенный сервис и занять поддомен чужой компании."
---

**Subdomain takeover** — это когда поддомен компании (например, `blog.target.com`) указывает CNAME-записью на внешний сервис (GitHub Pages, Heroku, S3, Azure), который больше не существует. Атакующий регистрирует этот сервис и получает контроль над поддоменом: размещает там свой контент, читает cookie домена (если `Domain=.target.com`), обходит CSP и OAuth-whitelist. Это популярная и хорошо оплачиваемая находка.

## Теория: как возникает

1. Компания завела `CNAME blog.target.com -> target-org.github.io`.
2. Проект удалили (страницу на GitHub Pages), но DNS-запись осталась.
3. Запрос к `blog.target.com` возвращает «404 / no such app / repository not found».
4. Атакующий создаёт у того же провайдера ресурс с нужным именем → поддомен снова «живой», но уже под его контролем.

Признаки «висящей» записи: CNAME на сервис + ответ сервиса об отсутствии ресурса:

| Сервис | Признак |
|--------|---------|
| GitHub Pages | «There isn't a GitHub Pages site here» |
| Heroku | «No such app» |
| AWS S3 | «NoSuchBucket» |
| Azure | «404 Web Site not found» |
| Shopify | «Sorry, this shop is currently unavailable» |
| Netlify | «Not Found - Request ID» |
| Fastly/CloudFront | «ERROR: The request could not be satisfied» |

## Теория: impact

- **Phishing/доверие:** поддомен `login.target.com` с фишингом.
- **Кража cookie:** если cookie выставлена с `Domain=.target.com`, поддомен её получит.
- **Обход CSP/`frame-ancestors`:** доверенный поддомен из whitelist.
- **OAuth `redirect_uri`:** если домен в whitelist клиента — увод кода.
- **Same-origin:** поддомен может взаимодействовать с родительским доменом через `document.domain` (устаревшее) или просто вводить в заблуждение.
- **Почта:** иногда через MX/поддомен.

## Инструменты: DNS и массовый поиск

Проверить CNAME и ответ:

```bash
dig +short CNAME blog.target.com
curl -s -i http://blog.target.com | head -20
```

Массовый поиск «висящих» записей — **subjack**, **nuclei** (шаблоны `takeover`), **dnsReaper**, **can-i-take-over-xyz** (список сервисов).

Собрать поддомены (см. `web-recon-fuzzing`) и проверить:

```bash
subfinder -d target.com -silent > subs.txt
subjack -w subs.txt -t 20 -timeout 20 -ssl -v
```

nuclei:

```bash
nuclei -l subs.txt -tags takeover -silent
```

Проверить конкретный CNAME вручную:

```bash
dig +short CNAME blog.target.com
# target-org.github.io.
curl -s http://target-org.github.io/ | grep -i "isn't a GitHub Pages"
```

## Разобранный пример: takeover GitHub Pages

Шаг 1. Находим подозрительный поддомен:

```bash
dig +short CNAME blog.target.com
# target-org.github.io.
```

Шаг 2. Проверяем, существует ли ресурс:

```bash
curl -s -i http://blog.target.com/ | head -5
# HTTP/1.1 404
# ... "There isn't a GitHub Pages site here."
```

Шаг 3. Проверяем, что имя `target-org` на GitHub свободно. Если да — **это подтверждённый takeover** (не «возможно»). В легальном тесте создавать репозиторий нельзя без разрешения; в CTF — создаёте и получаете поддомен.

Шаг 4. Доказательство: `dig CNAME` + ответ сервиса «не существует» + (в CTF) фактическое занятие имени. В отчёте bug bounty достаточно показать CNAME на несуществующий ресурс; для PoC иногда создают ресурс с уникальным именем, доказывая контроль.

## Разобранный пример: S3-бакет takeover

Шаг 1. Находим CNAME на S3:

```bash
dig +short CNAME assets.target.com
# assets-target.s3.amazonaws.com.
```

Шаг 2. Запрашиваем:

```bash
curl -s -i http://assets.target.com/ | grep -i 'NoSuchBucket'
```

`NoSuchBucket` означает, что бакет удалён и имя, возможно, свободно → можно создать бакет с тем же именем и раздавать свой контент через `assets.target.com`.

## Частые ошибки

- **Путать CNAME на «правильный» сервис с takeover.** Нужен именно ответ «ресурс не существует».
- **Не проверять, занято ли имя.** Иногда имя уже пересоздано — takeover невозможен.
- **Игнорировать поддомены из JS/сертификатов.** Ищите имена в CT-логах (crt.sh), в бандлах, в мобильных приложениях.
- **Забывать про wildcard DNS.** Wildcard может маскировать висящие записи.
- **Создавать ресурс без разрешения.** В bug bounty часто достаточно доказательства; иначе — нарушение.
- **Не проверить, что поддомен в scope.** Только разрешённые домены.

## Каталог отпечатков провайдеров

Takeover подтверждается, когда DNS-запись указывает на сервис, который отдаёт «нет такого ресурса» и позволяет его занять.

| Провайдер | Отпечаток | Тип |
|-----------|-----------|-----|
| GitHub Pages | «There isn't a GitHub Pages site here» | CNAME |
| AWS S3 | `NoSuchBucket` | CNAME |
| Heroku | «No such app» | CNAME |
| Azure | «404 Web Site not found» | CNAME |
| Shopify | «Sorry, this shop is currently unavailable» | CNAME |
| Fastly | «Fastly error: unknown domain» | CNAME |
| Surge.sh | «project not found» | CNAME |
| Zendesk | «Help Center Closed» | CNAME |
| WordPress.com | «Do you want to register» | CNAME |
| Tumblr | «There's nothing here» | CNAME |

```bash
# определение отпечатка вручную
curl -s https://blog.example.com | grep -iE "There isn't|NoSuchBucket|No such app"
```

## NS, MX, A/AAAA: не только CNAME

| Тип записи | Сценарий | Что даёт |
|-----------|----------|----------|
| NS | делегирование на мёртвые NS | контроль зоны/поддомена |
| MX | мёртвый почтовый сервис | перехват почты |
| A/AAAA | освобождённый облачный IP | занятие адреса |
| TXT | verify-токен сервиса | подмена верификации |

```bash
# поиск «висящих» записей
dig +short NS sub.example.com
dig +short MX mail.example.com
dig +short A old.example.com
# проверка, что цель не существует
dig +short sub.example.com
```

## Массовый поиск и автоматизация

```bash
# 1) поддомены
subfinder -d example.com -silent -all | anew subs.txt
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | anew subs.txt
# 2) резолв CNAME
dnsx -l subs.txt -cname -resp -silent | anew cnames.txt
# 3) сканеры takeover
subjack -w subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v
nuclei -l subs.txt -tags takeover -j -silent | tee takeover.json
```

## Impact: почему это серьёзно

```text
- фишинг на доверенном домене (высокое доверие)
- кража cookie родительского домена (если scope .example.com)
- обход Secure-флагов (HTTP-поддомен + document.domain)
- обход CORS/`document.domain`-проверок
- получение валидных TLS-сертификатов для поддомена
```

## Разобранный пример: S3 bucket takeover

```bash
# 1) CNAME указывает на несуществующий бакет
dig +short assets.example.com
# assets.example.com.s3.amazonaws.com.
curl -s https://assets.example.com | grep NoSuchBucket
# 2) регистрируем бакет с тем же именем
aws s3 mb s3://assets.example.com
# 3) размещаем маркер
echo 'taken over' | aws s3 cp - s3://assets.example.com/index.html
# 4) проверяем контроль
curl -s https://assets.example.com
```

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `subfinder`/`amass` | поддомены |
| `dnsx`/`massdns` | резолв записей |
| `subjack`/`subover` | takeover-сканер |
| `nuclei -tags takeover` | отпечатки |
| `crt.sh` | сертификаты |

## Что делать дальше / решение

1. **Соберите поддомены.** subfinder + crt.sh.
2. **Разрешите записи.** CNAME/NS/MX/A.
3. **Найдите «висящие».** Отпечатки провайдеров.
4. **Подтвердите контроль.** Займите ресурс, разместите маркер.
5. **Оцените риск.** Cookie/`document.domain`/TLS.
6. **Зафиксируйте PoC.** Запись DNS + HTTP-ответ.

## Практика и справочники

- **can-i-take-over-xyz** — каталог отпечатков.
- **HackTricks** — «Subdomain Takeover».
- **nuclei** — takeover-шаблоны.
- **subjack** — сканер.

## Приоритеты при поиске takeover

Соберите поддомены (`subfinder` + `crt.sh`), разрешите записи (`dnsx`) и найдите CNAME/NS/MX, указывающие на несуществующие цели. Проверьте отпечатки провайдеров в HTTP-ответе. Подтвердите контроль, заняв ресурс и разместив безобидный маркер. Оцените риск: cookie родительского домена, `document.domain`, TLS-сертификаты. Не выходите за рамки — никакого фишинга и вредоносного кода, только доказательство контроля.

## Кратко

1. Поддомены (subfinder/crt.sh).
2. Резолв записей (dnsx).
3. Поиск «висящих» (отпечатки).
4. Подтверждение контроля (маркер).
5. Оценка риска (cookie/TLS).
6. PoC — DNS + HTTP-ответ.

## Практика

- **can-i-take-over-xyz** — отпечатки.
- **subjack** — сканер.
- **nuclei -tags takeover** — шаблоны.

## Расширенный разбор: почему takeover живуч

Takeover возникает из-за рассинхрона между DNS-записями и жизненным циклом внешних сервисов. Команды удаляют аккаунт в SaaS или освобождают облачный ресурс, но забывают удалить DNS-запись — и она продолжает указывать на ресурс, который может занять кто угодно. В облаках добавляется переиспользование IP: освобождённый эластичный адрес можно заново арендовать, и старые A-записи начинают указывать на вашу инфраструктуру. Поэтому проверять нужно не только CNAME, но и NS/MX/A/TXT.

```bash
# пример «висящей» A-записи в облаке
dig +short old.example.com          # 203.0.113.10 (освобождён)
# если адрес переиспользуется -> занятие через аренду того же IP
```

Практический вывод: регулярный аудит DNS (а не разовый скан) — единственный надёжный способ ловить эти записи до того, как их найдёт атакующий.

## Итоговая заметка

Takeover — редкий, но высокоценный класс: он даёт контроль над доверенным поддоменом без эксплуатации уязвимости в коде. Проверяйте DNS регулярно, фиксируйте находки записями и всегда подтверждайте контроль безобидным маркером. Помните, что NS/MX/A-записи не менее опасны, чем CNAME.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что такое subdomain takeover?"
  options:
    - "Захват DNS-сервера"
    - "Занятие поддомена через CNAME на заброшенный внешний сервис"
    - "Перебор поддоменов"
    - "Кража TLS-сертификата"
  answer: 1
  explanation: "Висящий CNAME позволяет зарегистрировать ресурс и получить контроль."
- question: "Какой ответ сервиса указывает на потенциальный takeover?"
  options:
    - "`200 OK` с контентом"
    - "«There isn't a GitHub Pages site here» / «NoSuchBucket»"
    - "`301 Moved Permanently`"
    - "`403 Forbidden`"
  answer: 1
  explanation: "Ответ об отсутствии ресурса при существующем CNAME — признак."
- question: "Чем опасен takeover поддомена для cookie?"
  options:
    - "Cookie исчезают"
    - "Cookie с `Domain=.target.com` уйдёт на захваченный поддомен"
    - "Cookie шифруются"
    - "Ничем"
  answer: 1
  explanation: "Поддомен получает cookie родительского домена."
- question: "Какой инструмент ищет takeover массово?"
  options:
    - "`nmap`"
    - "`subjack` / `nuclei -tags takeover`"
    - "`sqlmap`"
    - "`binwalk`"
  answer: 1
  explanation: "Они проверяют список поддоменов на «висящие» CNAME."
- question: "Почему takeover поддомена усиливает OAuth-атаки?"
  options:
    - "Он ускоряет логин"
    - "Доверенный поддомен может быть в whitelist `redirect_uri`, уводя код"
    - "Он шифрует токен"
    - "Он отключает state"
  answer: 1
  explanation: "Whitelist по домену доверяет и поддомену."
```

## Где пригодится

- **CTF (Web):** takeover-задачи требуют найти висящий CNAME и занять сервис для получения флага.
- **Bug bounty:** subdomain takeover — стабильно оплачиваемый класс (medium/high).
- **Пентест:** инвентаризация поддоменов и проверка CNAME — часть внешнего периметра.
- **Работа (AppSec/Dev):** удаление DNS-записей при выводе сервисов — базовая гигиена инфраструктуры.
