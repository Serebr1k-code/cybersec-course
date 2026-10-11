---
id: web-subdomain-takeover-deep
title: "Subdomain takeover: провайдеры, DNS/NS/MX-тейковер"
category: web
parent: web-subdomain-takeover
difficulty: medium
order: 1
tags: [subdomain-takeover, dns, cname, ns, mx, providers, recon]
prerequisites: [web-subdomain-takeover, web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 36
summary: "Полный разбор subdomain takeover: список провайдеров, проверка CNAME/NS/MX, автоматизация и доказательство."
---

**Subdomain takeover** — это когда DNS-запись домена указывает на ресурс, который больше не существует/не принадлежит владельцу, и атакующий может **занять** этот ресурс, получив контроль над поддоменом. Базовый урок (`web-subdomain-takeover`) объясняет идею; здесь — **глубина**: каталог провайдеров, разные типы записей (CNAME/NS/MX/A), автоматизация и надёжное доказательство. Это классика bug bounty с высоким impact (фишинг, cookie-кража, обход CORS/`domain=`).

## Теория: почему возникает тейковер

Владелец создаёт `blog.example.com CNAME example-blog.s3.amazonaws.com`, затем удаляет bucket, но **запись остаётся**. Атакующий создаёт bucket с тем же именем → DNS указывает на его ресурс → он контролирует `blog.example.com`.

Причины:
- Удалённый ресурс (bucket, app, page), но DNS-запись жива.
- Истёкший/освобождённый сервис (Heroku, GitHub Pages, Netlify).
- Ошибочные/устаревшие записи.

## Теория: типы записей и векторы

- **CNAME** → сторонний сервис (самый частый).
- **NS** (delegation) → если домен делегирован на провайдера с освобождённой зоной, можно занять целую зону (NS takeover). Опаснее: контроль над поддоменом целиком.
- **MX** → если почтовый провайдер освободил домен, можно перехватить почту поддомена.
- **A/AAAA** → если IP теперь принадлежит другому (dangling IP), возможен контроль.
- **Проверка `_dmarc`/`_acme-challenge`** — иногда тоже.
- **Wildcard DNS** → если `*.example.com` указывает на сервис, любой несуществующий поддомен может быть угнан.

## Теория: каталог провайдеров и «отпечатки»

Каждый сервис имеет характерный **fingerprint** (страницу ошибки, которая говорит «нет такого ресурса»). Известные примеры:

| Провайдер | Отпечаток |
|-----------|-----------|
| AWS S3 | `NoSuchBucket` |
| GitHub Pages | `There isn't a GitHub Pages site here` |
| Heroku | `No such app` |
| Netlify | `Not Found - Request ID` |
| Shopify | `Sorry, this shop is currently unavailable` |
| Tumblr | `There's nothing here` |
| Zendesk | `Help Center Closed` |
| Fastly | `Fastly error: unknown domain` |
| Azure | `404 Web Site not found` |
| Surge | `project not found` |

Большой актуальный список — проект **can-i-take-over-xyz** (GitHub).

## Инструменты и команды

Собрать поддомены (см. `web-recon-fuzzing`) и найти CNAME:

```bash
for d in $(cat subs.txt); do
  cname=$(dig +short CNAME "$d")
  [ -n "$cname" ] && echo "$d -> $cname"
done
```

Проверить конкретный поддомен:

```bash
dig +short CNAME blog.target.local
dig +short NS sub.target.local
dig +short MX mail.target.local
```

Автоматизация — **subjack**, **nuclei** (templates `takeover`), **can-i-take-over-xyz**-чекер:

```bash
subjack -w subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v
nuclei -l subs.txt -t http/takeovers/ -silent
```

## Разобранный пример: CNAME takeover (S3)

Шаг 1. Находим dangling CNAME:

```bash
dig +short CNAME blog.target.local
# target-blog.s3.amazonaws.com
```

Шаг 2. Проверяем, отвечает ли S3 `NoSuchBucket`:

```bash
curl -s http://target-blog.s3.amazonaws.com/ | head -c 200
# <Error><Code>NoSuchBucket</Code>...
```

Шаг 3. (В рамках scope, только если разрешено занимать ресурс) Создаём bucket с тем же именем. Теперь `blog.target.local` обслуживается вашим содержимым. В отчёте: DNS-запись, отпечаток `NoSuchBucket`, доказательство контроля (например, свой файл на поддомене).

## Разобранный пример: NS takeover

Шаг 1. Проверяем делегирование:

```bash
dig +short NS internal.target.local
# ns1.abandoned-provider.net
```

Шаг 2. Если провайдер позволяет зарегистрировать освобождённую зону, вы получаете контроль над всеми записями `internal.target.local`. Доказываем через `dig` своей зоны. **Только в рамках scope и с осторожностью.**

## Частые ошибки

- **Останавливаться на CNAME.** NS/MX/A-тейковер опаснее и часто пропускается.
- **Не проверять отпечаток.** Наличие CNAME ≠ тейковер; нужен «нет ресурса»-ответ.
- **Забывать про wildcard.** `*.example.com` может угнаться массово.
- **Занимать ресурс без разрешения.** Это может нарушить правила; фиксируйте, но не злоупотребляйте.
- **Не перепроверять.** DNS/сервис могут восстановиться; тейковер надо подтверждать в моменте.

## MX, TXT и прочие «забытые» типы записей

Takeover — не только про CNAME. Любая запись, указывающая на внешний ресурс, может «повиснуть».

```bash
# MX на несуществующий/чужой почтовый сервис
dig +short MX mail.example.com
# если MX указывает на отключённый сервис — возможен перехват почты
```

| Тип | Сценарий takeover | Что получает атакующий |
|-----|-------------------|------------------------|
| CNAME | целевой сервис удалён | контроль поддомена (веб) |
| NS | делегирование на мёртвые NS | контроль всей зоны |
| MX | мёртвый почтовый провайдер | перехват почты домена |
| A/AAAA | IP переиспользован в облаке | занятие эластичного IP |
| TXT | SPF/DKIM/verify-токен | подмена верификации сервисов |
| NS делегация поддомена | sub-зона на чужой NS | полный контроль поддомена |

Dangling A/AAAA особенно коварны в облаках: освобождённый эластичный IP можно заново арендовать и «занять» старый адрес приложения.

## Автоматизация: массовый поиск «висящих» записей

```bash
# 1) собираем поддомены
subfinder -d example.com -silent -o subs.txt
# 2) резолвим CNAME и ищем неразрешённые
dnsx -l subs.txt -cname -resp -silent | tee cnames.txt
# 3) проверяем, что CNAME указывает на «мёртвый» сервис (NODATA)
while read c; do dig +short "$c" | grep -q . || echo "DANGLING: $c"; done < cnames.txt
```

```bash
# nuclei: шаблоны subdomain takeover по отпечаткам
nuclei -l subs.txt -tags takeover -j -silent | tee takeover.json
# subjack — классический сканер
subjack -w subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v
```

Отпечатки (fingerprints) — это строки вида «There isn’t a GitHub Pages site here», «NoSuchBucket», «404 Not Found» конкретных провайдеров. Их удобно держать в JSON и обновлять.

## Разобранный пример: GitHub Pages takeover

```bash
# 1) поддомен указывает на удалённую страницу GitHub Pages
dig +short blog.example.com
# blog.example.com.github.io.  (CNAME)

# 2) HTTP-ответ содержит отпечаток
curl -s https://blog.example.com | grep -i "There isn't a GitHub Pages site here"
# -> отпечаток найден, страница не привязана

# 3) создаём репозиторий blog.example.com.github.io и включаем Pages
# 4) проверяем контроль
curl -s https://blog.example.com | grep -i "hello"
```

После подтверждения контроля фиксируйте PoC: содержимое страницы, которое вы разместили, и HTTP-ответ. Для CTF это обычно флаг; в реальном пентесте — риск фишинга/кражи cookie с родительского домена.

## Что делать ПОСЛЕ takeover (и как это доказать)

Контроль поддомена — серьёзный риск, но действовать нужно безопасно:

- Разместите безобидную страницу-маркер (не фишинг, не вредоносный JS).
- Докажите риск: `document.domain`-совместимость, доступ к cookie родительского домена (если scope `.example.com`), возможность обхода `Secure`-флагов через HTTP-поддомен.
- Сделайте скриншот/запись HTTP-ответа как артефакт.
- **Не** трогайте чужие данные и не наносите ущерб.

```bash
# проверка, что поддомен может читать родительские cookie (в браузере)
# в консоли страницы поддомена:
document.cookie   # если видит cookie .example.com -> серьёзный риск
```

## Защита и почему она ломается

Правильная защита:

1. Регулярный аудит DNS: искать CNAME/NS/MX/A, указывающие на несуществующие цели.
2. Удалять записи **до** отключения внешнего сервиса.
3. Не выдавать поддомены под произвольные внешние хостинги.
4. Мониторинг (например, `dnsx`/`subjack` по расписанию).

Ломается обычно так: команда удаляет аккаунт в SaaS, но забывает DNS-запись; или переиспользует облачный IP без проверки, что на старый адрес уже кто-то претендует.

## Что делать дальше / решение

1. **Соберите поддомены.** subfinder/amass + сертификаты (crt.sh).
2. **Разрешите записи.** dnsx/massdns → CNAME/NS/MX.
3. **Найдите «висящие».** Отпечатки провайдеров, NODATA, 404-страницы сервисов.
4. **Подтвердите контроль.** Займите ресурс и покажите маркер.
5. **Оцените риск.** Cookie/`document.domain`, фишинг, обход TLS.
6. **Зафиксируйте PoC.** Запись DNS + HTTP-ответ + размещённый маркер.

## Практика и справочники

- **can-i-take-over-xyz** — каталог отпечатков и статусов.
- **subjack / subover / nuclei takeover** — автоматизация.
- **HackTricks** — «Subdomain Takeover».
- **crt.sh** — сертификаты для поиска поддоменов.

## Пайплайн непрерывного мониторинга takeover

Разовый скан ловит мало: записи появляются и «протухают» постоянно. Стройте пайплайн.

```bash
# 1) новые поддомены (в т.ч. из CT-логов)
subfinder -d example.com -silent -all | anew subs.txt
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | anew subs.txt

# 2) резолв и поиск CNAME на внешние сервисы
dnsx -l subs.txt -cname -resp -silent | anew cnames.txt

# 3) проверка «висящих» через отпечатки
subjack -w subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v 2>&1 | anew takeovers.txt

# 4) уведомление при находке
[ -s takeovers.txt ] && notify -data takeovers.txt
```

`anew` добавляет только новые строки — так вы видите **дельту**, а не один и тот же список. Запускайте по cron, обновляйте fingerprints.

## Таблица провайдеров: отпечаток → статус

| Провайдер | Отпечаток в ответе | Takeover возможен |
|-----------|--------------------|-------------------|
| GitHub Pages | «There isn't a GitHub Pages site here» | да |
| AWS S3 | `NoSuchBucket` | да |
| Heroku | «No such app» | да |
| Azure | «404 Web Site not found» | да |
| Shopify | «Sorry, this shop is currently unavailable» | да |
| Fastly | «Fastly error: unknown domain» | да |
| WordPress.com | «Do you want to register» | да |
| Surge.sh | «project not found» | да |
| Pantheon | «The gods are wise» | да |
| Tumblr | «There's nothing here» | да |
| Readme.io | «Project doesnt exist...» | да |
| Zendesk | «Help Center Closed» | да |

Актуальный и полный список — в репозитории **can-i-take-over-xyz**; его стоит подтягивать в fingerprints.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что такое subdomain takeover?"
  options:
    - "Занятие ресурса, на который указывает осиротевшая DNS-запись"
    - "Отравление кэша"
    - "SQL-инъекция"
    - "Отравление DNS"
  answer: 0
  explanation: "Владелец удалил ресурс, но запись осталась — вы занимаете ресурс."
- question: "Какой тип записи опаснее всего при тейковере?"
  options:
    - "NS (делегирование зоны)"
    - "TXT"
    - "SRV"
    - "CAA"
  answer: 0
  explanation: "NS-тейковер даёт контроль над всей зоной поддомена."
- question: "Что подтверждает S3-тейковер?"
  options:
    - "Ответ `NoSuchBucket` на CNAME-цели"
    - "Заголовок `Server`"
    - "Наличие cookie"
    - "Код 200 на главной"
  answer: 0
  explanation: "Отпечаток «ресурс не существует» + возможность его занять."
- question: "Какой инструмент автоматизирует поиск тейковеров?"
  options:
    - "`subjack` / `nuclei` (takeovers)"
    - "`sqlmap`"
    - "`hashcat`"
    - "`volatility`"
  answer: 0
  explanation: "subjack и nuclei-шаблоны проверяют отпечатки."
- question: "Почему наличие CNAME ещё не означает тейковер?"
  options:
    - "Нужен отпечаток «нет ресурса» и возможность занять его"
    - "CNAME всегда безопасен"
    - "CNAME шифруется"
    - "CNAME меняет cookie"
  answer: 0
  explanation: "Ресурс может быть жив и принадлежать владельцу."
```

## Где пригодится

- **CTF (Web):** задачи на recon и контроль поддомена.
- **Bug bounty:** subdomain takeover — классическая высокая выплата.
- **Пентест:** аудит DNS-инвентаря и внешних зависимостей.
- **Работа (AppSec/Dev):** удалять осиротевшие записи, инвентаризация DNS.
