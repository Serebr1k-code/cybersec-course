---
id: cloud-cdn-edge
title: "CDN и edge: CloudFront, Cloudflare, origin-экспозиция"
category: cloud
parent: cloud-foundations-providers
difficulty: medium
order: 4
tags: [cloud, cdn, cloudfront, cloudflare, origin, waf, edge]
prerequisites: [cloud-fundamentals]
useful_for:
  - "Поиск origin-серверов за CDN"
  - "Понимание edge-безопасности"
  - "Bug bounty: обход WAF/CDN"
estimated_minutes: 40
summary: "Как атаковать облачный edge: поиск origin за CDN (CloudFront/Cloudflare), обход WAF, неправильные конфигурации кэша и заголовков. Практические приёмы и защита."
---
## Зачем этот урок

CDN (CloudFront, Cloudflare, Azure Front Door, Google Cloud CDN, Akamai) стоит перед приложением и в глазах многих команд «является защитой». Но CDN — это прежде всего **прокси с кэшем**, а не барьер. Если реальный сервер (origin) доступен напрямую, то WAF, rate limiting и TLS-политики edge можно обойти целиком. Плюс сам edge часто настроен неверно: кэширует приватное, доверяет подделанным заголовкам, оставляет origin без allowlist. Этот урок — про поиск origin, обход edge-защиты и типовые мисконфиги.

## Как работает CDN и что такое origin

Клиент обращается к домену, DNS возвращает IP ближайшего edge-узла. Edge решает, есть ли ответ в кэше; если нет — идёт к **origin** (настоящему серверу приложения или бакету S3), забирает ответ, кладёт в кэш и отдаёт клиенту. Origin виден только CDN, его IP скрыт от клиента.

Важно понимать: CDN добавляет и модифицирует заголовки — `X-Forwarded-For` (реальный IP клиента), `X-Forwarded-Proto` (схема), `Via`, `X-Amz-Cf-Id` (CloudFront), `CF-Connecting-IP` (Cloudflare). Приложение, доверяющее этим заголовкам, ломается, если запрос пришёл не от CDN.

## Скрытие origin: что CDN реально защищает

CDN прячет IP origin и может фильтровать по WAF. Но если origin:
- имеет публичный IP и открытый порт,
- не проверяет, что запрос пришёл от CDN (нет allowlist по IP, нет секретного заголовка),
— он полностью доступен атакующему в обход edge. Это самая частая и самая ценная находка в облачном внешнем периметре.

## Origin discovery: методика и инструменты

Цель — найти «настоящий» IP за CDN. Порядок действий:

1. **Исторические DNS** — старые A-записи до подключения CDN. Источники: SecurityTrails, crt.sh, ViewDNS, Passive DNS, DNSdumpster.
2. **Certificate Transparency** — `crt.sh` показывает выданные сертификаты и их SAN; иногда сертификат выдан на прямой IP или на origin-поддомен.
3. **Поддомены без CDN** — `direct.`, `origin.`, `dev.`, `staging.`, `mail.`, `ftp.` часто указывают прямо на origin.
4. **MX-записи** — почтовый сервер нередко стоит на том же хостинге, что origin.
5. **Фингерпринт контента** — favicon hash, уникальные строки в HTML, заголовок `Server`; поиск по Shodan/Censys находит тот же контент на другом IP.
6. **Сканирование диапазонов** провайдера (AWS/Azure/GCP/GCP) с проверкой `Host`-заголовка.

```bash
# crt.sh
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u
# исторические A-записи
dig +short A example.com @1.1.1.1
# поддомены
subfinder -d example.com -silent | httpx -silent -title
```

## Проверка кандидата в origin

Найденный IP нужно подтвердить: он должен отдавать тот же сайт при правильном `Host`.

```bash
# Сравниваем ответ по Host с origin-IP и с CDN-версией
curl -s -H "Host: example.com" http://<CANDIDATE_IP>/ | head -40
curl -s https://example.com/ | head -40
# Сравниваем favicon hash
curl -s http://<CANDIDATE_IP>/favicon.ico -H "Host: example.com" | md5sum
curl -s https://example.com/favicon.ico | md5sum
```

Совпадение favicon-хеша, заголовков и контента — надёжное подтверждение.

## Обход WAF и rate limiting через origin

Если origin не проверяет, что запрос пришёл от CDN, вы обращаетесь к нему напрямую и WAF больше не мешает:

```bash
curl -s -H "Host: example.com" http://<ORIGIN_IP>/admin
curl -s -H "Host: example.com" http://<ORIGIN_IP>/?id=1%27%20OR%20%271%27=%271
```

Так обходятся блокировки SQLi/XSS-пейлоадов, лимиты запросов и гео-ограничения. Не забудьте про HTTPS и SNI: `curl --resolve example.com:443:<ORIGIN_IP> https://example.com/admin`.

## Кэширование: приватный контент и Vary

Опасные конфигурации:
- CDN кэширует ответы, зависящие от `Authorization` или cookie, если приложение не отдаёт `Cache-Control: private`. Тогда контент одного пользователя раздаётся другому.
- Отсутствие `Vary: Cookie`/`Vary: Accept-Encoding` приводит к смешиванию вариантов.
- Долгий TTL на динамических страницах.

Проверка: сделайте два запроса с разными cookie и сравните `X-Cache`/`Age`/`CF-Cache-Status`. `HIT` на приватном ответе — баг.

## Cache poisoning и cache deception

**Cache poisoning**: если заголовок влияет на тело ответа, но **не входит** в ключ кэша, отравленный ответ раздаётся всем.

```
GET /?cb=1 HTTP/1.1
Host: example.com
X-Forwarded-Host: evil.com
```

Если приложение строит ссылки/редиректы из `X-Forwarded-Host`, в кэш попадёт ответ со ссылками на `evil.com`. Типичные ключи для отравления: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`.

**Cache deception**: CDN кэширует `/account/profile.css` (несуществующий статический путь), а приложение отдаёт приватную страницу профиля → её получает атакующий. Проверяйте, отдаёт ли сервер приватный контент по пути с «статическим» расширением.

## Заголовки X-Forwarded-* и доверие к ним

Origin может доверять `X-Forwarded-For` для определения IP клиента (обход IP-allowlist, спуфинг аудита), `X-Forwarded-Proto` для схемы (redirect/secure-cookie), `X-Forwarded-Host` для абсолютных URL. Если origin доступен напрямую, все эти заголовки подделываются.

```bash
curl -s -H "Host: example.com" -H "X-Forwarded-For: 127.0.0.1" http://<ORIGIN_IP>/admin
```

## CloudFront/Cloudflare-специфика

- **CloudFront**: origin access control (OAC) защищает S3-origin; если его нет, бакет открыт. Custom header (`X-Origin-Verify`) — секрет, который origin проверяет. Функции `Lambda@Edge`/`CloudFront Functions` могут содержать логику авторизации.
- **Cloudflare**: authenticated origin pulls (mTLS) и `CF-Connecting-IP`. Прямые IP Cloudflare — публичны и известны; allowlist по ним слабый.
- **Azure Front Door**: `X-Azure-FDID` — секретный ID, по которому origin проверяет источник.

## Разобранный пример: обход Cloudflare end-to-end

1. Находим домен за Cloudflare (заголовок `Server: cloudflare`, `CF-RAY`).
2. Ищем исторические DNS через crt.sh/SecurityTrails → старый IP.
3. Проверяем кандидата: `curl -s -H "Host: example.com" http://<OLD_IP>/ | head -5`.
4. Ответ совпадает с сайтом → origin найден.
5. Обращаемся к защищённым путям напрямую, минуя WAF: `curl -s -H "Host: example.com" http://<OLD_IP>/admin`.
6. Находим админку/уязвимость, которую WAF бы заблокировал.

## Защита и аудит edge

- **Origin allowlist**: принимать трафик только с IP CDN (security group / firewall).
- **Секретный заголовок** от CDN, который origin проверяет (CloudFront custom header).
- **Authenticated origin pulls** (Cloudflare) / **origin access control** (CloudFront→S3).
- Корректный кэш: не кэшировать приватное, добавлять `Vary`, явный `Cache-Control`.
- Включить `X-Forwarded-*` в ключ кэша там, где они влияют на ответ.
- Мониторить прямые обращения к origin и необычные `Host`.

## Частые ошибки

- **Считать CDN защитой.** Он прячет IP, но не гарантирует недоступность origin.
- **Игнорировать исторические DNS.** Старые записи выдают origin.
- **Не проверять origin allowlist.** Прямой доступ — частая находка.
- **Забыть про cache poisoning.** Заголовки, влияющие на контент, должны быть в ключе.
- **Не смотреть `X-Forwarded-*`.** Origin может доверять подделанным заголовкам.

## Что делать дальше / решение

Практика: возьмите домен за Cloudflare, соберите исторические DNS и поддомены, подтвердите origin по favicon-хешу, обойдите WAF. Дальше — `cloud-storage-s3` (S3-origin), `cloud-metadata-ssrf` (если origin — облачный инстанс) и `web-ssrf` для внутренней экспансии.

## CDN-специфичные заголовки и их подделка

При прямом обращении к origin проверьте, какие заголовки он доверяет: `X-Forwarded-For` (IP клиента), `X-Forwarded-Proto` (схема), `X-Forwarded-Host` (хост), `X-Real-IP`. Подделка `X-Forwarded-For: 127.0.0.1` может обойти IP-allowlist админки. `X-Forwarded-Proto: https` — обойти проверку «secure cookie only». CloudFront добавляет `X-Amz-Cf-Id`; Cloudflare — `CF-Connecting-IP`; Azure Front Door — `X-Azure-FDID`.

## TLS, SNI и привязка к origin

Origin может отдавать разные сайты по SNI. Проверяйте `curl --resolve example.com:443:<ORIGIN_IP> https://example.com/`. Если origin требует клиентский сертификат (mTLS), прямой доступ без него не сработает — тогда ищите утечку сертификата.

## Итоговый алгоритм

1. Определить CDN по заголовкам (`Server`, `CF-RAY`, `X-Amz-Cf-Id`).
2. Собрать исторические DNS и поддомены.
3. Подтвердить origin по favicon/контенту.
4. Обойти WAF прямым запросом с `Host`.
5. Проверить `X-Forwarded-*` и cache poisoning.
6. Задокументировать и оценить влияние.

## Квиз

```quiz
- question: "Что такое origin в контексте CDN?"
  options:
    - "Edge-сервер CDN"
    - "Настоящий сервер приложения за CDN"
    - "DNS-сервер"
    - "WAF-правило"
  answer: 1
  explanation: "Origin — источник контента, который CDN кэширует."
- question: "Как найти origin за Cloudflare?"
  options:
    - "Спросить у CDN"
    - "Через исторические DNS, crt.sh, MX и фингерпринт контента"
    - "Через SSH"
    - "Через whois"
  answer: 1
  explanation: "Исторические DNS-записи и фингерпринты часто выдают реальный IP."
- question: "Что произойдёт, если origin не проверяет, что запрос пришёл от CDN?"
  options:
    - "Ничего"
    - "Можно обращаться к origin напрямую, обходя WAF и rate limiting"
    - "Сайт упадёт"
    - "CDN отключится"
  answer: 1
  explanation: "Без allowlist/CDN-секрета origin доступен напрямую."
- question: "Что такое cache poisoning?"
  options:
    - "Шифрование кэша"
    - "Отравление кэша ответом, зависящим от подконтрольного заголовка, который раздаётся всем"
    - "Удаление кэша"
    - "Сжатие контента"
  answer: 1
  explanation: "Если заголовок влияет на контент, но не входит в ключ кэша, ответ можно отравить."
- question: "Как защитить origin за CDN?"
  options:
    - "Открыть origin в интернет"
    - "Разрешить трафик только с IP CDN или проверять секретный заголовок CDN"
    - "Отключить TLS"
    - "Убрать WAF"
  answer: 1
  explanation: "Allowlist по IP CDN или проверка custom header защищает origin."
```

## Где пригодится

- **Bug bounty** — обход WAF, origin discovery.
- **Пентест** — внешний периметр.
- **Red team** — прямой доступ к защищённым приложениям.
- **IR/Blue team** — оценка конфигурации edge.
- **DevSecOps** — настройка origin protection.
