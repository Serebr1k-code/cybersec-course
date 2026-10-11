---
id: cloud-route53-dns
title: "Route 53 и Cloud DNS: поддомен-хайджек, записи и атаки на DNS"
category: cloud
parent: cloud-foundations-providers
difficulty: medium
order: 3
tags: [cloud, route53, dns, subdomain-takeover, cloudfront, dangling]
prerequisites: [cloud-fundamentals]
useful_for:
  - "Поиск subdomain takeover в облаке"
  - "Анализ DNS-записей облачных сервисов"
  - "Bug bounty: dangling DNS"
estimated_minutes: 30
summary: "Как атаковать облачный DNS: dangling-записи и subdomain takeover (S3, CloudFront, App Service), анализ hosted zones, злоупотребление зонами и DNS-логами."
---
## Зачем этот урок

Облачный DNS — это точка, где абстракция «инфраструктура как код» встречается с реальным периметром. AWS Route 53, Azure DNS и Google Cloud DNS хранят записи, связывающие человекочитаемые имена с конкретными ресурсами. Если ресурс удалён, а запись осталась, образуется **dangling DNS** — и имя можно перехватить. Это один из самых дешёвых в исполнении и самых дорогих по выплатам классов багов: не нужен 0day, достаточно заметить рассинхрон между DNS и облаком. Разберём устройство зон, техники поиска dangling-записей, полный цикл subdomain takeover для четырёх провайдеров, злоупотребление делегированием и AXFR, а также мониторинг на стороне защитника.

## Как устроен облачный DNS

Hosted zone — контейнер записей для домена или поддомена. В Route 53 зона имеет уникальный ID (например `Z1D633PJN98FT9`) и бывает public (видна из интернета) или private (видна только внутри VPC). Каждая запись описывается парой name + type + TTL + value. Route 53 поддерживает псевдонимы **ALIAS**, которые позволяют ссылаться на ресурсы AWS (S3 website, CloudFront, ELB, API Gateway) в вершине зоны (`@`), где обычный CNAME запрещён. Azure DNS и Google Cloud DNS аналогичны, но вместо ALIAS используют обычные CNAME/A с «привязкой» через сервис. Важно: облачный DNS — API-first сервис, и любой, кто получил право `route53:ChangeResourceRecordSets`, может менять трафик всего домена.

## Типы записей и их роль в атаках

| Тип | Назначение | Атака |
|-----|-----------|-------|
| A / AAAA | IPv4 / IPv6-адрес | подмена на свой хост при захвате зоны |
| CNAME | псевдоним | главный источник dangling DNS |
| ALIAS | ссылка на ресурс AWS | takeover при удалённом ресурсе |
| NS | делегирование поддомена | захват поддомена через чужую зону |
| MX | почта | перехват письма при takeover |
| TXT | верификации, SPF, DKIM | обход проверок владения доменом |
| CAA | ограничения выдачи сертификатов | ослабление контроля |
| SRV | сервисы | обнаружение внутренней инфраструктуры |

## Hosted zones и делегирование

Внешний наблюдатель видит только NS-записи родительской зоны. Делегирование `sub.example.com` на чужие NS — распространённая практика в крупных компаниях (отдельные команды, регионы, продуктовые домены). Если такая делегированная зона разрешает AXFR или её NS указывают на захватываемый сервис — это отдельный вектор. Проверка:

```bash
dig NS sub.example.com +short
dig +noall +answer NS example.com
```

Если NS-ответ пуст, а CNAME ведёт на облако — проверяем сам ресурс.

## Dangling DNS и subdomain takeover

Сценарий: CNAME `shop.example.com → mybucket.s3.amazonaws.com`, но бакет `mybucket` удалён. Любой может создать бакет с этим именем в том же регионе — и `shop.example.com` начнёт отдавать контент атакующего. Типовые цели:

- **S3 static website** — `bucket.s3-website-<region>.amazonaws.com`.
- **CloudFront** — distribution удалён, CNAME остался.
- **Azure** — `*.azurewebsites.net`, `*.cloudapp.azure.com`, `*.trafficmanager.net`.
- **GCP** — `*.appspot.com`, `*.storage.googleapis.com`.
- **Heroku, GitHub Pages, Fastly, Shopify, Surge**.

Ключевой признак — «service-specific» страница ошибки: `NoSuchBucket`, `404 Web Site not found`, «There isn't a GitHub Pages site here», `NoSuchWebsiteConfiguration`.

## Поиск dangling-записей

Перечислить зону можно при наличии прав:

```bash
aws route53 list-hosted-zones --query 'HostedZones[].{Id:Id,Name:Name}' --output table
aws route53 list-resource-record-sets --hosted-zone-id Z1D633PJN98FT9 \
  --query 'ResourceRecordSets[?Type==`CNAME`]' --output json
```

Внешняя разведка не требует доступа:

```bash
dig +short CNAME shop.example.com
dig +short A mybucket.s3.amazonaws.com
curl -sI https://mybucket.s3.amazonaws.com | head -1
# HTTP/1.1 404 Not Found  (код NoSuchBucket) → имя свободно
```

Массово: собрать поддомены, отрезолвить CNAME, отфильтровать указывающие на облачные домены из списка fingerprint, затем проверить каждый.

## Инструменты внешней разведки

```bash
subfinder -d example.com -all -silent -o subs.txt
amass enum -passive -d example.com -o amass.txt
dnsx -l subs.txt -cname -resp -silent -o cnames.txt
subjack -w subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v -o subjack.txt
nuclei -l subs.txt -t http/takeovers/ -severity high,critical -silent -o nuclei-takeover.txt
```

Флаги: `subjack -t` — потоки, `-timeout` — секунды, `-ssl` — проверять HTTPS, `-c` — файл сигнатур, `-v` — подробно, `-o` — вывод. `nuclei -t` — шаблоны, `-severity`, `-silent`, `-o`. Альтернативы: `can-i-take-over-xyz` (каталог сигнатур), `dnsReaper`, `tko-subs`.

## Захват: пошаговый PoC для S3

```bash
aws s3api create-bucket --bucket mybucket --region us-east-1
aws s3 website s3://mybucket --index-document index.html --error-document error.html
printf 'takeover-poc' > index.html
aws s3 cp index.html s3://mybucket/ --acl public-read
curl -s https://shop.example.com
# takeover-poc
```

Для Azure: `az webapp create` с тем же именем в том же регионе, затем `az webapp deploy`. Для GCP App Engine: `gcloud app create --region=...` — имя проекта должно совпасть. Всегда фиксируйте доказательство (ответ `curl`, скриншот) и разворачивайте только безобидный маркер — правило ответственного раскрытия.

## Злоупотребление зонами и AXFR

- **Слабое делегирование**: поддомен отдан на zone, которую можно занять.
- **AXFR**: `dig AXFR example.com @ns1.example.com` — дамп всех записей, если трансфер разрешён.
- **Wildcard-записи** поглощают несуществующие имена и мешают детекту.
- **Права на зону**: перенаправление трафика, выпуск валидных TLS-сертификатов (ACME-проверка), перехват почты через MX.

## DNS-логи и безопасность

Route 53 Resolver Query Logs пишут все DNS-запросы в CloudWatch Logs или S3 — ценно для IR и threat hunting. DNSSEC криптографически защищает целостность ответов; проверяйте `dig +dnssec` и наличие DS-записей. TTL: короткий ускоряет переключение при инциденте, но и ускоряет распространение подмены.

## Разобранный пример: takeover через удалённый App Service

1. Находим CNAME: `app.example.com → myapp.azurewebsites.net`.
2. Проверяем: `curl -sI https://myapp.azurewebsites.net | head -1` → `404 Web App - Unavailable`.
3. Создаём App Service с именем `myapp` в том же регионе (имя глобально уникально в рамках Azure).
4. Деплоим `index.html` с маркером.
5. `curl -s https://app.example.com` отдаёт наш контент — takeover подтверждён.

## Защита и remediation

- Удалять DNS-записи **вместе** с ресурсами (deprovision в IaC).
- Регулярный скан dangling-записей (CI-джоб, nuclei).
- DNSSEC и CAA.
- Ограничение прав `route53:ChangeResourceRecordSets`.
- Оповещения об удалении ресурсов, на которые ссылаются записи.

## Частые ошибки и подводные камни

- Удалили ресурс — оставили запись (классика).
- Не проверяют ALIAS/CNAME на облако — выглядит «нормально».
- Игнорируют Azure/GCP/Heroku — takeover не только в S3.
- Забывают про wildcard, который маскирует уязвимые имена.
- Не сканируют регулярно — новые dangling появляются постоянно.
- Считают 404 доказательством: нужен фактический контроль контента, иначе это ложное срабатывание.

## Что дальше / решение

Найденная dangling-запись → зафиксировать доказательство, оформить отчёт с PoC-маркером, оценить влияние (cookie-скоуп, CSP, OAuth redirect). В рамках пентеста — записать находку, проверить цепочку (перехват сессии, фишинг) и двигаться к следующему ресурсу. Для защиты — внедрить автоматический мониторинг и удаление записей в pipeline.

## Проверка через историю DNS и Certificate Transparency

Dangling-записи часто «проявляются» через историю. Сервисы вроде SecurityTrails, ViewDNS и crt.sh хранят прошлые значения A/CNAME. Если поддомен когда-то указывал на облачный ресурс, а сейчас не резолвится — высока вероятность захвата. Certificate Transparency дополнительно показывает, для каких имён выпускались сертификаты: поддомен в CT, но отсутствующий в текущем DNS, — кандидат.

```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u
# затем проверяем каждый на резолв и на облачную сигнатуру
```

## Сравнение провайдеров и сигнатуры ошибок

| Провайдер | Ресурс | Сигнатура ошибки | Захватываемо |
|-----------|--------|------------------|--------------|
| AWS | S3 website | NoSuchBucket | да |
| AWS | CloudFront | Bad request / распределение удалено | частично |
| Azure | App Service | 404 Web Site not found | да |
| Azure | Traffic Manager | endpoint отсутствует | да |
| GCP | App Engine | 404 | да |
| GCP | Cloud Storage | NoSuchBucket | да |
| GitHub | Pages | There isn't a GitHub Pages site here | да |
| Heroku | dyno | No such app | да |
| Fastly | CDN | Fastly error: unknown domain | да |

## Практический чек-лист

1. Собрать все поддомены (subfinder + amass + CT).
2. Отрезолвить CNAME и A, сохранить в таблицу.
3. Отфильтровать цели, указывающие на облачные домены.
4. Прогнать subjack/nuclei/dnsReaper по списку.
5. Для каждого кандидата вручную проверить HTTP-ответ и захватываемость.
6. Зафиксировать PoC-маркер и оформить отчёт.
7. Оценить влияние: cookie domain, CSP allow-list, OAuth redirect_uri, CORS.

## Автоматизация в pipeline защитника

```bash
# ежедневный скан dangling-записей
dnsx -l zones.txt -cname -silent | grep -E 's3|cloudfront|azurewebsites|appspot|herokuapp' \
  | nuclei -t http/takeovers/ -severity high,critical -silent \
  | notify -provider slack
```

Регулярный прогон позволяет поймать dangling-запись между удалением ресурса и её эксплуатацией.

## Квиз

```quiz
- question: "Что такое dangling DNS?"
  options:
    - "Запись с длинным TTL"
    - "DNS-запись, указывающая на уже удалённый облачный ресурс, который можно занять"
    - "Запись без DNSSEC"
    - "Wildcard-запись"
  answer: 1
  explanation: "Dangling-запись ссылается на несуществующий ресурс — имя можно перехватить."
- question: "Какая запись Route 53 ссылается на ресурс AWS без ограничений CNAME?"
  options:
    - "TXT"
    - "ALIAS"
    - "MX"
    - "NS"
  answer: 1
  explanation: "ALIAS указывает на ресурсы AWS (S3, CloudFront и др.)."
- question: "Как подтвердить, что имя S3-бакета свободно для takeover?"
  options:
    - "Создать бакет и посмотреть"
    - "curl -I на bucket.s3.amazonaws.com — ответ NoSuchBucket означает, что имя свободно"
    - "Спросить владельца"
    - "Проверить через SSH"
  answer: 1
  explanation: "Ответ NoSuchBucket указывает, что бакет с таким именем не существует."
- question: "Какой инструмент ищет subdomain takeover по сигнатурам?"
  options:
    - "sqlmap"
    - "subjack или nuclei с шаблонами takeovers"
    - "Wireshark"
    - "hashcat"
  answer: 1
  explanation: "subjack и nuclei имеют сигнатуры уязвимых сервисов."
- question: "Что защищает от подмены DNS-ответов?"
  options:
    - "DNSSEC"
    - "HTTP/2"
    - "CORS"
    - "TLS 1.3"
  answer: 0
  explanation: "DNSSEC криптографически защищает целостность DNS-ответов."
```

## Где пригодится

- **Bug bounty** — subdomain takeover, высокооплачиваемые отчёты.
- **Пентест** — внешний периметр и DNS.
- **Red team** — фишинг и перехват трафика через захваченные поддомены.
- **IR/Blue team** — мониторинг dangling-записей.
- **DevSecOps** — процесс удаления DNS вместе с ресурсами.
