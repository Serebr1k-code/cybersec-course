---
id: network-proxy-cdn-waf
title: "Прокси, CDN и WAF: инфраструктура на пути трафика"
category: network
parent: network-module-analysis
difficulty: medium
order: 3
tags: [network, proxy, cdn, waf, origin, xff, bypass]
prerequisites: [network-module-analysis]
useful_for:
  - "CTF Network (инфраструктура)"
  - "Пентест: поиск origin, обход WAF"
  - "Работа (SOC): анализ цепочки посредников"
estimated_minutes: 55
summary: "Forward/reverse прокси, CDN и WAF: как они меняют модель трафика, как найти реальный origin за CDN, как обходятся WAF и как анализировать заголовки цепочки (X-Forwarded-For, Via)."
---

Между клиентом и сервером почти всегда стоит посредник: прокси, CDN или WAF. Он кэширует, защищает и скрывает origin — и одновременно создаёт новые точки анализа и обхода. Понимание этой цепочки нужно и для пентеста (найти origin, обойти WAF), и для защиты (правильная конфигурация). Урок продолжает [`network-module-analysis`](network-module-analysis).

## Forward и reverse прокси

- **Forward proxy** — для клиентов: кэш, фильтрация, анонимизация.
- **Reverse proxy** — перед серверами: балансировка, TLS-терминация, кэш (nginx, HAProxy).

Reverse-прокси часто добавляет заголовки о клиенте: `X-Forwarded-For`, `X-Real-IP`, `Via`. Они нужны приложению, но **подделываются**, если прокси не доверенный.

```bash
# Увидеть заголовки цепочки
curl -sI http://example.com | grep -iE 'server|via|x-forwarded|x-cache'
```

## CDN: кэш и защита на границе

**CDN** (Cloudflare, Akamai, Fastly) раздаёт контент с edge-серверов и защищает origin. Клиент видит edge-IP, а не реальный сервер. Это скрывает origin, но не делает его недоступным.

```bash
# Определить CDN по заголовкам/сертификату
curl -sI https://example.com | grep -iE 'cf-ray|server|akamai|x-cache'
dig +short example.com
# Сертификат может раскрыть вендора
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -issuer
```

## WAF: фильтр HTTP

**WAF** анализирует HTTP-запросы и блокирует атаки (SQLi, XSS, RCE) по правилам/эвристикам. Бывает сетевой, хостовый и облачный. WAF — не «серебряная пуля»: его можно обходить.

```bash
# Определить WAF (wafw00f)
wafw00f https://example.com
# Проверить реакцию на простой payload
curl -s -o /dev/null -w '%{http_code}\n' "https://example.com/?q=<script>alert(1)</script>"
```

## Поиск реального origin за CDN

Origin часто можно найти через:

- **DNS-историю** (старые A-записи);
- **сертификаты** (crt.sh, SAN);
- **поддомены**, не закрытые CDN (dev, direct, origin, mail);
- **утечки** (SSRF, `X-Forwarded-For` в ответах);
- **сравнение** поведения edge и прямых IP.

```bash
# DNS-история (пример через securitytrails API)
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/a" -H 'APIKEY: ...' | jq .
# Поддомены
for s in direct origin dev staging ftp mail cpanel; do dig +short $s.example.com; done
# Certificate Transparency
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u
```

## Обход WAF

- **кодирование** — URL/double-encoding, Unicode;
- **регистр и комментарии** — `UnIoN/**/SeLeCt`;
- **разделение параметров** — HPP;
- **альтернативные пути** — обход по поддомену/origin;
- **chunked/CL.TE** — request smuggling (см. web-ветку);
- **IP-спуфинг заголовков** — `X-Forwarded-For` для внутренних правил.

```bash
# Простой обход кодированием (лаборатория)
curl "https://example.com/?id=1%2527%2520or%25201=1"
# Обход через origin-IP с Host-заголовком
curl -H 'Host: example.com' http://<origin-ip>/
```

## Анализ цепочки в дампе

```bash
# Заголовки посредников в HTTP-трафике
tshark -r cap.pcap -Y 'http.request' -T fields -e http.host -e http.user_agent \
  -e http.x_forwarded_for | head
# Кэш-заголовки
tshark -r cap.pcap -Y 'http.response' -T fields -e http.response.code \
  -e http.cache_control -e http.x_cache | head
```

## Защита

| Мера | Против чего |
|---|---|
| Доверять XFF только от своих прокси | спуфинг логов |
| Скрыть origin (firewall по IP CDN) | прямой доступ |
| WAF + мониторинг + тюнинг | обход |
| Не полагаться только на WAF | defense in depth |
| Убрать лишние поддомены | поиск origin |
| Кэш-политики корректно | утечки |

## Частые ошибки

- **Доверять X-Forwarded-For** — подделывается.
- **Считать CDN «защитой origin»** — origin находят.
- **Полагаться только на WAF** — обходится кодированием.
- **Забывать про поддомены** — dev/direct не за CDN.
- **Не проверять кэш** — утечки между пользователями.
- **Игнорировать сертификаты** — SAN раскрывает origin.
- **Не мониторить обход** — атака проходит «мимо» WAF.

## Что дальше / решение

После инфраструктуры вернитесь к [`network-module-analysis`](network-module-analysis). Для веб-обхода — раздел web (WAF bypass, request smuggling). Для детекта — [`network-ids-suricata`](network-ids-suricata).

## Практика: анализ цепочки посредников

```bash
# 1. Заголовки ответа (CDN/WAF/прокси)
curl -sI https://example.com | grep -iE 'server|via|cf-ray|x-cache|x-amz|akamai'
# 2. Идентификация WAF
wafw00f https://example.com
# 3. Проверка origin-гипотез
for s in direct origin dev staging ftp mail; do echo "== $s"; dig +short $s.example.com; done
# 4. Certificate Transparency
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u
# 5. Заголовки XFF в дампе
tshark -r cap.pcap -Y 'http.request' -T fields -e http.host -e http.x_forwarded_for | head
```

## Сравнение прокси, CDN и WAF

| Система | Уровень | Функция | Скрывает |
|---|---|---|---|
| Forward proxy | прикл. | кэш/фильтр для клиентов | клиента |
| Reverse proxy | прикл. | балансировка/TLS | серверы |
| CDN | прикл./сеть | кэш/защита на границе | origin |
| WAF | прикл. | фильтр HTTP | (не скрывает) |
| Load balancer | L4/L7 | распределение | backend |

## Итог по инфраструктуре

Посредники на пути трафика меняют и защиту, и анализ:

- **CDN** скрывает origin, но origin находится по истории/сертификатам/поддоменам;
- **WAF** фильтрует, но обходится кодированием и нестандартными запросами;
- **заголовки цепочки** (XFF, Via) полезны, но подделываются.

Практический вывод: не полагайтесь на один слой. Origin закрывают firewall'ом по IP CDN, WAF дополняют мониторингом, а заголовки доверяют только от своих прокси. Для пентеста — ищите origin и обходите WAF, для SOC — детектируйте подделки заголовков.

## Модель угроз посредников

Посредники — это и защита, и поверхность атаки. Разберём по слоям.

**Прокси.** Обратный прокси терминирует TLS и передаёт `X-Forwarded-For`. Если он не проверяет источник, приложение получает подделанный IP — отсюда обход IP-фильтров и порча логов. Прямое подключение к backend в обход прокси — отдельный риск.

**CDN.** Origin скрыт, но часто достижим напрямую, если firewall пропускает по IP или не настроен. Найти origin помогают DNS-история, сертификаты, незакрытые поддомены и различия в поведении edge/origin.

**WAF.** Фильтрует HTTP, но обходится кодированием, регистром, комментариями, HPP, request smuggling. WAF не заменяет безопасный код — только снижает вероятность эксплуатации.

**Load balancer.** Распределяет нагрузку, но может раскрывать backend-хосты через заголовки/ошибки. Health-check и служебные пути иногда доступны снаружи.

```bash
# Проверить прямой доступ к origin (лаборатория)
curl -H 'Host: example.com' http://<origin-ip>/ | head
# Проверить реакцию на кодированный payload
curl -s -o /dev/null -w '%{http_code}\n' "https://example.com/?q=%253Cscript%253E"
```

## Итоговый вывод

Инфраструктура на пути — это слои доверия, которые надо явно проверять. Origin закрывают firewall'ом по IP CDN, XFF доверяют только от своих прокси, WAF дополняют мониторингом и безопасным кодом. Для пентеста — ищите origin, обходите WAF, тестируйте заголовки; для SOC — детектируйте подделки и аномалии цепочки.

## Мини-практикум: найти origin и обойти WAF

```bash
# 1. Подтвердить наличие CDN/WAF
curl -sI https://target.example | grep -iE 'server|cf-ray|x-cache'
wafw00f https://target.example
# 2. Собрать поддомены и историю
curl -s 'https://crt.sh/?q=%25.target.example&output=json' | jq -r '.[].name_value' | sort -u
for s in direct origin dev ftp mail; do dig +short $s.target.example; done
# 3. Проверить прямой origin по IP с Host
curl -H 'Host: target.example' http://<candidate-ip>/ -m 5 | head
# 4. Проверить обход WAF кодированием
curl -s -o /dev/null -w '%{http_code}\n' "https://target.example/?q=%253Cscript%253E"
# 5. Проверить XFF-спуфинг
curl -s -H 'X-Forwarded-For: 127.0.0.1' https://target.example/admin -o /dev/null -w '%{http_code}\n'
```

## Итоговый вывод

Инфраструктура на пути — это слои, каждый из которых нужно проверять отдельно. CDN не гарантирует недоступность origin; WAF не гарантирует отсутствие уязвимостей; заголовки цепочки не гарантируют достоверность IP. Для пентеста это три вектора: найти origin, обойти WAF, использовать доверие к заголовкам. Для защиты — закрыть origin, не полагаться только на WAF и доверять заголовкам лишь от своих посредников.

## Квиз

```quiz
- question: "Чем reverse proxy отличается от forward?"
  options:
    - "Стоит перед серверами и обслуживает клиентов"
    - "Работает только по UDP"
    - "Шифрует DNS"
    - "Назначает MAC"
  answer: 0
  explanation: "Reverse proxy — перед серверами, forward — для клиентов."
- question: "Что скрывает CDN?"
  options:
    - "Реальный origin-сервер"
    - "IP клиента"
    - "TLS-сертификат"
    - "HTTP-метод"
  answer: 0
  explanation: "Клиент видит edge-адреса, origin скрыт."
- question: "Какой заголовок часто подделывают для обхода правил?"
  options:
    - "X-Forwarded-For"
    - "Content-Type"
    - "Accept"
    - "Host"
  answer: 0
  explanation: "XFF используется для IP-фильтров и легко подделывается."
- question: "Как часто находят origin за CDN?"
  options:
    - "По DNS-истории, сертификатам и незакрытым поддоменам"
    - "Через ping CDN"
    - "По MAC-адресу"
    - "Через DHCP"
  answer: 0
  explanation: "Origin раскрывают история, CT-логи и поддомены."
- question: "Почему WAF не является полной защитой?"
  options:
    - "Его можно обойти кодированием и нестандартными запросами"
    - "Он замедляет"
    - "Он требует TLS"
    - "Он меняет IP"
  answer: 0
  explanation: "WAF обходят; нужна defense in depth."
```

## Где пригодится

- **CTF:** задачи с посредниками и origin.
- **Пентест:** поиск origin, обход WAF.
- **SOC:** анализ цепочки и подделок заголовков.
- **Инженерия:** настройка CDN/WAF/прокси.
