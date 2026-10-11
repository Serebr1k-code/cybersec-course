---
id: osint-zone-transfer
title: "Трансфер зоны DNS (AXFR) и перебор записей"
category: osint
parent: osint-dns-archive
difficulty: medium
order: 2
tags: [dns, axfr, zone-transfer, bind, enumeration]
prerequisites: [osint-dns-recon]
useful_for:
  - "Пентест: мгновенная карта зоны"
  - "CTF: поиск скрытых поддоменов"
estimated_minutes: 45
summary: "Как работает AXFR, почему он бывает открыт, как его запросить dig/флагами и что делать, если трансфер запрещён (перебор типов запросов и имён)."
---

Трансфер зоны — легитимный механизм синхронизации DNS-серверов: вторичный сервер забирает у первичного **всю** зону целиком. Если администратор забыл ограничить, кто может делать AXFR, зона утекает целиком — это одна из самых быстрых находок в разведке.

## Как работает AXFR

- Первичный сервер (master) держит зону; вторичные (slave) реплицируют её через `AXFR`.
- Разрешать AXFR можно списком IP (`allow-transfer { 10.0.0.2; }` в BIND).
- Если список пуст или содержит `any` — зону может забрать кто угодно.
- Зона передаётся по **TCP/53** (не UDP), поэтому запрос легко отличить по протоколу.
- Есть ещё `IXFR` (инкрементальный) — но для разведки нужен полный `AXFR`.

## Запрос AXFR

```bash
# прямой запрос к авторитетному серверу домена
dig AXFR example.com @ns1.example.com

# узнать NS, затем перебрать каждый
dig +short NS example.com
for ns in $(dig +short NS example.com); do
  echo "== $ns =="
  dig AXFR example.com @$ns +noall +answer
done
```

`host` делает то же короче:

```bash
host -l example.com ns1.example.com
```

Если ответ содержит много строк `IN A/CNAME/MX/TXT` — трансфер открыт. Если `Transfer failed` или `connection refused` — закрыт.

## Что видно в успешном AXFR

- **Все имена зоны**, включая внутренние: `db`, `backup`, `test`, `vpn`, `git`.
- **Полные CNAME-цепочки** и почтовые записи.
- **TXT** с ключами, верификациями, иногда паролями в комментариях.
- **SRV** — адреса сервисов (LDAP, SIP, Kerberos).
- **Serial** — дата последнего изменения зоны (по формату `YYYYMMDDnn`).

## Если AXFR закрыт

Отказ не значит «пусто». Переходите к перебору:

```bash
# перебор типов записей по домену
for t in A AAAA MX TXT NS SOA SRV CAA; do echo "== $t =="; dig example.com $t +short; done

# перебор имён словарём (dnsx)
dnsx -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -silent -a -resp

# проверка зоны на wildcard перед брутфорсом
dig +short random123456.example.com
```

Если `random123456.example.com` резолвится — у зоны wildcard, и брутфорс утонет в ложных срабатываниях. Сравнивайте ответы и отбрасывайте имена, резолвящиеся в wildcard-адрес.

## Смежные слабости

- **NSEC-walking** (при DNSSEC): NSEC-записи позволяют перечислить зону по цепочке, даже когда AXFR закрыт.
- **Открытый резолвер**: рекурсивный сервер, отвечающий всем, — отдельная находка (DNS amplification).
- **DNS-сервер как сервис**: если порт 53 открыт на самом хосте, проверьте версию (`dig chaos txt version.bind @ip`).
- **Динамические обновления**: незащищённый `nsupdate` может позволить менять записи.
- **Кэш-снупинг**: если есть доступ к рекурсивному резолверу.

## Разбор кейса

Задача: получить карту зоны `example.com`.

1. `dig +short NS example.com` → `ns1.example.com`, `ns2.example.com`.
2. `dig AXFR example.com @ns1.example.com` → `Transfer failed` (закрыт).
3. Пробуем `ns2.example.com` → тоже закрыт.
4. Проверяем wildcard: `dig +short random123.example.com` → пусто (wildcard нет).
5. Брутфорс: `dnsx -d example.com -w subdomains.txt -a -resp` → находим `dev`, `staging`, `vpn`.
6. Фиксируем: имена зоны, IP, тип записей.

## Частые ошибки

- **Запрашивать AXFR по UDP**: трансфер работает только по TCP — используйте `dig` (он сам переключится) или `dig +tcp`.
- **Останавливаться на первом NS**: разные NS могут иметь разную конфигурацию `allow-transfer`.
- **Считать отказ доказательством закрытости**: попробуйте каждый NS и вторичные серверы.
- **Забыть про wildcard**: иначе получите «все поддомены существуют».
- **Не проверять DNSSEC-перечисление**: NSEC-walking может дать зону без AXFR.

## Разбор успешного AXFR

Если трансфер открыт, вывод нужно быстро превратить в карту:

```bash
dig AXFR example.com @ns1.example.com +noall +answer \
  | tee zone.txt

# только имена
awk '{print $1}' zone.txt | sort -u > names.txt
# только IP
awk '$4=="A"{print $1, $5}' zone.txt | sort -u > a_records.txt
# подозрительные имена
grep -iE 'dev|test|internal|admin|vpn|backup|db|git' names.txt
```

Обратите внимание на **TXT** (верификации, ключи), **SRV** (внутренние сервисы), **CNAME** (облака).

## Смежные атаки на DNS-инфраструктуру

- **Динамические обновления**: `nsupdate` без аутентификации → можно менять записи.
- **Открытый резолвер**: рекурсивный сервер, отвечающий всем → amplification-риск.
- **Кэш-снупинг**: доступ к кэшу резолвера → история запросов.
- **DNS rebinding**: смена ответа для обхода same-origin.
- **Zone file exposure**: иногда файл зоны доступен по HTTP.

## От AXFR к брутфорсу: рабочий процесс

```text
1. Найти все NS:        dig +short NS example.com
2. Попробовать AXFR на каждом NS (TCP/53)
3. Если открыт → карта зоны готова
4. Если закрыт → проверить wildcard
5. Брутфорс словарём (dnsx/amass/puredns)
6. Проверить DNSSEC NSEC-walking
7. Обогатить найденные имена (HTTP, порты)
```

## AXFR по всем NS и оценка результатов

Трансфер зоны нужно пробовать на **каждом** авторитетном сервере — конфигурации часто различаются.

```bash
# перечислить NS и попробовать AXFR на каждом
for ns in $(dig +short example.com NS); do
  echo "=== AXFR @ $ns ==="
  dig axfr example.com @$ns | tee "axfr_${ns}.txt"
done
# IXFR (инкрементальный) иногда открыт там, где AXFR закрыт
dig ixfr=1 example.com @ns1.example.com
# через dnsrecon / fierce
dnsrecon -d example.com -t axfr
fierce --domain example.com
```

Успешный AXFR вернёт: SOA, NS, A/AAAA, CNAME, MX, TXT, SRV, PTR — полную карту зоны. Если зона большая, `dig` режет вывод — используйте `+noall +answer` и пишите в файл.

## Что искать в успешном AXFR

| Запись | Что выдаёт |
|--------|-----------|
| A/AAAA | хосты, внутренние имена (`intranet`, `vpn`, `dev`) |
| CNAME | сторонние сервисы, висячие цели takeover |
| MX | почтовые шлюзы, внешние провайдеры |
| TXT | верификации, SPF, иногда пароли/ключи |
| SRV | сервисы (`_ldap._tcp`, `_sip._tcp`, `_autodiscover`) |
| PTR | обратные имена, сегменты сети |

Ищите «говорящие» имена: `db`, `backup`, `old`, `test`, `staging`, `jenkins`, `gitlab`, `k8s`. Они указывают на некритичные/забытые системы.

## Если AXFR закрыт: NSEC-walking и перебор

- **NSEC-walking**: если зона подписана DNSSEC и использует NSEC (не NSEC3), можно «пройти» по цепочке имён.
- **NSEC3 offline crack**: собрать хэши и перебрать имена офлайн (hashcat -m 8300).
- **Брутфорс по словарю**: `dnsrecon -D wordlist -d example.com`, `massdns`, `shuffledns`.

```bash
# NSEC-walking
ldns-walk example.com 2>/dev/null | head -100
# NSEC3-хэши → offline
nsec3map --zone example.com --output nsec3.txt
hashcat -m 8300 nsec3.txt /usr/share/seclists/Discovery/DNS/namelist.txt
# shuffledns (массовый брутфорс с wildcard-защитой)
shuffledns -d example.com -w namelist.txt -r resolvers.txt -o found.txt
```

## Смежные атаки на DNS-инфраструктуру

- **Subdomain takeover**: висячий CNAME на снятый сервис (S3, Heroku, GitHub Pages). Проверка: `dig +short CNAME sub.example.com` → сервис отдаёт «no such app».
- **DNS rebinding**: имя резолвится сначала в публичный IP, потом в 127.0.0.1/внутренний — обход SSRF-фильтров (см. osint-network).
- **Cache poisoning**: подделка ответов на пути; защита — DNSSEC, source-port randomization.
- **DNS tunneling**: эксфильтрация через TXT/NULL/A-запросы (osint-network-covert).

```bash
# проверка кандидата на takeover
host sub.example.com
curl -sI "http://sub.example.com" | head -5
# признаки: 404 «NoSuchBucket», «There isn't a GitHub Pages site here», «No such app»
```

## От AXFR к полному рабочему процессу

```text
1. NS зоны → попытка AXFR на каждом сервере
2. нет AXFR → CT-логи + passive DNS + брутфорс/NSEC-walking
3. собрать имена → резолвить (dnsx)
4. классифицировать: внешние / внутренние / сторонние (CNAME)
5. для каждого: MX/TXT/SRV, проверка takeover, версии сервисов
6. приоритизировать «говорящие» имена (dev/old/backup)
7. результат → карта поверхности для дальнейшего тестирования
```

## Практический разбор: полная карта зоны

Дано: `example.com`, AXFR закрыт.

1. `subfinder -d example.com` + `crt.sh` → 120 имён.
2. `dnsgen`/`gotator` → 3000 перестановок, `dnsx` оставляет 80 живых.
3. На каждом живом: `dig MX/TXT/SRV`; находим `_autodiscover` и почтовые шлюзы.
4. Проверяем CNAME на takeover-сервисы → один висячий на Heroku (потенциальный захват).
5. «Говорящие» имена `dev`, `old`, `backup` → приоритет на тестирование.
6. Итог: карта поверхности с категориями риска.

## Частые ошибки

- **Пробовать AXFR только на одном NS** — на другом он может быть открыт.
- **Игнорировать CNAME-цепочки** — takeover живёт именно там.
- **Путать wildcard-ответ с реальным поддоменом** — проверяйте отрицательным контролем.
- **Не смотреть SRV** — они раскрывают внутренние сервисы (LDAP, SIP, Kerberos).
- **Забыть про историю** — SecurityTrails/passive DNS дают имена, которых уже нет в зоне.

## Квиз

```quiz
- question: "Что делает AXFR?"
  options:
    - "Запрашивает одну A-запись"
    - "Передаёт всю зону DNS целиком от сервера к клиенту"
    - "Шифрует DNS-трафик"
    - "Меняет NS-сервер"
  answer: 1
- question: "По какому протоколу работает AXFR?"
  options:
    - "UDP/53"
    - "TCP/53"
    - "TCP/443"
    - "UDP/5353"
  answer: 1
- question: "Что нужно проверить перед брутфорсом имён зоны?"
  options:
    - "Наличие MX-записи"
    - "Наличие wildcard DNS (`dig random.example.com`)"
    - "TTL зоны"
    - "DNSSEC"
  answer: 1
- question: "Какой механизм при DNSSEC позволяет перечислить зону без AXFR?"
  options:
    - "NSEC-walking"
    - "EDNS0"
    - "DoH"
    - "TSIG"
  answer: 0
- question: "Почему стоит пробовать AXFR на каждом NS-сервере?"
  options:
    - "Они всегда идентичны"
    - "Настройки `allow-transfer` могут отличаться"
    - "Так требует RFC"
    - "Это ускоряет резолв"
  answer: 1
```

## Где пригодится

- **CTF:** быстрый способ вытащить скрытый поддомен с флагом.
- **Bug bounty:** мгновенное расширение охвата, если зона утекает.
- **Пентест:** полная карта внешней DNS-зоны на этапе разведки.
- **Blue team:** проверка собственных зон на открытый трансфер.
