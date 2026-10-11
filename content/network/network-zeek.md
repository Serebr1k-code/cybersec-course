---
id: network-zeek
title: "Zeek: сетевая безопасность через логи, а не пакеты"
category: network
parent: network-wireshark
difficulty: medium
order: 1
tags: [network, zeek, bro, ids, logs, forensics, monitoring]
prerequisites: [network-wireshark, network-tcpdump]
useful_for:
  - "Работа/SOC — сетевой мониторинг"
  - "Инцидент-респонс и форензика"
  - "Пентест — анализ трафика"
estimated_minutes: 42
summary: "Zeek (ex-Bro): архитектура, установка, ключевые логи (conn/dns/http/ssl/files/notice), кастомные скрипты, извлечение файлов, интеграция с Elastic и RITA."
---

Wireshark показывает пакеты, Suricata ищет сигнатуры, а **Zeek** превращает трафик в **структурированные логи**: одну строку на соединение, DNS-запрос, HTTP-транзакцию, TLS-сессию, извлечённый файл. Это делает его основой сетевого мониторинга и форензики: по логам можно расследовать инцидент без повторного разбора пакетов. Для пентеста Zeek полезен тем, что быстро отвечает на вопрос «что вообще происходило в сети».

## Что такое Zeek

Zeek (раньше Bro) — это **сетевой анализатор** с собственным скриптовым языком. Он декодирует протоколы (до десятков, включая HTTP, DNS, TLS, SMB, SSH, DHCP, FTP, SMTP, IRC, Modbus) и пишет логи в `TSV`-формате. В отличие от сигнатурного IDS, Zeek по умолчанию ничего не блокирует и не «алертит» — он **описывает** трафик, а правила пишутся отдельно.

| Инструмент | Подход |
|---|---|
| Wireshark | Ручной разбор пакетов |
| tcpdump | Захват по фильтру |
| Suricata | Сигнатурный IDS/IPS |
| Zeek | Структурированные логи и скрипты |

## Установка и запуск

```bash
# Debian/Ubuntu: репозиторий Zeek
sudo apt install zeek
# Разовый анализ дампа
zeek -r capture.pcap
# Мониторинг интерфейса (нужен доступ к трафику)
sudo zeek -i eth0
# Свои скрипты + вывод в каталог
zeek -r capture.pcap local Log::default_path=/tmp/zeeklogs
```

По умолчанию логи появляются в текущем каталоге (`conn.log`, `dns.log`, `http.log`, `ssl.log` и т.д.).

## Ключевые логи

| Лог | Что внутри |
|---|---|
| conn.log | Каждое соединение: 5-tuple, байты, длительность, сервис |
| dns.log | Запросы/ответы DNS, query, answers, rcode |
| http.log | Метод, host, URI, user-agent, статус, MIME |
| ssl.log | TLS: версия, SNI, сертификат, JA3 |
| files.log | Извлечённые файлы: MIME, хэши, имя |
| notice.log | Срабатывания скриптов/правил |
| weird.log | Аномалии протоколов |

Пример `conn.log` (TSV) — по нему видно, кто с кем говорил и сколько передал. `ssl.log` содержит **JA3** — отпечаток TLS-клиента, полезный для детекта malware/C2.

## Пользовательские скрипты

Скрипты Zeek пишутся на его языке и реагируют на события (`event http_request`, `event dns_request`). Пример: логировать все HTTP-запросы к необычным портам.

```zeek
# http-weird.zeek
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if (c$id$resp_p != 80/tcp && c$id$resp_p != 443/tcp)
        print fmt("HTTP on %s -> %s", c$id$id, original_URI);
}
```

Запуск: `zeek -r capture.pcap http-weird.zeek`. Так можно писать под свои задачи: детект beaconing, редких доменов, DNS-туннелей.

## Разобранный пример: разбор дампа и извлечение файлов

1. Прогоняем дамп: `zeek -r suspicious.pcap`.
2. Смотрим `dns.log` на подозрительные домены (длинные, энтропийные, редкие TLD):
   ```bash
   zeek-cut query < dns.log | sort | uniq -c | sort -rn | head
   ```
3. В `http.log` ищем загрузки:
   ```bash
   zeek-cut host uri resp_mime_types < http.log | grep -i "exe\|dll\|zip"
   ```
4. Включаем извлечение файлов (`file-extract` framework) и получаем содержимое:
   ```zeek
   @load /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files
   ```
   Файлы появятся в `extract_files/`.
5. Считаем хэши и проверяем в VirusTotal (в лабе — по своим файлам).

## Детект и интеграции

- **Notice framework** — свои уведомления при событиях.
- **Intel framework** — сопоставление с индикаторами (IP/домены/хэши).
- **Signatures** — простые сигнатуры по regex (как в Snort, но в Zeek).
- **RITA** — анализ `conn.log` на beaconing (регулярные интервалы C2).
- **Zeek + Elastic/Kibana** — визуализация и поиск.
- **Zeek + Suricata** — Zeek описывает, Suricata алертит.

## Защита и применение

| Задача | Как |
|---|---|
| Инвентаризация протоколов | conn.log + service |
| Детект C2/beaconing | RITA, ssl.log JA3 |
| Форензика инцидента | Все логи + files |
| Охота за эксфильтрацией | dns.log, conn.log объёмы |
| Мониторинг TLS | ssl.log без расшифровки |

## Частые ошибки и подводные камни

- **Ждать блокировок от Zeek.** Он не IPS; для блокировок — Suricata/фаервол.
- **Забывать про объём логов.** На быстром канале логи быстро растут; нужна ротация.
- **Игнорировать timezone/UTC.** Логи в UTC — корреляция с другими источниками требует пересчёта.
- **Путать `conn.log` и `http.log`.** Соединение — не транзакция; одно соединение может содержать много HTTP-запросов.
- **Не включать извлечение файлов.** Иначе `files.log` есть, а содержимого нет.
- **Считать Zeek заменой Wireshark.** Для глубокого разбора нестандартного протокола пакеты всё ещё нужны.

## Что дальше / решение

Zeek — «глаза» сети: свяжите его с `network-tcpdump`, `network-wireshark`, `network-pcap-analysis` и `network-traffic-analysis-ctf`. Дальше — SIEM-интеграции и RITA для детекта C2. Для CTF Zeek ускоряет разбор больших дампов. Для SOC постройте пайплайн Zeek → Elastic → дашборды.

## Справочная таблица

| Лог | Ключевые поля |
|---|---|
| conn | id, proto, service, bytes, duration |
| dns | query, qtype, answers |
| http | method, host, uri, status |
| ssl | version, server_name, ja3 |
| files | mime_type, md5, sha1, filename |

| Инструмент | Роль |
|---|---|
| zeek | Анализатор |
| zeek-cut | Выборка колонок |
| RITA | Beaconing-детект |
| Elastic | Визуализация |

## Zeek в кластере и производительность

На быстрых каналах одиночный Zeek не справляется с одним ядром. Решение — **кластер** из фронтенда-«прокси» и нескольких «воркеров», которые делят трафик по потокам и пишут логи в общий каталог. Ключевые моменты:

- **Load-balancing по потокам** (не по пакетам) через PF_RING/AF_PACKET или `pf_ring`-модуль;
- **`Log::default_path`** — общий NFS/локальный каталог для всех воркеров;
- **`zeekctl`** — управление кластером (`zeekctl deploy`, `status`, `diag`);
- **`node.cfg`** — конфигурация узлов (типы proxy/manager/worker/logger).

```bash
# /opt/zeek/etc/node.cfg
[zeek]
type=standalone
host=localhost
interface=af_packet::eth0
```

Для производительности включают `AF_PACKET`/`PF_RING` (zero-copy), отключают ненужные анализаторы и настраивают ротацию логов. Ориентир: один воркер тянет порядка 1–2 Гбит/с в зависимости от трафика и числа скриптов.

## Лаборатория: детект DNS-туннеля

1. Прогоните дамп с подозрительной активностью: `zeek -r tunnel.pcap`.
2. Проанализируйте `dns.log`:
   ```bash
   zeek-cut query qtype < dns.log | awk '{print length($1), $0}' | sort -rn | head
   ```
   Длинные, энтропийные поддомены одного домена — признак туннеля.
3. Напишите скрипт, который считает запросы на домен и алертит при превышении порога:
   ```zeek
   @load base/protocols/dns
   global dns_count: table[string] of count &default=0;
   event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
       if (qtype == 1 || qtype == 16) {
           dns_count[query] += 1;
           if (dns_count[query] > 50)
               NOTICE([$note=Notice::ACTION_LOG, $msg=fmt("Possible DNS tunnel: %s", query)]);
       }
   }
   ```
4. Свяжите с RITA для beaconing и с `network-dns-tunnel` для техник туннелирования.

## Сравнение с другими анализаторами

| Критерий | tcpdump | Wireshark | Suricata | Zeek |
|---|---|---|---|---|
| Уровень | Пакеты | Пакеты (GUI) | Сигнатуры | Логи/скрипты |
| Блокировка | Нет | Нет | Да (IPS) | Нет |
| Формат | PCAP | PCAP | EVE JSON | TSV/JSON |
| Расширяемость | Фильтры BPF | Lua/диссекторы | Правила | Скрипты |
| Для SOC | Базово | Ручной | Детект | Мониторинг/форензика |

Zeek и Suricata отлично дополняют друг друга: Zeek описывает, Suricata алертит, а вместе они дают полную картину.

## Квиз

```quiz
- question: "Чем Zeek принципиально отличается от Suricata?"
  options:
    - "Zeek быстрее"
    - "Zeek описывает трафик структурированными логами, а не ищет сигнатуры"
    - "Zeek шифрует трафик"
    - "Zeek не работает с PCAP"
  answer: 1
  explanation: "Zeek превращает трафик в логи (conn/dns/http/ssl), а не блокирует по сигнатурам."
- question: "В каком логе Zeek хранится отпечаток TLS-клиента JA3?"
  options:
    - "conn.log"
    - "dns.log"
    - "ssl.log"
    - "files.log"
  answer: 2
  explanation: "ssl.log содержит параметры TLS-сессий, включая JA3."
- question: "Как запустить Zeek на дампе capture.pcap?"
  options:
    - "zeek -i capture.pcap"
    - "zeek -r capture.pcap"
    - "zeek --dump capture.pcap"
    - "zeek capture.pcap -w"
  answer: 1
  explanation: "-r читает PCAP-файл."
- question: "Какой инструмент анализирует conn.log на beaconing?"
  options:
    - "RITA"
    - "Wireshark"
    - "nmap"
    - "hashcat"
  answer: 0
  explanation: "RITA выявляет регулярные C2-коммуникации (beaconing)."
- question: "Почему Zeek не заменяет IPS?"
  options:
    - "Он не поддерживает TCP"
    - "Он не блокирует трафик по умолчанию"
    - "Он не пишет логи"
    - "Он работает только с UDP"
  answer: 1
  explanation: "Zeek описывает трафик; для блокировок нужны Suricata/фаервол."
```

## Где пригодится

- **Работа/SOC:** основа сетевого мониторинга и детекта.
- **Инцидент-респонс:** форензика по структурированным логам.
- **Пентест:** быстрый анализ больших дампов.
- **CTF:** разбор трафика и поиск аномалий.
