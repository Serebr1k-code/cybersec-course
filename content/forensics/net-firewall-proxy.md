---
id: net-firewall-proxy
title: 'Firewall и прокси в форензике: куда ходил трафик'
category: forensics
parent: forensics-net-services
difficulty: medium
order: 4
tags: [network, firewall, proxy, logs, forensics]
prerequisites: [forensics-network-deep]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как читать логи firewall и прокси, восстанавливать сетевую активность и находить следы эксфильтрации.'
lab:
  kind: shell
  title: 'Практика: Firewall и прокси в форензике'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Хост мог общаться с внешним миром — но куда именно? Прямой дамп снять не всегда
удается, зато остаются логи **firewall** и **прокси**. Это готовый журнал сетевых
решений. Разберём, как из них выжать картину.

## Наш пример: логи прокси

## Шаг 1: что логирует прокси

Squid пишет строки в формате, похожем на access.log:

```
$ tail -3 /var/log/squid/access.log
1705000000.123  200 10.10.20.9 TCP_MISS/200 4523 GET http://203.0.113.5/payload.dmg - HIER_DIRECT/203.0.113.5 application/octet-stream
```

Поля: время (unix), статус, клиент, размер, метод, URL, тип. Здесь видно загрузку
`payload.dmg` с `203.0.113.5`.

## Шаг 2: агрегируем

```
$ awk '{print $3, $7}' /var/log/squid/access.log | sort | uniq -c | sort -rn | head
   120 10.10.20.9 http://203.0.113.5/
    40 10.10.20.9 https://update.example/
```

Аномально частые обращения к одному внешнему хосту — признак beaconing или
эксфильтрации.

## Шаг 3: firewall

Linux `iptables`/`nftables` не логирует по умолчанию — нужны правила LOG. Логи
попадают в kernel log:

```
$ grep -i 'DPT=443' /var/log/kern.log | tail
IN=eth0 OUT= SRC=10.10.20.9 DST=203.0.113.5 DPT=443 ... SYN
```

Отсюда видно, кто и куда инициировал соединения. Для DNS:

```
$ grep -i 'DPT=53' /var/log/kern.log | awk '{print $12, $13}' | sort -u | head
```

## Шаг 4: DNS-запросы

Если логируется DNS, видно домены:

```
$ grep -i 'query' /var/log/named/query.log | tail
14-Jan-2026 03:29:00.123 client 10.10.20.9#53: query: update.example A
```

Домен `update.example` — зацепка. Сопоставь с известными IOC.

## Шаг 5: эксфильтрация

Ключевой вопрос: уходили ли данные? Признаки:

- большой исходящий объём (колонка размеров);
- соединения на нестандартные порты;
- регулярные запросы фиксированного размера (beaconing);
- использование доменов, похожих на легитимные (DGA/тайпсквоттинг).

## Что мы теперь знаем

- Прокси логирует URL, клиента, размер, статус.
- Агрегация выявляет аномалии (beaconing, эксфильтрация).
- Firewall логирует через правила LOG в kern.log.
- DNS-логи показывают домены.
- Большой исходящий объём + нестандартные порты = эксфильтрация.

## Если не сработало

- Логи не ведутся? Проверь конфиг и включи (но это уже после инцидента).
- Прокси прозрачный? Смотри DNS и NetFlow.
- Нужен объём? Используй NetFlow/IPFIX.

## Квиз

Проверь себя.

```quiz
- question: Что логирует прокси-сервер?
  options:
    - 'только ошибки'
    - 'URL, клиента, размер, статус запросов'
    - 'пароли'
    - 'файлы'
  answer: 1
  explanation: 'access.log прокси содержит метод, URL, клиента и размер.'
- question: Признак beaconing в логах?
  options:
    - 'одна ошибка'
    - 'регулярные обращения к одному хосту фиксированного размера'
    - 'много DNS'
    - 'нет трафика'
  answer: 1
  explanation: 'Периодические одинаковые запросы — типичный «маячок» C2.'
- question: Как firewall логирует соединения?
  options:
    - 'по умолчанию всегда'
    - 'через правила LOG в kern.log'
    - 'в /etc/passwd'
    - 'никак'
  answer: 1
  explanation: 'Нужны явные правила LOG; записи идут в kernel log.'
- question: Что указывает на эксфильтрацию?
  options:
    - 'маленький трафик'
    - 'большой исходящий объём и нестандартные порты'
    - 'DNS-запрос'
    - 'ARP-ответ'
  answer: 1
  explanation: 'Объёмные исходящие соединения на редкие порты — признак вывода данных.'
```
