---
id: network-quic
title: "QUIC и HTTP/3: анализ зашифрованного транспорта нового поколения"
category: network
parent: network-tls-inspection
difficulty: hard
order: 2
tags: [network, quic, http3, udp, tls13, analysis]
prerequisites: [network-tls-inspection, network-tcpip]
useful_for:
  - "CTF Network (разбор QUIC)"
  - "Пентест: анализ современного трафика"
  - "Работа (SOC): видимость и инспекция QUIC"
estimated_minutes: 50
summary: "Как устроен QUIC поверх UDP, что видно без расшифровки и как инспектировать и блокировать его в корпоративной сети."
lab:
  kind: shell
  title: "Практика: разбор QUIC-пакетов"
  toolset: [core, tshark]
  workdir: /home/student/task
  files: [task.md, q.pcap]
  check: "grep -q '5c8a3f1e2b4d' answer.txt"
  hints:
    - "Типы QUIC-пакетов: `tshark -r q.pcap -Y quic -T fields -e quic.long.packet_type`."
    - "0 — это Initial; именно он несёт Destination Connection ID клиента."
    - "DCID клиентского Initial: `tshark -r q.pcap -Y 'quic.long.packet_type==0' -T fields -e quic.dcid`."
---

## Вопрос, с которого всё начинается

В прошлом уроке мы расшифровывали HTTPS — TLS поверх TCP. Но замечал ли ты, что современные браузеры иногда не ходят по TCP/443 вовсе? Они используют **QUIC** — новый транспорт, несущий **HTTP/3**. Проблема для анализа в том, что QUIC работает поверх **UDP** и шифрует почти всё, включая часть служебных заголовков. Классические TCP-инструменты и сетевые посредники (middlebox) его «не видят».

Разберёмся, что всё-таки удаётся вытащить из QUIC-трафика и как он устроен — на нашем дампе.

## Наш пример: дамп q.pcap

Мы открыли в браузере сайт, и на интерфейсе появился UDP-трафик на порт 443. Снимем его:

```
$ sudo tcpdump -i any -n udp port 443 -c 200 -w q.pcap
200 packets captured
```

Теперь посмотрим, что вообще внутри, через `tshark`:

```
$ tshark -r q.pcap -q -z io,phs | head -20
===================================================================
Protocol Hierarchy Statistics
Filter:
frame                      frames:200 bytes:145320
  eth                      frames:200 bytes:145320
    ip                     frames:200 bytes:145320
      udp                  frames:200 bytes:145320
        quic               frames:198 bytes:144900
```

Почти весь трафик — `quic`. Вот первое отличие от HTTPS: транспорт здесь UDP, а не TCP.

## Шаг 1: почему QUIC — вызов для анализа

Несколько свойств делают QUIC неудобным для перехвата:

- Работает по **UDP/443** — порт, который почти везде разрешён и плохо инспектируется.
- **TLS 1.3 встроен прямо в протокол** — handshake и данные идут в одном потоке.
- Шифруются не только данные, но и заголовки (защита от «окостенения» посредников).
- Соединение живёт по **connection ID**, а не по паре адрес-порт — его сложно отследить при смене сети.
- Есть **Retry** и **Version Negotiation** — неочевидные ветки поведения.

Но не всё потеряно: первый пакет соединения, **Initial**, несёт **ClientHello** в открытом виде.

## Шаг 2: вытаскиваем SNI и ALPN из Initial

Ключевая зацепка — то же, что и в TLS: `Initial`-пакет открыт, и в нём видно, к какому домену идёт клиент:

```
$ tshark -r q.pcap -Y 'quic.tls.handshake.type==1' -T fields -e ip.dst -e quic.tls.server_name -e quic.tls.alpn
93.184.216.34	example.com	h3
```

Три факта: адрес сервера, домен `example.com` (**SNI**) и **ALPN** — согласование протокола прикладного уровня. Здесь `h3` означает HTTP/3. Не путай: `h2` — это HTTP/2 поверх TCP, а `h3` — HTTP/3 поверх QUIC.

Проверим версии QUIC:

```
$ tshark -r q.pcap -Y 'quic.version' -T fields -e quic.version | sort | uniq -c
     96 1
     94 1
```

Версия `1` — это QUIC v1 (RFC 9000). Есть и v2 (RFC 9369) с другой солью для вывода ключей.

## Шаг 3: разбираем handshake по шагам

Посмотрим, какие типы пакетов прошли:

```
$ tshark -r q.pcap -Y 'quic' -T fields -e quic.packet_type | sort | uniq -c
     2 initial
     4 handshake
    192 1-RTT
```

Расшифровка стадий:

1. **Initial** — клиент шлёт ClientHello открыто; ключи выведены из фиксированной соли.
2. **Handshake** — здесь сертификат сервера, проверка, Finished; всё уже зашифровано.
3. **1-RTT** — данные приложения (это и есть наши 192 пакета).

Есть ещё **Retry** — если сервер хочет подтвердить адрес клиента (защита от amplification, когда на маленький запрос нельзя ответить втрое большим объёмом):

```
$ tshark -r q.pcap -Y 'quic.retry' -V | head -10
```

## Шаг 4: что осталось видимым без ключей

После handshake всё зашифровано, но метаданные никуда не делись:

- **Connection ID** — идентификатор соединения, который переживает смену IP/порта:

```
$ tshark -r q.pcap -Y 'quic.connection.id' -T fields -e quic.connection.id | sort -u | head
5c8a3f1e2b4d
```

- **Spin bit** — открытый бит для измерения задержки:

```
$ tshark -r q.pcap -Y 'quic.spin_bit' -T fields -e quic.spin_bit | head -5
0
0
1
```

- **Размеры и тайминги** пакетов.

Смысл connection ID: при **connection migration** клиент переходит с Wi-Fi на LTE, и пары адрес-порт меняются, но соединение не рвётся — балансировщик маршрутизирует по ID.

## Шаг 5: расшифровка через SSLKEYLOGFILE

QUIC использует TLS 1.3, поэтому ключи берутся тем же способом, что и в прошлом уроке, — из файла клиента:

```
$ export SSLKEYLOGFILE=/tmp/keys.log
$ curl --http3 https://example.com/ -o /dev/null
$ tshark -r q.pcap -o tls.keylog_file:/tmp/keys.log -Y http3 -T fields -e http3.headers | head
:method: GET
:authority: example.com
:path: /
```

Так зашифрованный `1-RTT` раскрывается в обычный HTTP/3. Без ключей расшифровка невозможна — остаются только SNI, размеры и тайминги.

## Шаг 6: ECH — когда и SNI пропадает

**Encrypted ClientHello (ECH)** шифрует SNI. Признак простой: в Initial нет читаемого имени:

```
$ tshark -r q.pcap -Y 'quic.tls.handshake.type==1' -T fields -e quic.tls.server_name

```

Пусто, но ALPN `h3` есть — вероятно, включён ECH. Тогда фильтрация по имени сайта перестаёт работать, и остаются только IP, размеры и тайминги.

## Шаг 7: как это используют на практике

Для защиты периметра у инженера есть рычаг — заставить клиента отказаться от QUIC:

```
$ curl -sI https://example.com/ | grep -i alt-svc
alt-svc: h3=":443"; ma=86400
```

Заголовок **Alt-Svc** сообщает браузеру, что сервис умеет `h3`. Если заблокировать UDP/443, браузер откатится на инспектируемый TCP/HTTP2:

```
$ iptables -A FORWARD -p udp --dport 443 -j DROP
```

Так SOC возвращает себе видимость. Для пентестера обратный вывод: блокировка UDP/443 — это шумное, но эффективное решение, а его отсутствие оставляет канал «слепым».

## Что мы теперь знаем

По-простому:

1. QUIC — транспорт поверх UDP (обычно 443), несущий HTTP/3.
2. Первый пакет (Initial) открыт: из него видно SNI и ALPN (`h3`).
3. Дальше всё шифруется — видны только connection ID, spin bit, размеры и тайминги.
4. Расшифровка — через `SSLKEYLOGFILE` (TLS 1.3), а не ключом сервера.
5. ECH прячет SNI; защита периметра строится на блокировке UDP/443 и политике Alt-Svc.

## На что смотреть дальше

- **Не сканируй QUIC как TCP.** Он только UDP — `nmap -sU -p 443`.
- **Не жди HTTP-запроса без ключей.** Виден только Initial.
- **Проверь ECH.** Пустой SNI при ALPN `h3` — сигнал, что имя скрыто.

## Разбираем QUIC Initial пакет

Вернёмся к нашему `q.pcap`. QUIC-пакет снаружи — это UDP, но внутри длинный заголовок с полями, часть из которых видна без ключей. Извлечём самое полезное:

```
$ tshark -r q.pcap -Y quic -T fields -e quic.version -e tls.handshake.extensions_server_name -e tls.handshake.type -e quic.long.packet_type -c 3
0x00000001  example.com  1  0
0x00000001  example.com  1  0
```

Читается так: версия QUIC `0x00000001` (RFC 9000), SNI `example.com`, тип TLS-handshake `1` (ClientHello), тип long-пакета `0` (Initial). Уже отсюда мы знаем, **куда** клиент подключается — SNI в Initial-пакете не шифруется (пока не включён ECH). Это главное, что остаётся видимым.

## Что видно, а что скрыто

| Данные | Видно без ключей? | Почему |
|---|---|---|
| Версия QUIC | да | открытое поле заголовка |
| SNI | да (без ECH) | в Initial ClientHello |
| ALPN (h3/h2) | да | расширение ClientHello |
| Порт назначения | да | UDP-заголовок |
| Заголовки HTTP | нет | защищены ключами |
| Cookies, тело | нет | защищены ключами |
| Размер запроса | приблизительно | по размеру пакетов |

Вывод для SOC: **QUIC не «чёрный ящик»** — метаданные соединения видны. А вот содержимое — нет, и без `SSLKEYLOGFILE` его не достать.

## Разбираем handshake по шагам

QUIC объединяет транспорт и TLS 1.3. Первый пакет — Initial с ClientHello. Сервер отвечает Initial + Handshake, затем всё уходит в 1-RTT-пакеты. Ключи Initial выводятся из **известной константы** (salt) и случайного connection ID — это позволяет декодировать сам Initial, но **не** последующий трафик. Именно поэтому `tshark` умеет показать ClientHello, но не HTTP-заголовки.

Практический приём: если приложение пишет `SSLKEYLOGFILE`, ключи попадают в файл, и `tshark` расшифровывает всё:

```
$ SSLKEYLOGFILE=/tmp/keys.log curl --http3 https://example.com -o /dev/null
$ tshark -r q.pcap -o tls.keylog_file:/tmp/keys.log -Y http3
```

## ECH: когда и SNI пропадает

Encrypted Client Hello шифрует сам ClientHello, включая SNI. Тогда в дампе видно только внешний SNI (обычно «прикрытие»), а настоящий адрес скрыт. Это делает пассивный анализ QUIC почти бессмысленным для определения цели — и одновременно подсказывает защитнику, что трафик с ECH стоит рассматривать по другим признакам (IP-адрес, размеры, тайминги).

## Если не сработало: QUIC не виден

Три причины. Первая — **трафик на TCP**: если сайт не поддерживает HTTP/3 или клиент его отключил, всё пойдёт обычным TLS на 443, и QUIC не появится. Вторая — **UDP/443 заблокирован**: тогда браузер откатится на TCP (happy eyeballs), и ты увидишь только TLS. Третья — не тот фильтр: QUIC-пакеты маскируются под «UDP high ports», поэтому фильтруй `udp.port==443` или по наличию `quic` в `tshark -d udp.port==443,quic`. И помни про **версии**: старое ПО может использовать gQUIC (Google) вместо стандартного — заголовки у них разные.

## Квиз

Проверь себя.

```quiz
- question: 'Поверх какого транспорта работает QUIC?'
  options:
    - 'UDP'
    - 'TCP'
    - 'SCTP'
    - 'ICMP'
  answer: 0
  explanation: 'QUIC работает поверх UDP (обычно 443) и включает TLS 1.3 внутрь.'
- question: 'Что видно в QUIC Initial-пакете без расшифровки?'
  options:
    - 'ClientHello: SNI и ALPN (например, h3)'
    - 'Полный HTTP-запрос'
    - 'Пароли'
    - 'Содержимое ответа'
  answer: 0
  explanation: 'Initial несёт ClientHello открыто; дальше всё зашифровано.'
- question: 'Как чаще всего заставляют клиента отказаться от QUIC в корпоративной сети?'
  options:
    - 'Заблокировать UDP/443, чтобы браузер откатился на TCP/HTTP2'
    - 'Отключить DNS'
    - 'Включить IPv6'
    - 'Сменить MAC-адрес'
  answer: 0
  explanation: 'Блокировка UDP/443 вынуждает fallback на инспектируемый TCP.'
- question: 'Какой ALPN-идентификатор означает HTTP/3?'
  options:
    - 'h3'
    - 'h2'
    - 'http/1.1'
    - 'spdy/3'
  answer: 0
  explanation: 'HTTP/3 использует ALPN h3; h2 — это HTTP/2 поверх TCP.'
- question: 'Что нужно для расшифровки QUIC в Wireshark?'
  options:
    - 'Файл ключей TLS (SSLKEYLOGFILE)'
    - 'Пароль Wi-Fi'
    - 'MAC-адрес'
    - 'Сертификат сервера'
  answer: 0
  explanation: 'QUIC использует TLS 1.3, поэтому ключи берутся из SSLKEYLOGFILE.'
```

## Куда дальше

Дальше мы вернёмся к прикладным протоколам поверх TLS и TCP: разберём, как устроены базы данных «по проводу», и какие из них отдают данные без шифрования. А пока главное запомни: QUIC прячет содержимое, но Initial и метаданные всё ещё рассказывают, кто и куда ходит.

## Где пригодится

- **CTF:** разбор QUIC-трафика, поиск SNI и метаданных.
- **Пентест:** анализ современного шифрованного транспорта.
- **SOC:** видимость и инспекция QUIC, политика блокировки.
- **Работа:** настройка firewall/прокси для HTTP/3.
- **Сетевая инженерия:** понимание миграции с TCP на QUIC.
