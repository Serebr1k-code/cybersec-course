---
id: network-traffic-analysis-ctf
title: "CTF traffic analysis: методичный разбор PCAP от начала до флага"
category: network
parent: network-pcap-analysis
difficulty: medium
order: 2
tags: [network, ctf, pcap, traffic-analysis, workflow, forensics]
prerequisites: [network-pcap-analysis, network-wireshark]
useful_for:
  - "CTF Network/Forensics (PCAP-задачи)"
  - "Работа (IR): разбор инцидентов"
  - "Пентест: анализ захваченного трафика"
estimated_minutes: 50
summary: "Повторяемый workflow анализа PCAP в CTF: инвентаризация, протоколы, объекты, скрытые каналы, восстановление и поиск флага."
---
PCAP-задачи в CTF почти всегда решаются одним и тем же повторяемым workflow. Если действовать методично (а не «искать флаг в hex»), вы не пропустите канал, которым воспользовались авторы. Ключевая идея — идти от общего к частному: сначала инвентаризация, затем протоколы, потом объекты и секреты, и лишь в конце — скрытые каналы. Урок опирается на [`network-pcap-analysis`](network-pcap-analysis) и [`network-wireshark`](network-wireshark).

## Шаг 0: инвентаризация

Понять масштаб и состав трафика. `capinfos` даёт размер, число пакетов, время начала/конца и среднюю скорость — это подсказывает, «живой» это дамп или синтетический.

```bash
capinfos capture.pcap            # размер, число пакетов, время, хэши
tshark -r capture.pcap -q -z io,phs    # иерархия протоколов
tshark -r capture.pcap -Y 'ip.addr' -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn | head
```

`-z io,phs` (protocol hierarchy statistics) — самый быстрый способ увидеть, какие протоколы есть в дампе. Необычный протокол (например, Modbus или USB) сразу бросается в глаза.

## Шаг 1: протоколы и сессии

- **Conversations**: Statistics → Conversations (Wireshark) — топ пар по объёму.
- **Follow stream** (TCP/UDP) — содержимое сессии целиком, как текст.
- Необычные протоколы/порты — часто там «спрятано».

```bash
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -q -z conv,udp
# Список протоколов по частоте
tshark -r capture.pcap -T fields -e frame.protocols | tr ':' '\n' | sort | uniq -c | sort -rn | head
# Follow stream конкретного TCP-потока
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

## Шаг 2: извлечение объектов и файлов

```bash
# HTTP-объекты
tshark -r capture.pcap --export-objects http,out/
# SMB-объекты
tshark -r capture.pcap --export-objects smb,out/
# TFTP/прочее
tshark -r capture.pcap --export-objects tftp,out/
# Carve по сигнатурам
foremost -i capture.pcap -o carved/
binwalk -e capture.pcap
```

Проверьте извлечённые файлы: `file`, `strings`, стего (`zsteg`, `binwalk`, [`forensics-image-ela`](forensics-image-ela)). Wireshark: File → Export Objects → HTTP/SMB/TFTP/DICOM.

## Шаг 3: учётные данные и секреты

```bash
# HTTP Basic/логины
tshark -r capture.pcap -Y 'http.authorization or http.request.method=="POST"' -T fields -e http.authorization -e http.file_data
# FTP
tshark -r capture.pcap -Y 'ftp.request.command=="PASS"' -T fields -e ftp.request.arg
# SMTP/POP/IMAP
tshark -r capture.pcap -Y 'smtp or pop or imap' | head
# Kerberos/NTLM (для hashcat)
tshark -r capture.pcap -Y 'kerberos' -T fields -e kerberos.Cipher
tshark -r capture.pcap -Y 'ntlmssp' -T fields -e ntlmssp.auth.username -e ntlmssp.ntlmserverchallenge
# Telnet (плейнтекст)
tshark -r capture.pcap -Y 'telnet' -z follow,tcp,ascii,0
```

NTLMv2-хэши из трафика брутятся: `hashcat -m 5600 ntlm.txt rockyou.txt`. Kerberos-билеты — `-m 18200/13100`.

## Шаг 4: скрытые каналы

- **DNS-туннель**: длинные base32/base64-поддомены одного родителя.
- **ICMP**: большой/частый payload, данные в поле data.
- **HTTP-заголовки**: данные в `Cookie`/`User-Agent`/`X-*`.
- **Timing**: задержки между пакетами кодируют биты.

```bash
# DNS: длина меток и частоты
tshark -r capture.pcap -Y 'dns.flags.response==0' -T fields -e dns.qry.name | \
  awk -F. '{print $1}' | sort | uniq -c | sort -rn | head
# ICMP payload
tshark -r capture.pcap -Y 'icmp' -T fields -e data | tr -d '\n' | xxd -r -p | strings
# HTTP-заголовки как канал
tshark -r capture.pcap -Y 'http.request' -T fields -e http.user_agent -e http.cookie | head
```

## Шаг 5: специализированные протоколы

- **USB HID** — нажатия клавиатуры ([`network-usb-pcap`](network-usb-pcap)).
- **VoIP/RTP** — разговор, извлечение аудио ([`network-voip`](network-voip)).
- **TLS** — с `SSLKEYLOGFILE` расшифровка.
- **Wi-Fi (802.11)** — handshake для подбора PSK.
- **Modbus/SCADA** — промышленные протоколы.
- **SMB/NFS** — переданные файлы.

## Разобранный пример: типичная CTF-задача

```bash
# 1. Инвентаризация
capinfos cap.pcap
tshark -r cap.pcap -q -z io,phs | head -30
# 2. Подозрительный DNS
tshark -r cap.pcap -Y 'dns.flags.response==0' -T fields -e dns.qry.name | tail -20
# -> NDUwLg==.t.evil.com, ... (base64-поддомены!)
# 3. Собираем и декодируем
tshark -r cap.pcap -Y 'dns.flags.response==0' -T fields -e dns.qry.name | \
  awk -F. '{print $1}' | sed 's/\.$//' | while read s; do echo "$s" | base64 -d 2>/dev/null; done
# -> флаг
# 4. Проверяем HTTP-объекты на всякий случай
tshark -r cap.pcap --export-objects http,out/; ls out/
```

Если в задаче «ключ в рукопожатии Wi-Fi» — извлекаем EAPOL и подбираем:

```bash
tshark -r wifi.pcap -Y 'eapol' -w eapol.pcap
aircrack-ng -w rockyou.txt eapol.pcap
```

## Чек-лист

- [ ] `capinfos` + иерархия протоколов (`io,phs`)
- [ ] Conversations / follow stream
- [ ] Export objects (http/smb/tftp)
- [ ] Carving (foremost/binwalk)
- [ ] Креды (http/ftp/smtp/kerberos/telnet/ntlm)
- [ ] DNS/ICMP/HTTP covert
- [ ] Спец-протоколы (USB/VoIP/TLS/802.11)
- [ ] Проверка извлечённых файлов на стего

## Частые ошибки

- **Искать флаг «глазами»** в Wireshark, не фильтруя — сотни тысяч пакетов не просмотреть.
- **Пропустить DNS/ICMP** — самый частый скрытый канал.
- **Не извлечь объекты** — файл мог быть передан по HTTP/SMB.
- **Игнорировать извлечённые файлы** — флаг внутри картинки/архива.
- **Забывать про follow stream** — сессия собирается целиком, а не по одному пакету.
- **Не проверять тайминги** — covert по времени легко пропустить.
- **Путать ретрансмиссии с данными** — `tcp.analysis.retransmission` стоит исключать.

## Полезные tshark-однострочники

```bash
# Топ разговоров
tshark -r c.pcap -q -z conv,tcp | head -20
# HTTP-хосты и URI
tshark -r c.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri | sort | uniq -c | sort -rn | head
# DNS-запросы
tshark -r c.pcap -Y 'dns.flags.response==0' -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head
# Извлечь пароли (ftp/http basic)
tshark -r c.pcap -Y 'ftp.request.command=="USER" or ftp.request.command=="PASS" or http.authorization' -T fields -e ftp.request.arg -e http.authorization
# TLS SNI
tshark -r c.pcap -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name | sort -u
# Экспорт объектов
tshark -r c.pcap --export-objects http,out/ ; tshark -r c.pcap --export-objects smb,smb/
```

## Порядок «если застрял»

1. Проверить **все** протоколы в иерархии (`io,phs`) — не пропущен ли необычный.
2. Посмотреть **все** conversations — вдруг есть скрытый хост.
3. Экспортировать объекты и **carve** всё.
4. Прогнать `strings`/`binwalk` по дампу.
5. Проверить DNS/ICMP/HTTP-заголовки на covert.
6. Заглянуть в специализированные протоколы (USB/VoIP/802.11).
7. Перечитать подсказку задачи — она часто указывает вектор.

## Расшифровка TLS в CTF

```bash
# Если есть ключи (SSLKEYLOGFILE от браузера)
tshark -r c.pcap -o tls.keylog_file:keys.log -Y http2 -T fields -e http2.header.value
# RSA-ключ сервера (старый TLS без PFS)
tshark -r c.pcap -o tls.keys_list:"1.2.3.4,443,http,server.key"
# Захват ключей браузером: export SSLKEYLOGFILE=keys.log (перед запуском)
```

## Что дальше / решение

Если задача не решается по чек-листу, действуйте по дереву решений:

1. **Есть «необычный» протокол в `io,phs`** → идите туда (USB, Modbus, RTP).
2. **Много DNS/ICMP с энтропийными данными** → декодируйте base32/base64, соберите по порядку.
3. **Есть HTTP/SMB-трафик** → export objects, затем `file`/`strings`/`binwalk` по объектам.
4. **Трафик зашифрован (TLS)** → ищите ключи/`SSLKEYLOGFILE` в подсказке или слабый шифр.
5. **Всё «обычно»** → смотрите тайминги, размеры пакетов, поля заголовков (id, seq, TTL) — covert бывает в метаданных.
6. **Wi-Fi** → EAPOL/handshake, `aircrack-ng`.

Решение-эвристика: флаг почти всегда лежит в одном из трёх мест — объекте (файле), скрытом канале (DNS/ICMP/timing) или секрете (креды). Проверяйте в этом порядке.

## Резюме

Методичность важнее скорости: инвентаризация → протоколы → объекты → креды → covert → спец-протоколы. Ведите чек-лист и не пропускайте шаги. `tshark` в связке с `capinfos`/`foremost`/`binwalk` покрывает 90% CTF-задач по трафику.

## Метаданные как канал

Иногда данные прячут не в полезной нагрузке, а в **полях заголовков**. Проверяйте:

- **IP ID** — монотонный счётчик; аномальные значения кодируют байты.
- **TCP sequence/ack** — большие «случайные» числа могут быть ASCII.
- **TTL** — вариация кодирует биты (часто 64±n).
- **Размер пакета** — длина payload как код символа.
- **Метки времени** — задержки (timing covert).

```bash
# IP ID как байты
tshark -r c.pcap -Y 'ip' -T fields -e ip.id | head
# TTL-распределение
tshark -r c.pcap -Y 'ip' -T fields -e ip.ttl | sort | uniq -c | sort -rn | head
# Размеры пакетов
tshark -r c.pcap -T fields -e frame.len | sort -n | uniq -c | sort -rn | head
```

## Работа с большими дампами

Дамп на гигабайты нельзя открыть в Wireshark целиком. Используйте потоковые инструменты:

```bash
# Разрезать по времени/размеру
editcap -c 100000 big.pcap chunk.pcap        # по 100k пакетов
editcap -A '2024-01-01 10:00:00' -B '2024-01-01 10:05:00' big.pcap window.pcap
# Отфильтровать в отдельный файл до анализа
tshark -r big.pcap -Y 'http or dns' -w small.pcap
# Сжать/распаковать
editcap -F pcapng big.pcap out.pcapng
```

Приёмы: сначала `capinfos` и `io,phs`, затем сужайте фильтром и только потом экспортируйте. `tshark -z io,phs` на большом дампе может занять минуты — запускайте фоном с `tee`.

## Сравнение подходов

| Инструмент | Сильная сторона | Ограничение |
|------------|-----------------|-------------|
| tshark | CLI, скриптуемость, `-T fields` | без GUI-визуализации |
| Wireshark | визуальный анализ, follow stream | тяжёл на больших дампах |
| tcpdump | быстрый захват/фильтр BPF | нет dissector'ов |
| foremost/binwalk | carving из «сырого» потока | могут резать по ложным сигнатурам |
| NetworkMiner | артефакты (хосты, файлы) в GUI | платформа Windows/моно |

## Квиз

```quiz
- question: "С чего начинают анализ PCAP?"
  options:
    - "С инвентаризации: capinfos и иерархия протоколов"
    - "С поиска флага в hex"
    - "С расшифровки TLS"
    - "С перебора паролей"
  answer: 0
  explanation: "Понимание масштаба и протоколов задаёт направление."
- question: "Какой приём извлекает файлы из HTTP-трафика?"
  options:
    - "Export objects (http)"
    - "Follow stream"
    - "capinfos"
    - "DNS-фильтр"
  answer: 0
  explanation: "--export-objects http восстанавливает переданные по HTTP файлы."
- question: "Какой признак DNS-туннеля в PCAP?"
  options:
    - "Длинные base32-поддомены одного родителя"
    - "Короткие A-запросы"
    - "TTL=64"
    - "Использование TCP/80"
  answer: 0
  explanation: "Энтропийные длинные метки указывают на скрытый канал."
- question: "Что делать с извлечённым файлом-картинкой?"
  options:
    - "Проверить на стеганографию (strings, binwalk, zsteg)"
    - "Удалить"
    - "Отправить на печать"
    - "Перекодировать в base64"
  answer: 0
  explanation: "Флаг часто спрятан внутри изображения методами стеганографии."
- question: "Зачем нужен follow stream?"
  options:
    - "Чтобы увидеть содержимое конкретной сессии целиком"
    - "Чтобы ускорить захват"
    - "Чтобы расшифровать TLS"
    - "Чтобы сменить MAC"
  answer: 0
  explanation: "Follow stream собирает байты сессии в читаемый вид."
```

## Где пригодится

- **CTF:** методичное решение PCAP-задач.
- **IR:** разбор инцидентов по сетевому трафику.
- **Пентест:** анализ перехваченного трафика.
- **SOC:** понимание, что искать в телеметрии.
- **Обучение:** навык, применимый к любой задаче с трафиком.
