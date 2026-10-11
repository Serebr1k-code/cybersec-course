---
id: mobile-mitm-advanced
title: "Продвинутый MITM мобильного трафика: transparent, VPN, QUIC"
category: mobile
parent: mobile-network-security
difficulty: medium
order: 1
tags: [mitmproxy, burp, transparent, iptables, vpn, quic, http2, ssl, android, ios]
prerequisites: [mobile-mitm-burp]
useful_for:
  - "Пентест мобильных приложений"
  - "Bug bounty"
  - "Анализ трафика"
estimated_minutes: 50
summary: "Продвинутые техники перехвата: transparent proxy через iptables, VPN-режим mitmproxy, обход игнорирования прокси, HTTP/2 и QUIC/HTTP3."
---
## Введение

Обычная схема «прокси в Wi-Fi настройках + CA» работает не всегда: приложения игнорируют системный прокси (делают свои сокеты), используют HTTP/3 (QUIC поверх UDP), пиннят, или прокси-настройка недоступна (Wi-Fi без настройки, приложение на iOS без профиля). Тогда применяют **transparent proxy** (перехват на уровне iptables без настройки в приложении), **VPN-режим mitmproxy** (перехват через TUN), и специальные приёмы для QUIC/HTTP2. Этот урок — практическое расширение `mobile-mitm-burp`.

Ментальная модель: приложение может не знать про прокси, но трафик всё равно идёт через сетевой стек устройства — если завернуть его на уровне ядра (iptables/VPN), перехват не зависит от настроек приложения.

## Transparent proxy через iptables

Идея: на root-устройстве перенаправляем TCP-трафик портов 80/443 в mitmproxy, работающий в режиме `transparent`.

```bash
# на ПК запускаем mitmproxy в transparent-режиме
mitmproxy --mode transparent --showhost -p 8080
# либо mitmweb
mitmweb --mode transparent --listen-port 8080
```

```bash
# на устройстве (root): заворачиваем трафик в прокси ПК (192.168.1.10:8080)
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.1.10:8080'
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 80  -j DNAT --to-destination 192.168.1.10:8080'
# исключить трафик самого прокси/устройства по необходимости
adb shell su -c 'iptables -t nat -L OUTPUT -n -v'
```

Теперь даже приложение, игнорирующее прокси-настройку, идёт через mitmproxy. Важно: для HTTPS нужен доверенный CA (системный на root) — иначе TLS не расшифруется.

## VPN-режим mitmproxy (без iptables)

mitmproxy умеет поднимать WireGuard-VPN, который сам заворачивает трафик:

```bash
mitmweb --mode wireguard
# приложение WireGuard на телефоне подключается к конфигу, который выдаёт mitmproxy
```

Плюс: не нужен root для iptables, работает через обычный VPN-профиль. Минус: приложение может детектить VPN (`NetworkCapabilities.TRANSPORT_VPN`).

## Полный сквозной пример: перехват приложения, игнорирующего прокси

```bash
# 1. Приложение не видит Burp даже с CA -> переходим на transparent
mitmproxy --mode transparent --showhost -p 8080
# 2. Заворачиваем трафик на устройстве
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.1.10:8080'
# 3. Ставим системный CA (см. mobile-network-security-config)
# 4. Запускаем приложение -> в mitmproxy видим поток запросов
# 5. Сохраняем поток
#    (в mitmproxy: w flows.mitm  / в mitmweb: Export)
```

Если после заворота трафик не расшифровывается — это pinning (см. `mobile-tls-pinning-bypass`), а не проблема прокси.

## QUIC/HTTP3

QUIC работает поверх UDP:443 — iptables-DNAT для TCP его не поймает. Варианты:

1. **Заблокировать UDP:443**, чтобы приложение откатилось на TCP (TLS/TCP):
```bash
adb shell su -c 'iptables -A OUTPUT -p udp --dport 443 -j REJECT'
```
2. **Проксировать QUIC** (mitmproxy поддерживает HTTP/3 в новых версиях) — сложнее.
3. **Хукать нативно** через Frida (`SSL_write`/`SSL_read` в `libssl`/BoringSSL) — `r0capture`-подход.

```bash
# r0capture: Frida-скрипт для дампа TLS в нативном коде
frida -U -f com.target.app -l r0capture.js
```

## HTTP/2 и нестандартные порты

HTTP/2 (h2) mitmproxy/Burp поддерживают. Нестандартные порты — добавляйте iptables-правила для них. WebSocket — тоже перехватывается (mitmproxy показывает frames). gRPC (HTTP/2) — работает, но читать нужно как protobuf.

## iOS-специфика

На iOS transparent proxy через iptables недоступен без jailbreak; используйте:
- системный прокси в Wi-Fi (Burp/mitmproxy);
- VPN-режим mitmproxy (WireGuard-профиль);
- на jailbreak — `iptables`/`pf`-правила (аналог transparent).

CA и pinning — см. `mobile-ios-ssl-killswitch`.

## Частые ошибки

- **Забыть про UDP/QUIC**: часть трафика уходит мимо TCP-прокси.
- **Прокси-петля**: заворачивание трафика самого прокси в прокси — исключайте IP ПК.
- **Нет системного CA**: transparent-прокси без доверенного CA даёт ошибки TLS.
- **VPN-детект**: приложение проверяет `TRANSPORT_VPN` — комбинируйте с Frida-хуком.
- **Не тот интерфейс**: на устройстве несколько сетей — проверяйте `-o wlan0`.
- **iptables сбрасывается**: некоторые прошивки чистят правила — переприменяйте.

## Что дальше / решение

Порядок: обычный прокси → transparent (iptables) → VPN (mitmproxy wireguard) → блокировка QUIC → нативные хуки. Если трафик не расшифровывается — pinning; если не виден — proxy-ignore/QUIC; если падает — детект окружения. Свяжите с `mobile-network-security-config`, `mobile-emulator-detection`, `mobile-tls-pinning-bypass`.

## Справочная таблица

| Ситуация | Решение |
|----------|---------|
| Игнорирует прокси | transparent (iptables) |
| Нет root | VPN (mitmproxy wireguard) |
| QUIC/HTTP3 | блок UDP:443 / нативный хук |
| HTTP/2 | mitmproxy/Burp (поддержка есть) |
| iOS | системный прокси / VPN |

| Инструмент | Режим |
|-----------|-------|
| mitmproxy | `--mode transparent` / `wireguard` |
| Burp | invisible proxying |
| r0capture | Frida TLS dump |

## Сквозной кейс: transparent-перехват приложения без прокси

Разберём полный сценарий на root-устройстве.

Первый этап — подготовка. Приложение игнорирует системный прокси и не принимает пользовательский CA. Ставим системный CA (root) и поднимаем mitmproxy в transparent-режиме на ПК:

```bash
mitmproxy --mode transparent --showhost -p 8080
```

Второй этап — заворот трафика. На устройстве правилами iptables перенаправляем TCP 80/443 на ПК:

```bash
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.1.10:8080'
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 192.168.1.10:8080'
adb shell su -c 'iptables -t nat -L OUTPUT -n -v'
```

Третий этап — проверка. Запускаем приложение, выполняем действие. В mitmproxy видим поток. Если трафик не расшифровывается — pinning (см. `mobile-tls-pinning-bypass`). Если не видим вообще — QUIC (UDP:443) или нативный стек.

Четвёртый этап — QUIC. Блокируем UDP:443, чтобы приложение откатилось на TCP:

```bash
adb shell su -c 'iptables -A OUTPUT -p udp --dport 443 -j REJECT'
```

Пятый этап — сохранение. Экспортируем поток (`w flows.mitm`) для дальнейшего анализа и отчёта.

## VPN-режим без root

Если root нет, используем mitmproxy в режиме wireguard: он выдаёт конфиг, который подключается как VPN-профиль на телефоне. Трафик идёт через TUN mitmproxy. Минус — приложение может детектить VPN (`NetworkCapabilities.TRANSPORT_VPN`), обходится Frida-хуком.

## HTTP/2, gRPC, WebSocket

mitmproxy/Burp поддерживают HTTP/2 и WebSocket. gRPC (HTTP/2) перехватывается, но тело — protobuf; для чтения нужен парсер. WebSocket показывает кадры.

## Диагностика проблем

Если трафик не идёт: проверьте IP ПК (не заворачивайте трафик прокси в прокси), интерфейс (`-o wlan0`), что iptables применились, что CA доверенный. Если расшифровка не удаётся — pinning. Если запросы к IP, а не домену — pinning по сертификату.

## Чек-лист

Подготовить CA, поднять transparent/VPN, заворотить трафик, проверить поток, разобраться с QUIC/pinning, сохранить и проанализировать.

## Рекомендации в отчёте

Прокси-настройки — не защита; сервер должен полагаться на аутентификацию и валидацию, а не на «невидимость» трафика. Pinning и аттестация повышают стоимость MITM, но обходятся инструментированным клиентом.

## Настройка mitmproxy для мобильных: конфиги и плагины

Для мобильного перехвата mitmproxy удобно запускать с конфигом, чтобы не повторять флаги. Создайте `~/.mitmproxy/config.yaml` с параметрами по умолчанию (порт, режим, сохранение потоков). Для transparent-режима обязательно указывайте `--showhost`, иначе хосты в логе будут IP-адресами. Полезен плагин, который логирует только интересные запросы (по домену) и складывает их в файл.

Пример плагина на Python, который печатает тело POST к API целевого домена:

```python
from mitmproxy import http
def request(flow: http.HTTPFlow):
    if "api.target.com" in flow.request.pretty_host and flow.request.method == "POST":
        print(flow.request.pretty_url, flow.request.get_text()[:200])
```

Запуск с плагином: `mitmproxy -s log_api.py --mode transparent`. Это избавляет от ручного поиска в потоке и позволяет сразу видеть параметры запросов.

Для повторного воспроизведения запросов используйте `mitmproxy` → `replay` или экспорт в curl. В Burp аналогично работает Repeater. Комбинируйте перехват с Frida-обходом pinning, чтобы видеть расшифрованный трафик.

## Работа с бинарными протоколами

Если приложение использует protobuf/gRPC, тело будет бинарным. Сохраняйте потоки и разбирайте protobuf-схемой (если есть) или инструментами декодирования. Для WebSocket смотрите кадры в mitmproxy. Для HTTP/3 убедитесь, что блокировка QUIC применена, иначе часть трафика уйдёт мимо.

## Практикум: transparent-перехват с нуля

Разберём полный transparent-перехват на root-устройстве.

Шаг 1. Системный CA. Положите Burp/mitmproxy CA в системное хранилище:

```bash
openssl x509 -inform PEM -subject_hash_old -in ca.pem | head -1   # => 9a5ba575
cp ca.pem 9a5ba575.0
adb push 9a5ba575.0 /sdcard/
adb shell su -c 'cp /sdcard/9a5ba575.0 /system/etc/security/cacerts/ && chmod 644 /system/etc/security/cacerts/9a5ba575.0'
adb reboot
```

Шаг 2. mitmproxy transparent:

```bash
mitmproxy --mode transparent --showhost -p 8080
```

Шаг 3. Заворот трафика:

```bash
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.1.10:8080'
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 192.168.1.10:8080'
```

Шаг 4. Проверка. Запускаем приложение, выполняем действие. Смотрим поток в mitmproxy.

Шаг 5. QUIC. Если часть трафика не видна — блокируем UDP:443:

```bash
adb shell su -c 'iptables -A OUTPUT -p udp --dport 443 -j REJECT'
```

Шаг 6. Нативный стек. Если трафик не расшифровывается — pinning (см. `mobile-tls-pinning-bypass`) или нативный TLS (хукать `SSL_write`).

## Что писать в отчёте

Transparent-прокси показывает, что приложение не защищено от перехвата даже без настройки прокси в нём. Рекомендация — pinning + аттестация + серверная валидация.

## Квиз

```quiz
- question: "Зачем нужен transparent proxy?"
  options:
    - "Перехватывать трафик приложений, игнорирующих системный прокси"
    - "Ускорять сеть"
    - "Менять CA"
    - "Снимать root"
  answer: 0
- question: "Какой режим mitmproxy не требует root для заворота трафика?"
  options:
    - "transparent"
    - "wireguard (VPN)"
    - "regular"
    - "socks5"
  answer: 1
- question: "Почему QUIC не перехватывается TCP-прокси?"
  options:
    - "QUIC работает поверх UDP"
    - "QUIC зашифрован дважды"
    - "QUIC — это IPv6"
    - "QUIC только для iOS"
  answer: 0
- question: "Что делать, чтобы приложение откатилось с QUIC на TCP?"
  options:
    - "Заблокировать UDP:443"
    - "Отключить Wi-Fi"
    - "Включить HTTP/2"
    - "Сменить CA"
  answer: 0
- question: "Если трафик виден, но не расшифровывается, причина — ..."
  options:
    - "Pinning"
    - "QUIC"
    - "Нет интернета"
    - "Слабый сигнал"
  answer: 0
```

## Где пригодится

- **Пентест:** перехват в сложных условиях.
- **Bug bounty:** тестирование API без настройки прокси в приложении.
- **Анализ малвари:** перехват C2 (в т.ч. QUIC).
- **CTF:** Mobile-задачи с сетью.
