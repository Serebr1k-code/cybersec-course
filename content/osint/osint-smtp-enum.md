---
id: osint-smtp-enum
title: "Перечисление почтовых ящиков через SMTP (VRFY/EXPN/RCPT)"
category: osint
parent: osint-email-headers
difficulty: medium
order: 3
tags: [smtp, enum, vrfy, expn, rcpt, email]
prerequisites: [osint-email-headers]
useful_for:
  - "Пентест: сбор валидных учёток"
  - "OSINT: подтверждение существования адресов"
estimated_minutes: 45
summary: "Команды VRFY/EXPN/RCPT TO, smtp-user-enum, автоматический перебор и защита от enumeration, этика и rate-limit."
---

SMTP-серверы умеют отвечать на вопросы о пользователях. Команды `VRFY`, `EXPN` и `RCPT TO` позволяют проверить, существует ли ящик. Это классическая техника OSINT: подтвердить формат адресов (`имя.фамилия@`), собрать список сотрудников и подготовить почву для фишинга или подбора.

## Команды SMTP

- **VRFY user** — «существует ли такой пользователь?»; сервер отвечает `250` (есть), `252` (не может подтвердить) или `550` (нет).
- **EXPN list** — раскрыть список рассылки; часто отключён.
- **RCPT TO:<user@domain>** — используется при доставке; если сервер не отклоняет несуществующий ящик на этапе RCPT, перебор работает.
- **MAIL FROM / DATA** — полный цикл доставки; некоторые серверы отклоняют ящик только здесь.

```bash
# ручная сессия
nc mail.example.com 25
EHLO test
VRFY admin
EXPN all
RCPT TO:<admin@example.com>
QUIT
```

## smtp-user-enum

```bash
# проверить один пользователь разными методами
smtp-user-enum -M VRFY -U users.txt -t mail.example.com

# перебор методом RCPT (нужен домен)
smtp-user-enum -M RCPT -U users.txt -D example.com -t mail.example.com

# метод EXPN
smtp-user-enum -M EXPN -U lists.txt -t mail.example.com

# несколько серверов, таймаут, порт
smtp-user-enum -M VRFY -U users.txt -t mail.example.com -p 25 -w 5 -m 10
```

`-U` — список имён, `-D` — домен для RCPT, `-m` — интервал между запросами (анти-блокировка). Серверы с включённым VRFY дают быстрый и явный результат; современные (Postfix, Exchange) обычно отвечают `252` на VRFY и отклоняют несуществующие ящики только на этапе DATA.

## Формирование словаря имён

```bash
# типовые админы и служебные
printf '%s\n' admin administrator root postmaster webmaster hostmaster \
  info support sales billing noreply no-reply security abuse > users.txt

# комбинации имя.фамилия по найденным в LinkedIn сотрудникам
# (см. урок про LinkedIn OSINT и username enumeration)
```

Сначала определите **формат** адресов по утечкам/OSINT (`i.ivanov@`, `ivanov@`, `ivan@`), затем перебирайте только этот формат — иначе получите тысячи ложных.

## Открытый релей и другие проверки

- **Open relay** — сервер пересылает почту от чужих отправителей. Проверка: `swaks --to test@gmail.com --from x@evil.com --server mail.example.com`.
- **Banner grabbing** — `nc mail.example.com 25` покажет софт и версию.
- **STARTTLS** — `openssl s_client -starttls smtp -connect mail.example.com:25`.
- **Проверка конкретного ящика** — `swaks --server mail.example.com --to user@example.com --quit-after RCPT`.

## Защита и её обход

- Серверы отвечают одинаково на существующий и несуществующий ящик (`252`/`250` без разницы) — enumeration невозможен.
- **Tarpitting** — задержка после нескольких попыток; `smtp-user-enum` замедлится.
- **Fail2ban/rate-limit** — блокировка IP; снижайте темп (`-m 5`), используйте несколько источников.
- **Catch-all** — сервер принимает любой адрес; проверяется письмом-«приманкой».

## Разбор кейса

Задача: собрать валидные ящики `example.com`.

1. `nc mail.example.com 25` → Postfix, VRFY отвечает `252` (enumeration через VRFY не выйдет).
2. Пробуем `smtp-user-enum -M RCPT -U users.txt -D example.com` → сервер отклоняет несуществующие на RCPT (`550`) → перебор работает.
3. Находим `admin@`, `sales@`, `i.ivanov@` (формат подтверждён).
4. Проверяем catch-all приманкой `zzz123@` → `550`, значит домен не catch-all.
5. Фиксируем валидные адреса и формат для дальнейшего OSINT.

## Частые ошибки

- **Перебирать огромные словари**: enumeration — активная и заметная операция; ограничьте список и темп.
- **Игнорировать catch-all**: если домен принимает всё, «успех» перебора ничего не значит.
- **Считать `252` успехом**: `252` означает «не могу подтвердить», а не «существует».
- **Забыть про порт 587**: submission-порт часто настроен иначе, чем 25.
- **Не проверять несколько серверов**: у домена может быть несколько MX с разным поведением.

## Практические сессии и скрипты

```bash
# ручная проверка через nc
printf 'EHLO test\r\nVRFY admin\r\nRCPT TO:<admin@example.com>\r\nQUIT\r\n' | nc mail.example.com 25

# swaks: проверка конкретного адреса
swaks --server mail.example.com --to admin@example.com --quit-after RCPT

# несколько серверов разом
for mx in $(dig +short MX example.com | awk '{print $2}'); do
  echo "== $mx =="
  smtp-user-enum -M RCPT -U users.txt -D example.com -t $mx
done
```

## Защита от enumeration

На стороне сервера:

- **Единый ответ** для существующих/несуществующих (252/250 без разницы).
- **Отключить VRFY/EXPN** (Postfix: `disable_vrfy_command = yes`).
- **Tarpitting** — задержка после N попыток.
- **Fail2ban/rate-limit** — блокировка источников перебора.
- **Catch-all + приманка** — вводит переборщика в заблуждение.

## От адресов к учёткам

Собранные валидные адреса — основа для:

- **Фишинга** (в авторизованном scope).
- **Проверки утечек** (HIBP по каждому адресу).
- **Вывода формата** (для других сотрудников).
- **Корреляции** с соцсетями (см. osint-username-enum).

## SMTP-команды и коды ответов

Перечисление ящиков опирается на реакцию сервера на `VRFY`, `EXPN` и `RCPT TO`.

```text
HELO tester
MAIL FROM:<probe@example.com>
RCPT TO:<jsmith@example.com>     -> 250 (существует) / 550 (нет)
VRFY jsmith                       -> 250 <jsmith@example.com> / 550
EXPN listname                     -> раскрытие списка рассылки
QUIT
```

| Код | Значение | Вывод для enum |
|-----|----------|----------------|
| 250 | OK | ящик/команда принята → существует |
| 251 | forward | перенаправление, ящик есть |
| 252 | cannot VRFY | сервер не подтверждает (защита) |
| 450/451/452 | temp fail | временная ошибка, повторить |
| 550 | no such user | ящика нет |
| 551/553 | bad address | отклонено |

Серверы с отключённым `VRFY` отвечают 252 или 502 — тогда остаётся только `RCPT TO`.

## smtp-user-enum: флаги и режимы

```bash
smtp-user-enum -M VRFY -U users.txt -t mail.example.com
smtp-user-enum -M RCPT -U users.txt -D example.com -t mail.example.com
# -M метод (VRFY/EXPN/RCPT), -U файл юзеров, -D домен, -t цель, -p порт
# тайминги и вывод
smtp-user-enum -M RCPT -U users.txt -D example.com -t mail.example.com -m 10 -w 2 -v
```

Метод **RCPT** надёжнее VRFY (последний часто закрыт). Для RCPT важно правильно выставить `MAIL FROM` — некоторые серверы не принимают пустой отправитель.

## Catch-all и защита от ложных срабатываний

Если сервер отвечает 250 на **любой** адрес — включён **catch-all**, и enum бесполезен.

```bash
# проверка catch-all случайным адресом
smtp-user-enum -M RCPT -U <(echo "zzq7x9nonexist") -D example.com -t mail.example.com
# 250 на этот адрес => catch-all; результаты enum недостоверны
```

Также проверяйте **greylisting** (450 на первый запрос) — нужны повторы с паузами. И **rate-limit** — агрессивный enum ловит блокировку IP.

## Формирование словаря имён

Из OSINT-данных (osint-people-search, LinkedIn) соберите кандидаты и сгенерируйте паттерны:

```bash
# из списка "имя фамилия" -> варианты
while read f l; do
  for p in "$f" "$l" "$f.$l" "$f$l" "${f:0:1}$l" "$f.${l:0:1}"; do
    echo "${p,,}@example.com"
  done
done < names.txt | sort -u > candidates.txt
```

Паттерны: `first.last`, `flast`, `first`, `last`, `firstlast`, `f.last`. Корпоративный домен определяет суффикс (`@example.com`).

## swaks: ручная проверка и RCPT-скрипт

```bash
# одна проверка
swaks --to jsmith@example.com --from probe@example.com --server mail.example.com --quit-after RCPT
# ответ сервера покажет 250/550
# массовая проверка через RCPT
while read u; do
  r=$(swaks --to "$u" --from probe@example.com --server mail.example.com --quit-after RCPT 2>&1 | grep -oE '250|550' | head -1)
  echo "$u -> $r"
done < candidates.txt | tee smtp_enum.txt
```

`--quit-after RCPT` останавливается сразу после ответа на RCPT — быстро и без отправки письма.

## Открытый релей и другие проверки

- **Open relay**: сервер принимает `RCPT TO` на внешний домен при `MAIL FROM` чужого домена. Проверка — только в авторизованном тесте.

```bash
# тест open relay (авторизованно!)
swaks --to victim@gmail.com --from ceo@example.com --server mail.example.com
# 250 на внешний RCPT => потенциальный релей (или просто принимает, доставит локально)
```

- **STARTTLS downgrade**: если `STARTTLS` не обязателен, учётные данные могут уйти открыто.
- **Banner grab**: `nc mail.example.com 25` покажет версию (Postfix/Exim/Sendmail) и подсказки.

## От адресов к учёткам

Найденные ящики — вход в другие атаки:

1. **Password spray**: единый слабый пароль по найденным ящикам (O365/ADFS) — но это уже активная атака, нужна авторизация.
2. **Фишинг-поверхность**: список валидных адресов → целевые письма.
3. **Сброс пароля**: email как идентификатор в сервисах.
4. **Связь с OSINT**: адрес → утечки (HIBP/DeHashed) → пароль → проверка (osint-breach-data).

## Частые ошибки

- **Не проверять catch-all** — весь enum становится ложным.
- **Только VRFY** — на современных серверах почти всегда закрыт; используйте RCPT.
- **Слишком быстрый прогон** — greylisting и rate-limit портят результат.
- **Забыть про домен в RCPT** — `RCPT TO:<jsmith>` без `@domain` часто отклоняется.
- **Проверять внешний домен в RCPT без авторизации** — это уже тест релея (юридический риск, osint-legal-ethics).

## Квиз

```quiz
- question: "Какая SMTP-команда проверяет существование пользователя?"
  options:
    - "HELO"
    - "VRFY"
    - "DATA"
    - "QUIT"
  answer: 1
- question: "Что означает ответ `252` на VRFY?"
  options:
    - "Пользователь точно существует"
    - "Сервер не может подтвердить существование"
    - "Пользователь заблокирован"
    - "Команда не поддерживается"
  answer: 1
- question: "Что такое catch-all в контексте enumeration?"
  options:
    - "Сервер принимает любой адрес домена"
    - "Сервер блокирует перебор"
    - "Домен без MX-записи"
    - "Список рассылки"
  answer: 0
- question: "Какой инструмент перебирает пользователей по SMTP?"
  options:
    - "`nmap`"
    - "`smtp-user-enum`"
    - "`ffuf`"
    - "`hydra`"
  answer: 1
- question: "Почему перебор SMTP-ящиков требует осторожности?"
  options:
    - "Он всегда неточен"
    - "Это активная и заметная операция, возможны блокировки"
    - "Он требует пароля"
    - "Он портит почтовый сервер"
  answer: 1
```

## Где пригодится

- **CTF:** подтверждение существующего ящика для дальнейших шагов.
- **Bug bounty:** сбор валидных адресов в рамках программы.
- **Пентест:** подготовка списка учёток для фишинга и подбора.
- **Blue team:** проверка, не раскрывает ли ваш сервер пользователей.
