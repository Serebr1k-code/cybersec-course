---
id: net-ics-scada
title: 'ICS/SCADA в форензике: промышленные протоколы'
category: forensics
parent: forensics-net-ot
difficulty: hard
order: 1
tags: [network, ics, scada, modbus, dnp3, forensics]
prerequisites: [forensics-network-deep]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как анализировать промышленные протоколы (Modbus, DNP3), что означают операции и как найти вредоносное воздействие на PLC.'
lab:
  kind: shell
  title: "Практика: протокол Modbus/DNP3"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, scada_protocol.log]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "Modbus-функции: READ_HOLDING, WRITE_COIL и т.д."
    - "Запись (WRITE) от узла вне доверенной подсети — вторжение."
    - "`grep nto scada_protocol.log > answer.txt`."
---

## Вопрос, с которого всё начинается

На заводе произошла авария, и подозрение — на кибератаку. Обычные веб-логи тут не
помогут: контур говорит на **Modbus** и **DNP3**. Это простые протоколы без
аутентификации, поэтому их легко подделать. Разберём, что искать в дампе.

## Наш пример: Modbus-трафик

## Шаг 1: узнаём протокол

Modbus TCP — порт 502:

```
$ tshark -r ot.pcap -Y 'modbus' -T fields -e modbus.func_code -e ip.src -e ip.dst | head
16	10.10.30.5	10.10.30.20
6	10.10.30.5	10.10.30.20
```

`func_code=16` — Write Multiple Registers, `6` — Write Single Register. Оба **пишут**
в устройство. Чтения — это `3`/`4`.

## Шаг 2: что именно писали

```
$ tshark -r ot.pcap -Y 'modbus.func_code==6' -T fields -e modbus.reference_num -e modbus.word_cnt | head
100	1
```

`reference_num=100` — адрес регистра, в который писали. Регистры управляют
физическими процессами: клапанами, насосами, уставками. Запись в них меняет поведение
оборудования.

## Шаг 3: аномалии

Нормальный оператор читает (func 3/4) и редко пишет. Всплеск записей — подозрительно:

```
$ tshark -r ot.pcap -Y 'modbus.func_code==16' -T fields -e ip.src | sort | uniq -c | sort -rn
  500	10.10.30.99
```

Источник `10.10.30.99` — не инженерная станция, а неизвестный хост. Вот и злоумышленник.

## Шаг 4: DNP3

DNP3 (порт 20000) сложнее и используется в энергетике:

```
$ tshark -r ot.pcap -Y 'dnp3' -T fields -e dnp3.src -e dnp3.dst -e dnp3.al.func | head
```

Функции прикладного уровня (например, `OPERATE`) меняют состояние. Их тоже смотри.

## Шаг 5: что искать

- запись в регистры/уставки с необычного хоста;
- изменение конфигурации PLC (загрузка новой программы);
- «холодный» старт устройства;
- несоответствие времени (NTP-подмена).

## Что мы теперь знаем

- Modbus TCP — порт 502; func 3/4 — чтение, 6/16 — запись.
- Регистры управляют физическим процессом.
- Всплеск записей с чужого хоста — атака.
- DNP3 — энергетический протокол, функции меняют состояние.
- Аутентификации в классических протоколах нет.

## Если не сработало

- Трафик на уровне RTU/серийного? Нужен преобразователь и другой анализ.
- Нет дампа? Смотри логи HMI/SCADA.
- Нужна физика? Сопоставь с журналом датчиков.

## Квиз

Проверь себя.

```quiz
- question: Какой порт у Modbus TCP?
  options:
    - '80'
    - '502'
    - '443'
    - '22'
  answer: 1
  explanation: 'Modbus TCP слушает 502.'
- question: Какая функция Modbus пишет в регистр?
  options:
    - '3 (чтение)'
    - '6/16 (запись)'
    - '1'
    - '0'
  answer: 1
  explanation: 'Func 6 — Write Single, 16 — Write Multiple Registers.'
- question: Почему промышленные протоколы уязвимы?
  options:
    - 'они медленные'
    - 'в классических нет аутентификации'
    - 'они шифруются'
    - 'они новые'
  answer: 1
  explanation: 'Modbus/DNP3 создавались без проверки подлинности команд.'
- question: Что подозрительно в Modbus-дампе?
  options:
    - 'чтение регистров'
    - 'массовые записи с неизвестного хоста'
    - 'мало трафика'
    - 'TCP-соединение'
  answer: 1
  explanation: 'Записи в уставки с чужого адреса меняют физический процесс.'
```
