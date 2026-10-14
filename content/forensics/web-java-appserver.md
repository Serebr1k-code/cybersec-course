---
id: web-java-appserver
title: 'Java-серверы: Tomcat, JBoss и следы эксплуатации'
category: forensics
parent: forensics-web-apps
difficulty: hard
order: 2
tags: [forensics, web, tomcat, jboss, java, logs]
prerequisites: [forensics-web-forensics]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как расследовать компромисс Java-серверов: логи, деплои WAR, десериализация и веб-шеллы.'
lab:
  kind: shell
  title: 'Практика: Java-серверы'
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

Корпоративное Java-приложение (Tomcat/JBoss) скомпрометировано. Такие серверы известны
уязвимостями (десериализация, менеджер). Где следы? Разберём.

## Наш пример: Tomcat

## Шаг 1: логи

```
$ ls /var/log/tomcat*/
catalina.out  localhost_access_log.2026-01-14.txt
```

`catalina.out` — общий лог, `localhost_access_log` — запросы.

```
$ grep -iE 'exception|deserial' catalina.out | tail
```

Исключения десериализации — признак эксплуатации.

## Шаг 2: менеджер

Tomcat Manager (`/manager/html`) позволяет деплоить WAR:

```
$ grep '/manager/html' localhost_access_log.2026-01-14.txt | tail
203.0.113.5 - - "POST /manager/html/upload HTTP/1.1" 200
```

Загрузка WAR с внешнего IP — почти наверняка атака.

## Шаг 3: деплои

Смотрим, что развёрнуто и когда:

```
$ ls -la /var/lib/tomcat/webapps/
shell.war   (Jan 14 03:30)
```

Новый WAR-файл = внедрённый веб-шелл.

## Шаг 4: десериализация

Уязвимости Java-десериализации (ysoserial) выполняют команды. Признаки:

- большие бинарные тела в логах;
- вызовы `Runtime.exec`;
- аномальные процессы Java (сеть, файлы).

```
$ ps aux | grep java
```

## Шаг 5: что искать

- новые/изменённые WAR/class-файлы;
- обращения к `/manager`, `/jmx-console`, `/wls-wsat`;
- исключения десериализации;
- исходящие соединения от Java.

## Шаг 6: где Tomcat хранит данные

Tomcat — это каталог `CATALINA_HOME` (обычно `/opt/tomcat` или `/usr/share/tomcat`). Внутри:

```
$ ls /opt/tomcat
bin/  conf/  lib/  logs/  temp/  webapps/  work/
```

- `webapps/` — развёрнутые приложения (WAR распаковывается сюда);
- `conf/` — настройки (`server.xml`, `tomcat-users.xml`);
- `logs/` — `catalina.out` и access-логи;
- `work/` — скомпилированные JSP.

Это «место преступления»: здесь и код, и настройки, и следы запросов. В расследовании фиксируем содержимое `webapps/` и `conf/` до любых изменений.

## Шаг 7: конфигурация и учётки

`conf/tomcat-users.xml` хранит пользователей и роли:

```
$ grep -i 'user ' conf/tomcat-users.xml
<user username="admin" password="..." roles="manager-gui,admin-gui"/>
```

Роль `manager-gui` даёт доступ к веб-менеджеру — тому самому, через который деплоят WAR. Слабый пароль или доступ менеджера из интернета — прямой путь к RCE. Проверяем `server.xml` на то, слушает ли менеджер внешние адреса.

## Шаг 8: что внутри WAR

Внедрённый WAR распаковывается в каталог. Смотрим его содержимое:

```
$ unzip -l shell.war
WEB-INF/web.xml
WEB-INF/classes/Evil.class
```

`web.xml` описывает сервлет, `classes/*.class` — код. Даже если исходников нет, `.class` декомпилируется (`javap`, `cfr`). Так восстанавливают, что именно делал шелл: выполнял команды, отдавал файлы, открывал реверс.

## Шаг 9: десериализация в логах

Уязвимости десериализации оставляют характерные следы. Ищем исключения:

```
$ grep -iE 'ClassNotFoundException|InvalidClassException|readObject' catalina.out | tail
```

Такие исключения — след «гаджет-цепи», которую прислал атакующий. Полезно сопоставить время с POST-запросами в access-логе: тело POST (бинарный Java-объект) часто не логируется, но сам факт запроса виден.

## Шаг 10: JBoss и WildFly

Другие Java-серверы имеют свои точки:

```
$ grep -iE '/jmx-console|/wls-wsat|/invoker' access.log | tail
```

`/jmx-console` и `/wls-wsat` — исторически уязвимые консоли. Развёрнутые приложения лежат в `standalone/deployments/`. Признак тот же: новый/изменённый артефакт и подозрительные запросы.

## Шаг 11: практика

Дано: access-лог и каталог `webapps/`. Действия:

1. агрегируем IP в логе (`awk '{print $1}' | sort | uniq -c | sort -rn`);
2. ищем обращения к `/manager/html` и `/jmx-console`;
3. смотрим даты WAR-файлов (`ls -la webapps/`);
4. распаковываем подозрительный WAR и читаем `web.xml`;
5. сопоставляем время деплоя с запросом на загрузку.

Так выстраивается цепочка «доступ к менеджеру → загрузка WAR → выполнение команд».

## Что важно запомнить

- `CATALINA_HOME` — корень данных Tomcat.
- `tomcat-users.xml` и менеджер — ключевой вектор.
- WAR распаковывается; `.class` декомпилируется.
- Исключения десериализации — след эксплуатации.
- Время деплоя связывает файл с запросом.

## Что мы теперь знаем

- Tomcat логи: catalina.out + access-log.
- Manager позволяет деплоить WAR (вектор).
- Новый WAR = шелл.
- Десериализация даёт RCE.
- Ищем аномалии в логах и файлах.

- STL — геометрия; OBJ/GLTF/3MF несут метаданные.
- Бинарный STL: 80-байтовый заголовок + число треугольников.
- GLB = JSON+BIN; 3MF = ZIP+XML.
- Данные прячут в комментариях, чанках и самой геометрии.
- Сравнение с эталоном выявляет встраивание.

## Если не сработало

- Логи усечены? Смотри access-log по датам.
- WAR зашифрован? Распакуй и смотри class-файлы.
- Нужен процесс? Анализируй память Java.

## Квиз

Проверь себя.

```quiz
- question: Что такое catalina.out?
  options:
    - 'база данных'
    - 'основной лог Tomcat'
    - 'шелл'
    - 'сеть'
  answer: 1
  explanation: 'catalina.out — общий лог контейнера Tomcat.'
- question: Чем опасен Tomcat Manager?
  options:
    - 'ничем'
    - 'позволяет деплоить WAR (RCE)'
    - 'шифрует'
    - 'ускоряет'
  answer: 1
  explanation: 'Через manager можно загрузить вредоносный WAR.'
- question: Признак эксплуатации десериализации?
  options:
    - 'GET на главную'
    - 'исключения десериализации и большие бинарные тела'
    - 'много картинок'
    - 'ничего'
  answer: 1
  explanation: 'Гаджет-цепи оставляют исключения в логах.'
- question: Что искать в webapps?
  options:
    - 'обои'
    - 'новые/изменённые WAR'
    - 'шрифты'
    - 'музыку'
  answer: 1
  explanation: 'Лишний WAR — внедрённое приложение/шелл.'
```

## Куда дальше

Дальше — **аутентичность медиа**: C2PA и deepfake. А пока: 3D-файл — это контейнер и геометрия; читай текстовые части и сравнивай с эталоном.

## Где пригодится

- **CTF Forensics** — задачи с 3D-моделями.
- **DFIR / Incident Response** — анализ CAD/3D.
- **Анализ медиа** — поиск скрытых данных.
