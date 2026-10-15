#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_topup_gap8.py — clear the last small deficits in osint/rev/web/hardware."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _topup_gap

SEC = {
    'hardware': {
        'hardware-opc-ua': [('## Быстрый чек-лист OPC UA',
         'Порядок проверки: `GetEndpoints` (анонимно) → есть ли `None/None` → `Browse` дерева → '
         '`Read` значений → проверка `AccessLevel` управляющих узлов → оценка импакта. '
         'Инструменты: `opcua` (Python), `UaExpert`, `nmap --script opcua-info`. Ключевые '
         'находки: незащищённый endpoint, анонимный токен, узел с `CurrentWrite` среди '
         'управляющих. Активные действия (запись) — только на стенде.')],
        'hardware-smart-grid': [('## Быстрый чек-лист AMI/DLMS',
         'Порядок: определить канал (PLC/RF/GPRS) → установить HDLC → попробовать ассоциацию '
         '`Lowest` → при успехе читать публичные объекты по OBIS → оценить, даёт ли `Low`/`High` '
         'запись. Инструменты: `Gurux.DLMS`, `Gurux DLMS Director`, `dlms-cosem`. Ключевые '
         'находки: `Lowest`-ассоциация, дефолтный пароль, доступность из корпоративной сети, '
         'незашифрованный RF. Запись (реле, тариф) — только на стенде.')],
        'hardware-bacnet': [('## Быстрый чек-лист BACnet',
         'Порядок: `Who-Is` → `I-Am` (инвентарь) → `ReadProperty` на `object-list` → чтение '
         '`Present_Value` и `Priority_Array` → классификация точек (жизнеобеспечение?). '
         'Инструменты: `bacnet-stack`, `BAC0`, `YABE`, Wireshark. Ключевая находка — анонимная '
         'запись в критичную точку. Активные действия — только с разрешения.')],
        'hardware-zigbee-deep': [('## Быстрый чек-лист Zigbee',
         'Порядок: найти сеть (`zbstumbler`) → захват (`zbdump`) → проверка дефолтного TC Link '
         'Key → восстановление Network Key → расшифровка → карта ZCL-устройств. Ключевые '
         'находки: дефолтный TC Link Key, insecure rejoin, OTA без подписи. Инструменты: '
         '`killerbee`, `nRF Sniffer`, Wireshark, `ZigDiggity`.')],
        'hardware-autosar': [('## Быстрый чек-лист SecOC',
         'Порядок: `candump` → выделить защищённые PDU (постоянный MAC + счётчик) → определить '
         'длину MAC → проверить свежесть → проверить fallback. Ключевые находки: слабый/'
         'повторный ключ, короткий MAC, предсказуемая свежесть, приём незащищённых PDU. Всё — '
         'на стенде; CAN автомобиля не трогать.')],
        'hardware-cip-enip': [('## Быстрый чек-лист EtherNet/IP',
         'Порядок: `nmap --script enip-info` → `List Identity` (инвентарь) → `Register Session` '
         '→ `Read Tag` (карта тегов) → поиск управляющих тегов. Инструменты: `cpppo`, `pycomm3`, '
         'Wireshark (`enip`). Ключевая находка — анонимная запись в управляющий тег. UDP 2222 — '
         'реальное управление, не диагностика.')],
        'hardware-tpms': [('## Быстрый чек-лист TPMS',
         'Порядок: определить частоту → записать IQ (`rtl_sdr`) → демодулировать ASK/OOK → '
         'декодировать Manchester → выделить поля (ID, давление, CRC) → привязать ID. '
         'Инструменты: `urh`, `inspectrum`, GNU Radio. Находки: отсутствие аутентификации '
         '(спуфинг) и стабильный ID (трекинг).')],
        'hardware-6lowpan': [('## Быстрый чек-лист 6LoWPAN/Thread',
         'Порядок: найти сеть (`zbstumbler`/`nrf_sniffer`) → захват → при наличии ключа '
         'расшифровка → топология (MLE/RPL) → проверка ключей и commissioning. Инструменты: '
         '`killerbee`, nRF Sniffer, Wireshark, `tshark`. Находки: дефолтный ключ, открытое '
         'commissioning, insecure rejoin.')],
        'hardware-zwave-deep': [('## Быстрый чек-лист Z-Wave',
         'Порядок: сниффинг (`Zniffer`) → Home ID/топология → определить S0/S2 → при S0 добыть '
         'ключ (перехват join/дамп контроллера) → расшифровка → карта устройств. Находки: '
         'использование S0, дефолтные ключи, критичные устройства (замки). Управление — только '
         'на стенде.')],
        'hardware-keyless-relay': [('## Быстрый чек-лист RKE/PKE',
         'Порядок: определить тип (RKE/PKE) → проверить частоты LF/RF → оценить, есть ли UWB или '
         'motion-защита → попытка relay (на своём авто) → проверка rolling code на RollJam. '
         'Инструменты: `HackRF`, `YARD Stick One`, `Proxmark`. Вывод: без UWB защита от relay '
         'отсутствует.')],
    },
    'web': {
        'web-spring-boot-actuator': [('## Мини-шпаргалка по Actuator',
         '`/actuator` (список) → `/actuator/env` (конфиг) → `/actuator/configprops` → '
         '`/actuator/heapdump` (секреты) → `/actuator/jolokia` (JMX) → SpEL (Spring Cloud). '
         'Проверяй также другой порт (`management.server.port`) и базовый путь '
         '(`management.endpoints.web.base-path`). Активные шаги — в последнюю очередь.')],
        'web-sitecore': [('## Мини-шпаргалка по Sitecore',
         'Версия → `/sitecore/api/`, `/sitecore/admin/`, `-/item/` → `machineKey` в `web.config` '
         '(дефолт?) → ViewState-полезная нагрузка (`ysoserial.net`). Критичность зависит от '
         'ключей: дефолтный `machineKey` = RCE, уникальный = ограничение.')],
        'web-umbraco': [('## Мини-шпаргалка по Umbraco',
         'Версия (`/umbraco/`) → бэкенд-эндпоинты (`/umbraco/backoffice/`, `/umbraco/api/`) → '
         '`web.config`/`machineKey` → ViewState. Помни про разделение backoffice-пользователей и '
         'members и про чувствительность к нагрузке: один запрос за раз.')],
        'web-sharepoint': [('## Мини-шпаргалка по SharePoint',
         'Версия → публичные `_layouts`/`_vti_bin` → ToolShell (CVE-2025-53770) → `machineKey` '
         '→ ViewState RCE. После эксплуатации ключи надо ротировать. Без `machineKey` '
         'ViewState-атака невозможна.')],
        'web-wordpress': [('## Мини-шпаргалка по WordPress',
         'Версия → плагины/темы → `/wp-json/wp/v2/users` (логины) → `xmlrpc.php` (брут/SSRF) → '
         '`wp-config.php` (БД + соли). Ключевой актив — конфиг: оттуда и БД, и подделка '
         'auth-cookie.')],
        'web-wordpress-plugins': [('## Мини-шпаргалка по плагинам',
         'Список плагинов (`/?rest_route=/wp/v2/plugins`, исходник, `readme.txt`) → версии → '
         '`wpscan --enumerate vp` → ручной разбор changelog/кода. Классы: SQLi, загрузка, '
         'LFI, object injection. Проверяй безопасно (time-based, чтение безобидных файлов).')],
    },
}

if __name__ == '__main__':
    _topup_gap.apply(SEC['hardware'], 'hardware')
    _topup_gap.apply(SEC['web'], 'web')
