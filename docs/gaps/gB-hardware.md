# content/hardware — Gap Analysis (SECOND INDEPENDENT PASS, pass B)

Inventory: 117 md files (105 content lessons + 12 module/hub pages).
Verdict: **STRONG** on UART/JTAG/SWD/flash/filesystems/firmware/RF/SDR/RFID/NFC/
smartcard/side-channel/fault-injection/ICS/automotive.
Largest gaps: **Wi-Fi hardware (entirely missing)**, **cellular/2G-5G & SIM/baseband**,
**GNSS/satellite/DECT/TETRA/paging**, deeper automotive buses (FlexRay/LIN/DoIP/Automotive Ethernet),
ICS fieldbus breadth (EtherCAT/OPC UA/IEC 61850/IEC 104), MCU-family + architecture breadth,
physical silicon attacks (decapping/FIB/microprobing/EMFI), wireless wallets, consoles,
game/access-control, and emerging (PUF/chiplets/CXL/quantum).

One bullet per MISSING lesson: `- <proposed-id> — <short title>`.

## Wi-Fi / 802.11 hardware (entirely missing — highest-value gap)
- hardware-wifi-basics — Wi-Fi: каналы, кадры 802.11, monitor mode и чипсеты
- hardware-wifi-deauth — Deauth / disassoc атаки и защита (PMF)
- hardware-wifi-handshake — Захват WPA/WPA2 handshake и PMKID
- hardware-wifi-cracking — Офлайн-взлом WPA/WPA2: hashcat, словари и правила
- hardware-wifi-wpa3 — WPA3 / SAE / Dragonfly: атаки и downgrade
- hardware-wifi-krack — KRACK и атаки на 802.11-шифрование
- hardware-wifi-eviltwin — Evil Twin / rogue AP / captive-portal фишинг
- hardware-wifi-enterprise — WPA-Enterprise / 802.1X / EAP: обход и кража кредов
- hardware-wifi-driver-fw — Атаки на драйвер/прошивку Wi-Fi-чипсета
- hardware-wifi-6-7 — Wi-Fi 6/6E/7: OFDMA, MLO и новые поверхности
- hardware-wifi-pmkid-deep — PMKID / client-less атаки и форензика эфира
- hardware-wifi-ap-hacking — Взлом SOHO-роутеров и прошивок AP

## Cellular, SIM & baseband
- hardware-gsm-2g — GSM/2G: A5/1, IMSI-catcher и перехват
- hardware-umts-3g — UMTS/3G: защита, downgrade и атаки
- hardware-lte-4g — LTE/4G: attach, NAS, downgrade и IMSI-катчер
- hardware-5g-nr — 5G NR: архитектура, security, gNB и атаки
- hardware-sim-esim — SIM/eSIM: приложения, OTA, ключи и клонирование
- hardware-baseband — Baseband-процессор: реверс, фаззинг и уязвимости
- hardware-osmocom — Osmocom / srsRAN: построение базовой станции для тестов
- hardware-sms-ss7 — SS7 / Diameter / SMS-перехват и утечки
- hardware-imsi-catcher-det — Детект и защита от IMSI-катчеров

## GNSS, satellite & broadcast radio
- hardware-gps-gnss — GPS/GNSS: спуфинг, jamming и spoofing-детект
- hardware-satcom — SATCOM / Iridium / Inmarsat / Starlink: перехват и атаки
- hardware-dect — DECT: перехват, клонирование трубок и баз
- hardware-tetra — TETRA: протокол, шифрование и атаки на рации
- hardware-pocsag-flex — POCSAG / FLEX-пейджинг: декодирование и инъекции
- hardware-apco25 — APCO-25 / P25: цифровая радиосвязь и атаки
- hardware-ham-digital — DMR / D-STAR / Yaesu: цифровое радио и подмена

## RF protocols & wireless IoT breadth
- hardware-zwave-deep — Z-Wave deep: S0/S2, фреймы и атаки
- hardware-zigbee-deep — Zigbee deep: стек, ключи, OTA и атаки
- hardware-thread-matter — Thread / Matter: commissioning, ключи и атаки
- hardware-6lowpan — 6LoWPAN / 802.15.4: сетевой стек и атаки
- hardware-wirelesshart — WirelessHART / ISA100: промышленное беспроводное
- hardware-enocean — EnOcean / энергонезависимые датчики
- hardware-mbus — M-Bus / wM-Bus: счётчики и перехват
- hardware-knx-dali — KNX / DALI / LonWorks: здания и освещение
- hardware-bacnet — BACnet: здания, атаки и запись точек
- hardware-hart-ip — HART-IP: полевые приборы и инъекции

## Automotive & mobility deep
- hardware-flexray — FlexRay: шина, фреймы и анализ
- hardware-lin-bus — LIN-шина: автомобильный суб-протокол и атаки
- hardware-automotive-ethernet — Automotive Ethernet (100BASE-T1/1000BASE-T1)
- hardware-doip — DoIP (ISO 13400): диагностика по Ethernet
- hardware-iso-tp — ISO-TP / транспорт CAN: сегментация и фаззинг
- hardware-keyless-relay — Keyless entry / RKE/PKE: relay, RollJam, amplification
- hardware-tpms — TPMS: датчики давления, спуфинг и слежка
- hardware-telematics-tcu — Телематика / TCU: облако, eCall и захват
- hardware-infotainment — Инфоtainment / head-unit: Android Auto, CarPlay, атаки
- hardware-autosar — AUTOSAR: стек, Secure Onboard Communication и атаки
- hardware-ev-charging — EV-зарядка / OCPP: протокол, захват и billing
- hardware-ecu-flashing — Прошивка ECU: flashing, тюнинг и подмена
- hardware-immobilizer — Иммобилайзеры: обход и клонирование ключей

## ICS / SCADA fieldbus & protocols breadth
- hardware-ethercat — EtherCAT: промышленный Ethernet и атаки
- hardware-powerlink-sercos — POWERLINK / SERCOS: детерминированные сети
- hardware-opc-ua — OPC UA: безопасность, сертификаты и обход
- hardware-opc-da — OPC Classic/DA: DCOM, legacy-поверхность
- hardware-iec-61850 — IEC 61850: подстанции, GOOSE, MMS и атаки
- hardware-iec-104 — IEC 60870-5-104: телемеханика энергетики
- hardware-dnp3-sav5 — DNP3 Secure Authentication (SAv5) и его обход
- hardware-cip-enip — CIP / EtherNet/IP deep: объекты и запись
- hardware-plc-vendors — ПЛК вендоров: Siemens S7, Allen-Bradley, Schneider, Mitsubishi
- hardware-safety-plc — Safety-PLC / Triconex / SIS: атаки на системы безопасности
- hardware-rtu-remote — RTU / удалённые терминалы и телеметрия
- hardware-scada-hmi — SCADA HMI / historian: захват и подмена данных
- hardware-smart-grid — Smart grid / AMI / DLMS-COSEM: счётчики и инфраструктура
- hardware-powerline — Powerline (HomePlug/G3/PRIME): связь по электросети
- hardware-industrial-robot — Промышленные роботы / коботы: ROS, UR, KUKA, ABB

## MCU families & architectures
- hardware-arm-cortex-m — ARM Cortex-M: реверс, отладка и защита
- hardware-arm-cortex-a — ARM Cortex-A: TrustZone, MMU и эксплойты
- hardware-riscv — RISC-V: отладка, реверс и безопасность
- hardware-mips-embedded — MIPS-embedded: роутеры, реверс и эксплойты
- hardware-xtensa-esp — Xtensa / ESP32 / ESP8266: реверс и захват
- hardware-avr-pic — AVR / PIC / 8051: микроконтроллеры и их реверс
- hardware-stm32-nrf — STM32 / nRF / Nordic: отладка, DFU и secure boot
- hardware-ti-nxp — TI / NXP (SWIM/BDM) / Renesas: семейства и отладка
- hardware-embedded-os — FreeRTOS / Zephyr / VxWorks / QNX / ThreadX: реверс
- hardware-bare-metal — Bare-metal прошивки: реверс и анализ без ОС
- hardware-embedded-linux-deep — Embedded Linux deep: kernel, modules, rootfs
- hardware-rpi-arduino — Raspberry Pi / Arduino / Pico: платформы и атаки

## Silicon & physical attacks (beyond current)
- hardware-decapping — Декапсуляция чипов: кислоты, плазма и подготовка
- hardware-microprobing — Микропробирование: чтение внутренних сигналов
- hardware-fib-edit — FIB / circuit-edit: изменение цепей и обход защит
- hardware-emfi — Electromagnetic fault injection (EMFI) и импульсы
- hardware-body-bias — Body biasing injection (BBI) и другие инъекции
- hardware-clock-glitch — Clock glitching deep: параметры и стабильность
- hardware-voltage-glitch-deep — Voltage glitching deep: ChipWhisperer-сценарии
- hardware-optical-fault-deep — Оптические атаки deep: лазер, маскирование
- hardware-temperature-attacks — Термические атаки: нагрев, охлаждение, remanence
- hardware-cold-boot — Cold boot / DRAM remanence: извлечение ключей
- hardware-memory-bus-sniff — Перехват шины памяти: SDRAM-сниффинг
- hardware-xray-pcb — X-ray / CT / микроскопия плат и чипов
- hardware-pcb-netlist — Извлечение нетлиста и реверс многослойных плат
- hardware-tamper-response — Anti-tamper: меш, детекторы, potting и обход
- hardware-counterfeit-chips — Контрафактные чипы и supply-chain
- hardware-hardware-implant — Аппаратные импланты: сборка и сокрытие

## Side-channel depth
- hardware-template-attack — Template attacks / profiled side-channel
- hardware-tvla — TVLA / leakage assessment: методология оценки
- hardware-dema-sema — DEMA / SEMA: электромагнитный анализ
- hardware-cache-timing-hw — Cache-timing и микроархитектурные утечки в железе
- hardware-sca-align — Выравнивание трасс, preprocessing и борьба с шумом
- hardware-sca-countermeasures — Контрмеры side-channel и их обход
- hardware-fault-sca-combined — Комбинация fault + side-channel в одной атаке

## Secure elements & TEE depth
- hardware-tee-optree — OP-TEE / Trusted Firmware: сборка, отладка и эксплойты
- hardware-secure-world-exploit — Эксплуатация secure world и переход границ
- hardware-atecc-se050 — ATECC / SE050 / microchip secure elements
- hardware-puf — Physical Unclonable Functions (PUF) и их атаки
- hardware-hsm — HSM (PKCS#11 / Luna / nCipher): доступ и злоупотребление
- hardware-secure-boot-bypass-deep — Обход secure boot deep: подпись, fuse, ROM

## USB, PCIe & high-speed buses
- hardware-usb4-thunderbolt — USB4 / Thunderbolt: PCIe-tunneling и DMA
- hardware-pcie-dma — PCIe / DMA-атаки, IOMMU-обход и PCILeech
- hardware-pcie-fuzzing — Фаззинг PCIe/устройств и драйверов
- hardware-i3c-spmi — I3C / SPMI / SMBus: новые управляющие шины
- hardware-ps2-serial-deep — PS/2 / legacy-шины и их поверхности
- hardware-sdio-sd — SDIO / SD-карты: протокол, атаки и клонирование

## Hardware wallets & financial hardware
- hardware-wallet-ledger — Ledger / Trezor: архитектура и seed-извлечение
- hardware-wallet-fault — Fault/side-channel атаки на аппаратные кошельки
- hardware-wallet-secure-element — Secure element в кошельках: границы и обход
- hardware-pos-atm — POS-терминалы / банкоматы: аппаратные атаки
- hardware-payment-nfc — Бесконтактные платежи: relay, MITM и ограничения

## Mobile & consumer hardware
- hardware-iphone-hardware — iPhone: checkm8, DFU, Secure Enclave, аппаратные атаки
- hardware-android-hardware — Android: EDL (Qualcomm 9008), MTK, Odin/Samsung
- hardware-baseband-mobile — Мобильный baseband: реверс и уязвимости
- hardware-icloud-bypass — iCloud / FRP-обход и аппаратные методы
- hardware-consoles — Игровые консоли: Switch (Fusée Gelée/RCM), PS4/PS5, Xbox
- hardware-modchips — Modchips и аппаратные модификации консолей
- hardware-smarttv-cameras — Smart TV / IP-камеры / DVR: аппаратный доступ
- hardware-wearables — Носимые устройства: разбор, прошивка и данные

## Physical security & access control
- hardware-osdp — OSDP / Wiegand: доступ-контроль, перехват и спуфинг
- hardware-access-controllers — Контроллеры доступа и их обход
- hardware-electronic-locks — Электронные замки, отели и их обход
- hardware-alarm-systems — Сигнализации / датчики: обход и глушение
- hardware-cctv-analog — CCTV / аналоговое видео: перехват и подмена
- hardware-garage-gates — Ворота / шлагбаумы: sub-GHz и rolling codes
- hardware-badge-clone-deep — Клонирование бейджей deep: низко- и высокочастотные

## Boot, firmware & tooling breadth
- hardware-coreboot-tianocore — coreboot / TianoCore / GRUB: загрузка и атаки
- hardware-ota-update — OTA-обновления: подпись, downgrade и подмена
- hardware-firmware-automation — FirmAE / EMBA / Firmware Analysis Toolkit
- hardware-symbolic-firmware — Symbolic execution прошивок (angr) и её границы
- hardware-router-firmware — Прошивки роутеров/NAS/OpenWrt: реверс и CVEs
- hardware-jtagulator-greatfet — JTAGulator / GreatFET / Bus Pirate: автопоиск
- hardware-chipwhisperer — ChipWhisperer: стенд, скрипты и воспроизводимость
- hardware-hackrf-proxmark — HackRF / Proxmark3 / Flipper Zero: рабочие процессы
- hardware-vna-spectrum — VNA / спектроанализатор / генератор в исследованиях
- hardware-swo-rtt — SWO / RTT / semihosting: трассировка без halt
- hardware-openocd-gdb — OpenOCD / GDB-stub / vendor-отладка

## Emerging & advanced frontier
- hardware-chiplets-cxl — Чиплеты / CXL / die-to-die: поверхности и атаки
- hardware-riscv-security — RISC-V security extensions: PMP, debug и атаки
- hardware-pq-hardware — Пост-квантовая криптография в железе
- hardware-neuromorphic — Нейроморфные и AI-ускорители: реверс и атаки
- hardware-quantum-hardware — Квантовое железо: криоэлектроника и контроль
- hardware-embedded-ai — Embedded AI / TinyML: модели, кража и adversarial
- hardware-thermal-camera — Тепловидение в hardware-исследованиях
- hardware-mems-sensors — MEMS-датчики: акустические и инерциальные атаки
- hardware-acoustic-cryptanalysis — Акустический криптоанализ и side-channel
- hardware-supply-chain-secure — Безопасность supply chain железа end-to-end
- hardware-hardware-ctf — Hardware-CTF: типовые стенды, задачи и подходы
- hardware-lab-setup — Организация лаборатории: питание, ESD, инструменты, безопасность
