# Gap analysis (pass B) — `content/stego`

Inventory: **115 md lessons** (see `grep -h '^title:' content/stego/*.md`).
Verdict: **STRONG** — images (PNG/JPEG/DCT/F5/OutGuess/palette/GIF/BMP/WebP/TIFF/HEIF/RAW), audio (WAV/MP3/spectrogram/echo/DWT), text (whitespace/zero-width/emoji/linguistic), documents (PDF/DOCX), archives (ZIP/RAR/7z/ISO), network (HTTP/ICMP/TCP/VoIP/timing/DNS), steganalysis (chi-square/RS/SPA/ML), theory (capacity/QIM/STC/SSIS), exotic (DNA/blockchain/neural/physical).
This pass lists **~180 candidate NEW lessons** not covered by any existing title. Tagged by subcategory. `<proposed-id> — <short title>`.

## A. Fundamentals, theory & codes
- stego-reversible-data-hiding — Reversible / lossless data hiding (RDH) overview
- stego-difference-expansion — Difference expansion (DE) embedding
- stego-histogram-shifting — Histogram shifting / histogram modification
- stego-cover-selection — Cover selection & cover synthesis theory
- stego-security-models — Security models: Cachin's criterion, KL-divergence, detectability
- stego-game-theory — Steganographic game theory & adversarial detection bounds
- stego-taxonomy — Steganography vs watermarking vs fingerprinting vs covert channels
- stego-fragile-robust — Fragile vs semi-fragile vs robust embedding
- stego-perceptual-models — Perceptual models (HVS/HAS) for embedding
- stego-ecc — Error-correcting codes in stego (Reed–Solomon, BCH, turbo)
- stego-matrix-embedding — Matrix embedding beyond F5 (Hamming, BCH codes)
- stego-wet-paper-codes — Wet paper codes
- stego-minimum-distortion — Minimum-distortion embedding framework (cost functions)
- stego-key-management — Key management & password derivation in stego tools
- stego-capacity-security-tradeoff — Capacity vs security vs robustness tradeoff
- stego-legal-ethics — Legal, ethical & policy aspects of steganography
- stego-steganographic-file-system — Deniable / hidden filesystem theory (covered partially by stego-filesystem)

## B. Image steganography (formats & domains)
- stego-jpeg2000 — JPEG 2000 (JP2/J2K) wavelet stego
- stego-jpegxr — JPEG XR (HD Photo) stego
- stego-jpegxl — JPEG XL (JXL) stego
- stego-webp-lossless — WebP lossless (VP8L) embedding deep
- stego-avif-image — AVIF image stego deep
- stego-grayscale — Grayscale / monochrome image stego
- stego-cmyk — CMYK / print-color-space stego
- stego-multispectral — Multispectral & hyperspectral image stego
- stego-thermal-ir — Thermal / infrared image stego
- stego-stereo-anaglyph — Stereo / anaglyph / depth-map stego
- stego-panorama-360 — Panoramic / 360° image stego
- stego-raw-bayer — RAW Bayer-pattern sensor stego
- stego-dft-domain — DFT / log-polar domain embedding
- stego-dct-qim — QIM in DCT domain
- stego-svd — SVD-based image stego
- stego-fractal — Fractal-based image stego
- stego-chaos — Chaos-theory based embedding/encryption
- stego-ica-pca — ICA/PCA-based embedding
- stego-edge-adaptive-hugo — HUGO/WOW edge-adaptive deep (covered by stego-adaptive — extend)
- stego-robust-crop-resize — Robustness to crop/resize/recompression
- stego-print-scan — Print-scan resilient stego
- stego-invertible-nn — Invertible neural network stego (HiDDeN, UDH)
- stego-diffusion-cover — Diffusion-model generated covers
- stego-gan-steganalysis — GAN-based steganalysis

## C. Audio steganography
- stego-midi — MIDI steganography (note/pitch/velocity/timing)
- stego-flac-alac — FLAC / ALAC lossless audio stego
- stego-ogg-opus — Ogg Vorbis / Opus stego
- stego-aac — AAC audio stego
- stego-id3-tags — ID3v2 / APIC / chapter tag stego
- stego-audio-watermark — Audio watermarking (AudioSeal, robust schemes)
- stego-speech-lpc — LPC / formant / vocoder speech stego
- stego-audio-qim — QIM audio embedding
- stego-audio-nn — Neural audio stego
- stego-analog-media — Vinyl / cassette / tape analog stego
- stego-ultrasonic — Ultrasonic / acoustic covert channel

## D. Video & animation
- stego-av1 — AV1 video stego
- stego-vvc-h266 — VVC / H.266 video stego
- stego-h264-mv — H.264/H.265 motion-vector deep embedding
- stego-video-watermark — Video watermarking
- stego-gif-lzw — GIF LZW / dictionary stego
- stego-mjpeg — MJPEG / frame-sequence stego
- stego-subtitle-srt — Subtitle (SRT/ASS/VTT) stego
- stego-video-nn — Neural video stego

## E. Text & linguistic
- stego-json-whitespace — JSON whitespace / key-order stego
- stego-yaml — YAML stego
- stego-markdown — Markdown stego
- stego-csv-tsv — CSV/TSV stego
- stego-snow — SNOW whitespace stego tool
- stego-homoglyph — Homoglyph / IDN stego
- stego-unicode-tags — Unicode Tags block (U+E0000) stego
- stego-bidi-control — Bidirectional control-character stego
- stego-rtl-override — RTL override / mirroring stego
- stego-text-nn — Neural text stego
- stego-zerowidth-deep — Zero-width / variation-selector deep (covered by emoji — extend)

## F. Documents & office containers
- stego-odf — OpenDocument (ODT/ODS/ODP) stego
- stego-epub — EPUB ebook stego
- stego-chm — CHM help-file stego
- stego-xlsx-hidden — Spreadsheet hidden rows/sheets/defined-names stego
- stego-pptx — PowerPoint stego
- stego-pdf-incremental — PDF incremental-update stego
- stego-pdf-objectstream — PDF object-stream / xref-stream stego
- stego-office-customxml — OOXML custom-XML-parts stego
- stego-rtf — RTF stego
- stego-latex — LaTeX source stego
- stego-ps-eps — PostScript / EPS stego
- stego-word-fields — Word field-codes / tracked-changes stego
- stego-vba-macro — VBA macro stego
- stego-xps-oxps — XPS/OXPS document stego

## G. Archives, binaries & filesystems
- stego-zip-aes — ZIP AES / encrypted-archive stego
- stego-tar — TAR padding/header stego
- stego-cab-msi — CAB/MSI stego
- stego-udf — UDF filesystem stego
- stego-git-objects — Git object / packfile stego
- stego-docker-layers — Docker image layer stego
- stego-package-managers — npm/pip/apt package stego
- stego-registry — Windows Registry value stego
- stego-ntfs-timestamps — NTFS timestamp stego
- stego-firmware-rom — Firmware / ROM padding stego
- stego-pe-deep — PE resource/section/overlay deep
- stego-elf-notes — ELF section/note/overlay stego
- stego-macho — Mach-O stego
- stego-dotnet-il — .NET assembly / IL stego
- stego-java-class — Java class / JAR stego
- stego-wasm-module — WebAssembly module stego
- stego-memory-dump — Stego in memory dumps
- stego-swap-hibernation — Stego in swap / hibernation files

## H. Network & protocol covert channels
- stego-tls — TLS / HTTPS covert channel
- stego-ipv6-header — IPv6 header / extension-header covert channel
- stego-ipv4-options — IPv4 options / record-route covert channel
- stego-doh-dot — DNS-over-HTTPS / DNS-over-TLS covert channel
- stego-grpc-protobuf — gRPC / protobuf varint covert channel
- stego-websocket — WebSocket frame covert channel
- stego-ntp — NTP timestamp covert channel
- stego-ssh-channel — SSH covert channel
- stego-vpn-tunnel — VPN / tunneled payload stego
- stego-tor-i2p — Tor / I2P covert channels
- stego-dhcp — DHCP option covert channel
- stego-arp-mac — ARP / MAC-address covert channel
- stego-routing-proto — BGP / OSPF routing-protocol covert channel
- stego-sip-deep — SIP signaling covert channel
- stego-sms-pdu — SMS / PDU covert channel
- stego-quic-deep — QUIC packet-number/header covert channel

## I. RF, wireless, physical buses
- stego-sdr-iq — SDR / IQ-sample stego
- stego-satellite — Satellite-signal covert channel
- stego-usb-traffic — USB traffic covert channel
- stego-serial-uart — Serial / UART covert channel
- stego-can-bus — CAN bus covert channel
- stego-modbus-ics — Modbus / ICS protocol covert channel
- stego-powerline — Powerline-communication stego
- stego-bluetooth — Bluetooth / BLE covert channel
- stego-wifi-80211 — Wi-Fi 802.11 frame covert channel
- stego-lte-5g — LTE / 5G signaling covert channel
- stego-magnetic-media — Magnetic-media stego
- stego-uv-ink — UV / invisible-ink document stego
- stego-microdot — Paper microdot / microprint stego
- stego-gcode — 3D-print G-code stego
- stego-cad-step — CAD / STEP / STL stego (extend stego-3d-models)
- stego-gis-geojson — GIS / GeoJSON / KML stego
- stego-qr-micro — Micro QR / structured-append stego
- stego-datamatrix — DataMatrix / Aztec / PDF417 symbologies

## J. Modern & emerging
- stego-blockchain-l2 — Blockchain L2 / rollup / calldata stego
- stego-nft-metadata — NFT metadata stego
- stego-ipfs-deep — IPFS / content-addressed stego
- stego-model-weights — Stego in ML model weights
- stego-llm-token — LLM token / sampling covert channel
- stego-prompt-channel — Prompt-based covert channel
- stego-ai-watermark — AI content watermarking (SynthID etc.)
- stego-c2pa — C2PA / Content Credentials provenance stego
- stego-quantum — Quantum-state steganography
- stego-dna-protein — DNA / protein stego deep (extend stego-dna)
- stego-hologram-ar — Hologram / AR-marker stego
- stego-game-save — Game save-file stego
- stego-puzzle-board — Puzzle / chessboard / game stego
- stego-currency-security — Currency / security-printing features
- stego-iot-firmware — IoT firmware image stego

## K. Steganalysis
- stegoanalysis-ws — Weighted Stego (WS) analysis
- stegoanalysis-ensemble — Ensemble / FLD classifiers (SRM+EC)
- stegoanalysis-rich-models — DCTR / JRM / GFR rich models
- stegoanalysis-targeted-f5 — Targeted structural attack on F5
- stegoanalysis-quantitative — Quantitative steganalysis (payload-length estimation)
- stegoanalysis-cover-source-mismatch — Cover-source mismatch
- stegoanalysis-cnn — Deep CNN steganalysis (SRNet, Zhu-Net)
- stegoanalysis-universal — Universal / blind steganalysis
- stegoanalysis-timing — Timing-channel detection
- stegoanalysis-network — Network covert-channel detection
- stegoanalysis-hypothesis — Statistical hypothesis-testing framework
- stegoanalysis-color — Color-image specific detectors
- stegoanalysis-audio — Audio steganalysis (SAS)
- stegoanalysis-video — Video steganalysis
- stegoanalysis-steg-expose — StegExpose / Aletheia detection workflow

## L. Tools, workflow & CTF methodology
- stego-tool-cyberchef — CyberChef magic & recipes for stego
- stego-tool-stegoveritas — Stegoveritas workflow
- stego-tool-forensically — Forensically / Aperi'Solve web tools
- stego-tool-png-suite — pngcheck/pngcrush/optipng/zopfli
- stego-tool-jpeg-suite — jpegtran/jpegoptim manipulation
- stego-tool-openstego — OpenStego/Camouflage/wbStego
- stego-tool-deepsound — DeepSound / SilentEye audio
- stego-tool-binwalk-deep — binwalk deep / signature extraction
- stego-tool-foremost — foremost / scalpel recovery
- stego-tool-audacity — Audacity / Sonic Visualiser spectrogram workflow
- stego-tool-gimp — GIMP channel / bit-plane manipulation
- stego-tool-python — Python (PIL/numpy/scipy) stego scripting
- stego-tool-zsteg-deep — zsteg deep bit-order / module coverage
- stego-ctf-decision-tree — CTF stego decision tree
- stego-ctf-unknown-file — Unknown-file triage workflow
- stego-ctf-multi-layer — Multi-layer / chained stego puzzle solving
- stego-ctf-flag-hunt — Systematic flag hunting in containers
- stego-ctf-anti-tool — Challenges that break common tools
