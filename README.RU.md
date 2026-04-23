# Chameleon (genome)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19493628.svg)](https://doi.org/10.5281/zenodo.19493628)

Полиморфный протокол туннелирования трафика через UDP. Каждая сессия имеет уникальный wire format, детерминистически выведенный из общего секрета (PSK). Наблюдатель без PSK видит только случайные байты — никаких magic bytes, фиксированных заголовков или узнаваемых handshake.

[README in English](README.md)

## Принцип работы

```
Браузер / curl / любое приложение
        |  TCP
        v
  SOCKS5 (127.0.0.1:1080)        <-- клиент, принимает SOCKS5 CONNECT
        |
        v
  Хамелеон-клиент                 <-- мультиплексор + шифрование
        ║
   === UDP (полиморфный шум) ===  <-- снаружи виден только рандом
        ║
        v
  Хамелеон-сервер                 <-- расшифровка + демультиплексор
        |  TCP
        v
  Целевой хост (интернет)
```

Из PSK через HKDF выводится **геном сессии** — полное описание wire format:
- Псевдослучайный magic byte (фильтр «свой/чужой»)
- Порядок полей в заголовке (Fisher-Yates shuffle)
- 0-3 decoy-поля случайного размера
- Размер nonce: 12 или 24 байт
- Кодирование длины: uint16 BE / LE / varint / XOR-masked
- Диапазон padding'а
- Диапазон размеров «вагонов» (для stream-режима, см. ниже)

Обе стороны знают PSK -> знают геном -> могут общаться. Третья сторона видит шум с энтропией ~7.9 бит/байт.

## Stream-режим («поток») — постоянный cover-трафик

Опциональный режим, скрывающий **когда** пользователь реально что-то делает. С момента подключения по туннелю идёт постоянный поток «вагонов» фиксированной формы вне зависимости от реального трафика. Каждый вагон несёт либо реальные mux-данные (с префиксом длины), либо случайный наполнитель. Снаружи виден непрерывный поток шифртекста с предсказуемым рейтом — отличить активность от простоя невозможно.

- **Размер вагона** выбирается на каждый пакет из **диапазона, выводимого из генома** `[WagonMin, WagonMax]`. Снаружи размеры выглядят случайно; только знающий PSK партнёр знает рамки.
- **Envelope пропускной способности** задаётся в конфиге: `stream_min_bytes_per_sec` и `stream_max_bytes_per_sec`. Памп дрейфует целевой рейт внутри этого окна случайным блужданием с периодом 1 сек — «река не полноводная».
- **Частичное замещение**: когда реальные данные помещаются в вагон, они кладутся в начало, остаток — filler (`[uint16 RealLen][Real][Filler]`).
- **Полное замещение + burst**: когда очередь переполняется, памп входит в burst-режим и сливает до `4 × max_bps`, отправляя данные «как есть» пока очередь не опустеет.
- **Приёмник** снимает длину-префикс ниже mux-слоя — chaff невидим для приложения.

Включается флагом `-stream` на обеих сторонах. Envelope-настройки локальные. Совместимость: сессии без `-stream` работают ровно как раньше.

## Архитектура

| Слой | Пакет | Назначение |
|------|-------|------------|
| Crypto | `crypto/` | AEAD (ChaCha20-Poly1305 / AES-256-GCM / XChaCha20), HKDF ключи |
| Morph | `morph/` | Геном сессии, полиморфный framing (encode/decode) |
| Mux | `mux/` | Мультиплексор потоков с надежной доставкой (SACK, fast retransmit, NewReno, flow control) |
| Transport | `transport/` | UDP-туннель = morph framing + AEAD + anti-replay, stream pump |
| SOCKS5 | `socks5/` | SOCKS5 CONNECT сервер (RFC 1928) |
| Proxy | `proxy/` | Клиент (SOCKS5 -> mux) и сервер (mux -> dial TCP) |

## Установка сервера (одна команда)

```bash
curl -sSL https://raw.githubusercontent.com/william-aqn/genome/main/install-server.sh | sudo bash
```

Скрипт:
- Скачивает бинарник (или собирает из исходников)
- Генерирует PSK
- Открывает UDP-порт в файрволе (ufw/firewalld/iptables)
- Создает systemd-сервис
- Показывает команду для подключения клиента

Повторный запуск обновляет только бинарник, сохраняя PSK, конфиг и порт.

## Производительность

Замеры на реальном сервере (VDS, Россия -> Нидерланды):

| Метрика | Значение |
|---------|----------|
| Пиковая скорость | **30 Мбит/с** (3.75 MB/s) |
| Speedtest.net (Ookla) | **2.16 / 1.17 Мбит/с** |
| Загрузка 6.8 MB файла | **2 секунды** (стабильно, 5/5 попыток) |
| Параллельные стримы | 67 одновременных запросов без зависаний |
| Деградация | **нет** — скорость не падает между загрузками |
| Шифрование | ChaCha20-Poly1305 |
| Overhead | ~100-150 байт/пакет (morph header + AEAD + padding) |

## Клиент

### Интерактивный режим (без параметров)

```
> chameleon-client.exe

Chameleon Client — Interactive Setup

  Server IP: YOUR_SERVER_IP
  Server port [9000]: 10322
  PSK (hex): 3e02d433...
  SOCKS5 port [random=38741]:
  SOCKS5 username [random=auto]:
  SOCKS5 password [random=auto]:

===========================================
  SOCKS5 proxy:  127.0.0.1:38741
  Username:      k7m2x9ab
  Password:      p3nq8fw2v5jt
  Server:        YOUR_SERVER_IP:10322
===========================================
```

Конфиг сохраняется в `client.json` рядом с exe. При следующем запуске подхватывается автоматически — просто двойной клик.

### С флагами

```bash
./chameleon-client -server SERVER_IP:9000 -psk $PSK -socks-user myuser -socks-pass mypass
```

### Консольный дашборд

При запуске клиент показывает real-time дашборд с трафиком, активными соединениями и логами. Для отладки без UI:

```bash
./chameleon-client -no-ui -log debug
```

### Использование

```bash
# curl через туннель
curl --proxy socks5://user:pass@127.0.0.1:1080 https://example.com

# Браузер: настроить SOCKS5-прокси на 127.0.0.1:1080 с логином/паролем
```

## Сервер (ручная настройка)

```bash
PSK=$(openssl rand -hex 32)
./chameleon-server -listen :9000 -psk $PSK
```

## Сборка

```bash
# Один бинарник
go build -o chameleon-client ./cmd/client
go build -o chameleon-server ./cmd/server

# Кросс-компиляция (linux/windows, amd64/arm64)
bash build.sh
```

## Флаги CLI

### Клиент

| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `-psk` | | PSK в hex |
| `-server` | | Адрес сервера (host:port) |
| `-socks` | случайный порт | Адрес SOCKS5-прокси |
| `-socks-user` | случайный | SOCKS5 логин (RFC 1929) |
| `-socks-pass` | случайный | SOCKS5 пароль |
| `-cipher` | `chacha20` | `chacha20` или `aes256gcm` |
| `-log` | `info` | `debug`, `info`, `warn`, `error` |
| `-no-ui` | `false` | Отключить дашборд, чистые логи |
| `-config` | `client.json` | Путь к JSON-конфигу (авто-поиск рядом с exe) |
| `-stream` | `false` | Включить постоянный cover-трафик |
| `-stream-min-bps` | `500000` (при `-stream`) | Нижняя граница envelope, байт/сек |
| `-stream-max-bps` | `3000000` (при `-stream`) | Верхняя граница envelope, байт/сек |

### Сервер

| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `-psk` | | PSK в hex |
| `-listen` | `:9000` | UDP listen адрес |
| `-cipher` | `chacha20` | `chacha20` или `aes256gcm` |
| `-log` | `info` | `debug`, `info`, `warn`, `error` |
| `-config` | | Путь к JSON-конфигу |
| `-stream` | `false` | Включить постоянный cover-трафик |
| `-stream-min-bps` | `500000` (при `-stream`) | Нижняя граница envelope, байт/сек |
| `-stream-max-bps` | `3000000` (при `-stream`) | Верхняя граница envelope, байт/сек |

### JSON-конфиг

```json
{
  "psk": "a1b2c3d4...",
  "listen_addr": ":9000",
  "peer_addr": "1.2.3.4:9000",
  "socks_addr": "127.0.0.1:1080",
  "socks_user": "myuser",
  "socks_pass": "mypass",
  "cipher_suite": "chacha20",
  "log_level": "info",
  "idle_timeout_sec": 300,

  "stream_mode": true,
  "stream_min_bytes_per_sec": 500000,
  "stream_max_bytes_per_sec": 3000000
}
```

## Тесты

```bash
go test ./... -v          # все тесты
bash test.sh              # vet + unit + integration + race detector
bash e2e-test.sh          # полный тест: билд, клиент+сервер, curl через туннель
```

Покрытие:
- **Детерминизм**: одинаковый seed -> идентичный геном и PRNG
- **Round-trip**: encode -> decode для всех слоев (frame, command, AEAD)
- **Энтропия**: wire output >= 7.9 бит/байт (тест Шеннона)
- **Replay protection**: anti-replay sliding window
- **Mux**: буферы отправки/приема, SACK, RTT estimator, NewReno, flow control
- **SOCKS5**: IPv4, domain, unsupported command rejection
- **End-to-end**: HTTP через SOCKS5 -> tunnel -> HTTP-сервер
- **Параллельные потоки**: 10 одновременных запросов через туннель

## Диагностика

```bash
# Проверить связь с сервером
go run ./cmd/probe SERVER_IP:PORT PSK_HEX
```

Probe отправляет один OPEN-пакет и показывает ответ сервера или причину дропа (decode/replay/aead).

## Структура проекта

```
genome/
├── cmd/
│   ├── client/main.go          # CLI клиента
│   ├── server/main.go          # CLI сервера
│   └── probe/main.go           # Диагностика туннеля
├── config/config.go            # Конфигурация
├── crypto/
│   ├── aead.go                 # AEAD ciphers
│   └── keys.go                 # HKDF key derivation
├── internal/
│   ├── logger/logger.go        # slog обертка
│   └── randutil/deterministic.go # Детерминистический PRNG
├── morph/
│   ├── genome.go               # Derive(seed) -> Genome
│   ├── frame.go                # Encode/Decode wire packets
│   ├── lengthcodec.go          # 4 варианта кодирования длины
│   └── padding.go              # Рандомный padding
├── mux/
│   ├── command.go              # OPEN/DATA/CLOSE/ACK
│   ├── stream.go               # io.ReadWriteCloser поток
│   ├── session.go              # Менеджер потоков
│   ├── reliability.go          # Retransmit, SACK, RTT
│   ├── congestion.go           # NewReno
│   └── flowcontrol.go          # Per-stream flow control
├── proxy/
│   ├── client.go               # SOCKS5 -> mux
│   └── server.go               # mux -> TCP dial
├── socks5/server.go            # SOCKS5 CONNECT
├── transport/
│   ├── tunnel.go               # UDP + morph + AEAD
│   ├── stream_pump.go          # Постоянный cover-трафик («вагоны»)
│   └── shaper.go               # Timing jitter
├── build.sh                    # Кросс-компиляция
├── test.sh                     # Полный тест-сьют
├── e2e-test.sh                 # Live-тест через туннель
├── release.sh                  # Публикация GitHub-релиза
└── install-server.sh           # Установка сервера в одну строку
```

## Надежность доставки (TCP-over-UDP)

Мультиплексор обеспечивает:
- Per-stream sequence numbers
- Selective ACK (SACK)
- Fast retransmit (3 duplicate ACKs)
- RTT estimation (Jacobson/Karels EWMA)
- Congestion control (NewReno: slow start, congestion avoidance, fast recovery)
- Per-stream flow control (receive window)
- Keepalive / idle timeout

## Модель угроз

- **Пассивный наблюдатель с DPI**: не может построить сигнатуру — каждая сессия структурно уникальна
- **Replay attack**: anti-replay sliding window (256 эпох), случайный начальный epoch
- **Tampered packets**: AEAD аутентификация, epoch в additional data
- **Active probing**: сервер не отвечает без валидного первого пакета (PSK-only)
- **Анализ по времени/активности** (с `-stream`): постоянный поток вагонов скрывает моменты реальной отправки. Burst-режим частично ломает это скрытие при тяжёлых загрузках — сузить envelope если нужна более жёсткая маскировка ценой пропускной способности.

### Известные ограничения

- Высокоэнтропийный трафик может быть заблокирован по признаку «слишком случайный» (парадокс шума)
- PSK обменивается out-of-band
- Нет forward secrecy без ECDH handshake (запланировано)

## Зависимости

- `golang.org/x/crypto` — ChaCha20-Poly1305
- `golang.org/x/net` — SOCKS5 клиент (только в тестах)

Все остальное — стандартная библиотека Go.
