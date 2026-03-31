# Chameleon (genome)

Полиморфный протокол туннелирования трафика через UDP. Каждая сессия имеет уникальный wire format, детерминистически выведенный из общего секрета (PSK). Наблюдатель без PSK видит только случайные байты — никаких magic bytes, фиксированных заголовков или узнаваемых handshake.

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

Обе стороны знают PSK -> знают геном -> могут общаться. Третья сторона видит шум с энтропией ~7.9 бит/байт.

## Архитектура

| Слой | Пакет | Назначение |
|------|-------|------------|
| Crypto | `crypto/` | AEAD (ChaCha20-Poly1305 / AES-256-GCM / XChaCha20), HKDF ключи |
| Morph | `morph/` | Геном сессии, полиморфный framing (encode/decode) |
| Mux | `mux/` | Мультиплексор потоков с надежной доставкой (SACK, fast retransmit, NewReno, flow control) |
| Transport | `transport/` | UDP-туннель = morph framing + AEAD + anti-replay |
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

## Быстрый старт (ручная настройка)

### Генерация PSK

```bash
PSK=$(openssl rand -hex 32)
```

### Сервер

```bash
go run ./cmd/server -listen :9000 -psk $PSK
```

### Клиент

```bash
go run ./cmd/client -server SERVER_IP:9000 -socks 127.0.0.1:1080 -psk $PSK
```

### Использование

```bash
# Любое приложение через SOCKS5
curl --socks5 127.0.0.1:1080 https://example.com

# Браузер: настроить SOCKS5-прокси на 127.0.0.1:1080
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
| `-socks` | `127.0.0.1:1080` | Адрес SOCKS5-прокси |
| `-cipher` | `chacha20` | `chacha20` или `aes256gcm` |
| `-log` | `info` | `debug`, `info`, `warn`, `error` |
| `-config` | | Путь к JSON-конфигу |

### Сервер

| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `-psk` | | PSK в hex |
| `-listen` | `:9000` | UDP listen адрес |
| `-cipher` | `chacha20` | `chacha20` или `aes256gcm` |
| `-log` | `info` | `debug`, `info`, `warn`, `error` |
| `-config` | | Путь к JSON-конфигу |

### JSON-конфиг

```json
{
  "psk": "a1b2c3d4...",
  "listen_addr": ":9000",
  "peer_addr": "1.2.3.4:9000",
  "socks_addr": "127.0.0.1:1080",
  "cipher_suite": "chacha20",
  "log_level": "info",
  "idle_timeout_sec": 300
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

### Известные ограничения

- Высокоэнтропийный трафик может быть заблокирован по признаку «слишком случайный» (парадокс шума)
- PSK обменивается out-of-band
- Нет forward secrecy без ECDH handshake (запланировано)

## Зависимости

- `golang.org/x/crypto` — ChaCha20-Poly1305
- `golang.org/x/net` — SOCKS5 клиент (только в тестах)

Все остальное — стандартная библиотека Go.
