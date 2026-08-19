# Waveshare SX1262 HAT bring-up

The intended receiver is Waveshare's SPI **SX1262 868/915M LoRaWAN HAT**. We
will use it as a raw LoRa P2P receiver, not as a LoRaWAN gateway.

## Before writing the hardware backend

With the Pi booted, record the exact platform:

```sh
tr -d '\0' < /proc/device-tree/model; echo
uname -m
. /etc/os-release; printf '%s\n' "$PRETTY_NAME"
```

Enable SPI in Raspberry Pi OS with `sudo raspi-config`, then verify that Linux
exposes SPI0:

```sh
ls -l /dev/spidev0.0
```

Seat or remove the HAT only while the Pi is powered off. The 868 MHz antenna
belongs on the HAT's LoRa IPEX connector; on the GNSS model, do not confuse it
with the GPS connector.

## HAT pin map

The official Waveshare schematic uses BCM GPIO numbering:

| Function | BCM GPIO | Physical pin |
| --- | ---: | ---: |
| SPI clock | 11 | 23 |
| SPI MOSI | 10 | 19 |
| SPI MISO | 9 | 21 |
| manual NSS / chip select | 21 | 40 |
| reset | 18 | 12 |
| busy | 20 | 38 |
| DIO1 interrupt | 16 | 36 |
| receive RF-switch control | 6 | 31 |

The two documented RF-switch states use complementary controls:

- RX: BCM6 high and SX1262 DIO2 low
- TX: BCM6 low and SX1262 DIO2 high

Both controls low is not a documented off state. The first RX-only backend must
hold BCM6 high while receiving and use a board-specific interface rather than a
generic disable-switch path that could drive it low. The HAT uses a 32 MHz
crystal, not a TCXO.

Official references:

- [Waveshare product page](https://www.waveshare.com/product/sx1262-lorawan-hat.htm)
- [Waveshare setup wiki](https://www.waveshare.com/wiki/SX1262_XXXM_LoRaWAN/GNSS_HAT)
- [Waveshare HAT schematic](https://files.waveshare.com/wiki/SX1262-XXXM-LoRaWAN-GNSS-HAT/SX1262_XXXM_LoRaWAN_HAT_sch.pdf)
- [Semtech SX1262 product page](https://www.semtech.com/products/wireless-rf/lora-connect/sx1262)

## Matching P2P settings

The Pi must match the transmitter exactly:

| Setting | Value |
| --- | --- |
| frequency | 868.100 MHz |
| spreading factor | SF7 |
| bandwidth | 125 kHz |
| coding rate | 4/5 |
| preamble | 8 symbols |
| header | explicit |
| PHY CRC | enabled |
| IQ | normal |
| private sync word | `0x1424` |
| payload | v1: 48 bytes; v2: variable, at most 255 bytes |

## Rust backend

`vesta-receiver listen` contains a small board-specific, RX-only SX1262 driver
built on `rppal`. It uses:

- SPI0 mode 0 at a conservative 500 kHz
- manual chip select on BCM21 around each complete SPI transaction
- bounded BUSY waits and DIO1 rising-edge polling
- explicit LDO regulator mode and the HAT's 32 MHz crystal
- continuous receive mode with only terminal receive IRQs on DIO1
- packet RSSI, SNR, and signal RSSI metadata in exact centi-units

The driver deliberately contains no transmit opcode or API. BCM6 is claimed as
an output-high pin before radio setup and is never driven low. On orderly exit,
the radio enters standby RC while NSS, reset, and BCM6 remain high.

The IRQ classifier rejects header errors first and CRC errors second, before it
will accept `RxDone`. This ordering matters because multiple SX1262 IRQ flags
can be set together. A corrupt payload is never read or passed to the Vesta
decoder. Every PHY-valid payload up to 255 bytes is archived; unsupported or
malformed application records are marked in storage without being mistaken
for successful telemetry.

The implementation is intentionally direct instead of using `lora-phy` 3.0.1:
that upstream version processes `RxDone` after merely logging simultaneous
header/CRC error flags, and its generic RF-switch disable path is not compatible
with this HAT's two documented switch states.

Run a bounded bring-up without requiring a transmitter:

```sh
taskset -c 0 cargo run -j1 -p vesta-receiver -- \
  listen --duration 5 --output jsonl
```

The settings line and final counters are written to standard error. Valid
frames are written to standard output, so JSONL can be piped directly to a
consumer.

## Hardware validation completed

Validated on 2026-08-18 with a Raspberry Pi 5, Raspberry Pi OS 64-bit, and the
Waveshare 868/915 MHz HAT with its 868 MHz antenna connected:

- SPI0 and all documented GPIOs were available to the unprivileged `spi` and
  `gpio` groups.
- Reset/BUSY and `GetStatus` produced a real SX1262 response.
- The driver read back LoRa packet type, private sync word `0x1424`, and zero
  device-error flags before entering RX.
- A five-second listen and a separate three-second canonical `cargo run`
  completed with exit status 0. No transmitter was active, so all counters
  correctly remained zero.
- With the STM32 PCB transmitting once per minute, the receiver accepted and
  decoded a valid 48-byte frame from node `4fe608a9ee2f303e` with no header,
  CRC, length, or protocol errors. The captured signal was -42.00 dBm RSSI and
  12.50 dB SNR.
- After SQLite persistence was added, the next live frame (sequence 25) was
  committed as row 1 before printing. A separate read-only connection reported
  `integrity_check=ok`, WAL journal mode, schema version 1, one row, and an
  exact 48-byte stored payload.
- BCM6, reset, and manual NSS remained output-high after exit; the Pi reported
  `throttled=0x0`.

During initial dependency compilation the Pi unexpectedly rebooted. That
happened before radio initialization, the prior boot had no persistent journal,
and the current boot reports neither a PMIC power reset nor throttling. The
negotiated maximum current is 3000 mA, below the Pi 5's recommended 5 A supply,
so treat power integrity as an open system-level risk. Single-core, single-job
builds completed reliably during bring-up.

Relevant implementation references:

- [`lora-phy` 3.0.1 SX126x driver](https://github.com/lora-rs/lora-rs/blob/lora-phy-v3.0.1/lora-phy/src/sx126x/mod.rs)
- [Semtech SX1261/2 data sheet](https://files.waveshare.com/wiki/SX1262-XXXM-LoRaWAN-GNSS-HAT/DS_SX1261-2_V1.2.pdf)
