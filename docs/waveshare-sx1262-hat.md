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
| payload | 48 bytes |

## Planned Rust backend

The current implementation plan is an RX-only backend based on:

- `lora-phy` 3.0.1 for the SX1262 state machine and LoRa PHY
- `rppal` for Raspberry Pi SPI/GPIO access across Pi generations
- Tokio adapters for BUSY and DIO1 edge waits
- manual chip select on BCM21 for one complete SPI transaction
- a board-specific RF-switch interface that preserves the valid RX state

The backend will keep these dependencies outside `vesta-protocol`. It will
yield a received byte slice plus RSSI/SNR metadata, reject header/CRC errors,
then invoke the existing codec and output layer.

There is one known prerequisite before claiming this path is reliable:
upstream `lora-phy` 3.0.1 handles `RxDone` even when a CRC-error IRQ is also set.
We need a small audited patch that rejects header/CRC error flags before reading
the payload. Until that is implemented and tested, the repository deliberately
does not expose a misleading `listen` command.

Relevant implementation references:

- [`lora-phy` 3.0.1 SX126x driver](https://github.com/lora-rs/lora-rs/blob/lora-phy-v3.0.1/lora-phy/src/sx126x/mod.rs)
- [Semtech SX1261/2 data sheet](https://files.waveshare.com/wiki/SX1262-XXXM-LoRaWAN-GNSS-HAT/DS_SX1261-2_V1.2.pdf)
