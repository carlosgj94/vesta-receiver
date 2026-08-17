# Vesta telemetry wire format v1

Version 1 is exactly 48 bytes. Every multi-byte integer is big-endian. Its
equivalent Python `struct` format is:

```text
>2sBBQIhIIIIIHH6B
```

| Offset | Size | Type | Field | Unit / meaning |
| ---: | ---: | --- | --- | --- |
| 0 | 2 | bytes | magic | ASCII `VS` |
| 2 | 1 | `u8` | version | `1` |
| 3 | 1 | `u8` | BME68x status | bit field below |
| 4 | 8 | `u64` | node ID | stable node identity |
| 12 | 4 | `u32` | sequence | wrapping, per boot in current firmware |
| 16 | 2 | `i16` | temperature | centi-degrees Celsius |
| 18 | 4 | `u32` | pressure | pascals |
| 22 | 4 | `u32` | relative humidity | milli-percent RH |
| 26 | 4 | `u32` | gas resistance | ohms |
| 30 | 4 | `u32` | raw temperature | ADC code |
| 34 | 4 | `u32` | raw pressure | ADC code |
| 38 | 2 | `u16` | raw humidity | ADC code |
| 40 | 2 | `u16` | raw gas resistance | ADC code |
| 42 | 1 | `u8` | gas range | sensor range code |
| 43 | 1 | `u8` | gas index | heater/profile slot |
| 44 | 1 | `u8` | measurement index | sensor field index |
| 45 | 1 | `u8` | heater resistance | raw register value |
| 46 | 1 | `u8` | heater current | raw register value |
| 47 | 1 | `u8` | gas wait | raw register value |

## Status bits

| Mask | Meaning |
| ---: | --- |
| `0x80` | new sensor data |
| `0x20` | gas-resistance result is valid |
| `0x10` | gas heater was stable |

The codec retains all other bits so a newer transmitter cannot silently lose
information when decoded by this version.

## Interoperability fixture

```text
565301b001020304050607080a0b0c0dfb2e00018bcd0000b26e000f12060007eed00005902075300200080203040506
```

Important decoded values include:

- node ID `0102030405060708`
- sequence `168496141` (`0x0a0b0c0d`)
- temperature `-1234` centi-degrees Celsius
- pressure `101325` Pa
- humidity `45678` milli-percent RH
- gas resistance `987654` ohm
- raw temperature and pressure ADC codes `519888` and `364576`

`vesta-protocol` verifies that decoding and re-encoding this fixture produces
the identical 48 bytes.

## Validation boundary

The wire decoder checks exact length, magic, and version. It deliberately does
not reject unusual sensor values: raw channels and Bosch compensation outputs
must survive transport unchanged for later analysis.

The SX1262 backend must reject radio header or CRC error IRQs before passing a
payload here. Magic, version, and length are framing checks, not a replacement
for radio CRC, authentication, or encryption.
