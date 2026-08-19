# Vesta telemetry protocol v2

Status: the allocation-free codec and host receiver decoder/reassembler have
matching golden tests. Do not flash protocol-v2 firmware onto a deployed node
until this receiver version is installed and validated on the Raspberry Pi.

Version 1 remains exactly 48 bytes and byte-for-byte unchanged. Version 2 retains `VS`, uses version byte `2`, variable record lengths, and big-endian integers. It contains no RSSI/SNR, server timestamp, battery/SOC estimate, baseline, fire score, alert decision, or ML output.

The reference implementation is `crates/vesta-protocol/src/v2.rs`:
dependency-free, `#![no_std]`, no allocation, typed encoders/decoders for every
record, checked lengths/indices, and no panic path for malformed wire input.

## Common header: 48 bytes

| Offset | Width | Type | Field | Meaning |
| ---: | ---: | --- | --- | --- |
| 0 | 2 | bytes | magic | ASCII `VS` |
| 2 | 1 | `u8` | version | `2` |
| 3 | 1 | `u8` | frame type | `1=DeviceConfig`, `2=ProfileFragment`, `3=DeviceHealth` |
| 4 | 1 | `u8` | header length | `48` |
| 5 | 1 | `u8` | common flags | below |
| 6 | 1 | `u8` | fragment index | zero-based |
| 7 | 1 | `u8` | fragment count | nonzero; index must be smaller |
| 8 | 2 | `u16` | payload length | exact frame length is `48 + payload_length` |
| 10 | 8 | `u64` | node ID | existing stable hash of STM32 96-bit UID |
| 18 | 8 | `u64` | boot ID | fresh STM32 hardware-RNG nonce per boot |
| 26 | 4 | `u32` | scan sequence | scan number for profiles; effective/most-recent scan for config/health |
| 30 | 8 | `u64` | uptime | microcontroller uptime ms at scan start/snapshot creation |
| 38 | 8 | `u64` | config ID | nonzero FNV-1a-64 over canonical verified `DeviceConfig` payload; degraded zero sentinel rules below |
| 46 | 2 | `u16` | reset cause | normalized flags captured before RCC flags are cleared |

Common flags are `0x01=boot_id_valid`, `0x02=boot_id_from_hardware_rng`, `0x04=repeated_config`. A bounded RNG failure uses boot ID zero with both ID flags clear and reports the failure in health; it does not fabricate a nonce.

Config ID zero is reserved and is never a valid `DeviceConfig` hash. A
`ProfileFragment` may use zero only when it also reports collection flag bit 12
(`configuration_mismatch`) and a non-complete finish reason; its nonzero
profile ID/version still name the requested profile, while zero says the
actual sensor-register configuration could not be verified. `DeviceHealth`
may use config ID zero either for that explicit configuration-mismatch state,
or before any sensor configuration has been established. In the latter case
its profile ID and version are also zero, and `scan_sequence` counts degraded
health attempts rather than completed profile scans. Normal verified profile
and health records use a nonzero config ID.

Reset flags are `0x0001=radio_illegal_access`, `0x0002=option_byte_loader`, `0x0004=pin`, `0x0008=brownout`, `0x0010=software`, `0x0020=independent_watchdog`, `0x0040=window_watchdog`, `0x0080=low_power`. Health also retains the exact raw 32-bit STM32WLE5 RCC CSR snapshot.

For a valid boot nonce, `(node_id, boot_id, scan_sequence, config_id)` is the nominal logical scan identity. The receiver defensively keys reassembly by `(node_id, boot_id_valid, boot_id, scan_sequence, scan_start_uptime_ms, config_id)`; adding `(frame_type, fragment_index)` identifies a frame. All fragments from one scan repeat the same scan-start uptime, so out-of-order grouping is preserved. Uptime greatly reduces collision risk when RNG failure forces the zero nonce, but it cannot prove cross-boot identity: two failed-RNG boots can begin the same sequence at the same millisecond. Such scans remain explicitly boot-ambiguous and are never used for cross-scan temporal history.

## DeviceConfig payload

Length is `83 + 10 * expected_step_count`; a 10-step configuration is 183 payload bytes, 231 total.

Profile ID and version are nonzero. The common-header config ID is the
canonical payload hash and must also be nonzero; the vanishingly unlikely FNV
zero result is rejected rather than colliding with the degraded sentinel.

| Offset | Width | Type | Field | Meaning |
| ---: | ---: | --- | --- | --- |
| 0 | 1 | `u8` | schema | `1` |
| 1 | 1 | `u8` | config flags | `0x01=calibration_hash_valid`, `0x02=sensor_configuration_read_back` |
| 2 | 3 | `u8[3]` | firmware version | major, minor, patch |
| 5 | 1 | `u8` | build flags | `0x01=build_id_valid`, `0x02=dirty`, `0x04=debug_sleep` |
| 6 | 8 | `u64` | firmware build ID | first 64 bits of exact Git object ID; zero if invalid |
| 14 | 1 | `u8` | BME chip ID | expected `0x61` |
| 15 | 1 | `u8` | variant register | `0=GasLow`, `1=GasHigh`, `255=unknown` |
| 16 | 1 | `u8` | I2C address | normally `0x76`/`0x77` |
| 17 | 1 | `u8` | temperature oversampling | Bosch enum `0=off`, `1=x1`, `2=x2`, `3=x4`, `4=x8`, `5=x16` |
| 18 | 1 | `u8` | humidity oversampling | same enum |
| 19 | 1 | `u8` | pressure oversampling | same enum |
| 20 | 1 | `u8` | IIR filter | Bosch enum `0..7`: off, Size1, Size3, Size7, Size15, Size31, Size63, Size127 |
| 21 | 1 | `u8` | standby time | Bosch ODR enum `0..8`; `8=None` |
| 22 | 1 | `u8` | operating mode | `1=Forced`, `2=Parallel`, `3=Sequential` |
| 23 | 1 | `u8` | heater enabled | canonical boolean |
| 24 | 2 | `u16` | requested shared wait | ms; parallel only |
| 26 | 1 | `u8` | raw shared-wait register | read-back shared heater duration register |
| 27 | 4 | `u32` | quantized shared wait | µs represented by raw shared register |
| 31 | 4 | `u32` | TPHG duration | µs for current oversampling/configuration |
| 35 | 4 | `u32` | expected profile duration | µs; sum of all effective step durations |
| 39 | 2 | `u16` | profile ID | stable profile family |
| 41 | 2 | `u16` | profile version | increment for any profile change |
| 43 | 1 | `u8` | expected steps | `1..10` |
| 44 | 2 | `u16` | readback-valid bitmap | bit `n` means all raw IDAC_HEAT/RES_HEAT/GAS_WAIT bytes for descriptor `n` were successfully read and transmitted |
| 46 | 1 | `u8` | calibration hash algorithm | `0=none`, `1=FNV-1a-64` |
| 47 | 8 | `u64` | calibration fingerprint | hash of exact 42 register bytes captured in Bosch block/read order, never Rust layout/reconstructed coefficients |
| 55 | 4 | `u32` | scan interval | ms |
| 59 | 2 | `u16` | config repeat interval | scans; send at boot/change and periodically |
| 61 | 1 | `u8` | output routes | bitmask: `0x01=LoRa P2P`, `0x02=UART COBS+CRC32`, `0x04=RTT`; nonzero |
| 62 | 4 | `u32` | frequency | Hz |
| 66 | 1 | `i8` | TX power | dBm |
| 67 | 1 | `u8` | spreading factor | actual SF |
| 68 | 4 | `u32` | bandwidth | Hz |
| 72 | 1 | `u8` | coding-rate numerator | `4` |
| 73 | 1 | `u8` | coding-rate denominator | `5` currently |
| 74 | 2 | `u16` | preamble | symbols |
| 76 | 1 | `u8` | header mode | `0=explicit`, `1=implicit` |
| 77 | 1 | `u8` | PHY CRC | boolean |
| 78 | 1 | `u8` | IQ inverted | boolean |
| 79 | 2 | `u16` | sync word | `0x1424` currently |
| 81 | 1 | `u8` | maximum v2 frame | `231` |
| 82 | 1 | `u8` | steps/fragment | `3` |
| 83 | `10*N` | descriptors | ordered heater configuration, below |

Output routes are a bitmask rather than an exclusive mode because a laboratory build may send the same record over LoRa and RTT/UART simultaneously. Unknown bits and the all-zero value are rejected. The UART COBS/CRC32 and RTT length envelopes wrap the exact v2 record bytes and are transport framing, not bytes inside this record; the route bit records which envelope(s) are active. Radio fields remain the configured LoRa parameters, while the `0x01` route bit says whether that route is active.

Each descriptor is 10 bytes:

| Relative offset | Width | Type | Field |
| ---: | ---: | --- | --- |
| 0 | 2 | `u16` | target heater temperature, °C |
| 2 | 4 | `u32` | configured effective duration, µs |
| 6 | 1 | `u8` | Bosch parallel TPHG repetition multiplier; zero outside parallel mode |
| 7 | 1 | `u8` | raw `IDAC_HEATn` readback; read-only metadata, not a programmed-value comparison |
| 8 | 1 | `u8` | raw `RES_HEATn` readback |
| 9 | 1 | `u8` | raw `GAS_WAITn` readback |

For Bosch parallel mode, `GAS_WAITn` is a repetition multiplier, not milliseconds. With multiplier `r>0`, effective duration is `r * (quantized_shared_wait_us + tphg_duration_us)`. Bosch's special zero means one TPHG and no shared wait. Carrying requested wait, raw/quantized wait, TPHG time, repetition, effective time, and raw register bytes removes ambiguity.

The readback-valid bitmap is an acquisition-validity statement, not a claim
that IDAC matched an intended programmed value. Current firmware verifies
`RES_HEATn`, `GAS_WAITn`, shared/control registers, and the environmental
configuration; `IDAC_HEATn` is retained as read-only metadata.

## ProfileFragment payload

Metadata is 42 bytes plus zero to three 47-byte steps. Total frame length is `90 + 47*K`: 90, 137, 184, or 231 bytes.

| Offset | Width | Type | Field | Meaning |
| ---: | ---: | --- | --- | --- |
| 0 | 1 | `u8` | schema | `1` |
| 1 | 1 | `u8` | steps in fragment | `0..3` |
| 2 | 2 | `u16` | profile ID | repeated |
| 4 | 2 | `u16` | profile version | repeated |
| 6 | 1 | `u8` | expected steps | `1..10` |
| 7 | 1 | `u8` | observed unique steps | expected minus missing population count |
| 8 | 2 | `u16` | observed field count | includes duplicates; saturation reported |
| 10 | 2 | `u16` | missing bitmap | bit `n` means expected step `n` absent |
| 12 | 2 | `u16` | duplicate bitmap | bit `n` means duplicate(s) observed |
| 14 | 4 | `u32` | scan duration | µs |
| 18 | 4 | `u32` | collection flags | below |
| 22 | 1 | `u8` | finish reason | `0=complete`, `1=timeout`, `2=sensor_error`, `3=poll_budget`, `4=profile_rollover` |
| 23 | 2 | `u16` | duplicate count | all duplicate observations |
| 25 | 2 | `u16` | overwritten-field count | collector overwrite/drop audit |
| 27 | 2 | `u16` | out-of-order count | fields arriving behind expected order |
| 29 | 2 | `u16` | ambiguous index-jump count | index transitions not uniquely attributable |
| 31 | 2 | `u16` | invalid gas-index count | gas index outside configured range |
| 33 | 2 | `u16` | intermediate-field count | total discarded nonterminal fields: in-scan intermediate/dummy fields plus stale `NEW_DATA` fields explicitly drained before scan start |
| 35 | 2 | `u16` | profile-rollover count | detected complete-profile rollovers |
| 37 | 2 | `u16` | fields-after-rollover count | extra fields seen after selected profile completed |
| 39 | 2 | `u16` | poll count | bounded sensor field reads |
| 41 | 1 | `u8` | step-window start | exactly `fragment_index * 3` |
| 42 | `47*K` | steps | retained logical steps in ascending order |

Collection flags: bit 0 timeout, 1 I2C error, 2 duplicate, 3 overwritten field, 4 gas index out of range, 5 measurement-index discontinuity, 6 no-new-data, 7 invalid gas, 8 heater unstable, 9 polling budget exhausted, 10 observation overflow/drop, 11 exact sensor configuration restored and read back before the scan trigger, 12 configuration mismatch, 13 stale pre-scan fields discarded. Bit 11 is not a mid-scan change: the scan still uses the configuration named by the nonzero config ID, but the server resets that exact temporal series before accepting it as a new baseline. Bit 13 requires a nonzero intermediate-field count; that count includes the stale fields but may also include normal parallel-mode dummy/intermediate observations.

Before every scan, firmware verifies BME688 Sleep mode and reads/discards all
three field slots. Every discarded slot carrying `NEW_DATA` increments the
pre-scan stale count, is added saturating to `intermediate_field_count`, and
sets bit 13 when nonzero. The receiver retains this evidence and conservatively
excludes the affected scan from analysis; no wire widths or frame sizes change.

Fragment windows are fixed by logical heater step: `0..2`, `3..5`, `6..8`, and `9`. Fragment count is `ceil(expected/3)` even if a complete window is missing; an empty fragment is sent. Missing observations therefore never shift later steps between packets. The encoder rejects inconsistent presence maps, counts, bitmaps, or step indices.

### Profile step: 47 bytes

| Relative offset | Width | Type | Field | Unit/meaning |
| ---: | ---: | --- | --- | --- |
| 0 | 1 | `u8` | logical step index | configured step |
| 1 | 1 | `u8` | gas index | sensor-reported |
| 2 | 1 | `u8` | measurement index | sensor-reported |
| 3 | 1 | `u8` | combined status | Bosch-compatible flags; current firmware emits only `NEW_DATA`, `GAS_VALID`, and `HEAT_STAB` |
| 4 | 1 | `u8` | raw measurement status | unmodified BME688 `FIELDx[0]` byte |
| 5 | 1 | `u8` | raw gas status | unmodified variant-selected BME688 `FIELDx[14]` (Gas Low) or `FIELDx[16]` (Gas High) byte |
| 6 | 2 | `u16` | target heater temperature | °C |
| 8 | 4 | `u32` | configured effective duration | µs |
| 12 | 4 | `u32` | offset in scan | MCU field-read/poll observation offset in µs from the scan trigger anchor; this is an upper/read-time bound, not the sensor's exact conversion timestamp |
| 16 | 2 | `i16` | compensated temperature | centi-°C |
| 18 | 4 | `u32` | compensated pressure | Pa |
| 22 | 4 | `u32` | compensated humidity | milli-%RH |
| 26 | 4 | `u32` | compensated gas resistance | ohms |
| 30 | 4 | `u32` | raw temperature ADC | exact code |
| 34 | 4 | `u32` | raw pressure ADC | exact code |
| 38 | 2 | `u16` | raw humidity ADC | exact code |
| 40 | 2 | `u16` | raw gas-resistance ADC | exact code |
| 42 | 1 | `u8` | raw gas range | exact code |
| 43 | 1 | `u8` | repetition multiplier | configured Bosch parallel value |
| 44 | 1 | `u8` | raw heater resistance | field-associated register |
| 45 | 1 | `u8` | raw heater current/IDAC | field-associated register |
| 46 | 1 | `u8` | raw gas wait | field-associated register |

Combined known status bits remain `0x80=new_data`, `0x20=gas_valid`, `0x10=heater_stable`; unknown combined bits are `status & 0x4f`. The current firmware constructs the combined byte from only those three flags, so its unknown bits are zero. They remain representable for future producers. Physical measurement/gas indices, gas range, and reserved sensor bits are retained in their dedicated fields and exact raw bytes rather than copied into the combined byte. The receiver requires the combined `0xb0` bits to equal `(raw_measurement_status & 0x80) | (raw_gas_status & 0x30)`, `gas_index` to equal `raw_measurement_status & 0x0f`, and raw gas range to equal `raw_gas_status & 0x0f`. For this deterministic heater-profile collector, gas index must also equal logical step index. Contradictions fail closed rather than allowing decoded fields to hide different raw Bosch bytes. Invalid gas/heater state does not discard a step. If bounded memory forces a canonical duplicate choice, all duplicate/overwrite counters and flags still expose the loss; it is never silent.

## DeviceHealth payload

Base length is 54 bytes, so the frame is 102 bytes with no internal-ADC extensions.

| Offset | Width | Type | Field |
| ---: | ---: | --- | --- |
| 0 | 1 | `u8` | schema (`1`) |
| 1 | 1 | `u8` | health flags |
| 2 | 4 | `u32` | raw RCC reset-status snapshot captured before clear |
| 6 | 4 | `u32` | successful complete scans |
| 10 | 4 | `u32` | failed scans |
| 14 | 4 | `u32` | incomplete profiles |
| 18 | 4 | `u32` | I2C errors |
| 22 | 4 | `u32` | radio TX errors |
| 26 | 4 | `u32` | dropped profiles |
| 30 | 4 | `u32` | dropped fragments |
| 34 | 4 | `u32` | overwritten sensor fields |
| 38 | 4 | `u32` | current sample interval, ms |
| 42 | 3 | `u8[3]` | firmware version |
| 45 | 2 | `u16` | current profile ID |
| 47 | 2 | `u16` | current profile version |
| 49 | 2 | `u16` | last sensor error code |
| 51 | 2 | `u16` | last radio error code |
| 53 | 1 | `u8` | extension length |
| 54 | variable | TLVs | optional calibrated MCU readings |

Health flags are `0x01=counters_saturated`, `0x02=boot_id_unavailable/hardware_rng_failed`, `0x04=config_mismatch`, `0x08=last_scan_incomplete`, `0x10=sensor_error_seen`, `0x20=radio_error_seen`. Unknown bits are rejected. The boot-unavailable bit must agree with the common-header boot-ID validity bit.

Before sensor configuration exists, health uses config ID, profile ID, and
profile version all zero; its sequence is a degraded health-attempt sequence.
After a runtime configuration verification failure, health may instead retain
the requested nonzero profile ID/version with config ID zero, but must set the
configuration-mismatch health flag. This record remains independently
decodable and storable; it does not depend on a `DeviceConfig` foreign key.

Optional sorted, unique TLVs: `type=1,len=2,i16` is factory-calibrated MCU temperature in centi-°C; `type=2,len=2,u16` is VDD in mV using factory VREFINT calibration. They are absent until correctly implemented. VDD is not `BAT_RAW` or SOC; this PCB cannot measure battery voltage.

## Exact golden frames

Existing v1 fixture, unchanged:

```text
565301b001020304050607080a0b0c0dfb2e00018bcd0000b26e000f12060007eed00005902075300200080203040506
```

V2 10-step config, 231 bytes, calculated config ID `96392f014bce7745`. Its output-route byte is `0x05`, exercising simultaneous LoRa P2P and RTT output:

```text
565302013003000100b701020304050607081112131415161718ffffffff212223242526272896392f014bce77450005010302030401a0a1a2a3a4a5a6a76101760205010008030100637300017c1c0000a27600a331ea100100020a03ff01b0b1b2b3b4b5b6b70000ea6000100533be27a005070001e848040500080001001424e70300c800021e920120604000dc00043d240221614100f000065bb603226242010400087a48042363430118000a98da05246444012c000cb76c062565450140000ed5fe0726664601540010f4900827674701680013132209286848017c001531b40a296949
```

Complete 10-step profile: 231, 231, 231, 137 bytes:

```text
565302023003000400b701020304050607081112131415161718ffffffff21222324252627289999aaaabbbbcccc00050103100100020a0a000a0000000000bc4b20000000000000000000000000000000000000000000000700000080b0803d00c800021e9200000000fc18000186a000009c40000027100007a120000493e04e2001f40d0160aa40010181b0813d00dc00043d24000f4240fc19000186a100009c41000027110007a121000493e14e2101f50d0261aa41020282b0823d00f000065bb6001e8480fc1a000186a200009c42000027120007a122000493e24e2201f60d0362aa42
565302023003010400b701020304050607081112131415161718ffffffff21222324252627289999aaaabbbbcccc00050103100100020a0a000a0000000000bc4b20000000000000000000000000000000000000000000000703030383b0833d010400087a48002dc6c0fc1b000186a300009c43000027130007a123000493e34e2301f70d0463aa43040484b0843d0118000a98da003d0900fc1c000186a400009c44000027140007a124000493e44e2401f80d0564aa44050585b0853d012c000cb76c004c4b40fc1d000186a500009c45000027150007a125000493e54e2501f90d0665aa45
565302023003020400b701020304050607081112131415161718ffffffff21222324252627289999aaaabbbbcccc00050103100100020a0a000a0000000000bc4b20000000000000000000000000000000000000000000000706060686b0863d0140000ed5fe005b8d80fc1e000186a600009c46000027160007a126000493e64e2601fa0d0766aa46070787b0873d01540010f490006acfc0fc1f000186a700009c47000027170007a127000493e74e2701fb0d0867aa47080888b0883d016800131322007a1200fc20000186a800009c48000027180007a128000493e84e2801fc0d0968aa48
5653020230030304005901020304050607081112131415161718ffffffff21222324252627289999aaaabbbbcccc00050101100100020a0a000a0000000000bc4b20000000000000000000000000000000000000000000000709090989b0893d017c001531b400895440fc21000186a900009c49000027190007a129000493e94e2901fd0d0a69aa49
```

Health without internal TLVs, 102 bytes. This synthetic compatibility fixture deliberately uses unavailable boot ID and sets every defined health flag (`0x3f`) so the degraded path is byte-covered. It retains the established nonzero config ID for golden stability; operational firmware uses config ID zero for a configuration-mismatch report as specified above:

```text
5653020330000001003601020304050607080000000000000000ffffffff21222324252627289999aaaabbbbcccc0005013f1234567800000064000000020000000300000004000000050000000600000007000000080000ea60020304100100020009000a00
```

Unit tests assert every byte of all fixtures.

## Frame sizes and LoRa airtime

Current radio configuration: 868.100 MHz, SF7, BW125, CR4/5, preamble 8, explicit header, PHY CRC, normal IQ, TX +5 dBm, sync `0x1424`.

| Record | Bytes | Airtime |
| --- | ---: | ---: |
| v1 | 48 | 97.536 ms |
| v2 10-step DeviceConfig | 231 | 363.776 ms |
| ProfileFragment, 0 steps | 90 | 158.976 ms |
| ProfileFragment, 1 step | 137 | 225.536 ms |
| ProfileFragment, 2 steps | 184 | 297.216 ms |
| ProfileFragment, 3 steps | 231 | 363.776 ms |
| DeviceHealth, no internal TLVs | 102 | 174.336 ms |
| DeviceHealth, one internal TLV | 106 | 179.456 ms |
| DeviceHealth, both internal TLVs | 110 | 184.576 ms |

A complete 10-step scan is four packets of 231, 231, 231, and 137 bytes: 830 PHY payload bytes and 1.316864 seconds aggregate airtime, before gaps/retries. The codec does not set transmission policy; the golden configuration's repeat interval of 16 is a byte fixture, not the firmware cadence. With the firmware's current LoRa policy of repeating the config and base health every 6 scans, those records add an amortized 89.685 ms/scan, totaling 1.406549 seconds/scan. That is about 0.7814% at a 180-second cadence or 0.4689% at 300 seconds. The UART training policy may emit config every scan without consuming LoRa airtime.

The current CEPT ERC Recommendation 70-03 lists a 1% duty-cycle condition for non-specific SRDs in 868.0–868.6 MHz. Under that assumption, the current every-6-scans LoRa policy requires at least 140.655 seconds average cadence, so the firmware enforces 180 seconds for LoRa profile mode. Regulatory applicability under Spain's national allocation table and alternate spectrum-access modes still need product compliance review. Laboratory training should stream profiles over RTT/UART; fast sensor cadence does not authorize fast LoRa cadence.

Sources: [Semtech SX1261/SX1262 product/datasheet page](https://www.semtech.com/products/wireless-rf/lora-connect/sx1262), [Spain CNAF UN-39 in Order ETD/1449/2021](https://www.boe.es/eli/es/o/2021/12/16/etd1449), [CEPT ERC Recommendation 70-03](https://docdb.cept.org/download/4916).

## Integration locations

Firmware:

- Preserve `src/payload.rs` and the v1 fixture exactly.
- Put this shared codec in a target-independent module/crate. Keep v1 as the safe deployed default and select profile-v2 with a mutually exclusive Cargo feature.
- `src/bme688.rs`/the sensor crate performs bounded polling and creates `ProfileScan`; `src/output.rs` serializes/emits and updates TX/drop counters.
- Capture RCC status before clearing it. Generate one boot nonce with bounded RNG startup and retain it across STOP2.
- Emit config at boot, after changes, and periodically; emit health periodically/error transitions. Preserve production STOP2 between work.

Receiver:

- Add version dispatch to `crates/vesta-protocol/src/lib.rs` without altering `TelemetryV1::decode` or its fixture.
- Store raw frames plus decoded config, fragment, scan, step, and health data in versioned tables. Retain duplicate radio observations.
- Reassembly completes only when every fragment index is present; separately preserve sensor missing-step state. Receiver PHY metrics and receive timestamp remain receiver-side.

Workspace verification:

```sh
cd vesta-receiver
cargo fmt --all -- --check
cargo test --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo check -p vesta-protocol --no-default-features --target thumbv7em-none-eabi --locked
```
