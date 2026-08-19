# Server-side analysis foundation

The receiver deliberately separates four stages:

1. receive and archive the exact PHY-valid LoRa payload;
2. decode and validate a versioned wire record;
3. store protocol-independent configuration, profile, health, and measurement records;
4. derive quality-controlled numerical features for a future rule engine or trained model.

There is no fire classifier in this layer yet. A reliable classifier requires
labeled baseline, nuisance, and fire-exposure data. Hard-coding a fire score
before that data exists would make the system look more certain than it is.

## Durable SQLite records

Schema version 2 keeps the legacy `telemetry_readings` table and adds:

- `radio_packets`: every payload accepted by the LoRa PHY, including unknown
  versions and decoder failures, together with exact RSSI/SNR metadata;
- `device_configurations` and `heater_profile_steps`: the firmware, sensor,
  radio, acquisition interval, and ordered BME688 heater profile used to
  produce measurements;
- `profile_scans` and `profile_steps`: one acquisition plus every recovered
  heater-step value, raw ADC field, status bit, and expected/missing-step
  marker;
- `profile_scan_packets`: links a reassembled scan back to its original radio
  fragments for byte-level audit;
- `device_health`: boot/reset identity, acquisition errors, dropped records,
  and optional calibrated MCU temperature and supply measurements.

Opening a schema-version-1 database migrates it transactionally. Existing
legacy readings remain intact; their new `radio_packet_id` is null because the
old database did not have a separate packet archive.

The live receiver currently decodes version-1 48-byte records. Other lengths
or protocol versions are stored as `unsupported`, not discarded. A malformed
version-1 candidate is stored as `invalid` with the decoder error. The SX1262
is configured for explicit headers and payloads up to 255 bytes so the exact
future protocol does not have to fit the old 48-byte ceiling.

## Protocol-independent input records

`records.rs` defines the objects the eventual version-2 decoder must produce:

- `DeviceConfiguration`
- `ProfileScan` containing ordered `ProfileStep` values
- `DeviceHealth`

These types do not assume byte offsets, fragmentation rules, or a frame-type
number. That information belongs in the wire codec once the embedded firmware
publishes its exact protocol specification and golden byte fixtures.

Structural validation rejects impossible profile counts, non-contiguous
configuration steps, duplicate/out-of-range measurements, and missing-step
bitmaps that disagree with the decoded steps. Sensor-invalid or
heater-unstable measurements are still stored: they are evidence, but they are
gated out of model-ready features.

## Quality gates and features

`analysis.rs` emits deterministic features without deciding whether there is a
fire. Each sample carries a bitset:

| Bit | Meaning |
| ---: | --- |
| `0x0001` | BME688 field was not marked as new data |
| `0x0002` | gas conversion was invalid |
| `0x0004` | heater was not stable |
| `0x0008` | unknown BME688 status bits were present |
| `0x0010` | temperature was outside -40 to 85 C |
| `0x0020` | pressure was outside 300 to 1100 hPa |
| `0x0040` | relative humidity was outside 0 to 100 percent |
| `0x0080` | gas resistance was zero |

For each chronological, usable sample, `TemporalFeatureExtractor` produces:

- temperature, pressure, humidity, and natural-log gas resistance;
- elapsed time from the previous usable sample from the same node and boot;
- temperature, humidity, pressure, and log-gas rates per minute.

For a heater-profile scan, `extract_profile_features` preserves the ordered
per-step log-gas response and its offset from the scan mean. The step vector,
profile ID, and profile revision must remain together: measurements from
different heater programs are not directly comparable.

## Version-2 integration checklist

When the embedded implementation is ready, the server-side codec must be
implemented from its final wire document and golden frames, not by guessing.
The integration is complete only when it:

1. authenticates frame magic/version/type and validates every length/checksum;
2. archives the packet before attempting logical reassembly;
3. reassembles fragments by node, boot ID, sequence, and fragment identity with
   bounded memory and expiry;
4. maps decoded data into the protocol-independent records above;
5. stores the logical record and source-packet links transactionally;
6. proves byte-for-byte compatibility with fixtures produced by the embedded
   encoder, including truncated, duplicate, reordered, and missing fragments;
7. reprocesses any already archived `unsupported` v2 packets after deployment.

Only after representative labeled datasets are collected should the server add
baseline adaptation, cross-sensor fusion, fire/nuisance classification,
confidence, and alert persistence logic.
