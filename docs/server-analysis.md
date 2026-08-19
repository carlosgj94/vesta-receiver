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

Schema version 3 keeps the legacy `telemetry_readings` and raw `radio_packets`
tables and adds exact protocol-v2 tables:

- `v2_packet_decodes`: version/type/common identity and receiver-side
  reassembly state for each decoded v2 packet;
- `v2_device_configurations` and `v2_heater_profile_steps`: exact firmware,
  sensor, output route, radio, cadence, calibration fingerprint, quantized
  timing, read-back registers, and ordered BME688 profile;
- `v2_profile_scans` and `v2_profile_steps`: all sensor collection counters,
  microsecond timing, raw status bytes, compensated/raw channels, and separate
  sensor-missing versus receiver-missing bitmaps;
- `v2_profile_fragments`: links each unique fragment to its raw packet and its
  own receiver timestamp/RSSI/SNR instead of inventing a scan-level link value;
- `v2_device_health`: reset identity, sensor/I2C/radio/drop counters, firmware
  and profile versions, and only explicitly calibrated optional MCU readings.

Unsigned 64-bit node, boot, config, build, calibration, and uptime values are
stored as fixed-width hexadecimal text where SQLite's signed integer cannot
represent their full range. Canonical JSON records are retained alongside
queryable columns so no less-common configuration field is lost.

Opening schema version 1 or the prior draft schema version 2 migrates
transactionally. Draft record tables are not rebuilt or deleted. For a schema-2
database, `radio_packets` is rebuilt with the expanded `v2` disposition while
preserving packet IDs, payloads, metadata, and existing foreign-key links; a
foreign-key check runs before initialization succeeds. `v2_packet_decodes`
records the exact v2 frame kind and receiver-side reassembly state.

## Protocol-independent input records

`records.rs` defines the exact objects produced by the version-2 decoder:

- `DeviceConfiguration`
- `ProfileScan` containing ordered `ProfileStep` values
- `DeviceHealth`

Wire offsets and structural rules remain in the allocation-free
`vesta-protocol::v2` codec. The host records preserve exact units while keeping
storage and analysis independent from byte offsets.

Structural validation rejects impossible counts, non-contiguous configuration
steps, duplicate/out-of-range measurements, inconsistent counters, and data
attributed to a radio fragment the receiver never obtained. Sensor-invalid or
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

## Version-2 receiver behavior

The implemented receiver:

1. dispatches on magic/version and validates every v2 type, length, flag,
   fragment coordinate, config hash, step window, and optional health TLV;
2. archives each PHY-valid packet before logical processing;
3. reassembles profiles by `(node_id, boot_id, scan_sequence, config_id)` with
   bounded memory, a 120-second expiry, fixed 3/3/3/1 windows, and explicit
   duplicate/conflict/missing outcomes;
4. persists complete profiles immediately and incomplete profiles on expiry,
   capacity eviction, or graceful shutdown;
5. keeps receiver timestamp/RSSI/SNR solely on source-fragment rows;
6. proves v1 byte compatibility plus v2 golden, maximum, malformed,
   out-of-order, duplicate, missing, and ten-step behavior in host tests.

Before deployment, any v2 frames archived by an older receiver as unsupported
still require an explicit reprocessing command; this repository does not yet
provide that one-shot backfill tool. Newly decoded v2 frames are stored as
`radio_packets.disposition = 'v2'`.

Only after representative labeled datasets are collected should the server add
baseline adaptation, cross-sensor fusion, fire/nuisance classification,
confidence, and alert persistence logic.
