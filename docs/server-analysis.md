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
The Rust/JSON configuration field is `readback_heater_current`. The SQL column
retains the draft schema-v2 compatibility name `programmed_heater_current` to
avoid a destructive migration; its value is exact raw `IDAC_HEAT` readback,
not a claim that the driver programmed IDAC.

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
| `0x0100` | containing profile failed transport or collector integrity gates |

For each chronological, usable sample, `TemporalFeatureExtractor` produces:

- temperature, pressure, humidity, and natural-log gas resistance;
- elapsed time from the previous usable sample from the same node, valid boot,
  exact configuration/profile revision, and heater step;
- temperature, humidity, pressure, and log-gas rates per minute.

An unavailable v2 boot nonce is represented as absent and is never entered in
temporal history, because a quick reboot cannot otherwise be distinguished.
Legacy v1 retains its separate legacy history behavior.

For a heater-profile scan, `extract_profile_features` preserves the ordered
per-step log-gas response and its offset from the scan mean. The step vector,
config ID, profile ID, and profile revision must remain together: measurements
from different sensor/heater definitions are not directly comparable.
`usable_for_analysis` additionally requires a complete collector finish,
complete transport, no missing steps, no critical collection flags or
overwrite/index/rollover evidence, and valid status/range checks for every
terminal step. Expected duplicate/intermediate observations from polling the
three BME688 field slots remain diagnostics and do not alone reject a complete
terminal profile. The explicit stale-pre-scan-fields flag is conservatively
critical even though its discarded count shares `intermediate_field_count`;
raw records are still retained when this gate fails. A verified pre-scan
sensor reconfiguration remains usable because the exact configuration was read
back before the trigger, but it clears that series' prior temporal history:
the recovered scan becomes a fresh baseline and no derivative bridges the
sensor reset.

## Version-2 receiver behavior

The implemented receiver:

1. dispatches on magic/version and validates every v2 type, length, flag,
   fragment coordinate, config hash, step window, and optional health TLV;
2. archives each PHY-valid packet before logical processing;
3. reassembles profiles by `(node_id, boot_id_valid, boot_id, scan_sequence,
   scan_start_uptime_ms, config_id)` with bounded memory, a 120-second expiry,
   fixed 3/3/3/1 windows, and explicit duplicate/conflict/missing outcomes;
4. replays a fail-closed maximum of 1,024 archived pending fragments before
   opening the radio, completing scans across a receiver-process restart;
5. expires live state using monotonic elapsed time, while preserving Unix
   receive timestamps only as source-record provenance;
6. persists complete profiles immediately and incomplete profiles on expiry,
   capacity eviction, or graceful shutdown;
7. keeps receiver timestamp/RSSI/SNR solely on source-fragment rows;
8. checks every new/replayed fragment against persisted complete scans using
   the full logical key and exact archived payload; late duplicates/conflicts
   update both query columns and canonical JSON, and a conflict emits a
   machine-readable `profile_integrity_update` invalidation event;
9. proves v1 byte compatibility plus v2 golden, maximum, malformed,
   out-of-order, duplicate, missing, and ten-step behavior in host tests.

When the hardware boot nonce is unavailable, scan-start uptime reduces but
cannot eliminate identity collisions between quick reboots; two boots could
reach the same sequence and millisecond. Such records remain explicitly
boot-ambiguous and are excluded from temporal history. Config ID zero is stored
normally for pre-configuration health and explicit configuration-mismatch
profile/health records; it has no required configuration-table foreign key.

Before deployment, any v2 frames archived by an older receiver as unsupported
still require an explicit reprocessing command; this repository does not yet
provide that one-shot backfill tool. Newly decoded v2 frames are stored as
`radio_packets.disposition = 'v2'`.

Only after representative labeled datasets are collected should the server add
baseline adaptation, cross-sensor fusion, fire/nuisance classification,
confidence, and alert persistence logic.
