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
not a claim that the driver programmed IDAC. It is the canonical configuration
snapshot; each profile step separately preserves the live readback, which may
drift without representing a configuration change.

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

Protocol-v2 ordering and elapsed time use the device's scan-start uptime plus
the per-step MCU field-read/poll offset. Receiver Unix time is retained as
arrival provenance but cannot distort rates when packets are delayed or arrive
out of order. The offset is an observation/read-time upper bound, not the
BME688's exact conversion timestamp. Legacy v1 has no uptime and therefore
continues to use receiver time. Within one exact valid-boot/profile/step series,
a newer v2 sample must have `prior_sequence + 1` with wrapping arithmetic;
otherwise history is cleared and the sample becomes a fresh baseline. This
prevents an unreceived reconfiguration scan or ordinary packet gap from being
silently bridged by a derivative. `u32::MAX -> 0` remains continuous.

An unavailable v2 boot nonce is represented as absent and is never entered in
temporal history, because a quick reboot cannot otherwise be distinguished.
It also fails the final per-profile analysis-ready gate: raw storage remains
useful, but identical sequence/uptime/config tuples can collide across quick
boots. Legacy v1 retains its separate legacy history behavior.

For a heater-profile scan, `extract_profile_features` preserves the ordered
per-step log-gas response and its offset from the scan mean. The step vector,
config ID, profile ID, and profile revision must remain together: measurements
from different sensor/heater definitions are not directly comparable.
`profile_quality_usable` requires a complete collector finish, complete
transport, no missing steps, no critical collection flags or
overwrite/index/rollover evidence, and valid status/range checks for every
terminal step. Nonzero out-of-order and ambiguous-index-jump counters reject a
scan directly even if a malformed producer omitted the corresponding summary
flag. This gate is necessary but not sufficient: a server must also
join a validated `DeviceConfiguration` matching the node, config ID, profile
ID/revision, expected step count, and every received step's target temperature,
duration, and repetition multiplier. Final resolution requires the sensor
configuration-read-back flag and a readback-valid bitmap covering every
expected step; every programmed heater-resistance and gas-wait byte must then
match its step descriptor. Raw `IDAC_HEAT` is deliberately not an equality
gate because this driver does not program it and the live per-scan value can
drift; both the canonical configuration snapshot and live profile value remain
stored for diagnostics. `extract_profile_features` therefore
leaves `configuration_resolved=false` and final `usable_for_analysis=false`;
`extract_profile_features_with_configuration` sets them only for a validated
match. The features can be recomputed when a repeated configuration packet
arrives later, so temporary config packet loss does not permanently reject the
raw profile. Expected duplicate/intermediate observations from polling the
three BME688 field slots remain diagnostics and do not alone reject a complete
terminal profile. The explicit stale-pre-scan-fields flag is conservatively
critical even though its discarded count shares `intermediate_field_count`;
raw records are still retained when this gate fails. A verified pre-scan
sensor reconfiguration remains quality-usable because the exact configuration
was read back before the trigger, but it clears that series' prior temporal
history: the recovered scan becomes a fresh baseline and no derivative bridges
the sensor reset.

## Version-2 receiver behavior

The implemented receiver:

1. dispatches on magic/version and validates every v2 type, length, flag,
   fragment coordinate, config hash, step window, and optional health TLV;
2. commits configuration and health raw packets together with their logical
   rows in one SQLite transaction; profile fragments use a durable `pending`
   archive state so a crash between archive and reassembly is replayable;
3. reassembles profiles by `(node_id, boot_id_valid, boot_id, scan_sequence,
   scan_start_uptime_ms, config_id)` with bounded memory, a 120-second expiry,
   fixed 3/3/3/1 windows, and explicit duplicate/conflict/missing outcomes;
4. rehydrates persisted transport-incomplete scans and replays a fail-closed
   maximum of 1,024 archived pending fragments before opening the radio,
   completing scans across receiver-process restart and cache expiry;
   pending packets or persisted-incomplete sources that no longer decode or
   pass semantic reassembly are atomically quarantined as invalid with exact
   bytes and an error retained. Contaminated same-key partial rows are removed
   together, while their other valid source packets return to bounded pending
   replay, so one poison packet cannot prevent startup or orphan its peers;
5. expires live state using monotonic elapsed time, while preserving Unix
   receive timestamps only as source-record provenance;
6. persists complete profiles immediately and incomplete profiles on expiry,
   capacity eviction, or graceful shutdown; later complementary fragments
   atomically replace the older partial snapshot without deleting raw packets;
7. keeps receiver timestamp/RSSI/SNR solely on source-fragment rows;
8. checks every new/replayed fragment against persisted complete or incomplete
   scans using the full logical key and exact archived payload; late
   duplicates/conflicts update both query columns and canonical JSON, survive
   restart into any later completed scan, and a conflict emits a
   machine-readable `profile_integrity_update` invalidation event;
9. atomically snapshots receiver duplicate/conflict counters while a profile
   is still active, so a crash before completion cannot lose a taint already
   assigned to an archived source packet;
10. atomically merges and deletes obsolete legacy incomplete rows when a
    same-key complete scan already exists, preventing counter inflation across
    repeated restarts;
11. proves v1 byte compatibility plus v2 golden, maximum, malformed,
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
