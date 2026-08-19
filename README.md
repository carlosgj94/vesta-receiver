# vesta-receiver

Rust workspace for receiving and consuming telemetry from Vesta wildfire
detection nodes.

The workspace is split into two layers:

- `vesta-protocol` is a dependency-free `no_std` codec. It preserves the exact
  deployed 48-byte v1 API and adds variable-length protocol-v2 configuration,
  profile-fragment, and health records.
- `vesta-receiver` is a host CLI that receives through a Raspberry Pi
  Waveshare SX1262 HAT or decodes captured hexadecimal frames. It emits
  human-readable text or exact-integer JSONL.

## Listen on Raspberry Pi

On a Raspberry Pi with SPI enabled and the 868 MHz antenna attached:

```sh
taskset -c 0 cargo run -j1 -p vesta-receiver -- listen --output jsonl
```

For a bounded hardware smoke test that succeeds even if no transmitter is
currently active:

```sh
taskset -c 0 cargo run -j1 -p vesta-receiver -- \
  listen --duration 5 --output jsonl
```

Use `--count N` to stop after `N` valid frames. Diagnostics and the final
counter summary go to standard error, leaving standard output as clean JSONL.
Every PHY-valid packet is committed to `data/vesta-telemetry.sqlite3` before
logical processing. Decoded v1 readings and v2 configuration/health records
are linked to their source packet. V2 profile fragments are reassembled by
`(node_id, boot_id, scan_sequence, config_id)` in deterministic 3/3/3/1
windows; each fragment keeps its own receiver timestamp, RSSI, and SNR.
Unknown versions, malformed records, duplicates, conflicts, and incomplete
profiles remain auditable rather than being silently dropped. Override the
location with `--database PATH`.
The driver is RX-only: it exposes no transmit command, keeps the HAT's BCM6 RF
control in its documented RX state, and returns the radio to standby when the
process exits normally or receives SIGINT/SIGTERM.

The one-core, one-job prefix is recommended for this Pi until it has a verified
5 A supply. It affects compilation only; the receiver itself is lightweight.

## SQLite telemetry storage

The schema-version-3 database retains one `telemetry_readings` row per valid
legacy observation and an exact `radio_packets` row for every PHY-valid LoRa
payload. Schema versions 1 and the draft version 2 are migrated transactionally
without losing archived bytes, packet IDs, or foreign-key links. The schema-2
packet table is rebuilt solely to add the authoritative `v2` disposition; its
draft record tables remain untouched. Legacy telemetry preserves:

- UTC receive time, fixed-width node ID, protocol version, and sequence
- exact status bits plus decoded status flags
- every corrected and raw BME688 field in its integer wire unit
- packet RSSI, SNR, and signal RSSI in exact centi-units
- the original 48-byte payload as a BLOB for later audit or reprocessing

The `v2_*` tables store exact u64 identities as fixed-width hexadecimal text,
microsecond acquisition timing, raw BME688 status/register values, every
collector counter, deterministic fragment provenance, and periodic health.
Protocol-independent validation and feature extraction provide quality flags,
per-minute environmental rates, and heater-profile gas shape without claiming
to classify a fire. See [Server-side analysis](docs/server-analysis.md).

Repeated node/sequence pairs are retained because the transmitter sequence is
a wrapping counter, not a permanent database identity. SQLite uses WAL mode,
full synchronous commits, a five-second busy timeout, schema versioning, and
indexes for recent global/per-node readings. The generated `data/` directory is
ignored by Git.

Example query:

```sql
SELECT
  datetime(received_at_unix_ms / 1000, 'unixepoch') AS received_utc,
  node_id,
  sequence,
  temperature_centi_celsius / 100.0 AS temperature_c,
  pressure_pascal / 100.0 AS pressure_hpa,
  humidity_milli_percent_rh / 1000.0 AS humidity_percent,
  packet_rssi_centi_dbm / 100.0 AS rssi_dbm,
  snr_centi_db / 100.0 AS snr_db
FROM telemetry_readings
ORDER BY received_at_unix_ms DESC
LIMIT 20;
```

## Try the decoder

From the repository root:

```sh
cargo run -p vesta-receiver -- decode \
  565301b001020304050607080a0b0c0dfb2e00018bcd0000b26e000f12060007eed00005902075300200080203040506
```

Machine-readable output keeps every wire value as an exact integer and writes
the 64-bit node ID as hexadecimal text:

```sh
cargo run -p vesta-receiver -- decode \
  565301b001020304050607080a0b0c0dfb2e00018bcd0000b26e000f12060007eed00005902075300200080203040506 \
  --output jsonl
```

For one hexadecimal frame per line:

```sh
cargo run -p vesta-receiver -- decode --stdin --output jsonl < frames.txt
```

Blank lines are ignored. Invalid stream lines are reported to standard error;
valid records are still written to standard output, and the process exits with
a failure status if any line was invalid.

## Workspace layout

```text
crates/
├── vesta-protocol/  # no_std wire codec, units, status flags, raw channels
└── vesta-receiver/  # host CLI and presentation layer
```

Raspberry Pi GPIO/SPI dependencies are Linux-only and remain outside the
portable `vesta-protocol` crate.

## Validation

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
cargo check -p vesta-protocol --no-default-features --target thumbv7em-none-eabi --locked
```

The tests include the unchanged v1 fixture; exact v2 configuration,
four-fragment profile, and health goldens; malformed lengths and coordinates; a
ten-step scan proving three BME fields are not mistaken for a complete profile;
out-of-order, duplicate, missing, and bounded-eviction reassembly; exact SQLite
inserts and migrations; SX1262 behavior; quality gates; and CLI dispatch for
both protocol versions.

## Protocol and radio

- [Version 1 wire format](docs/wire-format-v1.md)
- [Version 2 wire format](docs/PROTOCOL_V2.md)
- [Waveshare SX1262 Raspberry Pi bring-up](docs/waveshare-sx1262-hat.md)
- [Server-side analysis and version-2 integration](docs/server-analysis.md)

This project uses private raw LoRa P2P, not LoRaWAN. PHY CRC detects accidental
transmission corruption; it does not authenticate or encrypt a packet.
