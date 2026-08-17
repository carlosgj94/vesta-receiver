# vesta-receiver

Rust workspace for receiving and consuming telemetry from Vesta wildfire
detection nodes.

The current milestone is intentionally split in two:

- `vesta-protocol` is a dependency-free `no_std` codec for the exact 48-byte
  payload emitted by the embedded firmware.
- `vesta-receiver` is a host CLI that decodes captured hexadecimal frames into
  human-readable text or exact-integer JSONL.

Direct reception from the Raspberry Pi's Waveshare SX1262 HAT is the next
milestone. It is not implemented or hardware-validated yet.

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

The future Raspberry Pi/SX1262 implementation will be isolated from both of
these crates so Linux GPIO/SPI dependencies never enter the portable protocol
layer.

## Validation

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo check -p vesta-protocol --no-default-features --target thumbv7em-none-eabi
```

The tests include the byte-for-byte fixture shared with the transmitter,
signed and unsigned boundaries, all truncated lengths, protocol failures, hex
input failures, JSON units, CLI exit codes, and mixed valid/invalid streams.

## Protocol and radio

- [Version 1 wire format](docs/wire-format-v1.md)
- [Waveshare SX1262 Raspberry Pi bring-up](docs/waveshare-sx1262-hat.md)

This project uses private raw LoRa P2P, not LoRaWAN. PHY CRC detects accidental
transmission corruption; it does not authenticate or encrypt a packet.
