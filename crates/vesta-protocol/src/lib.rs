#![no_std]

//! Dependency-free codec for the Vesta telemetry wire format.
//!
//! Version 1 is a fixed-size, 48-byte, big-endian frame. The API preserves all
//! transmitted integers exactly and wraps compensated values in unit-bearing
//! types so callers cannot accidentally confuse their scales.

use core::fmt;

/// Allocation-free protocol-v2 records and codec.
pub mod v2;

/// Number of bytes in a version 1 telemetry frame.
pub const FRAME_LEN: usize = 48;

/// Two-byte discriminator at the beginning of every Vesta telemetry frame.
pub const MAGIC: [u8; 2] = *b"VS";

/// Wire-format version understood by this crate.
pub const VERSION: u8 = 1;

/// A decoded Vesta frame selected by its on-wire version byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedTelemetry<'a> {
    /// Deployed fixed-size protocol-v1 telemetry.
    V1(TelemetryV1),
    /// A validated variable-size protocol-v2 record.
    V2(v2::DecodedFrame<'a>),
}

/// Decode either supported protocol version without guessing from length.
///
/// # Errors
///
/// Returns [`ProtocolDecodeError`] for a truncated discriminator, invalid
/// magic, unsupported version, or a version-specific structural error.
pub fn decode_any(bytes: &[u8]) -> Result<DecodedTelemetry<'_>, ProtocolDecodeError> {
    if bytes.len() < 3 {
        return Err(ProtocolDecodeError::TruncatedDiscriminator {
            actual: bytes.len(),
        });
    }
    let found_magic = [bytes[0], bytes[1]];
    if found_magic != MAGIC {
        return Err(ProtocolDecodeError::InvalidMagic { found: found_magic });
    }
    match bytes[2] {
        VERSION => TelemetryV1::decode(bytes)
            .map(DecodedTelemetry::V1)
            .map_err(ProtocolDecodeError::V1),
        v2::VERSION_V2 => v2::decode(bytes)
            .map(DecodedTelemetry::V2)
            .map_err(ProtocolDecodeError::V2),
        found => Err(ProtocolDecodeError::UnsupportedVersion { found }),
    }
}

/// Failure while selecting or decoding a versioned Vesta frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolDecodeError {
    /// Fewer than the magic and version bytes were supplied.
    TruncatedDiscriminator {
        /// Number of supplied bytes.
        actual: usize,
    },
    /// The first two bytes were not [`MAGIC`].
    InvalidMagic {
        /// Discriminator found in the input.
        found: [u8; 2],
    },
    /// The version byte is not supported by this codec.
    UnsupportedVersion {
        /// Version byte found in the input.
        found: u8,
    },
    /// Protocol-v1 decoding failed.
    V1(DecodeError),
    /// Protocol-v2 decoding failed.
    V2(v2::Error),
}

impl fmt::Display for ProtocolDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedDiscriminator { actual } => {
                write!(
                    formatter,
                    "truncated Vesta discriminator: got {actual} bytes"
                )
            }
            Self::InvalidMagic { found } => write!(
                formatter,
                "invalid frame magic: expected {:02x}{:02x}, got {:02x}{:02x}",
                MAGIC[0], MAGIC[1], found[0], found[1]
            ),
            Self::UnsupportedVersion { found } => {
                write!(formatter, "unsupported frame version: {found}")
            }
            Self::V1(error) => write!(formatter, "invalid protocol-v1 frame: {error}"),
            Self::V2(error) => write!(formatter, "invalid protocol-v2 frame: {error}"),
        }
    }
}

/// One hundredth of a degree Celsius.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Temperature(i16);

impl Temperature {
    /// Creates a temperature from the exact wire representation.
    #[must_use]
    pub const fn from_centi_celsius(value: i16) -> Self {
        Self(value)
    }

    /// Returns the exact signed integer transmitted on the wire.
    #[must_use]
    pub const fn centi_celsius(self) -> i16 {
        self.0
    }

    /// Returns the temperature in degrees Celsius.
    #[must_use]
    pub fn as_celsius(self) -> f32 {
        f32::from(self.0) / 100.0
    }
}

/// Pressure in pascals.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Pressure(u32);

impl Pressure {
    /// Creates a pressure from the exact wire representation.
    #[must_use]
    pub const fn from_pascals(value: u32) -> Self {
        Self(value)
    }

    /// Returns pressure in pascals, exactly as transmitted.
    #[must_use]
    pub const fn pascals(self) -> u32 {
        self.0
    }

    /// Returns pressure in hectopascals.
    #[must_use]
    pub fn as_hectopascals(self) -> f64 {
        f64::from(self.0) / 100.0
    }
}

/// Relative humidity in one thousandth of one percent RH.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RelativeHumidity(u32);

impl RelativeHumidity {
    /// Creates relative humidity from the exact wire representation.
    #[must_use]
    pub const fn from_milli_percent_rh(value: u32) -> Self {
        Self(value)
    }

    /// Returns milli-percent RH, exactly as transmitted.
    #[must_use]
    pub const fn milli_percent_rh(self) -> u32 {
        self.0
    }

    /// Returns relative humidity as percent RH.
    #[must_use]
    pub fn as_percent_rh(self) -> f64 {
        f64::from(self.0) / 1_000.0
    }
}

/// Gas-sensor resistance in ohms.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct GasResistance(u32);

impl GasResistance {
    /// Creates a gas resistance from the exact wire representation.
    #[must_use]
    pub const fn from_ohms(value: u32) -> Self {
        Self(value)
    }

    /// Returns resistance in ohms, exactly as transmitted.
    #[must_use]
    pub const fn ohms(self) -> u32 {
        self.0
    }
}

/// `BME68x` status byte, preserving both known and future flag bits.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Bme68xStatus(u8);

impl Bme68xStatus {
    /// The sensor reports that this sample contains new data.
    pub const NEW_DATA: u8 = 0x80;
    /// The gas-resistance measurement is valid.
    pub const GAS_MEASUREMENT_VALID: u8 = 0x20;
    /// The heater reached a stable state for the gas measurement.
    pub const HEATER_STABLE: u8 = 0x10;
    /// Mask of status bits understood by this version of the crate.
    pub const KNOWN_MASK: u8 = Self::NEW_DATA | Self::GAS_MEASUREMENT_VALID | Self::HEATER_STABLE;

    /// Creates a status value while preserving every transmitted bit.
    #[must_use]
    pub const fn from_bits_retain(bits: u8) -> Self {
        Self(bits)
    }

    /// Returns every transmitted status bit.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Returns whether this sample contains new data.
    #[must_use]
    pub const fn is_new_data(self) -> bool {
        self.0 & Self::NEW_DATA != 0
    }

    /// Returns whether the gas-resistance measurement is valid.
    #[must_use]
    pub const fn is_gas_measurement_valid(self) -> bool {
        self.0 & Self::GAS_MEASUREMENT_VALID != 0
    }

    /// Returns whether the gas heater was stable.
    #[must_use]
    pub const fn is_heater_stable(self) -> bool {
        self.0 & Self::HEATER_STABLE != 0
    }

    /// Returns status bits not understood by this version of the crate.
    #[must_use]
    pub const fn unknown_bits(self) -> u8 {
        self.0 & !Self::KNOWN_MASK
    }
}

/// Compensated environmental values emitted by the sensor driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompensatedReadings {
    /// Ambient temperature.
    pub temperature: Temperature,
    /// Atmospheric pressure.
    pub pressure: Pressure,
    /// Relative humidity.
    pub humidity: RelativeHumidity,
    /// `BME68x` gas-sensing resistance.
    pub gas_resistance: GasResistance,
}

/// Uncompensated `BME68x` channels and measurement metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawReadings {
    /// Raw temperature ADC channel.
    pub temperature_adc: u32,
    /// Raw pressure ADC channel.
    pub pressure_adc: u32,
    /// Raw humidity ADC channel.
    pub humidity_adc: u16,
    /// Raw gas-resistance ADC channel.
    pub gas_resistance_adc: u16,
    /// Gas range selected by the sensor.
    pub gas_range: u8,
    /// Gas-measurement slot index.
    pub gas_index: u8,
    /// Measurement index reported by the sensor.
    pub measurement_index: u8,
    /// Raw heater-resistance register value.
    pub heater_resistance: u8,
    /// Raw heater-current register value.
    pub heater_current: u8,
    /// Raw gas-wait register value.
    pub gas_wait: u8,
}

/// Fully decoded version 1 Vesta telemetry frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryV1 {
    /// `BME68x` sample validity and heater-state flags.
    pub sensor_status: Bme68xStatus,
    /// Stable 64-bit identity assigned to the transmitting node.
    pub node_id: u64,
    /// Wrapping per-node transmission sequence number.
    pub sequence: u32,
    /// Compensated readings with explicit units.
    pub compensated: CompensatedReadings,
    /// Uncompensated channels and measurement metadata.
    pub raw: RawReadings,
}

impl TelemetryV1 {
    /// Decodes one complete version 1 frame.
    ///
    /// The decoder rejects trailing bytes as well as truncation. It validates
    /// the magic and version before interpreting any payload fields.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] when the frame length, magic, or version is not
    /// exactly the version 1 wire format.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != FRAME_LEN {
            return Err(DecodeError::WrongLength {
                expected: FRAME_LEN,
                actual: bytes.len(),
            });
        }

        let found_magic = [bytes[0], bytes[1]];
        if found_magic != MAGIC {
            return Err(DecodeError::InvalidMagic { found: found_magic });
        }

        if bytes[2] != VERSION {
            return Err(DecodeError::UnsupportedVersion { found: bytes[2] });
        }

        Ok(Self {
            sensor_status: Bme68xStatus::from_bits_retain(bytes[3]),
            node_id: read_u64(bytes, 4),
            sequence: read_u32(bytes, 12),
            compensated: CompensatedReadings {
                temperature: Temperature::from_centi_celsius(read_i16(bytes, 16)),
                pressure: Pressure::from_pascals(read_u32(bytes, 18)),
                humidity: RelativeHumidity::from_milli_percent_rh(read_u32(bytes, 22)),
                gas_resistance: GasResistance::from_ohms(read_u32(bytes, 26)),
            },
            raw: RawReadings {
                temperature_adc: read_u32(bytes, 30),
                pressure_adc: read_u32(bytes, 34),
                humidity_adc: read_u16(bytes, 38),
                gas_resistance_adc: read_u16(bytes, 40),
                gas_range: bytes[42],
                gas_index: bytes[43],
                measurement_index: bytes[44],
                heater_resistance: bytes[45],
                heater_current: bytes[46],
                gas_wait: bytes[47],
            },
        })
    }

    /// Encodes this value using the canonical version 1 representation.
    #[must_use]
    pub fn encode(self) -> [u8; FRAME_LEN] {
        let mut frame = [0_u8; FRAME_LEN];
        frame[0..2].copy_from_slice(&MAGIC);
        frame[2] = VERSION;
        frame[3] = self.sensor_status.bits();
        frame[4..12].copy_from_slice(&self.node_id.to_be_bytes());
        frame[12..16].copy_from_slice(&self.sequence.to_be_bytes());
        frame[16..18].copy_from_slice(&self.compensated.temperature.centi_celsius().to_be_bytes());
        frame[18..22].copy_from_slice(&self.compensated.pressure.pascals().to_be_bytes());
        frame[22..26].copy_from_slice(&self.compensated.humidity.milli_percent_rh().to_be_bytes());
        frame[26..30].copy_from_slice(&self.compensated.gas_resistance.ohms().to_be_bytes());
        frame[30..34].copy_from_slice(&self.raw.temperature_adc.to_be_bytes());
        frame[34..38].copy_from_slice(&self.raw.pressure_adc.to_be_bytes());
        frame[38..40].copy_from_slice(&self.raw.humidity_adc.to_be_bytes());
        frame[40..42].copy_from_slice(&self.raw.gas_resistance_adc.to_be_bytes());
        frame[42] = self.raw.gas_range;
        frame[43] = self.raw.gas_index;
        frame[44] = self.raw.measurement_index;
        frame[45] = self.raw.heater_resistance;
        frame[46] = self.raw.heater_current;
        frame[47] = self.raw.gas_wait;
        frame
    }
}

impl TryFrom<&[u8]> for TelemetryV1 {
    type Error = DecodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(value)
    }
}

impl TryFrom<&[u8; FRAME_LEN]> for TelemetryV1 {
    type Error = DecodeError;

    fn try_from(value: &[u8; FRAME_LEN]) -> Result<Self, Self::Error> {
        Self::decode(value)
    }
}

/// Reason a byte slice could not be decoded as Vesta telemetry version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The input was truncated or had trailing bytes.
    WrongLength {
        /// Required version 1 frame length.
        expected: usize,
        /// Length supplied by the caller.
        actual: usize,
    },
    /// The first two bytes were not [`MAGIC`].
    InvalidMagic {
        /// Discriminator found in the input.
        found: [u8; 2],
    },
    /// The frame uses a version this decoder does not understand.
    UnsupportedVersion {
        /// Version byte found in the input.
        found: u8,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(
                    formatter,
                    "wrong frame length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidMagic { found } => write!(
                formatter,
                "invalid frame magic: expected {:02x}{:02x}, got {:02x}{:02x}",
                MAGIC[0], MAGIC[1], found[0], found[1]
            ),
            Self::UnsupportedVersion { found } => {
                write!(formatter, "unsupported frame version: {found}")
            }
        }
    }
}

#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_i16(bytes: &[u8], offset: usize) -> i16 {
    i16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: [u8; FRAME_LEN] = [
        0x56, 0x53, 0x01, 0xb0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c,
        0x0d, 0xfb, 0x2e, 0x00, 0x01, 0x8b, 0xcd, 0x00, 0x00, 0xb2, 0x6e, 0x00, 0x0f, 0x12, 0x06,
        0x00, 0x07, 0xee, 0xd0, 0x00, 0x05, 0x90, 0x20, 0x75, 0x30, 0x02, 0x00, 0x08, 0x02, 0x03,
        0x04, 0x05, 0x06,
    ];

    #[test]
    fn decodes_and_reencodes_interoperability_fixture_exactly() {
        let frame = TelemetryV1::decode(&FIXTURE).unwrap();

        assert_eq!(frame.sensor_status.bits(), 0xb0);
        assert_eq!(frame.node_id, 0x0102_0304_0506_0708);
        assert_eq!(frame.sequence, 0x0a0b_0c0d);
        assert_eq!(frame.compensated.temperature.centi_celsius(), -1_234);
        assert_eq!(frame.compensated.pressure.pascals(), 101_325);
        assert_eq!(frame.compensated.humidity.milli_percent_rh(), 45_678);
        assert_eq!(frame.compensated.gas_resistance.ohms(), 987_654);
        assert_eq!(frame.raw.temperature_adc, 519_888);
        assert_eq!(frame.raw.pressure_adc, 364_576);
        assert_eq!(frame.raw.humidity_adc, 30_000);
        assert_eq!(frame.raw.gas_resistance_adc, 512);
        assert_eq!(frame.raw.gas_range, 8);
        assert_eq!(frame.raw.gas_index, 2);
        assert_eq!(frame.raw.measurement_index, 3);
        assert_eq!(frame.raw.heater_resistance, 4);
        assert_eq!(frame.raw.heater_current, 5);
        assert_eq!(frame.raw.gas_wait, 6);
        assert_eq!(frame.encode(), FIXTURE);
    }

    #[test]
    fn interprets_known_status_flags_and_preserves_unknown_bits() {
        let status = TelemetryV1::decode(&FIXTURE).unwrap().sensor_status;

        assert!(status.is_new_data());
        assert!(status.is_gas_measurement_valid());
        assert!(status.is_heater_stable());
        assert_eq!(status.unknown_bits(), 0);

        let status = Bme68xStatus::from_bits_retain(0xff);
        assert_eq!(status.bits(), 0xff);
        assert_eq!(status.unknown_bits(), 0x4f);
    }

    #[test]
    fn exposes_human_scale_conversions_without_losing_integer_access() {
        let frame = TelemetryV1::decode(&FIXTURE).unwrap();

        assert!((frame.compensated.temperature.as_celsius() - -12.34).abs() < 0.000_01);
        assert!((frame.compensated.pressure.as_hectopascals() - 1_013.25).abs() < 0.000_1);
        assert!((frame.compensated.humidity.as_percent_rh() - 45.678).abs() < 0.000_1);
    }

    #[test]
    fn rejects_every_truncated_length_and_trailing_data() {
        for length in 0..FRAME_LEN {
            assert_eq!(
                TelemetryV1::decode(&FIXTURE[..length]),
                Err(DecodeError::WrongLength {
                    expected: FRAME_LEN,
                    actual: length,
                })
            );
        }

        let mut with_trailing_byte = [0_u8; FRAME_LEN + 1];
        with_trailing_byte[..FRAME_LEN].copy_from_slice(&FIXTURE);
        assert_eq!(
            TelemetryV1::decode(&with_trailing_byte),
            Err(DecodeError::WrongLength {
                expected: FRAME_LEN,
                actual: FRAME_LEN + 1,
            })
        );
    }

    #[test]
    fn rejects_bad_magic_before_examining_version() {
        let mut input = FIXTURE;
        input[..2].copy_from_slice(b"NO");
        input[2] = 99;

        assert_eq!(
            TelemetryV1::decode(&input),
            Err(DecodeError::InvalidMagic { found: *b"NO" })
        );
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut input = FIXTURE;
        input[2] = 2;

        assert_eq!(
            TelemetryV1::decode(&input),
            Err(DecodeError::UnsupportedVersion { found: 2 })
        );
    }

    #[test]
    fn decodes_signed_temperature_boundaries() {
        let mut input = FIXTURE;

        input[16..18].copy_from_slice(&i16::MIN.to_be_bytes());
        assert_eq!(
            TelemetryV1::decode(&input)
                .unwrap()
                .compensated
                .temperature
                .centi_celsius(),
            i16::MIN
        );

        input[16..18].copy_from_slice(&i16::MAX.to_be_bytes());
        assert_eq!(
            TelemetryV1::decode(&input)
                .unwrap()
                .compensated
                .temperature
                .centi_celsius(),
            i16::MAX
        );
    }

    #[test]
    fn decodes_big_endian_integer_boundaries() {
        let mut input = FIXTURE;
        input[4..12].copy_from_slice(&u64::MAX.to_be_bytes());
        input[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        input[18..22].copy_from_slice(&u32::MAX.to_be_bytes());
        input[38..40].copy_from_slice(&u16::MAX.to_be_bytes());

        let frame = TelemetryV1::decode(&input).unwrap();
        assert_eq!(frame.node_id, u64::MAX);
        assert_eq!(frame.sequence, u32::MAX);
        assert_eq!(frame.compensated.pressure.pascals(), u32::MAX);
        assert_eq!(frame.raw.humidity_adc, u16::MAX);
        assert_eq!(frame.encode(), input);
    }

    #[test]
    fn array_and_slice_try_from_implementations_match_decode() {
        let expected = TelemetryV1::decode(&FIXTURE).unwrap();

        assert_eq!(TelemetryV1::try_from(&FIXTURE).unwrap(), expected);
        assert_eq!(TelemetryV1::try_from(FIXTURE.as_slice()).unwrap(), expected);
    }

    #[test]
    fn errors_have_actionable_messages() {
        use std::string::ToString;

        assert_eq!(
            DecodeError::WrongLength {
                expected: 48,
                actual: 7,
            }
            .to_string(),
            "wrong frame length: expected 48, got 7"
        );
        assert_eq!(
            DecodeError::InvalidMagic { found: *b"NO" }.to_string(),
            "invalid frame magic: expected 5653, got 4e4f"
        );
        assert_eq!(
            DecodeError::UnsupportedVersion { found: 2 }.to_string(),
            "unsupported frame version: 2"
        );
    }
}
