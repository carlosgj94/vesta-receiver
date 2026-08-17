//! Host-side decoding and presentation for Vesta telemetry.
//!
//! Radio I/O is deliberately kept out of this crate for now. A Raspberry Pi
//! backend can pass received payload bytes through [`decode_hex`] or directly
//! into `vesta_protocol::TelemetryV1::decode` without changing the wire codec.

use core::fmt;

use serde::Serialize;
use vesta_protocol::{DecodeError, FRAME_LEN, TelemetryV1, VERSION};

/// Number of hexadecimal characters in one version 1 frame.
pub const FRAME_HEX_LEN: usize = FRAME_LEN * 2;

/// Decode a hexadecimal representation of one telemetry frame.
///
/// Uppercase and lowercase digits are accepted, as is an optional `0x`
/// prefix. Embedded spaces or separators are intentionally rejected.
///
/// # Errors
///
/// Returns [`TextDecodeError`] if the text is not exactly one frame or if the
/// decoded bytes fail protocol validation.
pub fn decode_hex(input: &str) -> Result<TelemetryV1, TextDecodeError> {
    let bytes = parse_frame_hex(input).map_err(TextDecodeError::Hex)?;
    TelemetryV1::decode(&bytes).map_err(TextDecodeError::Protocol)
}

/// Parse exactly one version 1 frame from hexadecimal text.
///
/// # Errors
///
/// Returns [`HexError`] for an incorrect length or a non-hexadecimal byte.
pub fn parse_frame_hex(input: &str) -> Result<[u8; FRAME_LEN], HexError> {
    let input = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);

    if input.len() != FRAME_HEX_LEN {
        return Err(HexError::WrongLength {
            expected: FRAME_HEX_LEN,
            actual: input.len(),
        });
    }

    let source = input.as_bytes();
    let mut frame = [0_u8; FRAME_LEN];
    for (index, output) in frame.iter_mut().enumerate() {
        let high_index = index * 2;
        let low_index = high_index + 1;
        let high = hex_nibble(source[high_index]).ok_or(HexError::InvalidByte {
            index: high_index,
            found: source[high_index],
        })?;
        let low = hex_nibble(source[low_index]).ok_or(HexError::InvalidByte {
            index: low_index,
            found: source[low_index],
        })?;
        *output = (high << 4) | low;
    }
    Ok(frame)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Text representation emitted by the receiver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    /// Readable multi-line output with converted display units.
    Human,
    /// One compact JSON object per frame, preserving exact integer units.
    JsonLines,
}

/// Render one decoded frame.
///
/// JSON uses a fixed-width hexadecimal string for `node_id` so JavaScript
/// consumers cannot lose precision by interpreting the 64-bit value as a
/// number.
///
/// # Errors
///
/// Returns a serialization error if JSON generation fails.
pub fn render(frame: &TelemetryV1, format: OutputFormat) -> Result<String, serde_json::Error> {
    match format {
        OutputFormat::Human => Ok(HumanFrame(frame).to_string()),
        OutputFormat::JsonLines => serde_json::to_string(&JsonFrame::from(frame)),
    }
}

struct HumanFrame<'a>(&'a TelemetryV1);

impl fmt::Display for HumanFrame<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let frame = self.0;
        let status = frame.sensor_status;
        writeln!(formatter, "Vesta telemetry v{VERSION}")?;
        writeln!(formatter, "  node_id: 0x{:016x}", frame.node_id)?;
        writeln!(formatter, "  sequence: {}", frame.sequence)?;
        writeln!(formatter, "  status: 0x{:02x}", status.bits())?;
        writeln!(formatter, "    new_data: {}", status.is_new_data())?;
        writeln!(
            formatter,
            "    gas_valid: {}",
            status.is_gas_measurement_valid()
        )?;
        writeln!(
            formatter,
            "    heater_stable: {}",
            status.is_heater_stable()
        )?;
        writeln!(
            formatter,
            "    unknown_bits: 0x{:02x}",
            status.unknown_bits()
        )?;
        writeln!(formatter, "  corrected:")?;
        writeln!(
            formatter,
            "    temperature: {:.2} deg C ({} centi-deg C)",
            frame.compensated.temperature.as_celsius(),
            frame.compensated.temperature.centi_celsius()
        )?;
        writeln!(
            formatter,
            "    pressure: {} Pa ({:.2} hPa)",
            frame.compensated.pressure.pascals(),
            frame.compensated.pressure.as_hectopascals()
        )?;
        writeln!(
            formatter,
            "    humidity: {:.3}% RH ({} milli-% RH)",
            frame.compensated.humidity.as_percent_rh(),
            frame.compensated.humidity.milli_percent_rh()
        )?;
        writeln!(
            formatter,
            "    gas_resistance: {} ohm",
            frame.compensated.gas_resistance.ohms()
        )?;
        writeln!(formatter, "  raw:")?;
        writeln!(
            formatter,
            "    temperature_adc: {}",
            frame.raw.temperature_adc
        )?;
        writeln!(formatter, "    pressure_adc: {}", frame.raw.pressure_adc)?;
        writeln!(formatter, "    humidity_adc: {}", frame.raw.humidity_adc)?;
        writeln!(
            formatter,
            "    gas_resistance_adc: {}",
            frame.raw.gas_resistance_adc
        )?;
        writeln!(formatter, "    gas_range: {}", frame.raw.gas_range)?;
        writeln!(formatter, "    gas_index: {}", frame.raw.gas_index)?;
        writeln!(
            formatter,
            "    measurement_index: {}",
            frame.raw.measurement_index
        )?;
        writeln!(
            formatter,
            "    heater_resistance: {}",
            frame.raw.heater_resistance
        )?;
        writeln!(
            formatter,
            "    heater_current: {}",
            frame.raw.heater_current
        )?;
        write!(formatter, "    gas_wait: {}", frame.raw.gas_wait)
    }
}

#[derive(Serialize)]
struct JsonFrame {
    protocol_version: u8,
    node_id: String,
    sequence: u32,
    status: JsonStatus,
    corrected: JsonCorrected,
    raw: JsonRaw,
}

#[derive(Serialize)]
struct JsonStatus {
    bits: u8,
    new_data: bool,
    gas_valid: bool,
    heater_stable: bool,
    unknown_bits: u8,
}

#[derive(Serialize)]
struct JsonCorrected {
    temperature_centi_celsius: i16,
    pressure_pascal: u32,
    humidity_milli_percent_rh: u32,
    gas_resistance_ohm: u32,
}

#[derive(Serialize)]
struct JsonRaw {
    temperature_adc: u32,
    pressure_adc: u32,
    humidity_adc: u16,
    gas_resistance_adc: u16,
    gas_range: u8,
    gas_index: u8,
    measurement_index: u8,
    heater_resistance: u8,
    heater_current: u8,
    gas_wait: u8,
}

impl From<&TelemetryV1> for JsonFrame {
    fn from(frame: &TelemetryV1) -> Self {
        let status = frame.sensor_status;
        Self {
            protocol_version: VERSION,
            node_id: format!("{:016x}", frame.node_id),
            sequence: frame.sequence,
            status: JsonStatus {
                bits: status.bits(),
                new_data: status.is_new_data(),
                gas_valid: status.is_gas_measurement_valid(),
                heater_stable: status.is_heater_stable(),
                unknown_bits: status.unknown_bits(),
            },
            corrected: JsonCorrected {
                temperature_centi_celsius: frame.compensated.temperature.centi_celsius(),
                pressure_pascal: frame.compensated.pressure.pascals(),
                humidity_milli_percent_rh: frame.compensated.humidity.milli_percent_rh(),
                gas_resistance_ohm: frame.compensated.gas_resistance.ohms(),
            },
            raw: JsonRaw {
                temperature_adc: frame.raw.temperature_adc,
                pressure_adc: frame.raw.pressure_adc,
                humidity_adc: frame.raw.humidity_adc,
                gas_resistance_adc: frame.raw.gas_resistance_adc,
                gas_range: frame.raw.gas_range,
                gas_index: frame.raw.gas_index,
                measurement_index: frame.raw.measurement_index,
                heater_resistance: frame.raw.heater_resistance,
                heater_current: frame.raw.heater_current,
                gas_wait: frame.raw.gas_wait,
            },
        }
    }
}

/// Failure while parsing hexadecimal input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HexError {
    /// The text does not contain exactly 48 bytes.
    WrongLength {
        /// Required count of hexadecimal characters.
        expected: usize,
        /// Supplied byte length after removing an optional prefix.
        actual: usize,
    },
    /// A byte is not an ASCII hexadecimal digit.
    InvalidByte {
        /// Zero-based byte position after removing an optional prefix.
        index: usize,
        /// Byte found at that position.
        found: u8,
    },
}

impl fmt::Display for HexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => write!(
                formatter,
                "wrong hexadecimal length: expected {expected} characters, got {actual}"
            ),
            Self::InvalidByte { index, found } => write!(
                formatter,
                "invalid hexadecimal byte 0x{found:02x} at position {index}"
            ),
        }
    }
}

impl std::error::Error for HexError {}

/// Failure while decoding a text frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextDecodeError {
    /// The hexadecimal representation is malformed.
    Hex(HexError),
    /// The decoded bytes do not contain valid Vesta telemetry.
    Protocol(DecodeError),
}

impl fmt::Display for TextDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hex(error) => error.fmt(formatter),
            Self::Protocol(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TextDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Hex(error) => Some(error),
            Self::Protocol(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "565301b001020304050607080a0b0c0dfb2e00018bcd0000b26e000f12060007eed00005902075300200080203040506";

    #[test]
    fn accepts_lowercase_uppercase_and_prefix() {
        let expected = decode_hex(FIXTURE).unwrap();

        assert_eq!(decode_hex(&FIXTURE.to_uppercase()).unwrap(), expected);
        assert_eq!(decode_hex(&format!("0x{FIXTURE}")).unwrap(), expected);
        assert_eq!(
            decode_hex(&format!("0X{}", FIXTURE.to_uppercase())).unwrap(),
            expected
        );
    }

    #[test]
    fn rejects_bad_hex_length_and_character() {
        assert_eq!(
            parse_frame_hex("1234"),
            Err(HexError::WrongLength {
                expected: FRAME_HEX_LEN,
                actual: 4,
            })
        );

        let mut invalid = FIXTURE.as_bytes().to_vec();
        invalid[17] = b'g';
        let invalid = String::from_utf8(invalid).unwrap();
        assert_eq!(
            parse_frame_hex(&invalid),
            Err(HexError::InvalidByte {
                index: 17,
                found: b'g',
            })
        );
    }

    #[test]
    fn json_preserves_exact_units_and_node_identity() {
        let frame = decode_hex(FIXTURE).unwrap();
        let json = render(&frame, OutputFormat::JsonLines).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["node_id"], "0102030405060708");
        assert_eq!(value["sequence"], 0x0a0b_0c0d_u32);
        assert_eq!(value["corrected"]["temperature_centi_celsius"], -1_234);
        assert_eq!(value["corrected"]["pressure_pascal"], 101_325);
        assert_eq!(value["raw"]["temperature_adc"], 519_888);
        assert_eq!(value["status"]["gas_valid"], true);
    }

    #[test]
    fn human_output_contains_corrected_raw_and_status_values() {
        let frame = decode_hex(FIXTURE).unwrap();
        let output = render(&frame, OutputFormat::Human).unwrap();

        assert!(output.contains("temperature: -12.34 deg C"));
        assert!(output.contains("pressure: 101325 Pa"));
        assert!(output.contains("gas_valid: true"));
        assert!(output.contains("temperature_adc: 519888"));
        assert!(output.contains("gas_wait: 6"));
    }
}
