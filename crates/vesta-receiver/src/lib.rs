//! Host-side decoding, presentation, and Raspberry Pi radio reception for
//! Vesta telemetry.

pub mod analysis;
pub mod database;
pub mod reassembly;
pub mod records;
#[cfg(target_os = "linux")]
pub mod sx1262;

use core::fmt;

use serde::Serialize;
use serde_json::{Value, json};
use vesta_protocol::v2::{DecodedFrame as DecodedFrameV2, ProfileFragmentView};
use vesta_protocol::{DecodeError, FRAME_LEN, TelemetryV1, VERSION};

use crate::reassembly::{ReassembledProfile, device_configuration, device_health, fragment_steps};
use crate::records::RecordIdentity;

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

/// Parse a variable-length Vesta frame from hexadecimal text.
///
/// Version 2 frames may contain between 48 and 255 bytes. This parser accepts
/// any whole-byte payload from 3 through 255 bytes and leaves exact
/// version-specific length validation to `vesta-protocol`.
///
/// # Errors
///
/// Returns [`HexError`] for odd length, an out-of-range payload, or a
/// non-hexadecimal character.
pub fn parse_payload_hex(input: &str) -> Result<Vec<u8>, HexError> {
    let input = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    if input.len() % 2 != 0 {
        return Err(HexError::OddLength {
            actual: input.len(),
        });
    }
    let byte_len = input.len() / 2;
    if !(3..=vesta_protocol::v2::MAX_PHY_FRAME_LEN).contains(&byte_len) {
        return Err(HexError::PayloadLength {
            minimum: 3,
            maximum: vesta_protocol::v2::MAX_PHY_FRAME_LEN,
            actual: byte_len,
        });
    }
    let source = input.as_bytes();
    let mut payload = Vec::with_capacity(byte_len);
    for index in 0..byte_len {
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
        payload.push((high << 4) | low);
    }
    Ok(payload)
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

/// Signal measurements reported by the SX1262 for one received packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RadioMetadata {
    /// Packet RSSI in one hundredth of a decibel-milliwatt.
    pub packet_rssi_centi_dbm: i16,
    /// Packet SNR in one hundredth of a decibel.
    pub snr_centi_db: i16,
    /// Signal RSSI in one hundredth of a decibel-milliwatt.
    pub signal_rssi_centi_dbm: i16,
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

/// Render a decoded radio frame together with its SX1262 measurements.
///
/// # Errors
///
/// Returns a serialization error if JSON generation fails.
pub fn render_received(
    frame: &TelemetryV1,
    format: OutputFormat,
    radio: RadioMetadata,
) -> Result<String, serde_json::Error> {
    match format {
        OutputFormat::Human => Ok(HumanReceivedFrame { frame, radio }.to_string()),
        OutputFormat::JsonLines => serde_json::to_string(&JsonReceivedFrame {
            frame: JsonFrame::from(frame),
            radio,
        }),
    }
}

/// Render one decoded protocol-v2 frame.
///
/// Device-originated identity values that exceed JavaScript's safe integer
/// range are emitted as fixed-width hexadecimal strings. Receiver RSSI/SNR is
/// included only when supplied by the receiver call site.
///
/// # Errors
///
/// Returns an error if a profile step cannot be extracted or JSON generation
/// fails.
pub fn render_v2(
    frame: DecodedFrameV2<'_>,
    format: OutputFormat,
    radio: Option<RadioMetadata>,
) -> Result<String, V2RenderError> {
    let value = match frame {
        DecodedFrameV2::DeviceConfig { header, config } => {
            let record = device_configuration(header, config);
            let identity = record.identity;
            let firmware_build_id = record.firmware_build_id;
            let calibration_hash = record.calibration_hash;
            let mut record_value = serde_json::to_value(record)?;
            exactify_identity(&mut record_value, identity);
            record_value["firmware_build_id"] = Value::String(hex_u64(firmware_build_id));
            record_value["calibration_hash"] = Value::String(hex_u64(calibration_hash));
            json!({
                "protocol_version": 2,
                "frame_type": "device_config",
                "record": record_value,
                "radio": radio,
            })
        }
        DecodedFrameV2::ProfileFragment(fragment) => fragment_json(fragment, radio)?,
        DecodedFrameV2::DeviceHealth { header, health } => {
            let record = device_health(header, health);
            let identity = record.identity;
            let mut record_value = serde_json::to_value(record)?;
            exactify_identity(&mut record_value, identity);
            json!({
                "protocol_version": 2,
                "frame_type": "device_health",
                "record": record_value,
                "radio": radio,
            })
        }
    };
    match format {
        OutputFormat::Human => serde_json::to_string_pretty(&value).map_err(V2RenderError::Json),
        OutputFormat::JsonLines => serde_json::to_string(&value).map_err(V2RenderError::Json),
    }
}

/// Render a complete or explicitly receiver-incomplete logical profile.
///
/// # Errors
///
/// Returns an error if JSON generation fails.
pub fn render_reassembled_profile(
    profile: &ReassembledProfile,
    format: OutputFormat,
) -> Result<String, serde_json::Error> {
    let mut record = serde_json::to_value(&profile.scan)?;
    exactify_identity(&mut record, profile.scan.identity);
    let value = json!({
        "protocol_version": 2,
        "frame_type": "profile_scan",
        "record": record,
        "receiver_fragments": profile.fragments,
    });
    match format {
        OutputFormat::Human => serde_json::to_string_pretty(&value),
        OutputFormat::JsonLines => serde_json::to_string(&value),
    }
}

fn fragment_json(
    fragment: ProfileFragmentView<'_>,
    radio: Option<RadioMetadata>,
) -> Result<Value, V2RenderError> {
    let identity = crate::reassembly::record_identity(fragment.header);
    let steps = fragment_steps(fragment)?;
    Ok(json!({
        "protocol_version": 2,
        "frame_type": "profile_fragment",
        "identity": identity_json(identity),
        "fragment_index": fragment.header.fragment_index,
        "fragment_count": fragment.header.fragment_count,
        "profile_id": fragment.profile_id,
        "profile_version": fragment.profile_version,
        "expected_step_count": fragment.expected_step_count,
        "observed_unique_step_count": fragment.observed_unique_step_count,
        "observed_field_count": fragment.observed_field_count,
        "missing_steps_bitmap": fragment.missing_steps_bitmap,
        "duplicate_steps_bitmap": fragment.duplicate_steps_bitmap,
        "scan_duration_us": fragment.scan_duration_us,
        "collection_flags": fragment.collection_flags,
        "finish_reason": fragment.finish_reason,
        "duplicate_count": fragment.duplicate_count,
        "overwritten_field_count": fragment.overwritten_field_count,
        "out_of_order_count": fragment.out_of_order_count,
        "ambiguous_index_jump_count": fragment.ambiguous_index_jump_count,
        "invalid_gas_index_count": fragment.invalid_gas_index_count,
        "intermediate_field_count": fragment.intermediate_field_count,
        "profile_rollover_count": fragment.profile_rollover_count,
        "fields_after_rollover_count": fragment.fields_after_rollover_count,
        "poll_count": fragment.poll_count,
        "step_window_start": fragment.step_window_start,
        "steps": steps,
        "radio": radio,
    }))
}

fn exactify_identity(value: &mut Value, identity: RecordIdentity) {
    value["identity"] = identity_json(identity);
}

fn identity_json(identity: RecordIdentity) -> Value {
    json!({
        "common_flags": identity.common_flags,
        "node_id": hex_u64(identity.node_id),
        "boot_id": hex_u64(identity.boot_id),
        "scan_sequence": identity.scan_sequence,
        "uptime_ms": identity.uptime_ms.to_string(),
        "config_id": hex_u64(identity.config_id),
        "reset_cause_flags": identity.reset_cause_flags,
    })
}

fn hex_u64(value: u64) -> String {
    format!("{value:016x}")
}

/// Failure while rendering a protocol-v2 record.
#[derive(Debug)]
pub enum V2RenderError {
    Codec(vesta_protocol::v2::Error),
    Json(serde_json::Error),
}

impl fmt::Display for V2RenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "invalid profile fragment: {error}"),
            Self::Json(error) => write!(formatter, "could not serialize v2 record: {error}"),
        }
    }
}

impl std::error::Error for V2RenderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(_) => None,
            Self::Json(error) => Some(error),
        }
    }
}

impl From<vesta_protocol::v2::Error> for V2RenderError {
    fn from(error: vesta_protocol::v2::Error) -> Self {
        Self::Codec(error)
    }
}

impl From<serde_json::Error> for V2RenderError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

struct HumanReceivedFrame<'a> {
    frame: &'a TelemetryV1,
    radio: RadioMetadata,
}

impl fmt::Display for HumanReceivedFrame<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", HumanFrame(self.frame))?;
        writeln!(formatter)?;
        writeln!(formatter, "  radio:")?;
        writeln!(
            formatter,
            "    packet_rssi: {:.2} dBm",
            f32::from(self.radio.packet_rssi_centi_dbm) / 100.0
        )?;
        writeln!(
            formatter,
            "    snr: {:.2} dB",
            f32::from(self.radio.snr_centi_db) / 100.0
        )?;
        write!(
            formatter,
            "    signal_rssi: {:.2} dBm",
            f32::from(self.radio.signal_rssi_centi_dbm) / 100.0
        )
    }
}

#[derive(Serialize)]
struct JsonReceivedFrame {
    #[serde(flatten)]
    frame: JsonFrame,
    radio: RadioMetadata,
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
    /// A variable-size payload contains half of a byte.
    OddLength {
        /// Supplied count of hexadecimal characters.
        actual: usize,
    },
    /// A variable-size payload is too short or exceeds the `LoRa` PHY maximum.
    PayloadLength {
        /// Smallest accepted byte count.
        minimum: usize,
        /// Largest accepted byte count.
        maximum: usize,
        /// Supplied byte count.
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
            Self::OddLength { actual } => {
                write!(formatter, "odd hexadecimal length: got {actual} characters")
            }
            Self::PayloadLength {
                minimum,
                maximum,
                actual,
            } => write!(
                formatter,
                "payload length must be {minimum}..={maximum} bytes, got {actual}"
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

    #[test]
    fn received_output_includes_exact_radio_measurements() {
        let frame = decode_hex(FIXTURE).unwrap();
        let radio = RadioMetadata {
            packet_rssi_centi_dbm: -10_050,
            snr_centi_db: -125,
            signal_rssi_centi_dbm: -10_250,
        };

        let json = render_received(&frame, OutputFormat::JsonLines, radio).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["radio"]["packet_rssi_centi_dbm"], -10_050);
        assert_eq!(value["radio"]["snr_centi_db"], -125);
        assert_eq!(value["node_id"], "0102030405060708");

        let human = render_received(&frame, OutputFormat::Human, radio).unwrap();
        assert!(human.contains("packet_rssi: -100.50 dBm"));
        assert!(human.contains("snr: -1.25 dB"));
        assert!(human.contains("signal_rssi: -102.50 dBm"));
    }

    #[test]
    fn renders_preconfiguration_health_without_a_configuration_record() {
        let encoded = vesta_protocol::v2::encode_device_health(
            vesta_protocol::v2::Common::boot_id_unavailable(1, 7, 12, 0, 0),
            &vesta_protocol::v2::DeviceHealth {
                flags: vesta_protocol::v2::HEALTH_FLAG_BOOT_ID_UNAVAILABLE,
                reset_cause_raw: 0,
                successful_sensor_scans: 0,
                failed_sensor_scans: 1,
                incomplete_profiles: 0,
                i2c_errors: 1,
                radio_tx_errors: 0,
                dropped_profiles: 0,
                dropped_fragments: 0,
                overwritten_fields: 0,
                current_sample_interval_ms: 180_000,
                firmware_version: [2, 0, 0],
                profile_id: 0,
                profile_version: 0,
                last_sensor_error: 1,
                last_radio_error: 0,
                calibrated_mcu_temperature_centi_celsius: None,
                calibrated_vdd_millivolt: None,
            },
        )
        .unwrap();
        let decoded = vesta_protocol::v2::decode(encoded.as_slice()).unwrap();
        let json = render_v2(decoded, OutputFormat::JsonLines, None).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["frame_type"], "device_health");
        assert_eq!(value["record"]["identity"]["config_id"], "0000000000000000");
        assert_eq!(value["record"]["profile_id"], 0);
        assert_eq!(value["record"]["profile_version"], 0);
        assert!(value["radio"].is_null());
    }
}
