//! Allocation-free codec for Vesta telemetry protocol v2.
//!
//! Version 2 uses a distinct version byte, variable record lengths, and
//! deterministic profile fragmentation. The crate root retains the deployed
//! 48-byte v1 API unchanged.

use core::fmt;

pub const MAGIC: [u8; 2] = *b"VS";
pub const VERSION_V1: u8 = 1;
pub const VERSION_V2: u8 = 2;
pub const V1_FRAME_LEN: usize = 48;
pub const HEADER_LEN: usize = 48;
pub const MAX_PHY_FRAME_LEN: usize = 255;
pub const MAX_PROFILE_STEPS: usize = 10;
pub const MAX_PROFILE_STEPS_U8: u8 = 10;
pub const STEPS_PER_FRAGMENT: usize = 3;
pub const STEPS_PER_FRAGMENT_U8: u8 = 3;
pub const MAX_PROFILE_FRAGMENTS: usize = 4;
pub const PROFILE_STEP_LEN: usize = 47;
pub const PROFILE_FRAGMENT_META_LEN: usize = 42;
pub const MAX_PROFILE_FRAME_LEN: usize =
    HEADER_LEN + PROFILE_FRAGMENT_META_LEN + STEPS_PER_FRAGMENT * PROFILE_STEP_LEN;
pub const MAX_PROFILE_FRAME_LEN_U8: u8 = 231;
pub const CONFIG_BASE_LEN: usize = 83;
pub const CONFIG_STEP_LEN: usize = 10;
pub const MAX_CONFIG_FRAME_LEN: usize =
    HEADER_LEN + CONFIG_BASE_LEN + MAX_PROFILE_STEPS * CONFIG_STEP_LEN;
pub const MAX_V2_FRAME_LEN: usize = MAX_PROFILE_FRAME_LEN;
pub const MAX_V2_FRAME_LEN_U8: u8 = 231;
pub const HEALTH_BASE_LEN: usize = 54;
pub const MAX_HEALTH_EXTENSION_LEN: usize = 8;
pub const MAX_HEALTH_FRAME_LEN: usize = HEADER_LEN + HEALTH_BASE_LEN + MAX_HEALTH_EXTENSION_LEN;

pub const COMMON_FLAG_BOOT_ID_VALID: u8 = 0x01;
pub const COMMON_FLAG_BOOT_ID_FROM_HW_RNG: u8 = 0x02;
pub const COMMON_FLAG_CONFIG_REPEAT: u8 = 0x04;
const COMMON_FLAGS_KNOWN: u8 =
    COMMON_FLAG_BOOT_ID_VALID | COMMON_FLAG_BOOT_ID_FROM_HW_RNG | COMMON_FLAG_CONFIG_REPEAT;

pub const CONFIG_FLAG_CALIBRATION_HASH_VALID: u8 = 0x01;
pub const CONFIG_FLAG_SENSOR_CONFIG_READ_BACK: u8 = 0x02;
const CONFIG_FLAGS_KNOWN: u8 =
    CONFIG_FLAG_CALIBRATION_HASH_VALID | CONFIG_FLAG_SENSOR_CONFIG_READ_BACK;

/// Exact v2 frame bytes are emitted as `LoRa` P2P PHY payloads.
pub const OUTPUT_ROUTE_LORA_P2P: u8 = 1 << 0;
/// Exact v2 frame bytes are carried by the UART COBS + CRC32 stream envelope.
pub const OUTPUT_ROUTE_UART_COBS_CRC32: u8 = 1 << 1;
/// Exact v2 frame bytes are carried by the RTT length-delimited stream envelope.
pub const OUTPUT_ROUTE_RTT: u8 = 1 << 2;
const OUTPUT_ROUTES_KNOWN: u8 =
    OUTPUT_ROUTE_LORA_P2P | OUTPUT_ROUTE_UART_COBS_CRC32 | OUTPUT_ROUTE_RTT;

pub const BUILD_FLAG_ID_VALID: u8 = 0x01;
pub const BUILD_FLAG_DIRTY: u8 = 0x02;
pub const BUILD_FLAG_DEBUG_SLEEP: u8 = 0x04;
const BUILD_FLAGS_KNOWN: u8 = BUILD_FLAG_ID_VALID | BUILD_FLAG_DIRTY | BUILD_FLAG_DEBUG_SLEEP;

pub const COLLECTION_FLAG_TIMEOUT: u32 = 1 << 0;
pub const COLLECTION_FLAG_I2C_ERROR: u32 = 1 << 1;
pub const COLLECTION_FLAG_DUPLICATE: u32 = 1 << 2;
pub const COLLECTION_FLAG_OVERWRITTEN: u32 = 1 << 3;
pub const COLLECTION_FLAG_GAS_INDEX_OUT_OF_RANGE: u32 = 1 << 4;
pub const COLLECTION_FLAG_MEASUREMENT_DISCONTINUITY: u32 = 1 << 5;
pub const COLLECTION_FLAG_NO_NEW_DATA: u32 = 1 << 6;
pub const COLLECTION_FLAG_INVALID_GAS: u32 = 1 << 7;
pub const COLLECTION_FLAG_HEATER_UNSTABLE: u32 = 1 << 8;
pub const COLLECTION_FLAG_POLL_BUDGET_EXHAUSTED: u32 = 1 << 9;
pub const COLLECTION_FLAG_OBSERVATION_OVERFLOW: u32 = 1 << 10;
/// Firmware restored and read back the exact configuration before triggering
/// this scan. Receivers should reset temporal history, not reject the scan.
pub const COLLECTION_FLAG_SENSOR_RECONFIGURED: u32 = 1 << 11;
pub const COLLECTION_FLAG_CONFIG_MISMATCH: u32 = 1 << 12;
/// One or more `NEW_DATA` fields were drained before the configured scan
/// started. Their count is included in `intermediate_field_count`.
pub const COLLECTION_FLAG_STALE_PRE_SCAN_FIELDS: u32 = 1 << 13;
const COLLECTION_FLAGS_KNOWN: u32 = 0x0000_3fff;
pub const FINISH_REASON_COMPLETE: u8 = 0;
pub const FINISH_REASON_TIMEOUT: u8 = 1;
pub const FINISH_REASON_SENSOR_ERROR: u8 = 2;
pub const FINISH_REASON_POLL_BUDGET: u8 = 3;
pub const FINISH_REASON_PROFILE_ROLLOVER: u8 = 4;
const RESET_CAUSE_FLAGS_KNOWN: u16 = 0x00ff;
pub const HEALTH_FLAG_COUNTERS_SATURATED: u8 = 1 << 0;
pub const HEALTH_FLAG_BOOT_ID_UNAVAILABLE: u8 = 1 << 1;
pub const HEALTH_FLAG_CONFIG_MISMATCH: u8 = 1 << 2;
pub const HEALTH_FLAG_LAST_SCAN_INCOMPLETE: u8 = 1 << 3;
pub const HEALTH_FLAG_SENSOR_ERROR_SEEN: u8 = 1 << 4;
pub const HEALTH_FLAG_RADIO_ERROR_SEEN: u8 = 1 << 5;
const HEALTH_FLAGS_KNOWN: u8 = 0x3f;

const CONFIG_SCHEMA_VERSION: u8 = 1;
const PROFILE_SCHEMA_VERSION: u8 = 1;
const HEALTH_SCHEMA_VERSION: u8 = 1;

/// Record discriminator in a v2 common header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameType {
    DeviceConfig = 1,
    ProfileFragment = 2,
    DeviceHealth = 3,
}

impl TryFrom<u8> for FrameType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DeviceConfig),
            2 => Ok(Self::ProfileFragment),
            3 => Ok(Self::DeviceHealth),
            found => Err(Error::UnknownFrameType(found)),
        }
    }
}

/// Metadata repeated in every v2 radio frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Common {
    pub flags: u8,
    pub node_id: u64,
    pub boot_id: u64,
    pub scan_sequence: u32,
    /// Profile frames use the uptime at scan start. Config/health records use
    /// the uptime when that record snapshot was created.
    pub uptime_ms: u64,
    /// Stable hash of the verified configuration. Zero is a degraded sentinel:
    /// it is forbidden for `DeviceConfig`, and is accepted for health/profile
    /// records only under the explicit pre-configuration/mismatch rules.
    pub config_id: u64,
    pub reset_cause_flags: u16,
}

impl Common {
    #[must_use]
    pub const fn production(
        node_id: u64,
        boot_id: u64,
        scan_sequence: u32,
        uptime_ms: u64,
        config_id: u64,
        reset_cause_flags: u16,
    ) -> Self {
        Self {
            flags: COMMON_FLAG_BOOT_ID_VALID | COMMON_FLAG_BOOT_ID_FROM_HW_RNG,
            node_id,
            boot_id,
            scan_sequence,
            uptime_ms,
            config_id,
            reset_cause_flags,
        }
    }

    /// Construct a degraded header after a bounded hardware-RNG failure.
    /// `boot_id` is deliberately zero and both validity/source flags are clear.
    #[must_use]
    pub const fn boot_id_unavailable(
        node_id: u64,
        scan_sequence: u32,
        uptime_ms: u64,
        config_id: u64,
        reset_cause_flags: u16,
    ) -> Self {
        Self {
            flags: 0,
            node_id,
            boot_id: 0,
            scan_sequence,
            uptime_ms,
            config_id,
            reset_cause_flags,
        }
    }
}

/// Parsed common header. Unknown flag bits are retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub frame_type: FrameType,
    pub common: Common,
    pub fragment_index: u8,
    pub fragment_count: u8,
    pub payload_len: u16,
}

/// Fixed storage used by the MCU encoder. `len` is always at most 255.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedFrame {
    bytes: [u8; MAX_PHY_FRAME_LEN],
    len: u8,
}

impl EncodedFrame {
    const EMPTY: Self = Self {
        bytes: [0; MAX_PHY_FRAME_LEN],
        len: 0,
    };

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl AsRef<[u8]> for EncodedFrame {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// One exact programmed heater step in the configuration record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeaterStepConfig {
    pub target_temperature_celsius: u16,
    /// Effective configured duration. For Bosch parallel mode this is the
    /// repetition multiplier times `(quantized shared wait + TPHG duration)`.
    pub configured_duration_us: u32,
    /// Bosch parallel-mode TPHG repetition multiplier; zero outside parallel
    /// mode (and retains Bosch's special zero semantics if ever configured).
    pub repetition_multiplier: u8,
    /// Canonical `IDAC_HEATn` snapshot. This is read-only metadata, not an
    /// expected-value check; live profile-step readback may differ.
    pub readback_heater_current: u8,
    /// Read-back `RES_HEATn`; meaningful only when the corresponding bit in
    /// `heater_readback_valid_bitmap` is set.
    pub programmed_heater_resistance: u8,
    /// Read-back `GAS_WAITn`; meaningful only when the corresponding bit in
    /// `heater_readback_valid_bitmap` is set.
    pub programmed_gas_wait: u8,
}

/// Device, BME688 profile, firmware, cadence, and radio configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceConfig {
    pub flags: u8,
    pub firmware_version: [u8; 3],
    pub firmware_build_flags: u8,
    pub firmware_build_id: u64,
    pub sensor_chip_id: u8,
    pub sensor_variant: u8,
    pub sensor_i2c_address: u8,
    pub temperature_oversampling: u8,
    pub humidity_oversampling: u8,
    pub pressure_oversampling: u8,
    pub iir_filter: u8,
    pub standby_time: u8,
    pub operation_mode: u8,
    pub heater_enabled: u8,
    pub parallel_requested_shared_wait_ms: u16,
    pub parallel_shared_wait_register: u8,
    pub parallel_quantized_shared_wait_us: u32,
    pub tphg_duration_us: u32,
    pub expected_profile_duration_us: u32,
    pub profile_id: u16,
    pub profile_version: u16,
    pub expected_step_count: u8,
    /// A set bit means all three raw `IDAC/RES/GAS_WAIT` descriptor bytes were
    /// successfully read and transmitted. It does not mean IDAC matched a
    /// programmed expectation.
    pub heater_readback_valid_bitmap: u16,
    pub calibration_hash_algorithm: u8,
    pub calibration_hash: u64,
    pub scan_interval_ms: u32,
    pub config_repeat_interval_scans: u16,
    /// Bitmask of destinations that emit the exact v2 frame bytes. Multiple
    /// routes may be active in a laboratory build.
    pub output_routes: u8,
    pub radio_frequency_hz: u32,
    pub radio_tx_power_dbm: i8,
    pub radio_spreading_factor: u8,
    pub radio_bandwidth_hz: u32,
    pub radio_coding_rate_numerator: u8,
    pub radio_coding_rate_denominator: u8,
    pub radio_preamble_symbols: u16,
    /// `0` is explicit and `1` is implicit.
    pub radio_header_mode: u8,
    pub radio_phy_crc_enabled: u8,
    pub radio_iq_inverted: u8,
    pub radio_sync_word: u16,
    pub max_frame_len: u8,
    pub profile_steps_per_fragment: u8,
    pub steps: [HeaterStepConfig; MAX_PROFILE_STEPS],
}

/// Every raw and compensated value retained for one logical profile step.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProfileStep {
    pub step_index: u8,
    pub gas_index: u8,
    pub measurement_index: u8,
    /// Bosch-compatible combined flags. Current firmware emits only
    /// `NEW_DATA` (bit 7), `GAS_VALID` (bit 5), and `HEAT_STAB` (bit 4).
    /// Other bits remain representable for forward-compatible producers.
    pub status: u8,
    /// Unmodified BME688 `FIELDx[0]` byte. Physical measurement-index and
    /// reserved bits remain here instead of being folded into `status`.
    pub raw_measurement_status: u8,
    /// Unmodified variant-selected BME688 `FIELDx[14]` (Gas Low) or
    /// `FIELDx[16]` (Gas High) byte, including gas-index/range-adjacent bits.
    pub raw_gas_status: u8,
    pub target_temperature_celsius: u16,
    pub configured_duration_us: u32,
    pub offset_us: u32,
    pub temperature_centi_celsius: i16,
    pub pressure_pascal: u32,
    pub humidity_milli_percent_rh: u32,
    pub gas_resistance_ohm: u32,
    pub temperature_adc: u32,
    pub pressure_adc: u32,
    pub humidity_adc: u16,
    pub gas_resistance_adc: u16,
    pub gas_range: u8,
    pub repetition_multiplier: u8,
    pub heater_resistance: u8,
    pub heater_current: u8,
    pub gas_wait: u8,
}

/// Complete bounded scan passed to the deterministic fragment encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileScan {
    pub profile_id: u16,
    pub profile_version: u16,
    pub expected_step_count: u8,
    pub observed_unique_step_count: u8,
    /// Counts every new field observed, including duplicates. It saturates at
    /// `u16::MAX` and sets the observation-overflow collection flag.
    pub observed_field_count: u16,
    pub missing_steps_bitmap: u16,
    pub duplicate_steps_bitmap: u16,
    pub scan_duration_us: u32,
    pub collection_flags: u32,
    pub finish_reason: u8,
    pub duplicate_count: u16,
    pub overwritten_field_count: u16,
    pub out_of_order_count: u16,
    pub ambiguous_index_jump_count: u16,
    pub invalid_gas_index_count: u16,
    /// Total discarded nonterminal fields: in-scan intermediate/dummy fields
    /// plus stale `NEW_DATA` fields explicitly drained before scan start.
    pub intermediate_field_count: u16,
    pub profile_rollover_count: u16,
    pub fields_after_rollover_count: u16,
    pub poll_count: u16,
    /// A missing logical step is `None`; present steps must carry the matching
    /// `step_index`. This is intentionally not a compact vector.
    pub steps: [Option<ProfileStep>; MAX_PROFILE_STEPS],
}

/// Four fixed slots are enough for a 10-step scan at three steps per frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedProfile {
    frames: [EncodedFrame; MAX_PROFILE_FRAGMENTS],
    count: u8,
}

impl EncodedProfile {
    #[must_use]
    pub fn frames(&self) -> &[EncodedFrame] {
        &self.frames[..usize::from(self.count)]
    }
}

/// Periodic counters and reset/diagnostic snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceHealth {
    pub flags: u8,
    /// Exact RCC reset-status register captured before it was cleared.
    pub reset_cause_raw: u32,
    pub successful_sensor_scans: u32,
    pub failed_sensor_scans: u32,
    pub incomplete_profiles: u32,
    pub i2c_errors: u32,
    pub radio_tx_errors: u32,
    pub dropped_profiles: u32,
    pub dropped_fragments: u32,
    pub overwritten_fields: u32,
    pub current_sample_interval_ms: u32,
    pub firmware_version: [u8; 3],
    /// Requested/current profile. Both identity fields are zero only for a
    /// pre-configuration health attempt whose common config ID is also zero.
    pub profile_id: u16,
    pub profile_version: u16,
    pub last_sensor_error: u16,
    pub last_radio_error: u16,
    /// Omitted from the wire when absent. Presence means firmware used the
    /// STM32 factory-calibration procedure, not an uncalibrated ADC guess.
    pub calibrated_mcu_temperature_centi_celsius: Option<i16>,
    /// This is regulated VDD, never battery voltage or state of charge.
    /// Omitted from the wire when factory-calibrated VREFINT is unavailable.
    pub calibrated_vdd_millivolt: Option<u16>,
}

/// Borrowed decoder result. No record needs allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedFrame<'a> {
    DeviceConfig {
        header: Header,
        config: DeviceConfig,
    },
    ProfileFragment(ProfileFragmentView<'a>),
    DeviceHealth {
        header: Header,
        health: DeviceHealth,
    },
}

/// Validated profile-fragment metadata and borrowed step bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileFragmentView<'a> {
    pub header: Header,
    pub profile_id: u16,
    pub profile_version: u16,
    pub expected_step_count: u8,
    pub observed_unique_step_count: u8,
    pub observed_field_count: u16,
    pub missing_steps_bitmap: u16,
    pub duplicate_steps_bitmap: u16,
    pub scan_duration_us: u32,
    pub collection_flags: u32,
    pub finish_reason: u8,
    pub duplicate_count: u16,
    pub overwritten_field_count: u16,
    pub out_of_order_count: u16,
    pub ambiguous_index_jump_count: u16,
    pub invalid_gas_index_count: u16,
    /// Total discarded nonterminal fields, including stale pre-scan fields
    /// when `COLLECTION_FLAG_STALE_PRE_SCAN_FIELDS` is set.
    pub intermediate_field_count: u16,
    pub profile_rollover_count: u16,
    pub fields_after_rollover_count: u16,
    pub poll_count: u16,
    pub step_window_start: u8,
    pub steps_in_fragment: u8,
    step_bytes: &'a [u8],
}

impl ProfileFragmentView<'_> {
    /// Return one step by its fragment-local index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StepIndexOutOfBounds`] when `local_index` is not
    /// present in this fragment.
    pub fn step(&self, local_index: usize) -> Result<ProfileStep, Error> {
        if local_index >= usize::from(self.steps_in_fragment) {
            return Err(Error::StepIndexOutOfBounds);
        }
        let offset = local_index * PROFILE_STEP_LEN;
        decode_step(&self.step_bytes[offset..offset + PROFILE_STEP_LEN])
    }
}

/// Codec or structural validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongLength { expected: usize, actual: usize },
    FrameTooLong(usize),
    InvalidMagic([u8; 2]),
    UnsupportedVersion(u8),
    InvalidHeaderLength(u8),
    UnknownFrameType(u8),
    InvalidFragmentCount(u8),
    InvalidFragmentIndex { index: u8, count: u8 },
    InvalidField(&'static str),
    UnknownFlags { field: &'static str, bits: u32 },
    ConfigIdMismatch { header: u64, calculated: u64 },
    StepIndexOutOfBounds,
    BufferExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

/// Encode a canonical one-frame configuration record. Its config ID is the
/// FNV-1a-64 hash of the canonical configuration payload, so volatile common
/// fields (boot ID, uptime, reset cause, repetition time) do not alter it.
///
/// # Errors
///
/// Returns an [`Error`] for unsupported flags, inconsistent optional fields,
/// an invalid step count, or a frame that cannot fit in one PHY packet.
pub fn encode_device_config(
    mut common: Common,
    config: &DeviceConfig,
    repeated: bool,
) -> Result<EncodedFrame, Error> {
    validate_config(config)?;
    let payload_len = CONFIG_BASE_LEN + usize::from(config.expected_step_count) * CONFIG_STEP_LEN;
    let mut frame = EncodedFrame::EMPTY;
    {
        let mut writer = Writer::new(&mut frame.bytes[HEADER_LEN..HEADER_LEN + payload_len]);
        write_config_payload(&mut writer, config)?;
        writer.finish()?;
    }
    common.config_id = device_config_id(config)?;
    if repeated {
        common.flags |= COMMON_FLAG_CONFIG_REPEAT;
    }
    encode_header(
        &mut frame.bytes[..HEADER_LEN],
        FrameType::DeviceConfig,
        common,
        0,
        1,
        payload_len,
    )?;
    frame.len = u8::try_from(HEADER_LEN + payload_len)
        .map_err(|_| Error::FrameTooLong(HEADER_LEN + payload_len))?;
    Ok(frame)
}

/// Calculate the stable ID used to associate profile and health records with
/// the exact canonical configuration payload.
///
/// # Errors
///
/// Returns an [`Error`] when the configuration is not canonically encodable.
pub fn device_config_id(config: &DeviceConfig) -> Result<u64, Error> {
    validate_config(config)?;
    let payload_len = CONFIG_BASE_LEN + usize::from(config.expected_step_count) * CONFIG_STEP_LEN;
    let mut bytes = [0_u8; CONFIG_BASE_LEN + MAX_PROFILE_STEPS * CONFIG_STEP_LEN];
    let mut writer = Writer::new(&mut bytes[..payload_len]);
    write_config_payload(&mut writer, config)?;
    writer.finish()?;
    let config_id = fnv1a64(&bytes[..payload_len]);
    if config_id == 0 {
        return Err(Error::InvalidField("reserved_config_id"));
    }
    Ok(config_id)
}

/// Encode all deterministic fragments for a logical profile. Logical steps
/// 0..2 always belong to fragment 0, 3..5 to fragment 1, 6..8 to fragment 2,
/// and 9 to fragment 3. Missing readings therefore cannot shift later
/// readings between packets.
///
/// # Errors
///
/// Returns an [`Error`] when scan metadata and fixed step slots disagree, a
/// bitmap references an impossible step, or the common header is invalid.
pub fn encode_profile(common: Common, scan: &ProfileScan) -> Result<EncodedProfile, Error> {
    validate_profile(scan)?;
    validate_profile_config_identity(common, scan.collection_flags, scan.finish_reason)?;
    let fragment_count = profile_fragment_count(scan.expected_step_count)?;
    let mut output = EncodedProfile {
        frames: [EncodedFrame::EMPTY; MAX_PROFILE_FRAGMENTS],
        count: fragment_count,
    };

    for fragment_index in 0..fragment_count {
        let window_start = usize::from(fragment_index) * STEPS_PER_FRAGMENT;
        let window_end = core::cmp::min(
            window_start + STEPS_PER_FRAGMENT,
            usize::from(scan.expected_step_count),
        );
        let steps_in_fragment = scan.steps[window_start..window_end]
            .iter()
            .filter(|step| step.is_some())
            .count();
        let payload_len = PROFILE_FRAGMENT_META_LEN + steps_in_fragment * PROFILE_STEP_LEN;
        let frame = &mut output.frames[usize::from(fragment_index)];
        encode_header(
            &mut frame.bytes[..HEADER_LEN],
            FrameType::ProfileFragment,
            common,
            fragment_index,
            fragment_count,
            payload_len,
        )?;
        {
            let payload = &mut frame.bytes[HEADER_LEN..HEADER_LEN + payload_len];
            let mut writer = Writer::new(payload);
            writer.u8(PROFILE_SCHEMA_VERSION)?;
            writer.u8(u8::try_from(steps_in_fragment)
                .map_err(|_| Error::InvalidField("steps_in_fragment"))?)?;
            writer.u16(scan.profile_id)?;
            writer.u16(scan.profile_version)?;
            writer.u8(scan.expected_step_count)?;
            writer.u8(scan.observed_unique_step_count)?;
            writer.u16(scan.observed_field_count)?;
            writer.u16(scan.missing_steps_bitmap)?;
            writer.u16(scan.duplicate_steps_bitmap)?;
            writer.u32(scan.scan_duration_us)?;
            writer.u32(scan.collection_flags)?;
            writer.u8(scan.finish_reason)?;
            writer.u16(scan.duplicate_count)?;
            writer.u16(scan.overwritten_field_count)?;
            writer.u16(scan.out_of_order_count)?;
            writer.u16(scan.ambiguous_index_jump_count)?;
            writer.u16(scan.invalid_gas_index_count)?;
            writer.u16(scan.intermediate_field_count)?;
            writer.u16(scan.profile_rollover_count)?;
            writer.u16(scan.fields_after_rollover_count)?;
            writer.u16(scan.poll_count)?;
            writer
                .u8(u8::try_from(window_start)
                    .map_err(|_| Error::InvalidField("step_window_start"))?)?;
            for step in scan.steps[window_start..window_end].iter().flatten() {
                write_step(&mut writer, step)?;
            }
            writer.finish()?;
        }
        frame.len = u8::try_from(HEADER_LEN + payload_len)
            .map_err(|_| Error::FrameTooLong(HEADER_LEN + payload_len))?;
    }
    Ok(output)
}

/// Encode one periodic health snapshot. Calibrated internal measurements are
/// optional TLVs and are absent—not zero-filled—when unsupported.
///
/// # Errors
///
/// Returns an [`Error`] when common-header metadata is invalid or the encoded
/// record cannot fit in one PHY packet.
pub fn encode_device_health(common: Common, health: &DeviceHealth) -> Result<EncodedFrame, Error> {
    validate_health_flags(common, health.flags)?;
    validate_health_config_identity(common, health)?;
    let extension_len = usize::from(health.calibrated_mcu_temperature_centi_celsius.is_some()) * 4
        + usize::from(health.calibrated_vdd_millivolt.is_some()) * 4;
    let payload_len = HEALTH_BASE_LEN + extension_len;
    let mut frame = EncodedFrame::EMPTY;
    encode_header(
        &mut frame.bytes[..HEADER_LEN],
        FrameType::DeviceHealth,
        common,
        0,
        1,
        payload_len,
    )?;
    {
        let mut writer = Writer::new(&mut frame.bytes[HEADER_LEN..HEADER_LEN + payload_len]);
        writer.u8(HEALTH_SCHEMA_VERSION)?;
        writer.u8(health.flags)?;
        writer.u32(health.reset_cause_raw)?;
        writer.u32(health.successful_sensor_scans)?;
        writer.u32(health.failed_sensor_scans)?;
        writer.u32(health.incomplete_profiles)?;
        writer.u32(health.i2c_errors)?;
        writer.u32(health.radio_tx_errors)?;
        writer.u32(health.dropped_profiles)?;
        writer.u32(health.dropped_fragments)?;
        writer.u32(health.overwritten_fields)?;
        writer.u32(health.current_sample_interval_ms)?;
        writer.bytes(&health.firmware_version)?;
        writer.u16(health.profile_id)?;
        writer.u16(health.profile_version)?;
        writer.u16(health.last_sensor_error)?;
        writer.u16(health.last_radio_error)?;
        writer
            .u8(u8::try_from(extension_len)
                .map_err(|_| Error::InvalidField("health_extension_len"))?)?;
        if let Some(value) = health.calibrated_mcu_temperature_centi_celsius {
            writer.u8(1)?;
            writer.u8(2)?;
            writer.i16(value)?;
        }
        if let Some(value) = health.calibrated_vdd_millivolt {
            writer.u8(2)?;
            writer.u8(2)?;
            writer.u16(value)?;
        }
        writer.finish()?;
    }
    frame.len = u8::try_from(HEADER_LEN + payload_len)
        .map_err(|_| Error::FrameTooLong(HEADER_LEN + payload_len))?;
    Ok(frame)
}

/// Decode and structurally validate any v2 record. It rejects truncation,
/// trailing bytes, impossible fragment coordinates, and non-canonical profile
/// fragments without indexing outside the supplied slice.
///
/// # Errors
///
/// Returns an [`Error`] for malformed framing, unsupported record values,
/// inconsistent lengths, or invalid record-specific structure.
pub fn decode(bytes: &[u8]) -> Result<DecodedFrame<'_>, Error> {
    let header = decode_header(bytes)?;
    let payload = &bytes[HEADER_LEN..];
    match header.frame_type {
        FrameType::DeviceConfig => {
            let config = decode_device_config(header, payload)?;
            Ok(DecodedFrame::DeviceConfig { header, config })
        }
        FrameType::ProfileFragment => {
            decode_profile_fragment(header, payload).map(DecodedFrame::ProfileFragment)
        }
        FrameType::DeviceHealth => {
            let health = decode_device_health(header, payload)?;
            Ok(DecodedFrame::DeviceHealth { header, health })
        }
    }
}

/// Exact `LoRa` packet duration rounded up to the next microsecond.
///
/// `coding_rate_denominator` is 5..8 for 4/5..4/8. The calculation follows
/// Semtech's explicit-header payload-symbol equation.
///
/// # Errors
///
/// Returns an [`Error`] for an oversized payload or unsupported radio
/// parameters.
pub fn lora_time_on_air_us(
    payload_len: usize,
    spreading_factor: u8,
    bandwidth_hz: u32,
    coding_rate_denominator: u8,
    preamble_symbols: u16,
    explicit_header: bool,
    crc_enabled: bool,
) -> Result<u64, Error> {
    if payload_len > MAX_PHY_FRAME_LEN {
        return Err(Error::FrameTooLong(payload_len));
    }
    if !(5..=12).contains(&spreading_factor) {
        return Err(Error::InvalidField("spreading_factor"));
    }
    if bandwidth_hz == 0 {
        return Err(Error::InvalidField("bandwidth_hz"));
    }
    if !(5..=8).contains(&coding_rate_denominator) {
        return Err(Error::InvalidField("coding_rate_denominator"));
    }

    let symbol_numerator = (1_u64 << spreading_factor) * 1_000_000;
    let low_data_rate_optimization = symbol_numerator >= 16_000 * u64::from(bandwidth_hz);
    let ih = i64::from(!explicit_header);
    let crc = i64::from(crc_enabled);
    let de = i64::from(low_data_rate_optimization);
    let numerator = 8 * i64::try_from(payload_len).map_err(|_| Error::FrameTooLong(payload_len))?
        - 4 * i64::from(spreading_factor)
        + 28
        + 16 * crc
        - 20 * ih;
    let denominator = 4 * (i64::from(spreading_factor) - 2 * de);
    let coded_blocks = if numerator <= 0 {
        0
    } else {
        (numerator + denominator - 1) / denominator
    };
    let payload_symbols = 8_u64
        + u64::try_from(coded_blocks).map_err(|_| Error::InvalidField("coded_blocks"))?
            * u64::from(coding_rate_denominator);
    // Preamble duration is preamble + 4.25 symbols. Work in quarter symbols.
    let total_quarter_symbols = 4 * (u64::from(preamble_symbols) + payload_symbols) + 17;
    let airtime_numerator = total_quarter_symbols * symbol_numerator;
    let airtime_denominator = 4 * u64::from(bandwidth_hz);
    Ok(airtime_numerator.div_ceil(airtime_denominator))
}

#[must_use]
pub const fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    hash
}

fn validate_config(config: &DeviceConfig) -> Result<(), Error> {
    ensure_known_u8("config_flags", config.flags, CONFIG_FLAGS_KNOWN)?;
    ensure_known_u8(
        "firmware_build_flags",
        config.firmware_build_flags,
        BUILD_FLAGS_KNOWN,
    )?;
    ensure_known_u8("output_routes", config.output_routes, OUTPUT_ROUTES_KNOWN)?;
    if config.output_routes == 0 {
        return Err(Error::InvalidField("output_routes"));
    }
    if config.profile_id == 0 || config.profile_version == 0 {
        return Err(Error::InvalidField("profile_identity"));
    }
    if config.sensor_variant != 0 && config.sensor_variant != 1 && config.sensor_variant != u8::MAX
    {
        return Err(Error::InvalidField("sensor_variant"));
    }
    if config.temperature_oversampling > 5
        || config.humidity_oversampling > 5
        || config.pressure_oversampling > 5
    {
        return Err(Error::InvalidField("oversampling"));
    }
    if config.iir_filter > 7 {
        return Err(Error::InvalidField("iir_filter"));
    }
    if config.standby_time > 8 {
        return Err(Error::InvalidField("standby_time"));
    }
    if !(1..=3).contains(&config.operation_mode) {
        return Err(Error::InvalidField("operation_mode"));
    }
    if !(1..=MAX_PROFILE_STEPS_U8).contains(&config.expected_step_count) {
        return Err(Error::InvalidField("expected_step_count"));
    }
    let valid_step_mask = step_mask(config.expected_step_count);
    if config.heater_readback_valid_bitmap & !valid_step_mask != 0 {
        return Err(Error::InvalidField("heater_readback_valid_bitmap"));
    }
    if config.heater_enabled > 1
        || config.radio_phy_crc_enabled > 1
        || config.radio_iq_inverted > 1
        || config.radio_header_mode > 1
    {
        return Err(Error::InvalidField("boolean"));
    }
    if config.profile_steps_per_fragment != STEPS_PER_FRAGMENT_U8 {
        return Err(Error::InvalidField("profile_steps_per_fragment"));
    }
    if usize::from(config.max_frame_len) != MAX_V2_FRAME_LEN {
        return Err(Error::InvalidField("max_frame_len"));
    }
    if config.flags & CONFIG_FLAG_CALIBRATION_HASH_VALID == 0 {
        if config.calibration_hash_algorithm != 0 || config.calibration_hash != 0 {
            return Err(Error::InvalidField("calibration_hash"));
        }
    } else if config.calibration_hash_algorithm != 1 {
        return Err(Error::InvalidField("calibration_hash_algorithm"));
    }
    if config.firmware_build_flags & BUILD_FLAG_ID_VALID == 0 && config.firmware_build_id != 0 {
        return Err(Error::InvalidField("firmware_build_id"));
    }
    if !(5..=12).contains(&config.radio_spreading_factor) {
        return Err(Error::InvalidField("radio_spreading_factor"));
    }
    if config.radio_bandwidth_hz == 0 {
        return Err(Error::InvalidField("radio_bandwidth_hz"));
    }
    if config.radio_coding_rate_numerator != 4
        || !(5..=8).contains(&config.radio_coding_rate_denominator)
    {
        return Err(Error::InvalidField("radio_coding_rate"));
    }
    if config.radio_preamble_symbols == 0 {
        return Err(Error::InvalidField("radio_preamble_symbols"));
    }
    for (index, step) in config.steps.iter().enumerate() {
        if index >= usize::from(config.expected_step_count) && *step != HeaterStepConfig::default()
        {
            return Err(Error::InvalidField("unused_heater_step"));
        }
        if index < usize::from(config.expected_step_count)
            && config.heater_readback_valid_bitmap & (1 << index) == 0
            && (step.readback_heater_current != 0
                || step.programmed_heater_resistance != 0
                || step.programmed_gas_wait != 0)
        {
            return Err(Error::InvalidField("unverified_heater_readback"));
        }
    }
    Ok(())
}

fn validate_profile(scan: &ProfileScan) -> Result<(), Error> {
    if scan.profile_id == 0 || scan.profile_version == 0 {
        return Err(Error::InvalidField("profile_identity"));
    }
    if !(1..=MAX_PROFILE_STEPS_U8).contains(&scan.expected_step_count) {
        return Err(Error::InvalidField("expected_step_count"));
    }
    ensure_known_u32(
        "collection_flags",
        scan.collection_flags,
        COLLECTION_FLAGS_KNOWN,
    )?;
    if scan.finish_reason > FINISH_REASON_PROFILE_ROLLOVER {
        return Err(Error::InvalidField("finish_reason"));
    }
    if scan.collection_flags & COLLECTION_FLAG_STALE_PRE_SCAN_FIELDS != 0
        && scan.intermediate_field_count == 0
    {
        return Err(Error::InvalidField("stale_pre_scan_fields"));
    }
    let valid_mask = step_mask(scan.expected_step_count);
    if scan.missing_steps_bitmap & !valid_mask != 0
        || scan.duplicate_steps_bitmap & !valid_mask != 0
    {
        return Err(Error::InvalidField("step_bitmap"));
    }
    let observed = scan.expected_step_count
        - u8::try_from(scan.missing_steps_bitmap.count_ones())
            .map_err(|_| Error::InvalidField("missing_steps_bitmap"))?;
    if observed != scan.observed_unique_step_count {
        return Err(Error::InvalidField("observed_unique_step_count"));
    }
    if scan.observed_field_count < u16::from(observed) {
        return Err(Error::InvalidField("observed_field_count"));
    }
    for index in 0..MAX_PROFILE_STEPS {
        let expected_present = index < usize::from(scan.expected_step_count)
            && scan.missing_steps_bitmap & (1 << index) == 0;
        match (expected_present, scan.steps[index]) {
            (true, Some(step)) if usize::from(step.step_index) == index => {
                validate_profile_step(&step)?;
            }
            (false, None) => {}
            _ => return Err(Error::InvalidField("profile_step_presence")),
        }
    }
    Ok(())
}

fn validate_profile_config_identity(
    common: Common,
    collection_flags: u32,
    finish_reason: u8,
) -> Result<(), Error> {
    if common.config_id == 0
        && (collection_flags & COLLECTION_FLAG_CONFIG_MISMATCH == 0
            || finish_reason == FINISH_REASON_COMPLETE)
    {
        return Err(Error::InvalidField("profile_config_id_status"));
    }
    Ok(())
}

fn profile_fragment_count(expected_step_count: u8) -> Result<u8, Error> {
    if !(1..=MAX_PROFILE_STEPS_U8).contains(&expected_step_count) {
        return Err(Error::InvalidField("expected_step_count"));
    }
    Ok(expected_step_count.div_ceil(STEPS_PER_FRAGMENT_U8))
}

fn write_config_payload(writer: &mut Writer<'_>, config: &DeviceConfig) -> Result<(), Error> {
    writer.u8(CONFIG_SCHEMA_VERSION)?;
    writer.u8(config.flags)?;
    writer.bytes(&config.firmware_version)?;
    writer.u8(config.firmware_build_flags)?;
    writer.u64(config.firmware_build_id)?;
    writer.u8(config.sensor_chip_id)?;
    writer.u8(config.sensor_variant)?;
    writer.u8(config.sensor_i2c_address)?;
    writer.u8(config.temperature_oversampling)?;
    writer.u8(config.humidity_oversampling)?;
    writer.u8(config.pressure_oversampling)?;
    writer.u8(config.iir_filter)?;
    writer.u8(config.standby_time)?;
    writer.u8(config.operation_mode)?;
    writer.u8(config.heater_enabled)?;
    writer.u16(config.parallel_requested_shared_wait_ms)?;
    writer.u8(config.parallel_shared_wait_register)?;
    writer.u32(config.parallel_quantized_shared_wait_us)?;
    writer.u32(config.tphg_duration_us)?;
    writer.u32(config.expected_profile_duration_us)?;
    writer.u16(config.profile_id)?;
    writer.u16(config.profile_version)?;
    writer.u8(config.expected_step_count)?;
    writer.u16(config.heater_readback_valid_bitmap)?;
    writer.u8(config.calibration_hash_algorithm)?;
    writer.u64(config.calibration_hash)?;
    writer.u32(config.scan_interval_ms)?;
    writer.u16(config.config_repeat_interval_scans)?;
    writer.u8(config.output_routes)?;
    writer.u32(config.radio_frequency_hz)?;
    writer.i8(config.radio_tx_power_dbm)?;
    writer.u8(config.radio_spreading_factor)?;
    writer.u32(config.radio_bandwidth_hz)?;
    writer.u8(config.radio_coding_rate_numerator)?;
    writer.u8(config.radio_coding_rate_denominator)?;
    writer.u16(config.radio_preamble_symbols)?;
    writer.u8(config.radio_header_mode)?;
    writer.u8(config.radio_phy_crc_enabled)?;
    writer.u8(config.radio_iq_inverted)?;
    writer.u16(config.radio_sync_word)?;
    writer.u8(config.max_frame_len)?;
    writer.u8(config.profile_steps_per_fragment)?;
    for step in &config.steps[..usize::from(config.expected_step_count)] {
        writer.u16(step.target_temperature_celsius)?;
        writer.u32(step.configured_duration_us)?;
        writer.u8(step.repetition_multiplier)?;
        writer.u8(step.readback_heater_current)?;
        writer.u8(step.programmed_heater_resistance)?;
        writer.u8(step.programmed_gas_wait)?;
    }
    Ok(())
}

fn write_step(writer: &mut Writer<'_>, step: &ProfileStep) -> Result<(), Error> {
    writer.u8(step.step_index)?;
    writer.u8(step.gas_index)?;
    writer.u8(step.measurement_index)?;
    writer.u8(step.status)?;
    writer.u8(step.raw_measurement_status)?;
    writer.u8(step.raw_gas_status)?;
    writer.u16(step.target_temperature_celsius)?;
    writer.u32(step.configured_duration_us)?;
    writer.u32(step.offset_us)?;
    writer.i16(step.temperature_centi_celsius)?;
    writer.u32(step.pressure_pascal)?;
    writer.u32(step.humidity_milli_percent_rh)?;
    writer.u32(step.gas_resistance_ohm)?;
    writer.u32(step.temperature_adc)?;
    writer.u32(step.pressure_adc)?;
    writer.u16(step.humidity_adc)?;
    writer.u16(step.gas_resistance_adc)?;
    writer.u8(step.gas_range)?;
    writer.u8(step.repetition_multiplier)?;
    writer.u8(step.heater_resistance)?;
    writer.u8(step.heater_current)?;
    writer.u8(step.gas_wait)?;
    Ok(())
}

fn decode_step(bytes: &[u8]) -> Result<ProfileStep, Error> {
    if bytes.len() != PROFILE_STEP_LEN {
        return Err(Error::WrongLength {
            expected: PROFILE_STEP_LEN,
            actual: bytes.len(),
        });
    }
    let mut reader = Reader::new(bytes);
    let step = ProfileStep {
        step_index: reader.u8()?,
        gas_index: reader.u8()?,
        measurement_index: reader.u8()?,
        status: reader.u8()?,
        raw_measurement_status: reader.u8()?,
        raw_gas_status: reader.u8()?,
        target_temperature_celsius: reader.u16()?,
        configured_duration_us: reader.u32()?,
        offset_us: reader.u32()?,
        temperature_centi_celsius: reader.i16()?,
        pressure_pascal: reader.u32()?,
        humidity_milli_percent_rh: reader.u32()?,
        gas_resistance_ohm: reader.u32()?,
        temperature_adc: reader.u32()?,
        pressure_adc: reader.u32()?,
        humidity_adc: reader.u16()?,
        gas_resistance_adc: reader.u16()?,
        gas_range: reader.u8()?,
        repetition_multiplier: reader.u8()?,
        heater_resistance: reader.u8()?,
        heater_current: reader.u8()?,
        gas_wait: reader.u8()?,
    };
    reader.finish()?;
    validate_profile_step(&step)?;
    Ok(step)
}

fn validate_profile_step(step: &ProfileStep) -> Result<(), Error> {
    let raw_known_status = (step.raw_measurement_status & 0x80) | (step.raw_gas_status & 0x30);
    if step.status & 0xb0 != raw_known_status {
        return Err(Error::InvalidField("step_status_raw"));
    }
    if step.gas_index != step.raw_measurement_status & 0x0f {
        return Err(Error::InvalidField("step_gas_index_raw"));
    }
    if step.gas_range != step.raw_gas_status & 0x0f {
        return Err(Error::InvalidField("step_gas_range_raw"));
    }
    if step.gas_index != step.step_index {
        return Err(Error::InvalidField("step_gas_index"));
    }
    Ok(())
}

fn encode_header(
    bytes: &mut [u8],
    frame_type: FrameType,
    common: Common,
    fragment_index: u8,
    fragment_count: u8,
    payload_len: usize,
) -> Result<(), Error> {
    if bytes.len() != HEADER_LEN {
        return Err(Error::WrongLength {
            expected: HEADER_LEN,
            actual: bytes.len(),
        });
    }
    if fragment_count == 0 {
        return Err(Error::InvalidFragmentCount(fragment_count));
    }
    if fragment_index >= fragment_count {
        return Err(Error::InvalidFragmentIndex {
            index: fragment_index,
            count: fragment_count,
        });
    }
    ensure_known_u8("common_flags", common.flags, COMMON_FLAGS_KNOWN)?;
    if common.flags & COMMON_FLAG_BOOT_ID_FROM_HW_RNG != 0
        && common.flags & COMMON_FLAG_BOOT_ID_VALID == 0
    {
        return Err(Error::InvalidField("boot_id_flags"));
    }
    if common.flags & COMMON_FLAG_BOOT_ID_VALID == 0 && common.boot_id != 0 {
        return Err(Error::InvalidField("invalid_boot_id_value"));
    }
    ensure_known_u16(
        "reset_cause_flags",
        common.reset_cause_flags,
        RESET_CAUSE_FLAGS_KNOWN,
    )?;
    let total_len = HEADER_LEN + payload_len;
    if total_len > MAX_PHY_FRAME_LEN {
        return Err(Error::FrameTooLong(total_len));
    }
    let mut writer = Writer::new(bytes);
    writer.bytes(&MAGIC)?;
    writer.u8(VERSION_V2)?;
    writer.u8(frame_type as u8)?;
    writer.u8(48)?;
    writer.u8(common.flags)?;
    writer.u8(fragment_index)?;
    writer.u8(fragment_count)?;
    writer.u16(u16::try_from(payload_len).map_err(|_| Error::FrameTooLong(total_len))?)?;
    writer.u64(common.node_id)?;
    writer.u64(common.boot_id)?;
    writer.u32(common.scan_sequence)?;
    writer.u64(common.uptime_ms)?;
    writer.u64(common.config_id)?;
    writer.u16(common.reset_cause_flags)?;
    writer.finish()
}

fn decode_header(bytes: &[u8]) -> Result<Header, Error> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::WrongLength {
            expected: HEADER_LEN,
            actual: bytes.len(),
        });
    }
    let mut reader = Reader::new(&bytes[..HEADER_LEN]);
    let found_magic = [reader.u8()?, reader.u8()?];
    if found_magic != MAGIC {
        return Err(Error::InvalidMagic(found_magic));
    }
    let version = reader.u8()?;
    if version != VERSION_V2 {
        return Err(Error::UnsupportedVersion(version));
    }
    let frame_type = FrameType::try_from(reader.u8()?)?;
    let header_len = reader.u8()?;
    if usize::from(header_len) != HEADER_LEN {
        return Err(Error::InvalidHeaderLength(header_len));
    }
    let flags = reader.u8()?;
    ensure_known_u8("common_flags", flags, COMMON_FLAGS_KNOWN)?;
    let fragment_index = reader.u8()?;
    let fragment_count = reader.u8()?;
    if fragment_count == 0 {
        return Err(Error::InvalidFragmentCount(fragment_count));
    }
    if fragment_index >= fragment_count {
        return Err(Error::InvalidFragmentIndex {
            index: fragment_index,
            count: fragment_count,
        });
    }
    let payload_len = reader.u16()?;
    let node_id = reader.u64()?;
    let boot_id = reader.u64()?;
    let scan_sequence = reader.u32()?;
    let uptime_ms = reader.u64()?;
    let config_id = reader.u64()?;
    let reset_cause_flags = reader.u16()?;
    reader.finish()?;
    ensure_known_u16(
        "reset_cause_flags",
        reset_cause_flags,
        RESET_CAUSE_FLAGS_KNOWN,
    )?;
    if flags & COMMON_FLAG_BOOT_ID_FROM_HW_RNG != 0 && flags & COMMON_FLAG_BOOT_ID_VALID == 0 {
        return Err(Error::InvalidField("boot_id_flags"));
    }
    if flags & COMMON_FLAG_BOOT_ID_VALID == 0 && boot_id != 0 {
        return Err(Error::InvalidField("invalid_boot_id_value"));
    }
    let expected_len = HEADER_LEN + usize::from(payload_len);
    if bytes.len() != expected_len {
        return Err(Error::WrongLength {
            expected: expected_len,
            actual: bytes.len(),
        });
    }
    Ok(Header {
        frame_type,
        common: Common {
            flags,
            node_id,
            boot_id,
            scan_sequence,
            uptime_ms,
            config_id,
            reset_cause_flags,
        },
        fragment_index,
        fragment_count,
        payload_len,
    })
}

fn validate_decoded_config(header: Header, payload: &[u8]) -> Result<(), Error> {
    if header.fragment_index != 0 || header.fragment_count != 1 {
        return Err(Error::InvalidField("unfragmented_record_coordinates"));
    }
    if payload.len() < CONFIG_BASE_LEN {
        return Err(Error::WrongLength {
            expected: CONFIG_BASE_LEN,
            actual: payload.len(),
        });
    }
    if payload[0] != CONFIG_SCHEMA_VERSION {
        return Err(Error::InvalidField("config_schema_version"));
    }
    let step_count = payload[43];
    if !(1..=MAX_PROFILE_STEPS_U8).contains(&step_count) {
        return Err(Error::InvalidField("expected_step_count"));
    }
    let expected_len = CONFIG_BASE_LEN + usize::from(step_count) * CONFIG_STEP_LEN;
    if payload.len() != expected_len {
        return Err(Error::WrongLength {
            expected: expected_len,
            actual: payload.len(),
        });
    }
    ensure_known_u8("config_flags", payload[1], CONFIG_FLAGS_KNOWN)?;
    ensure_known_u8("firmware_build_flags", payload[5], BUILD_FLAGS_KNOWN)?;
    if header.common.config_id == 0 {
        return Err(Error::InvalidField("reserved_config_id"));
    }
    let calculated = fnv1a64(payload);
    if calculated != header.common.config_id {
        return Err(Error::ConfigIdMismatch {
            header: header.common.config_id,
            calculated,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn decode_device_config(header: Header, payload: &[u8]) -> Result<DeviceConfig, Error> {
    validate_decoded_config(header, payload)?;
    let mut reader = Reader::new(payload);
    if reader.u8()? != CONFIG_SCHEMA_VERSION {
        return Err(Error::InvalidField("config_schema_version"));
    }
    let flags = reader.u8()?;
    let firmware_version = reader.take::<3>()?;
    let firmware_build_flags = reader.u8()?;
    let firmware_build_id = reader.u64()?;
    let sensor_chip_id = reader.u8()?;
    let sensor_variant = reader.u8()?;
    let sensor_i2c_address = reader.u8()?;
    let temperature_oversampling = reader.u8()?;
    let humidity_oversampling = reader.u8()?;
    let pressure_oversampling = reader.u8()?;
    let iir_filter = reader.u8()?;
    let standby_time = reader.u8()?;
    let operation_mode = reader.u8()?;
    let heater_enabled = reader.u8()?;
    let parallel_requested_shared_wait_ms = reader.u16()?;
    let parallel_shared_wait_register = reader.u8()?;
    let parallel_quantized_shared_wait_us = reader.u32()?;
    let tphg_duration_us = reader.u32()?;
    let expected_profile_duration_us = reader.u32()?;
    let profile_id = reader.u16()?;
    let profile_version = reader.u16()?;
    let expected_step_count = reader.u8()?;
    let heater_readback_valid_bitmap = reader.u16()?;
    let calibration_hash_algorithm = reader.u8()?;
    let calibration_hash = reader.u64()?;
    let scan_interval_ms = reader.u32()?;
    let config_repeat_interval_scans = reader.u16()?;
    let output_routes = reader.u8()?;
    let radio_frequency_hz = reader.u32()?;
    let radio_tx_power_dbm = reader.i8()?;
    let radio_spreading_factor = reader.u8()?;
    let radio_bandwidth_hz = reader.u32()?;
    let radio_coding_rate_numerator = reader.u8()?;
    let radio_coding_rate_denominator = reader.u8()?;
    let radio_preamble_symbols = reader.u16()?;
    let radio_header_mode = reader.u8()?;
    let radio_phy_crc_enabled = reader.u8()?;
    let radio_iq_inverted = reader.u8()?;
    let radio_sync_word = reader.u16()?;
    let max_frame_len = reader.u8()?;
    let profile_steps_per_fragment = reader.u8()?;
    let mut steps = [HeaterStepConfig::default(); MAX_PROFILE_STEPS];
    for step in &mut steps[..usize::from(expected_step_count)] {
        *step = HeaterStepConfig {
            target_temperature_celsius: reader.u16()?,
            configured_duration_us: reader.u32()?,
            repetition_multiplier: reader.u8()?,
            readback_heater_current: reader.u8()?,
            programmed_heater_resistance: reader.u8()?,
            programmed_gas_wait: reader.u8()?,
        };
    }
    reader.finish()?;
    let config = DeviceConfig {
        flags,
        firmware_version,
        firmware_build_flags,
        firmware_build_id,
        sensor_chip_id,
        sensor_variant,
        sensor_i2c_address,
        temperature_oversampling,
        humidity_oversampling,
        pressure_oversampling,
        iir_filter,
        standby_time,
        operation_mode,
        heater_enabled,
        parallel_requested_shared_wait_ms,
        parallel_shared_wait_register,
        parallel_quantized_shared_wait_us,
        tphg_duration_us,
        expected_profile_duration_us,
        profile_id,
        profile_version,
        expected_step_count,
        heater_readback_valid_bitmap,
        calibration_hash_algorithm,
        calibration_hash,
        scan_interval_ms,
        config_repeat_interval_scans,
        output_routes,
        radio_frequency_hz,
        radio_tx_power_dbm,
        radio_spreading_factor,
        radio_bandwidth_hz,
        radio_coding_rate_numerator,
        radio_coding_rate_denominator,
        radio_preamble_symbols,
        radio_header_mode,
        radio_phy_crc_enabled,
        radio_iq_inverted,
        radio_sync_word,
        max_frame_len,
        profile_steps_per_fragment,
        steps,
    };
    validate_config(&config)?;
    Ok(config)
}

#[allow(clippy::too_many_lines)]
fn decode_profile_fragment(
    header: Header,
    payload: &[u8],
) -> Result<ProfileFragmentView<'_>, Error> {
    if payload.len() < PROFILE_FRAGMENT_META_LEN {
        return Err(Error::WrongLength {
            expected: PROFILE_FRAGMENT_META_LEN,
            actual: payload.len(),
        });
    }
    let mut reader = Reader::new(payload);
    if reader.u8()? != PROFILE_SCHEMA_VERSION {
        return Err(Error::InvalidField("profile_schema_version"));
    }
    let steps_in_fragment = reader.u8()?;
    let profile_id = reader.u16()?;
    let profile_version = reader.u16()?;
    let expected_step_count = reader.u8()?;
    let observed_unique_step_count = reader.u8()?;
    let observed_field_count = reader.u16()?;
    let missing_steps_bitmap = reader.u16()?;
    let duplicate_steps_bitmap = reader.u16()?;
    let scan_duration_us = reader.u32()?;
    let collection_flags = reader.u32()?;
    let finish_reason = reader.u8()?;
    let duplicate_count = reader.u16()?;
    let overwritten_field_count = reader.u16()?;
    let out_of_order_count = reader.u16()?;
    let ambiguous_index_jump_count = reader.u16()?;
    let invalid_gas_index_count = reader.u16()?;
    let intermediate_field_count = reader.u16()?;
    let profile_rollover_count = reader.u16()?;
    let fields_after_rollover_count = reader.u16()?;
    let poll_count = reader.u16()?;
    let step_window_start = reader.u8()?;

    if !(1..=MAX_PROFILE_STEPS_U8).contains(&expected_step_count) {
        return Err(Error::InvalidField("expected_step_count"));
    }
    ensure_known_u32("collection_flags", collection_flags, COLLECTION_FLAGS_KNOWN)?;
    if profile_id == 0 || profile_version == 0 {
        return Err(Error::InvalidField("profile_identity"));
    }
    validate_profile_config_identity(header.common, collection_flags, finish_reason)?;
    if finish_reason > FINISH_REASON_PROFILE_ROLLOVER {
        return Err(Error::InvalidField("finish_reason"));
    }
    if collection_flags & COLLECTION_FLAG_STALE_PRE_SCAN_FIELDS != 0
        && intermediate_field_count == 0
    {
        return Err(Error::InvalidField("stale_pre_scan_fields"));
    }
    let required_fragment_count = profile_fragment_count(expected_step_count)?;
    if header.fragment_count != required_fragment_count {
        return Err(Error::InvalidFragmentCount(header.fragment_count));
    }
    let required_window_start = usize::from(header.fragment_index) * STEPS_PER_FRAGMENT;
    if usize::from(step_window_start) != required_window_start {
        return Err(Error::InvalidField("step_window_start"));
    }
    let valid_mask = step_mask(expected_step_count);
    if missing_steps_bitmap & !valid_mask != 0 || duplicate_steps_bitmap & !valid_mask != 0 {
        return Err(Error::InvalidField("step_bitmap"));
    }
    let required_observed = expected_step_count
        - u8::try_from(missing_steps_bitmap.count_ones())
            .map_err(|_| Error::InvalidField("missing_steps_bitmap"))?;
    if observed_unique_step_count != required_observed
        || observed_field_count < u16::from(required_observed)
    {
        return Err(Error::InvalidField("observed_counts"));
    }
    let window_end = core::cmp::min(
        required_window_start + STEPS_PER_FRAGMENT,
        usize::from(expected_step_count),
    );
    let mut required_steps = 0_u8;
    for index in required_window_start..window_end {
        if missing_steps_bitmap & (1 << index) == 0 {
            required_steps += 1;
        }
    }
    if steps_in_fragment != required_steps {
        return Err(Error::InvalidField("steps_in_fragment"));
    }
    let expected_payload_len =
        PROFILE_FRAGMENT_META_LEN + usize::from(steps_in_fragment) * PROFILE_STEP_LEN;
    if payload.len() != expected_payload_len {
        return Err(Error::WrongLength {
            expected: expected_payload_len,
            actual: payload.len(),
        });
    }
    let step_bytes = &payload[PROFILE_FRAGMENT_META_LEN..];
    let mut local = 0;
    for logical_index in required_window_start..window_end {
        if missing_steps_bitmap & (1 << logical_index) != 0 {
            continue;
        }
        let offset = local * PROFILE_STEP_LEN;
        let step = decode_step(&step_bytes[offset..offset + PROFILE_STEP_LEN])?;
        if usize::from(step.step_index) != logical_index {
            return Err(Error::InvalidField("step_index"));
        }
        local += 1;
    }

    Ok(ProfileFragmentView {
        header,
        profile_id,
        profile_version,
        expected_step_count,
        observed_unique_step_count,
        observed_field_count,
        missing_steps_bitmap,
        duplicate_steps_bitmap,
        scan_duration_us,
        collection_flags,
        finish_reason,
        duplicate_count,
        overwritten_field_count,
        out_of_order_count,
        ambiguous_index_jump_count,
        invalid_gas_index_count,
        intermediate_field_count,
        profile_rollover_count,
        fields_after_rollover_count,
        poll_count,
        step_window_start,
        steps_in_fragment,
        step_bytes,
    })
}

fn validate_decoded_health(header: Header, payload: &[u8]) -> Result<(), Error> {
    if header.fragment_index != 0 || header.fragment_count != 1 {
        return Err(Error::InvalidField("unfragmented_record_coordinates"));
    }
    if payload.len() < HEALTH_BASE_LEN {
        return Err(Error::WrongLength {
            expected: HEALTH_BASE_LEN,
            actual: payload.len(),
        });
    }
    if payload[0] != HEALTH_SCHEMA_VERSION {
        return Err(Error::InvalidField("health_schema_version"));
    }
    validate_health_flags(header.common, payload[1])?;
    let extension_len = usize::from(payload[53]);
    let expected_len = HEALTH_BASE_LEN + extension_len;
    if payload.len() != expected_len {
        return Err(Error::WrongLength {
            expected: expected_len,
            actual: payload.len(),
        });
    }
    let mut offset = HEALTH_BASE_LEN;
    let mut previous_type = 0;
    while offset < payload.len() {
        if payload.len() - offset < 2 {
            return Err(Error::BufferExhausted);
        }
        let kind = payload[offset];
        let len = usize::from(payload[offset + 1]);
        offset += 2;
        if kind <= previous_type {
            return Err(Error::InvalidField("health_tlv_order"));
        }
        if payload.len() - offset < len {
            return Err(Error::BufferExhausted);
        }
        match kind {
            1 | 2 if len == 2 => {}
            1 | 2 => return Err(Error::InvalidField("health_tlv_length")),
            _ => return Err(Error::InvalidField("health_tlv_type")),
        }
        previous_type = kind;
        offset += len;
    }
    Ok(())
}

fn validate_health_flags(common: Common, flags: u8) -> Result<(), Error> {
    ensure_known_u8("health_flags", flags, HEALTH_FLAGS_KNOWN)?;
    let header_says_unavailable = common.flags & COMMON_FLAG_BOOT_ID_VALID == 0;
    let health_says_unavailable = flags & HEALTH_FLAG_BOOT_ID_UNAVAILABLE != 0;
    if header_says_unavailable != health_says_unavailable {
        return Err(Error::InvalidField("health_boot_id_status"));
    }
    Ok(())
}

fn validate_health_config_identity(common: Common, health: &DeviceHealth) -> Result<(), Error> {
    let profile_id_missing = health.profile_id == 0;
    let profile_version_missing = health.profile_version == 0;
    if profile_id_missing != profile_version_missing {
        return Err(Error::InvalidField("health_profile_identity"));
    }
    if profile_id_missing {
        if common.config_id != 0 {
            return Err(Error::InvalidField("health_config_id_status"));
        }
        return Ok(());
    }
    if common.config_id == 0 && health.flags & HEALTH_FLAG_CONFIG_MISMATCH == 0 {
        return Err(Error::InvalidField("health_config_id_status"));
    }
    Ok(())
}

fn decode_device_health(header: Header, payload: &[u8]) -> Result<DeviceHealth, Error> {
    validate_decoded_health(header, payload)?;
    let mut reader = Reader::new(&payload[..HEALTH_BASE_LEN]);
    if reader.u8()? != HEALTH_SCHEMA_VERSION {
        return Err(Error::InvalidField("health_schema_version"));
    }
    let flags = reader.u8()?;
    let reset_cause_raw = reader.u32()?;
    let successful_sensor_scans = reader.u32()?;
    let failed_sensor_scans = reader.u32()?;
    let incomplete_profiles = reader.u32()?;
    let i2c_errors = reader.u32()?;
    let radio_tx_errors = reader.u32()?;
    let dropped_profiles = reader.u32()?;
    let dropped_fragments = reader.u32()?;
    let overwritten_fields = reader.u32()?;
    let current_sample_interval_ms = reader.u32()?;
    let firmware_version = reader.take::<3>()?;
    let profile_id = reader.u16()?;
    let profile_version = reader.u16()?;
    let last_sensor_error = reader.u16()?;
    let last_radio_error = reader.u16()?;
    let extension_len = reader.u8()?;
    reader.finish()?;
    if usize::from(extension_len) != payload.len() - HEALTH_BASE_LEN {
        return Err(Error::InvalidField("health_extension_len"));
    }

    let mut calibrated_mcu_temperature_centi_celsius = None;
    let mut calibrated_vdd_millivolt = None;
    let mut extensions = Reader::new(&payload[HEALTH_BASE_LEN..]);
    while extensions.offset < extensions.bytes.len() {
        let kind = extensions.u8()?;
        let len = extensions.u8()?;
        if len != 2 {
            return Err(Error::InvalidField("health_tlv_length"));
        }
        match kind {
            1 => calibrated_mcu_temperature_centi_celsius = Some(extensions.i16()?),
            2 => calibrated_vdd_millivolt = Some(extensions.u16()?),
            _ => return Err(Error::InvalidField("health_tlv_type")),
        }
    }
    extensions.finish()?;
    let health = DeviceHealth {
        flags,
        reset_cause_raw,
        successful_sensor_scans,
        failed_sensor_scans,
        incomplete_profiles,
        i2c_errors,
        radio_tx_errors,
        dropped_profiles,
        dropped_fragments,
        overwritten_fields,
        current_sample_interval_ms,
        firmware_version,
        profile_id,
        profile_version,
        last_sensor_error,
        last_radio_error,
        calibrated_mcu_temperature_centi_celsius,
        calibrated_vdd_millivolt,
    };
    validate_health_config_identity(header.common, &health)?;
    Ok(health)
}

const fn step_mask(step_count: u8) -> u16 {
    (1_u16 << step_count) - 1
}

fn ensure_known_u8(field: &'static str, value: u8, known: u8) -> Result<(), Error> {
    let unknown = value & !known;
    if unknown == 0 {
        Ok(())
    } else {
        Err(Error::UnknownFlags {
            field,
            bits: u32::from(unknown),
        })
    }
}

fn ensure_known_u16(field: &'static str, value: u16, known: u16) -> Result<(), Error> {
    let unknown = value & !known;
    if unknown == 0 {
        Ok(())
    } else {
        Err(Error::UnknownFlags {
            field,
            bits: u32::from(unknown),
        })
    }
}

fn ensure_known_u32(field: &'static str, value: u32, known: u32) -> Result<(), Error> {
    let unknown = value & !known;
    if unknown == 0 {
        Ok(())
    } else {
        Err(Error::UnknownFlags {
            field,
            bits: unknown,
        })
    }
}

struct Writer<'a> {
    bytes: &'a mut [u8],
    offset: usize,
}

impl<'a> Writer<'a> {
    const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), Error> {
        let end = self
            .offset
            .checked_add(value.len())
            .ok_or(Error::BufferExhausted)?;
        let destination = self
            .bytes
            .get_mut(self.offset..end)
            .ok_or(Error::BufferExhausted)?;
        destination.copy_from_slice(value);
        self.offset = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), Error> {
        self.bytes(&[value])
    }

    fn i8(&mut self, value: i8) -> Result<(), Error> {
        self.bytes(&value.to_be_bytes())
    }

    fn u16(&mut self, value: u16) -> Result<(), Error> {
        self.bytes(&value.to_be_bytes())
    }

    fn i16(&mut self, value: i16) -> Result<(), Error> {
        self.bytes(&value.to_be_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), Error> {
        self.bytes(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), Error> {
        self.bytes(&value.to_be_bytes())
    }

    fn finish(self) -> Result<(), Error> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::WrongLength {
                expected: self.bytes.len(),
                actual: self.offset,
            })
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let end = self.offset.checked_add(N).ok_or(Error::BufferExhausted)?;
        let source = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::BufferExhausted)?;
        let mut output = [0; N];
        output.copy_from_slice(source);
        self.offset = end;
        Ok(output)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take::<1>()?[0])
    }

    fn i8(&mut self) -> Result<i8, Error> {
        Ok(i8::from_be_bytes(self.take()?))
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn i16(&mut self) -> Result<i16, Error> {
        Ok(i16::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn finish(self) -> Result<(), Error> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::WrongLength {
                expected: self.bytes.len(),
                actual: self.offset,
            })
        }
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;

    const V1_GOLDEN: [u8; V1_FRAME_LEN] = [
        0x56, 0x53, 0x01, 0xb0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c,
        0x0d, 0xfb, 0x2e, 0x00, 0x01, 0x8b, 0xcd, 0x00, 0x00, 0xb2, 0x6e, 0x00, 0x0f, 0x12, 0x06,
        0x00, 0x07, 0xee, 0xd0, 0x00, 0x05, 0x90, 0x20, 0x75, 0x30, 0x02, 0x00, 0x08, 0x02, 0x03,
        0x04, 0x05, 0x06,
    ];

    fn common(config_id: u64) -> Common {
        Common::production(
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            0xffff_ffff,
            0x2122_2324_2526_2728,
            config_id,
            0x0005,
        )
    }

    fn config() -> DeviceConfig {
        let mut steps = [HeaterStepConfig::default(); MAX_PROFILE_STEPS];
        for (index, step) in steps.iter_mut().enumerate() {
            *step = HeaterStepConfig {
                target_temperature_celsius: 200 + u16::try_from(index).unwrap() * 20,
                configured_duration_us: 138_898 * (u32::try_from(index).unwrap() + 1),
                repetition_multiplier: u8::try_from(index).unwrap() + 1,
                readback_heater_current: 0x20 + u8::try_from(index).unwrap(),
                programmed_heater_resistance: 0x60 + u8::try_from(index).unwrap(),
                programmed_gas_wait: 0x40 + u8::try_from(index).unwrap(),
            };
        }
        DeviceConfig {
            flags: CONFIG_FLAG_CALIBRATION_HASH_VALID | CONFIG_FLAG_SENSOR_CONFIG_READ_BACK,
            firmware_version: [2, 3, 4],
            firmware_build_flags: BUILD_FLAG_ID_VALID,
            firmware_build_id: 0xa0a1_a2a3_a4a5_a6a7,
            sensor_chip_id: 0x61,
            sensor_variant: 1,
            sensor_i2c_address: 0x76,
            temperature_oversampling: 2,
            humidity_oversampling: 5,
            pressure_oversampling: 1,
            iir_filter: 0,
            standby_time: 8,
            operation_mode: 3,
            heater_enabled: 1,
            parallel_requested_shared_wait_ms: 99,
            parallel_shared_wait_register: 0x73,
            parallel_quantized_shared_wait_us: 97_308,
            tphg_duration_us: 41_590,
            expected_profile_duration_us: 10_695_146,
            profile_id: 0x1001,
            profile_version: 2,
            expected_step_count: 10,
            heater_readback_valid_bitmap: 0x03ff,
            calibration_hash_algorithm: 1,
            calibration_hash: 0xb0b1_b2b3_b4b5_b6b7,
            scan_interval_ms: 60_000,
            config_repeat_interval_scans: 16,
            output_routes: OUTPUT_ROUTE_LORA_P2P | OUTPUT_ROUTE_RTT,
            radio_frequency_hz: 868_100_000,
            radio_tx_power_dbm: 5,
            radio_spreading_factor: 7,
            radio_bandwidth_hz: 125_000,
            radio_coding_rate_numerator: 4,
            radio_coding_rate_denominator: 5,
            radio_preamble_symbols: 8,
            radio_header_mode: 0,
            radio_phy_crc_enabled: 1,
            radio_iq_inverted: 0,
            radio_sync_word: 0x1424,
            max_frame_len: MAX_V2_FRAME_LEN_U8,
            profile_steps_per_fragment: STEPS_PER_FRAGMENT_U8,
            steps,
        }
    }

    fn step(index: u8) -> ProfileStep {
        ProfileStep {
            step_index: index,
            gas_index: index,
            measurement_index: 0x80_u8.wrapping_add(index),
            status: 0xb0,
            raw_measurement_status: 0x80 | index,
            raw_gas_status: 0x3d,
            target_temperature_celsius: 200 + u16::from(index) * 20,
            configured_duration_us: 138_898 * (u32::from(index) + 1),
            offset_us: 1_000_000 * u32::from(index),
            temperature_centi_celsius: -1_000 + i16::from(index),
            pressure_pascal: 100_000 + u32::from(index),
            humidity_milli_percent_rh: 40_000 + u32::from(index),
            gas_resistance_ohm: 10_000 + u32::from(index),
            temperature_adc: 500_000 + u32::from(index),
            pressure_adc: 300_000 + u32::from(index),
            humidity_adc: 20_000 + u16::from(index),
            gas_resistance_adc: 500 + u16::from(index),
            gas_range: 13,
            repetition_multiplier: index + 1,
            heater_resistance: 0x60 + index,
            heater_current: 0xaa,
            gas_wait: 0x40 + index,
        }
    }

    fn complete_scan() -> ProfileScan {
        let mut steps = [None; MAX_PROFILE_STEPS];
        for (index, item) in steps.iter_mut().enumerate() {
            *item = Some(step(u8::try_from(index).unwrap()));
        }
        ProfileScan {
            profile_id: 0x1001,
            profile_version: 2,
            expected_step_count: 10,
            observed_unique_step_count: 10,
            observed_field_count: 10,
            missing_steps_bitmap: 0,
            duplicate_steps_bitmap: 0,
            scan_duration_us: 12_340_000,
            collection_flags: 0,
            finish_reason: FINISH_REASON_COMPLETE,
            duplicate_count: 0,
            overwritten_field_count: 0,
            out_of_order_count: 0,
            ambiguous_index_jump_count: 0,
            invalid_gas_index_count: 0,
            intermediate_field_count: 0,
            profile_rollover_count: 0,
            fields_after_rollover_count: 0,
            poll_count: 7,
            steps,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(output, "{byte:02x}").unwrap();
        }
        output
    }

    #[test]
    fn deployed_v1_fixture_is_unchanged_and_not_v2() {
        assert_eq!(V1_GOLDEN.len(), 48);
        assert_eq!(V1_GOLDEN[0..3], [b'V', b'S', 1]);
        assert_eq!(decode(&V1_GOLDEN), Err(Error::UnsupportedVersion(1)));
        assert_eq!(
            hex(&V1_GOLDEN),
            "565301b001020304050607080a0b0c0dfb2e00018bcd0000b26e000f12060007eed00005902075300200080203040506"
        );
    }

    #[test]
    fn ten_steps_encode_as_three_three_three_one_not_three_fields_total() {
        let encoded = encode_profile(common(0x9999_aaaa_bbbb_cccc), &complete_scan()).unwrap();
        assert_eq!(encoded.frames().len(), 4);
        assert_eq!(
            encoded
                .frames()
                .iter()
                .map(EncodedFrame::len)
                .collect::<std::vec::Vec<_>>(),
            [231, 231, 231, 137]
        );

        let mut decoded_steps = 0;
        for (index, frame) in encoded.frames().iter().enumerate().rev() {
            let DecodedFrame::ProfileFragment(fragment) = decode(frame.as_slice()).unwrap() else {
                panic!("wrong record type");
            };
            assert_eq!(usize::from(fragment.header.fragment_index), index);
            assert_eq!(fragment.header.fragment_count, 4);
            decoded_steps += usize::from(fragment.steps_in_fragment);
            for local in 0..usize::from(fragment.steps_in_fragment) {
                let decoded = fragment.step(local).unwrap();
                assert_eq!(decoded.step_index as usize, index * 3 + local);
            }
        }
        assert_eq!(decoded_steps, 10);
    }

    #[test]
    fn incomplete_scan_keeps_fixed_fragment_windows() {
        let mut scan = complete_scan();
        scan.steps[1] = None;
        scan.steps[8] = None;
        scan.observed_unique_step_count = 8;
        scan.observed_field_count = 9;
        scan.missing_steps_bitmap = (1 << 1) | (1 << 8);
        scan.duplicate_steps_bitmap = 1 << 4;
        scan.collection_flags = 1 << 2;
        let encoded = encode_profile(common(7), &scan).unwrap();
        assert_eq!(
            encoded
                .frames()
                .iter()
                .map(EncodedFrame::len)
                .collect::<std::vec::Vec<_>>(),
            [184, 231, 184, 137]
        );

        let DecodedFrame::ProfileFragment(last) = decode(encoded.frames()[3].as_slice()).unwrap()
        else {
            panic!("wrong record type");
        };
        assert_eq!(last.step_window_start, 9);
        assert_eq!(last.steps_in_fragment, 1);
        assert_eq!(last.step(0).unwrap().step_index, 9);
        assert_eq!(last.missing_steps_bitmap, (1 << 1) | (1 << 8));
    }

    #[test]
    fn stale_pre_scan_fields_are_counted_and_flagged_without_changing_layout() {
        let mut scan = complete_scan();
        scan.observed_field_count = 15;
        scan.intermediate_field_count = 5;
        scan.collection_flags = COLLECTION_FLAG_STALE_PRE_SCAN_FIELDS;

        let encoded = encode_profile(common(7), &scan).unwrap();
        assert_eq!(encoded.frames()[0].len(), MAX_PROFILE_FRAME_LEN);
        for frame in encoded.frames() {
            let DecodedFrame::ProfileFragment(fragment) = decode(frame.as_slice()).unwrap() else {
                panic!("wrong record type");
            };
            assert_eq!(fragment.intermediate_field_count, 5);
            assert_eq!(
                fragment.collection_flags,
                COLLECTION_FLAG_STALE_PRE_SCAN_FIELDS
            );
        }

        let mut invalid_scan = scan;
        invalid_scan.intermediate_field_count = 0;
        assert_eq!(
            encode_profile(common(7), &invalid_scan),
            Err(Error::InvalidField("stale_pre_scan_fields"))
        );

        let mut malformed = encoded.frames()[0];
        malformed.bytes[HEADER_LEN + 33..HEADER_LEN + 35].fill(0);
        assert_eq!(
            decode(malformed.as_slice()),
            Err(Error::InvalidField("stale_pre_scan_fields"))
        );
    }

    #[test]
    fn wholly_missing_sensor_window_still_emits_empty_radio_fragment() {
        let mut scan = complete_scan();
        for index in 3..=5 {
            scan.steps[index] = None;
            scan.missing_steps_bitmap |= 1 << index;
        }
        scan.observed_unique_step_count = 7;
        scan.observed_field_count = 7;
        scan.finish_reason = FINISH_REASON_TIMEOUT;
        scan.collection_flags = COLLECTION_FLAG_TIMEOUT;

        let encoded = encode_profile(common(7), &scan).unwrap();
        assert_eq!(encoded.frames().len(), 4);
        assert_eq!(
            encoded.frames()[1].len(),
            HEADER_LEN + PROFILE_FRAGMENT_META_LEN
        );
        let DecodedFrame::ProfileFragment(fragment) =
            decode(encoded.frames()[1].as_slice()).unwrap()
        else {
            panic!("wrong record type");
        };
        assert_eq!(fragment.header.fragment_index, 1);
        assert_eq!(fragment.header.fragment_count, 4);
        assert_eq!(fragment.step_window_start, 3);
        assert_eq!(fragment.steps_in_fragment, 0);
        assert_eq!(fragment.missing_steps_bitmap & 0x0038, 0x0038);
    }

    #[test]
    fn sequence_wrap_and_integer_boundaries_survive() {
        let mut scan = complete_scan();
        scan.expected_step_count = 1;
        scan.observed_unique_step_count = 1;
        scan.observed_field_count = u16::MAX;
        scan.steps[1..].fill(None);
        scan.steps[0] = Some(ProfileStep {
            status: u8::MAX,
            target_temperature_celsius: u16::MAX,
            configured_duration_us: u32::MAX,
            offset_us: u32::MAX,
            temperature_centi_celsius: i16::MIN,
            pressure_pascal: u32::MAX,
            humidity_milli_percent_rh: u32::MAX,
            gas_resistance_ohm: u32::MAX,
            temperature_adc: u32::MAX,
            pressure_adc: u32::MAX,
            humidity_adc: u16::MAX,
            gas_resistance_adc: u16::MAX,
            raw_gas_status: 0x3f,
            gas_range: 0x0f,
            heater_resistance: u8::MAX,
            heater_current: u8::MAX,
            gas_wait: u8::MAX,
            ..step(0)
        });
        let frame = encode_profile(common(u64::MAX), &scan).unwrap().frames()[0];
        let DecodedFrame::ProfileFragment(decoded) = decode(frame.as_slice()).unwrap() else {
            panic!("wrong record type");
        };
        assert_eq!(decoded.header.common.scan_sequence, u32::MAX);
        assert_eq!(decoded.header.common.config_id, u64::MAX);
        assert_eq!(decoded.step(0).unwrap().temperature_centi_celsius, i16::MIN);
        assert_eq!(decoded.step(0).unwrap().gas_resistance_ohm, u32::MAX);
    }

    #[test]
    fn malformed_fragment_coordinates_and_lengths_are_rejected() {
        let encoded = encode_profile(common(7), &complete_scan()).unwrap();
        let original = encoded.frames()[0];
        for length in 0..HEADER_LEN {
            assert!(decode(&original.as_slice()[..length]).is_err());
        }

        let mut bad = original;
        bad.bytes[7] = 0;
        assert_eq!(decode(bad.as_slice()), Err(Error::InvalidFragmentCount(0)));

        let mut bad = original;
        bad.bytes[6] = 3;
        bad.bytes[7] = 3;
        assert_eq!(
            decode(bad.as_slice()),
            Err(Error::InvalidFragmentIndex { index: 3, count: 3 })
        );

        let truncated = &original.as_slice()[..original.len() - 1];
        assert_eq!(
            decode(truncated),
            Err(Error::WrongLength {
                expected: original.len(),
                actual: original.len() - 1,
            })
        );
    }

    #[test]
    fn profile_steps_reject_decoded_raw_contradictions_on_encode_and_decode() {
        for (field, kind) in [
            ("step_status_raw", 0_usize),
            ("step_gas_index_raw", 1),
            ("step_gas_range_raw", 2),
            ("step_gas_index", 3),
        ] {
            let mut scan = complete_scan();
            let step = scan.steps[0].as_mut().unwrap();
            match kind {
                0 => step.raw_gas_status ^= 0x20,
                1 => step.raw_measurement_status ^= 1,
                2 => step.raw_gas_status ^= 1,
                3 => {
                    step.gas_index = 1;
                    step.raw_measurement_status =
                        (step.raw_measurement_status & 0xf0) | step.gas_index;
                }
                _ => unreachable!(),
            }
            assert_eq!(
                encode_profile(common(7), &scan),
                Err(Error::InvalidField(field))
            );

            let valid = encode_profile(common(7), &complete_scan()).unwrap();
            let mut malformed = valid.frames()[0];
            let step_offset = HEADER_LEN + PROFILE_FRAGMENT_META_LEN;
            match kind {
                0 => malformed.bytes[step_offset + 5] ^= 0x20,
                1 => malformed.bytes[step_offset + 4] ^= 1,
                2 => malformed.bytes[step_offset + 5] ^= 1,
                3 => {
                    malformed.bytes[step_offset + 1] = 1;
                    malformed.bytes[step_offset + 4] =
                        (malformed.bytes[step_offset + 4] & 0xf0) | 1;
                }
                _ => unreachable!(),
            }
            assert_eq!(
                decode(malformed.as_slice()),
                Err(Error::InvalidField(field))
            );
        }
    }

    #[test]
    fn config_is_self_identifying_and_repetition_does_not_change_id() {
        let first = encode_device_config(common(0), &config(), false).unwrap();
        let repeated = encode_device_config(common(0), &config(), true).unwrap();
        let DecodedFrame::DeviceConfig {
            header: a,
            config: decoded_config,
        } = decode(first.as_slice()).unwrap()
        else {
            panic!("wrong record type");
        };
        let DecodedFrame::DeviceConfig { header: b, .. } = decode(repeated.as_slice()).unwrap()
        else {
            panic!("wrong record type");
        };
        assert_eq!(first.len(), 231);
        assert_eq!(decoded_config, config());
        assert_eq!(a.common.config_id, device_config_id(&config()).unwrap());
        assert_eq!(first.as_ref(), first.as_slice());
        assert_eq!(a.common.config_id, b.common.config_id);
        assert_eq!(
            b.common.flags & COMMON_FLAG_CONFIG_REPEAT,
            COMMON_FLAG_CONFIG_REPEAT
        );

        let mut corrupted = first;
        corrupted.bytes[HEADER_LEN + 69] ^= 1;
        assert!(matches!(
            decode(corrupted.as_slice()),
            Err(Error::ConfigIdMismatch { .. })
        ));

        let mut no_output = config();
        no_output.output_routes = 0;
        assert_eq!(
            encode_device_config(common(0), &no_output, false),
            Err(Error::InvalidField("output_routes"))
        );

        let mut unknown_output = config();
        unknown_output.output_routes = 0x80;
        assert_eq!(
            encode_device_config(common(0), &unknown_output, false),
            Err(Error::UnknownFlags {
                field: "output_routes",
                bits: 0x80,
            })
        );

        for (field, mutate) in [
            (
                "sensor_variant",
                (|config: &mut DeviceConfig| config.sensor_variant = 2) as fn(&mut DeviceConfig),
            ),
            (
                "oversampling",
                (|config: &mut DeviceConfig| config.temperature_oversampling = 6)
                    as fn(&mut DeviceConfig),
            ),
            (
                "iir_filter",
                (|config: &mut DeviceConfig| config.iir_filter = 8) as fn(&mut DeviceConfig),
            ),
            (
                "standby_time",
                (|config: &mut DeviceConfig| config.standby_time = 9) as fn(&mut DeviceConfig),
            ),
            (
                "operation_mode",
                (|config: &mut DeviceConfig| config.operation_mode = 0) as fn(&mut DeviceConfig),
            ),
            (
                "radio_spreading_factor",
                (|config: &mut DeviceConfig| config.radio_spreading_factor = 13)
                    as fn(&mut DeviceConfig),
            ),
            (
                "radio_bandwidth_hz",
                (|config: &mut DeviceConfig| config.radio_bandwidth_hz = 0)
                    as fn(&mut DeviceConfig),
            ),
            (
                "radio_coding_rate",
                (|config: &mut DeviceConfig| config.radio_coding_rate_numerator = 3)
                    as fn(&mut DeviceConfig),
            ),
            (
                "radio_preamble_symbols",
                (|config: &mut DeviceConfig| config.radio_preamble_symbols = 0)
                    as fn(&mut DeviceConfig),
            ),
        ] {
            let mut malformed = config();
            mutate(&mut malformed);
            assert_eq!(
                encode_device_config(common(0), &malformed, false),
                Err(Error::InvalidField(field))
            );
        }

        let mut unknown_calibration_hash = config();
        unknown_calibration_hash.calibration_hash_algorithm = 2;
        assert_eq!(
            encode_device_config(common(0), &unknown_calibration_hash, false),
            Err(Error::InvalidField("calibration_hash_algorithm"))
        );
    }

    #[test]
    fn health_omits_uncalibrated_internal_values() {
        let health = DeviceHealth {
            flags: 0,
            reset_cause_raw: 0x1234_5678,
            successful_sensor_scans: 100,
            failed_sensor_scans: 2,
            incomplete_profiles: 3,
            i2c_errors: 4,
            radio_tx_errors: 5,
            dropped_profiles: 6,
            dropped_fragments: 7,
            overwritten_fields: 8,
            current_sample_interval_ms: 60_000,
            firmware_version: [2, 3, 4],
            profile_id: 0x1001,
            profile_version: 2,
            last_sensor_error: 0,
            last_radio_error: 0,
            calibrated_mcu_temperature_centi_celsius: None,
            calibrated_vdd_millivolt: None,
        };
        let without = encode_device_health(common(7), &health).unwrap();
        assert_eq!(without.len(), 102);
        assert_eq!(without.as_slice()[HEADER_LEN + 53], 0);
        assert!(matches!(
            decode(without.as_slice()),
            Ok(DecodedFrame::DeviceHealth { .. })
        ));

        let with = encode_device_health(
            common(7),
            &DeviceHealth {
                calibrated_mcu_temperature_centi_celsius: Some(-1_234),
                calibrated_vdd_millivolt: Some(3_301),
                ..health
            },
        )
        .unwrap();
        assert_eq!(with.len(), 110);
        assert_eq!(with.as_slice()[HEADER_LEN + 53], 8);
        assert!(matches!(
            decode(with.as_slice()),
            Ok(DecodedFrame::DeviceHealth { .. })
        ));

        let mut unknown_flags = without;
        unknown_flags.bytes[HEADER_LEN + 1] = 0x80;
        assert!(matches!(
            decode(unknown_flags.as_slice()),
            Err(Error::UnknownFlags {
                field: "health_flags",
                bits: 0x80
            })
        ));
    }

    #[test]
    fn zero_config_id_is_reserved_for_degraded_health_or_mismatch_profiles() {
        let normal_health = DeviceHealth {
            flags: 0,
            reset_cause_raw: 0,
            successful_sensor_scans: 0,
            failed_sensor_scans: 1,
            incomplete_profiles: 1,
            i2c_errors: 0,
            radio_tx_errors: 0,
            dropped_profiles: 0,
            dropped_fragments: 0,
            overwritten_fields: 0,
            current_sample_interval_ms: 180_000,
            firmware_version: [2, 0, 0],
            profile_id: 0x1001,
            profile_version: 2,
            last_sensor_error: 1,
            last_radio_error: 0,
            calibrated_mcu_temperature_centi_celsius: None,
            calibrated_vdd_millivolt: None,
        };

        assert_eq!(
            encode_device_health(common(0), &normal_health),
            Err(Error::InvalidField("health_config_id_status"))
        );
        let pre_config = DeviceHealth {
            profile_id: 0,
            profile_version: 0,
            ..normal_health
        };
        let pre_config_frame = encode_device_health(common(0), &pre_config).unwrap();
        let DecodedFrame::DeviceHealth {
            header,
            health: decoded_pre_config,
        } = decode(pre_config_frame.as_slice()).unwrap()
        else {
            panic!("wrong record type")
        };
        assert_eq!(header.common.config_id, 0);
        assert_eq!(decoded_pre_config.profile_id, 0);
        assert_eq!(decoded_pre_config.profile_version, 0);

        let mismatch_health = DeviceHealth {
            flags: HEALTH_FLAG_CONFIG_MISMATCH,
            ..normal_health
        };
        let mismatch_health_frame = encode_device_health(common(0), &mismatch_health).unwrap();
        let DecodedFrame::DeviceHealth {
            header,
            health: decoded_mismatch_health,
        } = decode(mismatch_health_frame.as_slice()).unwrap()
        else {
            panic!("wrong record type")
        };
        assert_eq!(header.common.config_id, 0);
        assert_eq!(decoded_mismatch_health.profile_id, normal_health.profile_id);

        let mut malformed_normal_health = encode_device_health(common(7), &normal_health).unwrap();
        malformed_normal_health.bytes[38..46].fill(0);
        assert_eq!(
            decode(malformed_normal_health.as_slice()),
            Err(Error::InvalidField("health_config_id_status"))
        );

        assert_eq!(
            encode_profile(common(0), &complete_scan()),
            Err(Error::InvalidField("profile_config_id_status"))
        );
        let mut mismatch_scan = complete_scan();
        mismatch_scan.collection_flags = COLLECTION_FLAG_CONFIG_MISMATCH;
        mismatch_scan.finish_reason = FINISH_REASON_SENSOR_ERROR;
        let mismatch_profile = encode_profile(common(0), &mismatch_scan).unwrap();
        let DecodedFrame::ProfileFragment(decoded_mismatch) =
            decode(mismatch_profile.frames()[0].as_slice()).unwrap()
        else {
            panic!("wrong record type")
        };
        assert_eq!(decoded_mismatch.header.common.config_id, 0);
        assert_eq!(decoded_mismatch.profile_id, mismatch_scan.profile_id);
        assert_eq!(
            decoded_mismatch.profile_version,
            mismatch_scan.profile_version
        );

        let mut zero_profile = config();
        zero_profile.profile_id = 0;
        assert_eq!(
            encode_device_config(common(1), &zero_profile, false),
            Err(Error::InvalidField("profile_identity"))
        );
        let mut config_frame = encode_device_config(common(1), &config(), false).unwrap();
        config_frame.bytes[38..46].fill(0);
        assert_eq!(
            decode(config_frame.as_slice()),
            Err(Error::InvalidField("reserved_config_id"))
        );
    }

    #[test]
    fn airtime_matches_exact_sf7_bw125_cr45_values() {
        let toa = |len| lora_time_on_air_us(len, 7, 125_000, 5, 8, true, true).unwrap();
        assert_eq!(toa(48), 97_536);
        assert_eq!(toa(230), 363_776);
        assert_eq!(toa(231), 363_776);
        assert_eq!(toa(137), 225_536);
        assert_eq!(toa(102), 174_336);
        assert_eq!(toa(110), 184_576);
        assert_eq!(toa(231) * 3 + toa(137), 1_316_864);
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn golden_frames_are_byte_exact() {
        let config_frame = encode_device_config(common(0), &config(), false).unwrap();
        let profile = encode_profile(common(0x9999_aaaa_bbbb_cccc), &complete_scan()).unwrap();
        let health = encode_device_health(
            Common::boot_id_unavailable(
                0x0102_0304_0506_0708,
                u32::MAX,
                0x2122_2324_2526_2728,
                0x9999_aaaa_bbbb_cccc,
                0x0005,
            ),
            &DeviceHealth {
                flags: HEALTH_FLAGS_KNOWN,
                reset_cause_raw: 0x1234_5678,
                successful_sensor_scans: 100,
                failed_sensor_scans: 2,
                incomplete_profiles: 3,
                i2c_errors: 4,
                radio_tx_errors: 5,
                dropped_profiles: 6,
                dropped_fragments: 7,
                overwritten_fields: 8,
                current_sample_interval_ms: 60_000,
                firmware_version: [2, 3, 4],
                profile_id: 0x1001,
                profile_version: 2,
                last_sensor_error: 9,
                last_radio_error: 10,
                calibrated_mcu_temperature_centi_celsius: None,
                calibrated_vdd_millivolt: None,
            },
        )
        .unwrap();
        const CONFIG_HEX: &str = "565302013003000100b701020304050607081112131415161718ffffffff212223242526272896392f014bce77450005010302030401a0a1a2a3a4a5a6a76101760205010008030100637300017c1c0000a27600a331ea100100020a03ff01b0b1b2b3b4b5b6b70000ea6000100533be27a005070001e848040500080001001424e70300c800021e920120604000dc00043d240221614100f000065bb603226242010400087a48042363430118000a98da05246444012c000cb76c062565450140000ed5fe0726664601540010f4900827674701680013132209286848017c001531b40a296949";
        const PROFILE0_HEX: &str = "565302023003000400b701020304050607081112131415161718ffffffff21222324252627289999aaaabbbbcccc00050103100100020a0a000a0000000000bc4b20000000000000000000000000000000000000000000000700000080b0803d00c800021e9200000000fc18000186a000009c40000027100007a120000493e04e2001f40d0160aa40010181b0813d00dc00043d24000f4240fc19000186a100009c41000027110007a121000493e14e2101f50d0261aa41020282b0823d00f000065bb6001e8480fc1a000186a200009c42000027120007a122000493e24e2201f60d0362aa42";
        const PROFILE1_HEX: &str = "565302023003010400b701020304050607081112131415161718ffffffff21222324252627289999aaaabbbbcccc00050103100100020a0a000a0000000000bc4b20000000000000000000000000000000000000000000000703030383b0833d010400087a48002dc6c0fc1b000186a300009c43000027130007a123000493e34e2301f70d0463aa43040484b0843d0118000a98da003d0900fc1c000186a400009c44000027140007a124000493e44e2401f80d0564aa44050585b0853d012c000cb76c004c4b40fc1d000186a500009c45000027150007a125000493e54e2501f90d0665aa45";
        const PROFILE2_HEX: &str = "565302023003020400b701020304050607081112131415161718ffffffff21222324252627289999aaaabbbbcccc00050103100100020a0a000a0000000000bc4b20000000000000000000000000000000000000000000000706060686b0863d0140000ed5fe005b8d80fc1e000186a600009c46000027160007a126000493e64e2601fa0d0766aa46070787b0873d01540010f490006acfc0fc1f000186a700009c47000027170007a127000493e74e2701fb0d0867aa47080888b0883d016800131322007a1200fc20000186a800009c48000027180007a128000493e84e2801fc0d0968aa48";
        const PROFILE3_HEX: &str = "5653020230030304005901020304050607081112131415161718ffffffff21222324252627289999aaaabbbbcccc00050101100100020a0a000a0000000000bc4b20000000000000000000000000000000000000000000000709090989b0893d017c001531b400895440fc21000186a900009c49000027190007a129000493e94e2901fd0d0a69aa49";
        const HEALTH_HEX: &str = "5653020330000001003601020304050607080000000000000000ffffffff21222324252627289999aaaabbbbcccc0005013f1234567800000064000000020000000300000004000000050000000600000007000000080000ea60020304100100020009000a00";

        assert_eq!(hex(config_frame.as_slice()), CONFIG_HEX);
        assert_eq!(hex(profile.frames()[0].as_slice()), PROFILE0_HEX);
        assert_eq!(hex(profile.frames()[1].as_slice()), PROFILE1_HEX);
        assert_eq!(hex(profile.frames()[2].as_slice()), PROFILE2_HEX);
        assert_eq!(hex(profile.frames()[3].as_slice()), PROFILE3_HEX);
        assert_eq!(hex(health.as_slice()), HEALTH_HEX);
    }
}
