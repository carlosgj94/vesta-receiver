//! Deterministic quality gates and feature extraction for server-side analysis.
//!
//! This module intentionally contains no fire classifier or alert thresholds.
//! It converts validated telemetry into reproducible numerical features that a
//! later rule engine or trained model can consume.

use std::collections::HashMap;

use serde::Serialize;
use vesta_protocol::TelemetryV1;
use vesta_protocol::v2::{
    COLLECTION_FLAG_DUPLICATE, COLLECTION_FLAG_SENSOR_RECONFIGURED, COMMON_FLAG_BOOT_ID_VALID,
    CONFIG_FLAG_SENSOR_CONFIG_READ_BACK, FINISH_REASON_COMPLETE,
};

use crate::records::{DeviceConfiguration, ProfileScan, ProfileStep};

const MIN_TEMPERATURE_CENTI_CELSIUS: i16 = -4_000;
const MAX_TEMPERATURE_CENTI_CELSIUS: i16 = 8_500;
const MIN_PRESSURE_PASCAL: u32 = 30_000;
const MAX_PRESSURE_PASCAL: u32 = 110_000;
const MAX_HUMIDITY_MILLI_PERCENT_RH: u32 = 100_000;
// This is deliberately an allowlist: new/unknown collector flags fail closed.
// Duplicate observations are expected while polling the BME688's three field
// slots and are safe after deterministic terminal-step reassembly. A verified
// pre-scan SENSOR_RECONFIGURED recovery resets temporal history but remains
// usable because firmware read back the exact configuration before triggering
// the scan. Every other flag, including stale pre-scan data, is critical.
const ANALYSIS_ALLOWED_COLLECTION_FLAGS: u32 =
    COLLECTION_FLAG_DUPLICATE | COLLECTION_FLAG_SENSOR_RECONFIGURED;

/// Bitset describing why one sensor sample should not feed analysis directly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct QualityFlags(u16);

impl QualityFlags {
    /// The field did not carry the BME688 new-data flag.
    pub const NOT_NEW_DATA: Self = Self(1 << 0);
    /// The BME688 marked gas conversion invalid.
    pub const GAS_INVALID: Self = Self(1 << 1);
    /// The BME688 heater was not stable.
    pub const HEATER_UNSTABLE: Self = Self(1 << 2);
    /// Unknown status bits were present.
    pub const UNKNOWN_STATUS: Self = Self(1 << 3);
    /// Compensated temperature lies outside the BME688 operating range.
    pub const TEMPERATURE_OUT_OF_RANGE: Self = Self(1 << 4);
    /// Compensated pressure lies outside the BME688 operating range.
    pub const PRESSURE_OUT_OF_RANGE: Self = Self(1 << 5);
    /// Compensated humidity lies outside 0–100 percent RH.
    pub const HUMIDITY_OUT_OF_RANGE: Self = Self(1 << 6);
    /// Gas resistance was zero and therefore cannot be log transformed.
    pub const GAS_RESISTANCE_ZERO: Self = Self(1 << 7);
    /// The containing profile did not pass collector/transport integrity gates.
    pub const PROFILE_SCAN_UNUSABLE: Self = Self(1 << 8);

    /// Raw integer representation suitable for storage and JSON output.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether no quality problem was found.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    const fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// Exact sensor channel represented by an analysis sample.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnalysisSeries {
    /// Legacy forced-mode v1 channel.
    LegacyV1,
    /// One exact heater step under one exact protocol-v2 profile definition.
    ProfileStep {
        /// Stable hash of the complete device/sensor/profile configuration.
        config_id: u64,
        /// Firmware-defined profile family.
        profile_id: u16,
        /// Revision of the profile family.
        profile_version: u16,
        /// Heater step within the profile.
        step_index: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct HistoryKey {
    node_id: u64,
    boot_id: Option<u64>,
    series: AnalysisSeries,
}

/// Device-monotonic timestamp for one BME688 heater-step field observation.
///
/// The two wire fields remain separate so the full `u64` millisecond uptime is
/// retained without overflowing when converted to microseconds. The offset is
/// when the MCU observed/read the field and is not an exact sensor conversion
/// timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceSampleTime {
    /// Device uptime captured immediately before the profile scan was started.
    pub scan_start_uptime_ms: u64,
    /// MCU field-read/poll observation offset of this step within the scan.
    pub relative_offset_us: u32,
}

impl DeviceSampleTime {
    fn total_microseconds(self) -> u128 {
        u128::from(self.scan_start_uptime_ms) * 1_000 + u128::from(self.relative_offset_us)
    }

    fn elapsed_since(self, prior: Self) -> Option<u64> {
        let elapsed = self
            .total_microseconds()
            .checked_sub(prior.total_microseconds())?;
        u64::try_from(elapsed).ok().filter(|elapsed| *elapsed != 0)
    }
}

/// Exact server-side observation before derivative calculation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AnalysisSample {
    /// Stable device node identity.
    pub node_id: u64,
    /// Optional boot nonce, unavailable in v1 or after a reported RNG failure.
    pub boot_id: Option<u64>,
    /// Sequence within the protocol stream or profile stream.
    pub sequence: u32,
    /// Exact channel/profile identity used to isolate temporal history.
    pub series: AnalysisSeries,
    /// Host receive time in Unix milliseconds.
    pub received_at_unix_ms: i64,
    /// Device-monotonic field-observation time for v2. V1 has no device uptime
    /// and therefore deliberately falls back to host receive time.
    pub device_sample_time: Option<DeviceSampleTime>,
    /// Compensated temperature in hundredths of a degree Celsius.
    pub temperature_centi_celsius: i16,
    /// Compensated pressure in pascals.
    pub pressure_pascal: u32,
    /// Compensated humidity in thousandths of a percent RH.
    pub humidity_milli_percent_rh: u32,
    /// Compensated gas resistance in ohms.
    pub gas_resistance_ohm: u32,
    /// Quality flags calculated before feature extraction.
    pub quality: QualityFlags,
    /// Clear prior history for this exact series before considering this
    /// observation. Protocol v2 sets this after verified sensor recovery.
    pub reset_temporal_history: bool,
}

impl AnalysisSample {
    /// Construct an observation from one legacy protocol-v1 frame.
    #[must_use]
    pub fn from_v1(frame: &TelemetryV1, received_at_unix_ms: i64) -> Self {
        let status = frame.sensor_status;
        let temperature = frame.compensated.temperature.centi_celsius();
        let pressure = frame.compensated.pressure.pascals();
        let humidity = frame.compensated.humidity.milli_percent_rh();
        let gas = frame.compensated.gas_resistance.ohms();
        Self {
            node_id: frame.node_id,
            boot_id: None,
            sequence: frame.sequence,
            series: AnalysisSeries::LegacyV1,
            received_at_unix_ms,
            device_sample_time: None,
            temperature_centi_celsius: temperature,
            pressure_pascal: pressure,
            humidity_milli_percent_rh: humidity,
            gas_resistance_ohm: gas,
            quality: sample_quality(status.bits(), temperature, pressure, humidity, gas),
            reset_temporal_history: false,
        }
    }

    /// Construct an observation from one step of a decoded profile scan.
    #[must_use]
    pub fn from_profile_step(
        scan: &ProfileScan,
        step: &ProfileStep,
        received_at_unix_ms: i64,
    ) -> Self {
        let boot_id = (scan.identity.common_flags & COMMON_FLAG_BOOT_ID_VALID != 0)
            .then_some(scan.identity.boot_id);
        let mut quality = sample_quality(
            step.status_bits,
            step.temperature_centi_celsius,
            step.pressure_pascal,
            step.humidity_milli_percent_rh,
            step.gas_resistance_ohm,
        );
        if !profile_scan_allows_analysis(scan) {
            quality.insert(QualityFlags::PROFILE_SCAN_UNUSABLE);
        }
        Self {
            node_id: scan.identity.node_id,
            boot_id,
            sequence: scan.identity.scan_sequence,
            series: AnalysisSeries::ProfileStep {
                config_id: scan.identity.config_id,
                profile_id: scan.profile_id,
                profile_version: scan.profile_version,
                step_index: step.step_index,
            },
            received_at_unix_ms,
            device_sample_time: Some(DeviceSampleTime {
                scan_start_uptime_ms: scan.identity.uptime_ms,
                relative_offset_us: step.relative_offset_us,
            }),
            temperature_centi_celsius: step.temperature_centi_celsius,
            pressure_pascal: step.pressure_pascal,
            humidity_milli_percent_rh: step.humidity_milli_percent_rh,
            gas_resistance_ohm: step.gas_resistance_ohm,
            quality,
            reset_temporal_history: scan.collection_flags & COLLECTION_FLAG_SENSOR_RECONFIGURED
                != 0,
        }
    }

    fn history_key(self) -> Option<HistoryKey> {
        // V1 has no boot nonce but remains one stable legacy channel. A v2
        // sample with an unavailable nonce must not build history across an
        // undetectable reboot.
        if matches!(self.series, AnalysisSeries::ProfileStep { .. }) && self.boot_id.is_none() {
            return None;
        }
        Some(HistoryKey {
            node_id: self.node_id,
            boot_id: self.boot_id,
            series: self.series,
        })
    }

    fn elapsed_since(self, prior: Self) -> Option<u64> {
        match self.series {
            AnalysisSeries::LegacyV1 => self
                .received_at_unix_ms
                .checked_sub(prior.received_at_unix_ms)
                .and_then(|elapsed_ms| u64::try_from(elapsed_ms).ok())
                .and_then(|elapsed_ms| elapsed_ms.checked_mul(1_000))
                .filter(|elapsed_us| *elapsed_us != 0),
            AnalysisSeries::ProfileStep { .. } => self
                .device_sample_time?
                .elapsed_since(prior.device_sample_time?),
        }
    }
}

/// Numerical features for one chronologically ingested observation.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct TemporalFeatures {
    /// Stable node identity.
    pub node_id: u64,
    /// Optional boot nonce.
    pub boot_id: Option<u64>,
    /// Device sequence.
    pub sequence: u32,
    /// Exact channel/profile identity used for this temporal series.
    pub series: AnalysisSeries,
    /// Host receive time in Unix milliseconds.
    pub received_at_unix_ms: i64,
    /// Device-monotonic field-observation time used for v2 ordering and rates.
    pub device_sample_time: Option<DeviceSampleTime>,
    /// Quality flags copied from the source sample.
    pub quality_flags: u16,
    /// Whether this observation cleared its exact series history because the
    /// sensor was reconfigured or a v2 scan sequence was discontinuous.
    pub temporal_history_reset: bool,
    /// Temperature in degrees Celsius.
    pub temperature_celsius: f64,
    /// Pressure in hectopascals.
    pub pressure_hectopascal: f64,
    /// Relative humidity in percent.
    pub humidity_percent_rh: f64,
    /// Natural logarithm of gas resistance in ohms, if non-zero.
    pub gas_log_ohm: Option<f64>,
    /// Elapsed time from the prior usable sample in the exact same series.
    pub elapsed_ms: Option<u64>,
    /// Exact elapsed microseconds used for derivative calculation.
    pub elapsed_us: Option<u64>,
    /// Temperature rate in degrees Celsius per minute.
    pub temperature_rate_celsius_per_minute: Option<f64>,
    /// Humidity rate in percentage points per minute.
    pub humidity_rate_percent_per_minute: Option<f64>,
    /// Pressure rate in hectopascals per minute.
    pub pressure_rate_hectopascal_per_minute: Option<f64>,
    /// Rate of change of natural-log gas resistance per minute.
    pub gas_log_rate_per_minute: Option<f64>,
}

/// Stateful chronological feature extractor isolated by node, valid boot,
/// profile definition, and heater step.
#[derive(Debug, Default)]
pub struct TemporalFeatureExtractor {
    previous: HashMap<HistoryKey, AnalysisSample>,
}

impl TemporalFeatureExtractor {
    /// Extract features and update history only when the sample passes quality
    /// gates and is newer than the prior observation.
    #[must_use]
    pub fn ingest(&mut self, sample: AnalysisSample) -> TemporalFeatures {
        let key = sample.history_key();
        let mut previous = key.and_then(|key| self.previous.get(&key).copied());
        let explicit_reset = sample.reset_temporal_history
            && previous.is_none_or(|prior| sample.elapsed_since(prior).is_some());
        let sequence_gap_reset = matches!(sample.series, AnalysisSeries::ProfileStep { .. })
            && previous.is_some_and(|prior| {
                sample.elapsed_since(prior).is_some()
                    && sample.sequence != prior.sequence.wrapping_add(1)
            });
        let temporal_history_reset = explicit_reset || sequence_gap_reset;
        if temporal_history_reset {
            if let Some(key) = key {
                self.previous.remove(&key);
            }
            previous = None;
        }
        let current_gas_log = gas_log(sample.gas_resistance_ohm);
        let mut features = TemporalFeatures {
            node_id: sample.node_id,
            boot_id: sample.boot_id,
            sequence: sample.sequence,
            series: sample.series,
            received_at_unix_ms: sample.received_at_unix_ms,
            device_sample_time: sample.device_sample_time,
            quality_flags: sample.quality.bits(),
            temporal_history_reset,
            temperature_celsius: f64::from(sample.temperature_centi_celsius) / 100.0,
            pressure_hectopascal: f64::from(sample.pressure_pascal) / 100.0,
            humidity_percent_rh: f64::from(sample.humidity_milli_percent_rh) / 1_000.0,
            gas_log_ohm: current_gas_log,
            elapsed_ms: None,
            elapsed_us: None,
            temperature_rate_celsius_per_minute: None,
            humidity_rate_percent_per_minute: None,
            pressure_rate_hectopascal_per_minute: None,
            gas_log_rate_per_minute: None,
        };

        let usable_previous = previous.and_then(|prior| {
            (sample.quality.is_empty() && prior.quality.is_empty())
                .then(|| sample.elapsed_since(prior).map(|elapsed| (prior, elapsed)))
                .flatten()
        });
        if let Some((prior, elapsed_us)) = usable_previous {
            let minutes = std::time::Duration::from_micros(elapsed_us).as_secs_f64() / 60.0;
            features.elapsed_ms = Some(elapsed_us / 1_000);
            features.elapsed_us = Some(elapsed_us);
            features.temperature_rate_celsius_per_minute = Some(
                (f64::from(sample.temperature_centi_celsius)
                    - f64::from(prior.temperature_centi_celsius))
                    / 100.0
                    / minutes,
            );
            features.humidity_rate_percent_per_minute = Some(
                (f64::from(sample.humidity_milli_percent_rh)
                    - f64::from(prior.humidity_milli_percent_rh))
                    / 1_000.0
                    / minutes,
            );
            features.pressure_rate_hectopascal_per_minute = Some(
                (f64::from(sample.pressure_pascal) - f64::from(prior.pressure_pascal))
                    / 100.0
                    / minutes,
            );
            features.gas_log_rate_per_minute = gas_log(sample.gas_resistance_ohm)
                .zip(gas_log(prior.gas_resistance_ohm))
                .map(|(current, prior)| (current - prior) / minutes);
        }

        if sample.quality.is_empty()
            && previous.is_none_or(|prior| sample.elapsed_since(prior).is_some())
            && (matches!(sample.series, AnalysisSeries::LegacyV1)
                || sample.device_sample_time.is_some())
        {
            if let Some(key) = key {
                self.previous.insert(key, sample);
            }
        }
        features
    }
}

/// Per-step gas features from one heater profile, without temporal baselining.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ProfileFeatures {
    /// Stable node identity.
    pub node_id: u64,
    /// Per-boot nonce, absent when the device reported RNG failure.
    pub boot_id: Option<u64>,
    /// Profile scan sequence.
    pub sequence: u32,
    /// Stable hash of the exact device/sensor/profile configuration.
    pub config_id: u64,
    /// Profile identifier.
    pub profile_id: u16,
    /// Profile revision.
    pub profile_revision: u16,
    /// Bitmap computed from decoded step positions.
    pub missing_steps: u16,
    /// Whether transport, collection, structure, and step quality gates pass.
    /// This is necessary but not sufficient for analysis until configuration
    /// metadata has been resolved.
    pub profile_quality_usable: bool,
    /// Whether a validated matching [`DeviceConfiguration`] was supplied.
    pub configuration_resolved: bool,
    /// Final analysis-ready gate: profile quality passed and exact
    /// configuration metadata is available.
    pub usable_for_analysis: bool,
    /// Ordered features for every decoded step.
    pub steps: Vec<ProfileStepFeatures>,
}

/// Numerical features from one profile step.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct ProfileStepFeatures {
    /// Heater-profile position.
    pub step_index: u8,
    /// Target heater temperature in degrees Celsius.
    pub target_temperature_celsius: u16,
    /// Quality flags for this step.
    pub quality_flags: u16,
    /// Natural logarithm of gas resistance in ohms, if non-zero.
    pub gas_log_ohm: Option<f64>,
    /// Log-resistance offset from the mean valid profile response.
    pub gas_log_offset_from_profile_mean: Option<f64>,
}

/// Extract a shape-preserving gas feature vector from one profile scan.
///
/// This variant deliberately leaves configuration unresolved. Call
/// [`extract_profile_features_with_configuration`] after joining a matching
/// configuration record; repeated configuration packets may arrive later.
#[must_use]
pub fn extract_profile_features(scan: &ProfileScan) -> ProfileFeatures {
    extract_profile_features_inner(scan, false)
}

/// Extract a shape-preserving vector and resolve its exact sensor/profile
/// configuration when the supplied record validates and matches the scan.
#[must_use]
pub fn extract_profile_features_with_configuration(
    scan: &ProfileScan,
    configuration: &DeviceConfiguration,
) -> ProfileFeatures {
    let configuration_resolved = configuration.validate().is_ok()
        && configuration.config_flags & CONFIG_FLAG_SENSOR_CONFIG_READ_BACK != 0
        && configuration.heater_readback_valid_bitmap
            == (1_u16 << configuration.expected_step_count) - 1
        && configuration.identity.node_id == scan.identity.node_id
        && configuration.identity.config_id == scan.identity.config_id
        && configuration.profile_id == scan.profile_id
        && configuration.profile_version == scan.profile_version
        && configuration.expected_step_count == scan.expected_steps
        && scan.steps.iter().all(|step| {
            let Some(configured) = configuration.heater_steps.get(usize::from(step.step_index))
            else {
                return false;
            };
            let descriptor_matches = configured.step_index == step.step_index
                && configured.target_temperature_celsius == step.target_temperature_celsius
                && configured.configured_duration_us == step.configured_duration_us
                && configured.repetition_multiplier == step.repetition_multiplier;
            let readback_matches = configured.readback_heater_current == step.raw_heater_current
                && configured.programmed_heater_resistance == step.raw_heater_resistance
                && configured.programmed_gas_wait == step.raw_gas_wait;
            descriptor_matches && readback_matches
        });
    extract_profile_features_inner(scan, configuration_resolved)
}

fn extract_profile_features_inner(
    scan: &ProfileScan,
    configuration_resolved: bool,
) -> ProfileFeatures {
    let scan_usable = profile_scan_allows_analysis(scan);
    let mut steps = scan
        .steps
        .iter()
        .map(|step| {
            let mut quality = sample_quality(
                step.status_bits,
                step.temperature_centi_celsius,
                step.pressure_pascal,
                step.humidity_milli_percent_rh,
                step.gas_resistance_ohm,
            );
            if !scan_usable {
                quality.insert(QualityFlags::PROFILE_SCAN_UNUSABLE);
            }
            ProfileStepFeatures {
                step_index: step.step_index,
                target_temperature_celsius: step.target_temperature_celsius,
                quality_flags: quality.bits(),
                gas_log_ohm: gas_log(step.gas_resistance_ohm),
                gas_log_offset_from_profile_mean: None,
            }
        })
        .collect::<Vec<_>>();
    steps.sort_unstable_by_key(|step| step.step_index);

    let (sum, count) = steps.iter().fold((0.0, 0_u32), |(sum, count), step| {
        match (step.quality_flags, step.gas_log_ohm) {
            (0, Some(value)) => (sum + value, count + 1),
            _ => (sum, count),
        }
    });
    if count != 0 {
        let mean = sum / f64::from(count);
        for step in &mut steps {
            if step.quality_flags == 0 {
                step.gas_log_offset_from_profile_mean = step.gas_log_ohm.map(|value| value - mean);
            }
        }
    }

    let profile_quality_usable = scan_usable && steps.iter().all(|step| step.quality_flags == 0);
    ProfileFeatures {
        node_id: scan.identity.node_id,
        boot_id: (scan.identity.common_flags & COMMON_FLAG_BOOT_ID_VALID != 0)
            .then_some(scan.identity.boot_id),
        sequence: scan.identity.scan_sequence,
        config_id: scan.identity.config_id,
        profile_id: scan.profile_id,
        profile_revision: scan.profile_version,
        missing_steps: scan.computed_unavailable_steps(),
        profile_quality_usable,
        configuration_resolved,
        usable_for_analysis: profile_quality_usable && configuration_resolved,
        steps,
    }
}

fn profile_scan_allows_analysis(scan: &ProfileScan) -> bool {
    scan.validate().is_ok()
        && scan.identity.common_flags & COMMON_FLAG_BOOT_ID_VALID != 0
        && scan.is_transport_complete()
        && scan.computed_unavailable_steps() == 0
        && scan.finish_reason == FINISH_REASON_COMPLETE
        && scan.collection_flags & !ANALYSIS_ALLOWED_COLLECTION_FLAGS == 0
        && scan.overwritten_field_count == 0
        && scan.out_of_order_count == 0
        && scan.ambiguous_index_jump_count == 0
        && scan.invalid_gas_index_count == 0
        && scan.profile_rollover_count == 0
        && scan.fields_after_rollover_count == 0
        && scan.conflicting_fragment_count == 0
}

fn sample_quality(
    status_bits: u8,
    temperature_centi_celsius: i16,
    pressure_pascal: u32,
    humidity_milli_percent_rh: u32,
    gas_resistance_ohm: u32,
) -> QualityFlags {
    let mut quality = QualityFlags::default();
    if status_bits & (1 << 7) == 0 {
        quality.insert(QualityFlags::NOT_NEW_DATA);
    }
    if status_bits & (1 << 5) == 0 {
        quality.insert(QualityFlags::GAS_INVALID);
    }
    if status_bits & (1 << 4) == 0 {
        quality.insert(QualityFlags::HEATER_UNSTABLE);
    }
    if status_bits & !0xb0 != 0 {
        quality.insert(QualityFlags::UNKNOWN_STATUS);
    }
    if !(MIN_TEMPERATURE_CENTI_CELSIUS..=MAX_TEMPERATURE_CENTI_CELSIUS)
        .contains(&temperature_centi_celsius)
    {
        quality.insert(QualityFlags::TEMPERATURE_OUT_OF_RANGE);
    }
    if !(MIN_PRESSURE_PASCAL..=MAX_PRESSURE_PASCAL).contains(&pressure_pascal) {
        quality.insert(QualityFlags::PRESSURE_OUT_OF_RANGE);
    }
    if humidity_milli_percent_rh > MAX_HUMIDITY_MILLI_PERCENT_RH {
        quality.insert(QualityFlags::HUMIDITY_OUT_OF_RANGE);
    }
    if gas_resistance_ohm == 0 {
        quality.insert(QualityFlags::GAS_RESISTANCE_ZERO);
    }
    quality
}

fn gas_log(gas_resistance_ohm: u32) -> Option<f64> {
    (gas_resistance_ohm != 0).then(|| f64::from(gas_resistance_ohm).ln())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode_hex;
    use crate::records::{HeaterStepConfiguration, ProfileStep, RecordIdentity};

    const FIXTURE: &str = "565301b001020304050607080a0b0c0dfb2e00018bcd0000b26e000f12060007eed00005902075300200080203040506";

    fn profile_step(index: u8, gas: u32, status_bits: u8) -> ProfileStep {
        ProfileStep {
            step_index: index,
            gas_index: index,
            measurement_index: index,
            status_bits,
            raw_measurement_status: (status_bits & 0x80) | index,
            raw_gas_status: (status_bits & 0x30) | 5,
            target_temperature_celsius: 200 + u16::from(index) * 50,
            configured_duration_us: 100_000,
            relative_offset_us: u32::from(index) * 100_000,
            temperature_centi_celsius: 2_500,
            pressure_pascal: 101_325,
            humidity_milli_percent_rh: 40_000,
            gas_resistance_ohm: gas,
            raw_temperature_adc: 1,
            raw_pressure_adc: 2,
            raw_humidity_adc: 3,
            raw_gas_resistance_adc: 4,
            raw_gas_range: 5,
            repetition_multiplier: 1,
            raw_heater_resistance: 6,
            raw_heater_current: 7,
            raw_gas_wait: 8,
        }
    }

    fn complete_profile_scan() -> ProfileScan {
        ProfileScan {
            identity: RecordIdentity {
                common_flags: COMMON_FLAG_BOOT_ID_VALID,
                node_id: 1,
                boot_id: 2,
                scan_sequence: 3,
                uptime_ms: 4,
                config_id: 7,
                reset_cause_flags: 0,
            },
            profile_id: 5,
            profile_version: 6,
            expected_steps: 3,
            observed_unique_steps: 3,
            observed_field_count: 3,
            reported_missing_steps: 0,
            duplicate_steps: 0,
            duration_us: 300_000,
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
            poll_count: 6,
            expected_fragment_count: 1,
            received_fragment_bitmap: 1,
            duplicate_fragment_count: 0,
            conflicting_fragment_count: 0,
            steps: vec![
                profile_step(2, 30_000, 0xb0),
                profile_step(0, 10_000, 0xb0),
                profile_step(1, 20_000, 0xb0),
            ],
        }
    }

    fn matching_configuration(scan: &ProfileScan) -> DeviceConfiguration {
        DeviceConfiguration {
            identity: scan.identity,
            repeated: true,
            config_flags: CONFIG_FLAG_SENSOR_CONFIG_READ_BACK,
            firmware_version: [2, 0, 0],
            firmware_build_flags: 0,
            firmware_build_id: 1,
            sensor_chip_id: 0x61,
            sensor_variant: 1,
            sensor_i2c_address: 0x76,
            temperature_oversampling: 2,
            humidity_oversampling: 1,
            pressure_oversampling: 16,
            iir_filter: 0,
            standby_time: 0,
            operation_mode: 2,
            heater_enabled: 1,
            parallel_requested_shared_wait_ms: 99,
            parallel_shared_wait_register: 0x73,
            parallel_quantized_shared_wait_us: 97_308,
            tphg_duration_us: 41_590,
            expected_profile_duration_us: scan.duration_us,
            profile_id: scan.profile_id,
            profile_version: scan.profile_version,
            expected_step_count: scan.expected_steps,
            heater_readback_valid_bitmap: (1_u16 << scan.expected_steps) - 1,
            calibration_hash_algorithm: 1,
            calibration_hash: 2,
            scan_interval_ms: 180_000,
            config_repeat_interval_scans: 6,
            output_routes: 1,
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
            max_frame_len: 231,
            profile_steps_per_fragment: 3,
            heater_steps: (0..scan.expected_steps)
                .map(|step_index| HeaterStepConfiguration {
                    step_index,
                    target_temperature_celsius: 200 + u16::from(step_index) * 50,
                    configured_duration_us: 100_000,
                    repetition_multiplier: 1,
                    readback_heater_current: 7,
                    programmed_heater_resistance: 6,
                    programmed_gas_wait: 8,
                })
                .collect(),
        }
    }

    #[test]
    fn v1_quality_and_temporal_features_preserve_exact_units() {
        let frame = decode_hex(FIXTURE).unwrap();
        let first = AnalysisSample::from_v1(&frame, 1_000);
        assert!(first.quality.is_empty());

        let mut extractor = TemporalFeatureExtractor::default();
        let first_features = extractor.ingest(first);
        assert!((first_features.temperature_celsius + 12.34).abs() < 1e-12);
        assert!((first_features.humidity_percent_rh - 45.678).abs() < 1e-12);
        assert_eq!(first_features.elapsed_ms, None);
        assert_eq!(first_features.elapsed_us, None);

        let mut second = first;
        second.sequence += 1;
        second.received_at_unix_ms += 60_000;
        second.temperature_centi_celsius += 100;
        second.humidity_milli_percent_rh -= 1_000;
        second.gas_resistance_ohm /= 2;
        let second_features = extractor.ingest(second);
        assert_eq!(second_features.elapsed_ms, Some(60_000));
        assert_eq!(second_features.elapsed_us, Some(60_000_000));
        assert_eq!(
            second_features.temperature_rate_celsius_per_minute,
            Some(1.0)
        );
        assert_eq!(second_features.humidity_rate_percent_per_minute, Some(-1.0));
        let gas_rate = second_features.gas_log_rate_per_minute.unwrap();
        assert!((gas_rate + core::f64::consts::LN_2).abs() < 1e-12);
    }

    #[test]
    fn bad_quality_does_not_pollute_temporal_history() {
        let frame = decode_hex(FIXTURE).unwrap();
        let mut valid = AnalysisSample::from_v1(&frame, 1_000);
        let mut invalid = valid;
        invalid.received_at_unix_ms = 61_000;
        invalid.quality = QualityFlags::GAS_INVALID;
        valid.received_at_unix_ms = 121_000;

        let mut extractor = TemporalFeatureExtractor::default();
        let _ = extractor.ingest(AnalysisSample::from_v1(&frame, 1_000));
        assert_eq!(extractor.ingest(invalid).elapsed_ms, None);
        assert_eq!(extractor.ingest(valid).elapsed_ms, Some(120_000));
    }

    #[test]
    fn profile_temporal_history_isolated_by_step_and_profile_definition() {
        let scan = complete_profile_scan();
        let step_zero = scan.steps.iter().find(|step| step.step_index == 0).unwrap();
        let step_one = scan.steps.iter().find(|step| step.step_index == 1).unwrap();
        let mut extractor = TemporalFeatureExtractor::default();

        let first = AnalysisSample::from_profile_step(&scan, step_zero, 1_000);
        assert_eq!(extractor.ingest(first).elapsed_ms, None);
        let other_step = AnalysisSample::from_profile_step(&scan, step_one, 61_000);
        assert_eq!(extractor.ingest(other_step).elapsed_ms, None);

        let mut other_profile = scan.clone();
        other_profile.identity.config_id += 1;
        other_profile.profile_version += 1;
        let other_profile_step = other_profile
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let changed_definition =
            AnalysisSample::from_profile_step(&other_profile, other_profile_step, 121_000);
        assert_eq!(extractor.ingest(changed_definition).elapsed_ms, None);

        let mut later_scan = scan.clone();
        later_scan.identity.scan_sequence += 1;
        later_scan.identity.uptime_ms += 180_000;
        let later_step = later_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let same_series = AnalysisSample::from_profile_step(&later_scan, later_step, 181_000);
        assert_eq!(extractor.ingest(same_series).elapsed_ms, Some(180_000));
    }

    #[test]
    fn unavailable_boot_nonce_never_builds_v2_temporal_history() {
        let mut scan = complete_profile_scan();
        scan.identity.common_flags &= !COMMON_FLAG_BOOT_ID_VALID;
        scan.identity.boot_id = 0;
        let step = scan.steps.iter().find(|step| step.step_index == 0).unwrap();
        let first = AnalysisSample::from_profile_step(&scan, step, 1_000);
        let second = AnalysisSample::from_profile_step(&scan, step, 61_000);
        assert_eq!(first.boot_id, None);
        assert_eq!(extract_profile_features(&scan).boot_id, None);

        let mut extractor = TemporalFeatureExtractor::default();
        assert_eq!(extractor.ingest(first).elapsed_ms, None);
        assert_eq!(extractor.ingest(second).elapsed_ms, None);
    }

    #[test]
    fn profile_features_preserve_shape_and_gate_bad_steps() {
        let scan = complete_profile_scan();
        let features = extract_profile_features(&scan);
        assert!(features.profile_quality_usable);
        assert!(!features.configuration_resolved);
        assert!(!features.usable_for_analysis);
        let resolved =
            extract_profile_features_with_configuration(&scan, &matching_configuration(&scan));
        assert!(resolved.configuration_resolved);
        assert!(resolved.usable_for_analysis);
        let mut wrong_configuration = matching_configuration(&scan);
        wrong_configuration.identity.config_id ^= 1;
        let unresolved = extract_profile_features_with_configuration(&scan, &wrong_configuration);
        assert!(!unresolved.configuration_resolved);
        assert!(!unresolved.usable_for_analysis);
        for field in 0..6 {
            let mut mismatched = matching_configuration(&scan);
            match field {
                0 => mismatched.heater_steps[0].target_temperature_celsius += 1,
                1 => mismatched.heater_steps[0].configured_duration_us += 1,
                2 => mismatched.heater_steps[0].repetition_multiplier += 1,
                3 => mismatched.heater_steps[0].readback_heater_current += 1,
                4 => mismatched.heater_steps[0].programmed_heater_resistance += 1,
                5 => mismatched.heater_steps[0].programmed_gas_wait += 1,
                _ => unreachable!(),
            }
            let features = extract_profile_features_with_configuration(&scan, &mismatched);
            assert!(!features.configuration_resolved, "mismatched field {field}");
            assert!(!features.usable_for_analysis);
        }
        let mut missing_readback_flag = matching_configuration(&scan);
        missing_readback_flag.config_flags &= !CONFIG_FLAG_SENSOR_CONFIG_READ_BACK;
        assert!(missing_readback_flag.validate().is_ok());
        assert!(
            !extract_profile_features_with_configuration(&scan, &missing_readback_flag)
                .configuration_resolved
        );
        for bitmap in [0, 0b011] {
            let mut partial_readback = matching_configuration(&scan);
            partial_readback.heater_readback_valid_bitmap = bitmap;
            assert!(partial_readback.validate().is_ok());
            assert!(
                !extract_profile_features_with_configuration(&scan, &partial_readback)
                    .configuration_resolved
            );
        }
        assert_eq!(features.config_id, scan.identity.config_id);
        assert_eq!(
            features
                .steps
                .iter()
                .map(|step| step.step_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        let mut invalid = scan;
        invalid.steps[1].status_bits = 0x80;
        let invalid_features = extract_profile_features(&invalid);
        assert!(!invalid_features.profile_quality_usable);
        assert_ne!(invalid_features.steps[0].quality_flags, 0);
    }

    #[test]
    fn profile_analysis_rejects_noncomplete_and_collector_anomaly_scans() {
        let complete = complete_profile_scan();
        assert!(extract_profile_features(&complete).profile_quality_usable);

        let mut noncomplete = complete.clone();
        noncomplete.finish_reason = vesta_protocol::v2::FINISH_REASON_TIMEOUT;
        assert!(!extract_profile_features(&noncomplete).profile_quality_usable);

        for flag in [
            vesta_protocol::v2::COLLECTION_FLAG_CONFIG_MISMATCH,
            vesta_protocol::v2::COLLECTION_FLAG_I2C_ERROR,
            vesta_protocol::v2::COLLECTION_FLAG_OVERWRITTEN,
            vesta_protocol::v2::COLLECTION_FLAG_STALE_PRE_SCAN_FIELDS,
            1 << 31,
        ] {
            let mut flagged = complete.clone();
            flagged.collection_flags = flag;
            assert!(!extract_profile_features(&flagged).profile_quality_usable);
        }

        let mut overwritten = complete.clone();
        overwritten.overwritten_field_count = 1;
        assert!(!extract_profile_features(&overwritten).profile_quality_usable);

        let mut out_of_order = complete.clone();
        out_of_order.out_of_order_count = 1;
        assert!(!extract_profile_features(&out_of_order).profile_quality_usable);

        let mut ambiguous_index = complete.clone();
        ambiguous_index.ambiguous_index_jump_count = 1;
        assert!(!extract_profile_features(&ambiguous_index).profile_quality_usable);

        let mut rollover = complete;
        rollover.profile_rollover_count = 1;
        assert!(!extract_profile_features(&rollover).profile_quality_usable);
    }

    #[test]
    fn profile_without_a_valid_boot_nonce_is_never_analysis_ready() {
        let mut scan = complete_profile_scan();
        scan.identity.common_flags &= !COMMON_FLAG_BOOT_ID_VALID;
        scan.identity.boot_id = 0;
        let configuration = matching_configuration(&scan);

        let features = extract_profile_features_with_configuration(&scan, &configuration);
        assert!(!features.profile_quality_usable);
        assert!(features.configuration_resolved);
        assert!(!features.usable_for_analysis);
    }

    #[test]
    fn complete_terminal_profile_allows_expected_polling_duplicates() {
        let mut scan = complete_profile_scan();
        scan.observed_field_count = 9;
        scan.duplicate_steps = 0b101;
        scan.duplicate_count = 4;
        scan.intermediate_field_count = 2;
        scan.collection_flags = vesta_protocol::v2::COLLECTION_FLAG_DUPLICATE;
        assert!(extract_profile_features(&scan).profile_quality_usable);
    }

    #[test]
    fn verified_sensor_reconfiguration_resets_only_the_exact_series_history() {
        let normal = complete_profile_scan();
        let normal_step = normal
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let mut extractor = TemporalFeatureExtractor::default();
        let first = AnalysisSample::from_profile_step(&normal, normal_step, 1_000);
        assert_eq!(extractor.ingest(first).elapsed_ms, None);

        let mut recovered = normal.clone();
        recovered.identity.scan_sequence += 1;
        recovered.identity.uptime_ms += 60_000;
        recovered.collection_flags = COLLECTION_FLAG_SENSOR_RECONFIGURED;
        let recovered_step = recovered
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        assert!(extract_profile_features(&recovered).profile_quality_usable);
        let recovery = AnalysisSample::from_profile_step(&recovered, recovered_step, 61_000);
        assert!(recovery.reset_temporal_history);
        let recovery_features = extractor.ingest(recovery);
        assert!(recovery_features.temporal_history_reset);
        assert_eq!(recovery_features.elapsed_ms, None);

        let mut after = recovered.clone();
        after.identity.scan_sequence += 1;
        after.identity.uptime_ms += 60_000;
        after.collection_flags = 0;
        let after_step = after
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let after_sample = AnalysisSample::from_profile_step(&after, after_step, 121_000);
        assert_eq!(extractor.ingest(after_sample).elapsed_ms, Some(60_000));
    }

    #[test]
    fn v2_rates_use_device_uptime_despite_delayed_and_out_of_order_delivery() {
        let first_scan = complete_profile_scan();
        let first_step = first_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let first = AnalysisSample::from_profile_step(&first_scan, first_step, 500_000);

        let mut later_scan = first_scan.clone();
        later_scan.identity.scan_sequence += 1;
        later_scan.identity.uptime_ms += 60_000;
        later_scan.steps[1].temperature_centi_celsius += 100;
        let later_step = later_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        // This newer device sample arrived earlier according to the host clock.
        let later = AnalysisSample::from_profile_step(&later_scan, later_step, 100_000);

        let mut extractor = TemporalFeatureExtractor::default();
        assert_eq!(extractor.ingest(first).elapsed_us, None);
        let features = extractor.ingest(later);
        assert_eq!(features.received_at_unix_ms, 100_000);
        assert_eq!(features.elapsed_us, Some(60_000_000));
        assert_eq!(features.temperature_rate_celsius_per_minute, Some(1.0));

        let mut delayed_old_scan = first_scan.clone();
        delayed_old_scan.identity.uptime_ms += 30_000;
        delayed_old_scan.steps[1].temperature_centi_celsius += 500;
        let delayed_old_step = delayed_old_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let delayed_old =
            AnalysisSample::from_profile_step(&delayed_old_scan, delayed_old_step, 900_000);
        let delayed_features = extractor.ingest(delayed_old);
        assert!(!delayed_features.temporal_history_reset);
        assert_eq!(delayed_features.elapsed_us, None);

        let mut newest_scan = later_scan.clone();
        newest_scan.identity.scan_sequence += 1;
        newest_scan.identity.uptime_ms += 60_000;
        newest_scan.steps[1].temperature_centi_celsius += 100;
        let newest_step = newest_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let newest = AnalysisSample::from_profile_step(&newest_scan, newest_step, 200_000);
        let features = extractor.ingest(newest);
        assert_eq!(features.elapsed_us, Some(60_000_000));
        assert_eq!(features.temperature_rate_celsius_per_minute, Some(1.0));
    }

    #[test]
    fn v2_step_offset_contributes_to_exact_elapsed_time() {
        let first_scan = complete_profile_scan();
        let first_step = first_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let first = AnalysisSample::from_profile_step(&first_scan, first_step, 1_000);

        let mut second_scan = first_scan.clone();
        second_scan.identity.scan_sequence += 1;
        second_scan.identity.uptime_ms += 1_000;
        second_scan.steps[1].relative_offset_us += 500;
        let second_step = second_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let second = AnalysisSample::from_profile_step(&second_scan, second_step, 2_000);

        let mut extractor = TemporalFeatureExtractor::default();
        let _ = extractor.ingest(first);
        let features = extractor.ingest(second);
        assert_eq!(features.elapsed_us, Some(1_000_500));
        assert_eq!(features.elapsed_ms, Some(1_000));
    }

    #[test]
    fn lost_v2_scan_resets_history_instead_of_bridging_a_hidden_reconfiguration() {
        let first_scan = complete_profile_scan();
        let first_step = first_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let first = AnalysisSample::from_profile_step(&first_scan, first_step, 1_000);

        // Sequence 4 could have carried SENSOR_RECONFIGURED but was lost in
        // transit. Sequence 5 must not derive a rate across that invisible gap.
        let mut after_gap_scan = first_scan.clone();
        after_gap_scan.identity.scan_sequence += 2;
        after_gap_scan.identity.uptime_ms += 120_000;
        let after_gap_step = after_gap_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let after_gap = AnalysisSample::from_profile_step(&after_gap_scan, after_gap_step, 2_000);

        let mut extractor = TemporalFeatureExtractor::default();
        let _ = extractor.ingest(first);
        let reset = extractor.ingest(after_gap);
        assert!(reset.temporal_history_reset);
        assert_eq!(reset.elapsed_us, None);

        let mut next_scan = after_gap_scan.clone();
        next_scan.identity.scan_sequence += 1;
        next_scan.identity.uptime_ms += 60_000;
        let next_step = next_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let next = AnalysisSample::from_profile_step(&next_scan, next_step, 3_000);
        let resumed = extractor.ingest(next);
        assert!(!resumed.temporal_history_reset);
        assert_eq!(resumed.elapsed_us, Some(60_000_000));
    }

    #[test]
    fn v2_sequence_wrap_is_continuous() {
        let mut first_scan = complete_profile_scan();
        first_scan.identity.scan_sequence = u32::MAX;
        let first_step = first_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let first = AnalysisSample::from_profile_step(&first_scan, first_step, 1_000);

        let mut wrapped_scan = first_scan.clone();
        wrapped_scan.identity.scan_sequence = 0;
        wrapped_scan.identity.uptime_ms += 60_000;
        let wrapped_step = wrapped_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let wrapped = AnalysisSample::from_profile_step(&wrapped_scan, wrapped_step, 2_000);

        let mut extractor = TemporalFeatureExtractor::default();
        let _ = extractor.ingest(first);
        let features = extractor.ingest(wrapped);
        assert!(!features.temporal_history_reset);
        assert_eq!(features.elapsed_us, Some(60_000_000));
    }

    #[test]
    fn delayed_older_reconfiguration_marker_does_not_erase_newer_history() {
        let first_scan = complete_profile_scan();
        let first_step = first_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let first = AnalysisSample::from_profile_step(&first_scan, first_step, 1_000);

        let mut newer_scan = first_scan.clone();
        newer_scan.identity.scan_sequence += 1;
        newer_scan.identity.uptime_ms += 60_000;
        let newer_step = newer_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let newer = AnalysisSample::from_profile_step(&newer_scan, newer_step, 2_000);

        let mut delayed_scan = first_scan.clone();
        delayed_scan.identity.uptime_ms += 30_000;
        delayed_scan.collection_flags = COLLECTION_FLAG_SENSOR_RECONFIGURED;
        let delayed_step = delayed_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let delayed = AnalysisSample::from_profile_step(&delayed_scan, delayed_step, 9_000);
        assert!(delayed.reset_temporal_history);

        let mut next_scan = newer_scan.clone();
        next_scan.identity.scan_sequence += 1;
        next_scan.identity.uptime_ms += 60_000;
        let next_step = next_scan
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let next = AnalysisSample::from_profile_step(&next_scan, next_step, 3_000);

        let mut extractor = TemporalFeatureExtractor::default();
        let _ = extractor.ingest(first);
        assert_eq!(extractor.ingest(newer).elapsed_us, Some(60_000_000));
        let delayed_features = extractor.ingest(delayed);
        assert!(!delayed_features.temporal_history_reset);
        assert_eq!(delayed_features.elapsed_us, None);
        let next_features = extractor.ingest(next);
        assert!(!next_features.temporal_history_reset);
        assert_eq!(next_features.elapsed_us, Some(60_000_000));
    }
}
