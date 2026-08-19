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
    FINISH_REASON_COMPLETE,
};

use crate::records::{ProfileScan, ProfileStep};

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
    /// Quality flags copied from the source sample.
    pub quality_flags: u16,
    /// Whether this observation intentionally cleared its exact series history.
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
        let previous = match key {
            Some(key) if sample.reset_temporal_history => {
                self.previous.remove(&key);
                None
            }
            Some(key) => self.previous.get(&key).copied(),
            None => None,
        };
        let current_gas_log = gas_log(sample.gas_resistance_ohm);
        let mut features = TemporalFeatures {
            node_id: sample.node_id,
            boot_id: sample.boot_id,
            sequence: sample.sequence,
            series: sample.series,
            received_at_unix_ms: sample.received_at_unix_ms,
            quality_flags: sample.quality.bits(),
            temporal_history_reset: sample.reset_temporal_history,
            temperature_celsius: f64::from(sample.temperature_centi_celsius) / 100.0,
            pressure_hectopascal: f64::from(sample.pressure_pascal) / 100.0,
            humidity_percent_rh: f64::from(sample.humidity_milli_percent_rh) / 1_000.0,
            gas_log_ohm: current_gas_log,
            elapsed_ms: None,
            temperature_rate_celsius_per_minute: None,
            humidity_rate_percent_per_minute: None,
            pressure_rate_hectopascal_per_minute: None,
            gas_log_rate_per_minute: None,
        };

        let usable_previous = previous.filter(|prior| {
            sample.quality.is_empty()
                && prior.quality.is_empty()
                && sample.received_at_unix_ms > prior.received_at_unix_ms
        });
        if let Some(prior) = usable_previous {
            let elapsed_ms = sample
                .received_at_unix_ms
                .abs_diff(prior.received_at_unix_ms);
            let minutes = std::time::Duration::from_millis(elapsed_ms).as_secs_f64() / 60.0;
            features.elapsed_ms = Some(elapsed_ms);
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
            && previous.is_none_or(|prior| sample.received_at_unix_ms > prior.received_at_unix_ms)
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
    /// Whether the record is structurally consistent and all expected steps
    /// pass sensor quality gates.
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
#[must_use]
pub fn extract_profile_features(scan: &ProfileScan) -> ProfileFeatures {
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

    let usable = scan_usable && steps.iter().all(|step| step.quality_flags == 0);
    ProfileFeatures {
        node_id: scan.identity.node_id,
        boot_id: (scan.identity.common_flags & COMMON_FLAG_BOOT_ID_VALID != 0)
            .then_some(scan.identity.boot_id),
        sequence: scan.identity.scan_sequence,
        config_id: scan.identity.config_id,
        profile_id: scan.profile_id,
        profile_revision: scan.profile_version,
        missing_steps: scan.computed_unavailable_steps(),
        usable_for_analysis: usable,
        steps,
    }
}

fn profile_scan_allows_analysis(scan: &ProfileScan) -> bool {
    scan.validate().is_ok()
        && scan.is_transport_complete()
        && scan.computed_unavailable_steps() == 0
        && scan.finish_reason == FINISH_REASON_COMPLETE
        && scan.collection_flags & !ANALYSIS_ALLOWED_COLLECTION_FLAGS == 0
        && scan.overwritten_field_count == 0
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
    use crate::records::{ProfileStep, RecordIdentity};

    const FIXTURE: &str = "565301b001020304050607080a0b0c0dfb2e00018bcd0000b26e000f12060007eed00005902075300200080203040506";

    fn profile_step(index: u8, gas: u32, status_bits: u8) -> ProfileStep {
        ProfileStep {
            step_index: index,
            gas_index: index,
            measurement_index: index,
            status_bits,
            raw_measurement_status: status_bits & 0x80,
            raw_gas_status: status_bits & 0x30,
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

        let mut second = first;
        second.sequence += 1;
        second.received_at_unix_ms += 60_000;
        second.temperature_centi_celsius += 100;
        second.humidity_milli_percent_rh -= 1_000;
        second.gas_resistance_ohm /= 2;
        let second_features = extractor.ingest(second);
        assert_eq!(second_features.elapsed_ms, Some(60_000));
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

        let same_series = AnalysisSample::from_profile_step(&scan, step_zero, 181_000);
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
        assert!(features.usable_for_analysis);
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
        assert!(!invalid_features.usable_for_analysis);
        assert_ne!(invalid_features.steps[0].quality_flags, 0);
    }

    #[test]
    fn profile_analysis_rejects_noncomplete_and_collector_anomaly_scans() {
        let complete = complete_profile_scan();
        assert!(extract_profile_features(&complete).usable_for_analysis);

        let mut noncomplete = complete.clone();
        noncomplete.finish_reason = vesta_protocol::v2::FINISH_REASON_TIMEOUT;
        assert!(!extract_profile_features(&noncomplete).usable_for_analysis);

        for flag in [
            vesta_protocol::v2::COLLECTION_FLAG_CONFIG_MISMATCH,
            vesta_protocol::v2::COLLECTION_FLAG_I2C_ERROR,
            vesta_protocol::v2::COLLECTION_FLAG_OVERWRITTEN,
            vesta_protocol::v2::COLLECTION_FLAG_STALE_PRE_SCAN_FIELDS,
            1 << 31,
        ] {
            let mut flagged = complete.clone();
            flagged.collection_flags = flag;
            assert!(!extract_profile_features(&flagged).usable_for_analysis);
        }

        let mut overwritten = complete.clone();
        overwritten.overwritten_field_count = 1;
        assert!(!extract_profile_features(&overwritten).usable_for_analysis);

        let mut rollover = complete;
        rollover.profile_rollover_count = 1;
        assert!(!extract_profile_features(&rollover).usable_for_analysis);
    }

    #[test]
    fn complete_terminal_profile_allows_expected_polling_duplicates() {
        let mut scan = complete_profile_scan();
        scan.observed_field_count = 9;
        scan.duplicate_steps = 0b101;
        scan.duplicate_count = 4;
        scan.intermediate_field_count = 2;
        scan.collection_flags = vesta_protocol::v2::COLLECTION_FLAG_DUPLICATE;
        assert!(extract_profile_features(&scan).usable_for_analysis);
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
        recovered.collection_flags = COLLECTION_FLAG_SENSOR_RECONFIGURED;
        let recovered_step = recovered
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        assert!(extract_profile_features(&recovered).usable_for_analysis);
        let recovery = AnalysisSample::from_profile_step(&recovered, recovered_step, 61_000);
        assert!(recovery.reset_temporal_history);
        let recovery_features = extractor.ingest(recovery);
        assert!(recovery_features.temporal_history_reset);
        assert_eq!(recovery_features.elapsed_ms, None);

        let mut after = recovered.clone();
        after.identity.scan_sequence += 1;
        after.collection_flags = 0;
        let after_step = after
            .steps
            .iter()
            .find(|step| step.step_index == 0)
            .unwrap();
        let after_sample = AnalysisSample::from_profile_step(&after, after_step, 121_000);
        assert_eq!(extractor.ingest(after_sample).elapsed_ms, Some(60_000));
    }
}
