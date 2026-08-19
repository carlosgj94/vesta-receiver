//! Deterministic quality gates and feature extraction for server-side analysis.
//!
//! This module intentionally contains no fire classifier or alert thresholds.
//! It converts validated telemetry into reproducible numerical features that a
//! later rule engine or trained model can consume.

use std::collections::HashMap;

use serde::Serialize;
use vesta_protocol::TelemetryV1;

use crate::records::{ProfileScan, ProfileStep};

const MIN_TEMPERATURE_CENTI_CELSIUS: i16 = -4_000;
const MAX_TEMPERATURE_CENTI_CELSIUS: i16 = 8_500;
const MIN_PRESSURE_PASCAL: u32 = 30_000;
const MAX_PRESSURE_PASCAL: u32 = 110_000;
const MAX_HUMIDITY_MILLI_PERCENT_RH: u32 = 100_000;

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

/// Exact server-side observation before derivative calculation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AnalysisSample {
    /// Stable device node identity.
    pub node_id: u64,
    /// Optional boot nonce, unavailable in protocol v1.
    pub boot_id: Option<u32>,
    /// Sequence within the protocol stream or profile stream.
    pub sequence: u32,
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
            received_at_unix_ms,
            temperature_centi_celsius: temperature,
            pressure_pascal: pressure,
            humidity_milli_percent_rh: humidity,
            gas_resistance_ohm: gas,
            quality: sample_quality(status.bits(), temperature, pressure, humidity, gas),
        }
    }

    /// Construct an observation from one step of a decoded profile scan.
    #[must_use]
    pub fn from_profile_step(
        scan: &ProfileScan,
        step: &ProfileStep,
        received_at_unix_ms: i64,
    ) -> Self {
        Self {
            node_id: scan.identity.node_id,
            boot_id: Some(scan.identity.boot_id),
            sequence: scan.identity.sequence,
            received_at_unix_ms,
            temperature_centi_celsius: step.temperature_centi_celsius,
            pressure_pascal: step.pressure_pascal,
            humidity_milli_percent_rh: step.humidity_milli_percent_rh,
            gas_resistance_ohm: step.gas_resistance_ohm,
            quality: sample_quality(
                step.status_bits,
                step.temperature_centi_celsius,
                step.pressure_pascal,
                step.humidity_milli_percent_rh,
                step.gas_resistance_ohm,
            ),
        }
    }
}

/// Numerical features for one chronologically ingested observation.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct TemporalFeatures {
    /// Stable node identity.
    pub node_id: u64,
    /// Optional boot nonce.
    pub boot_id: Option<u32>,
    /// Device sequence.
    pub sequence: u32,
    /// Host receive time in Unix milliseconds.
    pub received_at_unix_ms: i64,
    /// Quality flags copied from the source sample.
    pub quality_flags: u16,
    /// Temperature in degrees Celsius.
    pub temperature_celsius: f64,
    /// Pressure in hectopascals.
    pub pressure_hectopascal: f64,
    /// Relative humidity in percent.
    pub humidity_percent_rh: f64,
    /// Natural logarithm of gas resistance in ohms, if non-zero.
    pub gas_log_ohm: Option<f64>,
    /// Elapsed time from the prior usable sample from the same node and boot.
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

/// Stateful chronological feature extractor, isolated per node and boot.
#[derive(Debug, Default)]
pub struct TemporalFeatureExtractor {
    previous: HashMap<(u64, Option<u32>), AnalysisSample>,
}

impl TemporalFeatureExtractor {
    /// Extract features and update history only when the sample passes quality
    /// gates and is newer than the prior observation.
    #[must_use]
    pub fn ingest(&mut self, sample: AnalysisSample) -> TemporalFeatures {
        let key = (sample.node_id, sample.boot_id);
        let previous = self.previous.get(&key).copied();
        let current_gas_log = gas_log(sample.gas_resistance_ohm);
        let mut features = TemporalFeatures {
            node_id: sample.node_id,
            boot_id: sample.boot_id,
            sequence: sample.sequence,
            received_at_unix_ms: sample.received_at_unix_ms,
            quality_flags: sample.quality.bits(),
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
            self.previous.insert(key, sample);
        }
        features
    }
}

/// Per-step gas features from one heater profile, without temporal baselining.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ProfileFeatures {
    /// Stable node identity.
    pub node_id: u64,
    /// Per-boot nonce.
    pub boot_id: u32,
    /// Profile scan sequence.
    pub sequence: u32,
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
    let structural_valid = scan.validate().is_ok();
    let mut steps = scan
        .steps
        .iter()
        .map(|step| {
            let quality = sample_quality(
                step.status_bits,
                step.temperature_centi_celsius,
                step.pressure_pascal,
                step.humidity_milli_percent_rh,
                step.gas_resistance_ohm,
            );
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

    let usable = structural_valid
        && scan.computed_missing_steps() == 0
        && steps.iter().all(|step| step.quality_flags == 0);
    ProfileFeatures {
        node_id: scan.identity.node_id,
        boot_id: scan.identity.boot_id,
        sequence: scan.identity.sequence,
        profile_id: scan.profile_id,
        profile_revision: scan.profile_revision,
        missing_steps: scan.computed_missing_steps(),
        usable_for_analysis: usable,
        steps,
    }
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
            target_temperature_celsius: 200 + u16::from(index) * 50,
            heater_duration_ms: 100,
            relative_offset_ms: u32::from(index) * 100,
            status_bits,
            temperature_centi_celsius: 2_500,
            pressure_pascal: 101_325,
            humidity_milli_percent_rh: 40_000,
            gas_resistance_ohm: gas,
            raw_temperature_adc: 1,
            raw_pressure_adc: 2,
            raw_humidity_adc: 3,
            raw_gas_resistance_adc: 4,
            raw_gas_range: 5,
            raw_heater_resistance: 6,
            raw_heater_current: 7,
            raw_gas_wait: 8,
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
    fn profile_features_preserve_shape_and_gate_bad_steps() {
        let scan = ProfileScan {
            identity: RecordIdentity {
                node_id: 1,
                boot_id: 2,
                sequence: 3,
                uptime_ms: 4,
            },
            profile_id: 5,
            profile_revision: 6,
            expected_steps: 3,
            reported_missing_steps: 0,
            duration_ms: 300,
            collection_flags: 0,
            steps: vec![
                profile_step(2, 30_000, 0xb0),
                profile_step(0, 10_000, 0xb0),
                profile_step(1, 20_000, 0xb0),
            ],
        };
        let features = extract_profile_features(&scan);
        assert!(features.usable_for_analysis);
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
}
