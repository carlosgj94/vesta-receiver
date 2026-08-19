//! Protocol-independent records consumed by server storage and analytics.
//!
//! The on-air protocol decoder maps bytes into these types. Keeping these
//! records independent of a particular frame layout lets protocol v2 evolve
//! without coupling `SQLite` or analytical code to byte offsets.

use core::fmt;

use serde::Serialize;

/// Maximum number of heater steps supported by the BME688.
pub const MAX_HEATER_STEPS: u8 = 10;

/// Stable identity and timing shared by records from one device boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RecordIdentity {
    /// Stable 64-bit node identity derived by the embedded firmware.
    pub node_id: u64,
    /// Random nonce generated once for this boot.
    pub boot_id: u32,
    /// Monotonic record sequence within the boot.
    pub sequence: u32,
    /// Monotonic device uptime when acquisition began.
    pub uptime_ms: u64,
}

/// One configured BME688 heater step.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct HeaterStepConfiguration {
    /// Zero-based position in the heater profile.
    pub step_index: u8,
    /// Requested heater temperature in degrees Celsius.
    pub target_temperature_celsius: u16,
    /// Requested heater duration in milliseconds.
    pub duration_ms: u16,
}

/// Device and sensor configuration needed to reproduce a measurement profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceConfiguration {
    /// Identity of the configuration announcement.
    pub identity: RecordIdentity,
    /// Firmware build or source revision chosen by the embedded build.
    pub firmware_version: String,
    /// Raw reset-cause flags captured before firmware clears them.
    pub reset_cause_bits: u32,
    /// BME688 variant identifier, preserved exactly from the firmware.
    pub sensor_variant: u8,
    /// Optional stable hash of the sensor calibration block.
    pub calibration_hash: Option<u64>,
    /// Raw humidity oversampling configuration value.
    pub humidity_oversampling: u8,
    /// Raw temperature oversampling configuration value.
    pub temperature_oversampling: u8,
    /// Raw pressure oversampling configuration value.
    pub pressure_oversampling: u8,
    /// Raw IIR filter configuration value.
    pub iir_filter: u8,
    /// Raw BME688 operation-mode value.
    pub operation_mode: u8,
    /// Stable profile identifier assigned by firmware.
    pub profile_id: u16,
    /// Revision of the identified profile.
    pub profile_revision: u16,
    /// Requested interval between profile starts.
    pub scan_interval_ms: u32,
    /// Configured transmitter power in one hundredth of a dBm.
    pub tx_power_centi_dbm: i16,
    /// Configured `LoRa` center frequency.
    pub radio_frequency_hz: u32,
    /// Configured `LoRa` spreading factor.
    pub radio_spreading_factor: u8,
    /// Configured `LoRa` bandwidth.
    pub radio_bandwidth_hz: u32,
    /// Configured `LoRa` coding-rate denominator offset.
    pub radio_coding_rate: u8,
    /// Ordered heater steps used by this profile.
    pub heater_steps: Vec<HeaterStepConfiguration>,
}

impl DeviceConfiguration {
    /// Validate that the heater profile is bounded and ordered from step zero.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile is empty, exceeds the BME688 limit,
    /// or does not contain the contiguous ordered indices `0..len`.
    pub fn validate(&self) -> Result<(), RecordError> {
        let step_count = u8::try_from(self.heater_steps.len()).unwrap_or(u8::MAX);
        if !(1..=MAX_HEATER_STEPS).contains(&step_count) {
            return Err(RecordError::InvalidExpectedSteps(step_count));
        }

        for (step, position) in self.heater_steps.iter().zip(0_u8..step_count) {
            if step.step_index != position {
                return Err(RecordError::ConfigurationStepOrder {
                    position,
                    step_index: step.step_index,
                });
            }
        }
        Ok(())
    }
}

/// Exact sensor values captured for one heater step.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileStep {
    /// Zero-based position in the configured profile.
    pub step_index: u8,
    /// BME688 gas-index field.
    pub gas_index: u8,
    /// BME688 measurement-index field.
    pub measurement_index: u8,
    /// Requested heater temperature in degrees Celsius.
    pub target_temperature_celsius: u16,
    /// Requested heater duration in milliseconds.
    pub heater_duration_ms: u16,
    /// Monotonic offset from the beginning of the profile.
    pub relative_offset_ms: u32,
    /// Complete BME688 status byte.
    pub status_bits: u8,
    /// Compensated temperature in hundredths of a degree Celsius.
    pub temperature_centi_celsius: i16,
    /// Compensated pressure in pascals.
    pub pressure_pascal: u32,
    /// Compensated relative humidity in thousandths of a percent.
    pub humidity_milli_percent_rh: u32,
    /// Compensated gas resistance in ohms.
    pub gas_resistance_ohm: u32,
    /// Raw temperature ADC value.
    pub raw_temperature_adc: u32,
    /// Raw pressure ADC value.
    pub raw_pressure_adc: u32,
    /// Raw humidity ADC value.
    pub raw_humidity_adc: u16,
    /// Raw gas-resistance ADC value.
    pub raw_gas_resistance_adc: u16,
    /// Raw gas-range field.
    pub raw_gas_range: u8,
    /// Raw heater-resistance register.
    pub raw_heater_resistance: u8,
    /// Raw heater-current register.
    pub raw_heater_current: u8,
    /// Raw gas-wait register.
    pub raw_gas_wait: u8,
}

impl ProfileStep {
    const STATUS_NEW_DATA: u8 = 1 << 7;
    const STATUS_GAS_VALID: u8 = 1 << 5;
    const STATUS_HEATER_STABLE: u8 = 1 << 4;

    /// Whether the sensor marked this field as new.
    #[must_use]
    pub const fn is_new_data(self) -> bool {
        self.status_bits & Self::STATUS_NEW_DATA != 0
    }

    /// Whether the sensor marked the gas measurement as valid.
    #[must_use]
    pub const fn is_gas_valid(self) -> bool {
        self.status_bits & Self::STATUS_GAS_VALID != 0
    }

    /// Whether the sensor heater reached its requested condition.
    #[must_use]
    pub const fn is_heater_stable(self) -> bool {
        self.status_bits & Self::STATUS_HEATER_STABLE != 0
    }
}

/// One complete or explicitly incomplete BME688 heater-profile scan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileScan {
    /// Device identity and monotonic acquisition time.
    pub identity: RecordIdentity,
    /// Heater-profile identifier.
    pub profile_id: u16,
    /// Heater-profile revision.
    pub profile_revision: u16,
    /// Number of steps firmware expected to acquire.
    pub expected_steps: u8,
    /// Missing-step bitmap reported by firmware.
    pub reported_missing_steps: u16,
    /// Total acquisition duration.
    pub duration_ms: u32,
    /// Raw collection flags defined by the eventual wire protocol.
    pub collection_flags: u16,
    /// Steps that were actually recovered and decoded.
    pub steps: Vec<ProfileStep>,
}

impl ProfileScan {
    /// Compute missing profile positions from the decoded steps.
    #[must_use]
    pub fn computed_missing_steps(&self) -> u16 {
        let expected_mask = expected_step_mask(self.expected_steps);
        let observed_mask = self.steps.iter().fold(0_u16, |mask, step| {
            mask | 1_u16.checked_shl(u32::from(step.step_index)).unwrap_or(0)
        });
        expected_mask & !observed_mask
    }

    /// Validate bounded structure and profile completeness metadata.
    ///
    /// Sensor-quality flags are deliberately not structural errors: invalid or
    /// unstable steps must remain storable for later quality analysis.
    ///
    /// # Errors
    ///
    /// Returns an error for impossible step counts, duplicate/out-of-range
    /// indices, or a firmware missing bitmap that disagrees with decoded data.
    pub fn validate(&self) -> Result<(), RecordError> {
        if !(1..=MAX_HEATER_STEPS).contains(&self.expected_steps) {
            return Err(RecordError::InvalidExpectedSteps(self.expected_steps));
        }

        let expected_mask = expected_step_mask(self.expected_steps);
        if self.reported_missing_steps & !expected_mask != 0 {
            return Err(RecordError::MissingBitmapOutOfRange {
                bitmap: self.reported_missing_steps,
                expected_steps: self.expected_steps,
            });
        }

        let mut observed = 0_u16;
        for step in &self.steps {
            if step.step_index >= self.expected_steps {
                return Err(RecordError::StepIndexOutOfRange {
                    index: step.step_index,
                    expected_steps: self.expected_steps,
                });
            }
            let bit = 1_u16 << step.step_index;
            if observed & bit != 0 {
                return Err(RecordError::DuplicateStepIndex(step.step_index));
            }
            observed |= bit;
        }

        let computed = expected_mask & !observed;
        if computed != self.reported_missing_steps {
            return Err(RecordError::MissingBitmapMismatch {
                reported: self.reported_missing_steps,
                computed,
            });
        }
        Ok(())
    }
}

const fn expected_step_mask(expected_steps: u8) -> u16 {
    if expected_steps >= 16 {
        u16::MAX
    } else {
        (1_u16 << expected_steps) - 1
    }
}

/// Periodic health counters reported without interpreting fire risk.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceHealth {
    /// Device identity and monotonic report time.
    pub identity: RecordIdentity,
    /// Raw reset-cause flags.
    pub reset_cause_bits: u32,
    /// Completed sensor scans.
    pub successful_scans: u32,
    /// Failed sensor scans.
    pub failed_scans: u32,
    /// Profiles reported incomplete.
    pub incomplete_profiles: u32,
    /// I2C transaction errors.
    pub i2c_errors: u32,
    /// Radio transmission errors.
    pub radio_errors: u32,
    /// Profiles or fragments dropped before transmission.
    pub dropped_records: u32,
    /// Optional calibrated MCU temperature in hundredths of a degree Celsius.
    pub mcu_temperature_centi_celsius: Option<i16>,
    /// Optional calibrated device supply estimate in millivolts.
    pub vdd_millivolt: Option<u16>,
}

/// Structurally invalid decoded record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordError {
    /// Firmware declared an unsupported step count.
    InvalidExpectedSteps(u8),
    /// A reported missing bit lies beyond the configured profile.
    MissingBitmapOutOfRange {
        /// Firmware-provided bitmap.
        bitmap: u16,
        /// Expected number of steps.
        expected_steps: u8,
    },
    /// A decoded step index lies beyond the configured profile.
    StepIndexOutOfRange {
        /// Invalid step index.
        index: u8,
        /// Expected number of steps.
        expected_steps: u8,
    },
    /// Two decoded steps use the same profile index.
    DuplicateStepIndex(u8),
    /// A configured heater step is not in contiguous profile order.
    ConfigurationStepOrder {
        /// Position of the step in the configuration record.
        position: u8,
        /// Index declared by the step.
        step_index: u8,
    },
    /// Firmware and receiver disagree about which steps are missing.
    MissingBitmapMismatch {
        /// Firmware-provided bitmap.
        reported: u16,
        /// Bitmap derived from decoded steps.
        computed: u16,
    },
}

impl fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidExpectedSteps(count) => {
                write!(formatter, "invalid expected heater-step count {count}")
            }
            Self::MissingBitmapOutOfRange {
                bitmap,
                expected_steps,
            } => write!(
                formatter,
                "missing-step bitmap 0x{bitmap:04x} exceeds {expected_steps} expected steps"
            ),
            Self::StepIndexOutOfRange {
                index,
                expected_steps,
            } => write!(
                formatter,
                "heater-step index {index} exceeds {expected_steps} expected steps"
            ),
            Self::DuplicateStepIndex(index) => {
                write!(formatter, "duplicate heater-step index {index}")
            }
            Self::ConfigurationStepOrder {
                position,
                step_index,
            } => write!(
                formatter,
                "heater-step at profile position {position} declares index {step_index}"
            ),
            Self::MissingBitmapMismatch { reported, computed } => write!(
                formatter,
                "reported missing-step bitmap 0x{reported:04x} differs from decoded bitmap 0x{computed:04x}"
            ),
        }
    }
}

impl std::error::Error for RecordError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(index: u8) -> ProfileStep {
        ProfileStep {
            step_index: index,
            gas_index: index,
            measurement_index: index,
            target_temperature_celsius: 300,
            heater_duration_ms: 100,
            relative_offset_ms: u32::from(index) * 100,
            status_bits: 0xb0,
            temperature_centi_celsius: 2_500,
            pressure_pascal: 101_325,
            humidity_milli_percent_rh: 40_000,
            gas_resistance_ohm: 20_000,
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

    fn scan(steps: Vec<ProfileStep>, reported_missing_steps: u16) -> ProfileScan {
        ProfileScan {
            identity: RecordIdentity {
                node_id: 1,
                boot_id: 2,
                sequence: 3,
                uptime_ms: 4,
            },
            profile_id: 5,
            profile_revision: 6,
            expected_steps: 3,
            reported_missing_steps,
            duration_ms: 300,
            collection_flags: 0,
            steps,
        }
    }

    #[test]
    fn validates_complete_and_explicitly_incomplete_profiles() {
        let complete = scan(vec![step(0), step(1), step(2)], 0);
        assert_eq!(complete.computed_missing_steps(), 0);
        assert_eq!(complete.validate(), Ok(()));

        let incomplete = scan(vec![step(0), step(2)], 0b010);
        assert_eq!(incomplete.computed_missing_steps(), 0b010);
        assert_eq!(incomplete.validate(), Ok(()));
    }

    #[test]
    fn rejects_duplicate_and_inconsistent_profile_metadata() {
        assert_eq!(
            scan(vec![step(0), step(0)], 0b110).validate(),
            Err(RecordError::DuplicateStepIndex(0))
        );
        assert_eq!(
            scan(vec![step(0), step(2)], 0).validate(),
            Err(RecordError::MissingBitmapMismatch {
                reported: 0,
                computed: 0b010,
            })
        );
    }

    #[test]
    fn exposes_sensor_validity_without_rejecting_bad_quality() {
        let mut measurement = step(0);
        assert!(measurement.is_new_data());
        assert!(measurement.is_gas_valid());
        assert!(measurement.is_heater_stable());

        measurement.status_bits = 0;
        assert!(!measurement.is_new_data());
        assert!(!measurement.is_gas_valid());
        assert!(!measurement.is_heater_stable());
        assert_eq!(scan(vec![measurement], 0b110).validate(), Ok(()));
    }

    #[test]
    fn configuration_requires_a_bounded_contiguous_profile() {
        let identity = RecordIdentity {
            node_id: 1,
            boot_id: 2,
            sequence: 3,
            uptime_ms: 4,
        };
        let mut configuration = DeviceConfiguration {
            identity,
            firmware_version: "test".to_owned(),
            reset_cause_bits: 0,
            sensor_variant: 1,
            calibration_hash: None,
            humidity_oversampling: 1,
            temperature_oversampling: 2,
            pressure_oversampling: 3,
            iir_filter: 0,
            operation_mode: 2,
            profile_id: 7,
            profile_revision: 1,
            scan_interval_ms: 60_000,
            tx_power_centi_dbm: 1_400,
            radio_frequency_hz: 868_100_000,
            radio_spreading_factor: 7,
            radio_bandwidth_hz: 125_000,
            radio_coding_rate: 1,
            heater_steps: vec![
                HeaterStepConfiguration {
                    step_index: 0,
                    target_temperature_celsius: 200,
                    duration_ms: 100,
                },
                HeaterStepConfiguration {
                    step_index: 1,
                    target_temperature_celsius: 300,
                    duration_ms: 100,
                },
            ],
        };
        assert_eq!(configuration.validate(), Ok(()));

        configuration.heater_steps[1].step_index = 2;
        assert_eq!(
            configuration.validate(),
            Err(RecordError::ConfigurationStepOrder {
                position: 1,
                step_index: 2,
            })
        );
        configuration.heater_steps.clear();
        assert_eq!(
            configuration.validate(),
            Err(RecordError::InvalidExpectedSteps(0))
        );
    }
}
