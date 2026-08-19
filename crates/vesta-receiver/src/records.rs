//! Protocol-independent records consumed by server storage and analytics.
//!
//! These types preserve every protocol-v2 integer exactly. Radio link quality
//! and host reception time are deliberately kept in receiver-owned fragment
//! metadata rather than copied into device-originated records.

use core::fmt;

use serde::Serialize;

/// Maximum number of heater steps supported by the BME688.
pub const MAX_HEATER_STEPS: u8 = 10;

/// Stable identity and monotonic timing shared by one protocol-v2 record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct RecordIdentity {
    pub common_flags: u8,
    pub node_id: u64,
    pub boot_id: u64,
    pub scan_sequence: u32,
    pub uptime_ms: u64,
    pub config_id: u64,
    pub reset_cause_flags: u16,
}

/// One configured BME688 heater step.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct HeaterStepConfiguration {
    pub step_index: u8,
    pub target_temperature_celsius: u16,
    pub configured_duration_us: u32,
    pub repetition_multiplier: u8,
    pub programmed_heater_current: u8,
    pub programmed_heater_resistance: u8,
    pub programmed_gas_wait: u8,
}

/// Device, sensor, heater-profile, cadence, and radio configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceConfiguration {
    pub identity: RecordIdentity,
    pub repeated: bool,
    pub config_flags: u8,
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
    pub heater_readback_valid_bitmap: u16,
    pub calibration_hash_algorithm: u8,
    pub calibration_hash: u64,
    pub scan_interval_ms: u32,
    pub config_repeat_interval_scans: u16,
    /// Firmware output-route bitmap (`LoRa`, UART training, and/or RTT).
    pub output_routes: u8,
    pub radio_frequency_hz: u32,
    pub radio_tx_power_dbm: i8,
    pub radio_spreading_factor: u8,
    pub radio_bandwidth_hz: u32,
    pub radio_coding_rate_numerator: u8,
    pub radio_coding_rate_denominator: u8,
    pub radio_preamble_symbols: u16,
    pub radio_header_mode: u8,
    pub radio_phy_crc_enabled: u8,
    pub radio_iq_inverted: u8,
    pub radio_sync_word: u16,
    pub max_frame_len: u8,
    pub profile_steps_per_fragment: u8,
    pub heater_steps: Vec<HeaterStepConfiguration>,
}

impl DeviceConfiguration {
    /// Validate the bounded profile and exact contiguous heater-step order.
    ///
    /// # Errors
    ///
    /// Returns an error for an impossible count, a non-contiguous index, or a
    /// read-back bitmap that references an unconfigured step.
    pub fn validate(&self) -> Result<(), RecordError> {
        if !(1..=MAX_HEATER_STEPS).contains(&self.expected_step_count) {
            return Err(RecordError::InvalidExpectedSteps(self.expected_step_count));
        }
        if usize::from(self.expected_step_count) != self.heater_steps.len() {
            return Err(RecordError::ConfigurationStepCount {
                expected: self.expected_step_count,
                actual: self.heater_steps.len(),
            });
        }
        for (step, position) in self.heater_steps.iter().zip(0_u8..self.expected_step_count) {
            if step.step_index != position {
                return Err(RecordError::ConfigurationStepOrder {
                    position,
                    step_index: step.step_index,
                });
            }
        }
        let valid_mask = expected_step_mask(self.expected_step_count);
        if self.heater_readback_valid_bitmap & !valid_mask != 0 {
            return Err(RecordError::BitmapOutOfRange {
                field: "heater_readback_valid_bitmap",
                bitmap: self.heater_readback_valid_bitmap,
                expected_steps: self.expected_step_count,
            });
        }
        Ok(())
    }
}

/// Exact sensor values captured for one heater step.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileStep {
    pub step_index: u8,
    pub gas_index: u8,
    pub measurement_index: u8,
    pub status_bits: u8,
    pub raw_measurement_status: u8,
    pub raw_gas_status: u8,
    pub target_temperature_celsius: u16,
    pub configured_duration_us: u32,
    pub relative_offset_us: u32,
    pub temperature_centi_celsius: i16,
    pub pressure_pascal: u32,
    pub humidity_milli_percent_rh: u32,
    pub gas_resistance_ohm: u32,
    pub raw_temperature_adc: u32,
    pub raw_pressure_adc: u32,
    pub raw_humidity_adc: u16,
    pub raw_gas_resistance_adc: u16,
    pub raw_gas_range: u8,
    pub repetition_multiplier: u8,
    pub raw_heater_resistance: u8,
    pub raw_heater_current: u8,
    pub raw_gas_wait: u8,
}

impl ProfileStep {
    const STATUS_NEW_DATA: u8 = 1 << 7;
    const STATUS_GAS_VALID: u8 = 1 << 5;
    const STATUS_HEATER_STABLE: u8 = 1 << 4;

    #[must_use]
    pub const fn is_new_data(self) -> bool {
        self.status_bits & Self::STATUS_NEW_DATA != 0
    }

    #[must_use]
    pub const fn is_gas_valid(self) -> bool {
        self.status_bits & Self::STATUS_GAS_VALID != 0
    }

    #[must_use]
    pub const fn is_heater_stable(self) -> bool {
        self.status_bits & Self::STATUS_HEATER_STABLE != 0
    }

    #[must_use]
    pub const fn unknown_status_bits(self) -> u8 {
        self.status_bits
            & !(Self::STATUS_NEW_DATA | Self::STATUS_GAS_VALID | Self::STATUS_HEATER_STABLE)
    }
}

/// One complete or explicitly transport-incomplete heater-profile scan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileScan {
    pub identity: RecordIdentity,
    pub profile_id: u16,
    pub profile_version: u16,
    pub expected_steps: u8,
    pub observed_unique_steps: u8,
    pub observed_field_count: u16,
    pub reported_missing_steps: u16,
    pub duplicate_steps: u16,
    pub duration_us: u32,
    pub collection_flags: u32,
    pub finish_reason: u8,
    pub duplicate_count: u16,
    pub overwritten_field_count: u16,
    pub out_of_order_count: u16,
    pub ambiguous_index_jump_count: u16,
    pub invalid_gas_index_count: u16,
    pub intermediate_field_count: u16,
    pub profile_rollover_count: u16,
    pub fields_after_rollover_count: u16,
    pub poll_count: u16,
    pub expected_fragment_count: u8,
    pub received_fragment_bitmap: u16,
    pub duplicate_fragment_count: u16,
    pub conflicting_fragment_count: u16,
    pub steps: Vec<ProfileStep>,
}

impl ProfileScan {
    /// Bitmap of radio fragments absent at the receiver.
    #[must_use]
    pub const fn missing_fragment_bitmap(&self) -> u16 {
        expected_fragment_mask(self.expected_fragment_count) & !self.received_fragment_bitmap
    }

    /// Whether every deterministic radio fragment reached the receiver.
    #[must_use]
    pub const fn is_transport_complete(&self) -> bool {
        self.missing_fragment_bitmap() == 0
    }

    /// Compute unavailable positions from steps actually available at receiver.
    #[must_use]
    pub fn computed_unavailable_steps(&self) -> u16 {
        let expected_mask = expected_step_mask(self.expected_steps);
        let observed_mask = self.steps.iter().fold(0_u16, |mask, step| {
            mask | 1_u16.checked_shl(u32::from(step.step_index)).unwrap_or(0)
        });
        expected_mask & !observed_mask
    }

    /// Validate sensor metadata and receiver-side fragment state.
    ///
    /// # Errors
    ///
    /// Returns an error for impossible counts, out-of-range bitmaps, duplicate
    /// steps, or disagreement inside a fragment window that was received.
    pub fn validate(&self) -> Result<(), RecordError> {
        if !(1..=MAX_HEATER_STEPS).contains(&self.expected_steps) {
            return Err(RecordError::InvalidExpectedSteps(self.expected_steps));
        }
        let required_fragments = self.expected_steps.div_ceil(3);
        if self.expected_fragment_count != required_fragments {
            return Err(RecordError::InvalidFragmentCount {
                expected: required_fragments,
                actual: self.expected_fragment_count,
            });
        }
        let expected_mask = expected_step_mask(self.expected_steps);
        for (field, bitmap) in [
            ("reported_missing_steps", self.reported_missing_steps),
            ("duplicate_steps", self.duplicate_steps),
        ] {
            if bitmap & !expected_mask != 0 {
                return Err(RecordError::BitmapOutOfRange {
                    field,
                    bitmap,
                    expected_steps: self.expected_steps,
                });
            }
        }
        let fragment_mask = expected_fragment_mask(self.expected_fragment_count);
        if self.received_fragment_bitmap & !fragment_mask != 0 {
            return Err(RecordError::FragmentBitmapOutOfRange {
                bitmap: self.received_fragment_bitmap,
                expected_fragments: self.expected_fragment_count,
            });
        }
        let sensor_observed = self.expected_steps
            - u8::try_from(self.reported_missing_steps.count_ones()).unwrap_or(u8::MAX);
        if sensor_observed != self.observed_unique_steps {
            return Err(RecordError::ObservedCountMismatch {
                reported: self.observed_unique_steps,
                computed: sensor_observed,
            });
        }
        if self.observed_field_count < u16::from(self.observed_unique_steps) {
            return Err(RecordError::ObservedFieldCountTooSmall {
                fields: self.observed_field_count,
                unique: self.observed_unique_steps,
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
            let fragment_index = step.step_index / 3;
            if self.received_fragment_bitmap & (1 << fragment_index) == 0 {
                return Err(RecordError::StepFromMissingFragment {
                    step_index: step.step_index,
                    fragment_index,
                });
            }
            observed |= bit;
        }

        for step_index in 0..self.expected_steps {
            let bit = 1_u16 << step_index;
            let fragment_received = self.received_fragment_bitmap & (1 << (step_index / 3)) != 0;
            let sensor_present = self.reported_missing_steps & bit == 0;
            if fragment_received && sensor_present && observed & bit == 0 {
                return Err(RecordError::ReceivedFragmentMissingStep(step_index));
            }
        }
        if self.is_transport_complete()
            && self.computed_unavailable_steps() != self.reported_missing_steps
        {
            return Err(RecordError::MissingBitmapMismatch {
                reported: self.reported_missing_steps,
                computed: self.computed_unavailable_steps(),
            });
        }
        Ok(())
    }
}

const fn expected_step_mask(expected_steps: u8) -> u16 {
    (1_u16 << expected_steps) - 1
}

const fn expected_fragment_mask(expected_fragments: u8) -> u16 {
    (1_u16 << expected_fragments) - 1
}

/// Periodic health counters reported without interpreting fire risk.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceHealth {
    pub identity: RecordIdentity,
    pub health_flags: u8,
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
    pub profile_id: u16,
    pub profile_version: u16,
    pub last_sensor_error: u16,
    pub last_radio_error: u16,
    pub calibrated_mcu_temperature_centi_celsius: Option<i16>,
    /// Calibrated regulated VDD, never battery voltage or state of charge.
    pub calibrated_vdd_millivolt: Option<u16>,
}

/// Structurally invalid decoded record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordError {
    InvalidExpectedSteps(u8),
    ConfigurationStepCount {
        expected: u8,
        actual: usize,
    },
    ConfigurationStepOrder {
        position: u8,
        step_index: u8,
    },
    BitmapOutOfRange {
        field: &'static str,
        bitmap: u16,
        expected_steps: u8,
    },
    InvalidFragmentCount {
        expected: u8,
        actual: u8,
    },
    FragmentBitmapOutOfRange {
        bitmap: u16,
        expected_fragments: u8,
    },
    ObservedCountMismatch {
        reported: u8,
        computed: u8,
    },
    ObservedFieldCountTooSmall {
        fields: u16,
        unique: u8,
    },
    StepIndexOutOfRange {
        index: u8,
        expected_steps: u8,
    },
    DuplicateStepIndex(u8),
    StepFromMissingFragment {
        step_index: u8,
        fragment_index: u8,
    },
    ReceivedFragmentMissingStep(u8),
    MissingBitmapMismatch {
        reported: u16,
        computed: u16,
    },
}

impl fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RecordError {}

#[cfg(test)]
mod tests {
    use super::*;

    const fn identity() -> RecordIdentity {
        RecordIdentity {
            common_flags: 3,
            node_id: 1,
            boot_id: u64::MAX,
            scan_sequence: u32::MAX,
            uptime_ms: 4,
            config_id: 5,
            reset_cause_flags: 6,
        }
    }

    const fn step(index: u8) -> ProfileStep {
        ProfileStep {
            step_index: index,
            gas_index: index,
            measurement_index: index,
            status_bits: 0xb0,
            raw_measurement_status: 0x80,
            raw_gas_status: 0x30,
            target_temperature_celsius: 300,
            configured_duration_us: 138_898,
            relative_offset_us: index as u32 * 138_898,
            temperature_centi_celsius: 2_500,
            pressure_pascal: 101_325,
            humidity_milli_percent_rh: 40_000,
            gas_resistance_ohm: 20_000,
            raw_temperature_adc: 1,
            raw_pressure_adc: 2,
            raw_humidity_adc: 3,
            raw_gas_resistance_adc: 4,
            raw_gas_range: 5,
            repetition_multiplier: 2,
            raw_heater_resistance: 6,
            raw_heater_current: 7,
            raw_gas_wait: 8,
        }
    }

    fn complete_scan() -> ProfileScan {
        ProfileScan {
            identity: identity(),
            profile_id: 7,
            profile_version: 1,
            expected_steps: 4,
            observed_unique_steps: 4,
            observed_field_count: 4,
            reported_missing_steps: 0,
            duplicate_steps: 0,
            duration_us: 555_592,
            collection_flags: 0,
            finish_reason: 0,
            duplicate_count: 0,
            overwritten_field_count: 0,
            out_of_order_count: 0,
            ambiguous_index_jump_count: 0,
            invalid_gas_index_count: 0,
            intermediate_field_count: 0,
            profile_rollover_count: 0,
            fields_after_rollover_count: 0,
            poll_count: 8,
            expected_fragment_count: 2,
            received_fragment_bitmap: 0b11,
            duplicate_fragment_count: 0,
            conflicting_fragment_count: 0,
            steps: vec![step(0), step(1), step(2), step(3)],
        }
    }

    #[test]
    fn validates_complete_and_transport_incomplete_scans() {
        let complete = complete_scan();
        assert!(complete.is_transport_complete());
        assert_eq!(complete.validate(), Ok(()));
        let mut incomplete = complete;
        incomplete.received_fragment_bitmap = 0b01;
        incomplete.steps.truncate(3);
        assert_eq!(incomplete.missing_fragment_bitmap(), 0b10);
        assert_eq!(incomplete.validate(), Ok(()));
    }

    #[test]
    fn detects_missing_data_inside_a_received_fragment() {
        let mut scan = complete_scan();
        scan.steps.remove(1);
        assert_eq!(
            scan.validate(),
            Err(RecordError::ReceivedFragmentMissingStep(1))
        );
    }

    #[test]
    fn retains_raw_statuses_and_u64_boot_identity() {
        let measurement = step(0);
        assert!(measurement.is_new_data());
        assert!(measurement.is_gas_valid());
        assert!(measurement.is_heater_stable());
        assert_eq!(measurement.raw_measurement_status, 0x80);
        assert_eq!(measurement.raw_gas_status, 0x30);
        assert_eq!(identity().boot_id, u64::MAX);
    }
}
