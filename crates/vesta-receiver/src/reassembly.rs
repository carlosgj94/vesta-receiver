//! Deterministic protocol-v2 profile-fragment reassembly.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde::Serialize;
use vesta_protocol::v2::{
    self, COMMON_FLAG_BOOT_ID_VALID, COMMON_FLAG_CONFIG_REPEAT, DecodedFrame, Header,
    ProfileFragmentView,
};

use crate::RadioMetadata;
use crate::records::{
    DeviceConfiguration, DeviceHealth, HeaterStepConfiguration, ProfileScan, ProfileStep,
    RecordIdentity,
};

/// Default number of incomplete scans retained concurrently.
pub const DEFAULT_MAX_ACTIVE_SCANS: usize = 128;

/// Stable key for one logical profile scan.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProfileKey {
    pub node_id: u64,
    /// Distinguishes a trustworthy nonce from the zero RNG-failure sentinel.
    pub boot_id_valid: bool,
    pub boot_id: u64,
    pub scan_sequence: u32,
    /// Scan-start uptime reduces quick-reboot ambiguity without a boot nonce.
    pub uptime_ms: u64,
    pub config_id: u64,
}

impl From<&Header> for ProfileKey {
    fn from(header: &Header) -> Self {
        Self {
            node_id: header.common.node_id,
            boot_id_valid: header.common.flags & COMMON_FLAG_BOOT_ID_VALID != 0,
            boot_id: header.common.boot_id,
            scan_sequence: header.common.scan_sequence,
            uptime_ms: header.common.uptime_ms,
            config_id: header.common.config_id,
        }
    }
}

/// Receiver-owned provenance for one unique profile fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SourceFragment {
    pub packet_id: i64,
    pub fragment_index: u8,
    pub received_at_unix_ms: i64,
    pub radio: RadioMetadata,
}

/// Complete or explicitly incomplete logical profile plus packet provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReassembledProfile {
    pub scan: ProfileScan,
    pub fragments: Vec<SourceFragment>,
}

impl ReassembledProfile {
    #[must_use]
    pub fn first_received_at_unix_ms(&self) -> Option<i64> {
        self.fragments
            .iter()
            .map(|fragment| fragment.received_at_unix_ms)
            .min()
    }

    #[must_use]
    pub fn last_received_at_unix_ms(&self) -> Option<i64> {
        self.fragments
            .iter()
            .map(|fragment| fragment.received_at_unix_ms)
            .max()
    }
}

/// Progress after accepting one unique fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReassemblyProgress {
    pub key: ProfileKey,
    pub received_fragment_bitmap: u16,
    pub missing_fragment_bitmap: u16,
}

/// Receiver-side result of ingesting one valid profile fragment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FragmentEvent {
    Pending(ReassemblyProgress),
    Complete(ReassembledProfile),
    Duplicate { key: ProfileKey, fragment_index: u8 },
    Conflict { key: ProfileKey, fragment_index: u8 },
}

/// One ingest result, including an incomplete scan evicted to enforce bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngestResult {
    pub event: FragmentEvent,
    pub evicted: Option<ReassembledProfile>,
}

/// Failure before a fragment can be incorporated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReassemblyError {
    InvalidCapacity,
    SourceFragmentIndex { source: u8, wire: u8 },
    Codec(v2::Error),
    InternalState,
}

impl core::fmt::Display for ReassemblyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ReassemblyError {}

impl From<v2::Error> for ReassemblyError {
    fn from(error: v2::Error) -> Self {
        Self::Codec(error)
    }
}

/// Bounded out-of-order profile-fragment reassembler.
#[derive(Debug)]
pub struct ProfileReassembler {
    active: HashMap<ProfileKey, ActiveProfile>,
    completed: VecDeque<CompletedProfile>,
    max_active: usize,
}

impl Default for ProfileReassembler {
    fn default() -> Self {
        Self {
            active: HashMap::new(),
            completed: VecDeque::new(),
            max_active: DEFAULT_MAX_ACTIVE_SCANS,
        }
    }
}

impl ProfileReassembler {
    /// Construct a reassembler with a hard bound on incomplete scans.
    ///
    /// # Errors
    ///
    /// Returns [`ReassemblyError::InvalidCapacity`] when `max_active` is zero.
    pub fn with_capacity(max_active: usize) -> Result<Self, ReassemblyError> {
        if max_active == 0 {
            return Err(ReassemblyError::InvalidCapacity);
        }
        Ok(Self {
            active: HashMap::new(),
            completed: VecDeque::new(),
            max_active,
        })
    }

    /// Incorporate one structurally validated profile fragment.
    ///
    /// Fragments can arrive in any order. Byte-equivalent duplicates and
    /// conflicting duplicates are reported without replacing the first copy.
    /// When the active bound is reached, the least recently updated scan is
    /// returned explicitly as `evicted` rather than silently discarded.
    ///
    /// # Errors
    ///
    /// Returns an error only if extracting a step from the validated borrowed
    /// fragment unexpectedly fails.
    pub fn ingest(
        &mut self,
        fragment: ProfileFragmentView<'_>,
        source: SourceFragment,
    ) -> Result<IngestResult, ReassemblyError> {
        self.ingest_at(fragment, source, Instant::now())
    }

    /// Incorporate one fragment using an explicit monotonic observation time.
    ///
    /// This is useful for deterministic tests and startup replay. Unix receive
    /// timestamps remain in [`SourceFragment`] solely as record provenance.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::ingest`].
    #[allow(clippy::too_many_lines)]
    pub fn ingest_at(
        &mut self,
        fragment: ProfileFragmentView<'_>,
        source: SourceFragment,
        observed_at: Instant,
    ) -> Result<IngestResult, ReassemblyError> {
        let owned = OwnedFragment::from_view(fragment)?;
        if source.fragment_index != owned.fragment_index {
            return Err(ReassemblyError::SourceFragmentIndex {
                source: source.fragment_index,
                wire: owned.fragment_index,
            });
        }
        let key = owned.metadata.key;
        if let Some(completed) = self.completed.iter().find(|entry| entry.key == key) {
            let event = match completed.fragments.get(usize::from(owned.fragment_index)) {
                Some(Some(previous)) if previous == &owned => FragmentEvent::Duplicate {
                    key,
                    fragment_index: owned.fragment_index,
                },
                _ => FragmentEvent::Conflict {
                    key,
                    fragment_index: owned.fragment_index,
                },
            };
            return Ok(IngestResult {
                event,
                evicted: None,
            });
        }

        let mut evicted = None;
        if !self.active.contains_key(&key) && self.active.len() >= self.max_active {
            let oldest_key = self
                .active
                .iter()
                .min_by_key(|(_, scan)| scan.last_observed_at)
                .map(|(key, _)| *key);
            let oldest = oldest_key.and_then(|oldest_key| self.active.remove(&oldest_key));
            if let Some(oldest) = oldest {
                evicted = Some(oldest.finish());
            }
        }

        let active = self
            .active
            .entry(key)
            .or_insert_with(|| ActiveProfile::new(&owned, observed_at));
        if active.metadata != owned.metadata {
            active.conflicting_fragment_count = active.conflicting_fragment_count.saturating_add(1);
            return Ok(IngestResult {
                event: FragmentEvent::Conflict {
                    key,
                    fragment_index: owned.fragment_index,
                },
                evicted,
            });
        }

        let fragment_index = usize::from(owned.fragment_index);
        if let Some(previous) = &active.fragments[fragment_index] {
            let event = if previous == &owned {
                active.duplicate_fragment_count = active.duplicate_fragment_count.saturating_add(1);
                FragmentEvent::Duplicate {
                    key,
                    fragment_index: owned.fragment_index,
                }
            } else {
                active.conflicting_fragment_count =
                    active.conflicting_fragment_count.saturating_add(1);
                FragmentEvent::Conflict {
                    key,
                    fragment_index: owned.fragment_index,
                }
            };
            return Ok(IngestResult { event, evicted });
        }

        active.received_fragment_bitmap |= 1 << owned.fragment_index;
        active.last_observed_at = active.last_observed_at.max(observed_at);
        active.sources.push(source);
        active.fragments[fragment_index] = Some(owned);

        let expected_mask = fragment_mask(active.metadata.expected_fragment_count);
        if active.received_fragment_bitmap == expected_mask {
            let Some(active) = self.active.remove(&key) else {
                return Err(ReassemblyError::InternalState);
            };
            let completed_fingerprints = active.fragments.clone();
            let completed_at = active.last_observed_at;
            let profile = active.finish();
            self.completed.push_back(CompletedProfile {
                key,
                fragments: completed_fingerprints,
                completed_at,
            });
            while self.completed.len() > self.max_active {
                self.completed.pop_front();
            }
            Ok(IngestResult {
                event: FragmentEvent::Complete(profile),
                evicted,
            })
        } else {
            Ok(IngestResult {
                event: FragmentEvent::Pending(ReassemblyProgress {
                    key,
                    received_fragment_bitmap: active.received_fragment_bitmap,
                    missing_fragment_bitmap: expected_mask & !active.received_fragment_bitmap,
                }),
                evicted,
            })
        }
    }

    /// Remove and return scans not observed since a monotonic cutoff.
    #[must_use]
    pub fn expire_before(&mut self, cutoff: Instant) -> Vec<ReassembledProfile> {
        let expired_keys = self
            .active
            .iter()
            .filter_map(|(key, scan)| (scan.last_observed_at < cutoff).then_some(*key))
            .collect::<Vec<_>>();
        let mut expired = Vec::with_capacity(expired_keys.len());
        for key in expired_keys {
            if let Some(scan) = self.active.remove(&key) {
                expired.push(scan.finish());
            }
        }
        self.completed.retain(|entry| entry.completed_at >= cutoff);
        expired
    }

    /// Expire scans older than `maximum_age` using only the monotonic clock.
    #[must_use]
    pub fn expire_older_than(&mut self, maximum_age: Duration) -> Vec<ReassembledProfile> {
        let Some(cutoff) = Instant::now().checked_sub(maximum_age) else {
            return Vec::new();
        };
        self.expire_before(cutoff)
    }

    /// Drain all incomplete scans, for example during graceful shutdown.
    pub fn drain_incomplete(&mut self) -> Vec<ReassembledProfile> {
        self.active.drain().map(|(_, scan)| scan.finish()).collect()
    }

    #[must_use]
    pub fn active_len(&self) -> usize {
        self.active.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProfileMetadata {
    key: ProfileKey,
    identity: RecordIdentity,
    profile_id: u16,
    profile_version: u16,
    expected_steps: u8,
    observed_unique_steps: u8,
    observed_field_count: u16,
    reported_missing_steps: u16,
    duplicate_steps: u16,
    duration_us: u32,
    collection_flags: u32,
    finish_reason: u8,
    duplicate_count: u16,
    overwritten_field_count: u16,
    out_of_order_count: u16,
    ambiguous_index_jump_count: u16,
    invalid_gas_index_count: u16,
    intermediate_field_count: u16,
    profile_rollover_count: u16,
    fields_after_rollover_count: u16,
    poll_count: u16,
    expected_fragment_count: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnedFragment {
    metadata: ProfileMetadata,
    fragment_index: u8,
    steps: Vec<ProfileStep>,
}

impl OwnedFragment {
    fn from_view(view: ProfileFragmentView<'_>) -> Result<Self, v2::Error> {
        let steps = fragment_steps(view)?;
        Ok(Self {
            metadata: ProfileMetadata {
                key: ProfileKey::from(&view.header),
                identity: record_identity(view.header),
                profile_id: view.profile_id,
                profile_version: view.profile_version,
                expected_steps: view.expected_step_count,
                observed_unique_steps: view.observed_unique_step_count,
                observed_field_count: view.observed_field_count,
                reported_missing_steps: view.missing_steps_bitmap,
                duplicate_steps: view.duplicate_steps_bitmap,
                duration_us: view.scan_duration_us,
                collection_flags: view.collection_flags,
                finish_reason: view.finish_reason,
                duplicate_count: view.duplicate_count,
                overwritten_field_count: view.overwritten_field_count,
                out_of_order_count: view.out_of_order_count,
                ambiguous_index_jump_count: view.ambiguous_index_jump_count,
                invalid_gas_index_count: view.invalid_gas_index_count,
                intermediate_field_count: view.intermediate_field_count,
                profile_rollover_count: view.profile_rollover_count,
                fields_after_rollover_count: view.fields_after_rollover_count,
                poll_count: view.poll_count,
                expected_fragment_count: view.header.fragment_count,
            },
            fragment_index: view.header.fragment_index,
            steps,
        })
    }
}

#[derive(Debug)]
struct ActiveProfile {
    metadata: ProfileMetadata,
    fragments: Vec<Option<OwnedFragment>>,
    sources: Vec<SourceFragment>,
    received_fragment_bitmap: u16,
    duplicate_fragment_count: u16,
    conflicting_fragment_count: u16,
    last_observed_at: Instant,
}

impl ActiveProfile {
    fn new(fragment: &OwnedFragment, observed_at: Instant) -> Self {
        Self {
            metadata: fragment.metadata.clone(),
            fragments: vec![None; usize::from(fragment.metadata.expected_fragment_count)],
            sources: Vec::with_capacity(usize::from(fragment.metadata.expected_fragment_count)),
            received_fragment_bitmap: 0,
            duplicate_fragment_count: 0,
            conflicting_fragment_count: 0,
            last_observed_at: observed_at,
        }
    }

    fn finish(self) -> ReassembledProfile {
        let mut steps = self
            .fragments
            .iter()
            .flatten()
            .flat_map(|fragment| fragment.steps.iter().copied())
            .collect::<Vec<_>>();
        steps.sort_unstable_by_key(|step| step.step_index);
        let metadata = self.metadata;
        ReassembledProfile {
            scan: ProfileScan {
                identity: metadata.identity,
                profile_id: metadata.profile_id,
                profile_version: metadata.profile_version,
                expected_steps: metadata.expected_steps,
                observed_unique_steps: metadata.observed_unique_steps,
                observed_field_count: metadata.observed_field_count,
                reported_missing_steps: metadata.reported_missing_steps,
                duplicate_steps: metadata.duplicate_steps,
                duration_us: metadata.duration_us,
                collection_flags: metadata.collection_flags,
                finish_reason: metadata.finish_reason,
                duplicate_count: metadata.duplicate_count,
                overwritten_field_count: metadata.overwritten_field_count,
                out_of_order_count: metadata.out_of_order_count,
                ambiguous_index_jump_count: metadata.ambiguous_index_jump_count,
                invalid_gas_index_count: metadata.invalid_gas_index_count,
                intermediate_field_count: metadata.intermediate_field_count,
                profile_rollover_count: metadata.profile_rollover_count,
                fields_after_rollover_count: metadata.fields_after_rollover_count,
                poll_count: metadata.poll_count,
                expected_fragment_count: metadata.expected_fragment_count,
                received_fragment_bitmap: self.received_fragment_bitmap,
                duplicate_fragment_count: self.duplicate_fragment_count,
                conflicting_fragment_count: self.conflicting_fragment_count,
                steps,
            },
            fragments: self.sources,
        }
    }
}

#[derive(Debug)]
struct CompletedProfile {
    key: ProfileKey,
    fragments: Vec<Option<OwnedFragment>>,
    completed_at: Instant,
}

const fn fragment_mask(fragment_count: u8) -> u16 {
    (1_u16 << fragment_count) - 1
}

/// Convert a v2 common header into a protocol-independent identity record.
#[must_use]
pub const fn record_identity(header: Header) -> RecordIdentity {
    RecordIdentity {
        common_flags: header.common.flags,
        node_id: header.common.node_id,
        boot_id: header.common.boot_id,
        scan_sequence: header.common.scan_sequence,
        uptime_ms: header.common.uptime_ms,
        config_id: header.common.config_id,
        reset_cause_flags: header.common.reset_cause_flags,
    }
}

/// Convert one validated v2 configuration frame without losing units.
#[must_use]
pub fn device_configuration(header: Header, config: v2::DeviceConfig) -> DeviceConfiguration {
    let heater_steps = config.steps[..usize::from(config.expected_step_count)]
        .iter()
        .enumerate()
        .map(|(index, step)| HeaterStepConfiguration {
            step_index: u8::try_from(index).unwrap_or(u8::MAX),
            target_temperature_celsius: step.target_temperature_celsius,
            configured_duration_us: step.configured_duration_us,
            repetition_multiplier: step.repetition_multiplier,
            readback_heater_current: step.readback_heater_current,
            programmed_heater_resistance: step.programmed_heater_resistance,
            programmed_gas_wait: step.programmed_gas_wait,
        })
        .collect();
    DeviceConfiguration {
        identity: record_identity(header),
        repeated: header.common.flags & COMMON_FLAG_CONFIG_REPEAT != 0,
        config_flags: config.flags,
        firmware_version: config.firmware_version,
        firmware_build_flags: config.firmware_build_flags,
        firmware_build_id: config.firmware_build_id,
        sensor_chip_id: config.sensor_chip_id,
        sensor_variant: config.sensor_variant,
        sensor_i2c_address: config.sensor_i2c_address,
        temperature_oversampling: config.temperature_oversampling,
        humidity_oversampling: config.humidity_oversampling,
        pressure_oversampling: config.pressure_oversampling,
        iir_filter: config.iir_filter,
        standby_time: config.standby_time,
        operation_mode: config.operation_mode,
        heater_enabled: config.heater_enabled,
        parallel_requested_shared_wait_ms: config.parallel_requested_shared_wait_ms,
        parallel_shared_wait_register: config.parallel_shared_wait_register,
        parallel_quantized_shared_wait_us: config.parallel_quantized_shared_wait_us,
        tphg_duration_us: config.tphg_duration_us,
        expected_profile_duration_us: config.expected_profile_duration_us,
        profile_id: config.profile_id,
        profile_version: config.profile_version,
        expected_step_count: config.expected_step_count,
        heater_readback_valid_bitmap: config.heater_readback_valid_bitmap,
        calibration_hash_algorithm: config.calibration_hash_algorithm,
        calibration_hash: config.calibration_hash,
        scan_interval_ms: config.scan_interval_ms,
        config_repeat_interval_scans: config.config_repeat_interval_scans,
        output_routes: config.output_routes,
        radio_frequency_hz: config.radio_frequency_hz,
        radio_tx_power_dbm: config.radio_tx_power_dbm,
        radio_spreading_factor: config.radio_spreading_factor,
        radio_bandwidth_hz: config.radio_bandwidth_hz,
        radio_coding_rate_numerator: config.radio_coding_rate_numerator,
        radio_coding_rate_denominator: config.radio_coding_rate_denominator,
        radio_preamble_symbols: config.radio_preamble_symbols,
        radio_header_mode: config.radio_header_mode,
        radio_phy_crc_enabled: config.radio_phy_crc_enabled,
        radio_iq_inverted: config.radio_iq_inverted,
        radio_sync_word: config.radio_sync_word,
        max_frame_len: config.max_frame_len,
        profile_steps_per_fragment: config.profile_steps_per_fragment,
        heater_steps,
    }
}

/// Convert one validated v2 health frame without inferring battery state.
#[must_use]
pub const fn device_health(header: Header, health: v2::DeviceHealth) -> DeviceHealth {
    DeviceHealth {
        identity: record_identity(header),
        health_flags: health.flags,
        reset_cause_raw: health.reset_cause_raw,
        successful_sensor_scans: health.successful_sensor_scans,
        failed_sensor_scans: health.failed_sensor_scans,
        incomplete_profiles: health.incomplete_profiles,
        i2c_errors: health.i2c_errors,
        radio_tx_errors: health.radio_tx_errors,
        dropped_profiles: health.dropped_profiles,
        dropped_fragments: health.dropped_fragments,
        overwritten_fields: health.overwritten_fields,
        current_sample_interval_ms: health.current_sample_interval_ms,
        firmware_version: health.firmware_version,
        profile_id: health.profile_id,
        profile_version: health.profile_version,
        last_sensor_error: health.last_sensor_error,
        last_radio_error: health.last_radio_error,
        calibrated_mcu_temperature_centi_celsius: health.calibrated_mcu_temperature_centi_celsius,
        calibrated_vdd_millivolt: health.calibrated_vdd_millivolt,
    }
}

const fn profile_step(step: v2::ProfileStep) -> ProfileStep {
    ProfileStep {
        step_index: step.step_index,
        gas_index: step.gas_index,
        measurement_index: step.measurement_index,
        status_bits: step.status,
        raw_measurement_status: step.raw_measurement_status,
        raw_gas_status: step.raw_gas_status,
        target_temperature_celsius: step.target_temperature_celsius,
        configured_duration_us: step.configured_duration_us,
        relative_offset_us: step.offset_us,
        temperature_centi_celsius: step.temperature_centi_celsius,
        pressure_pascal: step.pressure_pascal,
        humidity_milli_percent_rh: step.humidity_milli_percent_rh,
        gas_resistance_ohm: step.gas_resistance_ohm,
        raw_temperature_adc: step.temperature_adc,
        raw_pressure_adc: step.pressure_adc,
        raw_humidity_adc: step.humidity_adc,
        raw_gas_resistance_adc: step.gas_resistance_adc,
        raw_gas_range: step.gas_range,
        repetition_multiplier: step.repetition_multiplier,
        raw_heater_resistance: step.heater_resistance,
        raw_heater_current: step.heater_current,
        raw_gas_wait: step.gas_wait,
    }
}

/// Decode every step carried by one validated fragment into owned records.
///
/// # Errors
///
/// Returns the codec's bounds error if a supposedly validated step cannot be
/// extracted. No sensor-quality condition is treated as an error.
pub fn fragment_steps(view: ProfileFragmentView<'_>) -> Result<Vec<ProfileStep>, v2::Error> {
    let mut steps = Vec::with_capacity(usize::from(view.steps_in_fragment));
    for local_index in 0..usize::from(view.steps_in_fragment) {
        steps.push(profile_step(view.step(local_index)?));
    }
    Ok(steps)
}

/// Convert a non-profile v2 frame to its server record.
pub enum ConvertedRecord {
    DeviceConfiguration(DeviceConfiguration),
    DeviceHealth(DeviceHealth),
}

/// Convert one non-profile decoded frame, leaving fragments for reassembly.
#[must_use]
pub fn convert_non_profile(frame: DecodedFrame<'_>) -> Option<ConvertedRecord> {
    match frame {
        DecodedFrame::DeviceConfig { header, config } => Some(
            ConvertedRecord::DeviceConfiguration(device_configuration(header, config)),
        ),
        DecodedFrame::DeviceHealth { header, health } => {
            Some(ConvertedRecord::DeviceHealth(device_health(header, health)))
        }
        DecodedFrame::ProfileFragment(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn common(sequence: u32) -> v2::Common {
        v2::Common::production(1, u64::MAX, sequence, 1_000, 9, 2)
    }

    fn step(index: u8) -> v2::ProfileStep {
        v2::ProfileStep {
            step_index: index,
            gas_index: index,
            measurement_index: index,
            status: 0xb0,
            raw_measurement_status: 0x80,
            raw_gas_status: 0x30,
            target_temperature_celsius: 200 + u16::from(index),
            configured_duration_us: 100_000,
            offset_us: u32::from(index) * 100_000,
            temperature_centi_celsius: 2_500,
            pressure_pascal: 101_325,
            humidity_milli_percent_rh: 40_000,
            gas_resistance_ohm: 20_000,
            temperature_adc: 1,
            pressure_adc: 2,
            humidity_adc: 3,
            gas_resistance_adc: 4,
            gas_range: 5,
            repetition_multiplier: 2,
            heater_resistance: 6,
            heater_current: 7,
            gas_wait: 8,
        }
    }

    fn encoded_profile(sequence: u32) -> v2::EncodedProfile {
        encoded_profile_with_common(common(sequence))
    }

    fn encoded_profile_with_common(common: v2::Common) -> v2::EncodedProfile {
        let mut steps = [None; v2::MAX_PROFILE_STEPS];
        for index in 0..10_u8 {
            steps[usize::from(index)] = Some(step(index));
        }
        v2::encode_profile(
            common,
            &v2::ProfileScan {
                profile_id: 1,
                profile_version: 1,
                expected_step_count: 10,
                observed_unique_step_count: 10,
                observed_field_count: 10,
                missing_steps_bitmap: 0,
                duplicate_steps_bitmap: 0,
                scan_duration_us: 1_000_000,
                collection_flags: 0,
                finish_reason: v2::FINISH_REASON_COMPLETE,
                duplicate_count: 0,
                overwritten_field_count: 0,
                out_of_order_count: 0,
                ambiguous_index_jump_count: 0,
                invalid_gas_index_count: 0,
                intermediate_field_count: 0,
                profile_rollover_count: 0,
                fields_after_rollover_count: 0,
                poll_count: 20,
                steps,
            },
        )
        .unwrap()
    }

    const fn source(index: u8, received_at: i64) -> SourceFragment {
        SourceFragment {
            packet_id: index as i64 + 1,
            fragment_index: index,
            received_at_unix_ms: received_at,
            radio: RadioMetadata {
                packet_rssi_centi_dbm: -4_200,
                snr_centi_db: 1_250,
                signal_rssi_centi_dbm: -4_250,
            },
        }
    }

    fn fragment(bytes: &[u8]) -> ProfileFragmentView<'_> {
        let DecodedFrame::ProfileFragment(fragment) = v2::decode(bytes).unwrap() else {
            unreachable!()
        };
        fragment
    }

    #[test]
    fn reassembles_ten_steps_out_of_order_without_truncating_to_three() {
        let encoded = encoded_profile(1);
        let frames = encoded.frames();
        let mut reassembler = ProfileReassembler::default();
        for index in [3_usize, 1, 0] {
            let result = reassembler
                .ingest(
                    fragment(frames[index].as_slice()),
                    source(u8::try_from(index).unwrap(), i64::try_from(index).unwrap()),
                )
                .unwrap();
            assert!(matches!(result.event, FragmentEvent::Pending(_)));
        }
        let result = reassembler
            .ingest(fragment(frames[2].as_slice()), source(2, 4))
            .unwrap();
        let FragmentEvent::Complete(profile) = result.event else {
            panic!("expected completion")
        };
        assert_eq!(profile.scan.steps.len(), 10);
        assert_eq!(profile.scan.received_fragment_bitmap, 0b1111);
        assert_eq!(profile.scan.validate(), Ok(()));
    }

    #[test]
    fn unavailable_boot_quick_reboots_use_scan_uptime_as_reassembly_identity() {
        let first = encoded_profile_with_common(v2::Common::boot_id_unavailable(1, 0, 100, 9, 2));
        let second = encoded_profile_with_common(v2::Common::boot_id_unavailable(1, 0, 200, 9, 2));
        let mut reassembler = ProfileReassembler::default();

        let first_pending = reassembler
            .ingest(fragment(first.frames()[0].as_slice()), source(0, 1))
            .unwrap();
        let second_pending = reassembler
            .ingest(fragment(second.frames()[0].as_slice()), source(0, 2))
            .unwrap();
        let FragmentEvent::Pending(first_progress) = first_pending.event else {
            panic!("expected first pending scan")
        };
        let FragmentEvent::Pending(second_progress) = second_pending.event else {
            panic!("expected second pending scan")
        };
        assert!(!first_progress.key.boot_id_valid);
        assert_eq!(first_progress.key.uptime_ms, 100);
        assert_eq!(second_progress.key.uptime_ms, 200);
        assert_ne!(first_progress.key, second_progress.key);
        assert_eq!(reassembler.active_len(), 2);

        let mut completed_uptimes = Vec::new();
        for encoded in [&first, &second] {
            for index in 1..4_usize {
                let result = reassembler
                    .ingest(
                        fragment(encoded.frames()[index].as_slice()),
                        source(
                            u8::try_from(index).unwrap(),
                            i64::try_from(index + 2).unwrap(),
                        ),
                    )
                    .unwrap();
                if let FragmentEvent::Complete(profile) = result.event {
                    completed_uptimes.push(profile.scan.identity.uptime_ms);
                }
            }
        }
        assert_eq!(completed_uptimes, vec![100, 200]);
        assert_eq!(reassembler.active_len(), 0);
    }

    #[test]
    fn boot_validity_bit_is_part_of_reassembly_identity() {
        let unavailable =
            encoded_profile_with_common(v2::Common::boot_id_unavailable(1, 7, 100, 9, 2));
        let valid_zero = encoded_profile_with_common(v2::Common::production(1, 0, 7, 100, 9, 2));
        let mut reassembler = ProfileReassembler::default();
        let unavailable_result = reassembler
            .ingest(fragment(unavailable.frames()[0].as_slice()), source(0, 1))
            .unwrap();
        let valid_result = reassembler
            .ingest(fragment(valid_zero.frames()[0].as_slice()), source(0, 2))
            .unwrap();
        let FragmentEvent::Pending(unavailable_progress) = unavailable_result.event else {
            panic!("expected unavailable pending scan")
        };
        let FragmentEvent::Pending(valid_progress) = valid_result.event else {
            panic!("expected valid pending scan")
        };
        assert!(!unavailable_progress.key.boot_id_valid);
        assert!(valid_progress.key.boot_id_valid);
        assert_ne!(unavailable_progress.key, valid_progress.key);
        assert_eq!(reassembler.active_len(), 2);
    }

    #[test]
    fn detects_duplicates_before_and_after_completion() {
        let encoded = encoded_profile(2);
        let frames = encoded.frames();
        let mut reassembler = ProfileReassembler::default();
        reassembler
            .ingest(fragment(frames[0].as_slice()), source(0, 0))
            .unwrap();
        assert!(matches!(
            reassembler
                .ingest(fragment(frames[0].as_slice()), source(0, 1))
                .unwrap()
                .event,
            FragmentEvent::Duplicate {
                fragment_index: 0,
                ..
            }
        ));
        for (index, frame) in frames.iter().enumerate().take(4).skip(1) {
            reassembler
                .ingest(
                    fragment(frame.as_slice()),
                    source(u8::try_from(index).unwrap(), i64::try_from(index).unwrap()),
                )
                .unwrap();
        }
        assert!(matches!(
            reassembler
                .ingest(fragment(frames[3].as_slice()), source(3, 9))
                .unwrap()
                .event,
            FragmentEvent::Duplicate {
                fragment_index: 3,
                ..
            }
        ));
    }

    #[test]
    fn rejects_a_conflicting_duplicate_without_overwriting_first_data() {
        let encoded = encoded_profile(22);
        let original = encoded.frames()[0].as_slice();
        let mut altered = original.to_vec();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        let mut reassembler = ProfileReassembler::default();
        reassembler
            .ingest(fragment(original), source(0, 0))
            .unwrap();
        assert!(matches!(
            reassembler
                .ingest(fragment(&altered), source(0, 1))
                .unwrap()
                .event,
            FragmentEvent::Conflict {
                fragment_index: 0,
                ..
            }
        ));
    }

    #[test]
    fn monotonic_expiration_ignores_wall_clock_and_reports_missing_fragments() {
        let encoded = encoded_profile(3);
        let mut reassembler = ProfileReassembler::default();
        let observed_at = Instant::now();
        reassembler
            .ingest_at(
                fragment(encoded.frames()[1].as_slice()),
                source(1, i64::MAX),
                observed_at,
            )
            .unwrap();
        let expired = reassembler.expire_before(observed_at + Duration::from_millis(1));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].scan.received_fragment_bitmap, 0b0010);
        assert_eq!(expired[0].scan.missing_fragment_bitmap(), 0b1101);
        assert_eq!(expired[0].scan.steps.len(), 3);
        assert_eq!(expired[0].scan.validate(), Ok(()));
    }

    #[test]
    fn bounded_capacity_returns_evicted_profile() {
        let one = encoded_profile(4);
        let two = encoded_profile(5);
        let mut reassembler = ProfileReassembler::with_capacity(1).unwrap();
        reassembler
            .ingest(fragment(one.frames()[0].as_slice()), source(0, 10))
            .unwrap();
        let result = reassembler
            .ingest(fragment(two.frames()[0].as_slice()), source(0, 20))
            .unwrap();
        assert_eq!(result.evicted.unwrap().scan.identity.scan_sequence, 4);
        assert_eq!(reassembler.active_len(), 1);
    }
}
