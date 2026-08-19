//! Durable `SQLite` storage for received Vesta telemetry.

use std::fmt;
use std::path::Path;
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
#[cfg(test)]
use vesta_protocol::v2::FrameType;
use vesta_protocol::v2::Header;
use vesta_protocol::{TelemetryV1, VERSION};

use crate::RadioMetadata;
use crate::reassembly::{ProfileKey, ReassembledProfile};
use crate::records::{DeviceConfiguration, DeviceHealth, RecordError};

const SCHEMA_VERSION: i64 = 3;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const PROFILE_REASSEMBLY_INDEX: &str = r"
CREATE INDEX IF NOT EXISTS v2_profile_reassembly_identity
    ON v2_profile_scans(
        node_id, boot_id, scan_sequence, uptime_ms, config_id, common_flags
    );
";

const SCHEMA_V1: &str = r"
CREATE TABLE IF NOT EXISTS telemetry_readings (
    id INTEGER PRIMARY KEY,
    received_at_unix_ms INTEGER NOT NULL CHECK (received_at_unix_ms >= 0),
    protocol_version INTEGER NOT NULL CHECK (protocol_version = 1),
    node_id TEXT NOT NULL CHECK (length(node_id) = 16 AND node_id NOT GLOB '*[^0-9a-f]*'),
    sequence INTEGER NOT NULL CHECK (sequence BETWEEN 0 AND 4294967295),
    status_bits INTEGER NOT NULL CHECK (status_bits BETWEEN 0 AND 255),
    status_new_data INTEGER NOT NULL CHECK (status_new_data IN (0, 1)),
    status_gas_valid INTEGER NOT NULL CHECK (status_gas_valid IN (0, 1)),
    status_heater_stable INTEGER NOT NULL CHECK (status_heater_stable IN (0, 1)),
    status_unknown_bits INTEGER NOT NULL CHECK (status_unknown_bits BETWEEN 0 AND 255),
    temperature_centi_celsius INTEGER NOT NULL,
    pressure_pascal INTEGER NOT NULL CHECK (pressure_pascal >= 0),
    humidity_milli_percent_rh INTEGER NOT NULL CHECK (humidity_milli_percent_rh >= 0),
    gas_resistance_ohm INTEGER NOT NULL CHECK (gas_resistance_ohm >= 0),
    raw_temperature_adc INTEGER NOT NULL CHECK (raw_temperature_adc >= 0),
    raw_pressure_adc INTEGER NOT NULL CHECK (raw_pressure_adc >= 0),
    raw_humidity_adc INTEGER NOT NULL CHECK (raw_humidity_adc >= 0),
    raw_gas_resistance_adc INTEGER NOT NULL CHECK (raw_gas_resistance_adc >= 0),
    raw_gas_range INTEGER NOT NULL CHECK (raw_gas_range BETWEEN 0 AND 255),
    raw_gas_index INTEGER NOT NULL CHECK (raw_gas_index BETWEEN 0 AND 255),
    raw_measurement_index INTEGER NOT NULL CHECK (raw_measurement_index BETWEEN 0 AND 255),
    raw_heater_resistance INTEGER NOT NULL CHECK (raw_heater_resistance BETWEEN 0 AND 255),
    raw_heater_current INTEGER NOT NULL CHECK (raw_heater_current BETWEEN 0 AND 255),
    raw_gas_wait INTEGER NOT NULL CHECK (raw_gas_wait BETWEEN 0 AND 255),
    packet_rssi_centi_dbm INTEGER NOT NULL,
    snr_centi_db INTEGER NOT NULL,
    signal_rssi_centi_dbm INTEGER NOT NULL,
    payload BLOB NOT NULL CHECK (length(payload) = 48)
) STRICT;
CREATE INDEX IF NOT EXISTS telemetry_readings_received_at
    ON telemetry_readings(received_at_unix_ms DESC);
CREATE INDEX IF NOT EXISTS telemetry_readings_node_received_at
    ON telemetry_readings(node_id, received_at_unix_ms DESC);
";

// Fresh schema-v3 databases classify successfully decoded v2 packets
// explicitly. Existing schema-v2 databases are rebuilt by the migration below
// because their CHECK constraint predates this disposition.
const PACKET_ARCHIVE_SCHEMA_V3: &str = r"
CREATE TABLE radio_packets (
    id INTEGER PRIMARY KEY,
    received_at_unix_ms INTEGER NOT NULL CHECK (received_at_unix_ms >= 0),
    packet_rssi_centi_dbm INTEGER NOT NULL,
    snr_centi_db INTEGER NOT NULL,
    signal_rssi_centi_dbm INTEGER NOT NULL,
    protocol_version INTEGER CHECK (protocol_version BETWEEN 0 AND 255),
    frame_type INTEGER CHECK (frame_type BETWEEN 0 AND 255),
    disposition TEXT NOT NULL CHECK (disposition IN ('v1', 'v2', 'unsupported', 'invalid')),
    decode_error TEXT,
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 0 AND 255)
) STRICT;
CREATE INDEX radio_packets_received_at
    ON radio_packets(received_at_unix_ms DESC);
CREATE INDEX radio_packets_version_received_at
    ON radio_packets(protocol_version, received_at_unix_ms DESC);
ALTER TABLE telemetry_readings
    ADD COLUMN radio_packet_id INTEGER REFERENCES radio_packets(id);
CREATE UNIQUE INDEX telemetry_readings_radio_packet
    ON telemetry_readings(radio_packet_id) WHERE radio_packet_id IS NOT NULL;
";

// Rebuild only the constrained packet table. Foreign-key enforcement is
// disabled around the transaction by `migrate_schema_two`; every primary key
// and byte of archived data is copied explicitly, then checked after foreign
// keys are restored. Legacy schema-v2 child tables keep referring to the final
// `radio_packets` name.
const RADIO_PACKETS_V2_TO_V3: &str = r"
CREATE TABLE radio_packets_v3 (
    id INTEGER PRIMARY KEY,
    received_at_unix_ms INTEGER NOT NULL CHECK (received_at_unix_ms >= 0),
    packet_rssi_centi_dbm INTEGER NOT NULL,
    snr_centi_db INTEGER NOT NULL,
    signal_rssi_centi_dbm INTEGER NOT NULL,
    protocol_version INTEGER CHECK (protocol_version BETWEEN 0 AND 255),
    frame_type INTEGER CHECK (frame_type BETWEEN 0 AND 255),
    disposition TEXT NOT NULL CHECK (disposition IN ('v1', 'v2', 'unsupported', 'invalid')),
    decode_error TEXT,
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 0 AND 255)
) STRICT;

INSERT INTO radio_packets_v3 (
    id, received_at_unix_ms, packet_rssi_centi_dbm, snr_centi_db,
    signal_rssi_centi_dbm, protocol_version, frame_type, disposition,
    decode_error, payload
)
SELECT
    id, received_at_unix_ms, packet_rssi_centi_dbm, snr_centi_db,
    signal_rssi_centi_dbm, protocol_version, frame_type, disposition,
    decode_error, payload
FROM radio_packets;

DROP TABLE radio_packets;
ALTER TABLE radio_packets_v3 RENAME TO radio_packets;
CREATE INDEX radio_packets_received_at
    ON radio_packets(received_at_unix_ms DESC);
CREATE INDEX radio_packets_version_received_at
    ON radio_packets(protocol_version, received_at_unix_ms DESC);
";

const SCHEMA_V3: &str = r"
CREATE TABLE IF NOT EXISTS v2_packet_decodes (
    packet_id INTEGER PRIMARY KEY REFERENCES radio_packets(id) ON DELETE CASCADE,
    frame_type INTEGER NOT NULL CHECK (frame_type IN (1, 2, 3)),
    record_kind TEXT NOT NULL CHECK (record_kind IN ('device_config', 'profile_fragment', 'device_health')),
    reassembly_status TEXT NOT NULL CHECK (reassembly_status IN ('not_applicable', 'pending', 'assembled', 'duplicate', 'conflict', 'incomplete')),
    node_id TEXT NOT NULL CHECK (length(node_id) = 16 AND node_id NOT GLOB '*[^0-9a-f]*'),
    boot_id TEXT NOT NULL CHECK (length(boot_id) = 16 AND boot_id NOT GLOB '*[^0-9a-f]*'),
    scan_sequence INTEGER NOT NULL CHECK (scan_sequence BETWEEN 0 AND 4294967295),
    uptime_ms TEXT NOT NULL CHECK (length(uptime_ms) = 16 AND uptime_ms NOT GLOB '*[^0-9a-f]*'),
    config_id TEXT NOT NULL CHECK (length(config_id) = 16 AND config_id NOT GLOB '*[^0-9a-f]*'),
    fragment_index INTEGER NOT NULL CHECK (fragment_index BETWEEN 0 AND 255),
    fragment_count INTEGER NOT NULL CHECK (fragment_count BETWEEN 1 AND 255)
) STRICT;

CREATE TABLE IF NOT EXISTS v2_device_configurations (
    id INTEGER PRIMARY KEY,
    received_at_unix_ms INTEGER NOT NULL CHECK (received_at_unix_ms >= 0),
    node_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    scan_sequence INTEGER NOT NULL,
    uptime_ms TEXT NOT NULL,
    config_id TEXT NOT NULL,
    common_flags INTEGER NOT NULL,
    reset_cause_flags INTEGER NOT NULL,
    repeated INTEGER NOT NULL CHECK (repeated IN (0, 1)),
    firmware_version TEXT NOT NULL,
    firmware_build_id TEXT NOT NULL,
    sensor_chip_id INTEGER NOT NULL,
    sensor_variant INTEGER NOT NULL,
    calibration_hash_algorithm INTEGER NOT NULL,
    calibration_hash TEXT NOT NULL,
    profile_id INTEGER NOT NULL,
    profile_version INTEGER NOT NULL,
    expected_step_count INTEGER NOT NULL CHECK (expected_step_count BETWEEN 1 AND 10),
    expected_profile_duration_us INTEGER NOT NULL,
    scan_interval_ms INTEGER NOT NULL,
    output_routes INTEGER NOT NULL,
    radio_frequency_hz INTEGER NOT NULL,
    radio_tx_power_dbm INTEGER NOT NULL,
    radio_spreading_factor INTEGER NOT NULL,
    radio_bandwidth_hz INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    source_packet_id INTEGER REFERENCES radio_packets(id)
) STRICT;
CREATE INDEX IF NOT EXISTS v2_config_node_received
    ON v2_device_configurations(node_id, received_at_unix_ms DESC);
CREATE INDEX IF NOT EXISTS v2_config_identity
    ON v2_device_configurations(node_id, config_id);

CREATE TABLE IF NOT EXISTS v2_heater_profile_steps (
    configuration_id INTEGER NOT NULL REFERENCES v2_device_configurations(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL CHECK (step_index BETWEEN 0 AND 9),
    target_temperature_celsius INTEGER NOT NULL,
    configured_duration_us INTEGER NOT NULL,
    repetition_multiplier INTEGER NOT NULL,
    -- Draft schema-v2 compatibility identifier; this stores exact raw IDAC_HEAT
    -- readback and does not claim that the driver programmed IDAC.
    programmed_heater_current INTEGER NOT NULL,
    programmed_heater_resistance INTEGER NOT NULL,
    programmed_gas_wait INTEGER NOT NULL,
    PRIMARY KEY (configuration_id, step_index)
) STRICT;

CREATE TABLE IF NOT EXISTS v2_profile_scans (
    id INTEGER PRIMARY KEY,
    first_received_at_unix_ms INTEGER NOT NULL,
    last_received_at_unix_ms INTEGER NOT NULL,
    node_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    scan_sequence INTEGER NOT NULL,
    uptime_ms TEXT NOT NULL,
    config_id TEXT NOT NULL,
    common_flags INTEGER NOT NULL,
    reset_cause_flags INTEGER NOT NULL,
    profile_id INTEGER NOT NULL,
    profile_version INTEGER NOT NULL,
    expected_steps INTEGER NOT NULL CHECK (expected_steps BETWEEN 1 AND 10),
    observed_unique_steps INTEGER NOT NULL,
    observed_field_count INTEGER NOT NULL,
    reported_missing_steps INTEGER NOT NULL,
    duplicate_steps INTEGER NOT NULL,
    duration_us INTEGER NOT NULL,
    collection_flags INTEGER NOT NULL,
    finish_reason INTEGER NOT NULL,
    duplicate_count INTEGER NOT NULL,
    overwritten_field_count INTEGER NOT NULL,
    out_of_order_count INTEGER NOT NULL,
    ambiguous_index_jump_count INTEGER NOT NULL,
    invalid_gas_index_count INTEGER NOT NULL,
    intermediate_field_count INTEGER NOT NULL,
    profile_rollover_count INTEGER NOT NULL,
    fields_after_rollover_count INTEGER NOT NULL,
    poll_count INTEGER NOT NULL,
    expected_fragment_count INTEGER NOT NULL,
    received_fragment_bitmap INTEGER NOT NULL,
    missing_fragment_bitmap INTEGER NOT NULL,
    duplicate_fragment_count INTEGER NOT NULL,
    conflicting_fragment_count INTEGER NOT NULL,
    transport_complete INTEGER NOT NULL CHECK (transport_complete IN (0, 1)),
    record_json TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS v2_profile_node_received
    ON v2_profile_scans(node_id, last_received_at_unix_ms DESC);
CREATE INDEX IF NOT EXISTS v2_profile_identity
    ON v2_profile_scans(node_id, boot_id, scan_sequence, config_id);
CREATE TABLE IF NOT EXISTS v2_profile_steps (
    scan_id INTEGER NOT NULL REFERENCES v2_profile_scans(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL CHECK (step_index BETWEEN 0 AND 9),
    gas_index INTEGER NOT NULL,
    measurement_index INTEGER NOT NULL,
    status_bits INTEGER NOT NULL,
    raw_measurement_status INTEGER NOT NULL,
    raw_gas_status INTEGER NOT NULL,
    target_temperature_celsius INTEGER NOT NULL,
    configured_duration_us INTEGER NOT NULL,
    relative_offset_us INTEGER NOT NULL,
    temperature_centi_celsius INTEGER NOT NULL,
    pressure_pascal INTEGER NOT NULL,
    humidity_milli_percent_rh INTEGER NOT NULL,
    gas_resistance_ohm INTEGER NOT NULL,
    raw_temperature_adc INTEGER NOT NULL,
    raw_pressure_adc INTEGER NOT NULL,
    raw_humidity_adc INTEGER NOT NULL,
    raw_gas_resistance_adc INTEGER NOT NULL,
    raw_gas_range INTEGER NOT NULL,
    repetition_multiplier INTEGER NOT NULL,
    raw_heater_resistance INTEGER NOT NULL,
    raw_heater_current INTEGER NOT NULL,
    raw_gas_wait INTEGER NOT NULL,
    PRIMARY KEY (scan_id, step_index)
) STRICT;

CREATE TABLE IF NOT EXISTS v2_profile_fragments (
    scan_id INTEGER NOT NULL REFERENCES v2_profile_scans(id) ON DELETE CASCADE,
    packet_id INTEGER NOT NULL REFERENCES radio_packets(id),
    fragment_index INTEGER NOT NULL,
    received_at_unix_ms INTEGER NOT NULL,
    packet_rssi_centi_dbm INTEGER NOT NULL,
    snr_centi_db INTEGER NOT NULL,
    signal_rssi_centi_dbm INTEGER NOT NULL,
    PRIMARY KEY (scan_id, fragment_index),
    UNIQUE (packet_id)
) STRICT;

CREATE TABLE IF NOT EXISTS v2_device_health (
    id INTEGER PRIMARY KEY,
    received_at_unix_ms INTEGER NOT NULL,
    node_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    scan_sequence INTEGER NOT NULL,
    uptime_ms TEXT NOT NULL,
    config_id TEXT NOT NULL,
    common_flags INTEGER NOT NULL,
    reset_cause_flags INTEGER NOT NULL,
    health_flags INTEGER NOT NULL,
    reset_cause_raw INTEGER NOT NULL,
    successful_sensor_scans INTEGER NOT NULL,
    failed_sensor_scans INTEGER NOT NULL,
    incomplete_profiles INTEGER NOT NULL,
    i2c_errors INTEGER NOT NULL,
    radio_tx_errors INTEGER NOT NULL,
    dropped_profiles INTEGER NOT NULL,
    dropped_fragments INTEGER NOT NULL,
    overwritten_fields INTEGER NOT NULL,
    current_sample_interval_ms INTEGER NOT NULL,
    firmware_version TEXT NOT NULL,
    profile_id INTEGER NOT NULL,
    profile_version INTEGER NOT NULL,
    last_sensor_error INTEGER NOT NULL,
    last_radio_error INTEGER NOT NULL,
    calibrated_mcu_temperature_centi_celsius INTEGER,
    calibrated_vdd_millivolt INTEGER,
    record_json TEXT NOT NULL,
    source_packet_id INTEGER REFERENCES radio_packets(id)
) STRICT;
CREATE INDEX IF NOT EXISTS v2_health_node_received
    ON v2_device_health(node_id, received_at_unix_ms DESC);
";

/// `SQLite` store for every PHY-valid packet and decoded logical record.
pub struct TelemetryStore {
    connection: Connection,
}

/// Identity assigned to one durable legacy reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredReading {
    pub id: i64,
    pub received_at_unix_ms: i64,
    pub radio_packet_id: Option<i64>,
}

/// Identity assigned to one archived PHY-valid packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredPacket {
    pub id: i64,
    pub received_at_unix_ms: i64,
}

/// One previously archived profile fragment awaiting startup reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingProfileFragment {
    pub packet_id: i64,
    pub received_at_unix_ms: i64,
    pub radio: RadioMetadata,
    pub payload: Vec<u8>,
}

/// Identity assigned to one logical protocol-v2 record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredRecord {
    pub id: i64,
    pub received_at_unix_ms: i64,
}

/// Receiver interpretation of one archived application payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketDisposition {
    /// Successfully decoded protocol-v1 telemetry.
    LegacyV1,
    /// Successfully decoded protocol-v2 telemetry.
    ProtocolV2,
    /// PHY-valid payload awaiting or unsupported by an application decoder.
    Unsupported,
    /// Payload recognized as Vesta data but rejected by its decoder.
    Invalid,
}

impl PacketDisposition {
    const fn database_value(self) -> &'static str {
        match self {
            Self::LegacyV1 => "v1",
            Self::ProtocolV2 => "v2",
            Self::Unsupported => "unsupported",
            Self::Invalid => "invalid",
        }
    }
}

/// Exact kind of a successfully decoded protocol-v2 frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V2PacketKind {
    DeviceConfig,
    ProfileFragment,
    DeviceHealth,
}

impl V2PacketKind {
    const fn database_value(self) -> &'static str {
        match self {
            Self::DeviceConfig => "device_config",
            Self::ProfileFragment => "profile_fragment",
            Self::DeviceHealth => "device_health",
        }
    }

    const fn initial_reassembly_status(self) -> &'static str {
        match self {
            Self::ProfileFragment => "pending",
            Self::DeviceConfig | Self::DeviceHealth => "not_applicable",
        }
    }
}

/// Receiver-side state for one decoded v2 profile-fragment packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FragmentStorageStatus {
    Pending,
    Assembled,
    Duplicate,
    Conflict,
    Incomplete,
}

/// A newly archived fragment matched an already persisted complete profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistedFragmentMatch {
    /// Its exact payload matches the persisted fragment at this index.
    Duplicate,
    /// Its payload differs from at least one persisted fragment at this index.
    Conflict,
}

impl PersistedFragmentMatch {
    const fn storage_status(self) -> FragmentStorageStatus {
        match self {
            Self::Duplicate => FragmentStorageStatus::Duplicate,
            Self::Conflict => FragmentStorageStatus::Conflict,
        }
    }
}

impl FragmentStorageStatus {
    const fn database_value(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Assembled => "assembled",
            Self::Duplicate => "duplicate",
            Self::Conflict => "conflict",
            Self::Incomplete => "incomplete",
        }
    }
}

impl TelemetryStore {
    /// Open or create a database and apply non-destructive migrations.
    ///
    /// # Errors
    ///
    /// Returns an error for filesystem, `SQLite`, or unsupported-schema failures.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        Self::initialize(Connection::open(path)?)
    }

    fn initialize(mut connection: Connection) -> Result<Self, StorageError> {
        connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;",
        )?;
        let version = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        match version {
            0 => {
                let transaction = connection.transaction()?;
                transaction.execute_batch(SCHEMA_V1)?;
                transaction.execute_batch(PACKET_ARCHIVE_SCHEMA_V3)?;
                transaction.execute_batch(SCHEMA_V3)?;
                transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                transaction.commit()?;
            }
            1 => {
                let transaction = connection.transaction()?;
                transaction.execute_batch(PACKET_ARCHIVE_SCHEMA_V3)?;
                transaction.execute_batch(SCHEMA_V3)?;
                transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                transaction.commit()?;
            }
            2 => {
                migrate_schema_two(&mut connection)?;
            }
            SCHEMA_VERSION => {}
            found => return Err(StorageError::UnsupportedSchemaVersion { found }),
        }
        // Schema-v3 databases may predate durable completed-profile checks.
        // Add the supporting index non-destructively without a version bump.
        connection.execute_batch(PROFILE_REASSEMBLY_INDEX)?;
        Ok(Self { connection })
    }

    /// Insert one valid v1 observation without a packet-archive link.
    ///
    /// # Errors
    ///
    /// Returns an error for timestamp or `SQLite` failures.
    pub fn insert(
        &self,
        frame: &TelemetryV1,
        payload: &[u8],
        radio: RadioMetadata,
    ) -> Result<StoredReading, StorageError> {
        insert_reading_at(
            &self.connection,
            frame,
            payload,
            radio,
            current_unix_ms()?,
            None,
        )
    }

    /// Atomically archive and store one decoded v1 packet.
    ///
    /// # Errors
    ///
    /// Returns an error for timestamp or transactional failures.
    pub fn insert_received_v1(
        &mut self,
        frame: &TelemetryV1,
        payload: &[u8],
        radio: RadioMetadata,
    ) -> Result<StoredReading, StorageError> {
        let received_at = current_unix_ms()?;
        let transaction = self.connection.transaction()?;
        let packet = insert_packet_at(
            &transaction,
            payload,
            radio,
            received_at,
            PacketDisposition::LegacyV1,
            Some(VERSION),
            None,
            None,
        )?;
        let reading = insert_reading_at(
            &transaction,
            frame,
            payload,
            radio,
            received_at,
            Some(packet.id),
        )?;
        transaction.commit()?;
        Ok(reading)
    }

    /// Archive a PHY-valid unsupported or malformed application payload.
    ///
    /// # Errors
    ///
    /// Returns an error for timestamp or `SQLite` failures.
    pub fn archive_packet(
        &self,
        payload: &[u8],
        radio: RadioMetadata,
        disposition: PacketDisposition,
        decode_error: Option<&str>,
    ) -> Result<StoredPacket, StorageError> {
        let version = payload
            .starts_with(b"VS")
            .then(|| payload.get(2).copied())
            .flatten();
        insert_packet_at(
            &self.connection,
            payload,
            radio,
            current_unix_ms()?,
            disposition,
            version,
            payload.get(3).copied(),
            decode_error,
        )
    }

    /// Archive a validated v2 frame and attach exact common-header metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if packet archival or metadata insertion fails.
    pub fn archive_v2_packet(
        &mut self,
        payload: &[u8],
        radio: RadioMetadata,
        header: Header,
        kind: V2PacketKind,
    ) -> Result<StoredPacket, StorageError> {
        let received_at = current_unix_ms()?;
        let transaction = self.connection.transaction()?;
        let packet = insert_packet_at(
            &transaction,
            payload,
            radio,
            received_at,
            PacketDisposition::ProtocolV2,
            Some(vesta_protocol::v2::VERSION_V2),
            Some(header.frame_type as u8),
            None,
        )?;
        transaction.execute(
            "INSERT INTO v2_packet_decodes (
                packet_id, frame_type, record_kind, reassembly_status,
                node_id, boot_id, scan_sequence, uptime_ms, config_id,
                fragment_index, fragment_count
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                packet.id,
                header.frame_type as u8,
                kind.database_value(),
                kind.initial_reassembly_status(),
                hex_u64(header.common.node_id),
                hex_u64(header.common.boot_id),
                header.common.scan_sequence,
                hex_u64(header.common.uptime_ms),
                hex_u64(header.common.config_id),
                header.fragment_index,
                header.fragment_count,
            ],
        )?;
        transaction.commit()?;
        Ok(packet)
    }

    /// Load every archived profile fragment still marked pending, up to a hard
    /// startup bound.
    ///
    /// The count is checked before any payload is returned, so callers never
    /// reconcile a silent prefix while abandoning the remainder.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero/unrepresentable bound, an exceeded bound,
    /// or an `SQLite` query failure.
    pub fn pending_profile_fragments(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingProfileFragment>, StorageError> {
        let limit_usize = limit;
        let limit = i64::try_from(limit_usize)
            .ok()
            .filter(|limit| *limit > 0)
            .ok_or(StorageError::InvalidPendingReplayLimit)?;
        let pending: i64 = self.connection.query_row(
            "SELECT count(*)
             FROM radio_packets AS packet
             JOIN v2_packet_decodes AS decoded ON decoded.packet_id = packet.id
             WHERE decoded.record_kind = 'profile_fragment'
               AND decoded.reassembly_status = 'pending'",
            [],
            |row| row.get(0),
        )?;
        if pending > limit {
            return Err(StorageError::PendingReplayLimitExceeded {
                pending,
                limit: limit_usize,
            });
        }

        let mut statement = self.connection.prepare(
            "SELECT packet.id, packet.received_at_unix_ms,
                    packet.packet_rssi_centi_dbm, packet.snr_centi_db,
                    packet.signal_rssi_centi_dbm, packet.payload
             FROM radio_packets AS packet
             JOIN v2_packet_decodes AS decoded ON decoded.packet_id = packet.id
             WHERE decoded.record_kind = 'profile_fragment'
               AND decoded.reassembly_status = 'pending'
             ORDER BY packet.id ASC
             LIMIT ?1",
        )?;
        let fragments = statement
            .query_map([limit], |row| {
                Ok(PendingProfileFragment {
                    packet_id: row.get(0)?,
                    received_at_unix_ms: row.get(1)?,
                    radio: RadioMetadata {
                        packet_rssi_centi_dbm: row.get(2)?,
                        snr_centi_db: row.get(3)?,
                        signal_rssi_centi_dbm: row.get(4)?,
                    },
                    payload: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(fragments)
    }

    /// Classify a fragment against any already persisted complete profile with
    /// the same full logical key.
    ///
    /// A match updates the new packet's reassembly disposition and saturating
    /// duplicate/conflict counters on every matching persisted scan. Conflict
    /// updates also make those scans fail the analysis integrity gate. This
    /// durable check survives receiver restarts and completed-cache expiry.
    ///
    /// # Errors
    ///
    /// Returns an error for an `SQLite` query/update or commit failure.
    pub fn reconcile_completed_profile_fragment(
        &mut self,
        key: ProfileKey,
        packet_id: i64,
        fragment_index: u8,
        payload: &[u8],
    ) -> Result<Option<PersistedFragmentMatch>, StorageError> {
        let transaction = self.connection.transaction()?;
        let persisted = {
            let mut statement = transaction.prepare(
                "SELECT scan.id, packet.payload
                 FROM v2_profile_scans AS scan
                 JOIN v2_profile_fragments AS fragment
                   ON fragment.scan_id = scan.id
                  AND fragment.fragment_index = ?7
                 JOIN radio_packets AS packet ON packet.id = fragment.packet_id
                 WHERE scan.node_id = ?1
                   AND scan.boot_id = ?2
                   AND scan.scan_sequence = ?3
                   AND scan.uptime_ms = ?4
                   AND scan.config_id = ?5
                   AND ((scan.common_flags & 1) != 0) = ?6
                   AND scan.transport_complete = 1
                 ORDER BY scan.id ASC",
            )?;
            statement
                .query_map(
                    params![
                        hex_u64(key.node_id),
                        hex_u64(key.boot_id),
                        key.scan_sequence,
                        hex_u64(key.uptime_ms),
                        hex_u64(key.config_id),
                        i64::from(key.boot_id_valid),
                        fragment_index,
                    ],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        if persisted.is_empty() {
            transaction.commit()?;
            return Ok(None);
        }

        let classification = if persisted
            .iter()
            .all(|(_, persisted_payload)| persisted_payload == payload)
        {
            PersistedFragmentMatch::Duplicate
        } else {
            PersistedFragmentMatch::Conflict
        };
        let (column, json_path) = match classification {
            PersistedFragmentMatch::Duplicate => {
                ("duplicate_fragment_count", "$.duplicate_fragment_count")
            }
            PersistedFragmentMatch::Conflict => {
                ("conflicting_fragment_count", "$.conflicting_fragment_count")
            }
        };
        let update = format!(
            "UPDATE v2_profile_scans
             SET {column} = min({column} + 1, 65535),
                 record_json = json_set(
                     record_json, '{json_path}', min({column} + 1, 65535)
                 )
             WHERE id = ?1"
        );
        for (scan_id, _) in &persisted {
            transaction.execute(&update, [scan_id])?;
        }
        transaction.execute(
            "UPDATE v2_packet_decodes SET reassembly_status = ?1
             WHERE packet_id = ?2",
            params![classification.storage_status().database_value(), packet_id],
        )?;
        transaction.commit()?;
        Ok(Some(classification))
    }

    /// Update receiver-side reassembly state for an archived fragment.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet does not identify a profile fragment or
    /// the update fails.
    pub fn mark_fragment_status(
        &self,
        packet_id: i64,
        status: FragmentStorageStatus,
    ) -> Result<(), StorageError> {
        let changed = self.connection.execute(
            "UPDATE v2_packet_decodes SET reassembly_status = ?1
             WHERE packet_id = ?2 AND record_kind = 'profile_fragment'",
            params![status.database_value(), packet_id],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StorageError::MissingV2Packet { packet_id })
        }
    }

    /// Store one exact v2 configuration and its ordered heater descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid structure, JSON, timestamps, or `SQLite`.
    pub fn insert_device_configuration(
        &mut self,
        configuration: &DeviceConfiguration,
        source_packet_id: Option<i64>,
    ) -> Result<StoredRecord, StorageError> {
        configuration.validate()?;
        let received_at = self.packet_or_current_time(source_packet_id)?;
        let record_json = serde_json::to_string(configuration)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO v2_device_configurations (
                received_at_unix_ms, node_id, boot_id, scan_sequence, uptime_ms,
                config_id, common_flags, reset_cause_flags, repeated,
                firmware_version, firmware_build_id, sensor_chip_id,
                sensor_variant, calibration_hash_algorithm, calibration_hash,
                profile_id, profile_version, expected_step_count,
                expected_profile_duration_us, scan_interval_ms, output_routes,
                radio_frequency_hz, radio_tx_power_dbm,
                radio_spreading_factor, radio_bandwidth_hz, record_json,
                source_packet_id
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24,
                ?25, ?26, ?27
             )",
            params![
                received_at,
                hex_u64(configuration.identity.node_id),
                hex_u64(configuration.identity.boot_id),
                configuration.identity.scan_sequence,
                hex_u64(configuration.identity.uptime_ms),
                hex_u64(configuration.identity.config_id),
                configuration.identity.common_flags,
                configuration.identity.reset_cause_flags,
                configuration.repeated,
                semver_text(configuration.firmware_version),
                hex_u64(configuration.firmware_build_id),
                configuration.sensor_chip_id,
                configuration.sensor_variant,
                configuration.calibration_hash_algorithm,
                hex_u64(configuration.calibration_hash),
                configuration.profile_id,
                configuration.profile_version,
                configuration.expected_step_count,
                configuration.expected_profile_duration_us,
                configuration.scan_interval_ms,
                configuration.output_routes,
                configuration.radio_frequency_hz,
                configuration.radio_tx_power_dbm,
                configuration.radio_spreading_factor,
                configuration.radio_bandwidth_hz,
                record_json,
                source_packet_id,
            ],
        )?;
        let id = transaction.last_insert_rowid();
        for step in &configuration.heater_steps {
            transaction.execute(
                "INSERT INTO v2_heater_profile_steps (
                    configuration_id, step_index, target_temperature_celsius,
                    configured_duration_us, repetition_multiplier,
                    programmed_heater_current, programmed_heater_resistance,
                    programmed_gas_wait
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    id,
                    step.step_index,
                    step.target_temperature_celsius,
                    step.configured_duration_us,
                    step.repetition_multiplier,
                    step.readback_heater_current,
                    step.programmed_heater_resistance,
                    step.programmed_gas_wait,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(StoredRecord {
            id,
            received_at_unix_ms: received_at,
        })
    }

    /// Store a complete or transport-incomplete reassembled profile.
    ///
    /// Every unique source fragment retains its own receiver timestamp and
    /// RSSI/SNR values; no synthetic scan-level link metric is created.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid structure, absent sources, JSON, or `SQLite`.
    #[allow(clippy::too_many_lines)]
    pub fn insert_profile_scan(
        &mut self,
        profile: &ReassembledProfile,
    ) -> Result<StoredRecord, StorageError> {
        profile.scan.validate()?;
        let first_received = profile
            .first_received_at_unix_ms()
            .ok_or(StorageError::ProfileWithoutFragments)?;
        let last_received = profile
            .last_received_at_unix_ms()
            .ok_or(StorageError::ProfileWithoutFragments)?;
        let scan = &profile.scan;
        let record_json = serde_json::to_string(scan)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO v2_profile_scans (
                first_received_at_unix_ms, last_received_at_unix_ms, node_id,
                boot_id, scan_sequence, uptime_ms, config_id, common_flags,
                reset_cause_flags, profile_id, profile_version, expected_steps,
                observed_unique_steps, observed_field_count,
                reported_missing_steps, duplicate_steps, duration_us,
                collection_flags, finish_reason, duplicate_count,
                overwritten_field_count, out_of_order_count,
                ambiguous_index_jump_count, invalid_gas_index_count,
                intermediate_field_count, profile_rollover_count,
                fields_after_rollover_count, poll_count,
                expected_fragment_count, received_fragment_bitmap,
                missing_fragment_bitmap, duplicate_fragment_count,
                conflicting_fragment_count, transport_complete, record_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24,
                ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35
             )",
            params![
                first_received,
                last_received,
                hex_u64(scan.identity.node_id),
                hex_u64(scan.identity.boot_id),
                scan.identity.scan_sequence,
                hex_u64(scan.identity.uptime_ms),
                hex_u64(scan.identity.config_id),
                scan.identity.common_flags,
                scan.identity.reset_cause_flags,
                scan.profile_id,
                scan.profile_version,
                scan.expected_steps,
                scan.observed_unique_steps,
                scan.observed_field_count,
                scan.reported_missing_steps,
                scan.duplicate_steps,
                scan.duration_us,
                scan.collection_flags,
                scan.finish_reason,
                scan.duplicate_count,
                scan.overwritten_field_count,
                scan.out_of_order_count,
                scan.ambiguous_index_jump_count,
                scan.invalid_gas_index_count,
                scan.intermediate_field_count,
                scan.profile_rollover_count,
                scan.fields_after_rollover_count,
                scan.poll_count,
                scan.expected_fragment_count,
                scan.received_fragment_bitmap,
                scan.missing_fragment_bitmap(),
                scan.duplicate_fragment_count,
                scan.conflicting_fragment_count,
                scan.is_transport_complete(),
                record_json,
            ],
        )?;
        let id = transaction.last_insert_rowid();
        for step in &scan.steps {
            transaction.execute(
                "INSERT INTO v2_profile_steps (
                    scan_id, step_index, gas_index, measurement_index,
                    status_bits, raw_measurement_status, raw_gas_status,
                    target_temperature_celsius, configured_duration_us,
                    relative_offset_us, temperature_centi_celsius,
                    pressure_pascal, humidity_milli_percent_rh,
                    gas_resistance_ohm, raw_temperature_adc, raw_pressure_adc,
                    raw_humidity_adc, raw_gas_resistance_adc, raw_gas_range,
                    repetition_multiplier, raw_heater_resistance,
                    raw_heater_current, raw_gas_wait
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                    ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23
                 )",
                params![
                    id,
                    step.step_index,
                    step.gas_index,
                    step.measurement_index,
                    step.status_bits,
                    step.raw_measurement_status,
                    step.raw_gas_status,
                    step.target_temperature_celsius,
                    step.configured_duration_us,
                    step.relative_offset_us,
                    step.temperature_centi_celsius,
                    step.pressure_pascal,
                    step.humidity_milli_percent_rh,
                    step.gas_resistance_ohm,
                    step.raw_temperature_adc,
                    step.raw_pressure_adc,
                    step.raw_humidity_adc,
                    step.raw_gas_resistance_adc,
                    step.raw_gas_range,
                    step.repetition_multiplier,
                    step.raw_heater_resistance,
                    step.raw_heater_current,
                    step.raw_gas_wait,
                ],
            )?;
        }
        for fragment in &profile.fragments {
            transaction.execute(
                "INSERT INTO v2_profile_fragments (
                    scan_id, packet_id, fragment_index, received_at_unix_ms,
                    packet_rssi_centi_dbm, snr_centi_db,
                    signal_rssi_centi_dbm
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    fragment.packet_id,
                    fragment.fragment_index,
                    fragment.received_at_unix_ms,
                    fragment.radio.packet_rssi_centi_dbm,
                    fragment.radio.snr_centi_db,
                    fragment.radio.signal_rssi_centi_dbm,
                ],
            )?;
            transaction.execute(
                "UPDATE v2_packet_decodes SET reassembly_status = ?1
                 WHERE packet_id = ?2",
                params![
                    if scan.is_transport_complete() {
                        FragmentStorageStatus::Assembled.database_value()
                    } else {
                        FragmentStorageStatus::Incomplete.database_value()
                    },
                    fragment.packet_id,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(StoredRecord {
            id,
            received_at_unix_ms: last_received,
        })
    }

    /// Store one exact device-health record.
    ///
    /// # Errors
    ///
    /// Returns an error for timestamp, JSON, or `SQLite` failures.
    pub fn insert_device_health(
        &self,
        health: &DeviceHealth,
        source_packet_id: Option<i64>,
    ) -> Result<StoredRecord, StorageError> {
        let received_at = self.packet_or_current_time(source_packet_id)?;
        let record_json = serde_json::to_string(health)?;
        self.connection.execute(
            "INSERT INTO v2_device_health (
                received_at_unix_ms, node_id, boot_id, scan_sequence,
                uptime_ms, config_id, common_flags, reset_cause_flags,
                health_flags, reset_cause_raw, successful_sensor_scans,
                failed_sensor_scans, incomplete_profiles, i2c_errors,
                radio_tx_errors, dropped_profiles, dropped_fragments,
                overwritten_fields, current_sample_interval_ms,
                firmware_version, profile_id, profile_version,
                last_sensor_error, last_radio_error,
                calibrated_mcu_temperature_centi_celsius,
                calibrated_vdd_millivolt, record_json, source_packet_id
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24,
                ?25, ?26, ?27, ?28
             )",
            params![
                received_at,
                hex_u64(health.identity.node_id),
                hex_u64(health.identity.boot_id),
                health.identity.scan_sequence,
                hex_u64(health.identity.uptime_ms),
                hex_u64(health.identity.config_id),
                health.identity.common_flags,
                health.identity.reset_cause_flags,
                health.health_flags,
                health.reset_cause_raw,
                health.successful_sensor_scans,
                health.failed_sensor_scans,
                health.incomplete_profiles,
                health.i2c_errors,
                health.radio_tx_errors,
                health.dropped_profiles,
                health.dropped_fragments,
                health.overwritten_fields,
                health.current_sample_interval_ms,
                semver_text(health.firmware_version),
                health.profile_id,
                health.profile_version,
                health.last_sensor_error,
                health.last_radio_error,
                health.calibrated_mcu_temperature_centi_celsius,
                health.calibrated_vdd_millivolt,
                record_json,
                source_packet_id,
            ],
        )?;
        Ok(StoredRecord {
            id: self.connection.last_insert_rowid(),
            received_at_unix_ms: received_at,
        })
    }

    fn packet_or_current_time(&self, packet_id: Option<i64>) -> Result<i64, StorageError> {
        if let Some(packet_id) = packet_id {
            self.connection
                .query_row(
                    "SELECT received_at_unix_ms FROM radio_packets WHERE id = ?1",
                    [packet_id],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(StorageError::MissingV2Packet { packet_id })
        } else {
            current_unix_ms()
        }
    }

    #[cfg(test)]
    fn open_in_memory() -> Result<Self, StorageError> {
        Self::initialize(Connection::open_in_memory()?)
    }
}

fn migrate_schema_two(connection: &mut Connection) -> Result<(), StorageError> {
    // SQLite cannot change foreign-key enforcement inside a transaction. Turn
    // it off before rebuilding the parent table, then restore it regardless of
    // whether the migration succeeds.
    connection.pragma_update(None, "foreign_keys", false)?;
    let migration = (|| -> Result<(), StorageError> {
        let transaction = connection.transaction()?;
        transaction.execute_batch(RADIO_PACKETS_V2_TO_V3)?;
        // The draft schema-v2 record tables deliberately remain intact. The
        // exact final wire model uses separately named schema-v3 tables.
        transaction.execute_batch(SCHEMA_V3)?;
        let violations: i64 =
            transaction.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })?;
        if violations != 0 {
            return Err(StorageError::MigrationForeignKeyViolations { count: violations });
        }
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
        Ok(())
    })();
    let restore_foreign_keys = connection.pragma_update(None, "foreign_keys", true);
    if let Err(error) = migration {
        let _ = restore_foreign_keys;
        return Err(error);
    }
    restore_foreign_keys?;
    Ok(())
}

fn current_unix_ms() -> Result<i64, StorageError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    i64::try_from(elapsed.as_millis()).map_err(|_| StorageError::TimestampOutOfRange)
}

fn hex_u64(value: u64) -> String {
    format!("{value:016x}")
}

fn semver_text(version: [u8; 3]) -> String {
    format!("{}.{}.{}", version[0], version[1], version[2])
}

#[allow(clippy::too_many_arguments)]
fn insert_packet_at(
    connection: &Connection,
    payload: &[u8],
    radio: RadioMetadata,
    received_at: i64,
    disposition: PacketDisposition,
    protocol_version: Option<u8>,
    frame_type: Option<u8>,
    decode_error: Option<&str>,
) -> Result<StoredPacket, StorageError> {
    connection.execute(
        "INSERT INTO radio_packets (
            received_at_unix_ms, packet_rssi_centi_dbm, snr_centi_db,
            signal_rssi_centi_dbm, protocol_version, frame_type,
            disposition, decode_error, payload
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            received_at,
            radio.packet_rssi_centi_dbm,
            radio.snr_centi_db,
            radio.signal_rssi_centi_dbm,
            protocol_version,
            frame_type,
            disposition.database_value(),
            decode_error,
            payload,
        ],
    )?;
    Ok(StoredPacket {
        id: connection.last_insert_rowid(),
        received_at_unix_ms: received_at,
    })
}

fn insert_reading_at(
    connection: &Connection,
    frame: &TelemetryV1,
    payload: &[u8],
    radio: RadioMetadata,
    received_at: i64,
    radio_packet_id: Option<i64>,
) -> Result<StoredReading, StorageError> {
    let status = frame.sensor_status;
    connection.execute(
        "INSERT INTO telemetry_readings (
            received_at_unix_ms, protocol_version, node_id, sequence,
            status_bits, status_new_data, status_gas_valid,
            status_heater_stable, status_unknown_bits,
            temperature_centi_celsius, pressure_pascal,
            humidity_milli_percent_rh, gas_resistance_ohm,
            raw_temperature_adc, raw_pressure_adc, raw_humidity_adc,
            raw_gas_resistance_adc, raw_gas_range, raw_gas_index,
            raw_measurement_index, raw_heater_resistance,
            raw_heater_current, raw_gas_wait, packet_rssi_centi_dbm,
            snr_centi_db, signal_rssi_centi_dbm, payload, radio_packet_id
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24,
            ?25, ?26, ?27, ?28
         )",
        params![
            received_at,
            VERSION,
            hex_u64(frame.node_id),
            frame.sequence,
            status.bits(),
            status.is_new_data(),
            status.is_gas_measurement_valid(),
            status.is_heater_stable(),
            status.unknown_bits(),
            frame.compensated.temperature.centi_celsius(),
            frame.compensated.pressure.pascals(),
            frame.compensated.humidity.milli_percent_rh(),
            frame.compensated.gas_resistance.ohms(),
            frame.raw.temperature_adc,
            frame.raw.pressure_adc,
            frame.raw.humidity_adc,
            frame.raw.gas_resistance_adc,
            frame.raw.gas_range,
            frame.raw.gas_index,
            frame.raw.measurement_index,
            frame.raw.heater_resistance,
            frame.raw.heater_current,
            frame.raw.gas_wait,
            radio.packet_rssi_centi_dbm,
            radio.snr_centi_db,
            radio.signal_rssi_centi_dbm,
            payload,
            radio_packet_id,
        ],
    )?;
    Ok(StoredReading {
        id: connection.last_insert_rowid(),
        received_at_unix_ms: received_at,
        radio_packet_id,
    })
}

/// Failure while creating, migrating, or writing the telemetry database.
#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    SystemTime(SystemTimeError),
    TimestampOutOfRange,
    InvalidRecord(RecordError),
    MissingV2Packet { packet_id: i64 },
    ProfileWithoutFragments,
    InvalidPendingReplayLimit,
    PendingReplayLimitExceeded { pending: i64, limit: usize },
    MigrationForeignKeyViolations { count: i64 },
    UnsupportedSchemaVersion { found: i64 },
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "database directory error: {error}"),
            Self::Sqlite(error) => write!(formatter, "SQLite error: {error}"),
            Self::Json(error) => write!(formatter, "record JSON error: {error}"),
            Self::SystemTime(error) => write!(formatter, "system clock error: {error}"),
            Self::TimestampOutOfRange => formatter.write_str("timestamp does not fit SQLite"),
            Self::InvalidRecord(error) => write!(formatter, "invalid decoded record: {error}"),
            Self::MissingV2Packet { packet_id } => {
                write!(formatter, "v2 source packet {packet_id} does not exist")
            }
            Self::ProfileWithoutFragments => {
                formatter.write_str("reassembled profile has no source fragments")
            }
            Self::InvalidPendingReplayLimit => {
                formatter.write_str("pending-fragment replay limit must be positive")
            }
            Self::PendingReplayLimitExceeded { pending, limit } => write!(
                formatter,
                "{pending} pending profile fragments exceed startup replay limit {limit}"
            ),
            Self::MigrationForeignKeyViolations { count } => write!(
                formatter,
                "schema migration left {count} foreign-key violation(s)"
            ),
            Self::UnsupportedSchemaVersion { found } => write!(
                formatter,
                "unsupported telemetry database schema version {found}; expected {SCHEMA_VERSION}"
            ),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::SystemTime(error) => Some(error),
            Self::InvalidRecord(error) => Some(error),
            Self::TimestampOutOfRange
            | Self::MissingV2Packet { .. }
            | Self::ProfileWithoutFragments
            | Self::InvalidPendingReplayLimit
            | Self::PendingReplayLimitExceeded { .. }
            | Self::MigrationForeignKeyViolations { .. }
            | Self::UnsupportedSchemaVersion { .. } => None,
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<SystemTimeError> for StorageError {
    fn from(error: SystemTimeError) -> Self {
        Self::SystemTime(error)
    }
}

impl From<RecordError> for StorageError {
    fn from(error: RecordError) -> Self {
        Self::InvalidRecord(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reassembly::{
        FragmentEvent, ProfileReassembler, SourceFragment, device_configuration, device_health,
    };
    use crate::{decode_hex, parse_frame_hex, parse_payload_hex};

    const FIXTURE: &str = "565301b001020304050607080a0b0c0dfb2e00018bcd0000b26e000f12060007eed00005902075300200080203040506";
    const CONFIG_V2: &str = "565302013003000100b701020304050607081112131415161718ffffffff212223242526272896392f014bce77450005010302030401a0a1a2a3a4a5a6a76101760205010008030100637300017c1c0000a27600a331ea100100020a03ff01b0b1b2b3b4b5b6b70000ea6000100533be27a005070001e848040500080001001424e70300c800021e920120604000dc00043d240221614100f000065bb603226242010400087a48042363430118000a98da05246444012c000cb76c062565450140000ed5fe0726664601540010f4900827674701680013132209286848017c001531b40a296949";

    const fn radio() -> RadioMetadata {
        RadioMetadata {
            packet_rssi_centi_dbm: -4_200,
            snr_centi_db: 1_250,
            signal_rssi_centi_dbm: -4_250,
        }
    }

    #[test]
    fn stores_v1_fixture_byte_exact_and_links_live_packet() {
        let mut store = TelemetryStore::open_in_memory().unwrap();
        let frame = decode_hex(FIXTURE).unwrap();
        let payload = parse_frame_hex(FIXTURE).unwrap();
        let stored = store.insert_received_v1(&frame, &payload, radio()).unwrap();
        let archived: (String, Vec<u8>) = store
            .connection
            .query_row(
                "SELECT disposition, payload FROM radio_packets WHERE id = ?1",
                [stored.radio_packet_id.unwrap()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(archived, ("v1".to_owned(), payload.to_vec()));
    }

    #[test]
    fn unsupported_packets_remain_byte_exact() {
        let store = TelemetryStore::open_in_memory().unwrap();
        let payload = b"VS\x09future";
        let packet = store
            .archive_packet(payload, radio(), PacketDisposition::Unsupported, None)
            .unwrap();
        let archived: Vec<u8> = store
            .connection
            .query_row(
                "SELECT payload FROM radio_packets WHERE id = ?1",
                [packet.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(archived, payload);
    }

    #[test]
    fn stores_preconfiguration_health_with_zero_config_id_as_protocol_v2() {
        let mut store = TelemetryStore::open_in_memory().unwrap();
        let common = vesta_protocol::v2::Common::boot_id_unavailable(1, 7, 12, 0, 0);
        let encoded = vesta_protocol::v2::encode_device_health(
            common,
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
        let vesta_protocol::v2::DecodedFrame::DeviceHealth { header, health } =
            vesta_protocol::v2::decode(encoded.as_slice()).unwrap()
        else {
            unreachable!()
        };
        let packet = store
            .archive_v2_packet(
                encoded.as_slice(),
                radio(),
                header,
                V2PacketKind::DeviceHealth,
            )
            .unwrap();
        store
            .insert_device_health(&device_health(header, health), Some(packet.id))
            .unwrap();

        let row: (String, String, i64, i64) = store
            .connection
            .query_row(
                "SELECT p.disposition, h.config_id, h.profile_id, h.profile_version
                 FROM v2_device_health AS h
                 JOIN radio_packets AS p ON p.id = h.source_packet_id",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(row, ("v2".to_owned(), "0000000000000000".to_owned(), 0, 0));
        let foreign_key_violations: i64 = store
            .connection
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(foreign_key_violations, 0);
    }

    fn protocol_step(index: u8) -> vesta_protocol::v2::ProfileStep {
        vesta_protocol::v2::ProfileStep {
            step_index: index,
            gas_index: index,
            measurement_index: index,
            status: 0xb0,
            raw_measurement_status: 0x80,
            raw_gas_status: 0x30,
            target_temperature_celsius: 200 + u16::from(index),
            configured_duration_us: 138_898,
            offset_us: u32::from(index) * 138_898,
            temperature_centi_celsius: 2_500,
            pressure_pascal: 101_325,
            humidity_milli_percent_rh: 40_000,
            gas_resistance_ohm: 20_000,
            temperature_adc: 1,
            pressure_adc: 2,
            humidity_adc: 3,
            gas_resistance_adc: 4,
            gas_range: 5,
            repetition_multiplier: 1,
            heater_resistance: 6,
            heater_current: 7,
            gas_wait: 8,
        }
    }

    fn protocol_profile(sequence: u32) -> vesta_protocol::v2::EncodedProfile {
        let mut steps = [None; vesta_protocol::v2::MAX_PROFILE_STEPS];
        for index in 0..10_u8 {
            steps[usize::from(index)] = Some(protocol_step(index));
        }
        vesta_protocol::v2::encode_profile(
            vesta_protocol::v2::Common::production(
                0x0102_0304_0506_0708,
                u64::MAX,
                sequence,
                u64::MAX,
                0x9639_2f01_4bce_7745,
                5,
            ),
            &vesta_protocol::v2::ProfileScan {
                profile_id: 0x1001,
                profile_version: 2,
                expected_step_count: 10,
                observed_unique_step_count: 10,
                observed_field_count: 10,
                missing_steps_bitmap: 0,
                duplicate_steps_bitmap: 0,
                scan_duration_us: 10_695_146,
                collection_flags: 0,
                finish_reason: vesta_protocol::v2::FINISH_REASON_COMPLETE,
                duplicate_count: 0,
                overwritten_field_count: 0,
                out_of_order_count: 0,
                ambiguous_index_jump_count: 0,
                invalid_gas_index_count: 0,
                intermediate_field_count: 0,
                profile_rollover_count: 0,
                fields_after_rollover_count: 0,
                poll_count: 120,
                steps,
            },
        )
        .unwrap()
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn stores_exact_v2_configuration_and_ten_step_profile() {
        let mut store = TelemetryStore::open_in_memory().unwrap();
        let config_payload = parse_payload_hex(CONFIG_V2).unwrap();
        let vesta_protocol::v2::DecodedFrame::DeviceConfig { header, config } =
            vesta_protocol::v2::decode(&config_payload).unwrap()
        else {
            unreachable!()
        };
        let packet = store
            .archive_v2_packet(&config_payload, radio(), header, V2PacketKind::DeviceConfig)
            .unwrap();
        let disposition: String = store
            .connection
            .query_row(
                "SELECT disposition FROM radio_packets WHERE id = ?1",
                [packet.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(disposition, "v2");
        let configuration = device_configuration(header, config);
        store
            .insert_device_configuration(&configuration, Some(packet.id))
            .unwrap();
        let config_row: (String, String, i64, i64) = store
            .connection
            .query_row(
                "SELECT boot_id, config_id, output_routes,
                        (SELECT count(*) FROM v2_heater_profile_steps)
                 FROM v2_device_configurations",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            config_row,
            (
                "1112131415161718".to_owned(),
                "96392f014bce7745".to_owned(),
                5,
                10,
            )
        );

        let encoded = protocol_profile(u32::MAX);
        let mut reassembler = ProfileReassembler::default();
        let mut completed = None;
        for index in [3_usize, 0, 2, 1] {
            let payload = encoded.frames()[index].as_slice();
            let vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) =
                vesta_protocol::v2::decode(payload).unwrap()
            else {
                unreachable!()
            };
            let archived = store
                .archive_v2_packet(
                    payload,
                    radio(),
                    fragment.header,
                    V2PacketKind::ProfileFragment,
                )
                .unwrap();
            let result = reassembler
                .ingest(
                    fragment,
                    SourceFragment {
                        packet_id: archived.id,
                        fragment_index: u8::try_from(index).unwrap(),
                        received_at_unix_ms: archived.received_at_unix_ms,
                        radio: radio(),
                    },
                )
                .unwrap();
            if let FragmentEvent::Complete(profile) = result.event {
                completed = Some(profile);
            }
        }
        let profile = completed.unwrap();
        store.insert_profile_scan(&profile).unwrap();
        let profile_row: (String, String, i64, i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT boot_id, uptime_ms, transport_complete,
                        (SELECT count(*) FROM v2_profile_steps),
                        (SELECT count(*) FROM v2_profile_fragments),
                        (SELECT raw_measurement_status FROM v2_profile_steps
                         WHERE step_index = 9)
                 FROM v2_profile_scans",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            profile_row,
            (
                "ffffffffffffffff".to_owned(),
                "ffffffffffffffff".to_owned(),
                1,
                10,
                4,
                0x80,
            )
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn persisted_profile_detects_late_duplicate_and_conflict_without_cache() {
        let mut store = TelemetryStore::open_in_memory().unwrap();
        let encoded = protocol_profile(11);
        let mut reassembler = ProfileReassembler::default();
        let mut completed = None;
        for (index, frame) in encoded.frames().iter().enumerate() {
            let vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) =
                vesta_protocol::v2::decode(frame.as_slice()).unwrap()
            else {
                unreachable!()
            };
            let packet = store
                .archive_v2_packet(
                    frame.as_slice(),
                    radio(),
                    fragment.header,
                    V2PacketKind::ProfileFragment,
                )
                .unwrap();
            let result = reassembler
                .ingest(
                    fragment,
                    SourceFragment {
                        packet_id: packet.id,
                        fragment_index: u8::try_from(index).unwrap(),
                        received_at_unix_ms: packet.received_at_unix_ms,
                        radio: radio(),
                    },
                )
                .unwrap();
            if let FragmentEvent::Complete(profile) = result.event {
                completed = Some(profile);
            }
        }
        store.insert_profile_scan(&completed.unwrap()).unwrap();
        drop(reassembler);

        let duplicate_payload = encoded.frames()[0].as_slice();
        let vesta_protocol::v2::DecodedFrame::ProfileFragment(duplicate) =
            vesta_protocol::v2::decode(duplicate_payload).unwrap()
        else {
            unreachable!()
        };
        let duplicate_packet = store
            .archive_v2_packet(
                duplicate_payload,
                radio(),
                duplicate.header,
                V2PacketKind::ProfileFragment,
            )
            .unwrap();
        let key = ProfileKey::from(&duplicate.header);
        assert_eq!(
            store
                .reconcile_completed_profile_fragment(
                    key,
                    duplicate_packet.id,
                    0,
                    duplicate_payload,
                )
                .unwrap(),
            Some(PersistedFragmentMatch::Duplicate)
        );

        let mut conflict_payload = duplicate_payload.to_vec();
        let last = conflict_payload.len() - 1;
        conflict_payload[last] ^= 1;
        let vesta_protocol::v2::DecodedFrame::ProfileFragment(conflict) =
            vesta_protocol::v2::decode(&conflict_payload).unwrap()
        else {
            unreachable!()
        };
        let conflict_packet = store
            .archive_v2_packet(
                &conflict_payload,
                radio(),
                conflict.header,
                V2PacketKind::ProfileFragment,
            )
            .unwrap();
        assert_eq!(
            store
                .reconcile_completed_profile_fragment(
                    ProfileKey::from(&conflict.header),
                    conflict_packet.id,
                    0,
                    &conflict_payload,
                )
                .unwrap(),
            Some(PersistedFragmentMatch::Conflict)
        );

        let counters: (i64, i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT duplicate_fragment_count, conflicting_fragment_count,
                        json_extract(record_json, '$.duplicate_fragment_count'),
                        json_extract(record_json, '$.conflicting_fragment_count')
                 FROM v2_profile_scans",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(counters, (1, 1, 1, 1));
        for (packet_id, expected) in [
            (duplicate_packet.id, "duplicate"),
            (conflict_packet.id, "conflict"),
        ] {
            let status: String = store
                .connection
                .query_row(
                    "SELECT reassembly_status FROM v2_packet_decodes WHERE packet_id = ?1",
                    [packet_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(status, expected);
        }
    }

    #[test]
    fn persists_receiver_missing_fragments_without_fabricating_link_metrics() {
        let mut store = TelemetryStore::open_in_memory().unwrap();
        let encoded = protocol_profile(7);
        let payload = encoded.frames()[2].as_slice();
        let vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) =
            vesta_protocol::v2::decode(payload).unwrap()
        else {
            unreachable!()
        };
        let archived = store
            .archive_v2_packet(
                payload,
                radio(),
                fragment.header,
                V2PacketKind::ProfileFragment,
            )
            .unwrap();
        let mut reassembler = ProfileReassembler::default();
        reassembler
            .ingest(
                fragment,
                SourceFragment {
                    packet_id: archived.id,
                    fragment_index: 2,
                    received_at_unix_ms: archived.received_at_unix_ms,
                    radio: radio(),
                },
            )
            .unwrap();
        let profile = reassembler.drain_incomplete().pop().unwrap();
        store.insert_profile_scan(&profile).unwrap();
        let row: (i64, i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT received_fragment_bitmap, missing_fragment_bitmap,
                        transport_complete,
                        (SELECT packet_rssi_centi_dbm
                         FROM v2_profile_fragments LIMIT 1)
                 FROM v2_profile_scans",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(row, (0b0100, 0b1011, 0, -4_200));
    }

    #[test]
    fn pending_fragment_replay_is_exact_and_refuses_a_silent_prefix() {
        let mut store = TelemetryStore::open_in_memory().unwrap();
        let encoded = protocol_profile(8);
        let mut archived = Vec::new();
        for index in [2_usize, 0, 1] {
            let payload = encoded.frames()[index].as_slice();
            let vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) =
                vesta_protocol::v2::decode(payload).unwrap()
            else {
                unreachable!()
            };
            archived.push(
                store
                    .archive_v2_packet(
                        payload,
                        radio(),
                        fragment.header,
                        V2PacketKind::ProfileFragment,
                    )
                    .unwrap(),
            );
        }
        store
            .mark_fragment_status(archived[1].id, FragmentStorageStatus::Duplicate)
            .unwrap();

        assert!(matches!(
            store.pending_profile_fragments(1),
            Err(StorageError::PendingReplayLimitExceeded {
                pending: 2,
                limit: 1
            })
        ));
        assert!(matches!(
            store.pending_profile_fragments(0),
            Err(StorageError::InvalidPendingReplayLimit)
        ));
        let pending = store.pending_profile_fragments(2).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].packet_id, archived[0].id);
        assert_eq!(pending[0].payload, encoded.frames()[2].as_slice());
        assert_eq!(pending[0].radio, radio());
        assert_eq!(pending[1].packet_id, archived[2].id);
    }

    #[test]
    fn migrates_schema_one_without_losing_readings() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA_V1).unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();
        let store = TelemetryStore::initialize(connection).unwrap();
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);
        let table_count: i64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='v2_profile_scans'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_count, 1);
    }

    #[test]
    fn migrates_schema_two_without_losing_packet_ids_bytes_or_foreign_keys() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA_V1).unwrap();
        let schema_v2 = PACKET_ARCHIVE_SCHEMA_V3.replace(
            "('v1', 'v2', 'unsupported', 'invalid')",
            "('v1', 'unsupported', 'invalid')",
        );
        connection.execute_batch(&schema_v2).unwrap();
        connection.pragma_update(None, "user_version", 2).unwrap();
        let payload = parse_frame_hex(FIXTURE).unwrap();
        connection
            .execute(
                "INSERT INTO radio_packets (
                    id, received_at_unix_ms, packet_rssi_centi_dbm,
                    snr_centi_db, signal_rssi_centi_dbm, protocol_version,
                    frame_type, disposition, decode_error, payload
                 ) VALUES (77, 1, -4200, 1250, -4250, 1, 176, 'v1', NULL, ?1)",
                [payload.as_slice()],
            )
            .unwrap();
        let frame = decode_hex(FIXTURE).unwrap();
        insert_reading_at(&connection, &frame, &payload, radio(), 2, Some(77)).unwrap();

        let mut store = TelemetryStore::initialize(connection).unwrap();
        let preserved: (i64, String, Vec<u8>, i64) = store
            .connection
            .query_row(
                "SELECT p.id, p.disposition, p.payload, r.radio_packet_id
                 FROM radio_packets AS p
                 JOIN telemetry_readings AS r ON r.radio_packet_id = p.id
                 WHERE p.id = 77",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(preserved, (77, "v1".to_owned(), payload.to_vec(), 77));
        let foreign_key_violations: i64 = store
            .connection
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(foreign_key_violations, 0);

        let config_payload = parse_payload_hex(CONFIG_V2).unwrap();
        let vesta_protocol::v2::DecodedFrame::DeviceConfig { header, .. } =
            vesta_protocol::v2::decode(&config_payload).unwrap()
        else {
            unreachable!()
        };
        let v2_packet = store
            .archive_v2_packet(&config_payload, radio(), header, V2PacketKind::DeviceConfig)
            .unwrap();
        let v2_disposition: String = store
            .connection
            .query_row(
                "SELECT disposition FROM radio_packets WHERE id = ?1",
                [v2_packet.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(v2_disposition, "v2");
    }

    #[test]
    fn schema_two_migration_rolls_back_when_existing_foreign_keys_are_invalid() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA_V1).unwrap();
        let schema_v2 = PACKET_ARCHIVE_SCHEMA_V3.replace(
            "('v1', 'v2', 'unsupported', 'invalid')",
            "('v1', 'unsupported', 'invalid')",
        );
        connection.execute_batch(&schema_v2).unwrap();
        connection.pragma_update(None, "user_version", 2).unwrap();
        connection
            .pragma_update(None, "foreign_keys", false)
            .unwrap();
        let payload = parse_frame_hex(FIXTURE).unwrap();
        let frame = decode_hex(FIXTURE).unwrap();
        insert_reading_at(&connection, &frame, &payload, radio(), 2, Some(999)).unwrap();
        connection
            .pragma_update(None, "foreign_keys", true)
            .unwrap();

        assert!(matches!(
            migrate_schema_two(&mut connection),
            Err(StorageError::MigrationForeignKeyViolations { count: 1 })
        ));
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 2);
        let packet_schema: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type = 'table' AND name = 'radio_packets'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!packet_schema.contains("'v2'"));
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let connection = Connection::open_in_memory().unwrap();
        connection.pragma_update(None, "user_version", 99).unwrap();
        assert!(matches!(
            TelemetryStore::initialize(connection),
            Err(StorageError::UnsupportedSchemaVersion { found: 99 })
        ));
    }

    #[test]
    fn frame_type_values_match_wire_discriminants() {
        assert_eq!(FrameType::DeviceConfig as u8, 1);
        assert_eq!(FrameType::ProfileFragment as u8, 2);
        assert_eq!(FrameType::DeviceHealth as u8, 3);
    }
}
