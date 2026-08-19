//! Durable `SQLite` storage for received Vesta telemetry.

use std::fmt;
use std::path::Path;
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

use rusqlite::{Connection, params};
use vesta_protocol::{TelemetryV1, VERSION};

use crate::RadioMetadata;
use crate::records::{DeviceConfiguration, DeviceHealth, ProfileScan, RecordError};

const SCHEMA_VERSION: i64 = 2;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const SCHEMA_V1: &str = r"
CREATE TABLE IF NOT EXISTS telemetry_readings (
    id                          INTEGER PRIMARY KEY,
    received_at_unix_ms         INTEGER NOT NULL CHECK (received_at_unix_ms >= 0),
    protocol_version            INTEGER NOT NULL CHECK (protocol_version = 1),
    node_id                     TEXT NOT NULL CHECK (
                                    length(node_id) = 16
                                    AND node_id NOT GLOB '*[^0-9a-f]*'
                                ),
    sequence                    INTEGER NOT NULL CHECK (sequence BETWEEN 0 AND 4294967295),

    status_bits                 INTEGER NOT NULL CHECK (status_bits BETWEEN 0 AND 255),
    status_new_data             INTEGER NOT NULL CHECK (status_new_data IN (0, 1)),
    status_gas_valid            INTEGER NOT NULL CHECK (status_gas_valid IN (0, 1)),
    status_heater_stable        INTEGER NOT NULL CHECK (status_heater_stable IN (0, 1)),
    status_unknown_bits         INTEGER NOT NULL CHECK (status_unknown_bits BETWEEN 0 AND 255),

    temperature_centi_celsius   INTEGER NOT NULL,
    pressure_pascal             INTEGER NOT NULL CHECK (pressure_pascal >= 0),
    humidity_milli_percent_rh   INTEGER NOT NULL CHECK (humidity_milli_percent_rh >= 0),
    gas_resistance_ohm          INTEGER NOT NULL CHECK (gas_resistance_ohm >= 0),

    raw_temperature_adc         INTEGER NOT NULL CHECK (raw_temperature_adc >= 0),
    raw_pressure_adc            INTEGER NOT NULL CHECK (raw_pressure_adc >= 0),
    raw_humidity_adc            INTEGER NOT NULL CHECK (raw_humidity_adc >= 0),
    raw_gas_resistance_adc      INTEGER NOT NULL CHECK (raw_gas_resistance_adc >= 0),
    raw_gas_range               INTEGER NOT NULL CHECK (raw_gas_range BETWEEN 0 AND 255),
    raw_gas_index               INTEGER NOT NULL CHECK (raw_gas_index BETWEEN 0 AND 255),
    raw_measurement_index       INTEGER NOT NULL CHECK (raw_measurement_index BETWEEN 0 AND 255),
    raw_heater_resistance       INTEGER NOT NULL CHECK (raw_heater_resistance BETWEEN 0 AND 255),
    raw_heater_current          INTEGER NOT NULL CHECK (raw_heater_current BETWEEN 0 AND 255),
    raw_gas_wait                INTEGER NOT NULL CHECK (raw_gas_wait BETWEEN 0 AND 255),

    packet_rssi_centi_dbm       INTEGER NOT NULL,
    snr_centi_db                INTEGER NOT NULL,
    signal_rssi_centi_dbm       INTEGER NOT NULL,
    payload                     BLOB NOT NULL CHECK (length(payload) = 48)
) STRICT;

CREATE INDEX IF NOT EXISTS telemetry_readings_received_at
    ON telemetry_readings(received_at_unix_ms DESC);
CREATE INDEX IF NOT EXISTS telemetry_readings_node_received_at
    ON telemetry_readings(node_id, received_at_unix_ms DESC);
";

const SCHEMA_V2: &str = r"
CREATE TABLE radio_packets (
    id                          INTEGER PRIMARY KEY,
    received_at_unix_ms         INTEGER NOT NULL CHECK (received_at_unix_ms >= 0),
    packet_rssi_centi_dbm       INTEGER NOT NULL,
    snr_centi_db                INTEGER NOT NULL,
    signal_rssi_centi_dbm       INTEGER NOT NULL,
    protocol_version            INTEGER CHECK (protocol_version BETWEEN 0 AND 255),
    frame_type                  INTEGER CHECK (frame_type BETWEEN 0 AND 255),
    disposition                 TEXT NOT NULL CHECK (
                                    disposition IN ('v1', 'unsupported', 'invalid')
                                ),
    decode_error                TEXT,
    payload                     BLOB NOT NULL CHECK (
                                    length(payload) BETWEEN 0 AND 255
                                )
) STRICT;

CREATE INDEX radio_packets_received_at
    ON radio_packets(received_at_unix_ms DESC);
CREATE INDEX radio_packets_version_received_at
    ON radio_packets(protocol_version, received_at_unix_ms DESC);

ALTER TABLE telemetry_readings
    ADD COLUMN radio_packet_id INTEGER REFERENCES radio_packets(id);
CREATE UNIQUE INDEX telemetry_readings_radio_packet
    ON telemetry_readings(radio_packet_id)
    WHERE radio_packet_id IS NOT NULL;

CREATE TABLE device_configurations (
    id                          INTEGER PRIMARY KEY,
    received_at_unix_ms         INTEGER NOT NULL CHECK (received_at_unix_ms >= 0),
    node_id                     TEXT NOT NULL CHECK (
                                    length(node_id) = 16
                                    AND node_id NOT GLOB '*[^0-9a-f]*'
                                ),
    boot_id                     INTEGER NOT NULL CHECK (boot_id BETWEEN 0 AND 4294967295),
    sequence                    INTEGER NOT NULL CHECK (sequence BETWEEN 0 AND 4294967295),
    uptime_ms                   INTEGER NOT NULL CHECK (uptime_ms >= 0),
    firmware_version            TEXT NOT NULL,
    reset_cause_bits            INTEGER NOT NULL CHECK (reset_cause_bits BETWEEN 0 AND 4294967295),
    sensor_variant              INTEGER NOT NULL CHECK (sensor_variant BETWEEN 0 AND 255),
    calibration_hash            TEXT CHECK (
                                    calibration_hash IS NULL
                                    OR (
                                        length(calibration_hash) = 16
                                        AND calibration_hash NOT GLOB '*[^0-9a-f]*'
                                    )
                                ),
    humidity_oversampling       INTEGER NOT NULL CHECK (humidity_oversampling BETWEEN 0 AND 255),
    temperature_oversampling    INTEGER NOT NULL CHECK (temperature_oversampling BETWEEN 0 AND 255),
    pressure_oversampling       INTEGER NOT NULL CHECK (pressure_oversampling BETWEEN 0 AND 255),
    iir_filter                  INTEGER NOT NULL CHECK (iir_filter BETWEEN 0 AND 255),
    operation_mode              INTEGER NOT NULL CHECK (operation_mode BETWEEN 0 AND 255),
    profile_id                  INTEGER NOT NULL CHECK (profile_id BETWEEN 0 AND 65535),
    profile_revision            INTEGER NOT NULL CHECK (profile_revision BETWEEN 0 AND 65535),
    scan_interval_ms            INTEGER NOT NULL CHECK (scan_interval_ms >= 0),
    tx_power_centi_dbm          INTEGER NOT NULL,
    radio_frequency_hz          INTEGER NOT NULL CHECK (radio_frequency_hz >= 0),
    radio_spreading_factor      INTEGER NOT NULL CHECK (radio_spreading_factor BETWEEN 0 AND 255),
    radio_bandwidth_hz          INTEGER NOT NULL CHECK (radio_bandwidth_hz >= 0),
    radio_coding_rate           INTEGER NOT NULL CHECK (radio_coding_rate BETWEEN 0 AND 255),
    source_packet_id            INTEGER REFERENCES radio_packets(id)
) STRICT;

CREATE INDEX device_configurations_node_received_at
    ON device_configurations(node_id, received_at_unix_ms DESC);

CREATE TABLE heater_profile_steps (
    configuration_id            INTEGER NOT NULL REFERENCES device_configurations(id) ON DELETE CASCADE,
    step_index                  INTEGER NOT NULL CHECK (step_index BETWEEN 0 AND 9),
    target_temperature_celsius  INTEGER NOT NULL CHECK (target_temperature_celsius BETWEEN 0 AND 65535),
    duration_ms                 INTEGER NOT NULL CHECK (duration_ms BETWEEN 0 AND 65535),
    PRIMARY KEY (configuration_id, step_index)
) STRICT;

CREATE TABLE profile_scans (
    id                          INTEGER PRIMARY KEY,
    received_at_unix_ms         INTEGER NOT NULL CHECK (received_at_unix_ms >= 0),
    node_id                     TEXT NOT NULL CHECK (
                                    length(node_id) = 16
                                    AND node_id NOT GLOB '*[^0-9a-f]*'
                                ),
    boot_id                     INTEGER NOT NULL CHECK (boot_id BETWEEN 0 AND 4294967295),
    sequence                    INTEGER NOT NULL CHECK (sequence BETWEEN 0 AND 4294967295),
    uptime_ms                   INTEGER NOT NULL CHECK (uptime_ms >= 0),
    profile_id                  INTEGER NOT NULL CHECK (profile_id BETWEEN 0 AND 65535),
    profile_revision            INTEGER NOT NULL CHECK (profile_revision BETWEEN 0 AND 65535),
    expected_steps              INTEGER NOT NULL CHECK (expected_steps BETWEEN 1 AND 10),
    observed_steps              INTEGER NOT NULL CHECK (observed_steps BETWEEN 0 AND 10),
    reported_missing_steps      INTEGER NOT NULL CHECK (reported_missing_steps BETWEEN 0 AND 1023),
    computed_missing_steps      INTEGER NOT NULL CHECK (computed_missing_steps BETWEEN 0 AND 1023),
    duration_ms                 INTEGER NOT NULL CHECK (duration_ms >= 0),
    collection_flags            INTEGER NOT NULL CHECK (collection_flags BETWEEN 0 AND 65535),
    packet_rssi_centi_dbm       INTEGER NOT NULL,
    snr_centi_db                INTEGER NOT NULL,
    signal_rssi_centi_dbm       INTEGER NOT NULL
) STRICT;

CREATE INDEX profile_scans_node_received_at
    ON profile_scans(node_id, received_at_unix_ms DESC);
CREATE INDEX profile_scans_identity
    ON profile_scans(node_id, boot_id, sequence);

CREATE TABLE profile_steps (
    scan_id                     INTEGER NOT NULL REFERENCES profile_scans(id) ON DELETE CASCADE,
    step_index                  INTEGER NOT NULL CHECK (step_index BETWEEN 0 AND 9),
    gas_index                   INTEGER NOT NULL CHECK (gas_index BETWEEN 0 AND 255),
    measurement_index           INTEGER NOT NULL CHECK (measurement_index BETWEEN 0 AND 255),
    target_temperature_celsius  INTEGER NOT NULL CHECK (target_temperature_celsius BETWEEN 0 AND 65535),
    heater_duration_ms          INTEGER NOT NULL CHECK (heater_duration_ms BETWEEN 0 AND 65535),
    relative_offset_ms          INTEGER NOT NULL CHECK (relative_offset_ms >= 0),
    status_bits                 INTEGER NOT NULL CHECK (status_bits BETWEEN 0 AND 255),
    temperature_centi_celsius   INTEGER NOT NULL,
    pressure_pascal             INTEGER NOT NULL CHECK (pressure_pascal >= 0),
    humidity_milli_percent_rh   INTEGER NOT NULL CHECK (humidity_milli_percent_rh >= 0),
    gas_resistance_ohm          INTEGER NOT NULL CHECK (gas_resistance_ohm >= 0),
    raw_temperature_adc         INTEGER NOT NULL CHECK (raw_temperature_adc >= 0),
    raw_pressure_adc            INTEGER NOT NULL CHECK (raw_pressure_adc >= 0),
    raw_humidity_adc            INTEGER NOT NULL CHECK (raw_humidity_adc >= 0),
    raw_gas_resistance_adc      INTEGER NOT NULL CHECK (raw_gas_resistance_adc >= 0),
    raw_gas_range               INTEGER NOT NULL CHECK (raw_gas_range BETWEEN 0 AND 255),
    raw_heater_resistance       INTEGER NOT NULL CHECK (raw_heater_resistance BETWEEN 0 AND 255),
    raw_heater_current          INTEGER NOT NULL CHECK (raw_heater_current BETWEEN 0 AND 255),
    raw_gas_wait                INTEGER NOT NULL CHECK (raw_gas_wait BETWEEN 0 AND 255),
    PRIMARY KEY (scan_id, step_index)
) STRICT;

CREATE TABLE profile_scan_packets (
    scan_id                     INTEGER NOT NULL REFERENCES profile_scans(id) ON DELETE CASCADE,
    packet_id                   INTEGER NOT NULL REFERENCES radio_packets(id),
    fragment_index              INTEGER NOT NULL CHECK (fragment_index BETWEEN 0 AND 255),
    PRIMARY KEY (scan_id, packet_id),
    UNIQUE (scan_id, fragment_index)
) STRICT;

CREATE TABLE device_health (
    id                          INTEGER PRIMARY KEY,
    received_at_unix_ms         INTEGER NOT NULL CHECK (received_at_unix_ms >= 0),
    node_id                     TEXT NOT NULL CHECK (
                                    length(node_id) = 16
                                    AND node_id NOT GLOB '*[^0-9a-f]*'
                                ),
    boot_id                     INTEGER NOT NULL CHECK (boot_id BETWEEN 0 AND 4294967295),
    sequence                    INTEGER NOT NULL CHECK (sequence BETWEEN 0 AND 4294967295),
    uptime_ms                   INTEGER NOT NULL CHECK (uptime_ms >= 0),
    reset_cause_bits            INTEGER NOT NULL CHECK (reset_cause_bits BETWEEN 0 AND 4294967295),
    successful_scans            INTEGER NOT NULL CHECK (successful_scans BETWEEN 0 AND 4294967295),
    failed_scans                INTEGER NOT NULL CHECK (failed_scans BETWEEN 0 AND 4294967295),
    incomplete_profiles         INTEGER NOT NULL CHECK (incomplete_profiles BETWEEN 0 AND 4294967295),
    i2c_errors                  INTEGER NOT NULL CHECK (i2c_errors BETWEEN 0 AND 4294967295),
    radio_errors                INTEGER NOT NULL CHECK (radio_errors BETWEEN 0 AND 4294967295),
    dropped_records             INTEGER NOT NULL CHECK (dropped_records BETWEEN 0 AND 4294967295),
    mcu_temperature_centi_celsius INTEGER,
    vdd_millivolt               INTEGER CHECK (vdd_millivolt BETWEEN 0 AND 65535),
    source_packet_id            INTEGER REFERENCES radio_packets(id)
) STRICT;

CREATE INDEX device_health_node_received_at
    ON device_health(node_id, received_at_unix_ms DESC);
";

/// `SQLite` store for every valid received observation.
pub struct TelemetryStore {
    connection: Connection,
}

/// Identity assigned to one durable database row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredReading {
    /// `SQLite` row identifier.
    pub id: i64,
    /// UTC receive time as milliseconds since the Unix epoch.
    pub received_at_unix_ms: i64,
    /// Archived raw radio packet, when insertion came from the live receiver.
    pub radio_packet_id: Option<i64>,
}

/// Identity assigned to one archived PHY-valid radio packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredPacket {
    /// `SQLite` row identifier.
    pub id: i64,
    /// UTC receive time as milliseconds since the Unix epoch.
    pub received_at_unix_ms: i64,
}

/// Identity assigned to one protocol-independent logical record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredRecord {
    /// `SQLite` row identifier.
    pub id: i64,
    /// UTC receive time as milliseconds since the Unix epoch.
    pub received_at_unix_ms: i64,
}

/// Receiver interpretation of one archived application payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketDisposition {
    /// Successfully decoded protocol-v1 telemetry.
    LegacyV1,
    /// PHY-valid payload awaiting or unsupported by an application decoder.
    Unsupported,
    /// Payload recognized as Vesta data but rejected by its decoder.
    Invalid,
}

impl PacketDisposition {
    const fn database_value(self) -> &'static str {
        match self {
            Self::LegacyV1 => "v1",
            Self::Unsupported => "unsupported",
            Self::Invalid => "invalid",
        }
    }
}

impl TelemetryStore {
    /// Open or create a telemetry database and apply the current schema.
    ///
    /// Parent directories are created when needed. Existing databases with a
    /// newer or otherwise unsupported schema version are rejected rather than
    /// modified.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory or database cannot be opened, `SQLite`
    /// initialization fails, or the schema version is unsupported.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }

        let connection = Connection::open(path)?;
        Self::initialize(connection)
    }

    /// Insert one valid Vesta frame and its exact raw payload atomically.
    ///
    /// A repeated node/sequence pair is retained as another observation. The
    /// sequence is a wrapping device counter and therefore is not a durable
    /// database identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the system clock predates the Unix epoch, the
    /// timestamp cannot fit `SQLite`'s signed integer, or the insert fails.
    pub fn insert(
        &self,
        frame: &TelemetryV1,
        payload: &[u8],
        radio: RadioMetadata,
    ) -> Result<StoredReading, StorageError> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let received_at_unix_ms =
            i64::try_from(elapsed.as_millis()).map_err(|_| StorageError::TimestampOutOfRange)?;
        self.insert_at(frame, payload, radio, received_at_unix_ms)
    }

    fn initialize(mut connection: Connection) -> Result<Self, StorageError> {
        connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;",
        )?;

        let version = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        match version {
            0 => {
                let transaction = connection.transaction()?;
                transaction.execute_batch(SCHEMA_V1)?;
                transaction.execute_batch(SCHEMA_V2)?;
                transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                transaction.commit()?;
            }
            1 => {
                let transaction = connection.transaction()?;
                transaction.execute_batch(SCHEMA_V2)?;
                transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                transaction.commit()?;
            }
            SCHEMA_VERSION => {}
            found => return Err(StorageError::UnsupportedSchemaVersion { found }),
        }

        Ok(Self { connection })
    }

    fn insert_at(
        &self,
        frame: &TelemetryV1,
        payload: &[u8],
        radio: RadioMetadata,
        received_at_unix_ms: i64,
    ) -> Result<StoredReading, StorageError> {
        insert_reading_at(
            &self.connection,
            frame,
            payload,
            radio,
            received_at_unix_ms,
            None,
        )
    }

    /// Atomically archive one PHY-valid packet and its decoded v1 reading.
    ///
    /// # Errors
    ///
    /// Returns an error if timestamp generation, packet archival, telemetry
    /// insertion, or transaction commit fails.
    pub fn insert_received_v1(
        &mut self,
        frame: &TelemetryV1,
        payload: &[u8],
        radio: RadioMetadata,
    ) -> Result<StoredReading, StorageError> {
        let received_at_unix_ms = current_unix_ms()?;
        let transaction = self.connection.transaction()?;
        let packet = insert_packet_at(
            &transaction,
            payload,
            radio,
            received_at_unix_ms,
            PacketDisposition::LegacyV1,
            None,
        )?;
        let reading = insert_reading_at(
            &transaction,
            frame,
            payload,
            radio,
            received_at_unix_ms,
            Some(packet.id),
        )?;
        transaction.commit()?;
        Ok(reading)
    }

    /// Archive a PHY-valid packet that could not be decoded yet.
    ///
    /// This is the compatibility boundary for future protocol versions: raw
    /// packets remain recoverable even before their exact decoder is merged.
    ///
    /// # Errors
    ///
    /// Returns an error if the timestamp or `SQLite` insert fails.
    pub fn archive_packet(
        &self,
        payload: &[u8],
        radio: RadioMetadata,
        disposition: PacketDisposition,
        decode_error: Option<&str>,
    ) -> Result<StoredPacket, StorageError> {
        insert_packet_at(
            &self.connection,
            payload,
            radio,
            current_unix_ms()?,
            disposition,
            decode_error,
        )
    }

    /// Store one decoded device-configuration record and its heater steps.
    ///
    /// # Errors
    ///
    /// Returns an error for structurally invalid configuration or a failed
    /// transactional insert.
    pub fn insert_device_configuration(
        &mut self,
        configuration: &DeviceConfiguration,
        source_packet_id: Option<i64>,
    ) -> Result<StoredRecord, StorageError> {
        configuration.validate()?;
        let received_at_unix_ms = current_unix_ms()?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO device_configurations (
                received_at_unix_ms, node_id, boot_id, sequence, uptime_ms,
                firmware_version, reset_cause_bits, sensor_variant,
                calibration_hash, humidity_oversampling,
                temperature_oversampling, pressure_oversampling, iir_filter,
                operation_mode, profile_id, profile_revision,
                scan_interval_ms, tx_power_centi_dbm, radio_frequency_hz,
                radio_spreading_factor, radio_bandwidth_hz,
                radio_coding_rate, source_packet_id
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23
             )",
            params![
                received_at_unix_ms,
                node_id_text(configuration.identity.node_id),
                configuration.identity.boot_id,
                configuration.identity.sequence,
                sqlite_u64(configuration.identity.uptime_ms, "uptime_ms")?,
                configuration.firmware_version.as_str(),
                configuration.reset_cause_bits,
                configuration.sensor_variant,
                configuration
                    .calibration_hash
                    .map(|hash| format!("{hash:016x}")),
                configuration.humidity_oversampling,
                configuration.temperature_oversampling,
                configuration.pressure_oversampling,
                configuration.iir_filter,
                configuration.operation_mode,
                configuration.profile_id,
                configuration.profile_revision,
                configuration.scan_interval_ms,
                configuration.tx_power_centi_dbm,
                configuration.radio_frequency_hz,
                configuration.radio_spreading_factor,
                configuration.radio_bandwidth_hz,
                configuration.radio_coding_rate,
                source_packet_id,
            ],
        )?;
        let id = transaction.last_insert_rowid();
        for step in &configuration.heater_steps {
            transaction.execute(
                "INSERT INTO heater_profile_steps (
                    configuration_id, step_index,
                    target_temperature_celsius, duration_ms
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    id,
                    step.step_index,
                    step.target_temperature_celsius,
                    step.duration_ms,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(StoredRecord {
            id,
            received_at_unix_ms,
        })
    }

    /// Store one decoded heater-profile scan and all recovered steps.
    ///
    /// Fragment packet IDs are optional until the v2 reassembler exists, but
    /// when provided their indices are persisted for byte-level audit.
    ///
    /// # Errors
    ///
    /// Returns an error for inconsistent profile structure, integer overflow,
    /// missing packet references, or a failed transactional insert.
    pub fn insert_profile_scan(
        &mut self,
        scan: &ProfileScan,
        radio: RadioMetadata,
        source_fragments: &[(i64, u8)],
    ) -> Result<StoredRecord, StorageError> {
        scan.validate()?;
        let observed_steps =
            i64::try_from(scan.steps.len()).map_err(|_| StorageError::IntegerOutOfRange {
                field: "observed_steps",
            })?;
        let received_at_unix_ms = current_unix_ms()?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO profile_scans (
                received_at_unix_ms, node_id, boot_id, sequence, uptime_ms,
                profile_id, profile_revision, expected_steps, observed_steps,
                reported_missing_steps, computed_missing_steps, duration_ms,
                collection_flags, packet_rssi_centi_dbm, snr_centi_db,
                signal_rssi_centi_dbm
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16
             )",
            params![
                received_at_unix_ms,
                node_id_text(scan.identity.node_id),
                scan.identity.boot_id,
                scan.identity.sequence,
                sqlite_u64(scan.identity.uptime_ms, "uptime_ms")?,
                scan.profile_id,
                scan.profile_revision,
                scan.expected_steps,
                observed_steps,
                scan.reported_missing_steps,
                scan.computed_missing_steps(),
                scan.duration_ms,
                scan.collection_flags,
                radio.packet_rssi_centi_dbm,
                radio.snr_centi_db,
                radio.signal_rssi_centi_dbm,
            ],
        )?;
        let id = transaction.last_insert_rowid();
        for step in &scan.steps {
            transaction.execute(
                "INSERT INTO profile_steps (
                    scan_id, step_index, gas_index, measurement_index,
                    target_temperature_celsius, heater_duration_ms,
                    relative_offset_ms, status_bits,
                    temperature_centi_celsius, pressure_pascal,
                    humidity_milli_percent_rh, gas_resistance_ohm,
                    raw_temperature_adc, raw_pressure_adc, raw_humidity_adc,
                    raw_gas_resistance_adc, raw_gas_range,
                    raw_heater_resistance, raw_heater_current, raw_gas_wait
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                    ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
                 )",
                params![
                    id,
                    step.step_index,
                    step.gas_index,
                    step.measurement_index,
                    step.target_temperature_celsius,
                    step.heater_duration_ms,
                    step.relative_offset_ms,
                    step.status_bits,
                    step.temperature_centi_celsius,
                    step.pressure_pascal,
                    step.humidity_milli_percent_rh,
                    step.gas_resistance_ohm,
                    step.raw_temperature_adc,
                    step.raw_pressure_adc,
                    step.raw_humidity_adc,
                    step.raw_gas_resistance_adc,
                    step.raw_gas_range,
                    step.raw_heater_resistance,
                    step.raw_heater_current,
                    step.raw_gas_wait,
                ],
            )?;
        }
        for &(packet_id, fragment_index) in source_fragments {
            transaction.execute(
                "INSERT INTO profile_scan_packets (
                    scan_id, packet_id, fragment_index
                 ) VALUES (?1, ?2, ?3)",
                params![id, packet_id, fragment_index],
            )?;
        }
        transaction.commit()?;
        Ok(StoredRecord {
            id,
            received_at_unix_ms,
        })
    }

    /// Store one decoded device-health report.
    ///
    /// # Errors
    ///
    /// Returns an error if integer conversion or the database insert fails.
    pub fn insert_device_health(
        &self,
        health: &DeviceHealth,
        source_packet_id: Option<i64>,
    ) -> Result<StoredRecord, StorageError> {
        let received_at_unix_ms = current_unix_ms()?;
        self.connection.execute(
            "INSERT INTO device_health (
                received_at_unix_ms, node_id, boot_id, sequence, uptime_ms,
                reset_cause_bits, successful_scans, failed_scans,
                incomplete_profiles, i2c_errors, radio_errors,
                dropped_records, mcu_temperature_centi_celsius,
                vdd_millivolt, source_packet_id
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                ?12, ?13, ?14, ?15
             )",
            params![
                received_at_unix_ms,
                node_id_text(health.identity.node_id),
                health.identity.boot_id,
                health.identity.sequence,
                sqlite_u64(health.identity.uptime_ms, "uptime_ms")?,
                health.reset_cause_bits,
                health.successful_scans,
                health.failed_scans,
                health.incomplete_profiles,
                health.i2c_errors,
                health.radio_errors,
                health.dropped_records,
                health.mcu_temperature_centi_celsius,
                health.vdd_millivolt,
                source_packet_id,
            ],
        )?;
        Ok(StoredRecord {
            id: self.connection.last_insert_rowid(),
            received_at_unix_ms,
        })
    }

    #[cfg(test)]
    fn open_in_memory() -> Result<Self, StorageError> {
        Self::initialize(Connection::open_in_memory()?)
    }
}

fn current_unix_ms() -> Result<i64, StorageError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    i64::try_from(elapsed.as_millis()).map_err(|_| StorageError::TimestampOutOfRange)
}

fn sqlite_u64(value: u64, field: &'static str) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::IntegerOutOfRange { field })
}

fn node_id_text(node_id: u64) -> String {
    format!("{node_id:016x}")
}

fn insert_packet_at(
    connection: &Connection,
    payload: &[u8],
    radio: RadioMetadata,
    received_at_unix_ms: i64,
    disposition: PacketDisposition,
    decode_error: Option<&str>,
) -> Result<StoredPacket, StorageError> {
    let protocol_version = payload
        .starts_with(b"VS")
        .then(|| payload.get(2).copied())
        .flatten();
    connection.execute(
        "INSERT INTO radio_packets (
            received_at_unix_ms, packet_rssi_centi_dbm, snr_centi_db,
            signal_rssi_centi_dbm, protocol_version, frame_type,
            disposition, decode_error, payload
         ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8)",
        params![
            received_at_unix_ms,
            radio.packet_rssi_centi_dbm,
            radio.snr_centi_db,
            radio.signal_rssi_centi_dbm,
            protocol_version,
            disposition.database_value(),
            decode_error,
            payload,
        ],
    )?;
    Ok(StoredPacket {
        id: connection.last_insert_rowid(),
        received_at_unix_ms,
    })
}

fn insert_reading_at(
    connection: &Connection,
    frame: &TelemetryV1,
    payload: &[u8],
    radio: RadioMetadata,
    received_at_unix_ms: i64,
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
            raw_heater_current, raw_gas_wait,
            packet_rssi_centi_dbm, snr_centi_db,
            signal_rssi_centi_dbm, payload, radio_packet_id
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
            ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
            ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28
        )",
        params![
            received_at_unix_ms,
            VERSION,
            node_id_text(frame.node_id),
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
        received_at_unix_ms,
        radio_packet_id,
    })
}

/// Failure while creating or writing the telemetry database.
#[derive(Debug)]
pub enum StorageError {
    /// Filesystem setup failed.
    Io(std::io::Error),
    /// `SQLite` operation failed.
    Sqlite(rusqlite::Error),
    /// The host clock is earlier than the Unix epoch.
    SystemTime(SystemTimeError),
    /// The millisecond timestamp cannot fit a `SQLite` integer.
    TimestampOutOfRange,
    /// An unsigned device value cannot fit a `SQLite` signed integer.
    IntegerOutOfRange {
        /// Logical field that overflowed.
        field: &'static str,
    },
    /// A decoded logical record is structurally inconsistent.
    InvalidRecord(RecordError),
    /// The database schema is not understood by this executable.
    UnsupportedSchemaVersion {
        /// Version read from `SQLite`'s `user_version` pragma.
        found: i64,
    },
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "database directory error: {error}"),
            Self::Sqlite(error) => write!(formatter, "SQLite error: {error}"),
            Self::SystemTime(error) => write!(formatter, "system clock error: {error}"),
            Self::TimestampOutOfRange => {
                formatter.write_str("receive timestamp does not fit a SQLite integer")
            }
            Self::IntegerOutOfRange { field } => {
                write!(formatter, "{field} does not fit a SQLite integer")
            }
            Self::InvalidRecord(error) => write!(formatter, "invalid decoded record: {error}"),
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
            Self::SystemTime(error) => Some(error),
            Self::InvalidRecord(error) => Some(error),
            Self::TimestampOutOfRange
            | Self::IntegerOutOfRange { .. }
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
    use crate::records::{
        DeviceConfiguration, DeviceHealth, HeaterStepConfiguration, ProfileScan, ProfileStep,
        RecordIdentity,
    };
    use crate::{decode_hex, parse_frame_hex};

    const FIXTURE: &str = "565301b001020304050607080a0b0c0dfb2e00018bcd0000b26e000f12060007eed00005902075300200080203040506";

    const fn radio() -> RadioMetadata {
        RadioMetadata {
            packet_rssi_centi_dbm: -4_200,
            snr_centi_db: 1_250,
            signal_rssi_centi_dbm: -4_250,
        }
    }

    const fn identity(sequence: u32) -> RecordIdentity {
        RecordIdentity {
            node_id: 0x0102_0304_0506_0708,
            boot_id: 0x1122_3344,
            sequence,
            uptime_ms: 60_000,
        }
    }

    const fn profile_step(index: u8) -> ProfileStep {
        ProfileStep {
            step_index: index,
            gas_index: index,
            measurement_index: index,
            target_temperature_celsius: 200 + index as u16 * 50,
            heater_duration_ms: 100,
            relative_offset_ms: index as u32 * 100,
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

    #[test]
    fn stores_exact_structured_values_and_payload() {
        let store = TelemetryStore::open_in_memory().unwrap();
        let frame = decode_hex(FIXTURE).unwrap();
        let payload = parse_frame_hex(FIXTURE).unwrap();
        let radio = RadioMetadata {
            packet_rssi_centi_dbm: -4_200,
            snr_centi_db: 1_250,
            signal_rssi_centi_dbm: -4_250,
        };

        let stored = store
            .insert_at(&frame, &payload, radio, 1_776_550_000_123)
            .unwrap();
        assert_eq!(stored.id, 1);
        assert_eq!(stored.received_at_unix_ms, 1_776_550_000_123);

        let identity: (i64, String, i64, i64, Vec<u8>) = store
            .connection
            .query_row(
                "SELECT received_at_unix_ms, node_id, sequence,
                        protocol_version, payload
                 FROM telemetry_readings WHERE id = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(identity.0, 1_776_550_000_123);
        assert_eq!(identity.1, "0102030405060708");
        assert_eq!(identity.2, i64::from(0x0a0b_0c0d_u32));
        assert_eq!(identity.3, i64::from(VERSION));
        assert_eq!(identity.4, payload);

        let measurements: (i64, i64, i64, i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT temperature_centi_celsius, pressure_pascal,
                        humidity_milli_percent_rh, gas_resistance_ohm,
                        packet_rssi_centi_dbm, snr_centi_db
                 FROM telemetry_readings WHERE id = 1",
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
            measurements,
            (-1_234, 101_325, 45_678, 987_654, -4_200, 1_250)
        );
    }

    #[test]
    fn retains_repeated_node_sequence_as_distinct_observations() {
        let store = TelemetryStore::open_in_memory().unwrap();
        let frame = decode_hex(FIXTURE).unwrap();
        let payload = parse_frame_hex(FIXTURE).unwrap();
        let radio = RadioMetadata {
            packet_rssi_centi_dbm: -4_200,
            snr_centi_db: 1_250,
            signal_rssi_centi_dbm: -4_200,
        };

        store.insert_at(&frame, &payload, radio, 100).unwrap();
        store.insert_at(&frame, &payload, radio, 200).unwrap();

        let count: i64 = store
            .connection
            .query_row("SELECT count(*) FROM telemetry_readings", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn live_v1_insert_archives_and_links_the_exact_packet() {
        let mut store = TelemetryStore::open_in_memory().unwrap();
        let frame = decode_hex(FIXTURE).unwrap();
        let payload = parse_frame_hex(FIXTURE).unwrap();

        let stored = store.insert_received_v1(&frame, &payload, radio()).unwrap();
        let packet_id = stored.radio_packet_id.unwrap();
        let archived: (i64, String, i64, Vec<u8>) = store
            .connection
            .query_row(
                "SELECT protocol_version, disposition,
                        packet_rssi_centi_dbm, payload
                 FROM radio_packets WHERE id = ?1",
                [packet_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(archived, (1, "v1".to_owned(), -4_200, payload.to_vec()));

        let linked_packet: i64 = store
            .connection
            .query_row(
                "SELECT radio_packet_id FROM telemetry_readings WHERE id = ?1",
                [stored.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(linked_packet, packet_id);
    }

    #[test]
    fn unsupported_packets_remain_byte_exact_for_future_decoders() {
        let store = TelemetryStore::open_in_memory().unwrap();
        let payload = b"VS\x02future-wire-record";
        let stored = store
            .archive_packet(payload, radio(), PacketDisposition::Unsupported, None)
            .unwrap();

        let archived: (i64, String, Option<String>, Vec<u8>) = store
            .connection
            .query_row(
                "SELECT protocol_version, disposition, decode_error, payload
                 FROM radio_packets WHERE id = ?1",
                [stored.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            archived,
            (2, "unsupported".to_owned(), None, payload.to_vec())
        );
    }

    #[test]
    fn stores_configuration_profile_and_health_as_structured_records() {
        let mut store = TelemetryStore::open_in_memory().unwrap();
        let configuration = DeviceConfiguration {
            identity: identity(10),
            firmware_version: "vesta-test-abc123".to_owned(),
            reset_cause_bits: 4,
            sensor_variant: 1,
            calibration_hash: Some(0x0123_4567_89ab_cdef),
            humidity_oversampling: 2,
            temperature_oversampling: 4,
            pressure_oversampling: 4,
            iir_filter: 3,
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
                    target_temperature_celsius: 250,
                    duration_ms: 100,
                },
            ],
        };
        let configuration_row = store
            .insert_device_configuration(&configuration, None)
            .unwrap();

        let scan = ProfileScan {
            identity: identity(11),
            profile_id: 7,
            profile_revision: 1,
            expected_steps: 2,
            reported_missing_steps: 0,
            duration_ms: 250,
            collection_flags: 0,
            steps: vec![profile_step(0), profile_step(1)],
        };
        let scan_row = store.insert_profile_scan(&scan, radio(), &[]).unwrap();

        let health = DeviceHealth {
            identity: identity(12),
            reset_cause_bits: 4,
            successful_scans: 100,
            failed_scans: 2,
            incomplete_profiles: 1,
            i2c_errors: 1,
            radio_errors: 3,
            dropped_records: 4,
            mcu_temperature_centi_celsius: Some(4_200),
            vdd_millivolt: Some(3_290),
        };
        let health_row = store.insert_device_health(&health, None).unwrap();

        let counts: (i64, i64, i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT
                    (SELECT count(*) FROM device_configurations),
                    (SELECT count(*) FROM heater_profile_steps),
                    (SELECT count(*) FROM profile_scans),
                    (SELECT count(*) FROM profile_steps),
                    (SELECT count(*) FROM device_health)",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(counts, (1, 2, 1, 2, 1));
        assert_eq!(
            (configuration_row.id, scan_row.id, health_row.id),
            (1, 1, 1)
        );
    }

    #[test]
    fn invalid_profile_is_rejected_without_partial_rows() {
        let mut store = TelemetryStore::open_in_memory().unwrap();
        let scan = ProfileScan {
            identity: identity(20),
            profile_id: 7,
            profile_revision: 1,
            expected_steps: 2,
            reported_missing_steps: 0,
            duration_ms: 250,
            collection_flags: 0,
            steps: vec![profile_step(0)],
        };
        assert!(matches!(
            store.insert_profile_scan(&scan, radio(), &[]),
            Err(StorageError::InvalidRecord(
                RecordError::MissingBitmapMismatch { .. }
            ))
        ));
        let count: i64 = store
            .connection
            .query_row("SELECT count(*) FROM profile_scans", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn migrates_schema_one_without_losing_existing_readings() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA_V1).unwrap();
        let payload = parse_frame_hex(FIXTURE).unwrap();
        connection
            .execute(
                "INSERT INTO telemetry_readings (
                    received_at_unix_ms, protocol_version, node_id, sequence,
                    status_bits, status_new_data, status_gas_valid,
                    status_heater_stable, status_unknown_bits,
                    temperature_centi_celsius, pressure_pascal,
                    humidity_milli_percent_rh, gas_resistance_ohm,
                    raw_temperature_adc, raw_pressure_adc, raw_humidity_adc,
                    raw_gas_resistance_adc, raw_gas_range, raw_gas_index,
                    raw_measurement_index, raw_heater_resistance,
                    raw_heater_current, raw_gas_wait,
                    packet_rssi_centi_dbm, snr_centi_db,
                    signal_rssi_centi_dbm, payload
                 ) VALUES (
                    1, 1, '0102030405060708', 2,
                    176, 1, 1, 1, 0,
                    2500, 101325, 40000, 20000,
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                    -4200, 1250, -4250, ?1
                 )",
                [payload],
            )
            .unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();

        let store = TelemetryStore::initialize(connection).unwrap();
        let migrated: (i64, Option<i64>) = store
            .connection
            .query_row(
                "SELECT count(*), max(radio_packet_id) FROM telemetry_readings",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(migrated, (1, None));
        assert_eq!(version, SCHEMA_VERSION);
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
}
