#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::fmt;
use std::io::{self, BufRead, Write};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, ValueEnum};
use vesta_protocol::{DecodedTelemetry, ProtocolDecodeError};
use vesta_receiver::database::{
    FragmentStorageStatus, PacketDisposition, PersistedFragmentMatch, PersistedIncompleteProfile,
    StorageError, TelemetryStore,
};
#[cfg(target_os = "linux")]
use vesta_receiver::reassembly::{
    FragmentEvent, IngestResult, ProfileReassembler, ReassemblyError, SourceFragment,
    device_configuration, device_health,
};
use vesta_receiver::{HexError, OutputFormat, V2RenderError, parse_payload_hex, render, render_v2};
#[cfg(target_os = "linux")]
use vesta_receiver::{render_reassembled_profile, render_received, sx1262};

#[cfg(target_os = "linux")]
const PROFILE_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(120);
#[cfg(target_os = "linux")]
const MAX_STARTUP_PENDING_FRAGMENTS: usize = 1_024;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Receive and decode Vesta environmental telemetry",
    long_about = "Receive Vesta environmental telemetry with the Raspberry Pi Waveshare SX1262 HAT, or decode captured hexadecimal payloads."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Decode one frame, or a line-delimited stream from standard input.
    Decode {
        /// One complete v1 or v2 frame encoded as hexadecimal characters.
        #[arg(value_name = "HEX", conflicts_with = "stdin")]
        frame: Option<String>,

        /// Read one hexadecimal frame per nonempty line from standard input.
        #[arg(long, required_unless_present = "frame")]
        stdin: bool,

        /// Select human-readable or machine-readable output.
        #[arg(long, value_enum, default_value_t = CliOutput::Human)]
        output: CliOutput,
    },
    /// Listen continuously with the Raspberry Pi Waveshare SX1262 HAT.
    Listen {
        /// Stop after this many seconds (1 through 86400).
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=86_400))]
        duration: Option<u64>,

        /// Stop after emitting this many valid Vesta frames.
        #[arg(long)]
        count: Option<NonZeroU64>,

        /// Select human-readable or machine-readable output.
        #[arg(long, value_enum, default_value_t = CliOutput::Human)]
        output: CliOutput,

        /// `SQLite` database that receives every PHY-valid radio packet.
        #[arg(long, default_value = "data/vesta-telemetry.sqlite3")]
        database: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum CliOutput {
    #[default]
    Human,
    Jsonl,
}

impl From<CliOutput> for OutputFormat {
    fn from(value: CliOutput) -> Self {
        match value {
            CliOutput::Human => Self::Human,
            CliOutput::Jsonl => Self::JsonLines,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut output = io::BufWriter::new(stdout.lock());
    let mut diagnostics = stderr.lock();

    let run_result = run(cli, stdin.lock(), &mut output, &mut diagnostics);
    let flush_result = output.flush();
    let mut succeeded = true;

    if let Err(error) = run_result {
        let _ = writeln!(diagnostics, "error: {error}");
        succeeded = false;
    }
    if let Err(error) = flush_result {
        let _ = writeln!(diagnostics, "error: could not flush output: {error}");
        succeeded = false;
    }

    if succeeded {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run(
    cli: Cli,
    input: impl BufRead,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<(), AppError> {
    match cli.command {
        Command::Decode {
            frame,
            stdin,
            output: format,
        } => {
            let format = OutputFormat::from(format);
            if stdin {
                decode_stream(input, output, diagnostics, format)
            } else {
                let frame = frame.ok_or(AppError::MissingFrame)?;
                write_frame(output, &frame, format)
            }
        }
        Command::Listen {
            duration,
            count,
            output: format,
            database,
        } => {
            #[cfg(target_os = "linux")]
            {
                listen(
                    output,
                    diagnostics,
                    OutputFormat::from(format),
                    duration,
                    count,
                    &database,
                )
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (output, diagnostics, format, duration, count, database);
                Err(AppError::UnsupportedPlatform)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn listen(
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
    duration_seconds: Option<u64>,
    count: Option<NonZeroU64>,
    database_path: &Path,
) -> Result<(), AppError> {
    let stopping = termination_flag()?;
    let mut database = TelemetryStore::open(database_path).map_err(AppError::Database)?;
    let mut reassembler = ProfileReassembler::default();
    write_listen_startup(diagnostics, database_path)?;
    reconcile_pending_profiles(&mut database, &mut reassembler, output, diagnostics, format)?;
    let mut radio = sx1262::Sx1262Hat::open().map_err(AppError::Radio)?;

    let started = Instant::now();
    let deadline = duration_seconds.map(|seconds| started + Duration::from_secs(seconds));
    let maximum_frames = count.map(NonZeroU64::get);
    let mut valid_frames = 0_u64;
    let mut header_errors = 0_u64;
    let mut crc_errors = 0_u64;
    let mut unsupported_packets = 0_u64;
    let mut protocol_errors = 0_u64;

    loop {
        if stopping.load(Ordering::Relaxed)
            || maximum_frames.is_some_and(|maximum| valid_frames >= maximum)
        {
            break;
        }

        let poll_time = match deadline {
            Some(end) => {
                let Some(remaining) = end.checked_duration_since(Instant::now()) else {
                    break;
                };
                remaining.min(Duration::from_millis(250))
            }
            None => Duration::from_millis(250),
        };

        match radio.poll_receive(poll_time).map_err(AppError::Radio)? {
            None => {}
            Some(sx1262::ReceiveEvent::Packet(packet)) => {
                match store_packet(
                    &mut database,
                    &mut reassembler,
                    &packet,
                    output,
                    diagnostics,
                    format,
                )? {
                    PacketOutcome::ValidV1 | PacketOutcome::ValidV2 => valid_frames += 1,
                    PacketOutcome::Unsupported => unsupported_packets += 1,
                    PacketOutcome::Invalid => protocol_errors += 1,
                }
            }
            Some(sx1262::ReceiveEvent::HeaderError { irq }) => {
                header_errors += 1;
                writeln!(diagnostics, "radio: rejected LoRa header (IRQ 0x{irq:04x})")
                    .map_err(AppError::Io)?;
            }
            Some(sx1262::ReceiveEvent::CrcError { irq }) => {
                crc_errors += 1;
                writeln!(diagnostics, "radio: rejected PHY CRC (IRQ 0x{irq:04x})")
                    .map_err(AppError::Io)?;
            }
            Some(sx1262::ReceiveEvent::RadioTimeout { irq }) => {
                writeln!(
                    diagnostics,
                    "radio: unexpected RX timeout (IRQ 0x{irq:04x})"
                )
                .map_err(AppError::Io)?;
            }
            Some(sx1262::ReceiveEvent::OtherIrq(irq)) => {
                writeln!(diagnostics, "radio: unexpected IRQ 0x{irq:04x}").map_err(AppError::Io)?;
            }
        }

        persist_expired_profiles(&mut database, &mut reassembler, output, diagnostics, format)?;
    }

    for profile in reassembler.drain_incomplete() {
        persist_profile(&mut database, &profile, output, diagnostics, format)?;
    }

    writeln!(
        diagnostics,
        "listen stopped: valid_frames={valid_frames}, unsupported={unsupported_packets}, header_errors={header_errors}, crc_errors={crc_errors}, protocol_errors={protocol_errors}"
    )
    .map_err(AppError::Io)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketOutcome {
    ValidV1,
    ValidV2,
    Unsupported,
    Invalid,
}

#[cfg(target_os = "linux")]
fn store_packet(
    database: &mut TelemetryStore,
    reassembler: &mut ProfileReassembler,
    packet: &sx1262::RadioPacket,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
) -> Result<PacketOutcome, AppError> {
    let decoded = match vesta_protocol::decode_any(&packet.payload) {
        Ok(frame) => frame,
        Err(error) => {
            let decode_error = error.to_string();
            let disposition = if matches!(
                error,
                ProtocolDecodeError::UnsupportedVersion { .. }
                    | ProtocolDecodeError::InvalidMagic { .. }
                    | ProtocolDecodeError::TruncatedDiscriminator { .. }
            ) {
                PacketDisposition::Unsupported
            } else {
                PacketDisposition::Invalid
            };
            let stored = database
                .archive_packet(
                    &packet.payload,
                    packet.metadata,
                    disposition,
                    Some(&decode_error),
                )
                .map_err(AppError::Database)?;
            writeln!(
                diagnostics,
                "database: archived undecodable packet {}: {error}",
                stored.id
            )
            .map_err(AppError::Io)?;
            return Ok(if disposition == PacketDisposition::Unsupported {
                PacketOutcome::Unsupported
            } else {
                PacketOutcome::Invalid
            });
        }
    };

    match decoded {
        DecodedTelemetry::V1(frame) => {
            store_v1(database, packet, &frame, output, diagnostics, format)
        }
        DecodedTelemetry::V2(frame) => store_v2(
            database,
            reassembler,
            packet,
            frame,
            output,
            diagnostics,
            format,
        ),
    }
}

#[cfg(target_os = "linux")]
fn store_v1(
    database: &mut TelemetryStore,
    packet: &sx1262::RadioPacket,
    frame: &vesta_protocol::TelemetryV1,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
) -> Result<PacketOutcome, AppError> {
    let stored = database
        .insert_received_v1(frame, &packet.payload, packet.metadata)
        .map_err(AppError::Database)?;
    let rendered = render_received(frame, format, packet.metadata).map_err(AppError::Json)?;
    writeln!(output, "{rendered}").map_err(AppError::Io)?;
    output.flush().map_err(AppError::Io)?;
    let packet_id = stored.radio_packet_id.ok_or(AppError::MissingPacketLink)?;
    writeln!(
        diagnostics,
        "database: stored reading {} from packet {} at {} ms",
        stored.id, packet_id, stored.received_at_unix_ms
    )
    .map_err(AppError::Io)?;
    Ok(PacketOutcome::ValidV1)
}

#[cfg(target_os = "linux")]
fn store_v2(
    database: &mut TelemetryStore,
    reassembler: &mut ProfileReassembler,
    packet: &sx1262::RadioPacket,
    frame: vesta_protocol::v2::DecodedFrame<'_>,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
) -> Result<PacketOutcome, AppError> {
    match frame {
        vesta_protocol::v2::DecodedFrame::DeviceConfig { header, config } => {
            let configuration = device_configuration(header, config);
            let stored = database
                .insert_received_device_configuration(
                    &packet.payload,
                    packet.metadata,
                    header,
                    &configuration,
                )
                .map_err(AppError::Database)?;
            let rendered = render_v2(frame, format, Some(packet.metadata))?;
            writeln!(output, "{rendered}").map_err(AppError::Io)?;
            writeln!(
                diagnostics,
                "database: stored v2 configuration {} from packet {}",
                stored.record.id, stored.packet.id
            )
            .map_err(AppError::Io)?;
        }
        vesta_protocol::v2::DecodedFrame::DeviceHealth { header, health } => {
            let health = device_health(header, health);
            let stored = database
                .insert_received_device_health(&packet.payload, packet.metadata, header, &health)
                .map_err(AppError::Database)?;
            let rendered = render_v2(frame, format, Some(packet.metadata))?;
            writeln!(output, "{rendered}").map_err(AppError::Io)?;
            writeln!(
                diagnostics,
                "database: stored v2 health {} from packet {}",
                stored.record.id, stored.packet.id
            )
            .map_err(AppError::Io)?;
        }
        vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) => {
            let stored_packet = database
                .archive_v2_profile_fragment(&packet.payload, packet.metadata, fragment.header)
                .map_err(AppError::Database)?;
            ingest_archived_profile_fragment(
                database,
                reassembler,
                fragment,
                SourceFragment {
                    packet_id: stored_packet.id,
                    fragment_index: fragment.header.fragment_index,
                    received_at_unix_ms: stored_packet.received_at_unix_ms,
                    radio: packet.metadata,
                },
                &packet.payload,
                Instant::now(),
                output,
                diagnostics,
                format,
            )?;
        }
    }
    output.flush().map_err(AppError::Io)?;
    Ok(PacketOutcome::ValidV2)
}

#[cfg(target_os = "linux")]
fn reconcile_pending_profiles(
    database: &mut TelemetryStore,
    reassembler: &mut ProfileReassembler,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
) -> Result<(), AppError> {
    let replay_started = Instant::now();
    let incomplete = database
        .incomplete_profiles(MAX_STARTUP_PENDING_FRAGMENTS)
        .map_err(AppError::Database)?;
    let incomplete_count = incomplete.len();
    let mut replay_ordinal = 0_u64;
    restore_incomplete_profiles(
        database,
        reassembler,
        incomplete,
        replay_started,
        &mut replay_ordinal,
        output,
        diagnostics,
        format,
    )?;

    let pending = database
        .pending_profile_fragments(MAX_STARTUP_PENDING_FRAGMENTS)
        .map_err(AppError::Database)?;
    if pending.is_empty() && incomplete_count == 0 {
        return Ok(());
    }

    let pending_count = pending.len();
    for archived in pending {
        let decoded = match vesta_protocol::v2::decode(&archived.payload) {
            Ok(decoded) => decoded,
            Err(error) => {
                quarantine_pending_replay(
                    database,
                    archived.packet_id,
                    &format!("startup replay decode failed: {error}"),
                    diagnostics,
                )?;
                continue;
            }
        };
        let vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) = decoded else {
            quarantine_pending_replay(
                database,
                archived.packet_id,
                "startup replay decoded as a non-profile frame",
                diagnostics,
            )?;
            continue;
        };
        if fragment.header.fragment_index != archived.fragment_index {
            quarantine_pending_replay(
                database,
                archived.packet_id,
                "startup replay fragment index disagrees with archived metadata",
                diagnostics,
            )?;
            continue;
        }
        let observed_at = replay_started
            .checked_add(Duration::from_nanos(replay_ordinal))
            .unwrap_or(replay_started);
        replay_ordinal = replay_ordinal.saturating_add(1);
        if let Err(error) = ingest_archived_profile_fragment(
            database,
            reassembler,
            fragment,
            SourceFragment {
                packet_id: archived.packet_id,
                fragment_index: fragment.header.fragment_index,
                received_at_unix_ms: archived.received_at_unix_ms,
                radio: archived.radio,
            },
            &archived.payload,
            observed_at,
            output,
            diagnostics,
            format,
        ) {
            if matches!(
                &error,
                AppError::Reassembly(_) | AppError::Database(StorageError::InvalidRecord(_))
            ) {
                quarantine_pending_replay(
                    database,
                    archived.packet_id,
                    &format!("startup replay semantic validation failed: {error}"),
                    diagnostics,
                )?;
                continue;
            }
            return Err(error);
        }
    }
    writeln!(
        diagnostics,
        "database: restored {incomplete_count} incomplete v2 profile(s) and reconciled {pending_count} pending fragment(s) at startup"
    )
    .map_err(AppError::Io)
}

#[cfg(target_os = "linux")]
fn quarantine_pending_replay(
    database: &mut TelemetryStore,
    packet_id: i64,
    error: &str,
    diagnostics: &mut impl Write,
) -> Result<(), AppError> {
    database
        .quarantine_pending_profile_fragment(packet_id, error)
        .map_err(AppError::Database)?;
    writeln!(
        diagnostics,
        "database: quarantined invalid pending v2 profile packet {packet_id}: {error}"
    )
    .map_err(AppError::Io)
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn quarantine_incomplete_replay(
    database: &mut TelemetryStore,
    reassembler: &mut ProfileReassembler,
    scan_id: i64,
    key: vesta_receiver::reassembly::ProfileKey,
    packet_id: i64,
    error: &str,
    diagnostics: &mut impl Write,
) -> Result<(), AppError> {
    database
        .quarantine_incomplete_profile_fragment(scan_id, key, packet_id, error)
        .map_err(AppError::Database)?;
    reassembler.discard(key);
    writeln!(
        diagnostics,
        "database: quarantined invalid source packet {packet_id} and dismantled incomplete v2 profile {scan_id}: {error}"
    )
    .map_err(AppError::Io)
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn restore_incomplete_profiles(
    database: &mut TelemetryStore,
    reassembler: &mut ProfileReassembler,
    profiles: Vec<PersistedIncompleteProfile>,
    replay_started: Instant,
    replay_ordinal: &mut u64,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
) -> Result<(), AppError> {
    let mut quarantined_keys = HashSet::new();
    'profiles: for profile in profiles {
        if quarantined_keys.contains(&profile.key) {
            continue;
        }
        if let Some(classifications) = database
            .coalesce_incomplete_profile_into_completed(&profile)
            .map_err(AppError::Database)?
        {
            for reconciled in classifications {
                report_persisted_fragment_classification(
                    reconciled.classification,
                    profile.key,
                    reconciled.packet_id,
                    reconciled.fragment_index,
                    output,
                    diagnostics,
                    format,
                )?;
            }
            continue;
        }
        let mut counts_restored = false;
        for archived in profile.fragments {
            let decoded = match vesta_protocol::v2::decode(&archived.payload) {
                Ok(decoded) => decoded,
                Err(error) => {
                    quarantine_incomplete_replay(
                        database,
                        reassembler,
                        profile.scan_id,
                        profile.key,
                        archived.packet_id,
                        &format!("incomplete-profile replay decode failed: {error}"),
                        diagnostics,
                    )?;
                    quarantined_keys.insert(profile.key);
                    continue 'profiles;
                }
            };
            let vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) = decoded else {
                quarantine_incomplete_replay(
                    database,
                    reassembler,
                    profile.scan_id,
                    profile.key,
                    archived.packet_id,
                    "incomplete-profile replay decoded as a non-profile frame",
                    diagnostics,
                )?;
                quarantined_keys.insert(profile.key);
                continue 'profiles;
            };
            let key = vesta_receiver::reassembly::ProfileKey::from(&fragment.header);
            if key != profile.key || fragment.header.fragment_index != archived.fragment_index {
                quarantine_incomplete_replay(
                    database,
                    reassembler,
                    profile.scan_id,
                    profile.key,
                    archived.packet_id,
                    "incomplete-profile replay metadata disagrees with its persisted key",
                    diagnostics,
                )?;
                quarantined_keys.insert(profile.key);
                continue 'profiles;
            }
            if !counts_restored && reassembler.contains_active(key) {
                reassembler.restore_receiver_counts(
                    key,
                    profile.duplicate_fragment_count,
                    profile.conflicting_fragment_count,
                )?;
                counts_restored = true;
            }
            let observed_at = replay_started
                .checked_add(Duration::from_nanos(*replay_ordinal))
                .unwrap_or(replay_started);
            *replay_ordinal = (*replay_ordinal).saturating_add(1);
            let result = reassembler.ingest_at(
                fragment,
                SourceFragment {
                    packet_id: archived.packet_id,
                    fragment_index: fragment.header.fragment_index,
                    received_at_unix_ms: archived.received_at_unix_ms,
                    radio: archived.radio,
                },
                observed_at,
            )?;
            if !counts_restored && reassembler.contains_active(key) {
                reassembler.restore_receiver_counts(
                    key,
                    profile.duplicate_fragment_count,
                    profile.conflicting_fragment_count,
                )?;
                counts_restored = true;
            }
            handle_profile_fragment_result(
                database,
                result,
                archived.packet_id,
                output,
                diagnostics,
                format,
            )?;
        }
        if !counts_restored {
            return Err(AppError::Reassembly(ReassemblyError::InternalState));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn persist_expired_profiles(
    database: &mut TelemetryStore,
    reassembler: &mut ProfileReassembler,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
) -> Result<(), AppError> {
    for profile in reassembler.expire_older_than(PROFILE_REASSEMBLY_TIMEOUT) {
        persist_profile(database, &profile, output, diagnostics, format)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn ingest_archived_profile_fragment(
    database: &mut TelemetryStore,
    reassembler: &mut ProfileReassembler,
    fragment: vesta_protocol::v2::ProfileFragmentView<'_>,
    source: SourceFragment,
    payload: &[u8],
    observed_at: Instant,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
) -> Result<(), AppError> {
    let key = vesta_receiver::reassembly::ProfileKey::from(&fragment.header);
    if let Some(classification) = database
        .reconcile_persisted_profile_fragment(key, source.packet_id, source.fragment_index, payload)
        .map_err(AppError::Database)?
    {
        if reassembler.contains_active(key) {
            let (duplicates, conflicts) = match classification {
                PersistedFragmentMatch::Duplicate => (1, 0),
                PersistedFragmentMatch::Conflict => (0, 1),
            };
            reassembler.restore_receiver_counts(key, duplicates, conflicts)?;
        }
        report_persisted_fragment_classification(
            classification,
            key,
            source.packet_id,
            source.fragment_index,
            output,
            diagnostics,
            format,
        )?;
        return Ok(());
    }

    if !reassembler.contains_active(key) {
        let incomplete = database
            .incomplete_profiles_for_key(key, MAX_STARTUP_PENDING_FRAGMENTS)
            .map_err(AppError::Database)?;
        let mut replay_ordinal = 0_u64;
        restore_incomplete_profiles(
            database,
            reassembler,
            incomplete,
            observed_at,
            &mut replay_ordinal,
            output,
            diagnostics,
            format,
        )?;
    }

    let result = reassembler.ingest_at(fragment, source, observed_at)?;
    handle_profile_fragment_result(
        database,
        result,
        source.packet_id,
        output,
        diagnostics,
        format,
    )
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn report_persisted_fragment_classification(
    classification: PersistedFragmentMatch,
    key: vesta_receiver::reassembly::ProfileKey,
    packet_id: i64,
    fragment_index: u8,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
) -> Result<(), AppError> {
    let classification = match classification {
        PersistedFragmentMatch::Duplicate => "duplicate",
        PersistedFragmentMatch::Conflict => {
            write_profile_integrity_update(output, format, key, packet_id, fragment_index)?;
            "conflict"
        }
    };
    writeln!(
        diagnostics,
        "v2 profile persisted {classification} fragment {fragment_index} in packet {packet_id}"
    )
    .map_err(AppError::Io)
}

#[cfg(target_os = "linux")]
fn write_profile_integrity_update(
    output: &mut impl Write,
    format: OutputFormat,
    key: vesta_receiver::reassembly::ProfileKey,
    packet_id: i64,
    fragment_index: u8,
) -> Result<(), AppError> {
    match format {
        OutputFormat::Human => writeln!(
            output,
            "Vesta receiver integrity update: persisted profile {:016x}/{:016x}/{}/uptime={}/config={:016x} invalidated by conflicting fragment {} in packet {}",
            key.node_id,
            key.boot_id,
            key.scan_sequence,
            key.uptime_ms,
            key.config_id,
            fragment_index,
            packet_id,
        )
        .map_err(AppError::Io)?,
        OutputFormat::JsonLines => {
            let update = serde_json::json!({
                "receiver_event": "profile_integrity_update",
                "protocol_version": 2,
                "node_id": format!("{:016x}", key.node_id),
                "boot_id_valid": key.boot_id_valid,
                "boot_id": format!("{:016x}", key.boot_id),
                "scan_sequence": key.scan_sequence,
                "scan_start_uptime_ms": key.uptime_ms.to_string(),
                "config_id": format!("{:016x}", key.config_id),
                "source_packet_id": packet_id,
                "fragment_index": fragment_index,
                "classification": "conflict",
                "usable_for_analysis": false,
            });
            writeln!(output, "{update}").map_err(AppError::Io)?;
        }
    }
    output.flush().map_err(AppError::Io)
}

#[cfg(target_os = "linux")]
fn handle_profile_fragment_result(
    database: &mut TelemetryStore,
    result: IngestResult,
    packet_id: i64,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
) -> Result<(), AppError> {
    let IngestResult {
        event,
        evicted,
        integrity_snapshot,
    } = result;
    if let Some(evicted) = evicted {
        persist_profile(database, &evicted, output, diagnostics, format)?;
    }
    match event {
        FragmentEvent::Pending(progress) => writeln!(
            diagnostics,
            "v2 profile {:016x}/valid={}/{:016x}/{}/uptime={}/config={:016x} pending fragments 0x{:x}",
            progress.key.node_id,
            progress.key.boot_id_valid,
            progress.key.boot_id,
            progress.key.scan_sequence,
            progress.key.uptime_ms,
            progress.key.config_id,
            progress.missing_fragment_bitmap,
        )
        .map_err(AppError::Io),
        FragmentEvent::Complete(profile) => {
            persist_profile(database, &profile, output, diagnostics, format)
        }
        FragmentEvent::Duplicate { fragment_index, .. } => {
            let snapshot = integrity_snapshot
                .as_ref()
                .ok_or(AppError::Reassembly(ReassemblyError::InternalState))?;
            database
                .insert_profile_integrity_snapshot(
                    snapshot,
                    packet_id,
                    FragmentStorageStatus::Duplicate,
                )
                .map_err(AppError::Database)?;
            writeln!(
                diagnostics,
                "v2 profile duplicate fragment {fragment_index} in packet {packet_id}"
            )
            .map_err(AppError::Io)
        }
        FragmentEvent::Conflict { fragment_index, .. } => {
            let snapshot = integrity_snapshot
                .as_ref()
                .ok_or(AppError::Reassembly(ReassemblyError::InternalState))?;
            database
                .insert_profile_integrity_snapshot(
                    snapshot,
                    packet_id,
                    FragmentStorageStatus::Conflict,
                )
                .map_err(AppError::Database)?;
            writeln!(
                diagnostics,
                "v2 profile conflicting fragment {fragment_index} in packet {packet_id}"
            )
            .map_err(AppError::Io)
        }
    }
}

#[cfg(target_os = "linux")]
fn persist_profile(
    database: &mut TelemetryStore,
    profile: &vesta_receiver::reassembly::ReassembledProfile,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
) -> Result<(), AppError> {
    let stored = database
        .insert_profile_scan(profile)
        .map_err(AppError::Database)?;
    let rendered = render_reassembled_profile(profile, format).map_err(AppError::Json)?;
    writeln!(output, "{rendered}").map_err(AppError::Io)?;
    output.flush().map_err(AppError::Io)?;
    writeln!(
        diagnostics,
        "database: stored v2 profile {} at {} ms; missing radio fragments 0x{:x}",
        stored.id,
        stored.received_at_unix_ms,
        profile.scan.missing_fragment_bitmap()
    )
    .map_err(AppError::Io)
}

#[cfg(target_os = "linux")]
fn termination_flag() -> Result<Arc<AtomicBool>, AppError> {
    use signal_hook::consts::signal::{SIGINT, SIGTERM};

    let stopping = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&stopping)).map_err(AppError::Signal)?;
    signal_hook::flag::register(SIGTERM, Arc::clone(&stopping)).map_err(AppError::Signal)?;
    Ok(stopping)
}

fn write_listen_startup(
    diagnostics: &mut impl Write,
    database_path: &Path,
) -> Result<(), AppError> {
    writeln!(
        diagnostics,
        "listening RX-only: 868.100 MHz, SF7, BW125, CR4/5, preamble 8, explicit header, CRC, private sync 0x1424"
    )
    .map_err(AppError::Io)?;
    writeln!(
        diagnostics,
        "database: archiving every PHY-valid packet in {}",
        database_path.display()
    )
    .map_err(AppError::Io)
}

fn decode_stream(
    input: impl BufRead,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
) -> Result<(), AppError> {
    let mut failures = 0_usize;
    for (index, line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = line.map_err(AppError::Io)?;
        let frame = line.trim();
        if frame.is_empty() {
            continue;
        }

        match write_frame(output, frame, format) {
            Ok(()) => {}
            Err(error) => {
                writeln!(diagnostics, "line {line_number}: {error}").map_err(AppError::Io)?;
                failures += 1;
            }
        }
    }

    if failures == 0 {
        Ok(())
    } else {
        Err(AppError::StreamFailures { count: failures })
    }
}

fn write_frame(
    output: &mut impl Write,
    encoded: &str,
    format: OutputFormat,
) -> Result<(), AppError> {
    let payload = parse_payload_hex(encoded).map_err(AppError::Hex)?;
    match vesta_protocol::decode_any(&payload).map_err(AppError::Protocol)? {
        DecodedTelemetry::V1(frame) => write_decoded_frame(output, &frame, format),
        DecodedTelemetry::V2(frame) => {
            let rendered = render_v2(frame, format, None)?;
            writeln!(output, "{rendered}").map_err(AppError::Io)
        }
    }
}

fn write_decoded_frame(
    output: &mut impl Write,
    frame: &vesta_protocol::TelemetryV1,
    format: OutputFormat,
) -> Result<(), AppError> {
    let rendered = render(frame, format).map_err(AppError::Json)?;
    writeln!(output, "{rendered}").map_err(AppError::Io)
}

#[derive(Debug)]
enum AppError {
    MissingFrame,
    Hex(HexError),
    Protocol(ProtocolDecodeError),
    V2Render(V2RenderError),
    Json(serde_json::Error),
    Io(io::Error),
    Database(StorageError),
    MissingPacketLink,
    #[cfg(target_os = "linux")]
    Reassembly(ReassemblyError),
    #[cfg(target_os = "linux")]
    Radio(sx1262::RadioError),
    #[cfg(target_os = "linux")]
    Signal(io::Error),
    #[cfg(not(target_os = "linux"))]
    UnsupportedPlatform,
    StreamFailures {
        count: usize,
    },
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFrame => formatter.write_str("a hexadecimal frame or --stdin is required"),
            Self::Hex(error) => error.fmt(formatter),
            Self::Protocol(error) => error.fmt(formatter),
            Self::V2Render(error) => error.fmt(formatter),
            Self::Json(error) => write!(formatter, "could not serialize frame: {error}"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::MissingPacketLink => formatter.write_str("database did not link archived packet"),
            #[cfg(target_os = "linux")]
            Self::Reassembly(error) => write!(formatter, "profile reassembly error: {error}"),
            #[cfg(target_os = "linux")]
            Self::Radio(error) => write!(formatter, "radio error: {error}"),
            #[cfg(target_os = "linux")]
            Self::Signal(error) => write!(formatter, "could not install signal handler: {error}"),
            #[cfg(not(target_os = "linux"))]
            Self::UnsupportedPlatform => {
                formatter.write_str("SX1262 listening is supported only on Linux")
            }
            Self::StreamFailures { count } => {
                write!(formatter, "{count} input frame(s) could not be decoded")
            }
        }
    }
}

impl std::error::Error for AppError {}

impl From<V2RenderError> for AppError {
    fn from(error: V2RenderError) -> Self {
        Self::V2Render(error)
    }
}

#[cfg(target_os = "linux")]
impl From<ReassemblyError> for AppError {
    fn from(error: ReassemblyError) -> Self {
        Self::Reassembly(error)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn radio_metadata() -> vesta_receiver::RadioMetadata {
        vesta_receiver::RadioMetadata {
            packet_rssi_centi_dbm: -4_200,
            snr_centi_db: 1_250,
            signal_rssi_centi_dbm: -4_250,
        }
    }

    fn encoded_profile() -> vesta_protocol::v2::EncodedProfile {
        let mut steps = [None; vesta_protocol::v2::MAX_PROFILE_STEPS];
        for index in 0..4_u8 {
            steps[usize::from(index)] = Some(vesta_protocol::v2::ProfileStep {
                step_index: index,
                gas_index: index,
                measurement_index: index,
                status: 0xb0,
                raw_measurement_status: 0x80 | index,
                raw_gas_status: 0x35,
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
                repetition_multiplier: 1,
                heater_resistance: 6,
                heater_current: 7,
                gas_wait: 8,
            });
        }
        vesta_protocol::v2::encode_profile(
            vesta_protocol::v2::Common::production(1, 2, 3, 4, 5, 0),
            &vesta_protocol::v2::ProfileScan {
                profile_id: 6,
                profile_version: 1,
                expected_step_count: 4,
                observed_unique_step_count: 4,
                observed_field_count: 4,
                missing_steps_bitmap: 0,
                duplicate_steps_bitmap: 0,
                scan_duration_us: 400_000,
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
                poll_count: 8,
                steps,
            },
        )
        .unwrap()
    }

    fn temporary_database_path() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vesta-receiver-reconcile-{}-{nonce}.sqlite3",
            std::process::id()
        ))
    }

    fn persist_fragment_after_expiry(store: &mut TelemetryStore, payload: &[u8]) -> i64 {
        let vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) =
            vesta_protocol::v2::decode(payload).unwrap()
        else {
            unreachable!()
        };
        let packet = store
            .archive_v2_profile_fragment(payload, radio_metadata(), fragment.header)
            .unwrap();
        let observed_at = Instant::now();
        let mut reassembler = ProfileReassembler::default();
        reassembler
            .ingest_at(
                fragment,
                SourceFragment {
                    packet_id: packet.id,
                    fragment_index: fragment.header.fragment_index,
                    received_at_unix_ms: packet.received_at_unix_ms,
                    radio: radio_metadata(),
                },
                observed_at,
            )
            .unwrap();
        let mut expired = reassembler.expire_before(observed_at + Duration::from_millis(1));
        assert_eq!(expired.len(), 1);
        store.insert_profile_scan(&expired.remove(0)).unwrap().id
    }

    #[allow(clippy::too_many_arguments)]
    fn archive_and_ingest(
        store: &mut TelemetryStore,
        reassembler: &mut ProfileReassembler,
        payload: &[u8],
        observed_at: Instant,
        output: &mut Vec<u8>,
        diagnostics: &mut Vec<u8>,
    ) -> i64 {
        let vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) =
            vesta_protocol::v2::decode(payload).unwrap()
        else {
            unreachable!()
        };
        let packet = store
            .archive_v2_profile_fragment(payload, radio_metadata(), fragment.header)
            .unwrap();
        ingest_archived_profile_fragment(
            store,
            reassembler,
            fragment,
            SourceFragment {
                packet_id: packet.id,
                fragment_index: fragment.header.fragment_index,
                received_at_unix_ms: packet.received_at_unix_ms,
                radio: radio_metadata(),
            },
            payload,
            observed_at,
            output,
            diagnostics,
            OutputFormat::JsonLines,
        )
        .unwrap();
        packet.id
    }

    fn set_all_profile_transport_complete(path: &Path, complete: bool) {
        let connection = rusqlite::Connection::open(path).unwrap();
        connection
            .execute(
                "UPDATE v2_profile_scans SET transport_complete = ?1",
                [i64::from(complete)],
            )
            .unwrap();
    }

    fn source_packet_for_scan(path: &Path, scan_id: i64) -> i64 {
        rusqlite::Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT packet_id FROM v2_profile_fragments WHERE scan_id = ?1",
                [scan_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn remove_database(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn startup_reconciles_archived_pending_fragments_after_restart() {
        let path = temporary_database_path();
        let encoded = encoded_profile();
        {
            let mut before_restart = TelemetryStore::open(&path).unwrap();
            for index in [1_usize, 0] {
                let payload = encoded.frames()[index].as_slice();
                let vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) =
                    vesta_protocol::v2::decode(payload).unwrap()
                else {
                    unreachable!()
                };
                before_restart
                    .archive_v2_profile_fragment(payload, radio_metadata(), fragment.header)
                    .unwrap();
            }
        }

        let mut after_restart = TelemetryStore::open(&path).unwrap();
        assert_eq!(
            after_restart.pending_profile_fragments(10).unwrap().len(),
            2
        );
        let mut reassembler = ProfileReassembler::default();
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        reconcile_pending_profiles(
            &mut after_restart,
            &mut reassembler,
            &mut output,
            &mut diagnostics,
            OutputFormat::JsonLines,
        )
        .unwrap();
        assert!(
            after_restart
                .pending_profile_fragments(10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(reassembler.active_len(), 0);
        assert!(!output.is_empty());
        assert!(
            String::from_utf8(diagnostics)
                .unwrap()
                .contains("reconciled 2 pending fragment")
        );
        drop(after_restart);
        remove_database(&path);
    }

    #[test]
    fn contradictory_profile_fragment_is_archived_invalid_and_cannot_poison_restart() {
        let path = temporary_database_path();
        let encoded = encoded_profile();
        let mut malformed = encoded.frames()[0].as_slice().to_vec();
        let raw_gas_status =
            vesta_protocol::v2::HEADER_LEN + vesta_protocol::v2::PROFILE_FRAGMENT_META_LEN + 5;
        malformed[raw_gas_status] ^= 0x20;
        assert!(vesta_protocol::decode_any(&malformed).is_err());

        {
            let mut store = TelemetryStore::open(&path).unwrap();
            let outcome = store_packet(
                &mut store,
                &mut ProfileReassembler::default(),
                &sx1262::RadioPacket {
                    payload: malformed.clone(),
                    metadata: radio_metadata(),
                },
                &mut Vec::new(),
                &mut Vec::new(),
                OutputFormat::JsonLines,
            )
            .unwrap();
            assert_eq!(outcome, PacketOutcome::Invalid);
            assert!(store.pending_profile_fragments(10).unwrap().is_empty());
        }

        let mut store = TelemetryStore::open(&path).unwrap();
        reconcile_pending_profiles(
            &mut store,
            &mut ProfileReassembler::default(),
            &mut Vec::new(),
            &mut Vec::new(),
            OutputFormat::JsonLines,
        )
        .unwrap();
        drop(store);
        let connection = rusqlite::Connection::open(&path).unwrap();
        let archived: (String, Vec<u8>, String, i64) = connection
            .query_row(
                "SELECT disposition, payload, decode_error,
                        (SELECT count(*) FROM v2_packet_decodes)
                 FROM radio_packets",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(archived.0, "invalid");
        assert_eq!(archived.1, malformed);
        assert!(archived.2.contains("step_status_raw"));
        assert_eq!(archived.3, 0);
        drop(connection);
        remove_database(&path);
    }

    #[test]
    fn startup_quarantines_a_legacy_pending_fragment_that_no_longer_validates() {
        let path = temporary_database_path();
        let encoded = encoded_profile();
        let packet_id = {
            let payload = encoded.frames()[0].as_slice();
            let vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) =
                vesta_protocol::v2::decode(payload).unwrap()
            else {
                unreachable!()
            };
            let mut store = TelemetryStore::open(&path).unwrap();
            store
                .archive_v2_profile_fragment(payload, radio_metadata(), fragment.header)
                .unwrap()
                .id
        };
        let mut malformed = encoded.frames()[0].as_slice().to_vec();
        let raw_gas_status =
            vesta_protocol::v2::HEADER_LEN + vesta_protocol::v2::PROFILE_FRAGMENT_META_LEN + 5;
        malformed[raw_gas_status] ^= 0x20;
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE radio_packets SET payload = ?1 WHERE id = ?2",
                rusqlite::params![malformed, packet_id],
            )
            .unwrap();
        drop(connection);

        for _ in 0..2 {
            let mut store = TelemetryStore::open(&path).unwrap();
            reconcile_pending_profiles(
                &mut store,
                &mut ProfileReassembler::default(),
                &mut Vec::new(),
                &mut Vec::new(),
                OutputFormat::JsonLines,
            )
            .unwrap();
            assert!(store.pending_profile_fragments(10).unwrap().is_empty());
        }
        let connection = rusqlite::Connection::open(&path).unwrap();
        let archived: (String, String, i64) = connection
            .query_row(
                "SELECT disposition, decode_error,
                        (SELECT count(*) FROM v2_packet_decodes)
                 FROM radio_packets WHERE id = ?1",
                [packet_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(archived.0, "invalid");
        assert!(archived.1.contains("step_status_raw"));
        assert_eq!(archived.2, 0);
        drop(connection);
        remove_database(&path);
    }

    #[test]
    fn startup_quarantines_a_legacy_incomplete_fragment_that_no_longer_validates() {
        let path = temporary_database_path();
        let encoded = encoded_profile();
        {
            let mut store = TelemetryStore::open(&path).unwrap();
            persist_fragment_after_expiry(&mut store, encoded.frames()[0].as_slice());
            assert_eq!(store.incomplete_profiles(10).unwrap().len(), 1);
        }
        let connection = rusqlite::Connection::open(&path).unwrap();
        let packet_id: i64 = connection
            .query_row("SELECT packet_id FROM v2_profile_fragments", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut malformed = encoded.frames()[0].as_slice().to_vec();
        let raw_gas_status =
            vesta_protocol::v2::HEADER_LEN + vesta_protocol::v2::PROFILE_FRAGMENT_META_LEN + 5;
        malformed[raw_gas_status] ^= 0x20;
        connection
            .execute(
                "UPDATE radio_packets SET payload = ?1 WHERE id = ?2",
                rusqlite::params![malformed, packet_id],
            )
            .unwrap();
        drop(connection);

        for _ in 0..2 {
            let mut store = TelemetryStore::open(&path).unwrap();
            reconcile_pending_profiles(
                &mut store,
                &mut ProfileReassembler::default(),
                &mut Vec::new(),
                &mut Vec::new(),
                OutputFormat::JsonLines,
            )
            .unwrap();
            assert!(store.incomplete_profiles(10).unwrap().is_empty());
            assert!(store.pending_profile_fragments(10).unwrap().is_empty());
        }
        let connection = rusqlite::Connection::open(&path).unwrap();
        let archived: (String, Vec<u8>, String, i64, i64) = connection
            .query_row(
                "SELECT disposition, payload, decode_error,
                        (SELECT count(*) FROM v2_packet_decodes),
                        (SELECT count(*) FROM v2_profile_scans)
                 FROM radio_packets WHERE id = ?1",
                [packet_id],
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
        assert_eq!(archived.0, "invalid");
        assert_eq!(archived.1, malformed);
        assert!(archived.2.contains("step_status_raw"));
        assert_eq!((archived.3, archived.4), (0, 0));
        drop(connection);
        remove_database(&path);
    }

    #[test]
    fn poison_partial_dismantles_same_key_rows_and_salvages_valid_fragments() {
        let path = temporary_database_path();
        let encoded = encoded_profile();
        let first_scan = {
            let mut store = TelemetryStore::open(&path).unwrap();
            persist_fragment_after_expiry(&mut store, encoded.frames()[0].as_slice())
        };
        set_all_profile_transport_complete(&path, true);
        let poison_scan = {
            let mut store = TelemetryStore::open(&path).unwrap();
            persist_fragment_after_expiry(&mut store, encoded.frames()[0].as_slice())
        };
        set_all_profile_transport_complete(&path, true);
        let complement_scan = {
            let mut store = TelemetryStore::open(&path).unwrap();
            persist_fragment_after_expiry(&mut store, encoded.frames()[1].as_slice())
        };
        set_all_profile_transport_complete(&path, false);
        let poison_packet = source_packet_for_scan(&path, poison_scan);
        assert_ne!(source_packet_for_scan(&path, first_scan), poison_packet);
        assert_ne!(
            source_packet_for_scan(&path, complement_scan),
            poison_packet
        );

        let mut malformed = encoded.frames()[0].as_slice().to_vec();
        let raw_gas_status =
            vesta_protocol::v2::HEADER_LEN + vesta_protocol::v2::PROFILE_FRAGMENT_META_LEN + 5;
        malformed[raw_gas_status] ^= 0x20;
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE radio_packets SET payload = ?1 WHERE id = ?2",
                rusqlite::params![malformed, poison_packet],
            )
            .unwrap();
        drop(connection);

        for restart in 0..2 {
            let mut store = TelemetryStore::open(&path).unwrap();
            reconcile_pending_profiles(
                &mut store,
                &mut ProfileReassembler::default(),
                &mut Vec::new(),
                &mut Vec::new(),
                OutputFormat::JsonLines,
            )
            .unwrap();
            assert!(store.incomplete_profiles(10).unwrap().is_empty());
            assert!(store.pending_profile_fragments(10).unwrap().is_empty());
            drop(store);

            let connection = rusqlite::Connection::open(&path).unwrap();
            let state: (i64, i64, i64, i64, String) = connection
                .query_row(
                    "SELECT count(*), sum(transport_complete),
                            (SELECT count(*) FROM v2_profile_fragments),
                            (SELECT count(*) FROM radio_packets),
                            (SELECT disposition FROM radio_packets WHERE id = ?1)
                     FROM v2_profile_scans",
                    [poison_packet],
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
            assert_eq!(
                state,
                (1, 1, 2, 3, "invalid".to_owned()),
                "restart {restart}"
            );
        }
        remove_database(&path);
    }

    #[test]
    fn poison_salvage_replays_unlinked_conflict_evidence_before_completion() {
        let path = temporary_database_path();
        let encoded = encoded_profile();
        let (conflict_packet, poison_scan) = {
            let mut store = TelemetryStore::open(&path).unwrap();
            let mut reassembler = ProfileReassembler::default();
            let observed_at = Instant::now();
            archive_and_ingest(
                &mut store,
                &mut reassembler,
                encoded.frames()[0].as_slice(),
                observed_at,
                &mut Vec::new(),
                &mut Vec::new(),
            );
            let mut conflict = encoded.frames()[0].as_slice().to_vec();
            let last = conflict.len() - 1;
            conflict[last] ^= 1;
            let conflict_packet = archive_and_ingest(
                &mut store,
                &mut reassembler,
                &conflict,
                observed_at + Duration::from_millis(1),
                &mut Vec::new(),
                &mut Vec::new(),
            );
            assert_eq!(reassembler.active_len(), 1);

            // Reproduce legacy schema-v3 rows: preserve the conflict-bearing
            // snapshot while independently persisting the other fragment.
            set_all_profile_transport_complete(&path, true);
            let poison_scan =
                persist_fragment_after_expiry(&mut store, encoded.frames()[1].as_slice());
            set_all_profile_transport_complete(&path, false);

            // A later raw-valid complement is pending when the old source is
            // discovered to violate the strengthened protocol semantics.
            let payload = encoded.frames()[1].as_slice();
            let vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) =
                vesta_protocol::v2::decode(payload).unwrap()
            else {
                unreachable!()
            };
            store
                .archive_v2_profile_fragment(payload, radio_metadata(), fragment.header)
                .unwrap();
            (conflict_packet, poison_scan)
        };
        let poison_packet = source_packet_for_scan(&path, poison_scan);
        let mut malformed = encoded.frames()[1].as_slice().to_vec();
        let raw_gas_status =
            vesta_protocol::v2::HEADER_LEN + vesta_protocol::v2::PROFILE_FRAGMENT_META_LEN + 5;
        malformed[raw_gas_status] ^= 0x20;
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE radio_packets SET payload = ?1 WHERE id = ?2",
                rusqlite::params![malformed, poison_packet],
            )
            .unwrap();
        drop(connection);

        for restart in 0..2 {
            let mut store = TelemetryStore::open(&path).unwrap();
            reconcile_pending_profiles(
                &mut store,
                &mut ProfileReassembler::default(),
                &mut Vec::new(),
                &mut Vec::new(),
                OutputFormat::JsonLines,
            )
            .unwrap();
            assert!(store.incomplete_profiles(10).unwrap().is_empty());
            assert!(store.pending_profile_fragments(10).unwrap().is_empty());
            drop(store);

            let connection = rusqlite::Connection::open(&path).unwrap();
            let state: (i64, i64, i64, i64, String, String) = connection
                .query_row(
                    "SELECT count(*), sum(transport_complete),
                            sum(conflicting_fragment_count),
                            sum(json_extract(record_json, '$.conflicting_fragment_count')),
                            (SELECT reassembly_status FROM v2_packet_decodes
                             WHERE packet_id = ?1),
                            (SELECT disposition FROM radio_packets WHERE id = ?2)
                     FROM v2_profile_scans",
                    rusqlite::params![conflict_packet, poison_packet],
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
                state,
                (1, 1, 1, 1, "conflict".to_owned(), "invalid".to_owned()),
                "restart {restart}"
            );
        }
        remove_database(&path);
    }

    #[test]
    fn late_complement_replaces_a_profile_persisted_after_expiry() {
        let path = temporary_database_path();
        let encoded = encoded_profile();
        let mut store = TelemetryStore::open(&path).unwrap();
        persist_fragment_after_expiry(&mut store, encoded.frames()[0].as_slice());
        assert_eq!(store.incomplete_profiles(10).unwrap().len(), 1);

        // The in-memory cache is deliberately empty, as it is after expiry.
        let mut reassembler = ProfileReassembler::default();
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        archive_and_ingest(
            &mut store,
            &mut reassembler,
            encoded.frames()[1].as_slice(),
            Instant::now(),
            &mut output,
            &mut diagnostics,
        );
        assert_eq!(reassembler.active_len(), 0);
        drop(store);

        let connection = rusqlite::Connection::open(&path).unwrap();
        let state: (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT count(*), sum(transport_complete),
                        (SELECT count(*) FROM v2_profile_steps),
                        (SELECT count(*) FROM v2_profile_fragments)
                 FROM v2_profile_scans",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(state, (1, 1, 4, 2));
        drop(connection);
        remove_database(&path);
    }

    #[test]
    fn restart_preserves_late_conflict_when_partial_scan_later_completes() {
        let path = temporary_database_path();
        let encoded = encoded_profile();
        {
            let mut before_restart = TelemetryStore::open(&path).unwrap();
            persist_fragment_after_expiry(&mut before_restart, encoded.frames()[0].as_slice());

            let mut conflict = encoded.frames()[0].as_slice().to_vec();
            let last = conflict.len() - 1;
            conflict[last] ^= 1;
            let mut reassembler = ProfileReassembler::default();
            archive_and_ingest(
                &mut before_restart,
                &mut reassembler,
                &conflict,
                Instant::now(),
                &mut Vec::new(),
                &mut Vec::new(),
            );
            assert_eq!(reassembler.active_len(), 0);
        }

        let mut after_restart = TelemetryStore::open(&path).unwrap();
        let mut reassembler = ProfileReassembler::default();
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        reconcile_pending_profiles(
            &mut after_restart,
            &mut reassembler,
            &mut output,
            &mut diagnostics,
            OutputFormat::JsonLines,
        )
        .unwrap();
        assert_eq!(reassembler.active_len(), 1);

        archive_and_ingest(
            &mut after_restart,
            &mut reassembler,
            encoded.frames()[1].as_slice(),
            Instant::now(),
            &mut output,
            &mut diagnostics,
        );
        assert_eq!(reassembler.active_len(), 0);
        drop(after_restart);

        let connection = rusqlite::Connection::open(&path).unwrap();
        let state: (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT count(*), sum(transport_complete),
                        sum(conflicting_fragment_count),
                        sum(json_extract(record_json, '$.conflicting_fragment_count'))
                 FROM v2_profile_scans",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(state, (1, 1, 1, 1));
        drop(connection);
        remove_database(&path);
    }

    #[test]
    fn active_duplicate_and_conflict_counters_survive_a_crash_before_completion() {
        for conflict in [false, true] {
            let path = temporary_database_path();
            let encoded = encoded_profile();
            let repeated_packet_id;
            {
                let mut before_restart = TelemetryStore::open(&path).unwrap();
                let mut reassembler = ProfileReassembler::default();
                let observed_at = Instant::now();
                archive_and_ingest(
                    &mut before_restart,
                    &mut reassembler,
                    encoded.frames()[0].as_slice(),
                    observed_at,
                    &mut Vec::new(),
                    &mut Vec::new(),
                );
                let mut repeated = encoded.frames()[0].as_slice().to_vec();
                if conflict {
                    let last = repeated.len() - 1;
                    repeated[last] ^= 1;
                }
                repeated_packet_id = archive_and_ingest(
                    &mut before_restart,
                    &mut reassembler,
                    &repeated,
                    observed_at + Duration::from_millis(1),
                    &mut Vec::new(),
                    &mut Vec::new(),
                );
                assert_eq!(reassembler.active_len(), 1);
                // Simulate abrupt process loss: do not expire or complete the
                // active reassembler before dropping it.
            }

            let mut after_restart = TelemetryStore::open(&path).unwrap();
            let mut reassembler = ProfileReassembler::default();
            reconcile_pending_profiles(
                &mut after_restart,
                &mut reassembler,
                &mut Vec::new(),
                &mut Vec::new(),
                OutputFormat::JsonLines,
            )
            .unwrap();
            assert_eq!(reassembler.active_len(), 1);
            archive_and_ingest(
                &mut after_restart,
                &mut reassembler,
                encoded.frames()[1].as_slice(),
                Instant::now(),
                &mut Vec::new(),
                &mut Vec::new(),
            );
            assert_eq!(reassembler.active_len(), 0);
            drop(after_restart);

            let connection = rusqlite::Connection::open(&path).unwrap();
            let state: (i64, i64, i64, i64, i64, String) = connection
                .query_row(
                    "SELECT count(*), sum(transport_complete),
                            sum(duplicate_fragment_count),
                            sum(conflicting_fragment_count),
                            (SELECT count(*) FROM radio_packets),
                            (SELECT reassembly_status FROM v2_packet_decodes
                             WHERE packet_id = ?1)
                     FROM v2_profile_scans",
                    [repeated_packet_id],
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
            let expected = if conflict {
                (1, 1, 0, 1, 3, "conflict".to_owned())
            } else {
                (1, 1, 1, 0, 3, "duplicate".to_owned())
            };
            assert_eq!(state, expected);
            let json_counts: (i64, i64) = connection
                .query_row(
                    "SELECT json_extract(record_json, '$.duplicate_fragment_count'),
                            json_extract(record_json, '$.conflicting_fragment_count')
                     FROM v2_profile_scans",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(json_counts, (i64::from(!conflict), i64::from(conflict)));
            drop(connection);
            remove_database(&path);
        }
    }

    #[test]
    fn startup_coalesces_legacy_partial_rows_before_classifying_late_conflicts() {
        let path = temporary_database_path();
        let encoded = encoded_profile();

        // Build the shape of a schema-v3 database created by the old receiver:
        // several separately persisted partial rows with the same full key.
        // Temporarily protecting earlier rows from replacement lets this test
        // reproduce that historical state through current public APIs.
        {
            let mut store = TelemetryStore::open(&path).unwrap();
            persist_fragment_after_expiry(&mut store, encoded.frames()[0].as_slice());
        }
        set_all_profile_transport_complete(&path, true);
        {
            let mut store = TelemetryStore::open(&path).unwrap();
            persist_fragment_after_expiry(&mut store, encoded.frames()[1].as_slice());
        }
        set_all_profile_transport_complete(&path, true);
        {
            let mut conflict = encoded.frames()[0].as_slice().to_vec();
            let last = conflict.len() - 1;
            conflict[last] ^= 1;
            let mut store = TelemetryStore::open(&path).unwrap();
            persist_fragment_after_expiry(&mut store, &conflict);
        }
        set_all_profile_transport_complete(&path, false);

        let mut store = TelemetryStore::open(&path).unwrap();
        assert_eq!(store.incomplete_profiles(10).unwrap().len(), 3);
        let mut reassembler = ProfileReassembler::default();
        let mut output = Vec::new();
        reconcile_pending_profiles(
            &mut store,
            &mut reassembler,
            &mut output,
            &mut Vec::new(),
            OutputFormat::JsonLines,
        )
        .unwrap();
        assert_eq!(reassembler.active_len(), 0);
        assert!(store.incomplete_profiles(10).unwrap().is_empty());
        drop(store);

        let connection = rusqlite::Connection::open(&path).unwrap();
        let state: (i64, i64, i64, i64, i64) = connection
            .query_row(
                "SELECT count(*), sum(transport_complete),
                        sum(conflicting_fragment_count),
                        sum(json_extract(record_json, '$.conflicting_fragment_count')),
                        (SELECT count(*) FROM v2_profile_fragments)
                 FROM v2_profile_scans",
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
        assert_eq!(state, (1, 1, 1, 1, 2));
        let event: serde_json::Value = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
            .find(|value| value["receiver_event"] == "profile_integrity_update")
            .unwrap();
        assert_eq!(event["receiver_event"], "profile_integrity_update");
        assert_eq!(event["usable_for_analysis"], false);
        drop(connection);
        remove_database(&path);
    }

    #[test]
    fn complete_plus_legacy_partial_is_coalesced_once_across_restarts() {
        let path = temporary_database_path();
        let encoded = encoded_profile();
        let conflict_packet_id;
        {
            let mut store = TelemetryStore::open(&path).unwrap();
            let mut reassembler = ProfileReassembler::default();
            for frame in encoded.frames() {
                archive_and_ingest(
                    &mut store,
                    &mut reassembler,
                    frame.as_slice(),
                    Instant::now(),
                    &mut Vec::new(),
                    &mut Vec::new(),
                );
            }
            assert_eq!(reassembler.active_len(), 0);

            let mut conflict = encoded.frames()[0].as_slice().to_vec();
            let last = conflict.len() - 1;
            conflict[last] ^= 1;
            let before_packets: i64 = rusqlite::Connection::open(&path)
                .unwrap()
                .query_row("SELECT count(*) FROM radio_packets", [], |row| row.get(0))
                .unwrap();
            persist_fragment_after_expiry(&mut store, &conflict);
            conflict_packet_id = before_packets + 1;
            assert_eq!(store.incomplete_profiles(10).unwrap().len(), 1);
        }

        for restart in 0..2 {
            let mut store = TelemetryStore::open(&path).unwrap();
            reconcile_pending_profiles(
                &mut store,
                &mut ProfileReassembler::default(),
                &mut Vec::new(),
                &mut Vec::new(),
                OutputFormat::JsonLines,
            )
            .unwrap();
            assert!(store.incomplete_profiles(10).unwrap().is_empty());
            drop(store);

            let connection = rusqlite::Connection::open(&path).unwrap();
            let state: (i64, i64, i64, String) = connection
                .query_row(
                    "SELECT count(*), sum(conflicting_fragment_count),
                            sum(json_extract(record_json, '$.conflicting_fragment_count')),
                            (SELECT reassembly_status FROM v2_packet_decodes
                             WHERE packet_id = ?1)
                     FROM v2_profile_scans",
                    [conflict_packet_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
            assert_eq!(state, (1, 1, 1, "conflict".to_owned()), "restart {restart}");
        }
        remove_database(&path);
    }

    #[test]
    fn late_conflict_emits_a_machine_readable_invalidation_event() {
        let key = vesta_receiver::reassembly::ProfileKey {
            node_id: 1,
            boot_id_valid: true,
            boot_id: 2,
            scan_sequence: 3,
            uptime_ms: 4,
            config_id: 5,
        };
        let mut output = Vec::new();
        write_profile_integrity_update(&mut output, OutputFormat::JsonLines, key, 6, 2).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(value["receiver_event"], "profile_integrity_update");
        assert_eq!(value["node_id"], "0000000000000001");
        assert_eq!(value["boot_id_valid"], true);
        assert_eq!(value["scan_start_uptime_ms"], "4");
        assert_eq!(value["source_packet_id"], 6);
        assert_eq!(value["fragment_index"], 2);
        assert_eq!(value["usable_for_analysis"], false);
    }
}
