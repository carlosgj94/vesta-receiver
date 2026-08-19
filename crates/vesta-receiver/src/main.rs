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
    FragmentStorageStatus, PacketDisposition, PersistedFragmentMatch, StorageError, TelemetryStore,
    V2PacketKind,
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
    let (header, kind) = match frame {
        vesta_protocol::v2::DecodedFrame::DeviceConfig { header, .. } => {
            (header, V2PacketKind::DeviceConfig)
        }
        vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) => {
            (fragment.header, V2PacketKind::ProfileFragment)
        }
        vesta_protocol::v2::DecodedFrame::DeviceHealth { header, .. } => {
            (header, V2PacketKind::DeviceHealth)
        }
    };
    let stored_packet = database
        .archive_v2_packet(&packet.payload, packet.metadata, header, kind)
        .map_err(AppError::Database)?;

    match frame {
        vesta_protocol::v2::DecodedFrame::DeviceConfig { header, config } => {
            let configuration = device_configuration(header, config);
            let stored = database
                .insert_device_configuration(&configuration, Some(stored_packet.id))
                .map_err(AppError::Database)?;
            let rendered = render_v2(frame, format, Some(packet.metadata))?;
            writeln!(output, "{rendered}").map_err(AppError::Io)?;
            writeln!(
                diagnostics,
                "database: stored v2 configuration {} from packet {}",
                stored.id, stored_packet.id
            )
            .map_err(AppError::Io)?;
        }
        vesta_protocol::v2::DecodedFrame::DeviceHealth { header, health } => {
            let health = device_health(header, health);
            let stored = database
                .insert_device_health(&health, Some(stored_packet.id))
                .map_err(AppError::Database)?;
            let rendered = render_v2(frame, format, Some(packet.metadata))?;
            writeln!(output, "{rendered}").map_err(AppError::Io)?;
            writeln!(
                diagnostics,
                "database: stored v2 health {} from packet {}",
                stored.id, stored_packet.id
            )
            .map_err(AppError::Io)?;
        }
        vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) => {
            ingest_archived_profile_fragment(
                database,
                reassembler,
                fragment,
                SourceFragment {
                    packet_id: stored_packet.id,
                    fragment_index: header.fragment_index,
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
    let pending = database
        .pending_profile_fragments(MAX_STARTUP_PENDING_FRAGMENTS)
        .map_err(AppError::Database)?;
    if pending.is_empty() {
        return Ok(());
    }

    let replay_started = Instant::now();
    let pending_count = pending.len();
    for (ordinal, archived) in pending.into_iter().enumerate() {
        let decoded = vesta_protocol::v2::decode(&archived.payload).map_err(|error| {
            AppError::PendingReplayDecode {
                packet_id: archived.packet_id,
                error,
            }
        })?;
        let vesta_protocol::v2::DecodedFrame::ProfileFragment(fragment) = decoded else {
            return Err(AppError::PendingReplayWrongType {
                packet_id: archived.packet_id,
            });
        };
        let observed_at = replay_started
            .checked_add(Duration::from_nanos(
                u64::try_from(ordinal).unwrap_or(u64::MAX),
            ))
            .unwrap_or(replay_started);
        ingest_archived_profile_fragment(
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
        )?;
    }
    writeln!(
        diagnostics,
        "database: reconciled {pending_count} pending v2 profile fragment(s) at startup"
    )
    .map_err(AppError::Io)
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
        .reconcile_completed_profile_fragment(key, source.packet_id, source.fragment_index, payload)
        .map_err(AppError::Database)?
    {
        let classification = match classification {
            PersistedFragmentMatch::Duplicate => "duplicate",
            PersistedFragmentMatch::Conflict => {
                write_profile_integrity_update(
                    output,
                    format,
                    key,
                    source.packet_id,
                    source.fragment_index,
                )?;
                "conflict"
            }
        };
        writeln!(
            diagnostics,
            "v2 profile persisted {classification} fragment {} in packet {}",
            source.fragment_index, source.packet_id
        )
        .map_err(AppError::Io)?;
        return Ok(());
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
    if let Some(evicted) = result.evicted {
        persist_profile(database, &evicted, output, diagnostics, format)?;
    }
    match result.event {
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
            database
                .mark_fragment_status(packet_id, FragmentStorageStatus::Duplicate)
                .map_err(AppError::Database)?;
            writeln!(
                diagnostics,
                "v2 profile duplicate fragment {fragment_index} in packet {packet_id}"
            )
            .map_err(AppError::Io)
        }
        FragmentEvent::Conflict { fragment_index, .. } => {
            database
                .mark_fragment_status(packet_id, FragmentStorageStatus::Conflict)
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
    #[cfg(target_os = "linux")]
    PendingReplayDecode {
        packet_id: i64,
        error: vesta_protocol::v2::Error,
    },
    #[cfg(target_os = "linux")]
    PendingReplayWrongType {
        packet_id: i64,
    },
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
            #[cfg(target_os = "linux")]
            Self::PendingReplayDecode { packet_id, error } => {
                write!(
                    formatter,
                    "pending profile packet {packet_id} no longer decodes: {error}"
                )
            }
            #[cfg(target_os = "linux")]
            Self::PendingReplayWrongType { packet_id } => write!(
                formatter,
                "pending profile packet {packet_id} decodes as another frame type"
            ),
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
                    .archive_v2_packet(
                        payload,
                        radio_metadata(),
                        fragment.header,
                        V2PacketKind::ProfileFragment,
                    )
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
                .contains("reconciled 2 pending v2 profile fragment")
        );
        drop(after_restart);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite3-shm"));
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
