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
#[cfg(target_os = "linux")]
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use vesta_protocol::{DecodedTelemetry, ProtocolDecodeError};
use vesta_receiver::database::{
    FragmentStorageStatus, PacketDisposition, StorageError, TelemetryStore, V2PacketKind,
};
#[cfg(target_os = "linux")]
use vesta_receiver::reassembly::{
    FragmentEvent, ProfileReassembler, ReassemblyError, SourceFragment, device_configuration,
    device_health,
};
use vesta_receiver::{HexError, OutputFormat, V2RenderError, parse_payload_hex, render, render_v2};
#[cfg(target_os = "linux")]
use vesta_receiver::{render_reassembled_profile, render_received, sx1262};

#[cfg(target_os = "linux")]
const PROFILE_REASSEMBLY_TIMEOUT_MS: i64 = 120_000;

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
    let mut radio = sx1262::Sx1262Hat::open().map_err(AppError::Radio)?;
    let mut reassembler = ProfileReassembler::default();
    write_listen_startup(diagnostics, database_path)?;

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

        persist_expired_profiles(
            &mut database,
            &mut reassembler,
            output,
            diagnostics,
            format,
            unix_ms()?.saturating_sub(PROFILE_REASSEMBLY_TIMEOUT_MS),
        )?;
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
            let result = reassembler.ingest(
                fragment,
                SourceFragment {
                    packet_id: stored_packet.id,
                    fragment_index: header.fragment_index,
                    received_at_unix_ms: stored_packet.received_at_unix_ms,
                    radio: packet.metadata,
                },
            )?;
            if let Some(evicted) = result.evicted {
                persist_profile(database, &evicted, output, diagnostics, format)?;
            }
            match result.event {
                FragmentEvent::Pending(progress) => {
                    writeln!(
                        diagnostics,
                        "v2 profile {:016x}/{:016x}/{} pending fragments 0x{:x}",
                        progress.key.node_id,
                        progress.key.boot_id,
                        progress.key.scan_sequence,
                        progress.missing_fragment_bitmap,
                    )
                    .map_err(AppError::Io)?;
                }
                FragmentEvent::Complete(profile) => {
                    persist_profile(database, &profile, output, diagnostics, format)?;
                }
                FragmentEvent::Duplicate { fragment_index, .. } => {
                    database
                        .mark_fragment_status(stored_packet.id, FragmentStorageStatus::Duplicate)
                        .map_err(AppError::Database)?;
                    writeln!(
                        diagnostics,
                        "v2 profile duplicate fragment {fragment_index} in packet {}",
                        stored_packet.id
                    )
                    .map_err(AppError::Io)?;
                }
                FragmentEvent::Conflict { fragment_index, .. } => {
                    database
                        .mark_fragment_status(stored_packet.id, FragmentStorageStatus::Conflict)
                        .map_err(AppError::Database)?;
                    writeln!(
                        diagnostics,
                        "v2 profile conflicting fragment {fragment_index} in packet {}",
                        stored_packet.id
                    )
                    .map_err(AppError::Io)?;
                }
            }
        }
    }
    output.flush().map_err(AppError::Io)?;
    Ok(PacketOutcome::ValidV2)
}

#[cfg(target_os = "linux")]
fn persist_expired_profiles(
    database: &mut TelemetryStore,
    reassembler: &mut ProfileReassembler,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
    cutoff_unix_ms: i64,
) -> Result<(), AppError> {
    for profile in reassembler.expire_before(cutoff_unix_ms) {
        persist_profile(database, &profile, output, diagnostics, format)?;
    }
    Ok(())
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
fn unix_ms() -> Result<i64, AppError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(AppError::Clock)?;
    i64::try_from(elapsed.as_millis()).map_err(|_| AppError::ClockOutOfRange)
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
    Clock(std::time::SystemTimeError),
    #[cfg(target_os = "linux")]
    ClockOutOfRange,
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
            Self::Clock(error) => write!(formatter, "system clock error: {error}"),
            #[cfg(target_os = "linux")]
            Self::ClockOutOfRange => formatter.write_str("system timestamp is out of range"),
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
