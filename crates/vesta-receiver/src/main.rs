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
use vesta_receiver::database::{PacketDisposition, StorageError, TelemetryStore};
use vesta_receiver::{OutputFormat, TextDecodeError, decode_hex, render};
#[cfg(target_os = "linux")]
use vesta_receiver::{render_received, sx1262};

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
        /// One complete 48-byte frame encoded as 96 hexadecimal characters.
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
                match store_packet(&mut database, &packet, output, diagnostics, format)? {
                    PacketOutcome::ValidV1 => valid_frames += 1,
                    PacketOutcome::Unsupported => unsupported_packets += 1,
                    PacketOutcome::InvalidV1 => protocol_errors += 1,
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
    }

    writeln!(
        diagnostics,
        "listen stopped: valid_v1={valid_frames}, unsupported={unsupported_packets}, header_errors={header_errors}, crc_errors={crc_errors}, protocol_errors={protocol_errors}"
    )
    .map_err(AppError::Io)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketOutcome {
    ValidV1,
    Unsupported,
    InvalidV1,
}

#[cfg(target_os = "linux")]
fn store_packet(
    database: &mut TelemetryStore,
    packet: &sx1262::RadioPacket,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    format: OutputFormat,
) -> Result<PacketOutcome, AppError> {
    let is_v1_candidate = packet.payload.len() == vesta_protocol::FRAME_LEN
        && packet.payload.get(2) == Some(&vesta_protocol::VERSION);
    if !is_v1_candidate {
        let stored = database
            .archive_packet(
                &packet.payload,
                packet.metadata,
                PacketDisposition::Unsupported,
                None,
            )
            .map_err(AppError::Database)?;
        writeln!(
            diagnostics,
            "database: archived unsupported packet {} ({} bytes)",
            stored.id,
            packet.payload.len(),
        )
        .map_err(AppError::Io)?;
        return Ok(PacketOutcome::Unsupported);
    }

    let frame = match vesta_protocol::TelemetryV1::decode(&packet.payload) {
        Ok(frame) => frame,
        Err(error) => {
            let decode_error = error.to_string();
            let stored = database
                .archive_packet(
                    &packet.payload,
                    packet.metadata,
                    PacketDisposition::Invalid,
                    Some(&decode_error),
                )
                .map_err(AppError::Database)?;
            writeln!(
                diagnostics,
                "database: archived invalid v1 packet {}: {error}",
                stored.id
            )
            .map_err(AppError::Io)?;
            return Ok(PacketOutcome::InvalidV1);
        }
    };

    let stored = database
        .insert_received_v1(&frame, &packet.payload, packet.metadata)
        .map_err(AppError::Database)?;
    let rendered = render_received(&frame, format, packet.metadata).map_err(AppError::Json)?;
    writeln!(output, "{rendered}").map_err(AppError::Io)?;
    output.flush().map_err(AppError::Io)?;
    writeln!(
        diagnostics,
        "database: stored reading {} from packet {} at {} ms",
        stored.id,
        stored
            .radio_packet_id
            .expect("live v1 insert always archives its packet"),
        stored.received_at_unix_ms
    )
    .map_err(AppError::Io)?;
    Ok(PacketOutcome::ValidV1)
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

        match decode_hex(frame) {
            Ok(frame) => write_decoded_frame(output, &frame, format)?,
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
    let frame = decode_hex(encoded).map_err(AppError::Decode)?;
    write_decoded_frame(output, &frame, format)
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
    Decode(TextDecodeError),
    Json(serde_json::Error),
    Io(io::Error),
    Database(StorageError),
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
            Self::Decode(error) => error.fmt(formatter),
            Self::Json(error) => write!(formatter, "could not serialize frame: {error}"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Database(error) => write!(formatter, "database error: {error}"),
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
