use std::fmt;
use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use vesta_receiver::{OutputFormat, TextDecodeError, decode_hex, render};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Decode Vesta environmental telemetry",
    long_about = "Decode Vesta environmental telemetry from captured hexadecimal payloads. Raspberry Pi SX1262 reception will be added as a separate backend."
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

    match run(cli, stdin.lock(), &mut output, &mut diagnostics) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(diagnostics, "error: {error}");
            ExitCode::FAILURE
        }
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
    }
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
    StreamFailures { count: usize },
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFrame => formatter.write_str("a hexadecimal frame or --stdin is required"),
            Self::Decode(error) => error.fmt(formatter),
            Self::Json(error) => write!(formatter, "could not serialize frame: {error}"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::StreamFailures { count } => {
                write!(formatter, "{count} input frame(s) could not be decoded")
            }
        }
    }
}

impl std::error::Error for AppError {}
