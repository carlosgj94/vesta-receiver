//! Receive-only driver for the Waveshare SX1262 868/915 MHz HAT.
//!
//! This module intentionally contains no transmit opcode or transmit-facing
//! API. BCM6 remains high for the lifetime of [`Sx1262Hat`], which preserves
//! the HAT's documented receive RF-switch state.

use std::fmt;
use std::thread;
use std::time::{Duration, Instant};

use rppal::gpio::{Gpio, InputPin, Level, OutputPin, Trigger};
use rppal::spi::{Bus, Mode, SlaveSelect, Spi};

use crate::RadioMetadata;

/// Configured `LoRa` center frequency.
pub const FREQUENCY_HZ: u32 = 868_100_000;
/// Configured `LoRa` spreading factor.
pub const SPREADING_FACTOR: u8 = 7;
/// Configured `LoRa` bandwidth in hertz.
pub const BANDWIDTH_HZ: u32 = 125_000;
/// Maximum application payload accepted by the SX1262 in explicit-header mode.
pub const MAX_PAYLOAD_LEN: usize = 255;

const GPIO_RF_RX: u8 = 6;
const GPIO_RESET: u8 = 18;
const GPIO_NSS: u8 = 21;
const GPIO_BUSY: u8 = 20;
const GPIO_DIO1: u8 = 16;

const SPI_SPEED_HZ: u32 = 500_000;
const BUSY_TIMEOUT: Duration = Duration::from_secs(1);
const BUSY_POLL_INTERVAL: Duration = Duration::from_micros(100);
const NSS_SETTLE_TIME: Duration = Duration::from_micros(10);

const OP_SET_STANDBY: u8 = 0x80;
const OP_SET_RX: u8 = 0x82;
const OP_SET_PACKET_TYPE: u8 = 0x8a;
const OP_SET_RF_FREQUENCY: u8 = 0x86;
const OP_SET_BUFFER_BASE_ADDRESS: u8 = 0x8f;
const OP_SET_MODULATION_PARAMS: u8 = 0x8b;
const OP_SET_PACKET_PARAMS: u8 = 0x8c;
const OP_SET_DIO_IRQ_PARAMS: u8 = 0x08;
const OP_GET_IRQ_STATUS: u8 = 0x12;
const OP_CLEAR_IRQ_STATUS: u8 = 0x02;
const OP_GET_RX_BUFFER_STATUS: u8 = 0x13;
const OP_GET_PACKET_STATUS: u8 = 0x14;
const OP_GET_STATUS: u8 = 0xc0;
const OP_GET_PACKET_TYPE: u8 = 0x11;
const OP_GET_DEVICE_ERRORS: u8 = 0x17;
const OP_CALIBRATE_IMAGE: u8 = 0x98;
const OP_SET_REGULATOR_MODE: u8 = 0x96;
const OP_SET_DIO2_AS_RF_SWITCH: u8 = 0x9d;
const OP_SET_STOP_RX_TIMER_ON_PREAMBLE: u8 = 0x9f;
const OP_SET_LORA_SYMBOL_TIMEOUT: u8 = 0xa0;
const OP_WRITE_REGISTER: u8 = 0x0d;
const OP_READ_REGISTER: u8 = 0x1d;
const OP_READ_BUFFER: u8 = 0x1e;

const PACKET_TYPE_LORA: u8 = 0x01;
const STANDBY_RC: u8 = 0x00;
const REGULATOR_LDO: u8 = 0x00;
const RX_CONTINUOUS: [u8; 3] = [0xff, 0xff, 0xff];

const IRQ_RX_DONE: u16 = 0x0002;
const IRQ_HEADER_ERROR: u16 = 0x0020;
const IRQ_CRC_ERROR: u16 = 0x0040;
const IRQ_RX_TX_TIMEOUT: u16 = 0x0200;
const IRQ_TERMINAL_MASK: u16 = IRQ_RX_DONE | IRQ_HEADER_ERROR | IRQ_CRC_ERROR | IRQ_RX_TX_TIMEOUT;

const REGISTER_LORA_SYNC_WORD: u16 = 0x0740;
const REGISTER_IQ_POLARITY: u16 = 0x0736;
const REGISTER_RX_GAIN: u16 = 0x08ac;
const PRIVATE_SYNC_WORD: [u8; 2] = [0x14, 0x24];
const IQ_NORMAL_MASK: u8 = 1 << 2;
const RX_GAIN_POWER_SAVING: u8 = 0x94;

// floor(868_100_000 * 2^25 / 32_000_000), as specified by the SX1262.
const RF_FREQUENCY_WORD: u32 = 0x3641_9999;

/// One terminal receive event reported by the SX1262.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveEvent {
    /// One packet whose PHY header and CRC were accepted by the radio.
    Packet(RadioPacket),
    /// The radio rejected a malformed `LoRa` header.
    HeaderError {
        /// Complete IRQ bitmap observed for this event.
        irq: u16,
    },
    /// The radio rejected the packet's PHY CRC.
    CrcError {
        /// Complete IRQ bitmap observed for this event.
        irq: u16,
    },
    /// The radio reported an RX timeout.
    RadioTimeout {
        /// Complete IRQ bitmap observed for this event.
        irq: u16,
    },
    /// DIO1 fired without one of the configured terminal conditions.
    OtherIrq(u16),
}

/// A received raw `LoRa` packet and its signal measurements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RadioPacket {
    /// Bytes read from the SX1262 receive buffer.
    pub payload: Vec<u8>,
    /// Measurements reported for this packet.
    pub metadata: RadioMetadata,
}

/// Failure while controlling the Raspberry Pi HAT.
#[derive(Debug)]
pub enum RadioError {
    /// Raspberry Pi GPIO access failed.
    Gpio(rppal::gpio::Error),
    /// Raspberry Pi SPI access failed.
    Spi(rppal::spi::Error),
    /// SX1262 BUSY did not return low within the bounded wait.
    BusyTimeout,
    /// The SPI controller transferred fewer bytes than requested.
    ShortTransfer {
        /// Required transfer length.
        expected: usize,
        /// Length reported by the SPI controller.
        actual: usize,
    },
    /// The returned SX1262 status byte is electrically or structurally invalid.
    InvalidStatus {
        /// Command opcode associated with the read.
        opcode: u8,
        /// Returned status byte.
        status: u8,
    },
    /// The SX1262 reported a command timeout or processing/execution failure.
    CommandRejected {
        /// Command opcode that failed.
        opcode: u8,
        /// SX1262 status byte.
        status: u8,
    },
    /// Packet type readback did not report `LoRa` mode.
    UnexpectedPacketType(u8),
    /// Private `LoRa` sync-word readback did not match `0x1424`.
    SyncWordMismatch(u16),
    /// The SX1262 retained one or more device error flags after reset.
    DeviceErrors(u16),
    /// The radio did not enter the expected chip mode.
    UnexpectedMode {
        /// Expected mode bits from the status byte.
        expected: u8,
        /// Full observed status byte.
        status: u8,
    },
}

impl fmt::Display for RadioError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gpio(error) => write!(formatter, "GPIO access failed: {error}"),
            Self::Spi(error) => write!(formatter, "SPI access failed: {error}"),
            Self::BusyTimeout => formatter.write_str("SX1262 BUSY remained high for one second"),
            Self::ShortTransfer { expected, actual } => write!(
                formatter,
                "short SPI transfer: expected {expected} bytes, transferred {actual}"
            ),
            Self::InvalidStatus { opcode, status } => write!(
                formatter,
                "invalid SX1262 status byte 0x{status:02x} for command 0x{opcode:02x}"
            ),
            Self::CommandRejected { opcode, status } => write!(
                formatter,
                "SX1262 rejected command 0x{opcode:02x} with status 0x{status:02x}"
            ),
            Self::UnexpectedPacketType(packet_type) => write!(
                formatter,
                "SX1262 packet type readback was 0x{packet_type:02x}, not LoRa"
            ),
            Self::SyncWordMismatch(sync_word) => write!(
                formatter,
                "SX1262 sync-word readback was 0x{sync_word:04x}, expected 0x1424"
            ),
            Self::DeviceErrors(errors) => {
                write!(
                    formatter,
                    "SX1262 device error flags are set: 0x{errors:04x}"
                )
            }
            Self::UnexpectedMode { expected, status } => write!(
                formatter,
                "SX1262 mode mismatch: expected 0x{expected:02x}, status was 0x{status:02x}"
            ),
        }
    }
}

impl std::error::Error for RadioError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Gpio(error) => Some(error),
            Self::Spi(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rppal::gpio::Error> for RadioError {
    fn from(error: rppal::gpio::Error) -> Self {
        Self::Gpio(error)
    }
}

impl From<rppal::spi::Error> for RadioError {
    fn from(error: rppal::spi::Error) -> Self {
        Self::Spi(error)
    }
}

/// RX-only controller for a Waveshare SX1262 HAT on Raspberry Pi SPI0.
pub struct Sx1262Hat {
    spi: Spi,
    nss: OutputPin,
    reset: OutputPin,
    busy: InputPin,
    dio1: InputPin,
    // This field is never written low. Its lifetime enforces the HAT's RX state.
    rf_rx: OutputPin,
    initialized: bool,
}

impl Sx1262Hat {
    /// Claim the HAT pins, reset the radio, verify configuration readback, and
    /// enter continuous receive mode.
    ///
    /// # Errors
    ///
    /// Returns an error for missing permissions/devices, bounded BUSY timeout,
    /// SPI failure, rejected command, or mismatched radio readback.
    pub fn open() -> Result<Self, RadioError> {
        let gpio = Gpio::new()?;

        let mut rf_rx = gpio.get(GPIO_RF_RX)?.into_output_high();
        let mut reset = gpio.get(GPIO_RESET)?.into_output_high();
        let mut nss = gpio.get(GPIO_NSS)?.into_output_high();
        rf_rx.set_reset_on_drop(false);
        reset.set_reset_on_drop(false);
        nss.set_reset_on_drop(false);

        let busy = gpio.get(GPIO_BUSY)?.into_input_pulldown();
        let dio1 = gpio.get(GPIO_DIO1)?.into_input_pulldown();
        let spi = Spi::new(Bus::Spi0, SlaveSelect::Ss0, SPI_SPEED_HZ, Mode::Mode0)?;

        let mut radio = Self {
            spi,
            nss,
            reset,
            busy,
            dio1,
            rf_rx,
            initialized: false,
        };
        radio.hardware_reset()?;
        // From this point onward Drop can safely request standby, including if
        // a later configuration readback fails.
        radio.initialized = true;
        radio.configure_receive()?;
        Ok(radio)
    }

    /// Wait for at most `timeout` for one terminal receive event.
    ///
    /// A CRC or header error always takes precedence over `RxDone`; corrupt
    /// bytes are never read from the packet buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if GPIO polling or radio communication fails.
    pub fn poll_receive(&mut self, timeout: Duration) -> Result<Option<ReceiveEvent>, RadioError> {
        let interrupted = if self.dio1.read() == Level::High {
            true
        } else {
            self.dio1.poll_interrupt(false, Some(timeout))?.is_some()
        };
        if !interrupted {
            return Ok(None);
        }

        let irq = self.get_irq_status()?;
        let event_result = match classify_irq(irq) {
            IrqKind::HeaderError => Ok(ReceiveEvent::HeaderError { irq }),
            IrqKind::CrcError => Ok(ReceiveEvent::CrcError { irq }),
            IrqKind::Packet => self.read_packet().map(ReceiveEvent::Packet),
            IrqKind::Timeout => Ok(ReceiveEvent::RadioTimeout { irq }),
            IrqKind::Other => Ok(ReceiveEvent::OtherIrq(irq)),
        };

        let restart_result = self.restart_receive();
        let event = event_result?;
        restart_result?;
        Ok(Some(event))
    }

    fn hardware_reset(&mut self) -> Result<(), RadioError> {
        self.rf_rx.set_high();
        self.nss.set_high();
        self.reset.set_high();
        thread::sleep(Duration::from_millis(10));
        self.reset.set_low();
        thread::sleep(Duration::from_millis(1));
        self.reset.set_high();
        // BUSY can still read low briefly before the reset sequence asserts it.
        // Do not mistake that pre-assertion window for reset completion.
        thread::sleep(Duration::from_millis(10));
        self.wait_busy_low()?;

        let status = self.get_status()?;
        ensure_mode(status, 0x20)
    }

    fn configure_receive(&mut self) -> Result<(), RadioError> {
        self.command(&[OP_SET_STANDBY, STANDBY_RC])?;
        self.command(&[OP_SET_REGULATOR_MODE, REGULATOR_LDO])?;
        self.command(&[OP_SET_DIO2_AS_RF_SWITCH, 0x01])?;
        self.command(&[OP_SET_PACKET_TYPE, PACKET_TYPE_LORA])?;

        self.write_register(REGISTER_LORA_SYNC_WORD, &PRIVATE_SYNC_WORD)?;
        self.command(&[OP_SET_BUFFER_BASE_ADDRESS, 0x00, 0x00])?;
        self.command(&[OP_CALIBRATE_IMAGE, 0xd7, 0xdb])?;

        let frequency = RF_FREQUENCY_WORD.to_be_bytes();
        self.command(&[
            OP_SET_RF_FREQUENCY,
            frequency[0],
            frequency[1],
            frequency[2],
            frequency[3],
        ])?;

        // SF7, BW125, CR4/5, low-data-rate optimization disabled.
        self.command(&[OP_SET_MODULATION_PARAMS, 0x07, 0x04, 0x01, 0x00])?;
        // Preamble 8, explicit header, maximum payload, CRC, normal IQ. The
        // packet's actual length is reported by GetRxBufferStatus.
        self.command(&[OP_SET_PACKET_PARAMS, 0x00, 0x08, 0x00, u8::MAX, 0x01, 0x00])?;

        let iq_polarity = self.read_register(REGISTER_IQ_POLARITY, 1)?[0];
        self.write_register(REGISTER_IQ_POLARITY, &[iq_polarity | IQ_NORMAL_MASK])?;
        self.write_register(REGISTER_RX_GAIN, &[RX_GAIN_POWER_SAVING])?;

        self.command(&[OP_SET_STOP_RX_TIMER_ON_PREAMBLE, 0x01])?;
        self.command(&[OP_SET_LORA_SYMBOL_TIMEOUT, 0x00])?;

        let irq = IRQ_TERMINAL_MASK.to_be_bytes();
        self.command(&[
            OP_SET_DIO_IRQ_PARAMS,
            irq[0],
            irq[1],
            irq[0],
            irq[1],
            0x00,
            0x00,
            0x00,
            0x00,
        ])?;

        self.verify_readback()?;
        self.dio1.set_interrupt(Trigger::RisingEdge, None)?;
        let _ = self.dio1.poll_interrupt(true, Some(Duration::ZERO))?;
        self.clear_all_irq()?;
        self.enter_continuous_receive()
    }

    fn verify_readback(&mut self) -> Result<(), RadioError> {
        let packet_type = self.read_command(OP_GET_PACKET_TYPE, 1)?[0];
        if packet_type != PACKET_TYPE_LORA {
            return Err(RadioError::UnexpectedPacketType(packet_type));
        }

        let sync_word_bytes = self.read_register(REGISTER_LORA_SYNC_WORD, 2)?;
        let sync_word = u16::from_be_bytes([sync_word_bytes[0], sync_word_bytes[1]]);
        if sync_word != u16::from_be_bytes(PRIVATE_SYNC_WORD) {
            return Err(RadioError::SyncWordMismatch(sync_word));
        }

        let error_bytes = self.read_command(OP_GET_DEVICE_ERRORS, 2)?;
        let errors = u16::from_be_bytes([error_bytes[0], error_bytes[1]]);
        if errors != 0 {
            return Err(RadioError::DeviceErrors(errors));
        }
        Ok(())
    }

    fn read_packet(&mut self) -> Result<RadioPacket, RadioError> {
        let buffer_status = self.read_command(OP_GET_RX_BUFFER_STATUS, 2)?;
        let payload_length = usize::from(buffer_status[0]);
        let offset = buffer_status[1];
        let payload = self.read_buffer(offset, payload_length)?;

        let packet_status = self.read_command(OP_GET_PACKET_STATUS, 3)?;
        Ok(RadioPacket {
            payload,
            metadata: decode_packet_status([packet_status[0], packet_status[1], packet_status[2]]),
        })
    }

    fn restart_receive(&mut self) -> Result<(), RadioError> {
        self.clear_all_irq()?;
        self.enter_continuous_receive()
    }

    fn enter_continuous_receive(&mut self) -> Result<(), RadioError> {
        self.command(&[
            OP_SET_RX,
            RX_CONTINUOUS[0],
            RX_CONTINUOUS[1],
            RX_CONTINUOUS[2],
        ])?;
        Ok(())
    }

    fn get_status(&mut self) -> Result<u8, RadioError> {
        let received = self.transaction(&[OP_GET_STATUS, 0x00])?;
        let status = received[1];
        check_status(OP_GET_STATUS, status)?;
        Ok(status)
    }

    fn get_irq_status(&mut self) -> Result<u16, RadioError> {
        let bytes = self.read_command(OP_GET_IRQ_STATUS, 2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn clear_all_irq(&mut self) -> Result<(), RadioError> {
        self.command(&[OP_CLEAR_IRQ_STATUS, 0xff, 0xff])?;
        Ok(())
    }

    fn command(&mut self, command: &[u8]) -> Result<(), RadioError> {
        // SX1262 write commands do not include the explicit NOP/status phase
        // used by read commands. Completion is bounded by BUSY, while command
        // status and configuration are verified through subsequent reads.
        self.transaction(command)?;
        Ok(())
    }

    fn read_command(&mut self, opcode: u8, length: usize) -> Result<Vec<u8>, RadioError> {
        let mut command = vec![0_u8; length + 2];
        command[0] = opcode;
        let received = self.transaction(&command)?;
        check_status(opcode, received[1])?;
        Ok(received[2..].to_vec())
    }

    fn write_register(&mut self, address: u16, data: &[u8]) -> Result<(), RadioError> {
        let address = address.to_be_bytes();
        let mut command = Vec::with_capacity(data.len() + 3);
        command.extend_from_slice(&[OP_WRITE_REGISTER, address[0], address[1]]);
        command.extend_from_slice(data);
        self.command(&command)?;
        Ok(())
    }

    fn read_register(&mut self, address: u16, length: usize) -> Result<Vec<u8>, RadioError> {
        let address = address.to_be_bytes();
        let mut command = vec![0_u8; length + 4];
        command[0] = OP_READ_REGISTER;
        command[1] = address[0];
        command[2] = address[1];
        let received = self.transaction(&command)?;
        Ok(received[4..].to_vec())
    }

    fn read_buffer(&mut self, offset: u8, length: usize) -> Result<Vec<u8>, RadioError> {
        let mut command = vec![0_u8; length + 3];
        command[0] = OP_READ_BUFFER;
        command[1] = offset;
        let received = self.transaction(&command)?;
        Ok(received[3..].to_vec())
    }

    fn transaction(&mut self, outgoing: &[u8]) -> Result<Vec<u8>, RadioError> {
        self.wait_busy_low()?;
        let mut incoming = vec![0_u8; outgoing.len()];

        self.nss.set_low();
        thread::sleep(NSS_SETTLE_TIME);
        let transfer_result = self.spi.transfer(&mut incoming, outgoing);
        thread::sleep(NSS_SETTLE_TIME);
        self.nss.set_high();

        let transferred = transfer_result?;
        if transferred != outgoing.len() {
            return Err(RadioError::ShortTransfer {
                expected: outgoing.len(),
                actual: transferred,
            });
        }
        self.wait_busy_low()?;
        Ok(incoming)
    }

    fn wait_busy_low(&self) -> Result<(), RadioError> {
        let deadline = Instant::now() + BUSY_TIMEOUT;
        while self.busy.read() == Level::High {
            if Instant::now() >= deadline {
                return Err(RadioError::BusyTimeout);
            }
            thread::sleep(BUSY_POLL_INTERVAL);
        }
        Ok(())
    }
}

impl Drop for Sx1262Hat {
    fn drop(&mut self) {
        if self.initialized {
            let _ = self.command(&[OP_SET_STANDBY, STANDBY_RC]);
        }
        self.nss.set_high();
        self.reset.set_high();
        self.rf_rx.set_high();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IrqKind {
    HeaderError,
    CrcError,
    Packet,
    Timeout,
    Other,
}

const fn classify_irq(irq: u16) -> IrqKind {
    if irq & IRQ_HEADER_ERROR != 0 {
        IrqKind::HeaderError
    } else if irq & IRQ_CRC_ERROR != 0 {
        IrqKind::CrcError
    } else if irq & IRQ_RX_DONE != 0 {
        IrqKind::Packet
    } else if irq & IRQ_RX_TX_TIMEOUT != 0 {
        IrqKind::Timeout
    } else {
        IrqKind::Other
    }
}

fn check_status(opcode: u8, status: u8) -> Result<(), RadioError> {
    if status == 0x00 || status == 0xff {
        return Err(RadioError::InvalidStatus { opcode, status });
    }

    match status & 0x0e {
        0x06 | 0x08 | 0x0a => Err(RadioError::CommandRejected { opcode, status }),
        _ => Ok(()),
    }
}

fn ensure_mode(status: u8, expected: u8) -> Result<(), RadioError> {
    if status & 0x70 == expected {
        Ok(())
    } else {
        Err(RadioError::UnexpectedMode { expected, status })
    }
}

fn decode_packet_status(raw: [u8; 3]) -> RadioMetadata {
    RadioMetadata {
        packet_rssi_centi_dbm: -i16::from(raw[0]) * 50,
        snr_centi_db: i16::from(i8::from_ne_bytes([raw[1]])) * 25,
        signal_rssi_centi_dbm: -i16::from(raw[2]) * 50,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_flags_take_precedence_over_rx_done() {
        assert_eq!(
            classify_irq(IRQ_RX_DONE | IRQ_HEADER_ERROR),
            IrqKind::HeaderError
        );
        assert_eq!(classify_irq(IRQ_RX_DONE | IRQ_CRC_ERROR), IrqKind::CrcError);
        assert_eq!(classify_irq(IRQ_RX_DONE), IrqKind::Packet);
    }

    #[test]
    fn frequency_word_matches_868_100_mhz() {
        assert_eq!(RF_FREQUENCY_WORD.to_be_bytes(), [0x36, 0x41, 0x99, 0x99]);
    }

    #[test]
    fn packet_status_preserves_fractional_and_negative_snr() {
        assert_eq!(
            decode_packet_status([201, 0xfb, 205]),
            RadioMetadata {
                packet_rssi_centi_dbm: -10_050,
                snr_centi_db: -125,
                signal_rssi_centi_dbm: -10_250,
            }
        );
    }

    #[test]
    fn status_validation_rejects_electrical_and_command_errors() {
        assert!(matches!(
            check_status(OP_GET_STATUS, 0x00),
            Err(RadioError::InvalidStatus {
                opcode: OP_GET_STATUS,
                status: 0x00
            })
        ));
        assert!(matches!(
            check_status(OP_SET_RX, 0x26),
            Err(RadioError::CommandRejected {
                opcode: OP_SET_RX,
                status: 0x26
            })
        ));
        assert!(check_status(OP_GET_STATUS, 0x22).is_ok());
        assert!(check_status(OP_GET_PACKET_TYPE, 0xa2).is_ok());
    }
}
