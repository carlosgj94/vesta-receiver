use std::io::Write;
use std::process::{Command, Stdio};

const FIXTURE: &str = "565301b001020304050607080a0b0c0dfb2e00018bcd0000b26e000f12060007eed00005902075300200080203040506";
const CONFIG_V2: &str = "565302013003000100b701020304050607081112131415161718ffffffff212223242526272896392f014bce77450005010302030401a0a1a2a3a4a5a6a76101760205010008030100637300017c1c0000a27600a331ea100100020a03ff01b0b1b2b3b4b5b6b70000ea6000100533be27a005070001e848040500080001001424e70300c800021e920120604000dc00043d240221614100f000065bb603226242010400087a48042363430118000a98da05246444012c000cb76c062565450140000ed5fe0726664601540010f4900827674701680013132209286848017c001531b40a296949";

fn receiver() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vesta-receiver"))
}

#[test]
fn decodes_one_frame_for_humans() {
    let output = receiver()
        .args(["decode", FIXTURE])
        .output()
        .expect("receiver should start");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("output should be UTF-8");
    assert!(stdout.contains("node_id: 0x0102030405060708"));
    assert!(stdout.contains("temperature: -12.34 deg C"));
    assert!(stdout.contains("temperature_adc: 519888"));
    assert!(output.stderr.is_empty());
}

#[test]
fn emits_exact_jsonl_units() {
    let output = receiver()
        .args(["decode", FIXTURE, "--output", "jsonl"])
        .output()
        .expect("receiver should start");

    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be JSON");
    assert_eq!(value["node_id"], "0102030405060708");
    assert_eq!(value["corrected"]["temperature_centi_celsius"], -1_234);
    assert_eq!(value["raw"]["gas_resistance_adc"], 512);
}

#[test]
fn streams_valid_frames_and_reports_bad_lines() {
    let mut child = receiver()
        .args(["decode", "--stdin", "--output", "jsonl"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("receiver should start");

    let mut input = child.stdin.take().expect("stdin should be piped");
    writeln!(input, "{FIXTURE}").expect("fixture should be writable");
    writeln!(input).expect("blank line should be writable");
    writeln!(input, "not-hex").expect("bad line should be writable");
    drop(input);

    let output = child.wait_with_output().expect("receiver should exit");
    assert!(!output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("output should be UTF-8");
    assert_eq!(stdout.lines().count(), 1);
    assert!(stdout.contains("\"node_id\":\"0102030405060708\""));

    let stderr = String::from_utf8(output.stderr).expect("diagnostics should be UTF-8");
    assert!(stderr.contains("line 3: odd hexadecimal length"));
    assert!(stderr.contains("1 input frame(s) could not be decoded"));
}

#[test]
fn rejects_protocol_errors_with_nonzero_status() {
    let mut unsupported = FIXTURE.as_bytes().to_vec();
    unsupported[5] = b'9';
    let unsupported = String::from_utf8(unsupported).expect("fixture should remain UTF-8");

    let output = receiver()
        .args(["decode", &unsupported])
        .output()
        .expect("receiver should start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("diagnostics should be UTF-8");
    assert!(stderr.contains("unsupported frame version: 9"));
}

#[test]
fn decodes_v2_golden_configuration_with_exact_identifiers() {
    let output = receiver()
        .args(["decode", CONFIG_V2, "--output", "jsonl"])
        .output()
        .expect("receiver should start");

    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be JSON");
    assert_eq!(value["protocol_version"], 2);
    assert_eq!(value["frame_type"], "device_config");
    assert_eq!(value["record"]["identity"]["boot_id"], "1112131415161718");
    assert_eq!(value["record"]["identity"]["config_id"], "96392f014bce7745");
    assert_eq!(value["record"]["output_routes"], 5);
    assert_eq!(
        value["record"]["heater_steps"].as_array().unwrap().len(),
        10
    );
}

#[test]
fn help_exposes_rx_only_listen_command() {
    let output = receiver()
        .arg("--help")
        .output()
        .expect("receiver should start");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("output should be UTF-8");
    assert!(stdout.contains("listen"));
    assert!(stdout.contains("Waveshare SX1262 HAT"));
}

#[test]
fn listen_help_documents_default_database() {
    let output = receiver()
        .args(["listen", "--help"])
        .output()
        .expect("receiver should start");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("output should be UTF-8");
    assert!(stdout.contains("--database"));
    assert!(stdout.contains("data/vesta-telemetry.sqlite3"));
    assert!(stdout.contains("every PHY-valid radio packet"));
}

#[test]
fn rejects_zero_listen_duration_before_accessing_hardware() {
    let output = receiver()
        .args(["listen", "--duration", "0"])
        .output()
        .expect("receiver should start");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("diagnostics should be UTF-8");
    assert!(stderr.contains("0 is not in 1..=86400"));
}

#[cfg(target_os = "linux")]
#[test]
fn reports_output_flush_failures() {
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("Linux should provide /dev/full");
    let output = receiver()
        .args(["decode", FIXTURE])
        .stdout(Stdio::from(full))
        .stderr(Stdio::piped())
        .output()
        .expect("receiver should start");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("diagnostics should be UTF-8");
    assert!(stderr.contains("could not flush output"));
}
