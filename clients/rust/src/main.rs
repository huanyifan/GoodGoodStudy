use config::{Profile, Result};
use goodgoodstudy::{app, config, load_profile, platform, save_profile};
use std::{fs, path::Path};
use zeroize::Zeroizing;

fn print_trace(event: serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string(&event).expect("serializable trace")
    );
}
fn debug_crypto(bridge: &str) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let device = uuid::Uuid::new_v4().to_string();
    let session = config::Session::new(&device);
    session.trace_handshake(Some(&mut print_trace));
    let mut child = Command::new("python")
        .args(["-B", bridge])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| "Python crypto bridge unavailable")?;
    let request = serde_json::to_vec(&session.request).map_err(|_| "invalid handshake")?;
    child
        .stdin
        .take()
        .ok_or("bridge stdin unavailable")?
        .write_all(&request)
        .map_err(|_| "bridge handshake write failed")?;
    let output = child
        .wait_with_output()
        .map_err(|_| "crypto bridge failed")?;
    if !output.status.success() || output.stdout.len() > 131072 {
        return Err("crypto bridge failed");
    }
    let response: config::Response =
        serde_json::from_slice(&output.stdout).map_err(|_| "invalid bridge response")?;
    let c = session.decrypt_with_trace(&response, Some(&mut print_trace))?;
    if c.interval_seconds != 42 || c.batch_size != 3 || c.mail.enabled {
        return Err("synthetic configuration mismatch");
    }
    for field in ["mac", "iv", "ciphertext", "serverNonce"] {
        let mut value = serde_json::to_value(&response).map_err(|_| "invalid response")?;
        let target = if field == "serverNonce" {
            &mut value[field]
        } else {
            &mut value["payload"][field]
        };
        let mut bytes = B64
            .decode(target.as_str().ok_or("invalid envelope")?)
            .map_err(|_| "invalid envelope")?;
        bytes[0] ^= 1;
        *target = serde_json::Value::String(B64.encode(bytes));
        let modified: config::Response =
            serde_json::from_value(value).map_err(|_| "invalid response")?;
        let error = session
            .decrypt(&modified)
            .err()
            .ok_or("tampering was accepted")?;
        print_trace(
            serde_json::json!({"side":"test", "step":"tamper_rejected", "field":field, "reason":error}),
        );
    }
    let other = config::Session::new(&device);
    let error = other
        .decrypt(&response)
        .err()
        .ok_or("cross-session replay accepted")?;
    print_trace(
        serde_json::json!({"side":"test", "step":"cross_session_replay_rejected", "reason":error}),
    );
    println!("Local Rust/Python encryption round-trip and five negative checks passed; no screenshots or email.");
    Ok(())
}

fn run(args: &[String]) -> Result<()> {
    let root = platform::state_dir()?;
    fs::create_dir_all(&root).map_err(|_| "state directory unavailable")?;
    if let Some(command) = args.first() {
        match command.as_str() {
            "--debug-crypto" => {
                if args.len() != 2 {
                    return Err("expected Python server/crypto_debug.py path");
                }
                return debug_crypto(&args[1]);
            }
            "--debug-config" => {
                if args.len() > 2 {
                    return Err("invalid arguments");
                }
                let address = args.get(1).map(String::as_str).unwrap_or(config::ENDPOINT);
                config::fetch_with_trace(address, &load_profile(&root)?, Some(&mut print_trace))?;
                println!("Live HTTPS/ECDH trace passed; no screenshots or email.");
                return Ok(());
            }
            "--stop-instance" => {
                if args.len() != 1 {
                    return Err("invalid arguments");
                }
                platform::stop_existing(20000)?;
                println!("GoodGoodStudy instance stopped or not running.");
                return Ok(());
            }
            "--create-profile" => {
                if args.len() != 2 || root.join("device-profile.dpapi").exists() {
                    return Err("profile already exists or invalid arguments");
                }
                let p = Profile::create();
                let json =
                    Zeroizing::new(serde_json::to_vec(&p).map_err(|_| "invalid credential")?);
                platform::private_write(Path::new(&args[1]), &json)?;
                save_profile(&root, &p)?;
                println!("Device credential created; enroll its hash on the server.");
                return Ok(());
            }
            "--import-profile" => {
                if !(args.len() == 2 || (args.len() == 3 && args[2] == "--replace"))
                    || (root.join("device-profile.dpapi").exists() && args.len() != 3)
                {
                    return Err("profile exists or invalid arguments");
                }
                let path = Path::new(&args[1]);
                if fs::metadata(path).map_err(|_| "profile unavailable")?.len() > 4096 {
                    return Err("profile too large");
                }
                let b = Zeroizing::new(fs::read(path).map_err(|_| "profile unavailable")?);
                let p: Profile = serde_json::from_slice(&b).map_err(|_| "invalid credential")?;
                save_profile(&root, &p)?;
                println!(
                    "Device credential imported with DPAPI; no session encryption key stored."
                );
                return Ok(());
            }
            "--export-profile" => {
                if args.len() != 2 {
                    return Err("invalid arguments");
                }
                let p = load_profile(&root)?;
                let b = Zeroizing::new(serde_json::to_vec(&p).map_err(|_| "invalid credential")?);
                return platform::private_write(Path::new(&args[1]), &b);
            }
            "--convert-ini" => {
                if args.len() != 3 {
                    return Err("invalid arguments");
                }
                if fs::metadata(&args[1]).map_err(|_| "INI unavailable")?.len() > 65536 {
                    return Err("INI too large");
                }
                let b =
                    Zeroizing::new(fs::read_to_string(&args[1]).map_err(|_| "INI unavailable")?);
                let c = config::parse_ini(&b)?;
                let out =
                    Zeroizing::new(serde_json::to_vec(&c).map_err(|_| "invalid configuration")?);
                platform::private_write(Path::new(&args[2]), &out)?;
                println!("Private server configuration written; keep outside public web root.");
                return Ok(());
            }
            "--check-config" => {
                if args.len() > 2 {
                    return Err("invalid arguments");
                }
                let address = args.get(1).map(String::as_str).unwrap_or(config::ENDPOINT);
                config::fetch(address, &load_profile(&root)?)?;
                println!("Rust HTTPS/ECDH configuration validated; no screenshots or email.");
                return Ok(());
            }
            _ => {}
        }
    }
    let address = if args.is_empty() {
        config::ENDPOINT
    } else if args.len() == 2 && args[0] == "--config-url" {
        &args[1]
    } else {
        return Err("invalid arguments");
    };
    app::run(address, &root)
}
fn main() {
    if let Err(error) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        if let Ok(root) = platform::state_dir() {
            app::log(&root, error);
        }
        if std::env::args()
            .nth(1)
            .is_some_and(|arg| matches!(arg.as_str(), "--debug-config" | "--debug-crypto"))
        {
            print_trace(
                serde_json::json!({"side":"client", "step":"debug_failed", "reason":error}),
            );
        }
        eprintln!("GoodGoodStudy stopped; check device profile, HTTPS configuration and logs.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_dpapi_and_private_export() {
        let root =
            std::env::temp_dir().join(format!("ggs-rust-profile-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let p = Profile::create();
        save_profile(&root, &p).unwrap();
        let loaded = load_profile(&root).unwrap();
        assert!(loaded.access_token == p.access_token);
        let data = fs::read(root.join("device-profile.dpapi")).unwrap();
        assert!(!data
            .windows(p.access_token.len())
            .any(|part| part == p.access_token.as_bytes()));
        assert!(!root.join("config-key.dpapi").exists());
        let export = root.join("private.json");
        platform::private_write(&export, b"test").unwrap();
        assert!(platform::private_write(&export, b"overwrite").is_err());
        assert!(platform::sid().unwrap().starts_with("S-1-"));
        assert!(root.starts_with(std::env::temp_dir()));
        fs::remove_dir_all(root).unwrap();
    }
}
