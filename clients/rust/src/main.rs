mod app;
mod config;
mod platform;
use config::{Profile, Result};
use std::{fs, path::Path};
use zeroize::Zeroizing;

fn load_profile(root: &Path) -> Result<Profile> {
    let encrypted =
        fs::read(root.join("device-profile.dpapi")).map_err(|_| "import device profile first")?;
    let plain = Zeroizing::new(platform::dpapi(&encrypted, true)?);
    let p: Profile = serde_json::from_slice(&plain).map_err(|_| "invalid credential")?;
    p.validate()?;
    Ok(p)
}
fn save_profile(root: &Path, p: &Profile) -> Result<()> {
    p.validate()?;
    let plain = Zeroizing::new(serde_json::to_vec(p).map_err(|_| "invalid credential")?);
    let protected = platform::dpapi(&plain, false)?;
    platform::atomic_write(&root.join("device-profile.dpapi"), &protected)
}
fn run(args: &[String]) -> Result<()> {
    let root = platform::state_dir()?;
    fs::create_dir_all(&root).map_err(|_| "state directory unavailable")?;
    if let Some(command) = args.first() {
        match command.as_str() {
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
    if run(&std::env::args().skip(1).collect::<Vec<_>>()).is_err() {
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
