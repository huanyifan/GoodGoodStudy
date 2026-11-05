use goodgoodstudy::{config::Profile, load_profile, platform, save_profile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{Cursor, Read},
    os::windows::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;
use zip::ZipArchive;

pub type Result<T> = std::result::Result<T, &'static str>;
pub const VERSION: &str = "3.2.2";
pub const PROFILE_ENTRY: &str = "provisioning/device-profile.json";
pub const FILES: &[&str] = &[
    "GoodGoodStudy.exe",
    "README.md",
    "LICENSE",
    "config.example.json",
    "Import-Profile.cmd",
    "Enable-Autostart.cmd",
    "Disable-Autostart.cmd",
    "Autostart-Status.cmd",
    "tools/Autostart.ps1",
    "tools/Convert-Ini.ps1",
    "tools/Install-Integration.ps1",
    "Uninstall.ps1",
];

#[derive(Deserialize, Serialize)]
pub struct Manifest {
    pub version: String,
    pub sha256: HashMap<String, String>,
}
pub struct Asset {
    pub name: String,
    pub bytes: Vec<u8>,
}
pub struct Payload {
    pub assets: Vec<Asset>,
    profile: Zeroizing<Vec<u8>>,
}
#[derive(Serialize)]
pub struct Verification {
    pub version: &'static str,
    pub files: usize,
    pub total_bytes: usize,
    pub credential_valid: bool,
    pub writes_plaintext_profile: bool,
    pub remote_config_verified: bool,
}
#[derive(Clone)]
pub struct Paths {
    pub app: PathBuf,
    pub state: PathBuf,
}
impl Paths {
    pub fn for_user(local_app_data: &Path) -> Result<Self> {
        if !local_app_data.is_absolute() {
            return Err("local application data path must be absolute");
        }
        Ok(Self {
            app: local_app_data.join("Programs/GoodGoodStudy"),
            state: local_app_data.join("GoodGoodStudy"),
        })
    }
}
fn bounded_read(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    name: &str,
    limit: usize,
) -> Result<Vec<u8>> {
    let mut entry = archive.by_name(name).map_err(|_| "payload entry missing")?;
    if entry.size() > limit as u64 || entry.is_dir() {
        return Err("payload entry invalid");
    }
    let mut bytes = Vec::new();
    entry
        .by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "payload read failed")?;
    if bytes.len() > limit {
        return Err("payload entry too large");
    }
    Ok(bytes)
}
impl Payload {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 32 * 1024 * 1024 {
            return Err("invalid payload size");
        }
        let mut archive =
            ZipArchive::new(Cursor::new(bytes)).map_err(|_| "payload is not a ZIP archive")?;
        let expected: HashSet<&str> = FILES
            .iter()
            .copied()
            .chain([PROFILE_ENTRY, "manifest.json"])
            .collect();
        if archive.len() != expected.len() {
            return Err("unexpected payload entries");
        }
        let mut names = HashSet::new();
        for index in 0..archive.len() {
            let entry = archive
                .by_index(index)
                .map_err(|_| "payload directory invalid")?;
            let name = entry.name().to_owned();
            if !expected.contains(name.as_str()) || !names.insert(name) {
                return Err("unsafe or duplicate payload entry");
            }
        }
        let manifest: Manifest =
            serde_json::from_slice(&bounded_read(&mut archive, "manifest.json", 16384)?)
                .map_err(|_| "invalid payload manifest")?;
        if manifest.version != VERSION || manifest.sha256.len() != FILES.len() + 1 {
            return Err("payload version or manifest invalid");
        }
        let mut assets = Vec::new();
        let mut profile = Zeroizing::new(Vec::new());
        let mut total = 0usize;
        for name in FILES.iter().copied().chain([PROFILE_ENTRY]) {
            let limit = if name == "GoodGoodStudy.exe" {
                16 * 1024 * 1024
            } else if name == PROFILE_ENTRY {
                4096
            } else {
                1024 * 1024
            };
            let data = bounded_read(&mut archive, name, limit)?;
            total += data.len();
            if total > 24 * 1024 * 1024 {
                return Err("expanded payload too large");
            }
            let actual = format!("{:x}", Sha256::digest(&data));
            if manifest.sha256.get(name) != Some(&actual) {
                return Err("payload checksum mismatch");
            }
            if name == PROFILE_ENTRY {
                *profile = data;
                let value: Profile =
                    serde_json::from_slice(&profile).map_err(|_| "invalid bundled credential")?;
                value.validate()?;
            } else {
                if name == "GoodGoodStudy.exe" && !data.starts_with(b"MZ") {
                    return Err("payload program is not a Windows executable");
                }
                assets.push(Asset {
                    name: name.to_owned(),
                    bytes: data,
                });
            }
        }
        Ok(Self { assets, profile })
    }
    pub fn verification(&self) -> Verification {
        Verification {
            version: VERSION,
            files: self.assets.len(),
            total_bytes: self.assets.iter().map(|asset| asset.bytes.len()).sum(),
            credential_valid: true,
            writes_plaintext_profile: false,
            remote_config_verified: false,
        }
    }
    pub fn extract(&self, root: &Path) -> Result<()> {
        ensure_directory(root)?;
        for asset in &self.assets {
            let relative = Path::new(&asset.name);
            if relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
            {
                return Err("unsafe asset path");
            }
            let target = root.join(relative);
            ensure_directory(target.parent().ok_or("asset parent missing")?)?;
            reject_reparse(&target)?;
            platform::atomic_write(&target, &asset.bytes)?;
        }
        Ok(())
    }
    pub fn verify_remote(&self) -> Result<()> {
        let profile: Profile =
            serde_json::from_slice(&self.profile).map_err(|_| "invalid bundled credential")?;
        goodgoodstudy::config::fetch(goodgoodstudy::config::ENDPOINT, &profile)?;
        Ok(())
    }
    pub fn provision(&self, state: &Path) -> Result<bool> {
        ensure_directory(state)?;
        if load_profile(state).is_ok() {
            return Ok(false);
        }
        let profile: Profile =
            serde_json::from_slice(&self.profile).map_err(|_| "invalid bundled credential")?;
        save_profile(state, &profile)?;
        Ok(true)
    }
}
fn reject_reparse(path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("installation path contains a reparse point");
        }
    }
    Ok(())
}
fn ensure_directory(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        reject_reparse(ancestor)?;
    }
    fs::create_dir_all(path).map_err(|_| "installation directory unavailable")
}
pub trait Integration {
    fn prepare(&mut self, script: &Path, app: &Path) -> Result<()>;
    fn stop_existing(&mut self, executable: &Path) -> Result<()>;
    fn finish(&mut self, script: &Path, app: &Path) -> Result<()>;
}
pub struct InstallResult {
    pub app: PathBuf,
    pub credential_imported: bool,
}
struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        // Only remove our fixed allowlist; never recurse through a user-supplied tree.
        for name in FILES {
            let _ = fs::remove_file(self.0.join(name));
        }
        let _ = fs::remove_dir(self.0.join("tools"));
        let _ = fs::remove_dir(&self.0);
    }
}
pub fn install(
    payload: &Payload,
    paths: &Paths,
    integration: &mut dyn Integration,
) -> Result<InstallResult> {
    ensure_directory(&paths.state)?;
    ensure_directory(&paths.app)?;
    let stage = Stage(
        paths
            .state
            .join(format!("setup-stage-{}", uuid::Uuid::new_v4())),
    );
    payload.extract(&stage.0)?;
    integration.prepare(&stage.0.join("tools/Install-Integration.ps1"), &paths.app)?;
    integration.stop_existing(&stage.0.join("GoodGoodStudy.exe"))?;
    payload.extract(&paths.app)?;
    let credential_imported = payload.provision(&paths.state)?;
    integration.finish(&paths.app.join("tools/Install-Integration.ps1"), &paths.app)?;
    Ok(InstallResult {
        app: paths.app.clone(),
        credential_imported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::{write::SimpleFileOptions, ZipWriter};

    fn fixture(change_hash: bool, bad_entry: bool) -> Vec<u8> {
        let mut entries: Vec<(&str, Vec<u8>)> = FILES
            .iter()
            .map(|name| {
                (
                    *name,
                    if *name == "GoodGoodStudy.exe" {
                        b"MZsynthetic-executable".to_vec()
                    } else {
                        b"synthetic asset".to_vec()
                    },
                )
            })
            .collect();
        let profile = Profile::create();
        entries.push((PROFILE_ENTRY, serde_json::to_vec(&profile).unwrap()));
        let mut hashes: HashMap<String, String> = entries
            .iter()
            .map(|(name, value)| (name.to_string(), format!("{:x}", Sha256::digest(value))))
            .collect();
        if change_hash {
            hashes.insert("README.md".into(), "bad".into());
        }
        let manifest = serde_json::to_vec(&Manifest {
            version: VERSION.into(),
            sha256: hashes,
        })
        .unwrap();
        entries.push(("manifest.json", manifest));
        if bad_entry {
            entries.push(("../escape", b"bad".to_vec()));
        }
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, value) in entries {
            zip.start_file(
                name,
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
            zip.write_all(&value).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }
    fn temporary() -> PathBuf {
        let root = std::env::temp_dir().join(format!("ggs-setup-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        root
    }
    fn cleanup(root: &Path) {
        assert!(root.starts_with(std::env::temp_dir()));
        assert!(root
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("ggs-setup-test-"));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn payload_validates_without_leaking_credential() {
        let p = Payload::decode(&fixture(false, false)).unwrap();
        let report = serde_json::to_string(&p.verification()).unwrap();
        assert_eq!(p.assets.len(), FILES.len());
        assert!(!report.contains("accessToken"));
        assert!(!report.contains("deviceId"));
    }
    #[test]
    fn checksum_tampering_is_rejected() {
        assert!(Payload::decode(&fixture(true, false)).is_err());
    }
    #[test]
    fn unsafe_entries_are_rejected() {
        assert!(Payload::decode(&fixture(false, true)).is_err());
    }
    #[test]
    fn extraction_never_writes_plaintext_profile() {
        let root = temporary();
        let p = Payload::decode(&fixture(false, false)).unwrap();
        p.extract(&root).unwrap();
        assert!(!root.join(PROFILE_ENTRY).exists());
        assert!(!root.join("provisioning").exists());
        assert!(root.join("GoodGoodStudy.exe").exists());
        cleanup(&root);
    }
    #[test]
    fn provision_is_dpapi_and_preserves_existing_valid_identity() {
        let root = temporary();
        let a = Payload::decode(&fixture(false, false)).unwrap();
        let b = Payload::decode(&fixture(false, false)).unwrap();
        assert!(a.provision(&root).unwrap());
        let first = load_profile(&root).unwrap();
        assert!(!b.provision(&root).unwrap());
        let second = load_profile(&root).unwrap();
        assert_eq!(first.device_id, second.device_id);
        assert!(root.join("device-profile.dpapi").exists());
        assert!(!root.join("client-profile.json").exists());
        cleanup(&root);
    }
    #[test]
    fn install_orders_steps_and_cleans_staging() {
        struct Fake {
            calls: Vec<&'static str>,
        }
        impl Integration for Fake {
            fn prepare(&mut self, _: &Path, _: &Path) -> Result<()> {
                self.calls.push("prepare");
                Ok(())
            }
            fn stop_existing(&mut self, _: &Path) -> Result<()> {
                self.calls.push("stop");
                Ok(())
            }
            fn finish(&mut self, _: &Path, app: &Path) -> Result<()> {
                assert!(app.join("GoodGoodStudy.exe").is_file());
                self.calls.push("finish");
                Ok(())
            }
        }
        let root = temporary();
        let paths = Paths::for_user(&root).unwrap();
        let p = Payload::decode(&fixture(false, false)).unwrap();
        let mut fake = Fake { calls: Vec::new() };
        let result = install(&p, &paths, &mut fake).unwrap();
        assert_eq!(fake.calls, ["prepare", "stop", "finish"]);
        assert!(result.credential_imported);
        assert_eq!(fs::read_dir(&paths.state).unwrap().count(), 1);
        cleanup(&root);
    }
    #[test]
    fn failed_prepare_does_not_install_or_import() {
        struct Fails;
        impl Integration for Fails {
            fn prepare(&mut self, _: &Path, _: &Path) -> Result<()> {
                Err("synthetic failure")
            }
            fn stop_existing(&mut self, _: &Path) -> Result<()> {
                panic!("unexpected stop")
            }
            fn finish(&mut self, _: &Path, _: &Path) -> Result<()> {
                panic!("unexpected start")
            }
        }
        let root = temporary();
        let paths = Paths::for_user(&root).unwrap();
        let p = Payload::decode(&fixture(false, false)).unwrap();
        assert!(install(&p, &paths, &mut Fails).is_err());
        assert!(!paths.app.join("GoodGoodStudy.exe").exists());
        assert!(!paths.state.join("device-profile.dpapi").exists());
        cleanup(&root);
    }
}
