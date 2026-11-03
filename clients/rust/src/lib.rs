pub mod app;
pub mod config;
pub mod platform;

use config::{Profile, Result};
use std::{fs, path::Path};
use zeroize::Zeroizing;

pub fn load_profile(root: &Path) -> Result<Profile> {
    let encrypted =
        fs::read(root.join("device-profile.dpapi")).map_err(|_| "import device profile first")?;
    let plain = Zeroizing::new(platform::dpapi(&encrypted, true)?);
    let p: Profile = serde_json::from_slice(&plain).map_err(|_| "invalid credential")?;
    p.validate()?;
    Ok(p)
}

pub fn save_profile(root: &Path, p: &Profile) -> Result<()> {
    p.validate()?;
    let plain = Zeroizing::new(serde_json::to_vec(p).map_err(|_| "invalid credential")?);
    let protected = platform::dpapi(&plain, false)?;
    platform::atomic_write(&root.join("device-profile.dpapi"), &protected)
}
