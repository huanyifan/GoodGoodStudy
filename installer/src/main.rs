#![cfg_attr(windows, windows_subsystem = "windows")]
#[cfg(not(ggs_private_payload))]
compile_error!(
    "Build this personal installer using tools/Build-Installer.ps1 and a private device profile."
);

use goodgoodstudy_setup::{install, Integration, Paths, Payload, Result};
use std::{
    ffi::OsStr,
    fs,
    os::windows::{ffi::OsStrExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
};

static PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.zip"));
#[link(name = "kernel32")]
extern "system" {
    fn CreateMutexW(
        attributes: *const std::ffi::c_void,
        owner: i32,
        name: *const u16,
    ) -> *mut std::ffi::c_void;
    fn GetLastError() -> u32;
    fn ReleaseMutex(handle: *mut std::ffi::c_void) -> i32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
}
struct SetupLock(*mut std::ffi::c_void);
impl SetupLock {
    fn acquire() -> Result<Self> {
        let name = wide(&format!(
            "Local\\GoodGoodStudySetup-{}",
            goodgoodstudy::platform::sid()?
        ));
        unsafe {
            let handle = CreateMutexW(std::ptr::null(), 1, name.as_ptr());
            if handle.is_null() {
                return Err("installer lock unavailable");
            }
            if GetLastError() == 183 {
                CloseHandle(handle);
                return Err("another installer is already running");
            }
            Ok(Self(handle))
        }
    }
}
impl Drop for SetupLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}
struct WindowsIntegration;
fn powershell(script: &Path, mode: &str, app: &Path) -> Result<()> {
    let system = std::env::var_os("SystemRoot").ok_or("Windows directory unavailable")?;
    let result =
        Command::new(PathBuf::from(system).join("System32/WindowsPowerShell/v1.0/powershell.exe"))
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-WindowStyle",
                "Hidden",
                "-File",
            ])
            .arg(script)
            .args(["-Mode", mode, "-InstallDirectory"])
            .arg(app)
            .creation_flags(0x08000000)
            .output()
            .map_err(|_| "installer integration could not start")?;
    if result.status.success() {
        Ok(())
    } else {
        Err("Windows integration failed; see setup.log")
    }
}
impl Integration for WindowsIntegration {
    fn prepare(&mut self, script: &Path, app: &Path) -> Result<()> {
        powershell(script, "Prepare", app)
    }
    fn stop_existing(&mut self, executable: &Path) -> Result<()> {
        let result = Command::new(executable)
            .arg("--stop-instance")
            .creation_flags(0x08000000)
            .output()
            .map_err(|_| "existing process check could not start")?;
        if result.status.success() {
            Ok(())
        } else {
            Err("existing application did not exit; close it and retry")
        }
    }
    fn finish(&mut self, script: &Path, app: &Path) -> Result<()> {
        powershell(script, "Finish", app)
    }
}
#[link(name = "user32")]
extern "system" {
    fn MessageBoxW(
        window: *mut std::ffi::c_void,
        text: *const u16,
        title: *const u16,
        flags: u32,
    ) -> i32;
}
fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}
fn message(value: &str, error: bool) {
    let text = wide(value);
    let title = wide("GoodGoodStudy Rust 安装器");
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            if error { 0x10 } else { 0x40 },
        );
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let payload = Payload::decode(PAYLOAD)?;
    if !args.is_empty() {
        let mode = args[0].to_str().ok_or("invalid argument")?;
        if args.len() != 2 || !matches!(mode, "--verify-only" | "--verify-online") {
            return Err("invalid argument");
        }
        let mut report = payload.verification();
        if mode == "--verify-online" {
            payload.verify_remote()?;
            report.remote_config_verified = true;
        }
        let bytes = serde_json::to_vec_pretty(&report).map_err(|_| "report unavailable")?;
        goodgoodstudy::platform::private_write(Path::new(&args[1]), &bytes)?;
        return Ok(());
    }
    let _lock = SetupLock::acquire()?;
    let local = std::env::var_os("LOCALAPPDATA").ok_or("local application data unavailable")?;
    let paths = Paths::for_user(Path::new(&local))?;
    fs::create_dir_all(&paths.state).map_err(|_| "setup state directory unavailable")?;
    let result = install(&payload, &paths, &mut WindowsIntegration);
    match result {
        Ok(result) => {
            goodgoodstudy::app::log(
                &paths.state,
                "Rust installer completed; startup watchdog enabled.",
            );
            message(&format!("安装完成，已自动配置并启用登录自启动与每分钟守护。\n\n安装目录：{}\n\n程序会按远端配置自动开始定时截图。开始菜单中可查看状态、停用或卸载。", result.app.display()), false);
            Ok(())
        }
        Err(error) => {
            goodgoodstudy::app::log(&paths.state, error);
            Err(error)
        }
    }
}
fn main() {
    if let Err(error) = run() {
        if std::env::args_os().len() == 1 {
            message(&format!("安装未完成：{}\n\n请检查当前用户权限、setup.log 或 runtime.log，退出旧版本后再次双击安装包。", error), true);
        }
        std::process::exit(1);
    }
}
