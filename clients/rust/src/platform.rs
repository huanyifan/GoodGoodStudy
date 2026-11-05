use crate::config::Result;
use std::{
    ffi::c_void,
    fs::{self, File},
    io::Write,
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
};
use zeroize::Zeroize;
type Handle = *mut c_void;
#[repr(C)]
struct Blob {
    len: u32,
    data: *mut u8,
}
#[repr(C)]
struct SecurityAttributes {
    len: u32,
    descriptor: *mut c_void,
    inherit: i32,
}
#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn LocalFree(handle: Handle) -> Handle;
    fn GetLastError() -> u32;
    fn CreateMutexW(attributes: *const SecurityAttributes, owner: i32, name: *const u16) -> Handle;
    fn ReleaseMutex(handle: Handle) -> i32;
    fn CreateEventW(
        attributes: *const SecurityAttributes,
        manual: i32,
        initial: i32,
        name: *const u16,
    ) -> Handle;
    fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> Handle;
    fn OpenMutexW(access: u32, inherit: i32, name: *const u16) -> Handle;
    fn SetEvent(handle: Handle) -> i32;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        attributes: *const SecurityAttributes,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
}
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        information: *mut c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *const c_void, string: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
}
#[link(name = "crypt32")]
extern "system" {
    fn CryptProtectData(
        data: *const Blob,
        description: *const u16,
        entropy: *const Blob,
        reserved: *mut c_void,
        prompt: *mut c_void,
        flags: u32,
        output: *mut Blob,
    ) -> i32;
    fn CryptUnprotectData(
        data: *const Blob,
        description: *mut *mut u16,
        entropy: *const Blob,
        reserved: *mut c_void,
        prompt: *mut c_void,
        flags: u32,
        output: *mut Blob,
    ) -> i32;
}
fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn text(value: &str) -> Vec<u16> {
    wide(std::ffi::OsStr::new(value))
}
pub fn state_dir() -> Result<PathBuf> {
    let root = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA missing")?;
    Ok(PathBuf::from(root).join("GoodGoodStudy"))
}

pub fn stop_existing(timeout_ms: u32) -> Result<()> {
    let id = sid()?;
    let event_name = text(&format!("Local\\GoodGoodStudyStop-{}", id));
    let mutex_name = text(&format!("Local\\GoodGoodStudy-{}", id));
    unsafe {
        let event = OpenEventW(2, 0, event_name.as_ptr());
        if !event.is_null() {
            SetEvent(event);
            CloseHandle(event);
        }
        let mutex = OpenMutexW(0x00100001, 0, mutex_name.as_ptr());
        if mutex.is_null() {
            return if GetLastError() == 2 {
                Ok(())
            } else {
                Err("existing instance status unavailable")
            };
        }
        let result = WaitForSingleObject(mutex, timeout_ms);
        if result == 0 || result == 0x80 {
            ReleaseMutex(mutex);
        }
        CloseHandle(mutex);
        if result == 0 || result == 0x80 {
            Ok(())
        } else {
            Err("existing instance has not stopped")
        }
    }
}
pub fn sid() -> Result<String> {
    unsafe {
        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), 8, &mut token) == 0 {
            return Err("token unavailable");
        }
        let mut length = 0;
        GetTokenInformation(token, 1, ptr::null_mut(), 0, &mut length);
        if length == 0 {
            CloseHandle(token);
            return Err("token unavailable");
        }
        let mut buffer = vec![0u8; length as usize];
        let success =
            GetTokenInformation(token, 1, buffer.as_mut_ptr().cast(), length, &mut length);
        CloseHandle(token);
        if success == 0 {
            return Err("token unavailable");
        }
        let sid = ptr::read_unaligned(buffer.as_ptr().cast::<*const c_void>());
        let mut value = ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut value) == 0 {
            return Err("SID unavailable");
        }
        let mut n = 0;
        while *value.add(n) != 0 {
            n += 1
        }
        let result = String::from_utf16_lossy(std::slice::from_raw_parts(value, n));
        LocalFree(value.cast());
        Ok(result)
    }
}
pub fn dpapi(data: &[u8], decrypt: bool) -> Result<Vec<u8>> {
    unsafe {
        let input = Blob {
            len: data.len() as u32,
            data: data.as_ptr() as *mut u8,
        };
        let entropy_bytes = b"GoodGoodStudy.DeviceCredential.v2";
        let entropy = Blob {
            len: entropy_bytes.len() as u32,
            data: entropy_bytes.as_ptr() as *mut u8,
        };
        let mut output = Blob {
            len: 0,
            data: ptr::null_mut(),
        };
        let ok = if decrypt {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                &entropy,
                ptr::null_mut(),
                ptr::null_mut(),
                1,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                ptr::null(),
                &entropy,
                ptr::null_mut(),
                ptr::null_mut(),
                1,
                &mut output,
            )
        };
        if ok == 0 {
            return Err("DPAPI failed");
        }
        let memory = std::slice::from_raw_parts_mut(output.data, output.len as usize);
        let result = memory.to_vec();
        memory.zeroize();
        LocalFree(output.data.cast());
        Ok(result)
    }
}
pub fn private_write(path: &Path, data: &[u8]) -> Result<()> {
    if !path.is_absolute() || path.to_string_lossy().starts_with("\\\\") {
        return Err("private output requires absolute local path");
    }
    let sddl = text(&format!("D:P(A;;FA;;;{})", sid()?));
    let mut descriptor = ptr::null_mut();
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err("ACL unavailable");
        }
        let attributes = SecurityAttributes {
            len: std::mem::size_of::<SecurityAttributes>() as u32,
            descriptor,
            inherit: 0,
        };
        let name = wide(path.as_os_str());
        let handle = CreateFileW(
            name.as_ptr(),
            0x40000000,
            0,
            &attributes,
            1,
            0x80,
            ptr::null_mut(),
        );
        LocalFree(descriptor);
        if handle as isize == -1 {
            return Err("private output exists or unavailable");
        }
        let mut file = File::from_raw_handle(handle);
        file.write_all(data)
            .map_err(|_| "private output write failed")?;
        file.sync_all().map_err(|_| "private output sync failed")
    }
}
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    private_write(&temporary, data)?;
    let from = wide(temporary.as_os_str());
    let to = wide(path.as_os_str());
    let ok = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 1 | 8) };
    if ok == 0 {
        let _ = fs::remove_file(temporary);
        return Err("atomic replacement failed");
    }
    Ok(())
}
struct EventInner(Handle);
unsafe impl Send for EventInner {} // Windows event handles can be waited/signalled across threads.
unsafe impl Sync for EventInner {}
impl Drop for EventInner {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
#[derive(Clone)]
pub struct StopEvent(Arc<EventInner>);
#[cfg(test)]
pub(crate) fn test_stop_event() -> StopEvent {
    let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    assert!(!event.is_null());
    StopEvent(Arc::new(EventInner(event)))
}
impl StopEvent {
    pub fn wait(&self, milliseconds: u32) -> bool {
        unsafe { WaitForSingleObject(self.0 .0, milliseconds) != 258 }
    }
    pub fn signal(&self) {
        unsafe {
            SetEvent(self.0 .0);
        }
    }
}
pub struct Guard {
    mutex: Handle,
    pub stop: StopEvent,
}
impl Guard {
    pub fn acquire() -> Result<Self> {
        let id = sid()?;
        let mutex_name = text(&format!("Local\\GoodGoodStudy-{}", id));
        unsafe {
            let mutex = CreateMutexW(ptr::null(), 1, mutex_name.as_ptr());
            if mutex.is_null() {
                return Err("mutex unavailable");
            }
            if GetLastError() == 183 {
                CloseHandle(mutex);
                return Err("already running");
            }
            let event_name = text(&format!("Local\\GoodGoodStudyStop-{}", id));
            let event = CreateEventW(ptr::null(), 1, 0, event_name.as_ptr());
            if event.is_null() {
                ReleaseMutex(mutex);
                CloseHandle(mutex);
                return Err("stop event unavailable");
            }
            Ok(Self {
                mutex,
                stop: StopEvent(Arc::new(EventInner(event))),
            })
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.mutex);
            CloseHandle(self.mutex);
        }
    }
}
#[repr(C)]
struct BitmapHeader {
    size: u32,
    width: i32,
    height: i32,
    planes: u16,
    bits: u16,
    compression: u32,
    image_size: u32,
    x: i32,
    y: i32,
    used: u32,
    important: u32,
}
#[repr(C)]
struct BitmapInfo {
    header: BitmapHeader,
    colors: [u32; 1],
}
#[link(name = "user32")]
extern "system" {
    fn GetDC(window: Handle) -> Handle;
    fn ReleaseDC(window: Handle, dc: Handle) -> i32;
    fn GetSystemMetrics(index: i32) -> i32;
    fn SetProcessDPIAware() -> i32;
}
#[link(name = "gdi32")]
extern "system" {
    fn CreateCompatibleDC(source: Handle) -> Handle;
    fn GdiFlush() -> i32;
    fn DeleteDC(dc: Handle) -> i32;
    fn DeleteObject(object: Handle) -> i32;
    fn SelectObject(dc: Handle, object: Handle) -> Handle;
    fn CreateDIBSection(
        dc: Handle,
        info: *const BitmapInfo,
        usage: u32,
        bits: *mut *mut c_void,
        section: Handle,
        offset: u32,
    ) -> Handle;
    fn BitBlt(
        target: Handle,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        source: Handle,
        sx: i32,
        sy: i32,
        operation: u32,
    ) -> i32;
}
struct ScreenDc(Handle);
impl Drop for ScreenDc {
    fn drop(&mut self) {
        unsafe {
            ReleaseDC(ptr::null_mut(), self.0);
        }
    }
}
struct MemoryDc(Handle);
impl Drop for MemoryDc {
    fn drop(&mut self) {
        unsafe {
            DeleteDC(self.0);
        }
    }
}
struct Bitmap {
    dc: Handle,
    bitmap: Handle,
    old: Handle,
}
impl Drop for Bitmap {
    fn drop(&mut self) {
        unsafe {
            if !self.old.is_null() {
                SelectObject(self.dc, self.old);
            }
            DeleteObject(self.bitmap);
        }
    }
}
pub fn screenshot() -> Result<(u32, u32, Vec<u8>)> {
    unsafe {
        SetProcessDPIAware();
        let width = GetSystemMetrics(0);
        let height = GetSystemMetrics(1);
        if width <= 0
            || height <= 0
            || width > 16384
            || height > 16384
            || width as u64 * height as u64 > 64000000
        {
            return Err("invalid screen bounds");
        }
        let source = ScreenDc(GetDC(ptr::null_mut()));
        if source.0.is_null() {
            return Err("screen DC unavailable");
        }
        let dc = MemoryDc(CreateCompatibleDC(source.0));
        if dc.0.is_null() {
            return Err("capture DC unavailable");
        }
        let info = BitmapInfo {
            header: BitmapHeader {
                size: 40,
                width,
                height: -height,
                planes: 1,
                bits: 32,
                compression: 0,
                image_size: 0,
                x: 0,
                y: 0,
                used: 0,
                important: 0,
            },
            colors: [0],
        };
        let mut pixels = ptr::null_mut();
        let raw = CreateDIBSection(source.0, &info, 0, &mut pixels, ptr::null_mut(), 0);
        if raw.is_null() || pixels.is_null() {
            return Err("bitmap unavailable");
        }
        let mut bitmap = Bitmap {
            dc: dc.0,
            bitmap: raw,
            old: ptr::null_mut(),
        };
        let old = SelectObject(dc.0, raw);
        if old.is_null() || old as isize == -1 {
            return Err("bitmap selection failed");
        }
        bitmap.old = old;
        if BitBlt(
            dc.0,
            0,
            0,
            width,
            height,
            source.0,
            0,
            0,
            0x00CC0020 | 0x40000000,
        ) == 0
        {
            return Err("screen copy failed");
        }
        // Synchronize GDI batching before reading DIB section memory.
        if GdiFlush() == 0 {
            return Err("screen synchronization failed");
        }
        let source =
            std::slice::from_raw_parts(pixels as *const u8, width as usize * height as usize * 4);
        let mut rgba = vec![0u8; source.len()];
        for (from, to) in source
            .as_chunks::<4>()
            .0
            .iter()
            .zip(rgba.as_chunks_mut::<4>().0.iter_mut())
        {
            to.copy_from_slice(&[from[2], from[1], from[0], 255]);
        }
        Ok((width as u32, height as u32, rgba))
    }
}
