use crate::{
    config::{self, Config, MailConfig, Result},
    load_profile,
    platform::{self, Guard, StopEvent},
};
use lettre::{
    message::{header::ContentType, Attachment, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};
static LOG_GATE: Mutex<()> = Mutex::new(());
/// Largest archive the sender will attach (before base64 expansion).
pub const MAX_ATTACHMENT_BYTES: u64 = 10 * 1024 * 1024;
/// Source bytes per batch; PNGs barely compress, so leave room for ZIP overhead.
pub const MAX_BATCH_SOURCE_BYTES: u64 = 9 * 1024 * 1024;
/// Suffix for archives that can never be mailed; kept until retention pruning.
const OVERSIZE_SUFFIX: &str = ".oversize";
pub fn log(root: &Path, message: &str) {
    let Ok(_lock) = LOG_GATE.lock() else { return };
    let path = root.join("runtime.log");
    if fs::metadata(&path)
        .map(|m| m.len() > 1048576)
        .unwrap_or(false)
    {
        let _ = fs::remove_file(root.join("runtime.log.1"));
        let _ = fs::rename(&path, root.join("runtime.log.1"));
    }
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(
            file,
            "{} {}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            message
        );
    }
}
fn unique(extension: &str) -> String {
    format!(
        "ggs-{:020}-{}.{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        uuid::Uuid::new_v4(),
        extension
    )
}
pub fn files(directory: &Path, extension: &str) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| "directory read failed")? {
        let entry = entry.map_err(|_| "directory read failed")?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry
            .file_type()
            .map_err(|_| "file type unavailable")?
            .is_file()
            && name.starts_with("ggs-")
            && name.ends_with(extension)
        {
            result.push(entry.path());
        }
    }
    result.sort();
    Ok(result)
}
fn stored(directories: &[&Path]) -> u64 {
    directories
        .iter()
        .filter_map(|d| fs::read_dir(d).ok())
        .flatten()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}
/// Apply retention and the storage limit to captures *and* the mail queue.
///
/// Files older than `days` are removed first. If the total is still at or above
/// `limit`, the oldest managed files (by their time-ordered `ggs-` names) are
/// removed until it fits. Unsent batches are therefore dropped oldest-first
/// instead of pausing capture forever while mail is unavailable.
fn prune(directory: &Path, queue: &Path, days: u32, limit: u64) {
    let max_age = Duration::from_secs(days as u64 * 86400);
    let mut managed = Vec::new();
    for dir in [directory, queue] {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("ggs-") || name.ends_with(".tmp") {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            let expired = metadata
                .modified()
                .ok()
                .and_then(|m| m.elapsed().ok())
                .is_some_and(|age| age > max_age);
            if expired {
                let _ = fs::remove_file(entry.path());
            } else {
                managed.push((name, entry.path(), metadata.len()));
            }
        }
    }
    let mut total = stored(&[directory, queue]);
    if total < limit {
        return;
    }
    managed.sort_by(|a, b| a.0.cmp(&b.0));
    for (_, path, len) in managed {
        if total < limit {
            break;
        }
        if fs::remove_file(path).is_ok() {
            total = total.saturating_sub(len);
        }
    }
}
/// How many leading files form the next batch, or `None` to keep waiting.
///
/// A batch closes at `batch_size` files or before the next file would push the
/// source total past `max_bytes`. A single file larger than `max_bytes` forms
/// its own batch so it cannot block the queue.
fn next_batch(sizes: &[u64], batch_size: usize, max_bytes: u64) -> Option<usize> {
    let mut total = 0u64;
    for (index, &size) in sizes.iter().enumerate() {
        if index > 0 && total.saturating_add(size) > max_bytes {
            return Some(index);
        }
        total = total.saturating_add(size);
        if index + 1 >= batch_size || total >= max_bytes {
            return Some(index + 1);
        }
    }
    None
}
/// Archive every complete batch currently waiting in `directory`.
fn archive_ready(directory: &Path, queue: &Path, batch_size: usize, root: &Path) {
    loop {
        let Ok(list) = files(directory, ".png") else {
            return;
        };
        let sizes: Vec<u64> = list
            .iter()
            .map(|p| fs::metadata(p).map(|m| m.len()).unwrap_or(0))
            .collect();
        let Some(count) = next_batch(&sizes, batch_size, MAX_BATCH_SOURCE_BYTES) else {
            return;
        };
        if let Err(error) = archive(queue, &list[..count]) {
            log(
                root,
                &format!("Archive failed: {error}; recoverable files retained."),
            );
            return;
        }
    }
}
/// Move an unsendable archive out of the mail queue (it stays subject to pruning).
fn quarantine(path: &Path) -> Result<PathBuf> {
    let mut target = path.as_os_str().to_owned();
    target.push(OVERSIZE_SUFFIX);
    let target = PathBuf::from(target);
    fs::rename(path, &target).map_err(|_| "oversize archive could not be moved aside")?;
    Ok(target)
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn capture(directory: &Path) -> Result<()> {
    let (width, height, rgba) = platform::screenshot()?;
    let final_path = directory.join(unique("png"));
    let temporary = Temporary(final_path.with_extension("png.tmp"));
    let mut output = File::create_new(&temporary.0).map_err(|_| "image create failed")?;
    {
        let mut encoder = png::Encoder::new(&mut output, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(|_| "PNG header failed")?;
        writer
            .write_image_data(&rgba)
            .map_err(|_| "PNG write failed")?;
        writer.finish().map_err(|_| "PNG finish failed")?;
    }
    output.sync_all().map_err(|_| "image sync failed")?;
    drop(output);
    fs::rename(&temporary.0, final_path).map_err(|_| "image publish failed")
}
pub fn archive(queue: &Path, sources: &[PathBuf]) -> Result<PathBuf> {
    if sources.is_empty() || sources.iter().any(|p| !p.is_file()) {
        return Err("incomplete batch");
    }
    let final_path = queue.join(unique("zip"));
    let temporary = Temporary(final_path.with_extension("zip.tmp"));
    let file = File::create_new(&temporary.0).map_err(|_| "archive create failed")?;
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(1));
    for source in sources {
        let name = source
            .file_name()
            .ok_or("invalid image name")?
            .to_string_lossy();
        writer
            .start_file(name, options)
            .map_err(|_| "archive entry failed")?;
        let mut input = File::open(source).map_err(|_| "image open failed")?;
        io::copy(&mut input, &mut writer).map_err(|_| "archive write failed")?;
    }
    let output = writer.finish().map_err(|_| "archive finish failed")?;
    output.sync_all().map_err(|_| "archive sync failed")?;
    drop(output);
    fs::rename(&temporary.0, &final_path).map_err(|_| "archive publish failed")?;
    for source in sources {
        fs::remove_file(source).map_err(|_| "original cleanup failed")?;
    }
    Ok(final_path)
}
fn send(mail: &MailConfig, path: &Path) -> Result<()> {
    deliver(mail, &build_message(mail, path, None)?).map(|_| ())
}
fn build_message(mail: &MailConfig, path: &Path, test_subject: Option<&str>) -> Result<Message> {
    let content = fs::read(path).map_err(|_| "attachment unavailable")?;
    let message = Message::builder()
        .from(mail.sender.parse().map_err(|_| "invalid sender")?)
        .to(mail.recipient.parse().map_err(|_| "invalid recipient")?)
        .subject(test_subject.map(str::to_owned).unwrap_or_else(|| {
            format!(
                "{} screenshots",
                std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows".into())
            )
        }))
        .multipart(
            MultiPart::mixed()
                .singlepart(SinglePart::plain(
                    if test_subject.is_some() {
                        "GoodGoodStudy SMTP test with a synthetic attachment."
                    } else {
                        "GoodGoodStudy screenshot batch."
                    }
                    .to_string(),
                ))
                .singlepart(
                    Attachment::new(
                        path.file_name()
                            .ok_or("invalid attachment")?
                            .to_string_lossy()
                            .into_owned(),
                    )
                    .body(
                        content,
                        ContentType::parse("application/zip")
                            .map_err(|_| "invalid content type")?,
                    ),
                ),
        )
        .map_err(|_| "message build failed")?;
    Ok(message)
}
fn deliver(mail: &MailConfig, message: &Message) -> Result<String> {
    let builder = if matches!(mail.port, 465 | 994) {
        SmtpTransport::relay(&mail.host)
    } else {
        SmtpTransport::starttls_relay(&mail.host)
    };
    let transport = builder
        .map_err(|_| "SMTP TLS unavailable")?
        .port(mail.port)
        .credentials(Credentials::new(
            mail.username.clone(),
            mail.password.clone(),
        ))
        .timeout(Some(Duration::from_secs(15)))
        .build();
    let response = transport.send(message).map_err(|error| {
        eprintln!(
            "SMTP failure: transient={}, permanent={}, timeout={}, tls={}, status={}",
            error.is_transient(),
            error.is_permanent(),
            error.is_timeout(),
            error.is_tls(),
            error
                .status()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "none".into())
        );
        if error.is_tls() {
            "SMTP TLS handshake failed"
        } else if error.is_timeout() {
            "SMTP operation timed out"
        } else if error.status().is_some_and(|code| code.to_string() == "535") {
            "SMTP authentication rejected"
        } else {
            "mail send failed"
        }
    })?;
    Ok(response.code().to_string())
}
fn sender(config: Arc<Config>, queue: PathBuf, root: PathBuf, stop: StopEvent) {
    let mut retry = 5u32;
    while !stop.wait(0) {
        let mut failed = false;
        if let Ok(list) = files(&queue, ".zip") {
            for path in list {
                if stop.wait(0) {
                    return;
                }
                let Ok(metadata) = fs::metadata(&path) else {
                    continue;
                };
                if metadata.len() > MAX_ATTACHMENT_BYTES {
                    match quarantine(&path) {
                        Ok(_) => log(
                            &root,
                            "Oversize archive moved aside (*.zip.oversize); 10 MiB mail limit.",
                        ),
                        Err(error) => {
                            log(&root, error);
                            failed = true;
                            break;
                        }
                    }
                    continue;
                }
                if let Err(error) = send(&config.mail, &path) {
                    log(&root, error);
                    log(&root, "Mail failed; archive retained.");
                    failed = true;
                    break;
                }
                if fs::remove_file(&path).is_err() && path.exists() {
                    log(
                        &root,
                        "Sent archive could not be removed; delivery may repeat.",
                    );
                    failed = true;
                    break;
                }
                log(&root, "Screenshot batch sent.");
            }
        }
        retry = if failed { (retry * 2).min(300) } else { 5 };
        if stop.wait(retry * 1000) {
            return;
        }
    }
}
pub fn run(address: &str, root: &Path) -> Result<()> {
    let guard = Guard::acquire()?;
    let mut observe = |event: serde_json::Value| {
        let step = event["step"].as_str().unwrap_or("");
        if matches!(step, "11.retry_scheduled" | "12.transport_failure")
            || (step == "03.https_response" && event["details"]["status"].as_u64() != Some(200))
        {
            if let Ok(message) = serde_json::to_string(&event) {
                log(root, &message);
            }
        }
    };
    let result = config::fetch_cancellable(
        address,
        &load_profile(root)?,
        Some(&mut observe),
        &mut |delay| {
            guard
                .stop
                .wait(delay.as_millis().min(u32::MAX as u128) as u32)
        },
    );
    if guard.stop.wait(0) {
        return Ok(());
    }
    let config = Arc::new(result?);
    let directory = if config.screenshot_directory.is_empty() {
        root.join("captures")
    } else {
        PathBuf::from(&config.screenshot_directory)
    };
    let queue = root.join("pending");
    for path in [&directory, &queue] {
        fs::create_dir_all(path).map_err(|_| "capture directory unavailable")?;
    }
    let signal = guard.stop.clone();
    ctrlc::set_handler(move || signal.signal()).map_err(|_| "interrupt handler unavailable")?;
    let worker = if config.mail.enabled {
        let c = config.clone();
        let q = queue.clone();
        let r = root.to_owned();
        let s = guard.stop.clone();
        Some(thread::spawn(move || sender(c, q, r, s)))
    } else {
        None
    };
    println!("GoodGoodStudy Rust running. Ctrl+C to stop.");
    log(root, "Rust capture started.");
    let interval = Duration::from_secs(config.interval_seconds as u64);
    let mut next = Instant::now() + interval;
    loop {
        let wait = next.saturating_duration_since(Instant::now());
        if guard
            .stop
            .wait(wait.as_millis().min(u32::MAX as u128) as u32)
        {
            break;
        }
        let limit = config.max_storage_mb as u64 * 1024 * 1024;
        prune(&directory, &queue, config.retention_days, limit);
        if stored(&[&directory, &queue]) < limit {
            if let Err(error) = capture(&directory) {
                log(
                    root,
                    &format!("Capture failed: {error}; retry at next interval."),
                );
            }
        } else {
            log(root, "Storage limit reached; capture skipped.");
        }
        if config.mail.enabled {
            archive_ready(&directory, &queue, config.batch_size, root);
        }
        next += interval;
        if next < Instant::now() {
            next = Instant::now() + interval
        }
    }
    guard.stop.signal();
    if let Some(worker) = worker {
        let _ = worker.join();
    }
    Ok(())
}

#[cfg(test)]
#[path = "mail_tests.rs"]
mod mail_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn archives_are_unique_and_durable() {
        let root = std::env::temp_dir().join(format!("ggs-rust-test-{}", uuid::Uuid::new_v4()));
        let queue = root.join("queue");
        fs::create_dir_all(&queue).unwrap();
        for _ in 0..2 {
            let sources: Vec<_> = (0..10)
                .map(|_| {
                    let p = root.join(unique("png"));
                    fs::write(&p, b"fake image").unwrap();
                    p
                })
                .collect();
            let archive = archive(&queue, &sources).unwrap();
            let zip = zip::ZipArchive::new(File::open(archive).unwrap()).unwrap();
            assert_eq!(zip.len(), 10);
            assert!(sources.iter().all(|p| !p.exists()));
        }
        assert_eq!(files(&queue, ".zip").unwrap().len(), 2);
        let keep = root.join(unique("png"));
        fs::write(&keep, b"keep").unwrap();
        assert!(archive(&queue, &[keep.clone(), root.join("missing.png")]).is_err());
        assert!(keep.exists());
        // A freshly created test-only directory, never a configured screenshot path.
        assert!(root.starts_with(std::env::temp_dir()));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn batches_close_on_count_or_size() {
        const M: u64 = 1024 * 1024;
        // Waits while under both the count and the size limits.
        assert_eq!(next_batch(&[], 10, 9 * M), None);
        assert_eq!(next_batch(&[M; 9], 10, 9 * M + 1), None);
        // Count limit.
        assert_eq!(next_batch(&[M; 12], 10, 100 * M), Some(10));
        // Size limit: stop before the file that would overflow.
        assert_eq!(next_batch(&[4 * M, 4 * M, 4 * M], 10, 9 * M), Some(2));
        // Exactly reaching the limit closes the batch.
        assert_eq!(next_batch(&[3 * M, 3 * M, 3 * M, M], 10, 9 * M), Some(3));
        // One huge file is sent alone instead of blocking forever.
        assert_eq!(next_batch(&[20 * M, M], 10, 9 * M), Some(1));
    }
    #[test]
    fn prune_covers_queue_and_drops_oldest_first() {
        let root = std::env::temp_dir().join(format!("ggs-rust-prune-{}", uuid::Uuid::new_v4()));
        let captures = root.join("captures");
        let queue = root.join("pending");
        fs::create_dir_all(&captures).unwrap();
        fs::create_dir_all(&queue).unwrap();
        // Names are time-ordered: zip (oldest) < png < png (newest).
        let old_zip = queue.join("ggs-00000000000000000001-a.zip");
        let oversize = queue.join("ggs-00000000000000000002-b.zip.oversize");
        let mid_png = captures.join("ggs-00000000000000000003-c.png");
        let new_png = captures.join("ggs-00000000000000000004-d.png");
        let foreign = captures.join("keep-me.txt");
        for path in [&old_zip, &oversize, &mid_png, &new_png] {
            fs::write(path, vec![0u8; 1000]).unwrap();
        }
        fs::write(&foreign, b"x").unwrap();
        // Under the limit: nothing is removed.
        prune(&captures, &queue, 7, 1_000_000);
        assert!(old_zip.exists() && new_png.exists());
        // Limit of 2500 bytes: the two oldest managed files go, newest stay.
        prune(&captures, &queue, 7, 2500);
        assert!(!old_zip.exists());
        assert!(!oversize.exists());
        assert!(mid_png.exists() && new_png.exists());
        assert!(foreign.exists(), "unmanaged files are never deleted");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn oversize_archive_leaves_mail_queue() {
        let root = std::env::temp_dir().join(format!("ggs-rust-oversize-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let zip = root.join(unique("zip"));
        fs::write(&zip, b"zip").unwrap();
        let moved = quarantine(&zip).unwrap();
        assert!(!zip.exists() && moved.exists());
        assert!(moved.to_string_lossy().ends_with(".zip.oversize"));
        assert!(files(&root, ".zip").unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
