use super::*;
use std::{
    io::Read,
    net::TcpListener,
    process::{Command, Stdio},
};

fn synthetic_batch(root: &Path) -> PathBuf {
    let queue = root.join("pending");
    fs::create_dir_all(&queue).unwrap();
    let source = root.join("SMTP-TEST-synthetic.txt");
    platform::private_write(
        &source,
        b"GoodGoodStudy SMTP test. Synthetic text only. No desktop capture.\r\n",
    )
    .unwrap();
    archive(&queue, &[source]).unwrap()
}
fn cleanup(root: &Path) {
    assert!(root.starts_with(std::env::temp_dir()));
    assert!(root
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("ggs-mail-test-"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn smtp_failure_keeps_real_worker_queue() {
    let root = std::env::temp_dir().join(format!("ggs-mail-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let zip = synthetic_batch(&root);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = platform::test_stop_event();
    let signal = stop.clone();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .write_all(b"421 Synthetic temporary SMTP failure\r\n")
            .unwrap();
        signal.signal();
    });
    let config = Config {
        mail: MailConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port,
            sender: "sender@example.test".into(),
            recipient: "recipient@example.test".into(),
            username: "synthetic-user".into(),
            password: "synthetic-password".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    sender(Arc::new(config), root.join("pending"), root.clone(), stop);
    server.join().unwrap();
    assert!(
        zip.is_file(),
        "SMTP rejection must retain the pending batch"
    );
    let log = fs::read_to_string(root.join("runtime.log")).unwrap();
    assert!(log.contains("Mail failed; archive retained."));
    assert!(!log.contains("synthetic-password"));
    let mut archive = zip::ZipArchive::new(File::open(zip).unwrap()).unwrap();
    let mut body = String::new();
    archive
        .by_index(0)
        .unwrap()
        .read_to_string(&mut body)
        .unwrap();
    assert!(body.contains("Synthetic text only"));
    drop(archive);
    cleanup(&root);
}

#[test]
#[ignore = "Sends exactly one synthetic test email to the configured real recipient; explicit user authorization required"]
fn real_configured_smtp_test_mail() {
    let state = platform::state_dir().unwrap();
    let mut config = config::fetch(config::ENDPOINT, &load_profile(&state).unwrap()).unwrap();
    if let Ok(port) = std::env::var("GGS_SMTP_TEST_PORT") {
        config.mail.port = port.parse().expect("invalid explicit test port");
    }
    assert!(
        config.mail.enabled,
        "SMTP is disabled in the remote configuration"
    );
    let id = uuid::Uuid::new_v4().to_string();
    let root = state.join("mail-tests").join(&id);
    fs::create_dir_all(&root).unwrap();
    let zip = synthetic_batch(&root);
    let subject = format!("[GoodGoodStudy SMTP TEST] {}", &id[..8]);
    let message = build_message(&config.mail, &zip, Some(&subject)).unwrap();
    // Decode the actual MIME builder's output independently using Python stdlib.
    let script = r#"
import email,email.policy,hashlib,io,json,sys,zipfile
m=email.message_from_bytes(sys.stdin.buffer.read(),policy=email.policy.default)
attachments=list(m.iter_attachments())
assert len(attachments)==1
a=attachments[0];data=a.get_payload(decode=True)
assert a.get_content_type()=='application/zip'
with zipfile.ZipFile(io.BytesIO(data)) as z:
 assert z.namelist()==['SMTP-TEST-synthetic.txt']
 assert b'Synthetic text only' in z.read(z.namelist()[0])
print(json.dumps({'subject':str(m['Subject']),'attachmentBytes':len(data),'zipSha256':hashlib.sha256(data).hexdigest(),'mimeValid':True,'zipValid':True}))
"#;
    let mut child = Command::new("python")
        .args(["-B", "-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&message.formatted())
        .unwrap();
    let decoded = child.wait_with_output().unwrap();
    assert!(
        decoded.status.success(),
        "MIME/ZIP verification failed before sending"
    );
    let metadata: serde_json::Value = serde_json::from_slice(&decoded.stdout).unwrap();
    assert_eq!(metadata["subject"], subject);
    let mut report = serde_json::json!({
        "testId":id,"subject":subject,"smtpHost":config.mail.host,"smtpPort":config.mail.port,
        "tls":if matches!(config.mail.port,465|994) {"implicit TLS with certificate verification"} else {"required STARTTLS with certificate verification"},"mime":metadata,
        "smtpAccepted":false,"inboxDeliveryVerified":false,"screenshotsCaptured":false,
        "historicalQueueUsed":false,"reportDirectory":root
    });
    println!("SMTP test prepared: subject={subject}; synthetic ZIP verified; one send attempt.");
    let result = deliver(&config.mail, &message);
    match &result {
        Ok(status) => {
            report["smtpAccepted"] = true.into();
            report["smtpStatus"] = status.clone().into();
        }
        Err(error) => {
            report["error"] = (*error).into();
        }
    }
    let report_path = root.join("mail-test.json");
    platform::private_write(&report_path, &serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    println!("Report: {}", report_path.display());
    assert!(
        result.is_ok(),
        "SMTP test failed; see sanitized error and retained synthetic batch"
    );
}
