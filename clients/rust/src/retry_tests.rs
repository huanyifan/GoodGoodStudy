use super::*;
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, Command, Stdio},
};

struct Fixture {
    child: Child,
    url: String,
    client: reqwest::blocking::Client,
    ca: reqwest::Certificate,
}
impl Fixture {
    fn start(mode: &str, profile: &Profile) -> Self {
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Tests/https_retry_fixture.py");
        let mut child = Command::new("python")
            .arg("-B")
            .arg(script)
            .arg(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("Python fixture unavailable");
        let mut input = child.stdin.take().unwrap();
        serde_json::to_writer(&mut input, profile).unwrap();
        input.write_all(b"\n").unwrap();
        drop(input);
        let mut metadata = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut metadata)
            .unwrap();
        let metadata: serde_json::Value =
            serde_json::from_str(&metadata).expect("TLS fixture startup failed");
        let ca =
            reqwest::Certificate::from_pem(metadata["ca"].as_str().unwrap().as_bytes()).unwrap();
        let client = client_builder()
            .no_proxy()
            .add_root_certificate(ca.clone())
            .build()
            .unwrap();
        Self {
            child,
            url: metadata["url"].as_str().unwrap().into(),
            client,
            ca,
        }
    }
    fn requests(&self) -> Vec<serde_json::Value> {
        self.client
            .get(format!("{}/stats", self.url))
            .send()
            .unwrap()
            .json::<serde_json::Value>()
            .unwrap()["requests"]
            .as_array()
            .unwrap()
            .clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self
            .client
            .get(format!("{}/shutdown", self.url))
            .timeout(Duration::from_secs(2))
            .send();
        // The fixture exits serve_forever after /shutdown and removes its synthetic TLS files.
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore = "explicit integration run requires Python and cryptography; uses a private loopback TLS CA"]
fn real_https_faults_recover_and_security_failures_do_not_retry() {
    let cases = [
        ("success", 1, true),
        ("502", 2, true),
        ("503", 2, true),
        ("504", 2, true),
        ("drop", 2, true),
        ("read_drop", 2, true),
        ("timeout", 2, true),
        ("always_503", 3, false),
        ("401", 1, false),
        ("403", 1, false),
        ("429", 1, false),
        ("500", 1, false),
        ("bad_mac", 1, false),
        ("invalid_json", 1, false),
    ];
    for (mode, expected, success) in cases {
        let profile = Profile::create();
        let fixture = Fixture::start(mode, &profile);
        let client = if mode == "timeout" {
            client_builder()
                .no_proxy()
                .timeout(Duration::from_millis(150))
                .add_root_certificate(fixture.ca.clone())
                .build()
                .unwrap()
        } else {
            fixture.client.clone()
        };
        let mut events = Vec::new();
        let mut waits = Vec::new();
        let result = fetch_using_client(
            &fixture.url,
            &profile,
            Some(&mut |e| events.push(e)),
            &mut |delay| {
                if !delay.is_zero() {
                    waits.push(delay.as_secs());
                }
                false
            },
            &client,
        );
        assert_eq!(
            result.is_ok(),
            success,
            "mode={mode}, error={:?}",
            result.err()
        );
        let requests = fixture.requests();
        assert_eq!(requests.len(), expected, "mode={mode}");
        assert_eq!(
            waits,
            match expected {
                3 => vec![1, 2],
                2 => vec![1],
                _ => vec![],
            },
            "mode={mode}"
        );
        for pair in requests.windows(2) {
            assert_ne!(
                pair[0]["clientPublicKey"], pair[1]["clientPublicKey"],
                "mode={mode}"
            );
            assert_ne!(
                pair[0]["clientNonce"], pair[1]["clientNonce"],
                "mode={mode}"
            );
        }
        println!("PASS HTTPS fixture mode={mode}, requests={expected}, recovered={success}, fresh_handshakes=true");
    }
    let profile = Profile::create();
    let fixture = Fixture::start("success", &profile);
    let untrusted = client_builder().no_proxy().build().unwrap();
    let mut events = Vec::new();
    let error = fetch_using_client(
        &fixture.url,
        &profile,
        Some(&mut |e| events.push(e)),
        &mut |_| false,
        &untrusted,
    )
    .err()
    .unwrap();
    assert_eq!(error, "HTTPS configuration unavailable");
    assert_eq!(
        events
            .iter()
            .filter(|e| e["step"] == "00.fetch_attempt")
            .count(),
        1
    );
    assert!(fixture.requests().is_empty());
    println!("PASS invalid TLS certificate rejected without retry or HTTP request");

    for cancel_before_first in [false, true] {
        let profile = Profile::create();
        let fixture = Fixture::start("always_503", &profile);
        let error = fetch_using_client(
            &fixture.url,
            &profile,
            None,
            &mut |delay| cancel_before_first || !delay.is_zero(),
            &fixture.client,
        )
        .err()
        .unwrap();
        assert_eq!(error, "configuration fetch cancelled");
        assert_eq!(fixture.requests().len(), usize::from(!cancel_before_first));
        println!("PASS cancellation before_first={cancel_before_first}");
    }
}
