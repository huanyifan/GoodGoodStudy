use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(ggs_private_payload)");
    println!("cargo:rerun-if-env-changed=GGS_INSTALL_PAYLOAD");
    println!("cargo:rerun-if-changed=resources/setup.manifest");
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    if let Some(payload) = env::var_os("GGS_INSTALL_PAYLOAD") {
        println!("cargo:rustc-cfg=ggs_private_payload");
        let payload = PathBuf::from(payload);
        println!("cargo:rerun-if-changed={}", payload.display());
        fs::copy(payload, out.join("payload.zip")).expect("private installer payload unavailable");
    } else {
        fs::write(out.join("payload.zip"), []).unwrap();
    }
    let kits = PathBuf::from(env::var_os("ProgramFiles(x86)").unwrap()).join("Windows Kits/10/bin");
    let mut compilers: Vec<_> = fs::read_dir(kits)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("x64/rc.exe"))
        .filter(|path| path.is_file())
        .collect();
    compilers.sort();
    let rc = compilers
        .last()
        .expect("Windows SDK resource compiler required");
    let manifest = root
        .join("resources/setup.manifest")
        .display()
        .to_string()
        .replace('\\', "\\\\");
    let icon = root
        .join("../Resources/book.ico")
        .display()
        .to_string()
        .replace('\\', "\\\\");
    let source = out.join("setup.rc");
    fs::write(
        &source,
        format!("#pragma code_page(65001)\n1 24 \"{manifest}\"\n1 ICON \"{icon}\"\n"),
    )
    .unwrap();
    let resource = out.join("setup.res");
    let status = Command::new(rc)
        .arg("/nologo")
        .arg("/fo")
        .arg(&resource)
        .arg(source)
        .status()
        .unwrap();
    assert!(status.success(), "installer resources could not be built");
    println!(
        "cargo:rustc-link-arg-bin=goodgoodstudy-setup={}",
        resource.display()
    );
}
