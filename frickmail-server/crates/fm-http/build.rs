use std::{fs, process};

fn main() {
    let package_path = "../../../package.json";
    println!("cargo:rerun-if-changed={package_path}");

    let package_json = match fs::read_to_string(package_path) {
        Ok(package_json) => package_json,
        Err(err) => {
            eprintln!("failed to read {package_path}: {err}");
            process::exit(1);
        }
    };
    let Some(version) = package_version(&package_json) else {
        eprintln!("failed to parse version from {package_path}");
        process::exit(1);
    };

    println!("cargo:rustc-env=FRICKMAIL_WEBMAIL_VERSION={version}");
}

fn package_version(package_json: &str) -> Option<&str> {
    package_json.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("\"version\"")?.trim_start();
        let rest = rest.strip_prefix(':')?.trim_start();
        let rest = rest.strip_prefix('"')?;
        rest.split('"').next()
    })
}
