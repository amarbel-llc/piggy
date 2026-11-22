//! hogtie(8); the command line is `hogtie::cli`.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    hogtie::cli::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("hogtie runs on Linux only");
    std::process::ExitCode::from(3)
}
