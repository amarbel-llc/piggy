//! `VmLck` grows by at least a page per allocation (piggy#378). Its own
//! test binary, so no other test allocates or frees locked memory in the
//! same process while it measures.

#[cfg(target_os = "linux")]
fn vm_locked_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmLck:"))
        .and_then(|v| v.trim().strip_suffix("kB"))
        .map(|v| v.trim().parse().unwrap())
        .expect("a VmLck line")
}

#[cfg(target_os = "linux")]
#[test]
fn each_allocation_locks_at_least_a_page() {
    let page_kib = 4;
    let before = vm_locked_kib();
    let secrets: Vec<_> = (0..3)
        .map(|_| piggy_guard::GuardedBytes::from_slice(b"123456").unwrap())
        .collect();
    if !secrets.iter().all(|s| s.protections().locked) {
        eprintln!(
            "skipped: mlock was refused here (RLIMIT_MEMLOCK); protections {:?}",
            secrets[0].protections()
        );
        return;
    }
    let held = vm_locked_kib();
    assert!(
        held >= before + 3 * page_kib,
        "VmLck {before} kB -> {held} kB for 3 allocations"
    );
    drop(secrets);
    assert_eq!(vm_locked_kib(), before, "dropping unlocks");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn each_allocation_locks_at_least_a_page() {
    eprintln!("skipped: VmLck is read from /proc/self/status, which only Linux has");
}
