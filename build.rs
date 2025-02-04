use libbpf_cargo::SkeletonBuilder;
use std::ffi::OsStr;
use std::process::{Command, Stdio};
use std::fs::File;
use std::os::unix::io::{FromRawFd, IntoRawFd};

fn main() -> Result<(), std::io::Error> {
    let file = File::create("src/bpf/vmlinux.h").expect("cannot create file.");

    let _vmlinux = Command::new("bpftool")
        .arg("btf")
        .arg("dump")
        .arg("file")
        .arg("/sys/kernel/btf/vmlinux")
        .arg("format")
        .arg("c")
        .stdout(unsafe {Stdio::from_raw_fd(file.into_raw_fd())})
        .output();

    SkeletonBuilder::new()
        .source("src/bpf/fsfilter.bpf.c")
        .debug(true)
        .clang_args([
            OsStr::new("-I"),
            OsStr::new("src/bpf"),
        ])
        .build_and_generate("./src/bpf/fsfilter.skel.rs")
        .unwrap();

    Ok(())
}
