use std::mem::MaybeUninit;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::OpenSkel;
use std::error::Error;
use std::io::Cursor;
use std::io::Read;
use std::path::{PathBuf};
use std::fs;
use regex::Regex;
use byteorder::{LittleEndian, ReadBytesExt};

mod fsfilter {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/fsfilter.skel.rs"
    ));
}

use fsfilter::*;

fn get_user_from_pid(pid: u32) -> String {
    let path = format!("/proc/{}/status", pid);
    let content = fs::read_to_string(path)
                    .map_or("".to_string(), |s| s);
    let mut re = Regex::new(r"Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)").unwrap();

    if let Some(caps) = re.captures(&content) {
        let uid = caps.get(1).unwrap().as_str();

        let passwd = fs::read_to_string("/etc/passwd")
                        .map_or("".to_string(), |s| s);

        let pattern = format!(r"(?m)^(.+):x:{}", uid);
        re = Regex::new(&pattern).unwrap();

        if let Some(caps) = re.captures(&passwd) {
            let user = caps.get(1).unwrap().as_str();
            return user.to_string();
        }
    }

    return "".to_string();
}

fn handle_event(data: &[u8]) -> i32 {
    let mut cur = Cursor::new(data);
    let fd = cur.read_i32::<LittleEndian>().unwrap();
    let pid = cur.read_u32::<LittleEndian>().unwrap();

    let mut comm_buf = [0;255];
    let _size = cur.read_exact(&mut comm_buf);
    let comm = std::str::from_utf8(&comm_buf)
                   .map_or("".to_string(), |s| s.to_string())
                   .trim_matches('\0')
                   .to_string();

    if comm == "fsfilter" {
        return 0;
    }

    let mut filename: String = "".to_string();
    if fd > 0 {
        let fd_path = format!("/proc/{}/fd/{}", pid, fd);
        filename = fs::read_link(fd_path)
                        .map_or(PathBuf::new(), |s| s)
                        .to_str().unwrap().to_string();
    }

    let user: String = get_user_from_pid(pid);

    println!("fd:{0:4}  pid:{1:6}  user:{2:25}  comm:{3:25} filename:{4:25}", fd, pid, user, &comm, filename);
    0
}

fn main() -> Result<(), Box<dyn Error>> {
    let skel_builder = FsfilterSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(&skel.maps.rb, handle_event)?;

    let ringbuf = ringbuf_builder.build()?;

    println!("Tracing started.");

    loop {
        ringbuf.poll(std::time::Duration::from_millis(100))?;
    }
}
