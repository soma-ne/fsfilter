use std::mem::MaybeUninit;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::OpenSkel;
use std::error::Error;
use std::io::Cursor;
use std::io::Read;
use std::path::{PathBuf};
use std::sync::Mutex;
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

const TYPE_OPEN :&str = "OPEN";
const FILE_RAW: &str = "RAW";
const FILE_PROC: &str = "PROC";

struct RecordList<'a> {
    list: Mutex<Vec<Record<'a>>>,
}

struct Record<'a> {
    rec_type: &'a str,
    fd: i32,
    pid: u32,
    user: String,
    comm: String,
    filename: String,
}

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

fn clean_str_buf(slice: &[u8]) -> &[u8] {
    if let Some(pos) = slice.iter().position(|&x| x == 0) {
        &slice[..=pos]
    } else {
        slice
    }
}

fn handle_event(data: &[u8]) -> i32 {
    let mut cur = Cursor::new(data);
    let fd = cur.read_i32::<LittleEndian>().unwrap();
    let pid = cur.read_u32::<LittleEndian>().unwrap();

    let mut filename_buf = [0;255];
    let _size = cur.read_exact(&mut filename_buf);
    let mut filename: String = String::from_utf8_lossy(clean_str_buf(&filename_buf))
                        .trim_matches('\0').to_string();

    let mut filename_type = FILE_RAW;

    let mut comm_buf = [0;255];
    let _size = cur.read_exact(&mut comm_buf);
    let comm: String = String::from_utf8_lossy(&comm_buf)
                    .trim_matches('\0').to_string();

    if comm == "fsfilter".to_string() {
        return 0;
    }

    if fd > 0 {
        let fd_path = format!("/proc/{}/fd/{}", pid, fd);
        let tmp = fs::read_link(fd_path)
                        .map_or(PathBuf::new(), |s| s)
                        .to_str().unwrap().to_string();
        if tmp != "".to_string() {
            filename = tmp;
            filename_type = FILE_PROC;
        }
    }

    let user: String = get_user_from_pid(pid);

    println!("{0:5}  {1:4}  {2:6}  {3:15}  {4:15}  {5:5} {6:25}",
             TYPE_OPEN, fd, pid, user, &comm, filename_type, filename);

    let record: Record = Record {
        rec_type: TYPE_OPEN,
        fd: fd,
        pid: pid,
        user: user,
        comm: comm,
        filename: filename,
    };

    REC_LIST.list.lock().unwrap().push(record);

    0
}

static REC_LIST: RecordList = RecordList { list: Mutex::new(Vec::<Record>::new()) };

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
    println!(" TYPE   FD     PID        USER             COMM         TYPE           FILENAME");

    loop {
        ringbuf.poll(std::time::Duration::from_millis(100))?;
    }
}
