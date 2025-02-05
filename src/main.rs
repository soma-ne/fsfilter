use std::mem::MaybeUninit;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::OpenSkel;
use std::error::Error;
use std::io::Cursor;
use std::io::Read;
use byteorder::{LittleEndian, ReadBytesExt};

mod fsfilter {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/fsfilter.skel.rs"
    ));
}

use fsfilter::*;

fn handle_event(data: &[u8]) -> i32 {
    let mut cur = Cursor::new(data);
    let fd = cur.read_i32::<LittleEndian>().unwrap();
    let dfd = cur.read_i32::<LittleEndian>().unwrap();
    let pid = cur.read_i32::<LittleEndian>().unwrap();

    let mut comm_buf = [0;255];
    let _size = cur.read_exact(&mut comm_buf);
    let comm = std::str::from_utf8(&comm_buf)
                   .map_or("".to_string(), |s| s.to_string())
                   .trim_matches('\0')
                   .to_string();

    let mut filename_buf = [0;255];
    let _size = cur.read_exact(&mut filename_buf);
    let filename = std::str::from_utf8(&filename_buf)
                       .map_or("".to_string(), |s| s.to_string())
                       .trim_matches('\0')
                       .to_string();

    println!("fd:{0:4}    dfd:{1:4}    pid:{2:6}      comm:{3:25}  filename:{4:25}", fd, dfd, pid, &comm, &filename);
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
