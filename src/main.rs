use std::mem::MaybeUninit;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::OpenSkel;
use std::error::Error;
use std::io::Cursor;
use std::io::BufRead;
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
    let mut buf: Vec<u8> = Vec::new();
    let fd = cur.read_i32::<LittleEndian>().unwrap();
    let dfd = cur.read_i32::<LittleEndian>().unwrap();
    let _size = cur.read_until(0x00, &mut buf);
    let filename = String::from_utf8(buf).unwrap();
    println!("fd:{0}, dfd:{1}, filename:{2}", fd, dfd, filename);
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
