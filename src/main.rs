use std::mem::MaybeUninit;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::OpenSkel;
use std::error::Error;

mod fsfilter {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/fsfilter.skel.rs"
    ));
}

use fsfilter::*;

fn handle_event(_data: &[u8]) -> i32 {
    println!("handler called!");
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
