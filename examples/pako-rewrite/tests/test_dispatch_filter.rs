use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use assert_cmd::Command;
use pcap_parser::PcapCapture;

/// Return the number of packets in `file`
fn packet_count(file: &Path) -> Result<u32> {
    let packets = fs::read(file)?;

    // empty file -> zero packets
    if packets.is_empty() {
        return Ok(0);
    }

    // we can't use the question mark operator here, because the returned
    // `PcapError` would keep `packets` borrowed
    Ok(PcapCapture::from_file(&packets)
        .expect("no capture found!")
        .blocks
        .len() as u32)
}

/// Rewrite the `input` pcap file into `output`. Apply the given filter and
/// assert that `expected_count` packages have been written into `output`
fn rewrite(
    input: PathBuf,
    output: PathBuf,
    filter_args: PathBuf,
    filter: &str,
    expected_count: u32,
) -> Result<()> {
    let mut trace_in = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    trace_in.push(input);
    let mut trace_out = env::temp_dir();
    trace_out.push(output);
    let mut key_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    key_file.push(filter_args);

    Command::cargo_bin(env!("CARGO_PKG_NAME"))?
        .arg("-f")
        .arg(format!("Dispatch:{}%k%{}", filter, key_file.display()))
        .arg(&trace_in)
        .arg(&trace_out)
        .assert()
        .success();

    let count = packet_count(&trace_out)?;
    // remove temp file
    fs::remove_file(&trace_out)?;
    assert_eq!(count, expected_count);
    Ok(())
}

// IPV4

#[test]
fn test_filter_ipv4_src_ipaddr() -> Result<()> {
    rewrite(
        "../assets/nmap_tcp_22_ipv4.pcap".into(),
        "output_src_ip_addr_ipv4".into(),
        "../assets/pcap-filter/ipv4_ipaddr".into(),
        "si",
        2,
    )
}

#[test]
fn test_filter_ipv4_dst_ipaddr() -> Result<()> {
    rewrite(
        "../assets/nmap_tcp_22_ipv4.pcap".into(),
        "output_dst_ip_addr_ipv4".into(),
        "../assets/pcap-filter/ipv4_ipaddr".into(),
        "di",
        2,
    )
}

#[test]
fn test_filter_ipv4_src_dst_ipaddr() -> Result<()> {
    rewrite(
        "../assets/nmap_tcp_22_ipv4.pcap".into(),
        "output_src_dst_ip_addr_ipv4".into(),
        "../assets/pcap-filter/ipv4_ipaddr".into(),
        "sdi",
        4,
    )
}

#[test]
fn test_filter_ipv4_src_ipaddr_proto_dst_port() -> Result<()> {
    rewrite(
        "../assets/nmap_tcp_22_ipv4.pcap".into(),
        "output_src_ipaddr_proto_dst_port_ipv4".into(),
        "../assets/pcap-filter/ipv4_ipaddr_proto_port".into(),
        "sipdp",
        1,
    )
}

#[test]
fn test_filter_ipv4_five_tuple() -> Result<()> {
    rewrite(
        "../assets/nmap_tcp_22_ipv4.pcap".into(),
        "output_five_tuple_ipv4".into(),
        "../assets/pcap-filter/ipv4_five_tuple".into(),
        "sdipsdp",
        2,
    )
}

// IPV6

#[test]
fn test_filter_ipv6_src_ipaddr() -> Result<()> {
    rewrite(
        "../assets/nmap_tcp_22_ipv6.pcap".into(),
        "output_src_ipaddr_ipv6.cap".into(),
        "../assets/pcap-filter/ipv6_ipaddr".into(),
        "si",
        2,
    )
}

#[test]
fn test_filter_ipv6_dst_ipaddr() -> Result<()> {
    rewrite(
        "../assets/nmap_tcp_22_ipv6.pcap".into(),
        "output_dst_ipaddr_ipv6.cap".into(),
        "../assets/pcap-filter/ipv6_ipaddr".into(),
        "di",
        2,
    )
}

#[test]
fn test_filter_ipv6_src_dst_ipaddr() -> Result<()> {
    rewrite(
        "../assets/nmap_tcp_22_ipv6.pcap".into(),
        "output_src_dst_ipaddr_ipv6.cap".into(),
        "../assets/pcap-filter/ipv6_ipaddr".into(),
        "sdi",
        4,
    )
}

#[test]
fn test_filter_ipv6_src_ipaddr_proto_dst_port() -> Result<()> {
    rewrite(
        "../assets/nmap_tcp_22_ipv6.pcap".into(),
        "output_src_ipaddr_proto_dst_port_ipv6".into(),
        "../assets/pcap-filter/ipv6_ipaddr_proto_port".into(),
        "sipdp",
        1,
    )
}

#[test]
fn test_filter_ipv6_five_tuple() -> Result<()> {
    rewrite(
        "../assets/nmap_tcp_22_ipv6.pcap".into(),
        "output_five_tuple_ipv6".into(),
        "../assets/pcap-filter/ipv6_five_tuple".into(),
        "sdipsdp",
        2,
    )
}
