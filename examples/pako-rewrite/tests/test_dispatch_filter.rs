use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use assert_cmd::Command;
use pcap_parser::PcapCapture;

// Return the number of packets in `file`
fn packet_count(file: &Path) -> Result<u32> {
    let packets = fs::read(file)?;

    // empty file -> zero packages
    if packets.len() == 0 {
        return Ok(0);
    }

    // we can't use the question mark operator here, because the returned
    // `PcapError` would keep `packets` borrowed
    Ok(PcapCapture::from_file(&packets)
        .expect("no capture found!")
        .blocks
        .len() as u32)
}

fn generic_test(
    trace_input_file_s: &str,
    trace_output_file_s: &str,
    key_file_s: &str,
    key_s: &str,
    expected_packet_number: u32,
) -> Result<()> {
    let mut trace_input_file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    trace_input_file_path.push(trace_input_file_s);

    let mut trace_output_file_path = std::env::temp_dir();
    trace_output_file_path.push(trace_output_file_s);

    let mut key_file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    key_file_path.push(key_file_s);

    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME"))?;
    cmd.arg("-f")
        .arg(format!("Dispatch:{}%k%{}", key_s, key_file_path.display()))
        .arg(&trace_input_file_path)
        .arg(&trace_output_file_path);

    cmd.output()?;

    let output_nb_packet = packet_count(&trace_output_file_path)?;

    fs::remove_file(&trace_output_file_path)?;

    assert_eq!(output_nb_packet, expected_packet_number);

    Ok(())
}

// IPV4

#[test]
fn test_filter_ipv4_src_ipaddr() -> Result<()> {
    generic_test(
        "../assets/nmap_tcp_22_ipv4.pcap",
        "output_src_ip_addr_ipv4",
        "../assets/pcap-filter/ipv4_ipaddr",
        "si",
        2,
    )
}

#[test]
fn test_filter_ipv4_dst_ipaddr() -> Result<()> {
    generic_test(
        "../assets/nmap_tcp_22_ipv4.pcap",
        "output_dst_ip_addr_ipv4",
        "../assets/pcap-filter/ipv4_ipaddr",
        "di",
        2,
    )
}

#[test]
fn test_filter_ipv4_src_dst_ipaddr() -> Result<()> {
    generic_test(
        "../assets/nmap_tcp_22_ipv4.pcap",
        "output_src_dst_ip_addr_ipv4",
        "../assets/pcap-filter/ipv4_ipaddr",
        "sdi",
        4,
    )
}

#[test]
fn test_filter_ipv4_src_ipaddr_proto_dst_port() -> Result<()> {
    generic_test(
        "../assets/nmap_tcp_22_ipv4.pcap",
        "output_src_ipaddr_proto_dst_port_ipv4",
        "../assets/pcap-filter/ipv4_ipaddr_proto_port",
        "sipdp",
        1,
    )
}

#[test]
fn test_filter_ipv4_five_tuple() -> Result<()> {
    generic_test(
        "../assets/nmap_tcp_22_ipv4.pcap",
        "output_five_tuple_ipv4",
        "../assets/pcap-filter/ipv4_five_tuple",
        "sdipsdp",
        2,
    )
}

// IPV6

#[test]
fn test_filter_ipv6_src_ipaddr() -> Result<()> {
    generic_test(
        "../assets/nmap_tcp_22_ipv6.pcap",
        "output_src_ipaddr_ipv6.cap",
        "../assets/pcap-filter/ipv6_ipaddr",
        "si",
        2,
    )
}

#[test]
fn test_filter_ipv6_dst_ipaddr() -> Result<()> {
    generic_test(
        "../assets/nmap_tcp_22_ipv6.pcap",
        "output_dst_ipaddr_ipv6.cap",
        "../assets/pcap-filter/ipv6_ipaddr",
        "di",
        2,
    )
}

#[test]
fn test_filter_ipv6_src_dst_ipaddr() -> Result<()> {
    generic_test(
        "../assets/nmap_tcp_22_ipv6.pcap",
        "output_src_dst_ipaddr_ipv6.cap",
        "../assets/pcap-filter/ipv6_ipaddr",
        "sdi",
        4,
    )
}

#[test]
fn test_filter_ipv6_src_ipaddr_proto_dst_port() -> Result<()> {
    generic_test(
        "../assets/nmap_tcp_22_ipv6.pcap",
        "output_src_ipaddr_proto_dst_port_ipv6",
        "../assets/pcap-filter/ipv6_ipaddr_proto_port",
        "sipdp",
        1,
    )
}

#[test]
fn test_filter_ipv6_five_tuple() -> Result<()> {
    generic_test(
        "../assets/nmap_tcp_22_ipv6.pcap",
        "output_five_tuple_ipv6",
        "../assets/pcap-filter/ipv6_five_tuple",
        "sdipsdp",
        2,
    )
}
