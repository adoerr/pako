use std::io::Read;

use crate::error::Error;

/// Interface for all Pcap engines
pub trait PcapEngine {
    /// Main function: given a reader, read all pcap data and call analyzer for each Packet
    fn run(&mut self, f: &mut dyn Read) -> Result<(), Error>;
}
