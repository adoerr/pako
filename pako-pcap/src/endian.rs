#![allow(dead_code)]

pub enum BigEndian {}

/// System native endianness
#[cfg(target_endian = "big")]
pub type NativeEndian = BigEndian;

pub enum LittleEndian {}

/// System native endianness
#[cfg(target_endian = "little")]
pub type NativeEndian = LittleEndian;
