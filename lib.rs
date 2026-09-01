pub fn version() -> &'static str {
    "0.1.0"

}

/// A trap is a safe crash of the guest.
/// The host process (this VM) must stay alive and report the trap to the user


/// derive is rust generating extra helpers to debug, etc
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trap {
    Malformed, 
    Unsupported, 
    Limit, 
    Runtime, 
    Exit(i32),
}

/// limits 
pub struct Limits {
    /// how many instructions we can run before we trap
    pub fuel: u64, 
    /// max guest ram in pages. one page = 64KB 
    pub memory_pages: u32, 
    /// how many deep guest functions may call each other 
    /// to avoid infinite recursion 
    pub call_depth: u32, 
    /// max bytes a guest can wrie to stdout/stderr
    pub out_bytes: u64
}
/// 64 bit box that can hold one wasm number 
/// run loop stores stack value as a u64 and does not tag the type at runtime
/// i32, i64, f32 and f64 are all stored as u64 wasm and fits in 64 bits 
pub type Slot = u64; 



/// read an unsigned 32-bit LEB128 number from `bytes`, starting at `*i`.
/// `*i` is our cursor: we move it forward as we eat bytes.
/// `Result<u32, Trap>` means: either the number, or a trap if the file is junk.
fn u32_leb(bytes: &[u8], i: &mut usize) -> Result<u32, Trap> {
    let mut result: u32 = 0;
    let mut shift = 0;

    // A u32 LEB is at most 5 bytes. A 6th byte is malformed.
    for _ in 0..5 {
        // `.get` is a safe index: None if we ran off the end of the file.
        let b = *bytes.get(*i).ok_or(Trap::Malformed)?;
        *i += 1;

        // Low 7 bits are payload. Glue them onto `result` at `shift`.
        result |= ((b & 0x7f) as u32) << shift;

        // High bit 0 means "this was the last byte".
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(Trap::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb_one_byte() {
        // 5 fits in 7 bits, so it is a single byte: 0x05.
        let bytes = [0x05];
        let mut i = 0;
        assert_eq!(u32_leb(&bytes, &mut i).unwrap(), 5);
        assert_eq!(i, 1);
    }

    #[test]
    fn leb_two_bytes() {
        // 300 needs two chunks: 0xAC, 0x02.
        let bytes = [0xAC, 0x02];
        let mut i = 0;
        assert_eq!(u32_leb(&bytes, &mut i).unwrap(), 300);
        assert_eq!(i, 2);
    }
    #[test]
fn header_only_is_ok() {
    // Smallest legal module: magic + version, no sections.
    let bytes = b"\0asm\x01\x00\x00\x00";
    assert_eq!(parse_module(bytes), Ok(()));
}

#[test]
fn bad_magic_is_malformed() {
    let bytes = b"nope\x01\x00\x00\x00xxxx";
    assert_eq!(parse_module(bytes), Err(Trap::Malformed));
}
}