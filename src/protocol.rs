use anyhow::{bail, Result};

pub const BLOCK_BYTES: u64 = 4096;
pub const MAGIC: &str = "dduper-csum-v1";

/// One token represents one logical 4 KiB file block, including a short EOF block.
/// A header and exact token count prevent accepting diagnostics, old helpers,
/// truncated output, or absent checksums as a successful lookup.
pub fn parse(output: &str, size: u64) -> Result<Vec<String>> {
    let mut lines = output.lines();
    let expected = size.div_ceil(BLOCK_BYTES) as usize;
    let header = format!("{MAGIC} {BLOCK_BYTES} {size} {expected}");
    if lines.next() != Some(header.as_str()) {
        bail!("checksums unavailable: missing/invalid protocol header (expected {header:?})");
    }
    let tokens: Vec<_> = lines.map(str::to_owned).collect();
    if expected == 0 || tokens.len() != expected {
        bail!(
            "checksums unavailable/incomplete: expected {expected} blocks, got {}",
            tokens.len()
        );
    }
    if tokens
        .iter()
        .any(|s| s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        bail!("checksums unavailable: malformed block token");
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_empty_old_truncated_and_diagnostic_output() {
        for s in [
            "",
            "deadbeef\n",
            "ERROR deadbeef\n",
            "dduper-csum-v1 4096 8192 2\n",
        ] {
            assert!(parse(s, 8192).is_err());
        }
    }
    #[test]
    fn accepts_partial_last_block_only_with_exact_count() {
        let s = format!(
            "{MAGIC} 4096 4097 2\n{}\n{}\n",
            "a".repeat(64),
            "b".repeat(64)
        );
        assert_eq!(parse(&s, 4097).unwrap().len(), 2);
        assert!(parse(&s, 4096).is_err());
    }
}
