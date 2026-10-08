use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::db::CsumDb;

// 4KB block size (BTRFS default)
pub const BLK_SIZE: u64 = 4;

/// Compute SHA256 hash of checksum data (used as short_hash in DB)
pub fn compute_csum_hash(csums: &[String]) -> String {
    let mut hasher = Sha256::new();
    let repr = format!("{:?}", csums);
    hasher.update(repr.as_bytes());
    hex::encode(hasher.finalize())
}

/// Locate the dedicated helper without falling back to an incompatible btrfs binary.
pub fn helper_path() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("DDUPER_BTRFS") {
        return path.into();
    }
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("dduper-btrfs");
        if sibling.is_file() {
            return sibling;
        }
    }
    for path in ["/usr/local/sbin/dduper-btrfs", "/usr/sbin/dduper-btrfs"] {
        if Path::new(path).is_file() {
            return path.into();
        }
    }
    "dduper-btrfs".into()
}

fn do_btrfs_dump_csum(filename: &Path, device: &Path) -> Result<Vec<String>> {
    let helper = helper_path();
    let before = std::fs::metadata(filename)?;
    let output = Command::new(&helper)
        .args(["inspect-internal", "dump-csum"])
        .arg(filename)
        .arg(device)
        .output()
        .with_context(|| {
            format!(
                "{}: checksums unavailable; helper {} could not start (exit status unavailable; stderr unavailable)",
                filename.display(),
                helper.display()
            )
        })?;
    let context = format!(
        "{}: helper {} exit status {}; stderr: {}",
        filename.display(),
        helper.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    if !output.status.success() {
        bail!("{context}; checksums unavailable");
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .with_context(|| format!("{context}; checksums unavailable"))?;
    let csums = crate::protocol::parse(stdout, before.len()).with_context(|| context.clone())?;
    if signature(&before) != signature(&std::fs::metadata(filename)?) {
        bail!("{context}; file changed during lookup; checksums unavailable");
    }
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(csums)
}

type Signature = (u64, u64, u64, i64, i64, i64, i64);
fn signature(meta: &std::fs::Metadata) -> Signature {
    use std::os::unix::fs::MetadataExt;
    (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}

// Cache only within this process, with filesystem/inode/size and nanosecond times.
// The SQLite database contains only this invocation's requested files.
type Cache = HashMap<(std::path::PathBuf, std::path::PathBuf), (Signature, Vec<String>)>;
thread_local! { static CACHE: std::cell::RefCell<Cache> = std::cell::RefCell::new(HashMap::new()); }

pub fn btrfs_dump_csum_cached(filename: &Path, device: &Path, db: &CsumDb) -> Result<Vec<String>> {
    let key = (std::fs::canonicalize(filename)?, device.to_path_buf());
    let stamp = signature(&std::fs::metadata(filename)?);
    let cached = CACHE.with(|c| {
        c.borrow()
            .get(&key)
            .filter(|(s, _)| *s == stamp)
            .map(|(_, v)| v.clone())
    });
    let csums = match cached {
        Some(csums) => csums,
        None => {
            let csums = do_btrfs_dump_csum(filename, device)?;
            CACHE.with(|c| c.borrow_mut().insert(key, (stamp, csums.clone())));
            csums
        }
    };
    let short_hash = compute_csum_hash(&csums);
    db.insert_csum(&filename.to_string_lossy(), &short_hash, &csums.join(" "))?;
    Ok(csums)
}

/// Group checksums into chunks and compute SHA256 hash for each chunk.
/// Returns (hash_map, collision_count) where hash_map maps SHA256 -> list of chunk offsets.
pub fn get_hashes(
    csums: &[String],
    ele_sz: usize,
    verbose: bool,
) -> (HashMap<String, Vec<usize>>, usize) {
    let mut hash_map: HashMap<String, Vec<usize>> = HashMap::new();
    let mut collision_count = 0;

    if ele_sz == 1 {
        for (idx, csum) in csums.iter().enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(csum.as_bytes());
            let hash = hex::encode(hasher.finalize());

            let entry = hash_map.entry(hash.clone()).or_default();
            if !entry.is_empty() {
                if verbose {
                    println!("Collision with: {} at offset: {}", hash, idx);
                }
                collision_count += 1;
            }
            entry.push(idx);
        }
    } else {
        for (idx, chunk) in csums.chunks(ele_sz).enumerate() {
            let chunk_str = chunk
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("");
            let mut hasher = Sha256::new();
            hasher.update(chunk_str.as_bytes());
            let hash = hex::encode(hasher.finalize());

            let entry = hash_map.entry(hash.clone()).or_default();
            if !entry.is_empty() {
                if verbose {
                    println!("Collision with: {} at offset: {}", hash, idx);
                }
                collision_count += 1;
            }
            entry.push(idx);
        }
    }

    (hash_map, collision_count)
}

/// Calculate element size based on chunk size in KB.
/// chunk_sz must be a positive multiple of 128.
pub fn get_ele_size(chunk_sz: u64) -> Result<usize> {
    if chunk_sz == 0 || chunk_sz > 16384 || !chunk_sz.is_multiple_of(128) {
        bail!("Ensure chunk size is a multiple of 128KB between 128KB and 16MiB");
    }
    let no_of_chunks = chunk_sz / BLK_SIZE;
    let ele_sz = no_of_chunks as usize;
    Ok(ele_sz)
}

/// Auto-adjust chunk size based on file size for perfect matches.
/// Returns (adjusted_chunk_sz, ele_sz).
pub fn auto_adjust_chunk_sz(
    src_file_sz: u64,
    analyze: bool,
    current_chunk_sz: u64,
) -> (u64, usize) {
    if analyze {
        return (
            current_chunk_sz,
            get_ele_size(current_chunk_sz).unwrap_or(1),
        );
    }

    let fz_mb = src_file_sz >> 20;

    let perfect_match_chunk_sz = if fz_mb >= 16 {
        16384
    } else if fz_mb >= 8 {
        8192
    } else if fz_mb >= 4 {
        4096
    } else if fz_mb >= 2 {
        2048
    } else if fz_mb >= 1 {
        1024
    } else if (src_file_sz >> 10) >= 512 {
        512
    } else {
        128
    };

    let ele_sz = get_ele_size(perfect_match_chunk_sz).unwrap_or(1);
    (perfect_match_chunk_sz, ele_sz)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ele_size_valid() {
        assert_eq!(get_ele_size(128).unwrap(), 32);
        assert_eq!(get_ele_size(256).unwrap(), 64);
        assert_eq!(get_ele_size(512).unwrap(), 128);
        assert_eq!(get_ele_size(1024).unwrap(), 256);
    }

    #[test]
    fn test_get_ele_size_invalid() {
        assert!(get_ele_size(0).is_err());
        assert!(get_ele_size(127).is_err());
        assert!(get_ele_size(100).is_err());
    }

    #[test]
    fn test_auto_adjust_chunk_sz() {
        // 16MB+ file -> 16384KB chunk
        let (sz, _) = auto_adjust_chunk_sz(20 * 1024 * 1024, false, 128);
        assert_eq!(sz, 16384);

        // 1MB file -> 1024KB chunk
        let (sz, _) = auto_adjust_chunk_sz(1024 * 1024, false, 128);
        assert_eq!(sz, 1024);

        // 100KB file -> 128KB chunk
        let (sz, _) = auto_adjust_chunk_sz(100 * 1024, false, 128);
        assert_eq!(sz, 128);

        // Analyze mode: keep current chunk_sz
        let (sz, _) = auto_adjust_chunk_sz(20 * 1024 * 1024, true, 256);
        assert_eq!(sz, 256);
    }

    #[test]
    fn test_get_hashes_ele_sz_1() {
        let csums: Vec<String> = vec!["0xaa".into(), "0xbb".into(), "0xaa".into()];
        let (map, collisions) = get_hashes(&csums, 1, false);
        // 0xaa appears twice -> 1 collision
        assert_eq!(collisions, 1);
        // Should have 2 unique hashes
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_compute_csum_hash() {
        let csums = vec!["0x1234".to_string(), "0x5678".to_string()];
        let hash = compute_csum_hash(&csums);
        // Should be deterministic
        assert_eq!(hash, compute_csum_hash(&csums));
        // Should be different for different input
        let other = vec!["0xabcd".to_string()];
        assert_ne!(hash, compute_csum_hash(&other));
    }
}
