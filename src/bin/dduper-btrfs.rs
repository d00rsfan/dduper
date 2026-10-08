//! Mounted-filesystem replacement for the obsolete btrfs-progs dump-csum patch.
//! All tree access is read-only through the running kernel, never raw disk IO.
use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[path = "../protocol.rs"]
mod protocol;
use protocol::{BLOCK_BYTES, MAGIC};

unsafe extern "C" {
    fn dduper_info(
        fd: i32,
        root: *mut u64,
        sector: *mut u32,
        node: *mut u32,
        csum_type: *mut u16,
        csum_size: *mut u16,
    ) -> i32;
    fn dduper_device(fd: i32, device: *const libc::c_char) -> i32;
    fn dduper_search(
        fd: i32,
        root: u64,
        objectid: u64,
        kind: u32,
        start: u64,
        end: u64,
        buf: *mut u8,
        capacity: u32,
        count: *mut u32,
    ) -> i32;
}

#[derive(Debug)]
struct Unavailable(&'static str);
impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "checksums unavailable: {}", self.0)
    }
}
impl std::error::Error for Unavailable {}

fn checked(ret: i32) -> Result<()> {
    if ret < 0 {
        return Err(io::Error::from_raw_os_error(-ret).into());
    }
    Ok(())
}

#[derive(Debug)]
struct Item {
    offset: u64,
    data: Vec<u8>,
}

fn le64(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data.get(offset..offset + 8)
            .context("truncated Btrfs item")?
            .try_into()?,
    ))
}

fn search(
    file: &File,
    root: u64,
    objectid: u64,
    kind: u32,
    start: u64,
    end: u64,
) -> Result<Vec<Item>> {
    let mut result = Vec::new();
    let mut next = start;
    loop {
        let mut buffer = vec![0u8; 256 * 1024];
        let mut count = 0;
        // SAFETY: C receives an allocated buffer with its exact size and valid output pointer.
        checked(unsafe { dduper_search(file.as_raw_fd(), root, objectid, kind, next, end,
            buffer.as_mut_ptr(), buffer.len() as u32, &mut count) })
            .with_context(|| format!("TREE_SEARCH root={root} inode/object={objectid} type={kind}; CAP_SYS_ADMIN (sudo) required"))?;
        if count == 0 {
            break;
        }
        let mut pos = 0;
        for _ in 0..count {
            let h = buffer
                .get(pos..pos + 32)
                .context("truncated search header")?;
            let obj = u64::from_ne_bytes(h[8..16].try_into()?);
            let offset = u64::from_ne_bytes(h[16..24].try_into()?);
            let typ = u32::from_ne_bytes(h[24..28].try_into()?);
            let len = u32::from_ne_bytes(h[28..32].try_into()?) as usize;
            ensure!(
                obj == objectid && typ == kind && offset >= next && offset <= end,
                "unexpected/out-of-order Btrfs search key"
            );
            pos += 32;
            let data = buffer
                .get(pos..pos + len)
                .context("truncated search item")?
                .to_vec();
            pos += len;
            result.push(Item { offset, data });
            if offset == end {
                return Ok(result);
            }
            next = offset + 1;
        }
    }
    Ok(result)
}

fn fingerprint(m: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn token(domain: &[u8], length: u64, data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(length.to_le_bytes());
    h.update(data);
    hex::encode(h.finalize())
}

fn content_tokens(file: &mut File, size: u64) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut remaining = size;
    let mut buffer = [0u8; BLOCK_BYTES as usize];
    while remaining > 0 {
        let len = remaining.min(BLOCK_BYTES) as usize;
        file.read_exact(&mut buffer[..len])
            .context("reading logical file contents")?;
        tokens.push(token(b"content-sha256-v1", len as u64, &buffer[..len]));
        remaining -= len as u64;
    }
    Ok(tokens)
}

/// None means an extent layout needing the explicitly reported logical-data fallback.
fn native_tokens(
    file: &File,
    extents: &[Item],
    size: u64,
    node: u32,
    csum_type: u16,
    csum_size: u16,
) -> Result<Option<Vec<String>>> {
    let mut covered = 0;
    for e in extents {
        ensure!(e.data.len() >= 21, "truncated extent item");
        if e.offset != covered || e.data[20] != 1 || e.data[16] != 0 {
            return Ok(None); // hole, inline, preallocation, compression
        }
        ensure!(e.data[17..20] == [0, 0, 0], "unsupported encoded extent");
        let disk = le64(&e.data, 21)?;
        let len = le64(&e.data, 45)?;
        if disk == 0 {
            return Ok(None);
        }
        ensure!(
            len > 0 && len.is_multiple_of(BLOCK_BYTES),
            "invalid extent length"
        );
        covered = covered.checked_add(len).context("extent length overflow")?;
    }
    if covered < size {
        return Ok(None);
    }
    let mut tokens = Vec::new();
    for e in extents {
        if e.offset >= size {
            break;
        }
        let disk = le64(&e.data, 21)?;
        let disk_len = le64(&e.data, 29)?;
        let extent_offset = le64(&e.data, 37)?;
        let len = le64(&e.data, 45)?.min((size - e.offset).div_ceil(BLOCK_BYTES) * BLOCK_BYTES);
        ensure!(
            extent_offset
                .checked_add(len)
                .is_some_and(|n| n <= disk_len),
            "extent exceeds disk range"
        );
        let start = disk
            .checked_add(extent_offset)
            .context("extent address overflow")?;
        let end = start.checked_add(len).context("extent end overflow")?;
        // TREE_SEARCH has no predecessor operation. A checksum item cannot exceed
        // one metadata leaf, so searching this bounded lookbehind includes the item
        // containing start even when start is in the middle of an existing item.
        let lookbehind = (node as u64 / csum_size as u64) * BLOCK_BYTES;
        let items = search(
            file,
            7,
            u64::MAX - 9,
            128,
            start.saturating_sub(lookbehind),
            end - 1,
        )?;
        let mut at = start;
        for item in items {
            ensure!(
                !item.data.is_empty() && item.data.len().is_multiple_of(csum_size as usize),
                "invalid checksum item size"
            );
            let item_end = item
                .offset
                .checked_add((item.data.len() / csum_size as usize) as u64 * BLOCK_BYTES)
                .context("checksum range overflow")?;
            if item_end <= at {
                continue;
            }
            if item.offset > at {
                break;
            }
            ensure!(
                (at - item.offset).is_multiple_of(BLOCK_BYTES),
                "misaligned checksum item"
            );
            while at < item_end && at < end {
                let index = ((at - item.offset) / BLOCK_BYTES) as usize * csum_size as usize;
                let logical = e.offset + at - start;
                let mut domain = b"btrfs-csum-v1".to_vec();
                domain.extend_from_slice(&csum_type.to_le_bytes());
                tokens.push(token(
                    &domain,
                    (size - logical).min(BLOCK_BYTES),
                    &item.data[index..index + csum_size as usize],
                ));
                at += BLOCK_BYTES;
            }
            if at == end {
                break;
            }
        }
        if at != end {
            return Err(
                Unavailable("missing checksum coverage (NODATASUM or changing extents)").into(),
            );
        }
    }
    ensure!(
        tokens.len() as u64 == size.div_ceil(BLOCK_BYTES),
        "incomplete logical block coverage"
    );
    Ok(Some(tokens))
}

fn dump(path: &Path, device: &Path) -> Result<()> {
    let mut file = File::open(path).context("open file")?;
    let initial = file.metadata()?;
    ensure!(initial.is_file(), "not a regular file");
    let mut root = 0;
    let (mut sector, mut node, mut csum_type, mut csum_size) = (0, 0, 0, 0);
    // SAFETY: all output pointers refer to live correctly typed locals.
    checked(unsafe {
        dduper_info(
            file.as_raw_fd(),
            &mut root,
            &mut sector,
            &mut node,
            &mut csum_type,
            &mut csum_size,
        )
    })
    .context("resolve containing Btrfs subvolume")?;
    let device = CString::new(device.as_os_str().as_bytes())?;
    checked(unsafe { dduper_device(file.as_raw_fd(), device.as_ptr()) }).context(
        "device does not belong to file's mounted Btrfs filesystem, or cannot be inspected",
    )?;
    ensure!(
        sector == BLOCK_BYTES as u32,
        "unsupported sectorsize {sector}; this protocol requires 4096 bytes"
    );
    ensure!(
        matches!((csum_type, csum_size), (0, 4) | (1, 8) | (2, 32) | (3, 32)),
        "unsupported Btrfs checksum type/size {csum_type}/{csum_size}"
    );
    if initial.len() == 0 {
        return Err(Unavailable("empty file").into());
    }
    // Flush this file's delayed allocation before reading its live extent tree.
    file.sync_all().context("fsync before extent lookup")?;
    let inodes = search(&file, root, initial.ino(), 1, 0, 0)?;
    ensure!(
        inodes.len() == 1,
        "inode missing in containing subvolume {root}"
    );
    if le64(&inodes[0].data, 64)? & 1 != 0 {
        return Err(Unavailable("NODATASUM file has no Btrfs data checksums").into());
    }
    let extents = search(&file, root, initial.ino(), 108, 0, u64::MAX)?;
    let (tokens, method) =
        match native_tokens(&file, &extents, initial.len(), node, csum_type, csum_size)? {
            Some(tokens) => (tokens, "Btrfs checksum tree"),
            None => (
                content_tokens(&mut file, initial.len())?,
                "logical SHA256 fallback (compressed/inline/sparse/preallocated)",
            ),
        };
    ensure!(
        fingerprint(&initial) == fingerprint(&file.metadata()?),
        "file changed during checksum lookup; retry with a quiescent file"
    );
    ensure!(!tokens.is_empty(), "checksums unavailable: no blocks found");
    // Buffer all results until every lookup and consistency check succeeds.
    let output = format!(
        "{MAGIC} {BLOCK_BYTES} {} {}\n{}\n",
        initial.len(),
        tokens.len(),
        tokens.join("\n")
    );
    protocol::parse(&output, initial.len())?;
    eprintln!(
        "{}: root={root} inode={} extents={} blocks={} method={method}",
        path.display(),
        initial.ino(),
        extents.len(),
        tokens.len()
    );
    let mut out = io::stdout().lock();
    out.write_all(output.as_bytes())?;
    out.flush()?;
    Ok(())
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 2 && (args[1] == "--help" || args[1] == "--version") {
        println!("dduper-btrfs {}\nUsage: dduper-btrfs inspect-internal dump-csum FILE DEVICE\nExit codes: 0 complete output; 1 error; 2 checksums unavailable", env!("CARGO_PKG_VERSION"));
        return;
    }
    let result = if args.len() == 5 && args[1] == "inspect-internal" && args[2] == "dump-csum" {
        dump(Path::new(&args[3]), Path::new(&args[4]))
            .with_context(|| format!("{}", Path::new(&args[3]).display()))
    } else {
        bail_usage()
    };
    if let Err(e) = result {
        eprintln!("dduper-btrfs: {e:#}");
        std::process::exit(if e.downcast_ref::<Unavailable>().is_some() {
            2
        } else {
            1
        });
    }
}

fn bail_usage() -> Result<()> {
    bail!("usage: dduper-btrfs inspect-internal dump-csum FILE DEVICE")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_domains_and_partial_blocks_do_not_alias() {
        assert_ne!(
            token(b"content-sha256-v1", 4096, b"abc"),
            token(b"btrfs-csum-v1", 4096, b"abc")
        );
        assert_ne!(token(b"x", 4096, b"abc"), token(b"x", 3, b"abc"));
    }
    #[test]
    fn rejects_truncated_items() {
        assert!(le64(&[0; 7], 0).is_err());
    }
}
