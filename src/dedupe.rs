use anyhow::{bail, Context, Result};
use itertools::Itertools;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::csum;
use crate::db::CsumDb;

// Linux FIDEDUPERANGE, single destination (same ABI on x86_64 and aarch64).
const FIDEDUPERANGE: u64 = 0xc0189436;

#[repr(C)]
struct FileDedupeRange {
    src_offset: u64,
    src_length: u64,
    dest_count: u16,
    reserved1: u16,
    reserved2: u32,
    // Inline single dest_info entry
    dest_fd: i64,
    dest_offset: u64,
    bytes_deduped: u64,
    status: i32,
    reserved3: u32,
}

/// Configuration for a dedup operation
pub struct DedupeConfig {
    pub device: PathBuf,
    pub dry_run: bool,
    pub verbose: bool,
    pub analyze: bool,
    pub perfect_match_only: bool,
    pub recurse: bool,
    pub chunk_sz: u64,
}

/// Entry in analyze results table
pub struct AnalyzeEntry {
    pub files: String,
    pub duplicate_kb: u64,
}

/// Session state for a dedup run (replaces global mutable state)
pub struct DedupeSession {
    pub processed_files: HashSet<PathBuf>,
    pub analyze_results: BTreeMap<u64, Vec<AnalyzeEntry>>,
    pub db: CsumDb,
}

impl DedupeSession {
    pub fn new(db: CsumDb) -> Self {
        DedupeSession {
            processed_files: HashSet::new(),
            analyze_results: BTreeMap::new(),
            db,
        }
    }
}

/// Stats from a single file-pair deduplication
#[allow(dead_code)]
pub struct DedupeStats {
    pub chunk_size: u64,
    pub src_chunks: usize,
    pub dst_chunks: usize,
    pub matched_chunks: usize,
    pub unmatched_chunks: usize,
    pub total_bytes_deduped: u64,
    pub perfect_match: bool,
    pub avail_dedupe_kb: u64,
}

// --- File validation ---

/// Validate a single file: must be a regular file >= 4KB
pub fn validate_file(path: &Path) -> Result<()> {
    let meta = fs::metadata(path).with_context(|| format!("Cannot stat {}", path.display()))?;
    if !meta.file_type().is_file() {
        bail!("{}: not a regular file", path.display());
    }
    if meta.len() < 4096 {
        bail!("{}: file size < 4KB", path.display());
    }
    Ok(())
}

/// Validate a pair of files for deduplication
pub fn validate_file_pair(src: &Path, dst: &Path, processed: &HashSet<PathBuf>) -> bool {
    if processed.contains(src) || processed.contains(dst) {
        return false;
    }

    let (src_stat, dst_stat) = match (fs::metadata(src), fs::metadata(dst)) {
        (Ok(s), Ok(d)) => (s, d),
        _ => return false,
    };

    src_stat.file_type().is_file()
        && dst_stat.file_type().is_file()
        && (src_stat.dev(), src_stat.ino()) != (dst_stat.dev(), dst_stat.ino())
        && src_stat.len() >= 4096
        && dst_stat.len() >= 4096
}

/// Perform FIDEDUPERANGE ioctl (safe mode)
/// # Safety: direct kernel ioctl call
unsafe fn ioctl_fideduperange(src_fd: i32, range: &mut FileDedupeRange) -> io::Result<(u64, i32)> {
    let ret = libc::ioctl(src_fd, FIDEDUPERANGE, range as *mut FileDedupeRange);
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((range.bytes_deduped, range.status))
}

// --- Core deduplication ---

/// Perform deduplication between two files
pub fn do_dedupe(
    src_file: &Path,
    dst_file: &Path,
    config: &DedupeConfig,
    session: &mut DedupeSession,
) -> Result<DedupeStats> {
    let src_file_sz = fs::metadata(src_file)?.len();
    let dst_file_sz = fs::metadata(dst_file)?.len();

    // Dump checksums (with caching)
    let src_csums = csum::btrfs_dump_csum_cached(src_file, &config.device, &session.db)?;
    let dst_csums = csum::btrfs_dump_csum_cached(dst_file, &config.device, &session.db)?;

    if src_csums.is_empty() || dst_csums.is_empty() {
        bail!(
            "Empty checksums for {}:{}",
            src_file.display(),
            dst_file.display()
        );
    }

    // Check for perfect match
    let perfect_match = src_file_sz == dst_file_sz && src_csums == dst_csums;

    if perfect_match {
        println!(
            "Checksum match : {} {}",
            src_file.display(),
            dst_file.display()
        );
        if config.perfect_match_only {
            return Ok(DedupeStats {
                chunk_size: config.chunk_sz,
                src_chunks: 0,
                dst_chunks: 0,
                matched_chunks: 0,
                unmatched_chunks: 0,
                total_bytes_deduped: 0,
                perfect_match: true,
                avail_dedupe_kb: dst_file_sz / 1024,
            });
        }
    }

    let (actual_chunk_sz, ele_sz) = if perfect_match {
        csum::auto_adjust_chunk_sz(src_file_sz, config.analyze, config.chunk_sz)
    } else {
        (config.chunk_sz, csum::get_ele_size(config.chunk_sz)?)
    };

    // Get hashes
    let (src_dict, src_ccount) = csum::get_hashes(&src_csums, ele_sz, config.verbose);
    let (dst_dict, dst_ccount) = if perfect_match {
        (src_dict.clone(), src_ccount)
    } else {
        csum::get_hashes(&dst_csums, ele_sz, config.verbose)
    };

    // Find matched and unmatched keys
    let src_keys: HashSet<_> = src_dict.keys().collect();
    let dst_keys: HashSet<_> = dst_dict.keys().collect();

    let matched_keys: Vec<String> = src_keys
        .intersection(&dst_keys)
        .map(|k| (*k).clone())
        .collect();
    let unmatched_keys: Vec<String> = dst_keys
        .difference(&src_keys)
        .map(|k| (*k).clone())
        .collect();

    let matched_chunks: usize = matched_keys
        .iter()
        .filter_map(|k| dst_dict.get(k))
        .map(|v| v.len())
        .sum();
    let unmatched_chunks: usize = unmatched_keys
        .iter()
        .filter_map(|k| dst_dict.get(k))
        .map(|v| v.len())
        .sum();

    let mut total_bytes_deduped = 0u64;
    let no_of_chunks = actual_chunk_sz / csum::BLK_SIZE;
    let src_len = no_of_chunks * csum::BLK_SIZE * 1024;

    if !config.dry_run {
        let src_fd = fs::File::open(src_file)?;
        let dst_fd = fs::OpenOptions::new().write(true).open(dst_file)?;
        let src_fd_raw = src_fd.as_raw_fd();
        let dst_fd_raw = dst_fd.as_raw_fd();

        println!("{}", "*".repeat(24));

        for key in &matched_keys {
            if let (Some(src_offsets), Some(dst_offsets)) = (src_dict.get(key), dst_dict.get(key)) {
                let src_offset = src_offsets[0] as u64 * src_len;

                for &dst_idx in dst_offsets {
                    let dst_offset = dst_idx as u64 * src_len;

                    // Adjust length for final chunk
                    let actual_len =
                        range_len(src_file_sz, dst_file_sz, src_offset, dst_offset, src_len)?;

                    // Safety: these are Linux kernel ioctls operating on valid file descriptors
                    unsafe {
                        let mut range = FileDedupeRange {
                            src_offset,
                            src_length: actual_len,
                            dest_count: 1,
                            reserved1: 0,
                            reserved2: 0,
                            dest_fd: dst_fd_raw as i64,
                            dest_offset: dst_offset,
                            bytes_deduped: 0,
                            status: 0,
                            reserved3: 0,
                        };

                        let mut done = 0;
                        while done < actual_len {
                            range.src_offset = src_offset + done;
                            range.dest_offset = dst_offset + done;
                            range.src_length = actual_len - done;
                            range.bytes_deduped = 0;
                            range.status = 0;
                            let (bytes_dup, status) = ioctl_fideduperange(src_fd_raw, &mut range)
                                .with_context(|| {
                                format!(
                                    "FIDEDUPERANGE {} -> {} offsets {}/{} length {}",
                                    src_file.display(),
                                    dst_file.display(),
                                    range.src_offset,
                                    range.dest_offset,
                                    range.src_length
                                )
                            })?;
                            if status == 1 {
                                eprintln!(
                                    "Kernel found different bytes: {} -> {} at {}/{}",
                                    src_file.display(),
                                    dst_file.display(),
                                    range.src_offset,
                                    range.dest_offset
                                );
                                break;
                            }
                            if status != 0 {
                                bail!(
                                    "FIDEDUPERANGE {} -> {} failed: status {} ({})",
                                    src_file.display(),
                                    dst_file.display(),
                                    status,
                                    io::Error::from_raw_os_error(-status)
                                );
                            }
                            if bytes_dup == 0 || bytes_dup > range.src_length {
                                bail!("FIDEDUPERANGE returned invalid progress: {bytes_dup}");
                            }
                            done += bytes_dup;
                            total_bytes_deduped += bytes_dup;
                        }
                    }
                }
            }
        }

        drop(src_fd);
        drop(dst_fd);

        println!(
            "Dedupe completed for {}:{}",
            src_file.display(),
            dst_file.display()
        );

        // Mark processed in DB
        if total_bytes_deduped == dst_file_sz {
            session.db.mark_processed(&dst_file.to_string_lossy())?;
        }
    }

    let mut available = 0;
    for key in &matched_keys {
        let src_offset = src_dict[key][0] as u64 * src_len;
        for &dst_idx in &dst_dict[key] {
            available += range_len(
                src_file_sz,
                dst_file_sz,
                src_offset,
                dst_idx as u64 * src_len,
                src_len,
            )?;
        }
    }
    let avail_dedupe_kb = available / 1024;
    let is_perfect = if config.dry_run {
        available == dst_file_sz
    } else {
        total_bytes_deduped == dst_file_sz
    };

    let stats = DedupeStats {
        chunk_size: actual_chunk_sz,
        src_chunks: src_dict.len() + src_ccount,
        dst_chunks: dst_dict.len() + dst_ccount,
        matched_chunks,
        unmatched_chunks,
        total_bytes_deduped,
        perfect_match: is_perfect,
        avail_dedupe_kb,
    };

    // Display or collect results
    if config.analyze {
        eprint!(
            "[Analyzing] {}:{}                   \r",
            src_file.display(),
            dst_file.display()
        );
        io::stderr().flush().ok();

        let entry = AnalyzeEntry {
            files: format!("{}:{}", src_file.display(), dst_file.display()),
            duplicate_kb: if is_perfect {
                dst_file_sz / 1024
            } else {
                avail_dedupe_kb
            },
        };
        session
            .analyze_results
            .entry(config.chunk_sz)
            .or_default()
            .push(entry);
    } else {
        println!("Summary");
        println!(
            "blk_size: {}KB  chunksize: {}KB",
            csum::BLK_SIZE,
            actual_chunk_sz
        );
        println!("{} has {} chunks", src_file.display(), stats.src_chunks);
        println!("{} has {} chunks", dst_file.display(), stats.dst_chunks);
        println!("Matched chunks: {}", stats.matched_chunks);
        println!("Unmatched chunks: {}", stats.unmatched_chunks);

        if config.dry_run {
            println!("Total size(KB) available for dedupe: {}", avail_dedupe_kb);
        } else {
            println!("Total size(KB) deduped: {}", total_bytes_deduped / 1024);
        }
    }

    Ok(stats)
}

/// Deduplicate a list of files (pairwise combinations)
pub fn dedupe_files(
    files: &[PathBuf],
    config: &DedupeConfig,
    session: &mut DedupeSession,
) -> Result<()> {
    if files.len() < 2 {
        println!("Single file given or empty directory. Try again with --recurse");
        return Ok(());
    }

    if config.dry_run {
        println!("Dry run mode");
    }

    // Validate all files first
    for file in files {
        validate_file(file)?;
    }

    // Process all pairwise combinations
    for pair in files.iter().combinations(2) {
        let (src, dst) = (pair[0], pair[1]);

        if !validate_file_pair(src, dst, &session.processed_files) {
            if config.verbose {
                println!("Skipping {:?} {:?}", src, dst);
            }
            continue;
        }

        let stats = do_dedupe(src, dst, config, session)?;
        if stats.perfect_match {
            session.processed_files.insert(dst.clone());
        }
    }

    Ok(())
}

/// Multi-phase directory deduplication (matches Python's 4-phase approach)
pub fn dedupe_dir(
    dirs: &[PathBuf],
    config: &DedupeConfig,
    session: &mut DedupeSession,
) -> Result<()> {
    // Phase 1: Validate and collect files
    log::debug!("Phase-1: Validating files and creating DB");
    let file_list = collect_valid_files(dirs, config.recurse)?;

    if file_list.len() < 2 {
        println!("Single file given or empty directory. Try again with --recurse");
        return Ok(());
    }

    if config.dry_run {
        println!("Dry run mode");
    }
    if config.recurse {
        println!("Recurse mode");
    }

    // Phase 1.1: Populate checksums in DB for all files
    log::debug!("Phase-1.1: Populate records");
    for file in &file_list {
        csum::btrfs_dump_csum_cached(file, &config.device, &session.db)?;
        session.db.mark_valid(&file.to_string_lossy())?;
    }

    // Phase 2: Detect duplicate files via DB
    log::debug!("Phase-2: Detecting duplicate files");
    let dup_groups = session.db.detect_duplicates()?;

    // Phase 3: Dedupe duplicate file groups
    log::debug!("Phase-3: Dedupe duplicate files");
    for group in &dup_groups {
        let paths: Vec<PathBuf> = group.iter().map(PathBuf::from).collect();
        log::debug!("Deduping group: {:?}", paths);
        dedupe_files(&paths, config, session)?;
    }

    // Phase 4: Dedupe remaining unprocessed files
    log::debug!("Phase-4: Dedupe remaining files");
    let remaining = session.db.get_unprocessed()?;
    let remaining_paths: Vec<PathBuf> = remaining.iter().map(PathBuf::from).collect();
    log::debug!("Remaining files: {:?}", remaining_paths);
    dedupe_files(&remaining_paths, config, session)?;

    Ok(())
}

/// Walk directories and collect valid files
fn collect_valid_files(dirs: &[PathBuf], recurse: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for dir in dirs {
        if recurse {
            for entry in WalkDir::new(dir) {
                let entry = entry?;
                if entry.file_type().is_file() && validate_file(entry.path()).is_ok() {
                    files.push(entry.into_path());
                }
            }
        } else {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if entry.file_type()?.is_file() && validate_file(&path).is_ok() {
                    files.push(path);
                }
            }
        }
    }

    Ok(files)
}

/// Bound every ioctl by BOTH EOFs, independently of how many unique hashes exist.
fn range_len(src_size: u64, dst_size: u64, src: u64, dst: u64, chunk: u64) -> Result<u64> {
    if src >= src_size || dst >= dst_size || chunk == 0 || chunk > 16 * 1024 * 1024 {
        bail!(
            "invalid dedupe range: offsets {src}/{dst}, sizes {src_size}/{dst_size}, chunk {chunk}"
        );
    }
    Ok(chunk.min(src_size - src).min(dst_size - dst))
}

#[cfg(test)]
mod range_tests {
    use super::*;
    #[test]
    fn final_chunk_and_repeated_hash_ranges_are_bounded() {
        assert_eq!(
            range_len(1048577, 1048577, 1048576, 1048576, 131072).unwrap(),
            1
        );
        assert_eq!(range_len(1048576, 1048576, 0, 0, 131072).unwrap(), 131072);
        assert!(range_len(4096, 4096, 8192, 0, 131072).is_err());
    }
}
