dduper
------

dduper is a block-level [out-of-band](https://btrfs.wiki.kernel.org/index.php/Deduplication#Out_of_band_.2F_batch_deduplication) BTRFS dedupe tool. This works by
fetching built-in checksum from BTRFS csum-tree, instead of reading file blocks
and computing checksum itself. This *hugely* improves the performance.

The maintained implementation is Rust. `./dduper` is a Python standard-library
compatibility launcher for `target/release/dduper`; it needs no numpy or PTable.
Build **both** `dduper` and `dduper-btrfs` using `cargo build --release --bins`.
See [INSTALL.md](INSTALL.md) for setup, helper lookup, and the small local test.

The helper uses the mounted filesystem's kernel ioctls and the file's actual
subvolume ID. Ubuntu's `btrfs` stays unchanged. Historical patches and the
bundled 5.7 `bin/btrfs.static` are obsolete and are not used or packaged.

Only the default kernel-verified `FIDEDUPERANGE` mode is enabled. The legacy
`--fast-mode` option returns an error; `--skip` is accepted for CLI compatibility
and does not disable kernel verification. This is beta software: validate a
small disposable dataset before using it on valuable data.

### Performance

The historical benchmark below applies to checksum-tree reads. Compressed,
inline, sparse and preallocated files use an explicitly reported logical SHA256
fallback, which reads file contents. Uncompressed checksummed extents keep the
checksum-tree optimization. Tokens from the two methods are deliberately
separate, so differently stored copies can miss deduplication opportunities.


dduper is **~40x faster** than traditional SHA256-based approaches because it reads
checksums from BTRFS's internal csum-tree instead of reading file data from disk.

| File Size | SHA256 (naive) | dduper Python | dduper Rust | Speedup |
|-----------|---------------|---------------|-------------|---------|
| 1 GB      | 8.68s         | 0.54s         | 0.26s       | 33x     |
| 5 GB      | 41.62s        | 1.27s         | 1.03s       | 40x     |
| 10 GB     | 83.05s        | 2.14s         | 2.09s       | 40x     |
| 20 GB     | 168.62s       | 4.02s         | 4.18s       | 40x     |
| 50 GB     | 422.88s       | 9.36s         | 10.23s      | 41x     |
| 100 GB    | 850.20s       | 18.48s        | 20.29s      | 42x     |

For a **100GB file pair**, SHA256 takes **14 minutes** while dduper takes **20 seconds**.

See [BENCHMARK.md](BENCHMARK.md) for details and reproduction steps.

Dedupe Files (default mode):
----------------------------

To dedupe two files f1 and f2 on partition sda1:

`dduper --device /dev/sda1 --files /mnt/f1 /mnt/f2`

This mode uses `FIDEDUPERANGE`: the kernel compares the selected regions byte
for byte and shares extents only when they match. Kernel errors propagate to
the caller; checksum matches alone never authorize cloning.

Dedupe multiple files:
----------------------

To dedupe more than two files on a partition (sda1), you simply pass
those filenames like:

`dduper --device /dev/sda1 --files /mnt/f1 /mnt/f2 /mnt/f3 /mnt/f4`

Dedupe Directory:
-----------------

To dedupe entire directory on sda1:

`dduper --device /dev/sda1 --dir /mnt/dir`

Dedupe Directory recursively:
-----------------------------

To dedupe entire directory also parse its sub-directories on sda1:

`dduper --device /dev/sda1 --dir /mnt/dir --recurse `

Dedupe multiple directories:
---------------------------

To dedupe multiple directories on sda1:

`dduper --device /dev/sda1 --dir /mnt/dir1 /mnt/dir2`

Analyze with different chunk size:
----------------------------------
You can analyze which chunk size provides better deduplication.

`dduper --device /dev/sda1 --files /mnt/f1 /mnt/f2 --analyze`

It will perform analysis and report dedupe data for different chunk values.

Sample output: f1 and f2 are 4MB files.

```
--------------------------------------------------
 Chunk Size(KB) :      Files      : Duplicate(KB) 
--------------------------------------------------
      256       : /mnt/f1:/mnt/f2 :     4096      
==================================================
dduper:4096KB of duplicate data found with chunk size:256KB 


--------------------------------------------------
 Chunk Size(KB) :      Files      : Duplicate(KB) 
--------------------------------------------------
      512       : /mnt/f1:/mnt/f2 :     4096      
==================================================
dduper:4096KB of duplicate data found with chunk size:512KB 


--------------------------------------------------
 Chunk Size(KB) :      Files      : Duplicate(KB) 
--------------------------------------------------
      1024      : /mnt/f1:/mnt/f2 :     4096      
==================================================
dduper:4096KB of duplicate data found with chunk size:1024KB 


--------------------------------------------------
 Chunk Size(KB) :      Files      : Duplicate(KB) 
--------------------------------------------------
      2048      : /mnt/f1:/mnt/f2 :       0       
==================================================
dduper:0KB of duplicate data found with chunk size:2048KB 


--------------------------------------------------
 Chunk Size(KB) :      Files      : Duplicate(KB) 
--------------------------------------------------
      4096      : /mnt/f1:/mnt/f2 :       0       
==================================================
dduper:0KB of duplicate data found with chunk size:4096KB 


--------------------------------------------------
 Chunk Size(KB) :      Files      : Duplicate(KB) 
--------------------------------------------------
      8192      : /mnt/f1:/mnt/f2 :       0       
==================================================
dduper:0KB of duplicate data found with chunk size:8192KB 

dduper took 0.149248838425 seconds
```

Above output shows, whole 4MB file (f2) can be deduped with chunk size 256KB, 512KB or 1MB.
With larger chunk size 2MB, 4MB and 8MB, dduper unable to detect deduplicate data. In this
case, its wise to use 1MB as chunk size while performing dedupe, because it invoke less
dedupe calls compared to 256KB/512KB chunk size.

You can analyze more than two files like,

`dduper --device /dev/sda1 --files /mnt/f1 /mnt/f2 /mnt/file3 --analyze`

or directory and its sub-directories using

`dduper --device /dev/sda1 --dir /mnt --recurse --analyze`

Changing dedupe chunk size:
---------------------------

By default, dduper uses 128KB chunk size. This can be modified using chunk-size
option. Below usage shows chunk size with 1MB

`dduper --device /dev/sda1 --files /mnt/f1 /mnt/f2 --chunk-size 1024`

Display stats:
-------------

To perform dry-run to display details without performing dedupe:

`dduper --device /dev/sda1 --files /mnt/f1 /mnt/f2 --dry-run`

Also check `--analyze` option for detailed data.

List duplicate files:
---------------------

To list duplicate files from a directory:

`dduper --device /dev/sda1 --dir /mnt --recurse --perfect-match-only`


Compatibility and limits:
-------------------------

- Linux with Btrfs, 4096-byte sectors and current Linux UAPI headers is required.
- The helper supports CRC32C, xxhash64, SHA256 and BLAKE2b-256 checksum sizes.
- Subvolume roots are resolved from the open file; no fallback to root 5 occurs.
- Empty and NODATASUM files return helper status 2 with a diagnostic. Other
  lookup errors return 1. Only complete, validated output returns 0.
- Tree searches need CAP_SYS_ADMIN (normally sudo). `--device` must identify a
  device belonging to the file's mounted Btrfs filesystem.
- Files should be quiescent. Metadata changes invalidate the invocation-local
  cache; kernel byte verification protects every actual dedupe operation.
- Checksum candidates can collide or become stale. `--perfect-match-only` is a
  checksum candidate report, not proof of byte equality.
- No persistent DB is reused. Existing `dduper.db` files are ignored and left in
  place, so prior runs cannot add files outside the requested paths.
- Checksums are collected in memory; very large files/directories can require
  substantial RAM. Identical blocks within a single file are not deduplicated.
- Legacy QEMU tests in `ci/gitlab` and old image-based scripts are historical;
  use the bounded `tests/validate_local.py` test instead on an existing host.


Reporting bugs:
--------------

To report issues please use

- [github issue track](https://github.com/lakshmipathi/dduper/issues)
