# Build and install

The supported build produces two Rust executables: `dduper` and
`dduper-btrfs`. The helper is an independent, read-only kernel-ioctl client;
no patched btrfs-progs build or raw block-device access is needed. It builds
against current Linux UAPI headers (including Ubuntu 26.04's generation).
Do not install `bin/btrfs.static` or apply the historical patches.

Requirements: Linux, a recent stable Rust toolchain (validated with 1.99.0), a C compiler,
Linux UAPI headers, and standard build tools. Cargo builds the bundled SQLite
library. On Ubuntu, `build-essential` and `linux-libc-dev` provide the C pieces.
The Python compatibility launcher only needs Python 3.

```sh
cargo build --release --bins --locked -j2
cargo test --locked -j2
python3 tests/test_caller.py
```

If you have installed an isolated Rust toolchain inside `build/`, activate
it for the current shell and reduce build artifacts with:

```sh
export RUSTUP_HOME="$PWD/build/rustup"
export CARGO_HOME="$PWD/build/cargo"
export PATH="$CARGO_HOME/bin:$PATH"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
cargo build --release --bins --locked -j2
cargo test --locked -j2
python3 tests/test_caller.py
```

Run directly from the checkout:

```sh
# Replace /dev/sdXN and the example file paths with your own.
sudo ./target/release/dduper-btrfs inspect-internal dump-csum /path/to/test/a /dev/sdXN
sudo ./target/release/dduper --device /dev/sdXN --files /path/to/test/a /path/to/test/b --dry-run
# Only after checking the dry-run:
sudo ./target/release/dduper --device /dev/sdXN --files /path/to/test/a /path/to/test/b
```

`sudo .venv/bin/python ./dduper ...` still works: the launcher executes the
same Rust program. It reports an actionable error if the build is absent.

To install separately from Ubuntu's tools:

```sh
sudo install -m 0755 target/release/dduper target/release/dduper-btrfs /usr/local/sbin/
/usr/local/sbin/dduper --help
```

This never replaces `/usr/bin/btrfs` or `/usr/sbin/btrfs.static`.
Cargo's Debian package metadata installs the two fresh binaries together in
`/usr/sbin`; `cargo deb` and the release workflow build both architectures'
helpers from source. Manual installation uses `/usr/local/sbin`.

Helper selection: explicit `DDUPER_BTRFS`, a sibling of the running executable,
`/usr/local/sbin/dduper-btrfs`, `/usr/sbin/dduper-btrfs`, then `dduper-btrfs` on
PATH. It never silently falls back to system `btrfs` or the obsolete 5.7 binary.
With sudo, pass an override explicitly: `sudo env DDUPER_BTRFS=/absolute/helper ...`.
The launcher's executable override is `DDUPER_BIN`.

# Bounded host validation

```sh
sudo python3 tests/validate_local.py --device /dev/sdXN --home-file /path/to/existing/file
```

The device and a regular file in a second subvolume must be specified explicitly.
The root-subvolume test file defaults to `/usr/bin/bash`; override it with
`--root-file`. The script reads these existing files and creates under 8 MiB of independent
test files in one fresh `build/validation-*` directory. Every write/dedupe is
preceded by a successful dry-run and uses kernel byte verification. SHA256,
full byte comparisons, FIEMAP and `btrfs filesystem du` validate the result.
It also reproduces the old helper's read-only failure if that binary exists.
Results and the disposable data remain in that directory for inspection.
No mounts, snapshots, filesystem creation, kernel changes or recursive scans
of existing directories are involved. Use `--help` for path/device overrides.

# Ubuntu filesystem scan wrapper

Run `ubuntu_deduper.sh` from this checkout after building both release binaries.
It uses Python 3's standard library, `ionice` (Ubuntu's `util-linux` package),
and the two local binaries. It does not install or build anything automatically.

```sh
./ubuntu_deduper.sh --help
./ubuntu_deduper.sh --list-exclusions
sudo ./ubuntu_deduper.sh --dry-run
# After reviewing the dry-run, explicitly request kernel-verified deduplication:
sudo ./ubuntu_deduper.sh --apply
```

The default roots are `/` and `/home`, scanned as separate live Btrfs subvolumes
on the same device. The device is detected from the mount table; an explicit
`--device /dev/sdXN` is also supported. The wrapper is **verbose and dry-run by default**.
`--apply` builds a fresh index and repeats a dry-run immediately before each
pair's actual dedupe; no stale index is reused. No unsafe mode is available.
Every run finishes indexing all selected files before starting pair operations.
On the first `--apply` run, space can be reclaimed progressively once pair
deduplication begins; indexing itself does not reclaim duplicate data.
No filesystem-wide run was performed while developing this wrapper.

Use `--root PATH` repeatedly to replace the default roots, and `--exclude PATH`
repeatedly to add exclusions. This example limits a run to the Snap package
files, including retained revisions:

```sh
sudo ./ubuntu_deduper.sh --root /var/lib/snapd/snaps --dry-run
```

Regular database files, container backing files, VM images, and stored `.snap`
packages are included, subject to the size limits below. The wrapper does not
stop services or skip files just because a database/container is running.
Active files whose inode, size, mtime or ctime changes during inspection are
reported and skipped. The kernel still compares bytes under its range locks
for every actual dedupe. Already-shared container layers may offer no additional
physical saving. NODATASUM files remain unsupported by the helper and are reported
as having unavailable checksums.

Skipped paths: `/dev`, `/proc`, `/sys`, `/run`, `/tmp`, `/var/tmp`, `/var/cache`,
`/var/log`, `/snap`, `/boot`, `/efi`, `/media`, `/mnt`, `/lost+found`, and the
wrapper's state directory. Nested mount views (including OverlayFS merged views,
SquashFS, and bind mounts), symlinks, nonregular files, and duplicate hardlinks
are skipped. Read-only subvolumes and paths named `.snapshots`, `timeshift`,
`timeshift-btrfs`, or beginning `@apt-snapshot-` are skipped. Writable nested
subvolumes are included, which permits Docker's Btrfs backing storage. Add
`--exclude` for any custom-named writable snapshot trees. A filesystem top-level
root (ID 5) is refused. Changes to the mount table stop the run; rerun after
mount/container activity settles. Other mounted Btrfs subvolumes require explicit
`--root` entries. This is a scan of eligible files in selected live roots, not
every object reachable through every mount alias.

## Priority and resource limits

Defaults: `--nice 19 --io-class idle --pause 0.05`, one subprocess operation at
a time. The settings are inherited by dduper and its helper. Adjust them with:

```sh
# More breathing room between operations:
sudo ./ubuntu_deduper.sh --dry-run --nice 19 --io-class idle --pause 0.5
# Low best-effort I/O instead of idle:
sudo ./ubuntu_deduper.sh --dry-run --nice 15 --io-class best-effort --io-level 7
```

`nice` regulates CPU scheduling; `ionice` regulates supported block-I/O scheduling.
Support depends on the active block scheduler; BFQ supports I/O priorities. These are not
write-bandwidth limits: Btrfs transaction/metadata work and asynchronous kernel
writeback need not inherit all of the process's priorities. `--pause` is between
subprocess operations, not between individual dedupe ioctls within one file pair.
Dry-run also reads checksums/content and the helper fsyncs inspected files, so
it can cause existing dirty data to be flushed.

| Option | Default | Purpose |
| --- | --- | --- |
| `--min-size` | `128K` | Skip small files |
| `--max-size` | `0` (unlimited) | Optional inclusive maximum file size |
| `--min-free` | `2G` | Stop when available space falls below this reserve |
| `--max-index-size` | `1G` | Cap the SQLite index; allocated as needed |
| `--max-files` | `250000` | Stop before pair operations if the scan exceeds this |
| `--max-pairs` | `20000` | Stop before pair operations if candidates exceed this |
| `--timeout` | `300` | Maximum seconds per subprocess operation; `0` disables the timeout |

Sizes use binary units. There is no default maximum file size: multi-gigabyte
duplicates and large VM images are eligible. Use, for example, `--max-size 8G`
to impose a limit, or `--max-size 0` to remove it explicitly. Files below the
minimum are logged as `below_min_size`; files above an explicitly selected cap
are logged as `above_max_size`, with the actual size and applicable limit.

Checksum token memory in the helper/application grows with file size; the SQLite
index cap is not a RAM cap. No data files are copied. Large compressed/sparse
files may require reading all logical contents. If the default five-minute
subprocess timeout is too short, increase `--timeout` or use `--timeout 0` for
no deadline. Ctrl-C still stops the process group when the timeout is disabled.
The free-space reserve and index limits remain active between operations.

The index stores hashes of aligned 128 KiB chunks, so partial
duplicates can be found across files of different sizes without comparing every
possible pair. One representative per matching chunk is paired with other
owners. This is not an exhaustive search for unaligned duplicate byte sequences;
changed representatives and the helper's separate native/logical token domains
can also cause missed matches.

Each run leaves its index, bounded event log, and summary in a fresh directory
under `build/ubuntu-deduper/`; the path is printed. The SQLite database is
`build/ubuntu-deduper/run-*/index.sqlite` relative to this checkout. The 1 GiB
cap does not preallocate or reserve disk blocks. The separate 2 GiB free-space
guard still applies. Override the cap with `--max-index-size` and the parent
directory with `--state-dir`. Already-running processes keep the options they
started with. These files are private to
the invoking user (normally root). Inspect them with `sudo cat RUN/summary.json`
or `sudo less RUN/events.jsonl`. The event log is capped at 16 MiB, with omitted
records counted in the summary; console verbosity is independent. The entire
run directory is checked against the index budget plus 32 MiB for logs. Retained
run directories consume space across runs; remove only reviewed, finished run
directories when you no longer need their reports. No automatic cleanup of user
files, snapshots or previous reports is performed. A lock prevents concurrent
runs using the same state directory; do not start parallel runs with other state
directories. `--quiet` keeps warnings, periodic progress and the summary.

Logical bytes reported as matching/deduped can overlap between pairs and can
already be shared: **they are not a measurement of physical space recovered**.
Snap archives are compressed SquashFS images; small changes between releases do
not guarantee identical aligned chunks. The backing files under
`/var/lib/snapd/snaps` are eligible; mounted views under `/snap` are excluded.

Exit status: 0 means the run finished (inspect skip counters), 2 means it
finished with per-file errors or unavailable checksums, 1 means it stopped at a limit or fatal
error, and 130 means interrupted. Busy executable pairs are reported and skipped;
other apply failures/timeouts stop the run. Any successful safe dedupe before a
failure remains in effect. Free-space checks cannot reserve space against other
writers or guarantee sufficient Btrfs metadata space. With a nearly full disk,
live database/container writes and later copy-on-write allocation still compete
for the remaining space.

Press Ctrl-C once to stop scheduling work and terminate the active subprocess
group, including helper children. The wrapper allows two seconds for termination
before sending SIGKILL if necessary, then writes its summary and exits with 130.
Completed safe deduplication stays in effect. An in-flight uninterruptible kernel
operation can delay exit, and already queued Btrfs transactions/writeback can
continue briefly after exit; this is not an immediate physical-disk stop.
Run the command again to start a fresh scan rather than resume an old index.

Wrapper checks (small temporary fixtures, no system scan or real dedupe):

```sh
bash -n ubuntu_deduper.sh
python3 tests/test_ubuntu_deduper.py
python3 tests/test_caller.py
```

# Helper contract

`dduper-btrfs inspect-internal dump-csum FILE DEVICE` opens the file, resolves
its subvolume with `BTRFS_IOC_INO_LOOKUP`, verifies the requested device via
`BTRFS_IOC_DEV_INFO`, fsyncs the file, and reads its inode/extents and checksum
tree with `BTRFS_IOC_TREE_SEARCH_V2`. It does not open the raw device.

Stdout is a versioned, complete token stream:

```text
dduper-csum-v1 4096 FILE_SIZE BLOCK_COUNT
64-hex-digit-token-for-logical-block-0
64-hex-digit-token-for-logical-block-1
...
```

Each token covers one logical 4096-byte block (or the short EOF block). For
uncompressed data it hashes a type-tagged Btrfs checksum; for compressed,
inline, sparse or preallocated layouts it hashes logical contents instead.
The method, root ID, inode, extent count and block count go to stderr. Output
is held until all lookups and the metadata stability check succeed.

Exit status 0 means complete checksums, 1 means an error, and 2 means
checksums are unavailable (empty or NODATASUM files/missing checksum coverage).
Both application entry points reject empty, malformed or truncated stdout,
even if a helper returns 0. Errors include the filename, helper status and
stderr. Only 4096-byte Btrfs sectors are currently supported.

# Container

The Dockerfile builds the same two executables. Allow enough free space for
container build layers; a local Cargo build uses less disk space.
Tree search requires CAP_SYS_ADMIN and the
mounted Btrfs files and matching device must be visible in the container.
