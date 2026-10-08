# Historical dump-csum patches

These nine patches are retained as historical reference, not supported build
inputs. All overwrite the extent lookup result with `close_ctree()`'s result.
Eight always use `info->fs_root` (root 5). The v6.11 `with-subvolume` variant
resolves a root but falls back to root 5 on failure and retains the masked
return status. The bundled `bin/btrfs.static` identifies as btrfs-progs 5.7.

Other defects include failure to stop when the inode changes, wrong handling
of extent offsets/compression/holes/inline items, a four-byte checksum buffer
used with larger checksum types, and checksum count arithmetic tied to CRC32C.
A missing key can return 1 from `btrfs_search_slot`, yet the old extent walker
checks `ret > 1`. A subsequent unrelated key returns an error that close_ctree
then masks, producing empty stdout and exit 0.

The replacement is `src/bin/dduper-btrfs.rs` with `src/btrfs_ioctl.c`, built by
Cargo. It selects the open file's subvolume and lets the mounted kernel read
the current trees through the Linux UAPI. This avoids maintaining a fork of
btrfs-progs 6.17.1 or using an offline tree reader on a live mounted filesystem.
See ../INSTALL.md for its protocol, fallback behavior and error statuses.
