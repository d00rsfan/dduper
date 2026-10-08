/* SPDX-License-Identifier: GPL-2.0-only */
/* Keep ioctl numbers and layouts in the system Linux UAPI, including on arm64. */
#include <errno.h>
#include <linux/btrfs.h>
#include <linux/btrfs_tree.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

/* Rust decodes packed disk items and native-endian search headers explicitly. */
_Static_assert(sizeof(struct btrfs_ioctl_search_header) == 32, "search header ABI");
_Static_assert(offsetof(struct btrfs_inode_item, flags) == 64, "inode flags ABI");
_Static_assert(offsetof(struct btrfs_file_extent_item, type) == 20, "extent type ABI");
_Static_assert(offsetof(struct btrfs_file_extent_item, disk_bytenr) == 21, "extent address ABI");
_Static_assert(offsetof(struct btrfs_file_extent_item, num_bytes) == 45, "extent length ABI");
_Static_assert(BTRFS_EXTENT_CSUM_OBJECTID == (uint64_t)-10 &&
               BTRFS_CSUM_TREE_OBJECTID == 7 && BTRFS_EXTENT_CSUM_KEY == 128 &&
               BTRFS_INODE_ITEM_KEY == 1 && BTRFS_EXTENT_DATA_KEY == 108,
               "tree key ABI");

int dduper_info(int fd, uint64_t *root, uint32_t *sector, uint32_t *node,
                uint16_t *csum_type, uint16_t *csum_size)
{
    struct btrfs_ioctl_ino_lookup_args ino = { .objectid = BTRFS_FIRST_FREE_OBJECTID };
    struct btrfs_ioctl_fs_info_args fs = { .flags = BTRFS_FS_INFO_FLAG_CSUM_INFO };
    if (ioctl(fd, BTRFS_IOC_INO_LOOKUP, &ino) < 0 ||
        ioctl(fd, BTRFS_IOC_FS_INFO, &fs) < 0)
        return -errno;
    *root = ino.treeid;
    *sector = fs.sectorsize;
    *node = fs.nodesize;
    *csum_type = fs.csum_type;
    *csum_size = fs.csum_size;
    return 0;
}

/* Verify the requested device belongs to the open file's mounted filesystem.
 * Compare device numbers, so /dev/disk/by-uuid aliases also work. No raw IO. */
int dduper_device(int fd, const char *device)
{
    struct stat requested, actual;
    struct btrfs_ioctl_fs_info_args fs = {0};
    if (stat(device, &requested) < 0)
        return -errno;
    if (!S_ISBLK(requested.st_mode))
        return -ENOTBLK;
    if (ioctl(fd, BTRFS_IOC_FS_INFO, &fs) < 0)
        return -errno;
    for (uint64_t id = 1; id <= fs.max_id; id++) {
        struct btrfs_ioctl_dev_info_args dev = { .devid = id };
        if (ioctl(fd, BTRFS_IOC_DEV_INFO, &dev) < 0) {
            if (errno == ENODEV)
                continue;
            return -errno;
        }
        dev.path[sizeof(dev.path) - 1] = 0;
        if (stat((char *)dev.path, &actual) == 0 &&
            S_ISBLK(actual.st_mode) && actual.st_rdev == requested.st_rdev)
            return 0;
    }
    return -EXDEV;
}

/* Copy the kernel's search headers and packed on-disk items to Rust. */
int dduper_search(int fd, uint64_t root, uint64_t objectid, uint32_t type,
                  uint64_t start, uint64_t end, unsigned char *buf,
                  uint32_t capacity, uint32_t *count)
{
    struct btrfs_ioctl_search_args_v2 *args = calloc(1, sizeof(*args) + capacity);
    if (!args)
        return -ENOMEM;
    args->key.tree_id = root;
    args->key.min_objectid = args->key.max_objectid = objectid;
    args->key.min_type = args->key.max_type = type;
    args->key.min_offset = start;
    args->key.max_offset = end;
    args->key.max_transid = UINT64_MAX;
    args->key.nr_items = UINT32_MAX;
    args->buf_size = capacity;
    int ret = ioctl(fd, BTRFS_IOC_TREE_SEARCH_V2, args) < 0 ? -errno : 0;
    if (!ret) {
        *count = args->key.nr_items;
        memcpy(buf, args->buf, capacity);
    }
    free(args);
    return ret;
}
