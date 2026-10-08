fn main() {
    println!("cargo:rerun-if-changed=src/btrfs_ioctl.c");
    cc::Build::new()
        .file("src/btrfs_ioctl.c")
        .warnings(true)
        .compile("dduper_ioctl");
}
