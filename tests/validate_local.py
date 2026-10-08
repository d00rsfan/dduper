#!/usr/bin/env python3
"""Small host-only integration test. Run with sudo; no mounts or raw writes.

Existing files are read only. All dedupe targets are independent files created
in one new build/validation-* directory in this checkout (< 8 MiB of test data).
Every actual dedupe is gated on the corresponding successful dry run.
"""
import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import traceback

REPO = Path(__file__).resolve().parents[1]
HELPER = REPO / "target/release/dduper-btrfs"
APP = REPO / "target/release/dduper"


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def extents(path):
    # Linux FIEMAP with FIEMAP_FLAG_SYNC, enough entries for these tiny files.
    buf = bytearray(32 + 256 * 56)
    struct.pack_into("=QQIIII", buf, 0, 0, (1 << 64) - 1, 1, 0, 256, 0)
    with path.open("rb") as f:
        fcntl.ioctl(f.fileno(), 0xC020660B, buf, True)
    count = struct.unpack_from("=I", buf, 20)[0]
    assert count < 256, "FIEMAP output truncated"
    return [struct.unpack_from("=QQQQQIIII", buf, 32 + 56 * i) for i in range(count)]


def independent(a, b):
    assert (a.stat().st_dev, a.stat().st_ino) != (b.stat().st_dev, b.stat().st_ino)
    ea, eb = extents(a), extents(b)
    assert ea and eb
    assert all(not e[5] & 0x2000 for e in ea + eb), "unexpected preexisting shared extent"
    for x in ea:
        for y in eb:
            # FIEMAP's length is logical, not compressed disk length. Encoded
            # extents may be adjacent on disk even when those ranges overlap.
            if (x[5] | y[5]) & 0x8:  # FIEMAP_EXTENT_ENCODED
                assert x[1] != y[1], "same compressed disk extent"
            else:
                assert not (x[1] < y[1] + y[2] and y[1] < x[1] + x[2]), "overlapping disk extents"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True, help="Btrfs device containing the selected files and checkout")
    parser.add_argument("--home-file", required=True, help="existing regular file in a second subvolume (read only)")
    parser.add_argument("--root-file", default="/usr/bin/bash", help="existing regular file in the root subvolume (read only)")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("sudo is required for Btrfs tree searches")
    assert HELPER.is_file() and APP.is_file(), "build --release --bins first"
    (REPO / "build").mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="validation-", dir=REPO / "build"))
    # mkdtemp defaults to root-only 0700 under sudo. Make the saved report
    # inspectable by the invoking user/agent without another sudo round trip.
    work.chmod(0o755)
    log = (work / "results.log").open("w", buffering=1)
    (work / "results.log").chmod(0o644)

    def say(text):
        print(text, flush=True)
        print(text, file=log, flush=True)

    def run(argv, expected=0, full=True):
        argv = list(map(str, argv))
        say("$ " + shlex.join(argv))
        result = subprocess.run(argv, cwd=work, capture_output=True, text=True)
        say(f"exit={result.returncode}; stdout_bytes={len(result.stdout.encode())}")
        if result.stderr:
            say("stderr: " + result.stderr.rstrip())
        if result.stdout:
            say(result.stdout.rstrip() if full else "stdout (first lines):\n" + "\n".join(result.stdout.splitlines()[:3]))
        if expected is not None:
            assert result.returncode == expected, f"expected exit {expected}"
        return result

    def dump(path, expected=0):
        result = run([HELPER, "inspect-internal", "dump-csum", path, args.device], expected, full=False)
        if expected == 0:
            lines = result.stdout.splitlines()
            count = (Path(path).stat().st_size + 4095) // 4096
            assert lines[0] == f"dduper-csum-v1 4096 {Path(path).stat().st_size} {count}"
            assert len(lines) == count + 1 and count > 0
            assert all(len(token) == 64 for token in lines[1:])
        else:
            assert not result.stdout, "failed helper must not emit partial checksums"
        return result

    def pair(name, data, expected_kb=None):
        folder = work / name
        folder.mkdir()
        a, b = folder / "a", folder / "b"
        # Two independent writes: never cp/reflink/hardlink.
        for p in (a, b):
            with p.open("xb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        independent(a, b)
        before = digest(a)
        assert before == digest(b)
        say(f"{name}: independent allocation, identical contents; sha256={before}")
        run(["filefrag", "-v", a, b])
        # Directory mode also proves the target set stays inside this test pair.
        command = [APP, "--device", args.device, "--dir", folder]
        dry = run(command + ["--dry-run"])
        kb = len(data) // 1024 if expected_kb is None else expected_kb
        assert f"Total size(KB) available for dedupe: {kb}" in dry.stdout.splitlines()
        independent(a, b)  # dry-run did not share extents
        assert a.read_bytes() == data and b.read_bytes() == data
        actual = run(command)  # Default FIDEDUPERANGE; no fast/skip flags.
        assert f"Total size(KB) deduped: {kb}" in actual.stdout.splitlines()
        assert digest(a) == digest(b) == before
        assert a.read_bytes() == data and b.read_bytes() == data
        assert any(e[5] & 0x2000 for e in extents(a)), "source has no shared extents after dedupe"
        assert any(e[5] & 0x2000 for e in extents(b)), "destination has no shared extents after dedupe"
        run(["filefrag", "-v", a, b])
        run(["btrfs", "filesystem", "du", "--raw", a, b])
        say(f"PASS {name}: dry-run, safe dedupe, unchanged SHA256 and byte contents, shared extents")
        return a, b

    try:
        say(f"Validation directory: {work}")
        run(["uname", "-a"])
        run(["btrfs", "--version"])
        run(["df", "-h", REPO])
        system_before = digest(Path("/usr/bin/btrfs"))
        for filename in (args.home_file, args.root_file):
            path = Path(filename)
            before = digest(path)
            # btrfs-progs 6.17.1 opens regular files O_RDWR for rootid, which
            # fails with ETXTBSY on a running executable. Its resolved parent
            # directory is in the same subvolume and is opened O_RDONLY.
            rootid = run(["btrfs", "inspect-internal", "rootid", path.resolve().parent]).stdout.strip()
            assert rootid.isdecimal(), "invalid rootid output"
            old = Path("/usr/sbin/btrfs.static")
            if old.is_file():
                run([old, "inspect-internal", "dump-csum", path, args.device], expected=None, full=False)
            fixed = dump(path)
            assert f"root={rootid} " in fixed.stderr, "helper selected wrong subvolume"
            assert digest(path) == before
        dump(work / "missing", expected=1)
        empty = work / "empty"
        empty.touch()
        dump(empty, expected=2)
        wrong = run([HELPER, "inspect-internal", "dump-csum", args.home_file, "/dev/null"], expected=1)
        assert not wrong.stdout
        a, b = pair("random-1MiB", os.urandom(1024 * 1024))
        # Compatibility launcher must use the same binary and helper.
        run(["python3", REPO / "dduper", "--device", args.device, "--files", a, b, "--dry-run"])
        pair("compressed-512KiB", b"dduper compression test\n".ljust(4096, b"x") * 128)
        pair("tail", os.urandom(128 * 1024 + 123))
        # Repeated hashes must not cause the last unique hash to imply EOF.
        pair("repeated", os.urandom(128 * 1024) * 4)
        assert digest(Path("/usr/bin/btrfs")) == system_before
        say("PASS: /usr/bin/btrfs and both existing files unchanged")
        run(["df", "-h", REPO])
        say("ALL LOCAL VALIDATION TESTS PASSED")
    except Exception:
        say(traceback.format_exc())
        raise
    finally:
        say(f"Results saved to {work / 'results.log'}")
        log.close()


if __name__ == "__main__":
    main()
