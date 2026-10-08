#!/usr/bin/env python3
"""Bounded, serial Btrfs deduplication driver. No third-party Python packages."""

import argparse
from collections import Counter
from dataclasses import dataclass
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parent.parent
MIB = 1024**2
GIB = 1024**3
DEFAULT_EXCLUDES = (
    "/dev", "/proc", "/sys", "/run", "/tmp", "/var/tmp", "/var/cache",
    "/var/log", "/snap", "/boot", "/efi", "/media", "/mnt", "/lost+found",
)
SNAPSHOT_NAMES = {".snapshots", "timeshift", "timeshift-btrfs"}
# Linux UAPI, asm-generic ioctl encoding (Ubuntu x86_64/aarch64).
INO_LOOKUP = 0xD0009412
SUBVOL_GETFLAGS = 0x80089419


class StopRun(RuntimeError):
    pass


def size_arg(value):
    match = re.fullmatch(r"(\d+)([KMGT]?)(?:i?B)?", value, re.I)
    if not match:
        raise argparse.ArgumentTypeError("use bytes or a suffix, e.g. 128K, 1G, 512MiB")
    return int(match[1]) * 1024 ** " KMGT".index(match[2].upper() or " ")


def parser():
    p = argparse.ArgumentParser(prog="ubuntu_deduper.sh", description=__doc__,
                                formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="inspect and estimate only (default)")
    mode.add_argument("--apply", action="store_true", help="dedupe each pair only after its successful dry-run")
    p.add_argument("--root", action="append", help="live Btrfs directory to scan; repeatable; default: / and /home")
    p.add_argument("--device", help="Btrfs device; default: first root's mount source")
    p.add_argument("--exclude", action="append", default=[], help="additional excluded path; repeatable")
    p.add_argument("--list-exclusions", action="store_true", help="print policy and exit without scanning")
    p.add_argument("--dduper", default=str(REPO / "target/release/dduper"))
    p.add_argument("--helper", default=str(REPO / "target/release/dduper-btrfs"))
    p.add_argument("--state-dir", default=str(REPO / "build/ubuntu-deduper"))
    p.add_argument("--min-size", type=size_arg, default=128 * 1024, help="smallest eligible regular file")
    p.add_argument("--max-size", type=size_arg, default=0, help="optional inclusive per-file size cap; 0 means unlimited")
    p.add_argument("--min-free", type=size_arg, default=2 * GIB, help="stop below this available-space reserve")
    p.add_argument("--max-index-size", type=size_arg, default=GIB, help="SQLite database size cap")
    p.add_argument("--max-files", type=int, default=250000, help="stop if this many eligible files is exceeded")
    p.add_argument("--max-pairs", type=int, default=20000, help="stop before pair operations if exceeded")
    p.add_argument("--timeout", type=float, default=300, help="timeout per helper/dduper invocation, seconds; 0 disables it")
    p.add_argument("--nice", type=int, choices=range(-20, 20), default=19, metavar="-20..19", help="CPU nice value")
    p.add_argument("--io-class", choices=("idle", "best-effort", "none"), default="idle", help="inherited I/O scheduling class")
    p.add_argument("--io-level", type=int, choices=range(8), default=7, help="best-effort level: 0 highest, 7 lowest")
    p.add_argument("--pause", type=float, default=0.05, help="seconds between subprocess operations")
    verbosity = p.add_mutually_exclusive_group()
    verbosity.add_argument("--verbose", action="store_true", help="show each inspection, exclusion and operation (default)")
    verbosity.add_argument("--quiet", action="store_true", help="only warnings, periodic progress and summary")
    return p


def beneath(path, parent):
    return path == parent or path.startswith(parent.rstrip("/") + "/")


def unescape_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)


@dataclass(frozen=True)
class Mount:
    path: str
    fs: str
    source: str
    options: tuple


def mounts(text):
    result = []
    for line in text.splitlines():
        left, right = line.split(" - ", 1)
        a, b = left.split(), right.split()
        result.append(Mount(unescape_mount(a[4]), b[0], unescape_mount(b[1]), tuple(a[5].split(","))))
    return result


def mount_for(path, entries):
    return max((m for m in entries if beneath(path, m.path)), key=lambda m: len(m.path))


def subvolume(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        lookup = bytearray(4096)
        struct.pack_into("=QQ", lookup, 0, 0, 256)
        fcntl.ioctl(fd, INO_LOOKUP, lookup, True)
        flags = bytearray(8)
        fcntl.ioctl(fd, SUBVOL_GETFLAGS, flags, True)
        return struct.unpack_from("=Q", lookup)[0], bool(struct.unpack("=Q", flags)[0] & 2)
    finally:
        os.close(fd)


def fingerprint(path):
    s = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(s.st_mode) or os.path.realpath(path) != path:
        raise OSError("not a regular file at its original, non-symlink path")
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def chunk_hashes(output, size):
    """Strictly validate the helper protocol, then hash aligned 128 KiB chunks."""
    lines = output.splitlines()
    count = (size + 4095) // 4096
    header = f"dduper-csum-v1 4096 {size} {count}".encode()
    if not count or not lines or lines[0] != header or len(lines) != count + 1:
        raise ValueError("checksums unavailable/incomplete: invalid header or block count")
    if any(re.fullmatch(rb"[0-9a-fA-F]{64}", token) is None for token in lines[1:]):
        raise ValueError("checksums unavailable: invalid block token")
    return {hashlib.sha256(b"".join(lines[i:i + 32])).digest() for i in range(1, len(lines), 32)}


def open_index(path, limit):
    db = sqlite3.connect(path)
    db.execute("PRAGMA page_size=4096")
    db.execute(f"PRAGMA max_page_count={limit // 4096}")
    # Disposable index, no resume: bounded per-file transactions, no disk rollback journal.
    db.execute("PRAGMA journal_mode=MEMORY")
    db.execute("PRAGMA cache_size=-8192")
    db.execute("PRAGMA temp_store=MEMORY")
    db.executescript("""
        CREATE TABLE files(id INTEGER PRIMARY KEY, path BLOB UNIQUE, dev INTEGER,
            ino INTEGER, size INTEGER, mtime INTEGER, ctime INTEGER, valid INTEGER DEFAULT 0,
            UNIQUE(dev, ino));
        CREATE TABLE chunks(hash BLOB, file_id INTEGER, PRIMARY KEY(hash, file_id)) WITHOUT ROWID;
        CREATE TABLE pairs(src INTEGER, dst INTEGER, PRIMARY KEY(src, dst)) WITHOUT ROWID;
    """)
    return db


def make_pairs(db, limit, check):
    """One representative per identical chunk, rather than all combinations."""
    count = 0
    for digest, source in db.execute("SELECT hash, MIN(file_id) FROM chunks GROUP BY hash HAVING COUNT(*) > 1"):
        check()
        for (dest,) in db.execute("SELECT file_id FROM chunks WHERE hash=? AND file_id != ?", (digest, source)):
            cur = db.execute("INSERT OR IGNORE INTO pairs VALUES (?, ?)", (source, dest))
            count += cur.rowcount
            if count > limit:
                raise StopRun(f"candidate pair limit {limit} exceeded; narrow --root or raise --max-pairs")
        db.commit()
    return count


def capture(argv, *, cwd, env, timeout):
    """Stop the entire child process group, including helper grandchildren."""
    with subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, start_new_session=True) as child:
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.communicate()
            raise
        return subprocess.CompletedProcess(argv, child.returncode, stdout, stderr)


class Driver:
    def __init__(self, args):
        self.args = args
        self.roots = list(dict.fromkeys(os.path.realpath(p) for p in (args.root or ["/", "/home"])))
        self.state = os.path.realpath(args.state_dir)
        self.excludes = (*DEFAULT_EXCLUDES, self.state, *(os.path.abspath(p) for p in args.exclude))
        self.counts = Counter()
        self.log = None
        self.logged_bytes = 0
        self.work = None
        self.db = None
        self.lock = None
        self.mount_text = Path("/proc/self/mountinfo").read_text()
        self.mounts = mounts(self.mount_text)
        self.mount_paths = {m.path for m in self.mounts}

    def event(self, kind, important=False, **fields):
        record = {"event": kind, **fields}
        line = json.dumps(record, ensure_ascii=True)
        if important or not self.args.quiet:
            print(line, flush=True)
        if self.log:
            data = line + "\n"
            if self.logged_bytes + len(data) <= 16 * MIB:
                self.log.write(data)
                self.log.flush()
                self.logged_bytes += len(data)
            else:
                self.counts["log_records_omitted_at_16MiB_cap"] += 1

    def skip(self, reason, path, **details):
        self.counts["skipped_" + reason] += 1
        self.event("skip", reason=reason, path=path, **details)

    def policy(self, path):
        if any(beneath(path, excluded) for excluded in self.excludes):
            return "excluded_path"
        if any(part in SNAPSHOT_NAMES or part.startswith("@apt-snapshot-") for part in Path(path).parts):
            return "snapshot_path"
        return None

    def check(self):
        if Path("/proc/self/mountinfo").read_text() != self.mount_text:
            raise StopRun("mount table changed; stopped to avoid entering a new mount view; rerun")
        for path in (*self.roots, self.work or self.state):
            free = shutil.disk_usage(path).free
            if free < self.args.min_free:
                raise StopRun(f"{path!r}: free space {free} is below --min-free {self.args.min_free}")
        if self.work:
            # Includes the core application's log, which is written in this run directory.
            used = sum(p.stat().st_size for p in Path(self.work).iterdir() if p.is_file())
            if used > self.args.max_index_size + 32 * MIB:
                raise StopRun("run directory exceeded index budget plus 32 MiB log allowance")

    def prepare(self):
        if os.geteuid() != 0:
            raise StopRun("run with sudo: Btrfs tree search requires CAP_SYS_ADMIN")
        self.device = os.path.realpath(self.args.device or mount_for(self.roots[0], self.mounts).source)
        dev_stat = os.stat(self.device)
        if not stat.S_ISBLK(dev_stat.st_mode):
            raise StopRun(f"not a block device: {self.device!r}")
        for root in self.roots:
            if self.policy(root):
                raise StopRun(f"root is excluded by the scan policy: {root!r}")
            m = mount_for(root, self.mounts)
            if m.fs != "btrfs" or "rw" not in m.options:
                raise StopRun(f"root must be on a writable Btrfs mount: {root!r}")
            if os.stat(m.source).st_rdev != dev_stat.st_rdev:
                raise StopRun(f"root is not on {self.device}: {root!r}; select roots from one filesystem")
            root_id, readonly = subvolume(root)
            if readonly or root_id == 5:
                raise StopRun(f"select a writable live subvolume, not read-only or top-level root 5: {root!r}")
            self.event("root", important=True, path=root, subvolume=root_id)
        for name in ("dduper", "helper"):
            value = os.path.realpath(getattr(self.args, name))
            if not os.path.isfile(value) or not os.access(value, os.X_OK):
                raise StopRun(f"missing executable: {value!r}; build first or set --{name}")
            setattr(self.args, name, value)
        os.makedirs(self.state, mode=0o700, exist_ok=True)
        self.lock = open(os.path.join(self.state, "run.lock"), "a")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise StopRun("another wrapper is using this state directory") from exc
        self.check()
        os.setpriority(os.PRIO_PROCESS, 0, self.args.nice)
        priority = ["ionice", "-c", {"idle": "3", "best-effort": "2", "none": "0"}[self.args.io_class]]
        if self.args.io_class == "best-effort":
            priority += ["-n", str(self.args.io_level)]
        priority_result = subprocess.run(priority + ["-p", str(os.getpid())], capture_output=True)
        if priority_result.returncode:
            raise StopRun(f"cannot set I/O priority: exit={priority_result.returncode}, "
                          f"stderr={priority_result.stderr.decode(errors='replace')!r}")
        self.work = tempfile.mkdtemp(prefix="run-", dir=self.state)
        self.log = open(os.path.join(self.work, "events.jsonl"), "w", encoding="utf-8")
        self.db = open_index(os.path.join(self.work, "index.sqlite"), self.args.max_index_size)
        self.env = {**os.environ, "DDUPER_BTRFS": self.args.helper}
        self.event("start", important=True, mode="APPLY" if self.args.apply else "DRY RUN",
                   device=self.device, roots=self.roots, state=self.work, nice=self.args.nice,
                   io_class=self.args.io_class, io_level=self.args.io_level, pause=self.args.pause,
                   min_free=self.args.min_free, min_size=self.args.min_size, max_size=self.args.max_size,
                   max_index_size=self.args.max_index_size, max_files=self.args.max_files,
                   max_pairs=self.args.max_pairs, excludes=list(self.excludes),
                   includes="database, container backing, VM and stored .snap files within size limits")

    def command(self, argv, phase):
        self.check()
        if self.args.pause:
            time.sleep(self.args.pause)
        self.event("command", phase=phase, argv=argv)
        try:
            result = capture(argv, cwd=self.work, env=self.env, timeout=self.args.timeout or None)
        except subprocess.TimeoutExpired as exc:
            # A partially completed safe dedupe is possible. Never continue to
            # apply after a timed-out dry-run.
            self.counts["errors"] += 1
            self.event("timeout", important=True, phase=phase, argv=argv, seconds=self.args.timeout,
                       stderr=(exc.stderr or b"").decode(errors="replace")[:8000])
            return None
        self.event("result", important=result.returncode != 0, phase=phase, status=result.returncode,
                   stderr=result.stderr.decode(errors="replace")[:8000],
                   stdout=("checksum stream omitted" if phase == "checksums" else result.stdout.decode(errors="replace")[:8000]))
        self.check()
        return result

    def scan(self):
        def walk_error(exc):
            self.counts["errors"] += 1
            self.event("walk_error", important=True, path=exc.filename, error=str(exc))

        for root in self.roots:
            for directory, dirs, names in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
                self.check()
                kept = []
                for name in sorted(dirs):
                    path = os.path.join(directory, name)
                    reason = self.policy(path)
                    if not reason and (path in self.mount_paths or path in self.roots):
                        reason = "mount_or_separate_root"
                    try:
                        s = os.lstat(path)
                        if not reason and stat.S_ISLNK(s.st_mode):
                            reason = "symlink"
                        if not reason and s.st_ino == 256:
                            _, readonly = subvolume(path)
                            if readonly:
                                reason = "readonly_subvolume"
                    except OSError as exc:
                        walk_error(exc)
                        reason = "unreadable_directory"
                    if reason:
                        self.skip(reason, path)
                    else:
                        kept.append(name)
                dirs[:] = kept
                for name in sorted(names):
                    path = os.path.join(directory, name)
                    reason = self.policy(path)
                    if path in self.mount_paths:
                        reason = "mounted_file"
                    if reason:
                        self.skip(reason, path)
                        continue
                    try:
                        s = os.lstat(path)
                        if not stat.S_ISREG(s.st_mode):
                            self.skip("nonregular_or_symlink", path)
                            continue
                        if s.st_size < self.args.min_size:
                            self.skip("below_min_size", path, bytes=s.st_size, min_size=self.args.min_size)
                            continue
                        if self.args.max_size and s.st_size > self.args.max_size:
                            self.skip("above_max_size", path, bytes=s.st_size, max_size=self.args.max_size)
                            continue
                        self.index_file(path)
                    except OSError as exc:
                        walk_error(exc)

    def index_file(self, path):
        before = fingerprint(path)
        cur = self.db.execute("INSERT OR IGNORE INTO files(path,dev,ino,size,mtime,ctime) VALUES (?,?,?,?,?,?)",
                              (os.fsencode(path), *before))
        if not cur.rowcount:
            self.skip("hardlink_or_duplicate_view", path)
            return
        file_id = cur.lastrowid
        self.counts["eligible_files"] += 1
        if self.counts["eligible_files"] > self.args.max_files:
            raise StopRun("eligible file limit exceeded; narrow --root or raise --max-files")
        result = self.command([self.args.helper, "inspect-internal", "dump-csum", path, self.device], "checksums")
        if result is None:
            self.db.commit()
            return
        if result.returncode != 0:
            self.counts["checksums_unavailable" if result.returncode == 2 else "errors"] += 1
            self.event("checksums_unavailable", important=True, path=path, status=result.returncode,
                       stderr=result.stderr.decode(errors="replace")[:8000])
            self.db.commit()
            return
        try:
            hashes = chunk_hashes(result.stdout, before[2])
        except ValueError as exc:
            self.counts["errors"] += 1
            self.event("invalid_checksums", important=True, path=path, status=0, error=str(exc),
                       stderr=result.stderr.decode(errors="replace")[:8000])
            self.db.commit()
            return
        if fingerprint(path) != before:
            self.skip("changed_during_inspection", path)
            self.db.commit()
            return
        self.db.executemany("INSERT INTO chunks VALUES (?,?)", ((digest, file_id) for digest in hashes))
        self.db.execute("UPDATE files SET valid=1 WHERE id=?", (file_id,))
        self.db.commit()
        self.counts["indexed_files"] += 1
        self.counts["indexed_bytes"] += before[2]
        self.event("indexed", path=path, bytes=before[2], unique_chunks=len(hashes))
        if self.counts["indexed_files"] % 100 == 0:
            self.event("progress", important=True, **dict(self.counts))

    def file_record(self, file_id):
        row = self.db.execute("SELECT path,dev,ino,size,mtime,ctime,valid FROM files WHERE id=?", (file_id,)).fetchone()
        return os.fsdecode(row[0]), tuple(row[1:6]), row[6]

    def stable(self, ids):
        ok = True
        for file_id in ids:
            path, saved, valid = self.file_record(file_id)
            try:
                equal = valid and fingerprint(path) == saved
            except OSError:
                equal = False
            if not equal:
                self.skip("changed_or_unavailable_before_pair", path)
                self.db.execute("UPDATE files SET valid=0 WHERE id=?", (file_id,))
                ok = False
        self.db.commit()
        return ok

    def process_pair(self, source, dest):
        ids = (source, dest)
        if not self.stable(ids):
            return
        paths = [self.file_record(i)[0] for i in ids]
        argv = [self.args.dduper, "--device", self.device, "--chunk-size", "128", "--files", *paths]
        dry = self.command([*argv, "--dry-run"], "dry-run")
        if dry is None:
            return
        match = re.search(rb"(?m)^Total size\(KB\) available for dedupe: (\d+)\r?$", dry.stdout)
        if dry.returncode != 0 or match is None:
            self.counts["errors"] += 1
            self.event("dry_run_failed", important=True, paths=paths, status=dry.returncode,
                       reason="nonzero exit or missing summary; no apply")
            return
        if not self.stable(ids):
            return
        kb = int(match[1])
        self.counts["dry_run_pairs"] += 1
        self.counts["matching_logical_KiB_in_pair_estimates"] += kb
        if not kb or not self.args.apply:
            return
        result = self.command(argv, "apply")
        if result is None:
            raise StopRun("dedupe timed out; stopped after possible partial progress")
        match = re.search(rb"(?m)^Total size\(KB\) deduped: (\d+)\r?$", result.stdout)
        if result.returncode != 0 or match is None:
            self.counts["errors"] += 1
            if result.returncode != 0 and re.search(rb"\(os error (16|26)\)", result.stderr):
                # EBUSY / ETXTBSY: notably running executables that cannot be
                # opened for writing. Keep other pairs eligible and report exit 2.
                self.event("busy_pair", important=True, paths=paths, status=result.returncode,
                           detail="skipped; kernel refused a busy file; earlier safe progress may remain")
                return
            raise StopRun(f"dedupe failed for {paths!r}, status={result.returncode}; stopped after possible partial progress")
        self.counts["applied_pairs"] += 1
        self.counts["kernel_reported_logical_KiB"] += int(match[1])
        # Sharing extents may update ctime. Permit only this change from our operation;
        # inode, size or mtime changes invalidate the candidate for the rest of the run.
        for file_id in ids:
            path, saved, _ = self.file_record(file_id)
            try:
                after = fingerprint(path)
            except OSError:
                after = None
            if after is not None and after[:4] == saved[:4]:
                self.db.execute("UPDATE files SET ctime=? WHERE id=?", (after[4], file_id))
            else:
                self.db.execute("UPDATE files SET valid=0 WHERE id=?", (file_id,))
                self.skip("changed_during_dedupe", path)
        self.db.commit()

    def run(self):
        status = 1
        try:
            self.prepare()
            self.scan()
            self.counts["candidate_pairs"] = make_pairs(self.db, self.args.max_pairs, self.check)
            self.event("candidates", important=True, pairs=self.counts["candidate_pairs"])
            for source, dest in self.db.execute("SELECT src,dst FROM pairs ORDER BY src,dst"):
                self.process_pair(source, dest)
            status = 2 if self.counts["errors"] or self.counts["checksums_unavailable"] else 0
        except KeyboardInterrupt:
            status = 130
            self.event("interrupted", important=True, detail="completed safe operations are retained")
        except (StopRun, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
            self.event("stopped", important=True, error=str(exc))
        finally:
            summary = {"exit_status": status, "mode": "apply" if self.args.apply else "dry-run",
                       "counts": dict(self.counts), "state": self.work,
                       "note": "Logical matching/deduped bytes are NOT physical space reclaimed; pair estimates can overlap."}
            self.event("summary", important=True, **summary)
            if self.work:
                try:
                    Path(self.work, "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
                except OSError as exc:
                    print(f"Cannot save summary: {exc}", file=sys.stderr)
            if self.db:
                self.db.close()
            if self.log:
                self.log.close()
            if self.lock:
                self.lock.close()
        return status


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if args.min_size < 4096 or (args.max_size and args.max_size < args.min_size):
        p.error("require --min-size >= 4096 and --max-size either 0 (unlimited) or >= --min-size")
    if args.max_index_size < MIB or args.max_files < 1 or args.max_pairs < 1 or args.min_free < MIB:
        p.error("index/free-space bounds must be >= 1MiB and file/pair counts positive")
    if not math.isfinite(args.pause) or not math.isfinite(args.timeout) or args.pause < 0 or args.timeout < 0:
        p.error("--pause and --timeout must be finite and nonnegative; timeout 0 means unlimited")
    if args.list_exclusions:
        print(json.dumps({"paths": [*DEFAULT_EXCLUDES, os.path.abspath(args.state_dir), *args.exclude],
                          "snapshot_names": sorted(SNAPSHOT_NAMES), "snapshot_prefix": "@apt-snapshot-",
                          "also_skip": ["nested mount views", "read-only subvolumes", "symlinks", "nonregular files",
                                        "duplicate hardlinks", "files outside size bounds", "changed files", "unavailable checksums"],
                          "included": ["database files", "Docker/container backing files", "VM images", "/var/lib/snapd/snaps/*.snap"],
                          "min_size": args.min_size, "max_size": args.max_size}, indent=2))
        return 0
    # Keep generated indexes/logs private; scanning as root can expose file names.
    os.umask(0o077)
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    return Driver(args).run()


if __name__ == "__main__":
    sys.exit(main())
