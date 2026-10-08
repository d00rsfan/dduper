#!/usr/bin/env python3
"""Small fixtures only: never scan or dedupe existing filesystem contents."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ubuntu_deduper", REPO / "scripts/ubuntu_deduper.py")
wrapper = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = wrapper
spec.loader.exec_module(wrapper)


def protocol(tokens, size=None):
    size = len(tokens) * 4096 if size is None else size
    return f"dduper-csum-v1 4096 {size} {len(tokens)}\n".encode() + b"\n".join(tokens) + b"\n"


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wrapper-test-")
        self.base = Path(self.temp.name)
        self.args = wrapper.parser().parse_args(["--root", str(self.base), "--pause", "0", "--quiet"])
        self.driver = wrapper.Driver(self.args)
        self.driver.excludes = (str(self.base / "state"),)
        self.driver.work = str(self.base)
        self.driver.device = "/dev/test-only"
        self.driver.env = os.environ.copy()
        self.driver.db = wrapper.open_index(self.base / "index.sqlite", wrapper.MIB)
        self.driver.check = mock.Mock()

    def tearDown(self):
        self.driver.db.close()
        self.temp.cleanup()

    def add_file(self, name, tokens):
        path = self.base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * (len(tokens) * 4096))
        row = self.driver.db.execute("INSERT INTO files(path,dev,ino,size,mtime,ctime,valid) VALUES (?,?,?,?,?,?,1)",
                                     (os.fsencode(path), *wrapper.fingerprint(str(path))))
        file_id = row.lastrowid
        self.driver.db.executemany("INSERT INTO chunks VALUES (?,?)",
                                   ((h, file_id) for h in wrapper.chunk_hashes(protocol(tokens), path.stat().st_size)))
        self.driver.db.commit()
        return file_id, path

    def test_defaults_are_verbose_dry_run_idle_and_bounded(self):
        args = wrapper.parser().parse_args([])
        self.assertFalse(args.apply)
        self.assertFalse(args.quiet)
        self.assertEqual((args.nice, args.io_class, args.pause), (19, "idle", 0.05))
        self.assertEqual((args.min_free, args.max_size), (2 * wrapper.GIB, 0))
        self.assertEqual(args.max_index_size, wrapper.GIB)
        self.assertEqual(wrapper.size_arg("512MiB"), 512 * wrapper.MIB)

    def test_scan_admits_large_files_by_default_and_honors_explicit_cap(self):
        # Simulate large metadata on tiny fixtures; do not allocate gigabytes.
        root = self.base / "input"
        root.mkdir()
        sizes = {"small": 4096, "boundary": wrapper.GIB,
                 "large-a": 5 * wrapper.GIB, "large-b": 5 * wrapper.GIB}
        for name in sizes:
            (root / name).write_bytes(b"tiny fixture")
        self.driver.roots = [str(root)]
        self.driver.args.quiet = False
        real_lstat = os.lstat
        def with_size(path, *args, **kwargs):
            result = real_lstat(path, *args, **kwargs)
            if Path(path).parent == root and Path(path).name in sizes:
                return mock.Mock(st_mode=result.st_mode, st_size=sizes[Path(path).name])
            return result
        with mock.patch.object(wrapper.os, "lstat", side_effect=with_size):
            self.driver.index_file = mock.Mock()
            with contextlib.redirect_stdout(io.StringIO()):
                self.driver.scan()
            self.assertEqual({Path(c.args[0]).name for c in self.driver.index_file.call_args_list},
                             {"boundary", "large-a", "large-b"})
            self.driver.args.max_size = wrapper.GIB
            self.driver.index_file.reset_mock()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.driver.scan()
            self.assertEqual([Path(c.args[0]).name for c in self.driver.index_file.call_args_list], ["boundary"])
            records = [json.loads(line) for line in output.getvalue().splitlines()]
            rejected = [r for r in records if r.get("reason") == "above_max_size"]
            self.assertEqual(len(rejected), 2)
            self.assertTrue(all(r["bytes"] == 5 * wrapper.GIB and r["max_size"] == wrapper.GIB for r in rejected))
            self.assertTrue(any(r.get("reason") == "below_min_size" for r in records))

    def test_zero_timeout_disables_deadline_without_changing_command(self):
        self.args.timeout = 0
        argv = [sys.executable, "-c", "print('ok')"]
        result = subprocess.CompletedProcess(argv, 0, b"ok\n", b"")
        with mock.patch.object(wrapper, "capture", return_value=result) as capture:
            self.assertIs(self.driver.command(argv, "dry-run"), result)
        self.assertIsNone(capture.call_args.kwargs["timeout"])
        self.assertEqual(capture.call_args.args[0], argv)

    def test_cli_accepts_unlimited_sizes_and_rejects_invalid_bounds(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(wrapper.main(["--max-size", "0", "--timeout", "0", "--list-exclusions"]), 0)
        self.assertEqual(json.loads(output.getvalue())["max_size"], 0)
        for argv in (["--min-size", "1K"], ["--max-size", "4K"], ["--timeout", "-1"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                wrapper.main([*argv, "--list-exclusions"])
            self.assertEqual(exc.exception.code, 2)

    def test_protocol_rejects_empty_truncated_and_invalid_output(self):
        for data in (b"", b"deadbeef\n", protocol([b"a" * 64])[:-65], protocol([b"z" * 64])):
            with self.subTest(data=data), self.assertRaises(ValueError):
                wrapper.chunk_hashes(data, 4096)
        self.assertEqual(len(wrapper.chunk_hashes(protocol([b"a" * 64, b"b" * 64], 4097), 4097)), 1)

    def test_partial_chunks_make_pairs_across_different_file_sizes(self):
        first, _ = self.add_file("a", [b"a" * 64] * 32 + [b"b" * 64] * 32)
        second, _ = self.add_file("b", [b"c" * 64] * 32 + [b"a" * 64] * 32 + [b"d" * 64])
        self.assertEqual(wrapper.make_pairs(self.driver.db, 10, lambda: None), 1)
        self.assertEqual(list(self.driver.db.execute("SELECT * FROM pairs")), [(first, second)])

    def test_identical_files_use_linear_number_of_pairs(self):
        for i in range(5):
            self.add_file(str(i), [b"a" * 64] * 32)
        self.assertEqual(wrapper.make_pairs(self.driver.db, 10, lambda: None), 4)
        self.driver.db.execute("DELETE FROM pairs")
        with self.assertRaises(wrapper.StopRun):
            wrapper.make_pairs(self.driver.db, 2, lambda: None)

    def test_database_containers_and_snap_backing_files_are_included(self):
        driver = wrapper.Driver(wrapper.parser().parse_args([]))
        for path in ("/var/lib/postgresql/18/main/base/1/123", "/var/lib/docker/overlay2/layer/diff/a",
                     "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs/a",
                     "/var/lib/snapd/snaps/firefox_123.snap", "/home/example/disk.qcow2"):
            self.assertIsNone(driver.policy(path), path)
        for path in ("/proc/1/mem", "/dev/sda2", "/snap/firefox/123", "/home/.snapshots/1/a",
                     "/timeshift-btrfs/snapshots/a", "/@apt-snapshot-release-upgrade/a"):
            self.assertIsNotNone(driver.policy(path), path)

    def test_walk_prunes_mounts_snapshots_symlinks_and_duplicate_hardlinks(self):
        for folder in ("data", "mount", ".snapshots", "postgres", "docker"):
            path = self.base / folder
            path.mkdir()
            (path / "file").write_bytes(b"x" * 131072)
        os.link(self.base / "data/file", self.base / "data/hardlink")
        (self.base / "link").symlink_to(self.base / "data", target_is_directory=True)
        self.driver.mount_paths.add(str(self.base / "mount"))
        self.driver.excludes += (str(self.base / "index.sqlite"),)
        self.driver.command = mock.Mock(return_value=subprocess.CompletedProcess([], 0, protocol([b"a" * 64] * 32), b""))
        with contextlib.redirect_stdout(io.StringIO()):
            self.driver.scan()
        self.assertEqual(self.driver.counts["indexed_files"], 3)
        self.assertEqual(self.driver.counts["skipped_hardlink_or_duplicate_view"], 1)
        self.assertEqual(self.driver.counts["skipped_snapshot_path"], 1)
        self.assertEqual(self.driver.counts["skipped_mount_or_separate_root"], 1)
        self.assertEqual(self.driver.counts["skipped_symlink"], 1)

    def test_readonly_subvolume_is_pruned_but_writable_container_subvolume_is_scanned(self):
        readonly = self.base / "custom-snapshot"
        writable = self.base / "container-layer"
        for path in (readonly, writable):
            path.mkdir()
            (path / "file").write_bytes(b"x" * 131072)
        real_lstat = os.lstat
        def fake_inode(path, *args, **kwargs):
            value = real_lstat(path, *args, **kwargs)
            if str(path) in (str(readonly), str(writable)):
                return mock.Mock(st_ino=256, st_mode=value.st_mode)
            return value
        self.driver.excludes += (str(self.base / "index.sqlite"),)
        self.driver.command = mock.Mock(return_value=subprocess.CompletedProcess([], 0, protocol([b"a" * 64] * 32), b""))
        with mock.patch.object(wrapper.os, "lstat", side_effect=fake_inode), \
             mock.patch.object(wrapper, "subvolume", side_effect=lambda p: (300, p == str(readonly))), \
             contextlib.redirect_stdout(io.StringIO()):
            self.driver.scan()
        self.assertEqual(self.driver.counts["skipped_readonly_subvolume"], 1)
        self.assertEqual(self.driver.counts["indexed_files"], 1)

    def test_all_unavailable_checksums_report_partial_failure_exit(self):
        root = self.base / "input"
        root.mkdir()
        (root / "file").write_bytes(b"x" * 131072)
        self.driver.roots = [str(root)]
        self.driver.prepare = mock.Mock()
        self.driver.command = mock.Mock(return_value=subprocess.CompletedProcess([], 2, b"", b"NODATASUM"))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.driver.run(), 2)
        self.assertEqual(self.driver.counts["candidate_pairs"], 0)

    def pair(self):
        return self.add_file("a", [b"a" * 64] * 32)[0], self.add_file("b", [b"a" * 64] * 32)[0]

    @staticmethod
    def dry_result(status=0):
        return subprocess.CompletedProcess([], status, b"Total size(KB) available for dedupe: 128\n", b"")

    def test_default_mode_never_applies(self):
        self.driver.command = mock.Mock(return_value=self.dry_result())
        self.driver.process_pair(*self.pair())
        self.assertEqual(self.driver.command.call_count, 1)
        self.assertIn("--dry-run", self.driver.command.call_args.args[0])

    def test_apply_is_always_preceded_by_successful_dry_run(self):
        self.args.apply = True
        self.driver.command = mock.Mock(side_effect=[self.dry_result(), subprocess.CompletedProcess([], 0, b"Total size(KB) deduped: 128\n", b"")])
        self.driver.process_pair(*self.pair())
        calls = self.driver.command.call_args_list
        self.assertEqual([call.args[1] for call in calls], ["dry-run", "apply"])
        self.assertEqual(calls[0].args[0][:-1], calls[1].args[0])
        self.assertNotIn("--fast-mode", calls[1].args[0])

    def test_failed_or_malformed_dry_run_blocks_apply(self):
        self.args.apply = True
        pair = self.pair()
        for result in (self.dry_result(1), subprocess.CompletedProcess([], 0, b"", b""), None):
            self.driver.command = mock.Mock(return_value=result)
            with contextlib.redirect_stdout(io.StringIO()):
                self.driver.process_pair(*pair)
            self.assertEqual(self.driver.command.call_count, 1)

    def test_change_during_dry_run_blocks_apply(self):
        self.args.apply = True
        first, second = self.pair()
        def changing(_argv, _phase):
            (self.base / "b").write_bytes(b"changed" * 20000)
            return self.dry_result()
        self.driver.command = mock.Mock(side_effect=changing)
        self.driver.process_pair(first, second)
        self.assertEqual(self.driver.command.call_count, 1)
        self.assertEqual(self.driver.counts["skipped_changed_or_unavailable_before_pair"], 1)

    def test_apply_failure_stops_run(self):
        self.args.apply = True
        self.driver.command = mock.Mock(side_effect=[self.dry_result(), subprocess.CompletedProcess([], 1, b"", b"ENOSPC")])
        with self.assertRaises(wrapper.StopRun):
            self.driver.process_pair(*self.pair())

    def test_busy_executable_is_reported_without_stopping_other_pairs(self):
        self.args.apply = True
        self.driver.command = mock.Mock(side_effect=[self.dry_result(), subprocess.CompletedProcess([], 1, b"", b"Text file busy (os error 26)")])
        with contextlib.redirect_stdout(io.StringIO()):
            self.driver.process_pair(*self.pair())
        self.assertEqual(self.driver.counts["errors"], 1)
        self.assertEqual(self.driver.counts["applied_pairs"], 0)

    def test_checksum_failure_and_mutation_are_not_indexed(self):
        path = self.base / "file"
        path.write_bytes(b"x" * 131072)
        self.driver.command = mock.Mock(return_value=subprocess.CompletedProcess([], 2, b"", b"NODATASUM"))
        with contextlib.redirect_stdout(io.StringIO()):
            self.driver.index_file(str(path))
        self.assertEqual(self.driver.counts["checksums_unavailable"], 1)
        self.assertEqual(self.driver.db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0], 0)
        self.driver.db.execute("DELETE FROM files")
        def changing(_argv, _phase):
            path.write_bytes(b"y" * 131072)
            return subprocess.CompletedProcess([], 0, protocol([b"a" * 64] * 32), b"")
        self.driver.command = mock.Mock(side_effect=changing)
        self.driver.index_file(str(path))
        self.assertEqual(self.driver.counts["skipped_changed_during_inspection"], 1)

    def test_space_and_mount_change_guards(self):
        with mock.patch.object(wrapper.shutil, "disk_usage", return_value=mock.Mock(free=0)):
            with self.assertRaisesRegex(wrapper.StopRun, "free space"):
                wrapper.Driver.check(self.driver)
        self.driver.mount_text = "old mounts"
        with self.assertRaisesRegex(wrapper.StopRun, "mount table changed"):
            wrapper.Driver.check(self.driver)

    def test_sqlite_size_cap_is_enforced(self):
        with self.assertRaisesRegex(sqlite3.OperationalError, "full"):
            self.driver.db.execute("INSERT INTO chunks VALUES (?,?)", (b"x" * (2 * wrapper.MIB), 1))
        self.assertLessEqual((self.base / "index.sqlite").stat().st_size, wrapper.MIB)

    def test_mount_parser_decodes_spaces_and_selects_longest_mount(self):
        entries = wrapper.mounts("1 0 0:1 /@ / rw - btrfs /dev/sda2 rw\n"
                                 "2 1 0:1 /@home /home rw - btrfs /dev/sda2 rw\n"
                                 "3 2 0:2 / /home/a\\040b ro - squashfs /dev/loop0 ro\n")
        self.assertEqual(wrapper.mount_for("/home/a b/file", entries).fs, "squashfs")
        self.assertEqual(wrapper.mount_for("/home/abc", entries).path, "/home")

    def test_filename_is_passed_without_shell_interpretation(self):
        name = "spaces ' and $(touch SENTINEL)\nnewline"
        first, _ = self.add_file(name, [b"a" * 64] * 32)
        second, _ = self.add_file("other", [b"a" * 64] * 32)
        self.driver.command = mock.Mock(return_value=self.dry_result())
        self.driver.process_pair(first, second)
        self.assertIn(str(self.base / name), self.driver.command.call_args.args[0])
        result = wrapper.capture([sys.executable, "-c", "import sys; print(repr(sys.argv[1]))", name],
                                 cwd=self.base, env=os.environ.copy(), timeout=10)
        self.assertEqual(result.stdout.decode().strip(), repr(name))
        self.assertFalse((self.base / "SENTINEL").exists())

    def test_complete_pipeline_with_real_subprocesses_and_fake_ioctls(self):
        root = self.base / "input"
        root.mkdir()
        for name in ("first", "second"):
            (root / name).write_bytes(b"fixture" * 32768)
        helper = self.base / "helper"
        helper.write_text("#!/usr/bin/env python3\n"
                          "import hashlib, pathlib, sys\n"
                          "data = pathlib.Path(sys.argv[3]).read_bytes()\n"
                          "print('dduper-csum-v1 4096', len(data), (len(data)+4095)//4096)\n"
                          "for i in range(0, len(data), 4096): print(hashlib.sha256(data[i:i+4096]).hexdigest())\n")
        app = self.base / "app"
        app.write_text("#!/usr/bin/env python3\n"
                       "import json, sys\n"
                       "with open('calls.jsonl', 'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                       "print('Total size(KB) available for dedupe: 224' if '--dry-run' in sys.argv else 'Total size(KB) deduped: 224')\n")
        helper.chmod(0o755)
        app.chmod(0o755)
        self.args.helper, self.args.dduper = str(helper), str(app)
        self.args.apply = True
        self.driver.roots = [str(root)]
        self.driver.prepare = mock.Mock()  # Only kernel/mount/priority preflight is replaced.
        with contextlib.redirect_stdout(io.StringIO()):
            status = self.driver.run()
        self.assertEqual(status, 0)
        self.assertEqual(self.driver.counts["indexed_files"], 2)
        self.assertEqual(self.driver.counts["candidate_pairs"], 1)
        self.assertEqual(self.driver.counts["applied_pairs"], 1)
        calls = [json.loads(s) for s in (self.base / "calls.jsonl").read_text().splitlines()]
        self.assertIn("--dry-run", calls[0])
        self.assertNotIn("--dry-run", calls[1])
        self.assertNotIn("--fast-mode", str(calls))
        self.assertEqual((root / "first").read_bytes(), b"fixture" * 32768)
        self.assertEqual((root / "second").read_bytes(), (root / "first").read_bytes())

    def test_process_timeout_is_reported(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            wrapper.capture([sys.executable, "-c", "import time; time.sleep(30)"],
                            cwd=self.base, env=os.environ.copy(), timeout=0.02)

    def test_ctrl_c_stops_child_and_helper_disk_activity(self):
        # A real process tree, without Btrfs access: wrapper -> app -> helper.
        # The helper appends tiny records so an orphan continuing I/O is visible.
        helper_code = (
            "import os, pathlib, time\n"
            "pathlib.Path('helper.pid').write_text(str(os.getpid()))\n"
            "with open('heartbeat', 'ab', buffering=0) as f:\n"
            " while True:\n"
            "  f.write(b'.'); time.sleep(0.02)\n"
        )
        app_code = (
            "import os, pathlib, signal, subprocess, sys\n"
            "pathlib.Path('app.pid').write_text(str(os.getpid()))\n"
            f"child = subprocess.Popen([sys.executable, '-c', {helper_code!r}])\n"
            "def stop(*_): sys.exit(0)\n"
            "signal.signal(signal.SIGTERM, stop)\n"
            "try: child.wait()\n"
            "finally: child.wait(timeout=2)\n"
        )
        harness = (
            "import os, sys\n"
            f"sys.path.insert(0, {str(REPO / 'scripts')!r})\n"
            "from ubuntu_deduper import capture\n"
            "try:\n"
            f" capture([sys.executable, '-c', {app_code!r}], cwd='.', env=os.environ.copy(), timeout=30)\n"
            "except KeyboardInterrupt: sys.exit(130)\n"
        )
        with subprocess.Popen([sys.executable, "-c", harness], cwd=self.base,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                deadline = time.monotonic() + 5
                while not (self.base / "heartbeat").exists():
                    self.assertIsNone(process.poll(), "test harness exited before child startup")
                    self.assertLess(time.monotonic(), deadline, "child startup timed out")
                    time.sleep(0.02)
                start = time.monotonic()
                process.send_signal(signal.SIGINT)
                _, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 130, stderr.decode())
                self.assertLess(time.monotonic() - start, 4)
                for name in ("app.pid", "helper.pid"):
                    pid = int((self.base / name).read_text())
                    self.assertFalse(Path(f"/proc/{pid}").exists(), f"{name} still running")
                before = (self.base / "heartbeat").stat().st_size
                time.sleep(0.1)
                self.assertEqual((self.base / "heartbeat").stat().st_size, before)
            finally:
                # Cleanup also covers a failing regression, without touching unrelated PIDs.
                for name in ("helper.pid", "app.pid"):
                    if (self.base / name).exists():
                        try:
                            os.kill(int((self.base / name).read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                if process.poll() is None:
                    process.kill()


if __name__ == "__main__":
    unittest.main()
