# Licensed under the terms of http://www.apache.org/licenses/LICENSE-2.0
"""Harness integration checks with stub tools; these do not benchmark Jena."""
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).with_name("benchmark.py")
sys.path.insert(0, str(SCRIPT.parent))
import benchmark  # noqa: E402


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="jena-bench-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.install = self.home / "installation"
        self.bin = self.install / "bin"
        self.bin.mkdir(parents=True)
        (self.install / "lib").mkdir()
        (self.install / "lib/test.jar").write_bytes(b"stub")
        for name in ("java", "jq"):
            self.tool(name, "echo stub-version\n")
        for name in ("sort", "gsort"):
            self.tool(name, 'case "$*" in *--version*) echo "sort (GNU coreutils) stub" ;; '
                      '*) /usr/bin/sort -u ;; esac\n')
        self.tool("tdb2.xloader", 'mkdir -p "$2"\nsort --version\n'
                  'sort --compress-program=/usr/bin/gzip --key=1,1 < /dev/null\n'
                  'echo loaded\nexit "${STUB_LOAD_RC:-0}"\n')
        self.tool("tdb2.tdbquery", 'echo triples=1\nexit "${STUB_QUERY_RC:-0}"\n')
        self.env = dict(os.environ, JENA_BENCHMARK_HOME=str(self.home),
                        JENA_HOME=str(self.install), JAVA=str(self.bin / "java"),
                        PATH=str(self.bin) + os.pathsep + os.environ["PATH"])
        self.input = self.home / "input.nt.gz"
        with gzip.open(self.input, "wb") as out:
            out.write(b'<urn:s> <urn:p> <urn:o> .\n')

    def tool(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    def invoke(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], env=self.env,
                              capture_output=True, text=True)

    def prepare(self, *args):
        result = self.invoke("prepare", "lexemes", "--input", str(self.input),
                             "--source", "test-fixture", *args)
        self.assertEqual(result.returncode, 0, result.stderr)

    def run_load(self, *args):
        return self.invoke("run", "lexemes", "--label", "test", "--revision", "fixture",
                           "--cache-note", "stub integration test", *args)

    def records(self):
        return [json.loads(p.read_text()) for p in self.home.glob("runs/lexemes/*/run.json")]

    def test_pin_fresh_runs_and_count(self):
        self.prepare("--count")
        for _ in range(2):
            result = self.run_load()
            self.assertEqual(result.returncode, 0, result.stderr)
        records = self.records()
        self.assertEqual(len(records), 2)
        self.assertTrue(all(r["status"] == "counted" for r in records))
        self.assertEqual(records[0]["input"]["statement_lines"], 1)

    def test_prepare_without_count(self):
        self.prepare()
        manifest = json.loads((self.home / "inputs" / "lexemes.json").read_text())
        self.assertIsNone(manifest["statement_lines"])
        self.assertIsNone(manifest["uncompressed_bytes"])
        self.assertEqual(len(manifest["sha256"]), 64)
        result = self.run_load()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.records()[0]["status"], "counted")

    def test_xloader_args_passed_before_input(self):
        self.prepare()
        result = self.run_load("--xloader-arg=--sort-compress-nodes", "--xloader-arg=--workfile-gzip-level=6")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.records()[0]
        self.assertEqual(record["xloader_args"], ["--sort-compress-nodes", "--workfile-gzip-level=6"])
        self.assertEqual(record["command"][-3:], ["--sort-compress-nodes", "--workfile-gzip-level=6",
                                                  str(self.input.resolve())])

    def test_dataset_names(self):
        result = self.invoke("prepare", "truthy-1b", "--input", str(self.input), "--source", "test-fixture")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.home / "inputs" / "truthy-1b.json").is_file())
        for bad in ("../x", "Truthy", "a/b", ""):
            result = self.invoke("prepare", bad, "--input", str(self.input), "--source", "test-fixture")
            self.assertNotEqual(result.returncode, 0, bad)
            self.assertIn("invalid dataset name", result.stderr)

    def test_changed_input_rejected(self):
        self.prepare()
        self.input.write_bytes(b"changed")
        self.assertNotEqual(self.run_load().returncode, 0)
        self.assertEqual(self.records(), [])

    def test_loader_failure_preserved_without_verification(self):
        self.prepare()
        self.env["STUB_LOAD_RC"] = "7"
        self.assertNotEqual(self.run_load().returncode, 0)
        record, = self.records()
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["exit_code"], 7)
        self.assertNotIn("verification_exit_code", record)

    def test_query_failure_not_success(self):
        self.prepare()
        self.env["STUB_QUERY_RC"] = "8"
        self.assertNotEqual(self.run_load().returncode, 0)
        record, = self.records()
        self.assertEqual(record["status"], "verification_failed")

    def test_explicit_sorter_reaches_loader_without_replacing_other_tools(self):
        self.prepare()
        self.tool("uu-sort", 'case "$*" in *--version*) echo "sort (uutils) stub" ;; '
                  '*) /usr/bin/sort -u ;; esac\n')
        result = self.run_load("--sort", str(self.bin / "uu-sort"))
        self.assertEqual(result.returncode, 0, result.stderr)
        record, = self.records()
        self.assertEqual(record["sort"]["executable"], str(self.bin / "uu-sort"))
        self.assertEqual(len(record["sort"]["sha256"]), 64)
        wrapper_dir = Path(record["environment"]["PATH"].split(os.pathsep)[0])
        self.assertEqual([p.name for p in wrapper_dir.iterdir()], ["sort"])
        self.assertIn("sort (uutils) stub", (wrapper_dir.parent / "loader.log").read_text())

    def test_sorter_rejecting_xloader_options_is_rejected_before_loading(self):
        self.prepare()
        self.tool("bad-sort", 'case "$*" in *--version*) echo candidate ;; *) exit 2 ;; esac\n')
        result = self.run_load("--sort", str(self.bin / "bad-sort"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("option smoke check", result.stderr)
        self.assertEqual(self.records(), [])

    def test_tmp_home_holds_workfiles_outside_benchmark_home(self):
        self.prepare()
        tmp_home = self.home / "internal"
        tmp_home.mkdir()
        result = self.run_load("--tmp-home", str(tmp_home))
        self.assertEqual(result.returncode, 0, result.stderr)
        record, = self.records()
        temporary = Path(record["temporary_directory"])
        self.assertTrue(temporary.is_dir())
        self.assertEqual(temporary.parents[3], tmp_home.resolve())
        self.assertEqual(record["command"][record["command"].index("--tmpdir") + 1], str(temporary))
        self.assertIn("temporary", record["lowest_free_bytes"])

    def test_low_free_space_refuses_to_start(self):
        self.prepare()
        result = self.run_load("--min-free-gb", "1e12")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--min-free-gb", result.stderr)
        self.assertEqual(self.records(), [])

    def test_watch_failure_stops_process_group(self):
        pidfile = self.home / "child.pid"

        def watch():
            if pidfile.exists():
                raise benchmark.LowDiskSpace("simulated")
        start = time.monotonic()
        with (self.home / "watch.log").open("w") as log, self.assertRaises(benchmark.LowDiskSpace):
            benchmark.logged(["sh", "-c", f"sleep 30 & echo $! > {pidfile}; wait"],
                             os.environ, log, watch, interval=0.1)
        self.assertLess(time.monotonic() - start, 10)
        child = int(pidfile.read_text())
        # The orphaned grandchild must be gone, not just the shell.
        for _ in range(40):
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            self.fail("sort-like grandchild survived")

    def recording_sort(self):
        # Records its arguments and exercises the compressor like a spilling sort.
        args, trip = self.home / "sort-args.txt", self.home / "roundtrip.txt"
        self.tool("rec-sort", 'case "$*" in *--version*) echo "sort (GNU coreutils) stub" ;; *)\n'
                  f'echo "$*" >> {args}\n'
                  'for a do case $a in --compress-program=*) p=${a#--compress-program=}\n'
                  f'echo hi | "$p" | "$p" -d >> {trip} ;; esac; done\n'
                  '/usr/bin/sort -u ;; esac\n')
        return args, trip

    def test_sort_compressor_passed_through_and_counted(self):
        self.prepare()
        args, trip = self.recording_sort()
        result = self.run_load("--sort", str(self.bin / "rec-sort"))
        self.assertEqual(result.returncode, 0, result.stderr)
        record, = self.records()
        self.assertEqual(record["sort_compress"], "as passed by xloader")
        wrapper = Path(record["environment"]["PATH"].split(os.pathsep)[0]).parent / "sort-compress"
        self.assertIn(f"--compress-program={wrapper} --key=1,1", args.read_text())
        # The sorter smoke check before loading also round-trips once, with gzip directly.
        self.assertEqual(trip.read_text(), "hi\nhi\n")
        self.assertEqual(record["sort_compress_calls"], {"compress": 1, "decompress": 1})

    def test_sort_compressor_replaced(self):
        self.prepare()
        _, trip = self.recording_sort()
        used = self.home / "fake-pigz-used.txt"
        self.tool("fake-pigz", 'case "$*" in --version) echo "fake-pigz 1.0" ;; *)\n'
                  f'echo "$*" >> {used}\nexec /usr/bin/gzip "$@" ;; esac\n')
        result = self.run_load("--sort", str(self.bin / "rec-sort"),
                               "--sort-compress", str(self.bin / "fake-pigz"))
        self.assertEqual(result.returncode, 0, result.stderr)
        record, = self.records()
        self.assertEqual(record["sort_compress"]["executable"], str(self.bin / "fake-pigz"))
        self.assertIn("fake-pigz 1.0", record["sort_compress"]["output"])
        # The sorter smoke check before loading also round-trips once, with gzip directly.
        self.assertEqual(trip.read_text(), "hi\nhi\n")
        # Two round-trip preflight calls, then one compress and one decompress in the load.
        self.assertEqual(sorted(used.read_text().splitlines()), ["", "", "-d", "-d"])
        self.assertEqual(record["sort_compress_calls"], {"compress": 1, "decompress": 1})

    def logging_compressor(self, name):
        # Records each call's arguments, then behaves like gzip.
        used = self.home / f"{name}-used.txt"
        self.tool(name, 'case "$*" in --version) echo "' + name + ' 1.0" ;; *)\n'
                  f'echo "[$*]" >> {used}\nexec /usr/bin/gzip "$@" ;; esac\n')
        return self.bin / name, used

    def launcher_passing(self, program):
        # A launcher stub whose sort gets PROGRAM as --compress-program, like xloader.
        self.tool("tdb2.xloader", 'mkdir -p "$2"\nsort --version\n'
                  f'sort --compress-program={program} --key=1,1 < /dev/null\n'
                  'echo loaded\n')

    def test_sort_compress_args_with_replaced_compressor(self):
        self.prepare()
        self.recording_sort()
        fake, used = self.logging_compressor("fake-pigz")
        result = self.run_load("--sort", str(self.bin / "rec-sort"), "--sort-compress", str(fake),
                               "--sort-compress-args=-1 -9")
        self.assertEqual(result.returncode, 0, result.stderr)
        record, = self.records()
        self.assertEqual(record["sort_compress_args"], "-1 -9")
        self.assertEqual(record["environment"]["SORT_COMPRESS_ARGS"], "-1 -9")
        self.assertEqual(record["sort_compress"]["arguments"], ["-1", "-9"])
        # Preflight round trip, then one compress and one decompress in the load; the
        # recording sort runs compress and decompress as a pipeline, so order varies.
        self.assertEqual(sorted(used.read_text().splitlines()), sorted(["[-1 -9 -d]", "[-1 -9]"] * 2))
        self.assertEqual(record["sort_compress_calls"], {"compress": 1, "decompress": 1})

    def test_sort_compress_passed_to_a_launcher_that_supports_it(self):
        self.prepare()
        fake, used = self.logging_compressor("fake-pigz")
        result = self.run_load("--sort-compress", str(fake))
        self.assertEqual(result.returncode, 0, result.stderr)
        record, = self.records()
        # The stub launcher does not mention --sort-compress, like an older launcher.
        self.assertFalse(record["sort_compress_passed_to_launcher"])
        self.assertNotIn("--sort-compress", record["command"])
        launcher = self.install / "bin" / "tdb2.xloader"
        launcher.write_text(launcher.read_text() + "\n# Accepts --sort-compress=PROGRAM\n")
        result = self.run_load("--sort-compress", str(fake))
        self.assertEqual(result.returncode, 0, result.stderr)
        newer = [r for r in self.records() if r["sort_compress_passed_to_launcher"]]
        self.assertEqual(len(newer), 1)
        i = newer[0]["command"].index("--sort-compress")
        self.assertEqual(newer[0]["command"][i + 1], newer[0]["sort_compress"]["executable"])

    def test_sort_compress_args_for_the_program_an_older_launcher_passes(self):
        self.prepare()
        self.recording_sort()
        passed, used = self.logging_compressor("plain-gzip")
        self.launcher_passing(passed)
        result = self.run_load("--sort", str(self.bin / "rec-sort"), "--sort-compress-args=-1")
        self.assertEqual(result.returncode, 0, result.stderr)
        record, = self.records()
        self.assertEqual(record["sort_compress"], "as passed by xloader")
        self.assertEqual(sorted(used.read_text().splitlines()), ["[-1 -d]", "[-1]"])

    def test_sort_compress_args_not_applied_twice_with_xloader_wrapper(self):
        self.prepare()
        self.recording_sort()
        # Stands in for xloader's bin/xloader-sort-compress, which applies the arguments itself.
        wrapper, used = self.logging_compressor("xloader-sort-compress")
        self.launcher_passing(wrapper)
        result = self.run_load("--sort", str(self.bin / "rec-sort"), "--sort-compress-args=-1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(used.read_text().splitlines()), ["[-d]", "[]"])

    def test_sort_compress_args_from_the_shell_are_not_inherited(self):
        self.prepare()
        self.recording_sort()
        passed, used = self.logging_compressor("plain-gzip")
        self.launcher_passing(passed)
        self.env["SORT_COMPRESS_ARGS"] = "-9"
        result = self.run_load("--sort", str(self.bin / "rec-sort"))
        self.assertEqual(result.returncode, 0, result.stderr)
        record, = self.records()
        self.assertIsNone(record["sort_compress_args"])
        self.assertIsNone(record["environment"]["SORT_COMPRESS_ARGS"])
        self.assertEqual(sorted(used.read_text().splitlines()), ["[-d]", "[]"])

    def test_bad_sort_compress_args_rejected_before_loading(self):
        self.prepare()
        result = self.run_load("--sort-compress-args=--no-such-option")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("round trip", result.stderr)
        self.assertIn("--no-such-option", result.stderr)
        self.assertEqual(self.records(), [])

    def test_broken_compressor_rejected_before_loading(self):
        self.prepare()
        self.tool("bad-zip", "exit 1\n")
        result = self.run_load("--sort-compress", str(self.bin / "bad-zip"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("round trip", result.stderr)
        self.assertEqual(self.records(), [])


if __name__ == "__main__":
    unittest.main()
