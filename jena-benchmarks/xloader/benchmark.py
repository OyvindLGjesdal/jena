#!/usr/bin/env python3
# Licensed under the terms of http://www.apache.org/licenses/LICENSE-2.0
"""Reproducible, opt-in benchmarks of an installed TDB2 xloader."""
import argparse
import re
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import time
import tempfile
import uuid


class LowDiskSpace(ValueError):
    pass


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def capture(command, env=None):
    result = subprocess.run(command, capture_output=True, text=True, env=env)
    return {"command": command, "exit_code": result.returncode,
            "output": result.stdout + result.stderr}


def executable(name):
    path = shutil.which(os.path.expanduser(name))
    if not path:
        raise ValueError(f"Executable not found: {name}")
    # Preserve the invoked name for multicall binaries such as uutils.
    return os.path.abspath(path)


def sorter(name=None):
    path = executable(name or ("gsort" if shutil.which("gsort") else "sort"))
    version = capture([path, "--version"])
    if version["exit_code"]:
        raise ValueError(f"Cannot read sorter version: {path}")
    if name is None and "GNU coreutils" not in version["output"]:
        raise ValueError("Default baseline requires GNU sort; install coreutils or select --sort explicitly")
    version.update(executable=path, resolved_path=str(Path(path).resolve()), sha256=digest(Path(path)))
    return version


def sort_preflight(path, home, threads):
    env = dict(os.environ, LC_ALL="C")
    gzip_program = "/bin/gzip" if Path("/bin/gzip").is_file() else "/usr/bin/gzip"
    with tempfile.TemporaryDirectory(prefix="sort-preflight-", dir=home) as temporary:
        command = [path, f"--temporary-directory={temporary}", "--buffer-size=50%",
                   f"--parallel={threads}", "--unique", f"--compress-program={gzip_program}",
                   "--key=1,1", "--key=2,2", "--key=3,3"]
        result = subprocess.run(command, input=b"02 01 03\n01 02 03\n02 01 03\n",
                                capture_output=True, env=env, timeout=30)
        if result.returncode or result.stdout != b"01 02 03\n02 01 03\n":
            raise ValueError(f"Sorter failed xloader option smoke check: {path}: "
                             + result.stderr.decode(errors="replace"))


def compressor(name, arguments=()):
    """Resolve a sort --compress-program candidate and check the round trip sort relies on.

    `arguments` are the SORT_COMPRESS_ARGS the load will use, placed before sort's -d.
    """
    path = executable(name)
    data = b"".join(f"{i:016x} {i * 7:016x} {i * 13:016x}\n".encode() for i in range(4096))
    packed = subprocess.run([path, *arguments], input=data, capture_output=True, timeout=30)
    unpacked = subprocess.run([path, *arguments, "-d"], input=packed.stdout, capture_output=True, timeout=30)
    if packed.returncode or unpacked.returncode or unpacked.stdout != data:
        shown = " ".join([path, *arguments])
        raise ValueError(f"Compressor failed the stdin/stdout and -d round trip used by sort: {shown}")
    version = capture([path, "--version"])
    version.update(executable=path, resolved_path=str(Path(path).resolve()), sha256=digest(Path(path)),
                   arguments=list(arguments))
    return version


# Sort passes --compress-program=PROG; route it through a logging wrapper so runs
# record whether index sorts spilled, optionally replacing PROG.
SORT_WRAPPER = """#!/bin/sh
for arg do
    shift
    case $arg in
        --compress-program=*)
            XLOADER_BENCH_COMPRESS=${{XLOADER_BENCH_COMPRESS:-${{arg#--compress-program=}}}}
            export XLOADER_BENCH_COMPRESS
            set -- "$@" --compress-program={compress} ;;
        *) set -- "$@" "$arg" ;;
    esac
done
exec {sorter} "$@"
"""

# SORT_COMPRESS_ARGS are applied exactly once: xloader's own wrapper (used by launchers
# that support the variable, when it is set) applies them itself; any other program,
# including a replacement from --sort-compress and an older launcher's gzip, gets them here.
COMPRESS_WRAPPER = """#!/bin/sh
echo "${{1:-compress}}" >> {log}
case "${{XLOADER_BENCH_COMPRESS##*/}}" in
    xloader-sort-compress) exec "$XLOADER_BENCH_COMPRESS" "$@" ;;
esac
set -f
exec "$XLOADER_BENCH_COMPRESS" $SORT_COMPRESS_ARGS "$@"
"""


def compress_calls(log):
    calls = log.read_text().split() if log.exists() else []
    return {"compress": calls.count("compress"), "decompress": calls.count("-d")}


def logged(command, env, log, watch=None, interval=5):
    process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    try:
        while True:
            try:
                return process.wait(timeout=interval if watch else None)
            except subprocess.TimeoutExpired:
                watch()
    except BaseException:
        # Include sort/compression subprocesses when a run is interrupted.
        try:
            os.killpg(process.pid, signal.SIGTERM)
            time.sleep(0.5)
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            # macOS reports EPERM when only the unreaped zombie leader remains.
            pass
        process.wait()
        raise


def compatible(path):
    # The existing xloader expands filenames without shell quoting.
    if any(c.isspace() or c in "*?[]" for c in str(path)):
        raise ValueError(f"xloader requires paths without whitespace or glob characters: {path}")
    return path


def prepare(args, home):
    source = compatible(Path(args.input).expanduser().resolve())
    if not source.is_file() or not source.name.endswith(".nt.gz"):
        raise ValueError("Input must be an existing .nt.gz file")
    manifest = home / "inputs" / f"{args.dataset}.json"
    if manifest.exists():
        raise ValueError(f"Input already pinned: {manifest}; use another benchmark home for another snapshot")
    if args.count:
        print("Hashing and checking gzip; counting N-Triples lines (outside benchmark timing).", flush=True)
    else:
        print("Hashing (outside benchmark timing).", flush=True)
    checksum = digest(source)
    if args.sha256 and checksum != args.sha256.lower():
        raise ValueError("SHA-256 mismatch")
    lines = None
    size = None
    if args.count:
        lines = 0
        size = 0
        with gzip.open(source, "rb") as stream:
            for line in stream:
                size += len(line)
                if line.strip() and not line.lstrip().startswith(b"#"):
                    lines += 1
    manifest.parent.mkdir(parents=True, exist_ok=True)
    save(manifest, {"dataset": args.dataset, "path": str(source), "source": args.source,
                    "sha256": checksum, "compressed_bytes": source.stat().st_size,
                    "uncompressed_bytes": size, "statement_lines": lines,
                    "note": "Line count assumes one N-Triples statement per line; not a distinct triple count."
                            if lines is not None else "Not decompressed or counted (prepare without --count)."})
    print(manifest)


def space_watch(volumes, reserve):
    """Track the lowest free space per volume; stop the load below the reserve."""
    lowest = {}

    def watch():
        for name, path in volumes.items():
            free = shutil.disk_usage(path).free
            lowest[name] = min(free, lowest.get(name, free))
            if free < reserve:
                raise LowDiskSpace(f"Only {free / 1e9:.1f} GB free on the {name} volume ({path}); "
                                   f"below --min-free-gb={reserve / 1e9:g}")
    return watch, lowest


def run(args, home):
    manifest = home / "inputs" / f"{args.dataset}.json"
    data = json.loads(manifest.read_text())
    source = compatible(Path(data["path"]))
    tmp_home = compatible(Path(args.tmp_home).expanduser().resolve()) if args.tmp_home else None
    if tmp_home and not tmp_home.is_dir():
        raise ValueError(f"--tmp-home must be an existing directory: {tmp_home}")
    volumes = {"database": home, "temporary": tmp_home or home}
    watch, lowest_free = space_watch(volumes, args.min_free_gb * 1e9)
    # Refuse to start on an already low volume.
    watch()
    installation = compatible(Path(os.environ["JENA_HOME"]).expanduser().resolve())
    for name in ("tdb2.xloader", "tdb2.tdbquery"):
        if not os.access(installation / "bin" / name, os.X_OK):
            raise ValueError(f"Missing executable: {installation / 'bin' / name}")
    for name in ("bash", "java", "gzip", "jq", "du"):
        if not shutil.which(name):
            raise ValueError(f"Required program not on PATH: {name}")
    sort_check = sorter(args.sort)
    sort_preflight(sort_check["executable"], tmp_home or home, args.threads)
    compress_arguments = args.sort_compress_args.split() if args.sort_compress_args else []
    compress_check = compressor(args.sort_compress, compress_arguments) if args.sort_compress else None
    if compress_arguments and not compress_check:
        # Check the arguments with the default compressor, which xloader passes as gzip.
        default_gzip = "/usr/bin/gzip" if Path("/usr/bin/gzip").is_file() else "gzip"
        compressor(default_gzip, compress_arguments)
    if platform.system() not in ("Darwin", "Linux"):
        raise ValueError("Timing support currently requires macOS or Linux")
    print("Verifying pinned input checksum (outside benchmark timing).", flush=True)
    if digest(source) != data["sha256"]:
        raise ValueError("Input differs from pinned checksum")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = stamp + "-" + uuid.uuid4().hex[:8]
    result_dir = home / "runs" / args.dataset / run_id
    result_dir.mkdir(parents=True)
    database = result_dir / "database"
    # xloader workfiles (triples/quads intermediates and sort spills) go here.
    temporary = (tmp_home / "runs" / args.dataset / run_id / "tmp") if tmp_home else result_dir / "tmp"
    temporary.mkdir(parents=True)
    env = os.environ.copy()
    env.update(JENA_HOME=str(installation), JVM_ARGS=args.jvm_args, LC_ALL="C")
    # Both launchers use JAVA; xloader does not select Java from JAVA_HOME.
    java = env.get("JAVA") or (str(Path(env["JAVA_HOME"]) / "bin/java") if env.get("JAVA_HOME") else "java")
    env["JAVA"] = executable(java)
    tools_dir = result_dir / "tools"
    tools_dir.mkdir()
    # Outside tools/, so only sort is shadowed on PATH.
    compress_wrapper = result_dir / "sort-compress"
    compress_log = result_dir / "sort-compress.log"
    compress_wrapper.write_text(COMPRESS_WRAPPER.format(log=shlex.quote(str(compress_log))))
    compress_wrapper.chmod(0o755)
    wrapper = tools_dir / "sort"
    wrapper.write_text(SORT_WRAPPER.format(compress=shlex.quote(str(compress_wrapper)),
                                           sorter=shlex.quote(sort_check["executable"])))
    wrapper.chmod(0o755)
    env["PATH"] = str(tools_dir) + os.pathsep + env["PATH"]
    # Unset: the wrapper uses the compressor xloader passes.
    env.pop("XLOADER_BENCH_COMPRESS", None)
    if compress_check:
        env["XLOADER_BENCH_COMPRESS"] = compress_check["executable"]
    # Only the recorded arguments, never a value left over in the calling shell.
    env.pop("SORT_COMPRESS_ARGS", None)
    if compress_arguments:
        env["SORT_COMPRESS_ARGS"] = args.sort_compress_args
    # Always use the recorded installation and standard index set.
    for key in ("JENA_CP", "CLASSPATH", "TRIPLES_IDX", "QUADS_IDX"):
        env.pop(key, None)
    # A launcher that supports --sort-compress also gets the program, so its own check of
    # SORT_COMPRESS_ARGS and its log use it rather than gzip. The wrapper above still runs
    # it (from XLOADER_BENCH_COMPRESS); older launchers only get the sort-level swap.
    launcher = installation / "bin/tdb2.xloader"
    pass_compress = bool(compress_check) and "--sort-compress" in launcher.read_text(errors="replace")
    command = [str(launcher), "--loc", str(database),
               "--tmpdir", str(temporary), "--threads", str(args.threads),
               *(["--sort-compress", compress_check["executable"]] if pass_compress else []),
               *(args.xloader_arg or []), str(source)]
    jars = {p.name: digest(p) for p in sorted((installation / "lib").glob("*.jar"))}
    if not jars:
        raise ValueError("JENA_HOME/lib contains no JARs; use an unpacked Jena distribution")
    metadata = {"status": "running", "label": args.label, "input": data,
                "started_utc": stamp, "platform": platform.platform(),
                "cpu_count": os.cpu_count(), "jena_home": str(installation),
                "jena_revision": args.revision, "jar_sha256": jars,
                "launcher_sha256": digest(installation / "bin/tdb2.xloader"),
                "jvm_args": args.jvm_args, "threads": args.threads,
                "xloader_args": args.xloader_arg or [],
                "java": capture([env["JAVA"], "-version"], env),
                "environment": {k: env.get(k) for k in ("PATH", "JAVA", "JAVA_HOME", "JVM_ARGS",
                                  "LC_ALL", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS",
                                  "SORT_COMPRESS_ARGS")},
                "sort_wrapper_sha256": digest(wrapper),
                "sort_compress": compress_check or "as passed by xloader",
                "sort_compress_args": args.sort_compress_args or None,
                "sort_compress_passed_to_launcher": pass_compress,
                "sort_compress_wrapper_sha256": digest(compress_wrapper),
                "sort": sort_check, "bash": capture(["bash", "--version"]),
                "storage": capture(["df", "-k", str(home)]),
                "free_bytes_before": shutil.disk_usage(home).free,
                "temporary_directory": str(temporary),
                "temporary_storage": capture(["df", "-k", str(temporary)]),
                "temporary_free_bytes_before": shutil.disk_usage(temporary).free,
                "min_free_gb": args.min_free_gb,
                "cache_note": args.cache_note, "command": command}
    save(result_dir / "run.json", metadata)
    (result_dir / "command.txt").write_text(shlex.join(command) + "\n")
    timing = ["/usr/bin/time", "-l" if platform.system() == "Darwin" else "-v"]
    print(f"Results: {result_dir}\nFollow loader.log for stage progress.", flush=True)
    start = time.monotonic()
    try:
        with (result_dir / "loader.log").open("w") as log:
            exit_code = logged(timing + command, env, log, watch)
        metadata.update(elapsed_seconds=time.monotonic() - start, exit_code=exit_code,
                        status="loaded" if exit_code == 0 else "failed")
        save(result_dir / "run.json", metadata)
        if exit_code == 0:
            query = result_dir / "count.rq"
            query.write_text("SELECT (COUNT(*) AS ?triples) WHERE { ?s ?p ?o }\n")
            verify = [str(installation / "bin/tdb2.tdbquery"), "--loc", str(database),
                      "--query", str(query)]
            with (result_dir / "verification.log").open("w") as log:
                check_code = logged(verify, env, log)
            metadata.update(verification_exit_code=check_code,
                            status="counted" if check_code == 0 else "verification_failed")
    except LowDiskSpace as error:
        metadata.update(status="stopped_low_disk_space", error=str(error))
        raise
    except BaseException:
        metadata["status"] = "interrupted_or_error"
        raise
    finally:
        metadata["retained_disk_usage"] = capture(["du", "-sk", str(database), str(temporary)])
        metadata["free_bytes_after"] = shutil.disk_usage(home).free
        metadata["temporary_free_bytes_after"] = shutil.disk_usage(temporary).free
        # Sampled at start and every few seconds during the load; includes other activity.
        metadata["lowest_free_bytes"] = lowest_free
        # Zero calls: no index sort spilled, so the compressor could not matter.
        metadata["sort_compress_calls"] = compress_calls(compress_log)
        save(result_dir / "run.json", metadata)
    print(f"Status: {metadata['status']}; compare verification.log across runs.")
    return 0 if metadata["status"] == "counted" else 1


def dataset_name(value):
    """A dataset name such as lexemes, truthy or truthy-1b; used in file names."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", value):
        raise argparse.ArgumentTypeError(f"invalid dataset name {value!r}: use lower-case letters, digits, '.', '_' or '-'")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    prep = subs.add_parser("prepare", help="Pin an already downloaded N-Triples gzip dump")
    prep.add_argument("dataset", type=dataset_name, help="For example lexemes, truthy or truthy-1b")
    prep.add_argument("--input", required=True)
    prep.add_argument("--source", required=True, help="Dated download URL or provenance")
    prep.add_argument("--sha256", help="Expected SHA-256, if independently available")
    prep.add_argument("--count", action="store_true",
                      help="Also decompress to check the gzip and count N-Triples lines (single-threaded; "
                           "hours for truthy). Without it, statement_lines and uncompressed_bytes are null")
    bench = subs.add_parser("run", help="Load into a fresh database and reopen to count triples")
    bench.add_argument("dataset", type=dataset_name, help="A dataset pinned with prepare")
    bench.add_argument("--label", required=True, help="For example baseline or parsort")
    bench.add_argument("--revision", required=True, help="Commit/tag used to build JENA_HOME")
    bench.add_argument("--threads", type=int, default=2)
    bench.add_argument("--sort", help="Sorter executable, e.g. gsort or uu-sort; default requires GNU sort")
    bench.add_argument("--sort-compress", help="Replace sort's temporary-file compressor (xloader passes gzip "
                       "for index sorts), e.g. pigz; must support stdin/stdout and -d")
    bench.add_argument("--sort-compress-args", help="Arguments for sort's temporary-file compressor, passed as "
                       "SORT_COMPRESS_ARGS and split at spaces, e.g. --sort-compress-args='-1 -p 4'. Applied "
                       "once, by xloader's wrapper where the launcher supports it, otherwise by the harness")
    bench.add_argument("--jvm-args", default="-Xmx4G")
    bench.add_argument("--xloader-arg", action="append", metavar="ARG",
                       help="Extra tdb2.xloader option, repeatable, e.g. --xloader-arg=--sort-compress-nodes "
                            "or --xloader-arg=--workfile-gzip-level=6; passed before the input file")
    bench.add_argument("--tmp-home", help="Existing directory for xloader workfiles and sort spills, "
                       "e.g. on a faster internal disk; defaults to the run directory")
    bench.add_argument("--min-free-gb", type=float, default=20,
                       help="Stop the load if either volume has less free space than this (default 20)")
    bench.add_argument("--cache-note", required=True, help="Describe cache conditions and other machine activity")
    args = parser.parse_args()
    try:
        home = compatible(Path(os.environ["JENA_BENCHMARK_HOME"]).expanduser().resolve())
        if not home.is_dir():
            raise ValueError("JENA_BENCHMARK_HOME must already exist (check that the drive is mounted)")
        if args.action == "prepare":
            prepare(args, home)
            return 0
        if args.threads < 1:
            raise ValueError("--threads must be positive")
        if args.min_free_gb < 0:
            raise ValueError("--min-free-gb must not be negative")
        return run(args, home)
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    sys.exit(main())
