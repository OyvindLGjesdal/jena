#!/usr/bin/env python3
# Licensed under the terms of http://www.apache.org/licenses/LICENSE-2.0
"""Compare a sorter with GNU sort on synthetic xloader records; no Java required."""
import argparse
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile

from benchmark import compressor, sorter


def fixtures():
    rng = random.Random(3986)
    nodes = [f"{i:032x} {i:08x}\n".encode() for i in range(2048)]
    triples = [" ".join(f"{rng.randrange(256):016x}" for _ in range(3)).encode() + b"\n"
               for _ in range(4096)]
    quads = [" ".join(f"{rng.randrange(256):016x}" for _ in range(4)).encode() + b"\n"
             for _ in range(4096)]
    for rows in (nodes, triples, quads):
        rows.extend(rows[:1024])
        rng.shuffle(rows)
    # Same key, distinct payload: --unique must deduplicate by key, not whole row.
    nodes.extend([b"f" * 32 + b" 02\n", b"f" * 32 + b" 01\n"])
    nodes.append(b"e" * 32 + b" " + b"ab" * 65536 + b"\n")
    yield "nodes", b"".join(nodes), (1,), False
    for name, order in (("SPO", (1, 2, 3)), ("POS", (2, 3, 1)), ("OSP", (3, 1, 2))):
        yield name, b"".join(triples), order, True
    for name, order in (("GSPO", (1, 2, 3, 4)), ("GPOS", (1, 3, 4, 2)),
                        ("GOSP", (1, 4, 2, 3)), ("SPOG", (2, 3, 4, 1)),
                        ("POSG", (3, 4, 2, 1)), ("OSPG", (4, 2, 3, 1))):
        yield name, b"".join(quads), order, True
    yield "empty-nodes", b"", (1,), False
    yield "empty-index", b"", (1, 2, 3), True


def compare(candidate, reference, root, gzip_program, compress_program):
    if "GNU coreutils" not in reference["output"]:
        raise ValueError("The reference must be GNU sort")
    env = dict(os.environ, LC_ALL="C")
    results = []
    for name, data, keys, compressed in fixtures():
        source = root / "input.txt"
        source.write_bytes(data)
        # Check the production percentage option as well as a small spill budget.
        for budget in ("64K", "50%"):
            for mode in ("stdin", "file"):
                outputs = []
                # The reference always uses gzip, so a faulty candidate compressor cannot
                # corrupt both outputs alike.
                for tool, compress in ((reference, gzip_program), (candidate, compress_program)):
                    flags = [f"--temporary-directory={root}", f"--buffer-size={budget}",
                             "--parallel=2", "--unique"]
                    if compressed:
                        flags.append(f"--compress-program={compress}")
                    flags.extend(f"--key={k},{k}" for k in keys)
                    if mode == "file":
                        flags.append(str(source))
                    result = subprocess.run([tool["executable"], *flags],
                                            input=data if mode == "stdin" else b"",
                                            capture_output=True, env=env, timeout=60)
                    if result.returncode:
                        raise ValueError(f"{tool['executable']} failed {name}/{budget}/{mode}: "
                                         + result.stderr.decode(errors="replace"))
                    outputs.append(result.stdout)
                if outputs[0] != outputs[1]:
                    raise ValueError(f"Output differs from GNU sort: {name}/{budget}/{mode}")
                results.append({"fixture": name, "buffer_size": budget, "mode": mode,
                                "input_bytes": len(data), "output_bytes": len(outputs[1])})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sort", required=True, help="Candidate executable, e.g. uu-sort or gsort")
    parser.add_argument("--reference-sort", help="GNU executable; defaults to gsort, then sort")
    parser.add_argument("--compress-program", help="Temporary-file compressor for index cases "
                        "(default: gzip, as xloader uses), e.g. pigz")
    parser.add_argument("--output", required=True, type=Path, help="New JSON report path")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Report already exists; choose a new output path")
    report = {"status": "failed"}
    try:
        candidate = sorter(args.sort)
        reference = sorter(args.reference_sort)
        gzip_program = "/bin/gzip" if Path("/bin/gzip").is_file() else "/usr/bin/gzip"
        compress = compressor(args.compress_program or gzip_program)
        report.update(candidate=candidate, reference=reference, compress_program=compress)
        with tempfile.TemporaryDirectory(prefix="jena-sort-check-") as temporary:
            report["checks"] = compare(candidate, reference, Path(temporary), gzip_program,
                                       compress["executable"])
        report["status"] = "passed"
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as out:
        json.dump(report, out, indent=2)
        out.write("\n")
    print(f"{report['status']}: {args.output}")
    if "error" in report:
        print(report["error"])
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
