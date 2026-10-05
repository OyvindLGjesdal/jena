#!/usr/bin/env python3
# Licensed under the terms of http://www.apache.org/licenses/LICENSE-2.0
"""Compare benchmark.py runs: one table row per run, with stage times from loader.log.

Reads JENA_BENCHMARK_HOME/runs/<dataset>/<run-id>/{run.json,loader.log,verification.log}.
Read-only; databases may already have been deleted.
"""
import argparse
import collections
import csv
import io
import json
import os
from pathlib import Path
import re
import sys

# xloader prints numbers in the JVM's locale: "464,373" and "229 392 099" (nb),
# "464.373" and "9,598.112" (en). Spaces may be U+00A0 or U+202F.
NUMBER = r"[0-9][0-9\s  .,]*"
SECONDS = re.compile(r"(" + NUMBER + r") seconds")
STAGES = [
    ("parse", re.compile(r":: == Parse \(nodes\): (" + NUMBER + r") seconds")),
    ("terms", re.compile(r":: == Index terms: (" + NUMBER + r") seconds")),
    ("node_table", re.compile(r":: ==-==-== NodeTable : (" + NUMBER + r") seconds")),
    ("ingest", re.compile(r":: ==-==-== Total: " + NUMBER + r" tuples : (" + NUMBER + r") seconds")),
]
INDEX = re.compile(r":: ==-==-== Index (\w+) : (" + NUMBER + r") seconds")
TERM_COUNT = re.compile(r":: == Index terms: " + NUMBER + r" seconds : (" + NUMBER + r") indexed RDF terms")
OVERALL = re.compile(r"\bOverall\s+(" + NUMBER + r") seconds")
REAL = re.compile(r"^\s*([0-9.]+) real\b", re.MULTILINE)
MAX_RSS = re.compile(r"^\s*([0-9]+)\s+maximum resident set size", re.MULTILINE)
COUNT = re.compile(r"^\|\s*([0-9]+)\s*\|\s*$", re.MULTILINE)
TRIPLE_INDEXES = ["SPO", "POS", "OSP"]
QUAD_INDEXES = ["GSPO", "GPOS", "GOSP", "SPOG", "POSG", "OSPG"]
# More than this difference between wall-clock and monotonic time means the run slept.
SLEEP_TOLERANCE = 30.0


def number(text):
    """Parse a number in either locale; None if it isn't one."""
    s = re.sub(r"[\s  ]", "", text).rstrip(".,")
    if not s:
        return None
    if "." in s and "," in s:
        decimal = "." if s.rfind(".") > s.rfind(",") else ","
        s = s.replace("," if decimal == "." else ".", "").replace(decimal, ".")
    elif "," in s:
        # One comma followed by 1-3 digits is a decimal comma (xloader always prints
        # fractional seconds); several commas are thousands separators.
        s = s.replace(",", ".") if re.fullmatch(r"[0-9]+,[0-9]{1,3}", s) else s.replace(",", "")
    try:
        return float(s)
    except ValueError:
        return None


def parse_loader_log(text):
    """Stage times (seconds), index times, term count, overall and max RSS from loader.log."""
    result = {"indexes": {}}
    for name, pattern in STAGES:
        match = pattern.search(text)
        if match:
            result[name] = number(match.group(1))
    for match in INDEX.finditer(text):
        result["indexes"][match.group(1)] = number(match.group(2))
    match = TERM_COUNT.search(text)
    if match:
        result["terms"] = int(number(match.group(1)))
    match = OVERALL.search(text)
    if match:
        result["overall"] = number(match.group(1))
    match = REAL.search(text)
    if match:
        result["real"] = float(match.group(1))
    match = MAX_RSS.search(text)
    if match:
        result["max_rss"] = int(match.group(1))
    return result


def first_line(value):
    return value.strip().splitlines()[0] if isinstance(value, str) and value.strip() else ""


def sorter_name(meta):
    sort = meta.get("sort") or {}
    version = first_line(sort.get("output", ""))
    executable = Path(sort.get("executable", "")).name
    if "GNU coreutils" in version:
        name = "GNU " + version.split()[-1]
    elif "uutils" in version:
        name = "uu " + version.split()[-1]
    else:
        name = version or executable or "?"
    if executable and executable not in ("sort", "gsort", "uu-sort") and not name.startswith(executable):
        name += f" ({executable})"
    return name


def compressor_name(meta):
    compress = meta.get("sort_compress")
    if isinstance(compress, dict):
        return Path(compress.get("executable", "?")).name
    return "gzip"


def load_run(directory):
    """One run as a flat dict; None if the directory has no run.json."""
    meta_path = directory / "run.json"
    if not meta_path.is_file():
        return None
    meta = json.loads(meta_path.read_text())
    log_path = directory / "loader.log"
    log = parse_loader_log(log_path.read_text(errors="replace")) if log_path.is_file() else {"indexes": {}}
    verification = directory / "verification.log"
    count = None
    if verification.is_file():
        match = COUNT.search(verification.read_text(errors="replace"))
        if match:
            count = int(match.group(1))
    calls = meta.get("sort_compress_calls") or {}
    elapsed = meta.get("elapsed_seconds")
    wall = log.get("real") or log.get("overall")
    flags = []
    if elapsed is not None and wall is not None and wall - elapsed > SLEEP_TOLERANCE:
        flags.append("slept")
    if meta.get("status") != "counted":
        flags.append(meta.get("status", "unknown"))
    return {
        "run": directory.name,
        "started": meta.get("started_utc", ""),
        "label": meta.get("label", ""),
        "build": Path(meta.get("jena_home", "")).name,
        "sort": sorter_name(meta),
        "compressor": compressor_name(meta),
        "threads": meta.get("threads"),
        "jvm_args": meta.get("jvm_args", ""),
        "status": meta.get("status", ""),
        "node_table": log.get("node_table"),
        "ingest": log.get("ingest"),
        "indexes": log["indexes"],
        "total": log.get("overall"),
        "elapsed": elapsed,
        "wall": wall,
        "triples": count,
        "terms": log.get("terms"),
        "compress_calls": calls.get("compress") if calls else None,
        "max_rss": log.get("max_rss"),
        "flags": flags,
    }


def find_runs(home, dataset):
    root = home / "runs" / dataset
    if not root.is_dir():
        raise ValueError(f"No runs for dataset {dataset!r} under {home}")
    runs = [run for run in (load_run(d) for d in sorted(root.iterdir()) if d.is_dir()) if run]
    return sorted(runs, key=lambda run: run["started"])


def check_counts(runs):
    """Flag runs whose triple or term counts differ from the most common value."""
    for key in ("triples", "terms"):
        values = collections.Counter(run[key] for run in runs if run[key] is not None)
        if len(values) > 1:
            expected = values.most_common(1)[0][0]
            for run in runs:
                if run[key] is not None and run[key] != expected:
                    run["flags"].append(f"{key} {run[key]:,} != {expected:,}")


def hms(seconds):
    if seconds is None:
        return ""
    seconds = round(seconds)
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


def rows(runs, reference):
    indexes = [name for name in TRIPLE_INDEXES + QUAD_INDEXES
               if any(name in run["indexes"] for run in runs)]
    # The first run with that label and no flags (not slept, finished, expected counts).
    base = next((run for run in runs if run["label"] == reference and not run["flags"]), None) if reference else None
    header = ["run", "label", "build", "sort", "compressor", "threads", "node table",
              "ingest", *indexes, "total", "elapsed"]
    if base:
        header.append(f"vs {reference}")
    header += ["triples", "terms", "compress calls", "max RSS", "flags"]
    table = [header]
    for run in runs:
        row = [run["run"], run["label"], run["build"], run["sort"], run["compressor"],
               str(run["threads"] or ""), hms(run["node_table"]), hms(run["ingest"]),
               *(hms(run["indexes"].get(name)) for name in indexes),
               hms(run["total"]), hms(run["elapsed"])]
        if base:
            if base["elapsed"] and run["elapsed"] and "slept" not in run["flags"]:
                row.append(f"{(run['elapsed'] - base['elapsed']) / base['elapsed']:+.0%}")
            else:
                row.append("")
        row += [f"{run['triples']:,}" if run["triples"] is not None else "",
                f"{run['terms']:,}" if run["terms"] is not None else "",
                str(run["compress_calls"]) if run["compress_calls"] is not None else "",
                f"{run['max_rss'] / 1e9:.1f} GB" if run["max_rss"] else "",
                "; ".join(run["flags"])]
        table.append(row)
    return table


def render(table, fmt):
    if fmt in ("csv", "tsv"):
        out = io.StringIO()
        csv.writer(out, delimiter="," if fmt == "csv" else "\t", lineterminator="\n").writerows(table)
        return out.getvalue()
    widths = [max(len(row[i]) for row in table) for i in range(len(table[0]))]
    lines = ["| " + " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)) + " |"
             for row in table]
    lines.insert(1, "| " + " | ".join("-" * width for width in widths) + " |")
    return "\n".join(lines) + "\n"


def dataset_name(value):
    """A dataset name such as lexemes, truthy or truthy-1b; used in file names."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", value):
        raise argparse.ArgumentTypeError(f"invalid dataset name {value!r}: use lower-case letters, digits, '.', '_' or '-'")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dataset", nargs="?", default="lexemes", type=dataset_name)
    parser.add_argument("--home", help="Benchmark home; defaults to JENA_BENCHMARK_HOME")
    parser.add_argument("--label", action="append", default=[],
                        help="Only runs whose label contains this text; repeatable")
    parser.add_argument("--counted", action="store_true", help="Only runs with status 'counted'")
    parser.add_argument("--reference", help="Label of the run to compare elapsed time against "
                        "(the first run with that label and no flags)")
    parser.add_argument("--format", choices=["markdown", "csv", "tsv"], default="markdown")
    parser.add_argument("--output", help="Also write the table to this file")
    args = parser.parse_args(argv)
    home = args.home or os.environ.get("JENA_BENCHMARK_HOME")
    if not home:
        parser.error("Set JENA_BENCHMARK_HOME or pass --home")
    runs = find_runs(Path(home).expanduser(), args.dataset)
    check_counts(runs)
    if args.label:
        runs = [run for run in runs if any(text in run["label"] for text in args.label)]
    if args.counted:
        runs = [run for run in runs if run["status"] == "counted"]
    if not runs:
        print("No matching runs.", file=sys.stderr)
        return 1
    text = render(rows(runs, args.reference), args.format)
    sys.stdout.write(text)
    sys.stdout.flush()
    if args.output:
        Path(args.output).write_text(text)
    if args.format == "markdown":
        print("\nTimes as m:ss. 'total' is xloader's wall clock; 'elapsed' is the harness's "
              "monotonic time, which stops while macOS sleeps. Counts are checked against "
              "the most common value across all runs of the dataset.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
