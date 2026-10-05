<!-- Licensed under the terms of http://www.apache.org/licenses/LICENSE-2.0 -->

# TDB2 xloader benchmarks

Use the official Wikidata lexemes N-Triples dump for development comparisons and
the truthy N-Triples dump for the large-scale report. Run both against the unchanged
loader before evaluating improvements. This harness does not modify xloader.
Requires Python 3.9+, Bash 4+, GNU sort, Java, gzip, jq and `/usr/bin/time`.
GNU sort is the default: the harness selects `gsort` if available, otherwise
`sort`, and verifies its GNU identity. Use `--sort` to select an explicit executable.
Only that sorter is exposed as `sort` through a per-run wrapper; other utilities
keep their existing PATH selection. No xloader production changes are needed.

## GNU sort and optional Rust sort

On macOS, GNU sort comes from `coreutils`. The Rust candidate here is **uutils
sort**, a separate project from `acefsm/rust_sort`:

```sh
brew install coreutils bash jq
# Optional candidate:
brew install uutils-coreutils
gsort --version
uu-sort --version
```

Homebrew installs uutils commands with a `uu-` prefix. Do not prepend the whole
uutils command directory to PATH for these comparisons: select only `uu-sort`.
See the [Homebrew formula](https://formulae.brew.sh/formula/uutils-coreutils).

Linux packages are available, but distribution versions can differ substantially:

| Distribution | Rust package installation |
| --- | --- |
| Debian / Ubuntu | `sudo apt install rust-coreutils` |
| Fedora | `sudo dnf install uutils-coreutils` |
| Arch | `sudo pacman -S uutils-coreutils` |

Locate the installed sort executable using the package's file list and supply its
full path with `--sort`. Names and locations vary; do not replace the system's
coreutils for a benchmark. Pin matching versions when comparing machines. See
the [upstream installation guide](https://uutils.org/coreutils/docs/installation.html).

Before attempting a Rust import, compare its output with GNU sort (no Java needed):

```sh
python3 jena-benchmarks/xloader/check_sort.py --sort gsort \
  --reference-sort gsort --output "$JENA_BENCHMARK_HOME/checks/gnu.json"
python3 jena-benchmarks/xloader/check_sort.py --sort uu-sort \
  --reference-sort gsort --output "$JENA_BENCHMARK_HOME/checks/uutils.json"
```

On Linux, substitute the verified GNU sort path for `gsort`. Reports are never
overwritten. These 48 comparisons cover node-key uniqueness, all nine tuple index
orders, duplicates, a long node row, empty input, stdin and file input, the 50%
memory option, and a 64K budget intended to exercise spilling. Index cases retain
xloader's external gzip compression option. These are synthetic output checks,
not performance measurements or proof of compatibility with every dataset; they
do not measure whether a sorter actually respects its requested memory budget.
A failed comparison should be investigated before running a large import.

## Storage and local build

Set these variables in your shell; no particular mount path is assumed:

```sh
export JENA_BENCHMARK_HOME=/path/on/your/external/drive/jena-benchmark
mkdir -p "$JENA_BENCHMARK_HOME"
```

For Java, use the same JDK selected for the successful IntelliJ Maven runs:

```sh
export JAVA_HOME=/path/to/that/jdk/Contents/Home
export JAVA="$JAVA_HOME/bin/java"
"$JAVA" -version
```

The harness resolves `JAVA`, then `JAVA_HOME/bin/java`, then `java` on PATH, and
passes the selected executable to both xloader and the verification query.

Check that the intended drive is mounted before creating this directory. The
harness requires it to exist and rejects whitespace and glob characters because
the existing xloader launcher does not quote all path expansions.

Build Jena from the repository root (the current POM requires Java 21 or later):

```sh
mvn -DskipTests -Dmaven.javadoc.skip=true clean install
```

This compiles tests but skips running them. Unpack the resulting
`apache-jena/target/apache-jena-<version>.tar.gz` into a dedicated directory under
`$JENA_BENCHMARK_HOME/builds/`, and set `JENA_HOME` to the unpacked distribution
(the directory containing `bin/` and `lib/`). Preserve this baseline installation
when building candidates. A source checkout itself is not an installed distribution.

The run records the supplied revision and hashes every installed JAR and the
xloader launcher. A revision label alone does not capture uncommitted source edits;
retain a diff with your results when applicable.

## Download and pin the data

Use **dated** `.nt.gz` files from
<https://dumps.wikimedia.org/wikidatawiki/entities/>, never a moving `latest` URL:
a resumed download or a later comparison must refer to the same file. The dated
lexemes and truthy files can live in different snapshot directories; the truthy
file dated 20260926 is in directory `20260923/`. The snapshots used so far:

| Dataset | File | Bytes | SHA-1 (published by Wikimedia) |
| --- | --- | --- | --- |
| lexemes | `20260925/wikidata-20260925-lexemes-BETA.nt.gz` | 1,522,459,371 | `08eab4f2b0aec76e58318e890011668ef60df518` |
| truthy | `20260923/wikidata-20260926-truthy-BETA.nt.gz` | 71,614,129,466 | `201d07ca877ac8ce07a73a936e52e2bd14fb9595` |

The checksums are in `wikidata-<date>-sha1sums.txt` next to each file.
dumps.wikimedia.org limits the speed per connection (about 0.3 MB/s measured from
Norway). The mirror of the Academic Computer Club in Umeå carries the same files
under `other/wikibase/wikidatawiki/` and gave about 16 MB/s; the list of mirrors is
at <https://meta.wikimedia.org/wiki/Mirroring_Wikimedia_project_XML_dumps>. The
SHA-1 check below makes the source irrelevant, so record the canonical Wikimedia URL
with `prepare` either way.

Download once, outside the timed runs, under `caffeinate -i` on macOS so the Mac
stays awake. `-C -` continues an interrupted download:

```sh
mkdir -p "$JENA_BENCHMARK_HOME/downloads" && cd "$JENA_BENCHMARK_HOME/downloads"
MIRROR=https://ftp.acc.umu.se/mirror/wikimedia.org/other/wikibase/wikidatawiki

caffeinate -i curl -fL -C - --retry 5 --retry-delay 30 -o wikidata-20260925-lexemes-BETA.nt.gz.part "$MIRROR/20260925/wikidata-20260925-lexemes-BETA.nt.gz"
echo "08eab4f2b0aec76e58318e890011668ef60df518  wikidata-20260925-lexemes-BETA.nt.gz.part" | shasum -a 1 -c - && mv wikidata-20260925-lexemes-BETA.nt.gz.part wikidata-20260925-lexemes-BETA.nt.gz

caffeinate -i curl -fL -C - --retry 5 --retry-delay 30 -o wikidata-20260926-truthy-BETA.nt.gz.part "$MIRROR/20260923/wikidata-20260926-truthy-BETA.nt.gz"
echo "201d07ca877ac8ce07a73a936e52e2bd14fb9595  wikidata-20260926-truthy-BETA.nt.gz.part" | shasum -a 1 -c - && mv wikidata-20260926-truthy-BETA.nt.gz.part wikidata-20260926-truthy-BETA.nt.gz
```

On Linux, drop `caffeinate -i` and use `sha1sum -c -` instead of `shasum -a 1 -c -`.
The file is renamed only when the checksum matches; if it doesn't, delete the `.part`
file and download again. Then pin each file, from the repository root:

```sh
python3 jena-benchmarks/xloader/benchmark.py prepare lexemes --input "$JENA_BENCHMARK_HOME/downloads/wikidata-20260925-lexemes-BETA.nt.gz" --source https://dumps.wikimedia.org/wikidatawiki/entities/20260925/wikidata-20260925-lexemes-BETA.nt.gz
python3 jena-benchmarks/xloader/benchmark.py prepare truthy --input "$JENA_BENCHMARK_HOME/downloads/wikidata-20260926-truthy-BETA.nt.gz" --source https://dumps.wikimedia.org/wikidatawiki/entities/20260923/wikidata-20260926-truthy-BETA.nt.gz
```

Do not overwrite a pinned download. Preparation records the SHA-256 and the
compressed size (about 1.8 GB/s, under a minute for truthy). `--count` also
decompresses the whole file, which checks the gzip, and records the uncompressed
size and the number of statement lines; this is single-threaded Python and takes
hours for truthy. The SHA-1 check above already confirms the download. `--sha256` optionally checks an independently obtained expected hash;
a computed hash by itself establishes identity, not publisher authenticity.

Each dataset can be pinned once per benchmark home. Input files remain in place;
the harness does not copy, download or delete them.

### A truthy prefix

Before a full truthy load, a prefix shows how ingest and the sorts behave once the
node table no longer fits in memory, and how much space the database and tmp need per
triple. Dataset names are free-form (lower-case letters, digits, `.`, `_`, `-`). The
first billion lines, recompressed fast (reads the whole prefix once, single-threaded
decompression):

```sh
caffeinate -i sh -c 'cd "$JENA_BENCHMARK_HOME/downloads" && pigz -dc wikidata-20260926-truthy-BETA.nt.gz | head -n 1000000000 | pigz -1 > wikidata-20260926-truthy-BETA-1b.nt.gz'
python3 jena-benchmarks/xloader/benchmark.py prepare truthy-1b --input "$JENA_BENCHMARK_HOME/downloads/wikidata-20260926-truthy-BETA-1b.nt.gz" --source "first 1,000,000,000 lines of https://dumps.wikimedia.org/wikidatawiki/entities/20260923/wikidata-20260926-truthy-BETA.nt.gz"
```

Then run it like lexemes, with `truthy-1b` as the dataset. `--tmp-home DIR` puts the
workfiles and sort spills on another volume; the database stays in the run directory
under `JENA_BENCHMARK_HOME`.

## Run the unchanged baseline

From the repository root, with `JENA_HOME` pointing to your baseline build:

```sh
python3 jena-benchmarks/xloader/benchmark.py run lexemes \
  --label baseline --revision "$(git rev-parse HEAD)" \
  --cache-note 'Normal filesystem cache; input checksum read immediately before load; machine otherwise idle'
```

Repeat three times. Each invocation creates a unique directory, so previous
databases, workfiles and results are preserved. Run `truthy` with the same settings
once to establish runtime and space requirements, then choose a practical repeat
count. Defaults match the launcher: `--threads 2` and `--jvm-args=-Xmx4G`.
Record tuned configurations separately from the default baseline.

Example, the unchanged baseline with 8 sort threads (`--threads` existed before the
xloader changes; it becomes sort's `--parallel`), from the repository root with
`JENA_BENCHMARK_HOME` exported:

```sh
caffeinate -i env JENA_HOME="$JENA_BENCHMARK_HOME/build/baseline" python3 jena-benchmarks/xloader/benchmark.py run lexemes --label baseline-t8 --threads 8 --revision 509136074c --cache-note 'baseline, --threads 8, GNU sort, gzip; caffeinate -i; mains power'
```

On macOS, run long loads under `caffeinate -i` (it holds a no-idle-sleep assertion
until the command exits) and keep the lid open. A load that sleeps keeps running
only during brief DarkWakes: xloader's stage times use the wall clock and become
meaningless, while `elapsed_seconds` in `run.json` uses a monotonic clock that stops
during sleep. If the two disagree, the run slept. `caffeinate -s` additionally
prevents system sleep, but only on mains power.

The fastest lexemes configuration so far (8:15 against 25:23 for `baseline-t8`; see
`xloader-plan.md`) uses the newer launcher options, all off by default, passed with
`--xloader-arg`: `--parallel-indexes` (build SPO, POS and OSP at once; a percentage
`--sort-buffer` is shared between the sorts), `--parse-threads=6` (parse N-Triples and
N-Quads on six threads in the node table and ingest steps). Parallel parsing needs a
larger heap and a throughput collector; about a quarter of RAM, here 8G of 32G, since
`JVM_ARGS` applies to every step:

```sh
caffeinate -i env JAVA=/path/to/jdk-25/bin/java JENA_HOME="$JENA_BENCHMARK_HOME/build/final" python3 jena-benchmarks/xloader/benchmark.py run lexemes --label uusort1024M-pigz1-t8-parallel-pt6-j25par8g --threads 8 --sort "$JENA_BENCHMARK_HOME/tools/uu-sort-xloader" --sort-compress pigz --sort-compress-args=-1 --xloader-arg=--parallel-indexes --xloader-arg=--parse-threads=6 --jvm-args='-Xmx8G -XX:+UseParallelGC -XX:+UseCompactObjectHeaders' --revision '<commit> + uncommitted' --cache-note 'best configuration; caffeinate -i; mains power'
```

On Java 21, drop `-XX:+UseCompactObjectHeaders` (Java 25 only; about 4% of ingest).
With GNU sort instead of uu-sort, lower `--sort-buffer` (for example `--xloader-arg=--sort-buffer=35%`),
since the JVM heap is also reserved while the sorts run. Run labels name the settings
that differ from the default, in the order sorter, compressor, threads, index mode,
parse threads, JVM.

For the initial sorter comparison, keep `JENA_HOME`, its revision, the dataset,
thread count and JVM settings identical; change only the sorter and label:

```sh
python3 jena-benchmarks/xloader/benchmark.py run lexemes \
  --sort gsort --label gnu-default --revision "$(git rev-parse HEAD)" \
  --cache-note 'Normal filesystem cache; machine otherwise idle'
python3 jena-benchmarks/xloader/benchmark.py run lexemes \
  --sort uu-sort --label uutils-default --revision "$(git rev-parse HEAD)" \
  --cache-note 'Normal filesystem cache; machine otherwise idle'
```

Run GNU first, inspect the results, then run the candidate after its compatibility
check passes. A cleanup build can be the fixed reference for a sorter comparison;
it is not the pre-cleanup baseline used to measure the cleanup change itself.
Each run checks a small sorted fixture with xloader options before loading and
records the sorter executable path, resolved target, SHA-256 and version, the
wrapper checksum, and relevant Java environment options in `run.json`.

### Sort temporary-file compressor

For index builds, xloader passes `--compress-program=/usr/bin/gzip` (Apple's gzip on
macOS) to sort. Its node-table sort does not compress. `--sort-compress` replaces
that program for the index sorts without changing the Jena build, so the unchanged
baseline distribution can be measured with each compressor:

```sh
python3 jena-benchmarks/xloader/check_sort.py --sort gsort --reference-sort gsort \
  --compress-program pigz --output "$JENA_BENCHMARK_HOME/checks/gnu-pigz.json"
python3 jena-benchmarks/xloader/benchmark.py run lexemes \
  --sort-compress pigz --label gnu-pigz --revision "$(git rev-parse HEAD)" \
  --cache-note 'Normal filesystem cache; machine otherwise idle'
```

`--sort-compress-args='-1 -p 4'` passes arguments to the compressor as the
environment variable `SORT_COMPRESS_ARGS` (split at spaces; use the `=` form so
values starting with `-` are not read as options). They are applied exactly once
for any build: launchers that support the variable apply them through their
`xloader-sort-compress` wrapper, and the harness applies them itself to any other
program, including a `--sort-compress` replacement and an older launcher's gzip. The
arguments are checked with the same round trip before loading and recorded as
`sort_compress_args` in `run.json`. Without the option the harness removes any
`SORT_COMPRESS_ARGS` set in the calling shell, so every run's arguments are recorded.

In `check_sort.py` the GNU reference always uses gzip, so a faulty candidate
compressor cannot corrupt both outputs in the same way. Before a load, the harness
also checks that the compressor restores a sample exactly with `-d`, and records
its path, version and SHA-256. Sort calls the program with no arguments to
compress and with `-d` to decompress; a wrapper script can add options such as a
compression level.

The sort wrapper routes every compressor call through `sort-compress`, including
the default gzip, and `run.json` records the count as `sort_compress_calls`. Sort
only compresses the temporary files it spills. **Zero calls means no index sort
spilled, so the compressor cannot have affected that run.** With
`--buffer-size=50%`, lexemes may not spill; check this before comparing timings.

### Temporary files on another volume

By default the database and xloader's workfiles share the run directory on
`JENA_BENCHMARK_HOME`. `--tmp-home` moves the workfiles to another existing
directory, such as the Mac's internal disk, while the database stays on the drive:

```sh
mkdir -p ~/jena-xloader-tmp
python3 jena-benchmarks/xloader/benchmark.py run lexemes \
  --tmp-home ~/jena-xloader-tmp --label gnu-internal-tmp \
  --revision "$(git rev-parse HEAD)" \
  --cache-note 'Normal filesystem cache; machine otherwise idle'
```

The workfiles are more than sort spills: xloader's `--tmpdir` also receives the
compressed `triples.tmp`/`quads.tmp` intermediates, which every index build rereads,
and `load.json`. Node-table sort spills are **not** compressed. Measure lexemes
first and do not assume truthy fits on the internal disk.

The harness samples free space on both volumes at start and every 5 seconds, and
records the lowest values as `lowest_free_bytes` in `run.json`. The difference from
the starting free space approximates peak usage, including any other activity on
that volume. If either volume drops below `--min-free-gb` (default 20), the harness
stops the whole loader process group and records `stopped_low_disk_space`; it also
refuses to start below that level. Samples 5 seconds apart can miss short peaks.

Workfiles are retained, like everything else. They live under
`<tmp-home>/runs/<dataset>/<run-id>/tmp/`, and `run.json` records the path;
delete them yourself once a run has been inspected. Temporary-file placement is a
configuration variable: label such runs separately, and keep one placement for the
whole baseline series.

The harness always uses the installed distribution and full standard index set;
ambient `JENA_CP`, `CLASSPATH`, `TRIPLES_IDX` and `QUADS_IDX` are removed for the run.

```text
JENA_BENCHMARK_HOME/
  downloads/                    retained input files
  builds/                       your unpacked baseline/candidate distributions
  inputs/{lexemes,truthy}.json   pinned input manifests
  runs/<dataset>/<unique-id>/
    run.json                    metadata, timings, exit codes, retained disk usage
    command.txt                 loader command (environment is recorded separately)
    loader.log                  stage progress and platform time resource summary
    verification.log            separate database reopen and COUNT(*) result
    count.rq
    tools/sort                  wrapper selecting only the chosen sorter
    sort-compress               compressor wrapper (not on PATH)
    sort-compress.log           one line per compressor call
    database/
    tmp/                        xloader workfiles unless --tmp-home is given
<tmp-home>/runs/<dataset>/<unique-id>/tmp/   workfiles with --tmp-home
```

Watch `loader.log` with `tail -f` during long runs. Download, input checksum reading,
installation hashing, database verification and final disk accounting are excluded
from the measured import elapsed time. The checksum scan affects filesystem cache;
these are **not cold-cache benchmarks**. Keep the same protocol for comparisons.

## Comparing with tdb2.tdbloader

The harness runs `tdb2.xloader` only. For reference, `tdb2.tdbloader` (modes `basic`,
`sequential`, `phased` (default), `parallel`, and `light`, which is in the command's help
but not in the documentation) on the lexemes, out of the box, on the same machine:
`parallel` 44:49 and `phased` 47:50, both with a 35 GB database, against 25:23 for the
unchanged `tdb2.xloader` and 8:15 for this branch's (20 GB databases); details in
`xloader-plan.md`. Run one mode by hand and count afterwards:

```sh
caffeinate -i /usr/bin/time -l "$JENA_BENCHMARK_HOME/build/final/bin/tdb2.tdbloader" --loader=phased --loc /path/to/new/database "$JENA_BENCHMARK_HOME/downloads/lexemes.nt.gz"
"$JENA_BENCHMARK_HOME/build/final/bin/tdb2.tdbquery" --loc /path/to/new/database 'SELECT (COUNT(*) AS ?n) { ?s ?p ?o }'
```

## Compare runs

`compare.py` prints one table row per run of a dataset, read from `run.json`,
`loader.log` and `verification.log`. It is read-only and works after the databases
have been deleted.

```sh
python3 jena-benchmarks/xloader/compare.py lexemes --reference baseline
```

Columns: label, build folder, sorter and compressor, threads, the node-table, ingest
and per-index times from xloader's log, xloader's wall-clock total, the harness's
monotonic `elapsed` time, the change against the `--reference` run, triple and term
counts, compressor calls and maximum RSS. The last column flags runs that slept
(wall clock more than 30 s above `elapsed`; not compared against the reference), that
did not finish (`running`, `interrupted_or_error`, …), or whose triple or term count
differs from the most common count for the dataset. `--label TEXT` (repeatable)
and `--counted` filter rows; `--format csv|tsv` and `--output FILE` help with
spreadsheets and reports. Stage times parse xloader's numbers in both `nb`/`de`
(`464,373`, `229 392 099`) and `en` (`464.373`, `9,598.112`) formats.
Tests: `python3 -m unittest test_compare` in this directory.

## Interpretation and report

Compare total elapsed time and xloader's node-table, ingestion and individual index
stage timings. Preserve all repetitions and report their spread alongside a median.
The separate count query checks that the database reopens. Compare its value across
baseline and candidate runs: status `counted` means the query succeeded, not that
dataset equivalence has been proved. Statement-line counts can exceed stored triple
counts because RDF graphs eliminate duplicates. Add fixed representative query
results before making correctness claims in the final report.

Record host RAM, CPU model, external-drive model, connection, filesystem, placement
of files and competing activity with the report. The harness captures platform,
CPU count, filesystem capacity and tool versions. Without `--tmp-home`, all run data
and sort temporary files share the benchmark home, so their shared I/O contention
is part of the test.

`time -l` (macOS) and `time -v` (Linux) have platform-specific accounting. Their
maximum RSS must not be described as simultaneous peak memory of the entire Java,
sort and gzip process tree. Final `du` output measures retained space, not peak
temporary sort space; see `lowest_free_bytes` for a sampled estimate. This harness
does not sample file descriptors or aggregate process-tree memory; collect those separately for
resource-leak or peak-resource claims. Both input datasets exercise triple indexes,
not named-graph quad indexes.

No automatic cleanup is performed. Budget space for the inputs, each retained
database and its intermediates; compressed download size is not a disk-space
estimate for an import. Failed runs are retained for inspection.

## Harness checks

```sh
python3 jena-benchmarks/xloader/test_benchmark.py
```

These use temporary fixtures and stub executables, not a real Jena import. On
macOS, restricted sandboxes can block the sysctl used by `/usr/bin/time -l`;
run the harness in a normal terminal with access to resource accounting.
