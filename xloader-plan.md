<!-- Licensed under the terms of http://www.apache.org/licenses/LICENSE-2.0 -->

# TDB2 xloader investigation and benchmark plan

Started: 2026-09-29. Updated: 2026-10-07.

Status (2026-10-07): best lexemes load 7:21 (`20261006T073325Z-a355af21`), against
25:23 for `baseline-t8` with main's code; counts identical. Two code reviews of the
branch against main, and their fixes, are in `xloader-review.md` (untracked); the last
build passed the 76 `TS_XLoader` tests. Next: preparing the PRs (see "Immediate next
steps"). The truthy run of 2026-10-04, whose database is on the external SSD, is to be
updated from that disk when it is mounted again.

Status (2026-09-29): stream-closure fix committed
(`b7df3069cf`). Cleanup, `--sort`, `--sort-compress` and the workfile gzip settings
committed together as `7eaccb4124`; TS_XLoader (16) and TS_IO (125) passed in
IntelliJ with GNU sort. Lexemes is pinned. Recorded lexemes imports: baseline 30:42,
current 30:25, current with pigz 28:11 (see "First lexemes runs"). uutils sort needs
a wrapper (fixed 1024M segments); with it, pigz and 8 threads the load took 17:11,
against 22:32 for GNU sort with pigz and 8 threads (see "uutils sort findings").
Parsing improvements are collected, not started (see "Parser speed ideas").
Verified: unchanged Jena 6.2.0 xloader fails on Ubuntu 26.04 LTS because its default
`sort` is uutils (see "Ubuntu's default `sort` breaks unchanged xloader").

## Objective and scope

Establish reproducible performance and correctness baselines for `tdb2.xloader`,
then investigate resource cleanup and alternative external sort implementations.
Use the results to write a report that separates measured improvements from
hypotheses. TDB1 and the ordinary `tdb2.tdbloader` are outside this investigation.

Preserve an unchanged baseline distribution for comparisons. Implementation of
the cleanup changes was authorized before the Wikidata baseline was recorded;
do not substitute the patched build for the original baseline. Build Jena locally from
this checkout and preserve the unpacked baseline distribution for later reruns.
Use an external drive selected through `JENA_BENCHMARK_HOME`; no mount path is
fixed. `JENA_HOME` selects the unpacked distribution being measured.

## Benchmark directory layout

`JENA_BENCHMARK_HOME` is one root directory on the external SSD, e.g.
`xloader-benchmarks/`. Each unpacked Jena distribution gets its own folder under
`builds/`, named after its source, not its role: `<purpose>-<short commit>`, plus
`-dirty` when built from uncommitted changes. Settings chosen by arguments (sorter,
compressor, temporary-file placement, threads, JVM options) are recorded per run in
`run.json` and need no build folder of their own.

```text
xloader-benchmarks/                  # JENA_BENCHMARK_HOME
  builds/
    baseline-5091360/                # before both cleanup commits
    xloader-7eaccb4/                 # cleanup + --sort, --sort-compress, workfile gzip
  downloads/                         # dated dumps, unchanged
  inputs/                            # pinned input manifests
  checks/                            # check_sort.py reports
  runs/                              # created by the harness
```

- The baseline is `509136074c`, the commit before "wrap import in a
  try-with-resources block", so it predates both cleanup changes.
- Unpack with `tar --strip-components=1 -C builds/<name>` so `JENA_HOME` is the
  build folder itself (containing `bin/` and `lib/`).
- A `-dirty` build is not reproducible from its commit alone; keep `source.diff`
  next to it. The JAR hashes in `run.json` identify the exact build either way.
- Run labels combine build and arguments, e.g. `baseline+gnu-gzip` or
  `xloader+gnu-pigz+internal-tmp`, so each label is meaningful by itself.
- Names must avoid whitespace and `* ? [ ]`, which the harness rejects.
- Role aliases such as `builds/candidate` may be symlinks; the harness resolves
  `JENA_HOME`, so `run.json` records the real folder.
- Workfiles from `--tmp-home` runs live outside this root, under
  `<tmp-home>/runs/<dataset>/<run-id>/tmp/`.

## Benchmark root as set up (2026-09-29)

- Root: `/Users/oyvindlgjesdal/xloader-benchmark` on the **internal** disk
  (`/System/Volumes/Data`, 122 GiB free of 926 GiB). Folders so far: `build/`
  (not `builds/`) and `downloads/`.
- `build/baseline`: an existing 6.3.0-SNAPSHOT distribution. Its jena-tdb2 JAR has
  no `SortProcess` and `ProcBuildIndexX.class` is dated 2026-07-27 15:26, so it
  predates both xloader changes. The manifest records no commit (built with JDK 25).
  No jena-tdb2/jena-db commits reached `509136074c` after that date, so its xloader
  code matches `509136074c`; five riot/base/core commits in that range differ.
  It also contains a stray partial Chrome download (`Ikke bekreftet 598141.crdownload`)
  and an empty `downloads/` folder.
- `downloads/lexemes.nt.gz`, 1,522,459,371 bytes, last written 16:27;
  `gzip -t` passes. Renamed from `.part` and pinned with `prepare` at 20:45:
  `inputs/lexemes.json`, SHA-256 `83573937…d0db3c`, 32,972,420,387 bytes
  uncompressed, 229,392,099 statement lines. Source identified afterwards (the
  manifest still says "URL not recorded"): its SHA-1 `08eab4f2b0aec76e58318e890011668ef60df518`
  matches the published checksum of
  `https://dumps.wikimedia.org/wikidatawiki/entities/20260925/wikidata-20260925-lexemes-BETA.nt.gz`
  (1,522,459,371 bytes, 25-Sep-2026 23:35), which `latest-lexemes.nt.gz` pointed to
  on 2026-09-29.
- Truthy candidate (not downloaded): `https://dumps.wikimedia.org/wikidatawiki/entities/20260923/wikidata-20260926-truthy-BETA.nt.gz`,
  71,614,129,466 bytes, 27-Sep-2026 02:38 UTC; SHA-1
  `201d07ca877ac8ce07a73a936e52e2bd14fb9595`, MD5 `deac935c48b351c72d94dd4761f0518f`
  (from `wikidata-20260926-sha1sums.txt`/`-md5sums.txt` in the same directory). Note
  the 20260926 file lives in directory `20260923/`. Same size as `latest-truthy.nt.gz`
  at the time.
- `build/current`: `apache-jena-6.3.0-SNAPSHOT.tar.gz` from a full `clean package`
  (BUILD SUCCESS, 20:18) of `7eaccb4124` plus the uncommitted `IO.gzipOutput`
  change (the default path is literally `new GZIPOutputStream(out)`). Its launcher
  has `--sort-compress` and the workfile gzip options; the baseline's has neither.
  No `REVISION` file was written; the runs record the revision via `--revision`.
- The external SSD is not mounted, so database and temporary files are both on the
  internal disk for the first runs. Machine: 12 cores (8 performance), 32 GiB RAM.
- The harness runs use Corretto 21.0.12 (HotSpot) from PATH; the IntelliJ build
  used Semeru 25 (OpenJ9). Keep Corretto for the matrix.
- Each retained run keeps about 21.4 GB (database 20 GB, `tmp/triples.tmp.gz`
  1.4 GB). Free space after two runs: 79 GB, room for about two more runs with the
  20 GB reserve.

## Building the distributions

Two builds are needed now. The earlier plan for separate `cleanup-…` and
`sort-option-…-dirty` builds is obsolete: those changes are one commit.

| Build folder | Commit | Contains |
| --- | --- | --- |
| `baseline-5091360` | `509136074c` | Unchanged xloader: the reference for all comparisons |
| `xloader-7eaccb4` | `7eaccb4124` | Stream fix, cleanup, `--sort`, `--sort-compress`, workfile gzip options with new defaults (level 1, 128 KiB) |

The stream-fix-only commit `b7df3069cf` is not built separately; add it only if
the cleanup's effect needs to be split further.

### 1. Create the benchmark root

```sh
export JENA_BENCHMARK_HOME=/Volumes/<ssd>/xloader-benchmarks   # choose the path
mkdir -p "$JENA_BENCHMARK_HOME"/{builds,downloads,inputs,checks}
```

Check the drive is mounted first. `runs/` is created by the harness. Move the
dated dumps into `downloads/` once complete; `prepare` records their final path.

### 2. Build the baseline in a separate worktree

A worktree keeps this checkout, its staging area and IntelliJ untouched (user runs git):

```sh
git worktree add ../jena-xloader-baseline 509136074c
cd ../jena-xloader-baseline
mvn -o -DskipTests -Dmaven.javadoc.skip=true -pl apache-jena -am clean package
mkdir "$JENA_BENCHMARK_HOME/builds/baseline-5091360"
tar -xzf apache-jena/target/apache-jena-*.tar.gz --strip-components=1 \
  -C "$JENA_BENCHMARK_HOME/builds/baseline-5091360"
```

Use `package`, not `install`: both commits have version `6.3.0-SNAPSHOT`, and
`install` would replace the snapshot JARs in `~/.m2` that IntelliJ's offline
builds of this checkout resolve against. `-pl apache-jena -am` builds only the
distribution and the modules it needs. Drop `-o` if Maven reports missing
artifacts. Remove the worktree afterwards with `git worktree remove`, or keep it
for rebuilding.

### 3. Build the current commit

From this checkout, with a clean tree for the modules in the distribution (the
unrelated `Query.vue` change is not part of it):

```sh
mvn -o -DskipTests -Dmaven.javadoc.skip=true -pl apache-jena -am clean package
mkdir "$JENA_BENCHMARK_HOME/builds/xloader-7eaccb4"
tar -xzf apache-jena/target/apache-jena-*.tar.gz --strip-components=1 \
  -C "$JENA_BENCHMARK_HOME/builds/xloader-7eaccb4"
```

Unpack each tarball immediately after its build: both are named
`apache-jena-6.3.0-SNAPSHOT.tar.gz`, and the next build overwrites the file.

### 4. Check each build

```sh
for b in baseline-5091360 xloader-7eaccb4; do
  h="$JENA_BENCHMARK_HOME/builds/$b"
  echo "== $b"; ls "$h/bin/tdb2.xloader" "$h/lib" | head -3
  "$h/bin/tdb2.xloader" --help | grep -c -- '--sort=' || true
done
```

The baseline must show `0` (no `--sort` option) and `xloader-7eaccb4` must show
`1`; this confirms each folder holds the intended launcher. Pass the matching
commit to the harness as `--revision` (`509136074c` or `7eaccb4124`), not
`git rev-parse HEAD` of whichever checkout happens to be current. `run.json`
also records every JAR's SHA-256.

### Comparing the two builds fairly

`xloader-7eaccb4` changes the workfile gzip defaults, so a plain comparison mixes
the cleanup with the gzip change. To separate them, run it once with the old
settings, `--workfile-gzip-level=-1 --workfile-gzip-buffer=512`, and once with
the defaults.

- [ ] The harness cannot yet pass extra `tdb2.xloader` arguments; add an option
  for that (e.g. repeated `--xloader-arg`) before these runs. The baseline
  launcher rejects unknown options, so only use it with `xloader-7eaccb4`.

## Current state

- [x] Trace the TDB2 xloader shell launcher and Java stages.
- [x] Identify stream and subprocess cleanup candidates through source review.
- [x] Create [benchmark.py](jena-benchmarks/xloader/benchmark.py) and its
  [operating instructions](jena-benchmarks/xloader/README.md).
- [x] Check the harness with four stub-based integration tests: fresh runs,
  input mutation, loader failure, and verification failure.
- [x] User confirmed GNU sort 9.12 is available as `sort` in their terminal.
- [x] Implement stream, dataset, channel and sort-subprocess cleanup changes.
- [x] Add `TS_XLoader` to the TDB2 test suite; validate all 11 dedicated tests
  in IntelliJ with GNU sort, with no failures, errors or skips.
- [x] Choose the benchmark directory layout (above).
- [ ] Select the external-drive path and record machine/storage details.
- [x] Build and preserve the two distributions, as `build/baseline` and
  `build/current` (see "Benchmark root as set up").
- [x] Download the dated dump (complete 2026-09-29).
- [x] Pin lexemes with `benchmark.py prepare` (2026-09-29 20:45).
- [x] First lexemes imports with `build/current`: gzip and pigz (see "First lexemes runs").
- [ ] Capture real lexemes and truthy baselines with the unchanged build.

The harness tests do not establish xloader correctness or performance. Dedicated
xloader tests now cover a small RDF fixture and selected failure paths, as recorded
below. Neither these tests nor the descriptor probe establish performance on
Wikidata or exhaustive failure cleanup.

## Datasets

| Dataset | Purpose | Initial run plan |
| --- | --- | --- |
| Official Wikidata lexemes, `.nt.gz` | Local development, correctness checks, repeatable comparisons | Three unchanged baseline runs, then repeated candidate runs |
| Official Wikidata truthy, `.nt.gz` | Large-scale evaluation and final report | One unchanged baseline first; select repeat count after observing runtime and space |

Choose dated URLs from the [official dump directory](https://dumps.wikimedia.org/wikidatawiki/entities/).
Keep each downloaded file unchanged and record its URL, snapshot date, SHA-256,
compressed/uncompressed sizes, and statement-line count. A moving `latest` URL
must not define a benchmark input. Do not resume a partial download against a
different snapshot.

Truthy contains direct best-ranked statements and omits qualifiers and references;
it is a broad Wikidata dataset, not a scholarly-only subset. See the
[dump documentation](https://www.wikidata.org/wiki/Wikidata:Database_download#RDF_dumps).
Both chosen inputs exercise triple indexes. Add a small named-graph fixture for
quad index correctness before generalizing changes to all of xloader.

## Phase 1: unchanged baseline

Follow the harness README for download, preparation and execution commands.

- [ ] Record CPU model/count, RAM, operating system, drive model, connection,
  filesystem, and where the input, temporary files and database reside.
- [ ] Record Jena revision and any local source diff; retain the installed JAR
  fingerprints. Record Java, Bash, sort and gzip versions and resolved paths.
- [ ] Use default loader settings first: two sort threads and `-Xmx4G`.
- [ ] Run each import into a fresh directory; retain logs and failed runs.
- [ ] Record total elapsed time and node-table, ingestion and individual index
  timings. Exclude download, preparation and post-load verification time.
- [ ] Reopen the database and record distinct triple count and fixed query results.
- [ ] Establish truthy runtime and disk requirements before sorter experiments.
  Cleanup changes preceded this baseline; retain a separate unchanged build.

Keep storage placement and machine activity consistent. The harness checks the
input checksum immediately before loading, which affects the filesystem cache.
Describe this as a normal-cache protocol, not a cold-cache test. Use the same
protocol for baseline and candidate runs; interleave configurations when practical
to reduce effects from temperature, background activity and run order.

Retain the original baseline even if a later GNU-sort tuning experiment is faster.
Compare alternative sorters both to the default and, where practical, to GNU sort
with comparable CPU and memory budgets.

### Measurement limits and harness follow-up

The current harness captures input identity, installed JAR/launcher checksums,
selected tool versions, commands, wall time, platform `time` output, retained disk
usage and a separate count query. Status `counted` means the query succeeded; it
does not prove that two databases contain identical RDF.

Before making resource-usage claims in the report:

- [ ] Record the resolved sorter executable and its checksum, including any
  wrapper, and all relevant JVM environment options.
- [ ] Add opt-in sampling of the process tree: Java, sort workers and compression
  processes, including open file descriptors and aggregate resident memory.
- [ ] Measure peak temporary disk usage and disk activity; final `du` is not peak
  space. Document sampling interval and monitoring overhead. Partly done: the
  harness now samples free space per volume every 5 s (`lowest_free_bytes`);
  disk activity is still unmeasured.
- [ ] Separate lightweight timing runs from more intrusive diagnostic runs.

Platform `time` maximum RSS is not necessarily simultaneous peak memory of the
whole process tree. Process exit can hide open-descriptor accumulation between
stages, so resource investigations need observation within each stage.

## Configurable sort program (2026-09-29, committed in `7eaccb4124`)

`tdb2.xloader --sort=PROGRAM` (also `--sort PROGRAM`) selects the sort executable;
the default remains `sort` on the PATH. The launcher checks that the program exists
and accepts `--parallel` after argument parsing, logs its resolved path and passes
`--sort` to `CmdxBuildNodeTable` and `CmdxBuildIndex`. `CmdxLoader` forwards it too.
`ProcBuildNodeTableX.exec` and `ProcBuildIndexX.exec` gained overloads taking the
program; the existing public signatures delegate with the default. The program must
accept xloader's GNU options unchanged; a wrapper script can adapt other sorters.
A start failure now names the program.

New tests in `TestXLoader`: `customSortProgram` (wrapper records arguments and
delegates to GNU sort; node table plus SPO/POS/OSP) and `missingSortProgramFails`.

- [x] Run `TS_XLoader` in IntelliJ with GNU sort: 16 tests passed.
- [ ] Decide whether the benchmark harness should pass `--sort` for patched builds;
  the PATH wrapper still works for the unchanged baseline distribution.

## Temporary-file placement (2026-09-29)

`benchmark.py run --tmp-home DIR` puts xloader's `--tmpdir` (sort spills plus
`triples.tmp`/`quads.tmp` intermediates) on another volume, e.g. the Mac's internal
disk, with the database on the external SSD. `--min-free-gb` (default 20) stops the
loader process group if either volume runs low. Nine stub-based harness tests pass.
Also fixed: `logged()` could raise `PermissionError` from `killpg` on macOS after an
interrupted run's group had already exited.

- [ ] Choose one placement before recording the baseline series; label any other.
- [ ] Measure lexemes' peak workfile usage before trying truthy on the internal disk.

## Sort temporary-file compressor (2026-09-29)

`benchmark.py run --sort-compress PROGRAM` replaces the gzip that xloader passes to
the index sorts, through the harness sort wrapper; no Jena change is needed, so the
unchanged baseline build can be measured with each compressor. Every run records
`sort_compress_calls`; zero means no index sort spilled and the compressor was
irrelevant. `check_sort.py --compress-program` compares against GNU sort using gzip.
Twelve stub-based harness tests pass. On macOS, `/usr/bin/gzip` is Apple gzip 479.

- [x] Install pigz (2.8, Homebrew). The harness's round-trip check passes.
- [ ] Pass `check_sort.py --compress-program pigz` (not yet run).
- [x] Confirm lexemes index sorts spill: `sort_compress_calls` = 6 compress,
  6 decompress in both runs, about two spill files per index sort. The node-table
  sort stayed in memory.
- [x] Compare gzip and pigz on the same build, dataset and placement: one run each,
  pigz 2:14 faster overall (see "First lexemes runs"). Repeat before reporting.
- [ ] Uncommitted: the Java commands (`AbstractCmdxLoad`) now also reject a missing
  `--sort` or `--sort-compress` program up front, via
  `BulkLoaderX.programAvailable`; previously only the launcher did, and the Java
  path failed only when an index sort first spilled. New test
  `TestXLoader.programAvailable`. Not yet built or tested:
  `mvn -pl jena-tdb2,jena-cmds install -Dtest='TS_XLoader,TS_Cmd' -Dsurefire.failIfNoSpecifiedTests=false`.
- [x] xloader option (committed in `7eaccb4124`): `tdb2.xloader --sort-compress=PROGRAM`
  and the same on `CmdxBuildNodeTable`, `CmdxBuildIndex` and `CmdxLoader`. It replaces
  gzip wherever xloader enables sort compression (index sorts by default). The
  launcher checks that the program exists and round-trips a sample with `-d`, and
  passes the option on only when given. Tests: `customSortProgram` now also checks
  the default gzip argument; `customSortCompressProgram` checks the argument placement.
  The harness keeps its wrapper, so older builds can still be compared.

The Java-side gzip for `triples.tmp.gz`/`quads.tmp.gz` is separate:
`IO.openOutputFile` uses `new GZIPOutputStream(out)`, i.e. default level and a
512-byte deflate buffer over an unbuffered `FileOutputStream`; reading uses
`GZIPInputStream(in, 8K)`. `--sort-compress` does not affect it.

Implemented (committed in `7eaccb4124`; TS_IO and TS_XLoader pass):

- `IO.openOutputFile(filename, gzipLevel, gzipBufferSize)` and the matching
  `openOutputFileEx` overload in jena-base. The existing methods delegate with
  `IO.GZIP_LEVEL_DEFAULT` (-1) and `IO.GZIP_BUFSIZE_DEFAULT` (512), so general Jena
  output is unchanged. `TestOutputFileGzip` checks only that the level reaches
  the `Deflater` and that bad arguments are rejected before the file is created.
- xloader's own workfile defaults: `BulkLoaderX.WorkfileGzipLevel` = 1 and
  `WorkfileGzipBufferSize` = 128 KiB (matching `IO`'s buffered output); unmeasured, chosen because the workfiles are
  temporary and written once.
- `tdb2.xloader --workfile-gzip-level=N --workfile-gzip-buffer=BYTES` (also on
  `CmdxIngestData` and `CmdxLoader`) override them. `-1` and `512` restore the
  previous behaviour exactly.

- [ ] Measure ingest time and workfile size, old versus new defaults, on lexemes.
  This changes xloader's default: a build with it differs from `baseline-5091360`
  in the ingest stage, and in index-stage decompression input.

## First lexemes runs (2026-09-29)

All three runs: harness defaults (2 sort threads, `-Xmx4G`), GNU sort 9.12,
Corretto 21, database and temporary files on the internal disk; `baseline` uses
`build/baseline`, the others `build/current`. One run of each configuration, so
the noise is not yet known.

| Stage | `baseline` | `current` (gzip) | `current-pigz` |
| --- | --- | --- | --- |
| Node table: parse | 5:49 | 5:47 | 5:48 |
| Node table: index terms (51.1 M terms) | 1:37 | 1:38 | 1:35 |
| **Node table** | **7:44** | **7:43** | **7:41** |
| Ingest | 4:02 (946 k/s) | 3:37 (1.05 M/s) | 3:38 |
| Index SPO | 4:12 | 4:23 | 3:08 |
| Index POS | 9:20 | 9:20 | 9:04 |
| Index OSP | 5:18 | 5:16 | 4:34 |
| **Total** | **30:42** | **30:25** | **28:11** |
| Workfile | 1.27 GB (level 6) | 1.40 GB (level 1) | 1.40 GB |

Runs: `runs/lexemes/20260929T184637Z-bff9748c` (current, gzip),
`20260929T191917Z-c2e4d8d5` (current, pigz) and `20260929T195114Z-1c70a680`
(baseline). All three spilled equally (6 compress, 6 decompress calls).

Cache: the harness reads the whole input for its checksum just before each load,
so every run, including the first, starts with the input in the page cache. My
first run's cache note ("cold cache") was wrong. For lexemes it hardly matters:
the parser reads about 4–5 MB/s of compressed input.

Comparisons (one run each):

- The code changes are speed-neutral: current is 17 s (1%) faster than baseline.
  The ingest step gains 25 s from the new workfile defaults (level 1, 128 KiB),
  at 10% more workfile. The other stages agree to within about ±10 s. So the cleanup
  costs nothing measurable. The ingest gain is modest because compression runs on its
  own thread alongside parsing and node lookups.
- pigz is the one clear gain: 2:31 (8%) faster than baseline, all in SPO and OSP.

Observations:

- All three runs counted 229,010,967 distinct triples: 381,132 duplicate statements
  merged. Every later run must match this count.
- The stages that don't use the compressor agree to within 2 s, so the difference
  is attributable to pigz. It is all in the index builds, 18:59 → 16:46 (−12%).
- During the gzip run's spills, gzip ran at 89–98% of one core while sort waited
  on it (about 55–60% CPU): the compressor was the bottleneck while spilling.
- POS spends most of its time sorting (sort at about 195–200% CPU, the compressor
  idle), so a faster compressor barely helps. POS needs more sort threads or a
  different sorter. With `--threads 2`, sort is capped at about 200% CPU, which
  suggests `--threads` is itself a limit.
- The index builds are about 60% of the load. The Java process is near 0% CPU
  while the sorts run, so the JVM matters only in the node-table and ingest stages.
- Maximum RSS about 12.2 GB (baseline) and 13.2–13.7 GB (current), the `time`
  figure for the largest process, not the whole process tree.
- `triples.tmp.gz`: 1.40 GB with the new level-1 default, 1.27 GB with the old
  default level. The baseline's SPO was 11 s faster, possibly from reading the
  smaller file, or noise.
- Parser warnings: a few `Bad IRI` warnings (`punjabipedia.org` IRIs with `%u0a38`
  escapes), once per parse. Data issues; the load continues.
- The launcher prints `Command /bin/gzip not found` at startup on macOS: it tries
  `/bin/gzip` before `/usr/bin/gzip` (`tdb2.xloader:80`). Harmless noise, also in the
  baseline launcher.
- The harness keeps `database/` and `tmp/` for each run, about 21.4 GB per run.

## uutils sort findings (2026-09-29)

`uu-sort` is uutils coreutils 0.12.0 (Homebrew `uutils-coreutils`). It is not the
crates.io `gnu-sort` crate: that is acefsm/rust_sort, a separate project (listed in
Phase 2 as `acefsm/rust_sort`, not yet tested; `cargo install gnu-sort` installs a
binary named `sort`, so call it by full path).

Two incompatibilities with xloader's arguments:

1. **`--buffer-size=50%` is rejected** ("invalid --buffer-size argument"). xloader
   always passes it, so plain `--sort uu-sort` fails in the first sort.
2. **`--buffer-size` means something else.** In uu-sort it is the size of each
   segment (man page: "maximum SIZE of each segment"), not a total memory cap as in
   GNU sort. Memory use is about 2.7–2.8 times the segment size. The first wrapper
   converted 50% into 16 GiB: uu-sort then held all 229 M SPO rows in one segment,
   reached a 27–31 GB footprint on the 32 GB Mac, filled 15.5 of 16 GB swap, and
   delivered 55–80 k rows/s (GNU sort: about 4 M/s). That load
   (`20260929T203022Z-84abe7f6`, `current-uusort-pigz-t8`) was stopped in SPO after
   15 min; status `interrupted_or_error`. Its node table was correct (51,145,822
   terms). A stack sample during the slow phase showed the main thread in
   `compare_by`/`memcmp` and 8 idle workers, and uu-sort at 2–16% CPU, because it
   was waiting on page-ins.

Everything else works: `--unique` with keys, `--parallel`, `--compress-program`
(including pigz), `-T` and stdin/stdout pipes. `check_sort.py` passes with the
wrapper (`checks/uu-sort-0.12.0-wrapper-pigz.json`, then
`checks/uu-sort-0.12.0-wrapper-1024M-pigz.json`); the unwrapped attempt failed
(`checks/uu-sort-0.12.0-pigz.json`).

Sort-only tests on the real SPO workfile (`--parallel=8 --unique`, SPO keys; every
output identical to GNU sort's; decompressing the workfile alone takes 5 s):

| Sort | Rows | `-S` | Compressor | Time | Peak memory |
| --- | --- | --- | --- | --- | --- |
| GNU | 10 M | 16384M | none | 2 s | |
| uu | 10 M | 16384M, 1024M, 256M, 64M | none | 2–3 s | |
| GNU / uu | 10 M, stdin and stdout pipes | 16384M, 256M | none | 2–4 s | |
| GNU / uu | 10 M | 16384M | pigz | 2 s | |
| GNU / uu | 50 M | 16384M | none | 15 s / 17 s | |
| GNU | 229 M | 16384M | none | 2:04 | |
| uu | 229 M | 16384M | none | stopped after about 6 min, swapping | 27–31 GB |
| uu | 229 M | 4096M | pigz | 1:20 | 11.6 GB |
| uu | 229 M | 2048M | pigz | 1:16 | about 5.5 GB |
| uu | 229 M | 1024M | pigz | 1:21 | 3.0 GB, 22 spill files |
| uu | 229 M | 512M | pigz | 1:18 | 3.0 GB, 22 spill files |

- Time doesn't depend on the segment size from 512M to 4096M; there is no sign of a
  costly extra merge pass at 22 spill files. Only a segment too large for RAM hurts,
  badly.
- 512M and 1024M give the same memory and spill count; uu-sort seems to have a
  minimum segment size (about 530 MB of data per spill file). Unexplained.
- Not like for like: GNU sort ran without a compressor. GNU sort with 8 threads and
  pigz is still to be measured. Only SPO's key order was tested; POS and OSP reorder
  columns.

Wrapper `xloader-benchmark/tools/uu-sort-xloader`: replaces a percentage
`--buffer-size` with a fixed `1024M` (3 GB, safe on small VMs, as fast as larger);
`UU_SORT_BUFFER` overrides it (e.g. `2048M`); absolute sizes pass through. `run.json`
records the wrapper's SHA-256, not the uu-sort binary's; the version is recorded.

- [x] Full load with the 1024M wrapper, pigz, `--threads 8`
  (`current-uusort1024M-pigz-t8`, `runs/lexemes/20260929T213526Z-7169a7b3`):
  **17:11**, status `counted`, 51,145,822 terms and 229,010,967 triples (both
  exact), 66 compress / 66 decompress calls, max RSS 6.0 GB.

  | Stage | `baseline` | `current-pigz` (GNU, 2 threads) | uu-sort 1024M, pigz, 8 threads |
  | --- | --- | --- | --- |
  | Node table | 7:44 | 7:41 | 7:44 |
  | Ingest | 4:02 | 3:38 | 3:38 |
  | Index SPO | 4:12 | 3:08 | 1:31 |
  | Index POS | 9:20 | 9:04 | 2:16 |
  | Index OSP | 5:18 | 4:34 | 1:58 |
  | **Total** | **30:42** | **28:11** | **17:11** |
  | Max RSS | 12.2 GB | 13.7 GB | 6.0 GB |

  The index builds went from about 17 min to 5:45; the load is 44% faster than
  baseline. uu-sort ran at about 550–840% CPU. The node-table sort spilled too
  (uncompressed, up to 6.6 GB), at no visible cost. Node table and ingest are now two
  thirds of the load, so the parser ideas are the next lever. Caveats: uu-sort and 8
  threads changed together; one run; uu-sort spills everything (11 times the
  compressor calls), which could reverse the advantage on a slow disk.
- [x] Same load with GNU sort, pigz and `--threads 8` (`current-pigz-t8`), to
  separate the sort program from the thread count. The first attempt
  (`20260929T215408Z-6fedb9e2`) is invalid for timing: the Mac went to sleep at
  00:11:55, during POS, with only short DarkWakes every 15–16 min, so xloader logged
  5 h 38 min wall clock (POS 2:40 h, OSP 2:44 h); the harness's monotonic
  `elapsed_seconds` (which stops during sleep on macOS) gave 22:23; counts correct.
  The rerun under `caffeinate -i` (`20260930T045635Z-285559fc`, on battery, low power
  mode off, no sleep; wall and monotonic time agree) took **22:32**: node table 7:50,
  ingest 3:40, SPO 2:27, POS 5:25, OSP 3:07; max RSS 14.1 GB; 9/9 compressor calls;
  counts exact. So from GNU with 2 threads (28:11): 8 threads save 5:39, and uu-sort
  another 5:21 (to 17:11), mostly in POS both times. `--threads 8` alone is a free
  gain with standard GNU sort.
- [ ] Harness: on macOS run the loader under `caffeinate -i` (and `-s` on mains power),
  and record a warning in `run.json` when wall-clock and monotonic time differ by more
  than a few seconds, so a slept run can't pass for a clean one.
- [ ] Power: runs so far were partly on mains power (current, current-pigz) and partly on
  battery (baseline onwards); low power mode off throughout. Prefer mains power for
  the repeat series.
- [ ] Report both uu-sort issues upstream to uutils, with the stack sample.
- [ ] For truthy (hundreds of segments), test larger segments on a prefix; the merge
  may behave differently there. `--batch-size` exists; its default is undocumented.

## Ubuntu's default `sort` breaks unchanged xloader (2026-09-30, verified)

Since Ubuntu 25.10, `/usr/bin/sort` is uutils by default (symlink to
`../lib/cargo/bin/coreutils/sort`, package `coreutils-from-uutils`): 25.10 has uutils
0.2.2, 26.04.1 LTS has 0.8.0 (0.10.0 in `resolute-updates`). 24.04 LTS still has GNU
coreutils 9.4. xloader hard-codes `"sort"` with `--buffer-size=50%` in both
`ProcBuildNodeTableX` and `ProcBuildIndexX`, unchanged since at least 2022 and still
on `main` (`509136074c`, as last fetched). Checked in Docker on this Mac (8.3 GB VM):

| Ubuntu | sort | 50% accepted | 40 M SPO rows (2 GB): peak RSS, temp files, time | Output |
| --- | --- | --- | --- | --- |
| 24.04.5 LTS | GNU 9.4 | yes | 3,970 MiB, 2, 23 s | reference |
| 25.10 | uutils 0.2.2 | yes | 25 MiB, 198,317, 42 s | identical |
| 26.04.1 LTS | uutils 0.8.0 | yes | 31 MiB, 31,090, 52 s | **one extra empty line** (deterministic; `1024M` gives identical output) |
| macOS Homebrew | uutils 0.12.0 | **rejected** | — | — |

So the older uutils versions misread `50%` as a tiny buffer (tens of KB: spilling
hundreds of thousands of files), and 0.8.0 then emits an empty line. Brew's 0.12.0 is
the newest; it rejects the percentage instead.

End-to-end with the official **Apache Jena 6.2.0** binary release (dlcdn.apache.org,
SHA-512 verified), unchanged `tdb2.xloader`, Java 21, first 20 M lines of lexemes:

- Ubuntu 26.04.1 LTS, default `sort`: **fails after 41 s** in the node table,
  `IllegalArgumentException: Bad hex char : 10 (0x0A)` at
  `ProcBuildNodeTableX.hexRead` (the empty line); exit 141.
- Ubuntu 26.04.1 LTS with a `sort` → `/usr/bin/gnusort` symlink first on `PATH`
  (GNU 9.7, from `gnu-coreutils`, installed by default): works, 2:13, 19,983,392 triples.
- Ubuntu 24.04.5 LTS, default GNU sort: works, 2:12, 19,983,392 triples.

6.2.0 has no environment variable or option for the sort program; the `PATH` shim is
the only workaround there. Switching the system with `coreutils-from-gnu` conflicts
with the essential uutils variant in the container. On this branch, `--sort gnusort`
works. For large loads on 25.10, the tiny buffer would also mean millions of spill
files. Scripts: `scratchpad/ubuntu-sort/{peak,dups,e2e}.sh` (session scratchpad; copy
into the repo if kept).

- [ ] Report to Jena (issue): xloader on Ubuntu 25.10+/26.04 LTS, with a minimal
  reproduction (the `Bad hex char` failure) and the `PATH` workaround.
- [ ] Report to uutils: 0.8.0 emits an empty line with `--buffer-size=50%` and
  `--unique` with keys under heavy spilling; percentage semantics differ from GNU
  (0.2.2/0.8.0 tiny buffer, 0.12.0 rejects).
- [ ] Jena fix options: in the launcher, detect uutils (`sort --version`) and prefer
  `gnusort` when present, or fail with a clear message; pass an absolute
  `--buffer-size` to uutils (per-segment semantics, see "uutils sort findings");
  make the Java readers reject empty or malformed sorted lines with a message naming
  the sort program.
- [ ] Test uutils 0.10.0 (26.04 `resolute-updates`) and 0.12.0 on Linux.

## Parser speed ideas (2026-09-29, not started)

The node-table parse takes 5:47 of the load (about 660 k triples/s), the ingest parse
about 3:37 (1.05 M/s). Both use Jena's RIOT N-Triples parser with checking enabled.
The ingest step does more per triple (three node-table lookups) and is still about
60% faster, because it uses `AsyncParser.asyncParse` (`ProcIngestDataX.java:151`):
parsing on one thread, the rest on another. The node-table stage calls
`RDFParser.source(datafile).parse(stream)` (`ProcBuildNodeTableX.java:161`) and does
everything on one thread (Java at about 100–125% CPU).

Per node, `NodeHashTmpStream.node` (from line 350) skips inline values and nodes in
a 500,000-entry cache, computes the 128-bit hash, serializes the term with Thrift,
and writes hash and Thrift bytes as hex, one byte at a time (two `write` calls per
byte, and double the size).

Ideas, by expected gain against effort (all hypotheses):

1. **`AsyncParser` in the node-table stage.** Small change; the ingest rate suggests a
   large gain for the 5:47 parse. Output unchanged.
2. **Faster hex output**: encode into a byte buffer through a lookup table and write
   once. Local change in `write`/`hexWrite`; output identical.
3. **A larger node cache** (500,000 is small for 51 M terms): less repeated hashing
   and serialization, fewer duplicates to sort. Costs heap; test with `-Xmx`.
4. **Decompress the input on another thread.** Java's inflater runs on the parser
   thread. With `AsyncParser` it at least doesn't compete with hashing; `pigz -dc` in
   a separate process would move it out of Java, but xloader reads each input twice.
   A single gzip stream can't be decompressed in parallel.
5. **Validate once, not in every pass** (user's idea). xloader parses the input twice:
   node table, then ingest. The node-table pass keeps checking on and reports invalid
   terms; the ingest pass runs with `checking(false)`, since the same input was just
   validated. Saves the checking cost in the second pass and prints each warning once
   instead of twice (today the `Bad IRI` warnings appear in both). Condition: both
   passes must produce exactly the same terms, because ingest looks up every node in
   the node table built by the first pass. Verify that RIOT's checking only reports
   and doesn't reject, drop or normalize terms differently; otherwise the lookups
   fail. Test with the node count, the triple count, and an input with invalid IRIs
   and literals. Could be a flag (e.g. `--validate=first|all|none`, default
   `first`). Also applies to parallel parsing (6). Plain `checking(false)` in both
   passes would load invalid terms silently; only as an explicit option.
6. **Parallel parsing.** A plain gzip is one DEFLATE stream and can't be split, so
   split after decompression: one inflate thread, a splitter cutting 4–16 MB chunks at
   newlines, N parser threads, results passed on in chunk order (the node table
   doesn't need order; ingest does, since SPO benefits from roughly subject-ordered
   input). Pitfalls: blank-node labels must map to the same node across all chunks
   and across both parses (check which label policy xloader uses today; Wikidata dumps
   probably use skolem IRIs instead of blank nodes); error line numbers need chunk
   offsets; inflate then becomes the limit (a few hundred MB/s against the current
   95 MB/s parse). Beyond that, recompress the dump once as block gzip (`bgzip -@ 8`,
   still valid gzip) so decompression can run in parallel too.

- [ ] Profile the node-table and ingest JVMs first with Java Flight Recorder:
  `--jvm-args "-Xmx4G -XX:StartFlightRecording=filename=<dir>/xloader-%p.jfr,settings=profile"`
  (check that `%p` works). Decide from where the time goes.
- [ ] Then 1 and 2; verify with the node count (51,145,822) and triple count.
- [ ] Then 5 (validate once): first check in RIOT that checking doesn't change the
  terms produced.
- [ ] Only if the parser thread is still the limit: 6, with blank-node agreement as
  the first test.

### First JMH measurement (2026-09-30)

`TestXLoaderParse` in `jena-benchmarks-xloader-jmh` on the first 20,000,000 lines of
the lexemes (`downloads/lexemes-20M.nt.gz`, gzip -1, 197 MB). SingleShotTime, 1 warmup
and 3 measured passes, one fork, `-Xmx4G`, under `caffeinate -i`, with the truthy
download running. Total 13:15; results in
`jena-benchmarks-xloader-jmh/TestXLoaderParse_20260930220335.json`.

| Benchmark | checking true | checking false |
|---|---|---|
| `nodeTable` (xloader now: parse + `NodeHashTmpStream`, one thread) | 34.4 s | 34.6 s |
| `nodeTableAsync` (the same with `AsyncParser`) | 21.5 s | 21.0 s |
| `parse` (parser only, counting stream) | 20.4 s | 20.2 s |
| `parseAsync` (parser only, `AsyncParser`) | 20.2 s | 20.4 s |

Passes within a benchmark differ by at most about 1.3 s; the JMH ±(99.9%) error is
wide only because there are 3 samples.

- Idea 1 confirmed: `AsyncParser` cuts the node-table parse step by 38% (1.6×,
  about 930 k against 580 k triples/s). If this holds for the whole file, the 5:47
  lexemes node-table parse would take about 3:35 (extrapolated, not measured).
- With `AsyncParser` the stage is within about 1 s of parsing alone: the per-node work
  (about 14 s on one thread) is hidden on the second thread. Ideas 2 (hex) and 3
  (cache) would then only save CPU, not time. The limit is parsing plus gzip
  decompression, which is where 4 (decompression thread) and 6 (parallel parsing)
  apply.
- Idea 5: `checking(false)` makes no measurable difference for N-Triples here, so
  "validate once" is unlikely to save parse time. Lower priority.
- Next: make the node-table stage use `AsyncParser`, verify node and triple counts on
  the full lexemes load; add a decompression-only benchmark (gzip read to a null
  sink) to see how much of the 20 s is inflate.

`TestXLoaderRead` on the same prefix (2,872,078,572 bytes uncompressed), reading the
file as RIOT opens it (`IO.openFile`), without parsing. Total 1:03; results in
`TestXLoaderRead_20260930222124.json`.

| Benchmark | Mean | Passes |
|---|---|---|
| `inflate` (`GZIPInputStream`, 64 KB blocks) | 2.53 s (about 1.1 GB/s) | 2.91 / 2.43 / 2.26 |
| `inflateUtf8` (+ `IO.asUTF8`, 64 K blocks) | 2.63 s | 2.62 / 2.64 / 2.65 |
| `peekReader` (+ `PeekReader.makeUTF8`, `readChar()` per character) | 8.69 s (about 330 M chars/s) | 8.65 / 8.75 / 8.65 |

Rough split of the 20.4 s parse, assuming the costs add: inflate 2.5 s (12%), UTF-8
decode 0.1 s, per-character `PeekReader` reads about 6 s (about 2 ns per character:
position/line/column bookkeeping, pushback check, `CharStream.advance()`), leaving
about 12 s for tokenizing and node creation.

- Idea 4 (decompression thread) would save at most about 2.6 s per 20 M lines (13%
  of the parse); lower than expected.
- New candidate: cheaper per-character input in `PeekReader` / the tokenizer (bulk
  scanning of IRIs and literals within the buffer). It is in jena-base and affects
  every RIOT text parser, so a larger change than the xloader ideas. Not measured
  inside the real tokenizer; the simple loop is probably a best case.

### `AsyncParser` in the node-table stage (2026-09-30, uncommitted)

`ProcBuildNodeTableX` now parses each file with `AsyncParser.asyncParse(datafile,
stream)` instead of `RDFParser.source(datafile).parse(stream)`; `NodeHashTmpStream`
and the progress monitor still run on the producer thread (the receiver dispatches on
the caller's thread). Parser defaults are unchanged (`AsyncParser.of` builds
`RDFParser.source(...)`), and parse errors are rethrown unchanged (`RiotException`,
`malformedNodeInputPropagates` passes).

Interruption: `AsyncParser`'s receiver catches `InterruptedException`, logs
"Interrupted" at ERROR and returns normally with the flag cleared, so the existing
`isInterrupted()` check would not stop the file loop. `SortProcess.close()` sets
`cancelled` before it cancels the producer, so `SortProcess.isCancelled()` (new,
package-private) is checked after each file. Also found: when the caller is already
interrupted, `AsyncParser`'s close action calls `parserThread.join()`, which throws at
once; the parser thread has been interrupted and aborted but is not waited for, so it
can end just after the stage fails (1 in 3 runs of the new test before it waited for
the thread). Harmless for xloader (each stage is its own JVM), but a jena-arq issue
worth reporting: `join()` should retry and restore the interrupt.

New test `TestXLoader.sortFailureStopsNodeParser`: a sort that reads 100 KB and exits
3 during a 200,000-triple node parse; expects a failure, the `AsyncParser` thread
gone within 10 s, and the database reopenable. Passed 8 times in a row; `TS_XLoader`
18 tests pass.

- [x] Full lexemes load with the change (`async-pigz-t8`, run
  `20260930T204425Z-2e456721`, `build/async`, GNU sort 9.12, pigz, `--threads 8`,
  under `caffeinate -i`, started right after the truthy download finished). Same
  51,145,822 terms and 229,010,967 triples. Against the clean `current-pigz-t8`
  (`20260930T045635Z-285559fc`):

  | Stage | current-pigz-t8 | async-pigz-t8 |
  |---|---|---|
  | Parse (nodes) | 353.9 s (648 k TPS) | 237.9 s (964 k TPS) |
  | Node table (parse + index terms) | 7:50 | 6:03 |
  | Ingest | 3:40 | 3:44 |
  | SPO / POS / OSP | 2:27 / 5:25 / 3:07 | 2:38 / 5:46 / 3:20 |
  | Total | 22:32 | 21:34 (-4%) |

  The node-table parse is 33% shorter (1.49×, the JMH prefix gave 1.6×) and saves
  1:47. The index stages, which the change does not touch, were 45 s slower in this
  run, so the total gains only 58 s. One run; repeat both to separate the index
  noise.
- [x] All changes together, uu-sort (`tools/uu-sort-xloader`, 1024M segments), pigz,
  `--threads 8` (`build/async`, 2026-09-30, machine otherwise idle):

  | Run | Node table | Ingest | SPO / POS / OSP | Total |
  |---|---|---|---|---|
  | `baseline-t8` (`20260930T074510Z-651f55ca`) | 7:51 | 4:16 | 3:27 / 5:45 / 4:00 | 25:23 |
  | `current-uusort1024M-pigz-t8` (sync parse) | 7:44 | 3:38 | 1:31 / 2:16 / 1:58 | 17:11 |
  | `async-uusort1024M-pigz-t8` (`20260930T211917Z-a322b179`) | 5:36 | 3:51 | 1:35 / 2:19 / 2:02 | 15:27 (-39%) |
  | `async-uusort1024M-pigz1-t8` (`20260930T213522Z-0209623b`, `--sort-compress-args=-1`) | 5:39 | 3:44 | 1:29 / 2:15 / 2:01 | 15:11 (-40%) |

  Counts identical in all runs. `pigz -1` saves 11 s on the index sorts (16 s in
  total), within what one pair of runs can resolve. Peak disk use from the harness's
  free-space samples (15.8 GB against 21.3 GB) is not usable: it is below the 20 GB
  final database, so the samples miss the peak or other space changes interfere.
  Measure spill size directly (a sort-only test) instead.

- [x] `--sort-compress-nodes` (new launcher option, off by default; compresses the
  node table sort's spills with the same compressor and `SORT_COMPRESS_ARGS`).
  `async-uusort1024M-pigz1-nodes-t8` (`20261002T215404Z-6ff07a75`, `build/async-nodes`,
  otherwise as `async-uusort1024M-pigz1-t8`): node table 5:43 (against 5:39), total
  14:59 (against 15:11); no regression, differences within noise. Node sort spills:
  14 extra compressor calls, peak tmp 2.3 GB compressed at the end of the node stage
  (sampled with du every 5 s); the uncompressed size was not measured.

  Harness note: with `--sort-compress-args`, the launcher logs
  `Compress: /usr/bin/gzip -1 (... via xloader-sort-compress)` because the harness
  replaces the compressor at the sort level and never passes `--sort-compress`; the
  process actually run was `/opt/homebrew/bin/pigz -1` (checked with `pgrep`).

### Bulk token scanning: JMH lower bound (2026-10-03)

`TestTokenizerScan` (jena-benchmarks-jmh, package `org.apache.jena.riot.tokens`, input
from `RIOT_JMH_DATA`) on `lexemes-20M.nt.gz`, 3 passes each, run with JMH's runner
against `build/async-nodes/lib` (the module's Maven build needs jena-geosparql and the
shaded Jena 5.6.0 module installed):

| Benchmark | Mean |
|---|---|
| `tokenizer` (`TokenizerText` over `PeekReader`, tokens only, no nodes) | 14.78 s |
| `peekReader` (`readChar()` per character) | 8.41 s |
| `bulkScan` (prototype: token ends found in a 128K char buffer, images copied) | 3.88 s |

Same token count from `tokenizer` and `bulkScan` (checked in setup). With the full parse
at 20.4 s: inflate and UTF-8 about 2.6 s, per-character reading about 5.8 s, token logic
about 6.4 s, parser and node creation about 5.6 s. `bulkScan` does no escape decoding or
checking, so it is a lower bound: a real bulk-scanning tokenizer might take 5-7 s instead
of 14.8 s, the parse about 11-13 s instead of 20.4 s (estimate, not measured).

Byte-level variants (scan undecoded UTF-8, decode only each token image; differ only
in the delimiter search), 20M prefix, 3 passes each:

| Benchmark | plain `.nt` | `.nt.gz` |
|---|---|---|
| `tokenizer` | 13.00 s | 14.83 s |
| `peekReader` | 6.69 s | 8.43 s |
| `bulkScan` (chars) | 2.27 s | 3.87 s |
| `bytesScalar` | 2.63 s | 4.46 s |
| `bytesSwar` | 2.08 s | 3.99 s |
| `bytesVector` (Vector API, 16 bytes on this Mac) | 1.94 s | 3.96 s |

The Vector API is about 7% faster than SWAR on plain input (within the error), and no
faster from gzip, where decompression (about 2.5 s) is the floor. Not worth an opt-in
flag with an incubator module; SWAR needs nothing special. Once tokens are scanned in
bulk, the search method matters little; decompression and the parser/node creation
(about 5.6 s) are what remain.

### Term repetition: a byte-keyed term cache (2026-10-03, measured; see the prototype below)

The node stage's `CacheSet<Node>` (500,000) only skips hashing and writing: every term
is still tokenized, checked and turned into a `Node` first. A cache keyed on the
token's raw bytes, before Node creation, would skip that too. Repetition on
`lexemes-20M.nt.gz` (token text, one shared LRU of 500,000 as in `NodeHashTmpStream`;
scratchpad `TermRepeats.java`):

| Position | Same as previous line | LRU hits | Distinct | Avg chars |
|---|---|---|---|---|
| subject | 81.6% | 99.4% | 2,828,398 | 56.1 |
| predicate | 33.4% | 100.0% | 1,684 | 49.5 |
| object | 9.3% | 76.1% | 4,764,373 | 48.1 |
| all | | 91.8% | | |

Subjects hit more often than they repeat: statement nodes appear as objects first.
So about 92% of term occurrences could skip tokenizing into a String, checking, Node
creation and hashing; ingest could cache bytes to NodeId the same way (it is also
parse-bound). Equal token text always means the same node in N-Triples (no prefixes or
base; blank node labels within one parse); different escapes of the same term only
cause extra misses. Check the hit rate on full lexemes and a truthy prefix: the
distinct-term count grows with the data.

### Alternative N-Triples front end with a term cache: prototype (2026-10-03, parked)

Not a change to xloader now: an alternative parser for N-Triples/N-Quads input, either
as an optional fast path (off by default, RIOT for everything else) or as part of a
separate loader design. `TestXLoaderTermCache` (jena-benchmarks-xloader-jmh) on
`lexemes-20M.nt.gz`, 3 passes each (`TestXLoaderTermCache_20261003013135.json`):

| Benchmark | Mean |
|---|---|
| `nodeTableAsync` (now: `AsyncParser` + `NodeHashTmpStream`, two threads) | 20.90 s |
| `termCache` (one thread: byte scan, 2^20-slot byte-keyed cache, RIOT tokenizer + profile on a miss) | 16.05 s |
| `termCacheIri` (as `termCache`; missed IRIs without `\` skip the tokenizer) | 15.27 s |

Hit rate 91.8% (55.1 M of 60 M terms); 4.67 M nodes written; setup checks that the
node hashes equal today's (blank nodes excluded). The 4.9 M misses now dominate (about
11-12 s: profile, hash, Thrift, hex); scanning and lookups about 4 s. Next if resumed:
miss handling on a second thread (bound by the misses, about 11 s), then cheaper misses.

Equivalence: a hit is safe because an N-Triples term's meaning depends only on its text
(no prefixes or base; a blank node label is one node within a parse). Not yet
equivalent in the prototype, and needed before any use:
- statement grammar: the scanner does not check what LangNTriples checks (subject IRI
  or blank node, predicate IRI, three terms then `.`, quads);
- `termCacheIri` skips the tokenizer's IRI character checks (for example a space); with
  N-Triples checking off the profile does not repeat them, so that shortcut is unsafe;
- the parser profile must be the one RDFParser builds for the load (checking, error
  handler); the prototype uses `RiotLib.profile` (not verified to match);
- diagnostics: a repeated bad term warns once instead of every time; error positions
  need the scanner's line numbers;
- RDF 1.2: triple terms `<<( s p o )>>` (object position only, nested; `LangNTuple`)
  are mis-scanned as IRIs. Either cache the whole triple term as one key (its meaning
  also depends only on its text) and parse it with RIOT on a miss, or fall back to RIOT
  for statements containing `<<`. Base-direction language tags (`@en--ltr`) already
  work. Check how Jena treats `VERSION "1.2"` in N-Triples and match it. The W3C RDF 1.2
  N-Triples/N-Quads suites cover these cases.
Verification would be differential: the W3C N-Triples/N-Quads test suites and real
dumps through both paths, comparing nodes and errors.

### Parse only once: measured, declined for now (2026-10-03)

Idea: the node stage also writes a hash file (per triple position the inline NodeId
or the 128-bit hash), and ingest resolves hashes against the finished node B+tree
instead of parsing again. `TestXLoaderIngest` (jena-benchmarks-xloader-jmh) on
`lexemes-20M.nt.gz`, 3 passes each, results in `TestXLoaderIngest_20261003002136.json`:

| Benchmark | Mean |
|---|---|
| `ingest` (as now: `AsyncParser` + node table lookups, 10M node cache) | 20.7 s |
| `resolve` (hash file, B+tree lookups, no cache) | 21.7 s |
| `resolveCached` (hash file, 10M hash cache) | 10.1 s |

Ingest already runs at parser speed (parse alone: 20.2-20.4 s), the lookups overlapping
on the other thread. Without a cache, resolving is no faster; with one it halves
ingest, about 1:50 of a 15-minute lexemes load (about 12%). The cost is the hash file:
about 1 GB per 20 M lines, so about 11 GB for lexemes and several hundred GB for
truthy, on the tmp volume. Declined for now; parallel parsing (6) attacks the same
limit without intermediate files, and both the node stage and ingest are parse-bound.

Found on the way: Wikidata uses blank nodes for unknown values (1,456 lines in
lexemes). Each parse labels blank nodes with a new random seed, so the node stage's
entries for them are never found again; ingest allocates them a second time. The data
is correct, but each blank node leaves an unused entry in `nodes.dat` and the node
B+tree. A fixed label seed shared by both parses of one load would avoid this (not
checked how RIOT exposes it).

### `--sort-buffer` and `--parallel-indexes` (2026-10-04, uncommitted)

Implemented items 1 and 2 below. `--sort-buffer=SIZE` sets sort's `--buffer-size` for
every sort (default `50%`). `--parallel-indexes` (off by default) builds the triple
indexes together, then the quad indexes, in one index step: one JVM, one thread and
one sort per index (separate JVMs would conflict on TDB2's process lock; each index
already has its own B+tree transaction). A percentage buffer is shared between the
sorts running together (50% -> 16% each); a fixed size applies to each. If one build
fails, the others are cancelled and their sorts killed. Tests: `parallelIndexes`,
`sortBufferSizeApplies`, `sortBufferSizeRules`, `parallelIndexFailureStopsOtherSorts`.

Lexemes, as `async-uusort1024M-pigz1-t8` (15:11) plus `--parallel-indexes`
(`build/parallel`, run `20261003T234548Z-6388f88d`, `--threads 8` per sort):

| | Sequential (15:11 run) | Parallel |
|---|---|---|
| SPO / POS / OSP (each) | 1:29 / 2:15 / 2:01 | 2:53 / 3:32 / 3:16 |
| Index stages, wall clock | 5:43 | 3:32 |
| Total | 15:11 | 12:51 (-15%) |

Each index is slower alone (load average about 28 on 12 cores: 24 sort threads plus
pigz), but the overlap saves 2:11. CPU 3,015 s in 771 s (3.9 cores on average).
`--threads 4` (`20261003T235932Z-d802f532`): indexes 3:40 (2:39 / 3:40 / 3:10),
total 12:56; the same as `--threads 8` within noise, so sort threads are not the
limit with three sorts at once. `--threads 4` with `--sort-compress-args='-1 -p 4'`
(`20261004T001438Z-efaf1f29`):

| Run | Threads | pigz | SPO / POS / OSP | Indexes (wall) | Total |
|---|---|---|---|---|---|
| sequential (`async-uusort1024M-pigz1-t8`) | 8 | `-1` | 1:29 / 2:15 / 2:01 | 5:43 | 15:11 |
| parallel | 8 | `-1` | 2:53 / 3:32 / 3:16 | 3:32 | 12:51 |
| parallel | 4 | `-1` | 2:39 / 3:40 / 3:10 | 3:40 | 12:56 |
| parallel | 4 | `-1 -p 4` | 2:35 / 3:40 / 3:15 | 3:40 | 12:54 |

Sort threads and pigz threads make no difference once the three sorts overlap; the
limit is elsewhere (disk, or the Java side decompressing the workfile and reading the
sorted output). Default `--threads` is fine with `--parallel-indexes`. For truthy: peak tmp
space rises (three sets of spills at once) and three merges share disk bandwidth;
likely good on fast local disks, possibly worse on slow volumes. Measure on a truthy
prefix. Note: `compare.py` per-index columns overlap in parallel runs; use the total.

### Shared blank node seed (2026-10-04, uncommitted; plan item 4)

The node table step creates a random seed for the load and writes it to
`TMPDIR/blank-node-seed.txt` (`BlankNodeSeed`); ingest reads it. Each input file gets
its own seed derived from the load seed and the file's position in the input list
(`UUID.nameUUIDFromBytes(seed + "/" + index)`), used with
`LabelToNode.createScopeByDocumentHash`, so both steps (and all parallel chunks) make
the same blank node for a label in a file, while equal labels in different files stay
different nodes (one document each). Without the seed file, ingest behaves as before.
Correctness: the loaded data is the same up to blank node identities, which were random
before too; what goes away are unused node table entries and ingest allocations.
Tests: `blankNodesFoundByIngest` (also with 4 parse threads): 20 blank nodes in the node
table for 20 in the data; `ingestWithoutSeedFile`: 40 (20 unused), as before.

### Parallel ingest (2026-10-04, uncommitted)

`--parse-threads=N` now also applies to ingest (`ParallelIngest`, on the generic
`ParallelParser`, which `ParallelNodeParser` now uses too): the calling thread holds the
write transaction; each worker parses chunks, finds node ids in its own read transaction
(inline values directly, else hash lookup in the node B+tree without `NodeTableNative`'s
lock, with a per-worker cache of 10M/N entries), writes rows to buffers and appends
them to the workfiles under a lock. Missing nodes go to the writer thread
(`getAllocateNodeId`), which returns the id; workers cache it. Rows and counts as
`IngestData` (default-graph quads written as triples, counted as quads).
Tests: `parallelIngestTriples` (isomorphic, with and without the seed file),
`parallelIngestQuads` (named and default graph, exact), `parallelIngestParseError`
(line 321 in the whole input).

Lexemes, as the 10:19 run but with parallel ingest (`build/pingest`, run `20261004T100320Z-44f3d594`):
node table 3:25, **ingest 2:41** (161 s, 1.42 M/s, against 3:36), indexes about 3:30,
**total 9:37** (-62% against baseline-t8). Counts identical.

Where ingest's time goes (not the 2.5x the JMH suggested):
- not decompression: `rapidgzip -d -c -P 4 lexemes.nt.gz` alone: 33.0 GB in 15.6 s
  (2.1 GB/s), ten times what ingest consumes; so a rapidgzip index would not help;
- not the shared workfile gzip stream: Java gzip level 1 (128 KiB buffer) compresses
  the whole 11.7 GB workfile on one thread in 22.5 s (520 MB/s), 14% of ingest.
Next suspects: garbage collection with six parsers in `-Xmx4G` (allocation rate six
times higher), smaller per-worker caches, or the reader thread copying chunks.

Measured (2026-10-04): the ingest step alone (`CmdxIngestData`, as the launcher runs it),
against the complete node table of that run, `XLOADER_DECOMPRESS=rapidgzip -d -c -P 4`,
`-Xlog:gc`, one configuration after another (scratchpad `ingest-matrix/run.sh`):

| # | Java | Heap, GC | Threads | Ingest | CPU | Peak RSS | GC pauses |
|---|---|---|---|---|---|---|---|
| 1 | 21 | 4G, G1 (as before) | 6 | 155.8 s | 1,304 s | 5.8 GB | 750, 49.5 s |
| 2 | 21 | 8G, G1 | 6 | 119.1 s | 906 s | 10.1 GB | 391, 21.3 s |
| 3 | 21 | 4G, G1 | 4 | 162.4 s | 1,215 s | 5.9 GB | 700, 48.3 s |
| 4 | 21 | 4G, G1 | 8 | 164.7 s | 1,506 s | 5.9 GB | 775, 51.1 s |
| 5 | 21 | 8G, ParallelGC | 6 | 100.1 s | 623 s | 10.1 GB | 155, 10.8 s |
| 6 | 25 | 8G, G1, compact headers | 6 | 108.7 s | 805 s | 10.2 GB | 251, 12.9 s |
| 7 | 25 | 8G, ParallelGC, compact headers | 6 | **96.2 s** | 603 s | 10.0 GB | 135, 7.8 s |

Garbage collection was the limit: with a 4G heap a third of the time was GC pauses
(G1 stops all workers), and thread count made no difference. 8G helps, ParallelGC more
(throughput collector, fewer and shorter pauses, half the CPU), Java 25 with compact
headers a little more. Ingest on one thread was 216 s: 2.2x with the best setting.
Recommendation with `--parse-threads`: `JVM_ARGS="-Xmx8G -XX:+UseParallelGC"` on 32 GB
(about a quarter of RAM; `JVM_ARGS` applies to every step, so with GNU sort lower
`--sort-buffer`), plus `-XX:+UseCompactObjectHeaders` on Java 25. For truthy, the heap
competes with the page cache for the node table, so not more than that.

### Full load with the JVM recommendation (2026-10-04)

Run `20261004T105838Z-b1f7532e`, label `uusort1024M-pigz1-t8-parallel-pt6-j25par8g` (run labels name the
settings that differ from the default: sorter, compressor, threads, index mode, parse
threads, JVM). `build/final` (all current changes, `XLOADER_DECOMPRESS` removed; the
folder name is not a statement that the work is final). uu-sort 1024M segments, pigz -1,
`--threads 8`, `--parallel-indexes`, `--parse-threads=6`, Corretto 25.0.3 with
`-Xmx8G -XX:+UseParallelGC -XX:+UseCompactObjectHeaders`, Java gzip for the input.

| Stage | baseline-t8 | 9:37 run (Java 21, G1, 4G) | This run |
|---|---|---|---|
| Node table | 7:51 | 3:25 | 3:16 (parse 87.8 s, 2.61 M/s) |
| Ingest | 4:16 | 2:41 | **1:33** |
| SPO / POS / OSP | 3:27 / 5:45 / 4:00 | 2:55 / 3:30 / 3:12 (parallel) | 2:44 / 3:23 / 3:06 (parallel) |
| Total | 25:23 | 9:37 | **8:15 (-67%)** |

Counts identical. CPU 3,196 s in 495 s (6.5 cores on average). The index stages (about
3:23 wall) and the node table (term index about 100 s, single-threaded) are now the
largest parts.

### Comparison with tdb2.tdbloader (2026-10-04)

`tdb2.tdbloader --loader=MODE` from the same distribution (`build/final`), out of the
box: no `JVM_ARGS` (Java's default heap, a quarter of RAM = 8 GB, G1), Corretto 21.0.12,
lexemes, under `caffeinate -i`, one after another (scratchpad `tdbloader-modes.sh`;
results in `runs/tdbloader/`). `tdbloader` has no thread option: each mode has a fixed
plan (`LoaderPlans`). `sequential` and `basic` were not run (expected to take hours);
`light` (in the command's help, not in the documentation) was not run either.

| Loader | Time | CPU | Peak RSS | Triples | Database |
|---|---|---|---|---|---|
| `tdb2.tdbloader --loader=parallel` | 44:49 | 1,251 s | 14.9 GB | 229,010,967 | 35 GB |
| `tdb2.tdbloader --loader=phased` (default) | 47:50 | 1,217 s | 14.9 GB | 229,010,967 | 35 GB |
| `tdb2.xloader`, unchanged (`baseline-t8`) | 25:23 | | | 229,010,967 | 20 GB |
| `tdb2.xloader`, this branch (8:15 run) | 8:15 | 3,196 s | | 229,010,967 | 20 GB |

- `parallel` inserts every triple into SPO, POS and OSP at once (one thread per index):
  157 k triples/s on average for the first 145 M, then 91 k/s once the trees outgrow the
  page cache (batches down to 39 k/s).
- `phased` loads the data into SPO only (6:51, about 0.56 M/s: SPO inserts are almost
  local, the input being grouped by subject), then builds POS and OSP from SPO. That
  second phase starts at about 1.9 M/s and falls to batches of 30-60 k/s after about
  50 M triples: inserts in POS and OSP order land at random places in the trees.
- Both write through ordinary transactions into B+trees built by insertion, which leaves
  blocks partly empty: 35 GB against 20 GB from xloader, which sorts and packs each tree
  bottom-up. Already at 229 M triples on 32 GB, random inserts are the limit; at
  billions of triples the gap to xloader should grow (not measured).

### Second full truthy run (2026-10-04, in progress)

Run `runs/truthy/20261004T173618Z-b18cd538` on the SSD, build `terms-pipeline`, settings
as the first run plus `--ingest-threads=32 --preload-node-table`.

- Node parse 60:30 (2.28 M triples/s; first run 59:14); spill merge about 9.5 min.
- Term index 24:18 at 1.10 M terms/s (first run 49:41): the faster term index works at
  full scale. Node table step 1:34:03 in total (first run 1:58:15).
- Preload: 38.8 GB in 11.3 s.
- **Ingest with 32 threads: 71 k/s falling to 42 k/s**, 86% of CPU in the kernel, 5% in
  user code, the SSD reading only about 77 MB/s. 26 of 32 workers were in B+tree page
  access on the mapped `nodes.dat` (`RecordBufferPage` creation): macOS's page-fault
  handling for one mapped file does not scale to 32 faulting threads. Stopped at 10 M
  triples.
- Resumed at ingest (node table kept) with `--ingest-threads=8`, by
  `resume.sh` in the run folder: a launcher copy that skips the node table step and the
  existing-database check, same environment as the harness. Ingest at about 250 k/s
  (peaks 318 k/s), kernel CPU 18%. Steps from here are timed by the launcher log
  (`loader-resume.log`), not the harness.
- Thread sweep (`sweep.sh` in the run folder): each setting restarted at ingest with the
  preload, average rate at 20 M triples:

  | `--ingest-threads` | avg at 20 M |
  |---|---|
  | 3 | 138 k/s |
  | 8 | 254 k/s |
  | **12** | **299 k/s** |
  | 16 | 207 k/s |
  | 24 | 48 k/s |
  | 32 | about 55 k/s (stopped at 10 M) |

  The roof is around 12 on this machine (M2 Pro, 12 cores, 32 GB): fewer threads leave
  too few page reads in flight; more make the kernel's page-fault handling for the one
  mapped file the limit (kernel CPU 18% at 8, 25% at 12, 86% at 32). Linux may differ.
- Heap test (`heap.sh`), 12 threads, average at 50 M: 8 GB, 4 GB, 2.5 GB with a 5 M
  cache. New in build `ingest-heap`: `JVM_ARGS_INGEST` in the launcher (the ingest
  step's JVM arguments in place of `JVM_ARGS`) and the system property
  `jena.xloader.ingest.cacheSize` (parallel ingest's cache, default 10 M entries).
  Ingest's live heap is mostly that cache: at 15 M triples the old generation held about
  2 GB and was still growing. Each GB less heap is about 2.6% more of `nodes.dat` in the
  page cache.

  | Ingest heap | cache | avg at 50 M |
  |---|---|---|
  | 8 GB | 10 M | 289 k/s |
  | 4 GB | 10 M | 285 k/s |
  | **2.5 GB** | **5 M** | **347 k/s** (+20%) |

  The heap alone made no difference, the smaller cache did: probably the cost of a large
  Caffeine cache (maintenance, a heap of long-lived small objects for the GC) rather than
  more page cache. Not yet tested: 1-2 M entries. Ingest continues with 2.5 GB / 5 M
  from 21:45 (about 6.5 h at this rate).
- **Node table in memory (`--node-table-in-memory`, build `compact-table`)**: the idea
  below, implemented (`CompactNodeTable`, `EliasFano`). Truthy: 1,609,180,945 terms in
  8,305 MB, built in 124-126 s from the B+tree (after the preload). With 12 threads, a
  1 M cache and the table, ingest ran at **2.9 M triples/s** (avg 2.92 M at 905 M
  triples), against 347 k/s at best without it; CPU 60% user, 5% kernel. Needs the old
  generation to hold the table: `-Xmx13G` (ParallelGC's default 1/3 young) left the old
  generation full and gave about 3.5 full GCs a second; `-Xmx12G -Xmn1536M` (old 10.5 GB)
  was normal (young GCs, 2 full). Stopped at 905 M for the main comparison below.
- Resumed 22:27 with the table (`-Xmx12G -Xmn1536M`, 12 threads, 1 M cache): table built
  in 127 s; **ingest of all 8,261,251,250 triples in 45:40 (2,739.5 s), 3.02 M
  triples/s**, steady at about 3.0 M/s from 200 M on. Workfile `triples.tmp.gz` 57 GB.
  Old generation full again but harmless: about 3 full GCs per 30 s, 1.5% of the time;
  `-Xmn1G` or a slightly larger heap would give it more room.
- SPO index build from 23:15:34 (sequential, uu-sort 1024M, pigz -1, 8 threads): spill
  files of 10.5 M rows, 70-87 MB compressed (about 8 bytes a row); 3.6 billion rows
  sorted in 13.5 min (4.5 M rows/s), so the run phase about 30 min, about 785 spill
  files, 60-70 GB (not the 170 GB estimated). Estimated SPO done about 00:25-00:35,
  all three indexes about 03:30-04:30. Run continues from `resume.sh`; step times in
  `loader-resume.log`.
- Estimated full run with these settings: node table 1:34 + ingest about 0:48 + indexes
  about 4:15, so about 6:40 (the first truthy run was heading for 15 h or more; main's
  ingest alone about 2 days).
- **main's ingest on truthy** (build `baseline`, same JVM: Java 25, 8 GB, ParallelGC),
  on an APFS clone of this run's database (node table from the branch, same format),
  cold page cache, no preload: 34 k rising to 60 k per batch, **48.6 k triples/s on
  average at 10 M**, one thread at 0.4 cores. About 2 days for truthy's ingest: the slow
  ingest at this scale is in main, not from the branch's changes.
- Idea behind the table (from before it was implemented): a compact in-memory hash -> NodeId table. The node
  table step gives NodeIds in hash order (terms written sorted by hash, NodeId = offset),
  so both sequences are sorted and compress well (Elias-Fano style): about 5-6 bytes per
  term, about 9 GB for truthy instead of 39 GB of B+tree leaves. Built by ingest at
  startup from one sequential read of `nodes.dat` (like the preload), checking the
  NodeIds increase; B+tree only for what the table lacks. Benchmark first on lexemes.

### Term index decoder threads (2026-10-04, uncommitted; not yet measured)

`--term-threads=N` (default 1, the behaviour before). In the second truthy run the term
index ran at 1.11 M terms/s with Java at about 1.3 cores: the single decoding thread
(hex, Thrift check) was the limit. `SortedNodeRecords` now has a reader thread cutting
1 MB blocks at line ends and numbering them, N decoder threads, and the iterating
thread taking decoded blocks strictly in order (the B+tree is packed in hash order).
At most 4N blocks are in flight. Errors are the same as with one decoder (tested with
1 and 4). Expected: perhaps 2-3x, until the writer or the sort's final merge limits.
To measure after the truthy run: `TestXLoaderTermIndex` variants `pipeline`,
`pipeline2`, `pipeline4` on the 20M lines.

### Sort merge passes (2026-10-04, notes; not pursued)

uu-sort's `--buffer-size` is the segment size (one spill file per segment); the number
of files merged at once is `--batch-size` (default not shown in the help; this run
suggests 64). Truthy node sort, 1024M segments: about 100 GB of compressed spills, so
roughly 600 files; one intermediate pass merged them into 9 files of about 9.3 GB
(about 9 minutes), then the final pass streamed into the term index. Doubling the
segment size would still leave more files than the batch size, so the intermediate pass
would remain. Skipping it needs files <= batch size, for example 4096M segments (sort
memory about 11.6 GB) with `--batch-size=160` (about 150 decompressors at once in the
final pass). Saves about 9 minutes on the node sort, perhaps 10-20 per index sort;
judged not worth the complexity for now. Would need `UU_SORT_BATCH` in
`tools/uu-sort-xloader`.

### Faster term index (2026-10-04, uncommitted; plan item 5)

The term index step (node table stage, after the sort) took 49:41 on one thread for
truthy's 1.61 G terms, at a constant 540 k terms/s. It read the sorted node lines one
byte at a time (`hexRead`, two `input.read()` per byte through `SortProcess`'s
cancellation check). Now `SortedNodeRecords`, in two stages: a reader thread reads 1 MB
blocks, decodes hex through a table and checks each term with `ThriftConvert`
(about 10% of the step; kept: without it a corrupt term would only show when read back
by a query); the thread packing the B+tree appends to the object file. Same records and
object file. Behaviour change on bad input only: an empty line is now an error (before,
it silently ended the term index). Tests: `TestSortedNodeRecords` (6).

`TestXLoaderTermIndex` (jena-benchmarks-xloader-jmh), `lexemes-20M.nt.gz`, 4.65 M terms
(`TestXLoaderTermIndex_20261004191541.json`):

| Variant | Time | Terms/s |
|---|---|---|
| `before` (previous reader) | 9.51 s | 489 k |
| `bulk` (one thread) | 4.97 s | 936 k |
| `bulkNoCheck` | 4.53 s | 1.03 M |
| `pipeline` (now in xloader) | 4.18 s | 1.11 M (2.3x) |

The reader stage is the limit; next, if wanted: several decoder threads with results
handed on in order. For truthy, about 50 min down to roughly 22 (estimate). Not yet
measured in a load (also shows whether `sort`'s final merge keeps up).

Also new (2026-10-04): the ingest workers share one Caffeine cache (10M entries in
total) instead of one each (`ParallelIngest.SharedCache`; system property
`jena.xloader.ingest.sharedCache=false` for the old behaviour). Caffeine is
`CacheFactory.createCache`'s implementation, as for TDB2's node table cache; Jena moved
from Guava's cache to Caffeine in 2023 (GH-1913).

### Full truthy run (2026-10-04, cancelled during ingest)

Run `/Volumes/SamsungSSD/xloader-benchmark/runs/truthy/20261004T142631Z-b47c71ba`, label
`uusort1024M-pigz1-t8-pt6-j25par8g-cnodes`: `build/final`, database on the external SSD
(USB4, 40 Gb/s, 3.3 GB/s sequential write), tmp on the internal disk, sequential
indexes, `--parse-threads=6`, `--sort-compress-nodes`, Java 25 `-Xmx8G` ParallelGC.

- Node table: 1:58:15. Parse 59:14 for **8,261,251,250 triples** (2.32 M/s throughout);
  node sort merge about 9 min (tmp peak about 101 GB compressed); term index 49:41 for
  **1,609,180,945 terms** (540 k terms/s, constant: sequential writes, single thread).
  Node table files: `nodes-data.obj` 61.9 GB, `nodes.dat` 38.7 GB.
- Ingest (from 18:24:48): about 200 k triples/s with 6 threads. Workers mostly waiting
  on page faults in the memory-mapped `nodes.dat` (Java about 1.1 cores, `kernel_task`
  about 1.0; jstack: `MappedByteBuffer.limit`), which is larger than the page cache.
  At 18:45, after closing Chrome, `nodes.dat` was read once by hand
  (`dd ... of=/dev/null`, 10.4 s at 3.7 GB/s): about 313 k triples/s since (batches up
  to 1.46 M/s). So this run is warmed up by hand from 18:45.
- Cancelled at 18:54 after 405 M of 8.26 G triples in ingest (about 228 k triples/s on
  average; the preload's effect faded as other parts of `nodes.dat` evicted it). At
  that rate ingest alone would have taken 10 hours or more. The run is recorded as
  `failed` (stopped by hand: the harness, started in the background, ignored SIGINT;
  the ingest JVM was stopped with SIGTERM).
- Next truthy run: `--ingest-threads` 32 or more and `--preload-node-table`, or a
  machine where the node B+tree fits in the page cache.
- New options from this (now tested: `ingestThreadsOverride`, `preloadNodeTable`): `--ingest-threads=N` (ingest only; default the `--parse-threads` value;
  more reads in flight when lookups wait on disk) and `--preload-node-table` (ingest
  reads `nodes.dat`/`nodes.idn` once before starting). Both off by default. On machines
  with 64-128 GB RAM the node B+tree (about 39 GB here) fits in the page cache.

### Correctness check of the parallel paths (2026-10-04)

Order-independent fingerprints (scratchpad `diag/CheckDb.java`, read only): every triple
without blank nodes as MD5 of its N-Triples line, summed and XORed; blank-node triples
compared by graph isomorphism; each of SPO, POS, OSP read in full and fingerprinted by
NodeId tuples; the node table's non-blank nodes fingerprinted. About 41 minutes per
database. The 8:15 run (`20261004T105838Z-b1f7532e`) against `baseline-t8`
(`20260930T074510Z-651f55ca`, unchanged code from main):

| | baseline-t8 (main) | 8:15 run |
|---|---|---|
| Triples without blank nodes | 229,009,514 | same count and fingerprint |
| Triples with blank nodes | 1,453 | 1,453, isomorphic |
| Nodes (not blank) | 51,144,369 | same count and fingerprint |
| Blank nodes in node table | 2,906 (1,453 unused) | 1,453 (all used) |
| SPO / POS / OSP consistent | yes | yes |

The parallel paths load the same data as main; only the unused blank node entries are
gone (the shared seed). Blank nodes in Wikidata: 89,760 in the first billion lines of
truthy (one per "unknown value"), 1,453 triples in lexemes.

### Parallel lookups for ingest: JMH (2026-10-04)

`TestXLoaderIngest.resolveCachedParallel` (hash file in fixed 17-byte records split
between threads; each thread has its own read transaction and a cache of 10M/threads
entries), `lexemes-20M.nt.gz`, 3 passes each (`TestXLoaderIngest_20261004112454.json`):

| Benchmark | Mean |
|---|---|
| `ingest` (as now: parse + lookups) | 20.25 s |
| `resolveCached` (lookups only, one thread) | 10.16 s |
| `resolveCachedParallel`, 1 / 2 / 4 / 8 threads | 9.99 / 5.71 / **3.52** / 4.42 s |

Concurrent read transactions work and scale to 2.8x at 4 threads; 8 is slower (smaller
per-thread caches or contention in the B+tree block managers; not investigated).
With parallel parsing (node stage: 2.5x) ingest might drop from about 20 s to 6-8 s per
20 M lines, lexemes ingest from 3:36 to roughly 1:20-1:30 (estimate). Next: implement
(workers parse chunks, look up in their own read transactions, write row batches; misses
to the writer thread); `XLOADER_JMH_INCLUDE` selects benchmarks by method name.

### Parallel parsing in the node table stage (2026-10-04, uncommitted)

`--parse-threads=N` (launcher and `CmdxBuildNodeTable`, default 1 = as before):
`ParallelNodeParser` reads the decompressed input (Java gzip or `XLOADER_DECOMPRESS`)
on the calling thread, cuts 4 MB chunks at line ends, and N workers parse each chunk
with RIOT (N-Triples/N-Quads only; other syntaxes as before). Each worker has its own
`NodeHashTmpStream` (now with its own `Hash` and Thrift serializer instead of shared
static ones) and appends a chunk's sort lines to the sort input under a lock. Blank
nodes: one seeded label policy per file (`LabelToNode.createScopeByDocumentHash(seed)`)
for all chunks. Parse errors report the line in the whole input. Correctness: the
node stage only pre-populates the node table; ingest is unchanged and still decides
every triple (any node missed would be allocated there). Tests: `TestParallelNodeParser`
(7) and `TestXLoader.parallelParseLoad` (isomorphic to an in-memory parse).

Launcher bug found on the way: `-*threads=*` (for `--threads=N`) also matched
`--parse-threads=6` and set sort threads; the `--parse-threads` patterns now come first.

Lexemes, best configuration plus `--parse-threads=6` (`build/pparse`, run
`20261004T011146Z-7d5a73e5`):

| | parallel + rapidgzip | + `--parse-threads=6` |
|---|---|---|
| Parse (nodes) | 229.3 s (1.00 M/s) | 90.0 s (2.55 M/s) |
| Node table | 5:32 | 3:13 |
| Ingest | 3:34 | 3:36 |
| Indexes (wall) | 3:25 | about 3:28 |
| Total | 12:33 | 10:19 (-59% against baseline-t8, 25:23) |

Counts identical (229,010,967 triples, 51,145,822 terms). 2.5x with 6 workers, not 6x:
the next limit is the reader thread, the lock on the sort input, or sort itself (to
check). Next: shared blank node seed for both stages, then parallel lookups in ingest
(read transactions per worker, misses to the writer).

### `XLOADER_DECOMPRESS` and the truthy prefix (2026-10-04; the option is removed again)

**Removed (2026-10-04):** with parallel ingest and the best JVM setting (Java 25,
`-Xmx8G -XX:+UseParallelGC -XX:+UseCompactObjectHeaders`, 6 threads), ingest alone took
93.6 s with rapidgzip and 93.7 s with Java's own gzip; Java's single-thread inflate keeps
up (rapidgzip alone 2.1 GB/s, Java about 1.1 GB/s, ingest needs about 0.35 GB/s). The
option, its launcher check, the harness `--decompress` and their tests are gone;
`InputFile` only opens files as RIOT does. rapidgzip stays useful outside xloader, for
cutting prefixes. The record below is kept for the measurements.


`XLOADER_DECOMPRESS` (environment variable, unset by default): a program and arguments
that decompress `.gz` input, run with the file name last (`InputFile`); the node table
and ingest steps parse its output instead of decompressing in Java. The launcher checks
it on a small test file and logs it; the harness option `--decompress` sets and records
it. Failures of the program fail the load with its stderr. Tests: `externalDecompress`,
`externalDecompressFailureFails`, `externalDecompressApplies`. Also fixed in the
harness: `--sort-compress` is now passed to launchers that support it, so the
launcher checks `SORT_COMPRESS_ARGS` against the real program (it checked gzip, which
rejected `-p 4`).

Lexemes, best parallel configuration plus `--decompress='rapidgzip -d -c -P 4'`
(rapidgzip 0.16.0, `build/decompress`, run `20261004T004337Z-7602e029`): parse (nodes)
229.3 s (229.1-234.0 s in the three parallel runs), node table 5:32, ingest 3:34
(1.07 M/s against 3:40-3:41), indexes 3:25, total 12:33 (-2% against 12:51). Within
or near noise: decompression in the parser thread costs less in the pipeline than the
2.5 s per 20 M lines measured alone. Worth it only with parallel parsing (then also a
rapidgzip index: `--export-index` in the node stage, `--import-index` in ingest).

Truthy prefix: the first 1,000,000,000 lines cut with
`rapidgzip -d -c -P 8 | head -n 1000000000 | pigz -1` in 4:21; 12.0 GB
(`downloads/wikidata-20260926-truthy-BETA-1b.nt.gz`), pinned as `truthy-1b`.

### Node parser cache: shared or per worker (2026-10-06)

Lexemes, label `uusort1024M-pigz1-t8-parallel-pt6-j25par8g` (as the 8:15 run: uu-sort
1024M, pigz -1, `--threads 8`, `--parallel-indexes`, `--parse-threads=6`, Corretto
25.0.3, `-Xmx8G -XX:+UseParallelGC -XX:+UseCompactObjectHeaders`). `build/review-fixes`
is `5ea675496a` plus the review fixes (#2, #6-#9), with `ParallelNodeParser`'s shared
node cache (one Caffeine `CacheSet` of 500,000 for all workers, review #5) on by default.

| Run | Build | Node parser cache | Power | Parse (nodes) | Term index | Node table | Ingest | Indexes | Total |
|---|---|---|---|---|---|---|---|---|---|
| `20261004T172717Z-0c478c99` | terms-pipeline | 500,000 per worker | not recorded | 84.5 s | 46.7 s | 2:13 | 1:52 | 3:24 | 7:31 |
| `20261006T070230Z-e0c64270` | review-fixes | shared, 500,000 | battery | 94.1 s | 47.7 s | 2:23 | 1:54 | 3:22 | 7:41 |
| `20261006T072231Z-0d4ea665` | review-fixes | shared, 500,000 | AC | 94.5 s | 43.8 s | 2:20 | 1:53 | 3:18 | 7:31 |
| `20261006T073325Z-a355af21` | review-fixes | 500,000 per worker (`-Djena.xloader.nodes.sharedCache=false`) | AC | **83.3 s** | 45.1 s | **2:10** | 1:53 | 3:16 | **7:21** |

Counts identical in all four (229,010,967 triples, 51,145,822 terms). Max RSS 16.8 GB
in both AC runs.

- The shared cache costs about 10 s (11%) of parsing, on battery and on AC alike. It
  sends 12% fewer node lines to sort (54.3 M against 61.8 M per worker), since every
  worker skips nodes the others have written, but the term index gains only a second
  or two from that. Likely cause: six workers contending on one Caffeine cache for
  about 690 M lookups. In ingest a hit saves a B+tree read, so a shared cache pays off
  there; here a hit only saves writing one line for sort.
- `SharedWorkfileReader` (first loads with it): index stages within a few seconds of
  before, so no cost, and no measurable gain with these sorts.
- The 7:41 run started while Defender and Spotlight scanned the new build (about 100%
  CPU) and on battery; its parse matches the AC run, so neither explains the 10 s.
- The first AC run started at a 1-minute load average of 2.97, the second at 4.2 (after
  the script's 3-minute wait for below 3 ran out), and was still the faster one. One
  run of each setting on AC.

**Change (after these runs):** one cache per worker again by default
(`jena.xloader.nodes.sharedCache=true` for the shared one), with a total cap against
review #5: each worker has 500,000 entries (as the single-threaded parser), or an equal
share of the total for more than 6 workers. The total is 3,000,000 entries unless the
system property `jena.xloader.nodes.cacheSize` is set (the shared cache has the total).
So `--parse-threads=6` is unchanged from the 7:21 run, and 32 threads hold 3 M entries,
not 16 M. The node table step logs the sizes ("Node cache: ...") and checks the
property before opening the database.

Measured (2026-10-07), `3d930b8dea` (`build/node-cache`; the rebuild from the commit is
identical), same settings, run `20261007T065315Z-4a3b09b1`, **on battery** (75%):
log "Node cache: 500 000 entries for each of 6 workers"; parse (nodes) 86.2 s, term
index 45.9 s, node table 2:14, 61.3 M node lines to sort (as per worker before), ingest
1:53, SPO / POS / OSP 2:52 / 3:27 / 3:10, total 7:36, max RSS 15.0 GB; counts identical.
The node table is as with per-worker caches on AC (2:10, not 2:20 shared). The index
stages, which this change does not touch, were about 11 s slower than on AC; the
battery run of 2026-10-06 was about 4 s slower there, so battery or noise.

### Node table sort lines written in one call (2026-10-07, uncommitted)

Second review #11: `NodeHashTmpStream` wrote each sort line a byte at a time (`hexWrite`,
`write(int)` twice per byte), as on `main`; each `write(int)` takes the output's lock
(`BufferedOutputStream`, or the parallel workers' `ByteArrayOutputStream`). Now the line is
encoded into a reused 4 KB buffer (a longer line gets its own array) and written once.

JMH `TestXLoaderParse.nodeTable` (`checking=true`, one thread, `lexemes-20M.nt.gz`, 1 warmup
and 3 measured passes), Corretto 25 `-Xmx8G -XX:+UseParallelGC -XX:+UseCompactObjectHeaders`,
on battery, builds alternating (`build/node-cache` before, `build/hexline` after); script and
results in the session scratchpad (`jmh-hexline.sh`, `jmh/`):

| Run | Build | Passes | Mean |
|---|---|---|---|
| 1 | before | 29.26 / 29.97 / 30.38 | 29.87 s |
| 2 | after | 26.91 / 27.08 / 26.92 | 26.97 s |
| 3 | before | 29.57 / 29.16 / 28.84 | 29.19 s |
| 4 | after | 26.15 / 26.18 / 26.03 | 26.12 s |

About 3 s (10%) less per 20 M lines on one thread; every pass after is faster than every
pass before. For lexemes (11.5 times the lines) about 35 CPU-seconds less in the parse
(nodes) stage, at most about 6 s of its 83 s with 6 workers. Not yet measured in a load.
Test: `TestParallelNodeParser.nodeLineFormat` (lines byte for byte as before).

### Further xloader improvements (2026-10-03, proposed)

Within xloader, keeping Jena's parser and the loader's design. Measured basis: the
fastest run (`async-uusort1024M-pigz1-t8`, 15:11) used 2,906 CPU-seconds in 912 s,
3.2 of 12 cores on average; most remaining gain is in idle cores. Rejected or parked:
validate once (no gain), the Vector API (no gain over SWAR), parse once (hash file too
large for truthy), JDK 25 options (no gain), the byte-keyed term cache (too many cases
for equivalence; see the prototype).

1. **Build SPO, POS and OSP at the same time** (largest expected gain). Now sequential:
   1:29 + 2:14 + 2:00. Each reads the same workfile with its own sort; none uses the
   whole machine. Running them in parallel might approach the slowest one (guess:
   saving about 3 minutes of 15). Needs: the launcher starting the three index
   processes together (check how the stages commit, as they share one database
   directory); sort memory shared (`--sort-buffer`, item 2; uutils 1024M segments
   already fit); peak tmp use rises (three sets of spills). Off by default, for example
   `--parallel-indexes`.
2. **`--sort-buffer=SIZE`** for all sorts (default `50%`), optionally
   `--sort-buffer-nodes`. Replaces the uutils wrapper; needed for 1.
3. **Parallel parsing with Jena's own parser** (idea 6, the safe form). Split the
   decompressed input at line ends; each chunk parsed by RIOT's N-Triples/N-Quads
   parser, so no equivalence argument is needed (one statement per line). Node stage:
   order irrelevant, hashing can be spread too. Ingest: chunks in order; the node table
   lookups then limit (measure with JMH). Needs item 4.
4. **A fixed blank node label seed per load.** Each parse labels blank nodes with a new
   random seed (`LabelToNode.createScopeByDocumentHash()`), so the node stage's entries
   for blank nodes are never found again and ingest allocates them a second time.
   RIOT has the seeded form (`createScopeByDocumentHash(UUID seed)`, "if repeated runs
   must give identical allocations") and `RDFParserBuilder.labelToNode(...)`. The
   launcher would create one seed per load and pass it to both stages. Each input file
   needs its own seed derived from it (for example from the load seed and the file's
   position), so equal labels in two files stay different blank nodes, as now.
5. **Faster term indexing in the node stage** (about 100 s, 445 k terms/s). The sorted
   node output is read by `hexRead`, one `input.read()` per byte, each through
   `SortProcess`'s cancellation check. Read blocks and decode hex in bulk; same output.
   Measure first (JMH reading records from a sorted file).
6. **Cheaper hex output in the node stage** (parser idea 2). Hidden behind the parse
   since `AsyncParser`; matters once item 3 makes the consumer the limit.
7. **Practical:** a disk space estimate before loading (truthy); document the
   measured best settings in the launcher help and the harness README; report the
   Ubuntu uutils issue and the `AsyncParser` interrupt issue.

Suggested order: 2 then 1 (small changes, large expected gain, one lexemes run each);
4; 5 with a JMH benchmark first; 3 as the larger piece once 4 is in.

## Slow OpenStack volumes (notes, 2026-09-29)

From earlier experience: xloader spent a lot of time waiting for I/O on OpenStack
volumes with slow writes. Notes for a load there:

- The 512-byte gzip buffer is probably not the problem: small writes go to the page
  cache, not the volume, unless mounted `sync`/`dirsync` or with `O_DIRECT`. Linux
  mounts ext4/XFS `async` by default (check with `findmnt -no OPTIONS <dir>`). TDB2
  still `fsync`s at the end of each stage, by design.
- The index builds read the workfile, write and merge spills and write the B+Tree at
  once, on one volume: probably the worst case. Put `--tmpdir` on another volume. A
  `mass_storage_ssd` volume for the temporary directory is planned; about 400 GB for
  truthy (estimate: workfile about 45–55 GB, index spills about 50 GB plus up to 2x
  during merges, node-table spills possibly 150–200 GB uncompressed; database about
  700 GB at lexemes' 87 bytes/triple). Measure a truthy prefix with `--tmp-home` and
  `lowest_free_bytes` first.
- On a slow disk the compression trade-off reverses: `--workfile-gzip-level=6` (or
  higher) and pigz at a higher level may be faster than level 1. Node-table spills are
  uncompressed (`CompressSortNodeTableFiles=false`); making that configurable would
  help there.
- Other levers: earlier write-back (`vm.dirty_background_bytes`, e.g. 256 MB), larger
  read-ahead (`blockdev --setra`), more RAM for larger sort buffers.
- Diagnose with `iostat -x 5` (`%util`, `await`) and `vmstat 5` (`wa`) per stage, and
  measure the volume with `fio` (sequential 1 MiB writes and reads, `--direct=1`).

## Further experiments and ideas (2026-09-29)

Hypotheses and candidate factors, not measured unless stated.

### Run matrix

| Label | Build | Sort | Sort compressor | Question |
| --- | --- | --- | --- | --- |
| `baseline` | baseline | GNU | gzip | Reference |
| `baseline-pigz` | baseline | GNU | pigz | Effect of pigz without the code change (the harness wrapper can swap the compressor for any build) |
| `current` | current | GNU | gzip | Effect of the code change; mainly the workfile gzip defaults (done) |
| `current-pigz` | current | GNU | pigz | Faster spill compression (done) |
| `current-parsort` | current | parsort | gzip | Parallel sort frontend |
| `current-parsort-pigz` | current | parsort | pigz | Both |
| `current-rustsort` | current | uutils `uu-sort` | gzip | Alternative implementation |
| `current-rustsort-pigz` | current | uutils `uu-sort` | pigz | Both |

- Run `check_sort.py` on parsort and `uu-sort` first. They must accept xloader's
  options unchanged, and parsort must pass `--compress-program` on to its child
  sorts. Otherwise the `-pigz` variants measure nothing (check `sort_compress_calls`).
- The full factorial is too large for the disk and the time. Change one factor at a
  time, starting with `baseline`, then `baseline-pigz`.

### Other factors

1. **Sort threads (`--threads` → `sort --parallel`)**: the harness default is 2 on
   8 performance cores. Try 8 with pigz; likely the most direct lever for POS.
2. **pigz threads (`-p`)**: the default is the number of online processors (12 here),
   compressing in 128 KiB blocks; decompression is essentially single-threaded
   whatever `-p` is. sort runs the compressor as a bare program (`PROG`,
   `PROG -d`), so a different `-p` needs a wrapper script (`exec pigz -p 4 "$@"`)
   passed as `--sort-compress`. It matters mainly with more sort threads, when sort
   and pigz compete for cores. If worth keeping: first a harness option
   (`--sort-compress-threads`), and only later a generic Jena option
   (`--sort-compress-args`, which has to generate the wrapper itself).
3. **Workfile gzip settings**: `baseline` vs `current` mixes the level and the
   buffer. Separating them needs `--workfile-gzip-level`/`--workfile-gzip-buffer`
   runs, which needs the harness `--xloader-arg` option.
4. **Uncompressed workfiles (`CompressDataFiles=false`, experiment D)**: removes
   one compression and three decompressions per load; not yet a command-line option.
5. **JVM**: OpenJ9 (Semeru) is optimized for footprint and startup, HotSpot for
   sustained throughput. Each stage lasts minutes, so HotSpot is expected to be as
   fast or faster. One Semeru comparison run, looking only at node table and ingest.
6. **GC and heap**: the default is G1; Parallel GC often gives more throughput for
   batch jobs. Heap size probably matters more than the collector. First measure with
   `-Xlog:gc:file=gc-%p.log:uptime`; drop GC from the matrix if pauses are under a
   few percent. The log path is relative to the JVM's working directory, so a
   harness option should put it in the run directory.
7. **Temporary files on another disk (`--tmp-home`)**: once the external SSD is
   mounted, so spills don't compete with index writes.
8. **Sort buffer size**: fixed at `--buffer-size=50%` (about 16 GB), not exposed.
   For uu-sort see "uutils sort findings".
9. **Compressor arguments: implemented, uncommitted.** Environment variable
   `SORT_COMPRESS_ARGS` (like `JVM_ARGS`), e.g. `SORT_COMPRESS_ARGS="-1 -p 4"`;
   combinable (`export SORT_COMPRESS_ARGS="-1 $SORT_COMPRESS_ARGS"`, later arguments
   win). Unset: no change at all. Set: the launcher passes
   `--compress-program=bin/xloader-sort-compress` (new script), which runs
   `$XLOADER_SORT_COMPRESS $SORT_COMPRESS_ARGS "$@"` (globbing off); both variables
   reach the compressor through Java and sort's inherited environment. Default
   program gzip if no `--sort-compress`. The round-trip check runs through the
   wrapper and names program and arguments on failure (exit 9, before the load). The
   launcher's internal array `SORT_COMPRESS_ARGS` (new in `7eaccb4124`, not in 6.2.0
   or `main`) is renamed `SORT_COMPRESS_PROGRAM`. Tested by hand on 300,000 lexemes
   lines with a 1M-buffer test sort and a logging compressor: arguments arrive as
   `[-1 -9]` / `[-1 -9 -d]` (106 calls each); unset gives `[]` / `[-d]` as before;
   gzip default works; bad arguments stop before the load; counts identical
   (299,098). No automated test yet (the launcher has none).
   Note: `--compress-program="pigz -1"` does not work: GNU sort treats the whole
   value as a program name, warns, and silently continues without compression.
10. **Compressor level and format for the spills.** The spills are temporary, written
   once and read once or twice. pigz defaults to level 6; `-1` is several times faster
   on these hex rows, with larger files. Wrapper needed (`exec pigz -1 "$@"`; `-d`
   ignores the level). Alternatives: zstd (`zstd -1 -T0`, much faster decompression,
   which pigz can't parallelize) and lz4 (faster still, larger); `brew install zstd lz4`.
   Upper bound without a code change: a no-op compressor (`exec cat`). Plan: sort-only
   test on the full SPO workfile, compressors {cat, pigz -1, pigz, zstd -1 -T0, lz4} ×
   {GNU sort `--parallel=8`, uu-sort 1024M}, outputs compared, spill sizes recorded;
   about 10 runs of 1–2 min. Run it when no load is running.
11. **Whole-line index sorts.** Workfile rows are fixed-width hex IDs in SPO order, so
    for SPO the three keys equal a plain whole-line sort (with `LC_ALL=C`), and
    `--unique` on all keys equals whole-line uniqueness. POS and OSP can use two keys
    (`--key=2,3 --key=1,1`, `--key=3,3 --key=1,2`). Better: Java writes each row in the
    index's column order before piping it to sort, so every index sort becomes a
    keyless whole-line sort (small change in `ProcBuildIndexX`, and the B+Tree builder
    reads the columns in index order). Likely helps GNU sort too. Check output
    identity with `cmp`. Context: first suggested when uu-sort's key comparison
    (`compare_by` in the stack sample) looked like the cause of its slowdown. The
    real cause was the segment size; uu-sort is fast with three keys. So this is a
    possible speed-up for both sorters, not the uu-sort fix. Measure it sort-only
    first (keys vs no keys, both sorters, SPO and a column-reordered POS sample).
12. **JDK 25 (HotSpot).** Jena needs at least 21. AOT cache (Leyden) and native image
    target startup and gain nothing here; compact object headers
    (`-XX:+UseCompactObjectHeaders`, product in 25, off by default) may gain a few
    percent in the node-table and ingest stages. Compare JDK 25 with and without it;
    keep one JDK fixed across a series. `brew install --cask corretto@25`.

    **Result (2026-10-03): minimal change; not pursued.** Corretto 25.0.3 with
    `-Xmx4G -XX:+UseCompactObjectHeaders -XX:+UseParallelGC`, otherwise as
    `async-uusort1024M-pigz1-t8` (Corretto 21.0.12, G1, 15:11); run
    `20261002T230631Z-d9ffb054`, stopped during ingest: parse 237.0 s (against
    239.5 s), node table 5:40 (against 5:39), ingest at 1.02 M triples/s on average
    (about the same as 3:44). The index sorts run outside Java. The runs of JDK 25
    alone and with compact headers alone were not made.

### Scaling to truthy (hypotheses)

- Truthy is roughly 30–35 times lexemes (about 7–8 billion triples; check the
  current dump). Nearly all index-sort input would spill, and with hundreds of spill
  files GNU sort merges in several passes (`--batch-size` 16 by default), each
  decompressing and recompressing. So pigz's gain should grow, both absolutely and
  as a share of the index builds.
- Limits: decompression doesn't parallelize, the node-table sort spills uncompressed
  (`CompressSortNodeTableFiles=false`), and sort, pigz and Java share 8 performance
  cores. A slow disk may become the limit instead.
- Truthy doesn't fit on the internal disk (database likely several hundred GB, plus
  workfile and spills). First test scaling on a 1–2 billion line prefix of truthy,
  comparing gzip and pigz.

### Harness improvements

- [x] Comparison table: `compare.py` (separate script, not a `benchmark.py`
  subcommand). One row per run with build, sorter, compressor, threads, stage and
  index times, wall-clock and monotonic totals, change against `--reference`, triple
  and term counts, compressor calls, max RSS and flags (slept, unfinished, differing
  counts); markdown, CSV or TSV. `--reference` uses the first run with that label
  and no flags (fixed 2026-09-30: it took the slept `current-pigz-t8`). 13 unit tests
  in `test_compare.py`.
- [x] JMH module `jena-benchmarks/jena-benchmarks-xloader-jmh` (2026-09-30), next to
  the Python harness. Skipped unless `-Dbenchmark.skip=false`. `TestXLoaderParse`
  measures the node-table parse step without sort (parser ideas 1 and 5):
  `parse`/`parseAsync` into a counting stream and `nodeTable`/`nodeTableAsync` into
  `NodeHashTmpStream` with a buffered null stream, each with `checking` true and false.
  Input from `XLOADER_JMH_DATA`. First results under "First JMH measurement".
- [ ] Optional cleanup of `database/` and `tmp/` after a successful count, keeping
  logs and `run.json` (disk space limits the matrix).
- [ ] `--xloader-arg` for extra launcher options (workfile gzip, later others).
- [ ] Record `threads`, compressor threads and GC logs in `run.json` when set.

### Measurement protocol

- At least two runs per configuration, interleaving configurations.
- Consistent cache state: either always warm (read the input once before each run)
  or `sudo purge` before each run; record which in `--cache-note`.
- Check the count against 229,010,967 for every lexemes run.

## Phase 2: sorter compatibility and isolated experiments

Current code launches GNU sort with `LC_ALL=C`, field keys, uniqueness,
`--parallel`, a 50% buffer-size setting and a selected temporary directory.
Index sorting also enables external gzip compression of sort workfiles by
default. Node-table input is piped from the parser. Index input is normally
decompressed by Java from an intermediate file and piped to sort. Disabling
intermediate-data compression makes index sorting pass a filename directly.

| Candidate | Reason to investigate | Required evidence |
| --- | --- | --- |
| GNU sort 9.12 | Current baseline; thread/memory tuning reference | Recorded settings and repeated runs |
| GNU Parallel `parsort` | Different parallel sorting strategy; direct files may help | Pipe and file tests; total memory across workers |
| uutils sort (`uu-sort`) | Rust coreutils implementation | Exact option semantics and output agreement under forced spilling |
| `acefsm/rust_sort` | Separate Rust implementation | Compatibility review before including in timed comparisons |

These are distinct implementations. Language choice and advertised speedups do
not establish an improvement for this workload. Documentation reviewed during
planning: [parsort](https://www.gnu.org/software/parallel/parsort.html),
[uutils sort](https://uutils.org/coreutils/docs/utils/sort.html),
[Homebrew uutils-coreutils](https://formulae.brew.sh/formula/uutils-coreutils),
[acefsm/rust_sort](https://github.com/acefsm/rust_sort).
Homebrew provides uutils as `uu-sort`; installation is optional. Preserve GNU sort
as the baseline command until a candidate is deliberately selected.

- [ ] Pin each candidate version/build and verify the actual xloader arguments,
  including percentage memory sizing and compression behavior.
- [ ] Compare sorted output to GNU sort using realistic node-hash and tuple rows.
- [ ] Verify `--unique` by key for node records, and every triple/quad key order.
- [ ] Force multiple spill runs with a small memory budget; include duplicates
  across run boundaries, empty input, long rows and stdin input.
- [ ] Check nonzero exits and diagnostic output on read/write/compressor failures.
- [ ] Preserve representative intermediate input for sorter-only timing.

Select only the sorter for these experiments. Prepending an entire alternative
coreutils suite to PATH would change other commands too. A dedicated directory
containing only a `sort` wrapper/symlink can isolate selection without changing
xloader source. The present harness preflight is not a compatibility test and
has GNU-specific error wording; review it when adding candidate selection.

## Phase 3: import performance matrix

Run compatibility checks before full imports. Change one factor at a time.

| Experiment | Intermediate index input | Sorter | Question |
| --- | --- | --- | --- |
| A: baseline | Compressed, piped | GNU sort | Current behavior |
| B | Compressed, piped | parsort | Does replacement alone improve the existing pipeline? |
| C | Compressed, piped | uutils sort | Does a Rust sorter improve the existing pipeline? |
| D | Uncompressed file | GNU sort | What is the cost/benefit of changing intermediate storage? |
| E | Uncompressed file | parsort | Does parallel file access justify additional disk use? |
| F, optional | Uncompressed file | uutils sort | Is its file path materially better than its stdin path? |

Intermediate compression is currently a Java setting, not an exposed benchmark
CLI option. Record any configuration/build change needed for D–F. Source RDF
compression and sort's own temporary-file compression are separate variables;
hold those fixed initially. Do not bundle cleanup changes into these comparisons.

Use lexemes to narrow the candidates, then measure selected configurations on the
same truthy snapshot. Lexemes may fit in memory where truthy spills; a local win
does not predict a large-scale win. Measure whole-import time as well as sorting
stages, since parsing, compression, index writing and shared-drive I/O may dominate.

Materializing node-table parser output before sorting is a separate, later
experiment: include the materialization time and extra disk usage in its result.

## Phase 4: resource cleanup investigation

Reproduce and address independently of sorter performance changes:

- [x] `ProcBuildIndexX`: explicitly close the decompressed intermediate input
  stream with try-with-resources.
- [x] `ProcBuildIndexX`: extend cleanup to failures during feeding and index building; expel the
  dataset on failure as well as success.
- [x] `ProcBuildNodeTableX`: propagate parser/builder thread failures to the
  controller; close owned pipes and cancel remaining work on failure.
- [x] Both sort stages: drain or redirect stderr while the child runs; stop and
  reap subprocesses on error/interruption; preserve useful diagnostics.
- [x] `ProcIngestDataX`: close intermediate outputs and release dataset resources
  when parsing, writing or finishing fails.
- [x] Review owned node-table state channels and flush/close exception handling
  in these three stages; retain primary exceptions through suppressed cleanup errors.

Use small deterministic failure tests for malformed RDF, a failing sort stub,
large stderr output, interrupted work, and simulated write errors. Bound test
runtime and check for surviving threads/processes and open resources. Avoid a
real disk-full experiment on the benchmark drive. Ordinary successful benchmark
runs alone cannot establish correct failure cleanup.

### First fix validation (2026-09-29)

The patch changes only the scope of `IO.openFile(datafile)` to try-with-resources.
It closes the input after a successful transfer and when transfer or output close
throws; it does not yet fix subprocess cancellation or other resource ownership.

Validation:

- `mvn -o -pl :jena-tdb2 -am -Dtest=TS_Loader -Dsurefire.failIfNoSpecifiedTests=false test`:
  70 tests passed. These are the existing loader tests, not dedicated xloader tests.
- A temporary Java probe ingested three RDF statements (two distinct triples),
  built SPO/POS/OSP with real GNU sort and gzip intermediates, and reopened the DB.
  Both original and patched code returned two distinct triples.
- With Epsilon GC (`-XX:+UnlockExperimentalVMOptions -XX:+UseEpsilonGC -Xmx1g`),
  `lsof` showed 1/2/3 open `triples.tmp.gz` descriptors after successive index builds
  in the original code, versus 0/0/0 with the patch. Normal GC masked the retained
  descriptors in the initial tiny run, so this is an ownership regression check,
  not a production descriptor-growth or performance measurement.

The probe used all three stages in one JVM to expose accumulation. The usual shell
launcher uses separate JVMs per stage, limiting accumulation after each JVM exits.

### Broader cleanup and validation (2026-09-29)

Implemented changes:

- Shared `SortProcess` manages the child process and workers, feeding stdin and
  draining stdout/stderr concurrently. Retained stderr diagnostics are capped at
  64 KiB while the entire stream is drained.
- Worker failures and nonzero sort exits propagate to the caller. Both builders
  check input production and sort completion before committing their transactions;
  sort failures no longer call `System.exit`.
- Cleanup stops subprocesses and joins workers, closes pipes, and preserves the
  caller's interrupt status. Dataset release runs on failure as well as success.
- Node-table building closes its owned state channel and propagates malformed
  sorted records and node-output failures instead of printing and continuing.
- Ingestion closes both intermediate outputs before publishing load information,
  including when parsing or opening the second output fails.

Validation supplied by the user from IntelliJ's Maven environment:

```sh
mvn -o -pl :jena-tdb2 -am -Dtest=TS_XLoader \
  -Dsurefire.failIfNoSpecifiedTests=false test
```

The run finished at 15:26:19 CEST: **11 tests, 0 failures, 0 errors, 0 skipped**.
GNU sort was available to this run. Use IntelliJ as the reference Java test
environment for this checkout until the standalone shell environment is verified.

- Five subprocess tests cover concurrent pipe traffic, producer and consumer
  failures, large stderr with nonzero exit, and interruption with child shutdown.
- Six loader tests cover a complete load with duplicate triples and a named graph,
  all nine index builds and bound/wildcard lookups, malformed RDF, failed output
  opening, malformed index input, and node-output errors. Failure tests include
  database reopen/write and gzip-output checks where applicable.
- The initial default-graph assertion used `Quad.defaultGraphNodeGenerated`;
  correcting the expected results to `Quad.defaultGraphIRI` matches the existing
  `dsg.find()` contract. No production default-graph behavior was changed.
- An earlier full distribution install passed, but skipped three GNU-sort-dependent
  xloader tests. The focused run above subsequently exercised all of them.
- An earlier agent-run test timed out acquiring the writer lock after malformed
  node input. It did not recur in the user's two subsequent GNU-sort runs. Sandbox
  restrictions or differing Java configuration are plausible explanations, not an
  established cause. Record this as unresolved and investigate if it recurs in the
  reference IntelliJ setup.

These results validate the exercised cases only. No large-dataset throughput,
peak-resource, disk-full or sorter-comparison measurements have been recorded.

## Phase 5: correctness and report

- [ ] Verify successful reopen and identical distinct triple counts.
- [ ] Compare fixed query results covering different triple access patterns;
  use dataset-equivalence checks on small fixtures, including duplicate data and
  named graphs. Counts alone are insufficient.
- [ ] Include all measured configurations and repetitions, failures and regressions.
- [ ] Report total/stage times, median and spread where repeated, and measured
  resource usage with accounting limitations.
- [ ] Describe exact dataset/build/tool identities, hardware, storage placement,
  cache protocol and commands so another operator can repeat the work.
- [ ] Separate cleanup fixes, settings changes and algorithm replacements.
- [ ] State conclusions per dataset and machine; avoid projecting published
  48-core or synthetic-sort speedups onto this setup.

Accept an improvement only when output checks pass and its measured benefit
exceeds ordinary run variation without unacceptable memory/disk costs. If truthy
has only one run per configuration, report that limitation explicitly.

## Immediate next steps

Updated 2026-10-07. Best lexemes load: 7:21 (see "Node parser cache: shared or per
worker"). Done since 2026-10-04: the correctness check of the parallel paths, the
faster term index, two code reviews and their fixes (`xloader-review.md`), the coding
conventions (`.claude/skills/coding-conventions`), per-worker node parser caches with a
total cap, one write per node line (JMH: 10% less), the launcher's program check
covering the programs a load runs, `--sort-buffer` left for sort to check, and the heap
note for `--ingest-threads`.

1. Commit the uncommitted work: second review #11 (one write per node line) and
   #12-#14 (progress helper, `InputFile.lang`, shared index name check).
2. ~~Run the full test suites.~~ Done 2026-10-07, a full reactor build with tests
   (BUILD SUCCESS, 9:12) with the uncommitted work in the tree: jena-base 847,
   jena-core 10,179, jena-arq 16,612 (12 skipped), jena-tdb2 941 (76 xloader) and
   jena-cmds 77 tests, no failures or errors; the root module's license check passed.
3. Split the work into PRs against main. Each is built from main without the
   experiments (`jena-benchmarks/`: the Python harness, the JMH modules and their pom
   changes; this plan; `discovered-issues.md`; the `.pyc` files), with the "wip"
   history squashed:
   - Fixes against main: close the workfile input stream (`b7df3069cf`; cherry-picks
     onto main as is); default-graph statements counted as triples
     (`discovered-issues.md` #4); the unused `hashNode` and static `Hash` removed (#5);
     optionally the cleanup and failure handling from `7eaccb4124`, if it can be
     separated from that commit's new options. The stream fix has no practical effect:
     the launcher runs each index build in its own JVM, and `CmdxLoader`, the
     single-JVM version, is only run by hand. Describe it as closing the stream, not as
     a leak.
   - Sort options and the launcher: `--sort`, `--sort-compress`, `SORT_COMPRESS_ARGS`,
     `--sort-buffer`, `--parallel-indexes`, uutils sort (`discovered-issues.md` #2).
   - Speed: parallel parsing and ingest, the term index pipeline, the in-memory node
     table, the shared workfile reader, one write per node line.
4. File the upstream issues drafted in `discovered-issues.md` first, so the PRs can
   refer to them: blank nodes stored twice, uutils sort on Ubuntu, `AsyncParser`
   interrupts, default-graph counts, `hashNode`.
5. PR descriptions: the measured results (lexemes 25:23 to 7:21; truthy once updated);
   the behaviour changes users will notice (workfile gzip level 1 by default, sort
   checks `--sort-buffer`, the program check covers only the programs a load runs);
   the recommended settings (`--parse-threads`, ParallelGC with 8 GB, the heap note for
   `--ingest-threads`).
6. Truthy: update the 2026-10-04 run (database on the external SSD, continued from
   `resume.sh`) from that disk when it is mounted again, and decide then whether the
   `truthy-1b` run from the 2026-10-04 list is still needed.
7. Optional measurements: one write per node line in a full lexemes load
   (`build/hexline`); the G1 rerun for the parse buffer reuse (`xloader-review.md`,
   "Measured: G1 and humongous parse chunks"); whether the shared workfile reader slows
   the parallel sorts.
8. Open review items, not blocking: second review #8 (misleading `AsyncParser` log on
   cancel; with `discovered-issues.md` #3), #10 (duplicated join and reader loops), #9
   and first review #11 (settings as static fields; a follow-up PR), #6 (CR-only line
   ends) and #15 (block reuse in the shared reader), both low priority.
9. Next speed targets, after the PRs: the index stages (3:16 of the 7:21 lexemes load).
10. Still open from the 2026-10-04 list: sort-only compressor test; repeats of the
    baseline runs; JFR profile; `check_sort.py`; OpenStack (see "Slow OpenStack
    volumes").
