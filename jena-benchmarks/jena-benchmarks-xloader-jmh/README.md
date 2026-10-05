# jena-benchmarks-xloader-jmh

JMH benchmarks for parts of the TDB2 xloader, run from JUnit like
`jena-benchmarks-jmh`. They are skipped unless `-Dbenchmark.skip=false` is given.

The whole-load benchmarks (`tdb2.xloader` with sort and compressor choices) are in
the Python harness in `../xloader`.

## TestXLoaderParse

The parse step of the node table stage, without the external sort:

| Benchmark | What each invocation does |
|---|---|
| `parse` | parse the file into a counting stream |
| `parseAsync` | the same, parsing on a separate thread with `AsyncParser` |
| `nodeTable` | parse into the node table stage's `NodeHashTmpStream` (cache, hash, Thrift, hex), written to a buffered null stream |
| `nodeTableAsync` | the same, parsing with `AsyncParser` |

Each is run with `checking` `true` (as xloader does now) and `false`.

The input file is read from the environment variable `XLOADER_JMH_DATA`, any
format and compression RIOT reads, for example `.nt.gz`.

Each invocation is one whole pass over the file (`SingleShotTime`, 1 warmup and 3
measurement iterations, one fork, `-Xmx4G`), so a run is 32 passes. For quicker runs,
point `XLOADER_JMH_DATA` at a prefix of the data:

```
gzip -dc "$JENA_BENCHMARK_HOME/downloads/lexemes.nt.gz" | head -n 20000000 | gzip -1 > "$JENA_BENCHMARK_HOME/downloads/lexemes-20M.nt.gz"
```

## TestXLoaderRead

Reading the input the way the parser does, without parsing, to see how much of a
`TestXLoaderParse` pass is decompression and character decoding. The file is opened
as RIOT opens it (`IO.openFile`, a `.gz` file through `GZIPInputStream`):

| Benchmark | What each invocation does |
|---|---|
| `inflate` | read the bytes in 64 KB blocks |
| `inflateUtf8` | decode to characters (`IO.asUTF8`) in 64 K blocks |
| `peekReader` | read one character at a time through `PeekReader.makeUTF8`, the tokenizer's input |

Same input variable and settings as `TestXLoaderParse`; a run is 12 passes. Run it
with `-Dtest=TestXLoaderRead`.

## TestXLoaderIngest

Would parsing the input only once help? Setup (not timed) builds the node table with
the real node table stage (GNU `sort` on the PATH, or `XLOADER_JMH_SORT`), then parses
the file again into a hash file: per triple position the encoded inline NodeId or the
128-bit node hash, as a single-parse node stage could write it.

| Benchmark | What each invocation does |
|---|---|
| `ingest` | the ingest step as now: parse with `AsyncParser`, look up each node through the node table (10M node cache, cold) |
| `resolve` | read the hash file, look up each hash in the node B+tree |
| `resolveCached` | the same with a cold 10M-entry hash-to-NodeId cache |

All write NodeId rows to a null stream (no gzip). Blank nodes get new labels in every
parse, so their node table entries are never found again: `ingest` allocates them,
`resolve` counts them as missing, and setup checks that only blank nodes are missing.

The database and hash file (up to 51 bytes per triple, about 1 GB for 20M lines) go in
`XLOADER_JMH_TMP` (default `java.io.tmpdir`) and are deleted afterwards. Run it with
`-Dtest=TestXLoaderIngest`.

`resolveCachedParallel` (parameter `threads`: 1, 2, 4, 8) splits the hash file between
threads, each with its own read transaction and a share of the 10M cache: whether
ingest's node lookups can run in parallel (they scale to about 4 threads).

## TestXLoaderTermCache

A prototype of an alternative N-Triples front end (parked): a cache keyed on each term's
raw bytes, checked before the term is tokenized or made into a Node. Compares
`nodeTableAsync` (the node table step as with one parser thread) with `termCache` and
`termCacheIri`; setup checks both write the same node hashes (blank nodes excluded) and
reports the hit rate (about 92% on lexemes). See `xloader-plan.md` for why it is not
used (equivalence with RIOT for every case).

## TestXLoaderTermIndex

The term index step of the node table stage: reading the sorted node lines (`hash
thrift`, both in hex), appending each term to the object file and making the node
table record (hash to NodeId). Building the B+tree from the records is left out (the
same for every variant). Setup makes the sorted lines as a load does
(`NodeHashTmpStream`, then `sort -u` on the hash with `LC_ALL=C`; `XLOADER_JMH_SORT` for
the sort program) and checks that every variant gives the same records and object file.

| Benchmark | What it does |
|---|---|
| `before` | a copy of the previous reader: one byte at a time through `hexRead`, on a stream that checks for cancellation on every read, as `SortProcess` does |
| `pipeline` | the load's reader (`SortedNodeRecords`): block reads, table hex decoding and the Thrift check on a reader thread; object file writes on the calling thread |
| `bulk` | the same decoding on one thread |
| `bulkNoCheck` | the same without the Thrift check |

On `lexemes-20M.nt.gz` (4.65 M terms): `before` 9.51 s, `bulk` 4.97 s, `bulkNoCheck`
4.53 s, `pipeline` 4.18 s (2.3x). The reader thread (decoding and the check) is the
limit of the pipeline.

## Selecting benchmarks

`XLOADER_JMH_INCLUDE` is an optional regular expression for benchmark method names, so
one run need not set up every benchmark, for example
`XLOADER_JMH_INCLUDE='resolveCached|resolveCachedParallel'`.

## Running

Install the Jena modules first (from the top of the repository):

```
mvn -pl jena-tdb2 -am install -DskipTests
```

Then run the benchmark:

```
XLOADER_JMH_DATA="$JENA_BENCHMARK_HOME/downloads/lexemes-20M.nt.gz" mvn -f jena-benchmarks/jena-benchmarks-xloader-jmh/pom.xml test -Dbenchmark.skip=false -Dtest=TestXLoaderParse
```

With the whole lexemes file (the same input as the Python harness):

```
caffeinate -i env XLOADER_JMH_DATA="$JENA_BENCHMARK_HOME/downloads/lexemes.nt.gz" mvn -f jena-benchmarks/jena-benchmarks-xloader-jmh/pom.xml test -Dbenchmark.skip=false -Dtest=TestXLoaderParse
```

Results are written to `TestXLoaderParse_<timestamp>.json` in this directory.
