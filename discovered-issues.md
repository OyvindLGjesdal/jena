# Discovered issues

Issue drafts for Apache Jena found during the TDB2 xloader investigation
(`xloader-plan.md`). Each uses the Jena issue template and describes the behaviour of
6.2.0 / main only.

## 1. tdb2.xloader stores every blank node twice in the node table

### Version

6.2.0 / main

### What happened?

`tdb2.xloader` stores every blank node twice in the node table, and only one copy is used.

The node table step and the ingest step parse the input separately, in separate JVMs, and each parse labels blank nodes with its own random seed (`LabelToNode.createScopeByDocumentHash()`, RIOT's default). So the node table step's entries for blank nodes are never found again: ingest looks up each blank node, misses, and allocates it a second time with `getAllocateNodeId`.

The extra entries are in the final database's node table (`nodes-data.obj` and the node B+tree `nodes.dat`/`nodes.idn`). No triple refers to them (the indexes only contain the NodeIds ingest wrote), so queries are not affected. The cost is:
- an unused node table entry for every blank node;
- writes to the node table during ingest, which is otherwise read-only after the node table step.

Example: a load of the Wikidata lexemes dump (229,010,967 triples, 1,453 of them with a blank node) has 2,906 blank nodes in the node table, of which 1,453 are used by any triple.

For Wikidata this is small: blank nodes are rare there ("unknown value"; about 90,000 in the first billion lines of the truthy dump). For data with many blank nodes (OWL, RDF lists, provenance) the extra entries and allocations add up.

`tdb2.tdbcompact` removes them, since compaction rebuilds the node table from the quads (`CopyDSG.copy`), but it is a full transactional reload and needs space for both generations; not a practical way to clean up after a large load.

Possible fix: use the same seed in both steps. The node table step creates a random seed for the load and saves it in the temporary directory; ingest reads it. Each input file gets its own seed derived from the load seed and the file's position in the input list, and both steps parse with `LabelToNode.createScopeByDocumentHash(seed)`. That keeps RDF's scoping: the same label in one file is one blank node, the same label in two files is two.

Happy to submit a PR if we agree on the approach.

### Are you interested in making a pull request?

Yes

## 2. tdb2.xloader fails on Ubuntu 26.04 LTS: default `sort` is uutils

Reproduction (Dockerfile): `jena-benchmarks/xloader/repro-ubuntu-uutils/`.

### Version

6.2.0 (binary release), Java 21, Ubuntu 26.04.1 LTS

### What happened?

Since Ubuntu 25.10, `/usr/bin/sort` is uutils coreutils (Rust) by default (`/usr/bin/sort -> ../lib/cargo/bin/coreutils/sort`). `tdb2.xloader` runs `sort` with `--buffer-size=50%`, hard-coded in `ProcBuildNodeTableX` and `ProcBuildIndexX`. uutils accepts the percentage but does not treat it as 50% of memory: it sorts in tiny segments and spills tens or hundreds of thousands of temporary files. Under that load, uutils 0.8.0 (Ubuntu 26.04 LTS) emits an extra empty line, and xloader's node-table step stops or fails on it:

```
ERROR Terms           :: Sort RC = 141 : Error:
```

With real data (Wikidata lexemes) the same step fails with `IllegalArgumentException: Bad hex char : 10 (0x0A)` in `ProcBuildNodeTableX.hexRead`.

Reproduce (Dockerfile attached; synthetic data, about 2 minutes):

```sh
docker build -t jena-xloader-uutils .
docker run --rm jena-xloader-uutils                    # tdb2.xloader exit code: 141
docker run --rm -e USE_GNU_SORT=1 jena-xloader-uutils  # loads, 5000000 triples
docker run --rm jena-xloader-uutils repro-sort         # sort alone
```

`repro-sort` shows the root cause without Jena, using the arguments of xloader's index sort on 40 M distinct rows:

```
sort: sort (uutils coreutils) 0.8.0
--buffer-size=50%: exit=0 output lines=40000001 empty lines=1
--buffer-size=1G: exit=0 output lines=40000000 empty lines=0
```

| Ubuntu | default `sort` | xloader 6.2.0 |
| --- | --- | --- |
| 24.04 LTS | GNU coreutils 9.4 | works |
| 25.10 | uutils 0.2.2 | works, but slow (tiny buffer, very many temporary files) |
| 26.04.1 LTS | uutils 0.8.0 | **fails** |

uutils 0.12.0 (Homebrew) rejects `--buffer-size=50%` outright ("invalid --buffer-size argument"), so xloader would fail at the first sort there.

Workaround: GNU sort is still installed on Ubuntu 26.04 as `/usr/bin/gnusort` (package `gnu-coreutils`). Put it first on `PATH` as `sort`:

```sh
mkdir -p ~/gnu-sort && ln -sf /usr/bin/gnusort ~/gnu-sort/sort
PATH=~/gnu-sort:$PATH tdb2.xloader --loc DB data.nt.gz
```

Possible fixes: let the launcher detect uutils (`sort --version`) and prefer `gnusort` or fail with a clear message; make the sort program configurable; pass an absolute `--buffer-size` when the sort is not GNU sort; reject empty or malformed sorted lines in the Java readers with a message naming the sort program.

### Are you interested in making a pull request?

Yes

## 3. AsyncParser: interrupting the consuming thread ends the parse silently

### Version

6.2.0 / main

### What happened?

If the thread consuming an `AsyncParser` is interrupted, parsing stops and the caller sees a normal, successful end of data: no exception, and the thread's interrupt flag is cleared.

- Pull API (`AsyncParser.asyncParseTriples`, `asyncParseQuads`, `streamTriples`, ...): the blocking iterator catches `InterruptedException` and ends; `hasNext()` returns false and nothing is logged.
- Push API (`AsyncParser.asyncParse(..., StreamRDF)`): the receiver catches `InterruptedException`, logs "Interrupted" at ERROR, and returns normally.

The parser's own checks cannot catch this: the parser thread is stopped before it reaches the end of the input, so a partial result looks complete, whatever the syntax. This also applies to `RDFDataMgr.createIteratorTriples/Quads` for syntaxes other than N-Triples/N-Quads, which use `AsyncParser`.

Reproduce (a small Turtle file `data.ttl` with two triples; parse once first so Jena and logging are initialised):

    // Pull: no triples, no exception, interrupt flag cleared
    Thread.currentThread().interrupt();
    Iterator<Triple> iter = AsyncParser.asyncParseTriples("data.ttl");
    iter.hasNext();          // false
    Thread.interrupted();    // false

    // Push: returns normally, logs ERROR "Interrupted", interrupt flag cleared
    Thread.currentThread().interrupt();
    AsyncParser.asyncParse("data.ttl", countingStream);   // 0 triples
    Thread.interrupted();    // false

Who is affected: Java code that reads through `AsyncParser` (directly, or `RDFDataMgr.createIteratorTriples/Quads` for syntaxes other than N-Triples/N-Quads, or the triple/quad iterators of a remote CONSTRUCT/DESCRIBE through `QueryExecHTTP`) and interrupts the reading thread, for example with `Future.cancel(true)`, `ExecutorService.shutdownNow()` or a timeout that interrupts. A remote server cannot trigger it (a dropped or truncated response is reported as an error), and Fuseki and the TDB2 loaders do not interrupt their `AsyncParser` threads.

Elsewhere in the core modules an interrupt becomes an exception (for example `SinkToQueue` throws `CancellationException`; `TransactionCoordinator` restores the flag and throws). `TestAsyncParser` covers cancellation by `close()` and by a failing sink, but not interrupts.

Suggested fix:
- On `InterruptedException` in the receiver and in the blocking iterator, restore the interrupt flag and throw (for example `CancellationException`) instead of ending normally.
- In the close action, retry `join()` until the parser thread has ended, then restore the interrupt flag, so the parser thread is always waited for.
- Add interrupt cases to `TestAsyncParser`.

This changes behaviour for any caller that relies on an interrupt ending the parse quietly.

Happy to submit a PR if we agree on the approach.

### Are you interested in making a pull request?

Yes

## 4. tdb2.xloader: default-graph N-Quads/TriG statements are counted as quads, so the triple indexes are skipped

Reproduction (JUnit): `jena-tdb2/src/test/java/org/apache/jena/tdb2/xloader/TestXLoaderLoadInfo.java`.

### Version

6.2.0 / main

### What happened?

When the input is N-Quads or TriG only, `tdb2.xloader` loads the named graphs but leaves the default graph empty.

The ingest step (`ProcIngestDataX.IngestData.quad`) writes a statement in the default graph to the triples workfile, which is right, but counts it as a quad (`countQuads++` before the default-graph test). N-Quads lines without a graph, and TriG default-graph blocks, reach the parser's `StreamRDF` as `quad()` with `Quad.defaultGraphNodeGenerated`, so with no N-Triples or Turtle input, `load.json` says `"triples":0` although `triples.tmp` has rows.

`tdb2.xloader` reads `load.json` to skip empty phases:

```sh
TRIPLES="$(jq .triples < $INFO)"
if [[ $TRIPLES -eq 0 ]] ; then
    TRIPLES_IDX=""
fi
```

So SPO, POS and OSP are never built, and the default-graph data is not in the database. The load finishes without an error and reports `Triples loaded = 0`. The quads count also includes the default-graph statements, so the quad indexes are built even when there are no named graphs.

Reproduce:

```sh
printf '%s\n' \
  '<urn:s> <urn:p> <urn:o1> .' \
  '<urn:s> <urn:p> <urn:o2> .' \
  '<urn:s> <urn:p> <urn:o3> <urn:g> .' > data.nq
tdb2.xloader --loc DB data.nq
tdb2.tdbquery --loc DB 'SELECT (COUNT(*) AS ?n) { ?s ?p ?o }'               # 0, expected 2
tdb2.tdbquery --loc DB 'SELECT (COUNT(*) AS ?n) { GRAPH ?g { ?s ?p ?o } }'  # 1
```

`TestXLoaderLoadInfo` runs the ingest step on the same data: the triples workfile has 2 rows and the quads workfile 1, but `load.json` has `"triples":0` and `"quads":3`.

Loads that include any N-Triples or Turtle file are not affected, since `triple()` counts those and the count is then non-zero; the count is still wrong.

Suggested fix: in `IngestData.quad`, count the statement as a triple when it goes to the triples workfile (graph is null after the default-graph test) and as a quad otherwise, so the counts match the workfile rows. Add the test above to `TS_XLoader`.

Happy to submit a PR if we agree on the approach.

### Are you interested in making a pull request?

Yes

## 5. tdb2.xloader: unused `ProcBuildNodeTableX.hashNode` with a shared static `Hash`

### Version

6.2.0 / main

### What happened?

Code cleanup; nothing user-visible.

`ProcBuildNodeTableX.hashNode(Node)` (package-private, `ProcBuildNodeTableX.java:373`) has no callers anywhere in the repository. It hashes into a shared static `Hash` (line 378) and returns `hash.getBytes()`, which is that `Hash`'s internal array. So:

- it is not thread-safe: two threads calling it at once would corrupt each other's hash;
- even on one thread, each call overwrites the bytes returned by the previous call.

Neither can happen today, since nothing calls it. The static `Hash` has one other user, `NodeHashTmpStream.node()`, which is correct: the node table step hashes on one thread, and `node()` writes the bytes to the sort input before hashing the next node. It is still a trap for anyone who calls `hashNode`, or who runs `NodeHashTmpStream` on several threads, for example to parse in parallel.

Suggested fix: delete `hashNode`. Give `NodeHashTmpStream` its own `Hash` instead of the static one, and delete the static. Neither is public API.

Happy to submit a PR if we agree on the approach.

### Are you interested in making a pull request?

Yes
