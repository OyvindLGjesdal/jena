### tdb2.xloader fails on Ubuntu 26.04 LTS: default `sort` is uutils

**Version:** Apache Jena 6.2.0 (binary release), Java 21, Ubuntu 26.04.1 LTS.

Since Ubuntu 25.10, `/usr/bin/sort` is uutils coreutils (Rust) by default
(`/usr/bin/sort -> ../lib/cargo/bin/coreutils/sort`). `tdb2.xloader` runs `sort` with
`--buffer-size=50%`, hard-coded in `ProcBuildNodeTableX` and `ProcBuildIndexX`. uutils
accepts the percentage but does not treat it as 50% of memory: it sorts in tiny
segments and spills tens or hundreds of thousands of temporary files. Under that load,
uutils 0.8.0 (Ubuntu 26.04 LTS) emits an extra empty line, and xloader's node-table
step stops or fails on it:

```
ERROR Terms           :: Sort RC = 141 : Error:
```

With real data (Wikidata lexemes) the same step fails with
`IllegalArgumentException: Bad hex char : 10 (0x0A)` in `ProcBuildNodeTableX.hexRead`.

**Reproduce** (Dockerfile attached; synthetic data, about 2 minutes):

```sh
docker build -t jena-xloader-uutils .
docker run --rm jena-xloader-uutils                    # tdb2.xloader exit code: 141
docker run --rm -e USE_GNU_SORT=1 jena-xloader-uutils  # loads, 5000000 triples
docker run --rm jena-xloader-uutils repro-sort         # sort alone
```

`repro-sort` shows the root cause without Jena, using the arguments of xloader's
index sort on 40 M distinct rows:

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

uutils 0.12.0 (Homebrew) rejects `--buffer-size=50%` outright ("invalid
--buffer-size argument"), so xloader would fail at the first sort there.

**Workaround:** GNU sort is still installed on Ubuntu 26.04 as `/usr/bin/gnusort`
(package `gnu-coreutils`). Put it first on `PATH` as `sort`:

```sh
mkdir -p ~/gnu-sort && ln -sf /usr/bin/gnusort ~/gnu-sort/sort
PATH=~/gnu-sort:$PATH tdb2.xloader --loc DB data.nt.gz
```

**Possible fixes:** let the launcher detect uutils (`sort --version`) and prefer
`gnusort` or fail with a clear message; make the sort program configurable; pass an
absolute `--buffer-size` when the sort is not GNU sort; reject empty or malformed
sorted lines in the Java readers with a message naming the sort program.
