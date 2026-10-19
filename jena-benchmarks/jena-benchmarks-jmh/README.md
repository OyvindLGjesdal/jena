# jena-benchmarks-jmh

This module contains benchmarks implemented using the Java Microbenchmark Harness (jmh) and JUnit.

## Troubleshooting

* `Unable to find the resource: /META-INF/BenchmarkList`: If you encounter this error while attempting to run the benchmark JUnit tests from the IDE of your choice then it means that the jmh annotation processor has not yet been run. The processor should run as part of the usual java compilation (via the `maven-compiler-plugin`). You can manually force the build by running `mvn -Pdev clean install` on the `jena-benchmarks-jmh` module from the command line.

## String comparison by code point (GH-4300)

Benchmarks for comparing strings by Unicode code point instead of UTF-16 code unit
([GH-4300](https://github.com/apache/jena/issues/4300), [#4314](https://github.com/apache/jena/pull/4314)).
They use strings sampled from the Wikidata lexemes dump.

| Class | Measures |
|---|---|
| `TestStringComparators` | Standalone comparators on plain `String`s: `utf16` (`String.compareTo`, before GH-4300), `codepoint-loop` (#4314), `fixup`, `guard`, `char-loop`. Sort 100k strings, random pairs, equal pairs. Its `variantsAgree` test checks the code point variants against a reference. |
| `TestStringEquality` | Standalone string equality: `compareTo == 0`, code point loop `== 0`, `String.equals`. |
| `TestNodeValueStringCompare` | Jena's `NodeValue.compareAlways` (`ORDER BY`), `compare` (`<`) and `sameValueAs` (`=`) with the jena-arq on the classpath. Run it on main and on a branch with the change to compare them. |

In Jena, equal RDF terms take a fast path in `NVCompare` and never reach `XSDFuncOp.compareString`,
so the standalone "equal pairs" numbers do not apply to queries. IRIs are ordered by `NodeCmp`, not
by `XSDFuncOp.compareString`.

### Data

The samples are in [`data/strcmp`](data/strcmp), about 13 MB gzipped: every 100th line of
`wikidata-20260925-lexemes-BETA.nt.gz`, fetched from the
[ACC mirror in Sweden](https://mirror.accum.se/mirror/wikimedia.org/other/wikibase/wikidatawiki/20260925/wikidata-20260925-lexemes-BETA.nt.gz).
[`data/strcmp/README.md`](data/strcmp/README.md) describes the source, the checksums and how the
files were made with [`scripts/extract_lexeme_strings.py`](scripts/extract_lexeme_strings.py).

| File | Contents |
|---|---|
| `literals.bin.gz` | 543,057 literal lexical forms, 909 of them with characters above U+FFFF |
| `langlits.bin.gz` | 461,173 (language tag, lexical form) pairs |
| `iris.bin.gz` | 628,996 IRIs |

To use another sample, pass `-Djena.strcmp.data=<directory>`.

### Running

```sh
# 1. Build the module and what it depends on
mvn install -DskipTests -pl jena-benchmarks/jena-benchmarks-jmh -am

# 2. Run one benchmark class (results go to <Class>_<timestamp>.json in the module directory)
mvn test -pl jena-benchmarks/jena-benchmarks-jmh -Dbenchmark.skip=false -Dtest=TestNodeValueStringCompare
```

To compare main with #4314, run `TestNodeValueStringCompare` on main, then check out the PR,
repeat step 1 and run it again.

### Results

JMH 1.37, JDK 21.0.12 (Corretto), macOS 27.0, 2 forks × (3 × 1 s warmup, 5 × 1 s measurement),
laptop on battery. Identical code varied by up to about 20% between runs, so treat differences
below that as noise.

Standalone comparators (`TestStringComparators`), time relative to `utf16`:

| Benchmark | Data | `utf16` | `codepoint-loop` (#4314) | `fixup` | `guard` | `char-loop` |
|---|---|---|---|---|---|---|
| sort 100k | literals | 27.8 ms | ≈37–40 ms (1.35x) | 28.6 ms (1.03x) | 50.1 ms (1.8x) | 29.7 ms (1.07x) |
| sort 100k | IRI text | 25.8 ms | 134.9 ms (5.2x) | 85.6 ms (3.3x) | 27.3 ms (1.06x) | 85.9 ms (3.3x) |
| random pairs | literals | 24.5 ns | 20.8 ns (0.85x) | 22.7 ns (0.93x) | 66.9 ns (2.7x) | 19.7 ns (0.80x) |
| random pairs | IRI text | 28.8 ns | 102.8 ns (3.6x) | 78.6 ns (2.7x) | 30.1 ns (1.05x) | 74.6 ns (2.6x) |
| equal pairs | literals | 15.3 ns | 54.1 ns (3.5x) | 29.3 ns (1.9x) | 15.1 ns (1.0x) | 29.3 ns (1.9x) |
| equal pairs | IRI text | 15.2 ns | 116.6 ns (7.7x) | 81.4 ns (5.4x) | 14.8 ns (1.0x) | 78.8 ns (5.2x) |

Through `NodeValue` (`TestNodeValueStringCompare`), main against #4314 at commit 61804b5:

| Operation | Data | main | #4314 |
|---|---|---|---|
| `ORDER BY`, sort 100k | `iristr` | 45.7 ms | 113.0 ms (2.47x) |
| `ORDER BY`, random pairs | `iristr` | 33.8 ns | 140.2 ns (4.15x) |
| `=` on unequal values | `iristr` | 45.8 ns | 123.5 ns (2.70x) |
| `ORDER BY`, sort 100k | `string` | 48.3 ms | 52.4 ms (1.08x) |
| `ORDER BY`, random pairs | `string` | 34.7 ns | 38.5 ns (1.11x) |
| `=` on unequal values | `string` | 47.0 ns | 46.3 ns (0.98x) |
| `ORDER BY`, sort 100k | `lang` | 263.9 ms | 276.4 ms (1.05x) |
| `<`, same language tag | `lang` | 38.2 ns | 41.7 ns (1.09x) |
| `=` on equal values | `string` | 31.3 ns | 31.4 ns |
| `=` on equal values | `lang` | 3.0 ns | 3.0 ns |
