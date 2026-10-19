# String samples from the Wikidata lexemes dump

Test data for the GH-4300 string comparison benchmarks (`TestStringComparators`,
`TestStringEquality`, `TestNodeValueStringCompare`).

## Source

`wikidata-20260925-lexemes-BETA.nt.gz`, 1,522,459,371 bytes, MD5 `efa95a9351de0eac709f53f0ba3c85a1`
(SHA-1 `08eab4f2b0aec76e58318e890011668ef60df518`), fetched from the ACC mirror in Sweden:

* https://mirror.accum.se/mirror/wikimedia.org/other/wikibase/wikidatawiki/20260925/wikidata-20260925-lexemes-BETA.nt.gz
* checksums: https://mirror.accum.se/mirror/wikimedia.org/other/wikibase/wikidatawiki/20260925/wikidata-20260925-md5sums.txt

The same dump is published at https://dumps.wikimedia.org/wikidatawiki/entities/ while it is current.
Dated dumps are removed from the mirrors after some weeks.

## How the files were made

```sh
curl -fLO https://mirror.accum.se/mirror/wikimedia.org/other/wikibase/wikidatawiki/20260925/wikidata-20260925-lexemes-BETA.nt.gz
mkdir -p out
gzip -dc wikidata-20260925-lexemes-BETA.nt.gz | python3 ../../scripts/extract_lexeme_strings.py 100 out
gzip -9 -n out/literals.bin out/langlits.bin out/iris.bin
```

`extract_lexeme_strings.py` reads the N-Triples dump and keeps every 100th line, starting with
line 100 (2,293,920 of 229,392,099 lines). From each kept line it takes:

* **the object literal**, if it is a plain literal, an `xsd:string` or a language-tagged literal.
  Its lexical form goes to `literals.bin`. A language-tagged literal also goes to `langlits.bin`
  as a (language tag, lexical form) pair. Other datatypes are skipped (55,909 lines).
* **the IRIs before the object** (subject and predicate). Each is kept with probability 0.1,
  using Python's `random.Random(7)`, and goes to `iris.bin`.

`\uXXXX` and `\UXXXXXXXX` escapes are decoded, and escaped surrogate pairs are joined into one
code point. No sampled literal contained a lone surrogate.

## Files

| File | Strings | Contents | Uncompressed | SHA-256 of the uncompressed file |
|---|---|---|---|---|
| `literals.bin.gz` | 543,057 | lexical forms; 909 contain characters above U+FFFF | 15,278,738 bytes | `84e13094a24027bc8049155d1ce95d8fcc5c7b6fac9f5133e0868d33bf4adea9` |
| `langlits.bin.gz` | 461,173 pairs | language tag, lexical form, alternating | 17,088,928 bytes | `c32b621b43ae4ee0ac18d4f3d05069811ae460ad2d8a1e01fa768837e7f90d82` |
| `iris.bin.gz` | 628,996 | IRIs | 59,354,356 bytes | `2acfcbd1cd853c7f2694a98abefbf7922a25f3708ac2bec4dd84fe6199393be1` |

Format of each string: a 4-byte big-endian length in UTF-16 code units, then the UTF-16BE chars.
`StringCompareData` reads the `.bin.gz` files directly.
