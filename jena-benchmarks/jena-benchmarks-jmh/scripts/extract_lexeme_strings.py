#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.
#
#    SPDX-License-Identifier: Apache-2.0

"""Sample strings from an N-Triples file for the string comparison benchmarks.

Reads N-Triples on stdin, keeps every STEP-th line, and writes to OUT_DIR:
  literals.bin  lexical forms of plain, xsd:string and language-tagged literals
  langlits.bin  (language tag, lexical form) pairs of language-tagged literals
  iris.bin      a 10% random sample (seed 7) of the IRIs in subject and predicate position

Each string is a 4-byte big-endian length in UTF-16 code units, then the UTF-16BE chars.

Usage:
  gzip -dc lexemes.nt.gz | python3 extract_lexeme_strings.py 100 OUT_DIR
"""

import itertools
import random
import re
import struct
import sys

STEP = int(sys.argv[1])
OUT_DIR = sys.argv[2]
XSD_STRING = b"<http://www.w3.org/2001/XMLSchema#string>"
# Object literal at the end of the line: "lex"(@lang | ^^<dt>)? .
LIT = re.compile(rb'"((?:[^"\\]|\\.)*)"(@[A-Za-z0-9-]+|\^\^<[^>]*>)?\s*\.\s*$')
IRI = re.compile(rb'<([^>]*)>')


def unescape(b):
    s = b.decode('ascii').encode('latin-1').decode('unicode_escape')
    # Join escaped surrogate pairs (𝄞) into one code point.
    return s.encode('utf-16-be', 'surrogatepass').decode('utf-16-be', 'surrogatepass')


def write(f, s):
    data = s.encode('utf-16-be', 'surrogatepass')
    f.write(struct.pack('>i', len(data) // 2))
    f.write(data)


counts = dict(lines=0, literals=0, lang_literals=0, typed_skipped=0, lone_surrogates=0,
              supplementary_literals=0, iris=0)
rnd = random.Random(7)
with open(f"{OUT_DIR}/literals.bin", "wb") as lf, \
     open(f"{OUT_DIR}/langlits.bin", "wb") as llf, \
     open(f"{OUT_DIR}/iris.bin", "wb") as itf:
    for line in itertools.islice(sys.stdin.buffer, STEP - 1, None, STEP):
        counts['lines'] += 1
        m = LIT.search(line)
        if m:
            tag = m.group(2)
            if tag is None or tag.startswith(b'@') or tag[2:] == XSD_STRING:
                s = unescape(m.group(1))
                try:
                    s.encode('utf-8')
                except UnicodeEncodeError:
                    counts['lone_surrogates'] += 1
                    continue
                if any(ord(c) > 0xFFFF for c in s):
                    counts['supplementary_literals'] += 1
                write(lf, s)
                counts['literals'] += 1
                if tag is not None and tag.startswith(b'@'):
                    write(llf, tag[1:].decode('ascii'))
                    write(llf, s)
                    counts['lang_literals'] += 1
            else:
                counts['typed_skipped'] += 1
            subject_part = line[:m.start()]
        else:
            subject_part = line
        for iri in IRI.findall(subject_part):
            if rnd.random() < 0.1:
                write(itf, unescape(iri))
                counts['iris'] += 1
print(counts)
