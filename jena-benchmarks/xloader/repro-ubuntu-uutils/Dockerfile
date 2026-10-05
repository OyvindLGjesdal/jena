# Licensed under the terms of http://www.apache.org/licenses/LICENSE-2.0
#
# Reproduce: unchanged Apache Jena tdb2.xloader with Ubuntu's default sort(1).
#
# Since Ubuntu 25.10, /usr/bin/sort is uutils (Rust coreutils). xloader always
# passes --buffer-size=50% to sort, which these uutils versions misread as a tiny
# buffer; under the resulting heavy spilling uutils 0.8.0 (Ubuntu 26.04 LTS) emits an
# empty line, and xloader's node-table reader stops or fails on it.
#
#   docker build -t jena-xloader-uutils .
#   docker run --rm jena-xloader-uutils                    # xloader fails (exit 141)
#   docker run --rm -e USE_GNU_SORT=1 jena-xloader-uutils  # workaround: GNU sort, loads
#   docker run --rm jena-xloader-uutils repro-sort         # sort alone: empty line
#
#   docker build --build-arg UBUNTU_VERSION=24.04 -t jena-xloader-gnu .   # control
#
# Ubuntu 25.10 (uutils 0.2.2) loads correctly but slowly (same tiny buffer, output
# correct); 24.04 LTS has GNU sort. Synthetic data only; no download besides the
# Jena release and Ubuntu packages.

ARG UBUNTU_VERSION=26.04
FROM ubuntu:${UBUNTU_VERSION}

ARG JENA_VERSION=6.2.0
ARG TRIPLES=5000000

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openjdk-21-jre-headless jq curl ca-certificates gzip \
 && rm -rf /var/lib/apt/lists/*

# Official binary release, checked against the published SHA-512.
RUN cd /opt \
 && base=https://archive.apache.org/dist/jena/binaries \
 && curl -fsSLO "$base/apache-jena-${JENA_VERSION}.tar.gz" \
 && curl -fsSLO "$base/apache-jena-${JENA_VERSION}.tar.gz.sha512" \
 && echo "$(cut -d' ' -f1 apache-jena-${JENA_VERSION}.tar.gz.sha512)  apache-jena-${JENA_VERSION}.tar.gz" | sha512sum -c - \
 && tar -xzf "apache-jena-${JENA_VERSION}.tar.gz" \
 && rm "apache-jena-${JENA_VERSION}.tar.gz" "apache-jena-${JENA_VERSION}.tar.gz.sha512" \
 && ln -s "/opt/apache-jena-${JENA_VERSION}" /opt/jena

# Synthetic N-Triples: many distinct IRIs and literals, some duplicate triples.
COPY <<'EOF' /usr/local/share/generate.awk
BEGIN {
    for (i = 0; i < n; i++) {
        line = sprintf("<http://example.org/s/%d> <http://example.org/p/%d> \"value %d\" .", int(i / 4), i % 97, (i * 7919) % (n * 2))
        print line
        if (i % 50 == 0)
            print line
    }
}
EOF
RUN mkdir /data \
 && awk -v n="${TRIPLES}" -f /usr/local/share/generate.awk | gzip -1 > /data/data.nt.gz

COPY <<'EOF' /usr/local/bin/repro
#!/bin/sh
. /etc/os-release
echo "== $PRETTY_NAME, Jena $(ls -d /opt/apache-jena-* | sed 's/.*apache-jena-//')"
if [ -n "${USE_GNU_SORT:-}" ]; then
    mkdir -p /opt/gnu-sort && ln -sf /usr/bin/gnusort /opt/gnu-sort/sort
    export PATH=/opt/gnu-sort:$PATH
fi
echo "sort: $(command -v sort) -> $(sort --version | head -1)"
echo "input: $(zcat /data/data.nt.gz | wc -l) lines"
/opt/jena/bin/tdb2.xloader --loc /tmp/db --tmpdir /tmp/work /data/data.nt.gz > /tmp/load.log 2>&1
rc=$?
echo "tdb2.xloader exit code: $rc"
grep -E '==-==-==|Overall' /tmp/load.log
if [ "$rc" -ne 0 ]; then
    echo "-- first error lines:"
    grep -m1 -A4 -E 'Exception|ERROR' /tmp/load.log
    exit "$rc"
fi
/opt/jena/bin/tdb2.tdbquery --loc /tmp/db 'SELECT (COUNT(*) AS ?triples) { ?s ?p ?o }'
EOF
# sort alone, with the arguments xloader's index sorts use, on 40 M rows of three
# 16-digit hex IDs (about 2 GB): 50% (as xloader passes it) against a fixed 1G.
COPY <<'EOF' /usr/local/bin/repro-sort
#!/bin/sh
export LC_ALL=C
echo "sort: $(sort --version | head -1)"
awk -v n="${ROWS:-40000000}" 'BEGIN { for (i = 0; i < n; i++) printf "%016X %016X %016X\n", (i * 2654435761) % 4294967296, i % 1000003, (i * 40503) % 65536 }' > /tmp/rows.txt
echo "input: $(wc -l < /tmp/rows.txt) distinct rows"
for b in 50% 1G; do
    sort -T /tmp --buffer-size=$b --parallel=4 --unique --key=1,1 --key=2,2 --key=3,3 /tmp/rows.txt > /tmp/out.txt
    echo "--buffer-size=$b: exit=$? output lines=$(wc -l < /tmp/out.txt) empty lines=$(grep -c '^$' /tmp/out.txt)"
done
EOF
RUN chmod +x /usr/local/bin/repro /usr/local/bin/repro-sort

CMD ["/usr/local/bin/repro"]
