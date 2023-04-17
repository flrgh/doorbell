#!/bin/bash

set -euo pipefail

readonly COMMIT=c1c74446c323acc0486cbf4720174e72d840623b
readonly BASE_URL=https://github.com/maxmind/MaxMind-DB/raw/${COMMIT}

mkdir -p geoip

readonly FILES=(
    source-data/GeoLite2-City-Test.json
    test-data/GeoLite2-City-Test.mmdb
    source-data/GeoLite2-Country-Test.json
    test-data/GeoLite2-Country-Test.mmdb
)

for file in "${FILES[@]}"; do
    fname=$(basename "$file")
    out=geoip/"$fname"

    curl \
        --silent \
        --fail \
        --location \
        --time-cond "$out" \
        --output "$out" \
        --url "${BASE_URL}/${file}"
done
