#!/bin/bash

set -euo pipefail

readonly GEOIP=./geoip
readonly DOWNLOAD=${GEOIP}/download
readonly GEOIP_CITY=${DOWNLOAD}/GeoLite2-City.tar.gz
readonly GEOIP_COUNTRY=${DOWNLOAD}/GeoLite2-Country.tar.gz
readonly GEOIP_ASN=${DOWNLOAD}/GeoLite2-ASN.tar.gz
readonly BASE_URL=https://download.maxmind.com/app/geoip_download

readonly NO_DOWNLOAD=${NO_DOWNLOAD:-0}
readonly NO_UNPACK=${NO_UNPACK:-0}

if [[ -z ${MAXMIND_LICENSE_KEY:-} ]]; then
    echo "MAXMIND_LICENSE_KEY env var is not set."
    echo "Please enter your license key now:"
    read \
        -p "> " \
        -r \
        -s \
        -t 30 \
        MAXMIND_LICENSE_KEY

    if [[ -z ${MAXMIND_LICENSE_KEY:-} ]]; then
        echo "Fatal: still missing the license key"
        exit 1
    fi
fi

mkdir -p "$DOWNLOAD"

if (( NO_DOWNLOAD == 0 )); then
    echo "Downloading GeoIP City DB"
    curl \
        --fail \
        --silent \
        --location \
        --time-cond "$GEOIP_CITY" \
        --output "$GEOIP_CITY" \
        --url "${BASE_URL}?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

    echo "Downloading GeoIP Country DB"
    curl \
        --fail \
        --silent \
        --location \
        --time-cond "$GEOIP_COUNTRY" \
        --output "$GEOIP_COUNTRY" \
        --url "${BASE_URL}?edition_id=GeoLite2-Country&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

    echo "Downloading GeoIP ASN DB"
    curl \
        --fail \
        --silent \
        --location \
        --time-cond "$GEOIP_ASN" \
        --output "$GEOIP_ASN" \
        --url "${BASE_URL}?edition_id=GeoLite2-ASN&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

fi

if (( NO_UNPACK == 0 )); then
    echo "Unpacking GeoIP City DB"
    tar xf "$GEOIP_CITY" \
      -C "$GEOIP" \
      --strip-components 1 \
      --wildcards '*.mmdb'

    echo "Unpacking GeoIP Country DB"
    tar xf "$GEOIP_COUNTRY" \
      -C "$GEOIP" \
      --strip-components 1 \
      --wildcards '*.mmdb'

    echo "Unpacking GeoIP ASN DB"
    tar xf "$GEOIP_ASN" \
      -C "$GEOIP" \
      --strip-components 1 \
      --wildcards '*.mmdb'

fi
