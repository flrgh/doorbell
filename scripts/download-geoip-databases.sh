#!/bin/bash

set -euo pipefail

readonly GEOIP=./geoip
readonly DOWNLOAD=${GEOIP}/download
readonly GEOIP_CITY=${DOWNLOAD}/GeoLite2-City.tar.gz
readonly GEOIP_COUNTRY=${DOWNLOAD}/GeoLite2-Country.tar.gz
readonly BASE_URL=https://download.maxmind.com/app/geoip_download

readonly DOWNLOAD_ONLY=${DOWNLOAD_ONLY:-0}
readonly UPDATE=${UPDATE:-1}
mkdir -p "$DOWNLOAD"

UPDATED=0

if [[ $UPDATE == 1 || $DOWNLOAD_ONLY == 1 || ! -e $GEOIP_CITY ]]; then
    echo "Downloading GeoIP City DB"

    curl \
        --fail \
        --silent \
        --location \
        --time-cond "$GEOIP_CITY" \
        --output "$GEOIP_CITY" \
        --url "${BASE_URL}?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

    UDPATED=1
fi

if [[ $UPDATE == 1 || $DOWNLOAD_ONLY == 1 || ! -e $GEOIP_COUNTRY ]]; then
    echo "Downloading GeoIP Country DB"

    curl \
        --fail \
        --silent \
        --location \
        --time-cond "$GEOIP_COUNTRY" \
        --output "$GEOIP_COUNTRY" \
        --url "${BASE_URL}?edition_id=GeoLite2-Country&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

    UDPATED=1
fi

if (( UPDATED == 1 && DOWNLOAD_ONLY == 0 )); then
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
fi
