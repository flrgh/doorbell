#!/usr/bin/env bash

set -euo pipefail

readonly GEOIP=${DOORBELL_GEOIP_DIR:-./geoip}
readonly DOWNLOAD=${GEOIP}/download
readonly BASE_URL=https://download.maxmind.com/app/geoip_download
readonly SUFFIX=tar.gz

readonly SKIP_EXISTING=${SKIP_EXISTING:-0}

readonly DBS=(
    GeoLite2-City
    GeoLite2-Country
    GeoLite2-ASN
)

mkdir -p "$DOWNLOAD"

unpack() {
    local -r db=${1:?}
    local -r archive=${2:?}

    if [[ -s $db && ! $db -ot $archive ]]; then
        return 1
    fi

    tar xf "$archive" \
      -C "$GEOIP" \
      --strip-components 1 \
      --wildcards '*.mmdb'

    if [[ ! -s $db ]]; then
        echo "archive ($archive) did not contain $db"
        exit 1
    fi

    touch -r "$archive" "$db"

    return 0
}

for NAME in "${DBS[@]}"; do
    DB=${GEOIP}/${NAME}.mmdb
    ARCHIVE=${DOWNLOAD}/${NAME}.${SUFFIX}

    if (( SKIP_EXISTING == 1 )) && [[ -e $DB ]]; then
        echo "not downloading $NAME ($DB exists)"
        continue
    fi

    NEW=${DOWNLOAD}/.new.${NAME}.${SUFFIX}

    curl \
        --fail \
        --silent \
        --location \
        --remote-time \
        --time-cond "$ARCHIVE" \
        --output "$NEW" \
        --url "$BASE_URL" \
        --url-query "edition_id=${NAME}" \
        --url-query "license_key=${MAXMIND_LICENSE_KEY}" \
        --url-query "suffix=${SUFFIX}"

    if [[ -s $NEW ]] && unpack "$DB" "$NEW"; then
        mv "$NEW" "$ARCHIVE"
        continue
    fi

    unpack "$DB" "$ARCHIVE" || true
done
