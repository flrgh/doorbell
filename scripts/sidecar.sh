#!/usr/bin/env bash

set -euo pipefail

rm -f /tmp/sidecar || true

readonly KEEP_RUNNING=${DOORBELL_SIDECAR_KEEP_RUNNING:-0}
readonly LE=${DOORBELL_LIBEXEC_PATH:-/usr/local/libexec/doorbell}

readonly LOGS=${DOORBELL_LOG_PATH:-/var/log/doorbell}

readonly GEOIP=${DOORBELL_GEOIP_DIR:-/geoip}
export DOORBELL_GEOIP_DIR=$GEOIP

mkdir -p "$GEOIP" "$LOGS"

if [[ ! -e "$GEOIP"/GeoLite2-ASN.mmdb || ! -e "$GEOIP"/GeoLite2-City.mmdb ]]; then
    SKIP_EXISTING=1 "$LE"/download-geoip-databases.sh
fi

touch "$LOGS"/{access,error,doorbell.json}.log

chown -R "${DOORBELL_USER_ID:?}:${DOORBELL_USER_ID:?}" \
    "$GEOIP" \
    "$LOGS"

chmod -R a+r \
    "$GEOIP" \
    "$LOGS"


touch /tmp/sidecar

while (( KEEP_RUNNING )); do
    sleep 60

    sudo -E \
        -u doorbell \
        -g doorbell \
        "$LE"/download-geoip-databases.sh \
    || {
        rm -f /tmp/sidecar
        exit 1
    }

    sleep $(( 60 * 60 * 4 ))
done
