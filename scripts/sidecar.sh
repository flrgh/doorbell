#!/usr/bin/env bash

set -euo pipefail

readonly KEEP_RUNNING=${DOORBELL_SIDECAR_KEEP_RUNNING:-0}
readonly LIBEXEC=${DOORBELL_LIBEXEC_PATH:-/usr/local/libexec/doorbell}

readonly LOGS=${DOORBELL_LOG_PATH:-/var/log/doorbell}
readonly LOG=${LOGS}/sidecar.log

readonly GEOIP_DOWNLOADER="$LIBEXEC"/download-geoip-databases.sh
readonly GEOIP=${DOORBELL_GEOIP_DIR:-/geoip}
export DOORBELL_GEOIP_DIR=$GEOIP

readonly DBS=(
    "$GEOIP"/GeoLite2-City.mmdb
    "$GEOIP"/GeoLite2-Country.mmdb
    "$GEOIP"/GeoLite2-ASN.mmdb
)

log() {
    local -r lvl=$1
    shift

    local ts
    printf -v ts '%(%Y-%m-%d %H:%M:%S%z)T' "$EPOCHSECONDS"
    # fix offset for formatting, so `-0700` -> `-07:00`
    ts="${ts:0:-2}:${ts: -2}"

    tee -a "$LOG" <<<"[$ts] $lvl - $*"
}

download_geoip() {
    sudo -E \
        -u "${DOORBELL_USER:?}" \
        -g "${DOORBELL_USER:?}" \
        "$GEOIP_DOWNLOADER"
}

update_geoip() {
    if download_geoip; then
        log INFO "GeoIP database files updated"
    else
        log WARN "GeoIP update failed" >&2
    fi
}

init_log_paths() {
    mkdir -p "$LOGS"

    touch "$LOGS"/{access,error,doorbell.json}.log

    chown -R "${DOORBELL_USER_ID:?}:${DOORBELL_USER_ID:?}" \
        "$LOGS"

    chmod -R a+r "$LOGS"
}

init_geoip() {
    mkdir -p "$GEOIP" "$GEOIP"/download

    local db
    local dl=0
    for db in "${DBS[@]}"; do
        if [[ ! -e $db ]]; then
            dl=1
            break
        fi
    done

    if (( dl )); then
        log INFO "downloading initial GeoIP files"
        SKIP_EXISTING=1 download_geoip
    else
        log INFO "GeoIP files are present, skipping initial download"
    fi

    chown -R "${DOORBELL_USER_ID:?}:${DOORBELL_USER_ID:?}" \
        "$GEOIP"

    chmod -R a+r "$GEOIP"
}

main() {
    log INFO "starting up"

    rm -f /tmp/sidecar

    init_log_paths
    init_geoip

    touch /tmp/sidecar
    log INFO "initial setup complete"

    if (( KEEP_RUNNING )); then
        # download initial updates briefly after startup
        sleep 60
        update_geoip

        while true; do
            sleep $(( 60 * 60 * 4 ))
            update_geoip
        done
    fi
}

main "$@"
