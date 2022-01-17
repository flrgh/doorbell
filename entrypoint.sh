#!/usr/bin/env bash

set -euo pipefail

export DOORBELL_ACCESS_LOG=${DOORBELL_ACCESS_LOG:-logs/access.log}
export DOORBELL_ERROR_LOG=${DOORBELL_ERROR_LOG:-logs/error.log}
export DOORBELL_ERROR_LOG_LEVEL=${DOORBELL_ERROR_LOG_LEVEL:-debug}
export DOORBELL_LISTEN=${DOORBELL_LISTEN:-9876}
export DOORBELL_PREFIX=${DOORBELL_PREFIX:-/usr/local/doorbell}
export DOORBELL_RESOLVER=${DOORBELL_RESOLVER:-8.8.8.8}
export DOORBELL_USER=${DOORBELL_USER:-nobody}
export DOORBELL_WORKER_PROCESSES=${DOORBELL_WORKER_PROCESSES:-auto}

if [[ ${1:-} = start ]]; then
    mkdir -p "$DOORBELL_PREFIX/logs"
    chown 775 "$DOORBELL_PREFIX/logs"

    luajit -e 'for line in io.lines() do print( (line:gsub("%${([^}]+)}", os.getenv)) ) end' \
        < "$DOORBELL_PREFIX"/nginx.template.conf \
        > "$DOORBELL_PREFIX"/nginx.conf

    exec nginx \
        -p "$DOORBELL_PREFIX" \
        -c "$DOORBELL_PREFIX/nginx.conf"
fi

exec "$@"
