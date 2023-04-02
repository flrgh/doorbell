#!/usr/bin/env bash

set -euo pipefail

DOORBELL_PREFIX=${DOORBELL_PREFIX:-/usr/local/doorbell}

for var in ${!DOORBELL_*}; do
    export "$var"
done

export LUA_PATH="${DOORBELL_PREFIX}/lib/?.lua;${DOORBELL_PREFIX}/lib/?/init.lua;${LUA_PATH:-};"

if [[ ${1:-} = start ]]; then
    mkdir -p "$DOORBELL_PREFIX/logs"
    chown 775 "$DOORBELL_PREFIX/logs"

    $DOORBELL_PREFIX/bin/render-nginx-template \
        < "$DOORBELL_PREFIX"/assets/nginx.template.conf \
        > "$DOORBELL_PREFIX"/nginx.conf

    exec nginx \
        -p "$DOORBELL_PREFIX" \
        -c "$DOORBELL_PREFIX/nginx.conf"
fi

exec "$@"
