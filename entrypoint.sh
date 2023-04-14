#!/usr/bin/env bash

set -euo pipefail

for var in ${!DOORBELL_*}; do
    export "${var}=${!var}"
done

export LUA_PATH="${DOORBELL_LIB_DIR}/?.lua;${DOORBELL_LIB_DIR}/?/init.lua;${LUA_PATH:-};"

if [[ ${1:-} = start ]]; then
    # nginx uses {{prefix}}/logs to log errors encountered before/during
    # config parsing, so it needs to exist
    mkdir -p "$DOORBELL_RUNTIME_DIR/logs"
    ln -sf /dev/stderr "$DOORBELL_RUNTIME_DIR/logs/error.log"
    ln -sf /dev/stdout "$DOORBELL_RUNTIME_DIR/logs/access.log"

    if [[ $DOORBELL_LOG_DIR == "stdio" ]]; then
        export DOORBELL_LOG_DIR=$DOORBELL_RUNTIME_DIR/logs
        ln -sf /dev/stderr "${DOORBELL_LOG_DIR}/logs/error.log"
        ln -sf /dev/stdout "${DOORBELL_LOG_DIR}/logs/access.log"
    fi

    "$DOORBELL_LIBEXEC_DIR"/render-nginx-template \
        < "$DOORBELL_ASSET_DIR"/nginx.template.conf \
        > "$DOORBELL_RUNTIME_DIR"/nginx.conf

    exec nginx \
        -p "$DOORBELL_RUNTIME_DIR" \
        -c "$DOORBELL_RUNTIME_DIR"/nginx.conf
fi

exec "$@"
