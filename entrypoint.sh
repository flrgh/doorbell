#!/usr/bin/env bash

set -euo pipefail

for var in ${!DOORBELL_*}; do
    export "${var}=${!var}"
done

export LUA_PATH="${DOORBELL_LIB_PATH}/?.lua;${DOORBELL_LIB_PATH}/?/init.lua;${LUA_PATH:-};"

if [[ ${1:-} = start ]]; then
    # nginx uses {{prefix}}/logs to log errors encountered before/during
    # config parsing, so it needs to exist
    mkdir -p "$DOORBELL_RUNTIME_PATH/logs"
    ln -sf /dev/stderr "$DOORBELL_RUNTIME_PATH/logs/error.log"
    ln -sf /dev/stdout "$DOORBELL_RUNTIME_PATH/logs/access.log"

    if [[ $DOORBELL_LOG_PATH == "stdio" ]]; then
        export DOORBELL_LOG_PATH=$DOORBELL_RUNTIME_PATH/logs
        ln -sf /dev/stderr "${DOORBELL_LOG_PATH}/logs/error.log"
        ln -sf /dev/stdout "${DOORBELL_LOG_PATH}/logs/access.log"
    fi

    if [[ -n ${DOORBELL_USER:-} ]]; then
        chown -R "$DOORBELL_USER:$DOORBELL_USER" \
            "$DOORBELL_RUNTIME_PATH" \
            "$DOORBELL_LOG_PATH"
    fi

    echo "Rendering NGINX template to ${DOORBELL_RUNTIME_PATH}/nginx.conf"
    "$DOORBELL_LIBEXEC_PATH"/render-nginx-template \
        < "$DOORBELL_ASSET_PATH"/nginx.template.conf \
        > "$DOORBELL_RUNTIME_PATH"/nginx.conf

    echo "Starting up..."
    exec nginx \
        -p "$DOORBELL_RUNTIME_PATH" \
        -c "$DOORBELL_RUNTIME_PATH"/nginx.conf
fi

exec "$@"
