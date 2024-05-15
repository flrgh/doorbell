#!/usr/bin/env bash

set -euo pipefail

for var in ${!DOORBELL_*}; do
    export "${var}=${!var}"
done

export LUA_PATH="${DOORBELL_LIB_PATH}/?.lua;${DOORBELL_LIB_PATH}/?/init.lua;${LUA_PATH:-};"

if [[ ${1:-} = start ]]; then
    USER_GROUP=${DOORBELL_USER}:${DOORBELL_USER}

    # nginx uses {{prefix}}/logs to log errors encountered before/during
    # config parsing, so it needs to exist
    mkdir -p "$DOORBELL_RUNTIME_PATH/logs"
    chown -R "$USER_GROUP" "$DOORBELL_RUNTIME_PATH"
    ln -sf /dev/stderr "$DOORBELL_RUNTIME_PATH/logs/error.log"
    ln -sf /dev/stdout "$DOORBELL_RUNTIME_PATH/logs/access.log"

    mkdir -p "$DOORBELL_LOG_PATH"
    if [[ $DOORBELL_LOG_PATH == "stdio" ]]; then
        DOORBELL_LOG_PATH="$DOORBELL_RUNTIME_PATH/logs"
        ln -sf /dev/stderr "${DOORBELL_LOG_PATH}/error.log"
        ln -sf /dev/stdout "${DOORBELL_LOG_PATH}/access.log"
    else
        touch "${DOORBELL_LOG_PATH}/error.log" \
              "${DOORBELL_LOG_PATH}/access.log"
    fi

    # can't use stdout for this yet
    touch "${DOORBELL_LOG_PATH}/doorbell.json.log"

    chown --no-dereference \
        "$USER_GROUP" \
        "${DOORBELL_LOG_PATH}/error.log" \
        "${DOORBELL_LOG_PATH}/access.log" \
        "${DOORBELL_LOG_PATH}/doorbell.json.log"

    echo "Rendering NGINX template to ${DOORBELL_RUNTIME_PATH}/nginx.conf"
    "$DOORBELL_LIBEXEC_PATH"/resty-doorbell \
    "$DOORBELL_LIBEXEC_PATH"/render-nginx-template \
        < "$DOORBELL_ASSET_PATH"/nginx.template.conf \
        > "$DOORBELL_RUNTIME_PATH"/nginx.conf

    find "$DOORBELL_RUNTIME_PATH" \
        -type s \
        -delete

    echo "Starting up..."
    exec nginx \
        -p "$DOORBELL_RUNTIME_PATH" \
        -c "$DOORBELL_RUNTIME_PATH"/nginx.conf
fi

exec "$@"
