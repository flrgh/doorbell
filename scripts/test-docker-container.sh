#!/usr/bin/env bash

set -euo pipefail

push-group() {
    printf "\n::group::%s\n" "$1"
}

pop-group() {
    printf "\n::endgroup::\n"
}

group() {
    push-group "${1}"
    shift

    local ec=0
    "${@}" || ec=$?

    pop-group

    return $ec
}

read-container-logs() {
    group "container logs" \
        docker logs doorbell \
            --details \
            2>&1 \
        || true
}

stop-container() {
    push-group "stopping container"
    docker container rm -f doorbell || true
    sleep 1
    pop-group
}

fail() {
    echo "::error::${1}"

    read-container-logs

    exit 1
}

await() {
    local timeout=$1
    shift

    local cond=$1
    shift

    local now; now=$(date +%s)
    local deadline=$((now + timeout))

    push-group "await ${cond} (timeout: $timeout)"

    while ! "$@"; do
        now=$(date +%s)

        if (( now >= deadline )); then
            fail "timeout while awaiting ${cond}"
        fi

        sleep 0.5
    done

    pop-group
}

TMP=$(mktemp -d)
readonly TMP
readonly RUNTIME=$TMP/runtime
readonly LOGS=$TMP/logs

mkdir -p "$LOGS" "$RUNTIME"


cleanup() {
    stop-container

    group "cleanup temp dir" rm -rfv "$TMP" || true
}

trap cleanup EXIT SIGINT


group "temp directories" \
    printf 'log: %s\nruntime: %s\n' "$LOGS" "$RUNTIME"


group "build image" \
    docker build \
        --build-arg NGINX_USER="$USER" \
        --build-arg NGINX_USER_ID="$(id -u)" \
        -t doorbell . \
|| fail "failed to build image"


group "start container" \
    docker run \
        --detach \
        --name doorbell \
        --publish 9876:9876 \
        -v "$LOGS:/var/log/doorbell" \
        -v "$RUNTIME:/var/run/doorbell" \
        -e DOORBELL_CONFIG_STRING='{ "trusted": [ "0.0.0.0/0" ], "auth": { "disabled": true } }' \
        doorbell \
|| fail "failed to start container"

await 5 "check /rules output health" \
    curl \
        --silent \
        --fail \
        --show-error \
        http://localhost:9876/rules


ring_args=(
    -H "X-Forwarded-For: 1.2.3.4"
    -H "X-Forwarded-Proto: https"
    -H "X-Forwarded-Port: 443"
    -H "X-Forwarded-Host: docker.test"
    -H "X-Forwarded-Method: GET"
    -H "X-Forwarded-URI: /hi"
    -H "User-Agent: test"
)


group "check denied /ring request" \
    test \
        "$(curl \
            --silent \
            "${ring_args[@]}" \
            --write-out "%{http_code}" \
            --output /dev/null \
            http://localhost:9876/ring
        )" \
        = 401 \
|| fail "request was not denied"


group "create rule via API" \
    curl \
        --silent \
        --fail \
        --show-error \
        --header "Content-Type: application/json" \
        --request POST \
        --data '{ "action": "allow", "ua": "test" }' \
        http://localhost:9876/rules \
|| fail "failed to create rule via API"


await 5 "rules.json saved to disk" \
    test -s "$RUNTIME/rules.json"


group "check allowed /ring request" \
    curl \
        --silent \
        --fail \
        --show-error \
        "${ring_args[@]}" \
        http://localhost:9876/ring

await 5 "doorbell.json.log written" \
    test -s "$LOGS/doorbell.json.log"

push-group "check for container errors"
if docker logs doorbell 2>&1 | grep -E '\[(error|crit|emerg|alert)\]'; then
    pop-group
    fail "container errors logged"
else
    pop-group
fi

push-group "check for logged errors"
if grep -E '\[(error|crit|emerg|alert)\]' "$LOGS/error.log"; then
    pop-group
    fail "nginx errors logged"
else
    pop-group
fi

await 5 "doorbell.json.log is present" \
    test -s "$LOGS/doorbell.json.log"
