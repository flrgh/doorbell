ARG OPENRESTY_VERSION=1.21.4.1-0

# TODO: adapt slim image
FROM openresty/openresty:${OPENRESTY_VERSION}-alpine-fat

RUN apk add --no-cache \
        ca-certificates \
        libmaxminddb && \
    ln -v -s /usr/lib/libGeoIP.so.1 /usr/lib/libGeoIP.so && \
    ln -v -s /usr/lib/libmaxminddb.so.0 /usr/lib/libmaxminddb.so

RUN apk add --no-cache --virtual .build-deps \
        git

COPY ./doorbell-dev-1.rockspec /tmp/
RUN luarocks install --deps-only /tmp/doorbell-dev-1.rockspec && \
    rm /tmp/doorbell-dev-1.rockspec

RUN apk del .build-deps

ARG INSTALL_PREFIX=/usr/local
ARG RUNTIME_PREFIX=/var/run
ARG LOG_PREFIX=/var/log

ENV DOORBELL_ASSET_PATH=${INSTALL_PREFIX}/share/doorbell
ENV DOORBELL_LIB_PATH=${INSTALL_PREFIX}/lib/doorbell
ENV DOORBELL_LIBEXEC_PATH=${INSTALL_PREFIX}/libexec/doorbell
ENV DOORBELL_RUNTIME_PATH=${RUNTIME_PREFIX}/doorbell
ENV DOORBELL_STATE_PATH=${RUNTIME_PREFIX}/doorbell
ENV DOORBELL_LOG_PATH=${LOG_PREFIX}/doorbell

COPY ./lib/ ${DOORBELL_LIB_PATH}/
COPY ./assets/ ${DOORBELL_ASSET_PATH}/
COPY ./bin/render-nginx-template ${DOORBELL_LIBEXEC_PATH}/
COPY ./bin/resty-doorbell ${DOORBELL_LIBEXEC_PATH}/

ARG NGINX_USER=doorbell
ARG NGINX_USER_ID=9876

ENV DOORBELL_USER=${NGINX_USER}

RUN adduser \
        -s /sbin/nologin \
        -g "" \
        -h "$DOORBELL_RUNTIME_PATH" \
        -D \
        -u "$NGINX_USER_ID" \
        "$NGINX_USER" \
        "$NGINX_USER" \
    && mkdir -p \
        "${DOORBELL_RUNTIME_PATH}/logs" \
        "${DOORBELL_LOG_PATH}" \
    && chown -R "${NGINX_USER_ID}:${NGINX_USER_ID}" \
        "${DOORBELL_RUNTIME_PATH}/logs" \
        "${DOORBELL_LOG_PATH}"

# this has to be hard-coded
COPY ./entrypoint.sh /usr/local/libexec/doorbell/entrypoint.sh
ENTRYPOINT ["/usr/local/libexec/doorbell/entrypoint.sh"]

ARG DOORBELL_LISTEN_PORT=9876
EXPOSE ${DOORBELL_LISTEN_PORT}/tcp

ENV DOORBELL_LISTEN=0.0.0.0:${DOORBELL_LISTEN_PORT}

STOPSIGNAL SIGQUIT

CMD ["start"]
