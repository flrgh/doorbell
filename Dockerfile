FROM openresty/openresty:alpine-fat

RUN apk add --no-cache \
        ca-certificates \
        libmaxminddb && \
    ln -v -s /usr/lib/libGeoIP.so.1 /usr/lib/libGeoIP.so && \
    ln -v -s /usr/lib/libmaxminddb.so.0 /usr/lib/libmaxminddb.so

COPY ./doorbell-dev-1.rockspec /tmp/
RUN luarocks install --deps-only /tmp/doorbell-dev-1.rockspec && \
    rm /tmp/doorbell-dev-1.rockspec

ARG DOORBELL_PREFIX=/usr/local/doorbell
ENV DOORBELL_PREFIX=${DOORBELL_PREFIX}

COPY ./lib/ ${DOORBELL_PREFIX}/lib/
COPY ./bin/render-nginx-template ${DOORBELL_PREFIX}/bin/
COPY ./assets/ ${DOORBELL_PREFIX}/assets/
COPY ./entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["start"]
