FROM openresty/openresty:alpine-fat

RUN apk add --no-cache \
        ca-certificates \
        libmaxminddb && \
    ln -v -s /usr/lib/libGeoIP.so.1 /usr/lib/libGeoIP.so && \
    ln -v -s /usr/lib/libmaxminddb.so.0 /usr/lib/libmaxminddb.so && \
    luarocks install luajit-geoip && \
    luarocks install lua-resty-http && \
    luarocks install lua-resty-ipmatcher && \
    luarocks install lua-resty-template && \
    luarocks install nginx-lua-prometheus && \
    luarocks install lua-resty-pushover && \
    luarocks install lua-resty-jit-uuid && \
    curl \
        --fail \
        --silent \
        --output /usr/local/openresty/lualib/lfs_ffi.lua \
        --url https://raw.githubusercontent.com/spacewander/luafilesystem/0.3.0/lfs_ffi.lua


ARG DOORBELL_PREFIX=/usr/local/doorbell
ENV DOORBELL_PREFIX=${DOORBELL_PREFIX}

COPY ./lib/ /usr/local/openresty/lualib/
COPY ./bin/render-nginx-template ${DOORBELL_PREFIX}/bin/
COPY ./assets/ ${DOORBELL_PREFIX}/assets/
COPY ./entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["start"]
