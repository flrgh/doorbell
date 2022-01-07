FROM openresty/openresty:alpine-fat

RUN apk add --no-cache \
        libmaxminddb && \
    ln -v -s /usr/lib/libGeoIP.so.1 /usr/lib/libGeoIP.so && \
    ln -v -s /usr/lib/libmaxminddb.so.0 /usr/lib/libmaxminddb.so && \
    luarocks install lua-resty-http && \
    luarocks install lua-resty-ipmatcher && \
    luarocks install lua-resty-template && \
    luarocks install nginx-lua-prometheus && \
    luarocks install luajit-geoip


COPY ./lua-resty-pushover/lib/resty/* /usr/local/openresty/lualib/resty/
COPY ./lib/ /usr/local/openresty/lualib/
COPY ./nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY ./assets/ /opt/doorbell/assets/
