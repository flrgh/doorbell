FROM openresty/openresty:alpine-fat

RUN luarocks install lua-resty-http && \
    luarocks install lua-resty-ipmatcher

COPY ./lua-resty-pushover/lib/resty/* /usr/local/openresty/lualib/resty/
COPY ./lib/doorbell.lua /usr/local/openresty/lualib/
COPY ./nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
