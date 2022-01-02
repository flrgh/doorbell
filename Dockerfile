FROM openresty/openresty:alpine-fat

RUN luarocks install lua-resty-http && \
    luarocks install lua-resty-ipmatcher && \
    luarocks install lua-resty-template

COPY ./lua-resty-pushover/lib/resty/* /usr/local/openresty/lualib/resty/
COPY ./lib/ /usr/local/openresty/lualib/
COPY ./nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
