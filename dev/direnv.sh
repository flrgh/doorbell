_path_munge() {
    local -r var=$1
    local -r elem=$2

    local -r val=${!var:-}

    if [[ -z ${val:-} ]]; then
        printf -v "$var" '%s' "$elem"
        return
    fi

    if [[ $val =~ (^|\;)"$elem"(\;|$) ]]; then
        return
    fi

    printf -v "$var" '%s;%s' "$elem" "$val"
}

LUA_PATH_add() {
    local path; path=$(realpath "$1")
    if [[ -e $path ]]; then
        _path_munge LUA_PATH "$path/?.lua"
        _path_munge LUA_PATH "$path/?/init.lua"
    else
        echo "WARN: cannot add $path to LUA_PATH"
        return 1
    fi
}

LUA_CPATH_add() {
    local path; path=$(realpath "$1")
    if [[ -e $path ]]; then
        _path_munge LUA_CPATH "$path/?.so"
    else
        echo "WARN: cannot add $path to LUA_CPATH"
        return 1
    fi
}


# discover OpenResty location for all the pathing things
if has openresty; then
    openresty=$(type -p openresty)
    prefix=${openresty%/*/*}

    echo "INFO: found OpenResty in $prefix"

    # ensures that luarocks will use OpenResty's luajit interpreter
    PATH_add "$prefix/luajit/bin"

    export LUAROCKS_CONFIG=$PWD/luarocks-config.lua

    unset LUA_PATH LUA_CPATH
    export LUA_PATH LUA_CPATH

    # add luarocks paths
    LUA_PATH_add "$PWD/share/lua/5.1"
    LUA_CPATH_add "$PWD/lib/lua/5.1"
    PATH_add "$PWD/bin"

    # add OpenResty paths
    LUA_PATH_add "$prefix/lualib"
    LUA_CPATH_add "$prefix/lualib"
else
    echo "WARN: no OpenResty installation found"
fi

LUA_PATH_add ..
LUA_PATH_add ../lib

PATH_add ../bin
