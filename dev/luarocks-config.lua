pwd = os_getenv("PWD")

rocks_trees = {
    {
        name = "dev",
        root = pwd .. "/dev",
    },
}

lua_interpreter = "luajit"
