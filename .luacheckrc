std             = "ngx_lua"
max_line_length = false

globals = {
  "_TEST",
}

not_globals = {
    "string.len",
    "table.getn",
}
