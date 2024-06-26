std             = "ngx_lua"
max_line_length = false

globals = {
  "_TEST",
  "ngx.config.is_console",
  "ngx.run_worker_thread",
  "table.unpack",
}

not_globals = {
    "string.len",
    "table.getn",
}

ignore = {
  -- don't complain when obj:method() doesn't make use of `self`
  "212/self",
}
