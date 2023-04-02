
-- stolen from Kong
local find_ca_certs
do
  local possible = {
    "/etc/ssl/certs/ca-certificates.crt",                -- Debian/Ubuntu/Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",                  -- Fedora/RHEL 6
    "/etc/ssl/ca-bundle.pem",                            -- OpenSUSE
    "/etc/pki/tls/cacert.pem",                           -- OpenELEC
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", -- CentOS/RHEL 7
    "/etc/ssl/cert.pem",                                 -- OpenBSD, Alpine
  }

  function find_ca_certs()
    for _, path in ipairs(possible) do
      local fh = io.open(path, "r")
      if fh then
        fh:close()
        return path
      end
    end
  end
end


return {
  access_log       = "logs/access.log",
  error_log        = "logs/error.log",
  error_log_level  = "debug",
  listen           = "9876",
  resolver         = "8.8.8.8",
  user             = "nobody",
  worker_processes = "auto",
  ca_certs         = find_ca_certs(),
  daemon           = "off",
}
