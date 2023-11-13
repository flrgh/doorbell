local _M = {
  _VERSION = require("doorbell.constants").version,
}

local rules = require "doorbell.rules"
local log = require "doorbell.log"

local ipmatcher = require "resty.ipmatcher"

local ngx         = ngx
local re_find     = ngx.re.find
local now         = ngx.now
local update_time = ngx.update_time
local assert      = assert
local max         = math.max
local insert      = table.insert
local sort        = table.sort
local pairs       = pairs


local new_match, release_match
do
  local tb = require "tablepool"
  local fetch = tb.fetch
  local release = tb.release
  local pool = "doorbell.rule.match"

  local size = 5
  local narr, nrec = size, size + 3

  --- The match table is a sequence of doorbell rules.
  ---
  ---@class doorbell.match : table
  ---
  ---@field conditions integer
  ---@field terminate  boolean
  ---@field n          integer
  ---
  ---@field [integer]  doorbell.rule
  ---
  ---@field [string]   integer # condition match count per rule


  ---@return doorbell.match
  function new_match()
    local m = fetch(pool, narr, nrec)
    m.conditions = 0
    m.n = 0
    m.terminate = false
    return m
  end

  ---@param m doorbell.rule[]
  function release_match(m)
    release(pool, m)
  end
end

---@alias doorbell.rule.criteria
---| "addr"
---| "cidr"
---| "path(plain)"
---| "path(regex)"
---| "host"
---| "ua(plain)"
---| "ua(regex)"
---| "method"
---| "country"
---| "asn"
---| "org(plain)"
---| "org(regex)"

local CRITERIA = {
  addr       = "addr",
  cidr       = "cidr",
  path_plain = "path(plain)",
  path_regex = "path(regex)",
  host       = "host",
  ua_plain   = "ua(plain)",
  ua_regex   = "ua(regex)",
  method     = "method",
  country    = "country",
  asn        = "asn",
  org_plain  = "org(plain)",
  org_regex  = "org(regex)",
}

local cmp_rule = rules.compare

---@param list doorbell.rule[]
function _M.new(list)
  local criteria = {}

  local max_possible_conditions = 0

  do
    update_time()
    local time = now()

    ---@param rule doorbell.rule
    ---@param match doorbell.rule.criteria
    ---@param value string|integer
    local function add_criteria(rule, match, value)
      if rule:expired(time) then
        log.debugf("not adding rule %s to matcher (expired at %s)",
                   rule.id, rule.expires)
        return
      end

      max_possible_conditions = max(max_possible_conditions, rule.conditions)

      criteria[match] = criteria[match] or {}
      criteria[match][value] = criteria[match][value] or { n = 0 }

      insert(criteria[match][value], rule)
      criteria[match][value].n = criteria[match][value].n + 1
    end

    for i = 1, #list do
      local r = list[i]

      if r.addr then
        add_criteria(r, CRITERIA.addr, r.addr)
      end

      if r.method then
        add_criteria(r, CRITERIA.method, r.method)
      end

      if r.path then
        if rules.is_regex(r.path) then
          add_criteria(r, CRITERIA.path_regex, rules.regex(r.path))
        else
          add_criteria(r, CRITERIA.path_plain, r.path)
        end
      end

      if r.host then
        add_criteria(r, CRITERIA.host, r.host)
      end

      if r.cidr then
        add_criteria(r, CRITERIA.cidr, r.cidr)
      end

      if r.ua then
        if rules.is_regex(r.ua) then
          add_criteria(r, CRITERIA.ua_regex, rules.regex(r.ua))
        else
          add_criteria(r, CRITERIA.ua_plain, r.ua)
        end
      end

      if r.country then
        add_criteria(r, CRITERIA.country, r.country)
      end

      if r.asn then
        add_criteria(r, CRITERIA.asn, r.asn)
      end

      if r.org then
        if rules.is_regex(r.org) then
          add_criteria(r, CRITERIA.org_regex, rules.regex(r.org))
        else
          add_criteria(r, CRITERIA.org_plain, r.org)
        end
      end
    end
  end

  local empty = {}

  local paths_plain = criteria[CRITERIA.path_plain] or empty
  local paths_regex = { n = 0 }

  for re, rs in pairs(criteria[CRITERIA.path_regex] or {}) do
    insert(paths_regex, {re, rs})
    paths_regex.n = (paths_regex.n or 0) + 1
  end

  local hosts   = criteria[CRITERIA.host]  or empty
  local methods = criteria[CRITERIA.method] or empty
  local countries = criteria[CRITERIA.country] or empty


  local addrs = criteria[CRITERIA.addr]  or empty
  local cidrs = assert(ipmatcher.new_with_value(criteria[CRITERIA.cidr] or {}))


  local uas_plain = criteria[CRITERIA.ua_plain] or empty
  local uas_regex = { n = 0 }

  for re, rs in pairs(criteria[CRITERIA.ua_regex] or {}) do
    insert(uas_regex, {re, rs})
    uas_regex.n = (uas_regex.n or 0) + 1
  end

  local asns = criteria[CRITERIA.asn] or empty

  local orgs_plain = criteria[CRITERIA.org_plain] or empty
  local orgs_regex = { n = 0 }

  for re, rs in pairs(criteria[CRITERIA.org_regex] or {}) do
    insert(orgs_regex, {re, rs})
    orgs_regex.n = (orgs_regex.n or 0) + 1
  end


  ---@param t table
  ---@param value string
  local function regex_match(t, value)
    for i = 1, t.n do
      local item = t[i]
      local re = item[1]
      if re_find(value, re, "oj") then
        return item[2]
      end
    end
  end

  ---@param match doorbell.match
  ---@param matched doorbell.rule[]
  ---@param received_at number
  local function update_match(match, matched, received_at)
    if match.terminate then return end
    if not matched then return end

    for i = 1, matched.n do
      if match.terminate then return end

      local rule = matched[i]
      local conditions = rule.conditions
      local terminate = rule.terminate

      if (terminate or conditions >= match.conditions)
         and not rule:expired(received_at)
      then
        local hash = rule.hash
        local count = (match[hash] or 0) + 1
        match[hash] = count

        -- if all of the match conditions for this rule have been met, add it to
        -- the array-like part of the match table
        if count == conditions then
          local n = match.n

          if terminate then
            match.terminate = true
          end

          -- if our rule has met more conditions than any other, we can clear out
          -- prior matches
          if terminate or count > match.conditions then
            match.conditions = count
            match[1] = rule
            for j = 2, n do
              match[j] = nil
            end
            match.n = 1

          -- otherwise, just append the rule to the match table
          elseif count == match.conditions then
            n = n + 1
            match[n] = rule
            match.n = n
          end
        end
      end
    end
  end

  ---@param req doorbell.forwarded_request
  ---@return doorbell.rule?
  return function(req)
    local addr    = assert(req.addr, "missing request addr")
    local path    = assert(req.path, "missing request path")
    local host    = assert(req.host, "missing request host")
    local method  = assert(req.method, "missing request method")
    local ua      = req.ua or ""
    local country = req.country
    local asn     = req.asn or 0
    local org     = req.org or ""
    local received_at = req.received_at

    local match = new_match()

    update_match(match, addrs[addr], received_at)
    update_match(match, paths_plain[path], received_at)
    update_match(match, methods[method], received_at)
    update_match(match, hosts[host], received_at)
    update_match(match, uas_plain[ua], received_at)
    update_match(match, asns[asn], received_at)
    update_match(match, orgs_plain[org], received_at)

    if country then
      update_match(match, countries[country], received_at)
    end

    if not match.terminate then
      -- plain/exact matches trump regex or cidr lookups
      --
      -- loop through each match whose conditions are met and check to see if
      -- we've matched the path, ua, or addr already
      --
      -- first, see if we have a match with the maximal number of conditions met
      if match.conditions < max_possible_conditions then
        update_match(match, cidrs:match(addr), received_at)

        if not match.terminate then
          update_match(match, regex_match(paths_regex, path), received_at)
        end

        if not match.terminate then
          update_match(match, regex_match(uas_regex, ua), received_at)
        end

        if not match.terminate then
          update_match(match, regex_match(orgs_regex, org), received_at)
        end
      end
    end

    if match.n > 1 then
      sort(match, cmp_rule)
    end

    local res = match[1]
    release_match(match)

    return res
  end
end

return _M
