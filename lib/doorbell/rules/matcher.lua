local _M = {
  _VERSION = require("doorbell.constants").version,
}

local rules = require "doorbell.rules"

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

  ---@return doorbell.rule[]
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
---| '"addr"'
---| '"cidr"'
---| '"path(plain)"'
---| '"path(regex)"'
---| '"host"'
---| '"ua(plain)"'
---| '"ua(regex)"'
---| '"method"'
---| '"country"'

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
    ---@param value string
    local function add_criteria(rule, match, value)
      if rule:expired(time) then
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

  ---@param match doorbell.rule[]
  ---@param matched doorbell.rule[]
  local function update_match(match, matched)
    if match.terminate then return end
    if not matched then return end

    for i = 1, matched.n do
      if match.terminate then return end

      local rule = matched[i]
      local conditions = rule.conditions
      local terminate = rule.terminate

      if terminate or conditions >= match.conditions then
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

  ---@param req doorbell.request
  ---@return doorbell.rule?
  return function(req)
    local addr   = assert(req.addr, "missing request addr")
    local path   = assert(req.path, "missing request path")
    local host   = assert(req.host, "missing request host")
    local method = assert(req.method, "missing request method")
    local ua     = req.ua or ""
    local country = req.country

    local match = new_match()

    update_match(match, addrs[addr])
    update_match(match, paths_plain[path])
    update_match(match, methods[method])
    update_match(match, hosts[host])
    update_match(match, uas_plain[ua])

    if country then
      update_match(match, countries[country])
    end

    if not match.terminate then
      -- plain/exact matches trump regex or cidr lookups
      --
      -- loop through each match whose conditions are met and check to see if
      -- we've matched the path, ua, or addr already
      --
      -- first, see if we have a match with the maximal number of conditions met
      if match.conditions < max_possible_conditions then
        update_match(match, cidrs:match(addr))
        if not match.terminate then
          update_match(match, regex_match(paths_regex, path))
        end
        if not match.terminate then
          update_match(match, regex_match(uas_regex, ua))
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
