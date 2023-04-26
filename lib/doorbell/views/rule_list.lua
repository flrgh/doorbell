local rules = require "doorbell.rules"
local manager = require "doorbell.rules.manager"
local stats = require "doorbell.rules.stats"
local http = require "doorbell.http"

local date = os.date

local function tfmt(stamp)
  return date("%Y-%m-%d %H:%M:%S", stamp)
end

---@type doorbell.view
---@param ctx doorbell.ctx
return function(ctx)
  local list = manager.list()

  stats.decorate_list(list)

  table.sort(list, function(a, b)
    return a.created > b.created
  end)

  local t = ngx.now()

  for _, rule in ipairs(list) do
    local matches = {}

    for _, key in ipairs(rules.CONDITIONS) do
      if rule[key] then
        table.insert(matches, key)
      end
    end

    rule.match = table.concat(matches, ",")
    rule.created = tfmt(rule.created)

    if rule.expires == 0 then
      rule.expires = "never"

    elseif rule.expires < t then
      rule.expires = "expired"

    else
      rule.expires = tfmt(rule.expires)
    end


    if rule.last_match and rule.last_match > 0 then
      rule.last_match = tfmt(rule.last_match)

    else
      rule.last_match = "never"
    end

    rule.match_count = rule.match_count or 0

  end

  http.send(200,
            ctx.template({ rules = list, conditions = rules.CONDITIONS })
            { ["content-type"] = "text/html" })
end
