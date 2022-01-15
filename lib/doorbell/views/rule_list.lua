local rules = require "doorbell.rules.manager"

local date = os.date
local header = ngx.header

local function tfmt(stamp)
  return date("%Y-%m-%d %H:%M:%S", stamp)
end

---@type doorbell.view
---@param ctx doorbell.ctx
return function(ctx)
  local list = rules.list()

  table.sort(list, function(a, b)
    return a.created > b.created
  end)

  local keys = {"addr", "cidr", "host", "ua", "method", "path", "country"}
  local t = ngx.now()

  for _, rule in ipairs(list) do
    local matches = {}
    for _, key in ipairs(keys) do
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

    if rule.last_match then
      rule.last_match = tfmt(rule.last_match)
    else
      rule.last_match = "never"
    end

    rule.match_count = rule.match_count or 0

  end

  header["content-type"] = "text/html"
  ngx.say(ctx.template({ rules = list, conditions = keys }))
  return ngx.exit(ngx.HTTP_OK)
end
