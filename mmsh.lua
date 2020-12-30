local _M = {
    _VERSION  = 'v0.20.12.31',
    _AUTHOR   = 'kEvinlove1986@gmail.com',
    _RULES    = {}
}
local cjson = require 'cjson.safe'
local http = require 'resty.http'

_M.ACTIONS = {
    ban = function(res)
        if res==nil then
            ngx.exit(403)
            return
        end
        ngx.say(res.body)
        ngx.exit(res.status)
    end
}

_M.MATCHER = {

    regex = function(text, pattern, reverse)
        if text == nil then text = '' end
        if reverse ~= 0 then
            return ngx.re.match(text, pattern) == nil
        else
            return ngx.re.match(text, pattern)
        end
    end,
 

    equals = function(text, pattern, reverse)
        if reverse ~= 0 then
            return text ~= pattern
        else
            return text == pattern
        end
    end,



    startswith = function(text, pattern, reverse)
        if text == nil then text = '' end
        if reverse ~= 0 then
            return string.sub(text, 1, #pattern) ~= pattern
        else
            return string.sub(text, 1, #pattern) == pattern
        end
    end,


    endswith = function(text, pattern, reverse)
        if text == nil then text = '' end
        if reverse ~= 0 then
            return string.sub(text, #pattern + 1) ~= pattern
        else
            return string.sub(text, #pattern + 1) == pattern
        end
    end,


    contains = function(text, pattern, reverse)
        if text == nil then text = '' end
        if reverse ~= 0 then
            return string.find(text, pattern) < 1
        else
            return string.find(text, pattern) > 0
        end
    end
}

local function match_single_rule(rules)
    for _, rule in pairs(rules["rule"]) do
        local match_zone = rule['mz']
        local match_method = rule['method']
        local match_target = rule['pattern']
        local match_rev = rule['rev']
        if match_zone == 'ip' then
            if _M.MATCHER[match_method](ngx.var.remote_addr, match_target, match_rev) == false then return end
        elseif string.sub(match_zone, 1, 5) == 'http_' then
            if _M.MATCHER[match_method](ngx.var[match_zone], match_target, match_rev) == false then return end
        elseif string.sub(match_zone, 1, 7) == 'cookie_' then
            if _M.MATCHER[match_method](ngx.var[match_zone], match_target, match_rev) == false then return end
        elseif string.sub(match_zone, 1, 4) == 'arg_' then
            if _M.MATCHER[match_method](ngx.var[match_zone], match_target, match_rev) == false then return end
        elseif match_zone == 'method' then
            if _M.MATCHER[match_method](ngx.req.get_method(), match_target, match_rev) == false then return end
        elseif match_zone == 'path' then
            local path
            local request_uri = ngx.var.request_uri
            local pos = string.find(request_uri, '?')
            if pos then
                path = string.sub(request_uri, 1, pos - 1)
            else
                path = request_uri
            end
            if _M.MATCHER[match_method](path, match_target, match_rev) == false then return end
        elseif match_zone == 'qs' then
            if _M.MATCHER[match_method](ngx.var.query_string, match_target, match_rev) == false then return end
        elseif match_zone == 'body' then
            ngx.req.read_body()
            if _M.MATCHER[match_method](ngx.req.get_body_data(), match_target, match_rev) == false then return end
        elseif string.sub(match_zone, 1, 9) == 'body_arg_' then
            ngx.req.read_body()
            for k, v in pairs(ngx.req.get_post_args()) do
                if k == string.sub(match_zone, 9) and
                _M.MATCHER[match_method](v, match_target, match_rev) == false then return end
            end
        end
    end
    return true
end


function _M.check_request()
    for _ruleid, rule in pairs(_M._RULES) do
        if match_single_rule(rule) == true then
            if rule["forceblock"] == 1 then
                ngx.var.sec_ruile_id = rule["ruleid"]
                _M.ACTIONS.ban(nil)
                return
            else
                _M.forward_request(rule)
            end
            ngx.ctx.sec_ruleid = rule["ruleid"]
            break
        end
    end
end

function _M.run(premature)
    if premature then return end
    _M.update_rules()
    local ok, err = ngx.timer.at(_M._CFG.rule_update_interval, _M.run)
    if not ok then
        if err ~= 'process exiting' then
            ngx.log(ngx.ERR, 'failed to create timer', err)
        end
        return
    end
end

function _M.update_rules()
    local httpc = http.new()
    local res, err = httpc:request_uri(
        _M._CFG.policy_server, 
        {
            method = "GET",
            headers = {
                ["X-Match-Version"] = _M._CFG.version
            }
        }
    )
    if res then
       local data = cjson.decode(res.body)
       if not data or data["stat"] < 2 then
            return
       end
       _M._RULES = {}
       for _, rule in ipairs(data["rules"]) do
           table.insert(_M._RULES, rule)
       end
       _M._CFG.version = data["version"]
       ngx.log(ngx.ERR, 'new rule version installed')
    end
end

function _M.forward_request(ruleid)

    local httpc = http.new()
    httpc:set_timeout(rule['timeout'] or _M._CFG['default_forward_timeout'])
    local reqheaders = ngx.req.get_headers()
    reqheaders["x-waf-match-id"] = rule['ruleid']
    reqheaders["x-real-ip"] = ngx.var.remote_addr
    reqheaders["x-protocol"] = ngx.var.server_protocol
    local method = ngx.req.get_method()
    if method == "POST" then
        ngx.req.read_body()
    end
    local res, err = httpc:request_uri(
        _M._CFG["waf_server"]..ngx.var.request_uri,
        {
            method = method,
            headers = reqheaders,
            body = ngx.req.get_body_data()
        }
    )
    if not err then
        if res.headers["X-Waf-Status"] == "block" then
            _M.ACTIONS.ban(res)
        end
    end

end


_M._CFG = {

    policy_server        = "http://127.0.0.1:4009/update_rule",        --[[  规则升级地址 ]]
    rule_update_interval = 5,                                          --[[  规则升级循环时间 ]]
    waf_server           = "http://127.0.0.1:4008",                    --[[  match的请求将转发给waf的地址 ]]
    rule_version         = "0000000000",
    default_forward_timeout = 300
}


return _M
