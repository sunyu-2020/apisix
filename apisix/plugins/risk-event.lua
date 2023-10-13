--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local bp_manager_mod = require("apisix.utils.batch-processor-manager")
local core = require("apisix.core")
local core_str = require("apisix.core.string")
local pairs = pairs
local ngx = ngx
local http = require("resty.http")
local req_get_body_data = ngx.req.get_body_data
local req_read_body = ngx.req.read_body
local batch_processor_manager = bp_manager_mod.new("risk logger")

local user_http_host_dev = "http://auac-inner-dev.yzw.cn.qa"
local user_http_host_qa = "http://auac-inner-qa.yzw.cn.qa"
local user_http_host_stg = "http://auac-inner-stg.yzw.cn"
local user_http_host_prd = "http://auac-inner.yzw.cn"
local user_http_uri = "/api/auac/sso/rpc/v1/auth/checkSsoUser"

local lrucache = core.lrucache.new({
    ttl = 300, count = 512
})
local user_lrucache = core.lrucache.new({
    ttl = 300, count = 1024 * 4
})

local schema = {
    type = "object",
    properties = {
        user_context = {
            type = "boolean",
            default = false
        },
        token_name = {
            type = "string",
            default = "x-yzw-auth-token"
        },
        env = {
            type = "string"
        },
        enable_intercept = {
            type = "boolean",
            default = false
        },
        global = {
            type = "boolean",
            default = false
        },
        rejected_code = {
            type = "integer", minimum = 200, maximum = 599, default = 503
        },
        rejected_msg = {
            type = "string", minLength = 1,
        },
        ip_whitelist = {
            type = "array",
            items = { anyOf = core.schema.ip_def },
            minItems = 1
        },
        host_white = {
            type = "boolean",
            default = "rcc.yzw.cn"
        },
        whitelist = {
            type = "array",
            items = {
                type = "object",
                properties = {
                    listId = {
                        type = "integer"
                    },
                    code = {
                        type = "string"
                    }
                }
            }
        },
        blacklist = {
            type = "array",
            items = {
                type = "object",
                properties = {
                    listId = {
                        type = "integer"
                    },
                    code = {
                        type = "string"
                    }
                }
            }

        },
        code = {
            type = "string"
        },
        rules = {
            type = "array",
            items = {
                type = "object",
                properties = {
                    host = {
                        type = "string"
                    },
                    uri_regex = {
                        type = "string"
                    },
                    target = {
                        type = "string"
                    },
                    black_list_key = {
                        type = "string"
                    }
                },
                minLength = 1,
                maxLength = 4096,
            }
        },
        risk_url = {
            type = "string",
        },
        http_timeout = {
            type = "integer",
            default = 100
        },
        include_req_body = { type = "boolean", default = false },
        include_resp_body = { type = "boolean", default = false },
    },
}

local plugin_name = "risk-event"

local _M = {
    version = 0.1,
    priority = 2901,
    name = plugin_name,
    schema = schema,
    run_policy = "prefer_route",
}

local function urlEncode(s)
    s = string.gsub(s, "([^%w%.%- ])", function(c)
        return string.format("%%%02X", string.byte(c))
    end)
    return string.gsub(s, " ", "+")
end

--发起http请求
local function httpRequest(conf, token)
    token = urlEncode(token)
    local params = {
        method = "GET",
    }
    local env = conf.env
    local host

    --获取用户中心host
    if env == "dev" then
        host = user_http_host_dev
    elseif env == "qa" then
        host = user_http_host_qa
    elseif env == "stg" then
        host = user_http_host_stg
    elseif env == "prd" then
        host = user_http_host_prd
    end

    local url = host .. user_http_uri .. "?token=" .. token

    core.log.info("防爬虫插件：用户中心url：", url)

    local httpc = http.new()
    httpc:set_timeout(conf.http_timeout)
    local res, err = httpc:request_uri(url, params)
    if err then
        return nil, err
    end

    return res, nil
end

local function getUser(conf, user_token)
    if not user_token then
        return nil
    end

    local response, err = httpRequest(conf, user_token)

    core.log.info("风控事件插件：获取的用户信息：", response.body)
    if not response.body then
        return nil
    end
    local response_body = core.json.decode(response.body)
    core.log.info("风控事件插件：是否调用成功 : ", response_body.success)

    if response_body.success == false then
        return nil
    end
    return response_body.data
end

local function is_access(res, err)
    if err then
        return true, nil
    end
    core.log.info("风控事件插件：获取的事件结果：", res.body)
    if not res then
        return true, nil
    elseif res.status ~= 200 then
        return true, nil
    end

    if not res.body then
        return true, nil
    end
    local body = core.json.decode(res.body)
    if not body then
        return true, nil
    end
    local data = body.data
    if not data then
        return true, nil
    end
    return data.access, res.body
end
function _M.rewrite(conf, ctx)
    local host = core.request.get_host(ctx)
    local uri = ctx.var.request_uri
    ctx.risk_uri = uri
    ctx.risk_host = host
    core.log.info("风控事件插件:host: ", host)
    core.log.info("风控事件插件:uri: ", uri)
    local white = false
    local remote_addr = core.request.get_ip(ctx)
    ctx.risk_remote_addr = remote_addr

    if conf.ip_whitelist then
        local matcher = lrucache(conf.ip_whitelist, nil,
                core.ip.create_ip_matcher, conf.ip_whitelist)
        if matcher then
            white = matcher:match(remote_addr)
        end
    end
    ctx.risk_white = white
    core.log.info("风控事件插件，是否命中白名单: ", white)
    --如果命中白名单，就直接放过
    if white then
        return
    end
    if conf.host_white == host then
        return
    end
    local request_id = core.request.header(ctx, "_trace_log_id");
    ctx.risk_request_id = request_id;
    local code = conf.code
    --如果没有规则，就执行通用上报逻辑
    if conf.global then
        local agent = core.request.header(ctx, "user-agent")
        ctx.risk_agent = agent
        local http_headers = core.request.headers(ctx);
        ctx.risk_http_headers = http_headers
        local http_headers_json = core.json.encode(http_headers)
        core.log.info("风控事件插件：风控header：", http_headers_json)
        local timestamp = ngx.now() * 1000
        --获取用户ip
        local requestBody = {}
        requestBody.requestId = request_id
        requestBody.code = code
        requestBody.whiteList = conf.whitelist
        local list = conf.blacklist
        local list_json = core.json.encode(list)
        core.log.info("风控事件插件：list_json：", list_json)
        requestBody.blackList = conf.blacklist
        requestBody.timestamp = timestamp
        ctx.risk_timestamp = timestamp;
        local data = {}
        if http_headers then
            data = http_headers
        end

        --获取用户token
        local token_name = conf.token_name
        if not token_name then
            token_name = "x-yzw-auth-token"
        end
        core.log.info("风控事件插件：token_name: ", token_name)
        local user_token = core.request.header(ctx, token_name);
        if not user_token then
            local token = "cookie_" .. token_name
            user_token = ngx.var[token]
        end
        core.log.info("风控事件插件:token: ", user_token)
        ctx.risk_user_token = user_token;

        data.uri = ctx.var.uri
        data.request_uri = uri
        data.token = user_token
        data.ip = remote_addr
        data.agent = agent
        --获取请求参数
        if conf.include_resp_body then
            data.request_type = "request"
        end
        if conf.include_req_body then
            req_read_body()
            local req_body = req_get_body_data()
            ctx.risk_request_body = req_body
        end

        local args = core.request.get_uri_args(ctx)
        ctx.risk_args = args

        core.log.info("风控事件插件:args: ", core.json.encode(args))

        requestBody.data = data
        local requestBodyJson = core.json.encode(requestBody)
        core.log.info("风控事件插件：发送风控事件消息请求体：", requestBodyJson)
        local params = {
            method = "POST",
            body = requestBodyJson,
            headers = {
                ["Content-Type"] = "application/json",
            }
        }
        local url = conf.risk_url
        core.log.info("风控事件插件：发送风控事件消息url：", url)
        local httpc = http.new()
        httpc:set_timeout(conf.http_timeout)
        local res, err = httpc:request_uri(url, params)
        if err then
            core.log.error("风控事件插件：消息发送失败：", err)
        end

        --如果开启了拦截，就进行拦截
        if conf.enable_intercept then
            local access, res_data = is_access(res, err)
            core.log.info("风控事件插件：访问结果：", access)
            if not access then
                core.response.set_header("Content-Type", "application/json")
                core.log.info("风控事件插件：执行拒绝操作：", conf.rejected_code, conf.rejected_msg)
                return 200, res_data
            end
        end
        return
    end

    for _, rule in pairs(conf.rules) do
        local match_host = rule.host
        core.log.info("风控事件插件：match_host: ", match_host)
        local regex_uri = rule.regex_uri
        if host == match_host then
            core.log.info("风控事件插件：regex_uri: ", regex_uri)
            local from = core_str.has_prefix(uri, regex_uri)
            if from then
                --获取时间戳
                local timestamp = ngx.now() * 1000
                --获取请求目标
                local target = rule.target
                --获取用户token
                local token_name = conf.token_name
                if not token_name then
                    token_name = "x-yzw-auth-token"
                end
                core.log.info("风控事件插件：token_name: ", token_name)
                local user_token = core.request.header(ctx, token_name);
                if not user_token then
                    local token = "cookie_" .. token_name
                    user_token = ngx.var[token]
                end
                core.log.info("风控事件插件:token: ", user_token)
                --获取http header
                local agent = core.request.header(ctx, "user-agent")
                local http_headers = core.request.headers(ctx);
                local http_headers_json = core.json.encode(http_headers)
                core.log.info("风控事件插件：风控header：", http_headers_json)
                --获取用户ip
                local requestBody = {}
                requestBody.requestId = request_id
                requestBody.code = code
                requestBody.whiteList = conf.whitelist
                local list = conf.blacklist
                local list_json = core.json.encode(list)
                core.log.info("风控事件插件：list_json：", list_json)
                requestBody.blackList = conf.blacklist
                requestBody.timestamp = timestamp

                local data = {}
                if http_headers then
                    data = http_headers
                end

                --获取用户信息
                if conf.user_context then
                    --通过缓存
                    local user_context = user_lrucache(user_token, nil, getUser, conf, user_token)
                    if user_context then
                        user_context.apps = nil
                        user_context.companyProfiles = nil
                        user_context.rootOrgs = nil
                        user_context.currentUserRootOrg = nil
                        user_context.roles = nil
                        local user_context_json = core.json.encode(user_context)
                        core.log.info("风控事件插件：风控用户：", user_context_json)
                        core.table.merge(data, user_context)
                    end
                end
                data.uri = ctx.var.uri
                data.request_uri = uri
                data.target = target
                data.token = user_token
                data.ip = remote_addr
                data.agent = agent
                requestBody.data = data
                local requestBodyJson = core.json.encode(requestBody)
                core.log.info("风控事件插件：发送风控事件消息请求体：", requestBodyJson)
                local params = {
                    method = "POST",
                    body = requestBodyJson,
                    headers = {
                        ["Content-Type"] = "application/json",
                    }
                }

                local url = conf.risk_url
                local httpc = http.new()
                httpc:set_timeout(conf.http_timeout)
                local res, err = httpc:request_uri(url, params)
                if err then
                    core.log.error("风控事件插件：消息发送失败：", err)
                end
                --如果开启了拦截
                if conf.enable_intercept then
                    local access, res_data = is_access(res, err)
                    core.log.info("风控事件插件：访问结果：", access)
                    if not access then
                        core.log.info("风控事件插件：执行拒绝操作：", conf.rejected_code, conf.rejected_msg)
                        core.response.set_header("Content-Type", "application/json")
                        return 200, res_data
                    end
                end
            end
        end

    end
end

local function send_http_data(conf, log_message)
    core.log.info("风控事件插件：发送风控事件消息请求体：", log_message)
    local params = {
        method = "POST",
        body = log_message,
        headers = {
            ["Content-Type"] = "application/json",
        }
    }

    local url = conf.risk_url
    core.log.info("风控事件插件：发送风控事件消息url：", url)
    local httpc = http.new()
    httpc:set_timeout(conf.http_timeout)
    return httpc:request_uri(url, params)
end

function _M.body_filter(conf, ctx)
    if conf.include_resp_body then
        local final_body = core.response.hold_body_chunk(ctx, true)
        if not final_body then
            return
        end
        ctx.resp_body = final_body
    end
end

function _M.log(conf, ctx)
    local host = ctx.risk_host
    if conf.host_white == host then
        return
    end
    if ctx.risk_white then
        return
    end
    if conf.include_resp_body then
        local data = {}
        if ctx.resp_body then
            local response_body = ctx.resp_body
            core.log.info("风控事件插件：response_body：", response_body)
            response_body = core.json.decode(response_body)
            if response_body ~= nil and next(response_body) then
                core.table.merge(data, response_body)
            end
        end
        local requestBody = {}
        requestBody.code = conf.code
        local request_id = ctx.risk_request_id
        requestBody.requestId = request_id
        local body = ctx.risk_request_body
        if body then
            local request_body = core.json.decode(body)
            if request_body ~= nil and next(request_body) then
                core.table.merge(data, request_body)
                core.log.info("风控事件插件：request_body：", core.json.encode(body))
            end
        end
        local args = ctx.risk_args
        if args ~= nil and next(args) then
            core.table.merge(data, args)
        end

        local http_headers = ctx.risk_http_headers
        if http_headers then
            core.table.merge(data, http_headers)
        end

        requestBody.timestamp = ctx.risk_timestamp

        local agent = ctx.risk_agent
        local user_token = ctx.risk_user_token
        local remote_addr = ctx.risk_remote_addr

        data.status = ngx.status
        data.uri = ctx.var.uri
        data.request_uri = ctx.risk_uri
        data.token = user_token
        data.ip = remote_addr
        data.agent = agent
        data.request_type = "response"
        requestBody.data = data
        if batch_processor_manager:add_entry(conf, requestBody) then
            return
        end
        -- Generate a function to be executed by the batch processor
        local func = function(entries, batch_max_size)
            local entity, err = core.json.encode(entries[1])
            if not entity then
                return false, 'error occurred while encoding the data: ' .. err
            end
            return send_http_data(conf, entity)
        end
        batch_processor_manager:add_entry_to_new_processor(conf, requestBody, ctx, func)
    end
end

return _M
