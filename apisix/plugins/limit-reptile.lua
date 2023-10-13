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
local limit_local_new = require("resty.limit.count").new
local core = require("apisix.core")
local apisix_plugin = require("apisix.plugin")
local configPatch = require("apisix.admin.routes").patch
local tab_insert = table.insert
local pairs = pairs
local http = require("resty.http")

local ip_second_limit_key = "ip_second_limit"
local ip_daily_limit_key = "ip_daily_limit"
local user_second_limit_key = "user_second_limit"
local user_daily_limit_key = "user_daily_limit"
local company_second_limit_key = "company_second_limit"
local company_daily_limit_key = "company_daily_limit"
local USER_TOKEN = "x-yzw-auth-token"
local plugin_name = "limit-reptile"
local limit_redis_cluster_new
local limit_redis_new
local second_times = 1
local daily_times = 86400

local user_http_host_dev = "http://auac-inner-dev.yzw.cn.qa"
local user_http_host_qa = "http://auac-inner-qa.yzw.cn.qa"
local user_http_host_stg = "http://auac-inner-stg.yzw.cn"
local user_http_host_prd = "http://auac-inner.yzw.cn"
local user_http_uri = "/api/auac/sso/rpc/v1/auth/checkSsoUser"

local message_host_dev = "http://msg-dev.yzw.cn.qa"
local message_host_qa = "http://msg-qa.yzw.cn.qa"
local message_host_stg = "http://msg-stg.yzw.cn"
local message_host_prd = "http://msg.yzw.cn"

local message_uri = "/api/msg/v1/public/messages/push"

do
    local redis_src = "apisix.plugins.limit-reptile.limit-reptile-redis"
    limit_redis_new = require(redis_src).new

    local cluster_src = "apisix.plugins.limit-count.limit-count-redis-cluster"
    limit_redis_cluster_new = require(cluster_src).new
end
local lrucache = core.lrucache.new({
    type = 'plugin', serial_creating = true,
})

local user_lrucache = core.lrucache.new({
    ttl = 300, count = 1024 * 4
})

local company_lrucache = core.lrucache.new({
    ttl = 300, count = 1024 * 4
})

local policy_to_additional_properties = {
    redis = {
        properties = {
            redis_host = {
                type = "string", minLength = 2
            },
            redis_port = {
                type = "integer", minimum = 1, default = 6379,
            },
            redis_password = {
                type = "string", minLength = 0,
            },
            redis_database = {
                type = "integer", minimum = 0, default = 0,
            },
            redis_timeout = {
                type = "integer", minimum = 1, default = 1000,
            },
        },
        required = { "redis_host" },
    },
    ["redis-cluster"] = {
        properties = {
            redis_cluster_nodes = {
                type = "array",
                minItems = 2,
                items = {
                    type = "string", minLength = 2, maxLength = 100
                },
            },
            redis_password = {
                type = "string", minLength = 0,
            },
            redis_timeout = {
                type = "integer", minimum = 1, default = 1000,
            },
            redis_cluster_name = {
                type = "string",
            },
        },
        required = { "redis_cluster_nodes", "redis_cluster_name" },
    },
}
local schema = {
    type = "object",
    properties = {
        ip = {
            type = "object",
            properties = {
                second_count = {
                    type = "integer"
                },
                daily_count = {
                    type = "integer"
                },
                whitelist = {
                    type = "array",
                    items = {
                        type = "string"
                    }
                },
                blacklist = {
                    type = "array",
                    items = {
                        type = "string"
                    }
                }
            }
        },
        user = {
            type = "object",
            properties = {
                second_count = {
                    type = "integer"
                },
                daily_count = {
                    type = "integer"
                },
                whitelist = {
                    type = "array",
                    items = {
                        type = "number"
                    }
                },
                blacklist = {
                    type = "array",
                    items = {
                        type = "number"
                    }
                }
            }
        },
        company = {
            type = "object",
            properties = {
                second_count = {
                    type = "integer"
                },
                daily_count = {
                    type = "integer"
                },
                whitelist = {
                    type = "array",
                    items = {
                        type = "number"
                    }
                },
                blacklist = {
                    type = "array",
                    items = {
                        type = "number"
                    }
                }
            }
        },
        policy = {
            type = "string",
            enum = { "local", "redis", "redis-cluster" },
            default = "local",
        },
        allow_degradation = { type = "boolean", default = false },
        allow_auto_disable = {
            type = "boolean",
            default = false
        },
        rejected_code = {
            type = "integer", minimum = 200, maximum = 599, default = 503
        },
        rejected_msg = {
            type = "string", minLength = 1,
        },
        match_token = {
            type = "array",
            items = "string"
        },
        env = {
            type = "string"
        },
        application = {
            type = "string"
        },
        message_application_key = {
            type = "string"
        },
        message_secret = {
            type = "string"
        },
        message_targets = {
            type = "array",
            items = "string"
        },
        http_timeout = {
            type = "integer",
            default = 2000
        }
    },
    ["if"] = {
        properties = {
            policy = {
                enum = { "redis" },
            },
        },
    },
    ["then"] = policy_to_additional_properties.redis,
    ["else"] = {
        ["if"] = {
            properties = {
                policy = {
                    enum = { "redis-cluster" },
                },
            },
        },
        ["then"] = policy_to_additional_properties["redis-cluster"],
    }
}

local _M = {
    version = 1.0,
    priority = 10002,
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end
    return true
end

local function create_limit_obj(time_window, count, conf)
    core.log.info("创建限流器实例-时间窗口：", time_window, "，调用次数：", count)

    if not conf.policy or conf.policy == "local" then
        return limit_local_new("plugin-" .. plugin_name, count,
                time_window)
    end

    if conf.policy == "redis" then
        return limit_redis_new("plugin-" .. plugin_name,
                count, time_window, conf)
    end

    if conf.policy == "redis-cluster" then
        return limit_redis_cluster_new("plugin-" .. plugin_name, count,
                time_window, conf)
    end

    return nil
end

--写入黑名单
local function insert_blacklist(ctx, conf)
    local route_id = ctx.route_id
    core.log.info("写入黑名单，路由id：", route_id)
    local code, err = configPatch(route_id, conf, "plugins/limit-reptile", {})
    core.log.info("写入黑名单，状态码：", code)
end
--发送公司禁用消息
local function send_company_disable_message(conf,company_id,company_name)
    local env = conf.env
    local host

    --获取时间戳
    local timestamp = ngx.now() * 1000
    --获取appKey
    local message_application_key = conf.message_application_key
    local message_secret = conf.message_secret
    local sign_string = message_application_key .. message_secret .. timestamp
    local req_id = message_application_key .. ":" .. timestamp
    local sign = ngx.md5(sign_string)
    local requestBody = {}
    requestBody.reqId = req_id
    requestBody.appKey = message_application_key
    requestBody.signature = sign
    requestBody.timestamp = timestamp
    local message_targets = conf.message_targets
    local targets = {}
    local date = os.date("%Y-%m-%d %H:%M:%S",os.time())
    for i,v in pairs(message_targets) do
        local item = {}
        item.seq = i
        item.targetType = 2
        item.targetValue = v
        item.templateId = "company_disable_dingtalk"
        item.extendParam = {
            companyId = company_id,
            companyName = company_name,
            date = date
        }
        tab_insert(targets,item)
    end
    requestBody.targets = targets


    --获取喵系中心host
    if env == "dev" then
        host = message_host_dev
    elseif env == "qa" then
        host = message_host_qa
    elseif env == "stg" then
        host = message_host_stg
    elseif env == "prd" then
        host = message_host_prd
    end
    local url = host .. message_uri
    local requestBodyJson = core.json.encode(requestBody)
    core.log.info("防爬虫插件：发送公司禁用消息请求体：",requestBodyJson)
    local params = {
        method = "POST",
        body = requestBodyJson,
        headers = {
            ["Content-Type"] = "application/json",
        }
    }

    local httpc = http.new()
    httpc:set_timeout(conf.http_timeout)
    local res, err = httpc:request_uri(url, params)
    if err then
        core.log.error("防爬虫插件：公司禁用消息发送失败：",err)
    end
end

--发送公司禁用消息
local function send_ip_disable_message(conf,ip)
    local env = conf.env
    local host

    --获取时间戳
    local timestamp = ngx.now() * 1000
    --获取appKey
    local message_application_key = conf.message_application_key
    local message_secret = conf.message_secret
    local sign_string = message_application_key .. message_secret .. timestamp
    local req_id = message_application_key .. ":" .. timestamp
    local sign = ngx.md5(sign_string)
    local requestBody = {}
    requestBody.reqId = req_id
    requestBody.appKey = message_application_key
    requestBody.signature = sign
    requestBody.timestamp = timestamp
    local message_targets = conf.message_targets
    local targets = {}
    local date = os.date("%Y-%m-%d %H:%M:%S",os.time())
    for i,v in pairs(message_targets) do
        local item = {}
        item.seq = i
        item.targetType = 2
        item.targetValue = v
        item.templateId = "ip_disable_dingtalk"
        item.extendParam = {
            ip = ip,
            date = date
        }
        tab_insert(targets,item)
    end
    requestBody.targets = targets


    --获取喵系中心host
    if env == "dev" then
        host = message_host_dev
    elseif env == "qa" then
        host = message_host_qa
    elseif env == "stg" then
        host = message_host_stg
    elseif env == "prd" then
        host = message_host_prd
    end
    local url = host .. message_uri
    local requestBodyJson = core.json.encode(requestBody)
    core.log.info("防爬虫插件：发送IP禁用消息请求体：",requestBodyJson)
    local params = {
        method = "POST",
        body = requestBodyJson,
        headers = {
            ["Content-Type"] = "application/json",
        }
    }

    local httpc = http.new()
    httpc:set_timeout(conf.http_timeout)
    local res, err = httpc:request_uri(url, params)
    if err then
        core.log.error("防爬虫插件：IP禁用消息发送失败：",err)
    end
end
--发送用户禁用消息
local function send_user_disable_message(conf,user_id,user_name)
    local env = conf.env
    local host

    --获取时间戳
    local timestamp = ngx.now() * 1000
    --获取appKey
    local message_application_key = conf.message_application_key
    local message_secret = conf.message_secret
    local sign_string = message_application_key .. message_secret .. timestamp
    local req_id = message_application_key .. ":" .. timestamp
    local sign = ngx.md5(sign_string)
    local requestBody = {}
    requestBody.reqId = req_id
    requestBody.appKey = message_application_key
    requestBody.signature = sign
    requestBody.timestamp = timestamp
    local message_targets = conf.message_targets
    local targets = {}
    local date = os.date("%Y-%m-%d %H:%M:%S",os.time())
    for i,v in pairs(message_targets) do
        local item = {}
        item.seq = i
        item.targetType = 2
        item.targetValue = v
        item.templateId = "user_disable_dingtalk"
        item.extendParam = {
            userId = user_id,
            userName = user_name,
            date = date
        }
        tab_insert(targets,item)
    end
    requestBody.targets = targets


    --获取喵系中心host
    if env == "dev" then
        host = message_host_dev
    elseif env == "qa" then
        host = message_host_qa
    elseif env == "stg" then
        host = message_host_stg
    elseif env == "prd" then
        host = message_host_prd
    end
    local url = host .. message_uri
    local requestBodyJson = core.json.encode(requestBody)
    core.log.info("防爬虫插件：发送用户禁用消息请求体：",requestBodyJson)
    local params = {
        method = "POST",
        body = requestBodyJson,
        headers = {
            ["Content-Type"] = "application/json",
        }
    }

    local httpc = http.new()
    httpc:set_timeout(conf.http_timeout)
    local res, err = httpc:request_uri(url, params)
    if err then
        core.log.error("防爬虫插件：用户禁用消息发送失败：",err)
    end
end

--检查IP白名单
local function check_ip_whitelist(conf, ctx)
    local pass = false
    local remote_addr = core.request.get_ip(ctx)
    core.log.info("防爬虫插件：白名单远程操作ip：", remote_addr)
    local ip_reptile_conf = conf.ip
    core.log.info("防爬虫插件: 获取白名单配置", core.json.delay_encode(ip_reptile_conf.whitelist))
    --校验白名单
    if ip_reptile_conf.whitelist then
        local matcher = lrucache(ip_reptile_conf.whitelist, nil,
                core.ip.create_ip_matcher, ip_reptile_conf.whitelist)
        if matcher then
            pass = matcher:match(remote_addr)
        end
    end
    if pass then
        core.log.error("防爬虫插件：ip命中白名单，命中ip：", remote_addr)
    end
    return pass
end

--校验黑名单
local function check_ip_blacklist(conf, ctx)
    local block = false
    local remote_addr = core.request.get_ip(ctx)
    core.log.error("防爬虫插件：黑名单远程操作ip：", remote_addr)
    local ip_reptile_conf = conf.ip
    core.log.error("防爬虫插件: 获取黑名单配置", core.json.delay_encode(ip_reptile_conf.blacklist))
    if ip_reptile_conf.blacklist then
        local matcher = lrucache(ip_reptile_conf.blacklist, nil,
                core.ip.create_ip_matcher, ip_reptile_conf.blacklist)
        if matcher then
            block = matcher:match(remote_addr)
        end
    end

    if block then
        core.log.error("防爬虫插件：ip命中黑名单，命中ip：", remote_addr)
    end
    return block;
end

--校验每秒限流
local function check_ip_second_limit(conf, ctx)
    local second_count = conf.ip.second_count
    if second_count then
        core.log.info("防爬虫插件：执行ip每秒限流，限流次数：", second_count)
        --获取限流器
        local lim, err
        lim, err = core.lrucache.plugin_ctx(lrucache, ctx, "ip_second", create_limit_obj, second_times, second_count, conf)
        --如果无法创建限流器，就按照是否允许自动执行选项选择
        if not lim then
            core.log.error("failed to fetch limit.count object: ", err)
            if conf.allow_degradation then
                return true
            end
            return false
        end
        local remote_addr = core.request.get_ip(ctx)
        --获取限流key，此处为用户端ip
        local route_id = ctx.route_id
        local key = ip_second_limit_key .. ":" .. route_id .. ":" .. apisix_plugin.conf_version(conf) .. ":" .. remote_addr
        core.log.info("limit key: ", key)

        local delay, remaining = lim:incoming(key, true)
        if not delay then
            local err = remaining
            if err == "rejected" then
                return false
            end

            core.log.error("failed to limit count: ", err)
            if conf.allow_degradation then
                return true
            end
            return false
        end
        return true
    end
    return true
end


--检查IP每天限流
local function check_ip_daily_limit(conf, ctx)
    --校验每天限流
    local daily_count = conf.ip.daily_count
    if daily_count then
        core.log.info("防爬虫插件：执行ip每天限流，限流次数：", daily_count)
        --获取限流器
        local lim, err
        lim, err = core.lrucache.plugin_ctx(lrucache, ctx, "ip_daily", create_limit_obj, daily_times, daily_count, conf)
        --如果无法创建限流器，就按照是否允许自动执行选项选择
        if not lim then
            core.log.error("failed to fetch limit.count object: ", err)
            if conf.allow_degradation then
                return true
            end
            return false
        end
        local remote_addr = core.request.get_ip(ctx)
        local route_id = ctx.route_id
        --获取限流key，此处为用户端ip
        local key = ip_daily_limit_key .. ":" .. route_id .. ":" .. apisix_plugin.conf_version(conf) .. ":" .. remote_addr
        core.log.info("限流key: ", key)

        local delay, remaining = lim:incoming(key, true)
        if not delay then
            local err = remaining
            if err == "rejected" then
                return false
            end
            core.log.error("failed to limit count: ", err)
            if conf.allow_degradation then
                return true
            end
            return false
        end
        return true
    end
    return true
end
--是否包含元素
local function hasNumber(number, numbers)
    for k, v in pairs(numbers) do
        core.log.info("匹配数据:", v, ",目标数据:", number)
        if tonumber(number) == v then
            core.log.info("匹配成功,匹配数据:", number)
            return true
        end
    end
    return false
end
--是否包含成员
local function hasMember(member,members)
    for k, v in pairs(members) do
        core.log.info("匹配数据:", v, ",目标数据:", member)
        if member == v then
            core.log.info("匹配成功,匹配数据:", member)
            return true
        end
    end
    return false
end

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

    core.log.info("防爬虫插件：获取的用户信息：", response.body)
    if not response.body then
        return nil
    end
    local response_body = core.json.decode(response.body)
    core.log.info("防爬虫插件：是否调用成功 : ", response_body.success)

    if response_body.success == false then
        return nil
    end
    return response_body.data
end
--校验用户白名单
local function check_user_whitelist(conf, user_id)
    local pass = false
    core.log.info("防爬虫插件：白名单远程操作userId：", user_id)
    local user_reptile_conf = conf.user
    core.log.info("防爬虫插件: 获取白名单配置", core.json.delay_encode(user_reptile_conf.whitelist))
    --校验白名单
    if user_reptile_conf.whitelist then
        pass = hasNumber(user_id, user_reptile_conf.whitelist)
    end
    if pass then
        core.log.error("防爬虫插件：用户命中白名单，命中ip：", user_id)
    end
    return pass
end
--校验用户黑名单
local function check_user_blacklist(conf, user_id)
    local block = false
    core.log.info("防爬虫插件：黑名单远程操作userId：", user_id)
    local user_reptile_conf = conf.user
    core.log.info("防爬虫插件: 获取黑名单配置", core.json.delay_encode(user_reptile_conf.blacklist))
    --校验白名单
    if user_reptile_conf.blacklist then
        block = hasNumber(user_id, user_reptile_conf.blacklist)
    end
    if block then
        core.log.error("防爬虫插件：用户命中黑名单，命中ip：", user_id)
    end
    return block
end

--校验用户每秒限流
local function check_user_second_limit(conf, ctx, user_id)
    local second_count = conf.user.second_count
    if second_count then
        core.log.info("防爬虫插件：执行用户每秒限流，限流次数：", second_count)
        --获取限流器
        local lim, err
        lim, err = core.lrucache.plugin_ctx(lrucache, ctx, "user_second", create_limit_obj, second_times, second_count, conf)
        --如果无法创建限流器，就按照是否允许自动执行选项选择
        if not lim then
            core.log.error("failed to fetch limit.count object: ", err)
            if conf.allow_degradation then
                return true
            end
            return false
        end

        --获取限流key，此处为用户id
        local route_id = ctx.route_id
        local key = user_second_limit_key .. ":" .. route_id .. ":" .. apisix_plugin.conf_version(conf) .. ":" .. user_id
        core.log.info("limit key: ", key)

        local delay, remaining = lim:incoming(key, true)
        if not delay then
            local err = remaining
            if err == "rejected" then
                return false
            end

            core.log.error("failed to limit count: ", err)
            if conf.allow_degradation then
                return true
            end
            return false
        end
        return true
    end
    return true
end

--检查用户每天限流
local function check_user_daily_limit(conf, ctx, user_id)
    --校验每天限流
    local daily_count = conf.user.daily_count
    if daily_count then
        core.log.info("防爬虫插件：执行用户每天限流，限流次数：", daily_count)
        --获取限流器
        local lim, err
        lim, err = core.lrucache.plugin_ctx(lrucache, ctx, "user_daily", create_limit_obj, daily_times, daily_count, conf)
        --如果无法创建限流器，就按照是否允许自动执行选项选择
        if not lim then
            core.log.error("failed to fetch limit.count object: ", err)
            if conf.allow_degradation then
                return true
            end
            return false
        end

        --获取限流key，此处为用户端ip
        local route_id = ctx.route_id
        local key = user_daily_limit_key .. ":" .. route_id .. ":" .. apisix_plugin.conf_version(conf) .. ":" .. user_id
        core.log.info("限流key: ", key)

        local delay, remaining = lim:incoming(key, true)
        if not delay then
            local err = remaining
            if err == "rejected" then
                return false
            end
            core.log.error("failed to limit count: ", err)
            if conf.allow_degradation then
                return true
            end
            return false
        end
        return true
    end
    return true
end

local function check_ip(conf, ctx)
    local ip_reptile_conf = conf.ip
    --如果有ip防爬虫配置，就进行验证
    if ip_reptile_conf then
        --校验白名单
        local pass = check_ip_whitelist(conf, ctx);
        if pass then
            return true
        end
        --校验黑名单
        local block = check_ip_blacklist(conf, ctx)
        if block then
            return false
        end
        --校验ip每秒限流
        local remote_addr = core.request.get_ip(ctx)
        local second_limit = check_ip_second_limit(conf, ctx)

        if not second_limit then
            --如果开启自动禁用就将ip放到黑名单里
            if conf.allow_auto_disable then
                local blacklist = conf.ip.blacklist
                if not blacklist then
                    blacklist = {}
                end
                --如果不存在，就添加到黑名单中
                if not hasMember(remote_addr,blacklist) then
                    tab_insert(blacklist, remote_addr)
                    insert_blacklist(ctx, conf)
                    send_ip_disable_message(conf,remote_addr)
                end
            end
            return false
        end
        --校验ip每天限流
        local daily_limit = check_ip_daily_limit(conf, ctx)
        if not daily_limit then
            if conf.allow_auto_disable then
                local blacklist = conf.ip.blacklist
                if not blacklist then
                    blacklist = {}
                end
                if not hasMember(remote_addr,blacklist) then
                    tab_insert(blacklist, remote_addr)
                    insert_blacklist(ctx, conf)
                    send_ip_disable_message(conf,remote_addr)
                end
            end
            return false
        end
    end
    return true
end
--检查用户限流
local function check_user(conf, ctx)
    local user_reptile_conf = conf.user
    if user_reptile_conf then
        --通过缓存
        local user_token = core.request.header(ctx, USER_TOKEN);
        local user = user_lrucache(user_token, nil, getUser, conf, user_token)
        --如果获取不到用户，直接跳过
        if not user then
            return true
        end
        local user_id = user.id
        --验证用户白名单
        local pass = check_user_whitelist(conf, user_id)
        if pass then
            return true
        end
        --验证用户黑名单
        local block = check_user_blacklist(conf, user_id)
        if block then
            return false
        end
        local user_name = user.name
        --校验用户每秒限流
        local second_limit = check_user_second_limit(conf, ctx, user_id)
        if not second_limit then
            local blacklist = conf.user.blacklist
            if not blacklist then
                blacklist = {}
            end
            if not hasNumber(tonumber(user_id),blacklist) then
                core.table.insert(blacklist, tonumber(user_id))
                insert_blacklist(ctx, conf)
                send_user_disable_message(conf,user_id,user_name)
            end
            return false
        end
        --校验用户每天限流
        local daily_limit = check_user_daily_limit(conf, ctx, user_id)
        if not daily_limit then
            local blacklist = conf.user.blacklist
            if not blacklist then
                blacklist = {}
            end
            if not hasNumber(tonumber(user_id),blacklist) then
                core.table.insert(blacklist, tonumber(user_id))
                insert_blacklist(ctx, conf)
                send_user_disable_message(conf,user_id,user_name)
            end
            return false
        end

    end
    return true
end
--检查公司白名单
local function check_company_whitelist(conf, company_id)
    local pass = false
    core.log.info("防爬虫插件：白名单远程操作companyId：", company_id)
    local company_reptile_conf = conf.company
    core.log.info("防爬虫插件: 获取白名单配置", core.json.delay_encode(company_reptile_conf.whitelist))
    --校验白名单
    if company_reptile_conf.whitelist then
        pass = hasNumber(company_id, company_reptile_conf.whitelist)
    end
    if pass then
        core.log.error("防爬虫插件：公司命中白名单，命中ip：", company_id)
    end
    return pass
end

--校验公司黑名单
local function check_company_blacklist(conf, company_id)
    local block = false
    core.log.info("防爬虫插件：黑名单远程操作companyId：", company_id)
    local company_reptile_conf = conf.company
    core.log.info("防爬虫插件: 获取黑名单配置:", core.json.delay_encode(company_reptile_conf.blacklist))
    --校验白名单
    if company_reptile_conf.blacklist then
        block = hasNumber(company_id, company_reptile_conf.blacklist)
    end
    if block then
        core.log.error("防爬虫插件：公司命中黑名单，命中ip：", company_id)
    end
    return block
end

--校验公司每秒限流
local function check_company_second_limit(conf, ctx, company_id)
    local second_count = conf.company.second_count
    if second_count then
        core.log.info("防爬虫插件：执行用户每秒限流，限流次数：", second_count)
        --获取限流器
        local lim, err
        lim, err = core.lrucache.plugin_ctx(lrucache, ctx, "company_second", create_limit_obj, second_times, second_count, conf)
        --如果无法创建限流器，就按照是否允许自动执行选项选择
        if not lim then
            core.log.error("failed to fetch limit.count object: ", err)
            if conf.allow_degradation then
                return true
            end
            return false
        end

        --获取限流key，此处为用户id
        local route_id = ctx.route_id
        local key = company_second_limit_key .. ":" .. route_id .. ":" .. apisix_plugin.conf_version(conf) .. ":" .. company_id
        core.log.info("limit key: ", key)

        local delay, remaining = lim:incoming(key, true)
        if not delay then
            local err = remaining
            if err == "rejected" then
                return false
            end

            core.log.error("failed to limit count: ", err)
            if conf.allow_degradation then
                return true
            end
            return false
        end
        return true
    end
    return true
end

--检查用户每天限流
local function check_company_daily_limit(conf, ctx, company_id)
    --校验每天限流
    local daily_count = conf.company.daily_count
    if daily_count then
        core.log.info("防爬虫插件：执行公司每天限流，限流次数：", daily_count)
        --获取限流器
        local lim, err
        lim, err = core.lrucache.plugin_ctx(lrucache, ctx, "company_daily", create_limit_obj, daily_times, daily_count, conf)
        --如果无法创建限流器，就按照是否允许自动执行选项选择
        if not lim then
            core.log.error("failed to fetch limit.count object: ", err)
            if conf.allow_degradation then
                return true
            end
            return false
        end

        --获取限流key，此处为用户端ip
        local route_id = ctx.route_id
        local key = company_daily_limit_key .. ":" .. route_id .. ":" .. apisix_plugin.conf_version(conf) .. ":" .. company_id
        core.log.info("限流key: ", key)

        local delay, remaining = lim:incoming(key, true)
        if not delay then
            local err = remaining
            if err == "rejected" then
                return false
            end
            core.log.error("failed to limit count: ", err)
            if conf.allow_degradation then
                return true
            end
            return false
        end
        return true
    end
    return true
end

--检查公司限流
local function check_company(conf, ctx)
    local company_reptile_conf = conf.company
    if company_reptile_conf then
        local user_token = core.request.header(ctx, USER_TOKEN);
        local user = user_lrucache(user_token, nil, getUser, conf, user_token)
        --如果获取不到用户，直接跳过
        if not user then
            return true
        end
        local company_id = user.companyId
        --如果获取不到公司id，直接跳过
        if not company_id then
            return true
        end
        local company_name = user.companyName

        --验证用户白名单
        local pass = check_company_whitelist(conf, company_id)
        if pass then
            return true
        end
        --验证用户黑名单
        local block = check_company_blacklist(conf, company_id)
        if block then
            return false
        end
        --校验用户每秒限流
        local second_limit = check_company_second_limit(conf, ctx, company_id)
        if not second_limit then
            if conf.allow_auto_disable then
                local blacklist = conf.company.blacklist
                if not blacklist then
                    blacklist = {}
                end
                if not hasNumber(tonumber(company_id),blacklist) then
                    core.table.insert(blacklist, tonumber(company_id))
                    insert_blacklist(ctx, conf)
                    send_company_disable_message(conf,company_id,company_name)
                end
            end
            return false
        end
        --校验用户每天限流
        local daily_limit = check_company_daily_limit(conf, ctx, company_id)
        if not daily_limit then
            if conf.allow_auto_disable then
                local blacklist = conf.company.blacklist
                if not blacklist then
                    blacklist = {}
                end
                if not hasNumber(tonumber(company_id),blacklist) then
                    core.table.insert(blacklist, tonumber(company_id))
                    insert_blacklist(ctx, conf)
                    send_company_disable_message(conf,company_id,company_name)
                end
            end
            return false
        end

    end
    return true
end

function _M.access(conf, ctx)
    core.log.info("防爬虫插件: 获取插件配置：", core.json.delay_encode(conf))
    core.log.info("防爬虫插件: 获取路由id：", ctx.route_id)
    local ip_check = check_ip(conf, ctx)
    local rejected_code = conf.rejected_code
    local rejected_msg = conf.rejected_msg
    if not ip_check then
        return rejected_code, rejected_msg
    end

    local user_check = check_user(conf, ctx)

    if not user_check then
        return rejected_code, rejected_msg
    end

    local company_check = check_company(conf, ctx)
    if not company_check then
        return rejected_code, rejected_msg
    end
end

return _M

