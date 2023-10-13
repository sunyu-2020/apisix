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
local core = require("apisix.core")

local Util = require("apisix.plugins.gray.util")
local ipairs = ipairs
local type = type

local CorrelationContext = require('skywalking.correlation_context')
local ngx = ngx

local lrucache = core.lrucache.new({
    ttl = 0, count = 512
})

local _M = {}

function _M.matchRules(conf, ctx)

    if not conf or not conf.rules then
        return
    end

    local weighted_upstreams

    for _, rule in ipairs(conf.rules) do
        weighted_upstreams = rule.weighted_upstreams
    end

    -- 判断全链路灰度, 直接走灰
    local correlation = ngx.var.http_sw8_correlation
    if correlation ~= nil then
        local ref = CorrelationContext.fromSW8Value(correlation)
        local tags = ref["groupVersion"]
        if tags == "gray" then
            return nil, nil, true, weighted_upstreams, nil
        end
    end
    -- 非全链路匹配灰度规则
    local code, err, match_passed, weighted_upstreams, gray_type = Util.matchRules(conf, ctx)
    if err then
        return code, err, nil, nil, nil
    end

    if match_passed then
        -- 全链路灰度透传灰度标记
        if conf.strategy == "fullLink" then
            ctx.var.group_version = "gray"
        end
    else
        -- 全链路灰度透传灰度标记
        if conf.strategy == "fullLink" then
            ctx.var.group_version = "base"
        end
    end
    return nil, nil, match_passed, weighted_upstreams, gray_type
end

function _M.execute(conf, ctx, gray_type)

    if not ctx.match_passed then
        return
    end

    local service_type = conf.type
    if not service_type then
        return
    end

    local weighted_upstreams = ctx.weighted_upstreams
    local rr_up, err = lrucache(weighted_upstreams, nil, Util.new_rr_obj, weighted_upstreams)
    if not rr_up then
        core.log.error("lrucache roundrobin failed: ", err)
        return 500
    end
    local upstream = rr_up:find()

    if upstream and type(upstream) == "table" then
        core.log.info("upstream: ", core.json.encode(upstream))
        return Util.set_upstream(upstream, ctx)
    elseif upstream and upstream ~= "plugin#upstream#is#empty" then
        ctx.upstream_id = upstream
        core.log.info("upstream_id: ", upstream)
        return
    end

    ctx.upstream_id = nil
    core.log.info("route_up: ", upstream)
    return
end

return _M
