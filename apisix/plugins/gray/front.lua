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
local session = require("resty.session")
local ck = require("resty.cookie")
local type = type
local core_str = require("apisix.core.string")

local lrucache = core.lrucache.new({
    ttl = 0, count = 512
})

local _M = {}

local function set_front_tag(conf, ctx, tag, gray_type, up_conf)
    -- 流量灰度创建session
    if gray_type == "traffic" then
        -- 流量灰度创建session
        local open_session = session.open()
        local subject = open_session:get_subject();
        if not subject then
            local new_session = session.new()
            new_session:set_subject("gray session")
            new_session:set("service", conf.name)
            new_session:set("tag", tag)
            new_session:set("up_conf", up_conf)
            new_session:save()
        end
    end

    if gray_type == "content" then
        ck:new():set({
            key = ctx.service_name .. ".tag",
            value = tag,
            path = "/",
            domain = ".yzw.cn"
        })
    end
end

local function get_front_session_tag(conf, ctx)
    local open_session = session.open()
    local subject = open_session:get_subject();
    if subject == "gray session" then
        local tag = open_session:get("tag")
        local upstream_conf = open_session:get("up_conf")
        return tag, upstream_conf
    end

    return nil
end

local function get_front_cookie_tag(conf, ctx)

    return ck:new():get(ctx.service_name .. '.tag')

end

function _M.matchRules(conf, ctx)
    local gray_type
    for _, rule in ipairs(conf.rules) do
        gray_type = rule.gray_type
    end

    if gray_type == "traffic" then
        local tag, upstream_conf = get_front_session_tag(conf, ctx)
        if tag then
            ctx.gray_tag = tag
            ctx.gray_upstream_conf = upstream_conf
        else
            local uri = ngx.var.uri
            if core_str.has_suffix(uri, ".js") or core_str.has_suffix(uri, ".png") or core_str.has_suffix(uri, ".svg") or core_str.has_suffix(uri, ".css") then
                return
            end

            -- 匹配灰度规则
            return Util.matchRules(conf, ctx)
        end
    end

    if gray_type == "content" then
        local uri = ngx.var.uri
        if core_str.has_suffix(uri, ".js") or core_str.has_suffix(uri, ".png") or core_str.has_suffix(uri, ".svg") or core_str.has_suffix(uri, ".css") then
            ctx.gray_tag = get_front_cookie_tag(conf, ctx)
        else
            -- 匹配灰度规则
            return Util.matchRules(conf, ctx)
        end

    end

end

local function get_gray_upstream_id(weighted_upstreams)
    for i, upstream_obj in ipairs(weighted_upstreams) do
        if upstream_obj.upstream_id then
            return upstream_obj.upstream_id
        end

    end
end

function _M.execute(conf, ctx, gray_type)
    local tag = ctx.gray_tag
    if not tag then
        if not ctx.match_passed then
            set_front_tag(conf, ctx, "base", gray_type);
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
            local code, up_conf = Util.set_upstream(upstream, ctx)

            set_front_tag(conf, ctx, "gray", gray_type, up_conf);
            return
        elseif upstream and upstream ~= "plugin#upstream#is#empty" then
            ctx.upstream_id = upstream
            set_front_tag(conf, ctx, "gray", gray_type);
            core.log.info("upstream_id: ", upstream)
            return
        end

        ctx.upstream_id = nil
        set_front_tag(conf, ctx, "base", gray_type);
        core.log.info("route_up: ", upstream)
        return
    else

        if tag == "base" then
            ctx.upstream_id = nil
            return
        elseif tag == "gray" then
            ctx.upstream_conf = ctx.gray_upstream_conf

        end

    end

end

return _M
