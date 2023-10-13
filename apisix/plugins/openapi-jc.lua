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
local schema_def = require("apisix.schema_def")
local expr = require("apisix.plugins.expr.v1")
local ipairs = ipairs
local ext = require("apisix.plugins.ext-plugin.init")
local str_find = core.string.find
local ipmatcher = require("resty.ipmatcher")
local table_insert = table.insert
local upstream = require("apisix.upstream")
local roundrobin = require("resty.roundrobin")

local vars_schema = {
    type = "array",
}
local sub_str = string.sub

local lrucache = core.lrucache.new({
    ttl = 0, count = 512
})

local match_schema = {
    type = "array",
    items = {
        type = "object",
        properties = {
            vars = vars_schema
        }
    },
}

local upstreams_schema = {
    type = "array",
    items = {
        type = "object",
        properties = {
            upstream_id = schema_def.id_schema,
            upstream = schema_def.upstream,
            weight = {
                description = "used to split traffic between different" ..
                        "upstreams for plugin configuration",
                type = "integer",
                default = 1,
                minimum = 0
            }
        }
    },
    -- When the upstream configuration of the plugin is missing,
    -- the upstream of `route` is used by default.
    default = {
        {
            weight = 1
        }
    },
    minItems = 1,
    maxItems = 20
}

local schema = {
    type = "object",
    properties = {
        rules = {
            type = "array",
            items = {
                type = "object",
                properties = {
                    match = match_schema,
                    weighted_upstreams = upstreams_schema
                },
            }
        }
    },
}

local plugin_name = "openapi-jc"

local _M = {
    version = 0.1,
    priority = 11997,
    name = plugin_name,
    schema = schema
}

function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)

    if not ok then
        return false, err
    end

    if conf.rules then
        for _, rule in ipairs(conf.rules) do
            if rule.match then
                for _, m in ipairs(rule.match) do
                    for _, var in ipairs(m.vars) do
                        if m.vars then
                            local ok, err = expr.new(var)
                            if not ok then
                                return false, "failed to validate the 'vars' expression: " .. err
                            end
                        end
                    end

                end
            end
        end
    end

    return true
end

local function parse_domain_for_node(node)
    local host = node.host
    if not ipmatcher.parse_ipv4(host)
            and not ipmatcher.parse_ipv6(host)
    then
        node.domain = host

        local ip, err = core.resolver.parse_domain(host)
        if ip then
            node.host = ip
        end

        if err then
            core.log.error("dns resolver domain: ", host, " error: ", err)
        end
    end
end

local function set_upstream(upstream_info, ctx)
    local nodes = upstream_info.nodes
    local new_nodes = {}
    if core.table.isarray(nodes) then
        for _, node in ipairs(nodes) do
            parse_domain_for_node(node)
            table_insert(new_nodes, node)
        end
    else
        for addr, weight in pairs(nodes) do
            local node = {}
            local port, host
            host, port = core.utils.parse_addr(addr)
            node.host = host
            parse_domain_for_node(node)
            node.port = port
            node.weight = weight
            table_insert(new_nodes, node)
        end
    end

    local up_conf = {
        name = upstream_info.name,
        type = upstream_info.type,
        hash_on = upstream_info.hash_on,
        pass_host = upstream_info.pass_host,
        upstream_host = upstream_info.upstream_host,
        key = upstream_info.key,
        nodes = new_nodes,
        timeout = upstream_info.timeout,
    }

    local ok, err = upstream.check_schema(up_conf)
    if not ok then
        core.log.error("failed to validate generated upstream: ", err)
        return 500, err
    end

    local matched_route = ctx.matched_route
    up_conf.parent = matched_route
    local upstream_key = up_conf.type .. "#route_" ..
            matched_route.value.id .. "_" .. upstream_info.vid
    if upstream_info.node_tid then
        upstream_key = upstream_key .. "_" .. upstream_info.node_tid
    end
    core.log.info("upstream_key: ", upstream_key)
    upstream.set(ctx, upstream_key, ctx.conf_version, up_conf)

    return
end

local function new_rr_obj(weighted_upstreams)
    local server_list = {}
    for i, upstream_obj in ipairs(weighted_upstreams) do
        if upstream_obj.upstream_id then
            server_list[upstream_obj.upstream_id] = upstream_obj.weight
        elseif upstream_obj.upstream then
            -- Add a virtual id field to uniquely identify the upstream key.
            upstream_obj.upstream.vid = i
            -- Get the table id of the nodes as part of the upstream_key,
            -- avoid upstream_key duplicate because vid is the same in the loop
            -- when multiple rules with multiple weighted_upstreams under each rule.
            -- see https://github.com/apache/apisix/issues/5276
            local node_tid = tostring(upstream_obj.upstream.nodes):sub(#"table: " + 1)
            upstream_obj.upstream.node_tid = node_tid
            server_list[upstream_obj.upstream] = upstream_obj.weight
        else
            -- If the upstream object has only the weight value, it means
            -- that the upstream weight value on the default route has been reached.
            -- Mark empty upstream services in the plugin.
            upstream_obj.upstream = "plugin#upstream#is#empty"
            server_list[upstream_obj.upstream] = upstream_obj.weight

        end
    end

    return roundrobin:new(server_list)
end

local function deal_get_url(ctx, upstream_uri, separator_escaped)
    local index
    if separator_escaped then
        index = str_find(upstream_uri, "?")
    end

    if index then
        upstream_uri = core.utils.uri_safe_encode(sub_str(upstream_uri, 1, index - 1)) ..
                sub_str(upstream_uri, index)
    else
        -- The '?' may come from client request '%3f' when we use ngx.var.uri directly or
        -- via regex_uri
        upstream_uri = core.utils.uri_safe_encode(upstream_uri)
    end
    if ctx.var.is_args == "?" then

        if index then
            ctx.var.upstream_uri = upstream_uri .. "&" .. (ctx.var.args or "")
        else
            ctx.var.upstream_uri = upstream_uri .. "?" .. (ctx.var.args or "")
        end
    else
        ctx.var.upstream_uri = upstream_uri
    end

end

local function matchRules(conf, ctx)

    if not conf or not conf.rules then
        return
    end

    local weighted_upstreams

    for _, rule in ipairs(conf.rules) do
        weighted_upstreams = rule.weighted_upstreams
    end

    local match_passed = true

    for _, rule in ipairs(conf.rules) do

        if not rule.match then
            match_passed = true
            weighted_upstreams = rule.weighted_upstreams
            break
        end

        for _, single_match in ipairs(rule.match) do
            for _, var in ipairs(single_match.vars) do
                if var then
                    local express, err = expr.new(var)
                    if err then
                        core.log.error("vars expression does not match: ", err)
                        return 500, err, nil, nil
                    end
                    match_passed = express:eval(ctx.var)

                    if match_passed then
                        break
                    end
                end
            end
        end

        if match_passed then
            weighted_upstreams = rule.weighted_upstreams

            -- 改写路径
            if rule.new_path then
                local upstream_uri = core.utils.resolve_var(rule.new_path, ctx.var, true)
                deal_get_url(ctx, upstream_uri, true)
            end
            -- 改写请求头
            if rule.headers then
                if not rule.headers_arr then
                    rule.headers_arr = {}

                    for field, value in pairs(rule.headers) do
                        core.table.insert_tail(rule.headers_arr, field, value)
                    end
                end

                local field_cnt = #rule.headers_arr
                for i = 1, field_cnt, 2 do
                    core.request.set_header(ctx, rule.headers_arr[i],
                            core.utils.resolve_var(rule.headers_arr[i + 1], ctx.var))
                end
            end
            break
        end
    end

    return nil, nil, match_passed, weighted_upstreams

end

local function build_java_jc_md5_params()
    local ext_conf = {}
    ext_conf.allow_degradation = false
    ext_conf.disable = false

    local jc_md5_conf = {}
    jc_md5_conf.name = "JC_MD5"
    jc_md5_conf.value = ""
    local jc_md5_confs = {}
    core.table.insert(jc_md5_confs, jc_md5_conf)
    ext_conf.conf = jc_md5_confs

    return ext_conf
end

function _M.rewrite(conf, ctx)

    core.log.debug("进入openapi发布插件")

    local code, err, match_passed, weighted_upstreams = matchRules(conf, ctx)
    if err then
        return code, err
    end
    core.log.debug("匹配结果：", match_passed)
    if match_passed then
        ctx.match_passed = true
        ctx.weighted_upstreams = weighted_upstreams
    end
end

function _M.access(conf, ctx)
    if not ctx.match_passed then
        return
    end
    if conf.signature then
        -- 调用java插件验证jc签名
        local code, body = ext.communicate(build_java_jc_md5_params(), ctx, "ext-plugin-post-req")

        if code then
            return code, body
        end
    end
    local weighted_upstreams = ctx.weighted_upstreams
    local rr_up, err = lrucache(weighted_upstreams, nil, new_rr_obj, weighted_upstreams)
    if not rr_up then
        core.log.error("lrucache roundrobin failed: ", err)
        return 500
    end
    local upstream = rr_up:find()

    if upstream and type(upstream) == "table" then
        core.log.error("upstream: ", core.json.encode(upstream))
        return set_upstream(upstream, ctx)
    elseif upstream and upstream ~= "plugin#upstream#is#empty" then
        ctx.upstream_id = upstream
        core.log.error("upstream_id: ", upstream)
        return
    end

    ctx.upstream_id = nil
    core.log.info("route_up: ", upstream)
    return

end

return _M
