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
local ipmatcher = require("resty.ipmatcher")
local ngx_now = ngx.now
local ipairs = ipairs
local type = type
local request = require("apisix.core.request")

local _M = {}


local function sort_by_key_host(a, b)
    return a.host < b.host
end


local function compare_upstream_node(up_conf, new_t)
    if up_conf == nil then
        return false
    end

    local old_t = up_conf.original_nodes or up_conf.nodes
    if type(old_t) ~= "table" then
        return false
    end

    if #new_t ~= #old_t then
        return false
    end

    core.table.sort(old_t, sort_by_key_host)
    core.table.sort(new_t, sort_by_key_host)

    for i = 1, #new_t do
        local new_node = new_t[i]
        local old_node = old_t[i]
        for _, name in ipairs({"host", "port", "weight", "priority", "metadata"}) do
            if new_node[name] ~= old_node[name] then
                return false
            end
        end
    end

    return true
end
_M.compare_upstream_node = compare_upstream_node


local function parse_domain_for_nodes(nodes)
    local new_nodes = core.table.new(#nodes, 0)
    for _, node in ipairs(nodes) do
        local host = node.host
        if not ipmatcher.parse_ipv4(host) and
                not ipmatcher.parse_ipv6(host) then
            local ip, err = core.resolver.parse_domain(host)
            if ip then
                local new_node = core.table.clone(node)
                new_node.host = ip
                new_node.domain = host
                core.table.insert(new_nodes, new_node)
            end

            if err then
                core.log.error("dns resolver domain: ", host, " error: ", err)
            end
        else
            core.table.insert(new_nodes, node)
        end
    end
    return new_nodes
end
_M.parse_domain_for_nodes = parse_domain_for_nodes


function _M.parse_domain_in_up(up)
    local nodes = up.value.nodes
    local new_nodes, err = parse_domain_for_nodes(nodes)
    if not new_nodes then
        return nil, err
    end

    local ok = compare_upstream_node(up.dns_value, new_nodes)
    if ok then
        return up
    end

    if not up.orig_modifiedIndex then
        up.orig_modifiedIndex = up.modifiedIndex
    end
    up.modifiedIndex = up.orig_modifiedIndex .. "#" .. ngx_now()

    up.dns_value = core.table.clone(up.value)
    up.dns_value.nodes = new_nodes
    core.log.info("resolve upstream which contain domain: ",
                  core.json.delay_encode(up, true))
    return up
end


function _M.parse_domain_for_nodes(nodes)
    local new_nodes = core.table.new(#nodes, 0)
    for _, node in ipairs(nodes) do
        local host = node.host
        if not ipmatcher.parse_ipv4(host) and
                not ipmatcher.parse_ipv6(host) then
            local ip, err = core.resolver.parse_domain(host)
            if ip then
                local new_node = core.table.clone(node)
                new_node.host = ip
                new_node.domain = host
                core.table.insert(new_nodes, new_node)
            end

            if err then
                core.log.error("dns resolver domain: ", host, " error: ", err)
            end
        else
            core.table.insert(new_nodes, node)
        end
    end
    return new_nodes
end

function _M.get_path_args(up_conf)

    local pathArgs = up_conf.path_args
    if pathArgs == nil then
        core.log.error("can not find path args")
        return
    end
    local path = pathArgs.path
    if path == nil then
        core.log.error("can not find path args path args")
        return
    end
    return nil, path
end

function _M.get_consumer_url(api_ctx, consumer)

    if not consumer then
        core.log.error("can not find consumer")
        return
    end
    -- 多回调模式
    if consumer.callback_mode == "multi" then
        if not consumer.multi_uris then
            core.log.error("can not find consumer multi_uris")
        end
        for _, callback_info in ipairs(consumer.multi_uris) do
            local method = request.header(api_ctx, "method")
            if callback_info.key == method then
                return callback_info.method, callback_info.url
            end
        end
        return nil, nil
    else
        -- 单回调模式
        if not consumer.url then
            core.log.error("can not find consumer url")
            return
        end
        return consumer.method, consumer.url
    end

end

function _M.get_upstream_path_url(api_ctx, consumer)

    local up_conf = api_ctx.matched_upstream
    local pathType = up_conf.path_type

    if pathType == "static" then
        return _M.get_path_args(up_conf)
    end
    if pathType == "dynamic" then
        return _M.get_consumer_url(api_ctx, consumer)
    end
    return nil, nil
end

return _M
