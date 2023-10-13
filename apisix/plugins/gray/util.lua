local roundrobin = require("resty.roundrobin")
local upstream = require("apisix.upstream")
local ipmatcher = require("resty.ipmatcher")
local table_insert = table.insert
local tostring = tostring
local pairs = pairs
local core = require("apisix.core")
local expr = require("resty.expr.v1")

local _M = {}

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

function _M. set_upstream(upstream_info, ctx)
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
    -- 灰度兜底，如果没有灰度节点直接返回访问正式节点
    if #new_nodes == 0 then
        return
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
    upstream.set(ctx, upstream_key, ctx.conf_version, up_conf)
    return nil, up_conf
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

function _M.matchRules(conf, ctx)

    local weighted_upstreams
    local match_passed = true
    local gray_type

    for _, rule in ipairs(conf.rules) do

        gray_type = rule.gray_type

        if not rule.match then
            match_passed = true
            weighted_upstreams = rule.weighted_upstreams
            break
        end
        for _, single_match in ipairs(rule.match) do
            -- 路由匹配规则开始
            local match_route = true
            if single_match.routes then
                match_route = false
                for _, route_id in ipairs(single_match.routes) do
                    if ctx.var.route_id == route_id then
                        match_route = true
                    end
                end
            end

            if not match_route then
                core.log.error("not match route: ", ctx.var.route_id)
                return 500, "not match route", nil, nil, nil
            end
            -- 路由匹配规则结束
            if single_match.vars then
                local express, err = expr.new(single_match.vars)
                if err then
                    core.log.error("vars expression does not match: ", err)
                    return 500, err, nil, nil, nil
                end
                match_passed = express:eval(ctx.var)

                if match_passed then
                    break
                end
            end
        end

        if match_passed then
            weighted_upstreams = rule.weighted_upstreams
            break
        end
    end
    return nil, nil, match_passed, weighted_upstreams, gray_type
end

function _M.new_rr_obj(weighted_upstreams)
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

return _M