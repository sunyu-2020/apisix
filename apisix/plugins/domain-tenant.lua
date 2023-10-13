local core = require("apisix.core")
local http = require("resty.http")
local plugin = require("apisix.plugin")

local schema = {
    type = "object",
    properties = {
        cache = {
            description = "cache time, unit second",
            type = "integer"
        },
        url = {
            description = "tenant management system address",
            type = "string"
        },
        key = {
            type = "string",
            default = "tenant-id"
        },
        timeout = {
            description = "timeout, unit second",
            type = "integer",
            default = 3
        }
    },

}

local attr_schema = {
    type = "object",
    properties = {
        url = {
            description = "Tenant management system call address",
            type = "string"
        },
        cache = {
            description = "cache time, unit second",
            type = "integer"
        },
        timeout = {
            description = "timeout, unit second",
            type = "integer"
        }
    },
}

local plugin_name = "domain-tenant"
-- 设置开启缓存
local _M = {
    version = 0.1,
    priority = 414,
    name = plugin_name,
    schema = schema,
    attr_schema = attr_schema,
}

local function getCacheTime(conf)
    local cache = conf.cache
    if not cache then
        local attr = plugin.plugin_attr(plugin_name)
        if attr then
            cache = attr.cache
        end
    end
    return cache
end

local function getUrl(conf)
    local url = conf.url
    if not url then
        local attr = plugin.plugin_attr(plugin_name)
        if attr then
            url = attr.url
        end
    end
    return url
end

local function httpRequest(conf, url, domain)

    local params = {
        method = "POST",
        body = '{"domainName": "' .. domain .. '"}',
        headers = {
            ["Content-Type"] = "application/json",
        }
    }

    local httpc = http.new()
    httpc:set_timeout(conf.timeout * 1000)
    local res, err = httpc:request_uri(url, params)
    if err then
        return nil, err
    end

    return res, nil
end

local function getTenantCode(conf, url, domain)
    local res, err_msg = httpRequest(conf, url, domain)
    if err_msg then
        return nil, err_msg
    end

    core.log.info("get tenant info response：", res.body)
    if not res.body then
        return nil, "can not find tenant information"
    end

    local response_body = core.json.decode(res.body)
    core.log.info("response_body.data : ", response_body.success)

    if response_body.success == false then
        return nil, "can not find tenant information"
    end
    return response_body.data.tenantCode, nil

end

local function get_result_from_etcd(key)
    local res, err = core.etcd.get(key, false)
    if not res then
        core.log.error("failed to get upstream [", key, "]: ", err)
        return nil, { error_msg = err }
    end

    if res.status ~= 200 then
        return nil, res.status
    end
    local value = res.body.node.value
    return value, nil
end

local function send_http_data(conf, domain)

    local url = getUrl(conf)
    core.log.info("get domain tenant info from url:", url)
    if not url then
        return false, "can not find tenant tenant management system url"
    end

    local cache = getCacheTime(conf)
    -- 没有设置缓存直接调用url获取
    if not cache then
        return getTenantCode(conf, url, domain)
    end
    -- 设置了缓存
    -- 先判断etcd缓存中是否有数据
    local tenant_code_cache, _ = get_result_from_etcd("/plugin_metadata/domain_tenant/" .. domain)
    -- 有数据直接返回
    if tenant_code_cache then
        return tenant_code_cache, nil
    end
    -- 没数据调用url获取并放入缓存中
    local tenant_code, err_msg = getTenantCode(conf, url, domain)
    if tenant_code then
        core.etcd.set("/plugin_metadata/domain_tenant/" .. domain, tenant_code, cache)
    end
    return tenant_code, err_msg

end

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

function _M.rewrite(conf, ctx)
    local host = ctx.var.upstream_host
    local res, err_msg = send_http_data(conf, host)
    if err_msg then
        return 400, err_msg
    end

    core.request.set_header(ctx, conf.key, res)
end

return _M
