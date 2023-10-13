local core = require("apisix.core")
local url_parser = require("net.url")

local REFERER = "Referer"
local ORIGIN = "Origin"
local TENANT_ID = "tenant-id"
local PARAM_TENANT_ID = "tenantId"

local schema = {
    type = "object",
    properties = {
        key = {
            type = "string",
            default = "tenant-id"
        },
        default = {
            description = "default tenant id",
            type = "string"
        },
        tenant_config = {
            type = "string"
        }
    },

}

local _M = {
    version = 0.1,
    priority = 10000,
    name = "tenant",
    schema = schema,
}

local function getTenantId(tenantConfig, domain)
    core.log.info("租户插件 : 获取匹配域名", domain)
    for _, v in pairs(tenantConfig) do
        local tenant_id = v.code
        local domains = v.domains
        core.log.info("租户插件 : 获取租户配置当前租户ID:", tenant_id)
        for _, tenant_domain in pairs(domains) do
            core.log.info("租户插件 : 获取租户配置匹配域名", tenant_domain)
            core.log.info("租户插件 : 获取租户配置域名", domain)
            if domain == tenant_domain then
                core.log.info("租户插件 : 获取域名匹配成功租户id:", tenant_id)
                return tenant_id
            end
        end
    end
    return nil
end
--通过refer获取租户域名
local function get_domain_by_referer(ctx)
    local url = core.request.header(ctx, REFERER)
    core.log.info("租户插件：获取referer", url)
    if not url then
        return nil
    end

    local parsed_url = url_parser.parse(url)
    local host = parsed_url.host
    core.log.info("租户插件：获取referer域名", host)
    return host
end

--通过cookie获取域名
local function get_domain_by_origin(ctx)
    local url = core.request.header(ctx, ORIGIN)
    core.log.info("租户插件：获取origin：", url)
    if not url then
        return nil
    end
    local parsed_url = url_parser.parse(url)
    local host = parsed_url.host
    core.log.info("租户插件：获取origin域名", host)
    return host
end
--通过请求参数获取租户id
local function get_tenant_by_param(ctx, tenant_config)
    local params = core.request.get_uri_args(ctx)
    local tenant_id = params[PARAM_TENANT_ID]
    --如果不存在tenant-id就跳过
    if not tenant_id then
        return nil
    end

    --如果存在租户id，就进行校验

    if tenant_id then
        local isExistTenant = false
        for _, v in pairs(tenant_config) do
            local config_tenant_id = v.code
            if config_tenant_id == tenant_id then
                isExistTenant = true
            end
        end
        if isExistTenant == false then
            return nil, "租户id未配置"
        end
    end
    --没有分配也要报错
    core.log.info("租户插件：获取param里的租户id：", tenant_id)
    return tenant_id, nil
end
--通过header获取租户
local function get_tenant_by_header(ctx, tenant_config)
    local tenant_id = core.request.header(ctx, TENANT_ID);
    --如果header里没有tenant-id就跳过
    if not tenant_id then
        return nil
    end
    --如果存在租户id，就进行校验

    if tenant_id then
        local isExistTenant = false
        for _, v in pairs(tenant_config) do
            local config_tenant_id = v.code
            if config_tenant_id == tenant_id then
                isExistTenant = true
            end
        end
        if isExistTenant == false then
            return nil, "租户id未配置"
        end
    end
    --没有分配也要报错
    core.log.info("租户插件：获取header里的租户id：", tenant_id)
    return tenant_id, nil
end

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

function _M.rewrite(conf, ctx)
    core.log.info("进入租户插件")
    local config = conf.tenant_config
    if not config then
        return 400, "租户配置获取失败"
    end
    if not config then
        return 400, "无法获取租户配置"
    end
    core.log.info("租户插件 : 获取租户配置", config)
    local tenantConfig = core.json.decode(config)
    ----首先判断header里是否有租户id
    local tenant_id, error = get_tenant_by_header(ctx, tenantConfig)
    if error then
        return 400, error;
    end

    if tenant_id then
        ctx.isTenant = true
        core.request.set_header(ctx, conf.key, tenant_id)
        core.log.info("租户插件 : 从header里获取租户id：", tenant_id)
        return
    end

    tenant_id, error = get_tenant_by_param(ctx, tenantConfig)

    if error then
        return 400, error;
    end

    if tenant_id then
        ctx.isTenant = true
        core.request.set_header(ctx, conf.key, tenant_id)
        core.log.info("租户插件 : 从uri里获取租户id：", tenant_id)
        return
    end

    --如果从header里获取不到租户id就执行其他策略
    local domain = get_domain_by_referer(ctx)
    core.log.info("租户插件 : 获取referer域名：", domain)

    --如果从referer里获取不到，从origin里获取
    if not domain then
        domain = get_domain_by_origin(ctx)
        core.log.info("租户插件 : 获取origin域名：", domain)
    end

    --如果存在域名，就通过域名获取租户
    if domain then
        --将域名转换为租户id
        tenant_id = getTenantId(tenantConfig, domain)
    end
    --获取默认租户
    local default = conf.default
    core.log.info("租户插件 : 最终租户id：", tenant_id)
    if not tenant_id and default then
        tenant_id = default
    end

    if not tenant_id then
        return 400, "无法获取租户信息"
    end

    core.request.set_header(ctx, conf.key, tenant_id)
end

return _M
