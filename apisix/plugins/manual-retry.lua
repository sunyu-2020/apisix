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
--[[
手动重试插件
]]

local ngx = ngx
local core = require("apisix.core")
local log_util = require("apisix.utils.log-util")


local schema = {
    type = "object",
    properties = {
        retry_time = {
            type = "integer",
        },
        validity_period = {
            type = "integer",
        },
    },

}
local log_level = {
    STDERR = ngx.STDERR,
    EMERG = ngx.EMERG,
    ALERT = ngx.ALERT,
    CRIT = ngx.CRIT,
    ERR = ngx.ERR,
    ERROR = ngx.ERR,
    WARN = ngx.WARN,
    NOTICE = ngx.NOTICE,
    INFO = ngx.INFO,
    DEBUG = ngx.DEBUG
}


local metadata_schema = {
    type = "object",
}

local plugin_name = "manual-retry"

local _M = {
    version = 0.1,
    priority = 2551,
    name = plugin_name,
    schema = schema,
    metadata_schema = metadata_schema,
}

function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_METADATA then
        return core.schema.check(metadata_schema, conf)
    end
    return core.schema.check(schema, conf)
end

function _M.rewrite(conf, ctx)
    local notify_info = {}

    local retry_times = core.request.headers()["x-api-platform-notify-retry-times"]
    core.log.info("retry_times:", retry_times)
    if retry_times then
        notify_info.retry_times = retry_times
    end

    local notify_id = core.request.headers()["x-api-platform-notify-id"]

    if notify_id then
        notify_info.id = notify_id
    end
    ctx.api_notify_info = notify_info

end

function _M.body_filter(conf, ctx)
    conf.include_resp_body = true
    log_util.collect_body(conf, ctx)
end

function _M.log(conf, ctx)
    if not ctx.consumer or not ctx.consumer.url then
        core.log.error("can not find consumer url")
        return
    end
    conf.include_req_body = true
    local entry = log_util.get_full_log(ngx, conf)
    local notify_info = ctx.api_notify_info
    core.log.info("consumer url:", ctx.consumer.url)
    if entry.consumer then
        entry.consumer.url = ctx.consumer.url
    end
    local delay = 0
    local handler = function()
        local etcd = require "resty.etcd"
        local fetch_local_conf = require("apisix.core.config_local").local_conf
        local clone_tab = require("table.clone")
        local health_check = require("resty.etcd.health_check")

        local local_conf, err = fetch_local_conf()
        if not local_conf then
            return nil, nil, err
        end

        local etcd_conf = clone_tab(local_conf.etcd)
        etcd_conf.http_host = etcd_conf.host
        etcd_conf.host = nil
        etcd_conf.prefix = nil
        etcd_conf.protocol = "v3"
        etcd_conf.api_prefix = "/v3"

        -- default to verify etcd cluster certificate
        etcd_conf.ssl_verify = true
        if etcd_conf.tls then
            if etcd_conf.tls.verify == false then
                etcd_conf.ssl_verify = false
            end

            if etcd_conf.tls.cert then
                etcd_conf.ssl_cert_path = etcd_conf.tls.cert
                etcd_conf.ssl_key_path = etcd_conf.tls.key
            end

            if etcd_conf.tls.sni then
                etcd_conf.sni = etcd_conf.tls.sni
            end
        end

        -- enable etcd health check retry for curr worker
        if not health_check.conf then
            health_check.init({
                max_fails = #etcd_conf.http_host,
                retry = true,
            })
        end

        local etcd_cli
        etcd_cli, err = etcd.new(etcd_conf)
        local res, err = etcd_cli:set("/gen_id", 1)
        if not res then
            return nil, err
        end
        local exist_notify_id
        if notify_info.id then
            entry.retry_times = notify_info.retry_times
            exist_notify_id = notify_info.id
        else
            local res, err = etcd_cli:set("/gen_id", 1)
            if not res then
                return nil, err
            end
            local index = res.body.header.revision
            index = string.format("%020d", index)
            entry.id = index
            notify_info.id = index
        end

        local period = 60 * 60 * 24 * 7
        if conf.validity_period then
            period = conf.validity_period
        end
        --[[        设置数据有效期，默认7天]]
        local res, _ = etcd_cli:grant(period)
        etcd_cli:set("/apisix/notify/" .. notify_info.id, entry, { lease = res.body.ID })
        if exist_notify_id then
            entry.id = exist_notify_id .. "/" .. entry.retry_times
            etcd_cli:set("/apisix/noti_retry/" .. exist_notify_id .. "/" .. entry.retry_times, entry, { lease = res.body.ID })
        end
    end
    local ok, err = ngx.timer.at(delay, handler)
    if not ok then
        ngx.log(ngx.ERR, "failed to create the timer: =======", err)
        return
    end
end

return _M
