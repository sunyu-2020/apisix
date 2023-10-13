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

local require = require
local core = require("apisix.core")
local upstream_util = require("apisix.utils.upstream")
local url = require("net.url")
local _M = {}

local switch_map = { GET = ngx.HTTP_GET, POST = ngx.HTTP_POST, PUT = ngx.HTTP_PUT,
                     HEAD = ngx.HTTP_HEAD, DELETE = ngx.HTTP_DELETE,
                     OPTIONS = ngx.HTTP_OPTIONS, MKCOL = ngx.HTTP_MKCOL,
                     COPY = ngx.HTTP_COPY, MOVE = ngx.HTTP_MOVE,
                     PROPFIND = ngx.HTTP_PROPFIND, LOCK = ngx.HTTP_LOCK,
                     UNLOCK = ngx.HTTP_UNLOCK, PATCH = ngx.HTTP_PATCH,
                     TRACE = ngx.HTTP_TRACE,
}
local function parseUrl (urlStr, method, up_conf, api_ctx)
    core.log.info("urlStr:", urlStr)
    core.log.info("method:", method)
    local new_n = {}
    local urlInfo = url.parse(urlStr)
    local port = urlInfo.port
    local scheme = urlInfo.scheme
    if port == nil then
        if scheme == "http" then
            port = 80
        end
        if scheme == "https" then
            port = 443
        end
    end
    core.table.insert(new_n, {
        host = urlInfo.host,
        port = port,
        weight = 100
    })
    up_conf.nodes = upstream_util.parse_domain_for_nodes(new_n)
    api_ctx.var.upstream_uri = urlInfo.path
    api_ctx.upstream_scheme = urlInfo.scheme
    api_ctx.var.upstream_host = urlInfo.host
    if method then
        ngx.req.set_method(switch_map[method])
    end
end

local function static (up_conf, api_ctx)
    local path = upstream_util.get_path_args(up_conf)
    parseUrl(path, nil, up_conf, api_ctx)
end

local function dynamic (up_conf, api_ctx)

    local requestUri = api_ctx.var._cache.request_uri
    local requestUriInfo = url.parse(requestUri)
    local notifyUrl = requestUriInfo.query.notify_url
    if notifyUrl then
        parseUrl(notifyUrl, nil, up_conf, api_ctx)
        return
    end

    local consumer_callback_method, consumer_callback_url = upstream_util.get_consumer_url(api_ctx, api_ctx.consumer)
    if not consumer_callback_url then
        core.log.error("can not find consumer callback url")
        return
    end
    parseUrl(consumer_callback_url, consumer_callback_method, up_conf, api_ctx)
end

function _M.rewrite(api_ctx)
    local up_conf = api_ctx.matched_upstream
    local pathType = up_conf.path_type

    if pathType == "static" then
        static(up_conf, api_ctx)
    end
    if pathType == "dynamic" then
        dynamic(up_conf, api_ctx)
    end

end

return _M
