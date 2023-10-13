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
local plugin_name = "extend-info"
local pairs = pairs
local ngx = ngx

local switch_map = { GET = ngx.HTTP_GET, POST = ngx.HTTP_POST, PUT = ngx.HTTP_PUT,
                     HEAD = ngx.HTTP_HEAD, DELETE = ngx.HTTP_DELETE,
                     OPTIONS = ngx.HTTP_OPTIONS, MKCOL = ngx.HTTP_MKCOL,
                     COPY = ngx.HTTP_COPY, MOVE = ngx.HTTP_MOVE,
                     PROPFIND = ngx.HTTP_PROPFIND, LOCK = ngx.HTTP_LOCK,
                     UNLOCK = ngx.HTTP_UNLOCK, PATCH = ngx.HTTP_PATCH,
                     TRACE = ngx.HTTP_TRACE,
}

local schema_method_enum = {}
for key in pairs(switch_map) do
    core.table.insert(schema_method_enum, key)
end

local schema = {
    type = "object",
    properties = {
        params = {
            type = "array",
            items = {
                type = "object",
                properties = {
                    source = {
                        type = "string",
                        enum = { "consumer" },
                    },
                    position = {
                        type = "string",
                        enum = { "http-header" },
                    },
                    name = {
                        type = "string"
                    },
                    value = {
                        type = "string"
                    },
                },
                required = { "source", "position", "name" }
            }
        }

    },
    minProperties = 1,
}

local _M = {
    version = 0.1,
    priority = 1012,
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end
    -- check params
    if not conf.params then
        return false
    end
    return true
end
do
    local upstream_vars = {
        host = "upstream_host",
        upgrade = "upstream_upgrade",
        connection = "upstream_connection",
    }
    local upstream_names = {}
    for name, _ in pairs(upstream_vars) do
        core.table.insert(upstream_names, name)
    end
end

function _M.rewrite(conf, ctx)

    if not conf.params then
        return
    end
    for field, obj in pairs(conf.params) do
        if obj.source == 'consumer' then
            if ctx.consumer and ctx.consumer.extend_info then
                for key, value in pairs(ctx.consumer.extend_info) do
                    if obj.name == key then
                        if obj.position == 'http-header' then
                            core.request.set_header(ctx, key, value)
                        end
                    end
                end
            end
        end

    end
end

return _M
