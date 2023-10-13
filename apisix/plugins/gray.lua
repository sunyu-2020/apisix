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
local expr = require("resty.expr.v1")
local ipairs = ipairs

local vars_schema = {
    type = "array",
}

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

local plugin_name = "gray"

local _M = {
    version = 0.1,
    priority = 11999,
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
                    if m.vars then
                        local ok, err = expr.new(m.vars)
                        if not ok then
                            return false, "failed to validate the 'vars' expression: " .. err
                        end
                    end
                end
            end
        end
    end

    return true
end

function _M.rewrite(conf, ctx)

    core.log.debug("进入灰度发布插件")
    local service_type = conf.type
    if not service_type then
        return
    end

    local picker = require("apisix.plugins.gray." .. service_type)
    local code, err, match_passed, weighted_upstreams, gray_type = picker.matchRules(conf, ctx)
    if err then
        return code, err
    end

    ctx.gray_type = gray_type
    if match_passed then
        ctx.match_passed = true
        ctx.weighted_upstreams = weighted_upstreams
    end
end

function _M.access(conf, ctx)

    local service_type = conf.type
    if not service_type then
        return
    end
    local gray_type = ctx.gray_type
    local picker = require("apisix.plugins.gray." .. service_type)
    picker.execute(conf, ctx, gray_type)
    return
end

return _M
