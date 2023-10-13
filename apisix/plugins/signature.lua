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
local ipairs = ipairs
local core = require("apisix.core")
local consumer = require("apisix.consumer")

local SIGN_TYPE = "signType"
local plugin_name = "signature"
local MAX_REQ_BODY = 1024 * 512
local pickers = {}

local schema = {
    type = "object",
    title = "work with route or service object",
    properties = {
        type = {
            type = "string",
            enum = { "IN", "OUT" },
            default = "IN"
        },
        sign_type = {
            type = "string",
            enum = { "RSAWithSha256", "JC_MD5" },
        },
        rejected_code = {
            type = "integer", minimum = 200, maximum = 599, default = 401
        },
        rejected_msg = {
            type = "string", minLength = 1, default = "Invalid signature"
        },
        expire = {
            type = "number"
        }
    },
}

local consumer_schema = {
    type = "object",
    title = "work with consumer object",
    properties = {
    }
}

local _M = {
    version = 0.1,
    priority = 2550,
    type = 'auth',
    name = plugin_name,
    schema = schema,
    consumer_schema = consumer_schema
}

local lrucache = core.lrucache.new({
    type = "plugin",
})

local create_consumer_cache
do
    local consumer_names = {}
    function create_consumer_cache(consumers)
        core.table.clear(consumer_names)
        for _, consumer_info in ipairs(consumers.nodes) do
            if consumer_info.app_id then
                consumer_names[consumer_info.app_id] = consumer_info
            end
        end
        return consumer_names
    end

end -- do

local function get_consumer(app_id)
    if not app_id then
        return nil, { message = "missing app id" }
    end

    local consumer_conf = consumer.plugin(plugin_name)
    if not consumer_conf then
        core.log.error("plugin_name:", plugin_name)
        return nil, { message = "Missing related consumer" }
    end

    local consumers = lrucache("consumers_key", consumer_conf.conf_version,
            create_consumer_cache, consumer_conf)

    local consumer_info = consumers[app_id]
    if not consumer_info then
        return nil, { message = "Invalid app id" }
    end
    core.log.info("consumer: ", core.json.delay_encode(consumer_info))

    return consumer_info, nil
end

function _M.check_schema(conf, schema_type)
    core.log.info("input conf: ", core.json.delay_encode(conf))

    if schema_type == core.schema.TYPE_CONSUMER then
        return core.schema.check(consumer_schema, conf)
    else
        return core.schema.check(schema, conf)
    end
end

function _M.rewrite(conf, ctx)

    local signType = core.request.header(ctx, SIGN_TYPE)
    if not signType then
        signType = conf.sign_type
    end

    local picker = pickers[signType]
    if not picker then
        pickers[signType] = require("apisix.plugins.signature." .. signType)
        picker = pickers[signType]
    end

    local req_body, err = core.request.get_body(MAX_REQ_BODY, ctx)
    if err then
        return conf.rejected_code, { message = "Exceed body limit size" }
    end

    local params = picker.get_params(ctx, req_body)

    ctx.sign_type = conf.type

    core.log.info("conf_type: ", conf.type)

    local consumer_info, err = get_consumer(params.app_id)
    if err then
        return conf.rejected_code, err
    end

    local validated_consumer, err, code
    if conf.type == "IN" then
        validated_consumer, err, code = picker.validate(ctx, params, consumer_info, req_body)
    end
    if conf.type == "OUT" then
        validated_consumer, err = picker.signature(conf, ctx, params, consumer_info, req_body, false)
    end

    if code then
        return code, err
    else
        if err then
            return conf.rejected_code, err
        end
    end

    if not validated_consumer then
        return conf.rejected_code, { message = conf.rejected_msg }
    end
    local consumer_conf = consumer.plugin(plugin_name)
    consumer.attach_consumer(ctx, validated_consumer, consumer_conf)
    core.log.info("hit rsa-auth rewrite")

end

return _M

