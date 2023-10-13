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
local ngx = ngx
local type = type

local ngx_req = ngx.req
local pairs = pairs
local escape_uri = ngx.escape_uri
local core = require("apisix.core")
local upstream_util = require("apisix.utils.upstream")
local cert = require("apisix.cert")
local resty_rsa = require("resty.rsa")
local url = require("net.url")
local ngx_decode_base64 = ngx.decode_base64
local ngx_encode_base64 = ngx.encode_base64
local ngx_time = ngx.time
local SIGNATURE_KEY = "sign"
local APP_ID = "appId"
local TIMESTAMP = "timestamp"
local SIGN_TYPE = "signType"

local _M = {}

local function get_conf_field(consumer, field_name)

    return consumer.auth_conf[field_name]
end

local function do_nothing(v)
    return v
end

local function get_platform_cert(consumer_info)
    local consumer_cert = consumer_info.cert
    if not consumer_cert then
        return nil, { message = "can not find consumer certificate configuration" }
    end
    local platform_id = consumer_cert.platform_id
    if not platform_id then
        return nil, { message = "can not find consumer platform certificate configuration" }
    end
    local platform_cert, _ = cert.platform_cert()
    core.log.info("platform_cert_list:", core.json.delay_encode(platform_cert, true))
    core.log.info("platform_id:", platform_id)

    local result = platform_cert[platform_id]
    if not result then
        return nil, { message = "can not find consumer platform certificate in platform_cert" }
    end
    return result, nil
end

local function generate_signing_string(ctx, params, consumer, content, deal_type)

    local canonical_uri
    local request_method = ngx_req.get_method()
    if deal_type == "signature" then
        local callback_method, callback_url = upstream_util.get_consumer_url(ctx, consumer)
        if callback_url then
            local urlInfo = url.parse(callback_url)
            canonical_uri = urlInfo.path
            request_method = callback_method
        else
            canonical_uri = ctx.var.uri
        end
    else
        canonical_uri = ctx.var.uri
    end

    local canonical_query_string = ""
    local args = ngx_req.get_uri_args()

    if canonical_uri == "" then
        canonical_uri = "/"
    end

    if type(args) == "table" then
        local keys = {}
        local query_tab = {}

        for k, v in pairs(args) do
            core.table.insert(keys, k)
        end
        core.table.sort(keys)

        local field_val = get_conf_field(consumer, "encode_uri_params")
        core.log.info("encode_uri_params: ", field_val)

        local encode_or_not = do_nothing
        if field_val then
            encode_or_not = escape_uri
        end

        for _, key in pairs(keys) do
            local param = args[key]
            if type(param) == "boolean" then
                param = ""
            end

            -- whether to encode the uri parameters
            if type(param) == "table" then
                for _, val in pairs(param) do
                    core.table.insert(query_tab, encode_or_not(key) .. "=" .. encode_or_not(val))
                end
            else
                core.table.insert(query_tab, encode_or_not(key) .. "=" .. encode_or_not(param))
            end
        end
        canonical_query_string = core.table.concat(query_tab, "&")
    end

    core.log.info("all headers: ",
            core.json.delay_encode(core.request.headers(ctx), true))

    if not content then
        content = ""
    end
    local signing_string = "requestMethod=" .. request_method ..
            "&uri=" .. canonical_uri ..
            "&queryString=" .. canonical_query_string ..
            "&appId=" .. params.app_id ..
            "&timestamp=" .. params.timestamp ..
            "&requestBody=" .. ngx_encode_base64(content)

    core.log.info("signing_string: ", signing_string,
            " params.signed_headers:",
            core.json.delay_encode(params.signed_headers))

    return signing_string, nil
end

local function addSignature(private_key, signing_string)

    local priv, err = resty_rsa:new({ private_key = private_key, algorithm = "SHA256" })
    if not priv then
        core.log.error("new rsa err:", err)
        return
    end
    local sig, error = priv:sign(signing_string)
    if not sig then
        core.log.error("sign error:", error)
        return nil, { message = "add signature fail" }
    end
    return sig, nil
end

local function signVerify(public_key, signing_string, signature)
    if not signature then
        return false, { message = "signature value cannot be empty" }
    end
    if not ngx_decode_base64(signature) then
        return false, { message = "wrong signature value" }
    end

    local pub, err = resty_rsa:new({ public_key = public_key, algorithm = "SHA256" })
    if not pub then
        core.log.error("new rsa err: ", err)
        return false, { message = "resty_rsa new public fail " }
    end
    local verify, error = pub:verify(signing_string, ngx_decode_base64(signature))
    core.log.info("public_key: ", public_key)
    core.log.info("signature: ", signature)
    if not verify then
        core.log.error("verify err: ", error)
        return false, { message = "signature verification failed" }
    end
    return true, nil
end

function _M.validate(ctx, params, consumer, content)
    if not params.app_id or not params.signature then
        return nil, { message = "app id or signature missing" }
    end
    if not params.sign_type then
        return nil, { message = "sign_type  missing" }
    end

    if not params.timestamp then
        return nil, { message = "timestamp  missing" }
    end

    local expire = ctx.expire
    core.log.error("验签插件：过期时间：", expire)
    --如果时间间隔大于有效期
    local now = ngx.now() * 1000
    local interval = now - params.timestamp
    core.log.error("验签插件：当前时间戳", now, ",请求时间戳：", params.timestamp, ",间隔时间：", interval)
    if expire and interval > expire then
        core.log.error("验签插件：间隔大于过期时间")
        return nil, { message = "timestamp  expired" }
    end

    local signing_string, error = generate_signing_string(ctx, params, consumer, content, "validate")
    if error then
        return nil, error
    end
    core.log.error("singing_string:", signing_string)

    local consumer_cert = consumer.cert
    if not consumer_cert or not consumer_cert.key_type then
        return nil, { message = "get consumer signature information fail" }
    end
    local key_type = consumer_cert.key_type
    --[[    验证证书有效期]]
    if key_type == 'certificate' then
        local validity_start = consumer_cert.validity_start
        local validity_end = consumer_cert.validity_end
        local now = os.time()
        core.log.error(core.json.delay_encode(now))
        if now < validity_start or now > validity_end then
            return nil, { message = "not within the validity period of the certificate" }
        end
    end

    --[[    验签]]
    local public_key = consumer_cert.public_key
    local verify, error = signVerify(public_key, signing_string, params.signature)
    if not verify then
        return nil, error
    end
    return consumer
end

function _M.get_params(ctx)
    local params = {}

    local app_key = core.request.header(ctx, APP_ID)
    local signature = core.request.header(ctx, SIGNATURE_KEY)
    local timestamp = core.request.header(ctx, TIMESTAMP)
    local signType = core.request.header(ctx, SIGN_TYPE)
    core.log.info("signature_key: ", signature)

    if not app_key then
        return params
    end
    params.app_id = app_key
    params.signature = signature
    params.sign_type = signType
    params.timestamp = timestamp

    return params
end

function _M.signature(conf, ctx, params, consumer_info, content, isResponse)

    if not params.app_id then
        return nil, { message = "app id missing" }
    end
    -- 路由指定了加签算法，请求中不需要再加signType参数
    local sign_type = conf.sign_type
    if sign_type then
        params.sign_type = sign_type
        if not params.timestamp then
            params.timestamp = ngx_time()
        end

    end

    if not params.sign_type then
        return nil, { message = "sign_type  missing" }
    end

    local signing_string, error = generate_signing_string(ctx, params, consumer_info, content, "signature")
    if error then
        return nil, error
    end
    core.log.error("signing_string: ", signing_string)

    local consumer_cert = consumer_info.cert
    if not consumer_cert or not consumer_cert.key_type then
        return nil, { message = "get consumer signature information fail" }
    end

    local platform_cert, error = get_platform_cert(consumer_info)
    if error then
        return nil, error;
    end
    local key_type = consumer_cert.key_type
    --[[    验证证书有效期]]
    if key_type == 'certificate' then

        local validity_start = platform_cert.validity_start
        local validity_end = platform_cert.validity_end
        local now = os.time()
        if now < validity_start or now > validity_end then
            return nil, { message = "not within the validity period of the certificate" }
        end
    end

    --[[    加签]]
    local private_key = platform_cert.private_key
    local sig, error1 = addSignature(private_key, signing_string)
    if not sig then
        return nil, { message = "add signature fail: ", error1 }
    end
    if isResponse then
        core.log.error("Not currently supported response")
    else
        core.request.set_header(ctx, "sign", ngx_encode_base64(sig))
        core.request.set_header(ctx, "signType", "RSAWithSha256")
        core.request.set_header(ctx, "timestamp", params.timestamp)
    end
    return consumer_info
end

return _M
