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

local core = require("apisix.core")
local request      = require("apisix.core.request")
local ngx_decode_base64 = ngx.decode_base64
local ngx_time = ngx.time
local url = require("apisix.utils.url")
local special_characters = require("apisix.utils.special_characters")
local util = require("apisix.cli.util")
local uuid = require("resty.jit-uuid")
local SIGN = "sign"
local FORMAT = "format"
local APP_ID = "appId"
local APP_ID_SMALL = "appid"
local TIMESTAMP = "timestamp"
local DATA = "data"
local NONCE = "nonce"
local VERSION = "version"
local SIGN_TYPE = "signType"
local METHOD = "method"
local str_lower = string.lower


local _M = {}

local function generate_signing_string(params)
    if not params.data then
        params.data = ""
    end
    local signing_string = "appid=" .. params.app_id ..
            "&data=" .. params.data ..
            "&format=" .. params.format ..
            "&method=" .. params.method ..
            "&nonce=" .. params.nonce ..
            "&timestamp=" .. params.timestamp ..
            "&version=" .. params.version
    return signing_string, nil
end

local function generate_request_body(params)

    local request_body
    for key, value in pairs(params) do
        if key and value and key ~= "sign_type" then
            if key == 'app_id' then
                key = 'appid'
            end
            if request_body then
                request_body = request_body .. "&" .. key .. "=" .. url.encode(value)
            else
                request_body = key .. "=" .. url.encode(value)
            end
        end
    end
    return request_body, nil
end

local function addSignature(app_secret, signing_string)
    -- 签名串拼接密钥
    local deal_signing_string = special_characters.lower(signing_string)
    -- 转小写
    local final_signing_string = str_lower(deal_signing_string .. "&appsecret=" .. app_secret)

    --32位 MD5加密
    local sig = ngx.md5(final_signing_string)
    --32位 MD5加密
    core.log.error("sig:", sig)
    return sig, nil
end

local function parse_url_encoded_method(body)
    local parts = util.split(body, "&")
    local postBody = {}
    for _, val in pairs(parts) do
        local keyValue = util.split(val, "=")
        postBody[keyValue[1]] = keyValue[2]
    end
    local args = request.get_post_args()["data"]
    return postBody
end

local function get_params(request_body)

    local params = {}

    params.app_id = request.get_post_args()[APP_ID]
    if not params.app_id then
        params.app_id = request.get_post_args()[APP_ID_SMALL]
    end
    params.timestamp = request.get_post_args()[TIMESTAMP]
    params.data = request.get_post_args()[DATA]
    params.nonce = request.get_post_args()[NONCE]
    params.version = request.get_post_args()[VERSION]
    params.signature = request.get_post_args()[SIGN]
    params.format = request.get_post_args()[FORMAT]
    params.method = request.get_post_args()[METHOD]

    return params
end

local function signVerify(app_secret, signing_string, signature)
    if not signature then
        return false, { message = "signature value cannot be empty" }
    end
    if not ngx_decode_base64(signature) then
        return false, {
            Code = "-2",
            Message = "签名校验错误:验签失败!",
            Success = false
        }, 401
    end

    local sig, err = addSignature(app_secret, signing_string)
    if err then
        return false, {
            Code = "-2",
            Message = "签名校验错误:验签失败!",
            Success = false
        }, 401
    end
    if sig == str_lower(signature) then
        return true, nil
    end
    return false, nil

end

function _M.validate(ctx, params, consumer, content)
    if content == nil then
        return nil, { message = "request body can not be null" }
    end
    params = get_params(content)
    core.log.info("params:", core.json.delay_encode(params, true))

    if not params.app_id or not params.signature or not params.timestamp or not params.nonce
            or not params.version or not params.data or not params.format or not params.method
    then
        return nil, { message = "incomplete signature parameters" }
    end

    local signing_string, error = generate_signing_string(params)
    if error then
        return nil, error
    end
    core.response.add_header("Content-Type","application/json; charset=utf-8")
    local consumer_cert = consumer.cert
    --[[    验签]]
    local public_key = consumer_cert.public_key
    local verify, error, code = signVerify(public_key, signing_string, params.signature)

    if not verify then
        return nil, error, code
    end

    return consumer
end

function _M.get_params(ctx, request_body)
    local params = {}

    params.app_id = core.request.header(ctx, APP_ID)
    params.sign_type = core.request.header(ctx, SIGN_TYPE)
    params.method = core.request.header(ctx, METHOD)

    if not params.app_id then
        params = get_params(request_body)
    end

    core.request.set_header(ctx, "appid", params.app_id)
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
    end

    params.timestamp = ngx_time()
    params.format = 'json'
    params.nonce = uuid()
    params.version = '1.0'
    params.data = content

    if not params.sign_type then
        return nil, { message = "sign_type  missing" }
    end

    local signing_string, error = generate_signing_string(params)


    if error then
        return nil, error
    end

    local consumer_cert = consumer_info.cert
    if not consumer_cert or not consumer_cert.key_type then
        return nil, { message = "get consumer signature information fail" }
    end
    -- 集采加签秘钥
    local app_secret = consumer_cert.public_key
    --[[    加签]]
    local sig, error1 = addSignature(app_secret, signing_string)
    if not sig then
        return nil, { message = "add signature fail: ", error1 }
    end
    params.sign = sig

    local final_request_body = generate_request_body(params);
    core.log.error("最终requestBody:", final_request_body)

    core.response.clear_header_as_body_modified()
    core.request.set_header(ctx, "Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
    ngx.req.set_body_data(final_request_body)

    return consumer_info
end

return _M
