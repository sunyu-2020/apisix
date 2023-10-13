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

local platform_cert

local _M = {
    version = 0.3,
}

function _M.platform_cert()
    if not platform_cert then
        core.log.error("can not find etcd platform_cert")
        return nil, nil
    end
    local map = core.table.new(0, #platform_cert.values)
    core.log.info("platform_cert values:",core.json.delay_encode(platform_cert.values,true))
    core.log.info("platform_cert size:",#platform_cert.values)
    for _, cert in ipairs(platform_cert.values) do
        map[cert.value.id] = cert.value
    end
    return map, platform_cert.conf_version
end

function _M.init_worker()
    local err
    local cfg = {
        automatic = true,
        item_schema = core.schema.platform_cert,
    }

    platform_cert, err = core.config.new("/platform_cert", cfg)
    core.log.info("init platform_cert:",core.json.delay_encode(platform_cert,true))
    if not platform_cert then
        core.log.error("failed to create etcd instance for fetching platform_cert: " .. err)
        return
    end
end

return _M
