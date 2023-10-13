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
local resource = require("apisix.admin.resource")


local function check_conf(id, conf)
    -- core.log.error(core.json.encode(conf))
    if not conf then
        return nil, { error_msg = "missing configurations" }
    end

    core.log.info("schema: ", core.json.delay_encode(core.schema.permissions))
    core.log.info("conf  : ", core.json.delay_encode(conf))
    local ok, err = core.schema.check(core.schema.permission, conf)
    if not ok then
        core.log.error("permissions schema verification failed...")
        return nil, { error_msg = "invalid configuration: " .. err }
    end
    return id
end


return resource.new({
    name = "permissions",
    kind = "permission",
    schema = core.schema.permission,
    checker = check_conf,
})

