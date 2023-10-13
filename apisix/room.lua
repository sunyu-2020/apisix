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
local pairs = pairs
local utils = require("apisix.core.utils")
local local_conf = core.config.local_conf()
local nkeys = core.table.nkeys
local apisix_room = local_conf.apisix.room

local _M = {}

function _M.nodes(up_nodes)

    local apisix_room = local_conf.apisix.room
    if not apisix_room then
        return up_nodes
    end

    core.log.error("roundrobin,up_nodes:", core.json.delay_encode(up_nodes, true))
    local room_nodes = core.table.new(0, #up_nodes)
    local other_room_nodes = core.table.new(0, #up_nodes)
    local nodes = core.table.new(0, #up_nodes)

    for key, weight in pairs(up_nodes) do
        local host, port, room = utils.parse_room_addr(key)
        if room then
            if room == apisix_room then
                room_nodes[host .. ":" .. port] = weight
            else
                other_room_nodes[host .. ":" .. port] = weight
            end
        else
            nodes[host .. ":" .. port] = weight
        end
    end

    if nkeys(room_nodes) > 0 then
        return room_nodes
    end
    if nkeys(nodes) then
        return nodes
    end
    return other_room_nodes

end

local function get_room_node (nodes, room)

    local room_nodes = core.table.new(core.table.nkeys(nodes), 0)
    local other_nodes = core.table.new(core.table.nkeys(nodes), 0)
    for _, node in ipairs(nodes) do
        if node.room == room then
            core.table.insert(room_nodes, node)
        else
            core.table.insert(other_nodes, node)
        end
    end
    return room_nodes, other_nodes;

end

function _M. get_room_nodes(nodes, isTheRoom)
    if apisix_room then
        local room_nodes, other_nodes = get_room_node(nodes, apisix_room)
        if isTheRoom then
            nodes = room_nodes
        else
            nodes = other_nodes
        end
    end
    return nodes
end

return _M
