-- Copyright (c) 2024 OpenResty Inc.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local require = require
local setmetatable = setmetatable
local ngx = ngx
local type = type
local error = error
local tostring = tostring
local math_floor = math.floor
local os_time = os.time

local _M = {}
local mt = { __index = _M }

_M._VERSION = '0.1.0'

function _M.new(max_size, default_ttl)
    if type(max_size) ~= "number" or max_size < 1 then
        error("max_size must be a positive number")
    end

    local self = {
        store = {},
        expiry = {},
        max_size = max_size,
        size = 0,
        default_ttl = default_ttl or 300,
        hits = 0,
        misses = 0,
    }

    return setmetatable(self, mt)
end

function _M.set(self, key, value, ttl)
    if key == nil then
        return nil, "key is nil"
    end

    ttl = ttl or self.default_ttl

    if self.store[key] == nil then
        if self.size >= self.max_size then
            self:_evict()
        end
        self.size = self.size + 1
    end

    self.store[key] = value
    self.expiry[key] = os_time() + ttl

    return true
end

function _M.get(self, key)
    local value = self.store[key]
    if value == nil then
        self.misses = self.misses + 1
        return nil, "not found"
    end

    local exp = self.expiry[key]
    if exp and os_time() > exp then
        self:delete(key)
        self.misses = self.misses + 1
        return nil, "expired"
    end

    self.hits = self.hits + 1
    return value
end

function _M.delete(self, key)
    if self.store[key] ~= nil then
        self.store[key] = nil
        self.expiry[key] = nil
        self.size = self.size - 1
        return true
    end
    return false
end

function _M._evict(self)
    local oldest_key = nil
    local oldest_time = nil

    for key, exp in pairs(self.expiry) do
        if oldest_time == nil or exp < oldest_time then
            oldest_key = key
            oldest_time = exp
        end
    end

    if oldest_key then
        self:delete(oldest_key)
    end
end

function _M.flush(self)
    self.store = {}
    self.expiry = {}
    self.size = 0
end

function _M.stats(self)
    return {
        size = self.size,
        max_size = self.max_size,
        hits = self.hits,
        misses = self.misses,
        hit_rate = self.hits / (self.hits + self.misses + 1),
    }
end

return _M