local _M = {}
-- 编码
function _M.encode(s)
    s = string.gsub(s, "([^%w%.%- ])", function(c)
        return string.format("%%%02X", string.byte(c))
    end)
    return string.gsub(s, " ", "+")
end

-- 解码
function _M.decode(s)
    s = string.gsub(s, '%%(%x%x)', function(h)
        return string.char(tonumber(h, 16))
    end)
    return s
end

return _M
