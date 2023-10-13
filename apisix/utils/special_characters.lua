local _M = {}

local upper_special_characters = { "Ð", "Ñ", "Ò", "Ó", "Õ", "Õ", "Ö", "Ö", "Ø", "Ù", "Ú", "Ü", "Ý", "Þ", "Ÿ", "À", "Á", "Â", "Ã", "Ä", "Å", "Æ", "Ç", "È", "É", "Ë", "Ì", "Í", "Î", "Ï", "Φ", "Ω", "Ψ", "Ξ", "Δ", "Γ" ,"Π","Ⅰ", "Ⅱ", "Ⅲ", "Ⅳ", "Ⅴ", "Ⅵ", "Ⅶ", "Ⅷ", "Ⅸ","Ф"}
local with_shift = {
    ["Ð"] = "ð",
    ["Ñ"] = "ñ",
    ["Ò"] = "ò",
    ["Ó"] = "ó",
    ["Ô"] = "ô",
    ["Õ"] = "õ",
    ["Ö"] = "ö",
    ["Ø"] = "ø",
    ["Ù"] = "ù",
    ["Ú"] = "ú",
    ["Û"] = "û",
    ["Ü"] = "ü",
    ["Ý"] = "ý",
    ["Þ"] = "þ",
    ["Ÿ"] = "ÿ",
    ["À"] = "à",
    ["Á"] = "á",
    ["Â"] = "â",
    ["Ã"] = "ã",
    ["Ä"] = "ä",
    ["Å"] = "å",
    ["Æ"] = "æ",
    ["Ç"] = "ç",
    ["È"] = "è",
    ["É"] = "é",
    ["Ë"] = "ë",
    ["Ì"] = "ì",
    ["Í"] = "í",
    ["Î"] = "î",
    ["Ï"] = "ï",
    ["Φ"] = "φ",
    ["Ω"] = "ω",
    ["Ψ"] = "ψ",
    ["Ξ"] = "ξ",
    ["Δ"] = "δ",
    ["Γ"] = "γ",
    ["Π"] = "π",
    ["Ⅰ"] = "ⅰ",
    ["Ⅱ"] = "ⅱ",
    ["Ⅲ"] = "ⅲ",
    ["Ⅳ"] = "ⅳ",
    ["Ⅴ"] = "ⅴ",
    ["Ⅵ"] = "ⅵ",
    ["Ⅶ"] = "ⅶ",
    ["Ⅷ"] = "ⅷ",
    ["Ⅸ"] = "ⅸ",
    ["Ф"] = "ф",
}

-- 针对特殊字符进行小写处理(原生lua对特殊字符处理大小写存在问题)
function _M.lower(self)
    local keys = {}
    for _, character in pairs(upper_special_characters) do

        local exist_special_character = self:match(character)
        if exist_special_character then
            table.insert(keys, exist_special_character)
        end

    end

    for _, character in pairs(keys) do
        self = self:gsub(character, function(key)
            return with_shift[key]
        end)
    end
    return self
end

return _M

