-- ########################################################
-- ECHONET Lite Wireshark dissector
-- ########################################################
--
--   Author : Yuki MIZUNO
--   Version: 1.2.0
--   License: MIT
--
-- ########################################################
--
--  Copyright (c) 2016 Yuki MIZUNO
--  This software is released under the MIT License.
--  http://opensource.org/licenses/MIT
--
local devicesuperclass = require("device-superclass")
local list = require("echonet-lite-codelist")
local properties = {
    [0xe0] = "Degree-of-opening detection status 1",
    [0xb0] = "Detection threshold level",
    [0xb1] = "Degree-of-opening detection status 2",
}

-- ========================================================
-- ECHONET Lite epc parser
-- ========================================================

local function openclosesensor(classgroup, class, epc, pdc, edt, tree, edata)
    if classgroup:uint() == 0x00 and class:uint() == 0x29 then
        local label = properties[epc:uint()]
        if not label then
            devicesuperclass(classgroup, class, epc, pdc, edt, tree, edata, properties)
            do return end
        end
        tree:add(edata.fields.epc, epc, epc:uint(), nil, string.format("(%s)", label))
        tree:add(edata.fields.pdc, pdc)
        tree:append_text(string.format(": %s", label))
        if pdc:uint() == 0 or edt:len() == 0 then
            do return end
        end

        local edttree = tree:add(edata.fields.edt, edt)

        if epc:uint() == 0xe0 then
            if pdc:uint() ~= 1 then
                do return end
            end
            local state = {
                [0x30] = "Close detected",
                [0x39] = "Open deceted, level: unknown"
            }
            if edt:uint() == 0x30 or edt:uint() == 0x39 then
                edttree:append_text(string.format(" (%s)", state[edt:uint()]))
                tree:append_text(string.format(" = %s", state[edt:uint()]))
            elseif edt:uint() > 0x30 and edt:uint() < 0x39 then
                edttree:append_text(string.format(" (Open detected, level: 0x%02x)", edt:uint()))
                tree:append_text(string.format(" = Open detected, level: 0x%02x", edt:uint()))
            end
        elseif epc:uint() == 0xb0 then
            if pdc:uint() ~= 1 then
                do return end
            end
            if edt:uint() > 0x30 and edt:uint() < 0x39 then
                edttree:append_text(string.format(" (Detection threshold level: 0x%02x)", edt:uint()))
                tree:append_text(string.format(" = Detection threshold level: 0x%02x", edt:uint()))
            end
        elseif epc:uint() == 0xb1 then
            if pdc:uint() ~= 1 then
                do return end
            end
            local state = {
                [0x41] = "Open detected",
                [0x42] = "Close deceted"
            }
            edttree:append_text(string.format(" (%s)", state[edt:uint()]))
            tree:append_text(string.format(" = %s", state[edt:uint()]))
        end
    end
end

return openclosesensor
