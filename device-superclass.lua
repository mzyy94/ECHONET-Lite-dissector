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
local list = require("echonet-lite-codelist")
local properties = {
    [0x80] = "Operating status",
    [0x81] = "Installation location",
    [0x82] = "Standard version information",
    [0x83] = "Identification number",
    [0x84] = "Measured instantaneous power consumption",
    [0x85] = "Measured cumulative power consumption",
    [0x86] = "Manufacturer's fault code",
    [0x87] = "Current limit setting",
    [0x88] = "Fault status",
    [0x89] = "Fault description",
    [0x8a] = "Manufacturer code",
    [0x8b] = "Business facility code",
    [0x8c] = "Product code",
    [0x8d] = "Production number",
    [0x8e] = "Production date",
    [0x8f] = "Power-saving operation setting",
    [0x93] = "Remote control setting",
    [0x97] = "Current time setting",
    [0x98] = "Current date setting",
    [0x99] = "Power limit setting",
    [0x9a] = "Cumulative operating time",
    [0x9d] = "Status change announcement property map",
    [0x9e] = "Set property map",
    [0x9f] = "Get property map",
}

-- ========================================================
-- ECHONET Lite epc parser
-- ========================================================

local function devicesuperclass(classgroup, class, epc, pdc, edt, tree, edata, propmap)
    local propmap = propmap or {}
    local label = propmap[epc:uint()] or properties[epc:uint()]
    tree:add(edata.fields.epc, epc, epc:uint(), nil, string.format("(%s)", label))
    tree:add(edata.fields.pdc, pdc)
    tree:append_text(string.format(": %s", label))
    if pdc:uint() == 0 or edt:len() == 0 then
        do return end
    end

    local edttree = tree:add(edata.fields.edt, edt)
    if epc:uint() == 0x80 then
        local state = {
            [0x30] = "ON",
            [0x31] = "OFF"
        }
        edttree:append_text(string.format(" (%s)", state[edt:uint()]))
        tree:append_text(string.format(" = %s", state[edt:uint()]))
    -- elseif epc:uint() == 0x81 then -- TODO: Parse location
    elseif epc:uint() == 0x82 then
        if pdc:uint() ~= 4 then
            do return end
        end
        local release = edt:range(2, 1):string()

        edttree:append_text(string.format(" (Appendix. %s)", release))
        tree:append_text(string.format(" = Appendix. %s", release))
    elseif epc:uint() == 0x83 then
        if (not (edt:range(0, 1):uint() == 0xff and pdc:uint() == 9)) and (not (edt:range(0, 1):uint() == 0xfe and pdc:uint() == 17)) and (not edt:range(0, 1) == 0x00) then
            do return end
        end
        edttree:add(edt:range(0, 1), "Communication ID:", string.format("0x%02x", edt:range(0, 1):uint()))
        if edt:range(0, 1):uint() == 0x00 then
            edttree:add(edt:range(1, pdc:uint()), "Unique number:", tostring(edt:range(1):bytes()))
        elseif edt:range(0, 1):uint() == 0xfe then
            edttree:add(edt:range(1, 3), "Manufacturer code:", tostring(edt:range(1, 3):bytes()))
            edttree:add(edt:range(4, 13), "Unique ID:", tostring(edt:range(4, 13):bytes()))
        else
            edttree:add(edt:range(1, pdc:uint()), "Randomly generated protocol:", tostring(edt:range(1):bytes()))
        end
    elseif epc:uint() == 0x84 or epc:uint() == 0x99 then
        edttree:append_text(string.format(" (%d W)", edt:uint()))
        tree:append_text(string.format(" = %d W", edt:uint()))
    elseif epc:uint() == 0x85 then
        edttree:append_text(string.format(" (%d.%03d kWh)", edt:uint() / 1000, edt:uint() % 1000))
        tree:append_text(string.format(" = %d.%03d kWh", edt:uint() / 1000, edt:uint() % 1000))
    elseif epc:uint() == 0x86 then
        if pdc:uint() < 4 then
            do return end
        end
        edttree:add(edt:range(0, 1), "Fault code size:", tostring(edt:range(0, 1):uint()))
        edttree:add(edt:range(1, 3), "Manufacturer code:", tostring(edt:range(1, 3):bytes()))
        edttree:add(edt:range(4, edt:range(0, 1):uint()), "Manufacturer-defined fault code:", tostring(edt:range(4, edt:range(0, 1):uint()):bytes()))
    elseif epc:uint() == 0x87 then
        edttree:append_text(string.format(" (%d %)", edt:uint()))
        tree:append_text(string.format(" = %d %", edt:uint()))
    elseif epc:uint() == 0x88 then
        local state = {
            [0x41] = "Fault occurred",
            [0x42] = "No fault has occurred"
        }
        edttree:append_text(string.format(" (%s)", state[edt:uint()]))
        tree:append_text(string.format(" = %s", state[edt:uint()]))
    -- elseif epc:uint() == 0x89 then -- TODO: Parse fault description
    elseif epc:uint() == 0x8a then
        if pdc:uint() ~= 3 then
            do return end
        end
        edttree:add(edt:range(0, 3), "Manufacturer code:", tostring(edt:range(0, 3):bytes()))
    -- elseif epc:uint() == 0x8b then -- nothing to parse
    elseif epc:uint() == 0x8c or epc:uint() == 0x8d then
        if pdc:uint() ~= 12 then
            do return end
        end
        edttree:append_text(string.format(" [%s]", edt:range(0, 12):string()))
    elseif epc:uint() == 0x8e or epc:uint() == 0x98 then
        if pdc:uint() ~= 4 then
            do return end
        end
        edttree:append_text(string.format(" [%d/%d/%d]", edt:range(0, 2):uint(), edt:range(2,1):uint(), edt:range(3,1):uint()))
    elseif epc:uint() == 0x8f then
        local state = {
            [0x41] = "Power-saving mode",
            [0x42] = "Normal operation mode"
        }
        edttree:append_text(string.format(" (%s)", state[edt:uint()]))
        tree:append_text(string.format(" = %s", state[edt:uint()]))
    elseif epc:uint() == 0x93 then
        local state = {
            [0x41] = "Not through a public network",
            [0x42] = "Through a public network",
            [0x61] = "Bad communication network state",
            [0x62] = "Good communication network state",
        }
        edttree:append_text(string.format(" (%s)", state[edt:uint()]))
        tree:append_text(string.format(" = %s", state[edt:uint()]))
    elseif epc:uint() == 0x97 then
        if pdc:uint() ~= 2 then
            do return end
        end
        edttree:append_text(string.format(" [%02d:%02d]", edt:range(0, 1):uint(), edt:range(1, 1):uint()))
    -- elseif epc:uint() == 0x98 then -- Already defined. See above.
    -- elseif epc:uint() == 0x99 then -- Already defined. See above.
    elseif epc:uint() == 0x9a then
        if pdc:uint() ~= 5 then
            do return end
        end
        local state = {
            [0x41] = "Second",
            [0x42] = "Minute",
            [0x43] = "Hour",
            [0x44] = "Day",
        }
        edttree:add(edt:range(0, 1), "Unit:", state[edt:range(0, 1):uint()])
        edttree:add(edt:range(1, 4), "Time:", tostring(edt:range(1, 4):uint()))
        edttree:append_text(string.format(" (%d %ss)", edt:range(1, 4):uint(), state[edt:range(0,1):uint()]))
        tree:append_text(string.format(" = %d %ss", edt:range(1, 4):uint(), state[edt:range(0,1):uint()]))
    elseif epc:uint() == 0x9d or epc:uint() == 0x9e or epc:uint() == 0x9f then
        edttree:add(edt:range(0, 1), "Property count:", edt:range(0, 1):uint())
        for i=1,edt:range(0, 1):uint() do
            local property = propmap[edt:range(i, 1):uint()] or properties[edt:range(i, 1):uint()]
            edttree:add(edt:range(i, 1), "-", property)
            if i >= 16 then
                do return end
            end
        end
    end
end

return devicesuperclass
