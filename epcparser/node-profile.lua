-- ########################################################
-- ECHONET Lite Wireshark dissector
-- ########################################################
--
--   Author : Yuki MIZUNO
--   Version: 1.1.0
--   License: MIT
--
-- ########################################################
--
--  Copyright (c) 2016 Yuki MIZUNO
--  This software is released under the MIT License.
--  http://opensource.org/licenses/MIT
--
local list = require("../echonet-lite-codelist")
local properties = {
    [0x80] = "Operating status",
    [0x82] = "Version information",
    [0x83] = "Identification number",
    [0x88] = "Fault status",
    [0x89] = "Fault content",
    [0x8a] = "Manufacturer code",
    [0x8b] = "Business facility code",
    [0x8c] = "Product code",
    [0x8d] = "Production number",
    [0x8e] = "Production date",
    [0x9d] = "Status change announcement property map",
    [0x9e] = "Set property map",
    [0x9f] = "Get property map",
    [0xbf] = "Unique identifier data",
    [0xd3] = "Number of self-node instances",
    [0xd4] = "Number of self-node classes",
    [0xd5] = "Instance list notification",
    [0xd6] = "Self-node instance list S",
    [0xd7] = "Self-node class list S",
}

-- ========================================================
-- ECHONET Lite epc parser
-- ========================================================

local function nodeprofile(classgroup, class, epc, pdc, edt, tree, edata)
    if classgroup:uint() == 0x0e and class:uint() == 0xf0 then -- Node profile
        local label = properties[epc:uint()]
        tree:add(edata.fields.epc, epc, epc:uint(), nil, string.format("(%s)", label))
        tree:add(edata.fields.pdc, pdc)
        tree:append_text(string.format(": %s", label))
        if pdc:uint() == 0 or edt:len() == 0 then
            do return end
        end

        local edttree = tree:add(edata.fields.edt, edt)
        if epc:uint() == 0x80 then
            local state = {
                [0x30] = "Booting",
                [0x31] = "Not Booting"
            }
            edttree:append_text(string.format(" (%s)", state[edt:uint()]))
            tree:append_text(string.format(" = %s", state[edt:uint()]))
        elseif epc:uint() == 0x82 then
            if pdc:uint() ~= 4 then
                do return end
            end
            local major = edt:range(0, 1):uint()
            local minor = edt:range(1, 1):uint()
            local version = string.format("Version %d.%d", major, minor)
            local type = ""
            if edt:range(2, 1):uint() == 0x03 then
                type = "Format 1 and Format 2"
            elseif edt:range(2, 1):uint() == 0x02 then
                type = "Format 1"
            elseif edt:range(2, 1):uint() == 0x01 then
                type = "Format 2"
            end

            edttree:append_text(string.format(" (%s, %s)", version, type))
            tree:append_text(string.format(" = %s, %s", version, type))
        elseif epc:uint() == 0x83 then
            if pdc:uint() ~= 17 then
                do return end
            end
            edttree:add(edt:range(0, 1), "Communication ID:", string.format("0x%02x", edt:range(0, 1):uint()))
            edttree:add(edt:range(1, 3), "Manufacturer code:", tostring(edt:range(1, 3):bytes()))
            edttree:add(edt:range(4, 13), "Unique ID:", tostring(edt:range(4, 13):bytes()))
        elseif epc:uint() == 0x88 then
            local state = {
                [0x41] = "Fault encountered",
                [0x42] = "No fault encountered"
            }
            edttree:append_text(string.format(" (%s)", state[edt:uint()]))
            tree:append_text(string.format(" = %s", state[edt:uint()]))
        -- elseif epc:uint() == 0x89 then -- nothing to parse
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
        elseif epc:uint() == 0x8e then
            if pdc:uint() ~= 4 then
                do return end
            end
            edttree:append_text(string.format(" [%d/%d/%d]", edt:range(0, 2):uint(), edt:range(2,1):uint(), edt:range(3,1):uint()))
        elseif epc:uint() == 0x9d or epc:uint() == 0x9e or epc:uint() == 0x9f then
            edttree:add(edt:range(0, 1), "Property count:", edt:range(0, 1):uint())
            for i=1,edt:range(0, 1):uint() do
                local property = properties[edt:range(i, 1):uint()]
                edttree:add(edt:range(i, 1), "-", property)
                if i >= 16 then
                    do return end
                end
            end
        -- elseif epc:uint() == 0xbf then -- nothing to parse
        elseif epc:uint() == 0xd3 then
            if pdc:uint() ~= 3 then
                do return end
            end
            edttree:add(edt:range(0, 3), "Instance count:", tostring(edt:range(0, 3):uint()))
        elseif epc:uint() == 0xd4 then
            if pdc:uint() ~= 2 then
                do return end
            end
            edttree:add(edt:range(0, 2), "Instance count:", tostring(edt:range(0, 2):uint()))
        elseif epc:uint() == 0xd5 or epc:uint() == 0xd6 then
            edttree:add(edt:range(0, 1), "Instance count:", edt:range(0, 1):uint())
            for i=1,edt:range(0, 1):uint() do
                local index = i * 3 - 2
                local obj = "Unknown"
                if list.class[edt:range(index, 1):uint()] ~= nil and list.class[edt:range(index, 1):uint()][edt:range(index + 1, 1):uint()] ~= nil then
                    obj = list.class[edt:range(index, 1):uint()][edt:range(index + 1, 1):uint()]
                end
                edttree:add(edt:range(index, 3), "-", obj, string.format("(ID: %d)", edt:range(index + 2, 1):uint()))
                if i >= 84 then
                    do return end
                end
            end
        elseif epc:uint() == 0xd7 then
            edttree:add(edt:range(0, 1), "Class count:", edt:range(0, 1):uint())
            for i=1,edt:range(0, 1):uint() do
                local index = i * 2 - 1
                local obj = "Unknown"
                if list.class[edt:range(index, 1):uint()] ~= nil and list.class[edt:range(index, 1):uint()][edt:range(index + 1, 1):uint()] ~= nil then
                    obj = list.class[edt:range(index, 1):uint()][edt:range(index + 1, 1):uint()]
                end
                edttree:add(edt:range(index, 2), "-", obj)
                if i >= 8 then
                    do return end
                end
            end
        end
    end
end

return nodeprofile
