-- ########################################################
-- ECHONET Lite Wireshark dissector
-- ########################################################
--
--   Author : Yuki MIZUNO
--   Version: 1.0.0
--   License: MIT
--
-- ########################################################
--
--  Copyright (c) 2016 Yuki MIZUNO
--  This software is released under the MIT License.
--  http://opensource.org/licenses/MIT
--
local list = require("echonet-lite-codelist")

-- ========================================================
-- ECHONET Lite epc parser
-- ========================================================

local function epcparser(classgroup, class, epc, pdc, edt, tree, edata)
    if classgroup:uint() == 0x0e and class:uint() == 0xf0 then -- Node profile
        if epc:uint() == 0xd5 or epc:uint() == 0xd6 then
            if epc:uint() == 0xd5 then
                tree:add(edata.fields.epc, epc, epc:uint(), nil, "(Instance list notification)")
            else
                tree:add(edata.fields.epc, epc, epc:uint(), nil, "(Self-node instance list S)")
            end
            tree:add(edata.fields.pdc, pdc)
            if pdc:uint() == 0 then
                do return end
            end
            local edttree = tree:add(edata.fields.edt, edt)
            edttree:add(edt:range(0, 1), "Instance count:", edt:range(0, 1):uint())
            for i=1,edt:range(0, 1):uint() do
                local index = i * 3 - 2
                local obj = "Unknown"
                if list.class[edt:range(index, 1):uint()] ~= nil and list.class[edt:range(index, 1):uint()][edt:range(index + 1, 1):uint()] ~= nil then
                    obj = list.class[edt:range(index, 1):uint()][edt:range(index + 1, 1):uint()]
                end
                edttree:add(edt:range(index, 3), "-", obj, string.format("(ID: %d)", edt:range(index + 2, 1):uint()))
            end
            do return end
        end
        if epc:uint() == 0xd7 then
            tree:add(edata.fields.epc, epc, epc:uint(), nil, "(Self-node class list S)")
            tree:add(edata.fields.pdc, pdc)
            if pdc:uint() == 0 then
                do return end
            end
            local edttree = tree:add(edata.fields.edt, edt)
            edttree:add(edt:range(0, 1), "Class count:", edt:range(0, 1):uint())
            for i=1,edt:range(0, 1):uint() do
                local index = i * 2 - 1
                local obj = "Unknown"
                if list.class[edt:range(index, 1):uint()] ~= nil and list.class[edt:range(index, 1):uint()][edt:range(index + 1, 1):uint()] ~= nil then
                    obj = list.class[edt:range(index, 1):uint()][edt:range(index + 1, 1):uint()]
                end
                edttree:add(edt:range(index, 2), "-", obj)
            end
            do return end
        end
    end
    tree:add(edata.fields.epc, epc)
    tree:add(edata.fields.pdc, pdc)
    if edt:len() > 0 then
        tree:add(edata.fields.edt, edt)
    end
end

return epcparser
