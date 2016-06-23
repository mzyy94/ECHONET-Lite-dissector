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

local function epcparser(classgroup, class, epc, pdc, edt, tree, edata, buffer)
    if classgroup:uint() == 0x0e and class:uint() == 0xf0 then -- Node profile
        if epc:uint() == 0xd5 then
            tree:add(edata.fields.epc, epc, epc:uint(), nil, "(Instance list notification)")
            tree:add(edata.fields.pdc, pdc)
            local edttree = tree:add(edata.fields.edt, edt)
            edttree:add(buffer(10, 1), "Instance count:", buffer(10, 1):uint())
            for i=1,buffer(10, 1):uint() do
                local index = 8 + i * 3
                local obj = "Unknown"
                if list.class[buffer(index, 1):uint()] ~= nil and list.class[buffer(index, 1):uint()][buffer(index + 1, 1):uint()] ~= nil then
                    obj = list.class[buffer(index, 1):uint()][buffer(index + 1, 1):uint()]
                end
                edttree:add(buffer(index, 3), "-", obj, string.format("(ID: %d)", buffer(index + 2, 1):uint()))
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
