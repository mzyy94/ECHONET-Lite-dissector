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
local nodeprofile = require("epcparser/node-profile")

-- ========================================================
-- ECHONET Lite epc parser
-- ========================================================

local function epcparser(classgroup, class, epc, pdc, edt, tree, edata)
    if classgroup:uint() == 0x0e and class:uint() == 0xf0 then -- Node profile
        nodeprofile(classgroup, class, epc, pdc, edt, tree, edata)
        do return end
    end
    tree:add(edata.fields.epc, epc)
    tree:add(edata.fields.pdc, pdc)
    if edt:len() > 0 then
        tree:add(edata.fields.edt, edt)
    end
end

return epcparser
