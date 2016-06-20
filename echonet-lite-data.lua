-- ########################################################
-- ECHONET Lite Wireshark dissector
-- ########################################################
--
--   Author : Yuki MIZUNO
--   Version: 0.0.1
--   License: MIT
--
-- ########################################################
--
--  Copyright (c) 2016 Yuki MIZUNO
--  This software is released under the MIT License.
--  http://opensource.org/licenses/MIT
--

edata = Proto("echonetlite.edata", "ECHONET Lite Data (EDATA)")

-- ========================================================
-- ECHONET Lite Data fields definition.
-- ========================================================

edata.fields.seoj = ProtoField.uint24("echonetlite.edata.seoj", "SEOJ", base.HEX)
edata.fields.deoj = ProtoField.uint24("echonetlite.edata.deoj", "DEOJ", base.HEX)
edata.fields.esv  = ProtoField.uint8("echonetlite.edata.esv",   "ESV",  base.HEX)

-- ========================================================
-- Parse ECHONET Lite Data fields.
-- ========================================================

function edata.dissector(buffer, pinfo, tree)
    local data_len = buffer:len()

    local subtree = tree:add(edata, buffer(0, data_len))

    subtree:add(edata.fields.seoj, buffer(0, 3))
    subtree:add(edata.fields.deoj, buffer(3, 3))
    subtree:add(edata.fields.esv,  buffer(6, 1))
end
