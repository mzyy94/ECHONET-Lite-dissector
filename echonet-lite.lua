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

echonetlite = Proto("echonet-lite", "ECHONET Lite")

-- ========================================================
-- ECHONET Lite Header value table
-- ========================================================

ehd1 = {
    [0x10] = "ECHONET Lite Protocol"
}

ehd2 = {
    [0x81] = "Format 1",
    [0x82] = "Format 2"
}

-- ========================================================
-- ECHONET Lite UDP payload fields definition.
-- ========================================================

echonetlite.fields.ehd  = ProtoField.protocol("echonetlite.ehd",  "ECHONET Lite Header (EHD)")
echonetlite.fields.ehd1 = ProtoField.uint8("echonetlite.ehd1",  "EHD1", base.HEX, ehd1)
echonetlite.fields.ehd2 = ProtoField.uint8("echonetlite.ehd2",  "EHD2", base.HEX, ehd2)
echonetlite.fields.tid  = ProtoField.uint16("echonetlite.tid",  "TID",  base.HEX)
echonetlite.fields.seoj = ProtoField.uint24("echonetlite.seoj", "SEOJ", base.HEX)
echonetlite.fields.deoj = ProtoField.uint24("echonetlite.deoj", "DEOJ", base.HEX)
echonetlite.fields.esv  = ProtoField.uint8("echonetlite.esv",   "ESV",  base.HEX)

-- ========================================================
-- Parse ECHONET Lite UDP payload fields.
-- ========================================================

function echonetlite.dissector(buffer, pinfo, tree)
    local data_len = buffer:len()

    pinfo.cols.protocol = "ECHONET Lite"
    pinfo.cols.info = ""

    local subtree = tree:add(echonetlite, buffer(0, data_len))
    local ehdtree = subtree:add(echonetlite.fields.ehd, buffer(0, 2))
    ehdtree:add(echonetlite.fields.ehd1, buffer(0, 1))
    ehdtree:add(echonetlite.fields.ehd2, buffer(1, 1))
    subtree:add(echonetlite.fields.tid,  buffer(2, 2))
    subtree:add(echonetlite.fields.seoj, buffer(4, 3))
    subtree:add(echonetlite.fields.deoj, buffer(7, 3))
    subtree:add(echonetlite.fields.esv,  buffer(10, 1))

end

-- ========================================================
-- Register ECHONET Lite protocol to UDP port 3610
-- ========================================================

udp_table = DissectorTable.get("udp.port")
udp_table:add("3610", echonetlite)
